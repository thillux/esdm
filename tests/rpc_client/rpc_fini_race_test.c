/*
 * Test: esdm_rpcc_fini_unpriv_service() while other threads make calls
 *
 * A call picks its connection out of the array that init allocates and fini
 * frees. It used to load the array pointer first and take the connection only
 * afterwards, so a fini in between freed the array under it, and the call
 * then locked a mutex in freed memory. Fini and the lookup are serialized
 * since commit d8c7e95 - this test runs them against each other: some threads
 * keep asking for random bytes while another one sets the client up and tears
 * it down again, over and over.
 *
 * Every call has to either deliver all bytes it was asked for or fail. Freed
 * memory touched by a call is what an AddressSanitizer or ThreadSanitizer
 * build reports; a plain build only notices if it crashes or hangs.
 *
 * Like the -EAGAIN test, a stand-in server in this process answers on the
 * unprivileged socket, so neither a running ESDM nor root is needed.
 *
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"

#define TEST_LEN 32
#define TEST_FILL 0x5a
#define TEST_MAX_CONNS 64

/* Connections the client opens: few, so the stand-in can serve them all */
#define TEST_NODES 4
#define TEST_CALLERS 4
/* How long the client is set up and torn down while the callers run */
#define TEST_CHURN_MS 3000

static atomic_bool test_stop;
static atomic_bool test_callers_stop;
static atomic_uint test_served;
static atomic_uint test_refused;
static atomic_uint test_wrong;

static int test_listen_fd = -1;

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static size_t test_put_varint(uint8_t *buf, uint64_t val)
{
	size_t i = 0;

	do {
		buf[i] = (uint8_t)(val & 0x7f);
		val >>= 7;
		if (val)
			buf[i] |= 0x80;
		i++;
	} while (val);

	return i;
}

/* The len field (1) of a GetRandomBytesRequest, 0 if it has none */
static uint64_t test_request_len(const uint8_t *data, size_t len)
{
	uint64_t val = 0;
	unsigned int shift = 0;
	size_t i;

	if (len < 2 || data[0] != 0x08)
		return 0;

	for (i = 1; i < len && shift < 64; i++, shift += 7) {
		val |= (uint64_t)(data[i] & 0x7f) << shift;
		if (!(data[i] & 0x80))
			return val;
	}

	return 0;
}

/* Answer one request on @fd with the bytes asked for */
static bool test_serve(int fd)
{
	uint8_t resp[sizeof(struct esdm_rpc_proto_sc_header) + 32 + TEST_LEN];
	uint8_t req[512];
	struct esdm_rpc_proto_cs_header cs;
	struct esdm_rpc_proto_sc_header sc;
	uint8_t *msg = resp + sizeof(sc);
	size_t msglen = 0;
	uint64_t len;
	ssize_t rc;

	rc = recv(fd, req, sizeof(req), 0);
	if (rc <= 0)
		return false;
	if ((size_t)rc < sizeof(cs))
		return false;

	memcpy(&cs, req, sizeof(cs));
	len = test_request_len(req + sizeof(cs), (size_t)rc - sizeof(cs));
	if (len > TEST_LEN)
		len = TEST_LEN;

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg[msglen++] = 0x08;
	msglen += test_put_varint(msg + msglen, len);
	msg[msglen++] = 0x12;
	msglen += test_put_varint(msg + msglen, len);
	memset(msg + msglen, TEST_FILL, len);
	msglen += len;

	/* The client takes the header in little endian, as the server sends */
	sc.status_code = PROTOBUF_C_RPC_STATUS_CODE_SUCCESS;
	sc.method_index = cs.method_index;
	sc.message_length = (uint32_t)msglen;
	sc.request_id = cs.request_id;
	memcpy(resp, &sc, sizeof(sc));

	return send(fd, resp, sizeof(sc) + msglen, MSG_NOSIGNAL) ==
	       (ssize_t)(sizeof(sc) + msglen);
}

static void *test_server(void *unused)
{
	struct pollfd pfd[1 + TEST_MAX_CONNS];
	nfds_t nfds = 1, i;

	(void)unused;

	pfd[0].fd = test_listen_fd;
	pfd[0].events = POLLIN;

	while (!atomic_load(&test_stop)) {
		if (poll(pfd, nfds, 50) <= 0)
			continue;

		for (i = 1; i < nfds; i++) {
			if (!pfd[i].revents)
				continue;
			if ((pfd[i].revents & POLLIN) && test_serve(pfd[i].fd))
				continue;

			close(pfd[i].fd);
			pfd[i--] = pfd[--nfds];
		}

		if ((pfd[0].revents & POLLIN) && nfds < 1 + TEST_MAX_CONNS) {
			int fd = accept(test_listen_fd, NULL, NULL);

			if (fd >= 0) {
				pfd[nfds].fd = fd;
				pfd[nfds].events = POLLIN;
				pfd[nfds].revents = 0;
				nfds++;
			}
		}
	}

	for (i = 1; i < nfds; i++)
		close(pfd[i].fd);

	return NULL;
}

/* Listen on the unprivileged socket - unless an ESDM already does */
static int test_listen(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("Something listens on %s already\n", addr.sun_path);
		close(fd);
		return -EADDRINUSE;
	}
	close(fd);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	unlink(addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(fd, 16)) {
		int errsv = errno;

		printf("Cannot listen on %s: %s\n", addr.sun_path,
		       strerror(errsv));
		close(fd);
		return -errsv;
	}

	test_listen_fd = fd;

	return 0;
}

/* Keep asking for random bytes, whether the client is set up or not */
static void *test_caller(void *unused)
{
	uint8_t buf[TEST_LEN];
	ssize_t rc;
	size_t i;

	(void)unused;

	while (!atomic_load(&test_callers_stop)) {
		memset(buf, 0, sizeof(buf));
		rc = esdm_rpcc_get_random_bytes(buf, sizeof(buf));

		if (rc < 0) {
			atomic_fetch_add(&test_refused, 1);
			continue;
		}

		if (rc != TEST_LEN) {
			printf("FAIL: a call returned %zd bytes, expected %d\n",
			       rc, TEST_LEN);
			atomic_fetch_add(&test_wrong, 1);
			continue;
		}

		for (i = 0; i < sizeof(buf); i++) {
			if (buf[i] != TEST_FILL) {
				printf("FAIL: byte %zu of a call was not delivered\n",
				       i);
				atomic_fetch_add(&test_wrong, 1);
				break;
			}
		}
		if (i == sizeof(buf))
			atomic_fetch_add(&test_served, 1);
	}

	return NULL;
}

/* Set up and tear down the client while the callers run */
static int test_churn(void)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 0 };
	uint64_t start = test_now_ms();
	unsigned int cycles = 0;
	int ret;

	while (test_now_ms() - start < TEST_CHURN_MS) {
		ret = esdm_rpcc_init_unpriv_service(NULL);
		if (ret) {
			printf("FAIL: cannot initialize the RPC client: %d\n",
			       ret);
			return 1;
		}

		/* Vary how long the client stays up, up to a millisecond */
		pause.tv_nsec = (long)(cycles % 10) * 100000;
		nanosleep(&pause, NULL);

		esdm_rpcc_fini_unpriv_service();
		cycles++;
	}

	printf("%u set ups and tear downs of the client\n", cycles);

	return 0;
}

int main(void)
{
	pthread_t server, callers[TEST_CALLERS];
	uint8_t buf[TEST_LEN];
	unsigned int i, started = 0;
	ssize_t rc;
	int ret;

	ret = test_listen();
	/* Taken, or not ours to take in this environment */
	if (ret == -EADDRINUSE || ret == -EACCES || ret == -EPERM ||
	    ret == -ENOENT)
		return 77;
	if (ret)
		return 1;

	esdm_rpcc_set_max_online_nodes(TEST_NODES);

	/*
	 * The test mode statistics of the client live in a shared memory
	 * segment that the last fini of a service detaches - also while a call
	 * that is still running is about to count its bytes in it. That is not
	 * what this test is about: the privileged service, set up for the
	 * whole test and never called, keeps the segment attached.
	 */
	ret = esdm_rpcc_init_priv_service(NULL);
	if (ret) {
		printf("Cannot initialize the privileged RPC client: %d\n", ret);
		close(test_listen_fd);
		unlink(ESDM_RPC_UNPRIV_SOCKET);
		return 1;
	}

	if (pthread_create(&server, NULL, test_server, NULL)) {
		esdm_rpcc_fini_priv_service();
		close(test_listen_fd);
		unlink(ESDM_RPC_UNPRIV_SOCKET);
		return 1;
	}

	for (i = 0; i < TEST_CALLERS; i++) {
		if (pthread_create(&callers[i], NULL, test_caller, NULL)) {
			printf("FAIL: cannot start caller %u\n", i);
			ret = 1;
			break;
		}
		started++;
	}

	if (!ret)
		ret = test_churn();

	atomic_store(&test_callers_stop, true);
	for (i = 0; i < started; i++)
		pthread_join(callers[i], NULL);

	printf("%u calls served, %u refused, %u wrong\n",
	       atomic_load(&test_served), atomic_load(&test_refused),
	       atomic_load(&test_wrong));

	if (atomic_load(&test_wrong))
		ret = 1;

	/* The calls did meet a client that was set up */
	if (!ret && !atomic_load(&test_served)) {
		printf("FAIL: no call was served while the client was set up\n");
		ret = 1;
	}

	/* And the client still works after all of it */
	if (!ret) {
		ret = esdm_rpcc_init_unpriv_service(NULL);
		if (ret) {
			printf("FAIL: cannot initialize the RPC client: %d\n",
			       ret);
			ret = 1;
		} else {
			rc = esdm_rpcc_get_random_bytes(buf, sizeof(buf));
			if (rc != TEST_LEN) {
				printf("FAIL: the client does not work after the churn: %zd\n",
				       rc);
				ret = 1;
			}
			esdm_rpcc_fini_unpriv_service();
		}
	}

	esdm_rpcc_fini_priv_service();

	atomic_store(&test_stop, true);
	pthread_join(server, NULL);
	close(test_listen_fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	if (!ret)
		printf("PASS\n");

	return ret;
}
