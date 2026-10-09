/*
 * Test: esdm_rpcc_get_random_bytes() sends a request again that the server
 * answered with -EAGAIN
 *
 * The ESDM answers -EAGAIN when the node DRNG a request went to reached its
 * maximum output without full reseed and the initial DRNG had nothing left to
 * serve it with. That DRNG is out of rotation for the next request, so the
 * client asks again at once - and should the server keep answering so, after
 * the poll interval rather than in a spin.
 *
 * No ESDM can be made to answer -EAGAIN on cue, so a stand-in server in this
 * process does, on the unprivileged socket the client connects to: it answers
 * each request with -EAGAIN as often as the scenario says and then with the
 * bytes asked for.
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

/* How many answers of -EAGAIN precede the bytes, per request */
static atomic_uint test_eagain_answers;
/* -EAGAIN answers still to give for the request at hand */
static atomic_uint test_eagain_left;
/* Requests the server saw */
static atomic_uint test_requests;
static atomic_bool test_stop;

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

/* Answer one request on @fd; false when the connection is gone */
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

	atomic_fetch_add(&test_requests, 1);

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg[msglen++] = 0x08;
	if (atomic_load(&test_eagain_left)) {
		atomic_fetch_sub(&test_eagain_left, 1);
		msglen += test_put_varint(msg + msglen,
					  (uint64_t)(int64_t)-EAGAIN);
	} else {
		/* The next request starts its own sequence */
		atomic_store(&test_eagain_left,
			     atomic_load(&test_eagain_answers));
		msglen += test_put_varint(msg + msglen, len);
		msg[msglen++] = 0x12;
		msglen += test_put_varint(msg + msglen, len);
		memset(msg + msglen, TEST_FILL, len);
		msglen += len;
	}

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

/*
 * One call with @eagain answers of -EAGAIN before the bytes. It has to return
 * them all, after @eagain + 1 requests, and wait at least @min_ms and less than
 * @max_ms for them.
 */
static int test_call(unsigned int eagain, uint64_t min_ms, uint64_t max_ms)
{
	uint8_t buf[TEST_LEN + 8];
	unsigned int requests;
	uint64_t start, took;
	ssize_t rc;
	size_t i;

	printf("%u answer(s) of -EAGAIN\n", eagain);

	atomic_store(&test_eagain_answers, eagain);
	atomic_store(&test_eagain_left, eagain);
	atomic_store(&test_requests, 0);
	memset(buf, 0, sizeof(buf));

	start = test_now_ms();
	rc = esdm_rpcc_get_random_bytes(buf, TEST_LEN);
	took = test_now_ms() - start;
	requests = atomic_load(&test_requests);

	printf("  returned %zd after %u requests and %llu ms\n", rc, requests,
	       (unsigned long long)took);

	if (rc != TEST_LEN) {
		printf("FAIL: expected %d bytes\n", TEST_LEN);
		return 1;
	}
	for (i = 0; i < TEST_LEN; i++) {
		if (buf[i] != TEST_FILL) {
			printf("FAIL: byte %zu was not delivered\n", i);
			return 1;
		}
	}
	for (; i < sizeof(buf); i++) {
		if (buf[i]) {
			printf("FAIL: byte %zu beyond the request written\n",
			       i);
			return 1;
		}
	}
	if (requests != eagain + 1) {
		printf("FAIL: expected %u requests\n", eagain + 1);
		return 1;
	}
	if (took < min_ms || took >= max_ms) {
		printf("FAIL: expected to take %llu to %llu ms\n",
		       (unsigned long long)min_ms, (unsigned long long)max_ms);
		return 1;
	}

	return 0;
}

int main(void)
{
	pthread_t server;
	int ret;

	ret = test_listen();
	if (ret)
		return 77;

	if (pthread_create(&server, NULL, test_server, NULL)) {
		close(test_listen_fd);
		unlink(ESDM_RPC_UNPRIV_SOCKET);
		return 1;
	}

	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret) {
		printf("Cannot initialize the RPC client: %d\n", ret);
		ret = 1;
		goto out;
	}

	/* Served at once */
	ret = test_call(0, 0, 900);
	/* Asked again at once */
	if (!ret)
		ret = test_call(1, 0, 900);
	/* And then after the poll interval of one second, not in a spin */
	if (!ret)
		ret = test_call(3, 2000, 4000);

	esdm_rpcc_fini_unpriv_service();

out:
	atomic_store(&test_stop, true);
	pthread_join(server, NULL);
	close(test_listen_fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	if (!ret)
		printf("PASS\n");

	return ret;
}
