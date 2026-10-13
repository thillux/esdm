/*
 * Test: a privileged call interrupted after its request went out is not sent
 * again
 *
 * The server may apply such a request all the same - RNDADDENTROPY credits its
 * entropy whether or not the client still waits for the answer. The call must
 * therefore not return -EINTR, which esdm_invoke() and other callers take as
 * an invitation to send it again, but -EINPROGRESS.
 *
 * A stand-in server in this process listens on the privileged socket, counts
 * the requests and answers each after a delay. The interrupt function fires
 * once, as soon as the server has the request.
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

#define TEST_MAX_CONNS 8

/* The answer comes this late - long after the interruption */
#define TEST_ANSWER_DELAY_MS 1000

static atomic_uint test_requests;
static atomic_bool test_interrupt_fired;
static atomic_bool test_stop;

static int test_listen_fd = -1;

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/* Once, as soon as the server has the request */
static int test_interrupt(void *data)
{
	(void)data;

	if (!atomic_load(&test_requests))
		return 0;

	return !atomic_exchange(&test_interrupt_fired, true);
}

/* Answer one request on @fd with ret 0; false when the connection is gone */
static bool test_serve(int fd)
{
	struct esdm_rpc_proto_cs_header cs;
	struct esdm_rpc_proto_sc_header sc;
	uint8_t req[512];
	ssize_t rc;

	rc = recv(fd, req, sizeof(req), 0);
	if (rc < (ssize_t)sizeof(cs))
		return false;
	memcpy(&cs, req, sizeof(cs));

	atomic_fetch_add(&test_requests, 1);

	test_sleep_ms(TEST_ANSWER_DELAY_MS);

	/* An empty RetResponse is one with ret 0 */
	sc.status_code = PROTOBUF_C_RPC_STATUS_CODE_SUCCESS;
	sc.method_index = cs.method_index;
	sc.message_length = 0;
	sc.request_id = cs.request_id;

	return send(fd, &sc, sizeof(sc), MSG_NOSIGNAL) == (ssize_t)sizeof(sc);
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

/* Listen on the privileged socket - unless an ESDM already does */
static int test_listen(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_PRIV_SOCKET);

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

static int test_add_entropy(void)
{
	static const uint8_t data[32] = { 0 };
	unsigned int requests;
	int ret;

	printf("RNDADDENTROPY interrupted once the server has it\n");

	esdm_invoke(esdm_rpcc_rnd_add_entropy(data, sizeof(data), 8));

	/* A request sent again would turn up by now */
	test_sleep_ms(TEST_ANSWER_DELAY_MS);
	requests = atomic_load(&test_requests);

	printf("  returned %d after %u request(s)\n", ret, requests);

	if (!atomic_load(&test_interrupt_fired)) {
		printf("FAIL: the call was not interrupted\n");
		return 1;
	}
	if (requests != 1) {
		printf("FAIL: the request was sent %u times\n", requests);
		return 1;
	}
	if (ret != -EINPROGRESS) {
		printf("FAIL: expected -EINPROGRESS\n");
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
		unlink(ESDM_RPC_PRIV_SOCKET);
		return 1;
	}

	ret = esdm_rpcc_init_priv_service(test_interrupt);
	if (ret) {
		printf("Cannot initialize the RPC client: %d\n", ret);
		ret = 1;
		goto out;
	}

	ret = test_add_entropy();

	esdm_rpcc_fini_priv_service();

out:
	atomic_store(&test_stop, true);
	pthread_join(server, NULL);
	close(test_listen_fd);
	unlink(ESDM_RPC_PRIV_SOCKET);

	if (!ret)
		printf("PASS\n");

	return ret;
}
