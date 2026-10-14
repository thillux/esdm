/*
 * Test: the RPC client takes no answer of a random call at its word
 *
 * The return code of a RandValResponse is 64 bits wide. A negative one beyond
 * 32 bits turned into a byte count on a 32-bit system, so the client stepped
 * over buffer bytes it never wrote. And get_seed handed back the return code
 * of the server even when it named more bytes than came with the answer.
 *
 * get_seed with a buffer larger than an answer can carry got the server's
 * refusal with the size it can serve, and returned that as an errno.
 *
 * A stand-in server in this process gives those answers on the unprivileged
 * socket the client connects to.
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"

#define TEST_LEN 32
#define TEST_FILL 0x5a
#define TEST_MAX_CONNS 16

enum test_answer {
	/* A negative return code that is 1 when cut to 32 bits */
	test_answer_wrapping_ret,
	/* A seed claiming more bytes than the answer carries */
	test_answer_seed_overclaim,
	/* A seed, unless the request is larger than the server serves */
	test_answer_seed_limited,
};

/* The largest get_seed request the ESDM server serves */
#define TEST_SEED_MAX (ESDM_RPC_MAX_DATA / sizeof(uint64_t) * sizeof(uint64_t))

static _Atomic enum test_answer test_answer;
static atomic_bool test_stop;

static int test_listen_fd = -1;

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

/* The len field (1) of a request, 0 if it has none */
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

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg[msglen++] = 0x08;
	switch (atomic_load(&test_answer)) {
	case test_answer_wrapping_ret:
		msglen += test_put_varint(msg + msglen,
					  (uint64_t)-(int64_t)0xffffffffLL);
		break;
	case test_answer_seed_overclaim:
		msglen += test_put_varint(msg + msglen, 2 * TEST_LEN);
		msg[msglen++] = 0x12;
		msglen += test_put_varint(msg + msglen, TEST_LEN);
		memset(msg + msglen, TEST_FILL, TEST_LEN);
		msglen += TEST_LEN;
		break;
	case test_answer_seed_limited:
		/* As esdm_rpc_get_seed() refuses a request it cannot serve */
		if (len > TEST_SEED_MAX) {
			int64_t max = -(int64_t)TEST_SEED_MAX;

			msglen += test_put_varint(msg + msglen, (uint64_t)max);
			break;
		}
		msglen += test_put_varint(msg + msglen, TEST_LEN);
		msg[msglen++] = 0x12;
		msglen += test_put_varint(msg + msglen, TEST_LEN);
		memset(msg + msglen, TEST_FILL, TEST_LEN);
		msglen += TEST_LEN;
		break;
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

static int test_expect(const char *what, ssize_t rc, ssize_t expected)
{
	printf("%s: returned %zd\n", what, rc);
	if (rc == expected)
		return 0;

	printf("FAIL: expected %zd\n", expected);
	return 1;
}

static int test_run(void)
{
	static uint8_t large[TEST_SEED_MAX + 4096];
	uint8_t buf[TEST_LEN];
	int ret = 0;

	atomic_store(&test_answer, test_answer_wrapping_ret);
	ret |= test_expect("get_random_bytes, return code beyond 32 bits",
			   esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
			   -EPROTO);
	ret |= test_expect("get_random_bytes_pr, return code beyond 32 bits",
			   esdm_rpcc_get_random_bytes_pr(buf, sizeof(buf)),
			   -EPROTO);
	ret |= test_expect("get_seed, return code beyond 32 bits",
			   esdm_rpcc_get_seed(buf, sizeof(buf),
					      ESDM_GET_SEED_NONBLOCK),
			   -EPROTO);

	atomic_store(&test_answer, test_answer_seed_overclaim);
	ret |= test_expect("get_seed, more bytes claimed than sent",
			   esdm_rpcc_get_seed(buf, sizeof(buf),
					      ESDM_GET_SEED_NONBLOCK),
			   -EPROTO);

	atomic_store(&test_answer, test_answer_seed_limited);
	ret |= test_expect("get_seed, buffer larger than an answer",
			   esdm_rpcc_get_seed(large, sizeof(large),
					      ESDM_GET_SEED_NONBLOCK),
			   TEST_LEN);

	return ret;
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

	ret = test_run();

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
