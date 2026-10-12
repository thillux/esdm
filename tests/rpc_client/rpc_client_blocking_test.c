/*
 * Test: a call waiting for the ESDM to be seeded does not hold up other calls
 *
 * Calls such as esdm_rpcc_get_random_bytes_full() are answered -EAGAIN until
 * the ESDM is seeded, and ask again every second until then. Meanwhile other
 * threads of the process must still be served right away, a fork must not
 * wait for the seeding, the timeout of esdm_rpcc_get_random_bytes_full_timeout
 * must hold - also with an int_data given -, a child forked during such a
 * timed call must keep the registered interrupt function, and a teardown must
 * cope with a getter waiting for a busy connection.
 *
 * The client is limited to one connection, so that every call competes for
 * it. A stand-in server in this process answers on the unprivileged socket the
 * client connects to: -EAGAIN to the seeded calls as long as the test says the
 * ESDM is not seeded, the bytes asked for otherwise.
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

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"

#define TEST_LEN 32
#define TEST_FILL 0x5a
#define TEST_MAX_CONNS 64

/*
 * Method indices of the unprivileged service - the order of service
 * UnprivAccess in unpriv_access.proto.
 */
#define TEST_METHOD_GET_RANDOM_BYTES_FULL 3
#define TEST_METHOD_GET_RANDOM_BYTES 5

/* Whether the stand-in ESDM is seeded */
static atomic_bool test_seeded;
/* Milliseconds the stand-in takes to answer get_random_bytes */
static atomic_uint test_delay_ms;
static atomic_bool test_stop;

static int test_listen_fd = -1;

/* Handed to the interrupt function as int_data, counts its invocations */
struct test_int_ctx {
	atomic_uint calls;
};

static int test_interrupt(void *data)
{
	struct test_int_ctx *ctx = data;

	if (ctx)
		atomic_fetch_add(&ctx->calls, 1);

	return 0;
}

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
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

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg[msglen++] = 0x08;
	if (cs.method_index == TEST_METHOD_GET_RANDOM_BYTES_FULL &&
	    !atomic_load(&test_seeded)) {
		msglen += test_put_varint(msg + msglen,
					  (uint64_t)(int64_t)-EAGAIN);
	} else if (cs.method_index == TEST_METHOD_GET_RANDOM_BYTES_FULL ||
		   cs.method_index == TEST_METHOD_GET_RANDOM_BYTES) {
		if (cs.method_index == TEST_METHOD_GET_RANDOM_BYTES &&
		    atomic_load(&test_delay_ms))
			test_sleep_ms(atomic_load(&test_delay_ms));

		msglen += test_put_varint(msg + msglen, len);
		msg[msglen++] = 0x12;
		msglen += test_put_varint(msg + msglen, len);
		memset(msg + msglen, TEST_FILL, len);
		msglen += len;
	} else {
		msglen += test_put_varint(msg + msglen,
					  (uint64_t)(int64_t)-EOPNOTSUPP);
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

/* One client call, run in a thread of its own so that it can be timed out */
enum test_call_kind {
	test_call_bytes,
	test_call_full,
	test_call_full_timeout,
	test_call_full_timeout_int,
	test_call_fork,
};

struct test_call {
	enum test_call_kind kind;
	unsigned int timeout_ms;
	struct test_int_ctx ctx;
	pthread_t thread;
	atomic_bool done;
	ssize_t ret;
	uint64_t took_ms;
};

/*
 * The child of test_call_fork: a call with an int_data of its own has to reach
 * the interrupt function registered by the parent.
 */
static int test_child(void)
{
	struct test_int_ctx ctx;
	uint8_t buf[TEST_LEN];
	ssize_t ret;

	atomic_store(&ctx.calls, 0);
	ret = esdm_rpcc_get_random_bytes_int(buf, sizeof(buf), &ctx);
	if (ret != TEST_LEN) {
		printf("  child: call returned %zd\n", ret);
		return 1;
	}
	if (!atomic_load(&ctx.calls)) {
		printf("  child: the registered interrupt function was lost\n");
		return 2;
	}

	return 0;
}

static void *test_call_thread(void *arg)
{
	struct test_call *call = arg;
	struct timespec ts = { .tv_sec = call->timeout_ms / 1000,
			       .tv_nsec = (long)(call->timeout_ms % 1000) *
					  1000000 };
	uint8_t buf[TEST_LEN];
	uint64_t start = test_now_ms();
	pid_t pid;

	switch (call->kind) {
	case test_call_bytes:
		call->ret = esdm_rpcc_get_random_bytes(buf, sizeof(buf));
		break;
	case test_call_full:
		call->ret = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
		break;
	case test_call_full_timeout:
		call->ret = esdm_rpcc_get_random_bytes_full_timeout(
			buf, sizeof(buf), &ts);
		break;
	case test_call_full_timeout_int:
		call->ret = esdm_rpcc_get_random_bytes_full_timeout_int(
			buf, sizeof(buf), &ts, &call->ctx);
		break;
	case test_call_fork:
		/* Or the child prints what is buffered once more */
		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int child_ret = test_child();

			/* _exit() does not flush the child's output */
			fflush(stdout);
			_exit(child_ret);
		}
		/* The time it took to fork, not the one the child takes */
		call->took_ms = test_now_ms() - start;
		call->ret = pid;
		atomic_store(&call->done, true);
		return NULL;
	}

	call->took_ms = test_now_ms() - start;
	atomic_store(&call->done, true);

	return NULL;
}

static int test_call_start(struct test_call *call, enum test_call_kind kind,
			   unsigned int timeout_ms)
{
	memset(call, 0, sizeof(*call));
	call->kind = kind;
	call->timeout_ms = timeout_ms;
	call->ret = -ENODATA;

	if (pthread_create(&call->thread, NULL, test_call_thread, call)) {
		printf("FAIL: cannot start a thread\n");
		return 1;
	}

	return 0;
}

/* Wait at most @max_ms for the call to return; true if it did */
static bool test_call_wait(struct test_call *call, unsigned int max_ms)
{
	uint64_t end = test_now_ms() + max_ms;

	while (!atomic_load(&call->done) && test_now_ms() < end)
		test_sleep_ms(10);

	return atomic_load(&call->done);
}

/*
 * Collect a call that may be stuck because of the very defect under test:
 * declare the ESDM seeded, which ends every wait for it.
 */
static void test_call_join(struct test_call *call)
{
	if (!atomic_load(&call->done))
		atomic_store(&test_seeded, true);
	pthread_join(call->thread, NULL);
}

/* Wait for the child forked by @call; true if it exited with 0 */
static bool test_child_wait(struct test_call *call, unsigned int max_ms)
{
	uint64_t end = test_now_ms() + max_ms;
	pid_t pid = (pid_t)call->ret;
	int status;

	if (pid <= 0) {
		printf("FAIL: fork failed: %zd\n", call->ret);
		return false;
	}

	while (test_now_ms() < end) {
		if (waitpid(pid, &status, WNOHANG) == pid) {
			if (WIFEXITED(status) && !WEXITSTATUS(status))
				return true;
			printf("FAIL: child ended with status %d\n", status);
			return false;
		}
		test_sleep_ms(10);
	}

	printf("FAIL: child did not finish in %u ms\n", max_ms);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);

	return false;
}

/*
 * A thread waits for the seeding in esdm_rpcc_get_random_bytes_full(). Another
 * thread's call and a fork are served meanwhile, on the same connection.
 */
static int test_not_held_while_unseeded(void)
{
	struct test_call full, bytes, forker;
	int ret = 0;

	printf("A call waiting for the seeding does not hold the connection\n");

	atomic_store(&test_seeded, false);
	if (test_call_start(&full, test_call_full, 0))
		return 1;

	/* It asked, got -EAGAIN and is waiting now */
	test_sleep_ms(300);

	if (test_call_start(&bytes, test_call_bytes, 0)) {
		ret = 1;
		goto out_full;
	}
	if (!test_call_wait(&bytes, 2500)) {
		printf("FAIL: another call waits for the seeding as well\n");
		ret = 1;
	} else if (bytes.ret != TEST_LEN) {
		printf("FAIL: another call returned %zd\n", bytes.ret);
		ret = 1;
	} else {
		printf("  another call served after %llu ms\n",
		       (unsigned long long)bytes.took_ms);
	}
	test_call_join(&bytes);

	if (ret)
		goto out_full;

	if (test_call_start(&forker, test_call_fork, 0)) {
		ret = 1;
		goto out_full;
	}
	if (!test_call_wait(&forker, 2500)) {
		printf("FAIL: the fork waits for the seeding\n");
		ret = 1;
		test_call_join(&forker);
		test_child_wait(&forker, 5000);
		goto out_full;
	}
	test_call_join(&forker);
	printf("  fork returned after %llu ms\n",
	       (unsigned long long)forker.took_ms);
	if (!test_child_wait(&forker, 5000))
		ret = 1;

out_full:
	/* Once seeded, the waiting call completes with the next attempt */
	atomic_store(&test_seeded, true);
	if (!test_call_wait(&full, 2500)) {
		printf("FAIL: the call does not complete once seeded\n");
		ret = 1;
	} else if (full.ret != TEST_LEN) {
		printf("FAIL: the call returned %zd once seeded\n", full.ret);
		ret = 1;
	}
	pthread_join(full.thread, NULL);

	return ret;
}

/*
 * esdm_rpcc_get_random_bytes_full_timeout() ends at its timeout, and a child
 * forked meanwhile keeps the interrupt function the application registered.
 */
static int test_timeout_and_fork(void)
{
	struct test_call timed, forker;
	int ret = 0;

	printf("A timed call ends in time and leaves the interrupt function alone\n");

	atomic_store(&test_seeded, false);
	if (test_call_start(&timed, test_call_full_timeout, 1500))
		return 1;

	test_sleep_ms(300);

	if (test_call_start(&forker, test_call_fork, 0)) {
		ret = 1;
		goto out_timed;
	}
	if (!test_call_wait(&forker, 2500)) {
		printf("FAIL: the fork waits for the seeding\n");
		ret = 1;
		test_call_join(&forker);
		test_child_wait(&forker, 5000);
		goto out_timed;
	}
	pthread_join(forker.thread, NULL);
	if (!test_child_wait(&forker, 5000))
		ret = 1;

out_timed:
	if (!test_call_wait(&timed, 3000)) {
		printf("FAIL: the timed call did not end at its timeout\n");
		ret = 1;
	} else if (timed.ret != -ETIMEDOUT) {
		printf("FAIL: the timed call returned %zd\n", timed.ret);
		ret = 1;
	} else if (timed.took_ms < 1400 || timed.took_ms > 2500) {
		printf("FAIL: the timed call took %llu ms for 1500 ms\n",
		       (unsigned long long)timed.took_ms);
		ret = 1;
	} else {
		printf("  the timed call ended after %llu ms\n",
		       (unsigned long long)timed.took_ms);
	}
	test_call_join(&timed);

	return ret;
}

/*
 * esdm_rpcc_get_random_bytes_full_timeout_int() honours both its timeout and
 * the int_data handed to it.
 */
static int test_timeout_with_int_data(void)
{
	struct test_call timed;
	int ret = 0;

	printf("A timed call with int_data ends in time and uses the int_data\n");

	atomic_store(&test_seeded, false);
	if (test_call_start(&timed, test_call_full_timeout_int, 700))
		return 1;

	if (!test_call_wait(&timed, 3000)) {
		printf("FAIL: the timed call did not end at its timeout\n");
		ret = 1;
	} else if (timed.ret != -ETIMEDOUT) {
		printf("FAIL: the timed call returned %zd\n", timed.ret);
		ret = 1;
	} else if (timed.took_ms < 600 || timed.took_ms > 1500) {
		printf("FAIL: the timed call took %llu ms for 700 ms\n",
		       (unsigned long long)timed.took_ms);
		ret = 1;
	} else if (!atomic_load(&timed.ctx.calls)) {
		printf("FAIL: the interrupt function never saw the int_data\n");
		ret = 1;
	} else {
		printf("  the timed call ended after %llu ms\n",
		       (unsigned long long)timed.took_ms);
	}
	test_call_join(&timed);

	return ret;
}

/*
 * The connections are released while one call is in progress on the only
 * connection and another one waits for it. The waiting call fails, the one in
 * progress completes, and the release neither hangs nor frees the connection
 * under the waiting call - which a sanitizer build would see.
 */
static int test_fini_with_waiter(void)
{
	struct test_call busy, waiting;
	uint64_t start, took;
	int ret = 0;

	printf("Releasing the connections while a call waits for one\n");

	atomic_store(&test_seeded, true);
	atomic_store(&test_delay_ms, 600);

	if (test_call_start(&busy, test_call_bytes, 0))
		return 1;
	test_sleep_ms(100);
	if (test_call_start(&waiting, test_call_bytes, 0)) {
		pthread_join(busy.thread, NULL);
		return 1;
	}
	test_sleep_ms(100);

	start = test_now_ms();
	esdm_rpcc_fini_unpriv_service();
	took = test_now_ms() - start;
	printf("  released after %llu ms\n", (unsigned long long)took);

	pthread_join(busy.thread, NULL);
	pthread_join(waiting.thread, NULL);
	atomic_store(&test_delay_ms, 0);

	if (busy.ret != TEST_LEN) {
		printf("FAIL: the call in progress returned %zd\n", busy.ret);
		ret = 1;
	}
	/*
	 * -EFAULT if the waiting call was that late that it found the
	 * connections released already.
	 */
	if (waiting.ret != -ESHUTDOWN && waiting.ret != -EFAULT) {
		printf("FAIL: the waiting call returned %zd\n", waiting.ret);
		ret = 1;
	}
	if (took > 2500) {
		printf("FAIL: the release took %llu ms\n",
		       (unsigned long long)took);
		ret = 1;
	}

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

	/* One connection that all calls have to share */
	esdm_rpcc_set_max_online_nodes(1);

	ret = esdm_rpcc_init_unpriv_service(test_interrupt);
	if (ret) {
		printf("Cannot initialize the RPC client: %d\n", ret);
		ret = 1;
		goto out;
	}

	ret = test_not_held_while_unseeded();
	ret |= test_timeout_and_fork();
	ret |= test_timeout_with_int_data();
	/* Releases the connections */
	ret |= test_fini_with_waiter();

out:
	atomic_store(&test_stop, true);
	pthread_join(server, NULL);
	close(test_listen_fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	if (!ret)
		printf("PASS\n");

	return ret;
}
