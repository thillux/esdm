/*
 * Test: clients that do not read their answers do not stall the RPC server
 *
 * A worker thread of the server serves all of its connections in turn. When
 * the answers a client does not read fill the send buffer of its connection,
 * the server must drop the connection right away rather than wait for the
 * client: every moment it waits, it serves none of the other connections of
 * that worker, and a few hundred such connections - easily opened by any
 * unprivileged user - would push everybody else past the client's timeouts.
 *
 * Many connections send requests and never read the answers, while an ordinary
 * client asks for random bytes again and again. It has to be served promptly
 * every time, and the server has to drop the connections that do not read.
 *
 * The server serves its connections in turn, one request each per round. The
 * connections are prepared so that their send buffers fill up in the same
 * round: a server that drops them right away does so within that round, one
 * that waits for each of them only a few milliseconds first takes seconds.
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
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <linux/sockios.h>

#include "../test_env.h"
#include "../test_namespace.h"
#include "../test_wait.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"

/*
 * Connections that do not read their answers. All of them are served by the
 * one worker thread of a server started with --small_memory.
 */
#define TEST_SLOW_CONNS 600
/*
 * Size of the answers. Small, so that what the server has to do per round stays
 * small next to waiting for the clients, and so that each answer takes the same
 * space in the send buffer: a large one is partly held in pages, and how many
 * of those the kernel takes for it depends on the fragmentation of its memory.
 */
#define TEST_ANSWER_LEN 1024
/*
 * Method index of RpcGetRandomBytes - the order of service UnprivAccess in
 * unpriv_access.proto.
 */
#define TEST_METHOD_GET_RANDOM_BYTES 5
/*
 * How long the ordinary client may take, and the server to drop all of the
 * connections once their send buffers are full. A server that waits for each
 * of them only a few milliseconds before it drops it takes 3.3 s and more on
 * an idle machine, one that drops them at once a few hundred ms - but up to
 * 2 s on a loaded one, which is what the bound leaves room for.
 */
#define TEST_MAX_MS 2500
/* How long the server may take to drop the connections that do not read */
#define TEST_DROP_MS 60000

static pid_t test_server_pid;

/*
 * Start the server as env_init() does, but with a single worker thread for the
 * unprivileged interface, so that all connections share it.
 */
static int test_server_start(void)
{
	const char *server = getenv("ESDM_SERVER");
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	pid_t pid;
	int ret;

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return -ret;
	}

	ret = test_env_check_file(server);
	if (ret)
		return ret;

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	pid = fork();
	if (pid < 0)
		return errno;
	if (pid == 0) {
		char buf[FILENAME_MAX];
		char *server_argv[] = { buf, "--small_memory", NULL };

		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, server_argv, server_envp);
		_exit(EFAULT);
	}
	test_server_pid = pid;

	test_wait_for_type(ESDM_RPC_UNPRIV_SOCKET, S_IFSOCK,
			   TEST_WAIT_TIMEOUT_MS);

	return 0;
}

static void test_server_stop(void)
{
	if (test_server_pid > 0) {
		kill(test_server_pid, SIGTERM);
		waitpid(test_server_pid, NULL, 0);
	}
	test_server_pid = 0;
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

/* The default send buffer, which the server's connections have as well */
static size_t test_sndbuf(void)
{
	unsigned long val = 0;
	FILE *f = fopen("/proc/sys/net/core/wmem_default", "r");

	if (f) {
		if (fscanf(f, "%lu", &val) != 1)
			val = 0;
		fclose(f);
	}

	return val ? (size_t)val : 212992;
}

static int test_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	uint64_t end = test_now_ms() + 5000;
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/* A full listen backlog is reported as EAGAIN */
	while (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		if (errsv != EAGAIN || test_now_ms() > end) {
			close(fd);
			return -errsv;
		}
		test_sleep_ms(1);
	}

	return fd;
}

/* Send @num requests for @len bytes each, as far as they go */
static void test_send_requests(int fd, unsigned int num, uint32_t len)
{
	uint8_t req[sizeof(struct esdm_rpc_proto_cs_header) + 8];
	struct esdm_rpc_proto_cs_header cs = {
		.method_index = TEST_METHOD_GET_RANDOM_BYTES,
		.request_id = 0,
	};
	uint8_t *msg = req + sizeof(cs);
	size_t msglen = 0;
	uint32_t val = len;
	unsigned int i;

	/* GetRandomBytesRequest: len (field 1, varint) */
	msg[msglen++] = 0x08;
	do {
		msg[msglen] = (uint8_t)(val & 0x7f);
		val >>= 7;
		if (val)
			msg[msglen] |= 0x80;
		msglen++;
	} while (val);

	/* The server takes the header in little endian */
	cs.message_length = (uint32_t)msglen;
	memcpy(req, &cs, sizeof(cs));

	for (i = 0; i < num; i++) {
		if (send(fd, req, sizeof(cs) + msglen,
			 MSG_NOSIGNAL | MSG_DONTWAIT) < 0)
			break;
	}
}

static atomic_bool test_stop;
static atomic_uint test_calls;
static _Atomic uint64_t test_max_took;
static atomic_int test_failed;

/*
 * Ask for random bytes again and again, as an ordinary client, and note the
 * slowest call: the one that ran into the server waiting for the connections
 * that do not read, if it does.
 */
static void *test_caller(void *unused)
{
	uint8_t buf[32];

	(void)unused;

	while (!atomic_load(&test_stop)) {
		uint64_t start = test_now_ms(), took;
		ssize_t rc = esdm_rpcc_get_random_bytes(buf, sizeof(buf));

		took = test_now_ms() - start;
		if (rc != (ssize_t)sizeof(buf)) {
			atomic_store(&test_failed, (int)rc);
			break;
		}
		atomic_fetch_add(&test_calls, 1);
		if (took > atomic_load(&test_max_took))
			atomic_store(&test_max_took, took);
	}

	return NULL;
}

/*
 * Has the server read all requests sent on @fd? It answers each one as it
 * reads it, so the answers to them are queued then.
 */
static bool test_requests_read(int fd)
{
	int outq = 0;

	return !ioctl(fd, SIOCOUTQ, &outq) && !outq;
}

/* Wait until the server read all requests sent on @fds */
static bool test_wait_requests_read(const int *fds, unsigned int num)
{
	uint64_t end = test_now_ms() + TEST_DROP_MS;
	unsigned int i = 0;

	while (i < num) {
		if (test_requests_read(fds[i])) {
			i++;
			continue;
		}
		if (test_now_ms() > end)
			return false;
		test_sleep_ms(10);
	}

	return true;
}

/*
 * Did the server close @fd? Tells without reading the answers, which would
 * make room in the send buffer of the server.
 */
static bool test_closed_by_server(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLRDHUP };

	return poll(&pfd, 1, 0) > 0 && (pfd.revents & (POLLHUP | POLLRDHUP));
}

/*
 * Wait until the server closed all of @fds; the number of those it did. Also
 * tell how long it took from the first of them to the last.
 */
static unsigned int test_wait_closed(const int *fds, unsigned int num,
				     uint64_t *span_ms)
{
	uint64_t end = test_now_ms() + TEST_DROP_MS, first = 0, now;
	unsigned int i, closed;

	do {
		for (i = 0, closed = 0; i < num; i++) {
			if (test_closed_by_server(fds[i]))
				closed++;
		}

		now = test_now_ms();
		if (closed && !first)
			first = now;
		if (closed == num)
			break;

		test_sleep_ms(10);
	} while (now < end);

	*span_ms = first ? now - first : 0;

	return closed;
}

int main(void)
{
	static int fds[TEST_SLOW_CONNS];
	struct rlimit rl;
	uint8_t buf[32];
	unsigned int first, rest, i, opened = 0, closed = 0;
	size_t sndbuf;
	uint64_t span = 0;
	pthread_t caller;
	bool caller_running = false;
	ssize_t rc;
	int ret;

	ret = test_server_start();
	if (ret)
		return ret;

	/* The slow connections, the client's and some to spare */
	if (!getrlimit(RLIMIT_NOFILE, &rl) &&
	    rl.rlim_cur < TEST_SLOW_CONNS + 256) {
		rl.rlim_cur = TEST_SLOW_CONNS + 256;
		if (rl.rlim_max != RLIM_INFINITY && rl.rlim_cur > rl.rlim_max)
			rl.rlim_cur = rl.rlim_max;
		setrlimit(RLIMIT_NOFILE, &rl);
	}

	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret) {
		printf("FAIL: cannot initialize the RPC client: %d\n", ret);
		ret = 1;
		goto out;
	}

	/* Seeded, so that the requests below get answers with the bytes */
	rc = esdm_rpcc_get_random_bytes_full(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("FAIL: the ESDM does not answer: %zd\n", rc);
		ret = 1;
		goto out_fini;
	}

	/*
	 * Connect all of them before any sends a request: a server busy with
	 * the requests of the first ones accepts the later ones late.
	 */
	for (i = 0; i < TEST_SLOW_CONNS; i++) {
		fds[i] = test_connect();
		if (fds[i] < 0) {
			printf("Cannot open connection %u: %s\n", i,
			       strerror(-fds[i]));
			break;
		}
		opened++;
	}
	if (opened < TEST_SLOW_CONNS / 2) {
		printf("FAIL: too few connections\n");
		ret = 1;
		goto out_close;
	}

	/*
	 * Answers that fill a part of the send buffer of each connection - a
	 * quarter of it by their payload; with what the kernel adds, about
	 * half. Once the server answered all of them, the connections are all
	 * in the same state.
	 */
	sndbuf = test_sndbuf();
	first = (unsigned int)(sndbuf / TEST_ANSWER_LEN / 4);
	for (i = 0; i < opened; i++)
		test_send_requests(fds[i], first, TEST_ANSWER_LEN);
	if (!test_wait_requests_read(fds, opened)) {
		printf("FAIL: the server does not answer the requests\n");
		ret = 1;
		goto out_close;
	}

	for (i = 0; i < opened; i++) {
		if (test_closed_by_server(fds[i])) {
			printf("FAIL: the first answers filled a send buffer\n");
			ret = 1;
			goto out_close;
		}
	}

	/*
	 * Answers that fill the rest - asked for while the server is stopped,
	 * so that it finds all requests at once and the send buffers fill up in
	 * the same round over the connections.
	 */
	rest = (unsigned int)(sndbuf / TEST_ANSWER_LEN / 2);
	kill(test_server_pid, SIGSTOP);
	for (i = 0; i < opened; i++)
		test_send_requests(fds[i], rest, TEST_ANSWER_LEN);

	/*
	 * An ordinary client meanwhile, see test_caller(). Its first request
	 * is queued before the server continues, so that it is there for
	 * whichever round the send buffers fill up in.
	 */
	if (pthread_create(&caller, NULL, test_caller, NULL)) {
		kill(test_server_pid, SIGCONT);
		printf("FAIL: cannot start a thread\n");
		ret = 1;
		goto out_close;
	}
	caller_running = true;
	test_sleep_ms(200);

	kill(test_server_pid, SIGCONT);
	printf("%u connections sent %u + %u requests each without reading\n",
	       opened, first, rest);

	closed = test_wait_closed(fds, opened, &span);
	/* And some more calls after that */
	test_sleep_ms(500);
	atomic_store(&test_stop, true);
	pthread_join(caller, NULL);
	caller_running = false;

	printf("%u ordinary calls, the slowest took %llu ms\n",
	       atomic_load(&test_calls),
	       (unsigned long long)atomic_load(&test_max_took));
	if (atomic_load(&test_failed)) {
		printf("FAIL: an ordinary call failed: %d\n",
		       atomic_load(&test_failed));
		ret = 1;
	} else if (atomic_load(&test_max_took) > TEST_MAX_MS) {
		printf("FAIL: an ordinary call took longer than %u ms\n",
		       TEST_MAX_MS);
		ret = 1;
	}

	printf("The server dropped %u of the %u connections within %llu ms\n",
	       closed, opened, (unsigned long long)span);
	if (closed != opened) {
		printf("FAIL: connections that do not read are kept\n");
		ret = 1;
	} else if (span > TEST_MAX_MS) {
		/*
		 * They all filled up in the same round, and a server that drops
		 * them right away does so within that round - one that waits
		 * for each of them first takes as many times that wait.
		 */
		printf("FAIL: the server waited for the connections\n");
		ret = 1;
	}

out_close:
	if (caller_running) {
		atomic_store(&test_stop, true);
		pthread_join(caller, NULL);
	}
	for (i = 0; i < opened; i++)
		close(fds[i]);
out_fini:
	esdm_rpcc_fini_unpriv_service();
out:
	test_server_stop();

	if (!ret)
		printf("PASS\n");

	return ret;
}
