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
 * Method index of RpcStatus - the order of service UnprivAccess in
 * unpriv_access.proto. The connections that do not read ask for the status
 * report, cut to TEST_ANSWER_LEN, rather than for random bytes: they ask for
 * some 90 MiB in all, and a build with the reseeding caps of sp80090c, fips140
 * or ais2031_drg4 reseeds the DRNG every few KiB, each time waiting for the
 * Jitter RNG. The server then takes minutes for the first answers alone, and
 * its idle timeout reaps the connections it answered first long before it is
 * done - which the test cannot tell from being dropped for a full send buffer.
 * The report is the same size every time and costs no DRNG output.
 */
#define TEST_METHOD_STATUS 0
/*
 * How long the ordinary client may take, and the server to drop all of the
 * connections once their send buffers are full. A server that waits for each
 * of them only a few milliseconds before it drops it takes 3.3 s and more on
 * an idle machine, one that drops them at once a few hundred ms. On a loaded
 * machine, or with a server built with the sanitizers and for coverage, it
 * takes longer for everything, the dropping included - 2.5 s and more. The
 * bound is a number of the rounds the server takes over the connections, as
 * measured on the answers before, but no less than TEST_MAX_MS.
 */
#define TEST_MAX_MS 2500
#define TEST_MAX_ROUNDS 100
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

	test_wait_for_listener(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET,
			       TEST_WAIT_TIMEOUT_MS);

	return 0;
}

static void test_server_stop(void)
{
	if (test_server_pid > 0) {
		kill(test_server_pid, SIGTERM);
		test_env_reap_daemon_or_fail(test_server_pid, "esdm-server");
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

/* The most requests sent at once on a connection, see test_send_requests() */
#define TEST_MAX_REQUESTS 1024

/* Send @num requests for status reports of @len bytes, as far as they go */
static void test_send_requests(int fd, unsigned int num, uint32_t len)
{
	static struct mmsghdr msgs[TEST_MAX_REQUESTS];
	struct iovec iov;
	uint8_t req[sizeof(struct esdm_rpc_proto_cs_header) + 8];
	struct esdm_rpc_proto_cs_header cs = {
		.method_index = TEST_METHOD_STATUS,
		.request_id = 0,
	};
	uint8_t *msg = req + sizeof(cs);
	size_t msglen = 0;
	uint32_t val = len;
	unsigned int i;

	/* StatusRequest: maxlen (field 1, varint) */
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

	/*
	 * All of them in one call. Sent one call per request, the requests of
	 * the hundreds of connections took seconds where the test is slow -
	 * built with the sanitizers and for coverage, or with little of the
	 * CPU -, while the server stopped below holds the connections it is
	 * done with idle, which it reaps after its idle timeout.
	 */
	iov.iov_base = req;
	iov.iov_len = sizeof(cs) + msglen;
	if (num > TEST_MAX_REQUESTS)
		num = TEST_MAX_REQUESTS;
	memset(msgs, 0, num * sizeof(msgs[0]));
	for (i = 0; i < num; i++) {
		msgs[i].msg_hdr.msg_iov = &iov;
		msgs[i].msg_hdr.msg_iovlen = 1;
	}
	for (i = 0; i < num;) {
		int n = sendmmsg(fd, msgs + i, num - i,
				 MSG_NOSIGNAL | MSG_DONTWAIT);

		if (n <= 0)
			break;
		i += (unsigned int)n;
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
 * tell how long it took from the first of them to the last, and how many of
 * them the server had read all requests of before it closed them: those were
 * not dropped for a full send buffer but reaped as idle, which also closes
 * them all at once.
 */
static unsigned int test_wait_closed(const int *fds, unsigned int num,
				     uint64_t *span_ms, unsigned int *drained)
{
	static bool seen_closed[TEST_SLOW_CONNS];
	static bool all_read[TEST_SLOW_CONNS];
	uint64_t end = test_now_ms() + TEST_DROP_MS, first = 0, now;
	unsigned int i, closed;

	*drained = 0;

	do {
		for (i = 0, closed = 0; i < num; i++) {
			if (seen_closed[i]) {
				closed++;
			} else if (test_closed_by_server(fds[i])) {
				seen_closed[i] = true;
				if (all_read[i])
					(*drained)++;
				closed++;
			} else {
				all_read[i] = test_requests_read(fds[i]);
			}
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
	unsigned int first, rest, i, opened = 0, closed = 0, drained = 0;
	size_t sndbuf;
	uint64_t span = 0, start, round_ms, phase_ms, max_ms = TEST_MAX_MS;
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

	/* Seeded, so that the ordinary calls below get their random bytes */
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
	 *
	 * Asked for while the server is stopped, as the rest below: it finds
	 * the requests of all connections at once, and the time measured below
	 * is the server's alone.
	 */
	sndbuf = test_sndbuf();
	first = (unsigned int)(sndbuf / TEST_ANSWER_LEN / 4);
	kill(test_server_pid, SIGSTOP);
	for (i = 0; i < opened; i++)
		test_send_requests(fds[i], first, TEST_ANSWER_LEN);
	start = test_now_ms();
	kill(test_server_pid, SIGCONT);
	if (!test_wait_requests_read(fds, opened)) {
		printf("FAIL: the server does not answer the requests\n");
		ret = 1;
		goto out_close;
	}

	/*
	 * The bound below, on this machine as it runs the server now: as many
	 * of the rounds the server just took for these requests as
	 * TEST_MAX_ROUNDS, at least TEST_MAX_MS.
	 */
	round_ms = (test_now_ms() - start) / (first ? first : 1);
	max_ms = TEST_MAX_ROUNDS * round_ms;
	if (max_ms < TEST_MAX_MS)
		max_ms = TEST_MAX_MS;
	printf("A round over the connections took %llu ms, bound %llu ms\n",
	       (unsigned long long)round_ms, (unsigned long long)max_ms);

	/*
	 * A connection closed now was dropped for a send buffer the first
	 * answers filled - or reaped as idle, which takes the server serving
	 * them for longer than its idle timeout: it does not serve its
	 * connections strictly in turn, and those it is done with first wait
	 * for the others. Under such load the scenario cannot be set up.
	 */
	phase_ms = test_now_ms() - start;
	for (i = 0; i < opened; i++) {
		if (!test_closed_by_server(fds[i]))
			continue;

		if (phase_ms * 1000 >= ESDM_RPC_IDLE_TIMEOUT_USEC) {
			printf("The first answers took %llu ms, longer than the idle timeout of the server, which reaped connections done with them - skipping\n",
			       (unsigned long long)phase_ms);
			ret = 77;
		} else {
			printf("FAIL: the first answers filled a send buffer\n");
			ret = 1;
		}
		goto out_close;
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

	closed = test_wait_closed(fds, opened, &span, &drained);
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
	} else if (atomic_load(&test_max_took) > max_ms) {
		printf("FAIL: an ordinary call took longer than %llu ms\n",
		       (unsigned long long)max_ms);
		ret = 1;
	}

	printf("The server dropped %u of the %u connections within %llu ms\n",
	       closed, opened, (unsigned long long)span);
	if (closed != opened) {
		printf("FAIL: connections that do not read are kept\n");
		ret = 1;
	} else if (drained) {
		printf("FAIL: %u connections were reaped as idle\n", drained);
		ret = 1;
	} else if (span > max_ms) {
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
