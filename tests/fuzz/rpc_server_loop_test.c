/*
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

/*
 * The event loops of the RPC server: which one its workers wait with, and that
 * each serves the same.
 *
 * The server's accept loop and workers serve a stand-in service on sockets of
 * the test's own, through the serve hook of the fuzz harnesses - hence no
 * daemon, no ESDM and no privileges. Each case runs in a process of its own,
 * as the server cannot be started again in one that stopped it:
 *
 *   - by default: with io_uring where it is built (meson option rpc-io-uring)
 *     and the kernel lets this process set up a ring - receiving and sending
 *     through it where the kernel and liburing have the multishot receive -,
 *     with epoll otherwise,
 *   - with the receiving and sending through the ring switched off
 *     (esdm-server --no_io_uring_multishot): polling with the ring,
 *   - with the buffer rings refused - as a kernel before Linux 5.19 has it,
 *     here by a seccomp filter failing IORING_REGISTER_PBUF_RING with EINVAL:
 *     polling with the ring, with one log line for all workers,
 *   - with io_uring switched off (esdm-server --no_io_uring): with epoll,
 *   - with io_uring_setup(2) refused by a seccomp filter - with EPERM, as
 *     kernel.io_uring_disabled or the profile of a container has it, and with
 *     ENOSYS, as a kernel without io_uring has it: with epoll, falling back
 *     with one log line for all workers of both interfaces.
 *
 * Which one a worker waits with is told by its descriptors: an io_uring is an
 * anonymous inode of its own, as is an epoll instance. In every case, clients
 * on both interfaces have their requests answered - several in turn, a
 * request sent while the one before is still unanswered, which a loop has to
 * report again after it served the first, and the clients of connections that
 * others closed meanwhile. And in every case the same for what the receiving
 * through the ring has to get right:
 *
 *   - a message larger than a request can be ends its connection, unanswered,
 *   - clients closing their connections before they read their answers - the
 *     ring's send of each finding the peer gone - leave the others served,
 *   - more requests at once than the ring has buffers - its receives running
 *     out of them, ENOBUFS, and armed again - are all answered,
 *   - the connections are spread evenly over the workers of the unprivileged
 *     interface, whichever accepts them.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/filter.h>
#include <linux/seccomp.h>

#include "common.pb-c.h"
#include "common_test.h"
#include "config.h"
#include "conv_be_le.h"
#include "esdm_config.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

#ifdef ESDM_RPC_IO_URING
#include <liburing.h>
#endif

#define TEST_CLIENTS 8
#define TEST_REQUESTS 64
/* How long a client waits for an answer */
#define TEST_ANSWER_MS 5000

static char test_dir[] = "/tmp/esdm-rpc-loop-test.XXXXXX";
static char test_priv_path[sizeof(test_dir) + 16];
static char test_unpriv_path[sizeof(test_dir) + 16];
static char test_log_path[sizeof(test_dir) + 16];

/* What a case does to the server before it starts */
enum test_case {
	TEST_DEFAULT,
	TEST_POLL,
	TEST_NO_PBUF,
	TEST_SWITCHED_OFF,
	TEST_REFUSED_EPERM,
	TEST_REFUSED_ENOSYS,
};

static const char *const test_case_name[] = {
	[TEST_DEFAULT] = "default",
	[TEST_POLL] = "io_uring multishot switched off",
	[TEST_NO_PBUF] = "io_uring buffer rings refused",
	[TEST_SWITCHED_OFF] = "io_uring switched off",
	[TEST_REFUSED_EPERM] = "io_uring_setup refused with EPERM",
	[TEST_REFUSED_ENOSYS] = "io_uring_setup refused with ENOSYS",
};

/* The log lines telling how the workers wait */
#define TEST_LOG_MULTISHOT "wait with io_uring, receiving and sending"
#define TEST_LOG_POLLING "wait with io_uring, polling the connections"
#define TEST_LOG_NO_PBUF "cannot receive multishot, polling"

/* The size of the answers while test_big is set */
#define TEST_BIG_ANSWER 60000
static atomic_bool test_big;

/* A call while test_hold is set holds up its worker until it is cleared */
static atomic_bool test_hold;
static atomic_bool test_held;

/* The worker that served the last call */
static _Atomic pthread_t test_served_by;

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/****************************
 * Server
 ****************************/

/*
 * Answers every call with ret 0 - with TEST_BIG_ANSWER bytes while test_big is
 * set, after test_hold is cleared while it is set
 */
static void test_service_invoke(ProtobufCService *service,
				unsigned int method_index,
				const ProtobufCMessage *input,
				ProtobufCClosure closure, void *closure_data)
{
	static uint8_t big[TEST_BIG_ANSWER];
	RetResponse response = RET_RESPONSE__INIT;
	RandValResponse big_response = RAND_VAL_RESPONSE__INIT;
	unsigned int i;

	(void)service;
	(void)method_index;
	(void)input;

	if (atomic_load(&test_hold)) {
		atomic_store(&test_held, true);
		for (i = 0; i < 10000 && atomic_load(&test_hold); i++)
			test_sleep_ms(1);
		atomic_store(&test_held, false);
	}

	atomic_store(&test_served_by, pthread_self());

	if (atomic_load(&test_big)) {
		big_response.randval.data = big;
		big_response.randval.len = sizeof(big);
		closure((const ProtobufCMessage *)&big_response, closure_data);
		return;
	}

	closure((const ProtobufCMessage *)&response, closure_data);
}

static ProtobufCService test_priv_service = {
	.descriptor = &priv_access__descriptor,
	.invoke = test_service_invoke,
	.destroy = NULL,
};

static ProtobufCService test_unpriv_service = {
	.descriptor = &unpriv_access__descriptor,
	.invoke = test_service_invoke,
	.destroy = NULL,
};

static void *test_serve_priv(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(test_priv_path, &test_priv_service, true);
	if (ret)
		fprintf(stderr, "the privileged server did not run: %s\n",
			strerror(-ret));

	return NULL;
}

static void *test_serve_unpriv(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(test_unpriv_path, &test_unpriv_service,
				   false);
	if (ret)
		fprintf(stderr, "the unprivileged server did not run: %s\n",
			strerror(-ret));

	return NULL;
}

static bool test_wait_for_socket(const char *path)
{
	unsigned int i;
	struct stat sb;

	for (i = 0; i < 500; i++) {
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(10);
	}

	return false;
}

/*
 * Refuse io_uring_setup(2) with @err to this thread and the threads it starts.
 * The system calls of io_uring have the same numbers on every architecture,
 * so the filter does not need to look at it.
 */
static int test_refuse_io_uring(int err)
{
#ifdef __NR_io_uring_setup
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_ERRNO | ((unsigned int)err &
					      SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -errno;
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
		return -errno;

	return 0;
#else
	(void)err;
	return -EOPNOTSUPP;
#endif
}

/*
 * Fail the registration of buffer rings with EINVAL, as a kernel before Linux
 * 5.19 does, for this thread and the threads it starts. The opcode is the
 * second argument of io_uring_register(2) - its low word, with the flag of a
 * registered ring descriptor masked off.
 */
static int test_refuse_pbuf_ring(void)
{
#if defined(__NR_io_uring_register) && defined(ESDM_RPC_IO_URING)
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0,
			 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[1]) +
				 (__BYTE_ORDER == __BIG_ENDIAN ? 4 : 0)),
		BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xffff),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IORING_REGISTER_PBUF_RING,
			 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_ERRNO | (EINVAL & SECCOMP_RET_DATA)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = sizeof(filter) / sizeof(filter[0]),
		.filter = filter,
	};

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -errno;
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog))
		return -errno;

	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/****************************
 * Clients
 ****************************/

static int test_connect(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	return fd;
}

/* Send a request for the first method, of an empty message */
static bool test_send(int fd, uint32_t request_id)
{
	struct esdm_rpc_proto_cs_header header = {
		.message_length = 0,
		.method_index = 0,
		.request_id = le_bswap32(request_id),
	};

	return send(fd, &header, sizeof(header), MSG_NOSIGNAL) ==
	       (ssize_t)sizeof(header);
}

/* Receive the answer of request @request_id, a success */
static bool test_answered(int fd, uint32_t request_id)
{
	static _Thread_local uint8_t buf[TEST_BIG_ANSWER + 256];
	struct esdm_rpc_proto_sc_header header;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	ssize_t n;

	if (poll(&pfd, 1, TEST_ANSWER_MS) != 1)
		return false;

	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (n < (ssize_t)sizeof(header))
		return false;

	memcpy(&header, buf, sizeof(header));

	return le_bswap32(header.status_code) ==
		       PROTOBUF_C_RPC_STATUS_CODE_SUCCESS &&
	       le_bswap32(header.request_id) == request_id;
}

/* Clients of the interface on @path have their requests answered */
static void test_clients(const char *path)
{
	int fds[TEST_CLIENTS];
	unsigned int i, j, answered = 0, requests = 0;
	uint32_t id = 1;

	for (i = 0; i < TEST_CLIENTS; i++) {
		fds[i] = test_connect(path);
		CHECK(fds[i] >= 0, "cannot connect to %s: %s", path,
		      strerror(-fds[i]));
	}

	/* In turn, one request at a time on each connection */
	for (j = 0; j < TEST_REQUESTS; j++) {
		for (i = 0; i < TEST_CLIENTS; i++) {
			if (fds[i] < 0)
				continue;
			requests++;
			if (test_send(fds[i], id) && test_answered(fds[i], id))
				answered++;
			id++;
		}
	}
	CHECK_EQ(answered, requests);

	/*
	 * Two requests sent at once: the event of the connection reports the
	 * first, and the second is still waiting when the round served it -
	 * the loop has to report it again in the next one.
	 */
	for (i = 0; i < TEST_CLIENTS; i++) {
		if (fds[i] < 0)
			continue;
		CHECK(test_send(fds[i], id) && test_send(fds[i], id + 1),
		      "cannot send two requests");
		CHECK(test_answered(fds[i], id),
		      "first of two requests on connection %u unanswered", i);
		CHECK(test_answered(fds[i], id + 1),
		      "second of two requests on connection %u unanswered",
		      i);
		id += 2;
	}

	/* The others are served on while half of the clients leave */
	for (i = 0; i < TEST_CLIENTS; i += 2) {
		if (fds[i] >= 0)
			close(fds[i]);
		fds[i] = -1;
	}
	for (i = 1; i < TEST_CLIENTS; i += 2) {
		if (fds[i] < 0)
			continue;
		CHECK(test_send(fds[i], id) && test_answered(fds[i], id),
		      "connection %u unanswered after others closed", i);
		id++;
	}

	/* And new ones are taken */
	for (i = 0; i < TEST_CLIENTS; i += 2) {
		fds[i] = test_connect(path);
		CHECK(fds[i] >= 0, "cannot connect to %s again", path);
		if (fds[i] < 0)
			continue;
		CHECK(test_send(fds[i], id) && test_answered(fds[i], id),
		      "new connection %u unanswered", i);
		id++;
	}

	for (i = 0; i < TEST_CLIENTS; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

/* Is @fd closed by the server within TEST_ANSWER_MS, without an answer? */
static bool test_closed_unanswered(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	uint8_t buf[64];
	ssize_t n;

	if (poll(&pfd, 1, TEST_ANSWER_MS) != 1)
		return false;
	n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

	return n == 0 || (n < 0 && errno == ECONNRESET);
}

/*
 * A message larger than a request can be - ESDM_RPC_MAX_MSG_SIZE - ends its
 * connection without an answer, its header asking for a call all the same,
 * and others are served on.
 */
static void test_oversized(const char *path)
{
	static uint8_t msg[ESDM_RPC_MAX_MSG_SIZE + 4096];
	struct esdm_rpc_proto_cs_header header = {
		.message_length = 0,
		.method_index = 0,
		.request_id = le_bswap32(1),
	};
	int sndbuf = (int)sizeof(msg) * 2;
	int fd = test_connect(path);

	CHECK(fd >= 0, "cannot connect to %s", path);
	if (fd < 0)
		return;

	memcpy(msg, &header, sizeof(header));
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	CHECK(send(fd, msg, sizeof(msg), MSG_NOSIGNAL) == (ssize_t)sizeof(msg),
	      "cannot send %zu bytes: %s", sizeof(msg), strerror(errno));
	CHECK(test_closed_unanswered(fd),
	      "a message of %zu bytes did not end its connection",
	      sizeof(msg));
	close(fd);

	/* One of the size of a request is served */
	fd = test_connect(path);
	CHECK(fd >= 0, "cannot connect to %s", path);
	if (fd < 0)
		return;
	memset(msg, 0, sizeof(msg));
	memcpy(msg, &header, sizeof(header));
	CHECK(send(fd, msg, ESDM_RPC_MAX_MSG_SIZE, MSG_NOSIGNAL) ==
		      ESDM_RPC_MAX_MSG_SIZE,
	      "cannot send %u bytes", ESDM_RPC_MAX_MSG_SIZE);
	CHECK(test_answered(fd, 1), "a message of %u bytes was not answered",
	      ESDM_RPC_MAX_MSG_SIZE);
	close(fd);
}

/*
 * Clients asking for large answers and closing their connections at once: the
 * server finds them gone as it sends, and serves the others on.
 */
#define TEST_LEAVING 32
static void test_leaving(const char *path)
{
	int fds[TEST_LEAVING], fd;
	unsigned int i, round;

	atomic_store(&test_big, true);
	for (round = 0; round < 4; round++) {
		for (i = 0; i < TEST_LEAVING; i++) {
			fds[i] = test_connect(path);
			CHECK(fds[i] >= 0, "cannot connect to %s", path);
		}
		for (i = 0; i < TEST_LEAVING; i++) {
			if (fds[i] < 0)
				continue;
			CHECK(test_send(fds[i], i), "cannot send");
			/* Half of them before, half as the answer comes */
			if (i & 1)
				test_sleep_ms(0);
			close(fds[i]);
		}
	}

	/* Answered whole, in order, on a connection of its own */
	fd = test_connect(path);
	CHECK(fd >= 0, "cannot connect to %s", path);
	if (fd >= 0) {
		CHECK(test_send(fd, 7) && test_answered(fd, 7) &&
			      test_send(fd, 8) && test_send(fd, 9) &&
			      test_answered(fd, 8) && test_answered(fd, 9),
		      "large answers not served after clients left");
		close(fd);
	}
	atomic_store(&test_big, false);
}

/*
 * More requests at once than the ring of a worker has buffers: the privileged
 * worker - there is one - held up, a request on each of TEST_BURST connections
 * that were served before, then let go. Each is answered.
 */
#define TEST_BURST 200
static void test_burst(const char *path)
{
	static int fds[TEST_BURST];
	unsigned int i, answered = 0;
	int hold;

	for (i = 0; i < TEST_BURST; i++) {
		fds[i] = test_connect(path);
		CHECK(fds[i] >= 0, "cannot connect to %s: %s", path,
		      strerror(-fds[i]));
		if (fds[i] >= 0)
			CHECK(test_send(fds[i], i) && test_answered(fds[i], i),
			      "burst connection %u not served", i);
	}

	hold = test_connect(path);
	CHECK(hold >= 0, "cannot connect to %s", path);
	atomic_store(&test_hold, true);
	if (hold >= 0)
		CHECK(test_send(hold, 0), "cannot hold up the worker");
	for (i = 0; i < 2000 && !atomic_load(&test_held); i++)
		test_sleep_ms(1);
	CHECK(atomic_load(&test_held), "the worker was not held up");

	for (i = 0; i < TEST_BURST; i++) {
		if (fds[i] >= 0)
			CHECK(test_send(fds[i], 1000 + i), "cannot send");
	}
	atomic_store(&test_hold, false);

	if (hold >= 0) {
		CHECK(test_answered(hold, 0), "the holding call unanswered");
		close(hold);
	}
	for (i = 0; i < TEST_BURST; i++) {
		if (fds[i] < 0)
			continue;
		if (test_answered(fds[i], 1000 + i))
			answered++;
		close(fds[i]);
	}
	CHECK_EQ(answered, TEST_BURST);
}

/*
 * Connections made one after the other to the unprivileged interface, each
 * holding on: every worker serves as many of them, give or take one - the
 * worker accepting a connection hands it to the one serving the fewest.
 */
#define TEST_SPREAD_PER_WORKER 4
static void test_spread(const char *path)
{
	size_t workers = min_size(esdm_config_online_nodes(),
				  THREADING_MAX_WORKER_THREADS);
	size_t n = workers * TEST_SPREAD_PER_WORKER, i, j, distinct = 0;
	unsigned int cmin = UINT_MAX, cmax = 0;
	pthread_t *served;
	unsigned int *count;
	int *fds;

	fds = calloc(n, sizeof(*fds));
	served = calloc(n, sizeof(*served));
	count = calloc(n, sizeof(*count));
	CHECK(fds && served && count, "out of memory");
	if (!fds || !served || !count)
		goto out;

	for (i = 0; i < n; i++) {
		fds[i] = test_connect(path);
		CHECK(fds[i] >= 0, "cannot connect to %s", path);
		if (fds[i] < 0 || !test_send(fds[i], (uint32_t)i) ||
		    !test_answered(fds[i], (uint32_t)i)) {
			CHECK(0, "connection %zu not served", i);
			continue;
		}
		served[i] = atomic_load(&test_served_by);
	}

	/* Connections per worker */
	for (i = 0; i < n; i++) {
		for (j = 0; j < i && !pthread_equal(served[j], served[i]); j++)
			;
		count[j]++;
		if (j == i)
			distinct++;
	}
	for (i = 0; i < n; i++) {
		if (!count[i])
			continue;
		if (count[i] < cmin)
			cmin = count[i];
		if (count[i] > cmax)
			cmax = count[i];
	}
	CHECK(distinct == workers, "%zu connections served by %zu of %zu workers",
	      n, distinct, workers);
	CHECK(cmax <= cmin + 1, "%u to %u connections per worker", cmin,
	      cmax);

	for (i = 0; i < n; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
out:
	free(fds);
	free(served);
	free(count);
}

/*
 * The io_uring instances and the epoll instances of this process - those of
 * the workers, the test itself has none
 */
static void test_count_loops(unsigned int *uring, unsigned int *epoll)
{
	struct dirent *de;
	DIR *dir = opendir("/proc/self/fd");

	*uring = *epoll = 0;
	if (!dir)
		return;

	while ((de = readdir(dir))) {
		char fd[64 + sizeof(de->d_name)], target[64];
		ssize_t len;

		if (de->d_name[0] == '.')
			continue;
		snprintf(fd, sizeof(fd), "/proc/self/fd/%s", de->d_name);
		len = readlink(fd, target, sizeof(target) - 1);
		if (len <= 0)
			continue;
		target[len] = '\0';
		if (!strcmp(target, "anon_inode:[io_uring]"))
			(*uring)++;
		else if (!strcmp(target, "anon_inode:[eventpoll]"))
			(*epoll)++;
	}
	closedir(dir);
}

/* Lines of the log of the case holding @what */
static unsigned int test_log_lines(const char *what)
{
	char line[1024];
	unsigned int n = 0;
	FILE *fp = fopen(test_log_path, "r");

	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, what))
			n++;
	}
	fclose(fp);

	return n;
}

/* Print the lines of the log of the case holding @what */
static void test_log_print(const char *what)
{
	char line[1024];
	FILE *fp = fopen(test_log_path, "r");

	if (!fp)
		return;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, what))
			printf("  %s", line);
	}
	fclose(fp);
}

/*
 * The process of a case: the server, its clients, and whether its workers
 * wait with io_uring (@uring) - its exit status the failed checks.
 */
static int test_case_run(enum test_case tc, bool uring)
{
	pthread_t priv_thread, unpriv_thread;
	unsigned int rings, epolls, i;
	int log, ret;

	/* The log of the server, for the parent to look at */
	log = open(test_log_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		   0600);
	if (log < 0 || dup2(log, STDERR_FILENO) < 0)
		return 1;
	close(log);
	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								  LOGGER_STATUS);

	switch (tc) {
	case TEST_DEFAULT:
		break;
	case TEST_POLL:
		esdm_rpc_server_set_io_uring_multishot(false);
		break;
	case TEST_NO_PBUF:
		ret = test_refuse_pbuf_ring();
		if (ret) {
			printf("cannot install the seccomp filter: %s\n",
			       strerror(-ret));
			return 77;
		}
		break;
	case TEST_SWITCHED_OFF:
		esdm_rpc_server_set_io_uring(false);
		break;
	case TEST_REFUSED_EPERM:
		ret = test_refuse_io_uring(EPERM);
		if (ret) {
			printf("cannot install the seccomp filter: %s\n",
			       strerror(-ret));
			return 77;
		}
		break;
	case TEST_REFUSED_ENOSYS:
		ret = test_refuse_io_uring(ENOSYS);
		if (ret) {
			printf("cannot install the seccomp filter: %s\n",
			       strerror(-ret));
			return 77;
		}
		break;
	default:
		return 1;
	}

	/*
	 * Fewer buffers than the requests a round of the burst takes in at
	 * once - the kernel runs some 20 receives per wait at most
	 */
	esdm_rpcs_fuzz_uring_bufs(4);

	if (thread_init(1)) {
		fprintf(stdout, "cannot initialize threading support\n");
		return 1;
	}

	if (pthread_create(&priv_thread, NULL, test_serve_priv, NULL) ||
	    pthread_create(&unpriv_thread, NULL, test_serve_unpriv, NULL)) {
		fprintf(stdout, "cannot start the server threads\n");
		return 1;
	}

	if (!test_wait_for_socket(test_priv_path) ||
	    !test_wait_for_socket(test_unpriv_path)) {
		fprintf(stdout, "the server did not come up\n");
		return 1;
	}

	test_clients(test_unpriv_path);
	test_clients(test_priv_path);
	test_oversized(test_unpriv_path);
	test_oversized(test_priv_path);
	test_leaving(test_unpriv_path);
	test_burst(test_priv_path);
	test_clients(test_unpriv_path);
	/* Once the server has seen the connections above closed */
	test_sleep_ms(200);
	test_spread(test_unpriv_path);

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* Through the ring, the burst ran its receives out of buffers */
	if (uring && tc == TEST_DEFAULT)
		CHECK(esdm_rpcs_fuzz_uring_enobufs() > 0,
		      "no receive ran out of buffers in the burst");
	else
		CHECK_EQ(esdm_rpcs_fuzz_uring_enobufs(), 0);
#endif

	/*
	 * Every worker has set up its loop by now: each one serving a client
	 * did, and they all serve the same listening socket. Wait for the last
	 * of them all the same.
	 */
	for (i = 0; i < 100; i++) {
		test_count_loops(&rings, &epolls);
		if ((uring ? rings : epolls) >= 2 && !(uring ? epolls : rings))
			break;
		test_sleep_ms(10);
	}
	if (uring) {
		CHECK(rings >= 2, "%u io_uring instances, expected one per worker",
		      rings);
		CHECK_EQ(epolls, 0);
	} else {
		CHECK(epolls >= 2, "%u epoll instances, expected one per worker",
		      epolls);
		CHECK_EQ(rings, 0);
	}

	esdm_rpc_server_signal_exit();
	pthread_join(priv_thread, NULL);
	pthread_join(unpriv_thread, NULL);

	unlink(test_priv_path);
	unlink(test_unpriv_path);

	return common_test_failures ? 1 : 0;
}

/* Can this process set up an io_uring? */
static bool test_io_uring_usable(void)
{
#ifdef ESDM_RPC_IO_URING
	struct io_uring ring;
	int ret = io_uring_queue_init(4, &ring, 0);

	if (ret) {
		printf("io_uring cannot be set up here: %s\n", strerror(-ret));
		return false;
	}
	io_uring_queue_exit(&ring);

	return true;
#else
	return false;
#endif
}

int main(void)
{
	bool usable = test_io_uring_usable();
	unsigned int failed = 0, skipped = 0;
	unsigned int tc;

	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(test_priv_path, sizeof(test_priv_path), "%s/priv", test_dir);
	snprintf(test_unpriv_path, sizeof(test_unpriv_path), "%s/unpriv",
		 test_dir);
	snprintf(test_log_path, sizeof(test_log_path), "%s/log", test_dir);

#ifdef ESDM_RPC_IO_URING
	printf("Built with io_uring, %s here\n",
	       usable ? "which is usable" : "which is not usable");
#else
	printf("Built without io_uring\n");
#endif

	for (tc = TEST_DEFAULT; tc <= TEST_REFUSED_ENOSYS; tc++) {
		/* io_uring where it is built, usable and neither off nor refused */
		bool uring = usable && (tc == TEST_DEFAULT || tc == TEST_POLL ||
					tc == TEST_NO_PBUF);
		bool fallback = usable && (tc == TEST_REFUSED_EPERM ||
					   tc == TEST_REFUSED_ENOSYS);
		int status;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid < 0) {
			perror("fork");
			return 1;
		}
		if (!pid)
			_exit(test_case_run((enum test_case)tc, uring));

		if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
			printf("%s: the process of the case died\n",
			       test_case_name[tc]);
			failed++;
			continue;
		}
		if (WEXITSTATUS(status) == 77) {
			printf("%s: SKIP\n", test_case_name[tc]);
			skipped++;
			continue;
		}

		/*
		 * The workers of both interfaces tried to set up their ring,
		 * and one line says that they wait with epoll instead.
		 */
		if (fallback &&
		    test_log_lines("cannot be set up for the RPC worker") != 1) {
			printf("%s: expected one line on the fallback in the log, found %u\n",
			       test_case_name[tc],
			       test_log_lines(
				       "cannot be set up for the RPC worker"));
			failed++;
		} else if (uring &&
			   test_log_lines("wait with io_uring") != 1) {
			printf("%s: expected one line on io_uring in the log, found %u\n",
			       test_case_name[tc],
			       test_log_lines("wait with io_uring"));
			failed++;
		} else if (uring) {
			/* Receiving through the ring, or polling with it */
#ifdef ESDM_RPC_IO_URING_MULTISHOT
			bool mshot = tc == TEST_DEFAULT;
#else
			bool mshot = false;
#endif
			if (test_log_lines(mshot ? TEST_LOG_MULTISHOT :
						   TEST_LOG_POLLING) != 1) {
				printf("%s: expected the workers to %s\n",
				       test_case_name[tc],
				       mshot ? "receive through the ring" :
					       "poll with the ring");
				failed++;
			}
#ifdef ESDM_RPC_IO_URING_MULTISHOT
			if (test_log_lines(TEST_LOG_NO_PBUF) !=
			    (tc == TEST_NO_PBUF ? 1U : 0U)) {
				printf("%s: %u lines on the buffer rings refused\n",
				       test_case_name[tc],
				       test_log_lines(TEST_LOG_NO_PBUF));
				failed++;
			}
#endif
		}

		if (WEXITSTATUS(status)) {
			printf("%s: FAIL\n", test_case_name[tc]);
			test_log_print("FAIL ");
			failed++;
		} else {
			printf("%s: waiting with %s, PASS\n", test_case_name[tc],
			       uring ? "io_uring" : "epoll");
		}
	}

	unlink(test_log_path);
	rmdir(test_dir);

	if (failed)
		return 1;
	if (skipped == TEST_REFUSED_ENOSYS + 1)
		return 77;

	printf("PASS\n");
	return 0;
}
