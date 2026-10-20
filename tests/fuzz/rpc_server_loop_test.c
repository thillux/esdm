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
 *     and the kernel lets this process set up a ring, with epoll otherwise,
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
 * others closed meanwhile.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
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
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
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
	TEST_SWITCHED_OFF,
	TEST_REFUSED_EPERM,
	TEST_REFUSED_ENOSYS,
};

static const char *const test_case_name[] = {
	[TEST_DEFAULT] = "default",
	[TEST_SWITCHED_OFF] = "io_uring switched off",
	[TEST_REFUSED_EPERM] = "io_uring_setup refused with EPERM",
	[TEST_REFUSED_ENOSYS] = "io_uring_setup refused with ENOSYS",
};

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/****************************
 * Server
 ****************************/

/* Answers every call with ret 0 */
static void test_service_invoke(ProtobufCService *service,
				unsigned int method_index,
				const ProtobufCMessage *input,
				ProtobufCClosure closure, void *closure_data)
{
	RetResponse response = RET_RESPONSE__INIT;

	(void)service;
	(void)method_index;
	(void)input;

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
	uint8_t buf[256];
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
		bool uring = usable && tc == TEST_DEFAULT;
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
		}

		if (WEXITSTATUS(status)) {
			printf("%s: FAIL\n", test_case_name[tc]);
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
