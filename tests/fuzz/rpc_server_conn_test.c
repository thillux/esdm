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
 * How the RPC server handles its connections.
 *
 * The server's accept loop and worker threads serve a stand-in service on
 * sockets of the test's own, through the serve hook of the fuzz harnesses -
 * hence no daemon, no ESDM and no privileges:
 *
 *   - a connection is idle from its last answer on, not from its last
 *     request, so a call that takes longer than the idle timeout does not
 *     lose the connection right after its answer,
 *   - the unprivileged interface keeps descriptors in reserve, and a new
 *     connection beyond its bound makes room by closing an idle one rather
 *     than waiting for a descriptor that does not come.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.pb-c.h"
#include "common_test.h"
#include "config.h"
#include "conv_be_le.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

#define TEST_IDLE_MS (ESDM_RPC_IDLE_TIMEOUT_USEC / 1000)

/*
 * The descriptor limit of the server, and the connections opened against it.
 * The server holds at most half of the limit for the unprivileged connections
 * then, and without making room it runs out of descriptors long before the
 * last connection.
 */
#define TEST_NOFILE 256
#define TEST_CONNS 600

static char test_dir[] = "/tmp/esdm-rpc-conn-test.XXXXXX";
static char test_priv_path[sizeof(test_dir) + 16];
static char test_unpriv_path[sizeof(test_dir) + 16];

/* How long the stand-in service takes for a call */
static atomic_uint test_delay_ms;

static atomic_bool test_serve_failed;

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/* Answers every call with ret 0 after test_delay_ms */
static void test_service_invoke(ProtobufCService *service,
				unsigned int method_index,
				const ProtobufCMessage *input,
				ProtobufCClosure closure, void *closure_data)
{
	RetResponse response = RET_RESPONSE__INIT;

	(void)service;
	(void)method_index;
	(void)input;

	test_sleep_ms(atomic_load(&test_delay_ms));

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
	if (ret) {
		fprintf(stderr, "the privileged server did not run: %s\n",
			strerror(-ret));
		atomic_store(&test_serve_failed, true);
	}

	return NULL;
}

static void *test_serve_unpriv(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(test_unpriv_path, &test_unpriv_service,
				   false);
	if (ret) {
		fprintf(stderr, "the unprivileged server did not run: %s\n",
			strerror(-ret));
		atomic_store(&test_serve_failed, true);
	}

	return NULL;
}

static bool test_wait_for_socket(const char *path)
{
	unsigned int i;
	struct stat sb;

	for (i = 0; i < 500; i++) {
		if (atomic_load(&test_serve_failed))
			return false;
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(10);
	}

	return false;
}

static int test_connect(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		close(fd);
		return -errsv;
	}

	return fd;
}

/* Send a request for the first method, of an empty message */
static bool test_send(int fd, uint32_t request_id)
{
	struct esdm_rpc_proto_cs_header header = {
		.method_index = 0,
		.message_length = 0,
		.request_id = le_bswap32(request_id),
	};

	return send(fd, &header, sizeof(header), MSG_NOSIGNAL) ==
	       (ssize_t)sizeof(header);
}

/* Wait up to @timeout_ms for the answer to @request_id */
static bool test_answered(int fd, uint32_t request_id, int timeout_ms)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE];
	struct esdm_rpc_proto_sc_header reply;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	ssize_t received;

	if (poll(&pfd, 1, timeout_ms) != 1)
		return false;

	received = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (received < (ssize_t)sizeof(reply))
		return false;

	memcpy(&reply, buf, sizeof(reply));

	return le_bswap32(reply.request_id) == request_id;
}

/*
 * A call taking longer than the idle timeout keeps its connection: the next
 * request on it, sent once the server had the chance to reap it, is answered.
 */
static void test_long_call(void)
{
	int fd;

	printf("A call longer than the idle timeout of %u ms\n", TEST_IDLE_MS);

	fd = test_connect(test_priv_path);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;

	/* The idle timer fires at least once while the call runs */
	atomic_store(&test_delay_ms, TEST_IDLE_MS + 500);
	CHECK(test_send(fd, 1), "cannot send the long call");
	CHECK(test_answered(fd, 1, TEST_IDLE_MS + 5000),
	      "the long call was not answered");

	/* The server takes up the expired idle timer first */
	atomic_store(&test_delay_ms, 0);
	test_sleep_ms(200);

	CHECK(test_send(fd, 2), "cannot send the next call");
	CHECK(test_answered(fd, 2, 2000),
	      "the call after the long one was not answered - the connection was reaped");

	close(fd);
}

/*
 * The clients of test_many_conns(), in a process of their own: they need more
 * descriptors than the server is allowed. Returns the number of failures.
 */
static int test_many_conns_client(rlim_t nofile)
{
	struct rlimit rl = { .rlim_cur = nofile, .rlim_max = nofile };
	static int fds[TEST_CONNS];
	unsigned int i, closed = 0;
	int fail = 0;

	if (setrlimit(RLIMIT_NOFILE, &rl)) {
		fprintf(stderr, "cannot raise the descriptor limit\n");
		return 1;
	}

	for (i = 0; i < TEST_CONNS; i++) {
		fds[i] = test_connect(test_unpriv_path);
		if (fds[i] < 0) {
			fprintf(stderr, "connection %u: %s\n", i,
				strerror(-fds[i]));
			return fail + 1;
		}

		if (!test_send(fds[i], i)) {
			fprintf(stderr, "connection %u: cannot send\n", i);
			return fail + 1;
		}

		/*
		 * The answer of the first stays unread, which keeps it from
		 * being closed, although it is the least recently used.
		 */
		if (!i)
			continue;

		/* Well within the idle timeout, which would make room too */
		if (!test_answered(fds[i], i, 1000)) {
			fprintf(stderr, "connection %u was not served\n", i);
			return fail + 1;
		}
	}

	if (!test_answered(fds[0], 0, 0) ||
	    !test_send(fds[0], TEST_CONNS + 1) ||
	    !test_answered(fds[0], TEST_CONNS + 1, 1000)) {
		fprintf(stderr,
			"the connection with an unread answer was closed\n");
		fail++;
	}

	/* Those closed to make room tell by an end of file */
	for (i = 1; i < TEST_CONNS - 1; i++) {
		struct pollfd pfd = { .fd = fds[i], .events = POLLIN };
		uint8_t b;

		if (poll(&pfd, 1, 0) == 1 &&
		    recv(fds[i], &b, sizeof(b), MSG_DONTWAIT) == 0)
			closed++;
	}
	if (closed < TEST_CONNS - TEST_NOFILE / 2) {
		fprintf(stderr, "only %u connections were closed\n", closed);
		fail++;
	}

	/* The newest one is served on */
	if (!test_send(fds[TEST_CONNS - 1], TEST_CONNS) ||
	    !test_answered(fds[TEST_CONNS - 1], TEST_CONNS, 1000)) {
		fprintf(stderr, "the newest connection was closed\n");
		fail++;
	}

	for (i = 0; i < TEST_CONNS; i++)
		close(fds[i]);

	return fail;
}

/*
 * Many more connections than the server has descriptors for, one after the
 * other, each idle once served: every one is served, the oldest are closed -
 * but not one whose answer the client has not read yet.
 */
static void test_many_conns(rlim_t nofile)
{
	pid_t pid;
	int status;

	printf("%u connections against a descriptor limit of %u\n",
	       TEST_CONNS, TEST_NOFILE);

	fflush(stdout);
	pid = fork();
	CHECK(pid >= 0, "cannot fork: %s", strerror(errno));
	if (pid < 0)
		return;
	if (!pid)
		_exit(test_many_conns_client(nofile));

	CHECK(waitpid(pid, &status, 0) == pid, "cannot wait for the clients");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status),
	      "the clients failed");
}

int main(void)
{
	pthread_t priv_thread, unpriv_thread;
	struct rlimit rl;
	rlim_t client_nofile = 0;

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								  LOGGER_NONE);

	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(test_priv_path, sizeof(test_priv_path), "%s/priv", test_dir);
	snprintf(test_unpriv_path, sizeof(test_unpriv_path), "%s/unpriv",
		 test_dir);

	/*
	 * Before the server starts, which sizes its bound by the limit. The
	 * clients take theirs back up to what the hard limit allows.
	 */
	if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_max >= 2 * TEST_CONNS) {
		client_nofile = rl.rlim_max == RLIM_INFINITY ? 4 * TEST_CONNS :
							       rl.rlim_max;
		rl.rlim_cur = TEST_NOFILE;
		if (setrlimit(RLIMIT_NOFILE, &rl))
			client_nofile = 0;
	}

	if (thread_init(1)) {
		fprintf(stderr, "cannot initialize threading support\n");
		return 1;
	}

	if (pthread_create(&priv_thread, NULL, test_serve_priv, NULL) ||
	    pthread_create(&unpriv_thread, NULL, test_serve_unpriv, NULL)) {
		fprintf(stderr, "cannot start the server threads\n");
		return 1;
	}

	if (!test_wait_for_socket(test_priv_path) ||
	    !test_wait_for_socket(test_unpriv_path)) {
		fprintf(stderr, "the server did not come up\n");
		return 1;
	}

	test_long_call();

	if (client_nofile)
		test_many_conns(client_nofile);
	else
		printf("hard descriptor limit too low - skipping the many connections\n");

	esdm_rpc_server_signal_exit();
	pthread_join(priv_thread, NULL);
	pthread_join(unpriv_thread, NULL);

	unlink(test_priv_path);
	unlink(test_unpriv_path);
	rmdir(test_dir);

	if (!common_test_failures)
		printf("PASS\n");

	return common_test_failures ? 1 : 0;
}
