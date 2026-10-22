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
 * The event loop of the RPC server's workers.
 *
 * The server's accept loop and workers serve a stand-in service on sockets of
 * the test's own, through the serve hook of the fuzz harnesses - hence no
 * daemon, no ESDM and no privileges. Clients on both interfaces have their
 * requests answered - several in turn, a request sent while the one before is
 * still unanswered, which the loop has to report again after it served the
 * first, and the clients of connections that others closed meanwhile. And:
 *
 *   - a message larger than a request can be ends its connection, unanswered,
 *   - clients closing their connections before they read their answers - the
 *     server's write finding the peer gone - leave the others served,
 *   - many requests at once, arriving while their worker is held up, are all
 *     answered,
 *   - the connections are spread evenly over the workers of the unprivileged
 *     interface, whichever accepts them.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

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

#define TEST_CLIENTS 8
#define TEST_REQUESTS 64
/* How long a client waits for an answer */
#define TEST_ANSWER_MS 5000

static char test_dir[] = "/tmp/esdm-rpc-loop-test.XXXXXX";
static char test_priv_path[sizeof(test_dir) + 16];
static char test_unpriv_path[sizeof(test_dir) + 16];

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
 * Many requests at once: the privileged worker - there is one - held up, a
 * request on each of TEST_BURST connections that were served before, then let
 * go. Each is answered.
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

int main(void)
{
	pthread_t priv_thread, unpriv_thread;
	int ret = 1;

	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(test_priv_path, sizeof(test_priv_path), "%s/priv", test_dir);
	snprintf(test_unpriv_path, sizeof(test_unpriv_path), "%s/unpriv",
		 test_dir);
	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								  LOGGER_STATUS);

	if (thread_init(1)) {
		fprintf(stdout, "cannot initialize threading support\n");
		goto out;
	}

	if (pthread_create(&priv_thread, NULL, test_serve_priv, NULL) ||
	    pthread_create(&unpriv_thread, NULL, test_serve_unpriv, NULL)) {
		fprintf(stdout, "cannot start the server threads\n");
		goto out;
	}

	if (!test_wait_for_socket(test_priv_path) ||
	    !test_wait_for_socket(test_unpriv_path)) {
		fprintf(stdout, "the server did not come up\n");
		goto out;
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

	esdm_rpc_server_signal_exit();
	pthread_join(priv_thread, NULL);
	pthread_join(unpriv_thread, NULL);

	ret = common_test_result("rpc_server_loop_test");

out:
	unlink(test_priv_path);
	unlink(test_unpriv_path);
	rmdir(test_dir);

	return ret;
}
