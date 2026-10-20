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
 *     than waiting for a descriptor that does not come,
 *   - leaving answers unread does not keep a client's connections from
 *     being closed to make room, and the answers stay readable,
 *   - no connection is closed to make room while a worker has a free slot,
 *   - a request is not lost to a connection the server closes on its own: a
 *     connection with a request waiting is not idle, and one sent as the
 *     server closes the connection, idle or to make room, is still served,
 *   - new connections are accepted in the first rounds of a worker busy with
 *     others, not one per round.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
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
#include "esdm_config.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/*
 * The real ones, which the build renamed in the headers above - for the
 * server, see the server hooks below
 */
#undef epoll_wait
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
	       int timeout);
#undef shutdown
int shutdown(int fd, int how);

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

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/*
 * Send a request for the first method, of a message with its first field set to
 * @tag, which the stand-in service tells the request by - see test_tag(). Of
 * either interface, the first method takes a message of a single uint32.
 */
static bool test_send_tagged(int fd, uint32_t request_id, uint32_t tag)
{
	uint8_t req[sizeof(struct esdm_rpc_proto_cs_header) + 6];
	struct esdm_rpc_proto_cs_header header = {
		.method_index = 0,
		.request_id = le_bswap32(request_id),
	};
	size_t len = 0;

	/* Field 1, a varint - left out when 0, as protobuf does */
	if (tag) {
		req[sizeof(header) + len++] = 0x08;
		do {
			req[sizeof(header) + len] = (uint8_t)(tag & 0x7f);
			tag >>= 7;
			if (tag)
				req[sizeof(header) + len] |= 0x80;
			len++;
		} while (tag);
	}

	header.message_length = le_bswap32((uint32_t)len);
	memcpy(req, &header, sizeof(header));
	len += sizeof(header);

	return send(fd, req, len, MSG_NOSIGNAL) == (ssize_t)len;
}

/* Send a request for the first method, of an empty message */
static bool test_send(int fd, uint32_t request_id)
{
	return test_send_tagged(fd, request_id, 0);
}

/****************************
 * Server hooks
 ****************************/

/*
 * The build renames the server's wait for the events of a round and its
 * shutdown(2) of a connection to the wrappers below. They send a request on a
 * connection of the test at a moment of the server's choosing, as a client
 * sending just then would - see test_late_arm().
 */
enum test_late_at {
	TEST_LATE_NONE,
	/*
	 * Once the privileged worker collected the events of a round in which
	 * it closes idle connections, from a given time on
	 */
	TEST_LATE_REAP_ROUND,
	/* Right before the server shuts the connection down */
	TEST_LATE_SHUTDOWN,
};

/* When to send the request, on which connection, and its request ID */
static atomic_int test_late_at;
static atomic_int test_late_fd = -1;
static atomic_uint test_late_id;
/* The earliest time of TEST_LATE_REAP_ROUND */
static _Atomic uint64_t test_late_from_ms;
/*
 * The address the connection of TEST_LATE_SHUTDOWN is bound to, which the
 * server sees as its peer, see test_connect_from()
 */
static struct sockaddr_un test_late_addr;
static socklen_t test_late_addrlen;

/* The request went out: 1, or its send failed: -1 - and when */
static atomic_int test_late_sent;
static _Atomic uint64_t test_late_sent_ms;

/* Send the request if it is due at @at, which it is only once. */
static void test_late_send(int at)
{
	int expected = at;
	bool sent;

	if (!atomic_compare_exchange_strong(&test_late_at, &expected,
					    TEST_LATE_NONE))
		return;

	sent = test_send(atomic_load(&test_late_fd),
			 atomic_load(&test_late_id));
	atomic_store(&test_late_sent_ms, test_now_ms());
	atomic_store(&test_late_sent, sent ? 1 : -1);
}

/*
 * The worker that served the request tagged TEST_TAG_LOCATE, and which of the
 * workers of the unprivileged interface hold back for a moment when woken -
 * leaving a new connection to the others, see test_evict_late(). Shared with
 * the clients in a process of their own, which set it - mapped before the
 * server starts.
 */
#define TEST_TAG_LOCATE 0xc0ffee
static _Atomic uintptr_t test_located;
enum test_favor {
	TEST_FAVOR_NONE,
	/* The located worker holds back */
	TEST_FAVOR_OTHERS,
	/* All other workers hold back */
	TEST_FAVOR_LOCATED,
};
static atomic_int *test_favor;

/* Is the calling thread a worker of the interface named by @prefix? */
static bool test_in_worker(const char *prefix)
{
	char name[16] = { 0 };

	return !pthread_getname_np(pthread_self(), name, sizeof(name)) &&
	       !strncmp(name, prefix, strlen(prefix));
}

int test_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
		    int timeout);
int test_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
		    int timeout)
{
	int nfds = epoll_wait(epfd, events, maxevents, timeout), i;
	int favor = atomic_load(test_favor);

	/*
	 * Each worker listening is woken for a new connection, and the first
	 * to accept it takes it - not one holding back.
	 */
	if (favor != TEST_FAVOR_NONE && nfds > 0 &&
	    test_in_worker("ESDM rpc_up") &&
	    ((uintptr_t)pthread_self() == atomic_load(&test_located)) ==
		    (favor == TEST_FAVOR_OTHERS))
		test_sleep_ms(2);

	if (atomic_load(&test_late_at) != TEST_LATE_REAP_ROUND ||
	    test_now_ms() < atomic_load(&test_late_from_ms) ||
	    !test_in_worker("ESDM rpc_p"))
		return nfds;

	/* The worker's idle timer, see esdm_rpcs_handler() */
	for (i = 0; i < nfds; i++) {
		if (events[i].data.u64 == 1) {
			test_late_send(TEST_LATE_REAP_ROUND);
			break;
		}
	}

	return nfds;
}

/* Is the peer of the server's connection @fd the one of the request? */
static bool test_late_peer(int fd)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);

	return !getpeername(fd, (struct sockaddr *)&addr, &len) &&
	       len == test_late_addrlen && !memcmp(&addr, &test_late_addr, len);
}

int test_shutdown(int fd, int how);
int test_shutdown(int fd, int how)
{
	if (atomic_load(&test_late_at) == TEST_LATE_SHUTDOWN &&
	    test_late_peer(fd))
		test_late_send(TEST_LATE_SHUTDOWN);

	return shutdown(fd, how);
}

/*
 * Have request @id sent on @fd at @at - for TEST_LATE_REAP_ROUND once it is
 * @from_ms, for TEST_LATE_SHUTDOWN on @fd connected with test_connect_from().
 */
static void test_late_arm(int fd, uint32_t id, enum test_late_at at,
			  uint64_t from_ms)
{
	atomic_store(&test_late_sent, 0);
	atomic_store(&test_late_fd, fd);
	atomic_store(&test_late_id, id);
	atomic_store(&test_late_from_ms, from_ms);
	atomic_store(&test_late_at, (int)at);
}

/* Wait up to @timeout_ms for the request armed; was it sent? */
static bool test_late_wait(unsigned int timeout_ms)
{
	uint64_t end = test_now_ms() + timeout_ms;

	while (!atomic_load(&test_late_sent) && test_now_ms() < end)
		test_sleep_ms(10);

	atomic_store(&test_late_at, TEST_LATE_NONE);

	return atomic_load(&test_late_sent) == 1;
}

/* The tag of a request, see test_send_tagged() */
static uint32_t test_tag(const ProtobufCMessage *input)
{
	if (input->descriptor == &status_request__descriptor)
		return ((const StatusRequest *)input)->maxlen;
	if (input->descriptor == &rnd_add_to_ent_cnt_request__descriptor)
		return ((const RndAddToEntCntRequest *)input)->entcnt;

	return 0;
}

/*
 * The tags of the requests served, in the order they were, from those of
 * TEST_TAG_FIRST on - see test_accept_burst()
 */
#define TEST_TAG_FIRST 1
#define TEST_LOG_MAX 4096
static atomic_uint test_log[TEST_LOG_MAX];
static atomic_uint test_log_len;

/* A request with this tag waits while test_gate is set, holding up its worker */
#define TEST_TAG_GATE 0xffff
static atomic_bool test_gate;
static atomic_bool test_gated;

/* Answers every call with ret 0 after test_delay_ms */
static void test_service_invoke(ProtobufCService *service,
				unsigned int method_index,
				const ProtobufCMessage *input,
				ProtobufCClosure closure, void *closure_data)
{
	RetResponse response = RET_RESPONSE__INIT;
	uint32_t tag = test_tag(input);

	(void)service;
	(void)method_index;

	if (tag == TEST_TAG_LOCATE) {
		atomic_store(&test_located, (uintptr_t)pthread_self());
	} else if (tag == TEST_TAG_GATE) {
		uint64_t end = test_now_ms() + 10000;

		atomic_store(&test_gated, true);
		while (atomic_load(&test_gate) && test_now_ms() < end)
			test_sleep_ms(1);
		atomic_store(&test_gated, false);
	} else if (tag >= TEST_TAG_FIRST) {
		unsigned int n = atomic_fetch_add(&test_log_len, 1);

		if (n < TEST_LOG_MAX)
			atomic_store(&test_log[n], tag);
	}

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

/*
 * Connect to @path - if @late, from an address of its own: an abstract one the
 * kernel picks, which the server sees as the peer, and which tells
 * test_shutdown() the connection to send on.
 */
static int test_connect_from(const char *path, bool late)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (late) {
		struct sockaddr_un own = { .sun_family = AF_UNIX };

		test_late_addrlen = sizeof(test_late_addr);
		if (bind(fd, (struct sockaddr *)&own, sizeof(sa_family_t)) ||
		    getsockname(fd, (struct sockaddr *)&test_late_addr,
				&test_late_addrlen)) {
			int errsv = errno;

			close(fd);
			return -errsv;
		}
	}

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		close(fd);
		return -errsv;
	}

	return fd;
}

static int test_connect(const char *path)
{
	return test_connect_from(path, false);
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

/* Wait up to @timeout_ms for an answer, but leave it unread */
static bool test_answer_waiting(int fd, int timeout_ms)
{
	struct esdm_rpc_proto_sc_header reply;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	/* A connection closed without an answer polls readable as well */
	return poll(&pfd, 1, timeout_ms) == 1 &&
	       recv(fd, &reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT) ==
		       (ssize_t)sizeof(reply);
}

/* Does the server close @fd, whose answers were all read, within @timeout_ms? */
static bool test_closed_within(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	uint8_t b;

	return poll(&pfd, 1, timeout_ms) == 1 &&
	       recv(fd, &b, sizeof(b), MSG_DONTWAIT) == 0;
}

/* Has the server closed @fd, whose answers were all read? */
static bool test_closed(int fd)
{
	return test_closed_within(fd, 0);
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
 * A request that arrives in the round in which the server closes idle
 * connections, after the events of the round were collected, keeps its
 * connection, idle for the timeout before: the next round serves it.
 */
static void test_reap_pending(void)
{
	int fd;

	printf("A request arriving as its connection is found idle\n");

	fd = test_connect(test_priv_path);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;

	CHECK(test_send(fd, 1) && test_answered(fd, 1, 2000),
	      "the first call was not answered");

	/* Idle for the whole timeout once the request is sent */
	test_late_arm(fd, 2, TEST_LATE_REAP_ROUND,
		      test_now_ms() + TEST_IDLE_MS + 50);
	CHECK(test_late_wait(2 * TEST_IDLE_MS + 2000),
	      "the request could not be sent");
	CHECK(test_answered(fd, 2, 2000),
	      "the request was lost - its connection was closed as idle");

	close(fd);
}

/*
 * A request that arrives right as the server shuts down a connection it closes
 * as idle is still answered, and the connection closed after it.
 */
static void test_reap_late(void)
{
	int fd;

	printf("A request arriving as its idle connection is closed\n");

	fd = test_connect_from(test_priv_path, true);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;

	CHECK(test_send(fd, 1) && test_answered(fd, 1, 2000),
	      "the first call was not answered");

	test_late_arm(fd, 2, TEST_LATE_SHUTDOWN, 0);
	CHECK(test_late_wait(2 * TEST_IDLE_MS + 2000),
	      "the idle connection was not closed");
	CHECK(test_answered(fd, 2, 2000),
	      "the request sent as the connection was closed was lost");
	CHECK(test_closed_within(fd, 2000),
	      "the connection was not closed after the request");

	close(fd);
}

/*
 * Connections the privileged worker serves already, each with as many
 * requests, and new ones connecting meanwhile, see test_accept_burst(). The
 * tags of their requests: TEST_TAG_FIRST + i for the ith of the former,
 * TEST_TAG_NEW + j for the jth of the latter.
 */
#define TEST_BUSY_CONNS 30
#define TEST_BUSY_REQUESTS 40
#define TEST_NEW_CONNS 30
#define TEST_TAG_NEW 1000

/*
 * New connections get their turn in a round of the worker as the others with
 * a request do. The worker serves connections with requests, many of them in
 * the socket each, while new connections wait to be accepted: every one is
 * served in the first rounds, not one per round.
 *
 * The worker is held up while the requests are sent and the new connections
 * made, so that it finds them all at once. @nofile is the descriptor limit for
 * the time of the test, 0 to leave it.
 */
static void test_accept_burst(rlim_t nofile)
{
	static int busy[TEST_BUSY_CONNS], fresh[TEST_NEW_CONNS];
	unsigned int i, j = 0, n, len, busy_before = 0, served_new = 0;
	struct rlimit rl, saved;
	uint64_t end;
	int gate;

	printf("%u new connections while the worker serves %u others with %u requests each\n",
	       TEST_NEW_CONNS, TEST_BUSY_CONNS, TEST_BUSY_REQUESTS);

	/* Both sides of the connections are this process' */
	if (nofile && !getrlimit(RLIMIT_NOFILE, &saved)) {
		rl = saved;
		rl.rlim_cur = nofile;
		if (setrlimit(RLIMIT_NOFILE, &rl))
			nofile = 0;
	} else {
		nofile = 0;
	}

	gate = test_connect(test_priv_path);
	CHECK(gate >= 0, "cannot connect: %s", strerror(-gate));
	if (gate < 0)
		goto out_limit;
	CHECK(test_send(gate, 0) && test_answered(gate, 0, 2000),
	      "the gate connection was not served");

	/* Accepted and served once */
	for (i = 0; i < TEST_BUSY_CONNS; i++) {
		busy[i] = test_connect(test_priv_path);
		CHECK(busy[i] >= 0, "cannot connect: %s", strerror(-busy[i]));
		if (busy[i] < 0)
			goto out_busy;
		CHECK(test_send(busy[i], i) && test_answered(busy[i], i, 2000),
		      "connection %u was not served", i);
	}

	atomic_store(&test_log_len, 0);
	atomic_store(&test_gate, true);
	CHECK(test_send_tagged(gate, 1, TEST_TAG_GATE),
	      "cannot hold up the worker");
	end = test_now_ms() + 2000;
	while (!atomic_load(&test_gated) && test_now_ms() < end)
		test_sleep_ms(1);
	CHECK(atomic_load(&test_gated), "the worker was not held up");

	for (i = 0; i < TEST_BUSY_CONNS; i++) {
		for (n = 0; n < TEST_BUSY_REQUESTS; n++)
			CHECK(test_send_tagged(busy[i], n, TEST_TAG_FIRST + i),
			      "cannot send on connection %u", i);
	}
	for (j = 0; j < TEST_NEW_CONNS; j++) {
		fresh[j] = test_connect(test_priv_path);
		CHECK(fresh[j] >= 0, "cannot connect: %s", strerror(-fresh[j]));
		if (fresh[j] < 0)
			break;
		CHECK(test_send_tagged(fresh[j], j, TEST_TAG_NEW + j),
		      "cannot send on new connection %u", j);
	}
	atomic_store(&test_gate, false);

	end = test_now_ms() + 10000;
	while (atomic_load(&test_log_len) <
		       TEST_BUSY_CONNS * TEST_BUSY_REQUESTS + j &&
	       test_now_ms() < end)
		test_sleep_ms(10);

	/* The requests of the others served before the last new connection */
	len = atomic_load(&test_log_len);
	if (len > TEST_LOG_MAX)
		len = TEST_LOG_MAX;
	for (n = 0; n < len && served_new < j; n++) {
		if (atomic_load(&test_log[n]) >= TEST_TAG_NEW)
			served_new++;
		else
			busy_before++;
	}

	CHECK(served_new == TEST_NEW_CONNS,
	      "%u of %u new connections were served", served_new,
	      TEST_NEW_CONNS);
	printf("the last new connection was served after %u of the %u requests of the others\n",
	       busy_before, TEST_BUSY_CONNS * TEST_BUSY_REQUESTS);
	/*
	 * Accepted in the first round, they are served after the first request
	 * of each other connection, one per round after as many rounds as were
	 * before them.
	 */
	CHECK(busy_before <= 2 * TEST_BUSY_CONNS,
	      "the new connections were not served in the first rounds");

	while (j)
		close(fresh[--j]);
out_busy:
	while (i)
		close(busy[--i]);
	close(gate);
out_limit:
	if (nofile)
		setrlimit(RLIMIT_NOFILE, &saved);
}

/*
 * The clients of test_many_conns(), in a process of their own: they need more
 * descriptors than the server is allowed. Returns the number of failures.
 */
static int test_many_conns_client(void)
{
	static int fds[TEST_CONNS];
	unsigned int i, closed = 0;
	int fail = 0;

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
		if (test_closed(fds[i]))
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
 * The unprivileged connections the server admits in total, the way it sizes
 * them for TEST_NOFILE.
 */
static unsigned int test_conn_bound(void)
{
	unsigned int threads = esdm_config_online_nodes(), per_thread;

	if (threads > THREADING_MAX_WORKER_THREADS)
		threads = THREADING_MAX_WORKER_THREADS;
	per_thread = (TEST_NOFILE / 2) / threads;
	if (!per_thread)
		per_thread = 1;

	return per_thread * threads;
}

/*
 * The clients of test_fill(), each idle once served. Returns the number of
 * failures.
 */
static int test_fill_client(void)
{
	static int fds[TEST_CONNS];
	unsigned int i, bound = test_conn_bound(), closed = 0;
	struct timespec start, end;
	long elapsed_ms;
	int fail = 0;

	if (bound > TEST_CONNS)
		bound = TEST_CONNS;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (i = 0; i < bound; i++) {
		fds[i] = test_connect(test_unpriv_path);
		if (fds[i] < 0) {
			fprintf(stderr, "connection %u: %s\n", i,
				strerror(-fds[i]));
			return fail + 1;
		}

		if (!test_send(fds[i], i) || !test_answered(fds[i], i, 1000)) {
			fprintf(stderr, "connection %u was not served\n", i);
			return fail + 1;
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	elapsed_ms = (end.tv_sec - start.tv_sec) * 1000 +
		     (end.tv_nsec - start.tv_nsec) / 1000000;

	for (i = 0; i < bound; i++) {
		if (test_closed(fds[i]))
			closed++;
	}

	/* The idle reaper may close the first ones on a slow machine */
	if (elapsed_ms >= TEST_IDLE_MS / 2) {
		printf("connecting took %ld ms - not checked\n", elapsed_ms);
	} else if (closed) {
		fprintf(stderr,
			"%u of %u connections were closed below the bound\n",
			closed, bound);
		fail++;
	}

	for (i = 0; i < bound; i++)
		close(fds[i]);

	return fail;
}

/*
 * The clients of test_unread_answers(), each leaving its answer unread the
 * way one would that keeps its connections from being closed to make room.
 * Returns the number of failures.
 */
static int test_unread_answers_client(void)
{
	static int fds[TEST_CONNS];
	unsigned int i, closed = 0;
	int fail = 0;

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

		if (!test_answer_waiting(fds[i], 1000)) {
			fprintf(stderr, "connection %u was not served\n", i);
			return fail + 1;
		}
	}

	/* Those closed to make room still hand out their answer */
	for (i = 0; i < TEST_CONNS; i++) {
		if (!test_answered(fds[i], i, 0)) {
			fprintf(stderr, "the answer of connection %u was lost\n",
				i);
			fail++;
		} else if (test_closed(fds[i])) {
			closed++;
		}
	}
	if (closed < TEST_CONNS - TEST_NOFILE / 2) {
		fprintf(stderr, "only %u connections were closed\n", closed);
		fail++;
	}

	for (i = 0; i < TEST_CONNS; i++)
		close(fds[i]);

	return fail;
}

/*
 * Run @client in a process of its own: it needs more descriptors than the
 * server is allowed.
 */
static void test_clients(int (*client)(void), rlim_t nofile)
{
	struct rlimit rl = { .rlim_cur = nofile, .rlim_max = nofile };
	pid_t pid;
	int status;

	fflush(stdout);
	pid = fork();
	CHECK(pid >= 0, "cannot fork: %s", strerror(errno));
	if (pid < 0)
		return;
	if (!pid) {
		if (setrlimit(RLIMIT_NOFILE, &rl)) {
			fprintf(stderr, "cannot raise the descriptor limit\n");
			_exit(1);
		}
		_exit(client());
	}

	CHECK(waitpid(pid, &status, 0) == pid, "cannot wait for the clients");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status),
	      "the clients failed");
}

/*
 * As many connections as the server admits in total, each idle once served:
 * none is closed, whichever worker accepts it.
 */
static void test_fill(rlim_t nofile)
{
	printf("%u connections, the bound for a descriptor limit of %u\n",
	       test_conn_bound(), TEST_NOFILE);
	test_clients(test_fill_client, nofile);
}

/*
 * Many more connections than the server has descriptors for, one after the
 * other, each idle once served: every one is served, the oldest are closed -
 * but not one whose answer the client has not read yet while idle ones are
 * left.
 */
static void test_many_conns(rlim_t nofile)
{
	printf("%u connections against a descriptor limit of %u\n",
	       TEST_CONNS, TEST_NOFILE);
	test_clients(test_many_conns_client, nofile);
}

/*
 * As many connections, none of them idle as each answer stays unread: every
 * one is served all the same, and no answer is lost.
 */
static void test_unread_answers(rlim_t nofile)
{
	printf("%u connections with unread answers against a descriptor limit of %u\n",
	       TEST_CONNS, TEST_NOFILE);
	test_clients(test_unread_answers_client, nofile);
}

/*
 * The clients of test_evict_late(), each idle once served. Returns the number
 * of failures.
 */
static int test_evict_late_client(void)
{
	static int fds[TEST_CONNS];
	unsigned int i, opened;
	int fail = 0;

	for (opened = 0; opened < TEST_CONNS; opened++) {
		/*
		 * The slots are all taken from now on, the one of the test's
		 * connection among them. Its worker filled up last, and is
		 * the one to accept the next connection.
		 */
		if (opened == test_conn_bound() - 1)
			atomic_store(test_favor, TEST_FAVOR_LOCATED);

		fds[opened] = test_connect(test_unpriv_path);
		if (fds[opened] < 0) {
			fprintf(stderr, "connection %u: %s\n", opened,
				strerror(-fds[opened]));
			fail++;
			break;
		}

		if (!test_send(fds[opened], opened) ||
		    !test_answered(fds[opened], opened, 1000)) {
			fprintf(stderr, "connection %u was not served\n",
				opened);
			fail++;
			opened++;
			break;
		}
	}

	for (i = 0; i < opened; i++)
		close(fds[i]);

	return fail;
}

/*
 * A request that arrives right as the server shuts down its connection to make
 * room for a new one is still answered, and the connection closed after it.
 *
 * The connection is the first of many more than the server admits, opened one
 * after the other, and the least recently used one of its worker: that worker
 * closes it for the first one it accepts once all slots are taken. Of the
 * workers listening, the first to accept a connection takes it, and a worker
 * whose slots are taken stops listening while another has a free slot - until
 * it is woken. So its worker holds back while the slots fill up, and fills up
 * last; the others hold back from then on. If opening the connections takes
 * longer than the idle timeout, the connection is closed as idle instead.
 */
static void test_evict_late(rlim_t nofile)
{
	uint64_t start, took;
	int fd;

	printf("A request arriving as its connection is closed to make room\n");

	fd = test_connect_from(test_unpriv_path, true);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;

	atomic_store(&test_located, 0);
	CHECK(test_send_tagged(fd, 1, TEST_TAG_LOCATE) &&
		      test_answered(fd, 1, 2000),
	      "the first call was not answered");
	start = test_now_ms();

	test_late_arm(fd, 2, TEST_LATE_SHUTDOWN, 0);
	atomic_store(test_favor, TEST_FAVOR_OTHERS);
	test_clients(test_evict_late_client, nofile);
	atomic_store(test_favor, TEST_FAVOR_NONE);

	if (test_late_wait(2 * TEST_IDLE_MS + 2000)) {
		took = atomic_load(&test_late_sent_ms) - start;
		if (took >= TEST_IDLE_MS)
			printf("closed after %llu ms - as idle, not to make room\n",
			       (unsigned long long)took);
	} else {
		CHECK(false, "the connection was not closed");
	}
	CHECK(test_answered(fd, 2, 2000),
	      "the request sent as the connection was closed was lost");
	CHECK(test_closed_within(fd, 2000),
	      "the connection was not closed after the request");

	close(fd);
}

int main(void)
{
	pthread_t priv_thread, unpriv_thread;
	struct rlimit rl;
	rlim_t client_nofile = 0;
	void *favor;

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

	/* Before the workers start, which read it */
	favor = mmap(NULL, sizeof(*test_favor), PROT_READ | PROT_WRITE,
		     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (favor == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	test_favor = favor;
	atomic_store(test_favor, TEST_FAVOR_NONE);

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
	test_reap_pending();
	test_reap_late();
	test_accept_burst(client_nofile);

	if (client_nofile) {
		test_fill(client_nofile);
		test_many_conns(client_nofile);
		test_evict_late(client_nofile);
		test_unread_answers(client_nofile);
	} else
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
