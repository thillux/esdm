/*
 * Tests of the EGD server with all of its connection slots taken
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

/*
 * A user can take all connection slots of the EGD server despite the per-UID
 * bound - it connects under each UID of its subordinate range - and keep its
 * connections from ever being idle. Neither may lock anybody else out:
 *
 *   - a new client is served with all slots taken, a connection being closed
 *     to make room for it: the least recently active one of the UID holding
 *     the most, one with a request in flight only as a last resort,
 *   - with several UIDs (root only), the connection closed to make room is
 *     one of the UID holding the most, not the least recently active one of
 *     the server,
 *   - with slots short, the idle connections closed are those of the UID
 *     holding the most (root only) - a UID keeping its connections busy does
 *     not get the idle ones of everybody else closed instead,
 *   - both with a user connecting under a UID of its subordinate range for
 *     each connection (root only), from a user namespace of its own: its UIDs
 *     are one user, the one holding the most, and not each a UID holding one
 *     next to a UID holding two, which would make the latter the first to go,
 *   - root's connections are not closed for anybody, idle or not, even while
 *     root is the only one holding any (root only).
 *
 * Like egd_server_conn_test, the server runs in this process, so no daemon is
 * needed. Its build bounds it to a handful of connections, and it runs a single
 * worker: each worker makes room among the connections it serves itself, so
 * with several, which connection is closed depends on which worker accepted
 * the new client and which ones the old clients went to. The clients are
 * child processes, each under a UID of its own when the test runs as root;
 * otherwise they all share the test's UID, and the tests needing several are
 * skipped.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "threading_support.h"

/* See esdm_server_remove_stale_socket() in egd_server_raw_test.c. */
void esdm_server_remove_stale_socket(const char *path, int socktype);
int set_fd_nonblocking(int fd);

void esdm_server_remove_stale_socket(const char *path, int socktype)
{
	(void)path;
	(void)socktype;
}

int set_fd_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;

	return 0;
}

#if ESDM_EGD_MAX_CONNECTIONS > 64
#error "the test keeps track of the connections in a 64 bit mask"
#endif

#define TEST_SLOTS ESDM_EGD_MAX_CONNECTIONS

/* Backstop below the harness timeout, see egd_server_raw_test.c. */
#define TEST_WATCHDOG_SEC 120

/* How long an answer is waited for. */
#define TEST_RESPONSE_MS 10000

/*
 * Long enough for the server to have scanned for idle connections twice after
 * the timeout ran out - it scans once a second - plus room for a busy machine.
 */
#define TEST_IDLE_WAIT_MS (ESDM_EGD_IDLE_TIMEOUT_MS + 2 * 1000 + 1000)

/* Unprivileged UIDs the clients take on when the test runs as root. */
#define TEST_UID_A 60001
#define TEST_UID_B 60002

/*
 * The subordinate range of TEST_UID_B, which it maps in a user namespace of its
 * own to connect under each of its UIDs, see test_client_start_userns().
 */
#define TEST_SUB_BASE 61000
#define TEST_SUB_COUNT (TEST_SLOTS + 8)

static char tmpdir[] = "/tmp/esdm-egd-evict-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];

static int ret = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/****************************
 * Raw protocol client
 ****************************/

static int test_connect(void)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int test_send(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t written = 0;

	while (written < len) {
		ssize_t rc = send(fd, p + written, len - written, MSG_NOSIGNAL);

		if (rc > 0) {
			written += (size_t)rc;
			continue;
		}
		if (rc < 0 && errno == EINTR)
			continue;

		return -1;
	}

	return 0;
}

/* Read exactly @len bytes, see egd_server_conn_test.c. */
static int test_recv(int fd, void *buf, size_t len, int timeout_ms)
{
	uint8_t *p = buf;
	size_t received = 0;

	while (received < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t rc;
		int pret = poll(&pfd, 1, timeout_ms);

		if (pret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (pret == 0)
			return -ETIMEDOUT;

		rc = recv(fd, p + received, len - received, 0);
		if (rc > 0) {
			received += (size_t)rc;
			continue;
		}
		if (rc == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;

		return -errno;
	}

	return 0;
}

/* Command 0x00, see egd_server_conn_test.c. */
static int test_cmd_entropy_count(int fd, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint8_t resp[4];

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	return test_recv(fd, resp, sizeof(resp), timeout_ms);
}

/*
 * Did the server close the connection? Nothing else is ever readable on the
 * connections asked about: they have no request in flight, or one the ESDM
 * cannot answer as it is not operational.
 */
static bool test_closed(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int pret;

	do {
		pret = poll(&pfd, 1, 0);
	} while (pret < 0 && errno == EINTR);

	return (pret > 0);
}

/****************************
 * Client processes
 ****************************/

/*
 * A client process holding connections to the server, under a UID of its own
 * when the test runs as root. It is told what to do over a socket pair, one
 * command at a time, and answers each with a 64 bit result.
 */
struct test_client {
	pid_t pid;
	int ctl;
};

enum test_client_cmd {
	/* Open @arg more connections, each served once; result: 0 or 1 */
	test_client_open = 'o',
	/*
	 * The same, each under a UID of the user namespace of its own the
	 * client runs in, see test_client_start_userns(); result: 0 or 1
	 */
	test_client_open_sub = 's',
	/* Send a blocking read on connection @arg; result: 0 or 1 */
	test_client_block = 'b',
	/* A request on every connection from @arg on; result: failures */
	test_client_touch = 't',
	/* Which connections the server closed; result: a bit mask */
	test_client_closed = 'c',
	/* Leave; no result */
	test_client_quit = 'q',
};

struct test_client_msg {
	uint8_t cmd;
	uint32_t arg;
};

/*
 * Open a connection as @uid of the client's user namespace: from a process of
 * its own, which hands it over once it was served - by then the server has
 * accounted it, as the process it asked about - and is gone.
 *
 * @return the connection, < 0 on error
 */
static int test_connect_as(uid_t uid)
{
	char data = 0, cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { .iov_base = &data, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov,
			      .msg_iovlen = 1,
			      .msg_control = cbuf,
			      .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cmsg;
	int sv[2], fd = -1;
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (!pid) {
		close(sv[0]);
		if (setresuid(uid, uid, uid))
			_exit(1);
		fd = test_connect();
		if (fd < 0 || test_cmd_entropy_count(fd, TEST_RESPONSE_MS))
			_exit(2);

		memset(cbuf, 0, sizeof(cbuf));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		_exit(sendmsg(sv[1], &msg, 0) == 1 ? 0 : 3);
	}

	close(sv[1]);
	if (recvmsg(sv[0], &msg, MSG_CMSG_CLOEXEC) == 1) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	}
	close(sv[0]);
	waitpid(pid, NULL, 0);

	return fd;
}

static void test_client_main(int ctl, uid_t uid)
{
	int fds[TEST_SLOTS + 1];
	unsigned int n = 0, i;
	/* The next UID of its user namespace to connect as, see above */
	uid_t sub = 1;
	struct test_client_msg msg;

	if (uid != getuid()) {
		gid_t gid = (gid_t)uid;

		if (setgroups(0, NULL) || setresgid(gid, gid, gid) ||
		    setresuid(uid, uid, uid))
			_exit(2);
	}

	while (read(ctl, &msg, sizeof(msg)) == (ssize_t)sizeof(msg)) {
		uint64_t result = 0;

		switch (msg.cmd) {
		case test_client_open:
			for (i = 0; i < msg.arg; i++) {
				int fd;

				if (n >= sizeof(fds) / sizeof(fds[0])) {
					result = 1;
					break;
				}

				fd = test_connect();
				if (fd < 0 || test_cmd_entropy_count(
						      fd, TEST_RESPONSE_MS)) {
					if (fd >= 0)
						close(fd);
					result = 1;
					break;
				}
				fds[n++] = fd;
			}
			break;
		case test_client_open_sub:
			for (i = 0; i < msg.arg; i++) {
				int fd;

				if (n >= sizeof(fds) / sizeof(fds[0]) ||
				    sub >= TEST_SUB_COUNT) {
					result = 1;
					break;
				}

				fd = test_connect_as(sub++);
				if (fd < 0) {
					result = 1;
					break;
				}
				fds[n++] = fd;
			}
			break;
		case test_client_block: {
			const uint8_t cmd[2] = { ESDM_EGD_CMD_READ_BLOCK, 32 };

			result = (msg.arg >= n ||
				  test_send(fds[msg.arg], cmd, sizeof(cmd)));
			break;
		}
		case test_client_touch:
			for (i = msg.arg; i < n; i++) {
				if (test_cmd_entropy_count(fds[i],
							   TEST_RESPONSE_MS))
					result++;
			}
			break;
		case test_client_closed:
			for (i = 0; i < n; i++) {
				if (test_closed(fds[i]))
					result |= (uint64_t)1 << i;
			}
			break;
		case test_client_quit:
		default:
			_exit(0);
		}

		if (write(ctl, &result, sizeof(result)) !=
		    (ssize_t)sizeof(result))
			_exit(3);
	}

	_exit(0);
}

/*
 * Start a client under @uid. The server runs in threads of this process, which
 * the child does not have - it does nothing but talk to the server and to us.
 */
static int test_client_start(struct test_client *client, uid_t uid)
{
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -errno;

	client->pid = fork();
	if (client->pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return -errno;
	}

	if (!client->pid) {
		close(sv[0]);
		test_client_main(sv[1], uid);
	}

	close(sv[1]);
	client->ctl = sv[0];

	return 0;
}

/*
 * Start a client as @owner, the user, in a user namespace of its own, mapped to
 * @owner and to its subordinate range from TEST_SUB_BASE on - what newuidmap(1)
 * does for a user with that range in /etc/subuid. The map is written here: only
 * root may map a range. The client is root of its namespace and connects under
 * the UIDs of its range, one connection each, see test_client_open_sub. Needs
 * root.
 */
static int test_client_start_userns(struct test_client *client, uid_t owner)
{
	char map[64], path[64], b = 1;
	int sv[2], fd;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -errno;

	client->pid = fork();
	if (client->pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return -errno;
	}

	if (!client->pid) {
		close(sv[0]);
		if (setgroups(0, NULL) ||
		    setresgid((gid_t)owner, (gid_t)owner, (gid_t)owner) ||
		    setresuid(owner, owner, owner) || unshare(CLONE_NEWUSER))
			_exit(2);
		if (write(sv[1], &b, 1) != 1 || read(sv[1], &b, 1) != 1 || b)
			_exit(2);
		test_client_main(sv[1], getuid());
	}

	close(sv[1]);
	client->ctl = sv[0];

	snprintf(map, sizeof(map), "0 %u 1\n1 %u %u\n", (unsigned int)owner,
		 TEST_SUB_BASE, TEST_SUB_COUNT - 1);
	snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)client->pid);

	if (read(client->ctl, &b, 1) == 1) {
		fd = open(path, O_WRONLY | O_CLOEXEC);
		b = 1;
		if (fd >= 0) {
			if (write(fd, map, strlen(map)) == (ssize_t)strlen(map))
				b = 0;
			close(fd);
		}
	}
	if (write(client->ctl, &b, 1) != 1 || b) {
		kill(client->pid, SIGKILL);
		waitpid(client->pid, NULL, 0);
		close(client->ctl);
		client->pid = 0;
		return -EPERM;
	}

	return 0;
}

static uint64_t test_client_do(struct test_client *client, uint8_t cmd,
			       uint32_t arg)
{
	struct test_client_msg msg = { .cmd = cmd, .arg = arg };
	uint64_t result = UINT64_MAX;
	struct pollfd pfd = { .fd = client->ctl, .events = POLLIN };

	if (write(client->ctl, &msg, sizeof(msg)) != (ssize_t)sizeof(msg))
		return UINT64_MAX;

	/* Every command of the client is bounded by its answer timeout. */
	if (poll(&pfd, 1, 4 * TEST_RESPONSE_MS) != 1 ||
	    read(client->ctl, &result, sizeof(result)) !=
		    (ssize_t)sizeof(result))
		return UINT64_MAX;

	return result;
}

static void test_client_stop(struct test_client *client)
{
	struct test_client_msg msg = { .cmd = test_client_quit };

	if (client->pid <= 0)
		return;

	if (write(client->ctl, &msg, sizeof(msg)) != (ssize_t)sizeof(msg))
		kill(client->pid, SIGKILL);
	waitpid(client->pid, NULL, 0);
	close(client->ctl);
	client->pid = 0;
}

/* Number of connections in a mask of test_client_closed. */
static unsigned int test_popcount(uint64_t mask)
{
	return (unsigned int)__builtin_popcountll(mask);
}

/* Until the server released what earlier tests closed. */
static void test_settle(void)
{
	test_sleep_ms(500);
}

/****************************
 * Tests
 ****************************/

/*
 * All slots taken by one UID, and another client comes along - of the same UID
 * here, which is what a user filling the slots from the UIDs of its
 * subordinate range looks like to each of them. It has to be served, the
 * least recently active idle connection making room for it: not the one with
 * a request in flight, even though it is older, and none of the others.
 */
static void test_full_makes_room(void)
{
	struct test_client client = { 0 };
	uint64_t closed;
	int other = -1, second = -1;

	printf("EGD evict: a new client is served with all slots taken\n");

	if (esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is operational despite every entropy source being disabled\n");
		return;
	}

	if (test_client_start(&client, geteuid() ? geteuid() : TEST_UID_A)) {
		CHECK(0, "cannot start a client");
		return;
	}

	if (test_client_do(&client, test_client_open, TEST_SLOTS)) {
		CHECK(0, "the client could not take all %u slots", TEST_SLOTS);
		goto out;
	}

	/*
	 * Connection 0 waits for entropy that does not come, connection 1 is
	 * the least recently active one after it, the rest were active just
	 * now. The activity is tracked in milliseconds.
	 */
	CHECK(test_client_do(&client, test_client_block, 0) == 0,
	      "the blocking read could not be sent");
	test_sleep_ms(50);
	CHECK(test_client_do(&client, test_client_touch, 2) == 0,
	      "a connection was not served with all slots taken");

	other = test_connect();
	CHECK(other >= 0, "cannot connect to %s: %s", sockpath,
	      strerror(errno));
	if (other < 0)
		goto out;
	CHECK(test_cmd_entropy_count(other, TEST_RESPONSE_MS) == 0,
	      "a new client was not served with all slots taken");

	closed = test_client_do(&client, test_client_closed, 0);
	CHECK(closed == 2,
	      "not exactly the least recently active idle connection was closed to make room: mask 0x%llx",
	      (unsigned long long)closed);

	/* And again, the next one in line - the new client is the newest. */
	second = test_connect();
	CHECK(second >= 0 &&
		      test_cmd_entropy_count(second, TEST_RESPONSE_MS) == 0,
	      "a second new client was not served with all slots taken");
	closed = test_client_do(&client, test_client_closed, 0);
	CHECK(test_popcount(closed) == 2 && (closed & 2) && !(closed & 1),
	      "the second client did not make room with an idle connection: mask 0x%llx",
	      (unsigned long long)closed);

out:
	if (second >= 0)
		close(second);
	if (other >= 0)
		close(other);
	test_client_stop(&client);
	test_settle();
}

/*
 * The same with two UIDs, the one with fewer connections being the least
 * recently active one: the connection closed is one of the UID holding the
 * most all the same. Needs root for the UIDs.
 */
static void test_full_top_uid(void)
{
	struct test_client a = { 0 }, b = { 0 };
	unsigned int a_conns = 3, b_conns = TEST_SLOTS - 3;
	uint64_t closed_a, closed_b;
	int other;

	printf("EGD evict: room is made by the UID holding the most\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: several UIDs need root\n");
		return;
	}

	if (test_client_start(&a, TEST_UID_A) ||
	    test_client_start(&b, TEST_UID_B)) {
		CHECK(0, "cannot start the clients");
		goto out;
	}

	if (test_client_do(&a, test_client_open, a_conns) ||
	    test_client_do(&b, test_client_open, b_conns)) {
		CHECK(0, "the clients could not take all %u slots", TEST_SLOTS);
		goto out;
	}

	test_sleep_ms(50);
	CHECK(test_client_do(&b, test_client_touch, 0) == 0,
	      "a connection was not served with all slots taken");

	other = test_connect();
	CHECK(other >= 0 &&
		      test_cmd_entropy_count(other, TEST_RESPONSE_MS) == 0,
	      "a new client was not served with all slots taken");

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "a connection of the UID holding the fewest was closed: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(test_popcount(closed_b) == 1,
	      "not exactly one connection of the UID holding the most was closed: mask 0x%llx",
	      (unsigned long long)closed_b);

	if (other >= 0)
		close(other);

out:
	test_client_stop(&a);
	test_client_stop(&b);
	test_settle();
}

/*
 * Slots are short, and the UID holding the most keeps its connections busy:
 * the idle ones of another UID are not closed in their stead. Once it lets its
 * own go idle, those are closed - and only as many as bring the server below
 * its reaping mark. Needs root for the UIDs.
 */
static void test_scarce_top_uid(void)
{
	struct test_client a = { 0 }, b = { 0 };
	unsigned int a_conns = 2, b_conns = ESDM_EGD_IDLE_REAP_CONNECTIONS;
	uint64_t closed_a, closed_b, deadline;

	printf("EGD evict: with slots short, the idle connections of the UID holding the most go\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: several UIDs need root\n");
		return;
	}

	if (test_client_start(&a, TEST_UID_A) ||
	    test_client_start(&b, TEST_UID_B)) {
		CHECK(0, "cannot start the clients");
		goto out;
	}

	if (test_client_do(&a, test_client_open, a_conns) ||
	    test_client_do(&b, test_client_open, b_conns)) {
		CHECK(0, "the clients could not open their connections");
		goto out;
	}

	/* B is never idle for long, A never active. */
	deadline = test_now_ms() + TEST_IDLE_WAIT_MS;
	while (test_now_ms() < deadline) {
		test_sleep_ms(ESDM_EGD_IDLE_TIMEOUT_MS / 4);
		if (test_client_do(&b, test_client_touch, 0)) {
			CHECK(0, "a busy connection was not served");
			break;
		}
	}

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "idle connections of a UID holding few were closed for one keeping its own busy: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(closed_b == 0, "busy connections were closed: mask 0x%llx",
	      (unsigned long long)closed_b);

	/* Now B lets its own go idle. */
	test_sleep_ms(TEST_IDLE_WAIT_MS);

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "idle connections of the UID holding the fewest were closed: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(test_popcount(closed_b) == a_conns + 1,
	      "%u idle connections of the UID holding the most were closed, not the %u to get below the mark",
	      test_popcount(closed_b), a_conns + 1);

out:
	test_client_stop(&a);
	test_client_stop(&b);
	test_settle();
}

/*
 * All slots taken by a user connecting under a UID of its subordinate range
 * for each connection, which holds one per UID, and by a UID holding two - as
 * sshd's pre-authentication children do. A new connection of the user costs it
 * one of its own: its UIDs are one account, the biggest holder, rather than
 * each a holder of one next to the UID holding two. Needs root for the UIDs.
 */
static void test_full_subordinate(void)
{
	struct test_client a = { 0 }, b = { 0 };
	unsigned int a_conns = 2, b_conns = TEST_SLOTS - 2;
	uint64_t closed_a, closed_b;

	printf("EGD evict: the UIDs of a subordinate range make room as one user\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: several UIDs need root\n");
		return;
	}

	if (test_client_start(&a, TEST_UID_A) ||
	    test_client_start_userns(&b, TEST_UID_B)) {
		CHECK(0, "cannot start the clients");
		goto out;
	}

	/* A's connections are the least recently active ones. */
	if (test_client_do(&a, test_client_open, a_conns) ||
	    test_client_do(&b, test_client_open_sub, b_conns)) {
		CHECK(0, "the clients could not take all %u slots", TEST_SLOTS);
		goto out;
	}

	test_sleep_ms(50);
	CHECK(test_client_do(&b, test_client_open_sub, 1) == 0,
	      "a new connection under another subordinate UID was not served with all slots taken");

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "a connection of a UID holding two was closed for a user holding one per subordinate UID: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(test_popcount(closed_b) == 1,
	      "not exactly one connection of the user holding the most was closed: mask 0x%llx",
	      (unsigned long long)closed_b);

out:
	test_client_stop(&a);
	test_client_stop(&b);
	test_settle();
}

/*
 * Slots are short, held by a user under a UID of its subordinate range for
 * each busy connection, and by a UID with two idle ones: those are not closed
 * for being the UID holding the most - the user is. Once it lets its own go
 * idle, those are closed. Needs root for the UIDs.
 */
static void test_scarce_subordinate(void)
{
	struct test_client a = { 0 }, b = { 0 };
	unsigned int a_conns = 2, b_conns = ESDM_EGD_IDLE_REAP_CONNECTIONS;
	uint64_t closed_a, closed_b, deadline;

	printf("EGD evict: with slots short, the UIDs of a subordinate range are reaped as one user\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: several UIDs need root\n");
		return;
	}

	if (test_client_start(&a, TEST_UID_A) ||
	    test_client_start_userns(&b, TEST_UID_B)) {
		CHECK(0, "cannot start the clients");
		goto out;
	}

	if (test_client_do(&a, test_client_open, a_conns) ||
	    test_client_do(&b, test_client_open_sub, b_conns)) {
		CHECK(0, "the clients could not open their connections");
		goto out;
	}

	/* B is never idle for long, A never active. */
	deadline = test_now_ms() + TEST_IDLE_WAIT_MS;
	while (test_now_ms() < deadline) {
		test_sleep_ms(ESDM_EGD_IDLE_TIMEOUT_MS / 4);
		if (test_client_do(&b, test_client_touch, 0)) {
			CHECK(0, "a busy connection was not served");
			break;
		}
	}

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "idle connections of a UID holding two were closed for a user holding one per subordinate UID: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(closed_b == 0, "busy connections were closed: mask 0x%llx",
	      (unsigned long long)closed_b);

	/* Now B lets its own go idle. */
	test_sleep_ms(TEST_IDLE_WAIT_MS);

	closed_a = test_client_do(&a, test_client_closed, 0);
	closed_b = test_client_do(&b, test_client_closed, 0);
	CHECK(closed_a == 0,
	      "idle connections of the UID holding the fewest were closed: mask 0x%llx",
	      (unsigned long long)closed_a);
	CHECK(test_popcount(closed_b) == a_conns + 1,
	      "%u idle connections of the user holding the most were closed, not the %u to get below the mark",
	      test_popcount(closed_b), a_conns + 1);

out:
	test_client_stop(&a);
	test_client_stop(&b);
	test_settle();
}

/*
 * How a new client of @uid, root to stay root, fares while all slots are taken
 * by connections that may not be closed for it: 0 when it is left waiting in
 * the backlog, 1 when it is accepted only to be closed, 2 when it is served,
 * 3 on errors. From a process of its own, which may take on another UID.
 */
static int test_newcomer(uid_t uid)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return 3;

	if (!pid) {
		int fd, rc;

		if (uid && (setgroups(0, NULL) ||
			    setresgid((gid_t)uid, (gid_t)uid, (gid_t)uid) ||
			    setresuid(uid, uid, uid)))
			_exit(3);
		fd = test_connect();
		if (fd < 0)
			_exit(3);
		rc = test_cmd_entropy_count(fd, 1500);
		_exit(rc == -ETIMEDOUT ? 0 : (rc ? 1 : 2));
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return 3;

	return WEXITSTATUS(status);
}

/*
 * All slots taken by root, the only one holding any: none of its connections
 * is closed, neither for a new client of its own nor for one of anybody else,
 * nor while they sit idle with slots short - root holds none by the count that
 * picks the connections to close. The new clients are left waiting rather
 * than accepted only to be turned away. Needs root.
 */
static void test_full_root(void)
{
	struct test_client r = { 0 };
	uint64_t closed;
	int rc;

	printf("EGD evict: root's connections are not closed for anybody\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: needs root\n");
		return;
	}

	if (test_client_start(&r, 0)) {
		CHECK(0, "cannot start a client");
		return;
	}

	if (test_client_do(&r, test_client_open, TEST_SLOTS)) {
		CHECK(0, "the client could not take all %u slots", TEST_SLOTS);
		goto out;
	}

	/* Idle, with slots short. */
	test_sleep_ms(TEST_IDLE_WAIT_MS);
	closed = test_client_do(&r, test_client_closed, 0);
	CHECK(closed == 0,
	      "idle connections of root's were closed with slots short: mask 0x%llx",
	      (unsigned long long)closed);

	rc = test_newcomer(0);
	CHECK(rc == 0,
	      "a new client of root's was not left waiting with all slots root's: %d",
	      rc);
	rc = test_newcomer(TEST_UID_A);
	CHECK(rc == 0,
	      "a new client was not left waiting with all slots root's: %d",
	      rc);

	closed = test_client_do(&r, test_client_closed, 0);
	CHECK(closed == 0,
	      "a connection of root's was closed for a new client: mask 0x%llx",
	      (unsigned long long)closed);

out:
	test_client_stop(&r);
	test_settle();
}

/****************************
 * ESDM state
 ****************************/

/*
 * Take every entropy source out of the picture, so that the ESDM stays
 * non-operational and a blocking read keeps waiting.
 */
static void test_esdm_disable_es(void)
{
	esdm_config_es_cpu_entropy_rate_set(0);
	esdm_config_es_jent_entropy_rate_set(0);
	esdm_config_es_jent_kernel_entropy_rate_set(0);
	esdm_config_es_krng_entropy_rate_set(0);
	esdm_config_es_irq_entropy_rate_set(0);
	esdm_config_es_irq_ebpf_entropy_rate_set(0);
	esdm_config_es_sched_entropy_rate_set(0);
	esdm_config_es_sched_ebpf_entropy_rate_set(0);
	esdm_config_es_hwrand_entropy_rate_set(0);
	esdm_config_es_tpm2_entropy_rate_set(0);
	esdm_config_es_pkcs11_entropy_rate_set(0);
}

int main(int argc, char *argv[])
{
	int rc;

	(void)argc;
	(void)argv;

	/* Unbuffered and with a watchdog, see egd_server_raw_test.c. */
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(TEST_WATCHDOG_SEC);
	signal(SIGPIPE, SIG_IGN);

	esdm_logger_set_verbosity(LOGGER_WARN);

	/* One EGD worker, see above - the server starts one per node. */
	esdm_config_max_nodes_set(1);

	test_esdm_disable_es();

	rc = esdm_init();
	if (rc) {
		printf("esdm_init() failed: %d\n", rc);
		return 1;
	}

	rc = thread_init(1);
	if (rc) {
		printf("thread_init() failed: %d\n", rc);
		esdm_fini();
		return 1;
	}

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		esdm_fini();
		return 1;
	}
	/* Clients of other UIDs have to get to the socket. */
	if (chmod(tmpdir, 0755) < 0) {
		printf("Cannot open up the temporary directory: %s\n",
		       strerror(errno));
		ret = 1;
		goto out;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (esdm_egd_server_enable(sockpath) || esdm_egd_server_socket_init() ||
	    esdm_egd_server_start()) {
		printf("Cannot serve the EGD socket %s\n", sockpath);
		ret = 1;
		goto out;
	}

	test_full_makes_room();
	test_full_top_uid();
	test_scarce_top_uid();
	test_full_subordinate();
	test_scarce_subordinate();
	test_full_root();

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD server with its slots taken: %s\n",
	       ret ? "FAILED" : "passed");

	return ret;
}
