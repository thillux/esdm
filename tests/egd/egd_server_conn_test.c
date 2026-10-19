/*
 * Connection lifecycle tests of the EGD server
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
 * How the EGD server deals with the end of a connection - the client's or its
 * own. Like egd_server_raw_test, the server runs in this process and is spoken
 * to in raw protocol bytes, so no daemon and no privileges are needed.
 *
 * The end on the server's side is the closing of an idle connection, which is
 * only to happen when its slot is wanted. This build lets idle connections
 * time out after a second and puts the per-UID connection limit within the
 * test's reach.
 *
 * The insertion command has no response, so whether the server took what a
 * client sent cannot be seen on the socket. The build of this test renames the
 * server's call into the auxiliary pool to test_pool_insert_aux() below, which
 * counts the bytes on their way through - and can slow the pool down, so that
 * clients flooding it are sure to outpace it, see test_flood(). Its calls
 * rendering a status report and waiting for the events of a round are renamed
 * likewise, see test_status_budget().
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "threading_support.h"

/* The real ones, which the build renamed in esdm.h above. */
#undef esdm_pool_insert_aux
int esdm_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits);
#undef esdm_status
int esdm_status(char *buf, size_t buflen);
#undef esdm_status_json
int esdm_status_json(char *buf, size_t buflen);
#undef epoll_wait
int epoll_wait(int epfd, struct epoll_event *events, int maxevents,
	       int timeout);

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

/* Bytes the server handed to the auxiliary pool. */
static atomic_size_t test_inserted;

/* Time each insertion takes on top, in microseconds. */
static atomic_uint test_insert_delay_us;

/*
 * What lies behind the data of an insertion in the server's input buffer, see
 * test_input_wiped(): the length of the insertion to look behind, 0 for none,
 * how many bytes to look at, and whether one was seen and found anything.
 */
static atomic_uint test_probe_len;
static atomic_uint test_probe_span;
static atomic_bool test_probe_seen;
static atomic_bool test_probe_stale;

int test_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits);
int test_pool_insert_aux(const uint8_t *inbuf, size_t inbuflen,
			 uint32_t entropy_bits)
{
	unsigned int delay_us = atomic_load(&test_insert_delay_us);
	unsigned int probe_len = atomic_load(&test_probe_len);
	int rc = esdm_pool_insert_aux(inbuf, inbuflen, entropy_bits);

	if (probe_len && inbuflen == probe_len) {
		unsigned int i, span = atomic_load(&test_probe_span);
		bool stale = false;

		for (i = 0; i < span; i++)
			stale |= (inbuf[inbuflen + i] != 0);

		atomic_store(&test_probe_stale, stale);
		atomic_store(&test_probe_seen, true);
	}

	if (delay_us) {
		struct timespec ts = { .tv_sec = 0,
				       .tv_nsec = (long)delay_us * 1000 };

		nanosleep(&ts, NULL);
	}

	atomic_fetch_add(&test_inserted, inbuflen);

	return rc;
}

/*
 * Status reports the server rendered in the current round of the event loop of
 * the calling worker - which begins with its wait for the events of the round -
 * the most in any one round, and in total. See test_status_budget().
 */
static __thread unsigned int test_round_reports;
static atomic_uint test_round_reports_max;
static atomic_uint test_reports;

int test_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
		    int timeout);
int test_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
		    int timeout)
{
	test_round_reports = 0;

	return epoll_wait(epfd, events, maxevents, timeout);
}

static void test_report_rendered(void)
{
	unsigned int n = ++test_round_reports;
	unsigned int max = atomic_load(&test_round_reports_max);

	while (n > max &&
	       !atomic_compare_exchange_weak(&test_round_reports_max, &max, n))
		;

	atomic_fetch_add(&test_reports, 1);
}

int test_status(char *buf, size_t buflen);
int test_status(char *buf, size_t buflen)
{
	test_report_rendered();

	return esdm_status(buf, buflen);
}

int test_status_json(char *buf, size_t buflen);
int test_status_json(char *buf, size_t buflen)
{
	test_report_rendered();

	return esdm_status_json(buf, buflen);
}

/* Backstop below the harness timeout, see egd_server_raw_test.c. */
#define TEST_WATCHDOG_SEC 120

/* How long an answer - or an insertion - is waited for. */
#define TEST_RESPONSE_MS 10000

/* How long the absence of an answer is checked for. */
#define TEST_SILENCE_MS 750

static char tmpdir[] = "/tmp/esdm-egd-conn-test-XXXXXX";
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

/* A SIGPIPE can only come from the server, see egd_server_raw_test.c. */
static volatile sig_atomic_t test_sigpipe;

static void test_sigpipe_handler(int sig)
{
	(void)sig;
	test_sigpipe = 1;
}

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

/* MSG_NOSIGNAL for the reason given in egd_server_raw_test.c. */
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

/*
 * Read exactly @len bytes.
 *
 * @return 0 on success, -ETIMEDOUT when the peer went quiet, -EPIPE when it
 *	   closed the connection, negative errno otherwise
 */
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

/* Did the peer stay quiet for @timeout_ms? A closed connection is not quiet. */
static bool test_quiet(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int pret;

	do {
		pret = poll(&pfd, 1, timeout_ms);
	} while (pret < 0 && errno == EINTR);

	return (pret == 0);
}

/* Command 0x00: the available entropy as a 4 byte big endian bit count. */
static int test_cmd_entropy_count(int fd, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint8_t resp[4];

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	return test_recv(fd, resp, sizeof(resp), timeout_ms);
}

/*
 * Command 0x03 with @len bytes and no entropy claim. A claim is honored for
 * root, and credited data could take the ESDM operational, which
 * test_hangup_deferred() relies on it not being.
 */
static int test_send_write_entropy(int fd, uint8_t len)
{
	uint8_t cmd[4 + ESDM_EGD_MAX_TRANSFER];
	unsigned int i;

	cmd[0] = ESDM_EGD_CMD_WRITE_ENTROPY;
	cmd[1] = 0;
	cmd[2] = 0;
	cmd[3] = len;
	for (i = 0; i < len; i++)
		cmd[4 + i] = (uint8_t)i;

	return test_send(fd, cmd, 4 + (size_t)len);
}

/* Wait until the server inserted @expected bytes in total. */
static bool test_wait_inserted(size_t expected)
{
	uint64_t deadline = test_now_ms() + TEST_RESPONSE_MS;

	while (atomic_load(&test_inserted) < expected) {
		if (test_now_ms() > deadline)
			return false;
		test_sleep_ms(10);
	}

	return true;
}

/* The server still serves a new client right away. */
static void test_server_alive(const char *after)
{
	int other = test_connect();

	CHECK(other >= 0, "the server stopped accepting clients after %s",
	      after);
	if (other < 0)
		return;

	CHECK(test_cmd_entropy_count(other, TEST_RESPONSE_MS) == 0,
	      "the server stopped serving after %s", after);
	close(other);
}

/****************************
 * Tests
 ****************************/

/* The umask the server's socket is created under, see test_socket_mode(). */
#define TEST_UMASK 0077

/*
 * The socket is everybody's, whatever the umask of the process creating it -
 * and without a chmod(2) of its path after the fact, which runs as root and
 * would follow a symlink swapped in meanwhile. That is only seen in the mode
 * coming out right under a umask that would strip it, and in the umask of the
 * process being the one it had before: the server clears the umask for the
 * bind in a thread of its own, not for the process.
 */
static void test_socket_mode(void)
{
	struct stat sb;
	mode_t mask;

	printf("EGD conn: the socket is created accessible to all\n");

	CHECK(lstat(sockpath, &sb) == 0, "cannot stat %s: %s", sockpath,
	      strerror(errno));
	CHECK(S_ISSOCK(sb.st_mode), "%s is not a socket", sockpath);
	CHECK((sb.st_mode & 07777) == 0666,
	      "the socket was created with mode %04o, not 0666, under umask %04o",
	      (unsigned int)(sb.st_mode & 07777), (unsigned int)TEST_UMASK);

	mask = umask(TEST_UMASK);
	CHECK(mask == TEST_UMASK,
	      "creating the socket changed the umask of the process to %04o",
	      (unsigned int)mask);
}

/*
 * A feeder that hands over its data and exits - writing and closing back to
 * back, without waiting for anything since the command has no answer. Its
 * hangup reaches the server together with the data, more often than not before
 * the server got around to reading it, and the data has to count regardless.
 */
static void test_hangup_after_write(void)
{
#define TEST_FEEDERS 32
	size_t expected = atomic_load(&test_inserted);
	unsigned int i;

	printf("EGD conn: clients that write and close right away\n");

	for (i = 0; i < TEST_FEEDERS; i++) {
		int fd = test_connect();

		if (fd < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			return;
		}

		CHECK(test_send_write_entropy(fd, ESDM_EGD_MAX_TRANSFER) == 0,
		      "the insertion could not be sent");
		CHECK(test_send_write_entropy(fd, 16) == 0,
		      "the second insertion could not be sent");
		close(fd);

		expected += ESDM_EGD_MAX_TRANSFER + 16;
	}

	CHECK(test_wait_inserted(expected),
	      "%zu of %zu bytes written by clients that closed right away were inserted",
	      atomic_load(&test_inserted), expected);

	test_server_alive("the feeders left");
#undef TEST_FEEDERS
}

/*
 * The same with an answer pending: a request is in the stream before the
 * insertion and the client closes without reading. The server may get the
 * answer out before the close or not - whether it does decides between a
 * hangup and a connection reset on its side, and neither may cost the
 * insertion behind it.
 */
static void test_hangup_after_pipelined_request(void)
{
	const uint8_t count = ESDM_EGD_CMD_ENTROPY_COUNT;
	const uint8_t pid = ESDM_EGD_CMD_GET_PID;
	size_t expected = atomic_load(&test_inserted);
	unsigned int i;

	printf("EGD conn: clients that ask, write and close without reading\n");

	for (i = 0; i < 16; i++) {
		int fd = test_connect();

		if (fd < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			return;
		}

		CHECK(test_send(fd, &count, 1) == 0 &&
			      test_send_write_entropy(fd, 32) == 0 &&
			      test_send(fd, &pid, 1) == 0 &&
			      test_send_write_entropy(fd, 64) == 0,
		      "the pipelined commands could not be sent");

		/* Every other one gives the server time to answer first. */
		if (i & 1)
			test_sleep_ms(20);
		close(fd);

		expected += 32 + 64;
	}

	CHECK(test_wait_inserted(expected),
	      "%zu of %zu bytes written behind a request were inserted",
	      atomic_load(&test_inserted), expected);

	test_server_alive("clients left with answers unread");
}

/*
 * The deterministic case: a blocking read that waits for entropy the ESDM does
 * not have holds back everything behind it, so the insertion sent after it is
 * still in the socket when the client hangs up - the hangup is the only event
 * the server gets for it. The request is to be dropped with the client rather
 * than tie up the worker until the ESDM becomes operational.
 */
static void test_hangup_deferred(void)
{
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_BLOCK, 32 };
	size_t expected;
	int fd;

	printf("EGD conn: a client with a waiting request writes and closes\n");

	if (esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is operational despite every entropy source being disabled\n");
		return;
	}

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, cmd, sizeof(cmd)) == 0,
	      "the blocking read could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the blocking read was answered by an ESDM that is not operational");

	expected = atomic_load(&test_inserted) + ESDM_EGD_MAX_TRANSFER;
	CHECK(test_send_write_entropy(fd, ESDM_EGD_MAX_TRANSFER) == 0,
	      "the insertion could not be sent");

	/* Held back behind the request, as it has to be. */
	test_sleep_ms(TEST_SILENCE_MS);
	CHECK(atomic_load(&test_inserted) < expected,
	      "the insertion overtook the waiting request");

	close(fd);

	CHECK(test_wait_inserted(expected),
	      "the insertion behind a waiting request was lost with the client");

	test_server_alive("a client with a waiting request left");
}

/*
 * Long enough for the server to have scanned for idle connections twice after
 * the timeout ran out - it scans once a second - plus room for a busy machine.
 */
#define TEST_IDLE_WAIT_MS (ESDM_EGD_IDLE_TIMEOUT_MS + 2 * 1000 + 1000)

/*
 * A connection idle for longer than the timeout is left alone while the server
 * has slots and descriptors to spare: the consumers holding a connection for
 * their whole lifetime and using it rarely are the sandboxed ones that cannot
 * connect again.
 */
static void test_idle_kept(void)
{
	int fd;

	printf("EGD conn: an idle connection is kept while nobody needs its slot\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_entropy_count(fd, TEST_RESPONSE_MS) == 0,
	      "a new connection was not served");
	CHECK(test_quiet(fd, TEST_IDLE_WAIT_MS),
	      "an idle connection was closed with slots to spare");
	CHECK(test_cmd_entropy_count(fd, TEST_RESPONSE_MS) == 0,
	      "a connection that sat idle was not served any more");

	close(fd);
}

/*
 * A UID that wants more connections than its limit gets its idle ones closed -
 * the slots of its own clients that abandoned them without closing - and only
 * then, not merely because it is at its limit.
 */
static void test_idle_uid_exhausted(void)
{
#define TEST_UID_CONNECTIONS ESDM_EGD_MAX_CONNECTIONS_PER_UID
	int fds[TEST_UID_CONNECTIONS];
	unsigned int i, n = 0, closed = 0;
	uint8_t byte;
	int refused;

	printf("EGD conn: idle connections of a UID at its limit\n");

	if (geteuid() == 0) {
		printf("  SKIPPED: root is not subject to the per-UID limit\n");
		return;
	}

	/* Whatever the tests above closed has to be released by the server. */
	test_sleep_ms(500);

	for (n = 0; n < TEST_UID_CONNECTIONS; n++) {
		fds[n] = test_connect();
		if (fds[n] < 0 ||
		    test_cmd_entropy_count(fds[n], TEST_RESPONSE_MS)) {
			CHECK(0, "connection %u of %u was not served", n + 1,
			      TEST_UID_CONNECTIONS);
			if (fds[n] >= 0)
				close(fds[n]);
			goto out;
		}
	}

	/* At the limit, but nobody was refused: no reason to close any. */
	for (i = 0; i < n; i++) {
		if (!test_quiet(fds[i], i ? 0 : TEST_IDLE_WAIT_MS)) {
			CHECK(0,
			      "an idle connection of a UID at its limit was closed before it was refused one");
			break;
		}
	}

	/* One more is refused - the server closes it right away. */
	refused = test_connect();
	if (refused >= 0) {
		CHECK(test_recv(refused, &byte, sizeof(byte),
				TEST_RESPONSE_MS) == -EPIPE,
		      "a connection beyond the UID's limit was not refused");
		close(refused);
	}

	/* And now the slots of its idle connections are wanted. */
	test_sleep_ms(TEST_IDLE_WAIT_MS);
	for (i = 0; i < n; i++) {
		if (!test_quiet(fds[i], 0))
			closed++;
	}
	CHECK(closed > 0,
	      "no idle connection was closed for a UID refused at its limit");
	printf("  %u of %u idle connections closed\n", closed, n);

	/* The slot is the UID's again. */
	refused = test_connect();
	CHECK(refused >= 0 &&
		      test_cmd_entropy_count(refused, TEST_RESPONSE_MS) == 0,
	      "the UID was not served again after its idle connections were closed");
	if (refused >= 0)
		close(refused);

out:
	while (n--)
		close(fds[n]);
#undef TEST_UID_CONNECTIONS
}

/*
 * No copy of what a client inserted lingers in the server's input buffer.
 * Consuming a command moves what follows it - the beginning of the next
 * insertion, say - to the front of the buffer, and the bytes it was moved from
 * have to be wiped as well as the command itself.
 *
 * The insertion wrapper looks for them: the second insertion arrives in two
 * parts, the first together with the insertion before it, and is the only
 * command in the buffer by the time it is inserted. Behind its data, as far as
 * the first part reached, nothing but wiped memory may follow - the copy of the
 * first part left at its old offset otherwise.
 */
static void test_input_wiped(void)
{
#define TEST_FIRST 250
#define TEST_SECOND 201
#define TEST_SECOND_PART 100
	uint8_t stream[4 + TEST_FIRST + 4 + TEST_SECOND];
	const size_t split = 4 + TEST_FIRST + 4 + TEST_SECOND_PART;
	size_t expected = atomic_load(&test_inserted);
	unsigned int i;
	int fd;

	printf("EGD conn: inserted data does not linger in the input buffer\n");

	/* Without an entropy claim, and none of the data bytes zero. */
	memset(stream, 0, sizeof(stream));
	stream[0] = ESDM_EGD_CMD_WRITE_ENTROPY;
	stream[3] = TEST_FIRST;
	for (i = 0; i < TEST_FIRST; i++)
		stream[4 + i] = (uint8_t)(i | 0x80);
	stream[4 + TEST_FIRST] = ESDM_EGD_CMD_WRITE_ENTROPY;
	stream[4 + TEST_FIRST + 3] = TEST_SECOND;
	for (i = 0; i < TEST_SECOND; i++)
		stream[4 + TEST_FIRST + 4 + i] = (uint8_t)(i | 0x40);

	atomic_store(&test_probe_span, (unsigned int)(split - 4 - TEST_SECOND));
	atomic_store(&test_probe_seen, false);
	atomic_store(&test_probe_stale, false);
	atomic_store(&test_probe_len, TEST_SECOND);

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		goto out;
	}

	/*
	 * The first insertion with the first part of the second, then the rest
	 * of it once the first went in - and with it the move.
	 */
	CHECK(test_send(fd, stream, split) == 0,
	      "the first insertion could not be sent");
	CHECK(test_wait_inserted(expected + TEST_FIRST),
	      "the first insertion was not inserted");
	CHECK(test_send(fd, stream + split, sizeof(stream) - split) == 0,
	      "the rest of the second insertion could not be sent");
	CHECK(test_wait_inserted(expected + TEST_FIRST + TEST_SECOND),
	      "the second insertion was not inserted");

	CHECK(atomic_load(&test_probe_seen),
	      "the second insertion did not reach the pool");
	CHECK(!atomic_load(&test_probe_stale),
	      "a copy of the second insertion lingers in the input buffer");

	close(fd);

out:
	atomic_store(&test_probe_len, 0);
#undef TEST_FIRST
#undef TEST_SECOND
#undef TEST_SECOND_PART
}

/*
 * A status report is asked for with a single byte but takes long to render, so
 * a client pipelining the command and draining the answers would have the
 * worker render reports for as many bytes as it reads in a round, and hold up
 * everybody else on it meanwhile. One report is rendered per connection and
 * round, the rest in the rounds that follow - in order, all of them.
 *
 * The reports asked for all fit into the socket, so without that bound they
 * are all rendered in the round that reads them.
 */
static void test_status_budget(void)
{
#define TEST_REPORTS 8
	uint8_t cmds[TEST_REPORTS];
	unsigned int i, reports = atomic_load(&test_reports), answered = 0;
	char *report = malloc(ESDM_EGD_MAX_STATUS);
	int fd;

	printf("EGD conn: one status report per connection and round\n");

	if (!report) {
		CHECK(0, "no memory for the reports");
		return;
	}

	/* Text and JSON alternating, which share the budget */
	for (i = 0; i < TEST_REPORTS; i++)
		cmds[i] = (i & 1) ? ESDM_EGD_CMD_ESDM_STATUS_JSON :
				    ESDM_EGD_CMD_ESDM_STATUS;

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		goto out;
	}

	atomic_store(&test_round_reports_max, 0);

	CHECK(test_send(fd, cmds, sizeof(cmds)) == 0,
	      "the status requests could not be sent");

	for (i = 0; i < TEST_REPORTS; i++) {
		uint8_t hdr[4];
		uint32_t len;

		if (test_recv(fd, hdr, sizeof(hdr), TEST_RESPONSE_MS))
			break;
		len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
		      ((uint32_t)hdr[2] << 8) | hdr[3];
		if (len > ESDM_EGD_MAX_STATUS ||
		    (len && test_recv(fd, report, len, TEST_RESPONSE_MS)))
			break;
		answered++;
	}

	CHECK(answered == TEST_REPORTS, "%u of %u status requests answered",
	      answered, TEST_REPORTS);
	CHECK(atomic_load(&test_reports) - reports == TEST_REPORTS,
	      "%u reports rendered for %u requests",
	      atomic_load(&test_reports) - reports, TEST_REPORTS);
	CHECK(atomic_load(&test_round_reports_max) == 1,
	      "%u status reports rendered in one round",
	      atomic_load(&test_round_reports_max));

	/* And the connection is in step still */
	CHECK(test_cmd_entropy_count(fd, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over the reports");

	close(fd);

out:
	free(report);
#undef TEST_REPORTS
}

struct test_flooder {
	int fd;
	pthread_t thread;
};

/* Insertions without a pause, until the socket is shut down under it. */
static void *test_flood_thread(void *arg)
{
#define TEST_FLOOD_CMD 5
	struct test_flooder *flooder = arg;
	uint8_t cmds[1024 * TEST_FLOOD_CMD];
	size_t i;

	/* One byte each, without a claim - see test_send_write_entropy(). */
	for (i = 0; i < sizeof(cmds); i += TEST_FLOOD_CMD) {
		cmds[i] = ESDM_EGD_CMD_WRITE_ENTROPY;
		cmds[i + 1] = 0;
		cmds[i + 2] = 0;
		cmds[i + 3] = 1;
		cmds[i + 4] = (uint8_t)i;
	}

	while (!test_send(flooder->fd, cmds, sizeof(cmds)))
		;

	return NULL;
#undef TEST_FLOOD_CMD
}

/*
 * Clients streaming insertions faster than the server inserts them.
 *
 * An insertion has no response, so such a client never fills its own socket
 * and never stops being readable: a worker reading it until it runs dry is held
 * by it for good, and so is every other client of that worker. More flooders
 * than workers - a held worker accepts nobody, so each would end up held and
 * the next client never be accepted. It has to be served all the same.
 */
static void test_flood(void)
{
#define TEST_FLOODERS (2 * ESDM_THREAD_EGD_SLOTS)
	struct test_flooder flooders[TEST_FLOODERS];
	unsigned int i, started = 0;
	uint64_t start, deadline;
	size_t inserted;
	int other;

	printf("EGD conn: clients flooding the server with insertions\n");

	/*
	 * A pool slower than any client on any machine. The sleep comes on
	 * top of the insertion, and rounds up to the timer slack.
	 */
	atomic_store(&test_insert_delay_us, 20);

	for (i = 0; i < TEST_FLOODERS; i++) {
		/*
		 * The kernel's minimum. What a flooder has in flight is
		 * drained after the flood, and a default sized buffer holds
		 * tens of thousands of insertions - more than a sanitizer and
		 * coverage build inserts in the time waited for them below.
		 */
		int sndbuf = 1;

		flooders[i].fd = test_connect();
		if (flooders[i].fd < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			break;
		}

		if (setsockopt(flooders[i].fd, SOL_SOCKET, SO_SNDBUF, &sndbuf,
			       sizeof(sndbuf)) < 0) {
			CHECK(0, "cannot shrink a flooder's buffer: %s",
			      strerror(errno));
			close(flooders[i].fd);
			break;
		}

		if (pthread_create(&flooders[i].thread, NULL,
				   test_flood_thread, &flooders[i])) {
			CHECK(0, "cannot start a flooding client");
			close(flooders[i].fd);
			break;
		}
		started++;
	}

	/* Accepted, and well under way. */
	test_sleep_ms(500);

	other = test_connect();
	CHECK(other >= 0, "cannot connect to %s: %s", sockpath,
	      strerror(errno));
	if (other >= 0) {
		start = test_now_ms();
		CHECK(test_cmd_entropy_count(other, TEST_RESPONSE_MS) == 0,
		      "a client was not served while others flood the server");
		printf("  served within %llu ms\n",
		       (unsigned long long)(test_now_ms() - start));
		close(other);
	}

	/* A send blocked on a full socket returns EPIPE on the shutdown. */
	atomic_store(&test_insert_delay_us, 0);
	for (i = 0; i < started; i++)
		shutdown(flooders[i].fd, SHUT_RDWR);
	for (i = 0; i < started; i++) {
		pthread_join(flooders[i].thread, NULL);
		close(flooders[i].fd);
	}

	/*
	 * The server drains what the flooders left in their sockets. Wait for
	 * it, so the tests after this one count only their own insertions.
	 */
	deadline = test_now_ms() + TEST_RESPONSE_MS;
	do {
		inserted = atomic_load(&test_inserted);
		test_sleep_ms(200);
	} while (atomic_load(&test_inserted) != inserted &&
		 test_now_ms() < deadline);
	CHECK(atomic_load(&test_inserted) == inserted,
	      "the server did not finish the flooders' insertions");

	test_server_alive("clients flooded it");
#undef TEST_FLOODERS
}

/****************************
 * ESDM state
 ****************************/

/*
 * Take every entropy source out of the picture, so that the ESDM stays
 * non-operational and a blocking read keeps waiting, see test_hangup_deferred().
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
	struct sigaction sa;
	int rc;

	(void)argc;
	(void)argv;

	/* Unbuffered and with a watchdog, see egd_server_raw_test.c. */
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = test_sigpipe_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, NULL) < 0) {
		printf("Cannot install the SIGPIPE handler: %s\n",
		       strerror(errno));
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_WARN);

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
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	/* See test_socket_mode() */
	umask(TEST_UMASK);

	if (esdm_egd_server_enable(sockpath) ||
	    esdm_egd_server_socket_init() || esdm_egd_server_start()) {
		printf("Cannot serve the EGD socket %s\n", sockpath);
		ret = 1;
		goto out;
	}

	test_socket_mode();
	test_hangup_deferred();
	test_hangup_after_write();
	test_hangup_after_pipelined_request();
	test_input_wiped();
	test_status_budget();
	test_flood();
	test_idle_kept();
	test_idle_uid_exhausted();

	CHECK(!test_sigpipe, "the server raised SIGPIPE");

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD connection lifecycle: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
