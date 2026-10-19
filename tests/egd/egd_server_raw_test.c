/*
 * Wire protocol and deferral tests of the EGD server
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
 * The third of the EGD tests, reaching what the other two cannot:
 *
 * - It speaks the wire protocol byte by byte rather than through the client
 *   library. Both sides were written against one description of the protocol,
 *   so only bytes on the socket can tell whether it was read correctly.
 *
 * - It runs the server in this process against an ESDM whose seeding it
 *   controls, which is what the blocking read command needs: the request is
 *   issued while there is no entropy, and the answer has to arrive with it.
 *   Against the daemon of egd_server_test that moment has long passed.
 *
 * It also checks that waiting for entropy is not blocking: while one client's
 * request waits, the server has to keep serving everybody else.
 *
 * The ESDM's own commands are checked here as well, see esdm_egd_protocol.h:
 * the read that needs no seeding before the ESDM is seeded, the prediction
 * resistant reads, the state and the status reports, and the privileged
 * commands - carried out for root, refused to everybody else.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
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

#include "../status_json_check.h"

/*
 * Two helpers the EGD server shares with the RPC server, which is not linked
 * here - it would pull the entire RPC machinery into a test speaking a
 * different protocol. Declared rather than included from esdm_rpc_server.h for
 * the same reason, so only review keeps the signatures in step.
 */
void esdm_server_remove_stale_socket(const char *path, int socktype);
int set_fd_nonblocking(int fd);

/*
 * The socket of this test is created in a temporary directory of its own, where
 * a stale one cannot exist.
 */
void esdm_server_remove_stale_socket(const char *path, int socktype)
{
	(void)path;
	(void)socktype;
}

/*
 * Only reached on the systemd socket activation path, which this test does not
 * take. Implemented rather than stubbed anyway: a stub that silently succeeds
 * would leave a blocking descriptor behind should that ever change.
 */
int set_fd_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -errno;
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;

	return 0;
}

/*
 * Backstop for a request that never comes back. Below the timeout the harness
 * applies to the whole run, so such a failure is reported by this test rather
 * than by meson killing it.
 */
#define TEST_WATCHDOG_SEC 120

/*
 * How long a response is waited for. Generous: the answer to a deferred request
 * is produced by the server's own poll interval, and the machine running this
 * may be busy.
 */
#define TEST_RESPONSE_MS 10000

/*
 * How long the absence of a response is checked for. This is the window in
 * which a server that answers a blocking read without having the entropy for it
 * gives itself away, so it has to be well above the server's poll interval.
 */
#define TEST_SILENCE_MS 750

/* How long the ESDM is fed and given time to reach the operational state. */
#define TEST_SEED_ROUNDS 200
#define TEST_SEED_INTERVAL_MS 50

static char tmpdir[] = "/tmp/esdm-egd-raw-test-XXXXXX";
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

/*
 * Was a SIGPIPE raised?
 *
 * The server is driven in this very process, so the signal a vanished client
 * provokes lands here - which is what makes it observable at all. The test's own
 * client side never raises one: it sends with MSG_NOSIGNAL throughout, so
 * anything recorded here came from the server.
 */
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

/*
 * @return 0 when everything was written
 *
 * MSG_NOSIGNAL: writing to a peer the server has dropped is something several
 * of the tests below do on purpose, and it has to come back as an error to
 * check rather than as a signal - which would also be indistinguishable from
 * one the server raised, see test_sigpipe.
 */
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

static bool test_all_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

/****************************
 * Protocol exchanges
 ****************************/

/* Command 0x04: one length byte followed by the PID as a string. */
static int test_cmd_pid(int fd, pid_t *pid, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_GET_PID;
	char resp[UINT8_MAX + 1];
	uint8_t len;
	int rc;

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, &len, sizeof(len), timeout_ms);
	if (rc)
		return rc;
	if (!len)
		return -EPROTO;

	rc = test_recv(fd, resp, len, timeout_ms);
	if (rc)
		return rc;
	resp[len] = '\0';

	*pid = (pid_t)strtol(resp, NULL, 10);

	return 0;
}

/* Command 0x00: the available entropy as a 4 byte big endian bit count. */
static int test_cmd_entropy_count(int fd, uint32_t *bits, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint8_t resp[4];
	int rc;

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, resp, sizeof(resp), timeout_ms);
	if (rc)
		return rc;

	*bits = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
		((uint32_t)resp[2] << 8) | (uint32_t)resp[3];

	return 0;
}

/*
 * Command 0x01: one byte holding the number of delivered bytes, followed by
 * that many bytes.
 */
static int test_cmd_read_nonblock(int fd, uint8_t requested, uint8_t *buf,
				  uint8_t *delivered, int timeout_ms)
{
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, requested };
	int rc;

	if (test_send(fd, cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, delivered, sizeof(*delivered), timeout_ms);
	if (rc)
		return rc;

	if (*delivered > requested)
		return -EPROTO;

	if (!*delivered)
		return 0;

	return test_recv(fd, buf, *delivered, timeout_ms);
}

/* Command 0x02: exactly the requested number of bytes, and nothing else. */
static int test_send_read_block(int fd, uint8_t requested)
{
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_BLOCK, requested };

	return test_send(fd, cmd, sizeof(cmd)) ? -EIO : 0;
}

/* Command 0x03: an entropy claim, a length byte, the data - and no response. */
static int test_cmd_write_entropy(int fd, const uint8_t *buf, uint8_t len,
				  uint16_t entropy_bits)
{
	uint8_t header[4] = { ESDM_EGD_CMD_WRITE_ENTROPY,
			      (uint8_t)(entropy_bits >> 8),
			      (uint8_t)(entropy_bits & 0xff), len };

	if (test_send(fd, header, sizeof(header)))
		return -EIO;

	return test_send(fd, buf, len) ? -EIO : 0;
}

/****************************
 * ESDM state
 ****************************/

/*
 * Feed the auxiliary pool until the ESDM turns operational.
 *
 * Nothing here forces the seeding: the entropy is only made available, and
 * whoever asks the ESDM for random data next is what turns it into an
 * operational state. That is deliberate - the point of the test is that the
 * deferred request of the server is what picks the entropy up.
 *
 * The NTG.1 seeding strategy wants two entropy sources of 240 bits each for
 * the initial seeding, and the auxiliary pool is only one. The jitter RNG is
 * credited again as the second one - at this moment rather than from the
 * start, so the moment the ESDM becomes operational stays the test's to
 * choose. An NTG.1 conformant jitter RNG suffices on its own, which makes no
 * difference here.
 */
static int test_esdm_seed(void)
{
	uint8_t seed[64];
	unsigned int i, round;

	if (esdm_ntg1_2024_compliant())
		esdm_config_es_jent_entropy_rate_set(256);

	for (round = 0; round < TEST_SEED_ROUNDS; round++) {
		if (esdm_state_operational())
			return 0;

		for (i = 0; i < sizeof(seed); i++)
			seed[i] = (uint8_t)(i + round);

		esdm_pool_insert_aux(seed, sizeof(seed), 8 * sizeof(seed));

		test_sleep_ms(TEST_SEED_INTERVAL_MS);
	}

	return esdm_state_operational() ? 0 : -1;
}

/*
 * Take every entropy source out of the picture, so that the ESDM cannot reach
 * the operational state on its own and the moment it does is the test's to
 * choose. The auxiliary pool is not among them: it holds what is inserted into
 * it, which is exactly the handle this needs.
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

/****************************
 * Tests
 ****************************/

/* The commands that are answered no matter how much entropy there is. */
static void test_stateless_commands(void)
{
	uint32_t bits = 0;
	pid_t pid = 0;
	int fd;

	printf("EGD raw: PID and entropy count\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_pid(fd, &pid, TEST_RESPONSE_MS) == 0,
	      "the PID request was not answered");
	CHECK(pid == getpid(), "the server reports PID %d, this process is %d",
	      (int)pid, (int)getpid());

	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the entropy count was not answered");
	printf("  PID %d, %u bits available\n", (int)pid, bits);

	close(fd);
}

/*
 * Several commands in one write, whose responses have to come back in the order
 * the commands were sent - the protocol has no request identifiers, so that
 * order is all a client has to match them by.
 */
static void test_pipelining(void)
{
	uint8_t cmds[4] = { ESDM_EGD_CMD_ENTROPY_COUNT, ESDM_EGD_CMD_GET_PID,
			    ESDM_EGD_CMD_READ_NONBLOCK, 8 };
	uint8_t buf[8], count[4], len, delivered;
	char pidstr[UINT8_MAX + 1];
	int fd;

	printf("EGD raw: pipelined commands\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, cmds, sizeof(cmds)) == 0,
	      "the pipelined commands could not be sent");

	CHECK(test_recv(fd, count, sizeof(count), TEST_RESPONSE_MS) == 0,
	      "the entropy count of the pipeline was not answered");

	CHECK(test_recv(fd, &len, sizeof(len), TEST_RESPONSE_MS) == 0,
	      "the PID length of the pipeline was not answered");
	/* pidstr is sized for the longest length the byte can express. */
	CHECK(len > 0, "the PID was answered with an empty string");
	if (len > 0) {
		CHECK(test_recv(fd, pidstr, len, TEST_RESPONSE_MS) == 0,
		      "the PID of the pipeline was not answered");
		pidstr[len] = '\0';
		CHECK((pid_t)strtol(pidstr, NULL, 10) == getpid(),
		      "the pipelined PID request answered with %s", pidstr);
	}

	CHECK(test_recv(fd, &delivered, sizeof(delivered), TEST_RESPONSE_MS) ==
		      0,
	      "the non-blocking read of the pipeline was not answered");
	CHECK(delivered <= sizeof(buf), "%u bytes delivered, 8 were asked for",
	      delivered);
	if (delivered && delivered <= sizeof(buf)) {
		CHECK(test_recv(fd, buf, delivered, TEST_RESPONSE_MS) == 0,
		      "the data of the pipelined non-blocking read is missing");
	}

	close(fd);
}

/* A command that arrives in pieces is only acted on once it is complete. */
static void test_split_command(void)
{
	uint8_t cmd = ESDM_EGD_CMD_READ_BLOCK;
	uint8_t len = 16;
	uint8_t buf[16];
	int fd;

	printf("EGD raw: command split across two writes\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_send(fd, &cmd, sizeof(cmd)) == 0,
	      "the command byte could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the server answered a command whose length byte it had not seen");

	CHECK(test_send(fd, &len, sizeof(len)) == 0,
	      "the length byte could not be sent");
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the completed command was not answered");
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the answer is nothing but zeroes");

	close(fd);
}

/*
 * The protocol has no way to report an error, and an unknown command means the
 * stream is out of sync - the client has to be dropped rather than answered.
 */
static void test_unknown_command(void)
{
	/*
	 * Far off, between the standard commands and the ESDM's own, and right
	 * behind the ESDM's own.
	 */
	static const uint8_t cmds[] = { 0xff, 0x05, 0xdf,
					ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS +
						1 };
	uint8_t buf[1];
	unsigned int i;
	int fd;

	printf("EGD raw: unknown command\n");

	for (i = 0; i < sizeof(cmds); i++) {
		fd = test_connect();
		if (fd < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			return;
		}

		CHECK(test_send(fd, &cmds[i], 1) == 0,
		      "the unknown command 0x%02x could not be sent", cmds[i]);
		CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) ==
			      -EPIPE,
		      "the unknown command 0x%02x did not close the connection",
		      cmds[i]);

		close(fd);
	}
}

/*
 * A client that keeps asking without ever reading the answers.
 *
 * Its socket buffer fills up and the responses stop going out, which must cost
 * it nothing but its own progress: the server keeps the undelivered response,
 * stops reading the commands behind it - the backpressure bounding what it
 * holds per connection - and goes on serving everybody else.
 */
static void test_unread_responses(void)
{
	/*
	 * A UNIX socket accounts its buffer per queued message, at several
	 * hundred bytes for even the smallest, so a few thousand answers of
	 * two bytes are far more than it holds. The writes stop at the first
	 * that would block, which is where the client's own end is congested
	 * as well.
	 *
	 * One byte per request, not the largest transfer: a few hundred of
	 * those take the DRNG past its reseed threshold, and the entropy
	 * sources this test switched off cannot complete that reseed. Every
	 * request after it would retry the reseed, polling the entropy
	 * sources, which is the DRNG manager's business and not what this
	 * tests - on a slow machine it delays the answers to the other
	 * client beyond the response timeout.
	 */
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, 1 };
	unsigned int sent = 0, i;
	uint32_t bits = 0;
	pid_t pid = 0;
	int slow, other;

	printf("EGD raw: a client that does not read its responses\n");

	slow = test_connect();
	if (slow < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	if (fcntl(slow, F_SETFL, fcntl(slow, F_GETFL) | O_NONBLOCK) < 0) {
		CHECK(0, "the client cannot be set non-blocking: %s",
		      strerror(errno));
		close(slow);
		return;
	}

	for (i = 0; i < 8192; i++) {
		ssize_t rc = send(slow, cmd, sizeof(cmd), MSG_NOSIGNAL);

		if (rc == (ssize_t)sizeof(cmd)) {
			sent++;
			continue;
		}
		if (rc < 0 && errno == EINTR)
			continue;

		/*
		 * Congested in both directions - which is the point. Anything
		 * else means the server gave up on a client that is merely
		 * slow, so do not let it pass silently.
		 */
		CHECK(rc < 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
		      "the server dropped a client that does not read: %s",
		      (rc < 0) ? strerror(errno) : "short write");
		break;
	}
	printf("  %u requests sent without reading a single answer\n", sent);

	/* And now the client that behaves. */
	other = test_connect();
	CHECK(other >= 0, "a client was not accepted while another one is stuck");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "the entropy count was not answered while a client is stuck");
		CHECK(test_cmd_pid(other, &pid, TEST_RESPONSE_MS) == 0,
		      "the PID request was not answered while a client is stuck");
		close(other);
	}

	/*
	 * The stuck client is still a client: once it reads, its answers are
	 * there, in the order it asked for them.
	 */
	{
		uint8_t delivered = 0;
		uint8_t buf[ESDM_EGD_MAX_TRANSFER];

		CHECK(test_recv(slow, &delivered, sizeof(delivered),
				TEST_RESPONSE_MS) == 0,
		      "the stuck client got nothing at all");
		CHECK(delivered <= cmd[1],
		      "the stuck client got %u bytes for a request of %u",
		      delivered, cmd[1]);
		if (delivered && delivered <= cmd[1]) {
			CHECK(test_recv(slow, buf, delivered,
					TEST_RESPONSE_MS) == 0,
			      "the answer of the stuck client is truncated");
		}
	}

	close(slow);
}

/*
 * A client that asks and is gone before it is answered.
 *
 * The request is in the server's socket buffer and is served, but its peer no
 * longer exists. Writing to it is an EPIPE the server has to take as the end of
 * that one connection and nothing more: raising SIGPIPE would, with a daemon's
 * default disposition, let an optional interface take down the entropy supply
 * of the whole system.
 */
static void test_vanishing_client(void)
{
	/*
	 * More connections than the server takes events for in one round, so the
	 * ones without an event are the ones whose delivery it retries - into a
	 * peer gone by then. Otherwise a client closing while a response is on
	 * its way is reported as a hangup and the connection dropped before
	 * anything is written, which never reaches the write under test.
	 */
#define TEST_VANISHING_CLIENTS 96
	uint8_t cmd[2] = { ESDM_EGD_CMD_READ_NONBLOCK, ESDM_EGD_MAX_TRANSFER };
	int fds[TEST_VANISHING_CLIENTS];
	uint32_t bits = 0;
	unsigned int i, j;
	int other;

	printf("EGD raw: clients that vanish before their answer\n");

	for (i = 0; i < TEST_VANISHING_CLIENTS; i++) {
		fds[i] = test_connect();
		if (fds[i] < 0) {
			CHECK(0, "cannot connect to %s: %s", sockpath,
			      strerror(errno));
			while (i--)
				close(fds[i]);
			return;
		}

		if (fcntl(fds[i], F_SETFL,
			  fcntl(fds[i], F_GETFL) | O_NONBLOCK) < 0) {
			CHECK(0, "a client cannot be set non-blocking: %s",
			      strerror(errno));
			do {
				close(fds[i]);
			} while (i--);
			return;
		}
	}

	/*
	 * Ask on every one of them without reading, until each has a response
	 * the server could not deliver. Round robin rather than one connection
	 * after the other: the server works on them in the same interleaved way,
	 * so this is over in a fraction of the rounds.
	 */
	for (j = 0; j < 4096; j++) {
		bool congested = true;

		for (i = 0; i < TEST_VANISHING_CLIENTS; i++) {
			if (send(fds[i], cmd, sizeof(cmd), MSG_NOSIGNAL) ==
			    (ssize_t)sizeof(cmd))
				congested = false;
		}

		if (congested)
			break;
	}

	/* And now they are all gone at once. */
	for (i = 0; i < TEST_VANISHING_CLIENTS; i++)
		close(fds[i]);

	/* Give the server the chance to write into every one of them. */
	test_sleep_ms(500);

	CHECK(!test_sigpipe,
	      "answering a client that went away raised SIGPIPE in the server");

	other = test_connect();
	CHECK(other >= 0, "the server stopped accepting clients");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "the server stopped serving after its clients went away");
		close(other);
	}
#undef TEST_VANISHING_CLIENTS
}

/*
 * The insertion command has no response of its own, so what shows that the
 * server consumed exactly its bytes is the answer to the command behind it.
 */
static void test_write_entropy(void)
{
	uint8_t data[ESDM_EGD_MAX_TRANSFER];
	uint32_t bits = 0;
	unsigned int i;
	int fd;

	printf("EGD raw: entropy insertion\n");

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)i;

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_write_entropy(fd, data, sizeof(data),
				     8 * sizeof(data)) == 0,
	      "the insertion could not be sent");
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over an insertion");

	/* A claim of zero bits is legitimate and equally answerless. */
	CHECK(test_cmd_write_entropy(fd, data, sizeof(data), 0) == 0,
	      "the insertion without a claim could not be sent");
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over an insertion without a claim");

	close(fd);
}

/* Reads of the largest transfer the protocol can express. */
static void test_max_transfer(void)
{
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	uint8_t delivered = 0;
	int fd;

	printf("EGD raw: maximum sized transfers\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	memset(buf, 0, sizeof(buf));
	CHECK(test_send_read_block(fd, ESDM_EGD_MAX_TRANSFER) == 0,
	      "the blocking read could not be sent");
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the blocking read of %u bytes was not answered",
	      ESDM_EGD_MAX_TRANSFER);
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the blocking read delivered nothing but zeroes");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the blocking read delivered more than the requested bytes");

	memset(buf, 0, sizeof(buf));
	CHECK(test_cmd_read_nonblock(fd, ESDM_EGD_MAX_TRANSFER, buf, &delivered,
				     TEST_RESPONSE_MS) == 0,
	      "the non-blocking read of %u bytes was not answered",
	      ESDM_EGD_MAX_TRANSFER);
	printf("  %u of %u bytes delivered right away\n", delivered,
	       ESDM_EGD_MAX_TRANSFER);

	close(fd);
}

/*
 * The blocking read against an ESDM that has nothing to answer it with.
 *
 * This is the one exchange whose behaviour cannot be observed against a running
 * daemon: it has long been operational by the time anybody can connect to it.
 */
static void test_deferred_read(void)
{
	uint8_t buf[32];
	uint8_t delivered = 0;
	uint32_t bits = 0;
	pid_t pid = 0;
	int fd = -1, other = -1;

	printf("EGD raw: blocking read across the operational state\n");

	if (esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is operational despite every entropy source being disabled\n");
		return;
	}

	fd = test_connect();
	other = test_connect();
	if (fd < 0 || other < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		goto out;
	}

	/*
	 * The non-blocking command is what a client uses to find out that there
	 * is nothing to be had - it says so with a delivery of zero bytes
	 * rather than by waiting.
	 */
	CHECK(test_cmd_read_nonblock(fd, sizeof(buf), buf, &delivered,
				     TEST_RESPONSE_MS) == 0,
	      "the non-blocking read was not answered while the ESDM had no entropy");
	CHECK(delivered == 0,
	      "%u bytes were delivered by an ESDM that is not operational",
	      delivered);

	/* Now the request that has to wait. */
	CHECK(test_send_read_block(fd, sizeof(buf)) == 0,
	      "the blocking read could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the blocking read was answered by an ESDM that is not operational");

	/*
	 * A command sent behind the waiting one must not overtake it: its
	 * response would be read as the answer to the blocking read.
	 */
	CHECK(test_send(fd, &(uint8_t){ ESDM_EGD_CMD_GET_PID }, 1) == 0,
	      "the pipelined PID request could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "a command behind the waiting one was answered first");

	/*
	 * Waiting for entropy must not be blocking: everybody else has to be
	 * served meanwhile, including on a connection that did not even exist
	 * when the waiting request arrived.
	 */
	CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) == 0,
	      "another client was not served while a request was waiting");
	CHECK(test_cmd_pid(other, &pid, TEST_RESPONSE_MS) == 0,
	      "another client was not served while a request was waiting");
	close(other);
	other = test_connect();
	CHECK(other >= 0,
	      "a new client was not accepted while a request was waiting");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "a new client was not served while a request was waiting");
	}

	/* The entropy the waiting request is waiting for. */
	printf("  seeding the ESDM\n");
	if (test_esdm_seed()) {
		CHECK(0, "the ESDM did not become operational");
		goto out;
	}

	memset(buf, 0, sizeof(buf));
	CHECK(test_recv(fd, buf, sizeof(buf), TEST_RESPONSE_MS) == 0,
	      "the waiting request was not served after the ESDM became operational");
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the waiting request was served with nothing but zeroes");

	/* And only now the command that was sent behind it. */
	{
		uint8_t len = 0;
		char pidstr[UINT8_MAX + 1];

		CHECK(test_recv(fd, &len, sizeof(len), TEST_RESPONSE_MS) == 0,
		      "the command behind the waiting one was never answered");
		/* pidstr is sized for the longest length the byte can express. */
		if (len > 0) {
			CHECK(test_recv(fd, pidstr, len, TEST_RESPONSE_MS) == 0,
			      "the answer behind the waiting one is truncated");
			pidstr[len] = '\0';
			CHECK((pid_t)strtol(pidstr, NULL, 10) == getpid(),
			      "the answer behind the waiting one is %s, not the PID",
			      pidstr);
		} else {
			CHECK(0, "the answer behind the waiting one is empty");
		}
	}

out:
	if (fd >= 0)
		close(fd);
	if (other >= 0)
		close(other);
}

/****************************
 * ESDM extension commands
 ****************************/

/*
 * A read answered with a count byte and that many bytes - the standard
 * non-blocking read 0x01 and the ESDM's 0xe0 and 0xe2 alike.
 */
static int test_cmd_read_counted(int fd, uint8_t command, uint8_t requested,
				 uint8_t *buf, uint8_t *delivered,
				 int timeout_ms)
{
	uint8_t cmd[2] = { command, requested };
	int rc;

	if (test_send(fd, cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, delivered, sizeof(*delivered), timeout_ms);
	if (rc)
		return rc;

	if (*delivered > requested)
		return -EPROTO;

	if (!*delivered)
		return 0;

	return test_recv(fd, buf, *delivered, timeout_ms);
}

static uint32_t test_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/*
 * Command 0xe3: a count byte, then that many 4 byte fields. @fields receives
 * the first ESDM_EGD_STATE_NUM_FIELDS of them, @count how many there were.
 */
static int test_cmd_state(int fd, uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS],
			  uint8_t *count, int timeout_ms)
{
	const uint8_t cmd = ESDM_EGD_CMD_ESDM_GET_STATE;
	uint8_t resp[4 * UINT8_MAX];
	unsigned int i;
	int rc;

	if (test_send(fd, &cmd, sizeof(cmd)))
		return -EIO;

	rc = test_recv(fd, count, sizeof(*count), timeout_ms);
	if (rc)
		return rc;

	/* The answer has to fit into one EGD transfer, see the header */
	if (1 + 4 * (size_t)*count > 1 + ESDM_EGD_MAX_TRANSFER)
		return -EPROTO;

	rc = test_recv(fd, resp, 4 * (size_t)*count, timeout_ms);
	if (rc)
		return rc;

	for (i = 0; i < ESDM_EGD_STATE_NUM_FIELDS; i++)
		fields[i] = (i < *count) ? test_be32(resp + 4 * i) : 0;

	return 0;
}

/*
 * Commands 0xe4 and 0xe5: a 4 byte length, then the report. Returns it as a
 * NUL terminated string in @report, to be freed by the caller.
 */
static int test_cmd_status(int fd, uint8_t command, char **report,
			   uint32_t *len, int timeout_ms)
{
	uint8_t hdr[4];
	int rc;

	*report = NULL;

	if (test_send(fd, &command, sizeof(command)))
		return -EIO;

	rc = test_recv(fd, hdr, sizeof(hdr), timeout_ms);
	if (rc)
		return rc;

	*len = test_be32(hdr);
	if (*len > ESDM_EGD_MAX_STATUS)
		return -EPROTO;

	*report = calloc(1, (size_t)*len + 1);
	if (!*report)
		return -ENOMEM;

	return test_recv(fd, *report, *len, timeout_ms);
}

/*
 * Commands 0xe6 to 0xea: the command, the 4 byte argument for those that take
 * one, and a 4 byte status as answer.
 */
static bool test_cmd_has_arg(uint8_t command)
{
	return command == ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT ||
	       command == ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP ||
	       command == ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS;
}

static int test_send_priv(int fd, uint8_t command, uint32_t arg)
{
	uint8_t cmd[5] = { command, (uint8_t)(arg >> 24), (uint8_t)(arg >> 16),
			   (uint8_t)(arg >> 8), (uint8_t)arg };

	return test_send(fd, cmd, test_cmd_has_arg(command) ? 5 : 1) ? -EIO :
								      0;
}

static int test_cmd_priv(int fd, uint8_t command, uint32_t arg,
			 int32_t *status, int timeout_ms)
{
	uint8_t resp[4];
	int rc;

	if (test_send_priv(fd, command, arg))
		return -EIO;

	rc = test_recv(fd, resp, sizeof(resp), timeout_ms);
	if (rc)
		return rc;

	*status = (int32_t)test_be32(resp);

	return 0;
}

static const uint8_t test_priv_cmds[] = {
	ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT, ESDM_EGD_CMD_ESDM_CLEAR_POOL,
	ESDM_EGD_CMD_ESDM_RESEED, ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP,
	ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS
};

/*
 * The ESDM's commands before it is seeded: the state is answered, and every
 * read - the one with the semantics of /dev/urandom as well, as the ESDM hands
 * out nothing before it is operational - is answered empty rather than held.
 */
static void test_esdm_unseeded(void)
{
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	uint8_t count = 0, delivered = 0;
	int fd;

	printf("EGD raw: ESDM commands before the ESDM is seeded\n");

	if (esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is operational despite every entropy source being disabled\n");
		return;
	}

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");
	CHECK(count >= ESDM_EGD_STATE_NUM_FIELDS, "the state has %u fields",
	      count);
	CHECK(!(fields[ESDM_EGD_STATE_FLAGS] & ESDM_EGD_STATE_FLAG_OPERATIONAL),
	      "the state says operational, the ESDM is not");
	CHECK(!(fields[ESDM_EGD_STATE_FLAGS] &
		~(ESDM_EGD_STATE_FLAG_OPERATIONAL |
		  ESDM_EGD_STATE_FLAG_FULLY_SEEDED)),
	      "the state flags 0x%x carry unknown bits",
	      fields[ESDM_EGD_STATE_FLAGS]);
	CHECK(fields[ESDM_EGD_STATE_POOLSIZE] == esdm_avail_poolsize_aux(),
	      "the state reports a pool size of %u, the ESDM has %u",
	      fields[ESDM_EGD_STATE_POOLSIZE], esdm_avail_poolsize_aux());

	CHECK(test_cmd_read_counted(fd, ESDM_EGD_CMD_ESDM_READ_UNSEEDED,
				    sizeof(buf), buf, &delivered,
				    TEST_RESPONSE_MS) == 0,
	      "the unseeded read was not answered");
	CHECK(delivered == 0,
	      "the unseeded read delivered %u bytes before the ESDM is operational",
	      delivered);

	CHECK(test_cmd_read_counted(fd, ESDM_EGD_CMD_ESDM_READ_UNSEEDED, 0, buf,
				    &delivered, TEST_RESPONSE_MS) == 0,
	      "the unseeded read of nothing was not answered");
	CHECK(delivered == 0, "the unseeded read of nothing delivered %u bytes",
	      delivered);

	CHECK(test_cmd_read_counted(fd, ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK, 32,
				    buf, &delivered, TEST_RESPONSE_MS) == 0,
	      "the non-blocking PR read was not answered");
	CHECK(delivered == 0,
	      "%u prediction resistant bytes were delivered by an ESDM that is not operational",
	      delivered);

	close(fd);
}

/*
 * The blocking prediction resistant read waits for the entropy it is made of,
 * like the blocking read waits for the operational state - deferred, with the
 * commands behind it held back, and everybody else served meanwhile.
 */
static void test_esdm_pr_read(void)
{
	uint8_t seed[64], buf[32], len = 0, delivered = 0;
	char pidstr[UINT8_MAX + 1];
	uint32_t bits = 0;
	unsigned int i, round;
	int fd = -1, other = -1, rc = -ETIMEDOUT;

	printf("EGD raw: prediction resistant reads\n");

	if (!esdm_state_operational()) {
		printf("  SKIPPED: the ESDM is not operational\n");
		return;
	}

	fd = test_connect();
	other = test_connect();
	if (fd < 0 || other < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		goto out;
	}

	/* Whatever the PR DRNG had is taken, so the next one has to wait */
	CHECK(test_cmd_read_counted(fd, ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK,
				    sizeof(buf), buf, &delivered,
				    TEST_RESPONSE_MS) == 0,
	      "the non-blocking PR read was not answered");
	printf("  %u of %zu prediction resistant bytes right away\n", delivered,
	       sizeof(buf));

	CHECK(test_send(fd, (uint8_t[]){ ESDM_EGD_CMD_ESDM_PR_READ_BLOCK,
					 sizeof(buf) },
			2) == 0,
	      "the blocking PR read could not be sent");
	CHECK(test_send(fd, &(uint8_t){ ESDM_EGD_CMD_GET_PID }, 1) == 0,
	      "the pipelined PID request could not be sent");

	/* The entropy it waits for, a little at a time */
	memset(buf, 0, sizeof(buf));
	for (round = 0; round < TEST_SEED_ROUNDS; round++) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "another client was not served while a PR read waited");

		for (i = 0; i < sizeof(seed); i++)
			seed[i] = (uint8_t)(i * 7 + round);
		esdm_pool_insert_aux(seed, sizeof(seed), 8 * sizeof(seed));

		rc = test_recv(fd, buf, sizeof(buf), TEST_SEED_INTERVAL_MS);
		if (rc != -ETIMEDOUT)
			break;
	}

	CHECK(rc == 0, "the blocking PR read was not answered: %d", rc);
	if (rc)
		goto out;
	CHECK(!test_all_zero(buf, sizeof(buf)),
	      "the blocking PR read delivered nothing but zeroes");

	/* And only then what was sent behind it */
	CHECK(test_recv(fd, &len, sizeof(len), TEST_RESPONSE_MS) == 0 && len,
	      "the command behind the PR read was not answered");
	if (len) {
		CHECK(test_recv(fd, pidstr, len, TEST_RESPONSE_MS) == 0,
		      "the answer behind the PR read is truncated");
		pidstr[len] = '\0';
		CHECK((pid_t)strtol(pidstr, NULL, 10) == getpid(),
		      "the answer behind the PR read is %s, not the PID",
		      pidstr);
	}

out:
	if (fd >= 0)
		close(fd);
	if (other >= 0)
		close(other);
}

/* The state and the status reports of an operational ESDM, pipelined */
static void test_esdm_status(void)
{
	const uint8_t cmds[] = { ESDM_EGD_CMD_ESDM_STATUS,
				 ESDM_EGD_CMD_ESDM_GET_STATE,
				 ESDM_EGD_CMD_ESDM_STATUS_JSON,
				 ESDM_EGD_CMD_ENTROPY_COUNT };
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS], len = 0, json_len = 0;
	char *text = NULL, *json = NULL;
	uint8_t count = 0, hdr[4];
	uint32_t bits = 0;
	int fd;

	printf("EGD raw: state and status reports\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_status(fd, ESDM_EGD_CMD_ESDM_STATUS, &text, &len,
			      TEST_RESPONSE_MS) == 0,
	      "the status was not answered");
	CHECK(len > 0 && text && strlen(text) == len,
	      "the status of %u bytes is no text of that length", len);
	CHECK(text && strstr(text, "DRNG name: ") &&
		      strstr(text, "Entropy Source 0 properties:"),
	      "the status lacks its sections: %.200s", text ? text : "");
	free(text);
	text = NULL;

	CHECK(test_cmd_status(fd, ESDM_EGD_CMD_ESDM_STATUS_JSON, &json,
			      &json_len, TEST_RESPONSE_MS) == 0,
	      "the JSON status was not answered");
	CHECK(json_len > 0 && json && esdm_status_json_check(json) == 0,
	      "the JSON status of %u bytes is no well-formed status",
	      json_len);
	free(json);
	json = NULL;

	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");
	CHECK(fields[ESDM_EGD_STATE_FLAGS] & ESDM_EGD_STATE_FLAG_OPERATIONAL,
	      "the state does not say operational, the ESDM is");

	/* Now the read with the semantics of /dev/urandom delivers in full */
	{
		uint8_t buf[ESDM_EGD_MAX_TRANSFER], delivered = 0;

		memset(buf, 0, sizeof(buf));
		CHECK(test_cmd_read_counted(fd, ESDM_EGD_CMD_ESDM_READ_UNSEEDED,
					    sizeof(buf), buf, &delivered,
					    TEST_RESPONSE_MS) == 0,
		      "the unseeded read was not answered");
		CHECK(delivered == sizeof(buf),
		      "the unseeded read delivered %u of %zu bytes", delivered,
		      sizeof(buf));
		CHECK(!test_all_zero(buf, delivered),
		      "the unseeded read delivered nothing but zeroes");
	}
	CHECK(fields[ESDM_EGD_STATE_WRITE_WAKEUP] ==
		      esdm_get_write_wakeup_bits(),
	      "the state reports a write wakeup threshold of %u, the ESDM has %u",
	      fields[ESDM_EGD_STATE_WRITE_WAKEUP],
	      esdm_get_write_wakeup_bits());
	CHECK(fields[ESDM_EGD_STATE_MIN_RESEED_SECS] ==
		      esdm_get_reseed_max_time(),
	      "the state reports %u reseed seconds, the ESDM has %u",
	      fields[ESDM_EGD_STATE_MIN_RESEED_SECS],
	      esdm_get_reseed_max_time());

	/*
	 * All in one write: the large answers are held while they go out, and
	 * the ones behind them must not overtake them.
	 */
	CHECK(test_send(fd, cmds, sizeof(cmds)) == 0,
	      "the pipelined commands could not be sent");
	CHECK(test_recv(fd, hdr, sizeof(hdr), TEST_RESPONSE_MS) == 0,
	      "the pipelined status was not answered");
	len = test_be32(hdr);
	CHECK(len > 0 && len <= ESDM_EGD_MAX_STATUS,
	      "the pipelined status announces %u bytes", len);
	if (len > 0 && len <= ESDM_EGD_MAX_STATUS) {
		text = calloc(1, len + 1);
		CHECK(text && test_recv(fd, text, len, TEST_RESPONSE_MS) == 0,
		      "the pipelined status is truncated");
		CHECK(text && strstr(text, "DRNG name: "),
		      "the pipelined status is no status");
		free(text);
		text = NULL;
	}
	CHECK(test_recv(fd, &count, sizeof(count), TEST_RESPONSE_MS) == 0 &&
		      count >= ESDM_EGD_STATE_NUM_FIELDS && count < 64,
	      "the pipelined state was not answered behind the status");
	if (count < 64) {
		uint8_t skip[4 * 64];

		CHECK(test_recv(fd, skip, 4 * (size_t)count,
				TEST_RESPONSE_MS) == 0,
		      "the pipelined state is truncated");
	}
	CHECK(test_recv(fd, hdr, sizeof(hdr), TEST_RESPONSE_MS) == 0,
	      "the pipelined JSON status was not answered");
	json_len = test_be32(hdr);
	if (json_len > 0 && json_len <= ESDM_EGD_MAX_STATUS) {
		json = calloc(1, json_len + 1);
		CHECK(json &&
			      test_recv(fd, json, json_len, TEST_RESPONSE_MS) ==
				      0 &&
			      json[0] == '{',
		      "the pipelined JSON status is no JSON document");
		free(json);
	} else {
		CHECK(0, "the pipelined JSON status announces %u bytes",
		      json_len);
	}
	CHECK(test_recv(fd, hdr, sizeof(hdr), TEST_RESPONSE_MS) == 0,
	      "the entropy count behind the reports was not answered");

	/* And the connection is in step still */
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "the server lost the stream over the reports");

	close(fd);
}

/*
 * Every privileged command from a peer that is not root: refused with -EPERM,
 * nothing changed, and the connection usable after it. Returns the failures.
 */
static int test_esdm_priv_refused(void)
{
	uint32_t before[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t after[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t bits = 0;
	uint8_t count = 0;
	int32_t status = 0;
	unsigned int i;
	int fd, failed = 0;

	fd = test_connect();
	if (fd < 0) {
		printf("  FAIL: cannot connect as UID %u: %s\n", getuid(),
		       strerror(errno));
		return 1;
	}

	if (test_cmd_state(fd, before, &count, TEST_RESPONSE_MS)) {
		printf("  FAIL: the state was not answered\n");
		failed++;
	}

	for (i = 0; i < sizeof(test_priv_cmds); i++) {
		if (test_cmd_priv(fd, test_priv_cmds[i],
				  before[ESDM_EGD_STATE_WRITE_WAKEUP] + 8,
				  &status, TEST_RESPONSE_MS)) {
			printf("  FAIL: command 0x%02x was not answered\n",
			       test_priv_cmds[i]);
			failed++;
			continue;
		}
		if (status != -EPERM) {
			printf("  FAIL: command 0x%02x of UID %u answered %d, not -EPERM\n",
			       test_priv_cmds[i], getuid(), status);
			failed++;
		}
		if (test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS)) {
			printf("  FAIL: the connection was lost over the refusal of 0x%02x\n",
			       test_priv_cmds[i]);
			failed++;
		}
	}

	if (test_cmd_state(fd, after, &count, TEST_RESPONSE_MS) ||
	    after[ESDM_EGD_STATE_WRITE_WAKEUP] !=
		    before[ESDM_EGD_STATE_WRITE_WAKEUP] ||
	    after[ESDM_EGD_STATE_MIN_RESEED_SECS] !=
		    before[ESDM_EGD_STATE_MIN_RESEED_SECS]) {
		printf("  FAIL: a refused command changed the state\n");
		failed++;
	}

	close(fd);

	return failed;
}

/*
 * The privileged commands. Root has them carried out, anybody else is refused.
 * Run as root, a child dropping to nobody checks the refusal as well.
 */
static void test_esdm_priv(void)
{
	uint32_t orig[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t wakeup, secs, credited;
	uint8_t count = 0;
	int32_t status = 1;
	int fd, wstatus;
	pid_t child;

	printf("EGD raw: privileged commands%s\n",
	       geteuid() ? " are refused" : "");

	if (geteuid()) {
		CHECK(test_esdm_priv_refused() == 0,
		      "the privileged commands were not refused");
		printf("  not root - the commands carried out are left to a root run\n");
		return;
	}

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_state(fd, orig, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");

	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_CLEAR_POOL, 0, &status,
			    TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "clearing the pool was not carried out: %d", status);
	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0 &&
		      fields[ESDM_EGD_STATE_ENT_CNT] == 0,
	      "the pool holds %u bits after clearing it",
	      fields[ESDM_EGD_STATE_ENT_CNT]);

	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT, 64, &status,
			    TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "crediting entropy was not carried out: %d", status);
	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");
	credited = fields[ESDM_EGD_STATE_ENT_CNT];

	/*
	 * Credits add up. The pool reports them less its oversampling, if it
	 * applies one, which can take all of the first 64 bits: the second
	 * credit has to show.
	 */
	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT, 64, &status,
			    TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "crediting entropy once more was not carried out: %d", status);
	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0 &&
		      fields[ESDM_EGD_STATE_ENT_CNT] > credited,
	      "the pool holds %u bits after crediting 64 to its %u",
	      fields[ESDM_EGD_STATE_ENT_CNT], credited);

	/* A credit beyond the pool is capped, not wrapped around */
	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT, UINT32_MAX,
			    &status, TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "crediting the largest count was not carried out: %d", status);
	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0 &&
		      fields[ESDM_EGD_STATE_ENT_CNT] > 0 &&
		      fields[ESDM_EGD_STATE_ENT_CNT] <=
			      fields[ESDM_EGD_STATE_POOLSIZE],
	      "the pool holds %u of %u bits after crediting the largest count",
	      fields[ESDM_EGD_STATE_ENT_CNT], fields[ESDM_EGD_STATE_POOLSIZE]);

	wakeup = (orig[ESDM_EGD_STATE_WRITE_WAKEUP] == 64) ? 128 : 64;
	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP, wakeup,
			    &status, TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "setting the write wakeup threshold was not carried out: %d",
	      status);
	secs = (orig[ESDM_EGD_STATE_MIN_RESEED_SECS] == 120) ? 121 : 120;
	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS, secs,
			    &status, TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "setting the reseed seconds was not carried out: %d", status);
	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0 &&
		      fields[ESDM_EGD_STATE_WRITE_WAKEUP] == wakeup &&
		      fields[ESDM_EGD_STATE_MIN_RESEED_SECS] == secs,
	      "the state reports %u/%u, %u/%u were set",
	      fields[ESDM_EGD_STATE_WRITE_WAKEUP],
	      fields[ESDM_EGD_STATE_MIN_RESEED_SECS], wakeup, secs);

	CHECK(test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_RESEED, 0, &status,
			    TEST_RESPONSE_MS) == 0 &&
		      status == 0,
	      "the reseed was not carried out: %d", status);

	/* Back to what it was */
	test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP,
		      orig[ESDM_EGD_STATE_WRITE_WAKEUP], &status,
		      TEST_RESPONSE_MS);
	test_cmd_priv(fd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
		      orig[ESDM_EGD_STATE_MIN_RESEED_SECS], &status,
		      TEST_RESPONSE_MS);
	close(fd);

	/* Somebody else: the socket's directory has to be reachable for it */
	if (chmod(tmpdir, 0711) < 0) {
		CHECK(0, "cannot open %s to other users: %s", tmpdir,
		      strerror(errno));
		return;
	}

	child = fork();
	if (child < 0) {
		CHECK(0, "cannot fork: %s", strerror(errno));
		return;
	}
	if (!child) {
		alarm(TEST_WATCHDOG_SEC);
		if (setgid(65534) < 0 || setuid(65534) < 0)
			_exit(2);
		_exit(test_esdm_priv_refused() ? 1 : 0);
	}

	CHECK(waitpid(child, &wstatus, 0) == child && WIFEXITED(wstatus) &&
		      WEXITSTATUS(wstatus) == 0,
	      "the privileged commands of an unprivileged peer were not refused (status 0x%x)",
	      wstatus);
	chmod(tmpdir, 0700);
}

/*
 * An ESDM command arriving in pieces is only acted on once it is complete -
 * its argument counts as much as the length byte of a read.
 */
static void test_esdm_split_command(void)
{
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t secs;
	uint8_t count = 0, cmd[5], resp[4];
	int fd;

	printf("EGD raw: ESDM command split across writes\n");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	CHECK(test_cmd_state(fd, fields, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");

	/* Setting what is set already, so the outcome is the same for all */
	secs = fields[ESDM_EGD_STATE_MIN_RESEED_SECS];
	cmd[0] = ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS;
	cmd[1] = (uint8_t)(secs >> 24);
	cmd[2] = (uint8_t)(secs >> 16);
	cmd[3] = (uint8_t)(secs >> 8);
	cmd[4] = (uint8_t)secs;

	CHECK(test_send(fd, cmd, 3) == 0, "the first part could not be sent");
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the server answered a command whose argument it had not seen");
	CHECK(test_send(fd, cmd + 3, 2) == 0,
	      "the rest of the command could not be sent");
	CHECK(test_recv(fd, resp, sizeof(resp), TEST_RESPONSE_MS) == 0,
	      "the completed command was not answered");
	CHECK((int32_t)test_be32(resp) == (geteuid() ? -EPERM : 0),
	      "the completed command answered %d",
	      (int32_t)test_be32(resp));
	CHECK(test_quiet(fd, TEST_SILENCE_MS),
	      "the command was answered with more than its status");

	close(fd);
}

/*
 * A privileged command whose sender is gone right after sending it: carried
 * out all the same, like an insertion, but not answered. Only root's is
 * carried out, so only a root run can see that it was; anybody's has to leave
 * the server serving.
 */
static void test_esdm_priv_peer_gone(void)
{
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t orig, secs, bits = 0;
	uint8_t count = 0;
	int32_t status;
	unsigned int i;
	int fd, other;

	printf("EGD raw: privileged command of a client that is gone\n");

	other = test_connect();
	if (other < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}
	CHECK(test_cmd_state(other, fields, &count, TEST_RESPONSE_MS) == 0,
	      "the state was not answered");
	orig = fields[ESDM_EGD_STATE_MIN_RESEED_SECS];
	secs = (orig == 300) ? 301 : 300;

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		close(other);
		return;
	}
	CHECK(test_send_priv(fd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS, secs) ==
		      0,
	      "the command could not be sent");
	close(fd);

	if (geteuid()) {
		test_sleep_ms(TEST_SILENCE_MS);
	} else {
		for (i = 0; i < TEST_RESPONSE_MS / 50; i++) {
			if (test_cmd_state(other, fields, &count,
					   TEST_RESPONSE_MS) ||
			    fields[ESDM_EGD_STATE_MIN_RESEED_SECS] == secs)
				break;
			test_sleep_ms(50);
		}
		CHECK(fields[ESDM_EGD_STATE_MIN_RESEED_SECS] == secs,
		      "the command of a client that is gone was not carried out");
		test_cmd_priv(other, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
			      orig, &status, TEST_RESPONSE_MS);
	}

	CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) == 0,
	      "the server stopped serving over a client that is gone");
	close(other);
}

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/*
 * A connection that sits idle is closed, one that is in use is not.
 *
 * This build of the server closes idle connections after the short
 * ESDM_EGD_IDLE_TIMEOUT_MS it is compiled with instead of a minute. The server
 * scans for them once a second, so the close comes up to that much later.
 *
 * Root's connection is never closed for its slot, idle or not: root is not
 * accounted, and holds none by the count that picks the connections to close -
 * not even while it is the only one with any. Run as root, the test checks
 * that instead.
 */
static void test_idle_close(void)
{
	const int scan_slack_ms = 1000 + 2000;
	/*
	 * The server starts the idle time once it has sent the last answer,
	 * this test once it has read it - later, by however long the answer
	 * took to arrive and be parsed, which a loaded or sanitizer build
	 * stretches. So the close can come a little before the timeout as
	 * measured here. A close that is early by a scan interval of a second
	 * or more is still caught.
	 */
	const uint64_t clock_slack_ms = 250;
	uint64_t last_answer, closed_after;
	uint32_t bits = 0;
	uint8_t byte;
	unsigned int i;
	int fd, other, rc;

	printf("EGD raw: idle connections are closed%s\n",
	       geteuid() ? "" : " - but not root's");

	fd = test_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s: %s", sockpath, strerror(errno));
		return;
	}

	/*
	 * In use for longer than the idle timeout, with pauses shorter than
	 * it: every command keeps the connection alive.
	 */
	for (i = 0; i < 6; i++) {
		CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
		      "a connection in use was not served after %u pauses", i);
		test_sleep_ms(ESDM_EGD_IDLE_TIMEOUT_MS / 3);
	}
	CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
	      "a connection in use was closed");
	last_answer = test_now_ms();

	/* Now it falls silent, and the server is to close it. */
	rc = test_recv(fd, &byte, sizeof(byte),
		       ESDM_EGD_IDLE_TIMEOUT_MS + scan_slack_ms);
	closed_after = test_now_ms() - last_answer;

	if (geteuid() == 0) {
		CHECK(rc == -ETIMEDOUT,
		      "an idle connection of root's was closed after %llu ms: %d",
		      (unsigned long long)closed_after, rc);
		CHECK(test_cmd_entropy_count(fd, &bits, TEST_RESPONSE_MS) == 0,
		      "an idle connection of root's was not served any more");
		close(fd);
		return;
	}

	CHECK(rc == -EPIPE || rc == -ECONNRESET,
	      "an idle connection was not closed: %d", rc);
	CHECK(closed_after + clock_slack_ms >= ESDM_EGD_IDLE_TIMEOUT_MS,
	      "an idle connection was closed after %llu ms, its timeout is %u ms",
	      (unsigned long long)closed_after,
	      (unsigned int)ESDM_EGD_IDLE_TIMEOUT_MS);
	printf("  closed after %llu ms of silence\n",
	       (unsigned long long)closed_after);
	close(fd);

	/* Closing it costs nobody else anything. */
	other = test_connect();
	CHECK(other >= 0, "the server stopped accepting clients");
	if (other >= 0) {
		CHECK(test_cmd_entropy_count(other, &bits, TEST_RESPONSE_MS) ==
			      0,
		      "the server stopped serving after closing an idle client");
		close(other);
	}
}

int main(int argc, char *argv[])
{
	struct stat sb;
	int rc;

	(void)argc;
	(void)argv;

	/*
	 * Unbuffered: the watchdog and the harness timeout both kill this
	 * process outright, and how far it got must not die with it in a buffer.
	 */
	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	/*
	 * Record SIGPIPE rather than ignoring it: the server runs in this
	 * process, so one it raises is one this test has to report - see
	 * test_vanishing_client(). Handling it also keeps the signal from
	 * killing the run, which matters because the test's own client side
	 * talks to connections the server drops on purpose.
	 */
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = test_sigpipe_handler;
		sigemptyset(&sa.sa_mask);
		if (sigaction(SIGPIPE, &sa, NULL) < 0) {
			printf("Cannot install the SIGPIPE handler: %s\n",
			       strerror(errno));
			return 1;
		}
	}

#ifndef ESDM_ES_JENT
	/*
	 * The NTG.1 seeding strategy wants two entropy sources of 240 bits each
	 * for the initial seeding, and the auxiliary pool the entropy is
	 * inserted into is only one: without the jitter RNG as the second, see
	 * test_esdm_seed(), the ESDM would never become operational.
	 */
	if (esdm_ntg1_2024_compliant()) {
		printf("the NTG.1 seeding strategy needs the jitter RNG next to the auxiliary pool\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_WARN);

	/*
	 * Before esdm_init(): the rates decide what the initial seeding of the
	 * ESDM is allowed to collect.
	 */
	test_esdm_disable_es();

	rc = esdm_init();
	if (rc) {
		printf("esdm_init() failed: %d\n", rc);
		return 1;
	}

	/* Same setup as the RPC server, which is what starts the EGD worker. */
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

	if (esdm_egd_server_enable(sockpath) ||
	    esdm_egd_server_socket_init() || esdm_egd_server_start()) {
		printf("Cannot serve the EGD socket %s\n", sockpath);
		ret = 1;
		goto out;
	}

	if (stat(sockpath, &sb) < 0 || !S_ISSOCK(sb.st_mode)) {
		printf("The EGD socket %s was not created\n", sockpath);
		ret = 1;
		goto out;
	}

	/*
	 * The deferral first: it is the only test that needs an ESDM without
	 * entropy, and it is what makes one available to those below.
	 */
	test_esdm_unseeded();
	test_deferred_read();

	test_stateless_commands();
	test_esdm_pr_read();
	test_esdm_status();
	test_esdm_priv();
	test_esdm_split_command();
	test_esdm_priv_peer_gone();
	test_pipelining();
	test_split_command();
	test_write_entropy();
	test_max_transfer();
	test_unread_responses();
	test_vanishing_client();
	test_unknown_command();
	test_idle_close();

	/* Nothing anywhere above may have signalled the process. */
	CHECK(!test_sigpipe, "the server raised SIGPIPE");

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD raw protocol: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
