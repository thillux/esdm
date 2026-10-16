/*
 * Tests of the EGD server with prediction resistant requests on many
 * connections
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
 * A prediction resistant blocking read of the largest size on each of many
 * connections. Each generation costs a reseed, and a request of that size
 * takes several - one per connection and round of the worker's event loop. A
 * worker serves every client it accepted, and none while it generates: without
 * a bound of the round, its other clients wait for one generation per such
 * connection, round after round.
 *
 *   - a cheap command of another client is answered within a fraction of the
 *     time one generation for each of the connections takes,
 *   - every request is answered in full nonetheless.
 *
 * Like the other EGD server tests, the server runs in this process with a
 * single worker, and no daemon is needed. Unlike them, the ESDM has to be
 * operational - the Jitter RNG is enough.
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

/* Backstop below the harness timeout, see egd_server_raw_test.c. */
#define TEST_WATCHDOG_SEC 240

/* How long an answer to a cheap command is waited for. */
#define TEST_RESPONSE_MS 10000

/*
 * The time the server spends per round on prediction resistant generations,
 * see ESDM_EGD_ROUND_BUDGET_NS - plus the one generation that runs over it.
 * The flood is sized for one generation on each connection to take forty times
 * as long, and the other client may wait half of that at most.
 */
#define TEST_BUDGET_MS 25

/* Most connections the flood is spread over - below the per-user bound */
#define TEST_MAX_CONNS 200

/* For how long the other client is timed while the flood is served */
#define TEST_PROBE_MS 1500

static char tmpdir[] = "/tmp/esdm-egd-pr-budget-test-XXXXXX";
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

static uint64_t test_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static int test_connect(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int test_send(int fd, const void *buf, size_t len)
{
	return send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
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
 * Time one prediction resistant generation for a request of the largest size
 * takes here, in microseconds - what each connection costs the worker per round
 * of its event loop.
 */
static uint64_t test_pr_cost_us(void)
{
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	uint64_t start, best = UINT64_MAX;
	unsigned int i;

	for (i = 0; i < 5; i++) {
		ssize_t rc;

		start = test_now_us();
		rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (rc <= 0)
			continue;
		if (test_now_us() - start < best)
			best = test_now_us() - start;
	}

	return best;
}

static void test_flood(void)
{
	static int fds[TEST_MAX_CONNS];
	static uint8_t answer[ESDM_EGD_MAX_TRANSFER];
	const uint8_t cmd[2] = { ESDM_EGD_CMD_ESDM_PR_READ_BLOCK,
				 ESDM_EGD_MAX_TRANSFER };
	unsigned int i, conns, opened = 0, answered = 0, probes = 0;
	uint64_t cost, round_us, worst_us = 0, deadline;
	int other;

	printf("EGD PR budget: largest blocking reads on many connections\n");

	cost = test_pr_cost_us();
	if (cost == UINT64_MAX) {
		printf("  SKIPPED: the PR DRNG does not deliver here\n");
		return;
	}

	conns = (unsigned int)(40 * TEST_BUDGET_MS * 1000 / (cost ? cost : 1));
	if (conns < 16)
		conns = 16;
	if (conns > TEST_MAX_CONNS)
		conns = TEST_MAX_CONNS;
	round_us = conns * cost;
	printf("  %llu us per generation, %u connections, %llu ms for one generation each\n",
	       (unsigned long long)cost, conns,
	       (unsigned long long)(round_us / 1000));

	other = test_connect(sockpath);
	CHECK(other >= 0 &&
		      test_cmd_entropy_count(other, TEST_RESPONSE_MS) == 0,
	      "the other client is not served");
	if (other < 0)
		return;

	/*
	 * Each served once: the server accepts one connection per round, and
	 * those accepted only once the requests go out would trickle in.
	 */
	for (opened = 0; opened < conns; opened++) {
		fds[opened] = test_connect(sockpath);
		if (fds[opened] < 0 ||
		    test_cmd_entropy_count(fds[opened], TEST_RESPONSE_MS)) {
			CHECK(0, "connection %u is not served", opened);
			if (fds[opened] >= 0)
				close(fds[opened]);
			goto out;
		}
	}

	for (i = 0; i < conns; i++)
		CHECK(test_send(fds[i], cmd, sizeof(cmd)) == 0,
		      "cannot send request %u", i);

	/* The other client, while the requests are being served */
	deadline = test_now_us() + TEST_PROBE_MS * 1000;
	while (test_now_us() < deadline) {
		uint64_t start = test_now_us();

		if (test_cmd_entropy_count(other, TEST_RESPONSE_MS)) {
			CHECK(0, "the other client was not served");
			break;
		}
		if (test_now_us() - start > worst_us)
			worst_us = test_now_us() - start;
		probes++;
		test_sleep_ms(10);
	}

	for (i = 0; i < conns; i++) {
		if (test_recv(fds[i], answer, sizeof(answer), 120000) == 0)
			answered++;
	}

	printf("  other client answered after %llu ms at worst over %u commands, %u of %u requests answered\n",
	       (unsigned long long)(worst_us / 1000), probes, answered, conns);

	CHECK(worst_us * 2 < round_us,
	      "the other client waited %llu ms, the generations for all connections take %llu ms - the round had no bound",
	      (unsigned long long)(worst_us / 1000),
	      (unsigned long long)(round_us / 1000));
	CHECK(answered == conns, "%u of %u requests were not answered in full",
	      conns - answered, conns);

out:
	while (opened--)
		close(fds[opened]);
	close(other);
}

int main(int argc, char *argv[])
{
	unsigned int i;
	int rc;

	(void)argc;
	(void)argv;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(TEST_WATCHDOG_SEC);
	signal(SIGPIPE, SIG_IGN);

	esdm_logger_set_verbosity(LOGGER_WARN);

	/* One EGD worker, see above - the server starts one per node. */
	esdm_config_max_nodes_set(1);

	rc = esdm_init();
	if (rc) {
		printf("esdm_init() failed: %d\n", rc);
		return 1;
	}

	for (i = 0; i < 600 && !esdm_state_operational(); i++)
		test_sleep_ms(100);
	if (!esdm_state_operational()) {
		printf("SKIPPED: the ESDM does not become operational here\n");
		esdm_fini();
		return 77;
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

	if (esdm_egd_server_enable(sockpath) || esdm_egd_server_socket_init() ||
	    esdm_egd_server_start()) {
		printf("Cannot serve the EGD socket in %s\n", tmpdir);
		ret = 1;
		goto out;
	}

	test_flood();

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD server PR budget: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
