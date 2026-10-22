/*
 * Tests of the EGD server with prediction resistant requests on several
 * workers
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
 * One client keeps prediction resistant blocking reads of the largest size in
 * flight on its connection, as a heavy consumer of them does - or a client out
 * to keep the others away from the prediction resistance DRNG. Meanwhile:
 *
 *   - clients on further connections, which the server spreads over its
 *     workers, each ask for one prediction resistant block, and are all
 *     answered within a fraction of the time the flood goes on,
 *   - a caller of esdm_get_random_bytes_pr_noblock() outside the EGD server -
 *     an RPC worker, say - gets its bytes within the same time.
 *
 * Every worker, and every server, shares the one prediction resistance DRNG.
 * Taking it by a trylock, a worker that found it taken deferred its request
 * and came back after its poll interval, while the client of the other worker
 * had its next request generated the moment the previous one released it.
 *
 * Like the other EGD server tests, the server runs in this process, here with
 * several workers - one per node, up to the server's limit. The ESDM has to be
 * operational, which the Jitter RNG makes it.
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

/* Nodes asked for - the server starts a worker per node, up to its limit */
#define TEST_NODES 4

/* Reads the flooding client keeps in flight */
#define TEST_FLOOD_READS 4

/* Clients asking for one block each while the flood goes on */
#define TEST_CLIENTS 8

/* Bytes they ask for: one block of the prediction resistance DRNG */
#define TEST_BLOCK 32

/*
 * How long they may take to be answered: a block costs a seeding, so all of
 * them one after the other, interleaved with the flood's, take some twenty
 * blocks. Forty of them, or this, whichever is longer - a sanitizer, or a
 * busy machine, makes a seeding take far longer than the milliseconds it
 * takes otherwise. The flood goes on for longer than that.
 */
#define TEST_FAIR_MIN_MS 3000
#define TEST_FAIR_BLOCKS 40
#define TEST_FLOOD_EXTRA_MS 5000

static uint64_t test_fair_ms, test_flood_ms;

/* How long the flood runs before the others ask */
#define TEST_RAMP_MS 1000

static char tmpdir[] = "/tmp/esdm-egd-pr-fairness-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];

static atomic_bool test_flood_stop = false;
static atomic_ulong test_flood_reads = 0;

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

/* Read exactly @len bytes, or give up after @timeout_ms without any */
static int test_recv(int fd, void *buf, size_t len, int timeout_ms)
{
	uint8_t *p = buf;
	size_t received = 0;

	while (received < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int pret = poll(&pfd, 1, timeout_ms);
		ssize_t rc;

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

static uint64_t test_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

/*
 * Time one block of the prediction resistance DRNG takes here, in
 * milliseconds, rounded up: the best of a few, nobody else asking.
 */
static uint64_t test_block_cost_ms(void)
{
	uint8_t buf[TEST_BLOCK];
	uint64_t start, cost, best = UINT64_MAX;
	unsigned int i;

	for (i = 0; i < 5; i++) {
		start = test_now_us();
		if (esdm_get_random_bytes_pr_noblock(buf, sizeof(buf)) <= 0)
			continue;
		cost = test_now_us() - start;
		if (cost < best)
			best = cost;
	}

	return (best == UINT64_MAX) ? 0 : best / 1000 + 1;
}

/* The flooding client: the largest blocking reads, several in flight */
static void *test_flood(void *arg)
{
	static uint8_t answers[TEST_FLOOD_READS * ESDM_EGD_MAX_TRANSFER];
	uint8_t cmds[2 * TEST_FLOOD_READS];
	int fd = *(int *)arg;
	unsigned int i;

	for (i = 0; i < TEST_FLOOD_READS; i++) {
		cmds[2 * i] = ESDM_EGD_CMD_ESDM_PR_READ_BLOCK;
		cmds[2 * i + 1] = ESDM_EGD_MAX_TRANSFER;
	}

	while (!atomic_load(&test_flood_stop)) {
		if (send(fd, cmds, sizeof(cmds), MSG_NOSIGNAL) !=
		    (ssize_t)sizeof(cmds))
			break;
		if (test_recv(fd, answers, sizeof(answers), 60000))
			break;
		atomic_fetch_add(&test_flood_reads, TEST_FLOOD_READS);
	}

	return NULL;
}

/* A caller outside the EGD server, as an RPC worker is */
struct test_direct {
	uint64_t start;
	uint64_t answered;
	ssize_t rc;
};

static void *test_direct(void *arg)
{
	struct test_direct *d = arg;
	uint8_t buf[TEST_BLOCK];

	d->start = test_now_ms();
	while (test_now_ms() - d->start < test_flood_ms) {
		d->rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (d->rc > 0) {
			d->answered = test_now_ms();
			break;
		}
		/* An RPC client asks again after a pause */
		test_sleep_ms(10);
	}

	return NULL;
}

static void test_fairness(void)
{
	const uint8_t cmd[2] = { ESDM_EGD_CMD_ESDM_PR_READ_BLOCK, TEST_BLOCK };
	uint64_t start, done[TEST_CLIENTS] = { 0 }, worst = 0;
	struct test_direct direct = { 0 };
	pthread_t flooder, direct_thread;
	int flood_fd, fds[TEST_CLIENTS];
	unsigned int i, opened, answered = 0;

	printf("EGD PR fairness: one client floods, %u others ask for a block each\n",
	       TEST_CLIENTS);

	test_fair_ms = TEST_FAIR_BLOCKS * test_block_cost_ms();
	if (test_fair_ms < TEST_FAIR_MIN_MS)
		test_fair_ms = TEST_FAIR_MIN_MS;
	test_flood_ms = test_fair_ms + TEST_FLOOD_EXTRA_MS;
	printf("  answers expected within %llu ms, the flood lasting %llu ms\n",
	       (unsigned long long)test_fair_ms,
	       (unsigned long long)test_flood_ms);

	flood_fd = test_connect(sockpath);
	CHECK(flood_fd >= 0, "the flooding client cannot connect");
	if (flood_fd < 0)
		return;

	if (pthread_create(&flooder, NULL, test_flood, &flood_fd)) {
		CHECK(0, "cannot start the flooding client");
		close(flood_fd);
		return;
	}

	test_sleep_ms(TEST_RAMP_MS);

	for (opened = 0; opened < TEST_CLIENTS; opened++) {
		fds[opened] = test_connect(sockpath);
		if (fds[opened] < 0) {
			CHECK(0, "client %u cannot connect", opened);
			goto out;
		}
	}

	if (pthread_create(&direct_thread, NULL, test_direct, &direct)) {
		CHECK(0, "cannot start the direct caller");
		goto out;
	}

	start = test_now_ms();
	for (i = 0; i < TEST_CLIENTS; i++)
		CHECK(send(fds[i], cmd, sizeof(cmd), MSG_NOSIGNAL) ==
			      (ssize_t)sizeof(cmd),
		      "cannot send the request of client %u", i);

	/* Their answers, in whatever order they come */
	while (answered < TEST_CLIENTS &&
	       test_now_ms() - start < test_flood_ms) {
		struct pollfd pfd[TEST_CLIENTS];

		for (i = 0; i < TEST_CLIENTS; i++) {
			pfd[i].fd = done[i] ? -1 : fds[i];
			pfd[i].events = POLLIN;
			pfd[i].revents = 0;
		}

		if (poll(pfd, TEST_CLIENTS, 100) < 0 && errno != EINTR)
			break;

		for (i = 0; i < TEST_CLIENTS; i++) {
			uint8_t answer[TEST_BLOCK];

			if (pfd[i].fd < 0 || !(pfd[i].revents & POLLIN))
				continue;
			if (test_recv(fds[i], answer, sizeof(answer), 10000)) {
				CHECK(0, "client %u got no full answer", i);
				done[i] = UINT64_MAX;
			} else {
				done[i] = test_now_ms() - start;
				if (done[i] > worst)
					worst = done[i];
			}
			answered++;
		}
	}

	pthread_join(direct_thread, NULL);

	printf("  %lu reads of the flood served, %u of %u clients answered, the last after %llu ms; the direct caller %s after %llu ms\n",
	       atomic_load(&test_flood_reads), answered, TEST_CLIENTS,
	       (unsigned long long)worst,
	       direct.answered ? "was served" : "was NOT served",
	       (unsigned long long)((direct.answered ? direct.answered :
						       test_now_ms()) -
				    direct.start));

	for (i = 0; i < TEST_CLIENTS; i++) {
		CHECK(done[i] && done[i] != UINT64_MAX &&
			      done[i] <= test_fair_ms,
		      "client %u answered after %lld ms, not within %llu ms", i,
		      done[i] ? (long long)done[i] : -1LL,
		      (unsigned long long)test_fair_ms);
	}

	CHECK(direct.answered && direct.answered - direct.start <= test_fair_ms,
	      "the direct caller was not served within %llu ms (last %zd)",
	      (unsigned long long)test_fair_ms, direct.rc);

out:
	atomic_store(&test_flood_stop, true);
	shutdown(flood_fd, SHUT_RDWR);
	pthread_join(flooder, NULL);
	close(flood_fd);
	while (opened--)
		close(fds[opened]);
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

	/* Several EGD workers - the server starts one per node */
	esdm_config_max_nodes_set(TEST_NODES);
	if (esdm_config_online_nodes() < 2) {
		printf("SKIPPED: a single node, a single EGD worker\n");
		return 77;
	}

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

	test_fairness();

out:
	esdm_egd_server_fini();
	esdm_egd_server_cleanup();
	esdm_fini();
	rmdir(tmpdir);

	printf("EGD server PR fairness: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
