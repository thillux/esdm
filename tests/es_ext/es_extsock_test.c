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
 * The external entropy source of a provider process, read over a Unix domain
 * socket.
 *
 * - Without a provider configured, the source is there and does nothing.
 * - Served by the provider server of libesdm_es_ext, a block is credited with
 *   what the provider claims, at most with what the configured rate allows; a
 *   provider that fails, or fails its self test, is credited with nothing
 *   until it delivers again.
 * - A provider running as a user that is not accepted is not used.
 * - A provider that goes away is connected to again once it is back - by a
 *   seeding, or by the monitor of the source when no seeding asks; the same
 *   for a provider that was not there at start up.
 * - A provider failing its self test is credited with nothing until a self
 *   test passes, whatever it delivers meanwhile.
 * - A provider answering what the protocol does not allow - a wrong magic,
 *   more data than asked for, more entropy than the data holds - or not
 *   answering at all is disconnected and credited with nothing, and none of
 *   its data is handed on. It is not connected to again before the retry
 *   interval is over.
 *
 * The source is compiled into the test, with a short retry interval and
 * timeout so that the test does not have to wait for long.
 */

#include "config.h"

#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_SOCKET_TIMEOUT_MS 300

/* The unit under test */
#include "esdm_es_extsock.c"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>

#include "common_test.h"
#include "es_ext_test_plugin.h"

extern const struct esdm_es_ext_plugin es_ext_test_plugin;
extern struct esdm_es_ext_test_control esdm_es_ext_test_control;
static struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

static char test_dir[] = "/tmp/esdm-es-extsock-test-XXXXXX";
static char test_good[sizeof(test_dir) + 32];
static char test_evil[sizeof(test_dir) + 32];

/******************************************************************************
 * The provider of libesdm_es_ext
 ******************************************************************************/

static struct esdm_es_ext_server *test_server;
static pthread_t test_server_thread;

static void *test_server_run(void *arg)
{
	return (void *)(intptr_t)esdm_es_ext_server_run(arg);
}

static int test_server_start(void)
{
	int ret = esdm_es_ext_server_alloc(&es_ext_test_plugin, test_good, 0600,
					   &test_server);

	if (ret)
		return ret;
	return -pthread_create(&test_server_thread, NULL, test_server_run,
			       test_server);
}

static void test_server_stop(void)
{
	esdm_es_ext_server_stop(test_server);
	pthread_join(test_server_thread, NULL);
	esdm_es_ext_server_free(test_server);
	test_server = NULL;
}

/******************************************************************************
 * A provider breaking the protocol, as scripted
 ******************************************************************************/

enum test_evil_mode {
	TEST_EVIL_GOOD,
	TEST_EVIL_MAGIC,
	TEST_EVIL_TOO_LONG,
	TEST_EVIL_TOO_MUCH_ENTROPY,
	TEST_EVIL_SILENT,
};

static atomic_int test_evil_mode = TEST_EVIL_GOOD;
static atomic_bool test_evil_stop = false;
static atomic_uint test_evil_connections = 0;
static int test_evil_listen = -1;

static void *test_evil_run(void *arg)
{
	(void)arg;

	while (!atomic_load(&test_evil_stop)) {
		struct pollfd pfd = { .fd = test_evil_listen,
				      .events = POLLIN };
		int fd;

		if (poll(&pfd, 1, 50) <= 0)
			continue;
		fd = accept4(test_evil_listen, NULL, NULL, SOCK_CLOEXEC);
		if (fd < 0)
			continue;
		atomic_fetch_add(&test_evil_connections, 1);

		for (;;) {
			uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
			uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN +
				    ESDM_ES_EXT_PROTO_MAX_DATA + 8];
			uint8_t data[ESDM_ES_EXT_PROTO_MAX_DATA + 8];
			uint32_t length;
			uint16_t type;
			size_t len;
			ssize_t n;

			pfd = (struct pollfd){ .fd = fd, .events = POLLIN };
			if (poll(&pfd, 1, 50) <= 0) {
				if (atomic_load(&test_evil_stop))
					break;
				continue;
			}
			n = recv(fd, req, sizeof(req), 0);
			if (n <= 0 || esdm_es_ext_proto_req_unpack(
					      req, (size_t)n, &type, &length))
				break;

			memset(data, 0xee, sizeof(data));
			switch (atomic_load(&test_evil_mode)) {
			case TEST_EVIL_SILENT:
				continue;
			case TEST_EVIL_TOO_LONG:
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type, 0, 8, data, length + 1);
				break;
			case TEST_EVIL_TOO_MUCH_ENTROPY:
				len = esdm_es_ext_proto_rsp_pack(rsp, type, 0,
								 length * 8 + 1,
								 data, length);
				break;
			case TEST_EVIL_MAGIC:
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type, 0, 8, data, length);
				rsp[0] ^= 1;
				break;
			case TEST_EVIL_GOOD:
			default:
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type, 0, 8, data, length);
				break;
			}
			if (send(fd, rsp, len, MSG_NOSIGNAL) != (ssize_t)len)
				break;
		}
		close(fd);
	}

	return NULL;
}

static int test_evil_start(pthread_t *thread)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };

	test_evil_listen = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (test_evil_listen < 0)
		return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_evil);
	if (bind(test_evil_listen, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(test_evil_listen, 4))
		return -1;

	return pthread_create(thread, NULL, test_evil_run, NULL);
}

/******************************************************************************
 * Tests
 ******************************************************************************/

#define ES (&esdm_es_extsock)

static uint32_t test_get(uint32_t bits, uint8_t *first_byte)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	ES->get_ent(&eb_es, bits, true);
	if (first_byte)
		*first_byte = eb_es.e[0];

	return eb_es.e_bits;
}

static uint32_t test_level(uint32_t rate, uint32_t bits)
{
	return esdm_fast_noise_entropylevel(rate, bits);
}

static bool test_state_has(const char *what)
{
	char buf[1024];

	memset(buf, 0, sizeof(buf));
	ES->state(buf, sizeof(buf));
	return strstr(buf, what) != NULL;
}

static void test_wait_retry(void)
{
	const struct timespec ts = { .tv_sec =
					     ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC,
				     .tv_nsec = 100000000 };

	nanosleep(&ts, NULL);
}

static void test_unconfigured(void)
{
	CHECK_EQ(ES->init(), 0);
	CHECK(!ES->active(), "the source is active without a provider");
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK_EQ(test_get(ESDM_DRNG_SECURITY_STRENGTH_BITS, NULL), 0);
	CHECK_EQ(ES->selftest(), 0);
	CHECK(test_state_has("(unset)"), "the state names a socket");
	ES->fini();
}

static void test_arguments(void)
{
	char too_long[sizeof(((struct sockaddr_un *)0)->sun_path) + 1];

	memset(too_long, 'x', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';

	CHECK_EQ(esdm_es_ext_socket_set_path(NULL), -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_path(too_long), -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(-2), -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid((long)UINT32_MAX), -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(-1), 0);
}

static void test_credit(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	uint8_t first;

	CHECK_EQ(esdm_es_ext_socket_set_path(test_good), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active with a provider");
	CHECK(test_state_has("connected (uid"),
	      "the provider is not connected");

	esdm_config_es_ext_socket_entropy_rate_set(256);
	CHECK_EQ(ES->max_entropy(), test_level(256, esdm_security_strength()));
	CHECK_EQ(test_get(bits, &first), test_level(256, bits));
	CHECK_EQ(ctl->last_buflen, bits / 8);
	CHECK_EQ(first, ctl->get_calls & 0xff);

	CHECK_EQ(test_get(ESDM_DRNG_INIT_SEED_SIZE_BITS, NULL),
		 test_level(256, ESDM_DRNG_INIT_SEED_SIZE_BITS));
	CHECK_EQ(ctl->last_buflen, ESDM_DRNG_INIT_SEED_SIZE_BYTES);

	/* The rate caps the claim, a smaller claim stands */
	esdm_config_es_ext_socket_entropy_rate_set(64);
	CHECK_EQ(test_get(bits, NULL), test_level(64, bits));
	esdm_config_es_ext_socket_entropy_rate_set(256);
	ctl->claim_bits = 10;
	CHECK_EQ(test_get(bits, NULL), 10);

	/* A claim beyond the block is refused by the provider already */
	ctl->claim_bits = bits + 1;
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	ctl->claim_bits = UINT32_MAX;
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	/* A provider that fails, and recovers - on the same connection */
	ctl->get_ret = -EIO;
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK(test_state_has("failing"), "the state does not say it fails");
	ctl->get_ret = 0;
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	/* A failure is noticed by the monitor, without a seeding asking */
	ctl->get_ret = -EIO;
	CHECK_EQ(test_get(bits, NULL), 0);
	ctl->get_ret = 0;
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
	/* Nothing to probe for a provider that delivers */
	{
		unsigned int calls = ctl->get_calls;

		CHECK_EQ(ES->monitor_es(), 0);
		CHECK_EQ(ctl->get_calls, calls);
	}

	/* Its self test: no data delivered makes up for a failed one */
	CHECK_EQ(ES->selftest(), 0);
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(ES->selftest(), -EFAULT);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK(test_state_has("failing its self test"),
	      "the state does not say the self test fails");
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, ctl->get_calls & 0xff);
	CHECK_EQ(test_get(bits, NULL), 0);
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
}

static void test_peer_check(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;

	/* As root, the provider is root's and accepted anyway */
	if (!getuid())
		return;

	/* Root only: the provider runs as the test user */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(-1), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(test_good), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK(test_state_has("not connected"),
	      "a provider of another user was connected to");

	/* Accepted again, once the retry interval is over */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid((long)getuid()), 0);
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
}

static void test_reconnect(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;

	test_server_stop();
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK(ES->active(), "a provider away switched the source off");

	CHECK_EQ(test_server_start(), 0);
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK(test_state_has("connected (uid"), "the provider is not back");

	/*
	 * Once more, with nothing but the monitor to find out: a provider not
	 * connected is credited with nothing, which keeps an unforced reseed
	 * from asking it.
	 */
	test_server_stop();
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	test_wait_retry();
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK(test_state_has("connected (uid"),
	      "the monitor did not connect to the provider back");
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
}

/* A provider that is not there when the source starts is connected later */
static void test_late_provider(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;

	test_server_stop();
	ES->fini();
	CHECK_EQ(ES->init(), 0);
	CHECK(test_state_has("not connected"), "connected to nothing");
	CHECK_EQ(ES->max_entropy(), 0);

	CHECK_EQ(test_server_start(), 0);
	test_wait_retry();
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
}

static void test_protocol_breaches(void)
{
	static const int modes[] = { TEST_EVIL_MAGIC, TEST_EVIL_TOO_LONG,
				     TEST_EVIL_TOO_MUCH_ENTROPY,
				     TEST_EVIL_SILENT };
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct timespec start, end;
	pthread_t evil;
	unsigned int i;
	uint8_t first;

	CHECK_EQ(test_evil_start(&evil), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);

	/* It starts out well: 8 bits claimed */
	CHECK_EQ(test_get(bits, NULL), 8);

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		unsigned int conns = atomic_load(&test_evil_connections);

		atomic_store(&test_evil_mode, modes[i]);
		clock_gettime(CLOCK_MONOTONIC, &start);
		CHECK_EQ(test_get(bits, &first), 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		CHECK(first != 0xee, "data of a breach (mode %d) handed on",
		      modes[i]);
		CHECK(test_state_has("not connected"),
		      "a provider breaking the protocol (mode %d) stays connected",
		      modes[i]);
		CHECK(end.tv_sec - start.tv_sec <= 1,
		      "an unanswered request (mode %d) is waited for too long",
		      modes[i]);

		/*
		 * Not connected again at once - a provider failing that way
		 * would cost a connection, and a timeout, per seeding - but
		 * once the retry interval is over
		 */
		atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
		CHECK_EQ(test_get(bits, NULL), 0);
		CHECK_EQ(atomic_load(&test_evil_connections), conns);
		test_wait_retry();
		CHECK_EQ(test_get(bits, NULL), 8);
		CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);
	}

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
}

int main(void)
{
	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_good, sizeof(test_good), "%s/good.socket", test_dir);
	snprintf(test_evil, sizeof(test_evil), "%s/evil.socket", test_dir);

	test_arguments();
	test_unconfigured();

	/* The provider runs as the test user */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid((long)getuid()), 0);
	CHECK_EQ(test_server_start(), 0);
	if (!test_server)
		return common_test_result("es_extsock");

	test_credit();
	test_peer_check();
	test_reconnect();
	test_late_provider();
	test_protocol_breaches();

	if (test_server)
		test_server_stop();
	unlink(test_evil);
	rmdir(test_dir);

	return common_test_result("es_extsock");
}
