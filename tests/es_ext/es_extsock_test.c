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
 *   for a provider that was not there at start up. A connection the provider
 *   closed while it was idle, to make room for another client, is made again
 *   at once, the request about to be sent not lost on it.
 * - A provider failing its self test is credited with nothing until a self
 *   test passes, whatever it delivers meanwhile. Its first self test runs
 *   on the first connection to it, before it is credited.
 * - A provider answering what the protocol does not allow - a wrong magic,
 *   more data than asked for, more entropy than the data holds - or not
 *   answering at all is disconnected and credited with nothing, and none of
 *   its data is handed on. It is not connected to again before the retry
 *   interval is over.
 * - The status of the provider is the "provider" member of the state, if it
 *   is a JSON object. It is asked for at most once per interval, and not
 *   while a request is in progress - which neither the ESDM status nor the
 *   entropy available waits for. A provider that does not know STATUS - it
 *   closes the connection on it - is connected to again at once, and not
 *   asked again on that connection. One that was restarted is asked on a new
 *   connection at once. One that does not answer STATUS in time is
 *   disconnected as for any request, connected to again after the retry
 *   interval only - with DTLS - and not asked for its status for a while.
 *
 * The source is compiled into the test, with a short retry interval and
 * timeout so that the test does not have to wait for long.
 */

#include "config.h"

#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_SOCKET_TIMEOUT_MS 300
#define ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC 3

/* The unit under test */
#include "esdm_es_extsock.c"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "esdm_status_txt.h"
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

/* Whether the provider offers DTLS, as far as the library can */
static bool test_server_dtls = true;

static int test_server_start(void)
{
	int ret = esdm_es_ext_server_alloc(&es_ext_test_plugin, test_good, 0600,
					   &test_server);

	if (ret)
		return ret;
	if (!test_server_dtls)
		esdm_es_ext_server_set_dtls(test_server, 0);
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

/* How the provider answers STATUS, independent of the mode above */
enum test_evil_status {
	/* As any other request: data of the length asked for, no JSON */
	TEST_EVIL_STATUS_DATA,
	/* With a JSON object */
	TEST_EVIL_STATUS_JSON,
	/* Not at all: the connection is closed, as an old provider does */
	TEST_EVIL_STATUS_OLD,
	/* With more than asked for */
	TEST_EVIL_STATUS_TOO_LONG,
	/* Not at all, keeping the connection */
	TEST_EVIL_STATUS_SILENT,
};

#define TEST_EVIL_STATUS_TEXT "{\"evil\":1}"

static atomic_int test_evil_status = TEST_EVIL_STATUS_DATA;
/* A provider not knowing STARTDTLS: it closes the connection on it */
static atomic_bool test_evil_old = false;
static atomic_bool test_evil_stop = false;
static atomic_uint test_evil_connections = 0;
static atomic_uint test_evil_status_requests = 0;
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

			/* Its noise source is in order, whatever it answers else */
			if (type == ESDM_ES_EXT_PROTO_SELFTEST) {
				len = esdm_es_ext_proto_rsp_pack(rsp, type, 0,
								 0, NULL, 0);
				if (send(fd, rsp, len, MSG_NOSIGNAL) !=
				    (ssize_t)len)
					break;
				continue;
			}

			/* No DTLS here: refused, or unknown to an old provider */
			if (type == ESDM_ES_EXT_PROTO_STARTDTLS) {
				if (atomic_load(&test_evil_old))
					break;
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type, -EOPNOTSUPP, 0, NULL, 0);
				if (send(fd, rsp, len, MSG_NOSIGNAL) !=
				    (ssize_t)len)
					break;
				continue;
			}
			if (type == ESDM_ES_EXT_PROTO_STATUS) {
				int mode = atomic_load(&test_evil_status);

				atomic_fetch_add(&test_evil_status_requests, 1);
				if (mode == TEST_EVIL_STATUS_OLD)
					break;
				if (mode == TEST_EVIL_STATUS_SILENT)
					continue;
				if (mode == TEST_EVIL_STATUS_JSON) {
					memcpy(data, TEST_EVIL_STATUS_TEXT,
					       strlen(TEST_EVIL_STATUS_TEXT));
					length = (uint32_t)strlen(
						TEST_EVIL_STATUS_TEXT);
				} else if (mode == TEST_EVIL_STATUS_TOO_LONG) {
					length++;
				}
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type, 0, 0, data, length);
				if (send(fd, rsp, len, MSG_NOSIGNAL) !=
				    (ssize_t)len)
					break;
				continue;
			}

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

#define ES (&esdm_es_extsock[0])

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

/* Does the string member @key of the state contain @what? */
static bool test_state_has(const char *key, const char *what)
{
	struct json_object *state = es_state_get(ES);
	bool ret = es_state_str_has(state, key, what);

	if (!ret)
		printf("state: %s\n", es_state_print(state));
	json_object_put(state);
	return ret;
}

/* Make the next state ask the provider for its status anew */
static void test_status_expire(void)
{
	mutex_lock(&extsock[0].state_mutex);
	extsock[0].status.at = 0;
	mutex_unlock(&extsock[0].state_mutex);
}

/*
 * The "provider" member of the state, NULL if there is none - the status
 * kept, if it is recent
 */
static struct json_object *test_provider_kept(struct json_object **state)
{
	struct json_object *provider = NULL;

	*state = es_state_get(ES);
	if (!json_object_object_get_ex(*state, "provider", &provider))
		return NULL;
	return provider;
}

/* The same, the provider asked for its status anew */
static struct json_object *test_provider(struct json_object **state)
{
	test_status_expire();
	return test_provider_kept(state);
}

/* Is a request in progress, holding the source? */
static bool test_busy(void)
{
	if (pthread_rwlock_tryrdlock(&extsock[0].mutex))
		return true;
	pthread_rwlock_unlock(&extsock[0].mutex);
	return false;
}

static void test_wait_retry(void)
{
	const struct timespec ts = { .tv_sec =
					     ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC,
				     .tv_nsec = 100000000 };

	nanosleep(&ts, NULL);
}

/*
 * Wait out the backoff of a provider that did not answer STATUS, which began
 * up to a retry interval ago - in whole seconds of the monotonic clock
 */
static void test_wait_backoff(void)
{
	const struct timespec ts = { .tv_sec =
					     ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC,
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
	CHECK(test_state_has("provider_socket", "(unset)"),
	      "the state names a socket");
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
	/* Where a long holds it: with 32 bits, (long)UINT32_MAX is -1, no uid */
	if (sizeof(long) > sizeof(uint32_t))
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid((long)UINT32_MAX),
			 -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(-1), 0);
}

static void test_credit(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int selftest_calls = ctl->selftest_calls;
	uint8_t first;

	CHECK_EQ(esdm_es_ext_socket_set_path(test_good), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active with a provider");
	CHECK(test_state_has("status", "connected (uid"),
	      "the provider is not connected");

	/* Tested on the first connection, before it is credited */
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);

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
	CHECK(test_state_has("status", "failing"),
	      "the state does not say it fails");
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
	CHECK(test_state_has("status", "failing its self test"),
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
	CHECK(test_state_has("status", "not connected"),
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
	CHECK(test_state_has("status", "connected (uid"),
	      "the provider is not back");

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
	CHECK(test_state_has("status", "connected (uid"),
	      "the monitor did not connect to the provider back");
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
}

/*
 * The status of the provider of libesdm_es_ext, as its plugin reports it -
 * and nothing of one that reports none, or none that is a JSON object.
 */
static void test_status(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;
	unsigned int calls = ctl->status_calls;
	char txt[2048];

	provider = test_provider(&state);
	CHECK(provider != NULL, "the state has no status of the provider: %s",
	      es_state_print(state));
	CHECK(es_state_str_is(provider, "plugin", "es-ext-test"),
	      "the status is not the provider's: %s", es_state_print(state));
	CHECK_EQ(ctl->status_calls, calls + 1);
	CHECK_EQ(esdm_status_txt(state, NULL, txt, sizeof(txt)), 0);
	CHECK(strstr(txt, "\nProvider properties:\n Plugin: es-ext-test\n"),
	      "the text has no status of the provider: %s", txt);
	json_object_put(state);

	/* Failing, or no JSON object: none, and the connection stays */
	ctl->status_ret = -EIO;
	provider = test_provider(&state);
	CHECK(!provider, "the status of a failing provider is taken");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "a failing status took the connection");
	json_object_put(state);
	ctl->status_ret = 0;

	ctl->status_text = "[\"no object\"]";
	provider = test_provider(&state);
	CHECK(!provider, "a status that is no object is taken");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "an invalid status took the connection");
	json_object_put(state);
	ctl->status_text = NULL;

	/* Asked for once per interval, the last status shown in between */
	calls = ctl->status_calls;
	provider = test_provider(&state);
	CHECK(provider != NULL, "the status is gone");
	json_object_put(state);
	CHECK_EQ(ctl->status_calls, calls + 1);
	ctl->status_text = "{\"later\":1}";
	provider = test_provider_kept(&state);
	CHECK(provider && es_state_str_is(provider, "plugin", "es-ext-test"),
	      "the status was asked for again within its interval: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK_EQ(ctl->status_calls, calls + 1);
	provider = test_provider(&state);
	CHECK(provider && es_state_int(provider, "later", 0) == 1,
	      "the status was not asked for after its interval: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK_EQ(ctl->status_calls, calls + 2);
	ctl->status_text = NULL;

	/* And the provider delivers as before */
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	provider = test_provider(&state);
	CHECK(provider != NULL, "the status is gone");
	json_object_put(state);
}

/*
 * A provider restarted while the connection was idle: the request for its
 * status finds the connection gone, which is no refusal of STATUS - the
 * provider is connected to again and asked on the new connection at once.
 */
static void test_status_restarted(void)
{
	struct json_object *state, *provider;

	provider = test_provider(&state);
	CHECK(provider != NULL, "the status of the provider is not taken");
	json_object_put(state);

	test_server_stop();
	CHECK_EQ(test_server_start(), 0);

	provider = test_provider(&state);
	CHECK(provider != NULL,
	      "the restarted provider was not asked on a new connection: %s",
	      es_state_print(state));
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "the restarted provider is not connected to: %s",
	      es_state_print(state));
	json_object_put(state);

	provider = test_provider(&state);
	CHECK(provider != NULL, "the restarted provider is not asked again");
	json_object_put(state);
}

/*
 * A provider whose status takes longer than a request may: it is busy with
 * it when it is given up on, and could not take a new connection - whose
 * STARTDTLS would time out and leave the connection unencrypted. It is
 * disconnected as for any request instead, the source held for no longer
 * than the timeout, connected to again after the retry interval, encrypted
 * if it can be, and not asked for its status again before its backoff is
 * over.
 */
static void test_status_slow(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;
	struct timespec start, end;
	unsigned int calls;
	int64_t ms;

	/* On a new connection, whatever was asked on the one before */
	CHECK_EQ(esdm_es_ext_socket_set_path(test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	ctl->status_delay_ms = 3 * ESDM_EXT_SOCKET_TIMEOUT_MS;
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider(&state);
	clock_gettime(CLOCK_MONOTONIC, &end);
	ctl->status_delay_ms = 0;
	ms = (int64_t)(end.tv_sec - start.tv_sec) * 1000 +
	     (end.tv_nsec - start.tv_nsec) / 1000000;
	CHECK(!provider, "a status too late is taken");
	CHECK(es_state_str_has(state, "status", "not connected"),
	      "a provider busy with its status was connected to again: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK(ms < 2 * ESDM_EXT_SOCKET_TIMEOUT_MS,
	      "a status too late held the source for %ld ms", (long)ms);

	calls = ctl->status_calls;
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
#ifdef ESDM_DTLS
	CHECK(test_state_has("status", "DTLS"),
	      "the provider is not connected to with DTLS again");
#endif

	provider = test_provider(&state);
	CHECK(!provider, "a provider was asked for its status in its backoff");
	json_object_put(state);
	CHECK_EQ(ctl->status_calls, calls);
	test_wait_backoff();
	provider = test_provider(&state);
	CHECK(provider != NULL, "a provider is not asked after its backoff");
	json_object_put(state);
}

static void *test_get_thread(void *arg)
{
	(void)arg;
	test_get(ESDM_DRNG_SECURITY_STRENGTH_BITS, NULL);
	return NULL;
}

/*
 * A request in progress is not waited for - one the provider does not answer,
 * which holds the source for the whole timeout, as a seeding asking a provider
 * that hangs does: the recent status of the provider is shown, one that is due
 * is not asked for but left out, and the rest of the state and the entropy
 * available are as they were before the request.
 */
static void test_status_busy(void)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;
	unsigned int requests, i;
	pthread_t evil, getter;
	bool busy;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	CHECK_EQ(test_evil_start(&evil), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);

	provider = test_provider(&state);
	CHECK(provider != NULL, "the status of the provider is not taken");
	json_object_put(state);
	requests = atomic_load(&test_evil_status_requests);

	atomic_store(&test_evil_mode, TEST_EVIL_SILENT);
	CHECK_EQ(pthread_create(&getter, NULL, test_get_thread, NULL), 0);
	for (i = 0; i < 1000 && !test_busy(); i++)
		nanosleep(&ts, NULL);
	CHECK(test_busy(), "the request does not hold the source");

	provider = test_provider_kept(&state);
	CHECK(provider && es_state_int(provider, "evil", 0) == 1,
	      "the recent status is gone during a request: %s",
	      es_state_print(state));
	json_object_put(state);
	provider = test_provider(&state);
	CHECK(!provider, "the status was asked for during a request");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "the state of the connection is gone during a request: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
	CHECK_EQ(ES->max_entropy(), test_level(256, esdm_security_strength()));
	CHECK(ES->active(), "the source is not active during a request");
	busy = test_busy();
	pthread_join(getter, NULL);
	CHECK(busy, "the state waited for the request");
	CHECK_EQ(atomic_load(&test_evil_status_requests), requests);

	/* The request unanswered, the provider is connected to again */
	CHECK(test_state_has("status", "not connected"),
	      "an unanswered request kept the connection");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), 8);

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_DATA);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	CHECK_EQ(ES->init(), 0);
}

/*
 * A provider that does not know STATUS closes the connection on it: it is
 * connected to again at once, still credited, and not asked again on that
 * connection - but on the next one. One answering more than asked for breaks
 * the protocol, one not answering is connected to again as well.
 */
static void test_status_old_provider(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;
	struct timespec start, end;
	unsigned int conns, requests;
	pthread_t evil;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	CHECK_EQ(test_evil_start(&evil), 0);

	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	conns = atomic_load(&test_evil_connections);

	/* Its status, as it sends it */
	provider = test_provider(&state);
	CHECK(provider && es_state_int(provider, "evil", 0) == 1,
	      "the status of the provider is not taken: %s",
	      es_state_print(state));
	json_object_put(state);

	/* Data instead of JSON: none, on the same connection */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_DATA);
	provider = test_provider(&state);
	CHECK(!provider, "data is taken for a status");
	json_object_put(state);
	CHECK_EQ(atomic_load(&test_evil_connections), conns);

	/* An old provider: connected again at once */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_OLD);
	provider = test_provider(&state);
	CHECK(!provider, "an old provider reports a status");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "an old provider is not connected to again: %s",
	      es_state_print(state));
	json_object_put(state);
	/* Accepted by the provider by the time it answered */
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);

	/* Not asked again on that connection, whatever it would answer */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	provider = test_provider(&state);
	CHECK(!provider, "an old provider was asked again");
	json_object_put(state);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);

	/* On a new connection it is */
	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	provider = test_provider(&state);
	CHECK(provider != NULL, "a new connection was not asked");
	json_object_put(state);
	conns = atomic_load(&test_evil_connections);

	/*
	 * No answer: waited for no longer than a request, and disconnected as
	 * for one - not connected to again before the retry interval, nor
	 * asked for its status again before the backoff is over
	 */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_SILENT);
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider(&state);
	clock_gettime(CLOCK_MONOTONIC, &end);
	CHECK(!provider, "a silent provider reports a status");
	CHECK(es_state_str_has(state, "status", "not connected"),
	      "a silent provider was connected to again at once: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK(end.tv_sec - start.tv_sec <= 1,
	      "an unanswered status is waited for too long");
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(atomic_load(&test_evil_connections), conns);
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);
	requests = atomic_load(&test_evil_status_requests);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	provider = test_provider(&state);
	CHECK(!provider, "a provider was asked for its status in its backoff");
	json_object_put(state);
	CHECK_EQ(atomic_load(&test_evil_status_requests), requests);
	test_wait_backoff();
	provider = test_provider(&state);
	CHECK(provider != NULL, "a provider is not asked after its backoff");
	json_object_put(state);
	CHECK_EQ(atomic_load(&test_evil_status_requests), requests + 1);

	/* More than asked for breaks the protocol: disconnected */
	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_TOO_LONG);
	provider = test_provider(&state);
	CHECK(!provider, "a status longer than asked for is taken");
	json_object_put(state);
	provider = test_provider(&state);
	CHECK(es_state_str_has(state, "status", "not connected"),
	      "a provider breaking the protocol stays connected");
	json_object_put(state);

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_DATA);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	CHECK_EQ(ES->init(), 0);
}

/*
 * The provider makes room for another client by closing the connection idle
 * the longest when all its slots are taken - the one of the source, between
 * two seedings: the next request connects again at once, and is served.
 */
static void test_evicted(void)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000 };
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	/* The slots of the provider, the source holding one */
	int fds[8];
	bool closed = false;
	unsigned int i;

	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	nanosleep(&ts, NULL);

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_good);
	for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
		fds[i] = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
		CHECK(fds[i] >= 0 && !connect(fds[i], (struct sockaddr *)&addr,
					      sizeof(addr)),
		      "cannot connect client %u", i);
		nanosleep(&ts, NULL);
	}

	/* Closed to make room for the last client, once that is accepted */
	for (i = 0; i < 200; i++) {
		mutex_lock(&extsock[0].mutex);
		closed = extsock[0].fd >= 0 &&
			 esdm_es_extsock_closed_locked(&extsock[0]);
		mutex_unlock(&extsock[0].mutex);
		if (closed)
			break;
		nanosleep(&ts, NULL);
	}
	CHECK(closed, "the provider kept the connection idle the longest");
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK(test_state_has("status", "connected (uid"),
	      "the source is not connected again");
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));

	for (i = 0; i < sizeof(fds) / sizeof(fds[0]); i++) {
		if (fds[i] >= 0)
			close(fds[i]);
	}
}

/*
 * A provider that is not there when the source starts is connected later -
 * and tested then, before it is credited: the self test pass of the ESDM
 * found nothing to test.
 */
static void test_late_provider(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int selftest_calls;

	test_server_stop();
	ES->fini();
	CHECK_EQ(ES->init(), 0);
	CHECK(test_state_has("status", "not connected"),
	      "connected to nothing");
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK_EQ(ES->selftest(), 0);

	/* Failing that test, it is connected and credited with nothing */
	ctl->selftest_ret = -ENODEV;
	selftest_calls = ctl->selftest_calls;
	CHECK_EQ(test_server_start(), 0);
	test_wait_retry();
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
	CHECK(test_state_has("status", "failing its self test"),
	      "the first self test of a late provider did not run");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(test_get(bits, NULL), 0);

	/* Until a self test passes */
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));

	/* Passing it, credited at once */
	test_server_stop();
	ES->fini();
	CHECK_EQ(ES->init(), 0);
	selftest_calls = ctl->selftest_calls;
	CHECK_EQ(test_server_start(), 0);
	test_wait_retry();
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
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
		CHECK(test_state_has("status", "not connected"),
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

/******************************************************************************
 * The channel as a relay between the source and the provider sees it
 ******************************************************************************/

static char test_relay[sizeof(test_dir) + 32];
static int test_relay_listen = -1;
static atomic_bool test_relay_stop = false;
/* A message of the provider held the plaintext data of the test plugin */
static atomic_bool test_relay_saw_plaintext = false;
static atomic_uint test_relay_messages = 0;

/* The test plugin fills a block with one byte value - a run of 16 tells */
static bool test_has_run(const uint8_t *buf, size_t len)
{
	size_t i, run = 1;

	for (i = 1; i < len; i++) {
		run = buf[i] == buf[i - 1] ? run + 1 : 1;
		if (run >= 16)
			return true;
	}
	return false;
}

static void *test_relay_run(void *arg)
{
	(void)arg;

	while (!atomic_load(&test_relay_stop)) {
		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		struct pollfd pfd[2] = { { .fd = test_relay_listen,
					   .events = POLLIN } };
		int esdm, provider;

		if (poll(pfd, 1, 50) <= 0)
			continue;
		esdm = accept4(test_relay_listen, NULL, NULL, SOCK_CLOEXEC);
		if (esdm < 0)
			continue;

		provider = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
		snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_good);
		if (provider < 0 ||
		    connect(provider, (struct sockaddr *)&addr, sizeof(addr))) {
			close(esdm);
			if (provider >= 0)
				close(provider);
			continue;
		}

		/* Every message on to the other side, one by one */
		for (;;) {
			uint8_t buf[8192];
			ssize_t n;

			pfd[0] =
				(struct pollfd){ .fd = esdm, .events = POLLIN };
			pfd[1] = (struct pollfd){ .fd = provider,
						  .events = POLLIN };
			if (poll(pfd, 2, 50) <= 0) {
				if (atomic_load(&test_relay_stop))
					break;
				continue;
			}
			if (pfd[0].revents) {
				n = recv(esdm, buf, sizeof(buf), 0);
				if (n <= 0 || send(provider, buf, (size_t)n,
						   MSG_NOSIGNAL) != n)
					break;
			}
			if (pfd[1].revents) {
				n = recv(provider, buf, sizeof(buf), 0);
				if (n <= 0)
					break;
				atomic_fetch_add(&test_relay_messages, 1);
				if (test_has_run(buf, (size_t)n))
					atomic_store(&test_relay_saw_plaintext,
						     true);
				if (send(esdm, buf, (size_t)n, MSG_NOSIGNAL) !=
				    n)
					break;
			}
		}
		close(esdm);
		close(provider);
	}

	return NULL;
}

/*
 * What the channel shows to whoever can observe it: with DTLS, none of the
 * data delivered; unencrypted, all of it - which tells that the relay would
 * have seen the data if it was there.
 */
static void test_eavesdrop(bool dtls)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	pthread_t relay;
	unsigned int i;

	test_server_stop();
	test_server_dtls = dtls;
	CHECK_EQ(test_server_start(), 0);
	test_server_dtls = true;

	test_relay_listen = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_relay);
	unlink(test_relay);
	CHECK_EQ(bind(test_relay_listen, (struct sockaddr *)&addr,
		      sizeof(addr)),
		 0);
	CHECK_EQ(listen(test_relay_listen, 4), 0);
	atomic_store(&test_relay_stop, false);
	atomic_store(&test_relay_saw_plaintext, false);
	atomic_store(&test_relay_messages, 0);
	CHECK_EQ(pthread_create(&relay, NULL, test_relay_run, NULL), 0);

	CHECK_EQ(esdm_es_ext_socket_set_path(test_relay), 0);
	for (i = 0; i < 4; i++)
		CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK(atomic_load(&test_relay_messages) >= 4,
	      "the relay saw no answers");

#ifdef ESDM_DTLS
	if (dtls) {
		CHECK(test_state_has("status", "DTLS"),
		      "the connection is not encrypted");
		CHECK(!atomic_load(&test_relay_saw_plaintext),
		      "the data delivered can be read off the channel");
	} else
#endif
	{
		CHECK(test_state_has("status", "unencrypted"),
		      "the state does not say the connection is unencrypted");
		CHECK(atomic_load(&test_relay_saw_plaintext),
		      "the relay does not see the data of an unencrypted channel");
	}

	atomic_store(&test_relay_stop, true);
	ES->fini();
	pthread_join(relay, NULL);
	close(test_relay_listen);
	unlink(test_relay);
	CHECK_EQ(ES->init(), 0);
}

/*
 * A provider that does not know STARTDTLS closes the connection on it, and is
 * used unencrypted on the next connection, right away.
 */
static void test_old_provider(void)
{
#ifdef ESDM_DTLS
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	pthread_t evil;
	unsigned int conns;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_old, true);
	CHECK_EQ(test_evil_start(&evil), 0);
	conns = atomic_load(&test_evil_connections);

	CHECK_EQ(esdm_es_ext_socket_set_path(test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 2);
	CHECK(test_state_has("status", "unencrypted"),
	      "an old provider is not used unencrypted");

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_old, false);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	CHECK_EQ(ES->init(), 0);
#endif
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
	snprintf(test_relay, sizeof(test_relay), "%s/relay.socket", test_dir);

	test_arguments();
	test_unconfigured();

	/* The provider runs as the test user */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid((long)getuid()), 0);
	CHECK_EQ(test_server_start(), 0);
	if (!test_server)
		return common_test_result("es_extsock");

	test_credit();
	test_status();
	test_status_restarted();
	test_status_slow();
	test_evicted();
	test_peer_check();
	test_reconnect();
	test_late_provider();
	test_eavesdrop(true);
	test_eavesdrop(false);
	test_old_provider();
	test_status_old_provider();
	test_status_busy();
	test_protocol_breaches();

	if (test_server)
		test_server_stop();
	unlink(test_evil);
	rmdir(test_dir);

	return common_test_result("es_extsock");
}
