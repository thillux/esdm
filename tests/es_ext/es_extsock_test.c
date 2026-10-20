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
 *   test passes, whatever it delivers meanwhile. A self test runs on every
 *   new connection to it, before it is credited - on the first one, and on
 *   one to a provider restarted.
 * - A provider answering what the protocol does not allow - a wrong magic,
 *   more data than asked for, more entropy than the data holds - or not
 *   answering at all is disconnected and credited with nothing, and none of
 *   its data is handed on. It is not connected to again before the retry
 *   interval is over.
 * - The source is shown under the name the provider declares in its answer to
 *   INFO, which it is asked for once per connection - inside the DTLS session
 *   where there is one - with its instance name next to it. A name that is not
 *   valid, or that of another entropy source, is not taken; a provider that
 *   does not know INFO, or answers what the protocol does not allow, is
 *   connected to again at once without asking and works without a name.
 * - A source is credited at the rate configured for it, else at the one its
 *   provider declares in its answer to INFO - capped at 256 - else at 0; the
 *   rate is asked for anew on every connection. A provider that does not know
 *   INFO declares none.
 * - The status of the provider is the "provider" member of the state, if it
 *   is a JSON object. It is asked for at most once per interval, and not
 *   while a request is in progress - which neither the ESDM status nor the
 *   entropy available waits for. The ESDM status connects to no provider: a
 *   provider that does not know STATUS - it closes the connection on it - is
 *   connected to again by the next seeding, at once, and not asked on that
 *   connection; one that was restarted is asked on the connection the next
 *   seeding makes, at once. One that does not answer STATUS in time is not
 *   waited for any longer, but keeps its connection: its answer, coming in
 *   later, is taken off it by the next seeding, or the next ESDM status, and
 *   shown - and the seeding is served. Nor is it asked for its status for a
 *   while.
 *
 * The source is compiled into the test, with a short retry interval and
 * timeout so that the test does not have to wait for long.
 */

#include "config.h"

#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_SOCKET_TIMEOUT_MS 300
#define ESDM_EXT_SOCKET_STATUS_TIMEOUT_MS 50
#define ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC 2

/* The unit under test */
#include "esdm_es_extsock.c"

#include <pthread.h>
#include <stdatomic.h>
#include <sys/stat.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "esdm_status_txt.h"
#include "es_ext_test_plugin.h"

extern struct esdm_es_ext_plugin es_ext_test_plugin;
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

/* How the provider answers INFO, independent of the modes above */
enum test_evil_info {
	/* -EOPNOTSUPP: it declares nothing */
	TEST_EVIL_INFO_NONE,
	/* With the name of test_evil_name */
	TEST_EVIL_INFO_NAME,
	/* With one byte of name more than a name may have */
	TEST_EVIL_INFO_TOO_LONG,
	/* Not at all: the connection is closed, as an old provider does */
	TEST_EVIL_INFO_OLD,
};

static atomic_int test_evil_info = TEST_EVIL_INFO_NONE;
/* The rate of TEST_EVIL_INFO_NAME */
static atomic_uint test_evil_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
static atomic_uint test_evil_info_requests = 0;
/* The last INFO request as it arrived, byte for byte */
static uint8_t test_evil_info_req[ESDM_ES_EXT_PROTO_REQ_LEN];
/* The name of TEST_EVIL_INFO_NAME, set while no request is in progress */
static char test_evil_name[ESDM_ES_EXT_NAME_MAX + 2] = "evil";
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
				    ESDM_ES_EXT_PROTO_MAX_RSP_DATA + 8];
			/* A status of the length asked for, too */
			uint8_t data[ESDM_ES_EXT_PROTO_MAX_RSP_DATA + 8];
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
			if (type == ESDM_ES_EXT_PROTO_INFO) {
				int mode = atomic_load(&test_evil_info);
				uint32_t datalen;

				memcpy(test_evil_info_req, req,
				       sizeof(test_evil_info_req));
				atomic_fetch_add(&test_evil_info_requests, 1);
				if (mode == TEST_EVIL_INFO_OLD)
					break;
				esdm_es_ext_put_le32(
					data, atomic_load(&test_evil_rate));
				datalen = 4 + (uint32_t)strlen(test_evil_name);
				memcpy(data + 4, test_evil_name,
				       strlen(test_evil_name));
				if (mode == TEST_EVIL_INFO_TOO_LONG) {
					memset(data + 4, 'x',
					       ESDM_ES_EXT_NAME_MAX + 1);
					datalen = 4 + ESDM_ES_EXT_NAME_MAX + 1;
				}
				len = esdm_es_ext_proto_rsp_pack(
					rsp, type,
					mode == TEST_EVIL_INFO_NONE ?
						-EOPNOTSUPP :
						0,
					0, data, datalen);
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
 * The status of the plugin a provider of the library serves - the "plugin"
 * member of the "provider" member of the state, next to the fields of the
 * server - or the "provider" member itself for a provider of the test; NULL
 * if there is none. The status kept, if it is recent.
 */
static struct json_object *test_provider_kept(struct json_object **state)
{
	struct json_object *provider = NULL, *plugin = NULL;

	*state = es_state_get(ES);
	if (!json_object_object_get_ex(*state, "provider", &provider))
		return NULL;
	if (!json_object_object_get_ex(provider, "server", NULL))
		return provider;
	if (!json_object_object_get_ex(provider, "plugin", &plugin))
		return NULL;
	return plugin;
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

/* The milliseconds since @start, of the monotonic clock */
static int64_t test_ms_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)(now.tv_sec - start->tv_sec) * 1000 +
	       (now.tv_nsec - start->tv_nsec) / 1000000;
}

/* Sleep until the clock of the source passed @deadline, nanoseconds */
static void test_wait_until(uint64_t deadline)
{
	uint64_t now = esdm_es_extsock_now(), left;
	struct timespec ts;

	if (now > deadline)
		return;
	/* And a millisecond more, past the deadline for sure */
	left = deadline - now + 1000000;
	ts.tv_sec = (time_t)(left / ESDM_ES_EXTSOCK_NSEC_PER_SEC);
	ts.tv_nsec = (long)(left % ESDM_ES_EXTSOCK_NSEC_PER_SEC);
	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/*
 * Wait until the source connects again: until the end of the retry interval
 * it recorded when it gave up on the provider - not for a retry interval from
 * now, part of which a loaded machine may have spent already, nor one that a
 * clock of whole seconds made up to a second shorter
 */
static void test_wait_retry(void)
{
	uint64_t at;

	mutex_lock(&extsock[0].mutex);
	at = extsock[0].retry_at;
	mutex_unlock(&extsock[0].mutex);
	test_wait_until(at);
}

/*
 * Wait out the backoff of a provider that did not answer STATUS - until the
 * end of it the source recorded
 */
static void test_wait_backoff(void)
{
	uint64_t until;

	mutex_lock(&extsock[0].mutex);
	until = extsock[0].status_backoff_until;
	mutex_unlock(&extsock[0].mutex);
	test_wait_until(until);
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

	CHECK_EQ(esdm_es_ext_socket_set_path(0, NULL), -EINVAL);
	/* No source beyond those the build has */
	CHECK_EQ(esdm_es_ext_socket_set_path(ESDM_EXT_SOCKET_NUM, test_good),
		 -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(ESDM_EXT_SOCKET_NUM, -1),
		 -EINVAL);
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(ESDM_EXT_SOCKET_NUM,
							    256),
		 -EINVAL);
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate(ESDM_EXT_SOCKET_NUM), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, too_long), -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, -2), -EINVAL);
	/* Every uid fits, where a long has 32 bits as well: (uid_t)-1 is none */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, (int64_t)UINT32_MAX),
		 -EINVAL);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, (int64_t)UINT32_MAX - 1), 0);
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, -1), 0);
}

static void test_credit(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int selftest_calls = ctl->selftest_calls;
	uint8_t first;

	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active with a provider");
	CHECK(test_state_has("status", "connected (uid"),
	      "the provider is not connected");

	/* Tested on the first connection, before it is credited */
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);

	esdm_config_es_ext_socket_entropy_rate_set(0, 256);
	CHECK_EQ(ES->max_entropy(), test_level(256, esdm_security_strength()));
	CHECK_EQ(test_get(bits, &first), test_level(256, bits));
	CHECK_EQ(ctl->last_buflen, bits / 8);
	CHECK_EQ(first, ctl->get_calls & 0xff);

	CHECK_EQ(test_get(ESDM_DRNG_INIT_SEED_SIZE_BITS, NULL),
		 test_level(256, ESDM_DRNG_INIT_SEED_SIZE_BITS));
	CHECK_EQ(ctl->last_buflen, ESDM_DRNG_INIT_SEED_SIZE_BYTES);

	/* The rate caps the claim, a smaller claim stands */
	esdm_config_es_ext_socket_entropy_rate_set(0, 64);
	CHECK_EQ(test_get(bits, NULL), test_level(64, bits));
	esdm_config_es_ext_socket_entropy_rate_set(0, 256);
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
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, -1), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK(test_state_has("status", "not connected"),
	      "a provider of another user was connected to");

	/* Accepted again, once the retry interval is over */
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, (int64_t)getuid()), 0);
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
	struct json_object *state, *provider, *server, *val = NULL;
	char big[ESDM_ES_EXT_STATUS_MAX + 2];
	unsigned int calls = ctl->status_calls;
	char txt[2048];

	provider = test_provider(&state);
	CHECK(provider != NULL, "the state has no status of the provider: %s",
	      es_state_print(state));
	CHECK(es_state_str_is(provider, "plugin", "es-ext-test"),
	      "the status is not the provider's: %s", es_state_print(state));
	CHECK_EQ(ctl->status_calls, calls + 1);
	CHECK_EQ(esdm_status_txt(state, NULL, txt, sizeof(txt)), 0);
	CHECK(strstr(txt, "\nProvider properties:\n Server properties:\n") &&
		      strstr(txt, "\n Plugin properties:\n  Plugin: es-ext-test\n"),
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

	/*
	 * The fields of the server arrive whatever the plugin reports: the
	 * DTLS of the connection, and the status of the plugin left out -
	 * not cut short - when it is larger than a status of a plugin may be
	 */
	memset(big, 'a', sizeof(big));
	memcpy(big, "{\"x\":\"", 6);
	memcpy(big + ESDM_ES_EXT_STATUS_MAX - 1, "\"}", 3);
	ctl->status_text = big;
	provider = test_provider(&state);
	CHECK(!provider, "a status too large is taken");
	CHECK(json_object_object_get_ex(state, "provider", &server) &&
		      json_object_object_get_ex(server, "server", &server) &&
		      json_object_object_get_ex(server, "dtls", &val) &&
		      json_object_is_type(val, json_type_boolean),
	      "the fields of the server are gone with the status: %s",
	      es_state_print(state));
#ifdef ESDM_DTLS
	CHECK(json_object_get_boolean(val),
	      "the server does not report the DTLS of the connection: %s",
	      es_state_print(state));
#endif
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
 * status finds the connection gone, which is no refusal of STATUS. The ESDM
 * status goes without the status of the provider, and does not connect to it:
 * the next seeding does, at once, and the provider is asked on the new
 * connection.
 */
static void test_status_restarted(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;

	provider = test_provider(&state);
	CHECK(provider != NULL, "the status of the provider is not taken");
	json_object_put(state);

	test_server_stop();
	CHECK_EQ(test_server_start(), 0);

	provider = test_provider(&state);
	CHECK(!provider, "a provider restarted has the status of the one before");
	CHECK(es_state_str_has(state, "status", "not connected"),
	      "the ESDM status connected to the restarted provider: %s",
	      es_state_print(state));
	json_object_put(state);

	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	provider = test_provider(&state);
	CHECK(provider != NULL,
	      "the restarted provider was not asked on the new connection: %s",
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
 * A provider whose status takes longer than the ESDM status waits for it: the
 * source is held for no longer than that, and the provider keeps its
 * connection - it answers one request after the other. Its answer comes in
 * later, before the one to the next request: taken off the connection by the
 * next seeding - which is served on the connection - or by the next ESDM
 * status, it is shown as the status of the provider. Nor is the provider
 * asked for its status again before its backoff is over.
 */
static void test_status_slow(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	/* Longer than the timeout of any request */
	const unsigned int slow = 3 * ESDM_EXT_SOCKET_TIMEOUT_MS;
	/* Answered well within the timeout of the request after it */
	const unsigned int late = 2 * ESDM_EXT_SOCKET_STATUS_TIMEOUT_MS;
	struct json_object *state, *provider;
	unsigned int calls, selftests;
	struct timespec start;
	int64_t ms;

	/* On a new connection, whatever was asked on the one before */
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	/* Each connection tests the provider first: no new one is made */
	selftests = ctl->selftest_calls;

	ctl->status_text = "{\"slow\":1}";
	ctl->status_delay_ms = slow;
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider(&state);
	ms = test_ms_since(&start);
	ctl->status_delay_ms = 0;
	CHECK(!provider, "a status too late is taken");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "a provider slow with its status was disconnected: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK(ms < ESDM_EXT_SOCKET_TIMEOUT_MS,
	      "a status too late held the source for %ld ms", (long)ms);

	/*
	 * Its answer comes in while the connection is idle - no end of it:
	 * the next seeding takes it off, and is served on the connection
	 */
	test_wait_until(esdm_es_extsock_now() + (uint64_t)slow * 1000000);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ctl->selftest_calls, selftests);
	provider = test_provider_kept(&state);
	CHECK(provider && es_state_int(provider, "slow", 0) == 1,
	      "the late status of the provider is not shown: %s",
	      es_state_print(state));
	json_object_put(state);

	calls = ctl->status_calls;
	provider = test_provider(&state);
	CHECK(!provider, "a provider was asked for its status in its backoff");
	json_object_put(state);
	CHECK_EQ(ctl->status_calls, calls);
	test_wait_backoff();

	/*
	 * A seeding right after: it waits for the provider to answer the
	 * status first, takes that off the connection, and gets its data
	 */
	ctl->status_text = "{\"slow\":2}";
	ctl->status_delay_ms = late;
	provider = test_provider(&state);
	json_object_put(state);
	ctl->status_delay_ms = 0;
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ctl->selftest_calls, selftests);
	provider = test_provider_kept(&state);
	CHECK(provider && es_state_int(provider, "slow", 0) == 2,
	      "the status answered before the data is not shown: %s",
	      es_state_print(state));
	json_object_put(state);
	test_wait_backoff();

	/* No seeding in between: the next ESDM status takes it off */
	ctl->status_text = "{\"slow\":3}";
	ctl->status_delay_ms = late;
	provider = test_provider(&state);
	json_object_put(state);
	ctl->status_delay_ms = 0;
	test_wait_until(esdm_es_extsock_now() + (uint64_t)late * 1000000);
	provider = test_provider(&state);
	CHECK(provider && es_state_int(provider, "slow", 0) == 3,
	      "the late status was not taken by the next ESDM status: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK_EQ(ctl->selftest_calls, selftests);
	CHECK(test_state_has("status", "connected (uid"),
	      "the provider is not connected any more");
	ctl->status_text = NULL;
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
 *
 * What is looked at during the request has to be looked at within the
 * timeout: a round that a loaded machine made take longer tells nothing, and
 * is done again. A state waiting for the request takes longer in every round.
 */
static void test_status_busy(void)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct json_object *state, *provider;
	bool held = false, kept = false, asked = true, connected = false,
	     active = false, busy = false;
	uint32_t level = 0, poolsize = 0;
	unsigned int requests = 0, round;
	char kept_state[1024] = "", busy_state[1024] = "";
	pthread_t evil, getter;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	CHECK_EQ(test_evil_start(&evil), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);

	for (round = 0; round < 5 && !busy; round++) {
		struct timespec start;

		test_wait_retry();
		CHECK_EQ(test_get(bits, NULL), 8);
		provider = test_provider(&state);
		CHECK(provider != NULL,
		      "the status of the provider is not taken");
		json_object_put(state);
		requests = atomic_load(&test_evil_status_requests);

		atomic_store(&test_evil_mode, TEST_EVIL_SILENT);
		CHECK_EQ(pthread_create(&getter, NULL, test_get_thread, NULL),
			 0);
		clock_gettime(CLOCK_MONOTONIC, &start);
		while (test_ms_since(&start) < 5000 && !test_busy())
			nanosleep(&ts, NULL);
		held = test_busy();

		provider = test_provider_kept(&state);
		kept = provider && es_state_int(provider, "evil", 0) == 1;
		snprintf(kept_state, sizeof(kept_state), "%s",
			 es_state_print(state));
		json_object_put(state);
		provider = test_provider(&state);
		asked = provider != NULL;
		connected = es_state_str_has(state, "status", "connected (uid");
		snprintf(busy_state, sizeof(busy_state), "%s",
			 es_state_print(state));
		json_object_put(state);
		level = ES->curr_entropy(bits);
		poolsize = ES->max_entropy();
		active = ES->active();
		busy = test_busy();
		pthread_join(getter, NULL);
		atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
		if (held && !busy)
			printf("round %u: the request was over before the state was looked at, once more\n",
			       round);
	}

	CHECK(held, "the request does not hold the source");
	CHECK(busy, "the state waited for the request");
	CHECK(kept, "the recent status is gone during a request: %s",
	      kept_state);
	CHECK(!asked, "the status was asked for during a request");
	CHECK(connected,
	      "the state of the connection is gone during a request: %s",
	      busy_state);
	CHECK_EQ(level, test_level(256, bits));
	CHECK_EQ(poolsize, test_level(256, esdm_security_strength()));
	CHECK(active, "the source is not active during a request");
	CHECK_EQ(atomic_load(&test_evil_status_requests), requests);

	/* The request unanswered, the provider is connected to again */
	CHECK(test_state_has("status", "not connected"),
	      "an unanswered request kept the connection");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
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
	unsigned int conns, requests;
	struct timespec start;
	pthread_t evil;
	int64_t ms;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	CHECK_EQ(test_evil_start(&evil), 0);

	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
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

	/*
	 * An old provider: no status, and connected to again by the next
	 * seeding at once - not by the ESDM status
	 */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_OLD);
	provider = test_provider(&state);
	CHECK(!provider, "an old provider reports a status");
	CHECK(es_state_str_has(state, "status", "not connected"),
	      "the ESDM status connected to an old provider again: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);

	/* Not asked again on that connection, whatever it would answer */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_JSON);
	provider = test_provider(&state);
	CHECK(!provider, "an old provider was asked again");
	json_object_put(state);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);

	/* On a new connection it is */
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	provider = test_provider(&state);
	CHECK(provider != NULL, "a new connection was not asked");
	json_object_put(state);
	conns = atomic_load(&test_evil_connections);

	/*
	 * No answer: waited for no longer than the ESDM status waits, and the
	 * connection kept - the next seeding is answered on it, no answer to
	 * STATUS coming before - nor asked for its status again before the
	 * backoff is over
	 */
	atomic_store(&test_evil_status, TEST_EVIL_STATUS_SILENT);
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider(&state);
	ms = test_ms_since(&start);
	CHECK(!provider, "a silent provider reports a status");
	CHECK(es_state_str_has(state, "status", "connected (uid"),
	      "a provider silent on STATUS was disconnected: %s",
	      es_state_print(state));
	json_object_put(state);
	CHECK(ms < ESDM_EXT_SOCKET_TIMEOUT_MS,
	      "an unanswered status is waited for %ld ms", (long)ms);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_connections), conns);
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
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
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

/*
 * A provider given up on is not connected to again before a whole retry
 * interval is over, wherever in its second the clock was: given up on just
 * before the clock turned a second, it was connected to again just after
 * while the source kept its deadlines in whole seconds.
 */
static void test_retry_interval(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
	struct timespec now, dropped;
	pthread_t evil;
	long wait_ms;
	int64_t ms;

	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	CHECK_EQ(test_evil_start(&evil), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);

	/* The request times out 50 ms before the clock turns a second */
	clock_gettime(CLOCK_MONOTONIC, &now);
	wait_ms = 1000 - ESDM_EXT_SOCKET_TIMEOUT_MS - 50 -
		  now.tv_nsec / 1000000;
	if (wait_ms < 0)
		wait_ms += 1000;
	test_wait_until(esdm_es_extsock_now() + (uint64_t)wait_ms * 1000000);
	atomic_store(&test_evil_mode, TEST_EVIL_SILENT);
	CHECK_EQ(test_get(bits, NULL), 0);
	clock_gettime(CLOCK_MONOTONIC, &dropped);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);

	while (!test_get(bits, NULL) && test_ms_since(&dropped) < 5000)
		nanosleep(&ts, NULL);
	ms = test_ms_since(&dropped);
	CHECK(ms >= ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC * 1000 - 20 &&
		      ms < 5000,
	      "connected to again %ld ms after the provider was given up on",
	      (long)ms);

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	CHECK_EQ(ES->init(), 0);
}

/*
 * A provider restarted is another process, its noise source set up anew: it is
 * tested on the new connection before it is credited, whether the source
 * finds the connection closed by the restart or connects to the provider back
 * after the retry interval - rather than credited until the next self test
 * pass of the ESDM, up to ten minutes later.
 */
static void test_restarted_selftest(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int selftest_calls;

	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	/* Restarted while the connection was idle, failing its self test */
	test_server_stop();
	ctl->selftest_ret = -ENODEV;
	selftest_calls = ctl->selftest_calls;
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
	CHECK(test_state_has("status", "failing its self test"),
	      "a restarted provider was not tested on the new connection");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(test_get(bits, NULL), 0);

	/* Until a self test passes */
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	/* Gone for a while, and back failing its self test */
	test_server_stop();
	CHECK_EQ(test_get(bits, NULL), 0);
	ctl->selftest_ret = -ENODEV;
	selftest_calls = ctl->selftest_calls;
	CHECK_EQ(test_server_start(), 0);
	test_wait_retry();
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
	CHECK(test_state_has("status", "failing its self test"),
	      "a provider back was not tested on the new connection");

	/* Restarted again, passing it: credited at once */
	test_server_stop();
	ctl->selftest_ret = 0;
	selftest_calls = ctl->selftest_calls;
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);

	/* A connection kept is not tested again */
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
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
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);

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
/* An INFO request, and the name of the test plugin, in the clear */
static atomic_uint test_relay_plain_info = 0;
static atomic_bool test_relay_saw_name = false;

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
				uint32_t length;
				uint16_t type;

				n = recv(esdm, buf, sizeof(buf), 0);
				if (n > 0 &&
				    !esdm_es_ext_proto_req_unpack(
					    buf, (size_t)n, &type, &length) &&
				    type == ESDM_ES_EXT_PROTO_INFO)
					atomic_fetch_add(&test_relay_plain_info,
							 1);
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
				if (memmem(buf, (size_t)n, ES_EXT_TEST_NAME,
					   strlen(ES_EXT_TEST_NAME)))
					atomic_store(&test_relay_saw_name,
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
	atomic_store(&test_relay_plain_info, 0);
	atomic_store(&test_relay_saw_name, false);
	CHECK_EQ(pthread_create(&relay, NULL, test_relay_run, NULL), 0);

	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_relay), 0);
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
		/* INFO only inside the DTLS session, its name too */
		CHECK_EQ(atomic_load(&test_relay_plain_info), 0);
		CHECK(!atomic_load(&test_relay_saw_name),
		      "the name can be read off the channel");
		CHECK(test_state_has("name", ES_EXT_TEST_NAME),
		      "the name did not arrive through the DTLS session");
	} else
#endif
	{
		CHECK_EQ(atomic_load(&test_relay_plain_info), 1);
		CHECK(atomic_load(&test_relay_saw_name),
		      "the relay does not see the name of an unencrypted channel");
		CHECK(test_state_has("name", ES_EXT_TEST_NAME),
		      "the name did not arrive in the clear");
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

	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
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

/*
 * The name the provider declares: the one of the plugin, or another one the
 * server is given, shown in place of the instance name - which the state keeps
 * as "instance". A name that is not valid, or that of another entropy source,
 * is not taken; a provider that answers INFO with what the protocol does not
 * allow, or does not know it, is used without a name, on a new connection
 * that does not ask.
 */
static void test_names(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	static const char *const bad[] = {
		"tab\there", "\xff\xfe", "esc\x1b[31m", "c1\xc2\x9b",
		"rlo\xe2\x80\xae",
	};
	struct json_object *state;
	unsigned int conns, i;
	pthread_t evil;
	char txt[4096];

	/* The name of the test plugin, and the instance */
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	state = es_state_get(ES);
	CHECK(es_state_str_is(state, "name", ES_EXT_TEST_NAME) &&
		      es_state_str_is(state, "instance", ES->name),
	      "the source is not shown under the name of the plugin: %s",
	      es_state_print(state));
	CHECK_EQ(esdm_status_txt(state, NULL, txt, sizeof(txt)), 0);
	json_object_put(state);
	CHECK(strstr(txt, "Name: " ES_EXT_TEST_NAME "\nInstance: "),
	      "the text has no name and instance: %s", txt);

	/* Another one given to the server */
	test_server_stop();
	CHECK_EQ(esdm_es_ext_server_alloc(&es_ext_test_plugin, test_good, 0600,
					  &test_server),
		 0);
	CHECK_EQ(esdm_es_ext_server_set_name(test_server, "x\ny"), -EINVAL);
	CHECK_EQ(esdm_es_ext_server_set_name(test_server, "Quelle \xc3\xa4"),
		 0);
	CHECK_EQ(-pthread_create(&test_server_thread, NULL, test_server_run,
				 test_server),
		 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK(test_state_has("name", "Quelle \xc3\xa4"),
	      "the name given to the server is not shown");

	/* Back to the one of the plugin, and the plugin without one */
	test_server_stop();
	es_ext_test_plugin.name = NULL;
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK(test_state_has("name", ES->name),
	      "a provider without a name is not shown under its instance");
	test_server_stop();
	es_ext_test_plugin.name = ctl->name;
	CHECK_EQ(test_server_start(), 0);

	/* A provider of its own, declaring what the test has it declare */
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_info, TEST_EVIL_INFO_NAME);
	CHECK_EQ(test_evil_start(&evil), 0);
	conns = atomic_load(&test_evil_connections);
	atomic_store(&test_evil_info_requests, 0);

	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_state_has("name", "evil"), "the name is not taken");
	CHECK_EQ(atomic_load(&test_evil_info_requests), 1);
	/* The request as the protocol has it: type 5, length 0 */
	CHECK_MEM_EQ(test_evil_info_req,
		     "ESEX\x01\x00\x05\x00\x00\x00\x00\x00",
		     sizeof(test_evil_info_req));
	/* Once per connection */
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(atomic_load(&test_evil_info_requests), 1);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 1);

	/* Names that are none: refused, the source works on */
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		snprintf(test_evil_name, sizeof(test_evil_name), "%s", bad[i]);
		CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
		CHECK_EQ(test_get(bits, NULL), 8);
		CHECK(test_state_has("name", ES->name),
		      "the name %u that is none is taken", i);
	}

	/* The name of another entropy source */
	snprintf(test_evil_name, sizeof(test_evil_name), "%s",
		 esdm_es[esdm_ext_es_aux]->name);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_state_has("name", ES->name),
	      "the name of another entropy source is taken");
	snprintf(test_evil_name, sizeof(test_evil_name), "evil");

	/* A name too long breaks the protocol: once more, without asking */
	atomic_store(&test_evil_info, TEST_EVIL_INFO_TOO_LONG);
	conns = atomic_load(&test_evil_connections);
	atomic_store(&test_evil_info_requests, 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_state_has("name", ES->name), "a name too long is taken");
	CHECK_EQ(atomic_load(&test_evil_info_requests), 1);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 2);

	/* An old provider: the same, and it works without a name */
	atomic_store(&test_evil_info, TEST_EVIL_INFO_OLD);
	conns = atomic_load(&test_evil_connections);
	atomic_store(&test_evil_info_requests, 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_state_has("name", ES->name), "an old provider has a name");
	CHECK(test_state_has("status", "connected (uid"),
	      "an old provider is not connected to");
	CHECK_EQ(atomic_load(&test_evil_info_requests), 1);
	CHECK_EQ(atomic_load(&test_evil_connections), conns + 2);

	/* Declaring nothing */
	atomic_store(&test_evil_info, TEST_EVIL_INFO_NONE);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_state_has("name", ES->name),
	      "a provider declaring nothing has a name");

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	CHECK_EQ(ES->init(), 0);
}

/* Is the source credited at @rate, from @source, as the state says? */
static bool test_rate_is(uint32_t rate, const char *source)
{
	struct json_object *state = es_state_get(ES);
	bool ret = es_state_int(state, "entropy_rate", -1) == rate &&
		   es_state_str_is(state, "entropy_rate_source", source) &&
		   esdm_config_es_ext_socket_entropy_rate(0) == rate;

	if (!ret)
		printf("expected rate %u of the %s: %s\n", rate, source,
		       es_state_print(state));
	json_object_put(state);
	return ret;
}

/*
 * The rate of the source: the one configured for it, else the one its provider
 * declares - asked for on every connection - else 0.
 */
static void test_rates(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	pthread_t evil;

	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(
			 0, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
		 0);

	/* The provider of the library: the rate of its plugin, or its own */
	test_server_stop();
	ctl->entropy_rate = 64;
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(64, bits));
	CHECK(test_rate_is(64, "provider"),
	      "the rate of the plugin of the provider is not taken");

	test_server_stop();
	ctl->entropy_rate = ES_EXT_TEST_RATE_NONE;
	CHECK_EQ(esdm_es_ext_server_alloc(&es_ext_test_plugin, test_good, 0600,
					  &test_server),
		 0);
	CHECK_EQ(esdm_es_ext_server_set_entropy_rate(test_server, 257),
		 -EINVAL);
	CHECK_EQ(esdm_es_ext_server_set_entropy_rate(test_server, 32), 0);
	CHECK_EQ(-pthread_create(&test_server_thread, NULL, test_server_run,
				 test_server),
		 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(32, bits));
	CHECK(test_rate_is(32, "provider"),
	      "the rate given to the server is not taken");

	/* None declared: 0, the data credited with nothing */
	test_server_stop();
	CHECK_EQ(test_server_start(), 0);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_good), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK(test_rate_is(0, "default"), "a provider without a rate has one");

	/* A provider of the test, with the rates it declares */
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_mode, TEST_EVIL_GOOD);
	atomic_store(&test_evil_info, TEST_EVIL_INFO_NAME);
	atomic_store(&test_evil_rate, 4);
	CHECK_EQ(test_evil_start(&evil), 0);

	/* It claims 8 bits a block, credited at the rate it declares */
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 4);
	CHECK(test_rate_is(4, "provider"), "the declared rate is not taken");

	/* Asked anew on the next connection */
	atomic_store(&test_evil_rate, 6);
	CHECK_EQ(test_get(bits, NULL), 4);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 6);
	CHECK(test_rate_is(6, "provider"),
	      "the rate of the new connection is not taken");

	/* Beyond 256: capped; one configured takes precedence */
	atomic_store(&test_evil_rate, 1000);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_rate_is(256, "provider"), "a rate beyond 256 is not capped");
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(0, 2), 0);
	CHECK_EQ(test_get(bits, NULL), 2);
	CHECK(test_rate_is(2, "config"), "the rate configured is not taken");
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(
			 0, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
		 0);

	/* A provider that does not know INFO declares none */
	atomic_store(&test_evil_info, TEST_EVIL_INFO_OLD);
	CHECK_EQ(esdm_es_ext_socket_set_path(0, test_evil), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK(test_rate_is(0, "default"), "an old provider has a rate");
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(0, 8), 0);
	CHECK_EQ(test_get(bits, NULL), 8);
	CHECK(test_rate_is(8, "config"),
	      "the rate configured for an old provider is not taken");

	atomic_store(&test_evil_stop, true);
	ES->fini();
	pthread_join(evil, NULL);
	close(test_evil_listen);
	unlink(test_evil);
	atomic_store(&test_evil_stop, false);
	atomic_store(&test_evil_connections, 0);
	atomic_store(&test_evil_info, TEST_EVIL_INFO_NONE);
	atomic_store(&test_evil_rate, ESDM_ES_EXT_PROTO_RATE_NONE);
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(0, 256), 0);
	CHECK_EQ(ES->init(), 0);
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
	CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, (int64_t)getuid()), 0);
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
	test_restarted_selftest();
	test_eavesdrop(true);
	test_eavesdrop(false);
	test_old_provider();
	test_status_old_provider();
	test_status_busy();
	test_names();
	test_rates();
	test_retry_interval();
	test_protocol_breaches();

	if (test_server)
		test_server_stop();
	unlink(test_evil);
	rmdir(test_dir);

	return common_test_result("es_extsock");
}
