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
 * The external entropy source of a plugin library loaded into the ESDM.
 *
 * - Without a plugin configured, the source is there and does nothing.
 * - A plugin set with esdm_es_ext_lib_set_path() - what esdm-server
 *   --es_ext_lib does - is loaded and initialized by the init of the source,
 *   and the path outlives its fini.
 * - A block is credited with what the plugin claims, at most with what the
 *   configured rate allows. A plugin claiming more than the block holds, or
 *   failing, is credited with nothing - not by what it delivers, not by what
 *   it reports as available - until it delivers again, and the data of a
 *   refused block is not handed on. The monitor of the source finds out on
 *   its own that it delivers again.
 * - A plugin failing its self test is credited with nothing until a self test
 *   passes, whatever it delivers meanwhile - and a plugin is credited with
 *   nothing before its first self test: one loaded by the init of the source
 *   until the self test pass that follows, one loaded while the source runs
 *   is tested right away.
 * - The status of the plugin is asked for at most once per interval, and
 *   not while a request is in progress - which neither the ESDM status nor
 *   the entropy available waits for.
 * - A re-init initializes the plugin anew without loading it again.
 * - Plugin libraries that do not fit are refused.
 *
 * Usage: es_extlib_test <test plugin> <bad version> <no get_entropy>
 *	  <no plugin> [...]
 */

#include "config.h"

/* Every monitor pass probes a failed plugin, so the test need not wait */
#define ESDM_EXT_LIB_PROBE_INTERVAL_SEC 0

/* The unit under test */
#include "esdm_es_extlib.c"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "esdm_status_txt.h"
#include "es_ext_test_plugin.h"

#define ES (&esdm_es_extlib[0])

static struct esdm_es_ext_test_control *ctl;

static uint32_t test_get(uint32_t bits, uint8_t *first_byte)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0xff, sizeof(eb_es));
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

static void test_unconfigured(void)
{
	CHECK_EQ(ES->init(), 0);
	CHECK(!ES->active(), "the source is active without a plugin");
	CHECK_EQ(ES->curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS), 0);
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK_EQ(test_get(ESDM_DRNG_SECURITY_STRENGTH_BITS, NULL), 0);
	CHECK_EQ(ES->selftest(), 0);
	CHECK(test_state_has("status", "not loaded"),
	      "the state does not say so");
	CHECK(test_state_has("plugin_library", "(unset)"),
	      "the state names a plugin library");
	ES->fini();
}

static void test_credit(const char *path)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	uint8_t first;

	CHECK_EQ(esdm_es_ext_lib_set_path(NULL), -EINVAL);
	CHECK_EQ(esdm_es_ext_lib_set_path(path), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the plugin was not loaded");
	CHECK_EQ(ctl->init_calls, 1);
	CHECK(test_state_has("plugin_library", path),
	      "the state does not name the library");
	CHECK(test_state_has("plugin", "es-ext-test"),
	      "the state does not name the plugin");

	/*
	 * Nothing credited before its first self test, which the self test
	 * pass of the ESDM runs before the first seeding - one that fails
	 * keeps it that way.
	 */
	esdm_config_es_ext_lib_entropy_rate_set(256);
	CHECK(test_state_has("status", "awaiting its self test"),
	      "the state does not say the self test is due");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(ES->max_entropy(), 0);
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, ctl->get_calls & 0xff);
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(ES->selftest(), -EFAULT);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(test_get(bits, NULL), 0);
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK(test_state_has("status", "delivering"),
	      "the state does not say it delivers");

	/* The claim of the plugin, all of the block, at the full rate */
	CHECK_EQ(ES->max_entropy(), test_level(256, esdm_security_strength()));
	CHECK_EQ(test_get(bits, &first), test_level(256, bits));
	CHECK_EQ(ctl->last_buflen, bits / 8);
	CHECK_EQ(first, ctl->get_calls & 0xff);

	/* The data of the whole seed size */
	CHECK_EQ(test_get(ESDM_DRNG_INIT_SEED_SIZE_BITS, NULL),
		 test_level(256, ESDM_DRNG_INIT_SEED_SIZE_BITS));
	CHECK_EQ(ctl->last_buflen, ESDM_DRNG_INIT_SEED_SIZE_BYTES);

	/* The rate caps the claim */
	esdm_config_es_ext_lib_entropy_rate_set(64);
	CHECK_EQ(test_get(bits, NULL), test_level(64, bits));

	/* A smaller claim stands */
	ctl->claim_bits = 10;
	CHECK_EQ(test_get(bits, NULL), 10);
	ctl->claim_bits = UINT32_MAX;

	/* No rate, no credit, data all the same */
	esdm_config_es_ext_lib_entropy_rate_set(0);
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, ctl->get_calls & 0xff);
	esdm_config_es_ext_lib_entropy_rate_set(256);

	/* A claim beyond the block: nothing credited, the data not handed on */
	ctl->claim_bits = bits + 1;
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK(test_state_has("status", "failing"),
	      "the state does not say it fails");
	ctl->claim_bits = UINT32_MAX;

	/* Asked again all the same, the source recovers */
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));

	/* A plugin that fails */
	ctl->get_ret = -EIO;
	CHECK_EQ(test_get(bits, &first), 0);
	CHECK_EQ(first, 0);
	CHECK_EQ(ES->max_entropy(), 0);
	ctl->get_ret = 0;
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));

	/* A failure is noticed by the monitor, without a seeding asking */
	ctl->get_ret = -EIO;
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	ctl->get_ret = 0;
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
	/* Nothing to probe for a plugin that delivers */
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
	CHECK_EQ(ES->monitor_es(), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);
	ctl->selftest_ret = 0;
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(256, bits));
	CHECK_EQ(ctl->selftest_calls, 5);
}

/* Make the next state ask the plugin for its status anew */
static void test_status_expire(void)
{
	mutex_lock(&extlib[0].state_mutex);
	extlib[0].status.at = 0;
	mutex_unlock(&extlib[0].state_mutex);
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

/* The same, the plugin asked for its status anew */
static struct json_object *test_provider(struct json_object **state)
{
	test_status_expire();
	return test_provider_kept(state);
}

/* Is a request in progress, holding the source? */
static bool test_busy(void)
{
	if (pthread_rwlock_tryrdlock(&extlib[0].mutex))
		return true;
	pthread_rwlock_unlock(&extlib[0].mutex);
	return false;
}

static void *test_get_thread(void *arg)
{
	(void)arg;
	test_get(ESDM_DRNG_SECURITY_STRENGTH_BITS, NULL);
	return NULL;
}

/*
 * Start a request the plugin takes @ms for, as a seeding does, and wait until
 * it holds the source
 */
static bool test_busy_start(pthread_t *thread, unsigned int ms)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	unsigned int i;

	ctl->get_delay_ms = ms;
	if (pthread_create(thread, NULL, test_get_thread, NULL))
		return false;
	for (i = 0; i < 1000 && !test_busy(); i++)
		nanosleep(&ts, NULL);
	return test_busy();
}

/*
 * The status of the plugin is the "provider" member of the state, as the
 * plugin reports it - or not there at all for a plugin that reports none,
 * reports what is no JSON object of up to ESDM_ES_EXT_STATUS_MAX bytes, or is
 * busy. The rest of the state is there either way.
 */
static void test_status(const char *good, const char *v1)
{
	static const char *const bad[] = {
		"{\"a\":",
		"[1,2]",
		"\"text\"",
		"{\"a\":1} x",
		"{\"a\":1}{}",
		"{\"a\":1,}",
		"not json",
		"{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":1}}}}}}}}}",
	};
	char text[ESDM_ES_EXT_STATUS_MAX + 2], txt[2048];
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct esdm_es_ext_test_control *ctl_v1 = NULL;
	struct json_object *state, *provider, *val;
	unsigned int calls, i;
	pthread_t getter;
	bool busy;
	void *dl;

	provider = test_provider(&state);
	CHECK(provider && json_object_is_type(provider, json_type_object),
	      "the state has no status of the plugin: %s",
	      es_state_print(state));
	CHECK(es_state_str_is(provider, "plugin", "es-ext-test"),
	      "the status is not the plugin's: %s", es_state_print(state));
	CHECK(json_object_object_get_ex(provider, "healthy", &val) &&
		      json_object_is_type(val, json_type_boolean) &&
		      json_object_get_boolean(val),
	      "the status lost its boolean: %s", es_state_print(state));

	/* And in the text status, a section of the source */
	CHECK_EQ(esdm_status_txt(state, NULL, txt, sizeof(txt)), 0);
	CHECK(strstr(txt, "\nProvider properties:\n Plugin: es-ext-test\n"
			  " Healthy: true\n"),
	      "the text has no status of the plugin: %s", txt);
	json_object_put(state);

	/* What is no JSON object is left out */
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		ctl->status_text = bad[i];
		provider = test_provider(&state);
		CHECK(!provider, "the status %s is taken", bad[i]);
		CHECK(test_state_has("status", "delivering"),
		      "the state is gone with the status %s", bad[i]);
		json_object_put(state);
	}

	/* The largest status there may be, and one byte more */
	memset(text, 'a', sizeof(text));
	memcpy(text, "{\"x\":\"", 6);
	memcpy(text + ESDM_ES_EXT_STATUS_MAX - 2, "\"}", 3);
	ctl->status_text = text;
	provider = test_provider(&state);
	CHECK(provider != NULL, "the largest status is not taken");
	json_object_put(state);

	memcpy(text + ESDM_ES_EXT_STATUS_MAX - 2, "a\"}", 4);
	provider = test_provider(&state);
	CHECK(!provider, "a status beyond the largest is taken");
	json_object_put(state);
	ctl->status_text = NULL;

	/* Not terminated within the buffer, or failing */
	ctl->status_unterminated = 1;
	provider = test_provider(&state);
	CHECK(!provider, "an unterminated status is taken");
	json_object_put(state);
	ctl->status_unterminated = 0;

	ctl->status_ret = -EIO;
	provider = test_provider(&state);
	CHECK(!provider, "the status of a failing status callback is taken");
	json_object_put(state);
	ctl->status_ret = 0;

	/* Asked for once per interval, the last status shown in between */
	calls = ctl->status_calls;
	provider = test_provider(&state);
	CHECK(provider != NULL, "the status is gone after a valid one");
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

	/*
	 * A request of a seeding in progress, which the plugin takes its time
	 * for, is not waited for: the recent status is shown, one that is due
	 * is not asked for but left out, and the rest of the state and the
	 * entropy available are as they were before the request.
	 */
	provider = test_provider(&state);
	json_object_put(state);
	calls = ctl->status_calls;
	CHECK(test_busy_start(&getter, 500),
	      "the request does not hold the plugin");
	provider = test_provider_kept(&state);
	CHECK(provider != NULL, "the recent status is gone during a request");
	json_object_put(state);
	provider = test_provider(&state);
	CHECK(!provider, "a busy plugin was asked for its status");
	CHECK(es_state_str_has(state, "status", "delivering"),
	      "the state of a busy plugin is gone: %s", es_state_print(state));
	json_object_put(state);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));
	CHECK_EQ(ES->max_entropy(), test_level(256, esdm_security_strength()));
	CHECK(ES->active(), "a busy plugin is not active");
	busy = test_busy();
	pthread_join(getter, NULL);
	ctl->get_delay_ms = 0;
	CHECK(busy, "the state waited for the request");
	CHECK_EQ(ctl->status_calls, calls);

	provider = test_provider(&state);
	CHECK(provider != NULL, "the status is gone after a request");
	json_object_put(state);

	/* A plugin of version 1 has none, whatever lies beyond its struct */
	CHECK_EQ(esdm_es_ext_lib_set_path(v1), 0);
	dl = dlopen(v1, RTLD_NOW | RTLD_NOLOAD);
	if (dl) {
		ctl_v1 = dlsym(dl, ES_EXT_TEST_CONTROL_SYMBOL);
		dlclose(dl);
	}
	CHECK(ctl_v1 != NULL, "the plugin of version 1 has no control");
	CHECK(ES->active(), "the plugin of version 1 is not used");
	provider = test_provider(&state);
	CHECK(!provider, "a plugin of version 1 reports a status");
	CHECK(test_state_has("status", "delivering"),
	      "the plugin of version 1 does not deliver");
	json_object_put(state);
	if (ctl_v1)
		CHECK_EQ(ctl_v1->status_calls, 0);

	CHECK_EQ(esdm_es_ext_lib_set_path(good), 0);
	CHECK(ES->active(), "the test plugin is not back");
}

static void test_reinit(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int init_calls = ctl->init_calls;
	unsigned int fini_calls = ctl->fini_calls;
	unsigned int selftest_calls = ctl->selftest_calls;

	/* Initialized anew, not loaded again */
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the plugin is gone after a re-init");
	CHECK_EQ(ctl->fini_calls, fini_calls + 1);
	CHECK_EQ(ctl->init_calls, init_calls + 1);

	/* And credited with nothing until the self test pass that follows */
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK_EQ(ctl->selftest_calls, selftest_calls);
	CHECK_EQ(ES->selftest(), 0);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));

	/* The path outlives the fini of the source */
	ES->fini();
	CHECK_EQ(ctl->fini_calls, fini_calls + 2);
	CHECK(!ES->active(), "the plugin survived the fini");
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the plugin path did not survive the fini");
	CHECK_EQ(ctl->init_calls, init_calls + 2);

	/* An init that fails leaves the source off */
	ctl->init_ret = -ENODEV;
	CHECK_EQ(ES->init(), 0);
	CHECK(!ES->active(), "a plugin failing its init is used");
	CHECK_EQ(test_get(ESDM_DRNG_SECURITY_STRENGTH_BITS, NULL), 0);
	ctl->init_ret = 0;
}

static void test_bad_plugins(const char *good, const char *bad_version,
			     const char *no_get, const char *no_plugin)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	unsigned int selftest_calls = ctl->selftest_calls;

	/* Set while the source runs, a plugin is loaded - and tested - at once */
	CHECK_EQ(esdm_es_ext_lib_set_path(good), 0);
	CHECK(ES->active(), "the plugin was not loaded at once");
	CHECK_EQ(ctl->selftest_calls, selftest_calls + 1);
	CHECK_EQ(ES->curr_entropy(bits), test_level(256, bits));

	/* One failing the self test is used, but credited with nothing */
	ctl->selftest_ret = -ENODEV;
	CHECK_EQ(esdm_es_ext_lib_set_path(good), 0);
	CHECK(ES->active(), "a plugin failing its self test is not used");
	CHECK_EQ(ES->curr_entropy(bits), 0);
	CHECK(test_state_has("status", "failing its self test"),
	      "the state does not say the self test fails");
	ctl->selftest_ret = 0;

	CHECK_EQ(esdm_es_ext_lib_set_path(bad_version), -EPROTO);
	CHECK(!ES->active(), "a plugin of another version is used");
	CHECK_EQ(esdm_es_ext_lib_set_path(no_get), -EPROTO);
	CHECK(!ES->active(), "a plugin without get_entropy is used");
	CHECK_EQ(esdm_es_ext_lib_set_path(no_plugin), -ENOEXEC);
	CHECK(!ES->active(), "a library without a plugin is used");
	CHECK_EQ(esdm_es_ext_lib_set_path("/nonexistent/libnothing.so"),
		 -ENOENT);
	CHECK(!ES->active(), "a missing library is used");
	CHECK(test_state_has("plugin_library", "/nonexistent/libnothing.so"),
	      "the state does not name the library configured");

	/* Back to the build's, which names none */
	CHECK_EQ(esdm_es_ext_lib_set_path(""), 0);
	CHECK(!ES->active(), "a plugin is used without one configured");
	CHECK(test_state_has("plugin_library", "(unset)"),
	      "the state names a plugin library");

	ES->fini();
}

int main(int argc, char *argv[])
{
	void *ref;

	/* The plugins the tests of this directory share */
	if (argc < 7) {
		printf("usage: %s <test plugin> <bad version> <no get_entropy> <no plugin> <example plugin> <test plugin of version 1>\n",
		       argv[0]);
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * A reference of the test's own keeps the plugin library loaded when
	 * the source closes it, so that its control stays where it is.
	 */
	ref = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	CHECK(ref != NULL, "cannot load %s: %s", argv[1], dlerror());
	if (!ref)
		return common_test_result("es_extlib");
	ctl = dlsym(ref, ES_EXT_TEST_CONTROL_SYMBOL);
	CHECK(ctl != NULL, "the test plugin has no control");
	if (!ctl)
		return common_test_result("es_extlib");

	test_unconfigured();
	test_credit(argv[1]);
	test_status(argv[1], argv[6]);
	test_reinit();
	test_bad_plugins(argv[1], argv[2], argv[3], argv[4]);

	dlclose(ref);

	return common_test_result("es_extlib");
}
