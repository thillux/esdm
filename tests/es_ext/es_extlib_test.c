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
 *   passes, whatever it delivers meanwhile.
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
#include <stdio.h>
#include <string.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "es_ext_test_plugin.h"

#define ES (&esdm_es_extlib)

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

	/* The claim of the plugin, all of the block, at the full rate */
	esdm_config_es_ext_lib_entropy_rate_set(256);
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
	CHECK_EQ(ctl->selftest_calls, 3);
}

static void test_reinit(void)
{
	unsigned int init_calls = ctl->init_calls;
	unsigned int fini_calls = ctl->fini_calls;

	/* Initialized anew, not loaded again */
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the plugin is gone after a re-init");
	CHECK_EQ(ctl->fini_calls, fini_calls + 1);
	CHECK_EQ(ctl->init_calls, init_calls + 1);

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
	/* Set while the source runs, a plugin is loaded at once */
	CHECK_EQ(esdm_es_ext_lib_set_path(good), 0);
	CHECK(ES->active(), "the plugin was not loaded at once");

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

	/* The plugins the tests of this directory share; more may follow */
	if (argc < 5) {
		printf("usage: %s <test plugin> <bad version> <no get_entropy> <no plugin>\n",
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
	test_reinit();
	test_bad_plugins(argv[1], argv[2], argv[3], argv[4]);

	dlclose(ref);

	return common_test_result("es_extlib");
}
