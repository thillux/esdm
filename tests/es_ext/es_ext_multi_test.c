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
 * Several external entropy sources of each kind, in a build with at least two
 * plugin library and two provider socket sources (es_ext_lib_num,
 * es_ext_socket_num).
 *
 * - Each source is an entry of the ES table of its own, named with its index.
 * - The sources of a kind are independent: each has its own plugin or
 *   provider, entropy rate, accepted uid, self test verdict, failures and
 *   state; what happens to one - a failed self test, a failing request, a
 *   provider that goes away - does not change what another is credited with.
 * - A plugin library serves one source: a second source refuses the plugin
 *   another one uses.
 * - The JSON status of the ESDM lists every source once, under its name.
 *
 * Both sources are compiled into the test, with a short retry interval and
 * timeout of the provider sockets. The plugin libraries are copies of the test
 * plugin, each with a control of its own; the providers are esdm-es-ext-serve
 * processes serving further copies, steered through the environment.
 *
 * Usage: es_ext_multi_test <esdm-es-ext-serve> <plugin copy> x 8
 */

#define _GNU_SOURCE
#include "config.h"

#define ESDM_EXT_LIB_PROBE_INTERVAL_SEC 0
#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_SOCKET_TIMEOUT_MS 500

/* The units under test */
#include "esdm_es_extlib.c"
#include "esdm_es_extsock.c"

#include <dlfcn.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "esdm.h"
#include "esdm_status_txt.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"

#if ESDM_EXT_LIB_NUM < 2 || ESDM_EXT_SOCKET_NUM < 2
#error "The test needs two sources of each kind at least"
#endif

#define TEST_PLUGINS 8

static const char *test_serve_bin;
static const char *test_plugin[TEST_PLUGINS];
static struct esdm_es_ext_test_control *test_ctl[TEST_PLUGINS];
static void *test_ref[TEST_PLUGINS];

static char test_dir[] = "/tmp/esdm-es-ext-multi-test-XXXXXX";
static char test_socket[ESDM_EXT_SOCKET_NUM][sizeof(test_dir) + 32];

#define LIB(i) (&esdm_es_extlib[i])
#define SOCK(i) (&esdm_es_extsock[i])

static uint32_t test_level(uint32_t rate, uint32_t bits)
{
	return esdm_fast_noise_entropylevel(rate, bits);
}

static uint32_t test_get(const struct esdm_es_cb *es, uint32_t bits)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	es->get_ent(&eb_es, bits, true);
	return eb_es.e_bits;
}

/* Does the string member @key of the state of @es contain @what? */
static bool test_state_has(const struct esdm_es_cb *es, const char *key,
			   const char *what)
{
	struct json_object *state = es_state_get(es);
	bool ret = es_state_str_has(state, key, what);

	if (!ret)
		printf("state of %s: %s\n", es->name, es_state_print(state));
	json_object_put(state);
	return ret;
}

/*
 * Every source an entry of the ES table of its own, the plugin libraries and
 * then the provider sockets, each named with its index - and no two entries
 * of the table named alike.
 */
static void test_table(void)
{
	char name[32];
	unsigned int i, j;

	CHECK_EQ(esdm_ext_es_extlib_last - esdm_ext_es_extlib_first + 1,
		 ESDM_EXT_LIB_NUM);
	CHECK_EQ(esdm_ext_es_extsock_last - esdm_ext_es_extsock_first + 1,
		 ESDM_EXT_SOCKET_NUM);
	CHECK_EQ(esdm_ext_es_extsock_first, esdm_ext_es_extlib_last + 1);

	for (i = 0; i < ESDM_EXT_LIB_NUM; i++) {
		snprintf(name, sizeof(name), "ExternalLib%u", i);
		CHECK(esdm_es[esdm_ext_es_extlib_first + i] == LIB(i),
		      "plugin library source %u is not its entry", i);
		CHECK(!strcmp(LIB(i)->name, name), "%s is called %s", name,
		      LIB(i)->name);
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++) {
		snprintf(name, sizeof(name), "ExternalSocket%u", i);
		CHECK(esdm_es[esdm_ext_es_extsock_first + i] == SOCK(i),
		      "provider socket source %u is not its entry", i);
		CHECK(!strcmp(SOCK(i)->name, name), "%s is called %s", name,
		      SOCK(i)->name);
	}

	for (i = 0; i < esdm_ext_es_last; i++) {
		for (j = i + 1; j < esdm_ext_es_last; j++)
			CHECK(strcmp(esdm_es[i]->name, esdm_es[j]->name),
			      "two entropy sources are called %s",
			      esdm_es[i]->name);
	}
}

/*
 * Two plugin library sources, one failing its self test, the other credited,
 * each at a rate of its own: neither changes what the other is credited with.
 */
static void test_plugins(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	struct esdm_es_ext_test_control *ctl0 = test_ctl[0], *ctl1 = test_ctl[1];
	unsigned int i;

	/* Configuration of a source of its own, none beyond the build's */
	CHECK_EQ(esdm_es_ext_lib_set_path(0, test_plugin[0]), 0);
	CHECK_EQ(esdm_es_ext_lib_set_path(1, test_plugin[1]), 0);
	CHECK_EQ(esdm_es_ext_lib_set_path(ESDM_EXT_LIB_NUM, test_plugin[2]),
		 -EINVAL);
	CHECK_EQ(esdm_config_es_ext_lib_entropy_rate_set(0, 64), 0);
	CHECK_EQ(esdm_config_es_ext_lib_entropy_rate_set(1, 128), 0);
	CHECK_EQ(esdm_config_es_ext_lib_entropy_rate(0), 64);
	CHECK_EQ(esdm_config_es_ext_lib_entropy_rate(1), 128);

	for (i = 0; i < ESDM_EXT_LIB_NUM; i++)
		CHECK_EQ(LIB(i)->init(), 0);
	CHECK(LIB(0)->active() && LIB(1)->active(),
	      "the plugins were not loaded");
	for (i = 2; i < ESDM_EXT_LIB_NUM; i++)
		CHECK(!LIB(i)->active(), "%s is active without a plugin",
		      LIB(i)->name);
	CHECK(test_state_has(LIB(0), "plugin_library", test_plugin[0]),
	      "the first source does not name its library");
	CHECK(test_state_has(LIB(1), "plugin_library", test_plugin[1]),
	      "the second source does not name its library");
	CHECK_EQ(ctl0->init_calls, 1);
	CHECK_EQ(ctl1->init_calls, 1);

	/* One fails its self test, the other passes */
	ctl0->selftest_ret = -ENODEV;
	CHECK_EQ(LIB(0)->selftest(), -EFAULT);
	CHECK_EQ(LIB(1)->selftest(), 0);
	CHECK_EQ(LIB(0)->curr_entropy(bits), 0);
	CHECK_EQ(LIB(1)->curr_entropy(bits), test_level(128, bits));
	CHECK_EQ(test_get(LIB(0), bits), 0);
	CHECK_EQ(test_get(LIB(1), bits), test_level(128, bits));
	CHECK(test_state_has(LIB(0), "status", "failing its self test"),
	      "the failed self test is not the first source's");
	CHECK(test_state_has(LIB(1), "status", "delivering"),
	      "the second source does not deliver");

	/* The other one failing a request */
	ctl1->get_ret = -EIO;
	CHECK_EQ(test_get(LIB(1), bits), 0);
	CHECK(test_state_has(LIB(1), "status", "failing"),
	      "the failed request is not the second source's");
	CHECK(test_state_has(LIB(0), "status", "failing its self test"),
	      "the first source changed with the second");
	ctl1->get_ret = 0;
	CHECK_EQ(LIB(1)->monitor_es(), 0);
	CHECK_EQ(LIB(1)->curr_entropy(bits), test_level(128, bits));

	/* A rate of its own each */
	ctl0->selftest_ret = 0;
	CHECK_EQ(LIB(0)->selftest(), 0);
	CHECK_EQ(test_get(LIB(0), bits), test_level(64, bits));
	CHECK_EQ(esdm_config_es_ext_lib_entropy_rate_set(1, 256), 0);
	CHECK_EQ(test_get(LIB(1), bits), test_level(256, bits));
	CHECK_EQ(test_get(LIB(0), bits), test_level(64, bits));
	CHECK_EQ(ctl0->selftest_calls, 2);
	CHECK_EQ(ctl1->selftest_calls, 1);

	/* A plugin library serves one source */
	CHECK_EQ(esdm_es_ext_lib_set_path(1, test_plugin[0]), -EBUSY);
	CHECK(!LIB(1)->active(), "a plugin serves two sources");
	CHECK(LIB(0)->active(), "the plugin was taken from its source");
	CHECK_EQ(test_get(LIB(0), bits), test_level(64, bits));
	CHECK_EQ(esdm_es_ext_lib_set_path(1, test_plugin[1]), 0);
	CHECK(LIB(1)->active(), "the second plugin is not back");
	CHECK_EQ(test_get(LIB(1), bits), test_level(256, bits));

	for (i = 0; i < ESDM_EXT_LIB_NUM; i++)
		LIB(i)->fini();
	CHECK_EQ(ctl0->fini_calls, 1);
	CHECK_EQ(ctl1->fini_calls, 2);
	esdm_config_es_ext_lib_entropy_rate_set(0, 256);
	esdm_config_es_ext_lib_entropy_rate_set(1, 256);
}

/*
 * Two provider socket sources, each connected to an esdm-es-ext-serve of its
 * own: one failing its self test, the other credited at its own rate; a uid
 * accepted by one only; a provider gone for one only.
 */
static void test_providers(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	pid_t provider[2];
	unsigned int i;

	provider[0] = es_ext_test_serve(test_serve_bin, test_plugin[4],
					test_socket[0], NULL,
					"selftest_ret=-19");
	provider[1] = es_ext_test_serve(test_serve_bin, test_plugin[5],
					test_socket[1], NULL, NULL);
	CHECK(provider[0] > 0 && provider[1] > 0,
	      "the providers did not come up");

	for (i = 0; i < 2; i++) {
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
	}
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(0, 256), 0);
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(1, 128), 0);

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(SOCK(i)->init(), 0);
	for (i = 2; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK(!SOCK(i)->active(), "%s is active without a provider",
		      SOCK(i)->name);

	/* Tested on the first connection: the first fails, the second passes */
	CHECK(test_state_has(SOCK(0), "status", "failing its self test"),
	      "the first provider passed its self test");
	CHECK(test_state_has(SOCK(1), "status", "connected (uid"),
	      "the second provider is not connected");
	CHECK(!test_state_has(SOCK(1), "status", "failing"),
	      "the second provider fails with the first");
	CHECK(test_state_has(SOCK(0), "provider_socket", test_socket[0]),
	      "the first source does not name its socket");
	CHECK(test_state_has(SOCK(1), "provider_socket", test_socket[1]),
	      "the second source does not name its socket");
	CHECK_EQ(SOCK(0)->curr_entropy(bits), 0);
	CHECK_EQ(test_get(SOCK(0), bits), 0);
	CHECK_EQ(SOCK(1)->curr_entropy(bits), test_level(128, bits));
	CHECK_EQ(test_get(SOCK(1), bits), test_level(128, bits));

	/* A uid accepted by one source only: the other refuses the provider */
	if (getuid()) {
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(0, -1), 0);
		CHECK_EQ(esdm_es_ext_socket_set_path(0, test_socket[0]), 0);
		CHECK_EQ(test_get(SOCK(0), bits), 0);
		CHECK(test_state_has(SOCK(0), "status", "not connected"),
		      "a provider of a uid not accepted is connected");
		CHECK(test_state_has(SOCK(0), "provider_accepted", "root"),
		      "the first source accepts another uid");
		CHECK(test_state_has(SOCK(1), "provider_accepted",
				     "root and uid"),
		      "the second source lost its uid");
		CHECK_EQ(test_get(SOCK(1), bits), test_level(128, bits));
	}

	/* The second provider goes: the first source is not concerned */
	es_ext_test_terminate(provider[1]);
	provider[1] = -1;
	CHECK_EQ(test_get(SOCK(1), bits), 0);
	CHECK(test_state_has(SOCK(1), "status", "not connected"),
	      "a provider gone is still connected");
	CHECK_EQ(SOCK(1)->curr_entropy(bits), 0);
	if (!getuid())
		CHECK(test_state_has(SOCK(0), "status",
				     "failing its self test"),
		      "the first source changed with the second");

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		SOCK(i)->fini();
	for (i = 0; i < 2; i++) {
		es_ext_test_terminate(provider[i]);
		esdm_es_ext_socket_set_path(i, "");
		esdm_es_ext_socket_set_peer_uid(i, -1);
		esdm_config_es_ext_socket_entropy_rate_set(i, 0);
	}
}

/*
 * The JSON status of the ESDM lists each source once, under its name, with
 * its own configuration.
 */
static void test_status(void)
{
	static char buf[65536];
	struct json_object *root = NULL, *es;
	pid_t provider[2] = { -1, -1 };
	char name[32];
	unsigned int i;
	int ret;

	for (i = 0; i < 2; i++) {
		provider[i] = es_ext_test_serve(test_serve_bin,
						test_plugin[4 + i],
						test_socket[i], NULL, NULL);
		CHECK(provider[i] > 0, "provider %u did not come up", i);
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
		CHECK_EQ(esdm_es_ext_lib_set_path(i, test_plugin[i]), 0);
	}

	ret = esdm_init();
	CHECK_EQ(ret, 0);
	if (ret)
		goto out;

	CHECK_EQ(esdm_status_json(buf, sizeof(buf)), 0);
	root = json_tokener_parse(buf);
	CHECK(root != NULL, "the status is no JSON");
	if (!root)
		goto fini;

	for (i = 0; i < ESDM_EXT_LIB_NUM; i++) {
		snprintf(name, sizeof(name), "ExternalLib%u", i);
		es = es_ext_test_status_es(root, name);
		CHECK(es != NULL, "the status lists no %s", name);
		if (es && i < 2)
			CHECK(es_state_str_is(es, "plugin_library",
					      test_plugin[i]),
			      "%s does not name its library: %s", name,
			      es_state_print(es));
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++) {
		snprintf(name, sizeof(name), "ExternalSocket%u", i);
		es = es_ext_test_status_es(root, name);
		CHECK(es != NULL, "the status lists no %s", name);
		if (es && i < 2)
			CHECK(es_state_str_is(es, "provider_socket",
					      test_socket[i]) &&
				      es_state_str_has(es, "status",
						       "connected (uid"),
			      "%s is not connected to its provider: %s", name,
			      es_state_print(es));
	}

	json_object_put(root);

fini:
	esdm_fini();
out:
	for (i = 0; i < 2; i++) {
		es_ext_test_terminate(provider[i]);
		esdm_es_ext_socket_set_path(i, "");
		esdm_es_ext_lib_set_path(i, "");
	}
}

int main(int argc, char *argv[])
{
	unsigned int i;

	if (argc < 2 + TEST_PLUGINS) {
		printf("usage: %s <esdm-es-ext-serve> <plugin copy> x %u\n",
		       argv[0], TEST_PLUGINS);
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	test_serve_bin = argv[1];
	for (i = 0; i < TEST_PLUGINS; i++) {
		test_plugin[i] = argv[2 + i];

		/*
		 * A reference of the test's own keeps a library loaded when
		 * its source closes it, so that its control stays where it is
		 */
		test_ref[i] = dlopen(test_plugin[i], RTLD_NOW | RTLD_LOCAL);
		CHECK(test_ref[i] != NULL, "cannot load %s: %s",
		      test_plugin[i], dlerror());
		if (!test_ref[i])
			return common_test_result("es_ext_multi");
		test_ctl[i] = dlsym(test_ref[i], ES_EXT_TEST_CONTROL_SYMBOL);
		CHECK(test_ctl[i] != NULL, "%s has no control",
		      test_plugin[i]);
		if (!test_ctl[i])
			return common_test_result("es_ext_multi");
	}

	/* Traversable for a provider of another user */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		snprintf(test_socket[i], sizeof(test_socket[i]),
			 "%s/provider%u.socket", test_dir, i);

	test_table();
	test_plugins();
	test_providers();
	test_status();

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		unlink(test_socket[i]);
	rmdir(test_dir);
	for (i = 0; i < TEST_PLUGINS; i++)
		dlclose(test_ref[i]);

	return common_test_result("es_ext_multi");
}
