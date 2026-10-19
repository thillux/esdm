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
 * The external entropy sources of the esdm-server, as configured on its
 * command line.
 *
 * - --es_ext_lib loads the plugin library while the daemon has its
 *   privileges, and the plugin delivers once they are dropped.
 * - --es_ext_socket connects to a provider served by esdm-es-ext-serve. Once
 *   the provider was restarted, the daemon - its privileges dropped by then -
 *   connects to it again on demand.
 * - In a build with several sources of each kind, the options given several
 *   times configure one source each, the n-th occurrence the n-th source: each
 *   source has its own plugin or provider and rate, and is listed under its
 *   own instance name in the JSON and the text status.
 * - A source is shown under the name its plugin or provider declares, which
 *   esdm-es-ext-serve --name overrides; two sources may declare the same name.
 *
 * Skipped (77) unless run as root, as the esdm-server refuses to start
 * otherwise. The daemon claims the fixed socket, semaphore and IPC names, so
 * the test puts itself in namespaces of its own.
 *
 * Usage: es_ext_server_test <esdm-server> <esdm-es-ext-serve> <test plugin>
 *			     [<plugin copy> x 8 <rated plugin>]
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test_env.h"
#include "../test_namespace.h"
#include "common_test.h"
#include "config.h"
#include "es_ext_test_util.h"
#include "esdm_rpc_client.h"

/* The names of the first source of each kind, see esdm_es_extlib.h */
#if ESDM_EXT_LIB_NUM > 1
#define TEST_EXTLIB "ExternalLib0"
#else
#define TEST_EXTLIB "ExternalLib"
#endif
#if ESDM_EXT_SOCKET_NUM > 1
#define TEST_EXTSOCK "ExternalSocket0"
#else
#define TEST_EXTSOCK "ExternalSocket"
#endif

/* How long the daemon and the provider are given to come up */
#define TEST_START_SEC 30

static char test_dir[] = "/tmp/esdm-es-ext-server-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];
static char *test_envp[TEST_ENV_MAX_VARS + 1];

static void test_sleep_ms(long ms)
{
	const struct timespec ts = { .tv_sec = ms / 1000,
				     .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static pid_t test_spawn(char *const argv[])
{
	pid_t pid;

	if (posix_spawn(&pid, argv[0], NULL, NULL, argv, test_envp))
		return -1;
	return pid;
}

static void test_terminate(pid_t pid)
{
	if (pid <= 0)
		return;
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
}

/* The status of the daemon, once it answers */
static bool test_status(char *buf, size_t buflen)
{
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 10; i++) {
		memset(buf, 0, buflen);
		if (!esdm_rpcc_status(buf, buflen))
			return true;
		test_sleep_ms(100);
	}

	return false;
}

/*
 * The section of the status about the external entropy source of the
 * instance name @instance, from its name on
 */
static const char *test_es_section(const char *status, const char *instance)
{
	const char *section, *name;
	char needle[64];

	snprintf(needle, sizeof(needle), "\n Instance: %s\n", instance);
	section = strstr(status, needle);
	if (!section)
		return NULL;

	/* The line before, its name */
	for (name = section; name > status && name[-1] != '\n'; name--)
		;
	return name;
}

#if ESDM_EXT_SOCKET_NUM > 0
static bool test_wait_socket(void)
{
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 50; i++) {
		if (es_ext_test_socket_ready(test_socket))
			return true;
		test_sleep_ms(20);
	}

	return false;
}
#endif

#if ESDM_EXT_LIB_NUM > 0
static void test_plugin(const char *server, const char *plugin)
{
	char *const argv[] = { (char *)server, "-f", "--es_ext_lib",
			       (char *)plugin, NULL };
	static char status[65536];
	const char *es;
	/* Room for the seed of every source, of up to 16 of each external kind */
	static uint8_t seed[8192];
	pid_t pid;

	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		return;

	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, TEST_EXTLIB);
	CHECK(es != NULL, "the status lists no " TEST_EXTLIB " source");
	if (es) {
		CHECK(!strncmp(es, " Name: es-ext-test\n", 19),
		      "the source is not shown under its name (%.400s)", es);
		CHECK(strstr(es, "Plugin: es-ext-test") != NULL,
		      "the plugin was not loaded (%.400s)", es);
		CHECK(strstr(es, "Status: delivering") != NULL,
		      "the plugin does not deliver (%.400s)", es);
		/* The status of the plugin, a section of the source */
		CHECK(strstr(es, "\n Provider properties:\n"
				 "  Plugin: es-ext-test\n") != NULL,
		      "the status of the plugin is not shown (%.400s)", es);
	}

	/* Asked for its data with the privileges of the daemon dropped */
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the plugin loaded");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, TEST_EXTLIB);
	CHECK(es && strstr(es, "Status: delivering") != NULL,
	      "the plugin does not deliver after the privilege drop (%.400s)",
	      es ? es : "");

	test_terminate(pid);
}

#endif

#if ESDM_EXT_SOCKET_NUM > 0
static void test_socket_provider(const char *server, const char *serve,
				 const char *plugin)
{
	char *const serve_argv[] = { (char *)serve, "--plugin",	 (char *)plugin,
				     "--socket",    test_socket, NULL };
	char *const server_argv[] = { (char *)server, "-f", "--es_ext_socket",
				      test_socket, NULL };
	static char status[65536];
	const char *es;
	/* Room for the seed of every source, of up to 16 of each external kind */
	static uint8_t seed[8192];
	pid_t provider, pid;

	provider = test_spawn(serve_argv);
	CHECK(provider > 0, "cannot start %s", serve);
	CHECK(test_wait_socket(), "the provider did not create its socket");

	pid = test_spawn(server_argv);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		goto out;

	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, TEST_EXTSOCK);
	CHECK(es && strstr(es, "Status: connected (uid 0)") != NULL,
	      "the provider was not connected to (%.400s)", es ? es : "");
	CHECK(es && !strncmp(es, " Name: es-ext-test\n", 19),
	      "the source is not shown under the name of the provider (%.400s)",
	      es ? es : "");
	/*
	 * Its status: the fields of esdm-es-ext-serve and the status it
	 * fetches from the plugin
	 */
	CHECK(es && strstr(es, "\n Provider properties:\n"
			       "  Server properties:\n") != NULL &&
		      strstr(es, "\n  Plugin properties:\n"
				 "   Plugin: es-ext-test\n") != NULL,
	      "the status of the provider is not shown (%.600s)", es ? es : "");

	/* The provider goes, and comes back */
	test_terminate(provider);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider gone");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, TEST_EXTSOCK);
	CHECK(es && strstr(es, "Status: not connected") != NULL,
	      "a provider gone is still connected (%.400s)", es ? es : "");

	provider = test_spawn(serve_argv);
	CHECK(provider > 0, "cannot restart %s", serve);
	CHECK(test_wait_socket(), "the provider did not create its socket");

	/*
	 * After the retry interval of the source, a seeding connects again -
	 * from the daemon with its privileges dropped.
	 */
	test_sleep_ms(6000);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider back");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, TEST_EXTSOCK);
	CHECK(es && strstr(es, "Status: connected (uid 0)") != NULL,
	      "the provider back was not connected to again (%.400s)",
	      es ? es : "");

	test_terminate(pid);

out:
	test_terminate(provider);
}
#endif

#if ESDM_EXT_LIB_NUM >= 2 && ESDM_EXT_SOCKET_NUM >= 2

/* The integer member @key of the JSON object @obj, -1 if there is none */
static int64_t test_json_int(struct json_object *obj, const char *key)
{
	struct json_object *val;

	if (!obj || !json_object_object_get_ex(obj, key, &val) ||
	    !json_object_is_type(val, json_type_int))
		return -1;
	return json_object_get_int64(val);
}

/* Is the string member @key of the JSON object @obj @expected? */
static bool test_json_str_is(struct json_object *obj, const char *key,
			     const char *expected)
{
	struct json_object *val;

	return obj && json_object_object_get_ex(obj, key, &val) &&
	       json_object_is_type(val, json_type_string) &&
	       !strcmp(json_object_get_string(val), expected);
}

/* The text of @obj, for a message */
static const char *test_json_text(struct json_object *obj)
{
	return obj ? json_object_to_json_string(obj) : "(none)";
}

/*
 * Two sources of each kind, configured on the command line, the n-th
 * occurrence of an option for the n-th source: each with its own plugin or
 * provider, name and rate - the rate of the plugin or the provider where the
 * occurrence is auto, the one given otherwise - and the first provider
 * failing its self test.
 */
static void test_several(const char *server, const char *serve,
			 char *const copies[], const char *rated)
{
	const char *const serve0[] = { "--entropy_rate", "200", NULL };
	const char *const serve1[] = { "--name", "es-ext-test", NULL };
	char socket[2][sizeof(test_dir) + 32];
	char *const server_argv[] = {
		(char *)server, "-f",
		"--es_ext_lib", (char *)rated,
		"--es_ext_lib", copies[1],
		"--es_ext_lib_entropy_rate", "auto",
		"--es_ext_lib_entropy_rate", "64",
		"--es_ext_socket", socket[0],
		"--es_ext_socket", socket[1],
		"--es_ext_socket_entropy_rate", "auto",
		"--es_ext_socket_entropy_rate", "192",
		NULL
	};
	static char status[65536];
	struct json_object *root = NULL, *es;
	const char *section;
	pid_t provider[2], pid;
	unsigned int i;

	for (i = 0; i < 2; i++)
		snprintf(socket[i], sizeof(socket[i]), "%s/provider%u.socket",
			 test_dir, i);

	provider[0] = es_ext_test_serve(serve, copies[2], socket[0], serve0,
					"selftest_ret=-19;name=Quelle A");
	provider[1] = es_ext_test_serve(serve, copies[3], socket[1], serve1,
					"rate=96;name=overridden");
	CHECK(provider[0] > 0 && provider[1] > 0,
	      "the providers did not come up");

	pid = test_spawn(server_argv);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		goto out;

	/* Once it seeded from them */
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	for (i = 0; i < TEST_START_SEC * 10; i++) {
		if (!esdm_rpcc_status_json(status, sizeof(status)) &&
		    strstr(status, "\"fully_seeded\":true"))
			break;
		test_sleep_ms(100);
	}
	root = json_tokener_parse(status);
	CHECK(root != NULL, "the JSON status is no JSON");

	/* The rate of the plugin, for auto */
	es = es_ext_test_status_es(root, "ExternalLib0");
	CHECK(test_json_str_is(es, "name", "es-ext-rated") &&
		      test_json_str_is(es, "plugin_library", rated),
	      "ExternalLib0 does not have the plugin of its option: %s",
	      test_json_text(es));
	CHECK(test_json_int(es, "entropy_rate") == 128 &&
		      test_json_str_is(es, "entropy_rate_source", "plugin") &&
		      test_json_int(es, "entropy_rate_per_256_data_bits") == 128,
	      "ExternalLib0 is not credited at the rate of its plugin: %s",
	      test_json_text(es));

	/* The rate of the second occurrence */
	es = es_ext_test_status_es(root, "ExternalLib1");
	CHECK(test_json_str_is(es, "name", "es-ext-test") &&
		      test_json_str_is(es, "plugin_library", copies[1]),
	      "ExternalLib1 does not have the plugin of its option: %s",
	      test_json_text(es));
	CHECK(test_json_int(es, "entropy_rate") == 64 &&
		      test_json_str_is(es, "entropy_rate_source", "config") &&
		      test_json_int(es, "entropy_rate_per_256_data_bits") == 64,
	      "ExternalLib1 is not credited at the rate of its option: %s",
	      test_json_text(es));

	/*
	 * The name of the plugin, the rate of --entropy_rate of the provider -
	 * credited with nothing, as it fails its self test
	 */
	es = es_ext_test_status_es(root, "ExternalSocket0");
	CHECK(test_json_str_is(es, "name", "Quelle A") &&
		      test_json_str_is(es, "provider_socket", socket[0]),
	      "ExternalSocket0 does not have the provider of its option: %s",
	      test_json_text(es));
	CHECK(test_json_int(es, "entropy_rate") == 200 &&
		      test_json_str_is(es, "entropy_rate_source", "provider") &&
		      test_json_int(es, "entropy_rate_per_256_data_bits") == 0 &&
		      strstr(test_json_text(es), "failing its self test"),
	      "ExternalSocket0 is not as its provider says: %s",
	      test_json_text(es));

	/*
	 * The name of --name - the name of a plugin library source as well -
	 * and the rate of the option, not the one of the plugin
	 */
	es = es_ext_test_status_es(root, "ExternalSocket1");
	CHECK(test_json_str_is(es, "name", "es-ext-test") &&
		      test_json_str_is(es, "provider_socket", socket[1]),
	      "ExternalSocket1 does not have the provider of its option: %s",
	      test_json_text(es));
	CHECK(test_json_int(es, "entropy_rate") == 192 &&
		      test_json_str_is(es, "entropy_rate_source", "config") &&
		      test_json_int(es, "entropy_rate_per_256_data_bits") == 192,
	      "ExternalSocket1 is not credited at the rate of its option: %s",
	      test_json_text(es));
	json_object_put(root);

	/* And the text status names each of them */
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	CHECK(test_es_section(status, "ExternalLib0") &&
		      test_es_section(status, "ExternalLib1") &&
		      test_es_section(status, "ExternalSocket0") &&
		      test_es_section(status, "ExternalSocket1"),
	      "the text status does not name each source");
	section = test_es_section(status, "ExternalSocket0");
	CHECK(section && !strncmp(section, " Name: Quelle A\n", 16),
	      "the text status does not show the declared name (%.300s)",
	      section ? section : "");
	CHECK(section && strstr(section, " Entropy rate source: provider\n"),
	      "the text status does not show the source of the rate (%.300s)",
	      section ? section : "");

	test_terminate(pid);

out:
	for (i = 0; i < 2; i++) {
		es_ext_test_terminate(provider[i]);
		unlink(socket[i]);
	}
}

#endif

int main(int argc, char *argv[])
{
	int ret;

	if (argc < 4) {
		printf("usage: %s <esdm-server> <esdm-es-ext-serve> <test plugin> [<plugin copy> x 8 <rated plugin>]\n",
		       argv[0]);
		return 1;
	}

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	/* Traversable for the daemon once it dropped its privileges */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("Cannot create the directory: %s\n", strerror(errno));
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	test_env_daemon_envp(test_envp, TEST_ENV_MAX_VARS + 1);

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot set up the RPC client\n");
		return 1;
	}

#if ESDM_EXT_LIB_NUM > 0
	test_plugin(argv[1], argv[3]);
#endif
#if ESDM_EXT_SOCKET_NUM > 0
	test_socket_provider(argv[1], argv[2], argv[3]);
#endif
#if ESDM_EXT_LIB_NUM >= 2 && ESDM_EXT_SOCKET_NUM >= 2
	if (argc >= 13)
		test_several(argv[1], argv[2], argv + 4, argv[12]);
	else
		CHECK(0, "the plugin copies are missing");
#endif

	esdm_rpcc_fini_unpriv_service();
	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_server");
}
