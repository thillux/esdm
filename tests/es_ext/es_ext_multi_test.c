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
 * Several external entropy sources, in a build with at least two provider
 * socket sources (es_ext_socket_num).
 *
 * - Each source is an entry of the ES table of its own, named with its index.
 * - The sources are independent: each has its own provider, entropy rate,
 *   accepted uid, self test verdict, failures and state; what happens to one -
 *   a failed self test, a failing request, a provider that goes away - does
 *   not change what another is credited with.
 * - The JSON status of the ESDM lists every source once, under its instance
 *   name - and under the name its provider declares, which two sources may
 *   share; a source declaring none, or one that is not valid, is shown under
 *   its instance name. A provider restarted with another name changes the
 *   name of that source only, and a status taken meanwhile shows the old name
 *   or the new one.
 * - Each source is credited at its own rate: the one configured for it, else
 *   the one its provider declares, else 0. Configuring one source, or all of
 *   them, or restarting one provider with another rate, changes the rate of
 *   that source only.
 * - Each source has the status of its own provider - the fields of its
 *   server, the DTLS of its own connection included, next to the status of
 *   its source - none for one without, one failing, one that is no valid
 *   status; cached for each source on its own; a slow provider keeps only its
 *   own status out, a provider gone only its own source.
 *
 * The sources are compiled into the test, with a short retry interval and
 * timeout. The providers are esdm-es-ext-serve processes serving the test
 * plugin, steered through the environment.
 *
 * Usage: es_ext_multi_test <esdm-es-ext-serve> <test plugin>
 */

#define _GNU_SOURCE
#include "config.h"

#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 1
#define ESDM_EXT_SOCKET_TIMEOUT_MS 500
#define ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC 3

/* The unit under test */
#include "esdm_es_extsock.c"

#include <pthread.h>

#include "common_test.h"
#include "../es_state_check.h"
#include "esdm.h"
#include "esdm_status_txt.h"
#include "es_ext_test_plugin.h"
#include "es_ext_test_util.h"

#if ESDM_EXT_SOCKET_NUM < 2
#error "The test needs two sources at least"
#endif

static const char *test_serve_bin;
static const char *test_plugin;

static char test_dir[] = "/tmp/esdm-es-ext-multi-test-XXXXXX";
static char test_socket[ESDM_EXT_SOCKET_NUM][sizeof(test_dir) + 32];

#define SOCK(i) (&esdm_es_extsock[i])

/*
 * Start a provider on the socket of source @i, with the arguments @extra and
 * the settings @settings of the test plugin - see es_ext_test_serve()
 */
static pid_t test_serve(unsigned int i, const char *const *extra,
			const char *settings)
{
	return es_ext_test_serve(test_serve_bin, test_plugin, test_socket[i],
				 extra, settings);
}

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
 * Every source an entry of the ES table of its own, each named with its index
 * - and no two entries of the table named alike.
 */
static void test_table(void)
{
	char name[32];
	unsigned int i, j;

	CHECK_EQ(esdm_ext_es_extsock_last - esdm_ext_es_extsock_first + 1,
		 ESDM_EXT_SOCKET_NUM);
	CHECK_EQ(esdm_ext_es_extsock_last + 1, esdm_ext_es_aux);

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
 * Two provider socket sources, each connected to an esdm-es-ext-serve of its
 * own: one failing its self test, the other credited at its own rate; a uid
 * accepted by one only; a provider gone for one only.
 */
static void test_providers(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	pid_t provider[2];
	unsigned int i;

	provider[0] = test_serve(0, NULL, "selftest_ret=-19");
	provider[1] = test_serve(1, NULL, NULL);
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

/* The string member @key of the state of @es, into @buf */
static const char *test_state_str(const struct esdm_es_cb *es, const char *key,
				  char *buf, size_t buflen)
{
	struct json_object *state = es_state_get(es);
	const char *val = es_state_str(state, key);

	snprintf(buf, buflen, "%s", val ? val : "(none)");
	json_object_put(state);
	return buf;
}

/*
 * A status reader running while the name of a source changes: every name it
 * sees is one of @names, the instance name included - never anything else.
 */
struct test_reader {
	const struct esdm_es_cb *es;
	const char *names[3];
	atomic_bool stop;
	atomic_uint reads;
	unsigned int bad;
};


static void *test_reader_run(void *arg)
{
	struct test_reader *reader = arg;
	char name[64];
	unsigned int i;

	while (!atomic_load(&reader->stop)) {
		test_state_str(reader->es, "name", name, sizeof(name));
		for (i = 0; i < 3; i++) {
			if (reader->names[i] &&
			    !strcmp(name, reader->names[i]))
				break;
		}
		if (i == 3) {
			printf("the reader saw the name \"%s\"\n", name);
			reader->bad++;
		}
		atomic_fetch_add(&reader->reads, 1);
	}

	return NULL;
}

/* Start @reader, returning once it read */
static bool test_reader_start(struct test_reader *reader, pthread_t *thread)
{
	unsigned int i;

	if (pthread_create(thread, NULL, test_reader_run, reader))
		return false;
	for (i = 0; i < 5000 && !atomic_load(&reader->reads); i++)
		es_ext_test_sleep_ms(1);
	return atomic_load(&reader->reads) > 0;
}

/*
 * The names the providers declare: the one of --name, the one of the plugin -
 * the same for two of them. A provider restarted with another name shows it
 * once connected to again, the others keep theirs, and a status reader sees
 * the old name or the new one meanwhile.
 */
static void test_provider_names(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	const char *const name_a[] = { "--name", "Quelle A", NULL };
	const char *const name_c[] = { "--name", "Quelle C", NULL };
	struct test_reader reader = { .es = SOCK(0) };
	char name[64];
	pid_t provider[2];
	pthread_t thread;
	unsigned int i;

	provider[0] = test_serve(0, name_a, NULL);
	provider[1] = test_serve(1, NULL, "name=Quelle A");
	CHECK(provider[0] > 0 && provider[1] > 0,
	      "the providers did not come up");
	for (i = 0; i < 2; i++) {
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(SOCK(i)->init(), 0);

	/* The same name for both, apart by their instances */
	for (i = 0; i < 2; i++) {
		CHECK(!strcmp(test_state_str(SOCK(i), "name", name,
					     sizeof(name)),
			      "Quelle A"),
		      "%s is shown as %s", SOCK(i)->name, name);
		CHECK(!strcmp(test_state_str(SOCK(i), "instance", name,
					     sizeof(name)),
			      SOCK(i)->name),
		      "%s is the instance %s", SOCK(i)->name, name);
	}
	for (i = 2; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK(!strcmp(test_state_str(SOCK(i), "name", name,
					     sizeof(name)),
			      SOCK(i)->name),
		      "%s without a provider is shown as %s", SOCK(i)->name,
		      name);

	/* The first restarted with another name, read meanwhile */
	reader.names[0] = "Quelle A";
	reader.names[1] = "Quelle C";
	reader.names[2] = SOCK(0)->name;
	CHECK(test_reader_start(&reader, &thread), "the reader does not read");
	es_ext_test_terminate(provider[0]);
	CHECK(!strcmp(test_state_str(SOCK(0), "name", name, sizeof(name)),
		      "Quelle A"),
	      "the name changed before the provider came back: %s", name);
	provider[0] = test_serve(0, name_c, NULL);
	CHECK(provider[0] > 0, "the provider did not come back");
	CHECK_EQ(test_get(SOCK(0), bits), 0);
	es_ext_test_sleep_ms(1200);
	for (i = 0; i < 10 && strcmp(test_state_str(SOCK(0), "name", name,
						     sizeof(name)),
				     "Quelle C");
	     i++) {
		test_get(SOCK(0), bits);
		es_ext_test_sleep_ms(200);
	}
	atomic_store(&reader.stop, true);
	pthread_join(thread, NULL);
	CHECK(!strcmp(name, "Quelle C"),
	      "the provider back is not shown under its new name: %s", name);
	CHECK_EQ(reader.bad, 0);
	CHECK(!strcmp(test_state_str(SOCK(1), "name", name, sizeof(name)),
		      "Quelle A"),
	      "the second source changed with the first: %s", name);

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		SOCK(i)->fini();
	for (i = 0; i < 2; i++) {
		es_ext_test_terminate(provider[i]);
		esdm_es_ext_socket_set_path(i, "");
		esdm_es_ext_socket_set_peer_uid(i, -1);
	}
}

/* Is @es credited at @rate, from @source, as its state says? */
static bool test_rate_is(const struct esdm_es_cb *es, uint32_t rate,
			 const char *source)
{
	struct json_object *state = es_state_get(es);
	bool ret = es_state_int(state, "entropy_rate", -1) == rate &&
		   es_state_str_is(state, "entropy_rate_source", source);

	if (!ret)
		printf("expected rate %u of the %s for %s: %s\n", rate, source,
		       es->name, es_state_print(state));
	json_object_put(state);
	return ret;
}

/*
 * The rates of the provider socket sources, each of its own: declared by
 * esdm-es-ext-serve --entropy_rate, by the plugin it serves, by a plugin
 * declaring more than 256, or none - 0 then; configured for one source; a
 * provider restarted with another rate, read anew for its source only.
 */
static void test_provider_rates(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	const char *const rate_48[] = { "--entropy_rate", "48", NULL };
	const char *const rate_24[] = { "--entropy_rate", "24", NULL };
	const char *const no_dtls[] = { "--no_dtls", NULL };
	static const char *const settings[] = { NULL, "rate=96", NULL,
						"rate=1000" };
	static const uint32_t expected[] = { 48, 96, 0, 256 };
	static const char *const sources[] = { "provider", "provider",
					       "default", "provider" };
	unsigned int i, n = ESDM_EXT_SOCKET_NUM < 4 ? ESDM_EXT_SOCKET_NUM : 4;
	pid_t provider[4] = { -1, -1, -1, -1 };

	for (i = 0; i < n; i++) {
		/* The last one in the clear, the others over DTLS */
		provider[i] = test_serve(i,
					 !i	 ? rate_48 :
					 i == 3 ? no_dtls :
						  NULL,
					 settings[i]);
		CHECK(provider[i] > 0, "provider %u did not come up", i);
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
		CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(
				 i, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
			 0);
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(SOCK(i)->init(), 0);

	for (i = 0; i < n; i++) {
		CHECK(test_rate_is(SOCK(i), expected[i], sources[i]),
		      "%s is not credited at its rate", SOCK(i)->name);
#ifdef ESDM_DTLS
		CHECK(test_state_has(SOCK(i), "status",
				     i == 3 ? "unencrypted" : "DTLS"),
		      "%s does not run the connection it should", SOCK(i)->name);
#endif
		CHECK_EQ(esdm_config_es_ext_socket_entropy_rate(i),
			 expected[i]);
		CHECK_EQ(test_get(SOCK(i), bits),
			 test_level(expected[i], bits));
	}

	/* Configured for one source only */
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(1, 12), 0);
	for (i = 0; i < n; i++)
		CHECK(test_rate_is(SOCK(i), i == 1 ? 12 : expected[i],
				   i == 1 ? "config" : sources[i]),
		      "%s changed with another source", SOCK(i)->name);
	CHECK_EQ(test_get(SOCK(1), bits), test_level(12, bits));
	CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(
			 1, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
		 0);

	/* Configured for all, overriding every provider, and taken back */
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(i, 16), 0);
	for (i = 0; i < n; i++) {
		CHECK(test_rate_is(SOCK(i), 16, "config"),
		      "%s is not credited at the rate configured",
		      SOCK(i)->name);
		CHECK_EQ(test_get(SOCK(i), bits), test_level(16, bits));
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(esdm_config_es_ext_socket_entropy_rate_set(
				 i, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
			 0);
	for (i = 0; i < n; i++)
		CHECK(test_rate_is(SOCK(i), expected[i], sources[i]),
		      "%s is not back at its rate", SOCK(i)->name);

	/* The first restarted with another rate: read anew, for it only */
	es_ext_test_terminate(provider[0]);
	provider[0] = test_serve(0, rate_24, NULL);
	CHECK(provider[0] > 0, "the provider did not come back");
	test_get(SOCK(0), bits);
	for (i = 0; i < 10 && !test_rate_is(SOCK(0), 24, "provider"); i++) {
		es_ext_test_sleep_ms(300);
		test_get(SOCK(0), bits);
	}
	CHECK(test_rate_is(SOCK(0), 24, "provider"),
	      "the rate of the provider back is not read anew");
	CHECK_EQ(test_get(SOCK(0), bits), test_level(24, bits));
	for (i = 1; i < n; i++)
		CHECK(test_rate_is(SOCK(i), expected[i], sources[i]),
		      "%s changed with the first source", SOCK(i)->name);

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		SOCK(i)->fini();
	for (i = 0; i < n; i++) {
		es_ext_test_terminate(provider[i]);
		esdm_es_ext_socket_set_path(i, "");
		esdm_es_ext_socket_set_peer_uid(i, -1);
		esdm_config_es_ext_socket_entropy_rate_set(i, 0);
	}
}

/*
 * The "provider" member of the state of @es, NULL if there is none - asked
 * for anew if @fresh, the status kept otherwise
 */
static struct json_object *test_provider_of(const struct esdm_es_cb *es,
					    bool fresh, struct json_object **state)
{
	struct json_object *provider = NULL;
	unsigned int i;

	if (fresh) {
		for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++) {
			if (es == SOCK(i)) {
				mutex_lock(&extsock[i].state_mutex);
				extsock[i].status.at = 0;
				mutex_unlock(&extsock[i].state_mutex);
			}
		}
	}

	*state = es_state_get(es);
	if (!json_object_object_get_ex(*state, "provider", &provider))
		return NULL;
	return provider;
}

/* The member @key of the member @part of the provider status @provider */
static struct json_object *test_part(struct json_object *provider,
				     const char *part, const char *key)
{
	struct json_object *obj = NULL, *val = NULL;

	if (!json_object_object_get_ex(provider, part, &obj) || !obj ||
	    !json_object_object_get_ex(obj, key, &val))
		return NULL;
	return val;
}

static bool test_part_is(struct json_object *provider, const char *part,
			 const char *key, const char *want)
{
	struct json_object *val = test_part(provider, part, key);

	return val && json_object_is_type(val, json_type_string) &&
	       !strcmp(json_object_get_string(val), want);
}

/* Does the provider status @provider have a "plugin" that is null? */
static bool test_plugin_null(struct json_object *provider)
{
	struct json_object *val = (struct json_object *)1;

	return json_object_object_get_ex(provider, "plugin", &val) && !val;
}

/*
 * The status of each provider socket source its own: the fields of its
 * esdm-es-ext-serve - the name, the rate, the DTLS of its connection - and the
 * status of its plugin, null for none; cached for each source on its own; a
 * slow provider keeps only its own status out, and is not asked for it for a
 * while; a provider gone affects only its own source.
 */
static void test_provider_status(void)
{
	const char *const opts0[] = { "--name", "S0", "--entropy_rate", "10",
				      NULL };
	const char *const opts1[] = { "--no_dtls", NULL };
	static const char *const settings[] = {
		NULL, "status_ret=-95;name=S1",
		"selftest_ret=-19;name=S2;status={\"plugin\":\"zwei\"}",
		"name=S3"
	};
	unsigned int i, n = ESDM_EXT_SOCKET_NUM < 4 ? ESDM_EXT_SOCKET_NUM : 4;
	pid_t provider_pid[4] = { -1, -1, -1, -1 };
	struct json_object *state, *provider, *val;
	int64_t requests0, requests1;
	struct timespec start, end;
	long ms;

	for (i = 0; i < n; i++) {
		provider_pid[i] = test_serve(
			i, i == 0 ? opts0 : i == 1 ? opts1 : NULL, settings[i]);
		CHECK(provider_pid[i] > 0, "provider %u did not come up", i);
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		CHECK_EQ(SOCK(i)->init(), 0);

	/* Each with the fields of its own server and its own plugin part */
	for (i = 0; i < n; i++) {
		char name[8];

		snprintf(name, sizeof(name), "S%u", i);
		provider = test_provider_of(SOCK(i), true, &state);
		CHECK(provider && test_part_is(provider, "server", "name",
					       name),
		      "%s does not have the status of its own server: %s",
		      SOCK(i)->name, es_state_print(state));
		val = test_part(provider, "server", "dtls");
#ifdef ESDM_DTLS
		CHECK(val && json_object_get_boolean(val) == (i != 1),
		      "%s reports the DTLS of another connection: %s",
		      SOCK(i)->name, es_state_print(state));
#else
		CHECK(val && !json_object_get_boolean(val),
		      "%s reports DTLS: %s", SOCK(i)->name,
		      es_state_print(state));
#endif
		if (i == 0)
			CHECK(json_object_get_int64(test_part(provider,
							      "server",
							      "entropy_rate")) ==
					      10 &&
				      test_part_is(provider, "plugin",
						   "plugin",
						   ES_EXT_TEST_NAME),
			      "the first source is not its own: %s",
			      es_state_print(state));
		if (i == 1)
			CHECK(test_plugin_null(provider),
			      "the second source has a plugin status: %s",
			      es_state_print(state));
		if (i == 2)
			CHECK(test_part_is(provider, "plugin", "plugin",
					   "zwei") &&
				      test_part_is(provider, "server",
						   "selftest", "failed") &&
				      es_state_str_has(state, "status",
						       "failing its self test"),
			      "the third source is not its own: %s",
			      es_state_print(state));
		json_object_put(state);
	}

	/* Cached for each source on its own */
	provider = test_provider_of(SOCK(1), true, &state);
	requests1 = json_object_get_int64(
		test_part(provider, "server", "requests"));
	json_object_put(state);
	provider = test_provider_of(SOCK(0), true, &state);
	requests0 = json_object_get_int64(
		test_part(provider, "server", "requests"));
	json_object_put(state);
	provider = test_provider_of(SOCK(0), true, &state);
	CHECK(json_object_get_int64(test_part(provider, "server",
					      "requests")) == requests0 + 1,
	      "the first source was not asked anew: %s",
	      es_state_print(state));
	json_object_put(state);
	provider = test_provider_of(SOCK(1), false, &state);
	CHECK(json_object_get_int64(test_part(provider, "server",
					      "requests")) == requests1,
	      "the second source was asked with the first: %s",
	      es_state_print(state));
	json_object_put(state);

	/*
	 * The second provider slow to answer STATUS: the status of the first
	 * does not wait for it, and it is not asked for a while
	 */
	es_ext_test_terminate(provider_pid[1]);
	provider_pid[1] = test_serve(1, opts1, "status_delay_ms=900;name=S1");
	CHECK(provider_pid[1] > 0, "the slow provider did not come up");
	test_get(SOCK(1), ESDM_DRNG_SECURITY_STRENGTH_BITS);
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider_of(SOCK(0), true, &state);
	clock_gettime(CLOCK_MONOTONIC, &end);
	ms = (end.tv_sec - start.tv_sec) * 1000 +
	     (end.tv_nsec - start.tv_nsec) / 1000000;
	CHECK(provider != NULL && ms < ESDM_EXT_SOCKET_TIMEOUT_MS,
	      "the status of the first source took %ld ms", ms);
	json_object_put(state);
	provider = test_provider_of(SOCK(1), true, &state);
	CHECK(!provider, "the slow provider has a status");
	json_object_put(state);
	clock_gettime(CLOCK_MONOTONIC, &start);
	provider = test_provider_of(SOCK(1), true, &state);
	clock_gettime(CLOCK_MONOTONIC, &end);
	ms = (end.tv_sec - start.tv_sec) * 1000 +
	     (end.tv_nsec - start.tv_nsec) / 1000000;
	CHECK(!provider && ms < ESDM_EXT_SOCKET_TIMEOUT_MS,
	      "the slow provider was asked again within its backoff (%ld ms)",
	      ms);
	json_object_put(state);
	provider = test_provider_of(SOCK(0), true, &state);
	CHECK(provider != NULL, "the first source lost its status");
	json_object_put(state);

	/* The third provider gone: the others keep theirs */
	if (n > 2) {
		es_ext_test_terminate(provider_pid[2]);
		provider_pid[2] = -1;
		CHECK_EQ(test_get(SOCK(2), ESDM_DRNG_SECURITY_STRENGTH_BITS),
			 0);
		CHECK(test_state_has(SOCK(2), "status", "not connected"),
		      "a provider gone is still connected");
		provider = test_provider_of(SOCK(0), true, &state);
		CHECK(provider && es_state_str_has(state, "status",
						   "connected (uid"),
		      "the first source changed with the third: %s",
		      es_state_print(state));
		json_object_put(state);
	}

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		SOCK(i)->fini();
	for (i = 0; i < n; i++) {
		es_ext_test_terminate(provider_pid[i]);
		esdm_es_ext_socket_set_path(i, "");
		esdm_es_ext_socket_set_peer_uid(i, -1);
	}
}

/*
 * The JSON status of the ESDM lists each source once, under its name, with
 * its own configuration - and for a provider the fields of its own server, the
 * DTLS of its connection included, and the status of its plugin; the text
 * status shows them in sections of their own.
 */
static void test_status(void)
{
	const char *const opts[2][4] = { { "--name", "Quelle 0", NULL },
					 { "--no_dtls", "--name", "Quelle 1",
					   NULL } };
	static char buf[65536];
	struct json_object *root = NULL, *es, *provider_obj;
	pid_t provider[2] = { -1, -1 };
	char name[32];
	unsigned int i;
	int ret;

	for (i = 0; i < 2; i++) {
		provider[i] = test_serve(i, opts[i], NULL);
		CHECK(provider[i] > 0, "provider %u did not come up", i);
		CHECK_EQ(esdm_es_ext_socket_set_path(i, test_socket[i]), 0);
		CHECK_EQ(esdm_es_ext_socket_set_peer_uid(i, getuid()), 0);
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
		if (!es || i >= 2 ||
		    !json_object_object_get_ex(es, "provider", &provider_obj))
			continue;

		/* The fields of its own server, the DTLS of its connection */
		snprintf(name, sizeof(name), "Quelle %u", i);
		CHECK(es_state_str_is(es, "name", name) &&
			      test_part_is(provider_obj, "server", "name",
					   name) &&
			      test_part_is(provider_obj, "plugin", "plugin",
					   ES_EXT_TEST_NAME),
		      "the status of the provider is not its own: %s",
		      es_state_print(es));
#ifdef ESDM_DTLS
		CHECK(json_object_get_boolean(test_part(
			      provider_obj, "server", "dtls")) == !i,
		      "the provider reports the DTLS of another connection: %s",
		      es_state_print(es));
		CHECK(es_state_str_has(es, "status", i ? "unencrypted" : "DTLS"),
		      "the source does not say whether it uses DTLS: %s",
		      es_state_print(es));
#endif
	}

	json_object_put(root);

	/* The text status, with sections of the provider and its parts */
	CHECK_EQ(esdm_status(buf, sizeof(buf)), 0);
	CHECK(strstr(buf, " Instance: ExternalSocket1\n") &&
		      strstr(buf, "\n Provider properties:\n"
				  "  Server properties:\n"
				  "   Version: " VERSION "\n"),
	      "the text status does not show the status of the providers: %s",
	      buf);

fini:
	esdm_fini();
out:
	for (i = 0; i < 2; i++) {
		es_ext_test_terminate(provider[i]);
		esdm_es_ext_socket_set_path(i, "");
	}
}

int main(int argc, char *argv[])
{
	unsigned int i;

	if (argc < 3) {
		printf("usage: %s <esdm-es-ext-serve> <test plugin>\n",
		       argv[0]);
		return 1;
	}
	test_serve_bin = argv[1];
	test_plugin = argv[2];

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Traversable for a provider of another user */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		snprintf(test_socket[i], sizeof(test_socket[i]),
			 "%s/provider%u.socket", test_dir, i);

	test_table();
	test_providers();
	test_provider_names();
	test_provider_rates();
	test_provider_status();
	test_status();

	for (i = 0; i < ESDM_EXT_SOCKET_NUM; i++)
		unlink(test_socket[i]);
	rmdir(test_dir);

	return common_test_result("es_ext_multi");
}
