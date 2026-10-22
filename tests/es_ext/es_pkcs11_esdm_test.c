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
 * The PKCS#11 entropy source reaching the ESDM: esdm-es-pkcs11 serving a
 * SoftHSM token, read by an ExternalSocket source of the ESDM configured for
 * its socket and its user, as esdm-server --es_ext and
 * --es_ext_uid configure it - the ESDM needs nothing that knows of
 * PKCS#11.
 *
 * - The source passes its self test and delivers data of the token, credited
 *   at the rate the daemon declares, or at the one configured for the source.
 * - The ESDM shows the source under the name the daemon declares, "PKCS#11"
 *   and the token label, with the status of the daemon - the token, logged in
 *   to - as its "provider".
 * - A daemon restarted is connected to again on its own, and credited again:
 *   the ESDM does not have to be started after it.
 *
 * The ExternalSocket source is compiled into the test, with a short retry
 * interval, and called as the ES manager calls it.
 *
 * Usage: es_pkcs11_esdm_test <esdm-es-pkcs11> <es_pkcs11_shim module>
 */

#include "config.h"

#define ESDM_EXT_RETRY_INTERVAL_SEC 1

/* The unit under test */
#include "esdm_es_extsock.c"

#include "common_test.h"
#include "../es_state_check.h"
#include "es_ext_test_util.h"
#include "es_pkcs11_test_util.h"

#define ES (&esdm_es_extsock[0])

/* What the source credits a block of @bits with at @rate */
static uint32_t test_level(uint32_t rate, uint32_t bits)
{
	return esdm_fast_noise_entropylevel(rate, bits);
}

/* A block of @bits from the source, its data into @data: the bits credited */
static uint32_t test_get(uint32_t bits, uint8_t *data)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	ES->get_ent(&eb_es, bits, true);
	if (data)
		memcpy(data, eb_es.e, bits / 8);
	return eb_es.e_bits;
}

/* The object member @key of @obj, NULL if there is none */
static struct json_object *test_member(struct json_object *obj, const char *key)
{
	struct json_object *val;

	return obj && json_object_object_get_ex(obj, key, &val) ? val : NULL;
}

/* The daemon of the test, for the token of the test and with its PIN */
static bool test_daemon_start(void)
{
	const char *const args[] = { "--module",
				     pk.shim,
				     "--token_label",
				     PK_TOKEN_LABEL,
				     "--pin_file",
				     pk.pin_good,
				     NULL };

	return pk_start(args, NULL);
}

static void test_credited(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	const uint32_t level = test_level(ESDM_PKCS11_ENTROPY_RATE, bits);
	uint8_t first[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	uint8_t second[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	struct json_object *state, *plugin;

	/* Configured as esdm-server --es_ext does */
	CHECK_EQ(esdm_es_ext_set_path(0, pk.socket), 0);
	CHECK_EQ(ES->init(), 0);
	CHECK(ES->active(), "the source is not active");
	CHECK_EQ(ES->selftest(), 0);

	CHECK(level > 0, "the build credits the PKCS#11 source with nothing");
	CHECK_EQ(test_get(bits, first), level);
	CHECK_EQ(test_get(bits, second), level);
	CHECK(memcmp(first, second, sizeof(first)),
	      "two blocks of the token are the same");
	CHECK_EQ(ES->curr_entropy(bits), level);

	/* A rate configured for the source takes precedence */
	CHECK_EQ(esdm_config_es_ext_entropy_rate_set(0, 64), 0);
	CHECK_EQ(test_get(bits, NULL), test_level(64, bits));
	CHECK_EQ(esdm_config_es_ext_entropy_rate_set(
			 0, ESDM_ES_EXT_ENTROPY_RATE_AUTO),
		 0);

	state = es_state_get(ES);
	CHECK(es_state_str_is(state, "name", "PKCS#11 " PK_TOKEN_LABEL) &&
		      es_state_str_is(state, "instance", ES->name),
	      "the source is not shown under the name the daemon declares: %s",
	      es_state_print(state));
	CHECK_EQ(es_state_int(state, "entropy_rate", -1),
		 ESDM_PKCS11_ENTROPY_RATE);
	CHECK(es_state_str_is(state, "entropy_rate_source", "provider"),
	      "the rate is not the one the daemon declares: %s",
	      es_state_print(state));
	CHECK(es_state_str_has(state, "status", "connected (uid") &&
		      !es_state_str_has(state, "status", "failing"),
	      "the daemon is not connected: %s", es_state_print(state));
	CHECK(es_state_int(state, "available_entropy", 0) > 0,
	      "the source is not credited: %s", es_state_print(state));

	/* The status of the daemon, as the provider of the source */
	plugin = test_member(test_member(state, "provider"), "plugin");
	CHECK(es_state_str_is(plugin, "token", PK_TOKEN_LABEL) &&
		      es_state_has(plugin, "logged_in", json_type_boolean) &&
		      json_object_get_boolean(test_member(plugin, "logged_in")),
	      "the status of the daemon does not show the token logged in to: %s",
	      es_state_print(state));
	json_object_put(state);
}

/* A daemon restarted is found again, without the ESDM doing anything */
static void test_restarted(void)
{
	const uint32_t bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
	const uint32_t level = test_level(ESDM_PKCS11_ENTROPY_RATE, bits);
	unsigned int i;
	uint32_t got = 0;

	CHECK(pk_stop(), "esdm-es-pkcs11 did not end cleanly");
	CHECK_EQ(test_get(bits, NULL), 0);
	CHECK_EQ(ES->curr_entropy(bits), 0);

	CHECK(test_daemon_start(), "esdm-es-pkcs11 does not start again");
	for (i = 0; i < 20 && got != level; i++) {
		es_ext_test_sleep_ms(250);
		got = test_get(bits, NULL);
	}
	CHECK_EQ(got, level);
	CHECK_EQ(ES->curr_entropy(bits), level);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 3) {
		printf("Usage: %s <esdm-es-pkcs11> <shim module>\n", argv[0]);
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	signal(SIGPIPE, SIG_IGN);

	if (pk_setup(argv[1], argv[2])) {
		printf("cannot set up the test directory\n");
		return 1;
	}
	if (!pk_find_softhsm()) {
		printf("SoftHSM (softhsm2-util) is not available - skipping\n");
		pk_cleanup();
		return 77;
	}
	if (pk_softhsm_setup() || !test_daemon_start()) {
		printf("cannot serve a SoftHSM token\n");
		pk_cleanup();
		return 1;
	}

	/*
	 * The daemon runs as the test user, accepted as esdm-server
	 * --es_ext_uid accepts it
	 */
	CHECK_EQ(esdm_es_ext_set_peer_uid(0, (int64_t)getuid()), 0);

	test_credited();
	test_restarted();

	ES->fini();
	CHECK(pk_stop(), "esdm-es-pkcs11 did not end cleanly");
	ret = common_test_result("es_pkcs11_esdm");
	pk_cleanup();
	return ret;
}
