/*
 * The Jitter RNG as the only credited entropy source, and what the ESDM does
 * when it loses it
 *
 * The ESDM is brought up with every other source declared to deliver nothing,
 * so the seed it hands out comes from this one source: with it, output is
 * produced. It then loses that source - the entropy rate is set to zero, which
 * is what a Jitter RNG failing its SP800-90B health tests amounts to for the
 * accounting - and what each interface does about it is pinned down here.
 *
 * The prediction resistance interface stops at once: the entropy behind each
 * of its outputs is collected for that output, and there is none to collect.
 * At most one output can come from a seed collected before - see
 * ESDM_SEC_MAX_REQUESTS.
 *
 * The ordinary interface does not: a reseed that collects nothing leaves the
 * DRNG producing from the state it has until it has spent the generate
 * operations it is allowed without a full reseed - see
 * ESDM_DRNG_MAX_WITHOUT_RESEED in esdm_definitions.h. That is checked with the
 * budget the build configures. Then the budget is set to what the DRNG has
 * spent plus one, so that the next reseed that collects nothing is what ends
 * the output - and with it the operation of the ESDM, on every interface.
 *
 * Only the requests and the reseeds of this test move the counters the budget
 * is checked against: the spent generate operations are added up when a
 * reseed comes back without full entropy, and the reseeds are forced here
 * rather than waited for. The reseed interval is left as configured, far
 * longer than this test runs, so no request runs into a reseed falling due by
 * it in between.
 *
 * The NTG.1 seeding strategy does not let a single entropy source seed the
 * ESDM initially, unless that source is a Jitter RNG in its own NTG.1 mode.
 * Without that mode, the auxiliary pool is credited with one seed's worth of
 * entropy for the initial seeding as the second source. It is spent by that
 * seeding, so after it the Jitter RNG is again the only credited source.
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

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_jent.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "ret_checkers.h"
#include "../test_plan.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)

/*
 * Wait for the initial seeding at most this many 100ms slices. A working
 * Jitter RNG seeds the ESDM within seconds, a sanitizer build within a few
 * times that - running out of this is a failure, not a skip.
 */
#define ESDM_SEC_SEED_SLICES 900

/*
 * Requests made before the output has to have stopped. Two would do: the
 * prediction resistance DRNG may hold one seed collected before the source
 * was lost, and the ordinary DRNG stops at the first reseed after its budget
 * is used up, which the second forced reseed is at the latest.
 */
#define ESDM_SEC_MAX_REQUESTS 8

/*
 * Does the initial seeding need a second entropy source next to the Jitter
 * RNG? The NTG.1 seeding strategy wants two, unless the Jitter RNG is NTG.1
 * conformant on its own - see esdm_fully_seeded().
 */
static bool esdm_sec_needs_second_source(void)
{
	return esdm_ntg1_2024_compliant() && !esdm_jent_ntg1();
}

/*
 * Provide the second source for the initial seeding: one seed's worth of
 * entropy in the auxiliary pool, plus what the conditioning discounts for
 * oversampling, so that the pool counts as a source of its own. Inserted only
 * while the pool is empty, and no more than one seeding collects, so that
 * nothing is left over once the seeding has collected it.
 */
static void esdm_sec_feed_aux(void)
{
	uint8_t seed[2 * ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	size_t i;

	if (esdm_avail_entropy_aux())
		return;

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	esdm_pool_insert_aux(seed, sizeof(seed),
			     ESDM_DRNG_SECURITY_STRENGTH_BITS +
				     esdm_compress_osr());
}

/*
 * The counters of the DRNG serving ordinary requests, read back from the
 * statistics.
 */
struct esdm_sec_counters {
	unsigned int found;
	uint32_t requests_since_fully_seeded;
};

static void esdm_sec_counters_cb(const struct esdm_drng_stats *stats,
				 void *priv)
{
	struct esdm_sec_counters *counters = (struct esdm_sec_counters *)priv;

	if (!strcmp(stats->type, "prediction resistance"))
		return;

	counters->found++;
	counters->requests_since_fully_seeded =
		stats->requests_since_fully_seeded;
}

static struct esdm_sec_counters esdm_sec_counters_get(void)
{
	struct esdm_sec_counters counters = { .found = 0,
					      .requests_since_fully_seeded = 0 };

	esdm_drng_stats_foreach(esdm_sec_counters_cb, &counters);

	return counters;
}

static void esdm_sec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

static bool esdm_sec_buf_is_zero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return false;
	}

	return true;
}

static int esdm_jent_only_security_test(void)
{
	struct esdm_sec_counters counters;
	uint8_t buf[32];
	unsigned int i;
	uint32_t budget;
	ssize_t rc, max_rc = 0;
	size_t max_rc_if = 0;
	bool written = false;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * One DRNG, so that the requests below all land on the same instance
	 * and spend the same budget - with a DRNG per node they would be
	 * spread over instances that each have their own.
	 */
	TEST_STEP("use a single DRNG instance");
	esdm_config_max_nodes_set(1);

	/*
	 * Everything but the Jitter RNG is declared to deliver no entropy, so
	 * the ESDM can only reach the fully seeded level through that one
	 * source - and loses it with that source alone.
	 */
	TEST_STEP(
		"credit the Jitter RNG with %u bits, every other entropy source with 0 bits",
		ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_test_es_rates_zero();
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	/*
	 * No working Jitter RNG on this machine - its startup health test
	 * failed - so the source this test is about never delivers: there is
	 * nothing to observe losing. That is known right after the
	 * initialization, a seeding that does not happen with a working one is
	 * a failure.
	 */
	TEST_REQUIRE("the Jitter RNG works on this machine (test skipped otherwise)");
	if (!esdm_es_jent.active || !esdm_es_jent.active()) {
		printf("the Jitter RNG is not usable on this machine, skipping test\n");
		ret = 77;
		goto out;
	}

	if (esdm_sec_needs_second_source()) {
		TEST_RUNUNTIL(
			"credit the auxiliary pool with %u bits whenever it is empty and wait 100 ms until the ESDM is fully seeded, at most %u times",
			ESDM_DRNG_SECURITY_STRENGTH_BITS + esdm_compress_osr(),
			ESDM_SEC_SEED_SLICES);
	} else {
		TEST_RUNUNTIL(
			"wait 100 ms until the ESDM is fully seeded, at most %u times",
			ESDM_SEC_SEED_SLICES);
	}
	for (i = 0; i < ESDM_SEC_SEED_SLICES && !esdm_state_fully_seeded();
	     i++) {
		if (esdm_sec_needs_second_source())
			esdm_sec_feed_aux();
		esdm_sec_sleep(0, 100 * 1000 * 1000);
	}

	TEST_REQUIRE("the ESDM is fully seeded with the Jitter RNG credited");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded())) {
		printf("the ESDM is not fully seeded after %u ms with a working Jitter RNG credited\n",
		       ESDM_SEC_SEED_SLICES * 100);
		goto err;
	}

	/*
	 * Entropy left in the auxiliary pool would be a second source the
	 * reseeds below could collect from after the Jitter RNG is gone.
	 */
	TEST_REQUIRE("no entropy is left in the auxiliary pool");
	if (!TEST_CHECK(!esdm_avail_entropy_aux(), "%u",
			esdm_avail_entropy_aux())) {
		printf("%u bits left in the auxiliary pool after the initial seeding\n",
		       esdm_avail_entropy_aux());
		goto err;
	}

	/* The Jitter RNG on its own carries the ESDM */
	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full_noblock",
		  sizeof(buf));
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc)) {
		printf("cannot obtain %zu bytes with the Jitter RNG credited: %zd\n",
		       sizeof(buf), rc);
		goto err;
	}

	TEST_REQUIRE("the returned buffer is not all zero");
	if (!TEST_CHECK(!esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			!esdm_sec_buf_is_zero(buf, sizeof(buf)))) {
		printf("the ESDM handed out an all zero buffer\n");
		goto err;
	}

	printf("%zu bytes obtained with the Jitter RNG as the only credited source\n",
	       sizeof(buf));

	/*
	 * The source fails: a Jitter RNG whose SP800-90B health tests trip
	 * stops being credited, which is what a rate of zero expresses.
	 */
	TEST_STEP("fail the Jitter RNG by crediting it with 0 bits");
	esdm_config_es_jent_entropy_rate_set(0);

	/*
	 * The prediction resistance interface has nothing to collect for its
	 * next output. A seed collected while the source still worked can
	 * serve one more - the PR DRNG takes a fresh seed for each output -
	 * but no more than that.
	 */
	TEST_RUNUNTIL(
		"request %zu bytes from esdm_get_random_bytes_pr_noblock until it returns no bytes, at most %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	TEST_REQUIRE(
		"esdm_get_random_bytes_pr_noblock returns no bytes within %u requests",
		ESDM_SEC_MAX_REQUESTS);
	if (!TEST_CHECK(rc <= 0, "%zd", rc)) {
		printf("the prediction resistance generator still hands out random bits after %u requests without a credited entropy source\n",
		       ESDM_SEC_MAX_REQUESTS);
		goto err;
	}

	TEST_REQUIRE("the buffer of the refused request is left all zero");
	if (!TEST_CHECK(esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			esdm_sec_buf_is_zero(buf, sizeof(buf)))) {
		printf("the prediction resistance generator wrote into the buffer while reporting %zd\n",
		       rc);
		goto err;
	}

	printf("the prediction resistance generator hands out nothing after %u request(s) (%zd)\n",
	       i + 1, rc);

	/*
	 * A reseed that collects nothing does not stop the ordinary interface
	 * while the DRNG is within its budget of generate operations without
	 * a full reseed - the one the build configures.
	 */
	TEST_STEP(
		"force a reseed of the DRNGs and request %zu bytes from esdm_get_random_bytes_full_noblock",
		sizeof(buf));
	esdm_drng_force_reseed();
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc)) {
		printf("the ESDM stopped on a reseed without a credited entropy source within its budget of %u: %zd\n",
		       esdm_config_drng_max_wo_reseed(), rc);
		goto err;
	}

	TEST_REQUIRE("the returned buffer is not all zero");
	if (!TEST_CHECK(!esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			!esdm_sec_buf_is_zero(buf, sizeof(buf)))) {
		printf("the ESDM handed out an all zero buffer\n");
		goto err;
	}

	TEST_REQUIRE("the ESDM is operational");
	if (!TEST_CHECK(esdm_state_operational(), "%d",
			esdm_state_operational())) {
		printf("the ESDM left operational mode within its budget\n");
		goto err;
	}

	/* Size the budget to what the DRNG has spent, plus one */
	TEST_STEP(
		"read the generate operations since the last full reseed from the DRNG statistics");
	counters = esdm_sec_counters_get();
	TEST_REQUIRE("exactly one DRNG instance serves ordinary requests");
	if (!TEST_CHECK(counters.found == 1, "%u", counters.found)) {
		printf("%u DRNG instances serve ordinary requests, expected 1\n",
		       counters.found);
		goto err;
	}
	budget = counters.requests_since_fully_seeded + 1;
	TEST_STEP(
		"limit the generate operations without a full reseed to %u (spent + 1)",
		budget);
	esdm_config_drng_max_wo_reseed_set(budget);

	/*
	 * The spent operations are added up by a reseed that comes back
	 * without full entropy, so the budget by itself holds nothing back
	 * until the next one. The request above is not counted yet.
	 */
	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full_noblock",
		  sizeof(buf));
	memset(buf, 0, sizeof(buf));
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc)) {
		printf("the ESDM stopped before the reseed that uses up its budget of %u: %zd\n",
		       budget, rc);
		goto err;
	}

	TEST_REQUIRE("the ESDM is operational");
	if (!TEST_CHECK(esdm_state_operational(), "%d",
			esdm_state_operational())) {
		printf("the ESDM left operational mode before the reseed that uses up its budget of %u\n",
		       budget);
		goto err;
	}

	/*
	 * Now move the DRNG into reseeds it cannot satisfy - the operator
	 * action behind esdm-tool --reseed-crng, and what the ESDM does on its
	 * own once the reseed interval elapses. One per request, so that
	 * the requests made since the last one are always added up.
	 */
	TEST_RUNUNTIL(
		"force a reseed of the DRNGs and request %zu bytes from esdm_get_random_bytes_full_noblock until it returns no bytes, at most %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		esdm_drng_force_reseed();
		memset(buf, 0, sizeof(buf));
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	TEST_REQUIRE(
		"esdm_get_random_bytes_full_noblock returns no bytes within %u requests",
		ESDM_SEC_MAX_REQUESTS);
	if (!TEST_CHECK(rc <= 0, "%zd", rc)) {
		printf("the ESDM still hands out random bits %u requests after reseeds without a credited entropy source\n",
		       ESDM_SEC_MAX_REQUESTS);
		goto err;
	}

	TEST_REQUIRE("the buffer of the refused request is left all zero");
	if (!TEST_CHECK(esdm_sec_buf_is_zero(buf, sizeof(buf)), "%d",
			esdm_sec_buf_is_zero(buf, sizeof(buf)))) {
		printf("the ESDM wrote into the buffer while reporting %zd\n",
		       rc);
		goto err;
	}

	TEST_REQUIRE("the ESDM is not operational");
	if (!TEST_CHECK(!esdm_state_operational(), "%d",
			!esdm_state_operational())) {
		printf("the ESDM reports itself operational after refusing to hand out random bits\n");
		goto err;
	}

	TEST_STEP(
		"read the generate operations since the last full reseed from the DRNG statistics");
	counters = esdm_sec_counters_get();
	TEST_REQUIRE(
		"exactly one DRNG instance has spent at least %u generate operations",
		budget);
	if (!TEST_CHECK(counters.found == 1, "%u", counters.found) ||
	    !TEST_CHECK(counters.requests_since_fully_seeded >= budget, "%u",
			counters.requests_since_fully_seeded)) {
		printf("the DRNG is out of operation with %u of %u generate operations spent\n",
		       counters.requests_since_fully_seeded, budget);
		goto err;
	}

	printf("no output %u request(s) after reseeds that collected nothing (%zd), %u of %u spent\n",
	       i + 1, rc, counters.requests_since_fully_seeded, budget);

	/* And it stays that way, on every interface that produces output */
	TEST_STEP(
		"request %zu bytes from esdm_get_random_bytes_full_noblock, esdm_get_random_bytes_pr_noblock and esdm_get_random_bytes, %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		ssize_t rcs[3];
		size_t j;

		memset(buf, 0, sizeof(buf));
		rcs[0] = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		rcs[1] = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		rcs[2] = esdm_get_random_bytes(buf, sizeof(buf));

		/* The worst of all of them is what is checked below */
		for (j = 0; j < 3; j++) {
			if ((!i && !j) || rcs[j] > max_rc) {
				max_rc = rcs[j];
				max_rc_if = j;
			}
		}

		if (!esdm_sec_buf_is_zero(buf, sizeof(buf)))
			written = true;
	}

	TEST_REQUIRE("no interface returns any bytes");
	if (!TEST_CHECK(max_rc <= 0, "%zd", max_rc)) {
		printf("the ESDM resumed handing out random bits: interface %zu returned %zd\n",
		       max_rc_if, max_rc);
		goto err;
	}

	TEST_REQUIRE("the buffer is left all zero");
	if (!TEST_CHECK(!written, "%d", written)) {
		printf("the ESDM wrote into the buffer while refusing to hand out random bits\n");
		goto err;
	}

	printf("nothing is handed out on any interface afterwards\n");

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE && ESDM_ES_JENT */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_ES_JENT)
	return esdm_jent_only_security_test();
#else
	printf("test mode or the Jitter RNG entropy source not compiled in\n");
	return 77;
#endif
}
