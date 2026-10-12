/*
 * The Jitter RNG as the only credited entropy source, and what the ESDM does
 * when it loses it
 *
 * The ESDM is brought up with every other source declared to deliver nothing,
 * so the seed it hands out comes from this one source: with it, output is
 * produced. It then loses that source - the entropy rate is set to zero, which
 * is what a Jitter RNG failing its SP800-90B health tests amounts to for the
 * accounting - and after a reseed that collects nothing, no output is produced.
 *
 * A reseed that collects nothing leaves the DRNG producing from the state it
 * has until it has spent the generate operations it is allowed without a full
 * reseed - see ESDM_DRNG_MAX_WITHOUT_RESEED in esdm_definitions.h. That budget
 * is set to its minimum here, so the reseed is what ends the output.
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

/* Wait for the initial seeding at most this many 100ms slices */
#define ESDM_SEC_SEED_SLICES 100

/*
 * Requests granted before the output has to stop, once the budget of generate
 * operations without a full reseed is set to its minimum.
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

static void esdm_sec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

static int esdm_jent_only_security_test(void)
{
	uint8_t buf[32];
	unsigned int i;
	ssize_t rc;
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

	TEST_REQUIRE(
		"the ESDM is fully seeded with the Jitter RNG credited (test skipped otherwise)");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded())) {
		/*
		 * No working Jitter RNG on this machine, so the source this
		 * test is about never delivered - there is nothing to observe
		 * losing.
		 */
		printf("the ESDM is not fully seeded with the Jitter RNG credited, skipping test\n");
		ret = 77;
		goto out;
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
	rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc)) {
		printf("cannot obtain %zu bytes with the Jitter RNG credited: %zd\n",
		       sizeof(buf), rc);
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
	 * Without a budget of generate operations left, a reseed that collects
	 * nothing cannot keep the DRNG going on the state it has.
	 */
	TEST_STEP("limit the generate operations without a full reseed to 1");
	esdm_config_drng_max_wo_reseed_set(1);

	TEST_STEP("force a reseed of the DRNGs");
	esdm_drng_force_reseed();

	TEST_RUNUNTIL(
		"request %zu bytes from esdm_get_random_bytes_full_noblock until it returns no bytes, at most %u times",
		sizeof(buf), ESDM_SEC_MAX_REQUESTS);
	for (i = 0; i < ESDM_SEC_MAX_REQUESTS; i++) {
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc <= 0)
			break;
	}

	TEST_REQUIRE(
		"esdm_get_random_bytes_full_noblock returns no bytes within %u requests",
		ESDM_SEC_MAX_REQUESTS);
	if (!TEST_CHECK(rc <= 0, "%zd", rc)) {
		printf("the ESDM still hands out random bits %u requests after a reseed without a credited entropy source\n",
		       ESDM_SEC_MAX_REQUESTS);
		goto err;
	}

	printf("no output %u request(s) after a reseed that collected nothing (%zd)\n",
	       i + 1, rc);

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
