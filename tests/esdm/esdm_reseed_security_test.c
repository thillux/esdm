/*
 * The two conditions that reseed a DRNG: the reseed interval and the number of
 * generate requests served from one seed
 *
 * The seed generation of the DRNG serving ordinary requests is followed through
 * both: once the reseed interval elapses the reseed worker reseeds it without a
 * request, and the generate requests reseed it once their threshold is
 * reached. The threshold is lowered to 2^10 requests for the whole test, so
 * that it is reached in a fraction of a second.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "../test_plan.h"

#ifdef ESDM_TESTMODE

/* Generate requests after which a DRNG is reseeded, for the whole test */
#define ESDM_RSEC_THRESH (1U << 10)

/* Requests made - twice the threshold */
#define ESDM_RSEC_REQUESTS (1U << 11)

/*
 * Bytes per request. The output of a seed is limited as well: under SP800-90C
 * the DRNG reseeds after ESDM_DRNG_RESEED_THRESH_BITS, three quarters of 2^17
 * bits. All requests together stay below that, so that the request threshold
 * is the only reason for a reseed.
 */
#define ESDM_RSEC_REQSIZE 1

#if (ESDM_RSEC_REQUESTS * ESDM_RSEC_REQSIZE * 8 >= ESDM_DRNG_RESEED_THRESH_BITS)
#error "the requests reach the reseed threshold in bits"
#endif

/*
 * Reseed interval the worker is given, and how much longer than that a reseed
 * it owes may take to show up - generous, as it has to collect the seed from
 * the entropy sources first.
 */
#define ESDM_RSEC_INTERVAL 5
#define ESDM_RSEC_SLACK 25

/* The seed generation is polled in slices of this many milliseconds */
#define ESDM_RSEC_POLL_MS 20

/*
 * How much earlier than the interval the second reseed may be seen: the first
 * one is seen up to a poll slice, and whatever the scheduler adds to it, after
 * it happened.
 */
#define ESDM_RSEC_TOLERANCE_MS 500

/* Wait for the initial seeding at most this many 100ms slices */
#define ESDM_RSEC_SEED_SLICES 100

/* The DRNG serving ordinary requests, read back from the statistics */
struct esdm_rsec_drng {
	unsigned int found;
	long long seed_generation;
};

static void esdm_rsec_drng_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct esdm_rsec_drng *drng = (struct esdm_rsec_drng *)priv;

	if (!strcmp(stats->type, "prediction resistance"))
		return;

	drng->found++;
	drng->seed_generation = stats->seed_generation;
}

static struct esdm_rsec_drng esdm_rsec_drng_get(void)
{
	struct esdm_rsec_drng drng = { .found = 0, .seed_generation = 0 };

	esdm_drng_stats_foreach(esdm_rsec_drng_cb, &drng);

	return drng;
}

/* Check that the one DRNG serving ordinary requests is at @expected */
static int esdm_rsec_generation_check(long long expected)
{
	struct esdm_rsec_drng drng;

	TEST_STEP("read the seed generation of the DRNG from its statistics");
	drng = esdm_rsec_drng_get();

	TEST_REQUIRE("exactly one DRNG instance serves ordinary requests");
	if (!TEST_CHECK(drng.found == 1, "%u", drng.found)) {
		printf("%u DRNG instances serve ordinary requests, expected 1\n",
		       drng.found);
		return 1;
	}

	TEST_REQUIRE("the seed generation of the DRNG is %lld", expected);
	if (!TEST_CHECK(drng.seed_generation == expected, "%lld",
			drng.seed_generation)) {
		printf("the seed generation of the DRNG is %lld, expected %lld\n",
		       drng.seed_generation, expected);
		return 1;
	}

	printf("the DRNG is at seed generation %lld\n", drng.seed_generation);

	return 0;
}

static void esdm_rsec_sleep(time_t sec, long nsec)
{
	struct timespec ts = { .tv_sec = sec, .tv_nsec = nsec };

	nanosleep(&ts, NULL);
}

/* Milliseconds on CLOCK_MONOTONIC */
static long long esdm_rsec_now_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1)
		return 0;

	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / (1000 * 1000);
}

/*
 * Poll the seed generation of the DRNG until it moves past @from, for at most
 * @max_ms milliseconds. Returns the generation it found and, in @seen_ms, when
 * it was found - one poll slice after the seeding at the latest.
 */
static long long esdm_rsec_wait_next(long long from, long long max_ms,
				     long long *seen_ms)
{
	long long start = esdm_rsec_now_ms();
	long long gen;

	TEST_RUNUNTIL(
		"poll the seed generation every %d ms until it moves past %lld, for at most %lld ms",
		ESDM_RSEC_POLL_MS, from, max_ms);
	for (;;) {
		gen = esdm_rsec_drng_get().seed_generation;
		*seen_ms = esdm_rsec_now_ms();
		if (gen != from || *seen_ms - start > max_ms)
			return gen;
		esdm_rsec_sleep(0, ESDM_RSEC_POLL_MS * 1000 * 1000);
	}
}

/*
 * The reseed worker reseeds the DRNG at generation @from once more, within
 * the interval and the slack, and returns when that was seen in @seen_ms.
 */
static int esdm_rsec_interval_reseed(long long from, long long *seen_ms)
{
	long long gen = esdm_rsec_wait_next(
		from, (ESDM_RSEC_INTERVAL + ESDM_RSEC_SLACK) * 1000, seen_ms);

	TEST_REQUIRE("the reseed worker reseeds the DRNG within %d seconds",
		     ESDM_RSEC_INTERVAL + ESDM_RSEC_SLACK);
	if (!TEST_CHECK(gen != from, "%lld", gen)) {
		printf("the DRNG is still at seed generation %lld\n", gen);
		return 1;
	}

	return esdm_rsec_generation_check(from + 1);
}

static int esdm_reseed_security_test(void)
{
	uint8_t buf[ESDM_RSEC_REQSIZE];
	long long first_ms, second_ms;
	unsigned int i;
	ssize_t rc = 0;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * One DRNG, so that every request below lands on the instance whose
	 * seed generation is followed.
	 */
	TEST_STEP("use a single DRNG instance");
	esdm_config_max_nodes_set(1);

	TEST_STEP("set the reseed threshold to %u generate requests",
		  ESDM_RSEC_THRESH);
	esdm_config_drng_reseed_thresh_set(ESDM_RSEC_THRESH);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto out;

	TEST_RUNUNTIL(
		"wait 100 ms until the ESDM is fully seeded, at most %u times",
		ESDM_RSEC_SEED_SLICES);
	for (i = 0; i < ESDM_RSEC_SEED_SLICES && !esdm_state_fully_seeded();
	     i++)
		esdm_rsec_sleep(0, 100 * 1000 * 1000);

	TEST_REQUIRE("the ESDM is fully seeded");
	if (!TEST_CHECK(esdm_state_fully_seeded(), "%d",
			esdm_state_fully_seeded())) {
		printf("the ESDM is not fully seeded after %u slices\n",
		       ESDM_RSEC_SEED_SLICES);
		goto err;
	}

	/* Seeded once, by the initialization */
	if (esdm_rsec_generation_check(1))
		goto err;

	/* The worker reseeding on the interval is taken from the thread pool */
	TEST_STEP("initialize threading support");
	TEST_REQUIRE("threading support initializes");
	ret = thread_init(1);
	if (!TEST_CHECK(ret == 0, "%d", ret))
		goto err;

	TEST_STEP("start the reseed worker");
	esdm_drng_mgr_reseed_worker_start();
	TEST_REQUIRE("the reseed worker is on duty");
	if (!TEST_CHECK(esdm_drng_mgr_reseed_worker_running(), "%d",
			esdm_drng_mgr_reseed_worker_running())) {
		printf("the reseed worker is not on duty\n");
		goto err;
	}

	/*
	 * Nothing is requested meanwhile - the interval alone reseeds. The
	 * initial seeding may already lie further back than the interval, so
	 * the first reseed can come at once and only marks the start: the
	 * second one is measured against it.
	 */
	TEST_STEP("set the reseed interval to %d seconds", ESDM_RSEC_INTERVAL);
	esdm_set_reseed_max_time(ESDM_RSEC_INTERVAL);

	if (esdm_rsec_interval_reseed(1, &first_ms))
		goto err;

	if (esdm_rsec_interval_reseed(2, &second_ms))
		goto err;

	/*
	 * The seed time is kept in whole seconds and a reseed is due once a
	 * full second past the interval has begun, so the reseeds are more
	 * than the interval apart. The first is seen late by up to the
	 * tolerance, which is all the measurement may fall short by.
	 */
	TEST_REQUIRE("the DRNG is not reseeded before the interval of %d seconds elapsed",
		     ESDM_RSEC_INTERVAL);
	if (!TEST_CHECK(second_ms - first_ms >=
				ESDM_RSEC_INTERVAL * 1000 - ESDM_RSEC_TOLERANCE_MS,
			"%lld ms", second_ms - first_ms)) {
		printf("the DRNG was reseeded %lld ms after the previous seeding\n",
		       second_ms - first_ms);
		goto err;
	}

	/*
	 * The worker stays out of the way of what follows: the next interval
	 * elapses only well after the requests are done.
	 */
	TEST_STEP("set the reseed interval to 3600 seconds");
	esdm_set_reseed_max_time(3600);

	TEST_STEP(
		"request %zu bytes from esdm_get_random_bytes_full_noblock, %u times",
		sizeof(buf), ESDM_RSEC_REQUESTS);
	for (i = 0; i < ESDM_RSEC_REQUESTS; i++) {
		rc = esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
		if (rc != (ssize_t)sizeof(buf))
			break;
	}

	TEST_REQUIRE("every request returns %zu bytes", sizeof(buf));
	if (!TEST_CHECK(i == ESDM_RSEC_REQUESTS, "%u requests served", i)) {
		printf("request %u returned %zd\n", i + 1, rc);
		goto err;
	}

	if (esdm_rsec_generation_check(4))
		goto err;

	ret = 0;

out:
	esdm_drng_mgr_reseed_worker_stop();
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_reseed_security_test();
#else
	printf("test mode not compiled in\n");
	return 77;
#endif
}
