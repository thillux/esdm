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

/* Reseed interval the worker is given, and how long it is waited for */
#define ESDM_RSEC_INTERVAL 5
#define ESDM_RSEC_WAIT 7

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

static int esdm_reseed_security_test(void)
{
	uint8_t buf[32];
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

	TEST_STEP("set the reseed interval to %d seconds", ESDM_RSEC_INTERVAL);
	esdm_set_reseed_max_time(ESDM_RSEC_INTERVAL);

	/* Nothing is requested meanwhile - the interval alone reseeds */
	TEST_STEP("wait %d seconds without a request", ESDM_RSEC_WAIT);
	esdm_rsec_sleep(ESDM_RSEC_WAIT, 0);

	if (esdm_rsec_generation_check(2))
		goto err;

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

	if (esdm_rsec_generation_check(3))
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
