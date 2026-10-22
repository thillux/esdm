/*
 * Test of the seed stash
 *
 * While the DRNGs reseed at a high rate, the ES monitor collects seeds ahead of
 * them, see esdm_seed_stash_get():
 *
 *   - a burst of reseeds - a reseed interval of zero seconds has every
 *     request reseed - makes the monitor fill the stash,
 *   - a reseed takes a stashed seed,
 *   - a seed stashed before esdm_drng_force_reseed() is not the reseed asked
 *     for: the next reseed discards them all,
 *   - esdm_reset() empties it.
 *
 * The monitor is paused while the stash is looked at, so that it does not top
 * it up in between. A build without the stash must leave it empty under the
 * same burst, and skips the rest.
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
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "test_monitor.h"
#include "wait_seeded.h"

/* Wait for the monitor at most this many 100ms slices */
#define ESDM_SST_SLICES 100

static void esdm_sst_sleep_slice(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* One request, which reseeds the DRNG under a reseed interval of zero */
static int esdm_sst_reseed(void)
{
	uint8_t buf[16];

	if (esdm_get_random_bytes_full(buf, sizeof(buf)) != sizeof(buf)) {
		printf("a request was not served\n");
		return 1;
	}

	return 0;
}

/* Twice the reseeds the stash holds, which is a high rate */
static int esdm_sst_burst(unsigned int slots)
{
	unsigned int i;

	for (i = 0; i < 2 * (slots ? slots : 4); i++) {
		if (esdm_sst_reseed())
			return 1;
	}

	return 0;
}

static int esdm_sst_wait_filled(unsigned int slots)
{
	unsigned int i;

	for (i = 0; i < ESDM_SST_SLICES && esdm_seed_stash_filled() < slots;
	     i++)
		esdm_sst_sleep_slice();

	return esdm_seed_stash_filled() < slots;
}

static int esdm_sst_test(void)
{
	unsigned int slots = esdm_seed_stash_slots(), i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Every request lands on the initial DRNG */
	esdm_config_max_nodes_set(1);

	CKINT(esdm_init());
	if (test_monitor_start()) {
		printf("the ES monitor did not start\n");
		goto err;
	}

	if (test_wait_fully_seeded()) {
		printf("the ESDM did not reach the fully seeded state\n");
		ret = 77;
		goto out;
	}
	for (i = 0; i < ESDM_SST_SLICES && !esdm_pool_all_nodes_seeded_get();
	     i++)
		esdm_sst_sleep_slice();

	esdm_set_reseed_max_time(0);

	if (!slots) {
		if (esdm_sst_burst(slots))
			goto err;
		for (i = 0; i < 10; i++)
			esdm_sst_sleep_slice();
		if (esdm_seed_stash_filled()) {
			printf("FAIL: %u seeds stashed without a stash\n",
			       esdm_seed_stash_filled());
			goto err;
		}
		printf("no seed stash in this build, and nothing stashed\n");
		ret = 77;
		goto out;
	}

	/* A burst of reseeds, which the monitor stashes seeds for */
	if (esdm_sst_burst(slots))
		goto err;
	if (esdm_sst_wait_filled(slots)) {
		printf("FAIL: %u of %u seeds stashed after a burst of reseeds\n",
		       esdm_seed_stash_filled(), slots);
		goto err;
	}
	printf("the monitor filled the stash after a burst of reseeds\n");

	/* A reseed takes one */
	esdm_es_mgr_monitor_pause();
	ret = esdm_sst_reseed();
	i = esdm_seed_stash_filled();
	esdm_es_mgr_monitor_resume();
	if (ret)
		goto err;
	if (i != slots - 1) {
		printf("FAIL: %u of %u seeds left after a reseed\n", i, slots);
		goto err;
	}
	printf("a reseed took a stashed seed\n");

	/* Stashed before the forced reseed: discarded, not served */
	if (esdm_sst_wait_filled(slots)) {
		printf("FAIL: the stash was not topped up again\n");
		goto err;
	}
	esdm_es_mgr_monitor_pause();
	esdm_drng_force_reseed();
	ret = esdm_sst_reseed();
	i = esdm_seed_stash_filled();
	esdm_es_mgr_monitor_resume();
	if (ret)
		goto err;
	if (i) {
		printf("FAIL: %u seeds stashed before esdm_drng_force_reseed() are still there after the reseed\n",
		       i);
		goto err;
	}
	printf("esdm_drng_force_reseed() flushed the stash\n");

	/* And a reset empties it */
	if (esdm_sst_burst(slots) || esdm_sst_wait_filled(slots)) {
		printf("FAIL: the stash was not filled again\n");
		goto err;
	}
	esdm_es_mgr_monitor_pause();
	esdm_reset();
	i = esdm_seed_stash_filled();
	esdm_es_mgr_monitor_resume();
	if (i) {
		printf("FAIL: %u seeds stashed after esdm_reset()\n", i);
		goto err;
	}
	printf("esdm_reset() emptied the stash\n");

	ret = 0;

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return esdm_sst_test();
}
