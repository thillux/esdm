/*
 * Test of the reseed with a reseed interval of zero seconds
 *
 * Every request is reseeded then, and once is enough: a request the initial
 * DRNG serves must not be preceded by two seedings in a row.
 *
 * Nor may the reseed be skipped because somebody else holds the pool lock: the
 * request waits for it. With a node DRNG next to the initial one - the
 * argument is the number of DRNG instances asked for - that covers the
 * generate loop, which the initial DRNG skips for its first block.
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

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

/* Number of requests made */
#define ESDM_RPR_REQUESTS 4

static void esdm_rpr_cb(const struct esdm_drng_stats *stats, void *priv)
{
	long long *seed_generation = priv;

	/* Whichever instance served the request */
	if (strcmp(stats->type, "prediction resistance"))
		*seed_generation += stats->seed_generation;
}

static long long esdm_rpr_seed_generation(void)
{
	long long seed_generation = 0;

	esdm_drng_stats_foreach(esdm_rpr_cb, &seed_generation);
	return seed_generation;
}

/* The pool lock is held by this thread for a while once it is up */
static atomic_bool esdm_rpr_pool_held = false;

static void *esdm_rpr_hold_pool(void *arg)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 300 * 1000 * 1000 };

	(void)arg;

	esdm_pool_lock();
	atomic_store(&esdm_rpr_pool_held, true);
	nanosleep(&ts, NULL);
	esdm_pool_unlock();

	return NULL;
}

/* One request while another thread holds the pool lock */
static int esdm_rpr_busy_pool(void)
{
	struct timespec slice = { .tv_sec = 0, .tv_nsec = 1000 * 1000 };
	uint8_t buf[32];
	long long before, after;
	pthread_t thread;

	before = esdm_rpr_seed_generation();

	if (pthread_create(&thread, NULL, esdm_rpr_hold_pool, NULL))
		return 1;
	while (!atomic_load(&esdm_rpr_pool_held))
		nanosleep(&slice, NULL);

	if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
		printf("Request with a busy pool failed\n");
		pthread_join(thread, NULL);
		return 1;
	}
	after = esdm_rpr_seed_generation();

	pthread_join(thread, NULL);

	if (after != before + 1) {
		printf("Request with a busy pool seeded its DRNG %lld times\n",
		       after - before);
		return 1;
	}

	printf("Request with a busy pool waited for it and was reseeded\n");

	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t buf[32];
	long long before, after;
	unsigned int i;
	int ret;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* By default, only the initial DRNG serves requests */
	esdm_config_max_nodes_set(argc > 1 ? (uint32_t)atoi(argv[1]) : 1);

	ret = esdm_init();
	if (ret)
		return ret;

	esdm_force_fully_seeded_all_drbgs();
	esdm_set_reseed_max_time(0);

	for (i = 0; i < ESDM_RPR_REQUESTS; i++) {
		before = esdm_rpr_seed_generation();
		if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
			printf("Request %u failed\n", i);
			ret = 1;
			goto out;
		}
		after = esdm_rpr_seed_generation();

		if (after != before + 1) {
			printf("Request %u seeded its DRNG %lld times\n", i,
			       after - before);
			ret = 1;
			goto out;
		}
	}

	ret = esdm_rpr_busy_pool();

out:
	esdm_fini();
	return ret;
}
