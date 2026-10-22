/*
 * Test that the publication of the node DRNGs is not undone by a seeding
 *
 * A seeding takes its view of the node array, then the pool lock, and declares
 * all DRNGs seeded if it finds every one in that view seeded. A seeding that
 * took its view before the node array was published sees the initial and the
 * PR DRNG only. If the array is published and the state that all DRNGs are
 * seeded cleared while that seeding waits for the pool lock, it declares the
 * new node DRNGs seeded although nobody seeded them - and esdm_get_seed(), the
 * reseed on entropy arrival and the initial oversampling go by that state.
 *
 * The test holds the pool lock while a real seeding takes its view (no node
 * array yet) and queues up behind it, and while the node DRNGs are allocated.
 * Once the lock is released, whatever the order, the state that all DRNGs are
 * seeded must not be set while a node DRNG is not seeded.
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
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "esdm_selftest.h"

/* A seeding that finds the initial and the PR DRNG seeded */
static void *esdm_nas_seed(void *arg)
{
	(void)arg;

	esdm_force_fully_seeded();
	return NULL;
}

static void *esdm_nas_alloc(void *arg)
{
	(void)arg;

	esdm_drngs_node_alloc();
	return NULL;
}

/* Does the state that all DRNGs are seeded hold for every DRNG there is? */
static int esdm_nas_check(void)
{
	struct esdm_drng **drngs = esdm_drng_get_instances();
	uint32_t node, unseeded = 0;
	int ret = 0;

	if (!drngs) {
		printf("no node DRNGs allocated\n");
		ret = 1;
		goto out;
	}

	for (node = 0; node < esdm_drng_node_count_get(); node++) {
		if (drngs[node] && !atomic_load(&drngs[node]->fully_seeded))
			unseeded++;
	}

	printf("all DRNGs seeded: %d, node DRNGs not seeded: %u of %u\n",
	       esdm_pool_all_nodes_seeded_get(), unseeded,
	       esdm_drng_node_count_get());

	if (esdm_pool_all_nodes_seeded_get() && unseeded) {
		printf("the seeding declared node DRNGs seeded it never saw\n");
		ret = 1;
	}

out:
	esdm_drng_put_instances();
	return ret;
}

int main(int argc, char *argv[])
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	pthread_t seeder, allocator;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	if (esdm_config_online_nodes() < 2) {
		printf("Need at least two nodes\n");
		return 77;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* What esdm_init() does up to the node DRNGs */
	ret = esdm_config_init();
	if (ret)
		return ret;
	ret = esdm_drng_mgr_initialize();
	if (ret)
		return ret;
	ret = esdm_es_mgr_initialize();
	if (ret)
		goto out;
	esdm_selftest_run();
	esdm_force_fully_seeded_all_drbgs();

	if (!esdm_pool_all_nodes_seeded_get()) {
		printf("DRNGs cannot be seeded fully\n");
		ret = 77;
		goto out;
	}

	/*
	 * The initial and the PR DRNG are seeded, the state saying so is gone -
	 * which is all a seeding needs to declare it again.
	 */
	esdm_pool_lock();
	esdm_pool_all_nodes_seeded(false);

	if (pthread_create(&seeder, NULL, esdm_nas_seed, NULL)) {
		esdm_pool_unlock();
		ret = 1;
		goto out;
	}

	/* Time for the seeding to take its view and queue up for the lock */
	nanosleep(&ts, NULL);

	if (pthread_create(&allocator, NULL, esdm_nas_alloc, NULL)) {
		esdm_pool_unlock();
		pthread_join(seeder, NULL);
		ret = 1;
		goto out;
	}

	/* Time for the allocation to publish the array, if it does not wait */
	nanosleep(&ts, NULL);

	esdm_pool_unlock();

	pthread_join(seeder, NULL);
	pthread_join(allocator, NULL);

	ret = esdm_nas_check();

out:
	esdm_drng_mgr_reseed_worker_stop();
	esdm_es_mgr_finalize();
	esdm_drng_mgr_finalize();
	esdm_node_fini();
	return ret;
}
