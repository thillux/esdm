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
 * Node DRNGs running dry under sustained load.
 *
 * Under SP800-90C, FIPS 140 and AIS 20/31 DRG.4 a DRNG hands out at most 2^17
 * bits from one seed. Its reseed is asked for a quarter before, and the DRNG of
 * a node leaves it to the reseed worker - but that quarter is 4 KiB, which
 * sustained load spends in microseconds, while the reseed takes milliseconds of
 * entropy collection. So the node DRNGs run into the limit all the time, and
 * what matters is how they come back:
 *
 *   - the ESDM stays operational and esdm_get_seed() keeps serving: a node DRNG
 *     at its limit is one in need of a reseed, not one that was never seeded,
 *     and takes neither the state that all DRNGs are seeded nor anything that
 *     goes by it along,
 *   - every node DRNG that ran dry is reseeded, not only the first few: once
 *     the load stops, all of them are back in service right away, without a
 *     request asking for any of them,
 *   - every blocking request is answered in full: running dry is the normal
 *     case here, and no reason for esdm_get_random_bytes_full() to give up -
 *     nor for esdm_get_random_bytes_full_noblock(), which the RPC server
 *     serves its clients with, to fail: it may answer short.
 *
 * A build without the cap gets it applied here, so the path is covered by every
 * build with test mode. Several threads, each pinned to a CPU of its own, keep
 * the DRNGs of as many nodes busy; the rates are printed for the record.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "wait_seeded.h"

#ifdef ESDM_TESTMODE

/* The maximum output without full reseed of SP800-90C and DRG.4: 2^17 bits */
#define TEST_MAX_WO_RESEED_BITS (1U << 17)

/* What the load threads ask for per request */
#define TEST_REQUEST_BYTES 4096

/* How long the load is kept up */
#define TEST_LOAD_SECONDS 4.0

/*
 * How long the node DRNGs may take to all be back in service once the load
 * stopped. A pass of the worker reseeds every one of them, one entropy
 * collection each - a fraction of this even for all nodes of a large machine,
 * and under a sanitizer.
 */
#define TEST_RECOVER_SECONDS 10.0

/* Most load threads, and most nodes looked at */
#define TEST_MAX_THREADS 8
#define TEST_MAX_NODES 256

/* Pause between two samples */
#define TEST_SAMPLE_NS (2 * 1000 * 1000)

/*
 * Samples between two calls of esdm_get_seed(). Each of them collects from
 * the entropy sources under the pool lock, as a reseed does, and asked on
 * every sample it would compete with the reseeds it is to observe.
 */
#define TEST_SEED_EVERY 25

static atomic_bool test_stop = false;
static atomic_ullong test_bytes = 0, test_failed = 0, test_short = 0;
static atomic_llong test_first_error = 0;
static atomic_ullong test_nb_failed = 0, test_nb_short = 0;
static atomic_llong test_nb_first_error = 0;

struct test_node {
	bool seen;
	bool seeded;
	unsigned long drops;
	long long gen_start, gen_end;
};

static struct test_node test_nodes[TEST_MAX_NODES];

static double test_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void *test_load(void *arg)
{
	static _Thread_local uint8_t buf[TEST_REQUEST_BYTES];
	size_t cpu = (size_t)(uintptr_t)arg;
	cpu_set_t set;

	/* Best effort - without it the scheduler spreads the threads */
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);

	while (!atomic_load(&test_stop)) {
		ssize_t rc;

		/*
		 * Half the threads ask without blocking in between, as the RPC
		 * server does: such a request may come back short - a DRNG ran
		 * into its limit on the way - but not fail while the ESDM is
		 * operational.
		 */
		if (!(cpu & 1)) {
			rc = esdm_get_random_bytes_full_noblock(buf,
								sizeof(buf));
			if (rc < 0) {
				long long expected = 0;

				atomic_fetch_add(&test_nb_failed, 1);
				atomic_compare_exchange_strong(
					&test_nb_first_error, &expected, rc);
			} else {
				if ((size_t)rc != sizeof(buf))
					atomic_fetch_add(&test_nb_short, 1);
				atomic_fetch_add(&test_bytes,
						 (unsigned long long)rc);
			}
		}

		rc = esdm_get_random_bytes_full(buf, sizeof(buf));

		if (rc < 0) {
			long long expected = 0;

			atomic_fetch_add(&test_failed, 1);
			atomic_compare_exchange_strong(&test_first_error,
						       &expected, rc);
			continue;
		}
		if ((size_t)rc != sizeof(buf))
			atomic_fetch_add(&test_short, 1);
		atomic_fetch_add(&test_bytes, (unsigned long long)rc);
	}

	return NULL;
}

/* Note the state of a node DRNG */
static void test_node_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct test_node *n;

	(void)priv;

	if (stats->pr || !stats->node_valid || stats->node >= TEST_MAX_NODES)
		return;

	n = &test_nodes[stats->node];
	if (!n->seen) {
		n->seen = true;
		n->gen_start = stats->seed_generation;
	} else if (n->seeded && !stats->fully_seeded) {
		n->drops++;
	}
	n->seeded = stats->fully_seeded;
	n->gen_end = stats->seed_generation;
}

/* Count the node DRNGs that are not fully seeded right now */
static void test_unseeded_cb(const struct esdm_drng_stats *stats, void *priv)
{
	unsigned int *unseeded = priv;

	if (!stats->pr && stats->node_valid && !stats->fully_seeded)
		(*unseeded)++;
}

static unsigned int test_unseeded(void)
{
	unsigned int unseeded = 0;

	esdm_drng_stats_foreach(test_unseeded_cb, &unseeded);
	return unseeded;
}

static int esdm_drng_mgr_run_dry_test(void)
{
	static uint64_t seed[1024];
	struct timespec pause = { .tv_sec = 0, .tv_nsec = TEST_SAMPLE_NS };
	pthread_t threads[TEST_MAX_THREADS];
	unsigned long samples = 0, all_seeded = 0, nonop = 0;
	unsigned long seed_calls = 0, seed_ok = 0;
	unsigned long dried = 0, reseeded = 0;
	unsigned int nodes, num_threads, i, unseeded;
	double start, elapsed, recovered;
	uint8_t buf[32];
	int ret = 0;

	esdm_logger_set_verbosity(LOGGER_WARN);

	if (esdm_config_drng_max_wo_reseed_bits() > TEST_MAX_WO_RESEED_BITS)
		esdm_config_drng_max_wo_reseed_bits_set(
			TEST_MAX_WO_RESEED_BITS);

	CKINT(esdm_init());

	/* The reseed worker is taken from the thread pool */
	if (thread_init(1)) {
		printf("Cannot initialize threading support\n");
		goto err;
	}

	if (!esdm_drng_mgr_reseed_worker_start()) {
		printf("The reseed worker is not on duty\n");
		goto err;
	}

	/* The first request is what starts the seeding */
	esdm_get_random_bytes(buf, sizeof(buf));

	if (test_wait_fully_seeded()) {
		printf("The ESDM did not reach the fully seeded state\n");
		ret = 77;
		goto out;
	}

	nodes = esdm_drng_node_count_get();
	if (nodes < 2) {
		printf("%u DRNG node instances - no node DRNG to run dry\n",
		       nodes);
		ret = 77;
		goto out;
	}

	for (i = 0; i < 60 * 100 && !esdm_pool_all_nodes_seeded_get(); i++) {
		struct timespec ten_ms = { .tv_sec = 0,
					   .tv_nsec = 10 * 1000 * 1000 };

		nanosleep(&ten_ms, NULL);
	}
	if (!esdm_pool_all_nodes_seeded_get()) {
		printf("Not all DRNGs became fully seeded\n");
		ret = 77;
		goto out;
	}

	num_threads = nodes < TEST_MAX_THREADS ? nodes : TEST_MAX_THREADS;
	printf("%u DRNG node instances, %u load threads, %u bit reseed threshold, %u bits at most per seed\n",
	       nodes, num_threads, (unsigned int)ESDM_DRNG_RESEED_THRESH_BITS,
	       esdm_config_drng_max_wo_reseed_bits());

	start = test_now();
	for (i = 0; i < num_threads; i++) {
		if (pthread_create(&threads[i], NULL, test_load,
				   (void *)(uintptr_t)i)) {
			printf("Cannot start load thread %u\n", i);
			atomic_store(&test_stop, true);
			while (i--)
				pthread_join(threads[i], NULL);
			goto err;
		}
	}

	do {
		ssize_t rc;

		samples++;
		all_seeded += esdm_pool_all_nodes_seeded_get();
		nonop += !esdm_state_operational();

		if (!(samples % TEST_SEED_EVERY)) {
			rc = esdm_get_seed(seed, sizeof(seed),
					   ESDM_GET_SEED_NONBLOCK);
			seed_calls++;
			seed_ok += (rc > 0);
		}

		esdm_drng_stats_foreach(test_node_cb, NULL);
		nanosleep(&pause, NULL);
		elapsed = test_now() - start;
	} while (elapsed < TEST_LOAD_SECONDS);

	atomic_store(&test_stop, true);
	for (i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);

	/* Back in service without a request asking for any of them */
	start = test_now();
	do {
		unseeded = test_unseeded();
		if (!unseeded)
			break;
		nanosleep(&pause, NULL);
		recovered = test_now() - start;
	} while (recovered < TEST_RECOVER_SECONDS);
	recovered = test_now() - start;

	for (i = 0; i < TEST_MAX_NODES; i++) {
		if (!test_nodes[i].drops)
			continue;
		dried++;
		reseeded += (test_nodes[i].gen_end > test_nodes[i].gen_start);
		printf("node %3u: ran dry %lu times, seeded %lld times\n", i,
		       test_nodes[i].drops,
		       test_nodes[i].gen_end - test_nodes[i].gen_start);
	}

	printf("%.3f MB/s, %llu requests failed (first %lld), %llu answered short\n",
	       (double)atomic_load(&test_bytes) / elapsed / 1e6,
	       atomic_load(&test_failed), atomic_load(&test_first_error),
	       atomic_load(&test_short));
	printf("%lu samples: all DRNGs seeded in %lu, ESDM not operational in %lu; esdm_get_seed() served %lu of %lu calls\n",
	       samples, all_seeded, nonop, seed_ok, seed_calls);
	printf("%lu node DRNGs ran dry, %lu of them reseeded under load, %u not back in service %.3f s after the load stopped\n",
	       dried, reseeded, unseeded, recovered);

	if (atomic_load(&test_failed) || atomic_load(&test_short)) {
		printf("FAIL: %llu blocking requests failed, %llu were answered short\n",
		       atomic_load(&test_failed), atomic_load(&test_short));
		ret = 1;
	}

	printf("%llu non-blocking requests failed (first %lld), %llu answered short\n",
	       atomic_load(&test_nb_failed), atomic_load(&test_nb_first_error),
	       atomic_load(&test_nb_short));
	if (atomic_load(&test_nb_failed)) {
		printf("FAIL: non-blocking requests failed while the ESDM is operational\n");
		ret = 1;
	}

	if (!dried) {
		printf("No node DRNG ran dry - nothing more to check here\n");
		goto out;
	}

	if (nonop) {
		printf("FAIL: the ESDM left the operational state under load\n");
		ret = 1;
	}

	/*
	 * A node DRNG at its limit must not take the state that all DRNGs are
	 * seeded along with it, nor esdm_get_seed(), which refuses until that
	 * state is back - under sustained load, some node is always at its
	 * limit.
	 */
	if (all_seeded != samples) {
		printf("FAIL: the state that all DRNGs are seeded was gone in %lu of %lu samples\n",
		       samples - all_seeded, samples);
		ret = 1;
	}
	if (seed_ok != seed_calls) {
		printf("FAIL: esdm_get_seed() refused %lu of %lu calls\n",
		       seed_calls - seed_ok, seed_calls);
		ret = 1;
	}

	/*
	 * One node DRNG per pass of the worker, a second apart, and the others
	 * waiting for their turn - or never getting one.
	 */
	if (unseeded) {
		printf("FAIL: %u node DRNGs not back in service %.1f s after the load stopped\n",
		       unseeded, TEST_RECOVER_SECONDS);
		ret = 1;
	}

	if (!ret)
		printf("Node DRNGs come back from running dry\n");

out:
	esdm_drng_mgr_reseed_worker_stop();
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_drng_mgr_run_dry_test();
#else
	return 77;
#endif
}
