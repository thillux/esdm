/*
 * Test that only the initial DRNG makes the ESDM operational
 *
 * The initial DRNG is the fallback for every request, so the ESDM is
 * operational only while it is fully seeded. Here it loses its seed with no
 * entropy left to restore it, and the entropy that arrives afterwards goes to
 * the reseed of another DRNG: that reseed must not make the ESDM operational
 * again.
 *
 * The aux pool is the only source credited, so the test decides which seeding
 * gets entropy. The reseed worker looks after the seeded node DRNG before it
 * brings up the initial one, so the entropy goes to the node DRNG - unless a
 * seeding triggered elsewhere, e.g. by an entropy source buffer being filled,
 * got to the initial DRNG first. That attempt shows nothing and is repeated.
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
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "threading_support.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_NODE)

/* The initial DRNG and one more */
#define ESDM_OID_NODES 2

/* Seeding passes the DRNGs get to be seeded initially */
#define ESDM_OID_SEED_PASSES 10

/* Wait for the reseed worker at most this many 100ms slices */
#define ESDM_OID_SLICES 100

/* Attempts at handing the entropy to the node DRNG rather than the initial */
#define ESDM_OID_ATTEMPTS 10

struct esdm_oid_state {
	bool init_seeded;
	long long node_seed_generation;
};

static void esdm_oid_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct esdm_oid_state *state = priv;

	if (!strcmp(stats->type, "initial"))
		state->init_seeded = stats->fully_seeded;
	else if (!strcmp(stats->type, "node"))
		state->node_seed_generation = stats->seed_generation;
}

static struct esdm_oid_state esdm_oid_state_get(void)
{
	struct esdm_oid_state state = { .init_seeded = false,
					.node_seed_generation = -1 };

	esdm_drng_stats_foreach(esdm_oid_cb, &state);
	return state;
}

static void esdm_oid_sleep_slice(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/*
 * Take the seed away from the initial DRNG, make entropy for one seed available
 * and have the node DRNG reseeded with it.
 *
 * @return 0 if the node DRNG got the entropy and the ESDM stayed out of the
 *	   operational state, 1 if it did not stay out, -EAGAIN if the initial
 *	   DRNG got the entropy instead
 */
static int esdm_oid_attempt(const uint8_t *data, size_t datalen,
			    bool *worker_started)
{
	struct esdm_oid_state before, after;
	unsigned int i;
	bool operational;

	/* The initial DRNG loses its seed, and there is nothing to restore it */
	esdm_pool_set_entropy(0);
	esdm_unset_fully_seeded(esdm_drng_init_instance());
	if (esdm_state_operational()) {
		printf("ESDM operational without a seeded initial DRNG\n");
		return 1;
	}

	/*
	 * Entropy for one seed arrives. Holding the pool lock keeps the
	 * arrival from seeding the DRNGs right away, which would serve the
	 * initial DRNG first.
	 */
	esdm_pool_lock();
	esdm_pool_insert_aux(data, datalen, ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_pool_unlock();

	/*
	 * The other DRNG is asked to reseed, and the reseed worker gets to
	 * it before it looks after the initial DRNG.
	 */
	before = esdm_oid_state_get();
	esdm_drng_force_reseed();

	if (!*worker_started) {
		if (!esdm_drng_mgr_reseed_worker_start()) {
			printf("the reseed worker is not on duty\n");
			return 1;
		}
		*worker_started = true;
	}

	for (i = 0; i < ESDM_OID_SLICES; i++) {
		after = esdm_oid_state_get();
		if (after.node_seed_generation > before.node_seed_generation)
			break;
		esdm_oid_sleep_slice();
	}

	/*
	 * The operational state before the initial DRNG: a seeding of the
	 * initial DRNG in between may make the ESDM operational, but cannot
	 * hide that it was operational before the initial DRNG was seeded.
	 */
	operational = esdm_state_operational();
	after = esdm_oid_state_get();

	if (after.node_seed_generation <= before.node_seed_generation) {
		printf("the other DRNG was not reseeded within %u slices\n",
		       ESDM_OID_SLICES);
		return 1;
	}

	if (operational && !after.init_seeded) {
		printf("ESDM operational without a seeded initial DRNG after another DRNG was reseeded\n");
		return 1;
	}

	if (after.init_seeded)
		return -EAGAIN;

	return 0;
}

static int esdm_oid_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	bool worker_started = false;
	unsigned int i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (sysconf(_SC_NPROCESSORS_ONLN) < ESDM_OID_NODES) {
		printf("Need %d CPUs\n", ESDM_OID_NODES);
		return 77;
	}

	/*
	 * The aux pool is a single entropy source, which the NTG.1 seeding
	 * strategy does not accept for the initial seeding - nor, before the
	 * fix this test is for, would the seeding of the node DRNG have made
	 * the ESDM operational from it.
	 */
	if (esdm_ntg1_2024_compliant()) {
		printf("the NTG.1 seeding strategy cannot be seeded from the aux pool alone\n");
		return 77;
	}

	esdm_config_max_nodes_set(ESDM_OID_NODES);
	esdm_test_es_rates_zero();

	ret = esdm_init();
	if (ret)
		return ret;

	/* Seed every DRNG from a full aux pool each time */
	memset(data, 0x5a, sizeof(data));
	for (i = 0; i < ESDM_OID_SEED_PASSES && !esdm_pool_all_nodes_seeded_get();
	     i++) {
		esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);
		esdm_force_fully_seeded_all_drbgs();
	}
	if (!esdm_pool_all_nodes_seeded_get() || !esdm_state_operational()) {
		printf("DRNGs cannot be seeded from the aux pool\n");
		ret = 1;
		goto out;
	}

	if (thread_init(1)) {
		printf("cannot initialize threading support\n");
		ret = 1;
		goto out;
	}

	for (i = 0; i < ESDM_OID_ATTEMPTS; i++) {
		ret = esdm_oid_attempt(data, sizeof(data), &worker_started);
		if (ret != -EAGAIN)
			goto out;

		printf("the initial DRNG got the entropy first, attempt %u of %u\n",
		       i + 1, ESDM_OID_ATTEMPTS);
	}

	printf("the node DRNG never got the entropy ahead of the initial DRNG\n");
	ret = 1;

out:
	if (worker_started)
		esdm_drng_mgr_reseed_worker_stop();
	esdm_fini();
	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_NODE)
	return esdm_oid_test();
#else
	return 77;
#endif
}
