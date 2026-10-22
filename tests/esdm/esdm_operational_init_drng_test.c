/*
 * Test that only the initial DRNG makes the ESDM operational
 *
 * The initial DRNG is the fallback for every request, so the ESDM is
 * operational only while it is fully seeded. Here it loses its seed with no
 * entropy left to restore it, while another DRNG is still seeded and due for
 * a reseed. Entropy for one seed arrives: it must not go to that reseed - a
 * request goes no further than the operational check while the ESDM is out
 * of operation - and the ESDM comes back only with the initial DRNG, which a
 * bring-up seeds first.
 *
 * The aux pool is the only source credited, so the test decides which seeding
 * gets entropy. No ES monitor runs, which would bring up the initial DRNG as
 * soon as the entropy arrives.
 *
 * The NTG.1 seeding strategy wants a second source for the initial seeding of
 * the DRNGs, so the Jitter RNG is credited for those seedings and taken out
 * in between.
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

#if defined(ESDM_TESTMODE) && defined(ESDM_NODE)

/* The initial DRNG and one more */
#define ESDM_OID_NODES 2

/* Seeding passes the DRNGs get to be seeded initially */
#define ESDM_OID_SEED_PASSES 10

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

/* What the seedings did to the DRNGs and the ESDM */
static void esdm_oid_print(const char *when, struct esdm_oid_state *state)
{
	printf("%s: initial DRNG seeded %d, node DRNG seed generation %lld, operational %d\n",
	       when, state->init_seeded, state->node_seed_generation,
	       esdm_state_operational());
}

/*
 * Take the seed away from the initial DRNG, make entropy for one seed available
 * and ask the node DRNG for a reseed.
 *
 * @return 0 if the node DRNG was not reseeded before the initial DRNG and the
 *	   ESDM came back with the initial DRNG only, 1 otherwise
 */
static int esdm_oid_attempt(const uint8_t *data, size_t datalen)
{
	struct esdm_oid_state before, after;
	uint8_t buf[32];
	ssize_t rc;

	/* The initial DRNG loses its seed, and there is nothing to restore it */
	esdm_pool_set_entropy(0);
	esdm_unset_fully_seeded(esdm_drng_init_instance());
	if (esdm_state_operational()) {
		printf("ESDM operational without a seeded initial DRNG\n");
		return 1;
	}

	/*
	 * Entropy for an initial seed arrives: a full aux pool, which covers
	 * the SP800-90C oversampling of the seeding and of the pool itself. It
	 * seeds the DRNGs only once the sources report the boot threshold:
	 * raised out of reach, it stays in the aux pool for whichever seeding
	 * comes next.
	 */
	esdm_set_entropy_thresh(UINT32_MAX);
	esdm_pool_insert_aux(data, datalen, (uint32_t)datalen << 3);

	/* The node DRNG is due for a reseed, and a request is served by it */
	before = esdm_oid_state_get();
	esdm_oid_print("before", &before);
	esdm_drng_force_reseed();
	rc = esdm_get_random_bytes(buf, sizeof(buf));
	after = esdm_oid_state_get();
	esdm_oid_print("after the request", &after);

	if (rc > 0) {
		printf("%zd bytes without a seeded initial DRNG\n", rc);
		return 1;
	}
	if (after.node_seed_generation != before.node_seed_generation) {
		printf("the node DRNG was reseeded while the ESDM was out of operation\n");
		return 1;
	}
	if (esdm_state_operational()) {
		printf("ESDM operational without a seeded initial DRNG after another DRNG was asked for a reseed\n");
		return 1;
	}

	/*
	 * The bring-up, as the ES monitor or a request does it. The NTG.1
	 * seeding strategy wants the Jitter RNG next to the aux pool again.
	 */
	esdm_set_entropy_thresh(ESDM_FULL_SEED_ENTROPY_BITS);
	if (esdm_ntg1_2024_compliant())
		esdm_config_es_jent_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_force_fully_seeded();
	after = esdm_oid_state_get();
	esdm_oid_print("after the bring-up", &after);

	if (!after.init_seeded) {
		printf("the bring-up did not seed the initial DRNG\n");
		return esdm_ntg1_2024_compliant() ? 77 : 1;
	}
	if (!esdm_state_operational()) {
		printf("ESDM not operational with a seeded initial DRNG\n");
		return 1;
	}
	if (after.node_seed_generation != before.node_seed_generation) {
		printf("the bring-up seeded the node DRNG before the initial one\n");
		return 1;
	}

	/* And the reseed asked for is done by the next request */
	if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
		printf("no random bytes with the ESDM back in operation\n");
		return 1;
	}
	after = esdm_oid_state_get();
	if (after.node_seed_generation <= before.node_seed_generation) {
		printf("the node DRNG was not reseeded by the next request\n");
		return 1;
	}

	printf("the ESDM stayed out of operation until the initial DRNG was seeded\n");
	return 0;
}

static int esdm_oid_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	unsigned int i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (sysconf(_SC_NPROCESSORS_ONLN) < ESDM_OID_NODES) {
		printf("Need %d CPUs\n", ESDM_OID_NODES);
		return 77;
	}

	esdm_config_max_nodes_set(ESDM_OID_NODES);
	esdm_test_es_rates_zero();

	/*
	 * The aux pool is a single entropy source, which the NTG.1 seeding
	 * strategy does not accept for the initial seeding. The Jitter RNG is
	 * credited as the second one for that seeding only.
	 */
	if (esdm_ntg1_2024_compliant()) {
#ifdef ESDM_ES_JENT
		esdm_config_es_jent_entropy_rate_set(
			ESDM_DRNG_SECURITY_STRENGTH_BITS);
#else
		printf("the NTG.1 seeding strategy needs the Jitter RNG next to the aux pool\n");
		return 77;
#endif
	}

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
		/* No working Jitter RNG on this machine to stand next to it */
		if (esdm_ntg1_2024_compliant()) {
			printf("DRNGs cannot be seeded from the aux pool and the Jitter RNG, skipping test\n");
			ret = 77;
			goto out;
		}
		printf("DRNGs cannot be seeded from the aux pool\n");
		ret = 1;
		goto out;
	}

	/* From here on, the aux pool is the only credited source again */
	esdm_config_es_jent_entropy_rate_set(0);

	ret = esdm_oid_attempt(data, sizeof(data));

out:
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
