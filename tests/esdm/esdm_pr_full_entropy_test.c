/*
 * Test that the prediction resistance DRNG keeps back the RBG3(RS) margin
 *
 * Operated SP800-90C compliant, the PR DRNG is an RBG3(RS): its output has full
 * entropy, which takes 64 bits of entropy more in its seed than it hands out
 * (SP800-90C sec. 6.5.1.2). Here a seed holds the security strength of 256 bits
 * and no more, so it covers no more than 192 bits of output.
 *
 * The aux pool is the only source credited: it holds what was inserted, so the
 * entropy of a seed is set by the test rather than scaled with the request.
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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_OVERSAMPLE_ENTROPY_SOURCES)

/* RBG3(RS) oversampling in bits, see SP800-90C sec. 6.5.1.2 */
#define ESDM_PFE_RS_OSR 64

/*
 * Entropy inserted into the aux pool so that it is credited with the security
 * strength: the pool discounts its own oversampling of 64 bits.
 */
#define ESDM_PFE_SEED_BITS (ESDM_DRNG_SECURITY_STRENGTH_BITS + 64)

/* Seeding passes the DRNGs get to be seeded initially */
#define ESDM_PFE_SEED_PASSES 10

static void esdm_pfe_cb(const struct esdm_drng_stats *stats, void *priv)
{
	bool *fully_seeded = priv;

	*fully_seeded = stats->fully_seeded;
}

static bool esdm_pfe_pr_seeded(void)
{
	bool fully_seeded = false;

	esdm_drng_stats_pr(esdm_pfe_cb, &fully_seeded);
	return fully_seeded;
}

static int esdm_pfe_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	uint8_t buf[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	unsigned int i;
	ssize_t rc;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The initial DRNG and the PR DRNG are all there is to seed */
	esdm_config_max_nodes_set(1);

	esdm_config_force_fips_set(esdm_config_force_sp80090c_enabled);
	if (!esdm_config_sp80090c_compliant()) {
		printf("SP800-90C mode cannot be enabled\n");
		return 77;
	}

	esdm_test_es_rates_zero();

	ret = esdm_init();
	if (ret)
		return ret;

	/* Seed both DRNGs from a full aux pool each time */
	memset(data, 0x5a, sizeof(data));
	for (i = 0; i < ESDM_PFE_SEED_PASSES && !esdm_pfe_pr_seeded(); i++) {
		esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);
		esdm_force_fully_seeded_all_drbgs();
	}
	if (!esdm_pfe_pr_seeded()) {
		printf("PR DRNG cannot be seeded, skipping test\n");
		ret = 77;
		goto out;
	}

	/* Spend the initial seed, after which every output reseeds */
	rc = esdm_get_random_bytes_pr(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("First PR request failed: %zd\n", rc);
		ret = 1;
		goto out;
	}

	/*
	 * One seed of the security strength, and nothing after it: the pool
	 * is emptied of what is left from the initial seeding first.
	 */
	esdm_pool_set_entropy(0);
	esdm_pool_insert_aux(data, sizeof(data), ESDM_PFE_SEED_BITS);
	rc = esdm_get_random_bytes_pr(buf, sizeof(buf));
	if (rc <= 0) {
		printf("Second PR request failed: %zd\n", rc);
		ret = 1;
		goto out;
	}

	if ((size_t)rc >
	    (ESDM_DRNG_SECURITY_STRENGTH_BITS - ESDM_PFE_RS_OSR) >> 3) {
		printf("%zd bytes of full entropy output from a seed of %u bits\n",
		       rc, ESDM_DRNG_SECURITY_STRENGTH_BITS);
		ret = 1;
		goto out;
	}

	printf("%zd bytes of full entropy output from a seed of %u bits\n", rc,
	       ESDM_DRNG_SECURITY_STRENGTH_BITS);
	ret = 0;

out:
	esdm_fini();
	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_OVERSAMPLE_ENTROPY_SOURCES)
	return esdm_pfe_test();
#else
	return 77;
#endif
}
