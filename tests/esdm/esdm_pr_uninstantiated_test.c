/*
 * Test that the PR DRNG gives out nothing before it is instantiated
 *
 * A request to the PR DRNG only waits for the ESDM to be operational, which is
 * the state of the initial DRNG. If the PR DRNG is not instantiated by then,
 * the request instantiates it itself. An instantiation that falls short of the
 * initial seeding policy leaves it uninstantiated, and the request must then
 * produce nothing - not as many bytes as the entropy it did collect covers.
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
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "es_rates.h"

#ifdef ESDM_TESTMODE

/* Seeding passes the initial DRNG gets to be seeded */
#define ESDM_PRU_SEED_PASSES 10

/*
 * Entropy for the PR DRNG instantiation: short of the security strength the
 * initial seeding asks for at the least, yet more than the RBG3(RS)
 * oversampling of 64 bits and the aux pool's own oversampling of 64 bits keep
 * back - output would be capped to what is left, not refused.
 */
#define ESDM_PRU_SHORT_BITS (ESDM_DRNG_SECURITY_STRENGTH_BITS - 32)

static void esdm_pru_cb(const struct esdm_drng_stats *stats, void *priv)
{
	bool *initiated = priv;

	*initiated = stats->initiated;
}

static bool esdm_pru_pr_initiated(void)
{
	bool initiated = false;

	esdm_drng_stats_pr(esdm_pru_cb, &initiated);
	return initiated;
}

static int esdm_pru_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	uint8_t buf[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	unsigned int i;
	ssize_t rc;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The initial DRNG and the PR DRNG are all there is to seed */
	esdm_config_max_nodes_set(1);

	/* No esdm_init_monitor(): no reseed worker seeds behind our back */
	ret = esdm_init();
	if (ret)
		return ret;

	/*
	 * Start over, and bring up the initial DRNG alone: a seeding seeds one
	 * DRNG per call, the initial one first - the arrival of the entropy may
	 * have done so already. A full aux pool is the second source the NTG.1
	 * seeding strategy asks for.
	 */
	esdm_reset();
	memset(data, 0x5a, sizeof(data));
	for (i = 0; i < ESDM_PRU_SEED_PASSES; i++) {
		esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);
		if (esdm_state_operational())
			break;
		esdm_force_fully_seeded();
		if (esdm_state_operational())
			break;
	}
	if (!esdm_state_operational()) {
		printf("Initial DRNG cannot be seeded\n");
		ret = 77;
		goto out;
	}

	/*
	 * From here on, the aux pool is the only source, and holds too little.
	 * Under the pool lock: each of these calls tries a seeding, which
	 * would instantiate the PR DRNG from the sources still credited. The
	 * DRNG instances first, as every seeding takes them before the pool
	 * lock - the other order is a lock order inversion.
	 */
	esdm_drng_get_instances();
	esdm_pool_lock();
	esdm_test_es_rates_zero();
	esdm_pool_set_entropy(0);
	esdm_pool_insert_aux(data, sizeof(data), ESDM_PRU_SHORT_BITS);
	esdm_pool_unlock();
	esdm_drng_put_instances();

	if (esdm_pru_pr_initiated()) {
		printf("PR DRNG instantiated along with the initial DRNG\n");
		ret = 77;
		goto out;
	}

	rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));

	if (esdm_pru_pr_initiated()) {
		printf("PR DRNG instantiated from %u bits, nothing to test\n",
		       ESDM_PRU_SHORT_BITS);
		ret = 77;
		goto out;
	}

	if (rc > 0) {
		printf("%zd bytes from the PR DRNG before it was instantiated\n",
		       rc);
		ret = 1;
		goto out;
	}

	printf("PR request before the instantiation returned %zd\n", rc);
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

#ifdef ESDM_TESTMODE
	return esdm_pru_test();
#else
	return 77;
#endif
}
