/*
 * Test crediting entropy to the auxiliary pool
 *
 * esdm_pool_add_entropy(), what RNDADDTOENTCNT of the RPC and the EGD
 * interface does, adds to the count of the first pool in the pool's own units,
 * before the discount for the oversampling, up to the size of the pool:
 * credits add up, a credit of nothing changes nothing, the entropy of the other
 * pools is not credited once more, and a pool that holds no data - not
 * inserted into since its (re)initialization - is credited nothing.
 *
 * Driven through the entropy source callbacks without the rest of the ESDM, so
 * that nothing else is inserted into or taken from the pool between the steps.
 * Where the SP800-90C oversampling is compiled in, the SP800-90C mode is
 * switched on, so that the discount is covered as well.
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

/* The size of a pool in bits, which esdm_get_digestsize() has to report */
#define ESDM_AXA_POOL_BITS 512

/* The oversampling a pool discounts, see esdm_aux_avail_entropy_pool() */
static uint32_t esdm_axa_osr(void)
{
#ifdef ESDM_AUX_INPUT_HAS_FULL_ENTROPY
	return 0;
#else
	return esdm_compress_osr();
#endif
}

/* The entropy a pool reports when it is credited with @raw bits */
static uint32_t esdm_axa_avail(uint32_t raw)
{
	uint32_t osr = esdm_axa_osr();

	if (raw > ESDM_AXA_POOL_BITS)
		raw = ESDM_AXA_POOL_BITS;
	return (raw > osr) ? raw - osr : 0;
}

static int esdm_axa_check(uint32_t exp, const char *what)
{
	uint32_t avail = esdm_get_aux_ent();

	if (avail != exp) {
		printf("%s: the auxiliary pools report %u bits instead of %u\n",
		       what, avail, exp);
		return 1;
	}

	return 0;
}

/* Insert data credited with @entropy_bits */
static int esdm_axa_insert(uint32_t entropy_bits)
{
	uint8_t data[ESDM_AXA_POOL_BITS >> 3];
	int ret;

	memset(data, 0x5a, sizeof(data));
	ret = esdm_pool_insert_aux(data, sizeof(data), entropy_bits);
	if (ret) {
		printf("Insert into the auxiliary pool failed: %d\n", ret);
		return 1;
	}

	return 0;
}

/* A pool that absorbed nothing has no data to credit entropy to */
static int esdm_axa_no_data(const char *when)
{
	int ret = 0;

	esdm_pool_add_entropy(256);
	ret += esdm_axa_check(0, "Credit to a pool without data");

	esdm_pool_set_entropy(256);
	ret += esdm_axa_check(0, "Entropy set for a pool without data");

	if (!ret)
		printf("%s: a pool without data is credited nothing\n", when);
	return ret;
}

/* Credits add up in the units of the pool, up to its size */
static int esdm_axa_add_up(void)
{
	uint32_t raw;
	int ret = 0;

	/* Data without entropy goes into all pools and credits nothing */
	if (esdm_axa_insert(0))
		return 1;
	ret += esdm_axa_check(0, "Data without entropy");

	for (raw = 64; raw <= ESDM_AXA_POOL_BITS + 64; raw += 64) {
		esdm_pool_add_entropy(64);
		ret += esdm_axa_check(esdm_axa_avail(raw), "Credit of 64 bits");

		/* Not even the discount for the oversampling is taken again */
		esdm_pool_add_entropy(0);
		ret += esdm_axa_check(esdm_axa_avail(raw), "Credit of no bits");
	}

	esdm_pool_set_entropy(0);
	esdm_pool_add_entropy(UINT32_MAX);
	ret += esdm_axa_check(esdm_axa_avail(ESDM_AXA_POOL_BITS),
			      "Credit of the largest count");

	if (!ret)
		printf("Credits add up to the size of the pool\n");
	return ret;
}

#if ESDM_NUM_AUX_POOLS > 1
/* The credit goes to the first pool, which is not given the others' entropy */
static int esdm_axa_other_pools(struct esdm_es_cb *aux)
{
	struct entropy_es eb_es;
	uint32_t raw0, full = esdm_axa_avail(ESDM_AXA_POOL_BITS);
	int ret = 0;

	/* Two full pools, the first and the second, whichever is picked first */
	esdm_pool_set_entropy(0);
	if (esdm_axa_insert(ESDM_AXA_POOL_BITS) ||
	    esdm_axa_insert(ESDM_AXA_POOL_BITS))
		return 1;
	ret += esdm_axa_check(2 * full, "Two full pools");

	/* The extraction takes from the first of the two */
	memset(&eb_es, 0, sizeof(eb_es));
	aux->get_ent(&eb_es, 256, true);
	raw0 = ESDM_AXA_POOL_BITS - 256 - esdm_axa_osr();
	ret += esdm_axa_check(esdm_axa_avail(raw0) + full,
			      "Extraction from the first pool");

	esdm_pool_add_entropy(64);
	ret += esdm_axa_check(esdm_axa_avail(raw0 + 64) + full,
			      "Credit beside a full pool");

	if (!ret)
		printf("The credit leaves the other pools out\n");
	return ret;
}
#endif

int main(int argc, char *argv[])
{
	struct esdm_es_cb *aux = esdm_es[esdm_ext_es_aux];
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Covers the discount for the oversampling where it is compiled in */
	esdm_config_force_fips_set(esdm_config_force_sp80090c_enabled);
	printf("Oversampling of the auxiliary pool: %u bits\n", esdm_axa_osr());

	if (esdm_get_digestsize() != ESDM_AXA_POOL_BITS) {
		printf("Auxiliary pool reports a state of %u bits instead of %u\n",
		       esdm_get_digestsize(), ESDM_AXA_POOL_BITS);
		return 1;
	}

	ret = aux->init();
	if (ret) {
		printf("Auxiliary pool initialization failed: %d\n", ret);
		return 1;
	}

	ret = esdm_axa_no_data("Initialized");
	ret += esdm_axa_add_up();
#if ESDM_NUM_AUX_POOLS > 1
	ret += esdm_axa_other_pools(aux);
#endif

	/* As esdm_reinit() does: the pools start over without data */
	if (aux->init()) {
		printf("Auxiliary pool reinitialization failed\n");
		ret++;
	} else {
		ret += esdm_axa_no_data("Reinitialized");
	}

	aux->fini();
	return ret ? 1 : 0;
}
