/*
 * Test a request of 4 GiB
 *
 * The length of a request is a size_t, and it was cut to 32 bits before it was
 * compared with the size of one block: a request of exactly 4 GiB asked the
 * DRNG for zero bytes, which it refuses, and the request failed with -EFAULT.
 * The PR DRNG is asked here, as it stops after the first block once the
 * entropy sources run dry - the buffer is reserved, but only its first block
 * is ever written.
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
#include <sys/mman.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"

#if defined(ESDM_TESTMODE) && SIZE_MAX > UINT32_MAX

/* Seeding passes the DRNGs get to be seeded initially */
#define ESDM_PLR_SEED_PASSES 10

#define ESDM_PLR_LEN ((size_t)1 << 32)

static void esdm_plr_cb(const struct esdm_drng_stats *stats, void *priv)
{
	bool *initiated = priv;

	*initiated = stats->initiated;
}

static bool esdm_plr_pr_initiated(void)
{
	bool initiated = false;

	esdm_drng_stats_pr(esdm_plr_cb, &initiated);
	return initiated;
}

static int esdm_plr_test(void)
{
	uint8_t data[ESDM_MAX_DIGESTSIZE];
	uint8_t *buf;
	unsigned int i;
	ssize_t rc;
	int ret;

	/* Only the first block is written, so reserve no memory for it */
	buf = mmap(NULL, ESDM_PLR_LEN, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (buf == MAP_FAILED) {
		printf("Cannot map a buffer of 4 GiB\n");
		return 77;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The initial DRNG and the PR DRNG are all there is to seed */
	esdm_config_max_nodes_set(1);

	ret = esdm_init();
	if (ret)
		goto unmap;

	/* A full aux pool is the second source NTG.1 asks for */
	memset(data, 0x5a, sizeof(data));
	for (i = 0; i < ESDM_PLR_SEED_PASSES && !esdm_plr_pr_initiated(); i++) {
		esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);
		esdm_force_fully_seeded_all_drbgs();
	}
	if (!esdm_plr_pr_initiated()) {
		printf("PR DRNG cannot be instantiated\n");
		ret = 77;
		goto out;
	}

	/* One seed in the aux pool, and nothing after it */
	esdm_test_es_rates_zero();
	esdm_pool_set_entropy(0);
	esdm_pool_insert_aux(data, sizeof(data), sizeof(data) << 3);

	rc = esdm_get_random_bytes_pr(buf, ESDM_PLR_LEN);
	if (rc <= 0) {
		printf("PR request of 4 GiB failed: %zd\n", rc);
		ret = 1;
		goto out;
	}

	printf("PR request of 4 GiB returned %zd bytes\n", rc);
	ret = 0;

out:
	esdm_fini();
unmap:
	munmap(buf, ESDM_PLR_LEN);
	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && SIZE_MAX > UINT32_MAX
	return esdm_plr_test();
#else
	return 77;
#endif
}
