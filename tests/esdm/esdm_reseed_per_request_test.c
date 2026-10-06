/*
 * Test of the reseed with a reseed interval of zero seconds
 *
 * Every request is reseeded then, and once is enough: a request the initial
 * DRNG serves must not be preceded by two seedings in a row.
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
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"

/* Number of requests made */
#define ESDM_RPR_REQUESTS 4

static void esdm_rpr_cb(const struct esdm_drng_stats *stats, void *priv)
{
	long long *seed_generation = priv;

	if (!strcmp(stats->type, "initial"))
		*seed_generation = stats->seed_generation;
}

static long long esdm_rpr_seed_generation(void)
{
	long long seed_generation = -1;

	esdm_drng_stats_summary(esdm_rpr_cb, &seed_generation);
	return seed_generation;
}

int main(int argc, char *argv[])
{
	uint8_t buf[32];
	long long before, after;
	unsigned int i;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* Only the initial DRNG serves requests */
	esdm_config_max_nodes_set(1);

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

		if (before < 0 || after != before + 1) {
			printf("Request %u seeded the initial DRNG %lld times\n",
			       i, after - before);
			ret = 1;
			goto out;
		}
	}

	ret = 0;

out:
	esdm_fini();
	return ret;
}
