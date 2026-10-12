/*
 * Test that the prediction resistance DRNG leaves the seeding state alone
 *
 * The PR DRNG gives up its seed with every output on purpose. That says
 * nothing about the other DRNGs, so the state that all DRNGs are seeded -
 * which esdm_get_seed(), the reseed on entropy arrival and the initial
 * oversampling go by - has to survive a PR request.
 *
 * And every output is generated from a seed collected for it, the first one
 * after the instantiation of the DRNG at start up too: each request of one
 * block takes the DRNG one seed generation further.
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
#include <unistd.h>

#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

/* Number of PR requests made */
#define ESDM_PRS_REQUESTS 4

static void esdm_prs_generation_cb(const struct esdm_drng_stats *stats,
				   void *priv)
{
	long long *generation = priv;

	*generation = stats->seed_generation;
}

static long long esdm_prs_generation(void)
{
	long long generation = 0;

	esdm_drng_stats_pr(esdm_prs_generation_cb, &generation);
	return generation;
}

int main(int argc, char *argv[])
{
	/* One block of PR output: one seed */
	uint8_t buf[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	long long generation;
	unsigned int i;
	ssize_t rc;
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

	ret = esdm_init();
	if (ret)
		return ret;

	esdm_force_fully_seeded_all_drbgs();
	if (!esdm_pool_all_nodes_seeded_get()) {
		printf("DRNGs cannot be seeded fully\n");
		ret = 77;
		goto out;
	}

	for (i = 0; i < ESDM_PRS_REQUESTS; i++) {
		generation = esdm_prs_generation();
		rc = esdm_get_random_bytes_pr(buf, sizeof(buf));
		if (rc <= 0) {
			printf("PR request %u failed: %zd\n", i, rc);
			ret = 1;
			goto out;
		}

		if (esdm_prs_generation() != generation + 1) {
			printf("PR request %u was served from seed generation %lld, which it did not collect\n",
			       i, generation);
			ret = 1;
			goto out;
		}

		if (!esdm_pool_all_nodes_seeded_get()) {
			printf("PR request %u left the DRNGs not all seeded\n",
			       i);
			ret = 1;
			goto out;
		}
	}

	ret = 0;

out:
	esdm_fini();
	return ret;
}
