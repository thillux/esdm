/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "ret_checkers.h"
#include "wait_seeded.h"

#ifdef ESDM_TESTMODE
/*
 * The maximum number of bits without full reseed SP800-90C and AIS 20/31
 * DRG.4 allow: 2^17.
 */
#define TEST_MAX_WO_RESEED_BITS (1U << 17)

/* One request four times the size of that limit */
#define TEST_REQUEST_BYTES (4 * (TEST_MAX_WO_RESEED_BITS >> 3))

static int esdm_drng_mgr_max_wo_reseed_bits_large_test(bool single_drng)
{
	static uint8_t buf[TEST_REQUEST_BYTES];
	ssize_t rc;
	unsigned int i;
	int ret;

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	CKINT(esdm_init());

	esdm_get_random_bytes(buf, 32);

	if (test_wait_fully_seeded()) {
		printf("ESDM is not fully seeded!\n");
		goto err;
	}

	for (i = 0; i < 10; i++) {
		if (esdm_get_random_bytes(buf, 32) != 32) {
			printf("cannot obtain random data\n");
			goto err;
		}
	}

	/* No full reseed is possible from here on */
	esdm_test_es_rates_zero();
	esdm_config_drng_max_wo_reseed_bits_set(TEST_MAX_WO_RESEED_BITS);

	/*
	 * A single request larger than the limit must not get more out of
	 * one DRNG than the limit allows: the request stops short. Checking
	 * the limit only once ahead of the generate loop would hand out the
	 * full request.
	 */
	rc = esdm_get_random_bytes(buf, sizeof(buf));
	printf("request of %zu bytes returned %zd\n", sizeof(buf), rc);
	if (rc <= 0) {
		printf("no random data obtained\n");
		goto err;
	}
	if ((size_t)rc > (TEST_MAX_WO_RESEED_BITS >> 3)) {
		printf("obtained %zd bytes, more than the %u bits allowed without full reseed\n",
		       rc, TEST_MAX_WO_RESEED_BITS);
		goto err;
	}

	/*
	 * With only the initial DRNG, the spent DRNG takes the ESDM out of the
	 * operational state and no further bits are handed out.
	 */
	if (single_drng) {
		if (esdm_state_operational()) {
			printf("ESDM remained operational with a spent initial DRNG\n");
			goto err;
		}
		rc = esdm_get_random_bytes(buf, sizeof(buf));
		if (rc > 0) {
			printf("obtained %zd bytes from a spent DRNG\n", rc);
			goto err;
		}
	}

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif

int main(int argc, char *argv[])
{
#ifdef ESDM_TESTMODE
	cpu_set_t set;
	unsigned long drng_instances;

	if (argc != 2) {
		printf("Provide number of DRNG instances to be created\n");
		return 1;
	}

	drng_instances = strtoul(argv[1], NULL, 10);
	if (drng_instances == ULONG_MAX)
		return errno;
	if (drng_instances > UINT32_MAX)
		return 1;

	/*
	 * Test idea: once the DRNGs are seeded, let all entropy sources
	 * deliver no entropy and set the maximum number of bits without full
	 * reseed. Then request four times that limit at once and verify that
	 * the request stops short at the limit.
	 */
	esdm_config_max_nodes_set((uint32_t)drng_instances);
	if (drng_instances > 1) {
		CPU_ZERO(&set);
		CPU_SET(1, &set);
		if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) ==
		    -1) {
			printf("Cannot pin process to CPU 1\n");
			return 1;
		}
		if (sched_getcpu() < 1) {
			printf("Cannot pin process to CPU 1\n");
			return 1;
		}
	}

	return esdm_drng_mgr_max_wo_reseed_bits_large_test(drng_instances ==
							    1);
#else
	(void)argc;
	(void)argv;
	return 77;
#endif
}
