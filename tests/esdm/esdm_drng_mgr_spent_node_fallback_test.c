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
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_es_mgr.h"
#include "es_rates.h"
#include "ret_checkers.h"
#include "wait_seeded.h"

#ifdef ESDM_TESTMODE
/*
 * The maximum number of bits without full reseed SP800-90C and AIS 20/31
 * DRG.4 allow: 2^17.
 */
#define TEST_MAX_WO_RESEED_BITS (1U << 17)

/*
 * Requests of this size divide the limit, so the node DRNG serves the last
 * block below it in full and is found spent only by the request after.
 */
#define TEST_REQUEST_BYTES 32

/* Requests one DRNG can serve without full reseed */
#define TEST_REQUESTS_PER_DRNG                                                 \
	((TEST_MAX_WO_RESEED_BITS >> 3) / TEST_REQUEST_BYTES)

static int esdm_drng_mgr_spent_node_fallback_test(void)
{
	uint8_t buf[TEST_REQUEST_BYTES];
	unsigned int i, served = 0;
	int ret;

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	CKINT(esdm_init());

	esdm_get_random_bytes(buf, sizeof(buf));

	if (test_wait_fully_seeded()) {
		printf("ESDM is not fully seeded!\n");
		goto err;
	}

	/* No full reseed is possible from here on */
	esdm_test_es_rates_zero();
	esdm_config_drng_max_wo_reseed_bits_set(TEST_MAX_WO_RESEED_BITS);

	/*
	 * Use up the node DRNG and then the initial one. The request finding
	 * the node DRNG spent with nothing generated yet must be served by the
	 * initial DRNG, not fail: neither esdm_get_random_bytes() nor
	 * esdm_get_random_bytes_full() may fail while the ESDM is operational.
	 * Only once the initial DRNG is spent as well, the ESDM leaves the
	 * operational state and requests fail.
	 */
	for (i = 0; i < 3 * TEST_REQUESTS_PER_DRNG; i++) {
		ssize_t rc = (i & 1) ? esdm_get_random_bytes_full(buf,
								  sizeof(buf)) :
				       esdm_get_random_bytes(buf, sizeof(buf));

		if (rc == (ssize_t)sizeof(buf)) {
			served++;
			continue;
		}

		if (esdm_state_operational()) {
			printf("request %u returned %zd while the ESDM is operational\n",
			       i, rc);
			goto err;
		}
		break;
	}

	printf("%u requests served\n", served);
	if (served <= TEST_REQUESTS_PER_DRNG) {
		printf("no more requests served than one DRNG allows\n");
		goto err;
	}

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif

int main(void)
{
#ifdef ESDM_TESTMODE
	cpu_set_t set;

	/*
	 * Test idea: with two DRNG instances and this process on CPU 1, the
	 * requests are served by the node DRNG 1. Once seeded, let all entropy
	 * sources deliver no entropy, set the maximum number of bits without
	 * full reseed and use the node DRNG up. Requests must then move on to
	 * the initial DRNG without any of them failing.
	 */
	esdm_config_max_nodes_set(2);
	CPU_ZERO(&set);
	CPU_SET(1, &set);
	if (sched_setaffinity(getpid(), sizeof(cpu_set_t), &set) == -1 ||
	    sched_getcpu() < 1) {
		printf("Cannot pin process to CPU 1\n");
		return 1;
	}

	return esdm_drng_mgr_spent_node_fallback_test();
#else
	return 77;
#endif
}
