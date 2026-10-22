/*
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

/*
 * esdm_drbg_healthcheck_sanity() is to show that the generic DRBG layer
 * enforces the SP800-90A request and additional input limits. An unseeded
 * DRBG refuses every request before the limits are looked at, so the check
 * has to seed the DRBG first - otherwise it passes without evaluating a
 * single limit. A DRBG core that records what reaches it shows whether it
 * does.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_drbg.h"

static unsigned int seed_calls, generate_calls, zero_calls;
static size_t largest_request;
static int generate_unseeded;

static void probe_seed(struct esdm_drbg_state *drbg,
		       struct esdm_drbg_string *seed)
{
	(void)drbg;
	(void)seed;
	seed_calls++;
}

static size_t probe_generate(struct esdm_drbg_state *drbg, uint8_t *buf,
			     size_t buflen, struct esdm_drbg_string *addtl)
{
	(void)addtl;

	if (!drbg->seeded)
		generate_unseeded = 1;
	generate_calls++;
	if (buflen > largest_request)
		largest_request = buflen;

	memset(buf, 0xa5, buflen);
	return buflen;
}

static void probe_zero(struct esdm_drbg_state *drbg)
{
	(void)drbg;
	zero_calls++;
}

int main(int argc, char *argv[])
{
	struct esdm_drbg_state drbg_state;
	struct esdm_drbg_state *drbg = &drbg_state;
	int ret = 0;

	(void)argc;
	(void)argv;

	_ESDM_DRBG_SET_CTX(drbg, probe_seed, probe_generate, probe_zero);

	if (esdm_drbg_healthcheck_sanity(drbg)) {
		printf("FAIL: health check failed on a working DRBG\n");
		ret = 1;
	}

	/* The limit checks only run against a seeded DRBG */
	if (!seed_calls) {
		printf("FAIL: health check never seeded the DRBG\n");
		ret = 1;
	}

	/*
	 * A request within the limits reaches the core, which proves the
	 * DRBG would have generated - and none beyond them does.
	 */
	if (!generate_calls) {
		printf("FAIL: health check never generated within the limits\n");
		ret = 1;
	}
	if (largest_request > esdm_drbg_max_request_bytes()) {
		printf("FAIL: an oversized request of %zu bytes reached the DRBG\n",
		       largest_request);
		ret = 1;
	}
	if (generate_unseeded) {
		printf("FAIL: the DRBG generated while unseeded\n");
		ret = 1;
	}

	/* The test seed must not stay behind */
	if (!zero_calls || drbg->seeded) {
		printf("FAIL: health check left the DRBG seeded\n");
		ret = 1;
	}

	if (!ret)
		printf("DRBG health check: all checks passed\n");

	return ret;
}
