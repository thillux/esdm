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

#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"

#ifdef ESDM_TESTMODE
static int esdm_config_max_wo_reseed_bits_check(uint32_t set, uint32_t exp)
{
	uint32_t got;

	esdm_config_drng_max_wo_reseed_bits_set(set);
	got = esdm_config_drng_max_wo_reseed_bits();
	if (got != exp) {
		printf("maximum bits without full reseed set to %u reads %u, expected %u\n",
		       set, got, exp);
		return 1;
	}

	return 0;
}
#endif

int main(void)
{
#ifdef ESDM_TESTMODE
	int ret = 0;

	/*
	 * Test idea: the bits a DRNG generated since it was last fully seeded
	 * saturate at INT_MAX, so a limit above it would never be reached.
	 * Such a limit must read back as INT_MAX, while UINT32_MAX - the limit
	 * disabled - and limits up to INT_MAX are kept as they are.
	 */
	ret |= esdm_config_max_wo_reseed_bits_check(1U << 17, 1U << 17);
	ret |= esdm_config_max_wo_reseed_bits_check(INT_MAX, INT_MAX);
	ret |= esdm_config_max_wo_reseed_bits_check((uint32_t)INT_MAX + 1,
						    INT_MAX);
	ret |= esdm_config_max_wo_reseed_bits_check(UINT32_MAX - 1, INT_MAX);
	ret |= esdm_config_max_wo_reseed_bits_check(UINT32_MAX, UINT32_MAX);

	return ret;
#else
	return 77;
#endif
}
