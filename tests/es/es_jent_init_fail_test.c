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
 * A failing Jitter RNG startup self test must take out the Jitter RNG, and only
 * that.
 *
 * jent_entropy_init_ex() reports a failed health test with a positive error
 * code. The ESDM once let that through as success, so the Jitter RNG ran fully
 * credited after failing its startup test - and when the collector could not be
 * allocated either, the error aborted the initialization of the whole ESDM.
 *
 * The test defines jent_entropy_init_ex() itself, which takes precedence over
 * the library's, and lets it fail the way the health tests do.
 */

#include <stdio.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_mgr.h"

int jent_entropy_init_ex(unsigned int osr, unsigned int flags);

/* JENT_EHEALTH: a health test failed */
int jent_entropy_init_ex(unsigned int osr, unsigned int flags)
{
	(void)osr;
	(void)flags;

	return 9;
}

int main(void)
{
	int ret;

	esdm_config_es_jent_entropy_rate_set(256);

	ret = esdm_init();
	if (ret) {
		printf("ES Jitter RNG - fail: a failed Jitter RNG aborted the ESDM initialization: %d\n",
		       ret);
		return 1;
	}

	/*
	 * The configured rate stays, for a later reinitialization that
	 * succeeds; an uninitialized Jitter RNG is what is credited with
	 * nothing.
	 */
	if (esdm_es[esdm_ext_es_jitter]->curr_entropy(
		    ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES Jitter RNG - fail: still credited with %u bits after its self test failed\n",
		       esdm_es[esdm_ext_es_jitter]->curr_entropy(
			       ESDM_DRNG_INIT_SEED_SIZE_BITS));
		ret = 1;
	} else {
		printf("ES Jitter RNG - pass: disabled after its self test failed\n");
	}

	esdm_fini();

	return ret;
}
