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
 * A failing periodic Jitter RNG health test must take the credit away from the
 * Jitter RNG until a later run passes - the way a failing startup test does.
 *
 * The periodic self test re-runs jent_entropy_init_ex(). Its failure was only
 * reported, while the Jitter RNG stayed initialized and went on being credited
 * with its configured rate on every reseed.
 *
 * The test defines jent_entropy_init_ex() itself, which takes precedence over
 * the library's. It hands the call on to the library until told to fail the
 * way the health tests do.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_mgr.h"

int jent_entropy_init_ex(unsigned int osr, unsigned int flags);

static bool jent_fail = false;

int jent_entropy_init_ex(unsigned int osr, unsigned int flags)
{
	int (*real)(unsigned int, unsigned int);

	/* JENT_EHEALTH: a health test failed */
	if (jent_fail)
		return 9;

	*(void **)(&real) = dlsym(RTLD_NEXT, "jent_entropy_init_ex");
	if (!real)
		return 9;

	return real(osr, flags);
}

static uint32_t jent_credit(void)
{
	return esdm_es[esdm_ext_es_jitter]->curr_entropy(
		ESDM_DRNG_INIT_SEED_SIZE_BITS);
}

static uint32_t jent_read(void)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[esdm_ext_es_jitter]->get_ent(
		&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);

	return eb_es.e_bits;
}

int main(void)
{
	uint32_t bits;
	int ret;

	if (!dlsym(RTLD_NEXT, "jent_entropy_init_ex")) {
		printf("ES Jitter RNG - skip: the library's jent_entropy_init_ex() is out of reach\n");
		return 77;
	}

	esdm_config_es_jent_entropy_rate_set(256);

	ret = esdm_init();
	if (ret) {
		printf("ES Jitter RNG - fail: ESDM initialization failed: %d\n",
		       ret);
		return 1;
	}

	if (!jent_credit()) {
		printf("ES Jitter RNG - skip: not usable on this system\n");
		ret = 77;
		goto out;
	}

	/* A failing periodic health test */
	jent_fail = true;
	if (!esdm_es[esdm_ext_es_jitter]->selftest()) {
		printf("ES Jitter RNG - fail: the failing health test was reported as passed\n");
		ret = 1;
	}

	bits = jent_credit();
	if (bits) {
		printf("ES Jitter RNG - fail: still credited with %u bits after a failed health test\n",
		       bits);
		ret = 1;
	}

	bits = jent_read();
	if (bits) {
		printf("ES Jitter RNG - fail: delivered %u bits after a failed health test\n",
		       bits);
		ret = 1;
	}

	/* A later run that passes gives the credit back */
	jent_fail = false;
	if (esdm_es[esdm_ext_es_jitter]->selftest()) {
		printf("ES Jitter RNG - fail: the passing health test was reported as failed\n");
		ret = 1;
	}

	if (!jent_credit()) {
		printf("ES Jitter RNG - fail: not credited again after a passing health test\n");
		ret = 1;
	}

	bits = jent_read();
	if (!bits) {
		printf("ES Jitter RNG - fail: delivered no entropy after a passing health test\n");
		ret = 1;
	}

	if (!ret)
		printf("ES Jitter RNG - pass: uncredited from a failed health test until one passes\n");

out:
	esdm_fini();

	return ret;
}
