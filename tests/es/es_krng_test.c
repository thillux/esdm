/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * The kernel RNG entropy source: what it delivers, and what it is credited
 * with at every rate from 1 to 256 - which is what the ES derives from its
 * rate and the other sources, see esdm_krng_properties_entropylevel(): nothing
 * under the oversampling of SP800-90C - the FIPS mode - nor while a scheduler
 * source is credited, at most ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY while an
 * interrupt source takes the interrupts from the kernel, and what the rate
 * gives otherwise.
 *
 * Both modes are run, whatever mode the machine is in: with the FIPS mode
 * forced off, and forced on - which a build without the FIPS 140 or the
 * SP800-90C option ignores.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"

#include "../es_state_check.h"
#include "esdm_es_irq.h"
#include "esdm_es_irq_ebpf.h"
#include "esdm_es_sched.h"
#include "esdm_es_sched_ebpf.h"
#include "math_helper.h"

/* Is the kernel RNG credited with nothing, whatever its rate? */
static bool es_krng_uncredited(void)
{
	return esdm_es_oversampling() || esdm_sched_enabled() ||
	       esdm_sched_ebpf_enabled();
}

/* The entropy the ES credits a request of @bits with at the rate configured */
static uint32_t es_krng_expected(uint32_t bits)
{
	uint32_t rate = esdm_config_es_krng_entropy_rate();

	if (es_krng_uncredited())
		return 0;
	if (esdm_irq_present() || esdm_irq_ebpf_enabled())
		rate = min_uint32(rate, ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY);

	return esdm_fast_noise_entropylevel(rate, bits);
}

static int es_krng_getstate(void)
{
	struct json_object *obj = es_state_get(esdm_es[esdm_ext_es_krng]);
	int ret = 0;

	if (!obj) {
		printf("ES Kernel RNG - fail: state callback missing\n");
		return 1;
	}

	if (!es_state_has(obj, "entropy_rate_per_256_data_bits",
			  json_type_int) ||
	    !es_state_has(obj, "available_entropy", json_type_int)) {
		printf("ES Kernel RNG - fail: state information contains unexpected content: %s\n",
		       es_state_print(obj));
		ret = 1;
	} else {
		printf("ES KRNG - pass: get state test passed:\n%s\n",
		       es_state_print(obj));
	}

	json_object_put(obj);
	return ret;
}

static int es_krng_getdata(uint32_t expected_ent_level)
{
	struct entropy_es eb_es;
	uint8_t zero[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	if (!esdm_es[esdm_ext_es_krng]->get_ent) {
		printf("ES Kernel RNG - fail: get_ent callback missing\n");
		return 1;
	}

	esdm_config_es_krng_entropy_rate_set(expected_ent_level);

	memset(&eb_es, 0, sizeof(eb_es));
	memset(&zero, 0, sizeof(zero));

	esdm_es[esdm_ext_es_krng]->get_ent(&eb_es,
					   ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (eb_es.e_bits != es_krng_expected(ESDM_DRNG_INIT_SEED_SIZE_BITS)) {
		printf("ES Kernel RNG - fail: get_ent failed to deliver requested data (expected %u, received %u bits)\n",
		       es_krng_expected(ESDM_DRNG_INIT_SEED_SIZE_BITS),
		       eb_es.e_bits);
		return 1;
	}

	if (!memcmp(eb_es.e, zero, ESDM_DRNG_INIT_SEED_SIZE_BYTES)) {
		printf("ES Kernel RNG - fail: get_ent failed to deliver data\n");
		return 1;
	}

	printf("ES KRNG - pass: get data test for entropy level %u passed\n",
	       expected_ent_level);

	return 0;
}

static int es_krng_poolsize(uint32_t expected_ent_level)
{
	uint32_t ret, ret2;

	if (!esdm_es[esdm_ext_es_krng]->max_entropy) {
		printf("ES Kernel RNG - fail: max_entropy callback missing\n");
		return 1;
	}

	if (!esdm_es[esdm_ext_es_krng]->curr_entropy) {
		printf("ES Kernel RNG - fail: curr_entropy callback missing\n");
		return 1;
	}

	esdm_config_es_krng_entropy_rate_set(expected_ent_level);

	ret = esdm_es[esdm_ext_es_krng]->max_entropy();
	if (ret != es_krng_expected(esdm_security_strength())) {
		printf("ES Kernel RNG - fail: max_entropy failed: %d, expected %u\n",
		       ret, es_krng_expected(esdm_security_strength()));
		return 1;
	}

	/*
	 * In FIPS mode, or with a scheduler source credited, the rate is kept
	 * as configured, and the source credited with nothing at any of them
	 */
	if (es_krng_uncredited()) {
		if (ret) {
			printf("ES Kernel RNG - fail: credited with %u bits at the rate %u, which the mode does not allow\n",
			       ret, esdm_config_es_krng_entropy_rate());
			return 1;
		}
	} else if (esdm_config_es_krng_entropy_rate() !=
		   esdm_fast_noise_entropylevel(
			   esdm_config_es_krng_entropy_rate(),
			   esdm_security_strength())) {
		printf("ES Kernel RNG - fail: esdm_fast_noise_entropylevel returned unexpected value: %u\n",
		       esdm_fast_noise_entropylevel(
			       esdm_config_es_krng_entropy_rate(),
			       esdm_security_strength()));
		return 1;
	}

	ret2 = esdm_es[esdm_ext_es_krng]->curr_entropy(
		esdm_security_strength());
	if (ret != ret2) {
		printf("ES Kernel RNG - fail: max_entropy inconsisten with curr_entropy: max_entropy %u, curr_entropy %u\n",
		       ret, ret2);
		return 1;
	}

	printf("ES KRNG - pass: poolsize test for entropy level %u passed\n",
	       expected_ent_level);

	return 0;
}

static int es_krng_name(void)
{
	const char *name = esdm_es[esdm_ext_es_krng]->name;

	if (!name) {
		printf("ES Kernel RNG - fail: name not set!");
		return 1;
	}

	printf("ES KRNG - pass: name test passed: %s\n", name);

	return 0;
}

static int es_krng_init(void)
{
	int ret;

	if (!esdm_es[esdm_ext_es_krng]->init) {
		printf("ES Kernel RNG - fail: init callback missing\n");
		return 1;
	}

	ret = esdm_es[esdm_ext_es_krng]->init();
	if (ret) {
		printf("ES Kernel RNG - fail: init failed: %d\n", ret);
		return 1;
	}

	printf("ES KRNG - pass: init test passed\n");

	return 0;
}

static int es_krng_fini(void)
{
	if (!esdm_es[esdm_ext_es_krng]->fini) {
		printf("ES Kernel RNG - fail: fini callback missing\n");
		return 1;
	}
	esdm_es[esdm_ext_es_krng]->fini();

	printf("ES KRNG - pass: fini test passed\n");

	return 0;
}

int main(int argc, char *argv[])
{
	unsigned int i, fips;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = es_krng_init();
	if (ret)
		return ret;

	ret += es_krng_name();

	/* With the FIPS mode forced off, and forced on */
	for (fips = 0; fips < 2; fips++) {
		esdm_config_force_fips_set(
			fips ? esdm_config_force_fips_enabled :
			       esdm_config_force_fips_disabled);
		printf("ES KRNG - FIPS mode %s, oversampling %s\n",
		       esdm_config_fips_enabled() ? "on" : "off",
		       esdm_es_oversampling() ? "on" : "off");

		for (i = 1; i <= ESDM_DRNG_SECURITY_STRENGTH_BITS; i++) {
			ret += es_krng_poolsize(i);
			ret += es_krng_getdata(i);
		}
	}
	esdm_config_force_fips_set(esdm_config_force_fips_unset);

	ret += es_krng_getstate();
	ret += es_krng_fini();

	/* A count of failures, which the exit status would take modulo 256 */
	return ret ? 1 : 0;
}
