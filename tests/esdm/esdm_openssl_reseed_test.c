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
 * The OpenSSL DRNG backend has to mix the additional data into a reseed.
 *
 * The ESDM hands the output of the entropy sources it does not credit to the
 * DRNG as additional data. The backend once set it as the nonce of its TEST-RAND
 * seed source, which only an instantiation asks for, so every reseed dropped it
 * without a trace. Two DRNGs seeded alike and reseeded with the same entropy
 * must therefore differ as soon as their additional data does.
 *
 * The backend is compiled into the test, which reaches its callbacks without a
 * running ESDM.
 */

#include <stdint.h>
#include <string.h>

#include "common_test.h"
#include "esdm_crypto.h"
#include "esdm_openssl.h"

static const uint8_t seed[64] = { 0x01 };
static const uint8_t reseed[64] = { 0x02 };
/* Without it the first seed takes the clock as nonce */
static const uint8_t nonce[16] = { 0x03 };

static void drng_output(const uint8_t *addtl, size_t addtllen, uint8_t *out,
			size_t outlen)
{
	const struct esdm_drng_cb *cb = &esdm_openssl_drbg_cb;
	void *drng = NULL;

	CHECK_EQ(cb->drng_alloc(&drng, 256), 0);
	if (!drng)
		return;

	CHECK_EQ(cb->drng_seed(drng, seed, sizeof(seed), nonce, sizeof(nonce)), 0);
	CHECK_EQ(cb->drng_seed(drng, reseed, sizeof(reseed), addtl, addtllen),
		 0);
	CHECK_EQ(cb->drng_generate(drng, out, outlen), (ssize_t)outlen);

	cb->drng_dealloc(drng);
}

int main(void)
{
	static const uint8_t addtl_a[32] = { 0xaa };
	static const uint8_t addtl_b[32] = { 0xbb };
	uint8_t none[32], none2[32], a[32], b[32];

	drng_output(NULL, 0, none, sizeof(none));
	drng_output(NULL, 0, none2, sizeof(none2));
	drng_output(addtl_a, sizeof(addtl_a), a, sizeof(a));
	drng_output(addtl_b, sizeof(addtl_b), b, sizeof(b));

	/* Same input, same output - the comparison below means something */
	CHECK_MEM_EQ(none, none2, sizeof(none));

	CHECK(memcmp(none, a, sizeof(a)),
	      "additional data on reseed did not change the output");
	CHECK(memcmp(a, b, sizeof(a)),
	      "different additional data on reseed gave the same output");

	return common_test_result("openssl_reseed");
}
