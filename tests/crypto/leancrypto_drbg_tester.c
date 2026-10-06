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
 * The DRNG manager seeds the DRNG with a struct entropy_buf as additional
 * input - far more than the 84 bytes the XDRBG takes. Newer leancrypto
 * versions refuse such a seed, older ones use only its first 84 bytes. The
 * leancrypto backend has to accept it and mix in all of it.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_crypto.h"
#include "esdm_leancrypto.h"

#define ADDTL_LEN 300

static int seed_and_generate(const uint8_t *seed, size_t seedlen,
			     const uint8_t *addtl, size_t addtllen,
			     uint8_t *out, size_t outlen)
{
	const struct esdm_drng_cb *cb = &esdm_leancrypto_drbg_cb;
	void *drng = NULL;
	int ret;

	ret = cb->drng_alloc(&drng, 256);
	if (ret) {
		printf("FAIL: cannot allocate the DRNG: %d\n", ret);
		return 1;
	}

	ret = cb->drng_seed(drng, seed, seedlen, addtl, addtllen);
	if (ret) {
		printf("FAIL: seeding with %zu bytes of additional input: %d\n",
		       addtllen, ret);
		cb->drng_dealloc(drng);
		return 1;
	}

	if (cb->drng_generate(drng, out, outlen) != (ssize_t)outlen) {
		printf("FAIL: generating after seeding\n");
		cb->drng_dealloc(drng);
		return 1;
	}

	cb->drng_dealloc(drng);
	return 0;
}

int main(int argc, char *argv[])
{
	uint8_t seed[48], addtl[ADDTL_LEN], out1[32], out2[32];
	unsigned int i;
	int ret = 0;

	(void)argc;
	(void)argv;

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	for (i = 0; i < sizeof(addtl); i++)
		addtl[i] = (uint8_t)(i * 7);

	/* Short additional input goes to the XDRBG unchanged */
	ret |= seed_and_generate(seed, sizeof(seed), addtl, 32, out1,
				 sizeof(out1));

	/* Long additional input is accepted ... */
	ret |= seed_and_generate(seed, sizeof(seed), addtl, sizeof(addtl), out1,
				 sizeof(out1));

	/* ... and all of it counts, not only the first 84 bytes */
	addtl[ADDTL_LEN - 1] ^= 1;
	ret |= seed_and_generate(seed, sizeof(seed), addtl, sizeof(addtl), out2,
				 sizeof(out2));
	if (!ret && !memcmp(out1, out2, sizeof(out1))) {
		printf("FAIL: the tail of the additional input was ignored\n");
		ret = 1;
	}

	if (!ret)
		printf("leancrypto DRBG: all checks passed\n");

	return ret;
}
