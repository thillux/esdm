/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <leancrypto.h>
#include <stdlib.h>
#include <string.h>

#include "build_bug_on.h"
#include "config.h"
#include "esdm_crypto.h"
#include "esdm_leancrypto.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "selftest_kat.h"

#define ESDM_LEANCRYPTO_HASH lc_sha3_512

/*
 * Since leancrypto 1.6.0, lc_hash_init() fails when the self test of the hash
 * failed - before, it could not fail.
 */
static int esdm_lc_hash_init(struct lc_hash_ctx *hash_ctx)
{
#ifdef ESDM_LEANCRYPTO_HASH_INIT_RET
	return lc_hash_init(hash_ctx);
#else
	lc_hash_init(hash_ctx);
	return 0;
#endif
}

static uint32_t esdm_leancrypto_hash_digestsize(void *hash)
{
	struct lc_hash_ctx *hash_ctx = hash;

	return (uint32_t)lc_hash_digestsize(hash_ctx);
}

static int esdm_leancrypto_hash_init(void *hash)
{
	struct lc_hash_ctx *hash_ctx = hash;

	return esdm_lc_hash_init(hash_ctx);
}

static int esdm_leancrypto_hash_update(void *hash, const uint8_t *inbuf,
				       size_t inbuflen)
{
	struct lc_hash_ctx *hash_ctx = hash;

	lc_hash_update(hash_ctx, inbuf, inbuflen);
	return 0;
}

static int esdm_leancrypto_hash_final(void *hash, uint8_t *digest)
{
	struct lc_hash_ctx *hash_ctx = hash;

	lc_hash_final(hash_ctx, digest);
	return 0;
}

static int esdm_leancrypto_hash_alloc(void **ctx)
{
	struct lc_hash_ctx **hash_ctx = (struct lc_hash_ctx **)ctx;

	return lc_hash_alloc(ESDM_LEANCRYPTO_HASH, hash_ctx);
}

static void esdm_leancrypto_hash_dealloc(void *ctx)
{
	struct lc_hash_ctx *hash_ctx = ctx;

	lc_hash_zero_free(hash_ctx);
}

static const char *esdm_leancrypto_hash_name(void)
{
	return "Leancrypto SHA3-512";
}

static void esdm_leancrypto_hash_desc_zero(void *hash)
{
	(void)hash;
}

/* Hash @msg through the backend's own calls, as the entropy pools do */
static int esdm_leancrypto_hash_kat(const uint8_t *msg, size_t msglen,
				    uint8_t *digest)
{
	void *hash = NULL;
	int ret = esdm_leancrypto_hash_alloc(&hash);

	if (ret)
		return ret;

	ret = esdm_leancrypto_hash_init(hash);
	if (!ret)
		ret = esdm_leancrypto_hash_update(hash, msg, msglen);
	if (!ret)
		ret = esdm_leancrypto_hash_final(hash, digest);
	esdm_leancrypto_hash_dealloc(hash);

	return ret;
}

static int esdm_leancrypto_hash_selftest(void)
{
	/*
	 * leancrypto tests an algorithm once, before its first use. Its
	 * lc_rerun_selftests() only re-arms that lazy test and is not allowed
	 * in FIPS mode, while the periodic self tests are to catch a failure
	 * later on - hence a known answer test of our own.
	 */
	static const uint8_t msg[] = { 'a', 'b', 'c' };
	/* SHA3-512("abc"), FIPS 202 example */
	static const uint8_t exp[] = {
		0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a, 0x56, 0x93,
		0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e, 0x08, 0xf6, 0x21, 0x82,
		0x74, 0x44, 0xf7, 0x0d, 0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2,
		0x71, 0x2e, 0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
		0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40, 0x57, 0x34,
		0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5, 0x65, 0x92, 0xf8, 0x27,
		0x4e, 0xec, 0x53, 0xf0,
	};
	uint8_t act[sizeof(exp)];
	uint8_t mod[sizeof(msg)];
	int ret;

	ret = esdm_leancrypto_hash_kat(msg, sizeof(msg), act);
	if (ret)
		return ret;
	ret = esdm_kat_check(act, exp, sizeof(exp));
	if (ret)
		return ret;

	/* A message off by its first byte must not produce that digest */
	ret = esdm_kat_modify(mod, msg, sizeof(mod));
	if (ret)
		return ret;
	ret = esdm_leancrypto_hash_kat(mod, sizeof(mod), act);
	if (ret)
		return ret;

	return esdm_kat_check_differs(act, exp, sizeof(exp));
}

const struct esdm_hash_cb esdm_leancrypto_hash_cb = {
	.hash_name = esdm_leancrypto_hash_name,
	.hash_selftest = esdm_leancrypto_hash_selftest,
	.hash_digestsize = esdm_leancrypto_hash_digestsize,
	.hash_init = esdm_leancrypto_hash_init,
	.hash_update = esdm_leancrypto_hash_update,
	.hash_final = esdm_leancrypto_hash_final,
	.hash_desc_zero = esdm_leancrypto_hash_desc_zero,
	.hash_alloc = esdm_leancrypto_hash_alloc,
	.hash_dealloc = esdm_leancrypto_hash_dealloc,
};

/*
 * The XDRBG encodes the length of its additional input in a single byte, which
 * limits it to 84 bytes (XDRBG specification, appendix B.2). Older leancrypto
 * versions silently use only the first 84 bytes, newer ones refuse longer
 * input - while the DRNG manager hands over a struct entropy_buf, far longer
 * than that.
 */
#define ESDM_LEANCRYPTO_XDRBG_MAX_ADDTL 84

static int esdm_leancrypto_drbg_seed(void *drng, const uint8_t *inbuf,
				     size_t inbuflen, const uint8_t *addtl,
				     size_t addtllen)
{
	struct lc_rng_ctx *ctx = drng;
	uint8_t digest[LC_SHA3_512_SIZE_DIGEST];
	int ret;

	if (!addtl || addtllen <= ESDM_LEANCRYPTO_XDRBG_MAX_ADDTL)
		return lc_rng_seed(ctx, inbuf, inbuflen, addtl, addtllen);

	/*
	 * Condense longer additional input with SHA3-512 so all of it is
	 * mixed into the state, and pass on the digest instead.
	 */
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_512);

	ret = esdm_lc_hash_init(hash_ctx);
	if (!ret) {
		lc_hash_update(hash_ctx, addtl, addtllen);
		lc_hash_final(hash_ctx, digest);
		ret = lc_rng_seed(ctx, inbuf, inbuflen, digest, sizeof(digest));
	}

	lc_hash_zero(hash_ctx);
	memset_secure(digest, 0, sizeof(digest));

	return ret;
}

static ssize_t esdm_leancrypto_drbg_generate(void *drng, uint8_t *outbuf,
					     size_t outbuflen)
{
	struct lc_rng_ctx *ctx = drng;
	int ret;

	ret = lc_rng_generate(ctx, NULL, 0, outbuf, outbuflen);

	return ret ? ret : (ssize_t)outbuflen;
}

static int esdm_leancrypto_drbg_alloc(void **drng, uint32_t sec_strength)
{
	struct lc_rng_ctx **ctx = (struct lc_rng_ctx **)drng;
	int ret = lc_xdrbg256_drng_alloc(ctx);

	(void)sec_strength;

	if (ret)
		return ret;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "XDRBG allocated\n");

	return 0;
}

static void esdm_leancrypto_drbg_dealloc(void *drng)
{
	struct lc_rng_ctx *ctx = drng;

	lc_rng_zero_free(ctx);
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY, "XDRBG zeroized and freed\n");
}

static const char *esdm_leancrypto_drbg_name(void)
{
	return "Leancrypto XDRBG with SHAKE256 core";
}

/* Instantiate a fresh XDRBG from @seed and generate @outlen bytes */
static int esdm_leancrypto_drbg_kat(const uint8_t *seed, size_t seedlen,
				    uint8_t *out, size_t outlen)
{
	void *drng = NULL;
	int ret = esdm_leancrypto_drbg_alloc(&drng, 256);

	if (ret)
		return ret;

	ret = esdm_leancrypto_drbg_seed(drng, seed, seedlen, NULL, 0);
	if (!ret && esdm_leancrypto_drbg_generate(drng, out, outlen) !=
			    (ssize_t)outlen)
		ret = -EFAULT;
	esdm_leancrypto_drbg_dealloc(drng);

	return ret;
}

#define ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN 32
#define ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN 96
#define ESDM_LEANCRYPTO_DRBG_KAT_INLEN                                         \
	(2 * (ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN +                               \
	      ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN))

/*
 * Instantiate a fresh XDRBG from @in[0, 32) with the additional input
 * @in[32, 128), reseed it from @in[128, 160) with the additional input
 * @in[160, 256), generate twice and return the second output in @out.
 */
static int esdm_leancrypto_drbg_kat_addtl(const uint8_t *in, uint8_t *out,
					  size_t outlen)
{
	const uint8_t *reseed = in + ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN +
				ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN;
	void *drng = NULL;
	int ret = esdm_leancrypto_drbg_alloc(&drng, 256);

	if (ret)
		return ret;

	ret = esdm_leancrypto_drbg_seed(drng, in,
					ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN,
					in + ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN,
					ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN);
	if (!ret)
		ret = esdm_leancrypto_drbg_seed(
			drng, reseed, ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN,
			reseed + ESDM_LEANCRYPTO_DRBG_KAT_SEEDLEN,
			ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN);
	if (!ret && (esdm_leancrypto_drbg_generate(drng, out, outlen) !=
			     (ssize_t)outlen ||
		     esdm_leancrypto_drbg_generate(drng, out, outlen) !=
			     (ssize_t)outlen))
		ret = -EFAULT;
	esdm_leancrypto_drbg_dealloc(drng);

	return ret;
}

static int esdm_leancrypto_drbg_selftest(void)
{
	/*
	 * The known answer of leancrypto's own XDRBG-256 self test, cut to its
	 * first 64 bytes: the output beyond differs between leancrypto
	 * versions, which split the request differently. Run through the
	 * backend's calls for the same reason as the hash test above.
	 */
	static const uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp[] = {
		0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0, 0x79, 0x2c,
		0xc0, 0x69, 0x7d, 0x56, 0x6a, 0x65, 0xb8, 0x36, 0xbe, 0x7d,
		0x09, 0x12, 0x7c, 0x65, 0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24,
		0x39, 0x52, 0x29, 0xea, 0xce, 0x43, 0xdf, 0x16, 0x2c, 0x4f,
		0x1a, 0xed, 0xbd, 0x3f, 0xf5, 0x8e, 0xe6, 0x4d, 0x93, 0x07,
		0x3d, 0x7f, 0x3d, 0xd2, 0x50, 0x3c, 0xae, 0x04, 0x4a, 0x87,
		0x2c, 0x90, 0x30, 0xd4,
	};
	/*
	 * The test above seeds without additional input, while the DRNG manager
	 * always hands over a struct entropy_buf as additional input, which is
	 * longer than the XDRBG takes and thus goes through the SHA3-512
	 * condensation of esdm_leancrypto_drbg_seed(). This test covers that
	 * path: instantiate and reseed, each with 96 bytes of additional input,
	 * then generate twice and compare the second output - the sequence
	 * FIPS 140-3 IG 10.3.A accepts as test of instantiate, reseed and
	 * generate.
	 *
	 * The input is the byte sequence 0x00 ... 0xff, cut into
	 *	entropy input 0x00 ... 0x1f, additional input 0x20 ... 0x7f,
	 *	reseed entropy 0x80 ... 0x9f, additional input 0xa0 ... 0xff.
	 * The known answer is XDRBG-256 as specified (SHAKE256, |V| = 64,
	 * appendix B.2 encoding) over the SHA3-512 digests of the additional
	 * inputs, computed independently of leancrypto.
	 */
	static const uint8_t exp_addtl[] = {
		0x38, 0x34, 0x60, 0xb8, 0x96, 0xc6, 0x51, 0x5a, 0xb8, 0x9e,
		0x8a, 0x84, 0xbb, 0xe0, 0x84, 0x6d, 0x7e, 0x56, 0x68, 0xa8,
		0x61, 0xa0, 0xcc, 0x08, 0x47, 0xef, 0xd7, 0x70, 0xea, 0x6e,
		0xb1, 0xc8, 0x30, 0x62, 0x6e, 0x6b, 0x84, 0xa9, 0x19, 0x99,
		0x6a, 0x3b, 0xcd, 0x86, 0x25, 0x49, 0x86, 0x85, 0x5d, 0xe0,
		0xea, 0x9c, 0xd7, 0xf0, 0xe3, 0xb5, 0x3a, 0x88, 0xca, 0x26,
		0x26, 0x08, 0xcd, 0x36,
	};
	uint8_t act[sizeof(exp)];
	uint8_t mod[sizeof(seed)];
	uint8_t in[ESDM_LEANCRYPTO_DRBG_KAT_INLEN];
	size_t i;
	int ret;

	BUILD_BUG_ON(sizeof(exp_addtl) != sizeof(act));
	BUILD_BUG_ON(ESDM_LEANCRYPTO_DRBG_KAT_ADDTLLEN <=
		     ESDM_LEANCRYPTO_XDRBG_MAX_ADDTL);

	ret = esdm_leancrypto_drbg_kat(seed, sizeof(seed), act, sizeof(act));
	if (ret)
		goto out;
	ret = esdm_kat_check(act, exp, sizeof(exp));
	if (ret)
		goto out;

	/* Seed material off by its first byte must not produce that output */
	ret = esdm_kat_modify(mod, seed, sizeof(mod));
	if (ret)
		goto out;
	ret = esdm_leancrypto_drbg_kat(mod, sizeof(mod), act, sizeof(act));
	if (ret)
		goto out;
	ret = esdm_kat_check_differs(act, exp, sizeof(exp));
	if (ret)
		goto out;

	for (i = 0; i < sizeof(in); i++)
		in[i] = (uint8_t)i;
	ret = esdm_leancrypto_drbg_kat_addtl(in, act, sizeof(act));
	if (ret)
		goto out;
	ret = esdm_kat_check(act, exp_addtl, sizeof(exp_addtl));
	if (ret)
		goto out;

	/*
	 * Additional input off by its last byte must not produce that output:
	 * the XDRBG encoding itself only takes 84 bytes, so this is what shows
	 * that all of it reaches the state.
	 */
	in[sizeof(in) - 1] ^= 0xff;
	ret = esdm_leancrypto_drbg_kat_addtl(in, act, sizeof(act));
	if (ret)
		goto out;
	ret = esdm_kat_check_differs(act, exp_addtl, sizeof(exp_addtl));

out:
	memset_secure(act, 0, sizeof(act));
	return ret;
}

const struct esdm_drng_cb esdm_leancrypto_drbg_cb = {
	.drng_name = esdm_leancrypto_drbg_name,
	.drng_selftest = esdm_leancrypto_drbg_selftest,
	.drng_alloc = esdm_leancrypto_drbg_alloc,
	.drng_dealloc = esdm_leancrypto_drbg_dealloc,
	.drng_seed = esdm_leancrypto_drbg_seed,
	.drng_generate = esdm_leancrypto_drbg_generate,
};
