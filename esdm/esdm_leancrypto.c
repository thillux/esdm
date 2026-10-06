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

#include "config.h"
#include "esdm_crypto.h"
#include "esdm_leancrypto.h"
#include "esdm_logger.h"
#include "memset_secure.h"

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

static int esdm_leancrypto_hash_selftest(void)
{
	/* leancrypto automatically self-tests the implementation */
	return 0;
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

static int esdm_leancrypto_drbg_selftest(void)
{
	/* leancrypto automatically self-tests the implementation */
	return 0;
}

const struct esdm_drng_cb esdm_leancrypto_drbg_cb = {
	.drng_name = esdm_leancrypto_drbg_name,
	.drng_selftest = esdm_leancrypto_drbg_selftest,
	.drng_alloc = esdm_leancrypto_drbg_alloc,
	.drng_dealloc = esdm_leancrypto_drbg_dealloc,
	.drng_seed = esdm_leancrypto_drbg_seed,
	.drng_generate = esdm_leancrypto_drbg_generate,
};
