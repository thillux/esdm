/*
 * Copyright (C) 2016 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#ifndef _ESDM_CHACHA20_DRNG_H
#define _ESDM_CHACHA20_DRNG_H

#include <stdint.h>

#include "esdm_chacha20.h"

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_chacha20_drng_ctx {
	struct esdm_sym_ctx cc20;
	/*
	 * Generating from the zero key of a fresh or zeroized state would give
	 * predictable output - refused until the DRNG is seeded.
	 */
	unsigned int seeded : 1;
};

/*
 * The state follows the context rounded up to the alignment of the state:
 * with the seeded flag, the context is no multiple of it on 32-bit systems,
 * and the state would extend past the allocation.
 */
#define ESDM_CC20_DRNG_HDR_SIZE                                                \
	ESDM_ALIGN(sizeof(struct esdm_chacha20_drng_ctx),                      \
		   ESDM_SYM_ALIGNMASK(esdm_chacha20))
#define ESDM_CC20_DRNG_STATE_SIZE (ESDM_SYM_STATE_SIZE(esdm_chacha20))
#define ESDM_CC20_DRNG_CTX_SIZE                                                \
	(ESDM_CC20_DRNG_STATE_SIZE + ESDM_CC20_DRNG_HDR_SIZE)

#define _ESDM_CC20_DRNG_SET_CTX(name, ctx, offset)                             \
	_ESDM_SYM_SET_CTX((&name->cc20), esdm_chacha20, ctx, offset)

#define ESDM_CC20_DRNG_SET_CTX(name)                                           \
	_ESDM_CC20_DRNG_SET_CTX(name, name, ESDM_CC20_DRNG_HDR_SIZE)

/**
 * @brief Zeroize Hash context allocated with either ESDM_HASH_CTX_ON_STACK or
 *	  esdm_hmac_alloc
 *
 * @param [in] hash_state Hash context to be zeroized
 */
static inline void esdm_cc20_drng_zero(struct esdm_chacha20_drng_ctx *cc20_ctx)
{
	struct esdm_sym_ctx *sym_ctx = &cc20_ctx->cc20;

	memset_secure(sym_ctx->sym_state, 0, ESDM_CC20_DRNG_STATE_SIZE);
	esdm_sym_init(sym_ctx);
	cc20_ctx->seeded = 0;
}

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param [in] name Name of the stack variable
 */
#define ESDM_CC20_DRNG_CTX_ON_STACK(name)                                      \
	ESDM_ALIGNED_SYM_BUFFER(name##_ctx_buf, esdm_chacha20,                 \
				ESDM_CC20_DRNG_CTX_SIZE, uint64_t);            \
	struct esdm_chacha20_drng_ctx *name =                                  \
		(struct esdm_chacha20_drng_ctx *)name##_ctx_buf;               \
	ESDM_CC20_DRNG_SET_CTX(name);                                          \
	esdm_cc20_drng_zero(name)

/**
 * @brief Allocation of a ChaCha20 DRNG context
 *
 * @param [out] cc20_ctx ChaCha20 DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * You need to seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int esdm_cc20_drng_alloc(struct esdm_chacha20_drng_ctx **cc20_ctx);

/**
 * @brief Zeroize and ChaCha20 DRNG context
 *
 * @param [in] cc20_ctx ChaCha20 DRNG context to be zeroized and freed
 */
void esdm_cc20_drng_zero_free(struct esdm_chacha20_drng_ctx *cc20_ctx);

/**
 * @brief Obtain random numbers
 *
 * @param [in] cc20_ctx allocated ChaCha20 cipher handle
 * @param [out] outbuf allocated buffer that is to be filled with random numbers
 * @param [in] outbuflen length of outbuf indicating the size of the random
 *	number byte string to be generated
 *
 * Generate random numbers and fill the buffer provided by the caller.
 *
 * Before each request of random numbers, a high-resolution time stamp is
 * mixed into the random number generator state.
 *
 * If the last (re)seeding operation is longer than 600 seconds ago or
 * more than 1GB of random numbers were generated, an automated
 * reseed is performed.
 *
 * After the generation of random numbers, the internal state of the ChaCha20
 * DRNG is completely re-created using ChaCha20 to provide enhanced backtracking
 * resistance. I.e. if the state of the DRNG becomes known after generation
 * of random numbers, an attacker cannot deduce the already generated
 * random numbers.
 *
 * @return 0 upon success; -EINVAL if the DRNG was not seeded since its
 *	   allocation or last zeroization
 */
int esdm_cc20_drng_generate(struct esdm_chacha20_drng_ctx *cc20_ctx,
			    uint8_t *outbuf, size_t outbuflen);

/**
 * @brief Reseed the ChaCha20 DRNG
 *
 * @param [in] cc20_ctx allocated ChaCha20 cipher handle
 * @param [in] inbuf buffer with the seed data
 * @param [in] inbuflen length of inbuf
 *
 * When calling the function, the DRNG is first seeded from its internal
 * noise sources. This is followed by seeding the DRNG with the caller-provided
 * data.
 *
 * @return 0 upon succes; -EINVAL for an empty seed
 */
int esdm_cc20_drng_seed(struct esdm_chacha20_drng_ctx *cc20_ctx,
			const uint8_t *inbuf, size_t inbuflen);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_CHACHA20_DRNG_H */
