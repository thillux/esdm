/*
 * Known-answer tests of the built-in ChaCha20 (crypto/chacha20.c) and of the
 * ChaCha20 DRNG built on it (crypto/chacha20_drng.c)
 *
 * RFC 7539 defines the key, the nonce and the keystream of ChaCha20 as byte
 * strings that are read and written as little-endian 32-bit words. The cipher
 * is checked against the test vectors of RFC 7539 sections 2.3.2 (the block
 * function) and 2.4.2 (the encryption), both set up through setkey() and
 * setiv(): a key or nonce loaded in host byte order gives a different
 * keystream on big-endian machines.
 *
 * The DRNG is checked against the known answers of its self test in
 * esdm/crypto/esdm_builtin_chacha20.c, seeded with the seed bytes as they
 * are. Seed data injected into the key byte by byte rather than as
 * little-endian words gives a different output on big-endian machines - which
 * the self test used to hide by byte-swapping its seed on them, while the seed
 * of every real seeding went in unswapped.
 *
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm_chacha20.h"
#include "esdm_chacha20_drng.h"
#include "esdm_chacha20_private.h"
#include "esdm_sym.h"
#include "selftest_kat.h"

/* Key of both RFC 7539 test vectors: the bytes 0x00 to 0x1f */
static const uint8_t rfc_key[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* RFC 7539 section 2.3.2: nonce and the serialized block, counter 1 */
static const uint8_t rfc_block_nonce[12] = {
	0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t rfc_block[64] = {
	0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd,
	0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0,
	0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2,
	0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05,
	0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e,
	0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
};

/* RFC 7539 section 2.4.2: nonce, plaintext and ciphertext, counter 1 */
static const uint8_t rfc_enc_nonce[12] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
};

static const char rfc_enc_pt[] =
	"Ladies and Gentlemen of the class of '99: If I could offer you only "
	"one tip for the future, sunscreen would be it.";

static const uint8_t rfc_enc_ct[114] = {
	0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07,
	0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43,
	0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9,
	0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab,
	0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52,
	0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca,
	0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a,
	0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
	0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b,
	0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
	0x5e, 0x42, 0x87, 0x4d,
};

/*
 * The known answers of the DRNG self test, see
 * esdm/crypto/esdm_builtin_chacha20.c
 */
static const uint8_t drng_seed[64] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
	0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};

/* Zero state, one block pulled */
static const uint8_t drng_exp_block[32] = {
	0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a,
	0xe5, 0x53, 0x86, 0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d,
	0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
};

/* Zero state seeded with all 64 bytes of the seed, two blocks pulled */
static const uint8_t drng_exp_twoblocks[64] = {
	0xe3, 0xb0, 0x8a, 0xcc, 0x34, 0xc3, 0x17, 0x0e, 0xc3, 0xd8, 0xc3,
	0x40, 0xe7, 0x73, 0xe9, 0x0d, 0xd1, 0x62, 0xa3, 0x5d, 0x7d, 0xf2,
	0xf1, 0x4a, 0x24, 0x42, 0xb7, 0x1e, 0xb0, 0x05, 0x17, 0x07, 0xb9,
	0x35, 0x10, 0x69, 0x8b, 0x46, 0xfb, 0x51, 0xe9, 0x91, 0x3f, 0x46,
	0xf2, 0x4d, 0xea, 0xd0, 0x81, 0xc1, 0x1b, 0xa9, 0x5d, 0x52, 0x91,
	0x5f, 0xcd, 0xdc, 0xc6, 0xd6, 0xc3, 0x7c, 0x50, 0x23,
};

/*
 * Zero state seeded with the first 36 bytes of the seed - one key's worth and
 * a word more - one block and four bytes pulled
 */
static const uint8_t drng_exp_nonaligned[36] = {
	0x9c, 0xfc, 0x5e, 0x31, 0x21, 0x62, 0x11, 0x85, 0xd3, 0x77, 0xd3, 0x69,
	0x0f, 0xa8, 0x16, 0x55, 0xb4, 0x4c, 0xf6, 0x52, 0xf3, 0xa8, 0x37, 0x99,
	0x38, 0x76, 0xa0, 0x66, 0xec, 0xbb, 0xce, 0xa9, 0x9c, 0x95, 0xa1, 0xfd,
};

/*
 * Zero state seeded with the first 35 bytes of the seed - one key's worth and
 * three bytes, which fill the first key word in part only - one block and four
 * bytes pulled. Not part of the self test: the answer is what the
 * implementation gave on a little-endian machine, where the key bytes are the
 * little-endian words without any conversion.
 */
static const uint8_t drng_exp_partial_word[36] = {
	0x73, 0x5b, 0xb7, 0x8f, 0x51, 0x8e, 0x7a, 0x68, 0x21, 0x70, 0x0e, 0x4c,
	0x62, 0x38, 0xa5, 0x7e, 0x0e, 0x4b, 0xbe, 0x1d, 0xd3, 0xb8, 0xcb, 0x8e,
	0x69, 0x78, 0x40, 0x10, 0xe1, 0xb0, 0x0f, 0x72, 0xcb, 0x59, 0xa8, 0x01,
};

static int cc20_crypt_check(const char *name, const uint8_t *nonce,
			    const uint8_t *in, const uint8_t *exp, size_t len)
{
	ESDM_SYM_CTX_ON_STACK(cc20, esdm_chacha20);
	uint8_t key[sizeof(rfc_key)], iv[12], buf[128], act[128];
	int ret = 0;

	if (len > sizeof(buf))
		return 1;

	memcpy(key, rfc_key, sizeof(key));
	memcpy(iv, nonce, sizeof(iv));
	memcpy(buf, in, len);

	/* The block counter starts at 1, as in both test vectors */
	esdm_sym_init(cc20);
	if (esdm_sym_setkey(cc20, key, sizeof(key)) ||
	    esdm_sym_setiv(cc20, iv, sizeof(iv))) {
		printf("%s: cannot set the key or the nonce\n", name);
		ret = 1;
		goto out;
	}
	esdm_sym_encrypt(cc20, buf, act, len);

	/* Checks the output and that an output off by a byte is rejected */
	if (esdm_kat_check(act, exp, len)) {
		printf("%s: wrong output\n", name);
		ret = 1;
		goto out;
	}

	/* The same keystream takes the output back to the input */
	esdm_sym_init(cc20);
	if (esdm_sym_setkey(cc20, key, sizeof(key)) ||
	    esdm_sym_setiv(cc20, iv, sizeof(iv))) {
		printf("%s: cannot set the key or the nonce\n", name);
		ret = 1;
		goto out;
	}
	esdm_sym_decrypt(cc20, act, act, len);
	if (memcmp(act, in, len)) {
		printf("%s: decryption does not give the input back\n", name);
		ret = 1;
	}

out:
	esdm_sym_zero(cc20);
	return ret;
}

/*
 * Seed the zero state with @seedlen bytes of the seed - none for 0 - and pull
 * @explen bytes, which must be @exp.
 */
static int cc20_drng_check(const char *name, size_t seedlen,
			   const uint8_t *exp, size_t explen)
{
	ESDM_CC20_DRNG_CTX_ON_STACK(cc20_ctx);
	struct esdm_sym_state *state = cc20_ctx->cc20.sym_state;
	uint8_t act[64] __attribute__((aligned(sizeof(uint32_t))));
	int ret = 0;

	if (explen > sizeof(act))
		return 1;

	/* The self test starts at block counter 0 rather than at 1 */
	state->counter = 0;

	if (seedlen) {
		if (esdm_cc20_drng_seed(cc20_ctx, drng_seed, seedlen)) {
			printf("%s: seeding failed\n", name);
			return 1;
		}
	} else {
		/* The zero key is the known input, as in the self test */
		cc20_ctx->seeded = 1;
	}
	if (esdm_cc20_drng_generate(cc20_ctx, act, explen)) {
		printf("%s: generating failed\n", name);
		return 1;
	}

	if (esdm_kat_check(act, exp, explen)) {
		printf("%s: wrong output\n", name);
		ret = 1;
	}

	esdm_cc20_drng_zero(cc20_ctx);
	return ret;
}

/*
 * An unseeded DRNG would generate from its all-zero key, predictable output.
 * It must refuse - fresh, after an empty seed and after zeroization - and
 * leave the output buffer alone.
 */
static int cc20_drng_unseeded_check(void)
{
	ESDM_CC20_DRNG_CTX_ON_STACK(cc20_ctx);
	static const uint8_t untouched[16] = { 0 };
	uint8_t act[sizeof(untouched)] = { 0 };
	int ret = 0;

	if (esdm_cc20_drng_generate(cc20_ctx, act, sizeof(act)) != -EINVAL) {
		printf("DRNG generates unseeded\n");
		ret = 1;
	}

	if (esdm_cc20_drng_seed(cc20_ctx, drng_seed, 0) != -EINVAL ||
	    esdm_cc20_drng_generate(cc20_ctx, act, sizeof(act)) != -EINVAL) {
		printf("DRNG takes an empty seed as a seeding\n");
		ret = 1;
	}

	if (memcmp(act, untouched, sizeof(act))) {
		printf("DRNG writes output while refusing to generate\n");
		ret = 1;
	}

	if (esdm_cc20_drng_seed(cc20_ctx, drng_seed, sizeof(drng_seed)) ||
	    esdm_cc20_drng_generate(cc20_ctx, act, sizeof(act))) {
		printf("DRNG does not generate once seeded\n");
		ret = 1;
	}

	esdm_cc20_drng_zero(cc20_ctx);
	if (esdm_cc20_drng_generate(cc20_ctx, act, sizeof(act)) != -EINVAL) {
		printf("DRNG generates after zeroization\n");
		ret = 1;
	}

	esdm_cc20_drng_zero(cc20_ctx);
	return ret;
}

int main(int argc, char *argv[])
{
	static const uint8_t zero[sizeof(rfc_block)] = { 0 };
	int ret = 0;

	(void)argc;
	(void)argv;

	ret += cc20_crypt_check("RFC 7539 2.3.2 block function",
				rfc_block_nonce, zero, rfc_block,
				sizeof(rfc_block));
	ret += cc20_crypt_check("RFC 7539 2.4.2 encryption", rfc_enc_nonce,
				(const uint8_t *)rfc_enc_pt, rfc_enc_ct,
				sizeof(rfc_enc_ct));

	ret += cc20_drng_check("DRNG from the zero state", 0, drng_exp_block,
			       sizeof(drng_exp_block));
	ret += cc20_drng_check("DRNG seeded with two key sizes",
			       sizeof(drng_seed), drng_exp_twoblocks,
			       sizeof(drng_exp_twoblocks));
	ret += cc20_drng_check("DRNG seeded with a key size and a word", 36,
			       drng_exp_nonaligned,
			       sizeof(drng_exp_nonaligned));
	ret += cc20_drng_check("DRNG seeded with a key size and three bytes",
			       35, drng_exp_partial_word,
			       sizeof(drng_exp_partial_word));
	ret += cc20_drng_unseeded_check();

	if (!ret)
		printf("ChaCha20: passed\n");

	return ret ? 1 : 0;
}
