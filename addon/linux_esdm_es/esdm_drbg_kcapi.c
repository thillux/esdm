// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Backend for the ESDM providing the cryptographic primitives using the
 * kernel crypto API and its DRBG.
 *
 * Taken and adapted from LRNG.
 *
 * Copyright (C) 2022-2026, Stephan Mueller <smueller@chronox.de>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "esdm_definitions.h"

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/version.h>

#include "esdm_drbg_kcapi.h"
#include "esdm_drbg_string.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0)

/*
 * Define a DRBG used to build cryptographic post-processing
 * with memory (DRG.3) for the entropy sources
 *
 * The security strengths of the DRBGs are all 256 bits according to
 * SP800-57 section 5.6.1.
 *
 * This definition is allowed to be changed.
 */
#ifdef CONFIG_CRYPTO_DRBG_HMAC
static unsigned int esdm_drbg_type = 0;
#elif defined CONFIG_CRYPTO_DRBG_HASH
static unsigned int esdm_drbg_type = 1;
#elif defined CONFIG_CRYPTO_DRBG_CTR
static unsigned int esdm_drbg_type = 2;
#else
#error "Unknown DRBG in use"
#endif

/* The parameter must be r/o in sysfs as otherwise races appear. */
module_param(esdm_drbg_type, uint, 0444);
MODULE_PARM_DESC(
	esdm_drbg_type,
	"DRBG type used for ESDM (0->HMAC_DRBG, 1->Hash_DRBG, 2->CTR_DRBG)");

struct esdm_drbg {
	const char *hash_name;
	const char *drbg_core;
};

static const struct esdm_drbg esdm_drbg_types[] = {
	{
		/* HMAC_DRBG with SHA-512 */
		.drbg_core = "drbg_nopr_hmac_sha512",
	},
	{
		/* Hash_DRBG with SHA-512 using derivation function */
		.drbg_core = "drbg_nopr_sha512"
	},
	{
		/* CTR_DRBG with AES-256 using derivation function */
		.drbg_core = "drbg_nopr_ctr_aes256",
	}
};

static int esdm_drbg_seed_helper(void *drbg, struct list_head *seedlist)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;
	int ret;

	ret = drbg_s->d_ops->update(drbg_s, seedlist,
				    drbg_s->seeded != DRBG_SEED_STATE_UNSEEDED);

	if (ret == 0)
		drbg_s->seeded = DRBG_SEED_STATE_FULL;

	return ret;
}

static int esdm_drbg_generate_helper(void *drbg, u8 *outbuf, u32 outbuflen,
				     u8 *additional_data,
				     u32 additional_data_len)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;
	struct drbg_string addtl;
	LIST_HEAD(addtllist);

	if (additional_data != NULL && additional_data_len > 0) {
		drbg_string_fill(&addtl, additional_data, additional_data_len);
		list_add_tail(&addtl.list, &addtllist);
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen,
					       &addtllist);
	} else {
		return drbg_s->d_ops->generate(drbg, outbuf, outbuflen, NULL);
	}
}

static void *esdm_drbg_alloc(u8 *personalization, u32 perslen)
{
	const u32 sec_strength = 32;
	struct drbg_state *drbg_s;
	struct drbg_string data;
	LIST_HEAD(seedlist);
	int coreref = -1;
	bool pr = false;
	int ret;

	drbg_convert_tfm_core(esdm_drbg_types[esdm_drbg_type].drbg_core,
			      &coreref, &pr);
	if (coreref < 0)
		return ERR_PTR(-EFAULT);

	drbg_s = kvzalloc(sizeof(struct drbg_state), GFP_KERNEL);
	if (!drbg_s)
		return ERR_PTR(-ENOMEM);

	drbg_s->core = &drbg_cores[coreref];
	drbg_s->seeded = DRBG_SEED_STATE_UNSEEDED;
	ret = drbg_alloc_state(drbg_s);
	if (ret)
		goto err;

	if (sec_strength > drbg_sec_strength(drbg_s->core->flags)) {
		pr_err("Security strength of DRBG (%u bits) lower "
		       "than requested by ESDM (%u bits)\n",
		       drbg_sec_strength(drbg_s->core->flags) * 8,
		       sec_strength * 8);
		goto dealloc;
	}

	if (sec_strength < drbg_sec_strength(drbg_s->core->flags))
		pr_warn("Security strength of DRBG (%u bits) higher "
			"than requested by ESDM (%u bits)\n",
			drbg_sec_strength(drbg_s->core->flags) * 8,
			sec_strength * 8);

	drbg_string_fill(&data, personalization, perslen);
	list_add_tail(&data.list, &seedlist);
	ret = drbg_s->d_ops->update(drbg_s, &seedlist, 0);
	if (ret) {
		pr_warn("unable to add personalization string to DRBG instance\n");
		goto dealloc;
	}

	pr_info("DRBG with %s core allocated\n",
		drbg_s->core->backend_cra_name);

	return drbg_s;

dealloc:
	if (drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg_s);
err:
	kvfree(drbg_s);
	return ERR_PTR(-EINVAL);
}

static void esdm_drbg_dealloc(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (drbg && drbg_s->d_ops)
		drbg_s->d_ops->crypto_fini(drbg_s);
	drbg_dealloc_state(drbg);
	kvfree_sensitive(drbg, sizeof(struct drbg_state));
	pr_info("DRBG deallocated\n");
}

static const char *esdm_drbg_name(void)
{
	return esdm_drbg_types[esdm_drbg_type].drbg_core;
}

static u32 esdm_drbg_sec_strength(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (!drbg_s)
		return 0;

	return drbg_sec_strength(drbg_s->core->flags) * 8;
}

static int esdm_drbg_is_initialized(void *drbg)
{
	struct drbg_state *drbg_s = (struct drbg_state *)drbg;

	if (!drbg_s)
		return 0;

	return drbg_s->seeded == DRBG_SEED_STATE_FULL;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_sec_strength = esdm_drbg_sec_strength,
	.drbg_is_initialized = esdm_drbg_is_initialized,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

int esdm_drbg_selftest(void)
{
	struct crypto_rng *drbg = NULL;
	struct drbg_state *drbg_s;
	int ret = 0;

	/* Allocate the DRBG once to trigger the kernel crypto API self test */
	drbg = crypto_alloc_rng(esdm_drbg_types[esdm_drbg_type].drbg_core, 0,
				0);
	if (IS_ERR(drbg)) {
		pr_err("could not allocate DRBG and trigger self-test: %ld\n",
		       PTR_ERR(drbg));
		ret = PTR_ERR(drbg);
		/*
		 * Clear the error pointer so the "if (drbg)" cleanup below does
		 * not pass an ERR_PTR to crypto_free_rng().
		 */
		drbg = NULL;
		goto out;
	}

	/* trigger initialization */
	if (crypto_rng_reset(drbg, (u8 *)"ABC", 3)) {
		ret = -EINVAL;
		pr_warn("DRBG reset failed\n");
		goto out;
	}

	/* convert to underlying drbg struct */
	drbg_s = crypto_rng_ctx(drbg);
	if (!drbg_s) {
		ret = -EINVAL;
		pr_warn("DRBG not accessible in self-test\n");
		goto out;
	}

	/* check minimal security strength */
	if (esdm_drbg_cb->drbg_sec_strength(drbg_s) <
	    esdm_security_strength()) {
		ret = -EINVAL;
		pr_warn("DRBG sec. strength insufficient for post-processing\n");
		goto out;
	}

out:
	if (drbg) {
		crypto_free_rng(drbg);
		drbg = NULL;
	}

	return ret;
}

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0) */

/*
 * Linux 7.2 reduced the kernel DRBG to a single, private HMAC_DRBG with
 * SHA-512 (crypto/drbg.c no longer has drbg_cores, d_ops or a public
 * struct drbg_state, and <crypto/drbg.h> is gone). Its internal state cannot
 * be driven with ESDM's seed lists any more, so the identical HMAC_DRBG
 * (SP800-90A section 10.1.2) is built here from the kernel's HMAC-SHA512
 * library. The update and generate functions are a one-to-one translation of
 * drbg_hmac_update() / drbg_hmac_generate() as they were used via d_ops
 * before, including reseed semantics, so the post-processing output is
 * unchanged for the same input. A known-answer test with the NIST ACVP vector
 * the kernel used for drbg_nopr_hmac_sha512 guards the implementation.
 */

#include <crypto/sha2.h>
#include <linux/string.h>

#define ESDM_HMAC_DRBG_STATELEN SHA512_DIGEST_SIZE
/* Security strength of HMAC_DRBG with SHA-512 in bytes (SP800-57 5.6.1) */
#define ESDM_HMAC_DRBG_SEC_STRENGTH (SHA512_DIGEST_SIZE / 2)

struct esdm_hmac_drbg {
	u8 V[ESDM_HMAC_DRBG_STATELEN];
	u8 C[ESDM_HMAC_DRBG_STATELEN];	/* raw key, 10.1.2.1 1b */
	struct hmac_sha512_key key;	/* key prepared from C */
	bool seeded;
};

/* update function of HMAC DRBG as defined in 10.1.2.2 */
static void esdm_hmac_drbg_update(struct esdm_hmac_drbg *drbg,
				  const struct list_head *seed, bool reseed)
{
	struct hmac_sha512_ctx ctx;
	const struct drbg_string *s;
	u8 prefix;

	if (!reseed) {
		/* 10.1.2.3 step 2 -- C is all zero after allocation */
		memset(drbg->V, 1, ESDM_HMAC_DRBG_STATELEN);
		hmac_sha512_preparekey(&drbg->key, drbg->C,
				       ESDM_HMAC_DRBG_STATELEN);
	}

	/* first round uses 0x00, second 0x01 */
	for (prefix = 0; prefix < 2; prefix++) {
		/* 10.1.2.2 step 1 and 4 -- concatenation and HMAC for key */
		hmac_sha512_init(&ctx, &drbg->key);
		hmac_sha512_update(&ctx, drbg->V, ESDM_HMAC_DRBG_STATELEN);
		hmac_sha512_update(&ctx, &prefix, 1);
		/* input data of seed is allowed to be NULL at this point */
		if (seed) {
			list_for_each_entry(s, seed, list)
				hmac_sha512_update(&ctx, s->buf, s->len);
		}
		hmac_sha512_final(&ctx, drbg->C);
		hmac_sha512_preparekey(&drbg->key, drbg->C,
				       ESDM_HMAC_DRBG_STATELEN);

		/* 10.1.2.2 step 2 and 5 -- HMAC for V */
		hmac_sha512(&drbg->key, drbg->V, ESDM_HMAC_DRBG_STATELEN,
			    drbg->V);

		/* 10.1.2.2 step 3 */
		if (!seed)
			break;
	}
}

/* generate function of HMAC DRBG as defined in 10.1.2.5 */
static int esdm_hmac_drbg_generate(struct esdm_hmac_drbg *drbg, u8 *buf,
				   u32 buflen, const struct list_head *addtl)
{
	u32 len = 0;

	if (addtl && list_empty(addtl))
		addtl = NULL;

	/* 10.1.2.5 step 2 */
	if (addtl)
		esdm_hmac_drbg_update(drbg, addtl, true);

	while (len < buflen) {
		u32 outlen = min_t(u32, ESDM_HMAC_DRBG_STATELEN, buflen - len);

		/* 10.1.2.5 step 4.1 */
		hmac_sha512(&drbg->key, drbg->V, ESDM_HMAC_DRBG_STATELEN,
			    drbg->V);
		/* 10.1.2.5 step 4.2 */
		memcpy(buf + len, drbg->V, outlen);
		len += outlen;
	}

	/* 10.1.2.5 step 6 */
	esdm_hmac_drbg_update(drbg, addtl, true);

	return len;
}

static int esdm_drbg_seed_helper(void *drbg, struct list_head *seedlist)
{
	struct esdm_hmac_drbg *drbg_s = drbg;

	esdm_hmac_drbg_update(drbg_s, seedlist, drbg_s->seeded);
	drbg_s->seeded = true;

	return 0;
}

static int esdm_drbg_generate_helper(void *drbg, u8 *outbuf, u32 outbuflen,
				     u8 *additional_data,
				     u32 additional_data_len)
{
	struct drbg_string addtl;
	LIST_HEAD(addtllist);

	if (additional_data != NULL && additional_data_len > 0) {
		drbg_string_fill(&addtl, additional_data, additional_data_len);
		list_add_tail(&addtl.list, &addtllist);
		return esdm_hmac_drbg_generate(drbg, outbuf, outbuflen,
					       &addtllist);
	}

	return esdm_hmac_drbg_generate(drbg, outbuf, outbuflen, NULL);
}

static void *esdm_drbg_alloc(u8 *personalization, u32 perslen)
{
	struct esdm_hmac_drbg *drbg_s;
	struct drbg_string data;
	LIST_HEAD(seedlist);

	drbg_s = kvzalloc(sizeof(*drbg_s), GFP_KERNEL);
	if (!drbg_s)
		return ERR_PTR(-ENOMEM);

	drbg_string_fill(&data, personalization, perslen);
	list_add_tail(&data.list, &seedlist);
	esdm_hmac_drbg_update(drbg_s, &seedlist, false);

	pr_info("DRBG with hmac(sha512) core allocated\n");

	return drbg_s;
}

static void esdm_drbg_dealloc(void *drbg)
{
	kvfree_sensitive(drbg, sizeof(struct esdm_hmac_drbg));
	pr_info("DRBG deallocated\n");
}

static const char *esdm_drbg_name(void)
{
	return "drbg_nopr_hmac_sha512";
}

static u32 esdm_drbg_sec_strength(void *drbg)
{
	if (!drbg)
		return 0;

	return ESDM_HMAC_DRBG_SEC_STRENGTH * 8;
}

static int esdm_drbg_is_initialized(void *drbg)
{
	struct esdm_hmac_drbg *drbg_s = drbg;

	if (!drbg_s)
		return 0;

	return drbg_s->seeded;
}

static const struct esdm_drbg_cb esdm_drbg_cb_int = {
	.drbg_name = esdm_drbg_name,
	.drbg_alloc = esdm_drbg_alloc,
	.drbg_dealloc = esdm_drbg_dealloc,
	.drbg_seed = esdm_drbg_seed_helper,
	.drbg_generate = esdm_drbg_generate_helper,
	.drbg_sec_strength = esdm_drbg_sec_strength,
	.drbg_is_initialized = esdm_drbg_is_initialized,
};
const struct esdm_drbg_cb *esdm_drbg_cb = &esdm_drbg_cb_int;

/*
 * Known-answer test: drbg_nopr_hmac_sha512 vector of crypto/testmgr.h up to
 * Linux 7.1 (obtained during NIST ACVP testing): instantiate with entropy and
 * no personalization string, generate twice with additional input and compare
 * the second output.
 */
static const u8 esdm_drbg_kat_entropy[] = {
	0xDF, 0xB0, 0xF2, 0x18, 0xF0, 0x78, 0x07, 0x01, 0x29, 0xA4, 0x29, 0x26,
	0x2F, 0x8A, 0x34, 0xCB, 0x37, 0xEF, 0xEE, 0x41, 0xE6, 0x96, 0xF7, 0xFF,
	0x61, 0x47, 0xD3, 0xED, 0x41, 0x97, 0xEF, 0x64, 0x0C, 0x48, 0x56, 0x5A,
	0xE6, 0x40, 0x6E, 0x4A, 0x3B, 0x9E, 0x7F, 0xAC, 0x08, 0xEC, 0x25, 0xAE,
	0x0B, 0x51, 0x0E, 0x2C, 0x44, 0x2E, 0xBD, 0xDB, 0x57, 0xD0, 0x4A, 0x6D,
	0x80, 0x3E, 0x37, 0x0F
};

static const u8 esdm_drbg_kat_addtla[] = {
	0x6B, 0x0F, 0x4A, 0x48, 0x0B, 0x12, 0x85, 0xE4, 0x72, 0x23, 0x7F, 0x7F,
	0x94, 0x7C, 0x24, 0x69, 0x14, 0x9F, 0xDC, 0x72, 0xA6, 0x33, 0xAD, 0x3C,
	0x8C, 0x72, 0xC1, 0x88, 0x49, 0x59, 0x82, 0xC5
};

static const u8 esdm_drbg_kat_addtlb[] = {
	0xC4, 0xAF, 0x36, 0x3D, 0xB8, 0x5D, 0x9D, 0xFA, 0x92, 0xF5, 0xC3, 0x3C,
	0x2D, 0x1E, 0x22, 0x2A, 0xBD, 0x8B, 0x05, 0x6F, 0xA3, 0xFC, 0xBF, 0x16,
	0xED, 0xAA, 0x75, 0x8D, 0x73, 0x9A, 0xF6, 0xEC
};

static const u8 esdm_drbg_kat_expected[] = {
	0x48, 0xc6, 0xa8, 0xdb, 0x09, 0xae, 0xde, 0x5d, 0x8c, 0x77, 0xf3, 0x52,
	0x92, 0x71, 0xa7, 0xb9, 0x6d, 0x53, 0x6d, 0xa3, 0x73, 0xe3, 0x55, 0xb8,
	0x39, 0xd6, 0x44, 0x2b, 0xee, 0xcb, 0xe1, 0x32, 0x15, 0x30, 0xbe, 0x4e,
	0x9b, 0x1e, 0x06, 0xd1, 0x6b, 0xbf, 0xd5, 0x3e, 0xea, 0x7c, 0xf5, 0xaa,
	0x4b, 0x05, 0xb5, 0xd3, 0xa7, 0xb2, 0xc4, 0xfe, 0xe7, 0x1b, 0xda, 0x11,
	0x43, 0x98, 0x03, 0x70, 0x90, 0xbf, 0x6e, 0x43, 0x9b, 0xe4, 0x14, 0xef,
	0x71, 0xa3, 0x2a, 0xef, 0x9f, 0x0d, 0xb9, 0xe3, 0x52, 0xf2, 0x89, 0xc9,
	0x66, 0x9a, 0x60, 0x60, 0x99, 0x60, 0x62, 0x4c, 0xd6, 0x45, 0x52, 0x54,
	0xe6, 0x32, 0xb2, 0x1b, 0xd4, 0x48, 0xb5, 0xa6, 0xf9, 0xba, 0xd3, 0xff,
	0x29, 0xc5, 0x21, 0xe0, 0x91, 0x31, 0xe0, 0x38, 0x8c, 0x93, 0x0f, 0x3c,
	0x30, 0x7b, 0x53, 0xa3, 0xc0, 0x7f, 0x2d, 0xc1, 0x39, 0xec, 0x69, 0x0e,
	0xf2, 0x4a, 0x3c, 0x65, 0xcc, 0xed, 0x07, 0x2a, 0xf2, 0x33, 0x83, 0xdb,
	0x10, 0x74, 0x96, 0x40, 0xa7, 0xc5, 0x1b, 0xde, 0x81, 0xca, 0x0b, 0x8f,
	0x1e, 0x0a, 0x1a, 0x7a, 0xbf, 0x3c, 0x4a, 0xb8, 0x8c, 0xaf, 0x7b, 0x80,
	0xb7, 0xdc, 0x5d, 0x0f, 0xef, 0x1b, 0x97, 0x6e, 0x3d, 0x17, 0x23, 0x5a,
	0x31, 0xb9, 0x19, 0xcf, 0x5a, 0xc5, 0x00, 0x2a, 0xb6, 0xf3, 0x99, 0x34,
	0x65, 0xee, 0xe9, 0x1c, 0x55, 0xa0, 0x3b, 0x07, 0x60, 0xc9, 0xc4, 0xe4,
	0xf7, 0x57, 0x5c, 0x34, 0x9f, 0xc6, 0x31, 0x30, 0x3f, 0x23, 0xb2, 0x89,
	0xc0, 0xe7, 0x50, 0xf3, 0xde, 0x59, 0xd1, 0x0e, 0xb3, 0x0f, 0x78, 0xcc,
	0x7e, 0x54, 0x5e, 0x61, 0xf6, 0x86, 0x3d, 0xb3, 0x11, 0x94, 0x36, 0x3e,
	0x61, 0x5c, 0x48, 0x99, 0xf6, 0x7b, 0x02, 0x9a, 0xdc, 0x6a, 0x28, 0xe6,
	0xd1, 0xa7, 0xd1, 0xa3
};

int esdm_drbg_selftest(void)
{
	struct esdm_hmac_drbg *drbg;
	struct drbg_string entropy;
	LIST_HEAD(seedlist);
	u8 *buf;
	int ret = 0;

	BUILD_BUG_ON(sizeof(esdm_drbg_kat_expected) != 256);

	/* check minimal security strength */
	if (ESDM_HMAC_DRBG_SEC_STRENGTH * 8 < esdm_security_strength()) {
		pr_warn("DRBG sec. strength insufficient for post-processing\n");
		return -EINVAL;
	}

	drbg = kvzalloc(sizeof(*drbg), GFP_KERNEL);
	buf = kzalloc(sizeof(esdm_drbg_kat_expected), GFP_KERNEL);
	if (!drbg || !buf) {
		ret = -ENOMEM;
		goto out;
	}

	drbg_string_fill(&entropy, esdm_drbg_kat_entropy,
			 sizeof(esdm_drbg_kat_entropy));
	list_add_tail(&entropy.list, &seedlist);
	esdm_drbg_seed_helper(drbg, &seedlist);

	esdm_drbg_generate_helper(drbg, buf, sizeof(esdm_drbg_kat_expected),
				  (u8 *)esdm_drbg_kat_addtla,
				  sizeof(esdm_drbg_kat_addtla));
	esdm_drbg_generate_helper(drbg, buf, sizeof(esdm_drbg_kat_expected),
				  (u8 *)esdm_drbg_kat_addtlb,
				  sizeof(esdm_drbg_kat_addtlb));

	if (memcmp(buf, esdm_drbg_kat_expected,
		   sizeof(esdm_drbg_kat_expected))) {
		pr_err("HMAC_DRBG known-answer test failed\n");
		ret = -EINVAL;
	}

out:
	kfree_sensitive(buf);
	if (drbg)
		kvfree_sensitive(drbg, sizeof(*drbg));
	return ret;
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(7, 2, 0) */
