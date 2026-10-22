/*
 * Test that the auxiliary pool reports the digest size of its hash
 *
 * The pool can hold no more entropy than the hash conditioning it produces,
 * and its self test refuses a hash shorter than the security strength. Both
 * go by esdm_get_digestsize(), so it has to report the hash actually used -
 * here one that claims a shorter digest than the largest one supported.
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

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"

/* Digest size in bytes the hash claims */
#define ESDM_ADS_DIGESTSIZE 32

static struct esdm_hash_cb esdm_ads_hash_cb;

static uint32_t esdm_ads_hash_digestsize(void *hash)
{
	(void)hash;
	return ESDM_ADS_DIGESTSIZE;
}

int main(int argc, char *argv[])
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	uint32_t digestsize;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	/* Without a shorter one than the largest there is nothing to tell */
	BUILD_BUG_ON(ESDM_ADS_DIGESTSIZE >= ESDM_MAX_DIGESTSIZE);

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The default hash, except for the size it claims */
	esdm_ads_hash_cb = *hash_cb;
	esdm_ads_hash_cb.hash_digestsize = esdm_ads_hash_digestsize;
	drng->hash_cb = &esdm_ads_hash_cb;

	ret = esdm_init();
	if (ret)
		goto out;

	digestsize = esdm_get_digestsize();
	if (digestsize != ESDM_ADS_DIGESTSIZE << 3) {
		printf("Auxiliary pool reports a digest of %u bits instead of %u\n",
		       digestsize, ESDM_ADS_DIGESTSIZE << 3);
		ret = 1;
	}

	esdm_fini();

out:
	drng->hash_cb = hash_cb;
	return ret;
}
