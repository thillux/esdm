/*
 * Test that a failed extraction from the auxiliary pool keeps no credit
 *
 * When the hash chain of an extraction fails, the pool drops its hash states
 * and starts over with the next insert - and with them everything it absorbed.
 * The entropy it was credited with is gone along with that data, so it must not
 * be handed back to the counter: the next extraction would be credited with
 * entropy it never sees, and the pool would report it as available meanwhile.
 *
 * Driven through the entropy source callbacks without the rest of the ESDM, so
 * that no reseed running in the background takes the pool's entropy away
 * between the steps.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "esdm.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

static struct esdm_hash_cb esdm_ahf_hash_cb;
static int (*esdm_ahf_hash_final_real)(void *hash, uint8_t *digest);
static bool esdm_ahf_fail;

/* The default hash, except that its final operation fails on demand */
static int esdm_ahf_hash_final(void *hash, uint8_t *digest)
{
	if (esdm_ahf_fail)
		return -EFAULT;
	return esdm_ahf_hash_final_real(hash, digest);
}

static int esdm_ahf_insert(void)
{
	uint8_t data[ESDM_DRNG_INIT_SEED_SIZE_BYTES];

	memset(data, 0x5a, sizeof(data));
	return esdm_pool_insert_aux(data, sizeof(data),
				    ESDM_DRNG_INIT_SEED_SIZE_BITS);
}

int main(int argc, char *argv[])
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	struct esdm_es_cb *aux = esdm_es[esdm_ext_es_aux];
	struct entropy_es eb_es;
	uint32_t avail;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	esdm_ahf_hash_cb = *hash_cb;
	esdm_ahf_hash_final_real = hash_cb->hash_final;
	esdm_ahf_hash_cb.hash_final = esdm_ahf_hash_final;
	drng->hash_cb = &esdm_ahf_hash_cb;

	ret = aux->init();
	if (ret) {
		printf("Auxiliary pool initialization failed: %d\n", ret);
		goto out;
	}

	ret = esdm_ahf_insert();
	if (ret) {
		printf("Insert into the auxiliary pool failed: %d\n", ret);
		goto fini;
	}

	if (!aux->curr_entropy(0)) {
		printf("Auxiliary pool credited no entropy for the insert\n");
		ret = 1;
		goto fini;
	}

	/* An extraction whose hash chain fails */
	esdm_ahf_fail = true;
	memset(&eb_es, 0, sizeof(eb_es));
	aux->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	esdm_ahf_fail = false;

	if (eb_es.e_bits) {
		printf("Failed extraction credited with %u bits\n",
		       eb_es.e_bits);
		ret = 1;
	}

	avail = aux->curr_entropy(0);
	if (avail) {
		printf("Auxiliary pool still reports %u bits after its data was discarded\n",
		       avail);
		ret = 1;
	}

	/* The next insert starts the pool over, credited from then on */
	if (esdm_ahf_insert()) {
		printf("Insert after the failed extraction failed\n");
		ret = 1;
		goto fini;
	}

	memset(&eb_es, 0, sizeof(eb_es));
	aux->get_ent(&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, true);
	if (!eb_es.e_bits) {
		printf("Auxiliary pool delivered no entropy after its recovery\n");
		ret = 1;
	}

	if (!ret)
		printf("Auxiliary pool keeps no credit for discarded data\n");

fini:
	aux->fini();
out:
	drng->hash_cb = hash_cb;
	return ret;
}
