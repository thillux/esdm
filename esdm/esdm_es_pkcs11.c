/*
 * ESDM Fast Entropy Source: Linux PKCS11-based entropy source
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

#include <libp11.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_crypto.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_pkcs11.h"
#include "esdm_node.h"
#include "helper.h"
#include "mutex.h"

struct Pkcs11Context {
  PKCS11_CTX *ctx;
  PKCS11_SLOT *slots;
  unsigned int nslots;
  PKCS11_SLOT *slot;
};

static struct Pkcs11Context* pkcs11ctx = NULL;

static void esdm_pkcs11_finalize(void)
{
    if(pkcs11ctx == NULL)
        return;

    PKCS11_release_all_slots(pkcs11ctx->ctx, pkcs11ctx->slots, pkcs11ctx->nslots);
    PKCS11_CTX_unload(pkcs11ctx->ctx);
    PKCS11_CTX_free(pkcs11ctx->ctx);

    memset(pkcs11ctx, 0, sizeof(struct Pkcs11Context));
    free(pkcs11ctx);

	pkcs11ctx = NULL;
}

static int esdm_pkcs11_initialize(void)
{
	/* Allow the init function to be called multiple times */
	esdm_pkcs11_finalize();

    pkcs11ctx = malloc(sizeof(struct Pkcs11Context));
    assert(pkcs11ctx != NULL);
    
    pkcs11ctx->ctx = PKCS11_CTX_new();
    assert(pkcs11ctx->ctx != NULL);

    const char* pkcs11_engine_path = "/nix/store/720xwfzk4yq4hh65lnh5p94cj3ghj29v-system-path/lib/pkcs11/opensc-pkcs11.so";

    int ret = PKCS11_CTX_load(pkcs11ctx->ctx, pkcs11_engine_path);
    assert(ret == 0);

    ret = PKCS11_enumerate_slots(pkcs11ctx->ctx, &pkcs11ctx->slots, &pkcs11ctx->nslots);
    assert(ret == 0);
    pkcs11ctx->slot = PKCS11_find_token(pkcs11ctx->ctx, pkcs11ctx->slots, pkcs11ctx->nslots);
    if(pkcs11ctx->slot == NULL) {
        logger(LOGGER_WARN, LOGGER_C_ES, "Disabling PKCS11-based entropy source as device not present\n");
        esdm_pkcs11_finalize();
        return 0;
    }

    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot manufacturer......: %s\n",pkcs11ctx->slot->manufacturer);
    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot description.......: %s\n",pkcs11ctx->slot->description);
    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot token label.......: %s\n",pkcs11ctx->slot->token->label);
    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot token manufacturer: %s\n",pkcs11ctx->slot->token->manufacturer);
    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot token model.......: %s\n",pkcs11ctx->slot->token->model);
    logger(LOGGER_DEBUG2, LOGGER_C_ES, "Slot token serial......: %s\n",pkcs11ctx->slot->token->serialnr);

	return 0;
}

static uint32_t esdm_pkcs11_entropylevel(uint32_t requested_bits)
{
	if (pkcs11ctx == NULL)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_pkcs11_entropy_rate(), requested_bits);
}

static uint32_t esdm_pkcs11_poolsize(void)
{
	if (pkcs11ctx == NULL)
		return 0;

	return esdm_pkcs11_entropylevel(esdm_security_strength());
}

static void esdm_pkcs11_es_state(char *buf, size_t buflen)
{
	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n",
		 esdm_pkcs11_poolsize(),
		 esdm_pkcs11_entropylevel(256));
}

static bool esdm_pkcs11_active(void)
{
	return (pkcs11ctx != NULL);
}

static void esdm_pkcs11_get(struct entropy_es *eb_es, uint32_t requested_bits,
			    bool __unused unsused)
{
	if (pkcs11ctx == NULL)
		goto err;

    if(PKCS11_generate_random(pkcs11ctx->slot, eb_es->e, requested_bits >> 3) != 0)
        goto err;

	eb_es->e_bits = esdm_pkcs11_entropylevel(requested_bits);
	logger(LOGGER_DEBUG, LOGGER_C_ES,
	       "obtained %u bits of entropy from PKCS11 RNG entropy source\n",
	       eb_es->e_bits);

	return;

err:
	eb_es->e_bits = 0;
}

struct esdm_es_cb esdm_es_pkcs11 = {
	.name			= "PKCS11RNG",
	.init			= esdm_pkcs11_initialize,
	.fini			= esdm_pkcs11_finalize,
	.monitor_es		= NULL, //esdm_pkcs11_seed_monitor,
	.get_ent		= esdm_pkcs11_get,
	.curr_entropy		= esdm_pkcs11_entropylevel,
	.max_entropy		= esdm_pkcs11_poolsize,
	.state			= esdm_pkcs11_es_state,
	.reset			= NULL, //esdm_pkcs11_reset,
	.active			= esdm_pkcs11_active,
	.switch_hash		= NULL,
};