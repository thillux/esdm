/*
 * Test that the auxiliary pool is the XDRBG-256 as specified
 *
 * Instantiated from the bytes 0x00 ... 0x3f, the pool has to deliver the
 * output of XDRBG-256 (SHAKE256) with its alpha, and reseeded from 0x40 ...
 * 0x7f the output after the reseed - the known answers are computed
 * independently of the ESDM. Its state is 64 bytes, which is the entropy it
 * can hold at most.
 *
 * Driven through the entropy source callbacks without the rest of the ESDM, so
 * that nothing else is inserted into the pool between the steps.
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
#include <string.h>

#include "esdm.h"
#include "esdm_definitions.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

#define ESDM_AXT_OUTLEN 32

static int esdm_axt_extract(struct esdm_es_cb *aux, const uint8_t *seed,
			    const uint8_t *exp, const char *what)
{
	struct entropy_es eb_es;
	int ret;

	/* With entropy, so that the data goes into the first pool only */
	ret = esdm_pool_insert_aux(seed, 64, ESDM_AXT_OUTLEN << 3);
	if (ret) {
		printf("Insert into the auxiliary pool failed: %d\n", ret);
		return 1;
	}

	memset(&eb_es, 0, sizeof(eb_es));
	aux->get_ent(&eb_es, ESDM_AXT_OUTLEN << 3, true);
	if (!eb_es.e_bits) {
		printf("%s: no entropy credited\n", what);
		return 1;
	}
	if (memcmp(eb_es.e, exp, ESDM_AXT_OUTLEN)) {
		printf("%s: the output is not that of XDRBG-256\n", what);
		return 1;
	}

	printf("%s: XDRBG-256 output\n", what);
	return 0;
}

int main(int argc, char *argv[])
{
	static const uint8_t exp_instantiate[] = {
		0xa6, 0x72, 0xf6, 0xb2, 0x42, 0x5b, 0x61, 0xb0, 0xa3, 0xfe,
		0xad, 0x10, 0x1c, 0x71, 0xbc, 0x1e, 0x2b, 0xef, 0x4c, 0xf6,
		0x43, 0xf0, 0xa8, 0xf5, 0x27, 0x5e, 0x64, 0xaa, 0x66, 0xf1,
		0x95, 0x71,
	};
	static const uint8_t exp_reseed[] = {
		0x28, 0x38, 0x6c, 0x23, 0x92, 0xb8, 0xd1, 0x1f, 0x17, 0xa3,
		0x19, 0x95, 0x5c, 0x7b, 0x72, 0x2d, 0x9f, 0x82, 0xf6, 0x92,
		0xc7, 0xe3, 0x1b, 0x78, 0xae, 0x36, 0xab, 0x87, 0xd2, 0xc6,
		0xe7, 0x57,
	};
	struct esdm_es_cb *aux = esdm_es[esdm_ext_es_aux];
	uint8_t seed[128];
	unsigned int i;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (esdm_get_digestsize() != 512) {
		printf("Auxiliary pool reports a state of %u bits instead of 512\n",
		       esdm_get_digestsize());
		return 1;
	}

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	ret = aux->init();
	if (ret) {
		printf("Auxiliary pool initialization failed: %d\n", ret);
		return 1;
	}

	ret = esdm_axt_extract(aux, seed, exp_instantiate, "Instantiate");
	ret += esdm_axt_extract(aux, seed + 64, exp_reseed, "Reseed");

	aux->fini();
	return ret;
}
