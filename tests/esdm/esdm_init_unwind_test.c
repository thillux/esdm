/*
 * Test that a failed esdm_init() tears down what it set up
 *
 * The auxiliary pool cannot allocate its hash states, so the entropy source
 * manager fails after the DRNG manager came up. esdm_init() reports the error
 * and must not leave the DRNG manager behind.
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

#include "esdm.h"
#include "esdm_crypto.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"

static struct esdm_hash_cb esdm_iu_hash_cb;

static int esdm_iu_hash_alloc(void **hash)
{
	(void)hash;
	return -ENOMEM;
}

int main(int argc, char *argv[])
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_hash_cb *hash_cb = drng->hash_cb;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The default hash, except that no state can be allocated for it */
	esdm_iu_hash_cb = *hash_cb;
	esdm_iu_hash_cb.hash_alloc = esdm_iu_hash_alloc;
	drng->hash_cb = &esdm_iu_hash_cb;

	ret = esdm_init();
	drng->hash_cb = hash_cb;

	if (!ret) {
		printf("esdm_init() succeeded without the aux pool\n");
		esdm_fini();
		return 1;
	}

	if (drng->drng) {
		printf("esdm_init() failed with %d and left the DRNG allocated\n",
		       ret);
		return 1;
	}

	printf("esdm_init() failed with %d and tore down the DRNG manager\n",
	       ret);
	return 0;
}
