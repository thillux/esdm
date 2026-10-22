/*
 * Test that a failed esdm_init() tears down what it set up
 *
 * The auxiliary pool cannot allocate the context of its XOF, so the entropy
 * source manager fails after the DRNG manager came up. esdm_init() reports the
 * error and must not leave the DRNG manager behind - nor report success when it
 * is called again on what it tore down.
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

static struct esdm_xof_cb esdm_iu_xof_cb;
static int (*esdm_iu_xof_alloc_real)(void **xof);
static unsigned int esdm_iu_xof_allocs;

/*
 * The first context is that of the self test of the DRNG manager, which
 * comes up before the entropy source manager: only the ones after it fail.
 */
static int esdm_iu_xof_alloc(void **xof)
{
	if (esdm_iu_xof_allocs++)
		return -ENOMEM;
	return esdm_iu_xof_alloc_real(xof);
}

int main(int argc, char *argv[])
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	const struct esdm_xof_cb *xof_cb = esdm_default_xof_cb;
	int ret;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/* The default XOF, except that no context of the pool can be allocated */
	esdm_iu_xof_cb = *xof_cb;
	esdm_iu_xof_alloc_real = xof_cb->xof_alloc;
	esdm_iu_xof_cb.xof_alloc = esdm_iu_xof_alloc;
	esdm_default_xof_cb = &esdm_iu_xof_cb;

	ret = esdm_init();
	esdm_default_xof_cb = xof_cb;

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

	/*
	 * Which is final: an ESDM torn down does not come back, and a second
	 * esdm_init() has to say so rather than report success for an ESDM
	 * without a DRNG to serve a request from.
	 */
	ret = esdm_init();
	if (!ret) {
		printf("esdm_init() after the torn down one succeeded, DRNG %sallocated\n",
		       drng->drng ? "" : "not ");
		esdm_fini();
		return 1;
	}

	printf("esdm_init() after the torn down one failed with %d\n", ret);

	/*
	 * Neither may esdm_reinit() set the entropy sources up again against
	 * the DRNGs that are gone.
	 */
	ret = esdm_reinit();
	if (ret != -ESHUTDOWN) {
		printf("esdm_reinit() after the torn down one returned %d\n",
		       ret);
		return 1;
	}

	printf("esdm_reinit() after the torn down one failed with %d\n", ret);
	return 0;
}
