/*
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

/*
 * The self tests of the entropy sources run before esdm_init() seeds the
 * DRNGs from them: a plugin failing its self test at start up is credited for
 * none of the initial seeding.
 *
 * Every other source is credited with nothing, so that the plugin is the one
 * source the initial seeding could be fully seeded from - which it is once its
 * self test passes, which tells that the check before is no idle one.
 *
 * Usage: es_ext_init_test <test plugin>
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>

#include "common_test.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_extlib.h"
#include "esdm_selftest.h"
#include "../esdm/es_rates.h"
#include "es_ext_test_plugin.h"

int main(int argc, char *argv[])
{
	struct esdm_es_ext_test_control *ctl = NULL;
	void *ref;
	int ret;

	if (argc < 2) {
		printf("usage: %s <test plugin>\n", argv[0]);
		return 1;
	}

	/*
	 * A reference of the test's own, so that the control of the plugin is
	 * the one of the plugin the ESDM loads.
	 */
	ref = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	CHECK(ref != NULL, "cannot load %s: %s", argv[1], dlerror());
	if (ref)
		ctl = dlsym(ref, ES_EXT_TEST_CONTROL_SYMBOL);
	CHECK(ctl != NULL, "the test plugin has no control");
	if (!ctl)
		return common_test_result("es_ext_init");

	esdm_test_es_rates_zero();
	esdm_config_es_ext_socket_entropy_rate_set(0);
	esdm_config_es_ext_lib_entropy_rate_set(256);
	CHECK_EQ(esdm_es_ext_lib_set_path(argv[1]), 0);

	ctl->selftest_ret = -ENODEV;
	ret = esdm_init();
	CHECK_EQ(ret, 0);
	if (ret)
		goto out;

	/* Under the NTG.1 seeding strategy no single source seeds the ESDM */
	if (esdm_ntg1_2024_compliant()) {
		printf("one source does not seed the ESDM in this build - skipping\n");
		esdm_fini();
		dlclose(ref);
		return 77;
	}

	CHECK(ctl->selftest_calls > 0,
	      "the self test of the plugin did not run");
	CHECK(!esdm_state_fully_seeded(),
	      "the plugin failing its self test seeded the ESDM");

	/* Its self test passing, the plugin seeds the ESDM on its own */
	ctl->selftest_ret = 0;
	esdm_selftest_run();
	esdm_force_fully_seeded_all_drbgs();
	CHECK(esdm_state_fully_seeded(),
	      "the plugin passing its self test does not seed the ESDM");

	esdm_fini();

out:
	dlclose(ref);
	return common_test_result("es_ext_init");
}
