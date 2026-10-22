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
 * DRNGs from them: a provider failing its self test at start up is credited
 * for none of the initial seeding.
 *
 * Every other source is credited with nothing, so that the provider is the
 * one source the initial seeding could be fully seeded from - which it is once
 * its self test passes, which tells that the check before is no idle one.
 *
 * The provider is the test plugin served by the provider server of
 * libesdm_es_ext in a thread of the test, on a socket the first provider
 * socket source of the ESDM reads.
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_ext.h"
#include "esdm_es_extsock.h"
#include "esdm_selftest.h"
#include "../esdm/es_rates.h"
#include "es_ext_test_plugin.h"

extern struct esdm_es_ext_plugin es_ext_test_plugin;
extern struct esdm_es_ext_test_control esdm_es_ext_test_control;

static void *test_server_run(void *arg)
{
	return (void *)(intptr_t)esdm_es_ext_server_run(arg);
}

int main(void)
{
	struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;
	char dir[] = "/tmp/esdm-es-ext-init-test-XXXXXX";
	char socket[sizeof(dir) + 32];
	struct esdm_es_ext_server *server = NULL;
	pthread_t thread;
	int ret;

	if (!mkdtemp(dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(socket, sizeof(socket), "%s/provider.socket", dir);

	/* The provider fails its self test from the start */
	ctl->selftest_ret = -ENODEV;
	ret = esdm_es_ext_server_alloc(&es_ext_test_plugin, socket, 0600,
				       &server);
	CHECK_EQ(ret, 0);
	if (ret)
		goto out;
	ret = pthread_create(&thread, NULL, test_server_run, server);
	CHECK_EQ(ret, 0);
	if (ret) {
		esdm_es_ext_server_free(server);
		goto out;
	}

	esdm_test_es_rates_zero();
	esdm_config_es_ext_entropy_rate_set(0, 256);
	CHECK_EQ(esdm_es_ext_set_path(0, socket), 0);
	/* The provider runs as the user of the test */
	CHECK_EQ(esdm_es_ext_set_peer_uid(0, getuid()), 0);

	ret = esdm_init();
	CHECK_EQ(ret, 0);
	if (ret)
		goto stop;

	/* Under the NTG.1 seeding strategy no single source seeds the ESDM */
	if (esdm_ntg1_2024_compliant()) {
		printf("one source does not seed the ESDM in this build - skipping\n");
		esdm_fini();
		esdm_es_ext_server_stop(server);
		pthread_join(thread, NULL);
		esdm_es_ext_server_free(server);
		rmdir(dir);
		return 77;
	}

	CHECK(ctl->selftest_calls > 0,
	      "the self test of the provider did not run");
	CHECK(!esdm_state_fully_seeded(),
	      "the provider failing its self test seeded the ESDM");

	/* Its self test passing, the provider seeds the ESDM on its own */
	ctl->selftest_ret = 0;
	esdm_selftest_run();
	esdm_force_fully_seeded_all_drbgs();
	CHECK(esdm_state_fully_seeded(),
	      "the provider passing its self test does not seed the ESDM");

	esdm_fini();

stop:
	esdm_es_ext_server_stop(server);
	pthread_join(thread, NULL);
	esdm_es_ext_server_free(server);

out:
	unlink(socket);
	rmdir(dir);
	return common_test_result("es_ext_init");
}
