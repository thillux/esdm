/*
 * Test that the NTG.1 initial seeding gives up on a single source
 *
 * Under the NTG.1 seeding strategy a DRNG is instantiated from two entropy
 * sources of 240 bits each, or from a Jitter RNG in its own NTG.1 mode alone.
 * With the CPU entropy source as the only one credited, neither can ever be
 * met. The emergency reseeding, which holds the pool and DRNG locks, must then
 * stop after the pass that shows it, instead of adding up entropy from that
 * one source forever - esdm_init() does not return otherwise.
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

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_definitions.h"
#include "esdm_es_jent.h"
#include "esdm_es_mgr.h"
#include "esdm_es_mgr_cb.h"
#include "esdm_logger.h"
#include "es_rates.h"

#if defined(ESDM_AIS2031_NTG1_SEEDING_STRATEGY) && defined(ESDM_ES_CPU)

/* Well below the test timeout, so a hang is reported as one */
#define ESDM_TEST_HANG_SECONDS 60

static void esdm_test_hang(int sig)
{
	static const char msg[] =
		"ESDM did not return - emergency reseeding loops on one source\n";

	(void)sig;
	if (write(STDOUT_FILENO, msg, sizeof(msg) - 1) < 0) {
		/* Nothing left to report it with */
	}
	_exit(1);
}

int main(void)
{
	int ret;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	esdm_test_es_rates_zero();
	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	printf("Jitter RNG is NTG.1 conformant on its own: %s\n",
	       esdm_jent_ntg1() ? "true" : "false");
	/* A hang ends in _exit(), which drops what is still buffered */
	fflush(stdout);

	signal(SIGALRM, esdm_test_hang);
	alarm(ESDM_TEST_HANG_SECONDS);

	ret = esdm_init();
	if (ret) {
		printf("ESDM initialization failed: %d\n", ret);
		return 1;
	}

	if (!esdm_es[esdm_ext_es_cpu]->active()) {
		printf("CPU entropy source not available\n");
		ret = 77;
		goto out;
	}

	if (esdm_state_fully_seeded()) {
		printf("ESDM fully seeded from the CPU entropy source alone\n");
		ret = 1;
		goto out;
	}

	printf("ESDM initialization returned without being fully seeded\n");

out:
	esdm_fini();
	return ret;
}

#else

int main(void)
{
	printf("NTG.1 seeding strategy or CPU entropy source not compiled in\n");

	return 77;
}

#endif
