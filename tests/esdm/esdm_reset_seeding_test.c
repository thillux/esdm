/*
 * Test that esdm_reset() is not undone by a seeding in progress
 *
 * A seeding looks at the DRNGs and, if it finds them all seeded, declares so -
 * under the pool lock. A reset that slips in between clears that state,
 * only for the seeding to set it again on the strength of what it saw before:
 * the ESDM then believes all DRNGs seeded while none is, and the next initial
 * seeding takes the reseed rules instead of the initial seeding policy.
 *
 * The seeding is played by this test: it holds the pool lock while the reset is
 * started and declares the DRNGs all seeded before letting go of it, which is
 * what __esdm_drng_seed_work() does. The reset has to wait for it and be the
 * last word.
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

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"

static void *esdm_rs_reset(void *arg)
{
	(void)arg;

	esdm_reset();
	return NULL;
}

int main(int argc, char *argv[])
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	uint8_t buf[32];
	pthread_t thread;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ret = esdm_init();
	if (ret)
		return ret;

	esdm_force_fully_seeded_all_drbgs();
	if (!esdm_pool_all_nodes_seeded_get() || !esdm_state_operational()) {
		printf("DRNGs cannot be seeded fully\n");
		ret = 77;
		goto out;
	}

	/* A seeding is under way, and it found every DRNG seeded */
	esdm_pool_lock();

	if (pthread_create(&thread, NULL, esdm_rs_reset, NULL)) {
		esdm_pool_unlock();
		ret = 1;
		goto out;
	}

	/* Time for the reset to run, if it does not wait */
	nanosleep(&ts, NULL);

	/* The seeding concludes */
	esdm_pool_all_nodes_seeded(true);
	esdm_pool_unlock();

	pthread_join(thread, NULL);

	if (esdm_pool_all_nodes_seeded_get() || esdm_state_operational()) {
		printf("the reset was undone by the seeding in progress: all DRNGs seeded %d, operational %d\n",
		       esdm_pool_all_nodes_seeded_get(),
		       esdm_state_operational());
		ret = 1;
		goto out;
	}

	printf("the reset waited for the seeding in progress and had the last word\n");

	/* And the ESDM comes back from it */
	esdm_force_fully_seeded_all_drbgs();
	if (!esdm_state_operational()) {
		printf("DRNGs cannot be seeded again after the reset\n");
		ret = 77;
		goto out;
	}

	if (esdm_get_random_bytes_full(buf, sizeof(buf)) != sizeof(buf)) {
		printf("no random bytes after the reset\n");
		ret = 1;
		goto out;
	}

	ret = 0;

out:
	esdm_fini();
	return ret;
}
