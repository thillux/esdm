/*
 * Test of a blocking request in a process that uses libesdm without
 * esdm_init_monitor(), which therefore has neither reseed worker nor ES
 * monitor: a request that waits because its seeding collected too little
 * seeds again itself, and returns once the entropy sources deliver.
 *
 * The sources "recover" by their entropy rate being raised. The setters of the
 * rate trigger a seeding, which a source that starts to deliver does not: the
 * test holds the seed lock of the initial DRNG meanwhile, so that this
 * trigger finds the DRNG busy and seeds nothing.
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

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "es_rates.h"
#include "helper.h"

#ifdef ESDM_TESTMODE

/* How long the requests are left waiting before the sources recover */
#define TEST_WAIT_MS 1500

/* Seconds the requests are given to return after that */
#define TEST_RETURN_SECONDS 20

/* Seconds esdm_fini() is given to end a request that did not */
#define TEST_JOIN_SECONDS 20

/* Large enough for esdm_get_seed(), which answers -EMSGSIZE otherwise */
#define TEST_SEED_WORDS 1024

struct test_waiter {
	const char *name;
	bool seed;
	pthread_t thread;
	atomic_bool returned;
	ssize_t rc;
	ssize_t want;
};

static void test_sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static void *test_waiter_thread(void *arg)
{
	static _Thread_local uint64_t seed[TEST_SEED_WORDS];
	struct test_waiter *waiter = arg;
	uint8_t buf[32];

	if (waiter->seed) {
		waiter->rc = esdm_get_seed(seed, sizeof(seed), 0);
		/* The length of the seed buffer, which the build defines */
		waiter->want = (waiter->rc > 0) ? waiter->rc : 1;
	} else {
		waiter->rc = esdm_get_random_bytes_full(buf, sizeof(buf));
		waiter->want = sizeof(buf);
	}
	atomic_store(&waiter->returned, true);

	return NULL;
}

static int esdm_wait_retry_test(void)
{
	struct test_waiter waiters[] = {
		{ .name = "esdm_get_random_bytes_full" },
		{ .name = "esdm_get_seed", .seed = true },
	};
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct timespec deadline;
	unsigned int i, j;
	int ret;

	esdm_logger_set_verbosity(LOGGER_WARN);
	esdm_config_max_nodes_set(1);

	/* No source credits entropy: esdm_init() leaves the ESDM unseeded */
	esdm_test_es_rates_zero();

	ret = esdm_init();
	if (ret) {
		printf("esdm_init() failed: %d\n", ret);
		return 1;
	}
	if (esdm_state_operational()) {
		printf("the ESDM is operational without entropy, skipping\n");
		esdm_fini();
		return 77;
	}
	if (esdm_drng_mgr_reseed_worker_running()) {
		printf("a reseed worker runs without esdm_init_monitor()\n");
		esdm_fini();
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		atomic_store(&waiters[i].returned, false);
		if (pthread_create(&waiters[i].thread, NULL,
				   test_waiter_thread, &waiters[i])) {
			printf("cannot start a request\n");
			return 1;
		}
	}

	/* Several intervals of seedings that collect nothing */
	test_sleep_ms(TEST_WAIT_MS);
	ret = 0;
	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		if (atomic_load(&waiters[i].returned)) {
			printf("%s returned %zd without entropy\n",
			       waiters[i].name, waiters[i].rc);
			ret = 1;
		}
	}

	/* The sources recover, without a seeding triggered by it - see above */
	mutex_w_lock(&drng->seed_lock);
	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	if (esdm_state_operational()) {
		printf("raising the entropy rates seeded the ESDM, the test tests nothing\n");
		ret = 1;
	}
	mutex_w_unlock(&drng->seed_lock);

	for (j = 0; j < TEST_RETURN_SECONDS * 10; j++) {
		bool all = true;

		for (i = 0; i < ARRAY_SIZE(waiters); i++)
			all &= atomic_load(&waiters[i].returned);
		if (all)
			break;
		test_sleep_ms(100);
	}

	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		if (!atomic_load(&waiters[i].returned)) {
			printf("%s still waits %d seconds after the entropy sources recovered\n",
			       waiters[i].name, TEST_RETURN_SECONDS);
			ret = 1;
		}
	}

	/* Ends what still waits */
	esdm_fini();

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TEST_JOIN_SECONDS;
	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		if (pthread_timedjoin_np(waiters[i].thread, NULL, &deadline)) {
			printf("%s waits also after esdm_fini()\n",
			       waiters[i].name);
			/* The thread cannot be joined: leave without it */
			fflush(stdout);
			_exit(1);
		}

		printf("%s returned %zd\n", waiters[i].name, waiters[i].rc);
		if (waiters[i].rc != waiters[i].want)
			ret = 1;
	}

	return ret;
}
#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_wait_retry_test();
#else
	return 77;
#endif
}
