/*
 * Test of the output calls of esdm.h in a finalized library
 *
 *   - served: after esdm_init() and esdm_fini() of an operational ESDM, every
 *     output call returns -EOPNOTSUPP, the seed call included, and so after
 *     esdm_init() and esdm_reinit() were refused with -ESHUTDOWN.
 *   - waiting: esdm_fini() ends the calls that wait for an ESDM its entropy
 *     sources do not seed, and they return -EOPNOTSUPP as well.
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
#include <string.h>
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

/* Seconds the ESDM is given to reach the fully seeded state */
#define TEST_SEED_WAIT_SECONDS 30

/* How long the waiting calls are left waiting before esdm_fini() */
#define TEST_WAIT_MS 500

/* Seconds esdm_fini() is given to end a waiting call */
#define TEST_JOIN_SECONDS 20

/* Large enough for esdm_get_seed(), which answers -EMSGSIZE otherwise */
#define TEST_SEED_WORDS 1024

enum test_call {
	TEST_NB,
	TEST_FULL,
	TEST_FULL_NB,
	TEST_PR,
	TEST_PR_NB,
	TEST_SEED,
	TEST_SEED_NB,
	TEST_CALLS
};

static const char *const test_names[TEST_CALLS] = {
	[TEST_NB] = "esdm_get_random_bytes",
	[TEST_FULL] = "esdm_get_random_bytes_full",
	[TEST_FULL_NB] = "esdm_get_random_bytes_full_noblock",
	[TEST_PR] = "esdm_get_random_bytes_pr",
	[TEST_PR_NB] = "esdm_get_random_bytes_pr_noblock",
	[TEST_SEED] = "esdm_get_seed",
	[TEST_SEED_NB] = "esdm_get_seed (ESDM_GET_SEED_NONBLOCK)",
};

static void test_sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static ssize_t test_call(enum test_call call)
{
	static _Thread_local uint64_t seed[TEST_SEED_WORDS];
	uint8_t buf[32];

	switch (call) {
	case TEST_NB:
		return esdm_get_random_bytes(buf, sizeof(buf));
	case TEST_FULL:
		return esdm_get_random_bytes_full(buf, sizeof(buf));
	case TEST_FULL_NB:
		return esdm_get_random_bytes_full_noblock(buf, sizeof(buf));
	case TEST_PR:
		return esdm_get_random_bytes_pr(buf, sizeof(buf));
	case TEST_PR_NB:
		return esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
	case TEST_SEED:
		return esdm_get_seed(seed, sizeof(seed), 0);
	case TEST_SEED_NB:
		return esdm_get_seed(seed, sizeof(seed),
				     ESDM_GET_SEED_NONBLOCK);
	case TEST_CALLS:
	default:
		return -EINVAL;
	}
}

/* Every output call, each expected to return -EOPNOTSUPP */
static int test_all_refused(const char *when)
{
	unsigned int call;
	int ret = 0;

	for (call = 0; call < TEST_CALLS; call++) {
		ssize_t rc = test_call(call);

		printf("%s: %s returned %zd%s\n", when, test_names[call], rc,
		       rc == -EOPNOTSUPP ? "" : " instead of -EOPNOTSUPP");
		if (rc != -EOPNOTSUPP)
			ret = 1;
	}

	return ret;
}

static int test_served(void)
{
	uint8_t buf[32];
	unsigned int i;
	ssize_t rc;
	int ret;

	esdm_config_es_cpu_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	esdm_config_es_jent_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);

	ret = esdm_init();
	if (ret) {
		printf("esdm_init() failed: %d\n", ret);
		return 1;
	}

	esdm_get_random_bytes(buf, sizeof(buf));
	for (i = 0;
	     i < TEST_SEED_WAIT_SECONDS * 10 && !esdm_state_operational(); i++)
		test_sleep_ms(100);
	if (!esdm_state_operational()) {
		printf("the ESDM did not become operational, skipping\n");
		esdm_fini();
		return 77;
	}

	/* What is refused below was served before */
	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	if (rc != (ssize_t)sizeof(buf)) {
		printf("esdm_get_random_bytes_full returned %zd before esdm_fini()\n",
		       rc);
		esdm_fini();
		return 1;
	}

	esdm_fini();

	ret = test_all_refused("after esdm_fini()");

	rc = esdm_init();
	printf("esdm_init() after esdm_fini() returned %zd\n", rc);
	if (rc != -ESHUTDOWN)
		ret = 1;
	rc = esdm_reinit();
	printf("esdm_reinit() after esdm_fini() returned %zd\n", rc);
	if (rc != -ESHUTDOWN)
		ret = 1;

	/* The refused initializations did not bring anything back */
	ret |= test_all_refused("after the refused esdm_init()");

	return ret;
}

struct test_waiter {
	pthread_t thread;
	enum test_call call;
	atomic_bool returned;
	ssize_t rc;
};

static void *test_waiter_thread(void *arg)
{
	struct test_waiter *waiter = arg;

	waiter->rc = test_call(waiter->call);
	atomic_store(&waiter->returned, true);

	return NULL;
}

static int test_waiting(void)
{
	/* The calls that wait: for the operational state, for all DRNGs */
	struct test_waiter waiters[] = {
		{ .call = TEST_FULL },
		{ .call = TEST_PR },
		{ .call = TEST_SEED },
	};
	struct timespec deadline;
	unsigned int i;
	int ret;

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

	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		atomic_store(&waiters[i].returned, false);
		if (pthread_create(&waiters[i].thread, NULL,
				   test_waiter_thread, &waiters[i])) {
			printf("cannot start a waiting call\n");
			return 1;
		}
	}

	test_sleep_ms(TEST_WAIT_MS);
	ret = 0;
	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		if (atomic_load(&waiters[i].returned)) {
			printf("%s returned %zd instead of waiting\n",
			       test_names[waiters[i].call], waiters[i].rc);
			ret = 1;
		}
	}

	esdm_fini();

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TEST_JOIN_SECONDS;
	for (i = 0; i < ARRAY_SIZE(waiters); i++) {
		if (pthread_timedjoin_np(waiters[i].thread, NULL, &deadline)) {
			printf("%s still waits %d seconds after esdm_fini()\n",
			       test_names[waiters[i].call], TEST_JOIN_SECONDS);
			/* The thread cannot be joined: leave without it */
			fflush(stdout);
			_exit(1);
		}

		printf("waiting during esdm_fini(): %s returned %zd%s\n",
		       test_names[waiters[i].call], waiters[i].rc,
		       waiters[i].rc == -EOPNOTSUPP ?
			       "" :
			       " instead of -EOPNOTSUPP");
		if (waiters[i].rc != -EOPNOTSUPP)
			ret = 1;
	}

	return ret;
}
#endif

int main(int argc, char *argv[])
{
#ifdef ESDM_TESTMODE
	esdm_logger_set_verbosity(LOGGER_WARN);
	esdm_config_max_nodes_set(1);

	if (argc > 1 && !strcmp(argv[1], "waiting"))
		return test_waiting();
	return test_served();
#else
	(void)argc;
	(void)argv;
	return 77;
#endif
}
