/*
 * Test of the self tests: the pass the ESDM runs when it comes up, the same
 * pass on demand, and the same pass repeated by the periodic worker
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_selftest.h"
#include "threading_support.h"
#include "../test_plan.h"

#ifdef ESDM_TESTMODE

/* Wait for @cond for at most this many 100ms slices */
#define ESDM_SELFTEST_TEST_SLICES 200

static void esdm_selftest_test_sleep(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

#define WAIT_FOR(cond)                                                         \
	do {                                                                   \
		unsigned int __i;                                              \
                                                                               \
		for (__i = 0; __i < ESDM_SELFTEST_TEST_SLICES && !(cond);      \
		     __i++)                                                    \
			esdm_selftest_test_sleep();                            \
	} while (0)

/*
 * Ask esdm_get_seed() for seed material with a buffer of the size it asks for.
 */
static ssize_t esdm_selftest_test_get_seed(void)
{
	uint64_t probe[2] = { 0, 0 };
	uint64_t *buf;
	ssize_t ret;

	/*
	 * A buffer that is too small is answered with the required size in its
	 * first word - which is how the caller learns how much to provide.
	 */
	if (esdm_get_seed(probe, sizeof(probe), ESDM_GET_SEED_NONBLOCK) !=
		    -EMSGSIZE ||
	    !probe[0])
		return -EFAULT;

	buf = calloc(1, (size_t)probe[0]);
	if (!buf)
		return -ENOMEM;

	ret = esdm_get_seed(buf, (size_t)probe[0], ESDM_GET_SEED_NONBLOCK);
	free(buf);

	return ret;
}

static int esdm_selftest_test(void)
{
	uint8_t buf[64];
	long long passes;
	ssize_t rc;
	int ret = 0;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	TEST_STEP("initialize the ESDM");
	TEST_REQUIRE("the ESDM initializes");
	ret = esdm_init();
	if (!TEST_CHECK(ret == 0, "%d", ret))
		return ret;

	/* A full pass runs when the ESDM comes up */
	TEST_REQUIRE("the crypto self tests passed at start up");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%d",
			esdm_selftest_crypto_passed()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_crypto_state_name(), "passed"),
			"%s", esdm_selftest_crypto_state_name())) {
		printf("self tests did not pass at start up: %s\n",
		       esdm_selftest_crypto_state_name());
		goto err;
	}

	/*
	 * Including the entropy sources - their state is established at start
	 * up and not only once the periodic worker got around to it.
	 */
	TEST_REQUIRE("the entropy source self tests passed at start up");
	if (!TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%d",
			(int)esdm_selftest_es_state()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_es_state_name(), "passed"), "%s",
			esdm_selftest_es_state_name())) {
		printf("entropy source self tests did not pass at start up: %s\n",
		       esdm_selftest_es_state_name());
		goto err;
	}

	TEST_REQUIRE(
		"at least one entropy source was tested at start up, none failed");
	if (!TEST_CHECK(esdm_selftest_es_sources() > 0, "%u",
			esdm_selftest_es_sources()) ||
	    !TEST_CHECK(esdm_selftest_es_failures() == 0, "%u",
			esdm_selftest_es_failures())) {
		printf("start up pass tested %u entropy sources, %u failed\n",
		       esdm_selftest_es_sources(), esdm_selftest_es_failures());
		goto err;
	}

	/* The pass at start up is counted like every other one */
	TEST_STEP("read the number of self test passes");
	passes = esdm_selftest_passes();
	TEST_REQUIRE("the pass at start up is counted");
	if (!TEST_CHECK(passes >= 1, "%lld", passes)) {
		printf("the pass at start up was not counted: %lld\n", passes);
		goto err;
	}

	/* Random bits are handed out while the self tests pass */
	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full",
		  sizeof(buf));
	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	TEST_REQUIRE("%zu bytes are returned", sizeof(buf));
	if (!TEST_CHECK(rc == (ssize_t)sizeof(buf), "%zd", rc)) {
		printf("cannot obtain random data\n");
		goto err;
	}

	/* The worker needs a thread pool to be taken from */
	TEST_STEP("initialize threading support");
	TEST_REQUIRE("threading support initializes");
	ret = thread_init(1);
	if (!TEST_CHECK(ret == 0, "%d", ret)) {
		printf("cannot initialize threading support\n");
		goto err;
	}

	TEST_STEP("start the periodic self test worker");
	esdm_selftest_periodic_start();
	TEST_REQUIRE("the periodic self test worker is on duty");
	if (!TEST_CHECK(esdm_selftest_periodic_running(), "%d",
			esdm_selftest_periodic_running())) {
		printf("periodic self test worker is not on duty\n");
		goto err;
	}

	/*
	 * The pass is repeated on its interval - one second in a test mode
	 * build, so two more of them are seen without a long wait.
	 */
	TEST_RUNUNTIL(
		"wait 100 ms until two more self test passes ran, at most %u times",
		ESDM_SELFTEST_TEST_SLICES);
	WAIT_FOR(esdm_selftest_passes() >= passes + 2);
	TEST_REQUIRE("the self tests were repeated at least twice");
	if (!TEST_CHECK(esdm_selftest_passes() >= passes + 2, "%lld",
			esdm_selftest_passes())) {
		printf("self tests are not repeated: %lld passes after %lld\n",
		       esdm_selftest_passes(), passes);
		goto err;
	}

	TEST_REQUIRE("the crypto and entropy source self tests still pass");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name()) ||
	    !TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%s",
			esdm_selftest_es_state_name())) {
		printf("periodic self test failed unexpectedly: %s / %s\n",
		       esdm_selftest_crypto_state_name(),
		       esdm_selftest_es_state_name());
		goto err;
	}

	/* The same pass on demand - what the privileged RPC endpoint offers */
	passes = esdm_selftest_passes();
	TEST_STEP("run the self tests on demand");
	rc = esdm_selftest_run();
	TEST_REQUIRE("the on-demand self test passes");
	if (!TEST_CHECK(rc == 0, "%zd", rc)) {
		printf("the on-demand self test failed: %zd\n", rc);
		goto err;
	}

	TEST_REQUIRE("the crypto and entropy source self tests still pass");
	if (!TEST_CHECK(esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name()) ||
	    !TEST_CHECK(esdm_selftest_es_state() == esdm_selftest_passed, "%s",
			esdm_selftest_es_state_name())) {
		printf("the on-demand self test left an unexpected state: %s / %s\n",
		       esdm_selftest_crypto_state_name(),
		       esdm_selftest_es_state_name());
		goto err;
	}

	/* On demand or not, it is the same pass and is counted as one */
	TEST_REQUIRE("the on-demand self test is counted as a pass");
	if (!TEST_CHECK(esdm_selftest_passes() > passes, "%lld",
			esdm_selftest_passes())) {
		printf("the on-demand self test was not counted: %lld\n",
		       esdm_selftest_passes());
		goto err;
	}

	/* Now the same with a self test that failed */
	TEST_STEP("mark the crypto self test as failed");
	esdm_test_selftest_set_failed();

	TEST_REQUIRE("the crypto self test is reported as failed");
	if (!TEST_CHECK(!esdm_selftest_crypto_passed(), "%d",
			!esdm_selftest_crypto_passed()) ||
	    !TEST_CHECK(!strcmp(esdm_selftest_crypto_state_name(), "failed"),
			"%s", esdm_selftest_crypto_state_name())) {
		printf("failed self test is not reported: %s\n",
		       esdm_selftest_crypto_state_name());
		goto err;
	}

	TEST_STEP("request %zu bytes from esdm_get_random_bytes_full",
		  sizeof(buf));
	rc = esdm_get_random_bytes_full(buf, sizeof(buf));
	TEST_REQUIRE("the request is refused with -EOPNOTSUPP");
	if (!TEST_CHECK(rc == -EOPNOTSUPP, "%zd", rc)) {
		printf("random data is handed out after a failed self test: %zd\n",
		       rc);
		goto err;
	}

	TEST_STEP("request seed data from esdm_get_seed");
	rc = esdm_selftest_test_get_seed();
	TEST_REQUIRE("the request is refused with -EOPNOTSUPP");
	if (!TEST_CHECK(rc == -EOPNOTSUPP, "%zd", rc)) {
		printf("seed data is handed out after a failed self test: %zd\n",
		       rc);
		goto err;
	}

	/*
	 * A pass that runs after a failure passes on its own - the crypto is
	 * not broken, the state is - and does not clear it.
	 */
	TEST_STEP("run the self tests on demand");
	rc = esdm_selftest_run();
	TEST_REQUIRE("the on-demand self test passes");
	if (!TEST_CHECK(rc == 0, "%zd", rc)) {
		printf("the on-demand self test failed: %zd\n", rc);
		goto err;
	}

	TEST_REQUIRE("the crypto self test is still reported as failed");
	if (!TEST_CHECK(!esdm_selftest_crypto_passed(), "%s",
			esdm_selftest_crypto_state_name())) {
		printf("an on-demand self test cleared a failed self test\n");
		goto err;
	}

	/* The worker leaves, as the state it reports cannot be recovered */
	TEST_RUNUNTIL(
		"wait 100 ms until the periodic self test worker left, at most %u times",
		ESDM_SELFTEST_TEST_SLICES);
	WAIT_FOR(!esdm_selftest_periodic_running());
	TEST_REQUIRE("the periodic self test worker left");
	if (!TEST_CHECK(!esdm_selftest_periodic_running(), "%d",
			!esdm_selftest_periodic_running())) {
		printf("periodic self test worker stays on duty after a failure\n");
		goto err;
	}

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_selftest_test();
#else
	return 77;
#endif
}
