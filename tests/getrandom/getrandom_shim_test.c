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
 * Tests of the getrandom library against an ESDM that answers as told.
 *
 * What the library does depends on the state the ESDM is in - seeded or not -
 * which a real server cannot be held in. So the translation unit is compiled
 * into the test and the RPC client calls it makes are provided here instead.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"

/*
 * The kernel's getrandom(2), scripted: each entry is the outcome of one call,
 * a negative errno or the number of bytes delivered. Past the script, the real
 * system call answers.
 */
static ssize_t stub_kernel[4];
static unsigned int stub_kernel_len, stub_kernel_calls;

static long test_syscall(long nr, void *buf, size_t len, unsigned int flags)
{
	ssize_t rc;

	if (nr != __NR_getrandom || stub_kernel_calls >= stub_kernel_len)
		return syscall(nr, buf, len, flags);

	rc = stub_kernel[stub_kernel_calls++];
	if (rc < 0) {
		errno = (int)-rc;
		return -1;
	}
	if ((size_t)rc > len)
		rc = (ssize_t)len;
	memset(buf, 0x17, (size_t)rc);

	return rc;
}

/* Only the unit under test is redirected - <unistd.h> came before. */
#define syscall(nr, buf, len, flags) test_syscall(nr, buf, len, flags)

/* The unit under test */
#include "getrandom.c"

/******************************************************************************
 * The RPC client, as far as the library uses it
 ******************************************************************************/

static bool stub_fully_seeded;
static int stub_seeded_ret;
static ssize_t stub_full_ret;
static ssize_t stub_pr_nonblock_ret;
static ssize_t stub_insecure_ret;
static ssize_t stub_seed_ret;
static unsigned int stub_full_calls, stub_pr_calls, stub_pr_nonblock_calls,
	stub_init_calls;

/*
 * The checkout deadline the library set for the calls that follow, NULL once
 * it set it back - and whether one was set for each of these calls.
 */
static const struct timespec *stub_checkout_deadline;
static bool stub_seeded_bounded, stub_insecure_bounded, stub_pr_nonblock_bounded,
	stub_seed_bounded, stub_full_bounded, stub_pr_bounded;

const struct timespec *
esdm_rpcc_set_unpriv_checkout_deadline(const struct timespec *deadline)
{
	const struct timespec *prev = stub_checkout_deadline;

	stub_checkout_deadline = deadline;
	return prev;
}

int esdm_rpcc_set_max_online_nodes(uint32_t nodes)
{
	(void)nodes;

	return 0;
}

int esdm_rpcc_init_unpriv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	(void)interrupt_func;
	stub_init_calls++;

	return 0;
}

void esdm_rpcc_fini_unpriv_service(void)
{
	/*
	 * Reached from the library's destructor only, i.e. after main()
	 * returned, so the verdict is the exit code: 42 for a fini that pairs
	 * with an init, 3 for one that drops a reference it never took.
	 */
	_exit(stub_init_calls ? 42 : 3);
}

int esdm_rpcc_is_fully_seeded(bool *fully_seeded)
{
	stub_seeded_bounded = !!stub_checkout_deadline;
	*fully_seeded = stub_fully_seeded;

	return stub_seeded_ret;
}

static ssize_t stub_fill(uint8_t *buf, size_t buflen)
{
	memset(buf, 0x42, buflen);

	return (ssize_t)buflen;
}

ssize_t esdm_rpcc_get_random_bytes_full(uint8_t *buf, size_t buflen)
{
	stub_full_calls++;
	stub_full_bounded = !!stub_checkout_deadline;

	if (stub_full_ret)
		return stub_full_ret;

	return stub_fill(buf, buflen);
}

/*
 * The timed request a non-blocking caller's seeded randomness takes, scripted
 * call by call: 0 for success - the whole buffer, as the real one serves it in
 * full or not at all - or a negative errno. Past the script, it succeeds.
 */
static ssize_t stub_full_timeout[4];
static unsigned int stub_full_timeout_len, stub_full_timeout_calls;
static struct timespec stub_full_timeout_ts;

ssize_t esdm_rpcc_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
						struct timespec *ts)
{
	ssize_t rc = 0;

	stub_full_timeout_ts = *ts;
	if (stub_full_timeout_calls < stub_full_timeout_len)
		rc = stub_full_timeout[stub_full_timeout_calls];
	stub_full_timeout_calls++;

	if (rc < 0)
		return rc;

	return stub_fill(buf, buflen);
}

static void stub_full_timeout_set(ssize_t first, ssize_t second)
{
	stub_full_timeout[0] = first;
	stub_full_timeout[1] = second;
	stub_full_timeout_len = 2;
	stub_full_timeout_calls = 0;
}

ssize_t esdm_rpcc_get_random_bytes_pr(uint8_t *buf, size_t buflen)
{
	stub_pr_calls++;
	stub_pr_bounded = !!stub_checkout_deadline;

	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_random_bytes_pr_nonblock(uint8_t *buf, size_t buflen)
{
	stub_pr_nonblock_calls++;
	stub_pr_nonblock_bounded = !!stub_checkout_deadline;

	if (stub_pr_nonblock_ret)
		return stub_pr_nonblock_ret;

	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_random_bytes(uint8_t *buf, size_t buflen)
{
	stub_insecure_bounded = !!stub_checkout_deadline;
	if (stub_insecure_ret)
		return stub_insecure_ret;

	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_seed(uint8_t *buf, size_t buflen, unsigned int flags)
{
	(void)flags;

	stub_seed_bounded = !!stub_checkout_deadline;
	if (stub_seed_ret)
		return stub_seed_ret;

	return stub_fill(buf, buflen);
}

/******************************************************************************
 * Tests
 ******************************************************************************/

/*
 * getrandom(2) with GRND_NONBLOCK fails with EAGAIN as long as it would block.
 * The ESDM blocks until it is fully seeded and its client keeps asking until
 * then, so the library has to say no before it makes the request.
 */
static void test_nonblock_unseeded(void)
{
	uint8_t buf[16];

	stub_seeded_ret = 0;
	stub_fully_seeded = false;
	stub_full_calls = stub_pr_calls = 0;

	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK), -1);
	CHECK_EQ(errno, EAGAIN);

	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM), -1);
	CHECK_EQ(errno, EAGAIN);

	/* Neither request may have been made, it would have blocked */
	CHECK_EQ(stub_full_calls, 0);
	CHECK_EQ(stub_pr_calls, 0);

	/* Insecure randomness does not wait for anything */
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_INSECURE),
		 (ssize_t)sizeof(buf));
}

static void test_nonblock_seeded(void)
{
	uint8_t buf[16];

	stub_seeded_ret = 0;
	stub_fully_seeded = true;
	stub_full_calls = stub_pr_calls = 0;
	stub_full_timeout_len = stub_full_timeout_calls = 0;

	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM),
		 (ssize_t)sizeof(buf));

	/* Not the blocking request: the ESDM may stop being seeded meanwhile */
	CHECK_EQ(stub_full_calls, 0);
	CHECK_EQ(stub_full_timeout_calls, 1);

	/* The prediction resistant request is made without waiting, too */
	CHECK_EQ(stub_pr_calls, 0);
	CHECK_EQ(stub_pr_nonblock_calls, 1);
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_RANDOM),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(stub_pr_calls, 1);
	CHECK_EQ(stub_pr_nonblock_calls, 1);

	/* A blocking request does not ask first */
	stub_fully_seeded = false;
	CHECK_EQ(getrandom(buf, sizeof(buf), 0), (ssize_t)sizeof(buf));
	CHECK_EQ(stub_full_calls, 1);
	CHECK_EQ(stub_full_timeout_calls, 1);
}

/*
 * Seeded when asked, but no longer when the data is requested - an entropy
 * source failed its health test, say. The blocking request would wait for the
 * ESDM to be seeded again, the timed one gives up instead. That is the ESDM's
 * answer: EAGAIN, not the kernel's data.
 */
static void test_nonblock_unseeded_meanwhile(void)
{
	size_t large_len = ESDM_RPC_MAX_DATA + 16;
	uint8_t buf[16], *large;

	stub_seeded_ret = 0;
	stub_fully_seeded = true;
	stub_full_calls = 0;

	stub_full_timeout_set(-ETIMEDOUT, 0);
	memset(buf, 0xa5, sizeof(buf));
	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK), -1);
	CHECK_EQ(errno, EAGAIN);
	CHECK_EQ(stub_full_timeout_calls, 1);
	CHECK_EQ(stub_full_calls, 0);
	CHECK(buf[0] == 0xa5, "the kernel served the request instead");

	/*
	 * A zero timeout would end the request before it is sent, and the
	 * timeout is how long a non-blocking caller may be held at most.
	 */
	CHECK(stub_full_timeout_ts.tv_sec || stub_full_timeout_ts.tv_nsec,
	      "the non-blocking request never asks the ESDM");
	CHECK(stub_full_timeout_ts.tv_sec < 2,
	      "a non-blocking caller may be held for %ld s",
	      (long)stub_full_timeout_ts.tv_sec);

	/*
	 * What one RPC carries at most is one timed request each, so what was
	 * obtained before the ESDM stopped serving is returned as a short read.
	 */
	large = calloc(1, large_len);
	if (!large) {
		CHECK(0, "out of memory");
		goto out;
	}
	stub_full_timeout_set(0, -ETIMEDOUT);
	CHECK_EQ(getrandom(large, large_len, GRND_NONBLOCK),
		 (ssize_t)ESDM_RPC_MAX_DATA);
	CHECK_EQ(stub_full_timeout_calls, 2);
	CHECK(large[0] == 0x42 && large[ESDM_RPC_MAX_DATA - 1] == 0x42,
	      "the short read is not what the ESDM gave");

	/* And served in full when the ESDM keeps serving */
	stub_full_timeout_set(0, 0);
	CHECK_EQ(getrandom(large, large_len, GRND_NONBLOCK),
		 (ssize_t)large_len);
	CHECK_EQ(stub_full_timeout_calls, 2);
	free(large);

	/* An ESDM that went away meanwhile is covered by the kernel */
	stub_full_timeout_set(-ECONNREFUSED, 0);
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(stub_full_timeout_calls, 1);

out:
	stub_full_timeout_len = 0;
	CHECK_EQ(stub_full_calls, 0);
}

/* Without an answer from the ESDM, the kernel decides */
/*
 * Seeded, but the PR DRNG cannot serve right now - not operational, or busy
 * with another request. The blocking RPC client waits that out; a
 * non-blocking caller is told EAGAIN, and not served by the kernel instead,
 * as the ESDM did answer.
 */
static void test_nonblock_pr_busy(void)
{
	uint8_t buf[16];

	stub_seeded_ret = 0;
	stub_fully_seeded = true;
	stub_pr_nonblock_ret = -EAGAIN;
	stub_pr_calls = stub_pr_nonblock_calls = 0;

	memset(buf, 0xa5, sizeof(buf));
	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM), -1);
	CHECK_EQ(errno, EAGAIN);
	CHECK_EQ(stub_pr_nonblock_calls, 1);
	CHECK_EQ(stub_pr_calls, 0);
	CHECK(buf[0] == 0xa5, "the kernel served the request instead");

	/* A short answer is passed on as such, as getrandom(2) may do */
	stub_pr_nonblock_ret = 8;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM), 8);

	stub_pr_nonblock_ret = 0;
}

static void test_nonblock_no_esdm(void)
{
	uint8_t buf[16];

	stub_seeded_ret = -ECONNREFUSED;
	stub_full_calls = 0;

	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(stub_full_calls, 0);

	stub_seeded_ret = 0;
}

/*
 * The connections of the process are shared by its threads, and a request of
 * another one may hold them for seconds - prediction resistant data comes 32
 * bytes per round trip. A request that must not block waits for a connection
 * no longer than for an unseeded ESDM: the RPC client gives up the checkout at
 * the deadline the library sets, with -ETIMEDOUT, which the library answers
 * as it would a request it cannot serve without waiting. A blocking request
 * sets no deadline.
 */
static void test_nonblock_connections_busy(void)
{
	uint8_t buf[16];

	stub_fully_seeded = true;
	stub_full_calls = stub_pr_calls = stub_pr_nonblock_calls = 0;
	stub_full_timeout_len = stub_full_timeout_calls = 0;

	/* The check whether the ESDM is seeded: EAGAIN, no data asked for */
	stub_seeded_ret = -ETIMEDOUT;
	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK), -1);
	CHECK_EQ(errno, EAGAIN);
	CHECK(stub_seeded_bounded, "the seeding check waits for a connection");
	CHECK(!stub_checkout_deadline, "the deadline outlives the call");
	CHECK_EQ(stub_full_timeout_calls, 0);
	stub_seeded_ret = 0;

	/* Insecure data: the kernel's, as without an ESDM */
	stub_insecure_ret = -ETIMEDOUT;
	stub_kernel[0] = sizeof(buf);
	stub_kernel_len = 1;
	stub_kernel_calls = 0;
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_INSECURE),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(stub_kernel_calls, 1);
	CHECK(buf[0] == 0x17, "the kernel did not serve the request");
	CHECK(stub_insecure_bounded,
	      "the insecure request waits for a connection");
	CHECK(!stub_checkout_deadline, "the deadline outlives the call");
	stub_kernel_len = 0;
	stub_insecure_ret = 0;

	/* Prediction resistance without waiting: EAGAIN, as for a busy DRNG */
	stub_pr_nonblock_ret = -ETIMEDOUT;
	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM), -1);
	CHECK_EQ(errno, EAGAIN);
	CHECK(stub_pr_nonblock_bounded,
	      "the non-blocking PR request waits for a connection");
	CHECK(!stub_checkout_deadline, "the deadline outlives the call");
	stub_pr_nonblock_ret = 0;

	/* Seed material without waiting: EAGAIN as well */
	stub_seed_ret = -ETIMEDOUT;
	errno = 0;
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_SEED), -1);
	CHECK_EQ(errno, EAGAIN);
	CHECK(stub_seed_bounded,
	      "the non-blocking seed request waits for a connection");
	CHECK(!stub_checkout_deadline, "the deadline outlives the call");
	stub_seed_ret = 0;

	/* The blocking requests wait for a connection as long as it takes */
	CHECK_EQ(getrandom(buf, sizeof(buf), 0), (ssize_t)sizeof(buf));
	CHECK(!stub_full_bounded, "a blocking request gives up its wait");
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_RANDOM),
		 (ssize_t)sizeof(buf));
	CHECK(!stub_pr_bounded, "a blocking PR request gives up its wait");
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_SEED), (ssize_t)sizeof(buf));
	CHECK(!stub_seed_bounded, "a blocking seed request gives up its wait");
}

/*
 * getentropy(3) from the kernel, once the ESDM did not answer: its caller has
 * no reason to expect EINTR, so an interrupted call is retried and a partial
 * one continued, as glibc and musl do. A call delivering nothing fails with
 * EIO.
 */
static void test_getentropy_kernel(void)
{
	int (*const fns[])(void *, size_t) = { getentropy, __real_getentropy };
	uint8_t buf[32];
	unsigned int i;

	stub_full_ret = -ECONNREFUSED;

	for (i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
		stub_kernel[0] = -EINTR;
		stub_kernel[1] = 8;
		stub_kernel[2] = -EINTR;
		stub_kernel[3] = 24;
		stub_kernel_len = 4;
		stub_kernel_calls = 0;
		memset(buf, 0, sizeof(buf));
		CHECK_EQ(fns[i](buf, sizeof(buf)), 0);
		CHECK_EQ(stub_kernel_calls, 4);
		CHECK(buf[0] == 0x17 && buf[sizeof(buf) - 1] == 0x17,
		      "the buffer was not filled");

		stub_kernel[0] = 0;
		stub_kernel_len = 1;
		stub_kernel_calls = 0;
		errno = 0;
		CHECK_EQ(fns[i](buf, sizeof(buf)), -1);
		CHECK_EQ(errno, EIO);
	}

	stub_kernel_len = 0;
	stub_full_ret = 0;
}

/*
 * The RPC client is reference counted and shared with everybody else in the
 * process, so the library may only drop the reference it took itself. Each case
 * runs in a child, the destructor being what is under test.
 */
static int run_child(bool use_library)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;

	if (!pid) {
		if (use_library) {
			uint8_t buf[16];

			if (getrandom(buf, sizeof(buf), 0) != sizeof(buf))
				exit(1);
		}
		exit(0);
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static void test_fini_pairs_init(void)
{
	/* Never used, so there is no reference to drop */
	CHECK_EQ(run_child(false), 0);

	/* Used, so the reference taken is dropped again */
	CHECK_EQ(run_child(true), 42);
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	/* Before anything initializes the library in this process */
	test_fini_pairs_init();

	test_nonblock_unseeded();
	test_nonblock_seeded();
	test_nonblock_unseeded_meanwhile();
	test_nonblock_pr_busy();
	test_nonblock_no_esdm();
	test_nonblock_connections_busy();
	test_getentropy_kernel();

	ret = common_test_result("getrandom_shim");

	/* Leave without the destructor, which reports through the exit code */
	fflush(stdout);
	_exit(ret);
}
