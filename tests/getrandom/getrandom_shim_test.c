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
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "common_test.h"

/* The unit under test */
#include "getrandom.c"

/******************************************************************************
 * The RPC client, as far as the library uses it
 ******************************************************************************/

static bool stub_fully_seeded;
static int stub_seeded_ret;
static unsigned int stub_full_calls, stub_pr_calls;

int esdm_rpcc_set_max_online_nodes(uint32_t nodes)
{
	(void)nodes;

	return 0;
}

int esdm_rpcc_init_unpriv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	(void)interrupt_func;

	return 0;
}

void esdm_rpcc_fini_unpriv_service(void)
{
}

int esdm_rpcc_is_fully_seeded(bool *fully_seeded)
{
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

	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_random_bytes_pr(uint8_t *buf, size_t buflen)
{
	stub_pr_calls++;

	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_random_bytes(uint8_t *buf, size_t buflen)
{
	return stub_fill(buf, buflen);
}

ssize_t esdm_rpcc_get_seed(uint8_t *buf, size_t buflen, unsigned int flags)
{
	(void)flags;

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

	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(getrandom(buf, sizeof(buf), GRND_NONBLOCK | GRND_RANDOM),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(stub_full_calls, 1);
	CHECK_EQ(stub_pr_calls, 1);

	/* A blocking request does not ask first */
	stub_fully_seeded = false;
	CHECK_EQ(getrandom(buf, sizeof(buf), 0), (ssize_t)sizeof(buf));
	CHECK_EQ(stub_full_calls, 2);
}

/* Without an answer from the ESDM, the kernel decides */
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

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_nonblock_unseeded();
	test_nonblock_seeded();
	test_nonblock_no_esdm();

	return common_test_result("getrandom_shim");
}
