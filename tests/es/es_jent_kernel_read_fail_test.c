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
 * The kernel Jitter RNG entropy source against an RNG that stops delivering.
 *
 * The handle stays open when a read fails - with an error, or short as on an
 * EOF of the AF_ALG socket. The source must not be credited with entropy
 * meanwhile: not by what it reads, not by what it reports as available, and
 * not as a source that is credited at all. The same holds once a self test
 * found it not delivering. The next read that delivers in full gives the
 * credit back.
 *
 * The source is compiled into the test, with the libkcapi RNG calls replaced
 * by a stand-in that can be told to fail.
 */

#include "config.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct kcapi_handle;

static ssize_t test_kcapi_rng_generate(struct kcapi_handle *handle,
				       uint8_t *buffer, size_t len);
static int test_kcapi_rng_init(struct kcapi_handle **handle,
			       const char *ciphername, uint32_t flags);
static void test_kcapi_rng_destroy(struct kcapi_handle *handle);

#define kcapi_rng_generate test_kcapi_rng_generate
#define kcapi_rng_init test_kcapi_rng_init
#define kcapi_rng_destroy test_kcapi_rng_destroy

/* The unit under test */
#include "esdm_es_jent_kernel.c"

#include "common_test.h"
#include "esdm_logger.h"

enum test_kcapi_mode {
	test_kcapi_deliver,
	/* An error from the kernel */
	test_kcapi_error,
	/* A recv() that hits EOF */
	test_kcapi_eof,
};

static _Atomic int test_kcapi_mode = test_kcapi_deliver;
static uint8_t test_kcapi_handle;

static int test_kcapi_rng_init(struct kcapi_handle **handle,
			       const char *ciphername, uint32_t flags)
{
	(void)ciphername;
	(void)flags;

	*handle = (struct kcapi_handle *)&test_kcapi_handle;
	return 0;
}

static void test_kcapi_rng_destroy(struct kcapi_handle *handle)
{
	(void)handle;
}

static ssize_t test_kcapi_rng_generate(struct kcapi_handle *handle,
				       uint8_t *buffer, size_t len)
{
	static uint8_t counter;

	(void)handle;

	switch (atomic_load(&test_kcapi_mode)) {
	case test_kcapi_error:
		return -EFAULT;
	case test_kcapi_eof:
		return 0;
	default:
		break;
	}

	/* Output that differs from call to call */
	memset(buffer, ++counter, len);
	return (ssize_t)len;
}

static uint32_t test_get(void)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	/* Not from the cache: the RNG itself is asked */
	esdm_es_jent_kernel.get_ent(&eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS,
				    false);

	return eb_es.e_bits;
}

static void test_credited(uint32_t expected, const char *what)
{
	CHECK_EQ(esdm_es_jent_kernel.curr_entropy(
			 ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 expected);
	CHECK_EQ(esdm_es_jent_kernel.max_entropy(),
		 esdm_es_jent_kernel.curr_entropy(esdm_security_strength()));
	CHECK(!!esdm_es_jent_kernel.max_entropy() == !!expected,
	      "%s: the source counts as %scredited", what,
	      expected ? "not " : "");
}

static void test_failure(enum test_kcapi_mode mode, uint32_t expected,
			 const char *what)
{
	/* A failing read takes the credit away, the handle stays */
	atomic_store(&test_kcapi_mode, mode);
	CHECK_EQ(test_get(), 0);
	CHECK(esdm_es_jent_kernel.active(), "%s: the handle was dropped", what);
	test_credited(0, what);
	CHECK(esdm_es_jent_kernel.selftest() < 0,
	      "%s: an RNG that does not deliver passed the self test", what);

	/* The next read that delivers gives it back */
	atomic_store(&test_kcapi_mode, test_kcapi_deliver);
	CHECK_EQ(test_get(), expected);
	test_credited(expected, what);

	/* A self test the RNG does not deliver to takes it away */
	atomic_store(&test_kcapi_mode, mode);
	CHECK(esdm_es_jent_kernel.selftest() < 0,
	      "%s: an RNG that does not deliver passed the self test", what);
	test_credited(0, what);

	/* And one it delivers to gives it back */
	atomic_store(&test_kcapi_mode, test_kcapi_deliver);
	CHECK_EQ(esdm_es_jent_kernel.selftest(), 0);
	test_credited(expected, what);
}

int main(void)
{
	uint32_t expected;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	esdm_config_es_jent_kernel_entropy_rate_set(
		ESDM_DRNG_SECURITY_STRENGTH_BITS);
	expected =
		esdm_fast_noise_entropylevel(ESDM_DRNG_SECURITY_STRENGTH_BITS,
					     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	CHECK_EQ(esdm_es_jent_kernel.init(), 0);
	CHECK(esdm_es_jent_kernel.active(), "the stand-in was not taken");
	CHECK_EQ(esdm_es_jent_kernel.selftest(), 0);
	CHECK_EQ(test_get(), expected);
	test_credited(expected, "working RNG");

	test_failure(test_kcapi_error, expected, "read error");
	test_failure(test_kcapi_eof, expected, "short read");

	esdm_es_jent_kernel.fini();

	return common_test_result("es_jent_kernel_read_fail");
}
