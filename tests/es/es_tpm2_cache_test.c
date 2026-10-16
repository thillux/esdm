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
 * The block cache of the TPM 2.0 entropy source against what it serves.
 *
 * - A self test that sees the TPM repeat its output takes the credit away
 *   from the source. The blocks cached before were once still served with the
 *   entropy of the configured rate, and kept in the cache.
 *
 * - A request that has to be served with entropy collected for it - the
 *   seeding of the prediction resistance DRNG - must not take a cached block.
 *
 * - A TPM that answers TPM2_GetRandom with an error that is no reason to retry
 *   - TPM_RC_FAILURE of a TPM in failure mode - keeps its connection, but is
 *   credited with no entropy until it delivers again: not by what it reads,
 *   not by what it reports as available, and not as a source that is credited
 *   at all. The same holds once a self test found it not delivering.
 *
 * A TPM is simulated on a socket pair: the source is compiled into the test
 * and talks to the stand-in, which answers TPM2_GetRandom and TPM2_StirRandom
 * and can be told to repeat its output or to fail.
 */

#include "config.h"

static char tpm2_test_path[256];
#undef ESDM_TPM2_RM_PATH
#define ESDM_TPM2_RM_PATH tpm2_test_path

/* The unit under test */
#include "esdm_es_tpm2.c"

#include <pthread.h>
#include <sys/socket.h>

#include "common_test.h"
#include "esdm_logger.h"

#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)

static atomic_bool tpm2_test_repeat = false;
static atomic_bool tpm2_test_fail = false;

/* TPM_RC_FAILURE: the TPM is in failure mode */
static const TPM2_RC TPM2_RC_FAILURE = 0x00000101;

static int tpm2_test_read_full(int fd, uint8_t *buf, size_t len)
{
	return esdm_safe_read(fd, buf, len) == (ssize_t)len ? 0 : -1;
}

/* The stand-in TPM: one response per command, until the source hangs up */
static void *tpm2_test_device(void *arg)
{
	int fd = *(int *)arg;
	uint8_t counter = 0;

	for (;;) {
		uint8_t cmd[256], rsp[256];
		uint32_t size, code, rsp_size = 10;

		if (tpm2_test_read_full(fd, cmd, 10))
			break;
		size = ptr_to_be32(cmd + 2);
		code = ptr_to_be32(cmd + 6);
		if (size < 10 || size > sizeof(cmd) ||
		    tpm2_test_read_full(fd, cmd + 10, size - 10))
			break;

		memset(rsp, 0, sizeof(rsp));
		if (code == TPM2_CC_GET_RANDOM && size >= 12 &&
		    atomic_load(&tpm2_test_fail)) {
			uint16_t len = ptr_to_be16(cmd + 10);

			if (len > 32)
				break;

			/*
			 * An error response is the header alone. A TPM device
			 * ends the read after it, which a stream socket does
			 * not: the answer is padded to what the source reads,
			 * the header says 10 bytes all the same.
			 */
			be16_to_ptr(rsp, TPM2_ST_NO_SESSIONS);
			be32_to_ptr(rsp + 2, 10);
			be32_to_ptr(rsp + 6, TPM2_RC_FAILURE);
			rsp_size = 12 + len;
			if (esdm_safe_write(fd, rsp, rsp_size) !=
			    (ssize_t)rsp_size)
				break;
			continue;
		}

		if (code == TPM2_CC_GET_RANDOM && size >= 12) {
			uint16_t len = ptr_to_be16(cmd + 10);

			if (len > 32)
				break;
			be16_to_ptr(rsp + 10, len);
			/* Output that differs from call to call - or does not */
			counter++;
			memset(rsp + 12,
			       atomic_load(&tpm2_test_repeat) ? 0x42 : counter,
			       len);
			rsp_size = 12 + len;
		}

		be16_to_ptr(rsp, TPM2_ST_NO_SESSIONS);
		be32_to_ptr(rsp + 2, rsp_size);
		be32_to_ptr(rsp + 6, TPM2_RC_SUCCESS);
		if (esdm_safe_write(fd, rsp, rsp_size) != (ssize_t)rsp_size)
			break;
	}

	return NULL;
}

static unsigned int tpm2_test_filled(void)
{
	unsigned int i, filled = 0;

	for (i = 0; i < tpm2_buf.num_blocks; i++)
		filled +=
			atomic_load(&tpm2_buf.states[i]) == esdm_es_buf_filled;

	return filled;
}

static uint32_t tpm2_test_get(bool allow_cached)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es_tpm2.get_ent(&eb_es, esdm_get_seed_entropy_osr(false, true),
			     allow_cached);

	return eb_es.e_bits;
}

static void tpm2_test_fill_cache(void)
{
	/* The first run after an init or a reset is skipped by design */
	CHECK_EQ(esdm_es_tpm2.monitor_es(), 0);
	CHECK_EQ(esdm_es_tpm2.monitor_es(), 0);
	CHECK_EQ(tpm2_test_filled(), tpm2_buf.num_blocks);
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	uint32_t expected;
	pthread_t device;
	unsigned int filled;
	int sv[2], fd;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	snprintf(tpm2_test_path, sizeof(tpm2_test_path),
		 "%s/esdm-tpm2-cache-XXXXXX",
		 tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(tpm2_test_path);
	if (fd < 0) {
		printf("cannot create the stand-in device - skipping\n");
		return 77;
	}
	close(fd);

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		printf("cannot create the socket pair - skipping\n");
		unlink(tpm2_test_path);
		return 77;
	}

	esdm_config_es_tpm2_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK_EQ(esdm_es_tpm2.init(), 0);
	unlink(tpm2_test_path);

	/* The source talks to the stand-in from now on */
	mutex_lock(&tpm2_mutex);
	CHECK(tpm2_fd >= 0, "the device file was not opened");
	if (tpm2_fd >= 0)
		close(tpm2_fd);
	tpm2_fd = sv[0];
	mutex_unlock(&tpm2_mutex);
	CHECK_EQ(pthread_create(&device, NULL, tpm2_test_device, &sv[1]), 0);

	CHECK_EQ(esdm_es_tpm2.selftest(), 0);

	expected = esdm_fast_noise_entropylevel(
		ESDM_DRNG_SECURITY_STRENGTH_BITS,
		esdm_get_seed_entropy_osr(false, true));
	tpm2_test_fill_cache();

	/* A request for entropy collected for it leaves the cache alone */
	CHECK_EQ(tpm2_test_get(false), expected);
	CHECK_EQ(tpm2_test_filled(), tpm2_buf.num_blocks);

	/* Any other request is served from it */
	CHECK_EQ(tpm2_test_get(true), expected);
	CHECK_EQ(tpm2_test_filled(), tpm2_buf.num_blocks - 1);

	/*
	 * Once a self test saw the TPM repeat itself, a cached block is
	 * credited with nothing, just as a fresh read is.
	 */
	mutex_lock(&tpm2_mutex);
	tpm2_selftest_failed = true;
	mutex_unlock(&tpm2_mutex);
	filled = tpm2_test_filled();
	CHECK_EQ(tpm2_test_get(true), 0);
	CHECK_EQ(tpm2_test_filled(), filled - 1);
	CHECK_EQ(tpm2_test_get(false), 0);
	mutex_lock(&tpm2_mutex);
	tpm2_selftest_failed = false;
	mutex_unlock(&tpm2_mutex);

	/* The self test that sees it discards the cache */
	tpm2_test_fill_cache();
	atomic_store(&tpm2_test_repeat, true);
	CHECK(esdm_es_tpm2.selftest() < 0,
	      "a TPM repeating its output passed the self test");
	CHECK_EQ(tpm2_test_filled(), 0);
	CHECK_EQ(tpm2_test_get(true), 0);
	CHECK_EQ(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 0);

	/* A self test that passes again restores the credit */
	atomic_store(&tpm2_test_repeat, false);
	CHECK_EQ(esdm_es_tpm2.selftest(), 0);
	CHECK_EQ(tpm2_test_get(true), expected);

	/*
	 * A TPM in failure mode answers, so its connection stays - and it is
	 * credited with nothing while it does not deliver.
	 */
	atomic_store(&tpm2_test_fail, true);
	CHECK_EQ(tpm2_test_get(false), 0);
	CHECK(esdm_es_tpm2.active(), "a TPM that answers lost its connection");
	CHECK_EQ(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 0);
	CHECK_EQ(esdm_es_tpm2.max_entropy(), 0);
	CHECK(esdm_es_tpm2.selftest() < 0,
	      "a TPM in failure mode passed the self test");

	/* The next read that delivers restores the credit */
	atomic_store(&tpm2_test_fail, false);
	CHECK_EQ(tpm2_test_get(false), expected);
	CHECK(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS) > 0,
	      "a TPM that delivers again is credited with nothing");
	CHECK(esdm_es_tpm2.max_entropy() > 0,
	      "a TPM that delivers again counts as not credited");

	/* A self test the TPM does not deliver to takes the credit away */
	atomic_store(&tpm2_test_fail, true);
	CHECK(esdm_es_tpm2.selftest() < 0,
	      "a TPM in failure mode passed the self test");
	CHECK_EQ(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 0);
	CHECK_EQ(esdm_es_tpm2.max_entropy(), 0);

	/* And one it delivers to gives it back */
	atomic_store(&tpm2_test_fail, false);
	CHECK_EQ(esdm_es_tpm2.selftest(), 0);
	CHECK(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS) > 0,
	      "a TPM passing its self test is credited with nothing");

	/* Closes the source's end, which ends the stand-in */
	esdm_es_tpm2.fini();
	pthread_join(device, NULL);
	close(sv[1]);

	return common_test_result("es_tpm2_cache");
}

#else /* ESDM_TPM2_ENTROPY_BLOCKS == 0 */

int main(void)
{
	/* No cache in this build */
	return 77;
}

#endif
