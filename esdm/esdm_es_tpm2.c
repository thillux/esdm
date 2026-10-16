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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "bitshift.h"
#include "build_bug_on.h"
#include "conv_be_le.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_es_tpm2.h"
#include "helper.h"
#include "mutex.h"

static int tpm2_fd = -1;
static DEFINE_MUTEX_UNLOCKED(tpm2_mutex);

/*
 * A connection lost to an I/O error is reopened on demand, at most once per
 * interval: a resource manager restart must not take the source out for good,
 * nor a TPM that is gone cost an open() per request. A device absent at init
 * stays disabled, as before. Monotonic seconds, written under tpm2_mutex.
 */
#define ESDM_TPM2_REOPEN_INTERVAL_SEC 5
static bool tpm2_lost = false;
/* Set by a self test that saw a repeated output, cleared by one that passes */
static bool tpm2_selftest_failed = false;
static time_t tpm2_reopen_at = 0;

#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)
static uint32_t esdm_es_tpm2_buf_credit(uint32_t requested_bits);
static struct esdm_es_buf tpm2_buf;
static bool tpm2_buf_alloced = false;
#endif

static bool esdm_es_tpm2_active(void);

/* session type */
typedef uint16_t TPM2_ST;

/* command code */
typedef uint32_t TPM2_CC;

/* return code */
typedef uint32_t TPM2_RC;

static const TPM2_ST TPM2_ST_NO_SESSIONS = 0x8001;

#ifdef ESDM_TPM2_STIR
static const TPM2_CC TPM2_CC_STIR_RANDOM = 0x00000146;
#endif
static const TPM2_CC TPM2_CC_GET_RANDOM = 0x0000017B;

static const TPM2_RC TPM2_RC_SUCCESS = 0x00000000;
static const TPM2_RC TPM2_RC_RETRY = 0x00000922;
static const TPM2_RC TPM2_RC_TESTING = 0x0000090A;
static const TPM2_RC TPM2_RC_YIELDED = 0x00000908;

struct TPM2CommandHeader {
	TPM2_ST tag;
	uint32_t commandSize;
	TPM2_CC commandCode;
} __attribute((__packed__));

struct TPM2ResponseHeader {
	TPM2_ST tag;
	uint32_t responseSize;
	TPM2_RC responseCode;
} __attribute((__packed__));

static time_t esdm_es_tpm2_now(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return ts.tv_sec;
}

static void esdm_es_tpm2_finalize_locked(void)
{
	if (tpm2_fd < 0)
		return;

	close(tpm2_fd);
	tpm2_fd = -1;
}

/* Caller must hold tpm2_mutex (write lock). */
static void esdm_es_tpm2_lost_locked(void)
{
	esdm_es_tpm2_finalize_locked();
	tpm2_lost = true;
	tpm2_reopen_at = esdm_es_tpm2_now() + ESDM_TPM2_REOPEN_INTERVAL_SEC;
}

/* Caller must hold tpm2_mutex (write lock). */
static void esdm_es_tpm2_reopen_locked(void)
{
	time_t now;
	int fd;

	if (tpm2_fd >= 0 || !tpm2_lost)
		return;

	now = esdm_es_tpm2_now();
	if (now < tpm2_reopen_at)
		return;
	tpm2_reopen_at = now + ESDM_TPM2_REOPEN_INTERVAL_SEC;

	fd = open(ESDM_TPM2_RM_PATH, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "TPM 2.0 reopen failed: %s\n", strerror(errno));
		return;
	}

	tpm2_fd = fd;
	tpm2_lost = false;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "TPM 2.0 entropy source reopened its device\n");
}

/*
 * Send a TPM 2.0 command and receive the response.
 *
 * Returns 0 on success, -1 on failure (I/O error or TPM error).
 * Caller must hold tpm2_mutex (write lock), since tpm2_fd may be reset on
 * I/O failure.
 *
 * rsp_buffer may be NULL only when rsp_buffer_len is 0.
 */
static int esdm_es_tpm2_transceive(struct TPM2CommandHeader *cmd,
				   uint8_t *cmd_buffer, uint32_t cmd_buffer_len,
				   struct TPM2ResponseHeader *rsp,
				   uint8_t *rsp_buffer, uint32_t rsp_buffer_len)
{
	uint8_t buf[256];
	static const int max_retries = 5;
	int retries = 0;
	int ret = -1;
	ssize_t safe_ret = -1;

	if (sizeof(struct TPM2CommandHeader) + cmd_buffer_len > sizeof(buf) ||
	    sizeof(struct TPM2ResponseHeader) + rsp_buffer_len > sizeof(buf)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM 2.0 transceive: buffer too small\n");
		goto out;
	}

	do {
		retries++;
		memset(buf, 0, sizeof(buf));

		/* Serialize command header as big-endian into buf */
		be16_to_ptr(buf + offsetof(struct TPM2CommandHeader, tag),
			    cmd->tag);
		be32_to_ptr(buf + offsetof(struct TPM2CommandHeader,
					   commandSize),
			    cmd->commandSize);
		be32_to_ptr(buf + offsetof(struct TPM2CommandHeader,
					   commandCode),
			    cmd->commandCode);
		memcpy(buf + sizeof(struct TPM2CommandHeader), cmd_buffer,
		       cmd_buffer_len);

		safe_ret = esdm_safe_write(tpm2_fd, buf,
					   sizeof(struct TPM2CommandHeader) +
						   cmd_buffer_len);

		if (safe_ret != (ssize_t)(sizeof(struct TPM2CommandHeader) +
					  cmd_buffer_len)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				    "TPM 2.0 command write failed\n");
			esdm_es_tpm2_lost_locked();
			goto out;
		}

		safe_ret = esdm_safe_read(tpm2_fd, buf,
					  sizeof(struct TPM2ResponseHeader) +
						  rsp_buffer_len);

		/*
		 * A response shorter than the header - including a 0-byte EOF
		 * read (resource manager closed the fd) - cannot be parsed.
		 * Treat it as a hard I/O error instead of memcpy'ing the zeroed
		 * buffer below, which would otherwise yield responseCode 0 and
		 * be mistaken for TPM2_RC_SUCCESS.
		 */
		if (safe_ret < (ssize_t)sizeof(struct TPM2ResponseHeader)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				    "TPM 2.0 response read failed: %zd\n",
				    safe_ret);
			esdm_es_tpm2_lost_locked();
			goto out;
		}
		/*
		 * Parse the header before judging the length: a TPM error
		 * response is header-only (10 bytes), so requiring the full
		 * expected response length up front made every error response
		 * - including the retryable RC_RETRY/RC_YIELDED/RC_TESTING -
		 * an unparsed instant retry with the backoff below dead.
		 */
		memcpy(rsp, buf, sizeof(struct TPM2ResponseHeader));
		rsp->tag = ptr_to_be16((uint8_t *)&rsp->tag);
		rsp->responseSize = ptr_to_be32((uint8_t *)&rsp->responseSize);
		rsp->responseCode = ptr_to_be32((uint8_t *)&rsp->responseCode);

		if (rsp->responseCode == TPM2_RC_SUCCESS) {
			/* A success response must carry the full payload. */
			if (safe_ret !=
			    (ssize_t)(sizeof(struct TPM2ResponseHeader) +
				      rsp_buffer_len)) {
				continue;
			}

			/*
			 * Copy only the payload bytes (responseSize includes
			 * the header), and guard against a NULL rsp_buffer.
			 */
			if (rsp_buffer && rsp_buffer_len > 0) {
				size_t payload_len = 0;

				if (rsp->responseSize >
				    sizeof(struct TPM2ResponseHeader))
					payload_len =
						rsp->responseSize -
						sizeof(struct TPM2ResponseHeader);
				memcpy(rsp_buffer,
				       buf + sizeof(struct TPM2ResponseHeader),
				       min_size(payload_len, rsp_buffer_len));
			}

			ret = 0;
			break;
		}

		if (rsp->responseCode == TPM2_RC_RETRY ||
		    rsp->responseCode == TPM2_RC_YIELDED ||
		    rsp->responseCode == TPM2_RC_TESTING) {
			/*
			 * backoff: 10 ms, 20 ms, 30 ms
			 * should only happen shortly after boot/tpm2_selftest
			 */
			if (retries < max_retries)
				usleep(10000U * (unsigned int)retries);
			continue;
		}

		/* Unrecoverable TPM error */
		break;
	} while (retries < max_retries);

out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}

static void esdm_es_tpm2_finalize(void)
{
	mutex_lock(&tpm2_mutex);
	esdm_es_tpm2_finalize_locked();
	tpm2_lost = false;
	mutex_unlock(&tpm2_mutex);

#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)
	if (tpm2_buf_alloced) {
		esdm_es_buf_free(&tpm2_buf);
		tpm2_buf_alloced = false;
	}
#endif
}

static int esdm_es_tpm2_init(void)
{
	int ret;

	mutex_lock(&tpm2_mutex);

	/* Allow the init function to be called multiple times */
	esdm_es_tpm2_finalize_locked();
	tpm2_lost = false;

	ret = open(ESDM_TPM2_RM_PATH, O_RDWR | O_CLOEXEC);
	if (ret < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling TPM 2.0 entropy source as it is not present, error: %s\n",
			strerror(errno));
	} else {
		tpm2_fd = ret;
	}

	mutex_unlock(&tpm2_mutex);

#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)
	if (tpm2_buf_alloced) {
		esdm_es_buf_reset(&tpm2_buf);
	} else if (esdm_es_buf_alloc(&tpm2_buf, ESDM_TPM2_ENTROPY_BLOCKS,
				     "TPM2.0", esdm_config_es_tpm2_entropy_rate,
				     esdm_es_tpm2_buf_credit) == 0) {
		tpm2_buf_alloced = true;
	}
#endif

	return 0;
}

/* Caller must hold tpm2_mutex. */
static uint32_t esdm_es_tpm2_entropylevel_locked(uint32_t requested_bits)
{
	if (tpm2_fd < 0 || tpm2_selftest_failed)
		return 0;

	return esdm_fast_noise_entropylevel(esdm_config_es_tpm2_entropy_rate(),
					    requested_bits);
}

static uint32_t esdm_es_tpm2_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&tpm2_mutex);
	ret = esdm_es_tpm2_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&tpm2_mutex);

	return ret;
}

static uint32_t esdm_es_tpm2_poolsize(void)
{
	uint32_t ret;

	mutex_reader_lock(&tpm2_mutex);
	ret = esdm_es_tpm2_entropylevel_locked(esdm_security_strength());
	mutex_reader_unlock(&tpm2_mutex);

	return ret;
}

/*
 * Caller must hold tpm2_mutex (write lock).
 * len must be in [1, 32].
 */
static int esdm_es_tpm2_get_internal(uint8_t *buf, uint32_t len)
{
#ifdef ESDM_TPM2_STIR
	struct timespec stir_clock_real;
	struct timespec stir_clock_monotonic;
	static const uint16_t stir_data_len =
		sizeof(stir_clock_real) + sizeof(stir_clock_monotonic);
	uint8_t stir_buf[sizeof(uint16_t) + sizeof(stir_clock_real) +
			 sizeof(stir_clock_monotonic)] = { 0 };
	struct TPM2CommandHeader stirrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(stir_buf),
		.commandCode = TPM2_CC_STIR_RANDOM
	};
	struct TPM2ResponseHeader stirrandom_rsp = { 0 };
#endif
	struct TPM2CommandHeader getrandom_cmd = {
		.tag = TPM2_ST_NO_SESSIONS,
		.commandSize =
			sizeof(struct TPM2CommandHeader) + sizeof(uint16_t),
		.commandCode = TPM2_CC_GET_RANDOM
	};
	uint16_t bytes_requested = be_bswap16(len);
	uint8_t resp_buf[32 + 2] = { 0 };
	struct TPM2ResponseHeader getrandom_rsp = { 0 };
	uint16_t bytes_returned = 0;

	if (len == 0 || len > 32)
		return -1;

#ifdef ESDM_TPM2_STIR
	/*
	 * Explicitly trigger a reseed of the TPM's internal DRBG before
	 * requesting random data. Also mix in additional data on every
	 * request for additional domain separation inside the TPM.
	 * It is highly unlikely, to get the exact same realtime and monotonic
	 * time tuples on all systems every time.
	 */

	/* stir buffer size */
	be16_to_ptr(stir_buf, stir_data_len);

	/* inject real and monotonic time as additional input without entropy */
	(void)clock_gettime(CLOCK_REALTIME, &stir_clock_real);
	(void)clock_gettime(CLOCK_MONOTONIC, &stir_clock_monotonic);
	memcpy(stir_buf + sizeof(uint16_t), &stir_clock_real,
	       sizeof(stir_clock_real));
	memcpy(stir_buf + sizeof(uint16_t) + sizeof(stir_clock_real),
	       &stir_clock_monotonic, sizeof(stir_clock_monotonic));

	if (esdm_es_tpm2_transceive(&stirrandom_cmd, stir_buf, sizeof(stir_buf),
				    &stirrandom_rsp, NULL, 0)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 stir random failed\n");
		memset_secure(stir_buf, 0, sizeof(stir_buf));
		return -1;
	}
	memset_secure(stir_buf, 0, sizeof(stir_buf));
#endif

	/* The answer is the size field and exactly the bytes requested */
	if (esdm_es_tpm2_transceive(&getrandom_cmd, (uint8_t *)&bytes_requested,
				    sizeof(bytes_requested), &getrandom_rsp,
				    resp_buf, sizeof(uint16_t) + len)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 get random failed. RC: 0x%04x\n",
			    getrandom_rsp.responseCode);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	if (getrandom_rsp.responseSize !=
	    sizeof(struct TPM2ResponseHeader) + sizeof(uint16_t) + len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 unexpected response size: %u\n",
			    getrandom_rsp.responseSize);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	bytes_returned = ptr_to_be16(resp_buf);
	if (bytes_returned != len) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "TPM 2.0 returned %u bytes, expected %u\n",
			    bytes_returned, len);
		memset_secure(resp_buf, 0, sizeof(resp_buf));
		return -1;
	}

	memcpy(buf, resp_buf + 2, len);
	memset_secure(resp_buf, 0, sizeof(resp_buf));

	return 0;
}

static void esdm_es_tpm2_get_sync(struct entropy_es *eb_es,
				  uint32_t requested_bits)
{
	static const uint32_t tpm2_max_chunk_bytes = 32;
	uint8_t buffer[32];
	uint32_t done_bits = 0;

	/*
	 * Use an exclusive lock: transceive may close and reset tpm2_fd on
	 * I/O errors, which is a write to shared state.
	 */
	mutex_lock(&tpm2_mutex);

	esdm_es_tpm2_reopen_locked();
	if (tpm2_fd < 0)
		goto err;

	while (done_bits < requested_bits) {
		uint32_t chunk_bits = min_uint32(tpm2_max_chunk_bytes << 3,
						 requested_bits - done_bits);
		uint32_t chunk_bytes = chunk_bits >> 3;

		if (esdm_es_tpm2_get_internal(buffer, tpm2_max_chunk_bytes))
			goto err;
		memcpy(eb_es->e + (done_bits >> 3), buffer, chunk_bytes);
		done_bits += chunk_bits;
	}

	eb_es->e_bits = esdm_es_tpm2_entropylevel_locked(requested_bits);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from TPM 2.0 entropy source\n",
		    eb_es->e_bits);

	mutex_unlock(&tpm2_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	return;

err:
	mutex_unlock(&tpm2_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	eb_es->e_bits = 0;
}

#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)

/*
 * What a block of @requested_bits is credited with at present: the configured
 * rate, and nothing once a self test saw the TPM repeat its output. Unlike
 * esdm_es_tpm2_entropylevel() it does not ask whether the device is open now -
 * a block cached before the connection was lost was read from a TPM that
 * delivered.
 */
static uint32_t esdm_es_tpm2_buf_credit(uint32_t requested_bits)
{
	bool failed;

	mutex_reader_lock(&tpm2_mutex);
	failed = tpm2_selftest_failed;
	mutex_reader_unlock(&tpm2_mutex);

	if (failed)
		return 0;

	return esdm_fast_noise_entropylevel(esdm_config_es_tpm2_entropy_rate(),
					    requested_bits);
}

static void esdm_es_tpm2_buf_fill(struct entropy_es *eb_es,
				  uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_es_tpm2_get_sync(eb_es, requested_bits);
}

static int esdm_es_tpm2_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, true);

	/* A cache hit never reaches the reopen in esdm_es_tpm2_get_sync() */
	mutex_lock(&tpm2_mutex);
	esdm_es_tpm2_reopen_locked();
	mutex_unlock(&tpm2_mutex);

	if (!esdm_es_tpm2_active())
		return 0;

	return esdm_es_buf_monitor(&tpm2_buf, requested_bits,
				   esdm_es_tpm2_buf_fill, NULL);
}

static void esdm_es_tpm2_get(struct entropy_es *eb_es, uint32_t requested_bits,
			     bool __unused unsused)
{
	if (esdm_es_buf_try_get(&tpm2_buf, eb_es, requested_bits,
				!!esdm_config_es_tpm2_entropy_rate()))
		return;

	esdm_es_tpm2_get_sync(eb_es, requested_bits);
}

#else /* ESDM_TPM2_ENTROPY_BLOCKS == 0 */

static void esdm_es_tpm2_get(struct entropy_es *eb_es, uint32_t requested_bits,
			     bool __unused unsused)
{
	esdm_es_tpm2_get_sync(eb_es, requested_bits);
}

#endif

static void esdm_es_tpm2_es_state(char *buf, size_t buflen)
{
#ifdef ESDM_TPM2_STIR
	const bool stir = 1;
#else
	const bool stir = 0;
#endif
	uint32_t poolsize, entropy_rate;

	mutex_reader_lock(&tpm2_mutex);
	poolsize = esdm_es_tpm2_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_es_tpm2_entropylevel_locked(256);
	mutex_reader_unlock(&tpm2_mutex);

	/* Assume the esdm_drng_init lock is taken by caller */
	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Stir: %u\n",
		 poolsize, entropy_rate, stir);
}

static bool esdm_es_tpm2_active(void)
{
	bool ret;

	mutex_reader_lock(&tpm2_mutex);
	ret = tpm2_fd >= 0;
	mutex_reader_unlock(&tpm2_mutex);

	return ret;
}

/* Two reads of the TPM that have to succeed and have to differ. */
static int esdm_es_tpm2_selftest(void)
{
	uint8_t first[16], second[16];
	int ret = 0;

	mutex_lock(&tpm2_mutex);

	esdm_es_tpm2_reopen_locked();
	if (tpm2_fd < 0) {
		/* A device that went away is a failure, one never there not */
		if (tpm2_lost) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ES,
				    "TPM2 ES: connection to the TPM lost\n");
			ret = -EFAULT;
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "TPM2 ES: no device - nothing to test\n");
		}
		goto out;
	}

	if (esdm_es_tpm2_get_internal(first, sizeof(first)) ||
	    esdm_es_tpm2_get_internal(second, sizeof(second))) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM2 ES: the TPM did not deliver\n");
		ret = -EFAULT;
		goto out;
	}

	if (!memcmp(first, second, sizeof(first))) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "TPM2 ES: the TPM repeated its output\n");
		tpm2_selftest_failed = true;
		ret = -EFAULT;
		goto out;
	}

	tpm2_selftest_failed = false;

out:
	mutex_unlock(&tpm2_mutex);
	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));

	return ret;
}

struct esdm_es_cb esdm_es_tpm2 = {
	.name = "TPM2.0",
	.init = esdm_es_tpm2_init,
	.fini = esdm_es_tpm2_finalize,
#if (ESDM_TPM2_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_es_tpm2_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_es_tpm2_get,
	.curr_entropy = esdm_es_tpm2_entropylevel,
	.max_entropy = esdm_es_tpm2_poolsize,
	.state = esdm_es_tpm2_es_state,
	.reset = NULL,
	.active = esdm_es_tpm2_active,
	.selftest = esdm_es_tpm2_selftest,
};
