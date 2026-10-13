/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "esdm_rpc_client_helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "visibility.h"

struct esdm_get_random_bytes_full_timeout_buf {
	ssize_t ret;
	uint8_t *buf;
	size_t buflen;
};

static void esdm_rpcc_get_random_bytes_full_timeout_cb(
	const RandValResponse *response, void *closure_data)
{
	struct esdm_get_random_bytes_full_timeout_buf *buffer =
		(struct esdm_get_random_bytes_full_timeout_buf *)closure_data;

	esdm_rpcc_error_check(response, buffer);

	if (response->ret < 0) {
		buffer->ret = response->ret;
		return;
	}

	if (!response->randval.data || !response->randval.len) {
		buffer->ret = -EFAULT;
		return;
	}

	buffer->ret = (ssize_t)min_size(response->randval.len, buffer->buflen);
	memcpy(buffer->buf, response->randval.data, (size_t)buffer->ret);

	/* Zeroization of response is handled in esdm_rpc_client_read_handler */
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout_int(uint8_t *buf, size_t buflen,
						    struct timespec *ts,
						    void *int_data)
{
	GetRandomBytesRequest msg = GET_RANDOM_BYTES_REQUEST__INIT;
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	struct esdm_get_random_bytes_full_timeout_buf buffer;
	size_t maxbuflen = buflen, orig_buflen = buflen;
	struct timespec timeout;
	ssize_t ret = 0;

	CKNULL(ts, -EINVAL);

	/*
	 * A relative time, normalized as POSIX has it. Anything else makes a
	 * deadline that pthread_mutex_clocklock() refuses with EINVAL, on
	 * which the lock wrapper aborts the process.
	 */
	if (ts->tv_sec < 0 || ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000) {
		ret = -EINVAL;
		goto out;
	}

	CKINT(clock_gettime(CLOCK_MONOTONIC, &timeout));

	/* Capped at some 34 years, forever here, so the sum cannot overflow */
	timeout.tv_sec +=
		(time_t)min_uint64((uint64_t)ts->tv_sec, INT32_MAX / 2);
	timeout.tv_nsec += ts->tv_nsec;
	if (timeout.tv_nsec >= 1000000000) {
		timeout.tv_sec += timeout.tv_nsec / 1000000000;
		timeout.tv_nsec = timeout.tv_nsec % 1000000000;
	}

	/*
	 * The deadline is a property of this checkout of the connection, not of
	 * the connection: the interrupt function is shared by all users of the
	 * service and inherited by a child forked meanwhile, so replacing it
	 * for the duration of the call would take it away from everybody else
	 * and, in such a child, for good - the int_data of its later calls
	 * then taken for a struct timespec. Both the deadline and the
	 * registered interrupt function, invoked with @int_data, apply.
	 */
	CKINT(esdm_rpcc_get_unpriv_service_deadline(&rpc_conn, int_data,
						    &timeout));

	while (buflen) {
		buffer.ret = -ETIMEDOUT;
		buffer.buf = buf;
		buffer.buflen = buflen;

		/* only perform short waits in server,
		 * as they are blocking termination */
		msg.len = min_size(maxbuflen, buflen);

		unpriv_access__rpc_get_random_bytes_full(
			&rpc_conn->service, &msg,
			esdm_rpcc_get_random_bytes_full_timeout_cb, &buffer);

		/*
		 * The callback only runs once a response was received. When the
		 * request failed before that - no server listening, a refused
		 * or broken connection - buffer.ret still holds the placeholder
		 * set above, which would report every such failure as a
		 * timeout. Report what actually went wrong instead.
		 */
		ret = esdm_rpcc_last_error(rpc_conn);
		if (ret)
			goto out;

		/*
		 * The deadline passing interrupts the request. The write phase
		 * leaves the -ETIMEDOUT placeholder untouched (no closure
		 * call), the read phase invokes the closure with -EINTR. Report
		 * -ETIMEDOUT for both: propagating -EINTR would make the
		 * caller's esdm_invoke() restart the request up to five more
		 * times, each with a fresh deadline. An -EINTR before the
		 * deadline came from the interrupt function and is passed on.
		 */
		if (buffer.ret == -EINTR && esdm_rpcc_deadline_passed(&timeout)) {
			ret = -ETIMEDOUT;
			goto out;
		}

		if (buffer.ret < -255) {
			size_t new_max = (size_t)(-buffer.ret);

			/*
			 * The server signals the largest size it can serve by
			 * returning its negated value, asking us to retry with a
			 * smaller request. Only honor it if it actually shrinks
			 * the request; a buggy or hostile peer returning a
			 * non-shrinking value must not be able to spin this loop
			 * forever.
			 */
			if (new_max >= maxbuflen) {
				ret = -EPROTO;
				goto out;
			}
			maxbuflen = new_max;
			continue;
		} else if (buffer.ret == -EAGAIN) {
			/*
			 * Not seeded yet - wait without holding the connection,
			 * and not beyond the deadline.
			 */
			CKINT(esdm_rpcc_unpriv_service_pause(&rpc_conn, int_data,
							     &timeout));
			continue;
		} else if (buffer.ret < 0) {
			ret = buffer.ret;
			goto out;
		}

		esdm_test_shm_status_add_rpc_client_written((size_t)buffer.ret);
		buflen -= (size_t)buffer.ret;
		buf += buffer.ret;
	}

out:
	esdm_rpcc_put_unpriv_service(rpc_conn);
	return (ret < 0) ? ret : (ssize_t)orig_buflen;
}

DSO_PUBLIC
ssize_t esdm_rpcc_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
						struct timespec *ts)
{
	return esdm_rpcc_get_random_bytes_full_timeout_int(buf, buflen, ts,
							   NULL);
}
