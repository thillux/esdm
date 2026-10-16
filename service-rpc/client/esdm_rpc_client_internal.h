/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_CLIENT_INTERNAL_H
#define ESDM_RPC_CLIENT_INTERNAL_H

#include "config.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include "mutex_w.h"
#include "queue.h"

#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESDM_FUZZING
/**
 * @brief Hand one buffer to the client as if the server had answered with it
 * @param [in] message_desc Message type the client expects in the response
 * @param [in] data Bytes as they would have arrived from the server
 * @param [in] len Number of those bytes
 * @param [in] closure Invoked with the decoded message, as in a real call
 * @param [in] closure_data Opaque pointer handed to @p closure
 * @return 0 on success, < 0 on error - a malformed response is rejected, which
 * 	is the expected outcome
 */
int esdm_rpcc_fuzz_response(const ProtobufCMessageDescriptor *message_desc,
			    const uint8_t *data, size_t len,
			    ProtobufCClosure closure, void *closure_data);
#endif /* ESDM_FUZZING */

enum {
	esdm_rpcc_uninitialized,
	esdm_rpcc_in_initialization,
	esdm_rpcc_initialized,
	esdm_rpcc_in_termination,
};

struct esdm_dtls;

struct esdm_rpc_client_connection {
	ProtobufCService service;
	char socketname[FILENAME_MAX];
	int fd;

	/*
	 * The DTLS of the connection on fd, NULL while it is unencrypted - see
	 * ESDM_RPC_PROTO_STARTDTLS in esdm_rpc_protocol.h. Guarded by lock, as
	 * the socket is.
	 */
	struct esdm_dtls *dtls;

	/*
	 * The DTLS of a connection of the parent, left behind by a fork - see
	 * reinit_conns_after_fork(). Never used, only kept reachable.
	 */
	struct esdm_dtls *dtls_orphan;

	/*
	 * CLOCK_MONOTONIC time in milliseconds before which a new connection is
	 * not to ask for DTLS: the server did not agree to it the last time.
	 * 0 to ask. Guarded by lock.
	 */
	int64_t dtls_retry_ms;

	/*
	 * Caller can register function that is invoked to check whether call
	 * should be interrupted.
	 */
	esdm_rpcc_interrupt_func_t interrupt_func;
	void *interrupt_data;

	/*
	 * Absolute CLOCK_MONOTONIC time after which the requests of the current
	 * checkout are abandoned like an interrupted one, NULL for none. Set by
	 * every checkout together with interrupt_data, so - unlike a swapped
	 * interrupt_func - it never outlives the call that asked for it: not
	 * when the call returns, and not in a child forked meanwhile.
	 */
	const struct timespec *deadline;

	/*
	 * Both are robust mutexes, so a caller killed while owning the
	 * connection does not wedge it for the process' lifetime.
	 *
	 * lock	   - held by esdm_client_invoke() across one request/response
	 *	     exchange. Taken over from a died owner, the socket may sit
	 *	     mid-message and has to be dropped.
	 * ref_cnt - held between get and put, marking the connection checked
	 *	     out. It guards no data, so a takeover needs no recovery.
	 */
	mutex_w_t lock;
	mutex_w_t ref_cnt;
	atomic_int state;

	/*
	 * Getters waiting for ref_cnt. They wait without the connection lock,
	 * so this is what keeps the teardown from destroying the mutex under
	 * them - see esdm_rpcc_get_service().
	 */
	atomic_uint waiters;

	/*
	 * The request/response and unpack scratch buffers are not stored per
	 * connection but per calling thread (see struct esdm_rpcc_tbuf in
	 * esdm_rpc_client.c): they are only ever used during a single
	 * synchronous invoke held by the calling thread, so one buffer set per
	 * thread suffices instead of one per connection. This
	 * bounds the buffer memory by the number of threads issuing RPCs rather
	 * than by the size of the connection pool.
	 */

	/*
	 * Used to track successfull reads from esdm-server.
	 * esdm-server closes idle connections after ESDM_RPC_IDLE_TIMEOUT_USEC.
	 * Only update this, when data is received or on new connections.
	 * Otherwise, we may update on writes without answer and keep
	 * dead connections open for too long.
	 */
	struct timespec last_used;

	/*
	 * Outcome of the most recent esdm_client_invoke() on this connection: 0
	 * on success, a negative errno when the request never reached the server
	 * or no response came back. protobuf-c's invoke() returns void and only
	 * reports through the closure, which is not called at all on a transport
	 * failure - without this, callers can merely observe that and report a
	 * generic error. A connection is owned exclusively by one caller between
	 * get and put, so no further serialization is needed.
	 */
	int last_error;
};

/**
 * @brief Reason why the last RPC on this connection produced no response
 *
 * The RPC wrappers pre-set their closure result to -ETIMEDOUT and only learn
 * that something went wrong from the closure not being invoked; this turns that
 * into the actual reason. -EAGAIN is deliberately not reported: it is how an
 * interruption requested through esdm_rpcc_interrupt_func_t surfaces, for which
 * the callers' own -ETIMEDOUT placeholder is the right answer.
 *
 * @return negative errno describing the failure, 0 if the request reached the
 *	   server (or was interrupted on request of the caller)
 */
static inline int
esdm_rpcc_last_error(const esdm_rpc_client_connection_t *rpc_conn)
{
	int ret = rpc_conn->last_error;

	return (ret < 0 && ret != -EAGAIN) ? ret : 0;
}

/**
 * @brief Has the absolute CLOCK_MONOTONIC time @deadline passed?
 *
 * @return true once the clock reached @deadline, false before and for a NULL
 *	   @deadline
 */
static inline bool esdm_rpcc_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (!deadline)
		return false;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return now.tv_sec > deadline->tv_sec ||
	       (now.tv_sec == deadline->tv_sec &&
		now.tv_nsec >= deadline->tv_nsec);
}

/**
 * @brief Check out an unprivileged connection whose requests end at a deadline
 *
 * As esdm_rpcc_get_unpriv_service, but the requests sent on the connection
 * until it is put back are abandoned once @deadline passed, as if the interrupt
 * function had fired - in addition to whatever that function decides. A
 * checkout that has to wait for a busy connection gives up at @deadline.
 *
 * @param [out] rpc_conn Set to the connection handle to be used
 * @param [in] int_data Opaque data pointer for the interrupt function
 * @param [in] deadline Absolute CLOCK_MONOTONIC time, NULL for none. It must
 *			stay valid until the connection is put back.
 *
 * @return 0 on success, -ETIMEDOUT when @deadline passed while waiting for the
 *	   connection, < 0 on other errors as esdm_rpcc_get_unpriv_service
 */
int esdm_rpcc_get_unpriv_service_deadline(
	esdm_rpc_client_connection_t **rpc_conn, void *int_data,
	const struct timespec *deadline);

/* Sleep time for poll operations */
static const struct timespec esdm_client_poll_ts = { .tv_sec = 1,
						     .tv_nsec = 0 };

/**
 * @brief Wait the poll interval before an unprivileged request is sent again
 *
 * The ESDM answers -EAGAIN as long as it cannot serve a request, which may last
 * until it is seeded. The connection is put back for the wait and checked out
 * anew afterwards - holding it would stall every other caller that needs it
 * for as long, also those that must not block at all, such as a check whether
 * the ESDM is seeded.
 *
 * @param [in,out] rpc_conn The checked out connection, which is put back. Set
 *			    to the connection checked out after the wait, NULL
 *			    when that failed.
 * @param [in] int_data Opaque data pointer for the interrupt function
 * @param [in] deadline Absolute CLOCK_MONOTONIC time of the call, NULL for
 *			none. The wait does not last beyond it, and the new
 *			checkout carries it as well.
 *
 * @return 0 on success, -ETIMEDOUT when @deadline passed, < 0 on other errors
 *	   of esdm_rpcc_get_unpriv_service
 */
int esdm_rpcc_unpriv_service_pause(esdm_rpc_client_connection_t **rpc_conn,
				   void *int_data,
				   const struct timespec *deadline);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_INTERNAL_H */
