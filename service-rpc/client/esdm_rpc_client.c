/* RPC Client: Connection handler to server
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * Before any system header: MUTEX_UNLOCKED_PREFER_WRITER silently falls back
 * to the reader-preferring lock without the glibc extensions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include <stdbool.h>
#include "buffer.h"
#include "config.h"
#include "constructor.h"
#include "conv_be_le.h"
#include "esdm_dtls.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "mutex.h"
#include "memset_secure.h"
#include "ptr_err.h"
#include "ret_checkers.h"
#include "test_pertubation.h"
#include "visibility.h"

struct esdm_rpcc_write_buf {
	ProtobufCBuffer base;
	esdm_rpc_client_connection_t *rpc_conn;
};

/*
 * Per-thread request/response and unpack scratch buffers. An invoke runs
 * entirely in the calling thread while it holds the connection lock, and the
 * buffers are filled, processed and zeroized within that single synchronous
 * call - they never carry state across calls or get touched by another thread.
 * So one buffer set per calling thread suffices instead of one per connection,
 * bounding this memory by the number of RPC-issuing threads rather than by the
 * connection pool size. reqbuf is cast to the protocol header structs, hence
 * the 64-bit alignment.
 *
 * They are allocated on first use rather than declared __thread: glibc carves
 * the TLS of a library loaded at startup out of every thread's stack, and
 * 129 KiB of it broke threads with small stacks in any process linking or
 * preloading this library.
 */
struct esdm_rpcc_tbuf {
	uint8_t reqbuf[ESDM_RPC_MAX_MSG_SIZE]
		__attribute__((aligned(sizeof(uint64_t))));
	/*
	 * Scratch buffer used to unpack a response without a malloc()/free()
	 * round-trip per call; backs the esdm_rpc_alloc() bump allocator.
	 */
	uint8_t unpack_buf[ESDM_RPC_MAX_UNPACK_SIZE];
};

static pthread_key_t esdm_rpcc_tbuf_key;
static pthread_once_t esdm_rpcc_tbuf_once = PTHREAD_ONCE_INIT;
static bool esdm_rpcc_tbuf_key_valid;

/* The buffers are zeroized after every use, freeing them is all that is left */
static void esdm_rpcc_tbuf_free(void *tbuf)
{
	free(tbuf);
}

static void esdm_rpcc_tbuf_key_create(void)
{
	esdm_rpcc_tbuf_key_valid =
		!pthread_key_create(&esdm_rpcc_tbuf_key, esdm_rpcc_tbuf_free);
}

/* The calling thread's buffers, NULL when they cannot be allocated. */
static struct esdm_rpcc_tbuf *esdm_rpcc_tbuf_get(void)
{
	struct esdm_rpcc_tbuf *tbuf;

	pthread_once(&esdm_rpcc_tbuf_once, esdm_rpcc_tbuf_key_create);
	if (!esdm_rpcc_tbuf_key_valid)
		return NULL;

	tbuf = pthread_getspecific(esdm_rpcc_tbuf_key);
	if (tbuf)
		return tbuf;

	tbuf = calloc(1, sizeof(*tbuf));
	if (!tbuf)
		return NULL;
	if (pthread_setspecific(esdm_rpcc_tbuf_key, tbuf)) {
		free(tbuf);
		return NULL;
	}

	return tbuf;
}

/*
 * A library unloaded with dlclose() must not leave its key destructor behind
 * for threads exiting later. Buffers still held by other threads leak then.
 */
ESDM_DEFINE_DESTRUCTOR(esdm_rpcc_tbuf_key_delete)
{
	if (esdm_rpcc_tbuf_key_valid)
		pthread_key_delete(esdm_rpcc_tbuf_key);
}

static void register_fork_handler(void);

/* Wait for one answer, in milliseconds, see esdm_rpc_client_read_handler(). */
#define ESDM_RPCC_RX_POLL_MS                                                   \
	((1 << ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT) / 1000000)

/*
 * How long a privileged request may take to be answered. Its requests are
 * served one at a time by a single server thread and include long running
 * ones - the self test runs all of them -, and none of them may be sent again
 * once it went out: the second RNDADDENTROPY would be credited a second time,
 * a self test that takes longer than the wait would be started over and over.
 * So the answer is waited for, generously, rather than asked for again.
 */
#define ESDM_RPCC_PRIV_RX_TIMEOUT_MS 60000

/*
 * How long an unprivileged request is waited for in total. An answer that did
 * not come in time is asked for again on a new connection - which may well be
 * served by another, less busy, server thread - until this time is up, so a
 * wedged server does not keep its caller forever. No new submission starts
 * after it, an ongoing one still waits for its answer.
 *
 * Both are fixed times rather than multiples of ESDM_RPCC_RX_POLL_MS: with the
 * shortest client-rx-tx-timeout-exponent a poll lasts a millisecond, and a
 * budget counted in polls would let a caller fail behind a single request the
 * server takes a little longer for.
 */
#define ESDM_RPCC_RX_TIMEOUT_MS 6400

/* How long one submission of an unprivileged request waits for its answer. */
#define ESDM_RPCC_RX_SUBMISSION_MS 1600

/*
 * Forget the connection's socket. Only the descriptor is closed unless
 * @shut_down asks for the connection itself to be torn down, which also ends it
 * for every other process holding a copy of the descriptor.
 */
static void drop_conn_socket(esdm_rpc_client_connection_t *rpc_conn,
			     bool shut_down)
{
	if (rpc_conn == NULL) {
		return;
	}

	/*
	 * The DTLS goes with the socket it refers to. Nothing is sent for it -
	 * no closing alert, the server sees the connection closed as it does
	 * in the clear.
	 */
	esdm_dtls_free(rpc_conn->dtls);
	rpc_conn->dtls = NULL;

	if (rpc_conn->fd >= 0) {
		if (shut_down)
			shutdown(rpc_conn->fd, SHUT_RDWR);
		close(rpc_conn->fd);
	}
	rpc_conn->fd = -1;
	memset(&rpc_conn->last_used, 0, sizeof(rpc_conn->last_used));
}

static void reset_conn_socket(esdm_rpc_client_connection_t *rpc_conn)
{
	drop_conn_socket(rpc_conn, true);
}

static void esdm_fini_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	ProtobufCService *service;

	if (!rpc_conn)
		return;

	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}

	service = &rpc_conn->service;
	if (service->descriptor) {
		protobuf_c_service_destroy(service);
		service->descriptor = NULL;
	}

	mutex_w_destroy(&rpc_conn->lock);
	mutex_w_destroy(&rpc_conn->ref_cnt);
}

/*
 * Shall the request on @rpc_conn be abandoned? Either the caller's interrupt
 * function says so for the data the connection was checked out with, or the
 * deadline of that checkout passed.
 */
static bool esdm_rpcc_interrupted(const esdm_rpc_client_connection_t *rpc_conn)
{
	if (rpc_conn->interrupt_func &&
	    rpc_conn->interrupt_func(rpc_conn->interrupt_data))
		return true;

	return esdm_rpcc_deadline_passed(rpc_conn->deadline);
}

/* Open a connection to the server, in the clear. */
static int esdm_rpcc_open(esdm_rpc_client_connection_t *rpc_conn)
{
	const char *socketname = rpc_conn->socketname;
	struct timespec ts = {
		.tv_sec = 0,
		.tv_nsec = 1U << (ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT)
	};
	struct stat statbuf;
	struct sockaddr_un addr;
	unsigned int attempts = 0;
	int errsv;

	/* defensive check, detected by modern compilers if missing */
	if (socketname == NULL) {
		return -EFAULT;
	}

	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}

	/* Does the path exist? */
	if (stat(socketname, &statbuf) == -1) {
		errsv = errno;

		if (errsv == ENOENT) {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
				    "ESDM server interface %s not available\n",
				    socketname);
		}

		return -errsv;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Attempting to access ESDM server interface %s\n",
		    socketname);

	/* Connect to the Unix domain socket */
	addr.sun_family = AF_UNIX;

	if (strlen(socketname) >= sizeof(addr.sun_path)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Socket path too long: %s\n", socketname);
		return -ENAMETOOLONG;
	}
	memset(addr.sun_path, 0, sizeof(addr.sun_path));
	memcpy(addr.sun_path, socketname, strlen(socketname));

	/*
	 * The use of SOCK_SEQPACKET is intended to guarantee that the entire
	 * message is sent and that the receiving server will only receive
	 * the full message. Short reads will therefore not happen on the server
	 * side.
	 */
	rpc_conn->fd = socket(addr.sun_family,
			      SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (rpc_conn->fd < 0) {
		errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Error creating socket: %s\n", strerror(errsv));

		reset_conn_socket(rpc_conn);

		return -errsv;
	}

	do {
		/*
		 * If we have another attempt, try to wait a bit - unless the
		 * caller wants us to stop. The attempts add up to seconds, e.g.
		 * while a stale socket file refuses every connection, and the
		 * deadline of a timed call as well as the interrupt function
		 * would otherwise be ignored for as long. The error of the
		 * last attempt is what is reported then.
		 */
		if (attempts) {
			if (esdm_rpcc_interrupted(rpc_conn))
				break;
			nanosleep(&ts, NULL);
		}

		if (connect(rpc_conn->fd, (struct sockaddr *)&addr,
			    sizeof(addr)) < 0) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Error connecting socket: %s\n",
				    strerror(errsv));
			attempts++;
		} else {
			errsv = 0;
		}
	} while (attempts < (ESDM_CLIENT_RECONNECT_ATTEMPTS) &&
		 (errsv == EAGAIN || errsv == ECONNREFUSED || errsv == EINTR ||
		  errsv == EINPROGRESS));

	if (errsv || attempts >= ESDM_CLIENT_RECONNECT_ATTEMPTS) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Connection attempt using socket %s failed\n",
			    socketname);
		reset_conn_socket(rpc_conn);
	} else {
		/* only update this time on a successful connection */
		clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
	}

	return -errsv;
}

/* CLOCK_MONOTONIC in milliseconds */
static int64_t esdm_rpcc_now_ms(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return (int64_t)now.tv_sec * 1000LL + (int64_t)now.tv_nsec / 1000000LL;
}

#ifdef ESDM_DTLS

/*
 * How long a new connection may take to agree on DTLS and do the handshake -
 * the answers to STARTDTLS and the probe, and the handshake, see
 * ESDM_RPC_PROTO_STARTDTLS in esdm_rpc_protocol.h. The server answers them as
 * any request, and handshakes put off for its other clients are taken in its
 * next round. A server that did not get through in this time is used in the
 * clear, on a new connection.
 */
#define ESDM_RPCC_DTLS_TIMEOUT_MS 1000

/*
 * How long a connection whose server did not agree to DTLS goes without asking
 * again. The answer of a server stays the same until it is restarted, and
 * asking costs a round trip - with a server not knowing STARTDTLS, which closes
 * the connection on it, a second connection.
 */
#define ESDM_RPCC_DTLS_RETRY_MS 60000

/*
 * The DTLS context of the client side, one for the process. It is set up for
 * the first connection whose server agrees to DTLS - setting up the TLS stack
 * takes a few milliseconds, which a process talking to a server refusing it
 * is spared - and kept for the lifetime of the process: a call of another
 * thread may use it at any time, and the TLS stack keeps state of its own for
 * good as well. Should it not be set up, the connections go on in the clear,
 * not asking any more.
 */
static struct esdm_dtls_ctx *esdm_rpcc_dtls_ctx = NULL;
static atomic_bool esdm_rpcc_dtls_ctx_failed = false;
static pthread_mutex_t esdm_rpcc_dtls_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

static struct esdm_dtls_ctx *esdm_rpcc_dtls_ctx_get(void)
{
	struct esdm_dtls_ctx *ctx;

	pthread_mutex_lock(&esdm_rpcc_dtls_ctx_lock);
	if (!esdm_rpcc_dtls_ctx && !atomic_load(&esdm_rpcc_dtls_ctx_failed)) {
		int ret = esdm_dtls_ctx_alloc(false, &esdm_rpcc_dtls_ctx);

		if (ret) {
			atomic_store(&esdm_rpcc_dtls_ctx_failed, true);
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_RPC,
				"DTLS cannot be set up, connecting to the ESDM unencrypted: %s\n",
				strerror(-ret));
		}
	}
	ctx = esdm_rpcc_dtls_ctx;
	pthread_mutex_unlock(&esdm_rpcc_dtls_ctx_lock);

	return ctx;
}

/* Index of the probe method of the interface of @rpc_conn */
static uint32_t
esdm_rpcc_dtls_probe_index(const esdm_rpc_client_connection_t *rpc_conn)
{
	const ProtobufCServiceDescriptor *desc = rpc_conn->service.descriptor;
	const ProtobufCMethodDescriptor *method =
		protobuf_c_service_descriptor_get_method_by_name(
			desc, desc == &priv_access__descriptor ?
				      ESDM_RPC_PROTO_STARTDTLS_PROBE_PRIV :
				      ESDM_RPC_PROTO_STARTDTLS_PROBE);

	return (uint32_t)(method - desc->methods);
}

/*
 * Wait for the connection to become readable, until @end_ms on the clock of
 * esdm_rpcc_now_ms(). It is waited for in slices of the poll interval of an
 * answer, checking for an interruption between them as a request does.
 *
 * @return 0 to look again, -EAGAIN when the caller asked to stop, -ETIMEDOUT
 *	   at @end_ms, another negative errno if the poll failed
 */
static int esdm_rpcc_dtls_wait(esdm_rpc_client_connection_t *rpc_conn,
			       int64_t end_ms)
{
	struct pollfd pfd = { .fd = rpc_conn->fd, .events = POLLIN };
	int64_t left;

	if (esdm_rpcc_interrupted(rpc_conn))
		return -EAGAIN;

	left = end_ms - esdm_rpcc_now_ms();
	if (left <= 0)
		return -ETIMEDOUT;
	if (left > ESDM_RPCC_RX_POLL_MS)
		left = ESDM_RPCC_RX_POLL_MS;

	if (poll(&pfd, 1, (int)left) < 0 && errno != EINTR)
		return -errno;

	return 0;
}

/* The answer of a server agreeing to STARTDTLS */
struct esdm_rpcc_dtls_accept {
	struct esdm_rpc_proto_sc_header header;
	uint32_t magic;
} __attribute__((packed));

/*
 * Receive the next answer in the clear into @sc, as much of it as the
 * acceptance of STARTDTLS has, discarding the rest of its message. @len
 * receives the size of the whole message.
 *
 * @return 0 or a negative errno - -ECONNRESET if the server closed the
 *	   connection, others as esdm_rpcc_dtls_wait()
 */
static int esdm_rpcc_dtls_answer(esdm_rpc_client_connection_t *rpc_conn,
				 struct esdm_rpcc_dtls_accept *sc, size_t *len,
				 int64_t end_ms)
{
	for (;;) {
		/* MSG_TRUNC: the size of the message, if larger */
		ssize_t n = recv(rpc_conn->fd, sc, sizeof(*sc),
				 MSG_DONTWAIT | MSG_TRUNC);
		int ret;

		if (n == 0)
			return -ECONNRESET;
		if (n > 0) {
			if ((size_t)n < sizeof(sc->header))
				return -EPROTO;

			sc->header.status_code =
				le_bswap32(sc->header.status_code);
			sc->header.method_index =
				le_bswap32(sc->header.method_index);
			sc->header.message_length =
				le_bswap32(sc->header.message_length);
			sc->header.request_id =
				le_bswap32(sc->header.request_id);
			sc->magic = le_bswap32(sc->magic);
			*len = (size_t)n;

			return 0;
		}
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			return -errno;

		ret = esdm_rpcc_dtls_wait(rpc_conn, end_ms);
		if (ret)
			return ret;
	}
}

/* Send a request header alone, in the clear */
static int esdm_rpcc_dtls_request(esdm_rpc_client_connection_t *rpc_conn,
				  uint32_t method_index, uint32_t request_id)
{
	struct esdm_rpc_proto_cs_header cs = {
		.method_index = le_bswap32(method_index),
		.message_length = 0,
		.request_id = le_bswap32(request_id),
	};
	/* A new connection has room for its first two messages */
	ssize_t n = send(rpc_conn->fd, &cs, sizeof(cs),
			 MSG_DONTWAIT | MSG_NOSIGNAL);

	if (n < 0)
		return -errno;

	return n == (ssize_t)sizeof(cs) ? 0 : -EIO;
}

/*
 * Ask the server for DTLS on the connection just opened, and do the handshake
 * if it agrees - see ESDM_RPC_PROTO_STARTDTLS in esdm_rpc_protocol.h.
 *
 * @return 0 when the connection is encrypted now; -EOPNOTSUPP when it goes on in
 *	   the clear; -EAGAIN when the caller asked to stop, the connection is gone
 *	   then; another negative errno when the connection is gone - the server
 *	   closed it, did not answer in time, or the handshake failed
 */
static int esdm_rpcc_startdtls(esdm_rpc_client_connection_t *rpc_conn)
{
	const uint32_t probe = esdm_rpcc_dtls_probe_index(rpc_conn);
	const int64_t end_ms = esdm_rpcc_now_ms() + ESDM_RPCC_DTLS_TIMEOUT_MS;
	struct esdm_rpcc_dtls_accept sc;
	struct esdm_dtls_ctx *ctx;
	struct esdm_dtls *dtls = NULL;
	bool accepted;
	size_t len;
	int ret;

	/* The probe right behind STARTDTLS, without waiting for its answer */
	CKINT(esdm_rpcc_dtls_request(rpc_conn, ESDM_RPC_PROTO_STARTDTLS,
				     ESDM_RPC_PROTO_STARTDTLS));
	CKINT(esdm_rpcc_dtls_request(rpc_conn, probe, 0));

	CKINT(esdm_rpcc_dtls_answer(rpc_conn, &sc, &len, end_ms));

	/*
	 * The probe answered first: a server leaving STARTDTLS unanswered. The
	 * answers are matched by order, and none is outstanding.
	 */
	if (sc.header.method_index == probe) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "STARTDTLS left unanswered by the server\n");
		return -EOPNOTSUPP;
	}

	if (sc.header.method_index != ESDM_RPC_PROTO_STARTDTLS) {
		ret = -EPROTO;
		goto out;
	}

	/* Anything else is a server not switching */
	accepted =
		(sc.header.status_code == PROTOBUF_C_RPC_STATUS_CODE_SUCCESS &&
		 len == sizeof(sc) &&
		 sc.header.message_length == sizeof(sc.magic) &&
		 sc.header.request_id == ESDM_RPC_PROTO_STARTDTLS &&
		 sc.magic == ESDM_RPC_PROTO_STARTDTLS);

	/* The answer to the probe, of no interest beyond its coming */
	CKINT(esdm_rpcc_dtls_answer(rpc_conn, &sc, &len, end_ms));
	if (sc.header.method_index != probe) {
		ret = -EPROTO;
		goto out;
	}

	if (!accepted)
		return -EOPNOTSUPP;

	/* The server waits for the handshake now, whatever comes */
	ctx = esdm_rpcc_dtls_ctx_get();
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}
	CKINT(esdm_dtls_alloc(ctx, rpc_conn->fd, ESDM_RPC_MAX_MSG_SIZE, &dtls));

	for (;;) {
		ret = esdm_dtls_handshake(dtls);
		if (ret != -EAGAIN)
			break;

		CKINT(esdm_rpcc_dtls_wait(rpc_conn, end_ms));
	}
	if (ret)
		goto out;

	rpc_conn->dtls = dtls;
	dtls = NULL;

out:
	if (ret) {
		esdm_dtls_free(dtls);
		reset_conn_socket(rpc_conn);
	}
	return ret;
}

#endif /* ESDM_DTLS */

/*
 * Open a connection to the server - encrypted if it can be, in the clear if
 * not, see ESDM_RPC_PROTO_STARTDTLS in esdm_rpc_protocol.h.
 *
 * Asking for DTLS can take up to ESDM_RPCC_DTLS_TIMEOUT_MS on top of the
 * connection. It ends early as the request does when the caller asks to stop,
 * which is the -EAGAIN of an interrupted request - nothing of the request has
 * gone out yet then.
 */
static int esdm_connect_proto_service(esdm_rpc_client_connection_t *rpc_conn)
{
	int ret = esdm_rpcc_open(rpc_conn);

	if (ret)
		return ret;

#ifdef ESDM_DTLS
	if (esdm_rpcc_now_ms() >= rpc_conn->dtls_retry_ms &&
	    !atomic_load(&esdm_rpcc_dtls_ctx_failed)) {
		ret = esdm_rpcc_startdtls(rpc_conn);
		if (ret == -EAGAIN)
			return ret;

		/* Opportunistic as the DTLS is, the server is used in the clear */
		if (ret) {
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_RPC,
				"No DTLS with ESDM server interface %s: %s\n",
				rpc_conn->socketname,
				ret == -EOPNOTSUPP ? "not offered" :
						     strerror(-ret));
			rpc_conn->dtls_retry_ms =
				esdm_rpcc_now_ms() + ESDM_RPCC_DTLS_RETRY_MS;
		}

		/* The connection is gone unless the server just refused */
		if (ret && ret != -EOPNOTSUPP) {
			ret = esdm_rpcc_open(rpc_conn);
			if (ret)
				return ret;
		}
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Connected to ESDM server interface %s %s%s\n",
		    rpc_conn->socketname,
		    rpc_conn->dtls ? "with DTLS " : "unencrypted",
		    rpc_conn->dtls ? esdm_dtls_cipher(rpc_conn->dtls) : "");
#endif

	return 0;
}

static int esdm_rpc_client_write_data_fd(esdm_rpc_client_connection_t *rpc_conn,
					 const uint8_t *data, size_t len)
{
	static const int CLIENT_TX_TIMEOUT_MS =
		(1 << ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT) / 1000000;
	unsigned int retries = 0;
	int pret, err = -EIO;
	ssize_t ret;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	do {
		/* Does the caller wants us to interrupt? */
		if (esdm_rpcc_interrupted(rpc_conn))
			return -EAGAIN;

		retries++;

		if (rpc_conn->dtls) {
			int rc = esdm_dtls_send(rpc_conn->dtls, data, len);

			if (!rc) {
				esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY,
					    "%zu bytes written encrypted\n",
					    len);
				return 0;
			}

			/*
			 * The server has none of the request unless it has
			 * all of it: a request is served once its last record
			 * is in, and that one did not go out. Whatever the
			 * reason - the server went away as with EPIPE below, or
			 * its socket is full -, the connection is of no use any
			 * more, as the DTLS cannot take up a message cut short.
			 * The request goes out on a new one, which is safe for
			 * a privileged request as well.
			 */
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_RPC,
				"Encrypted write failed (%s), reconnecting\n",
				strerror(-rc));
			err = rc;
			ret = -1;
			reset_conn_socket(rpc_conn);
			rc = esdm_connect_proto_service(rpc_conn);
			if (rc)
				return rc;
			continue;
		}

		/*
		 * Only a poll timeout of this very attempt counts - a stale
		 * one would divert a later EPIPE from the reconnect below.
		 */
		pret = -1;
		ret = write(rpc_conn->fd, data, len);
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pfd = { .fd = rpc_conn->fd,
					      .events = POLLOUT };

			pret = poll(&pfd, 1, CLIENT_TX_TIMEOUT_MS);
			/* data available before timeout? */
			if (pret > 0) {
				continue;
			}
			if (pret < 0 && errno == EINTR) {
				continue;
			}
		}

		if (ret < 0) {
			int errsv = errno;

			/*
			 * EPIPE is due to the server was restarted -> reconnect
			 */
			if (pret == 0) {
				err = -ETIMEDOUT;
				continue;
			}

			if (errsv == EPIPE) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Connection to server needs to be re-established\n");

				err = -EPIPE;
				reset_conn_socket(rpc_conn);
				int rc = esdm_connect_proto_service(rpc_conn);
				if (rc)
					return rc;
				continue;
			}

			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Writing of data to file descriptor %d failed: %s\n",
				rpc_conn->fd, strerror(errsv));

			return -errsv;
		}
	} while (ret < 0 && retries <= ESDM_MAX_RX_TX_RETRIES);

	/* The retries ran out: report why the last one failed */
	if (ret < 0)
		return err;

	/*
	 * SOCK_SEQPACKET guarantees atomic messages - a short write is a
	 * protocol violation, not a partial transfer to be retried.
	 */
	if (ret != (ssize_t)len) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_RPC,
			"Partial write on SEQPACKET socket: %zd of %zu bytes on fd %d\n",
			ret, len, rpc_conn->fd);
		return -EIO;
	}
	esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n", len);

	return 0;
}

/*
 * Implementation of packing data and sending it out. Properties:
 *
 * - one call to write data out to the file descriptor
 *
 * - one more copy of entire data required to linearize all data
 */
static int esdm_rpc_client_pack(const ProtobufCMessage *message,
				unsigned int method_index,
				esdm_rpc_client_connection_t *rpc_conn,
				struct esdm_rpcc_tbuf *tbuf)
{
#define ESDM_RPCC_BUF_WRITE_HEADER_SZ (sizeof(struct esdm_rpc_proto_cs_header))

	size_t message_length;
	int ret;
	struct esdm_rpc_proto_cs_header *cs_header;
	struct esdm_rpc_write_data_buf tmp = {
		.dst_len = sizeof(tbuf->reqbuf) - ESDM_RPCC_BUF_WRITE_HEADER_SZ,
		.dst_written = 0,
	};

	tmp.base.append = esdm_rpc_append_data;

	message_length = protobuf_c_message_get_packed_size(message);
	if (message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Unexpected message length: %zu\n", message_length);
		return -EMSGSIZE;
	}

	tmp.dst_buf = tbuf->reqbuf + ESDM_RPCC_BUF_WRITE_HEADER_SZ;

	cs_header = (struct esdm_rpc_proto_cs_header *)tbuf->reqbuf;
	cs_header->method_index = le_bswap32(method_index);
	cs_header->message_length = le_bswap32(message_length);
	cs_header->request_id = le_bswap32(0);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Client sending: message length %u, message index %u, request ID %u\n",
		cs_header->message_length, cs_header->method_index,
		cs_header->request_id);

	if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
	    message_length) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Short write of data to file descriptor \n");
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(esdm_rpc_client_write_data_fd(rpc_conn, tbuf->reqbuf,
						ESDM_RPCC_BUF_WRITE_HEADER_SZ +
							message_length),
		  "Submission of message data failed with error %d\n", ret);

out:
	/*
	 * Zeroization only here is not sufficient.
	 * Make sure to enable zeroize on alloc and free in your Linux kernel
	 * and clear data from ESDM in your application or patch
	 * ESDM to include a cryptographic tunnel to your application.
	 */
	memset_secure(tbuf->reqbuf, 0,
		      message_length + ESDM_RPCC_BUF_WRITE_HEADER_SZ);
	return ret;
}

/*
 * Receive a message on the encrypted connection into @buf of @len bytes,
 * waiting for at most @timeout_ms for it to complete.
 *
 * Unlike a message in the clear, an answer may arrive in several records, one
 * after the other, each waking the poll below. They count as one wait, so a
 * large answer does not use up the waits of the caller - and a server sending
 * records forever cannot keep the caller beyond @timeout_ms either.
 *
 * @return the size of the message, -EAGAIN when it did not complete in that
 *	   time, another negative errno when the connection is of no use any more
 *	   - -ECONNRESET if the server closed it
 */
static ssize_t esdm_rpcc_dtls_recv(esdm_rpc_client_connection_t *rpc_conn,
				   uint8_t *buf, size_t len, int timeout_ms)
{
	const int64_t end_ms = esdm_rpcc_now_ms() + timeout_ms;

	for (;;) {
		struct pollfd pfd = { .fd = rpc_conn->fd, .events = POLLIN };
		ssize_t n = esdm_dtls_recv(rpc_conn->dtls, buf, len);
		int64_t left;

		if (n != -EAGAIN)
			return n;

		left = end_ms - esdm_rpcc_now_ms();
		if (left <= 0)
			return -EAGAIN;

		/* A record the DTLS holds already is not signalled any more */
		if (esdm_dtls_pending(rpc_conn->dtls))
			continue;

		if (poll(&pfd, 1, (int)left) < 0 && errno != EINTR)
			return -errno;
	}
}

/*
 * Receive the answer, waiting for at most @max_retries rounds of
 * ESDM_RPCC_RX_POLL_MS. Returns -EAGAIN when it did not come in that time.
 */
static int
esdm_rpc_client_read_handler(esdm_rpc_client_connection_t *rpc_conn,
			     struct esdm_rpcc_tbuf *tbuf,
			     const ProtobufCMessageDescriptor *message_desc,
			     ProtobufCClosure closure, void *closure_data,
			     unsigned int max_retries)
{
	static const int CLIENT_RX_TIMEOUT_MS = ESDM_RPCC_RX_POLL_MS;
	struct esdm_rpc_proto_sc *received_data;
	struct esdm_rpc_proto_sc_header *header = NULL;
	/*
	 * Must start at 0: the interrupt check below can break out of the read
	 * loop before the first read() ever runs, and the zeroization at out:
	 * uses this as the length of the data to wipe.
	 */
	ssize_t received = 0;
	unsigned int retries = 0;
	int ret = 0;
	int pret, errsv;
	bool interrupted = false;

	if (rpc_conn->fd < 0)
		return -EINVAL;

	/* The cast is appropriate as the buffer is aligned to 64 bits. */
	received_data = (struct esdm_rpc_proto_sc *)tbuf->reqbuf;

	/* Read the data into the local buffer storage */
	do {
		/* Does the caller wants us to interrupt? */
		if (esdm_rpcc_interrupted(rpc_conn)) {
			interrupted = true;
			break;
		}

		retries++;

		if (rpc_conn->dtls) {
			received = esdm_rpcc_dtls_recv(rpc_conn, tbuf->reqbuf,
						       sizeof(tbuf->reqbuf),
						       CLIENT_RX_TIMEOUT_MS);

			/* One round of waiting, as a poll timeout below */
			if (received == -EAGAIN) {
				received = -1;
				continue;
			}

			/*
			 * The DTLS is of no use after an error, and nor is the
			 * connection - a message too large included, which the
			 * DTLS refuses rather than reading it partly. A socket
			 * failing is -EIO to the DTLS, which is what the read
			 * in the clear below sees as the connection reset by
			 * the server - one closing it with the request unread,
			 * as when it reaps it as idle just as the request goes
			 * out.
			 */
			if (received < 0) {
				ret = received == -EIO ? -ECONNRESET :
							 (int)received;
				received = 0;
				esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
					    "Encrypted read failed: %s\n",
					    strerror(-ret));
				reset_conn_socket(rpc_conn);
				break;
			}

			goto received;
		}

		/*
		 * The server uses SOCK_SEQPACKET which ensures that always the
		 * full message is submitted in one send operation. Therefore,
		 * short-reads cannot occur here and can be ignored.
		 */
		received = read(rpc_conn->fd, tbuf->reqbuf,
				sizeof(tbuf->reqbuf));

		/*
		 * Only a poll timeout of this very read keeps the wait going -
		 * any other read error is reported as it is, not as a timeout
		 * once the retry budget is spent.
		 */
		pret = -1;
		errsv = errno;
		if (received < 0 && (errsv == EAGAIN || errsv == EWOULDBLOCK)) {
			struct pollfd pfd = { .fd = rpc_conn->fd,
					      .events = POLLIN };

			pret = poll(&pfd, 1, CLIENT_RX_TIMEOUT_MS);
			/* data available before timeout? */
			if (pret > 0) {
				continue;
			}
			if (pret < 0) {
				errsv = errno;
				if (errsv == EINTR)
					continue;
			}
		} else if (received < 0 && errsv == EINTR) {
			continue;
		}

		/* Handle a read timeout */
		if (received < 0) {
			if (pret == 0) {
				/*
				 * Keep waiting rather than asking again. The
				 * request is already at the server - a connected
				 * SOCK_SEQPACKET socket cannot lose it - and it
				 * answers everything it accepted. Re-sending
				 * would produce the answer twice and leave the
				 * first one queued as the reply to the next
				 * call, as responses are matched by order. The
				 * retry budget bounds the wait; whether the
				 * request is sent again once it is exhausted is
				 * up to the caller.
				 */
				continue;
			}

			ret = -errsv;
			esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
				    "Read failed: %s\n", strerror(errsv));
			break;
		}

	received:
		/*
		 * The server closed the connection, e.g. reaping it as idle
		 * just as this request went out. No answer can come any more.
		 */
		if (received == 0) {
			ret = -ECONNRESET;
			break;
		}

		if (received < (ssize_t)sizeof(*header))
			continue;

		header = &received_data->header;

		/* Convert incoming data to LE */
		header->status_code = le_bswap32(header->status_code);
		header->message_length = le_bswap32(header->message_length);
		header->method_index = le_bswap32(header->method_index);
		header->request_id = le_bswap32(header->request_id);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_RPC,
			"Client received: server status %u, message length %u, message index %u, request ID %u\n",
			header->status_code, header->message_length,
			header->method_index, header->request_id);

		/*
		 * Reject if the server specified too much buffer
		 * data. As the server also checks this, it is a
		 * clear protocol violation.
		 */
		if (header->message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
			ret = -EOVERFLOW;
			break;
		}

		if (received <
		    (ssize_t)(sizeof(struct esdm_rpc_proto_sc_header) +
			      header->message_length)) {
			ret = -EPROTO;
			break;
		}
	} while (received <= 0 && retries <= max_retries);

	/*
	 * The answer never came within the whole budget. The caller resets the
	 * connection before anything else goes out on it, so the answer to the
	 * abandoned request cannot turn up later and be taken for the next one.
	 */
	if (!interrupted && received < 0 && !ret)
		ret = -EAGAIN;

	/*
	 * Nothing is decoded unless the header checked out: the loop above
	 * leaves a rejected response behind with its error in ret, and its
	 * message length is then a number the server sent rather than one the
	 * receive buffer holds.
	 */
	if (!interrupted && !ret && header &&
	    header->status_code == PROTOBUF_C_RPC_STATUS_CODE_SUCCESS) {
		/*
		 * We now have a filled buffer that has a header and received
		 * as much data as the header defined. We also start the
		 * processing of data which returns it to the caller.
		 */
		if (esdm_rpc_is_fast_bytes_response(message_desc)) {
			/*
			 * Zero-copy fast path for the random responses:
			 * decode the (ret, randval) message in place so
			 * randval.data points straight into the receive buffer.
			 * The closure then performs the single mandatory copy
			 * into the caller's buffer - avoiding the extra copy and
			 * allocation that a full unpack would incur. The receive
			 * buffer (and thus the payload) is zeroized at out:.
			 */
			RandValResponse resp =
				RAND_VAL_RESPONSE__INIT;
			const uint8_t *payload;
			size_t payload_len;
			int64_t retval;

			if (!esdm_rpc_decode_bytes_response(
				    received_data->data, header->message_length,
				    &retval, &payload, &payload_len)) {
				resp.base.descriptor = message_desc;
				resp.ret = retval;
				resp.randval.data = (uint8_t *)payload;
				resp.randval.len = payload_len;
				closure((ProtobufCMessage *)&resp, closure_data);
			} else {
				esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
					    "Response message could not be decoded\n");
				closure(ERR_PTR(-EPROTO), closure_data);
			}
		} else {
			/*
			 * Unpack into a per-thread scratch buffer via a bump
			 * allocator instead of malloc()/free(). This avoids a
			 * heap allocation per call and lets us reliably zeroize
			 * the unpacked copy afterwards - the default allocator's
			 * free() would otherwise leave it in the heap unscrubbed.
			 */
			struct buffer tlh = {
				.len = sizeof(tbuf->unpack_buf),
				.consumed = 0,
				.buf = tbuf->unpack_buf,
			};
			ProtobufCAllocator allocator = {
				.alloc = esdm_rpc_alloc,
				.free = esdm_rpc_free,
				.allocator_data = &tlh,
			};
			ProtobufCMessage *msg = protobuf_c_message_unpack(
				message_desc, &allocator, header->message_length,
				received_data->data);
			if (msg) {
				closure(msg, closure_data);
				protobuf_c_message_free_unpacked(msg, &allocator);
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Data with length %u send to client closure handler\n",
					header->message_length);
			} else {
				esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
					    "Response message not found\n");
				msg = ERR_PTR(-EFAULT);
				closure(msg, closure_data);
			}
			if (tlh.consumed)
				memset_secure(tbuf->unpack_buf, 0,
					      tlh.consumed);
		}
		clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
	} else if (interrupted) {
		const bool privileged = (rpc_conn->service.descriptor ==
					 &priv_access__descriptor);
		ProtobufCMessage *msg;

		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Request interrupted\n");

		/*
		 * The request is at the server and it answers everything it
		 * accepted, so the answer to the request just abandoned is
		 * still to come.
		 */
		reset_conn_socket(rpc_conn);

		/*
		 * And the server may well apply it. -EINTR invites the caller
		 * to send it again, as esdm_invoke() does, which a privileged
		 * request must never be - see esdm_client_invoke().
		 */
		msg = ERR_PTR(privileged ? -EINPROGRESS : -EINTR);
		closure(msg, closure_data);
	} else if (!ret) {
		/*
		 * An answer, but a failure status or less than a header. No
		 * answer at all (ret < 0) is no case for the closure: the
		 * caller resubmits or reports it through last_error, and a
		 * result set here would outlive a resubmission that fails.
		 */
		ProtobufCMessage *msg;

		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Server returned with an error\n");
		msg = ERR_PTR(-EPROTO);
		closure(msg, closure_data);
	}

	if (received > 0) {
		memset_secure(tbuf->reqbuf, 0, (size_t)received);
	}
	return ret;
}

#ifdef ESDM_FUZZING
/* Documented with its declaration in esdm_rpc_client_internal.h */
int esdm_rpcc_fuzz_response(const ProtobufCMessageDescriptor *message_desc,
			    const uint8_t *data, size_t len,
			    ProtobufCClosure closure, void *closure_data)
{
	esdm_rpc_client_connection_t rpc_conn;
	struct esdm_rpcc_tbuf *tbuf;
	int sockets[2];
	int ret;

	if (!message_desc || (len && !data))
		return -EINVAL;

	/*
	 * The type and the non-blocking mode of a real client connection - a
	 * message is delivered whole or not at all, and the read path handles
	 * its own waiting.
	 */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) < 0)
		return -errno;

	if (write(sockets[1], data, len) != (ssize_t)len) {
		ret = -EIO;
		goto out;
	}

	if (set_fd_nonblocking(sockets[0])) {
		ret = -EBADF;
		goto out;
	}

	tbuf = esdm_rpcc_tbuf_get();
	if (!tbuf) {
		ret = -ENOMEM;
		goto out;
	}

	memset(&rpc_conn, 0, sizeof(rpc_conn));
	rpc_conn.fd = sockets[0];

	ret = esdm_rpc_client_read_handler(&rpc_conn, tbuf, message_desc,
					   closure, closure_data,
					   ESDM_MAX_RX_TX_RETRIES);

out:
	close(sockets[0]);
	close(sockets[1]);

	return ret;
}
#endif /* ESDM_FUZZING */

/* Milliseconds passed since @start on CLOCK_MONOTONIC. */
static int64_t esdm_rpcc_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return ((int64_t)now.tv_sec - (int64_t)start->tv_sec) * 1000LL +
	       ((int64_t)now.tv_nsec - (int64_t)start->tv_nsec) / 1000000LL;
}

static void esdm_client_invoke(ProtobufCService *service,
			       unsigned int method_index,
			       const ProtobufCMessage *input,
			       ProtobufCClosure closure, void *closure_data)
{
	const ProtobufCServiceDescriptor *desc = service->descriptor;
	const ProtobufCMethodDescriptor *method = desc->methods + method_index;
	esdm_rpc_client_connection_t *rpc_conn =
		(esdm_rpc_client_connection_t *)service;
	static const int64_t half_server_timeout_ns =
		(int64_t)ESDM_RPC_IDLE_TIMEOUT_USEC * 1000 / 2;
	/* See ESDM_RPCC_PRIV_RX_TIMEOUT_MS and ESDM_RPCC_RX_TIMEOUT_MS */
	const bool privileged = (desc == &priv_access__descriptor);
	const unsigned int rx_retries =
		privileged ?
			ESDM_RPCC_PRIV_RX_TIMEOUT_MS / ESDM_RPCC_RX_POLL_MS :
			max_uint32(ESDM_MAX_RX_TX_RETRIES,
				   ESDM_RPCC_RX_SUBMISSION_MS /
					   ESDM_RPCC_RX_POLL_MS);
	struct esdm_rpcc_tbuf *tbuf = esdm_rpcc_tbuf_get();
	struct timespec current_time, start_time;
	int64_t used_before_ns;
	bool reconnected = false;
	int ret;

	/*
	 * EOWNERDEAD means the lock was taken over from a thread that died mid
	 * request. The lock is consistent again, the connection is not: a
	 * partial request or an unconsumed response desynchronizes every later
	 * request, as responses are matched by order. Drop the socket so the
	 * loop below establishes a fresh one.
	 */
	if (mutex_w_lock(&rpc_conn->lock) == EOWNERDEAD)
		reset_conn_socket(rpc_conn);

	rpc_conn->last_error = 0;

	if (!tbuf) {
		ret = -ENOMEM;
		goto out;
	}

	clock_gettime(CLOCK_MONOTONIC, &start_time);

	do {
		clock_gettime(CLOCK_MONOTONIC, &current_time);
		used_before_ns =
			((int64_t)current_time.tv_sec -
			 (int64_t)rpc_conn->last_used.tv_sec) *
				1000000000LL +
			((int64_t)current_time.tv_nsec -
			 (int64_t)rpc_conn->last_used.tv_nsec);

		/*
		 * Connect to the server if we do not have a connection,
		 * otherwise reuse the session.
		 *
		 * Server keeps the connection open for
		 * ESDM_RPC_IDLE_TIMEOUT_USEC, consider it closed a bit earlier.
		 */
		if (rpc_conn->fd == -1 ||
		    used_before_ns >= half_server_timeout_ns) {
			reset_conn_socket(rpc_conn);
			CKINT(esdm_connect_proto_service(rpc_conn));
		}

		/* Pack the protobuf-c data and send it over the wire */
		CKINT_LOG(esdm_rpc_client_pack(input, method_index, rpc_conn,
					       tbuf),
			  "Sending of data failed: %d\n", ret);

		/* Receive data */
		ret = esdm_rpc_client_read_handler(rpc_conn, tbuf,
						   method->output,
						   closure, closure_data,
						   rx_retries);

		if (ret == -ECONNRESET && !reconnected && !privileged) {
			/*
			 * The server closed the connection without answering.
			 * Ask once more on a fresh one - only once, so a server
			 * that keeps closing on us cannot hold the caller here.
			 *
			 * Not for a privileged request: those change the state
			 * of the ESDM, e.g. credit entropy, and whether the
			 * server applied it before the connection went away
			 * cannot be told. Applying it twice is worse than
			 * reporting the failure.
			 */
			reconnected = true;
			ret = -EAGAIN;
		} else if (ret == -EAGAIN &&
			   (privileged ||
			    esdm_rpcc_elapsed_ms(&start_time) >=
				    ESDM_RPCC_RX_TIMEOUT_MS)) {
			/*
			 * The answer did not come in time, again and again - or,
			 * for a privileged request, once: give up rather than
			 * wait for a wedged server forever.
			 */
			ret = -ETIMEDOUT;
		}

		/* EAGAIN is ok here, since sockets are non-blocking now */
		if (ret < 0 && ret != -EAGAIN) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Receiving of data failed: %d\n", ret);
		}

		/*
		 * Re-submitting or giving up abandons the answer to the request
		 * just sent. Drop the socket so it cannot arrive afterwards:
		 * responses are matched purely by order, so a late one would be
		 * handed out as the reply to the next call.
		 */
		if (ret == -EAGAIN || ret == -ETIMEDOUT)
			reset_conn_socket(rpc_conn);
	} while (ret == -EAGAIN);

out:
	/*
	 * Hand the reason for a failed request to the caller: the closure is
	 * not invoked when the RPC never reached the server, so this is the
	 * only place the actual errno survives.
	 */
	if (ret < 0)
		rpc_conn->last_error = ret;

	mutex_w_unlock(&rpc_conn->lock);
}

static void esdm_client_destroy(ProtobufCService *service)
{
	esdm_rpc_client_connection_t *rpc_conn =
		(esdm_rpc_client_connection_t *)service;

	mutex_w_lock(&rpc_conn->lock);
	if (rpc_conn->fd >= 0) {
		reset_conn_socket(rpc_conn);
	}
	/*
	 * No per-connection buffer to wipe - the per-thread buffers are
	 * zeroized after every invoke in esdm_rpc_client_read_handler().
	 */
	mutex_w_unlock(&rpc_conn->lock);
}

static int esdm_init_proto_service(const ProtobufCServiceDescriptor *descriptor,
				   const char *socketname,
				   esdm_rpcc_interrupt_func_t interrupt_func,
				   esdm_rpc_client_connection_t *rpc_conn)
{
	ProtobufCService *service;
	int ret = 0;

	CKNULL(rpc_conn, -EINVAL);
	service = &rpc_conn->service;

	strncpy(rpc_conn->socketname, socketname, sizeof(rpc_conn->socketname));
	rpc_conn->socketname[sizeof(rpc_conn->socketname) - 1] = '\0';
	rpc_conn->interrupt_func = interrupt_func;

	service->descriptor = descriptor;
	service->invoke = esdm_client_invoke;
	service->destroy = esdm_client_destroy;

	/*
	 * Both mutexes are robust. A caller holds ref_cnt from
	 * esdm_rpcc_get_*_service() until it returns the connection and
	 * rpc_conn->lock across the request, so a killed thread would leave a
	 * plain mutex locked forever - wedging that connection and leaking it at
	 * teardown. A robust mutex hands the lock on with EOWNERDEAD, which the
	 * mutex_w_* wrappers recover from. A failed initialization must not be
	 * published: the lock would neither serialize nor be destroyable.
	 */
	CKINT(mutex_w_init(&rpc_conn->ref_cnt, 0, 1));
	rpc_conn->fd = -1;
	reset_conn_socket(rpc_conn);

	ret = mutex_w_init(&rpc_conn->lock, 0, 1);
	if (ret) {
		/*
		 * Undo the ref_cnt initialization here: the caller only runs
		 * esdm_fini_proto_service() over the connections that were
		 * initialized completely, so this one is not covered there.
		 */
		mutex_w_destroy(&rpc_conn->ref_cnt);
		goto out;
	}

	/* Only a fully constructed connection may be handed out. */
	atomic_store(&rpc_conn->state, esdm_rpcc_initialized);

out:
	return ret;
}

/******************************************************************************
 * General service handlers
 ******************************************************************************/
/*
 * Upper bound for the number of connections of a service. Only ever lowered
 * (see esdm_rpcc_set_max_online_nodes), which together with the caching in
 * esdm_online_nodes() is what makes the connection count of a service
 * non-growing - see esdm_rpcc_init_service(). Atomic as the getters read it
 * outside of any lock.
 */
static _Atomic uint32_t esdm_rpcc_max_nodes = UINT32_MAX;

/*
 * Guards the pairing of a connection-array pointer and its count across
 * init/fini versus concurrent getters. A getter holds the reader side from
 * loading the array pointer until it owns a connection's ref_cnt or is counted
 * as a waiter for it, so a concurrent fini (which takes the writer side for the
 * pointer swap and only then waits for the waiters and each ref_cnt) can no
 * longer destroy and free the array between the getter's pointer load and its
 * ref_cnt acquisition. The same writer side serializes concurrent init calls
 * against each other. Writer-preferring so init/fini cannot be starved by a
 * flood of getters.
 */
static mutex_t esdm_rpcc_conn_lock = MUTEX_UNLOCKED_PREFER_WRITER;

DSO_PUBLIC
int esdm_rpcc_set_max_online_nodes(uint32_t nodes)
{
	/*
	 * Clamp to at least one node: esdm_rpcc_curr_node() divides by this
	 * value, so accepting 0 would turn every later service lookup into a
	 * SIGFPE.
	 */
	uint32_t new_nodes = max_uint32(nodes, 1);
	uint32_t curr = atomic_load(&esdm_rpcc_max_nodes);

	/*
	 * Lower the limit, never raise it. The loop keeps that true also when
	 * two callers race, which the read-modify-write of a plain variable
	 * would not - and the whole connection handling relies on the limit
	 * being monotonic (see esdm_rpcc_init_service).
	 */
	while (new_nodes < curr &&
	       !atomic_compare_exchange_weak(&esdm_rpcc_max_nodes, &curr,
					     new_nodes))
		;

	return 0;
}

static uint32_t esdm_rpcc_get_online_nodes(void)
{
	return (min_uint32(esdm_rpcc_max_nodes, esdm_online_nodes()));
}

static uint32_t esdm_rpcc_curr_node(void)
{
	return (esdm_curr_node() % esdm_rpcc_max_nodes);
}

/*
 * Release a connection array that is not reachable through the global service
 * pointer any more.
 *
 * The caller must have removed the array from that pointer first, so no getter
 * can pick up one of its connections. Invoke this without holding
 * esdm_rpcc_conn_lock: waiting for the in-flight callers can take up to a
 * second per connection, which must not block getters of a meanwhile installed
 * array.
 *
 * @return true if the connections are released, false if they are leaked
 *	   because a caller still uses one of them
 */
static bool esdm_rpcc_release_conns(
	esdm_rpc_client_connection_t *rpc_conn_array, uint32_t num_conn)
{
	static const struct timespec waiter_poll_ts = { .tv_sec = 0,
							.tv_nsec = 1000000 };
	struct timespec abstime;
	esdm_rpc_client_connection_t *rpc_conn_p;
	uint32_t i;
	bool still_in_use = false;

	if (!rpc_conn_array)
		return true;

	/* Tell everybody that the connection is about to terminate */
	for (i = 0, rpc_conn_p = rpc_conn_array; i < num_conn; i++, rpc_conn_p++)
		atomic_store(&rpc_conn_p->state, esdm_rpcc_in_termination);

	/*
	 * Wait until the processing for a connection completed and then delete
	 * it.
	 */
	for (i = 0, rpc_conn_p = rpc_conn_array; i < num_conn;
	     i++, rpc_conn_p++) {
		/*
		 * Do not wait forever: a caller that is still working on its
		 * request would otherwise block the shutdown for as long as it
		 * takes. A handle whose owner was killed does not need the
		 * timeout - ref_cnt is robust, so it is handed over right away.
		 */
		clock_gettime(CLOCK_MONOTONIC, &abstime);
		abstime.tv_sec += 1;

		/*
		 * Getters queued for a busy connection wait on its ref_cnt
		 * without the connection lock (see esdm_rpcc_get_service()), so
		 * the mutex must not be destroyed while one of them is left.
		 * All of them are known by now - none can join once the array
		 * is unreachable - and each leaves soon after the owner put the
		 * connection back, finding it in termination.
		 */
		while (atomic_load(&rpc_conn_p->waiters) &&
		       !esdm_rpcc_deadline_passed(&abstime))
			nanosleep(&waiter_poll_ts, NULL);

		if (atomic_load(&rpc_conn_p->waiters) ||
		    mutex_w_timedlock(&rpc_conn_p->ref_cnt, &abstime)) {
			/*
			 * A live caller still owns this connection, or waits
			 * for it, and did not return it in time. Neither the
			 * mutexes nor the socket may be recycled while a
			 * running request can reach them, so leak the whole
			 * array below rather than risk a
			 * use-after-free. A connection whose owner died is not
			 * this case: ref_cnt is robust, so the timedlock takes
			 * it over and the handle is torn down normally.
			 */
			still_in_use = true;
			continue;
		}
		mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Terminate the handle */
		esdm_fini_proto_service(rpc_conn_p);
	}

	if (still_in_use) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_RPC,
			"Connection handles still in use on termination - leaking the connection memory\n");
		return false;
	}

	free(rpc_conn_array);

	return true;
}

/*
 * Release the connections of a service.
 *
 * @param force If false, this is one matching counterpart of an init call: the
 *		connections are only torn down once as many finis as inits were
 *		seen. If true, the connections are released regardless of how
 *		many init calls are still outstanding.
 */
static void esdm_rpcc_fini_service(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn, uint32_t *num,
	uint32_t *init_ref, bool force)
{
	esdm_rpc_client_connection_t *rpc_conn_array;
	uint32_t num_conn;

	/*
	 * Swap the pointer/count pair under the writer side of the connection
	 * lock: getters read both and take their ref_cnt - or register as its
	 * waiter - under the reader side, so afterwards every getter either
	 * sees NULL or is accounted for in a connection the release below
	 * waits for. The same lock guards the init reference count, making the
	 * teardown decision and the swap atomic against a concurrent init.
	 */
	mutex_lock(&esdm_rpcc_conn_lock);

	/* Not initialized, or already released - nothing to do. */
	if (!*init_ref) {
		mutex_unlock(&esdm_rpcc_conn_lock);
		return;
	}

	/* Other users are still around - keep the connections alive. */
	if (!force && --(*init_ref)) {
		mutex_unlock(&esdm_rpcc_conn_lock);
		return;
	}

	*init_ref = 0;
	num_conn = *num;
	rpc_conn_array = atomic_exchange(rpc_conn, NULL);
	*num = 0;
	mutex_unlock(&esdm_rpcc_conn_lock);
	if (!rpc_conn_array)
		return;

	/*
	 * Counterpart of the one esdm_test_shm_status_init() that the initial
	 * allocation of this service performed - a mere replacement of the
	 * connections keeps the shared memory attached.
	 *
	 * Only once the calls in flight are done: they account the bytes they
	 * obtained in the shared memory while they hold their connection, and
	 * the last fini detaches it. Calls that are not done in time keep
	 * their connections, and the shared memory, for good.
	 */
	if (esdm_rpcc_release_conns(rpc_conn_array, num_conn))
		esdm_test_shm_status_fini();
}

/*
 * Set up the connections of a service.
 *
 * Every successful call adds one reference which esdm_rpcc_fini_service()
 * consumes again, so independent users within one process (e.g. an application
 * and a preloaded library) can init and fini without pulling the connections
 * away from each other.
 *
 * The first init allocates and only the last fini releases - an init never
 * replaces an existing set, which is what makes a handle from
 * esdm_rpcc_get_service() safe to use. That costs nothing, as the number of
 * nodes cannot grow during a process' lifetime:
 * esdm_rpcc_set_max_online_nodes() only lowers its limit and
 * esdm_online_nodes() caches the CPU count on its first call.
 */
static int esdm_rpcc_init_service(const ProtobufCServiceDescriptor *descriptor,
				  const char *socketname,
				  esdm_rpcc_interrupt_func_t interrupt_func,
				  _Atomic(esdm_rpc_client_connection_t *) *rpc_conn,
				  uint32_t *num_conn, uint32_t *init_ref)
{
	esdm_rpc_client_connection_t *tmp = NULL, *tmp_p, *curr_conn_array;
	uint32_t i = 0, nodes = esdm_rpcc_get_online_nodes();
	int ret = 0;

	/* Serialize against concurrent init/fini and exclude getters. */
	mutex_lock(&esdm_rpcc_conn_lock);
	curr_conn_array = atomic_load(rpc_conn);

	/*
	 * It is a legitimate scenario that this function is called twice for
	 * one connection as follows: if the libesdm_getrandom is preloaded, the
	 * connection is already allocated. Now, the caller also wants to
	 * establish a new connection, it cannot assume that libesdm_getrandom
	 * is preloaded. Thus, it will unconditionally call the init function
	 * as well. Thus catch this issue here and avoid double allocation.
	 * Note, the esdm_rpcc_fini_service will ensure that there is also no
	 * double free.
	 */
	if (curr_conn_array) {
		/*
		 * The interrupt function is a property of the connection and
		 * thus shared by all users of the service. The one supplied
		 * with the first init stays in effect - replacing it would
		 * silently disable the interrupt handling of its owner.
		 */
		if (interrupt_func &&
		    interrupt_func != curr_conn_array->interrupt_func) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_RPC,
				"Interrupt function for socket %s ignored: the connections are already established\n",
				socketname);
		}

		/*
		 * Cannot happen as the node count never grows (see above). Do
		 * not silently hand out fewer connections than asked for if it
		 * ever does - the existing ones are kept either way, as freeing
		 * them would break the callers currently using them.
		 */
		if (*num_conn < nodes) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_RPC,
				"Keeping the %u existing connections for socket %s although %u are requested\n",
				*num_conn, socketname, nodes);
		}

		(*init_ref)++;
		goto out;
	}

	/*
	 * Build the connections completely before publishing them: a failure
	 * thus leaves the service in the uninitialized state it had before
	 * instead of a half-built one.
	 */
	tmp = calloc(nodes, sizeof(*tmp));
	CKNULL(tmp, -ENOMEM);

	for (i = 0, tmp_p = tmp; i < nodes; i++, tmp_p++) {
		CKINT(esdm_init_proto_service(descriptor, socketname,
					      interrupt_func, tmp_p));
	}

	/* Paired with the fini in esdm_rpcc_fini_service(). */
	CKINT(esdm_test_shm_status_init());

	/*
	 * Publish the connections. A plain store is sufficient: the pointer is
	 * NULL at this point and only init and fini ever write it, both under
	 * the writer side of the connection lock which is held throughout.
	 */
	atomic_store(rpc_conn, tmp);
	*num_conn = nodes;
	(*init_ref)++;

	/* The connection array is owned by the service now. */
	tmp = NULL;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ANY,
		"Service supporting %u parallel requests for socket %s enabled\n",
		nodes, socketname);

out:
	/* Only still set if the connections were not published. */
	if (tmp) {
		uint32_t j;

		for (j = 0, tmp_p = tmp; j < i; j++, tmp_p++)
			esdm_fini_proto_service(tmp_p);

		free(tmp);
	}
	mutex_unlock(&esdm_rpcc_conn_lock);

	return ret;
}

static int esdm_rpcc_get_service(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn_array_ptr,
	uint32_t *num_conn_ptr, esdm_rpc_client_connection_t **ret_rpc_conn,
	void *int_data, const struct timespec *deadline)
{
	esdm_rpc_client_connection_t *rpc_conn_array, *rpc_conn_p;
	uint32_t node, num_conn;
	bool found_unused_conn = false;
	int ret = 0;
	uint32_t i;

	if (!ret_rpc_conn)
		return -EFAULT;

	/*
	 * A call from inside the DTLS layer of this very client: the TLS stack
	 * asked for random numbers while it set up or used a connection, in a
	 * process where they are served by the ESDM - libesdm_getrandom, or an
	 * application whose getrandom(3) or getentropy(3) asks the ESDM. The
	 * outer call holds a connection - with a single one, this call would
	 * wait for it forever -, and the TLS stack may hold the lock of the
	 * random number generator it is seeding, which a handshake on another
	 * connection would wait for. So it fails at once, as when no ESDM is
	 * there: its caller takes the random numbers from the kernel. See
	 * esdm_dtls_busy().
	 */
	if (esdm_dtls_busy())
		return -EDEADLK;

	/*
	 * Hold the reader side from the pointer load until the connection's
	 * ref_cnt is owned - or, if the connection is busy, until this getter
	 * is registered as one of its waiters: fini swaps the pointer under the
	 * writer side and only then waits for the waiters and each ref_cnt, so
	 * it cannot destroy and free the array between our load and the
	 * ref_cnt acquisition. The lock also makes the pointer and count a
	 * consistent pair (no transient non-NULL pointer with count 0 and its
	 * modulo-by-zero SIGFPE).
	 */
	mutex_reader_lock(&esdm_rpcc_conn_lock);

	rpc_conn_array = atomic_load(rpc_conn_array_ptr);
	num_conn = *num_conn_ptr;

	if (!rpc_conn_array) {
		ret = -EFAULT;
		goto out;
	}
	if (!num_conn) {
		ret = -ESHUTDOWN;
		goto out;
	}

	/*
	 * Protection against client programming errors: esdm_rpcc_curr_node()
	 * is bounded by the node limit, which may exceed the number of
	 * connections this service actually holds.
	 */
	node = min_uint32(esdm_rpcc_curr_node(), num_conn - 1);

	/*
	 * Always using a fixed connection based on the current
	 * core slows the client down, as under load a thread waiting
	 * on a reply from ESDM is paused and probably another thread
	 * also communicating with ESDM scheduled on the same node
	 * waiting for the RPC connection to become available again
	 * with no gain.
	 *
	 * Try to optimistically find a free connection slot first.
	 */
	for (i = 0; i < num_conn; ++i) {
		rpc_conn_p = rpc_conn_array + (i + node) % num_conn;
		if (mutex_w_trylock(&rpc_conn_p->ref_cnt) == 0) {
			found_unused_conn = true;
			break;
		}
	}

	if (!found_unused_conn) {
		int lock_ret;

		rpc_conn_p = rpc_conn_array + node % num_conn;

		/*
		 * Wait until the previous call completed - each connection
		 * handle has only one caller at one given time. Lock the
		 * ref_cnt if we obtained the connection handle.
		 *
		 * Not under the connection lock: the wait lasts as long as the
		 * owner's request, and meanwhile the writer-preferring lock
		 * would hold off a fork in prepare_fork() and, behind it, every
		 * new getter of the process - also those that would find an
		 * idle connection. Being a waiter keeps the connection alive
		 * instead: fini only destroys it once there are none left, and
		 * none can join after fini removed the array, which it does
		 * under the writer side. So the array outlives the wait and
		 * the state check below - which, as fini marks the connections
		 * before it waits, also tells whether it was torn down.
		 */
		atomic_fetch_add(&rpc_conn_p->waiters, 1);
		mutex_reader_unlock(&esdm_rpcc_conn_lock);

		if (deadline) {
			lock_ret = mutex_w_timedlock(&rpc_conn_p->ref_cnt,
						     deadline);
		} else {
			mutex_w_lock(&rpc_conn_p->ref_cnt);
			lock_ret = 0;
		}

		/*
		 * The last access to the connection unless ref_cnt is owned -
		 * fini may free it right after.
		 */
		atomic_fetch_sub(&rpc_conn_p->waiters, 1);

		if (lock_ret) {
			*ret_rpc_conn = NULL;
			return -ETIMEDOUT;
		}
	} else {
		mutex_reader_unlock(&esdm_rpcc_conn_lock);
	}

	/*
	 * The connection lock is not held any more, ref_cnt is - fini waits
	 * for it before it tears the connection down.
	 */
	if (atomic_load(&rpc_conn_p->state) != esdm_rpcc_initialized) {
		mutex_w_unlock(&rpc_conn_p->ref_cnt);

		/* Safety measure */
		*ret_rpc_conn = NULL;

		return -ESHUTDOWN;
	}

	*ret_rpc_conn = rpc_conn_p;
	rpc_conn_p->interrupt_data = int_data;
	rpc_conn_p->deadline = deadline;

	return 0;

out:
	mutex_reader_unlock(&esdm_rpcc_conn_lock);
	return ret;
}

static void esdm_rpcc_put_service(esdm_rpc_client_connection_t *rpc_conn)
{
	if (!rpc_conn)
		return;

	mutex_w_unlock(&rpc_conn->ref_cnt);
}

/******************************************************************************
 * Unprivileged connection
 ******************************************************************************/
static _Atomic(esdm_rpc_client_connection_t *) unpriv_rpc_conn = NULL;
static uint32_t unpriv_rpc_conn_num = 0;
/* Number of outstanding init calls, guarded by esdm_rpcc_conn_lock */
static uint32_t unpriv_rpc_conn_init_ref = 0;

DSO_PUBLIC
int esdm_rpcc_get_unpriv_service(esdm_rpc_client_connection_t **rpc_conn,
				 void *int_data)
{
	return esdm_rpcc_get_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
				     rpc_conn, int_data, NULL);
}

/* Documented with its declaration in esdm_rpc_client_internal.h */
int esdm_rpcc_get_unpriv_service_deadline(
	esdm_rpc_client_connection_t **rpc_conn, void *int_data,
	const struct timespec *deadline)
{
	return esdm_rpcc_get_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
				     rpc_conn, int_data, deadline);
}

/* Documented with its declaration in esdm_rpc_client_internal.h */
int esdm_rpcc_unpriv_service_pause(esdm_rpc_client_connection_t **rpc_conn,
				   void *int_data,
				   const struct timespec *deadline)
{
	struct timespec sleep_ts = esdm_client_poll_ts;

	esdm_rpcc_put_unpriv_service(*rpc_conn);
	*rpc_conn = NULL;

	if (deadline) {
		struct timespec now;
		int64_t left_ns;

		clock_gettime(CLOCK_MONOTONIC, &now);
		left_ns = ((int64_t)deadline->tv_sec - (int64_t)now.tv_sec) *
				  1000000000LL +
			  ((int64_t)deadline->tv_nsec - (int64_t)now.tv_nsec);
		if (left_ns <= 0)
			return -ETIMEDOUT;

		if (left_ns < (int64_t)sleep_ts.tv_sec * 1000000000LL +
				      sleep_ts.tv_nsec) {
			sleep_ts.tv_sec = (time_t)(left_ns / 1000000000LL);
			sleep_ts.tv_nsec = (long)(left_ns % 1000000000LL);
		}
	}

	nanosleep(&sleep_ts, NULL);

	return esdm_rpcc_get_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
				     rpc_conn, int_data, deadline);
}

DSO_PUBLIC
void esdm_rpcc_put_unpriv_service(esdm_rpc_client_connection_t *rpc_conn)
{
	esdm_rpcc_put_service(rpc_conn);
}

DSO_PUBLIC
int esdm_rpcc_init_unpriv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	register_fork_handler();

	return esdm_rpcc_init_service(&unpriv_access__descriptor,
				      ESDM_RPC_UNPRIV_SOCKET, interrupt_func,
				      &unpriv_rpc_conn, &unpriv_rpc_conn_num,
				      &unpriv_rpc_conn_init_ref);
}

DSO_PUBLIC
void esdm_rpcc_fini_unpriv_service(void)
{
	esdm_rpcc_fini_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
			       &unpriv_rpc_conn_init_ref, false);
}

DSO_PUBLIC
void esdm_rpcc_force_fini_unpriv_service(void)
{
	esdm_rpcc_fini_service(&unpriv_rpc_conn, &unpriv_rpc_conn_num,
			       &unpriv_rpc_conn_init_ref, true);
}

/******************************************************************************
 * Privileged connection
 ******************************************************************************/
static _Atomic(esdm_rpc_client_connection_t *) priv_rpc_conn = NULL;
static uint32_t priv_rpc_conn_num = 0;
/* Number of outstanding init calls, guarded by esdm_rpcc_conn_lock */
static uint32_t priv_rpc_conn_init_ref = 0;

DSO_PUBLIC
int esdm_rpcc_get_priv_service(esdm_rpc_client_connection_t **rpc_conn,
			       void *int_data)
{
	return esdm_rpcc_get_service(&priv_rpc_conn, &priv_rpc_conn_num,
				     rpc_conn, int_data, NULL);
}

DSO_PUBLIC
void esdm_rpcc_put_priv_service(esdm_rpc_client_connection_t *rpc_conn)
{
	esdm_rpcc_put_service(rpc_conn);
}

DSO_PUBLIC
int esdm_rpcc_init_priv_service(esdm_rpcc_interrupt_func_t interrupt_func)
{
	register_fork_handler();

	return esdm_rpcc_init_service(&priv_access__descriptor,
				      ESDM_RPC_PRIV_SOCKET, interrupt_func,
				      &priv_rpc_conn, &priv_rpc_conn_num,
				      &priv_rpc_conn_init_ref);
}

DSO_PUBLIC
void esdm_rpcc_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num,
			       &priv_rpc_conn_init_ref, false);
}

DSO_PUBLIC
void esdm_rpcc_force_fini_priv_service(void)
{
	esdm_rpcc_fini_service(&priv_rpc_conn, &priv_rpc_conn_num,
			       &priv_rpc_conn_init_ref, true);
}

/******************************************************************************
 * Fork Handling
 ******************************************************************************/
/*
 * The child handler below runs where only the forking thread exists: the
 * inherited connections have shared sockets and mutexes possibly left locked by
 * a thread that is gone here.
 *
 * Registration happens from the init calls, which may run concurrently - hence
 * pthread_once. A plain "already registered" flag races: two threads both see
 * it unset, register twice and both run the cleanup right away, destroying the
 * mutexes of connections a third thread may be using.
 *
 * One registration covers both services, as they share esdm_rpcc_conn_lock and
 * two prepare handlers taking its non-recursive writer side would deadlock the
 * fork. Touching an uninitialized service is harmless - NULL array, count 0.
 */
static pthread_once_t fork_handler_once = PTHREAD_ONCE_INIT;

/*
 * Hold the connection lock across the fork. Without it the child can come up
 * with a torn view: the array pointer and its count are two separate stores, so
 * a fork in between leaves a NULL array with a non-zero count (fini) or an
 * array the child considers empty forever (init). It also keeps the child from
 * inheriting the lock held by a thread that no longer exists, which would
 * deadlock its first esdm_rpcc_get_service(). The price is that a fork waits
 * for the getters inside the lock, which only look for an idle connection
 * there - one that has to wait for a busy connection does so outside of it.
 */
static void prepare_fork(void)
{
	mutex_lock(&esdm_rpcc_conn_lock);
}

static void cleanup_after_fork_parent(void)
{
	mutex_unlock(&esdm_rpcc_conn_lock);
}

/* does nothing, if no connections were allocated and num_conn is 0 */
static void reinit_conns_after_fork(
	_Atomic(esdm_rpc_client_connection_t *) *rpc_conn, uint32_t num_conn)
{
	esdm_rpc_client_connection_t *rpc_conn_array = atomic_load(rpc_conn);
	uint32_t i;

	if (!rpc_conn_array)
		return;

	/*
	 * Close all sockets and reinit the mutexes - robust, matching
	 * esdm_init_proto_service(). Recreating them rather than recovering
	 * them is what is needed here: a mutex left locked by a thread of the
	 * parent has no owner in this process at all, so there is nobody for
	 * the robustness protocol to hand it over to.
	 */
	for (i = 0; i < num_conn; ++i) {
		/*
		 * The DTLS of the connection is the parent's: its records go on
		 * with the parent's sequence numbers, and nothing of it may be
		 * sent from here. Releasing it is no business of this handler
		 * either: freeing it goes into the TLS stack, whose locks a
		 * thread of the parent may have held at the fork - it would
		 * wait for them forever, in every child of the process, also
		 * those that only exec. It is left behind, never used - its
		 * memory is shared with the parent copy-on-write, so it costs
		 * nothing as long as nobody touches it. Kept reachable for leak
		 * checkers; a child forking again replaces it.
		 */
		rpc_conn_array[i].dtls_orphan = rpc_conn_array[i].dtls;
		rpc_conn_array[i].dtls = NULL;

		/*
		 * Close only - no shutdown(). The socket is shared with the
		 * parent, which may be in the middle of a request on it: a
		 * shutdown would end the connection for the parent as well,
		 * which then re-sends its request on a new one, and a request
		 * such as RNDADDENTROPY would be credited twice.
		 */
		drop_conn_socket(&rpc_conn_array[i], false);
		/*
		 * Whatever a parent's thread checked the connection out with
		 * belongs to a call that does not exist here.
		 */
		rpc_conn_array[i].interrupt_data = NULL;
		rpc_conn_array[i].deadline = NULL;
		atomic_store(&rpc_conn_array[i].waiters, 0);
		mutex_w_destroy(&rpc_conn_array[i].ref_cnt);
		mutex_w_destroy(&rpc_conn_array[i].lock);
		mutex_w_init(&rpc_conn_array[i].ref_cnt, 0, 1);
		mutex_w_init(&rpc_conn_array[i].lock, 0, 1);
	}
}

/*
 * Create esdm_rpcc_conn_lock anew with the kind its static initializer gives
 * it. mutex_init() would create a default, reader-preferring rwlock, and from
 * the first fork on the child's init and fini could then be starved by a
 * steady stream of getters - see esdm_rpcc_conn_lock.
 */
static void esdm_rpcc_conn_lock_reinit(void)
{
#ifdef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
	pthread_rwlockattr_t attr;

	if (!pthread_rwlockattr_init(&attr)) {
		int ret = pthread_rwlockattr_setkind_np(
			&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);

		if (!ret)
			ret = pthread_rwlock_init(&esdm_rpcc_conn_lock, &attr);
		pthread_rwlockattr_destroy(&attr);
		if (!ret)
			return;
	}
#endif

	mutex_init(&esdm_rpcc_conn_lock, 0);
}

static void cleanup_after_fork_child(void)
{
	reinit_conns_after_fork(&unpriv_rpc_conn, unpriv_rpc_conn_num);
	reinit_conns_after_fork(&priv_rpc_conn, priv_rpc_conn_num);

#ifdef ESDM_DTLS
	/*
	 * A thread of the parent may have been setting up the DTLS context:
	 * the lock is created anew, and the child sets up a context of its own
	 * should the parent's not be there.
	 */
	pthread_mutex_init(&esdm_rpcc_dtls_ctx_lock, NULL);
#endif

	/*
	 * Drop the lock taken by prepare_fork(). Re-initializing rather than
	 * unlocking discards any waiter state inherited from the parent's
	 * threads, none of which exist here. This is safe precisely because
	 * prepare_fork() ran: the sole surviving thread is the owner, so no
	 * other thread in this process can be inside the lock.
	 */
	esdm_rpcc_conn_lock_reinit();
}

static void do_register_fork_handler(void)
{
	pthread_atfork(&prepare_fork, &cleanup_after_fork_parent,
		       &cleanup_after_fork_child);
}

/*
 * The registration survives a fork, so the child does not need to repeat it -
 * which is what the inherited pthread_once state provides. As the handler is
 * installed before any connection can be allocated, every fork after that
 * point runs the cleanup in the child.
 */
static void register_fork_handler(void)
{
	pthread_once(&fork_handler_once, do_register_fork_handler);
}
