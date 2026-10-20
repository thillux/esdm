/*
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

#define _GNU_SOURCE
#include <bits/time.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <poll.h>
#include <protobuf-c/protobuf-c.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>

#include <stdatomic.h>
#include "buffer.h"
#include "build_bug_on.h"
#include "conv_be_le.h"
#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_dtls.h"
#include "esdm_egd_server.h"
#include "esdm_peer_account.h"
#include "esdm_peer_limit.h"
#include "esdm_shm_status.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_protocol_helper.h"
#include "esdm_rpc_server.h"
#include "esdm_server_socket.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "linux_support.h"
#include "math_helper.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "unpriv_access.pb-c.h"
#include "privileges.h"
#include "ret_checkers.h"
#include "queue.h"
#include "systemd_support.h"
#include "threading_support.h"

#ifdef ESDM_RPC_IO_URING
#include <liburing.h>
#endif

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
	for ((var) = TAILQ_FIRST((head));                                      \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

struct esdm_rpcs {
	ProtobufCService *service;
	int server_listening_fd;
	bool privileged;
	/* Connections of all workers, and their slots, see esdm_rpcs_full() */
	atomic_size_t num_connections;
	atomic_size_t max_connections;
};

/*
 * Where a connection is on its way to DTLS, see ESDM_RPC_PROTO_STARTDTLS in
 * esdm_rpc_protocol.h
 */
enum esdm_rpcs_dtls_state {
	/* In the clear, as connected */
	esdm_rpcs_dtls_none,
	/* STARTDTLS accepted, the probe still to be answered in the clear */
	esdm_rpcs_dtls_probe,
	/* The handshake in progress */
	esdm_rpcs_dtls_handshake,
	/* Requests and answers as DTLS records */
	esdm_rpcs_dtls_active,
};

struct esdm_rpcs_connection {
	struct esdm_rpcs *proto;
	int child_fd;
	/* Peer UID, and the user it is accounted to, see esdm_peer_account.h */
	uid_t peer_uid;
	uid_t peer_account;
	/* Accounted in esdm_rpcs_peer_limit, as peer_account */
	bool peer_counted;
	/* Holds a slot of its worker, see esdm_rpcs_conn_get() */
	bool slot_counted;
	/*
	 * Shut down for reading by the server, which closes it once it served
	 * what the client sent before - see esdm_rpcs_reclaim()
	 */
	bool closing;
	/* enum esdm_rpcs_dtls_state */
	uint8_t dtls_state;
	/* Accounted in esdm_rpcs_dtls_limit and esdm_rpcs_worker_dtls */
	bool dtls_counted;
	/*
	 * The DTLS of the connection from STARTDTLS on, NULL in the clear. What
	 * an idle connection holds of it is the state of the TLS stack - the
	 * request and answer pass through the buffers of the worker, see
	 * esdm_rpcs_reqbuf, and a message of several records is collected in
	 * a buffer only while it arrives.
	 */
	struct esdm_dtls *dtls;
	uint32_t method_index;
	uint32_t request_id;
	struct timespec last_used;

	/* list handling for cleanup */
	TAILQ_ENTRY(esdm_rpcs_connection) tailq;

#ifdef ESDM_RPC_IO_URING
	/*
	 * The poll of the io_uring of its worker, see esdm_rpcs_loop: armed -
	 * its completion still to come -, waiting in the list of those to be
	 * armed again, or - once the connection is closed - its cancellation
	 * submitted. A connection closed with its poll armed is freed only
	 * with the completion of the poll, which carries its address.
	 */
	bool poll_armed;
	bool poll_queued;
	bool poll_cancelled;
	bool closed;
	TAILQ_ENTRY(esdm_rpcs_connection) poll_entry;
#endif
};
TAILQ_HEAD(esdm_rpcs_connection_list, esdm_rpcs_connection);

struct esdm_rpc_thread {
	struct esdm_rpcs *proto;
	uint32_t id;
	int eventfd;
	/* Connection slots of this worker, see esdm_rpcs_worker_slots() */
	size_t max_connections;
};

/*
 * Per-worker-thread scratch buffer holding the single in-flight request and
 * its response. A worker processes its connections one at a time in its event
 * loop, and the buffer is filled by the read, parsed in place, the response
 * packed back into it, written out and zeroized - all within one synchronous
 * request handling. It never carries state across epoll events, so one buffer
 * per worker thread suffices instead of one per connection. This bounds the
 * server's request-buffer memory by the (small, fixed) number of worker
 * threads rather than by the number of open connections. It is cast to the
 * protocol header structs, hence the 64-bit alignment.
 */
static __thread uint8_t esdm_rpcs_reqbuf[ESDM_RPC_MAX_MSG_SIZE]
	__attribute__((aligned(sizeof(uint64_t))));

struct esdm_rpcs_write_buf {
	ProtobufCBuffer base;
	struct esdm_rpcs_connection *rpc_conn;
};

enum esdm_rpcs_init_state {
	esdm_rpcs_state_uninitialized,
	esdm_rpcs_state_priv_init_complete,
	esdm_rpcs_state_unpriv_init,
	esdm_rpcs_state_perm_dropped,
};

static atomic_int esdm_rpc_init_state =
	esdm_rpcs_state_uninitialized;
static DECLARE_WAIT_QUEUE(esdm_rpc_thread_init_wait);

static atomic_int server_exit = 0;

/*
 * Concurrent connections of one unprivileged user over all RPC worker threads -
 * root is exempt. Each worker serves up to 1024 connections and all of them
 * share one RLIMIT_NOFILE with the EGD interface; without a bound per peer a
 * single local user could exhaust them and lock every other client out.
 *
 * A user is its account, see esdm_peer_account.h, not the UID it connects
 * under: the UIDs of its /etc/subuid range it may map in a user namespace and
 * connect as count as its own, so it cannot multiply the bound by spreading
 * its connections over them.
 *
 * A client process holds up to one connection per online node, and idle ones
 * are closed after ESDM_RPC_IDLE_TIMEOUT_USEC. A fixed bound would therefore
 * only admit a handful of busy processes of one user on a large machine. The
 * bound scales with the online nodes instead, admitting
 * ESDM_RPC_PROCESSES_PER_UID such processes, but never less than
 * ESDM_RPC_MIN_CONNECTIONS_PER_UID. The descriptor limit caps both: no single
 * user can take more than half of RLIMIT_NOFILE, which leaves the other half
 * to the remaining users and the EGD interface (see
 * esdm_rpcs_peer_limit_init()).
 */
#define ESDM_RPC_MIN_CONNECTIONS_PER_UID 512
#define ESDM_RPC_PROCESSES_PER_UID 16

/*
 * The per-user bound alone does not protect the descriptors: a few users
 * together exhaust them, and keep their connections from being reaped as idle
 * with a cheap request every second. The unprivileged connections are
 * therefore also bounded in total, leaving ESDM_RPC_RESERVED_FDS of
 * RLIMIT_NOFILE - but at most half of it - to the EGD interface (up to 2048
 * connections), the privileged interface and the server itself. The bound is
 * split evenly over the worker threads, each holding at most
 * ESDM_RPCS_MAX_WORKER_CONNECTIONS.
 *
 * A worker whose slots are all taken stops accepting while another worker has
 * a free slot. Once all are taken, it does not turn a new connection away -
 * whoever holds the slots would lock everybody else out - but closes one of
 * its connections to make room: the least recently active one of the user with
 * the most connections in that worker. The clients reconnect transparently, so
 * service goes on for everybody, at the price of churn under attack. Never
 * closed are a connection with a request not read yet, and any connection of
 * the privileged interface; a request arriving as one is closed is still
 * served, see esdm_rpcs_reclaim(). One with an answer the client did not read
 * yet is closed only when no idle one is left: the answer stays readable after
 * the close, and sparing such connections altogether would let a client that
 * always leaves its last answer unread hold its slots forever. The choice is
 * made within the accepting worker, as each worker owns its connections:
 * closing one of another worker would race with that worker serving it.
 */
#define ESDM_RPC_RESERVED_FDS (2048 + 512)
#define ESDM_RPCS_MAX_WORKER_CONNECTIONS 1024

static struct esdm_peer_limit esdm_rpcs_peer_limit = ESDM_PEER_LIMIT_INIT(
	"RPC server", ESDM_RPC_MIN_CONNECTIONS_PER_UID);

/*
 * Encrypted connections of one unprivileged user, and of one worker.
 *
 * The state the TLS stack keeps for an idle encrypted connection is large next
 * to the rest of one: with OpenSSL some 130 KiB of heap - of which some 70 KiB
 * are touched -, against a few hundred bytes for a connection in the clear. So
 * an unprivileged user could make the server hold a multiple of the memory it
 * holds for it now, with the connections the bounds above admit. A STARTDTLS
 * beyond these bounds is refused instead, and the connection goes on in the
 * clear - DTLS being opportunistic, that is what a client is prepared for.
 * The bound per user keeps one user from taking the encrypted connections of
 * everybody else; a busy process holds one connection per node, so it admits a
 * good number of busy processes. The bound per worker - a fourth of its
 * connections - bounds the memory over all users, some 32 MiB per worker.
 * Root is exempt from the first, as from the connection bound.
 */
#define ESDM_RPC_DTLS_CONNECTIONS_PER_UID 64
#define ESDM_RPCS_MAX_WORKER_DTLS (ESDM_RPCS_MAX_WORKER_CONNECTIONS / 4)

static struct esdm_peer_limit esdm_rpcs_dtls_limit = ESDM_PEER_LIMIT_INIT(
	"RPC server DTLS", ESDM_RPC_DTLS_CONNECTIONS_PER_UID);

/*
 * Encrypted connections of the calling worker. A connection is set up, served
 * and closed by the worker that accepted it, so a counter per thread suffices.
 */
static __thread unsigned int esdm_rpcs_worker_dtls;

/*
 * Size the per-user bound of the RPC interface. To be called before the first
 * RPC worker thread starts.
 */
static void esdm_rpcs_peer_limit_init(void)
{
	uint64_t max = max_uint64((uint64_t)esdm_online_nodes() *
					  ESDM_RPC_PROCESSES_PER_UID,
				  ESDM_RPC_MIN_CONNECTIONS_PER_UID);
	struct rlimit rl;

	/*
	 * The cap comes last: it is what keeps a single UID from taking the
	 * descriptors of everybody else, and the minimum must not lift it.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY)
		max = min_uint64(max, rl.rlim_cur / 2);

	esdm_rpcs_peer_limit.max_per_uid = (unsigned int)min_uint64(max,
								  UINT_MAX);

	esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
		    "Admitting at most %u RPC connections per unprivileged user\n",
		    esdm_rpcs_peer_limit.max_per_uid);

	/* While the privileges are still held, see esdm_peer_account.h. */
	esdm_peer_account_init();
}

/* Connection slots of each of @num_threads workers serving @proto */
static size_t esdm_rpcs_worker_slots(const struct esdm_rpcs *proto,
				     size_t num_threads)
{
	uint64_t total;
	struct rlimit rl;

	if (proto->privileged || getrlimit(RLIMIT_NOFILE, &rl) ||
	    rl.rlim_cur == RLIM_INFINITY)
		return ESDM_RPCS_MAX_WORKER_CONNECTIONS;

	total = rl.rlim_cur -
		min_uint64(rl.rlim_cur / 2, ESDM_RPC_RESERVED_FDS);

	return (size_t)max_uint64(min_uint64(total / num_threads,
					     ESDM_RPCS_MAX_WORKER_CONNECTIONS),
				  1);
}

/*
 * Set while the thread serving the unprivileged interface runs. A master that
 * gives up during the initialization waits for it before it returns: the
 * teardown that follows takes the thread pool down, and a thread still busy
 * starting its workers then waits for a free slot forever.
 */
static atomic_bool esdm_rpc_unpriv_running = false;

/* The error the thread serving the unprivileged interface gave up with. */
static atomic_int esdm_rpc_unpriv_ret = 0;

/*
 * The DTLS of the RPC interfaces, see ESDM_RPC_PROTO_STARTDTLS in
 * esdm_rpc_protocol.h: one context for both, holding the pre-shared key of
 * esdm_dtls.h.
 *
 * esdm_rpc_server_init() sets it up before the privileges are dropped and
 * before the first worker serves a connection. What the TLS stack loads for it
 * - its configuration, its providers - is thus read with the privileges of the
 * starting server rather than with those of the user it drops to, and a
 * failure shows at startup rather than at the first client. Nothing of the
 * context depends on the privileges: the key is a constant of the ESDM, and
 * there is no certificate. The context is shared by all workers of both
 * interfaces and kept for the lifetime of the process, as the TLS stack keeps
 * its own state: a worker may still be serving a connection while the server
 * shuts down.
 *
 * Without it - not built, switched off, or failing to set up - STARTDTLS is
 * refused, and every connection served in the clear.
 */
static struct esdm_dtls_ctx *esdm_rpcs_dtls_ctx = NULL;
static pthread_once_t esdm_rpcs_dtls_once = PTHREAD_ONCE_INIT;
/* Is STARTDTLS accepted? See esdm_rpc_server_set_dtls() */
static atomic_bool esdm_rpcs_dtls_enabled = true;

static void esdm_rpcs_dtls_ctx_init(void)
{
#ifdef ESDM_DTLS
	int ret = esdm_dtls_ctx_alloc(true, &esdm_rpcs_dtls_ctx);

	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_RPC,
			"DTLS cannot be set up, serving the RPC interfaces unencrypted: %s\n",
			strerror(-ret));
	} else {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "DTLS offered on the RPC interfaces\n");
	}
#endif
}

/* The context to accept STARTDTLS with, NULL to refuse it */
static struct esdm_dtls_ctx *esdm_rpcs_dtls_ctx_get(void)
{
	if (!atomic_load(&esdm_rpcs_dtls_enabled))
		return NULL;

	pthread_once(&esdm_rpcs_dtls_once, esdm_rpcs_dtls_ctx_init);

	return esdm_rpcs_dtls_ctx;
}

void esdm_rpc_server_set_dtls(bool enable)
{
	atomic_store(&esdm_rpcs_dtls_enabled, enable);
}

/* Do the workers wait with io_uring? See esdm_rpc_server_set_io_uring() */
static atomic_bool esdm_rpcs_io_uring_enabled = true;

void esdm_rpc_server_set_io_uring(bool enable)
{
	atomic_store(&esdm_rpcs_io_uring_enabled, enable);
}

/*
 * Is each worker of the unprivileged interface mapped to a node DRNG of its
 * own? See esdm_rpc_server_set_drng_mapping()
 */
static atomic_bool esdm_rpcs_drng_mapping = true;

void esdm_rpc_server_set_drng_mapping(bool enable)
{
	atomic_store(&esdm_rpcs_drng_mapping, enable);
	esdm_egd_server_set_drng_mapping(enable);
}

/*
 * Close the socket of a connection, releasing its DTLS with it: the DTLS refers
 * to the descriptor, whose number the next accept() may hand out again. Nothing
 * goes out on the connection for it - no closing alert, the client sees the
 * connection closed as it does in the clear. @shut_down ends the connection for
 * every other holder of the descriptor as well.
 */
static void esdm_rpcs_conn_close(struct esdm_rpcs_connection *rpc_conn,
				 bool shut_down)
{
	esdm_dtls_free(rpc_conn->dtls);
	rpc_conn->dtls = NULL;
	rpc_conn->dtls_state = esdm_rpcs_dtls_none;

	if (rpc_conn->dtls_counted) {
		esdm_peer_limit_put(&esdm_rpcs_dtls_limit,
				    rpc_conn->peer_account);
		esdm_rpcs_worker_dtls--;
		rpc_conn->dtls_counted = false;
	}

	if (rpc_conn->child_fd >= 0) {
		if (shut_down)
			shutdown(rpc_conn->child_fd, SHUT_RDWR);
		close(rpc_conn->child_fd);
		rpc_conn->child_fd = -1;
	}
}

/* Remove a potentially left-over old Unix Domain socket. */
void esdm_server_remove_stale_socket(const char *path, int socktype)
{
	struct sockaddr_un addr;
	struct stat statbuf;
	int errsv, fd;

	/*
	 * Use lstat to detect symlinks - do not follow them.
	 * This prevents a symlink attack where an attacker replaces the
	 * socket file between stat and unlink.
	 */
	if (lstat(path, &statbuf) < 0)
		return;
	if (!S_ISSOCK(statbuf.st_mode))
		return;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlen(path) >= sizeof(addr.sun_path))
		return;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	fd = socket(PF_UNIX, socktype, 0);
	if (fd < 0)
		return;
	set_fd_nonblocking(fd);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
		/* Somebody is listening - the socket is live, keep it. */
		close(fd);
		return;
	}
	errsv = errno;
	close(fd);

	/*
	 * Only ECONNREFUSED proves that nothing is listening. Any other error
	 * leaves the question open - notably EAGAIN, which a listening socket
	 * returns once its backlog is full. That is what a systemd managed
	 * socket looks like while it queues clients for a pending activation,
	 * and removing it would break every future activation.
	 */
	if (errsv != ECONNREFUSED)
		return;

	/*
	 * Re-verify with lstat before unlink to narrow the TOCTOU window.
	 * Verify inode hasn't changed since our first check.
	 */
	{
		struct stat statbuf2;

		if (lstat(path, &statbuf2) < 0)
			return;
		if (!S_ISSOCK(statbuf2.st_mode))
			return;
		if (statbuf.st_ino != statbuf2.st_ino ||
		    statbuf.st_dev != statbuf2.st_dev)
			return;
	}
	unlink(path);
}

/*
 * Write data into an RPC connection.
 *
 * A write that cannot be completed closes the connection: the client would
 * otherwise wait for an answer that never comes. This includes a full send
 * buffer, which is not waited for at all. The clients have one request in
 * flight at a time and read its answer before they send the next one, or drop
 * the connection, so the answers of a connection never pile up beyond one - a
 * full send buffer means a client that sends requests without reading the
 * answers. Waiting for it, even briefly, would have the worker serve none of
 * its other connections meanwhile, and a few hundred such connections of one
 * unprivileged user would push everybody else on that worker past the
 * client's timeouts. A client that does not read its answers loses them -
 * SOCK_SEQPACKET hands out a message whole or not at all, so nothing is lost
 * in the middle of one, and queueing the answer instead would only buy
 * per-connection buffers for clients that do not want it.
 */
static int esdm_rpcs_write_data(struct esdm_rpcs_connection *rpc_conn,
				const uint8_t *data, size_t len)
{
	ssize_t ret;
	int errsv;

	if (rpc_conn->child_fd < 0)
		return -EINVAL;

	/*
	 * The same for an encrypted connection, whose answer may span several
	 * records: the client reads them as they come, and one record that
	 * does not fit means it does not read. A message cut short is no
	 * message to the client, and the connection is of no use any more.
	 */
	if (rpc_conn->dtls_state == esdm_rpcs_dtls_active) {
		errsv = -esdm_dtls_send(rpc_conn->dtls, data, len);
		if (!errsv) {
			esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY,
				    "%zu bytes written encrypted\n", len);
			return 0;
		}

		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_RPC,
			"Writing of data to file descriptor %d failed: %s\n",
			rpc_conn->child_fd,
			errsv == EAGAIN ?
				"the client does not read its answers" :
				strerror(errsv));
		esdm_rpcs_conn_close(rpc_conn, false);
		return -errsv;
	}

	do {
		ret = write(rpc_conn->child_fd, data, len);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		errsv = errno;

		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_RPC,
			"Writing of data to file descriptor %d failed: %s\n",
			rpc_conn->child_fd,
			(errsv == EAGAIN || errsv == EWOULDBLOCK) ?
				"the client does not read its answers" :
				strerror(errsv));

		esdm_rpcs_conn_close(rpc_conn, false);

		return -errsv;
	}

	/*
	 * SOCK_SEQPACKET guarantees atomic messages - a short write is a
	 * protocol violation, not a partial transfer to be retried.
	 */
	if (ret != (ssize_t)len) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_RPC,
			"Partial write on SEQPACKET socket: %zd of %zu bytes on fd %d\n",
			ret, len, rpc_conn->child_fd);
		return -EIO;
	}

	esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n", len);

	return 0;
}

/*
 * Answer the request with a header-only failure status. A response that cannot
 * be sent leaves the client without any answer - it would wait for its receive
 * timeout and then send the request again, only to run into the same failure.
 */
static int esdm_rpcs_send_failure(struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpc_proto_sc_header sc_header;

	sc_header.status_code =
		le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED);
	sc_header.method_index = le_bswap32(rpc_conn->method_index);
	sc_header.message_length = 0;
	sc_header.request_id = le_bswap32(rpc_conn->request_id);

	return esdm_rpcs_write_data(rpc_conn, (uint8_t *)&sc_header,
				    sizeof(sc_header));
}

/*
 * Implementation of packing data and sending it out. Properties:
 *
 * - one call to write data out to the file descriptor
 *
 * - one more copy of entire data required to linearize all data
 */
static int esdm_rpcs_pack_internal(const ProtobufCMessage *message,
				   struct esdm_rpcs_connection *rpc_conn)
{
#define ESDM_RPCS_BUF_WRITE_HEADER_SZ (sizeof(struct esdm_rpc_proto_sc_header))

	uint8_t *const payload_buf =
		esdm_rpcs_reqbuf + ESDM_RPCS_BUF_WRITE_HEADER_SZ;
	const size_t payload_max =
		sizeof(esdm_rpcs_reqbuf) - ESDM_RPCS_BUF_WRITE_HEADER_SZ;
	size_t message_length;
	int ret;
	struct esdm_rpc_proto_sc_header *sc_header;

	if (esdm_rpc_is_fast_bytes_response(message->descriptor)) {
		/*
		 * Fast path for the get_random_bytes{,_full,_pr} responses:
		 * encode the (ret, randval) message straight into the buffer,
		 * bypassing the generic descriptor walk and the per-chunk
		 * append callbacks of protobuf_c_message_pack_to_buffer().
		 * This is the encode counterpart of the client's zero-copy
		 * decode fast path. The encoder bounds its writes to
		 * payload_max, so the resulting message_length can never
		 * exceed ESDM_RPC_MAX_INTERNAL_MSG_SIZE.
		 */
		const RandValResponse *resp =
			(const RandValResponse *)message;

		ret = esdm_rpc_encode_bytes_response(payload_buf, payload_max,
						     resp->ret,
						     resp->randval.data,
						     resp->randval.len,
						     &message_length);
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Message too large for connection buffer\n");
			goto out_failure;
		}
	} else {
		struct esdm_rpc_write_data_buf tmp = {
			.dst_len = payload_max,
			.dst_written = 0,
		};

		tmp.base.append = esdm_rpc_append_data;

		message_length = protobuf_c_message_get_packed_size(message);
		if (message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
				    "Unexpected message length: %zu > %zu\n",
				    message_length,
				    ESDM_RPC_MAX_INTERNAL_MSG_SIZE);
			ret = -EFAULT;
			goto out_failure;
		}

		if (message_length > payload_max) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Message too large for connection buffer: %zu > %zu\n",
				message_length + ESDM_RPCS_BUF_WRITE_HEADER_SZ,
				sizeof(esdm_rpcs_reqbuf));
			ret = -EOVERFLOW;
			goto out_failure;
		}

		tmp.dst_buf = payload_buf;

		if (protobuf_c_message_pack_to_buffer(message, &tmp.base) !=
		    message_length) {
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
				    "Short write of data to file descriptor\n");
			memset_secure(payload_buf, 0, tmp.dst_written);
			ret = -EFAULT;
			goto out_failure;
		}
	}

	sc_header = (struct esdm_rpc_proto_sc_header *)esdm_rpcs_reqbuf;
	sc_header->status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	sc_header->method_index = le_bswap32(rpc_conn->method_index);
	sc_header->message_length = le_bswap32(message_length);
	sc_header->request_id = le_bswap32(rpc_conn->request_id);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Server sending: server status %u, message length %u, message index %u, request ID %u\n",
		sc_header->status_code, sc_header->message_length,
		sc_header->method_index, sc_header->request_id);

	/* this message is also printed when the client closed early, don't spam logs */
	ret = esdm_rpcs_write_data(rpc_conn, esdm_rpcs_reqbuf,
				   ESDM_RPCS_BUF_WRITE_HEADER_SZ +
					   message_length);
	if (ret != 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Submission of message data failed with error %d\n",
			    ret);
		ret = -EFAULT;
		goto out;
	}

out:
	/*
	 * Zeroization only here is not sufficient.
	 * Make sure to enable zeroize on alloc and free in your Linux kernel
	 * and clear data from ESDM in your application or patch
	 * ESDM to include a cryptographic tunnel to your application.
	 */
	memset_secure(esdm_rpcs_reqbuf, 0,
		      ESDM_RPCS_BUF_WRITE_HEADER_SZ + message_length);

	return ret;

out_failure:
	/* Nothing was written yet - tell the client the call failed */
	esdm_rpcs_send_failure(rpc_conn);
	return ret;
}

/* Pack the message into a ProtobufC structure and write it to the receiver. */
static int esdm_rpcs_pack(const ProtobufCMessage *message,
			  struct esdm_rpcs_connection *rpc_conn)
{
	if (!protobuf_c_message_check(message))
		return esdm_rpcs_send_failure(rpc_conn);

	return esdm_rpcs_pack_internal(message, rpc_conn);
}

/* Is the calling RPC client a privileged user? */
bool esdm_rpc_client_is_privileged(void *closure_data)
{
	struct esdm_rpcs_connection *rpc_conn = closure_data;
	struct ucred cred;
	socklen_t len = sizeof(cred);

	if (getsockopt(rpc_conn->child_fd, SOL_SOCKET, SO_PEERCRED, &cred,
		       &len) < 0)
		return false;

	if (cred.uid == 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Remote client is privileged\n");
		return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "Remote client is not privileged\n");
	return false;
}

static void esdm_rpcs_response_closure(const ProtobufCMessage *message,
				       void *closure_data)
{
	struct esdm_rpcs_connection *rpc_conn = closure_data;
	int ret;

	ret = esdm_rpcs_pack(message, rpc_conn);

	if (ret) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Failed to serialize response: %d\n", ret);
	}

	return;
}

/* Unpack the received data and invoke the intended ProtobufC handler. */
static int esdm_rpcs_unpack(struct esdm_rpcs_connection *rpc_conn,
			    struct esdm_rpc_proto_cs *received_data)
{
	const ProtobufCMessageDescriptor *desc;
	struct esdm_rpcs *proto = rpc_conn->proto;
	ProtobufCService *service = proto->service;
	ProtobufCMessage *message = NULL;
	struct esdm_rpc_proto_cs_header *header = &received_data->header;
	uint32_t method_index = header->method_index;
	int ret = 0;

	/*
	 * Unpack the request into a thread-local scratch buffer via a bump
	 * allocator rather than malloc()/free() on every call. Each worker
	 * thread processes one request at a time, so a single reused buffer
	 * is safe. The consumed range is zeroized at the end to avoid leaving
	 * a copy of the request payload (e.g. write_data entropy) in memory.
	 */
	static __thread uint8_t unpack_buf[ESDM_RPC_MAX_UNPACK_SIZE];
	struct buffer tlh = {
		.len = sizeof(unpack_buf),
		.consumed = 0,
		.buf = unpack_buf,
	};
	ProtobufCAllocator allocator = {
		.alloc = esdm_rpc_alloc,
		.free = esdm_rpc_free,
		.allocator_data = &tlh,
	};

	CKINT(esdm_rpc_proto_get_descriptor(service, received_data, &desc));
	message = protobuf_c_message_unpack(desc, &allocator,
					    header->message_length,
					    received_data->data);

	CKNULL(message, -ENOMEM);

	rpc_conn->method_index = method_index;
	rpc_conn->request_id = header->request_id;

	/* Invoke the RPC call */
	service->invoke(service, method_index, message,
			esdm_rpcs_response_closure, rpc_conn);

out:
	if (message)
		protobuf_c_message_free_unpacked(message, &allocator);
	if (tlh.consumed)
		memset_secure(unpack_buf, 0, tlh.consumed);

	/* Pick up the error from esdm_rpcs_write_data */
	if (rpc_conn->child_fd == -1)
		ret = -EPIPE;

	return ret;
}

/*
 * Answer a STARTDTLS request, in the clear - see ESDM_RPC_PROTO_STARTDTLS in
 * esdm_rpc_protocol.h. Accepted, the connection goes on to the probe, and to
 * the handshake after it.
 *
 * The DTLS is set up before the answer goes out: the client starts the
 * handshake as soon as it has the answer, and what it sends then is to find
 * the DTLS there.
 */
static int esdm_rpcs_startdtls(struct esdm_rpcs_connection *rpc_conn,
			       const struct esdm_rpc_proto_cs_header *header)
{
	struct {
		struct esdm_rpc_proto_sc_header header;
		uint32_t magic;
	} __attribute__((packed)) answer;
	struct esdm_dtls_ctx *ctx;
	struct esdm_dtls *dtls = NULL;
	int ret;

	/* Once, in the clear, and with nothing but the header */
	if (rpc_conn->dtls_state != esdm_rpcs_dtls_none ||
	    header->message_length)
		return -EINVAL;

	rpc_conn->method_index = header->method_index;
	rpc_conn->request_id = header->request_id;

	ctx = esdm_rpcs_dtls_ctx_get();
	if (!ctx || esdm_rpcs_worker_dtls >= ESDM_RPCS_MAX_WORKER_DTLS ||
	    !esdm_peer_limit_get(&esdm_rpcs_dtls_limit, rpc_conn->peer_account))
		goto refuse;

	if (esdm_dtls_alloc(ctx, rpc_conn->child_fd, ESDM_RPC_MAX_MSG_SIZE,
			    &dtls)) {
		esdm_peer_limit_put(&esdm_rpcs_dtls_limit,
				    rpc_conn->peer_account);
		goto refuse;
	}
	rpc_conn->dtls_counted = true;
	esdm_rpcs_worker_dtls++;

	answer.header.status_code =
		le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	answer.header.method_index = le_bswap32(rpc_conn->method_index);
	answer.header.message_length = le_bswap32(sizeof(answer.magic));
	answer.header.request_id = le_bswap32(rpc_conn->request_id);
	answer.magic = le_bswap32(ESDM_RPC_PROTO_STARTDTLS);

	ret = esdm_rpcs_write_data(rpc_conn, (uint8_t *)&answer,
				   sizeof(answer));
	if (ret) {
		/* The connection is closed, and its accounting undone */
		esdm_dtls_free(dtls);
		return ret;
	}

	rpc_conn->dtls = dtls;
	rpc_conn->dtls_state = esdm_rpcs_dtls_probe;

	return 0;

refuse:
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Refusing DTLS on client FD %d\n", rpc_conn->child_fd);
	return esdm_rpcs_send_failure(rpc_conn);
}

/*
 * Handle one request that was received in full into the per-worker request
 * buffer: validate its header, then unpack and dispatch it.
 */
static int esdm_rpcs_process(struct esdm_rpcs_connection *rpc_conn,
			     ssize_t received)
{
	int ret = 0;

	/* We insist on having at least a header received. */
	if (received < (ssize_t)sizeof(struct esdm_rpc_proto_cs_header)) {
		ret = -EINVAL;
		goto out;
	}

	/* Header is received, analyze it. */
	struct esdm_rpc_proto_cs_header *header =
		(struct esdm_rpc_proto_cs_header *)esdm_rpcs_reqbuf;

	/* Convert incoming data to LE */
	header->message_length = le_bswap32(header->message_length);
	header->method_index = le_bswap32(header->method_index);
	header->request_id = le_bswap32(header->request_id);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Server received: message length %u, message index %u, request ID %u\n",
		header->message_length, header->method_index,
		header->request_id);

	/*
	 * Fail, if the buffer length the client specified
	 * contains too much buffer data. As the client also
	 * checks this, it is a clear failure.
	 */
	if (header->message_length > ESDM_RPC_MAX_INTERNAL_MSG_SIZE) {
		ret = -EINVAL;
		goto out;
	}

	/* Is data received to small? */
	if (received < (ssize_t)(sizeof(struct esdm_rpc_proto_cs_header) +
				 header->message_length)) {
		ret = -EINVAL;
		goto out;
	}

	/* Not a method of the service, but a step towards DTLS */
	if (header->method_index == ESDM_RPC_PROTO_STARTDTLS) {
		ret = esdm_rpcs_startdtls(rpc_conn, header);
		goto out;
	}

	/*
	 * We now have a filled buffer that has a header and received
	 * as much data as the header defined. We also start the
	 * processing of data and the subsequent submission of the answer here.
	 */
	CKINT(esdm_rpcs_unpack(rpc_conn,
			       (struct esdm_rpc_proto_cs *)esdm_rpcs_reqbuf));

out:
	if (received > 0) {
		memset_secure(esdm_rpcs_reqbuf, 0, (size_t)received);
	}
	return ret;
}

static bool esdm_rpcs_handshake_begin(uint64_t *start);
static void esdm_rpcs_handshake_end(uint64_t start);

/*
 * Go on with the DTLS handshake of a connection, as far as what the client
 * sent allows.
 *
 * @return 0 when it is complete, -EAGAIN while it waits for the client - or is
 *	   put off to the next round, see ESDM_RPCS_HANDSHAKE_BUDGET_NS -, another
 *	   negative errno if it failed
 */
static int esdm_rpcs_handshake(struct esdm_rpcs_connection *rpc_conn)
{
	uint64_t start;
	int ret;

	/* Left in the socket, the client's message makes it ready again */
	if (!esdm_rpcs_handshake_begin(&start))
		return -EAGAIN;

	ret = esdm_dtls_handshake(rpc_conn->dtls);
	esdm_rpcs_handshake_end(start);
	if (ret == -EAGAIN)
		return -EAGAIN;

	if (ret) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "DTLS handshake with client FD %d failed: %s\n",
			    rpc_conn->child_fd, strerror(-ret));
		return ret;
	}

	rpc_conn->dtls_state = esdm_rpcs_dtls_active;
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Client FD %d of UID %u encrypted with DTLS (%s)\n",
		    rpc_conn->child_fd, (unsigned int)rpc_conn->peer_uid,
		    esdm_dtls_cipher(rpc_conn->dtls));

	/* Idle from here on, the handshake counts as an answer */
	clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);

	return 0;
}

/* Read data from the RPC connection into a local buffer. */
static int esdm_rpcs_read(struct esdm_rpcs_connection *rpc_conn)
{
	ssize_t received;
	int ret;

	if (rpc_conn->child_fd < 0)
		return -EINVAL;

	if (rpc_conn->dtls_state == esdm_rpcs_dtls_handshake) {
		ret = esdm_rpcs_handshake(rpc_conn);
		/*
		 * The client sends its first request only once it has the end
		 * of the handshake - unless the DTLS holds one already, which
		 * the socket does not signal any more.
		 */
		if (ret || !esdm_dtls_pending(rpc_conn->dtls))
			return ret;
	}

	do {
		bool probe = rpc_conn->dtls_state == esdm_rpcs_dtls_probe;

		if (rpc_conn->dtls_state == esdm_rpcs_dtls_active) {
			/*
			 * A request spanning several records is not complete
			 * before its last one: no request yet, and no activity
			 * either - the idle timeout bounds how long the parts
			 * received so far are kept.
			 */
			received =
				esdm_dtls_recv(rpc_conn->dtls, esdm_rpcs_reqbuf,
					       sizeof(esdm_rpcs_reqbuf));
			if (received < 0) {
				if (received != -EAGAIN)
					esdm_logger(
						LOGGER_DEBUG, LOGGER_C_RPC,
						"Receiving on client FD %d failed: %s\n",
						rpc_conn->child_fd,
						strerror((int)-received));
				return (int)received;
			}
		} else {
			/*
			 * The client uses SOCK_SEQPACKET which ensures that
			 * always the full message is submitted in one send
			 * operation.
			 */
			received = read(rpc_conn->child_fd, esdm_rpcs_reqbuf,
					sizeof(esdm_rpcs_reqbuf));
			if (received < 0)
				return -errno;
		}

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Read %zd bytes\n",
			    received);

		ret = esdm_rpcs_process(rpc_conn, received);

		/* The probe is answered in the clear, the handshake follows */
		if (!ret && probe)
			rpc_conn->dtls_state = esdm_rpcs_dtls_handshake;

		/*
		 * Idle from the answer on, not from the request: a call that
		 * takes longer than the idle timeout - a privileged one such as
		 * the self test - would otherwise have its connection reaped
		 * right after its answer, failing the next request the client
		 * sends on it.
		 */
		clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);

		/*
		 * A request the DTLS read off the socket already is not
		 * signalled by it any more. A client sends one at a time and
		 * reads its answer first, so this is a client not following
		 * the protocol - which the answers it does not read stop.
		 */
	} while (!ret && rpc_conn->dtls_state == esdm_rpcs_dtls_active &&
		 esdm_dtls_pending(rpc_conn->dtls));

	return ret;
}

#ifdef ESDM_FUZZING
/* Documented with its declaration in esdm_rpc_server.h */
bool esdm_rpcs_fuzz_conn_encrypted(void *closure_data)
{
	const struct esdm_rpcs_connection *rpc_conn = closure_data;

	return rpc_conn && rpc_conn->dtls_state == esdm_rpcs_dtls_active;
}

/* Documented with its declaration in esdm_rpc_server.h */
int esdm_rpcs_fuzz_request(ProtobufCService *service, bool privileged,
			   const uint8_t *data, size_t len, int out_fd)
{
	struct esdm_rpcs proto;
	struct esdm_rpcs_connection rpc_conn;
	int ret;

	if (!service || (len && !data))
		return -EINVAL;

	/* A read cannot deliver more than the buffer holds */
	if (len > sizeof(esdm_rpcs_reqbuf))
		len = sizeof(esdm_rpcs_reqbuf);

	memset(&proto, 0, sizeof(proto));
	proto.service = service;
	proto.server_listening_fd = -1;
	proto.privileged = privileged;

	memset(&rpc_conn, 0, sizeof(rpc_conn));
	rpc_conn.proto = &proto;

	/*
	 * A failed write closes the connection's descriptor. Hand over a
	 * duplicate, so that the caller's one stays usable for the next
	 * request whatever becomes of this one.
	 */
	rpc_conn.child_fd = fcntl(out_fd, F_DUPFD_CLOEXEC, 0);
	if (rpc_conn.child_fd < 0)
		return -errno;

	memcpy(esdm_rpcs_reqbuf, data, len);

	ret = esdm_rpcs_process(&rpc_conn, (ssize_t)len);

	/* Along with whatever a STARTDTLS request set up */
	esdm_rpcs_conn_close(&rpc_conn, false);

	return ret;
}
#endif /* ESDM_FUZZING */

/*
 * Close the connection and give up what it holds - but its memory, which the
 * event loop may still be referring to, see esdm_rpcs_loop_del().
 */
static void esdm_rpcs_end_conn(struct esdm_rpcs_connection *rpc_conn)
{
	esdm_rpcs_conn_close(rpc_conn, true);
	if (rpc_conn->peer_counted) {
		esdm_peer_limit_put(&esdm_rpcs_peer_limit,
				    rpc_conn->peer_account);
		rpc_conn->peer_counted = false;
	}
	/*
	 * No per-connection request buffer to wipe here anymore - the shared
	 * per-worker esdm_rpcs_reqbuf is zeroized after every request in
	 * esdm_rpcs_read()/esdm_rpcs_pack_internal().
	 */
}

static void esdm_rpcs_release_conn(struct esdm_rpcs_connection *rpc_conn)
{
	if (!rpc_conn)
		return;
	esdm_rpcs_end_conn(rpc_conn);
	free(rpc_conn);
}

/*
 * Time a worker may spend per round of its event loop on the calls that
 * collect from the entropy sources, see esdm_rpcs_expensive_begin().
 *
 * A worker serves the requests of up to ESDM_RPCS_MAX_EVENTS ready connections
 * per round, one after the other. A prediction resistant request of at most
 * ESDM_RPC_MAX_PR_REQUEST_SIZE bytes costs a full reseed each - some 6 ms with
 * the Jitter RNG as the only entropy source, more with slower sources - and a
 * request for seed material collects from every entropy source just the same
 * (esdm_get_seed()). Unbound, a client spreading such requests over a few
 * hundred connections holds up every other client of that worker for seconds
 * per round. The prediction resistant DRNG and the seed collection serve one
 * caller at a time anyway (in turns, and under the lock of esdm_get_seed()),
 * so the bound costs no throughput of either, only how long a worker may be
 * tied to them at a stretch. Both kinds of calls share it: what holds up the other
 * clients is the time spent on them together.
 *
 * A time rather than a number of requests, as the cost of one depends on the
 * entropy sources. The first request of a round is always served, so even a
 * collection longer than this makes progress.
 */
#define ESDM_RPCS_ROUND_BUDGET_NS (25ULL * 1000 * 1000)

/*
 * Time a worker may spend per round of its event loop on DTLS handshakes, see
 * esdm_rpcs_handshake_begin().
 *
 * A handshake costs the server an ECDH key generation, an ECDSA signature and
 * an ECDH key agreement, which is what a few hundred requests in the clear
 * cost. The clients reconnect once a connection was idle for half of
 * ESDM_RPC_IDLE_TIMEOUT_USEC, and every new connection does a handshake: a
 * burst of them - or a client opening connections for nothing but their
 * handshakes - would otherwise hold up the requests of every other client of
 * the worker for as long. Beyond this time, a step of a handshake is put off
 * to the next round. Its message is left in the socket, which makes the
 * connection ready again at once, so the step is taken in the next round, after
 * the requests of the other connections.
 *
 * A bound of its own rather than a share of ESDM_RPCS_ROUND_BUDGET_NS: a
 * handshake put off costs its client a moment, whereas a prediction resistant
 * or seed request turned away for its budget is retried by the client only
 * after a pause - handshakes would push those out where they did not before.
 * The first step of a round is always taken, so handshakes make progress
 * whatever they cost.
 */
#define ESDM_RPCS_HANDSHAKE_BUDGET_NS (10ULL * 1000 * 1000)

/*
 * Time this worker thread spent in such calls and in handshakes in the current
 * round of its event loop. Only bounded inside a worker's event loop: a request
 * handed to the service any other way - the fuzz harnesses do - is not part of
 * a round.
 */
static __thread struct {
	bool in_round;
	uint64_t spent_ns;
	uint64_t handshake_ns;
} esdm_rpcs_round;

static uint64_t esdm_rpcs_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* A new round of this worker's event loop begins. */
static void esdm_rpcs_round_start(void)
{
	esdm_rpcs_round.in_round = true;
	esdm_rpcs_round.spent_ns = 0;
	esdm_rpcs_round.handshake_ns = 0;
}

/*
 * May the calling worker start a call collecting from the entropy sources in
 * this round, see ESDM_RPCS_ROUND_BUDGET_NS? @what names the call for the log.
 * If so, @start receives the time it starts, to be handed to
 * esdm_rpcs_expensive_end() once it returned.
 */
static bool esdm_rpcs_expensive_begin(const char *what, uint64_t *start)
{
	if (esdm_rpcs_round.in_round &&
	    esdm_rpcs_round.spent_ns >= ESDM_RPCS_ROUND_BUDGET_NS) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "%s: budget of this round used up - client to retry\n",
			    what);
		return false;
	}

	*start = esdm_rpcs_now_ns();

	return true;
}

/* Charge a call started with esdm_rpcs_expensive_begin() to the round. */
static void esdm_rpcs_expensive_end(uint64_t start)
{
	esdm_rpcs_round.spent_ns += esdm_rpcs_now_ns() - start;
}

/*
 * May the calling worker take a step of a DTLS handshake in this round, see
 * ESDM_RPCS_HANDSHAKE_BUDGET_NS? If so, @start receives the time it starts, to
 * be handed to esdm_rpcs_handshake_end().
 */
static bool esdm_rpcs_handshake_begin(uint64_t *start)
{
	if (esdm_rpcs_round.in_round &&
	    esdm_rpcs_round.handshake_ns >= ESDM_RPCS_HANDSHAKE_BUDGET_NS)
		return false;

	*start = esdm_rpcs_now_ns();

	return true;
}

/* Charge a step started with esdm_rpcs_handshake_begin() to the round. */
static void esdm_rpcs_handshake_end(uint64_t start)
{
	esdm_rpcs_round.handshake_ns += esdm_rpcs_now_ns() - start;
}

ssize_t esdm_rpcs_get_random_bytes_pr(uint8_t *buf, size_t buflen)
{
	uint64_t start;
	ssize_t ret;

	if (!esdm_rpcs_expensive_begin("Prediction resistant generation",
				       &start))
		return -EAGAIN;

	ret = esdm_get_random_bytes_pr_noblock(buf, buflen);
	esdm_rpcs_expensive_end(start);

	return ret;
}

ssize_t esdm_rpcs_get_seed(uint64_t *buf, size_t nbytes, unsigned int flags)
{
	uint64_t start;
	ssize_t ret;

	if (!esdm_rpcs_expensive_begin("Seed collection", &start))
		return -EAGAIN;

	ret = esdm_get_seed(buf, nbytes, flags | ESDM_GET_SEED_NONBLOCK);
	esdm_rpcs_expensive_end(start);

	return ret;
}

static bool esdm_time_after(struct timespec *curr, struct timespec *timeout)
{
	if (curr == NULL || timeout == NULL)
		return false;

	if (curr->tv_sec > timeout->tv_sec)
		return true;
	if (curr->tv_sec == timeout->tv_sec && curr->tv_nsec > timeout->tv_nsec)
		return true;

	return false;
}

/* Where the client of a connection is in a call, see esdm_rpcs_conn_state() */
enum esdm_rpcs_conn_state {
	esdm_rpcs_conn_idle,
	/* An answer the client did not read yet - it can after a close */
	esdm_rpcs_conn_answered,
	/* A request not read yet - a close would lose it */
	esdm_rpcs_conn_requested,
};

static enum esdm_rpcs_conn_state
esdm_rpcs_conn_state(const struct esdm_rpcs_connection *rpc_conn)
{
	int inq = 0, outq = 0;

	/*
	 * In doubt, the client is further into the call. A request read off
	 * the socket by the DTLS already is one not read yet as well. A
	 * connection in the middle of its handshake is idle while the server
	 * waits for the client, and closing it ends the handshake: the client
	 * goes on in the clear on its next connection then, see
	 * ESDM_RPC_PROTO_STARTDTLS.
	 */
	if (ioctl(rpc_conn->child_fd, SIOCINQ, &inq) || inq > 0 ||
	    (rpc_conn->dtls && esdm_dtls_pending(rpc_conn->dtls)))
		return esdm_rpcs_conn_requested;
	if (ioctl(rpc_conn->child_fd, SIOCOUTQ, &outq) || outq > 0)
		return esdm_rpcs_conn_answered;

	return esdm_rpcs_conn_idle;
}

static int esdm_rpcs_uid_cmp(const void *a, const void *b)
{
	uid_t x = *(const uid_t *)a, y = *(const uid_t *)b;

	return (x > y) - (x < y);
}

/*
 * The connection of a full worker to close for a new one, see
 * ESDM_RPC_RESERVED_FDS. @list is in the order of the last activity, the least
 * recent first. NULL if every connection has a request not read yet. One left
 * to drain holds no slot any more, see esdm_rpcs_reclaim(), and is not counted.
 */
static struct esdm_rpcs_connection *
esdm_rpcs_evict_candidate(struct esdm_rpcs_connection_list *list)
{
	uid_t uids[ESDM_RPCS_MAX_WORKER_CONNECTIONS];
	/* The first one found, per state and whether of the preferred UID */
	struct esdm_rpcs_connection *rpc_conn,
		*cand[esdm_rpcs_conn_requested][2] = { { NULL } };
	size_t i, n = 0, run = 0, best_run = 0;
	uid_t best = 0;

	TAILQ_FOREACH(rpc_conn, list, tailq)
	{
		if (n == ARRAY_SIZE(uids))
			break;
		if (!rpc_conn->closing)
			uids[n++] = rpc_conn->peer_account;
	}

	/* The user with the most connections */
	qsort(uids, n, sizeof(uids[0]), esdm_rpcs_uid_cmp);
	for (i = 0; i < n; i++) {
		run = (i && uids[i] == uids[i - 1]) ? run + 1 : 1;
		if (run > best_run) {
			best_run = run;
			best = uids[i];
		}
	}

	/*
	 * The least recent idle one of that user, else of any user - which is
	 * also the choice when no user holds more than one. Only without an
	 * idle one, one with an unread answer, chosen the same way.
	 */
	TAILQ_FOREACH(rpc_conn, list, tailq)
	{
		bool preferred =
			(best_run > 1 && rpc_conn->peer_account == best);
		enum esdm_rpcs_conn_state state;

		if (rpc_conn->closing ||
		    (!preferred && cand[esdm_rpcs_conn_idle][0]))
			continue;

		state = esdm_rpcs_conn_state(rpc_conn);
		if (state == esdm_rpcs_conn_requested)
			continue;
		if (state == esdm_rpcs_conn_idle && preferred)
			return rpc_conn;
		if (!cand[state][preferred])
			cand[state][preferred] = rpc_conn;
	}

	for (i = 0; i < ARRAY_SIZE(cand); i++) {
		if (cand[i][1])
			return cand[i][1];
		if (cand[i][0])
			return cand[i][0];
	}

	return NULL;
}

/* Are the slots of all workers serving @proto taken? */
static bool esdm_rpcs_full(struct esdm_rpcs *proto)
{
	return atomic_load(&proto->num_connections) >=
	       atomic_load(&proto->max_connections);
}

/* Account the slot @rpc_conn of @thread takes up, in @num of its own */
static void esdm_rpcs_conn_get(struct esdm_rpc_thread *thread,
			       struct esdm_rpcs_connection *rpc_conn,
			       size_t *num)
{
	++*num;
	atomic_fetch_add(&thread->proto->num_connections, 1);
	rpc_conn->slot_counted = true;
}

/* Give up the slot of @rpc_conn of @thread, unless it was already */
static void esdm_rpcs_conn_put(struct esdm_rpc_thread *thread,
			       struct esdm_rpcs_connection *rpc_conn,
			       size_t *num)
{
	if (!rpc_conn->slot_counted)
		return;

	--*num;
	atomic_fetch_sub(&thread->proto->num_connections, 1);
	rpc_conn->slot_counted = false;
}

/*
 * The event loop of a worker: what it waits for - its listening socket, its
 * connections, its idle timer and the eventfd that ends it - and the wait for
 * the events of its next round. The events of a round come as epoll events
 * whichever way they were waited for: of a connection with its address as the
 * data, of the others with the ESDM_RPCS_EVENT_* below.
 *
 * Two ways to wait, both telling when a descriptor is ready - the worker reads
 * and writes its connections itself, as does the DTLS of a connection:
 *
 * epoll, the default: one epoll instance per worker, every descriptor in it
 * level triggered. What is left unread is reported again in the next round -
 * a request put off for the budget of the round, a connection left to drain,
 * an event voided for a connection closed to make room, connections waiting
 * beyond the ESDM_RPCS_MAX_ACCEPTS of a round.
 *
 * io_uring (meson option rpc-io-uring): one ring per worker, set up by the
 * worker itself and used by nobody else. Each descriptor has a poll of the
 * ring, one-shot: its completion is the event, and the poll is armed anew once
 * the round served the event, in the system call that waits for the next ones
 * - the re-armed polls and the wait go to the kernel together. A poll armed on
 * a descriptor that is ready completes at once, so what is left unread is
 * reported again in the next round, as by epoll. A multishot poll would not:
 * it completes when the socket is woken, once per wakeup, and a request left
 * in it would not be reported again - so only the idle timer, whose event is
 * read in full each time, has one, where the kernel offers it. A connection
 * closed while its poll is armed is kept in memory until the completion of the
 * poll, which carries the address of the connection, cancelled by the next
 * submission; the ring's teardown takes the remaining ones along at the exit.
 *
 * The listening socket is not polled while the worker takes no new connection,
 * see esdm_rpcs_handler(). With epoll, it is taken out of the epoll instance;
 * with io_uring, its poll is not armed again - one armed already completes
 * when a client connects, and the worker looks at the socket once more,
 * finding no slot and leaving the connection to another worker, as with epoll.
 *
 * Where io_uring cannot be set up - a kernel without it or with
 * kernel.io_uring_disabled set, or a seccomp filter of a container or a service
 * manager refusing it - the worker falls back to epoll, saying so once.
 */
struct esdm_rpcs_loop {
	/* The epoll instance, -1 while the worker waits with its io_uring */
	int epfd;
	int listen_fd;
	int timer_fd;
	int exit_fd;
	/* Is the listening socket polled? See esdm_rpcs_loop_listen() */
	bool listen_armed;
#ifdef ESDM_RPC_IO_URING
	bool uring;
	struct io_uring ring;
	/* The polls of the ring in flight for the descriptors but connections */
	bool listen_polled;
	bool timer_polled;
	bool exit_polled;
	/* The idle timer is polled multishot, until the kernel refuses it */
	bool timer_multishot;
	/* Connections whose poll is to be armed again with the next wait */
	struct esdm_rpcs_connection_list rearm;
	/*
	 * Connections closed while their poll was armed, freed with its
	 * completion - linked by their tailq, see esdm_rpcs_loop_del()
	 */
	struct esdm_rpcs_connection_list closed;
#endif
};

/* Events a worker takes per round of its event loop */
#define ESDM_RPCS_MAX_EVENTS 512

/*
 * The data of the events of a round but those of the connections - no address
 * of a connection has these values
 */
#define ESDM_RPCS_EVENT_LISTEN 0
#define ESDM_RPCS_EVENT_TIMER 1
#define ESDM_RPCS_EVENT_EXIT 2
/* An event of a connection closed before the event was handled */
#define ESDM_RPCS_EVENT_STALE 3
/* The completion of the cancellation of a poll, io_uring only */
#define ESDM_RPCS_EVENT_CANCEL 4

/* Ready to be torn down, see esdm_rpcs_loop_open() for the setup */
static void esdm_rpcs_loop_init(struct esdm_rpcs_loop *loop)
{
	memset(loop, 0, sizeof(*loop));
	loop->epfd = -1;
	loop->listen_fd = -1;
	loop->timer_fd = -1;
	loop->exit_fd = -1;
	loop->listen_armed = true;
#ifdef ESDM_RPC_IO_URING
	TAILQ_INIT(&loop->rearm);
	TAILQ_INIT(&loop->closed);
#endif
}

static int esdm_rpcs_epoll_open(struct esdm_rpcs_loop *loop)
{
	int ret;

	loop->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (loop->epfd < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to create epoll instance: %s\n",
			    strerror(-ret));
		return ret;
	}

	/* server socket */
	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->listen_fd,
		      &(struct epoll_event){
			      .events = EPOLLIN,
			      .data.u64 = ESDM_RPCS_EVENT_LISTEN,
		      }) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to add server FD %d to epoll: %s\n",
			    loop->listen_fd, strerror(-ret));
		return ret;
	}

	/* timerfd for cleanup */
	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->timer_fd,
		      &(struct epoll_event){
			      .events = EPOLLIN,
			      .data.u64 = ESDM_RPCS_EVENT_TIMER,
		      }) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to add timer FD %d to epoll: %s\n",
			    loop->timer_fd, strerror(-ret));
		return ret;
	}

	/* eventfd for fast termination */
	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, loop->exit_fd,
		      &(struct epoll_event){
			      .events = EPOLLIN,
			      .data.u64 = ESDM_RPCS_EVENT_EXIT,
		      }) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to add event FD %d to epoll: %s\n",
			    loop->exit_fd, strerror(-ret));
		return ret;
	}

	return 0;
}

#ifdef ESDM_RPC_IO_URING

/*
 * Flags of the ring a liburing too old to know them is not asked for: it would
 * not use the ring the way they require.
 */
#ifndef IORING_SETUP_SUBMIT_ALL
#define IORING_SETUP_SUBMIT_ALL 0
#endif
#ifndef IORING_SETUP_COOP_TASKRUN
#define IORING_SETUP_COOP_TASKRUN 0
#endif
#ifndef IORING_SETUP_SINGLE_ISSUER
#define IORING_SETUP_SINGLE_ISSUER 0
#endif
#ifndef IORING_SETUP_DEFER_TASKRUN
#define IORING_SETUP_DEFER_TASKRUN 0
#endif

/*
 * Size of the rings. A round re-arms the polls of at most ESDM_RPCS_MAX_EVENTS
 * connections; should the submission queue run full all the same, what it
 * holds is submitted on the way. Completions are in flight for at most one poll
 * per connection, a worker holding ESDM_RPCS_MAX_WORKER_CONNECTIONS, and for
 * the cancellations of polls - the kernel keeps what does not fit in the queue
 * (IORING_FEAT_NODROP, which is required).
 */
#define ESDM_RPCS_URING_SQ_ENTRIES ESDM_RPCS_MAX_EVENTS
#define ESDM_RPCS_URING_CQ_ENTRIES (2 * ESDM_RPCS_MAX_WORKER_CONNECTIONS)

/* The fallback, or the ring, is reported once per process */
static atomic_flag esdm_rpcs_uring_reported = ATOMIC_FLAG_INIT;

static int esdm_rpcs_uring_open(struct esdm_rpcs_loop *loop)
{
	/*
	 * Most wanted first: the completions processed as the worker waits
	 * for them, by the worker - which is the only one submitting -, rather
	 * than by interrupting it at once (Linux 6.1); the cooperative variant
	 * of that (Linux 5.19); then whatever the kernel takes.
	 */
	static const unsigned int setup_flags[] = {
		IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN |
			IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
		IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN,
		0,
	};
	struct io_uring_params params;
	unsigned int i;
	int ret = -EINVAL;

	BUILD_BUG_ON(POLLIN != EPOLLIN || POLLERR != EPOLLERR ||
		     POLLHUP != EPOLLHUP || POLLRDHUP != EPOLLRDHUP);

	for (i = 0; i < ARRAY_SIZE(setup_flags); i++) {
		memset(&params, 0, sizeof(params));
		params.flags = IORING_SETUP_CQSIZE | setup_flags[i];
		params.cq_entries = ESDM_RPCS_URING_CQ_ENTRIES;
		ret = io_uring_queue_init_params(ESDM_RPCS_URING_SQ_ENTRIES,
						 &loop->ring, &params);
		if (ret != -EINVAL)
			break;
	}

	/*
	 * Without IORING_FEAT_NODROP (Linux 5.5), a completion that does not
	 * fit is dropped - and with it a connection, whose poll would never
	 * be armed again.
	 */
	if (!ret && !(params.features & IORING_FEAT_NODROP)) {
		io_uring_queue_exit(&loop->ring);
		ret = -EOPNOTSUPP;
	}

	/*
	 * Logged whatever the verbosity: whoever built it in is to see that it
	 * is not used - in a container, say, which refuses io_uring.
	 */
	if (ret) {
		if (!atomic_flag_test_and_set(&esdm_rpcs_uring_reported))
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_RPC,
				"io_uring cannot be set up for the RPC worker threads, waiting with epoll: %s\n",
				strerror(-ret));
		return ret;
	}

	/* Spares looking up the ring's descriptor in every system call */
	(void)io_uring_register_ring_fd(&loop->ring);

	loop->uring = true;
	loop->timer_multishot = true;

	if (!atomic_flag_test_and_set(&esdm_rpcs_uring_reported))
		esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
			    "RPC worker threads wait with io_uring\n");

	return 0;
}

/* An entry of the submission queue - NULL if it stays full */
static struct io_uring_sqe *esdm_rpcs_uring_sqe(struct esdm_rpcs_loop *loop)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(&loop->ring);

	if (!sqe) {
		/* Full: hand what it holds to the kernel already */
		io_uring_submit(&loop->ring);
		sqe = io_uring_get_sqe(&loop->ring);
	}

	return sqe;
}

/* Submit a poll of @fd for @events, @data the data of its event */
static bool esdm_rpcs_uring_poll(struct esdm_rpcs_loop *loop, int fd,
				 unsigned int events, uint64_t data,
				 bool multishot)
{
	struct io_uring_sqe *sqe = esdm_rpcs_uring_sqe(loop);

	if (!sqe)
		return false;

	if (multishot)
		io_uring_prep_poll_multishot(sqe, fd, events);
	else
		io_uring_prep_poll_add(sqe, fd, events);
	io_uring_sqe_set_data64(sqe, data);

	return true;
}

/* Have the poll of @rpc_conn armed with the next wait */
static void esdm_rpcs_uring_rearm(struct esdm_rpcs_loop *loop,
				  struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->poll_armed || rpc_conn->poll_queued)
		return;

	TAILQ_INSERT_TAIL(&loop->rearm, rpc_conn, poll_entry);
	rpc_conn->poll_queued = true;
}

/*
 * Submit what is to be polled - every descriptor without a poll in flight but
 * the listening socket while it is not to be - and the cancellations of the
 * polls of closed connections. What finds no room in the submission queue is
 * submitted with the next wait.
 */
static void esdm_rpcs_uring_arm(struct esdm_rpcs_loop *loop)
{
	struct esdm_rpcs_connection *rpc_conn, *tmp;
	struct io_uring_sqe *sqe;

	if (loop->listen_armed && !loop->listen_polled)
		loop->listen_polled =
			esdm_rpcs_uring_poll(loop, loop->listen_fd, POLLIN,
					     ESDM_RPCS_EVENT_LISTEN, false);
	if (!loop->timer_polled)
		loop->timer_polled = esdm_rpcs_uring_poll(
			loop, loop->timer_fd, POLLIN, ESDM_RPCS_EVENT_TIMER,
			loop->timer_multishot);
	if (!loop->exit_polled)
		loop->exit_polled = esdm_rpcs_uring_poll(loop, loop->exit_fd,
							 POLLIN,
							 ESDM_RPCS_EVENT_EXIT,
							 false);

	TAILQ_FOREACH_SAFE(rpc_conn, &loop->rearm, poll_entry, tmp)
	{
		if (!esdm_rpcs_uring_poll(loop, rpc_conn->child_fd,
					  POLLIN | POLLRDHUP,
					  (uint64_t)(uintptr_t)rpc_conn, false))
			break;
		TAILQ_REMOVE(&loop->rearm, rpc_conn, poll_entry);
		rpc_conn->poll_queued = false;
		rpc_conn->poll_armed = true;
	}

	TAILQ_FOREACH(rpc_conn, &loop->closed, tailq)
	{
		if (rpc_conn->poll_cancelled)
			continue;
		sqe = esdm_rpcs_uring_sqe(loop);
		if (!sqe)
			break;
		io_uring_prep_cancel64(sqe, (uint64_t)(uintptr_t)rpc_conn, 0);
		io_uring_sqe_set_data64(sqe, ESDM_RPCS_EVENT_CANCEL);
		rpc_conn->poll_cancelled = true;
	}
}

/*
 * Wait for the completions of the polls, at most @maxevents of which are taken
 * as the events of the round - the others stay in the completion queue for the
 * next one. Returns the number of events, a negative errno if the wait failed,
 * or a poll of a descriptor but a connection did.
 */
static int esdm_rpcs_uring_wait(struct esdm_rpcs_loop *loop,
				struct epoll_event *events, int maxevents)
{
	struct esdm_rpcs_connection *rpc_conn;
	struct io_uring_cqe *cqe;
	unsigned int head, seen = 0;
	int n = 0, ret;

	esdm_rpcs_uring_arm(loop);

	ret = io_uring_submit_and_wait(&loop->ring, 1);
	/*
	 * Completions the kernel could not post yet, see IORING_FEAT_NODROP:
	 * those posted are taken first, which makes room.
	 */
	if (ret == -EBUSY || ret == -EAGAIN)
		ret = 0;
	if (ret < 0)
		return ret;

	ret = 0;
	io_uring_for_each_cqe(&loop->ring, head, cqe)
	{
		uint64_t data = io_uring_cqe_get_data64(cqe);
		int res = cqe->res;

		if (n >= maxevents)
			break;
		seen++;

		switch (data) {
		case ESDM_RPCS_EVENT_CANCEL:
			continue;
		case ESDM_RPCS_EVENT_LISTEN:
			loop->listen_polled = false;
			break;
		case ESDM_RPCS_EVENT_TIMER:
			if (!(cqe->flags & IORING_CQE_F_MORE))
				loop->timer_polled = false;
			/* A kernel before Linux 5.13 refuses multishot */
			if (res == -EINVAL && loop->timer_multishot) {
				loop->timer_multishot = false;
				continue;
			}
			break;
		case ESDM_RPCS_EVENT_EXIT:
			loop->exit_polled = false;
			break;
		default:
			rpc_conn = (struct esdm_rpcs_connection *)(uintptr_t)
				data;
			rpc_conn->poll_armed = false;

			/* The poll was the last reference to it */
			if (rpc_conn->closed) {
				TAILQ_REMOVE(&loop->closed, rpc_conn, tailq);
				free(rpc_conn);
				continue;
			}

			/* Polled again after this round served the event */
			esdm_rpcs_uring_rearm(loop, rpc_conn);

			/* A poll that failed is a connection that failed */
			events[n].events = res < 0 ? EPOLLERR : (uint32_t)res;
			events[n].data.u64 = 0;
			events[n].data.ptr = rpc_conn;
			n++;
			continue;
		}

		if (res < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Polling with io_uring failed: %s\n",
				    strerror(-res));
			ret = res;
			break;
		}

		events[n].events = (uint32_t)res;
		events[n].data.u64 = data;
		n++;
	}
	io_uring_cq_advance(&loop->ring, seen);

	return ret ? ret : n;
}

#endif /* ESDM_RPC_IO_URING */

/*
 * Set up the event loop of a worker polling @listen_fd, @timer_fd and
 * @exit_fd, with io_uring where it is built, not switched off and can be set
 * up, with epoll otherwise.
 */
static int esdm_rpcs_loop_open(struct esdm_rpcs_loop *loop, int listen_fd,
			       int timer_fd, int exit_fd)
{
	loop->listen_fd = listen_fd;
	loop->timer_fd = timer_fd;
	loop->exit_fd = exit_fd;

#ifdef ESDM_RPC_IO_URING
	if (atomic_load(&esdm_rpcs_io_uring_enabled) &&
	    !esdm_rpcs_uring_open(loop))
		return 0;
#endif

	return esdm_rpcs_epoll_open(loop);
}

/* Wait for the events of the next round, see esdm_rpcs_loop */
static int esdm_rpcs_loop_wait(struct esdm_rpcs_loop *loop,
			       struct epoll_event *events, int maxevents)
{
	int nfds;

#ifdef ESDM_RPC_IO_URING
	if (loop->uring)
		return esdm_rpcs_uring_wait(loop, events, maxevents);
#endif

	nfds = epoll_wait(loop->epfd, events, maxevents, -1);

	return nfds < 0 ? -errno : nfds;
}

/* Poll the listening socket, or stop doing so, see esdm_rpcs_loop */
static void esdm_rpcs_loop_listen(struct esdm_rpcs_loop *loop, bool armed)
{
	struct epoll_event lev = {
		.events = armed ? EPOLLIN : 0,
		.data.u64 = ESDM_RPCS_EVENT_LISTEN,
	};

	if (armed == loop->listen_armed)
		return;

#ifdef ESDM_RPC_IO_URING
	if (loop->uring) {
		loop->listen_armed = armed;
		return;
	}
#endif

	if (epoll_ctl(loop->epfd, EPOLL_CTL_MOD, loop->listen_fd, &lev) == 0)
		loop->listen_armed = armed;
}

/* Poll a new connection; returns a negative errno if it cannot be */
static int esdm_rpcs_loop_add(struct esdm_rpcs_loop *loop,
			      struct esdm_rpcs_connection *rpc_conn)
{
	struct epoll_event ev = { .events = EPOLLIN | EPOLLRDHUP,
				  .data.ptr = rpc_conn };

#ifdef ESDM_RPC_IO_URING
	/* From the end of this round on, like a connection whose event it served */
	if (loop->uring) {
		esdm_rpcs_uring_rearm(loop, rpc_conn);
		return 0;
	}
#endif

	if (epoll_ctl(loop->epfd, EPOLL_CTL_ADD, rpc_conn->child_fd, &ev) < 0)
		return -errno;

	return 0;
}

/*
 * Stop polling a connection that is closed for good. Returns whether it may
 * be freed: one whose poll of the io_uring is still armed is taken over by the
 * loop instead and freed with the completion of the poll - or at the end of the
 * loop -, which carries its address.
 */
static bool esdm_rpcs_loop_del(struct esdm_rpcs_loop *loop,
			       struct esdm_rpcs_connection *rpc_conn)
{
#ifdef ESDM_RPC_IO_URING
	if (loop->uring) {
		if (rpc_conn->poll_queued) {
			TAILQ_REMOVE(&loop->rearm, rpc_conn, poll_entry);
			rpc_conn->poll_queued = false;
		}
		if (!rpc_conn->poll_armed)
			return true;

		rpc_conn->closed = true;
		TAILQ_INSERT_TAIL(&loop->closed, rpc_conn, tailq);
		return false;
	}
#endif

	epoll_ctl(loop->epfd, EPOLL_CTL_DEL, rpc_conn->child_fd, NULL);

	return true;
}

/* Tear the event loop down, once its connections are dropped */
static void esdm_rpcs_loop_close(struct esdm_rpcs_loop *loop)
{
#ifdef ESDM_RPC_IO_URING
	if (loop->uring) {
		struct esdm_rpcs_connection *rpc_conn, *tmp;

		/* No completion comes any more, nothing refers to them */
		io_uring_queue_exit(&loop->ring);
		loop->uring = false;

		TAILQ_FOREACH_SAFE(rpc_conn, &loop->closed, tailq, tmp)
		{
			TAILQ_REMOVE(&loop->closed, rpc_conn, tailq);
			free(rpc_conn);
		}
	}
#endif

	if (loop->epfd >= 0) {
		close(loop->epfd);
		loop->epfd = -1;
	}
}

/*
 * Close a connection of @thread for good: out of the event loop @loop and out
 * of @list, its slot given up unless it was already.
 */
static void esdm_rpcs_conn_drop(struct esdm_rpc_thread *thread,
				struct esdm_rpcs_loop *loop,
				struct esdm_rpcs_connection_list *list,
				struct esdm_rpcs_connection *rpc_conn,
				size_t *num)
{
	TAILQ_REMOVE(list, rpc_conn, tailq);
	esdm_rpcs_conn_put(thread, rpc_conn, num);
	if (esdm_rpcs_loop_del(loop, rpc_conn))
		esdm_rpcs_release_conn(rpc_conn);
	else
		esdm_rpcs_end_conn(rpc_conn);

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %zu\n", *num);
}

/*
 * Did the client send something the server has not read yet? It waits in the
 * socket's receive queue until the event loop takes it - in the next round if
 * it came after the events of this one were collected, or was not among them.
 * Nothing counts as sent if the queue cannot be told.
 */
static bool esdm_rpcs_input_queued(const struct esdm_rpcs_connection *rpc_conn)
{
	int inq = 0;

	if (ioctl(rpc_conn->child_fd, SIOCINQ, &inq))
		return false;

	return inq > 0;
}

/*
 * Close a connection the server gives up on by itself - one idle for the idle
 * timeout, or one closed to make room for a new one. Unlike one whose client
 * hung up, its client may be sending a request on it right now: closing the
 * socket would discard what arrived since the connection was found idle,
 * although the client's write succeeded. The client would see its connection
 * closed without an answer then - and it does not send a privileged request
 * again, as it cannot tell whether the server carried it out.
 *
 * So the reading side is shut down first. Every later write of the client
 * fails from then on, which tells it that the server never got the request,
 * and it sends it again on a new connection. What arrived before stays
 * readable: if anything did, the connection is not closed yet but served on,
 * and closed once the server read all of it - see esdm_rpcs_handler(). Its
 * slot and its user's count are given up right away all the same, which also
 * keeps it from being chosen to be closed once more.
 *
 * @return true if the connection was closed, false if it is left to drain
 */
static bool esdm_rpcs_reclaim(struct esdm_rpc_thread *thread,
			      struct esdm_rpcs_loop *loop,
			      struct esdm_rpcs_connection_list *list,
			      struct esdm_rpcs_connection *rpc_conn,
			      size_t *num)
{
	shutdown(rpc_conn->child_fd, SHUT_RD);

	if (!esdm_rpcs_input_queued(rpc_conn)) {
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		return true;
	}

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Serving what the client on FD %d sent before closing its connection\n",
		rpc_conn->child_fd);

	rpc_conn->closing = true;
	esdm_rpcs_conn_put(thread, rpc_conn, num);
	if (rpc_conn->peer_counted) {
		esdm_peer_limit_put(&esdm_rpcs_peer_limit,
				    rpc_conn->peer_account);
		rpc_conn->peer_counted = false;
	}

	return false;
}

/*
 * Close a connection of the full worker @thread, whose connections are @list,
 * for a new one, which takes over its slot - see esdm_rpcs_reclaim(). The
 * events still to be handled in this round, @num of @pending, are voided for
 * it: one left to drain is reported again in the next round. Returns false if
 * every connection has a request not read yet.
 */
static bool esdm_rpcs_make_room(struct esdm_rpc_thread *thread,
				struct esdm_rpcs_loop *loop,
				struct esdm_rpcs_connection_list *list,
				struct epoll_event *pending, int num,
				size_t *num_connections)
{
	struct esdm_rpcs_connection *victim = esdm_rpcs_evict_candidate(list);
	int i;

	if (!victim)
		return false;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Closing client FD %d of UID %u (user %u) to make room\n",
		    victim->child_fd, (unsigned int)victim->peer_uid,
		    (unsigned int)victim->peer_account);

	for (i = 0; i < num; i++) {
		if (pending[i].data.ptr == victim)
			pending[i].data.u64 = ESDM_RPCS_EVENT_STALE;
	}

	esdm_rpcs_reclaim(thread, loop, list, victim, num_connections);

	return true;
}

/*
 * May the connection be closed as idle? Only when it was idle for the whole
 * timeout, @threshold being its start, and no request of its client waits to
 * be read - the next round serves one that came in after the events of this
 * round were collected, or was not among them. A connection already left to
 * drain is closed by the event loop, see esdm_rpcs_reclaim().
 */
static bool esdm_rpcs_idle_reapable(struct esdm_rpcs_connection *rpc_conn,
				    struct timespec *threshold)
{
	if (rpc_conn->closing ||
	    !esdm_time_after(threshold, &rpc_conn->last_used))
		return false;

	return !esdm_rpcs_input_queued(rpc_conn);
}

/*
 * Connections a worker accepts per round of its event loop, as far as its
 * slots allow.
 *
 * A round serves every connection with a request once, in turn - the listening
 * socket is but one of its events. Accepting a single connection for it, a
 * worker busy with many connections let a burst of new ones in at one per
 * round, and a round takes as long as the requests of all others: the clients
 * connecting last waited for hundreds of rounds before their first request was
 * read, while those accepted first had all their requests served and went idle.
 * New connections take their turn in the round like the others instead, the
 * worker accepting as many of them as it serves requests of connections at
 * most.
 */
#define ESDM_RPCS_MAX_ACCEPTS ESDM_RPCS_MAX_EVENTS

/*
 * Serve an event of a connection of @thread, its connections @list: read and
 * answer the request of its client, or close it if its client is gone or it
 * failed. @revents are the events of the connection, 0 for one just accepted.
 * @accept_paused is cleared when the connection is closed.
 */
static void esdm_rpcs_serve(struct esdm_rpc_thread *thread,
			    struct esdm_rpcs_loop *loop,
			    struct esdm_rpcs_connection_list *list,
			    struct esdm_rpcs_connection *rpc_conn,
			    uint32_t revents, size_t *num, bool *accept_paused)
{
	int read_ret;

	/*
	 * The server's own shutdown of the reading side of a connection left to
	 * drain shows as EPOLLRDHUP as well, see esdm_rpcs_reclaim() - its
	 * client is still there.
	 */
	if (revents &
	    (rpc_conn->closing ? (EPOLLERR | EPOLLHUP) :
				 (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing client FD %d\n", rpc_conn->child_fd);
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		*accept_paused = false;
		return;
	}

	read_ret = esdm_rpcs_read(rpc_conn);

	/*
	 * Decide on the returned code, not the global errno: intermediate
	 * logger/handler calls may have clobbered errno since the failing read,
	 * and e.g. a stale EAGAIN would leave a half-torn connection (child_fd
	 * already closed on the EPIPE path) linger in the list until the idle
	 * timeout reaps it.
	 *
	 * A connection left to drain is closed once the server read all its
	 * client sent.
	 */
	if (read_ret && read_ret != -EAGAIN) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing incoming connection for FD %d\n",
			    rpc_conn->child_fd);
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		*accept_paused = false;
	} else if (rpc_conn->closing && !esdm_rpcs_input_queued(rpc_conn)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing drained connection for FD %d\n",
			    rpc_conn->child_fd);
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		*accept_paused = false;
	} else if (!read_ret) {
		/* Keep the list in the order of use */
		TAILQ_REMOVE(list, rpc_conn, tailq);
		TAILQ_INSERT_TAIL(list, rpc_conn, tailq);
	}
}

/*
 * Accept a connection on the listening socket of @thread and register it with
 * the event loop @loop and @list. The events of this round still to be
 * handled are @num_pending of @pending - a full worker closes one of its
 * connections to make room for the new one, see ESDM_RPC_RESERVED_FDS.
 *
 * @return 0 when a connection was taken off the backlog: the new one in
 *	   @new_conn, NULL there if it was turned away; -EAGAIN when no more is
 *	   to be accepted in this round - none is waiting, the descriptors ran
 *	   out (@accept_paused is set then), or every connection of a full
 *	   worker has a request not read yet; another negative errno when the
 *	   worker cannot go on.
 */
static int esdm_rpcs_accept(struct esdm_rpc_thread *thread,
			    struct esdm_rpcs_loop *loop,
			    struct esdm_rpcs_connection_list *list,
			    struct epoll_event *pending, int num_pending,
			    size_t *num, bool *accept_paused,
			    struct esdm_rpcs_connection **new_conn)
{
	struct esdm_rpcs_connection *rpc_conn;
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	bool admitted = false;
	int accepted_fd, ret;

	*new_conn = NULL;

	accepted_fd = accept4(thread->proto->server_listening_fd, NULL, NULL,
			      SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (accepted_fd < 0) {
		/*
		 * Out of file descriptors or memory: the connection stays
		 * queued and the level triggered listener would wake us again
		 * right away. Stop listening until a connection closes or the
		 * idle timer fires instead of spinning.
		 */
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
		    errno == ENOMEM) {
			if (!*accept_paused)
				esdm_logger(LOGGER_WARN, LOGGER_C_RPC,
					    "Cannot accept connections: %s\n",
					    strerror(errno));
			*accept_paused = true;
		}
		return -EAGAIN;
	}

	rpc_conn = calloc(1, sizeof(struct esdm_rpcs_connection));
	/*
	 * gracefully handle failing alloc after being initialized, we may only
	 * arrive here under temporary memory pressure
	 */
	if (rpc_conn == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to alloc client conn\n");
		close(accepted_fd);
		return 0;
	}
	rpc_conn->child_fd = accepted_fd;
	rpc_conn->proto = thread->proto;

	/*
	 * Refuse a peer at its connection limit right away rather than leave it
	 * queued, which would block the backlog for everybody else.
	 */
	if (getsockopt(accepted_fd, SOL_SOCKET, SO_PEERCRED, &cred,
		       &cred_len) == 0) {
		rpc_conn->peer_uid = cred.uid;
		rpc_conn->peer_account = esdm_peer_account(accepted_fd, &cred);
		admitted = esdm_peer_limit_get(&esdm_rpcs_peer_limit,
					       rpc_conn->peer_account);
	}
	if (!admitted) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Refusing client FD %d\n", accepted_fd);
		esdm_rpcs_release_conn(rpc_conn);
		return 0;
	}
	rpc_conn->peer_counted = true;

	/*
	 * Once no room can be made, there is none for the connections waiting
	 * behind this one either - they stay queued for the next round.
	 */
	if (*num >= thread->max_connections &&
	    !esdm_rpcs_make_room(thread, loop, list, pending, num_pending,
				 num)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_RPC,
			"Refusing client FD %d, every connection has a request pending\n",
			accepted_fd);
		esdm_rpcs_release_conn(rpc_conn);
		return -EAGAIN;
	}

	/*
	 * Idle since now, not since the epoch - or the idle reaper could close
	 * the connection before its first request is read.
	 */
	clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
	ret = esdm_rpcs_loop_add(loop, rpc_conn);
	if (ret < 0) {
		switch (-ret) {
		case ENOMEM:
		case ENOSPC:
			/* resource limit — reject this connection, keep running */
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Unable to add client FD %d to epoll: %s\n",
				    accepted_fd, strerror(-ret));
			esdm_rpcs_release_conn(rpc_conn);
			return 0;
		default:
			/*
			 * This conn was never inserted into the list, so the
			 * cleanup of the worker cannot reach it - free/close
			 * here to avoid leaking the conn and its fd.
			 */
			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Unable to add client FD %d to epoll, exiting worker: %s\n",
				accepted_fd, strerror(-ret));
			esdm_rpcs_release_conn(rpc_conn);
			return ret;
		}
	}
	TAILQ_INSERT_TAIL(list, rpc_conn, tailq);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Processing new incoming connection for FD %d\n",
		    rpc_conn->child_fd);
	esdm_rpcs_conn_get(thread, rpc_conn, num);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "num connections: %zu\n", *num);

	*new_conn = rpc_conn;

	return 0;
}

/* Thread main for receiving new connections and processing them. */
static int esdm_rpcs_handler(void *args)
{
	struct esdm_rpcs_connection_list rpc_conn_list;
	struct esdm_rpc_thread *thread = args;
	struct esdm_rpcs_connection *tmp1;
	struct esdm_rpcs_connection *tmp2;
	struct esdm_rpcs_loop loop;
	struct epoll_event events[ESDM_RPCS_MAX_EVENTS];
	size_t max_connections = 0, num_connections = 0;
	/*
	 * Close a connection for a new one once all workers are full, see
	 * ESDM_RPC_RESERVED_FDS
	 */
	bool evict = false;
	/* accept() ran out of resources - see the accept path below */
	bool accept_paused = false;
	int tfd = -1;
	int ret = 0;

	/* Initialized first - the cleanup at out: walks the list. */
	TAILQ_INIT(&rpc_conn_list);
	esdm_rpcs_loop_init(&loop);

	if (thread == NULL) {
		ret = -EINVAL;
		goto out;
	}

	thread_set_name(thread->proto->privileged ? rpc_handler_priv :
						    rpc_handler_unpriv,
			thread->id);

	max_connections = thread->max_connections;
	evict = !thread->proto->privileged;

	/*
	 * The random numbers this worker hands out from a node DRNG of its own -
	 * worker i from node i + 1, the DRNG of node 0 being the initial one -
	 * rather than from whichever node DRNG it finds free, probing them
	 * under the lock of the node array like every other worker: see
	 * esdm_drng_node_bind(). There is a worker per node, so the last one
	 * wraps around to node 1 with worker 0 and the others have their node
	 * to themselves; the EGD workers take theirs from the last node
	 * downwards. Not the privileged interface, none of whose calls
	 * generates random numbers. The prediction resistant calls stay on the
	 * prediction resistance DRNG.
	 */
	if (!thread->proto->privileged && atomic_load(&esdm_rpcs_drng_mapping)) {
		ret = esdm_drng_node_bind(thread->id, false);
		if (ret < 0) {
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
				    "Unprivileged RPC worker %u is mapped to no node DRNG: %s\n",
				    thread->id, strerror(-ret));
		} else {
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
				    "Unprivileged RPC worker %u is mapped to node DRNG %d\n",
				    thread->id, ret);
		}
		ret = 0;
	}

	/* cleanup timer */
	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	struct itimerspec its = {
		.it_interval = {
			.tv_sec = ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000,
			.tv_nsec = ESDM_RPC_IDLE_TIMEOUT_USEC % 1000000 * 1000,
		 },
		.it_value = {
			.tv_sec = ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000,
			.tv_nsec = ESDM_RPC_IDLE_TIMEOUT_USEC % 1000000 * 1000,
		},
	};
	if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to arm cleanup timer: %s\n",
			    strerror(-ret));
		goto out;
	}

	/* The listening socket, the cleanup timer, the eventfd to terminate */
	ret = esdm_rpcs_loop_open(&loop, thread->proto->server_listening_fd,
				  tfd, thread->eventfd);
	if (ret)
		goto out;

	while (atomic_load(&server_exit) == 0) {
		int nfds;

		/*
		 * The listening socket is level-triggered: while it is polled
		 * and a connection is pending, it keeps being reported
		 * readable. Once the per-worker connection cap is reached the
		 * accept branch below stops accepting, so leaving it polled
		 * would spin the worker at 100% CPU. Reconcile whether it is
		 * polled with the current connection count before blocking:
		 * stop at the cap, and poll it again once a slot frees up so new
		 * connections are served again. This also gives real
		 * backpressure (pending clients stay queued in the listen
		 * backlog instead of being dropped) and leaves the connection
		 * to a worker with a free slot. Once all are full, a worker
		 * that makes room by closing a connection keeps accepting
		 * instead.
		 */
		esdm_rpcs_loop_listen(
			&loop, (num_connections < max_connections ||
				(evict && esdm_rpcs_full(thread->proto))) &&
				       !accept_paused);

		nfds = esdm_rpcs_loop_wait(&loop, events,
					   ESDM_RPCS_MAX_EVENTS);
		/* signal? */
		if (nfds == -EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Waiting for events interrupted\n");
			continue;
		}

		if (nfds < 0) {
			ret = nfds;
			esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
				    "Waiting for events failed: %s\n",
				    strerror(-ret));
			goto out;
		}

		/* The events below are this round, see ESDM_RPCS_ROUND_BUDGET_NS */
		esdm_rpcs_round_start();

		bool do_cleanup = false;

		for (int i = 0; i < nfds; i++) {
			struct esdm_rpcs_connection *rpc_conn = NULL;

			if (events[i].data.u64 == ESDM_RPCS_EVENT_STALE)
				continue;

			/* timer fired */
			if (events[i].data.u64 == ESDM_RPCS_EVENT_TIMER) {
				uint64_t expirations;
				ssize_t v = read(tfd, &expirations,
						 sizeof(expirations));
				do_cleanup = true;
				accept_paused = false;
				(void)v;
				continue;
			}

			/* event fired */
			if (events[i].data.u64 == ESDM_RPCS_EVENT_EXIT) {
				uint64_t event_val;
				ssize_t v = read(thread->eventfd, &event_val,
						 sizeof(event_val));
				(void)v;
				esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
					    "termination event triggered\n");
				break;
			}

			/* new connections? */
			if (events[i].data.u64 == ESDM_RPCS_EVENT_LISTEN) {
				unsigned int accepted;

				for (accepted = 0;
				     (events[i].events & EPOLLIN) &&
				     accepted < ESDM_RPCS_MAX_ACCEPTS &&
				     (num_connections < max_connections ||
				      (evict && esdm_rpcs_full(thread->proto)));
				     accepted++) {
					ret = esdm_rpcs_accept(
						thread, &loop, &rpc_conn_list,
						events + i + 1, nfds - i - 1,
						&num_connections,
						&accept_paused, &rpc_conn);
					if (ret == -EAGAIN) {
						ret = 0;
						break;
					}
					if (ret)
						goto out;

					/* Its first request, if it sent one */
					if (rpc_conn)
						esdm_rpcs_serve(
							thread, &loop,
							&rpc_conn_list,
							rpc_conn, 0,
							&num_connections,
							&accept_paused);
				}
				continue;
			}

			rpc_conn = events[i].data.ptr;
			esdm_rpcs_serve(thread, &loop, &rpc_conn_list, rpc_conn,
					events[i].events, &num_connections,
					&accept_paused);
		}

		if (do_cleanup) {
			struct timespec timeout_threshold;
			clock_gettime(CLOCK_MONOTONIC, &timeout_threshold);
			/*
			 * Subtract the whole timeout, including the part below
			 * one second - dropping it would keep a connection for
			 * up to a second longer than configured, or reap it
			 * not at all with a timeout below one second.
			 */
			timeout_threshold.tv_sec -=
				ESDM_RPC_IDLE_TIMEOUT_USEC / 1000000;
			timeout_threshold.tv_nsec -=
				(long)(ESDM_RPC_IDLE_TIMEOUT_USEC % 1000000) *
				1000;
			if (timeout_threshold.tv_nsec < 0) {
				timeout_threshold.tv_nsec += 1000000000L;
				timeout_threshold.tv_sec--;
			}

			TAILQ_FOREACH_SAFE(tmp1, &rpc_conn_list, tailq, tmp2)
			{
				if (!esdm_rpcs_idle_reapable(
					    tmp1, &timeout_threshold))
					continue;

				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_RPC,
					"Closing incoming connection for FD %d after timeout\n",
					tmp1->child_fd);
				esdm_rpcs_reclaim(thread, &loop, &rpc_conn_list,
						  tmp1, &num_connections);
				accept_paused = false;
			}
		}
	}

out:
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "Exiting worker thread\n");

	TAILQ_FOREACH_SAFE(tmp1, &rpc_conn_list, tailq, tmp2)
	{
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing incoming connection for FD %d at exit\n",
			    tmp1->child_fd);
		esdm_rpcs_conn_drop(thread, &loop, &rpc_conn_list, tmp1,
				    &num_connections);
	}

	esdm_rpcs_loop_close(&loop);
	if (tfd >= 0) {
		close(tfd);
	}

	esdm_drng_node_unbind();

	/*
	 * A worker that gives up leaves its share of the clients unserved, and
	 * the last one to go leaves the interface dead while the server looks
	 * alive. Take the server down with an error instead, so that a service
	 * manager notices and restarts it - the error reaches the exit status
	 * through thread_wait() in esdm_rpcs_workerloop().
	 */
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_RPC,
			"RPC worker thread failed, terminating server: %s\n",
			strerror(-ret));
		esdm_rpc_server_signal_exit();
	}

	return ret;
}

/* The ESDM RPC server main worker loop. */
static int esdm_rpcs_workerloop(struct esdm_rpcs *proto)
{
	struct esdm_rpc_thread *threads = NULL;
	size_t num_threads = 0, max_connections;
	int ret = 0;
	uint32_t t;

	if (proto->server_listening_fd < 0)
		return -EINVAL;

	CKNULL(proto->service, -EINVAL);

	/*
	 * Done by esdm_rpcs_peer_limit_init() already for the server - but not
	 * for a harness serving the interface, whose first accept would wait
	 * for it otherwise.
	 */
	esdm_peer_account_init();

	if (proto->privileged) {
		num_threads = 1;
	} else {
		num_threads = min_size(esdm_config_online_nodes(),
				       THREADING_MAX_WORKER_THREADS);
	}

	threads = calloc(num_threads, sizeof(struct esdm_rpc_thread));
	if (threads == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Unable to allocate thread structures in memory\n");
		ret = -errno;
		goto out;
	}

	max_connections = esdm_rpcs_worker_slots(proto, num_threads);
	atomic_store(&proto->num_connections, 0);
	atomic_store(&proto->max_connections, max_connections * num_threads);

	esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
		    "Using %zu %sprivileged RPC worker threads, %zu connections each\n",
		    num_threads, proto->privileged ? "" : "un",
		    max_connections);

	for (t = 0; t < num_threads; ++t) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
			    "Starting %sprivileged RPC worker thread %u\n",
			    proto->privileged ? "" : "un", t);
		threads[t].proto = proto;
		threads[t].id = t;
		threads[t].max_connections = max_connections;
		threads[t].eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (threads[t].eventfd < 0) {
			ret = -errno;
		} else {
			ret = thread_start(esdm_rpcs_handler, &threads[t], 0,
					   NULL);
			if (ret) {
				close(threads[t].eventfd);
				threads[t].eventfd = -1;
			}
		}

		/*
		 * The workers started so far already use their slots of
		 * threads[] and all serve the same listening socket. Carry on
		 * with them, and give up only if there is none at all.
		 */
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"Starting %sprivileged RPC worker thread %u failed: %s\n",
				proto->privileged ? "" : "un", t,
				strerror(-ret));
			if (!t)
				goto out;
			num_threads = t;
			atomic_store(&proto->max_connections,
				     max_connections * num_threads);
			break;
		}

		esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
			    "Started %sprivileged RPC worker thread %u\n",
			    proto->privileged ? "" : "un", t);
	}

	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_load(&server_exit) != 0));

	for (t = 0; t < num_threads; ++t) {
		uint64_t val = 1;
		ssize_t v = write(threads[t].eventfd, &val, sizeof(val));
		(void)v;
	}

	ret = thread_wait(true);

	for (t = 0; t < num_threads; ++t) {
		close(threads[t].eventfd);
		threads[t].eventfd = -1;
	}

out:
	if (threads != NULL) {
		free(threads);
		threads = NULL;
	}
	esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
		    "Exiting %sprivileged RPC worker loop\n",
		    proto->privileged ? "" : "un");
	return ret;
}

/*
 * Open the socket that we want to use for receiving data. A Unix domain socket
 * file is created with @mode, see esdm_server_bind_unix().
 */
static int esdm_rpcs_start(const char *unix_socket, mode_t mode,
			   uint16_t tcp_port, ProtobufCService *service,
			   struct esdm_rpcs *proto)
{
	struct sockaddr_un addr_un;
	struct sockaddr_in addr_in;
	struct sockaddr *address;
	int errsv, fd = -1, protocol_family;
	socklen_t address_len;

	if (unix_socket) {
		protocol_family = PF_UNIX;
		addr_un.sun_family = AF_UNIX;
		snprintf(addr_un.sun_path, sizeof(addr_un.sun_path), "%s",
			 unix_socket);
		address_len = sizeof(addr_un);
		address = (struct sockaddr *)(&addr_un);

		esdm_server_remove_stale_socket(unix_socket, SOCK_SEQPACKET);
	} else if (tcp_port) {
		protocol_family = PF_INET;
		memset(&addr_in, 0, sizeof(addr_in));
		addr_in.sin_family = AF_INET;
		addr_in.sin_port = htons(tcp_port);
		address_len = sizeof(addr_in);
		address = (struct sockaddr *)(&addr_in);
	} else {
		return -EINVAL;
	}

	/*
	 * The use of SOCK_SEQPACKET is intended to guarantee that the entire
	 * message is sent and that the receiving client will only receive
	 * the full message. Short reads will therefore not happen on the client
	 * side.
	 */
	fd = socket(protocol_family,
		    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot create socket: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	/*
	 * The socket file gets its access mode as it is created: setting it
	 * with a chmod(2) of the path afterwards would follow a symlink swapped
	 * in for the socket meanwhile - and run as root.
	 */
	if (unix_socket)
		errsv = -esdm_server_bind_unix(fd, &addr_un, mode);
	else
		errsv = bind(fd, address, address_len) < 0 ? errno : 0;
	if (errsv) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot bind to socket: %s\n",
			    strerror(errsv));
		if (errsv == EADDRINUSE && unix_socket)
			esdm_logger(
				LOGGER_ERR, LOGGER_C_RPC,
				"RPC Server: another process is listening on %s - is its systemd socket unit already started?\n",
				unix_socket);
		close(fd);
		return -errsv;
	}

	if (listen(fd, 4096) < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "RPC Server: cannot listen on socket: %s\n",
			    strerror(errsv));
		close(fd);
		return -errsv;
	}

	proto->server_listening_fd = fd;
	proto->service = service;

	return 0;
}

/* Use the socket that we want to use for receiving data. */
static int esdm_rpcs_start_systemd(const char *socket_name,
				   ProtobufCService *service,
				   struct esdm_rpcs *proto)
{
#ifdef ESDM_SYSTEMD_SUPPORT
	int fd = -1;
	int type;
	socklen_t length = sizeof(type);

	if (systemd_listen_fds() > 0) {
		fd = systemd_listen_fd_for_name(socket_name);
	}
	if (fd >= 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "use systemd provided socket %s = %i\n",
			    socket_name, fd);

		if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == -1) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"unable to fetch socket type of systemd provided socket");
			close(fd);
			return -1;
		}

		if (type != SOCK_SEQPACKET) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"systemd provided socket is not of type SOCK_SEQPACKET");
			close(fd);
			return -1;
		}

		(void)fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
		int flags = fcntl(fd, F_GETFL);
		if (!(flags & O_NONBLOCK)) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_SERVER,
				"systemd provided socket cannot be set to non-blocking");
			close(fd);
			return -1;
		}

		proto->server_listening_fd = fd;
		proto->service = service;
		return 0;
	}

	esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
		    "unable to find systemd provided socket %s\n", socket_name);
	return -ENOENT;
#else
	(void)socket_name;
	(void)service;
	(void)proto;
	return -ENOENT;
#endif
}

/*
 * Set to true once a socket had to be bound by us despite a socket activation
 * environment being present: the sockets are then ours and have to be removed
 * at shutdown like in a non-activated run. A PID namespace supervisor forked
 * before the sockets were set up never observes this and keeps treating them as
 * systemd-owned - the conservative choice, as removing a socket systemd still
 * listens on would break every future activation.
 */
static atomic_bool esdm_rpcs_self_bound_socket = false;

/*
 * Obtain the listening socket, preferring one handed over by systemd.
 *
 * A socket bound here is created with @mode. One handed over by systemd is
 * left as it is: its lifecycle and its access mode are systemd's business, not
 * ours.
 */
static int esdm_rpcs_start_socket(const char *socket_name,
				  const char *socket_path, mode_t mode,
				  ProtobufCService *service,
				  struct esdm_rpcs *proto)
{
	int ret;

	if (systemd_listen_fds() > 0) {
		ret = esdm_rpcs_start_systemd(socket_name, service, proto);
		if (!ret)
			return 0;

		/*
		 * A socket that was handed over but is unusable is a hard
		 * error: systemd is listening on it, so binding it ourselves
		 * would only fail with EADDRINUSE and hide the real cause.
		 */
		if (ret != -ENOENT)
			return ret;

		/*
		 * LISTEN_FDS is set, but none of the descriptors is ours - the
		 * environment was inherited from an unrelated socket activated
		 * context. Bind the socket ourselves instead of refusing to
		 * start.
		 */
		esdm_logger(
			LOGGER_WARN, LOGGER_C_SERVER,
			"No systemd socket named %s handed over - binding %s directly\n",
			socket_name, socket_path);
		atomic_store(&esdm_rpcs_self_bound_socket, true);
	}

	return esdm_rpcs_start(socket_path, mode, 0, service, proto);
}

/* Terminating the RPC server. */
static void eesdm_rpcs_stop(struct esdm_rpcs *proto)
{
	if (proto->server_listening_fd >= 0) {
		close(proto->server_listening_fd);
		proto->server_listening_fd = -1;
	}
}

/* Initialize one thread handling an unprivileged interface instance */
static int esdm_rpcs_unpriv_init(void *args)
{
	struct esdm_rpcs unpriv_proto;
	ProtobufCService *unpriv_service =
		(ProtobufCService *)&unpriv_access_service;
	int ret;

	(void)args;

	thread_set_name(rpc_unpriv_server, 0);
	memset(&unpriv_proto, 0, sizeof(unpriv_proto));

	unpriv_proto.server_listening_fd = -1;
	unpriv_proto.privileged = false;

	/*
	 * Create the server handler for the unprivileged interface, its socket
	 * available for all users. A socket handed over by systemd carries the
	 * access mode of its .socket unit (SocketMode=), which is left alone:
	 * overriding it would silently ignore the administrator's
	 * configuration.
	 */
	CKINT(esdm_rpcs_start_socket(
		"ESDM_RPC_UNPRIV_SOCKET", ESDM_RPC_UNPRIV_SOCKET,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH,
		unpriv_service, &unpriv_proto));

	/* Notify the mother that the unprivileged thread is initialized. */
	atomic_store(&esdm_rpc_init_state, esdm_rpcs_state_unpriv_init);
	thread_wake_all(&esdm_rpc_thread_init_wait);

	if (atomic_load(&server_exit) != 0) {
		goto out;
	}

	/* Wait for the mother to drop the privileges. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_load(&esdm_rpc_init_state) ==
			   esdm_rpcs_state_perm_dropped) ||
				  (atomic_load(&server_exit) != 0));

	/* The privilege drop failed, or the server goes down meanwhile. */
	if (atomic_load(&server_exit) != 0)
		goto out;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Unprivileged server thread for %s available\n",
		    ESDM_RPC_UNPRIV_SOCKET);

	/* Server handing unprivileged interface in current thread */
	CKINT(esdm_rpcs_workerloop(&unpriv_proto));

out:
	eesdm_rpcs_stop(&unpriv_proto);

	/*
	 * Without this interface the server is of no use to most of its
	 * clients. Hand the error to the master and take the server down - the
	 * master may well still be waiting for the notification above, which
	 * is not going to come.
	 */
	if (ret) {
		atomic_store(&esdm_rpc_unpriv_ret, ret);
		esdm_rpc_server_signal_exit();
	}

	atomic_store(&esdm_rpc_unpriv_running, false);
	thread_wake_all(&esdm_rpc_thread_init_wait);

	return ret;
}

#ifdef ESDM_FUZZING
/* Documented with its declaration in esdm_rpc_server.h */
int esdm_rpcs_fuzz_serve(const char *socket_path, ProtobufCService *service,
			 bool privileged)
{
	struct esdm_rpcs proto;
	int ret;

	if (!socket_path || !service)
		return -EINVAL;

	memset(&proto, 0, sizeof(proto));
	proto.server_listening_fd = -1;
	proto.privileged = privileged;

	/*
	 * The socket rather than esdm_rpcs_start_socket(): a harness is not
	 * socket activated, and a stray LISTEN_FDS in its environment would
	 * otherwise take it to a descriptor that is not its own.
	 */
	CKINT(esdm_rpcs_start(socket_path, S_IRUSR | S_IWUSR, 0, service,
			      &proto));

	/*
	 * What is skipped compared to the interface initialization below is the
	 * privilege drop and the notifications around it, neither of which a
	 * harness can do - it does not run as root, and dropping to nobody is
	 * permanent.
	 */
	ret = esdm_rpcs_workerloop(&proto);

out:
	eesdm_rpcs_stop(&proto);

	return ret;
}
#endif /* ESDM_FUZZING */

/*
 * Initialize the RPC server interfaces:
 *	* The current thread processes the privileged RPC interface.
 *	* A newly started thread processes the unprivileged RPC interface.
 */
static int esdm_rpcs_interfaces_init(const char *username,
				     const char *groupname)
{
	struct esdm_rpcs priv_proto;
	ProtobufCService *priv_service =
		(ProtobufCService *)&priv_access_service;
	int ret;

	thread_set_name(rpc_priv_server, 0);
	memset(&priv_proto, 0, sizeof(priv_proto));

	priv_proto.server_listening_fd = -1;
	priv_proto.privileged = true;

	/*
	 * Create the server handler for the privileged interface in the main
	 * thread, its socket available for root only - from its creation on,
	 * so the file never has a looser mode for somebody else to connect
	 * through, not even for a moment. See above on the socket activation
	 * case.
	 */
	CKINT(esdm_rpcs_start_socket("ESDM_RPC_PRIV_SOCKET",
				     ESDM_RPC_PRIV_SOCKET, S_IRUSR | S_IWUSR,
				     priv_service, &priv_proto));

	/*
	 * Create the optional EGD compatibility socket while the privileges to
	 * bind it and to make it accessible to all users are still held. Its
	 * worker is only started after the privilege drop below.
	 */
	CKINT(esdm_egd_server_socket_init());

	/* Spawn the thread handling the unprivileged interface */
	atomic_store(&esdm_rpc_unpriv_running, true);
	ret = thread_start(esdm_rpcs_unpriv_init, NULL,
			   ESDM_THREAD_RPC_UNPRIV_GROUP, NULL);
	if (ret) {
		atomic_store(&esdm_rpc_unpriv_running, false);
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Starting server thread failed\n");
		goto out;
	}

	if (atomic_load(&server_exit) != 0) {
		goto out;
	}

	/* Wait for the unprivileged thread to complete initialization. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_load(&esdm_rpc_init_state) ==
			   esdm_rpcs_state_unpriv_init) ||
				  (atomic_load(&server_exit) != 0));

	/* The unprivileged thread failed, or the server goes down meanwhile. */
	if (atomic_load(&server_exit) != 0)
		goto out;

	/* Permanently drop all privileges */
	CKINT(drop_privileges_permanent(username ? username : "nobody",
					groupname ? groupname : NULL));

	/* Notify all unpriv handler threads that they can become active */
	atomic_store(&esdm_rpc_init_state, esdm_rpcs_state_perm_dropped);
	thread_wake_all(&esdm_rpc_thread_init_wait);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Privileged server thread for %s available\n",
		    ESDM_RPC_PRIV_SOCKET);

	/*
	 * Serve the optional EGD interface. Started only now so that all
	 * handling of the data its clients supply happens unprivileged.
	 */
	CKINT(esdm_egd_server_start());

	systemd_notify_status("ESDM ready, all sockets allocated");
	systemd_notify_ready();
	systemd_notify_status("Running");

	/* Server handing privileged interface in current thread */
	ret = esdm_rpcs_workerloop(&priv_proto);

out:
	eesdm_rpcs_stop(&priv_proto);

	/*
	 * Take the threads started so far down with us - the unprivileged one
	 * may still wait for the privilege drop that is not going to happen -
	 * and let it finish before the caller tears everything down.
	 */
	if (ret)
		esdm_rpc_server_signal_exit();
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  !atomic_load(&esdm_rpc_unpriv_running));

	/* A failure of the unprivileged interface is a failure of the server. */
	if (!ret)
		ret = atomic_load(&esdm_rpc_unpriv_ret);

	return ret;
}

static void esdm_rpc_priv_init_complete(void)
{
	if (atomic_load(&esdm_rpc_init_state) != esdm_rpcs_state_uninitialized)
		return;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "Privileged initialization complete\n");
	/* Notification that the privileged initialization is complete. */
	atomic_store(&esdm_rpc_init_state, esdm_rpcs_state_priv_init_complete);
	thread_wake_all(&esdm_rpc_thread_init_wait);
}

static int esdm_rpc_server_es_monitor(void __unused *unused)
{
	thread_set_name(es_monitor, 0);

	return esdm_init_monitor(esdm_rpc_priv_init_complete);
}

int esdm_rpc_server_init(const char *username, const char *groupname)
{
	int ret = 0;

	pthread_setname_np(pthread_self(), "ESDM master");

	/*
	 * Leave the mount, cgroup and network namespaces before the first
	 * thread is created. unshare() only moves the calling thread, and a
	 * thread inherits the namespaces of the thread creating it. Doing this
	 * later - e.g. as part of the privilege drop - leaves every thread
	 * created up to then, including the one spawning the unprivileged RPC
	 * workers, in the namespaces of the host.
	 *
	 * Nothing set up below needs the namespaces left here: the RPC and EGD
	 * sockets are bound to file system paths, which the copied mount table
	 * resolves to the same inodes as the host does, and a path bound
	 * AF_UNIX socket is reachable across network namespaces. Sockets passed
	 * in by systemd are file descriptors already and unaffected.
	 */
	CKINT(linux_isolate_namespace());

	/* Main ESDM Init DRNG state, ES', ... */
	CKINT(esdm_init());

	esdm_rpcs_peer_limit_init();

	/*
	 * The DTLS of the RPC interfaces, with the privileges still held and
	 * before any of their threads starts - see esdm_rpcs_dtls_ctx.
	 */
	esdm_rpcs_dtls_ctx_get();

	/* Initialize test pertubation support */
	CKINT(esdm_test_shm_status_init());

	/* One thread group */
	CKINT(thread_init(1));

	/*
	 * Create thread for entropy source monitor. This is fatal if it fails:
	 * the monitor thread is the only producer of the priv_init_complete
	 * notification (via esdm_rpc_priv_init_complete()), so the
	 * thread_wait_event() below would otherwise block forever waiting for a
	 * completion that can never arrive (short of a SIGTERM setting
	 * server_exit). Bail out instead of hanging startup.
	 */
	ret = thread_start(esdm_rpc_server_es_monitor, NULL,
			   ESDM_THREAD_ES_MONITOR, NULL);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_RPC,
			    "Starting ES monitor thread failed\n");
		goto out;
	}

	if (atomic_load(&server_exit) != 0) {
		goto out;
	}

	/* Wait for the privileged initialization to complete. */
	thread_wait_event(&esdm_rpc_thread_init_wait,
			  (atomic_load(&esdm_rpc_init_state) ==
			   esdm_rpcs_state_priv_init_complete) ||
				  (atomic_load(&server_exit) != 0));

	esdm_logger(LOGGER_WARN, LOGGER_C_RPC, "RPC server started\n");

	/*
	 * Start the RPC server threads. A failure must reach the exit status:
	 * a daemon that cannot serve its interfaces and still exits with 0 is
	 * not restarted by a service manager watching for failures.
	 */
	ret = esdm_rpcs_interfaces_init(username, groupname);

out:
	return ret;
}

/*
 * Async-signal-safe shutdown trigger. Only sets the exit flag and wakes
 * waiting threads. Does NOT join threads, acquire mutexes, or free memory.
 */
void esdm_rpc_server_signal_exit_safe(void)
{
	/*
	 * Async-signal-safe: the atomic store is just a barrier + store. No condvar
	 * broadcast here - pthread_cond_broadcast is not async-signal-safe and
	 * could self-deadlock if the interrupted thread held the condvar's
	 * internal lock. thread_wait_event()'s bounded re-poll makes blocked
	 * waiters observe server_exit within the backstop interval.
	 */
	atomic_store(&server_exit, 1);

	/* Also an atomic store only, hence equally async-signal-safe. */
	esdm_egd_server_signal_exit_safe();
}

void esdm_rpc_server_signal_exit(void)
{
	esdm_rpc_server_signal_exit_safe();
	thread_wake_all(&esdm_rpc_thread_init_wait);
}

void esdm_rpc_server_fini(void)
{
	esdm_rpc_server_signal_exit();

	/*
	 * Terminate the EGD worker before the ESDM is finalized - it is a
	 * special thread and therefore not covered by thread_wait_all(false).
	 */
	esdm_egd_server_fini();

	thread_wait_all(false);

	/* Terminate test pertubation support */
	esdm_test_shm_status_fini();
}

static void esdm_rpcs_cleanup_socket(const char *path)
{
	if (unlink(path) < 0) {
		if (errno != ENOENT) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_RPC,
				"ESDM Unix domain socket %s cannot be deleted: %s\n",
				path, strerror(errno));
		}
	} else {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "ESDM Unix domain socket %s deleted\n", path);
	}
}

void esdm_rpc_server_cleanup(void)
{
	if (!esdm_config_ipc_cleanup())
		return;

	/*
	 * Sockets passed in by systemd socket activation are created and
	 * removed by systemd - leave their lifecycle to it. Removing a socket
	 * systemd still listens on would leave the .socket unit bound to an
	 * unlinked inode and silently break every future activation.
	 *
	 * systemd_listen_fds() reports the state latched by
	 * systemd_listen_fds_init() before the server forked, so this decision
	 * cannot disagree with the one taken when the sockets were set up -
	 * not even in the PID namespace supervisor, which performs the cleanup
	 * on behalf of the daemon that dropped its privileges.
	 */
	if (systemd_listen_fds() <= 0 ||
	    atomic_load(&esdm_rpcs_self_bound_socket)) {
		esdm_rpcs_cleanup_socket(ESDM_RPC_UNPRIV_SOCKET);
		esdm_rpcs_cleanup_socket(ESDM_RPC_PRIV_SOCKET);
	}

	/*
	 * The EGD sockets may be socket activated as well, but whether one
	 * belongs to systemd is decided per listener - esdm_egd_server_cleanup()
	 * applies the systemd check itself rather than the one above. The
	 * --keep_ipc request is honored for them too: it is evaluated for all
	 * IPC objects at the top of this function.
	 */
	esdm_egd_server_cleanup();

	esdm_shm_status_cleanup_ipc();
}
