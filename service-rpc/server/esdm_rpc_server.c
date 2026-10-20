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
#include <sys/mman.h>
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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/*
	 * Served through the ring, see esdm_rpcs_loop: its requests arrive by
	 * the multishot receive of the connection, armed - recv_armed - until
	 * it ends, and its answers leave as sends of the ring, the one at
	 * the head of tx_head in flight - tx_inflight - while the others wait
	 * for it. A connection in the clear only: one switching to DTLS goes
	 * over to the poll, its receive cancelled - recv_cancel, set while it
	 * waits in the list rearm of the loop - before the answer to STARTDTLS
	 * goes out. So is the receive of a client sending a request before
	 * it has the answer of the one before, see esdm_rpcs_rx.
	 */
	bool ring_io;
	bool recv_armed;
	/*
	 * Is the receive armed a multishot one? Is the next one to take a
	 * single request? See esdm_rpcs_uring_recv().
	 */
	bool recv_multishot;
	bool recv_single;
	bool recv_cancel;
	bool recv_cancelled;
	bool tx_inflight;
	bool tx_queued;
	/* The client ended the connection, or the server's SHUT_RD drained it */
	bool rx_eof;
	/* In the list deferq of the loop, with requests in rx_defer_head */
	bool deferred;
	/* Requests received by the ring the worker did not serve yet */
	unsigned int rx_pending;
	/* The round of the loop that has a request of it, see esdm_rpcs_rx */
	uint64_t rx_round;
	unsigned int rx_defer_num;
	struct esdm_rpcs_rx *rx_defer_head, *rx_defer_tail;
	TAILQ_ENTRY(esdm_rpcs_connection) defer_entry;
	/* Answers waiting in tx_head, the first one possibly in flight */
	unsigned int tx_num;
	struct esdm_rpcs_tx *tx_head, *tx_tail;
	TAILQ_ENTRY(esdm_rpcs_connection) tx_entry;
#endif
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

#ifdef ESDM_RPC_IO_URING_MULTISHOT
/*
 * An answer of a connection served through the ring, see esdm_rpcs_loop: the
 * per-worker request buffer is used for the next request before the send of
 * the answer is submitted, so the answer is packed into one of these instead,
 * which the connection holds until its send completed. Taken from a small
 * cache of the worker, zeroized when it goes back.
 */
struct esdm_rpcs_tx {
	struct esdm_rpcs_tx *next;
	size_t len;
	uint8_t buf[ESDM_RPC_MAX_MSG_SIZE]
		__attribute__((aligned(sizeof(uint64_t))));
};

/* Answers of the worker kept for reuse, at most ESDM_RPCS_TX_CACHE */
#define ESDM_RPCS_TX_CACHE 16
static __thread struct esdm_rpcs_tx *esdm_rpcs_tx_cache;
static __thread unsigned int esdm_rpcs_tx_cached;

static struct esdm_rpcs_tx *esdm_rpcs_tx_get(void)
{
	struct esdm_rpcs_tx *tx = esdm_rpcs_tx_cache;

	if (tx) {
		esdm_rpcs_tx_cache = tx->next;
		esdm_rpcs_tx_cached--;
	} else {
		tx = malloc(sizeof(*tx));
		if (!tx)
			return NULL;
	}

	tx->next = NULL;
	/* All of it is wiped should it go back before it is sent */
	tx->len = sizeof(tx->buf);

	return tx;
}

static void esdm_rpcs_tx_put(struct esdm_rpcs_tx *tx)
{
	if (!tx)
		return;

	memset_secure(tx->buf, 0, tx->len);
	if (esdm_rpcs_tx_cached >= ESDM_RPCS_TX_CACHE) {
		free(tx);
		return;
	}
	tx->next = esdm_rpcs_tx_cache;
	esdm_rpcs_tx_cache = tx;
	esdm_rpcs_tx_cached++;
}

/* The cache of the calling worker, as it exits */
static void esdm_rpcs_tx_cache_free(void)
{
	struct esdm_rpcs_tx *tx;

	while ((tx = esdm_rpcs_tx_cache)) {
		esdm_rpcs_tx_cache = tx->next;
		free(tx);
	}
	esdm_rpcs_tx_cached = 0;
}

/*
 * Give up the answers of a connection that is closed - but the one whose send
 * is in flight, which its completion gives up
 */
static void esdm_rpcs_tx_drop(struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpcs_tx *tx = rpc_conn->tx_head, *next;

	if (tx && rpc_conn->tx_inflight) {
		next = tx->next;
		tx->next = NULL;
		rpc_conn->tx_tail = tx;
		rpc_conn->tx_num = 1;
		tx = next;
	} else {
		rpc_conn->tx_head = rpc_conn->tx_tail = NULL;
		rpc_conn->tx_num = 0;
	}

	while (tx) {
		next = tx->next;
		esdm_rpcs_tx_put(tx);
		tx = next;
	}
}

/*
 * Answers a connection may have waiting - a client sends one request at a
 * time and reads its answer before the next one, so more is a client that does
 * not read them, which is closed as one whose answer does not fit into its
 * socket, see esdm_rpcs_write_data().
 */
#define ESDM_RPCS_TX_MAX 16

static int esdm_rpcs_tx_queue(struct esdm_rpcs_connection *rpc_conn,
			      struct esdm_rpcs_tx *tx, size_t len);

/*
 * A request the ring received for a connection that has one in the round
 * already: copied out of the buffer of the ring, which goes back at once, and
 * served in a round to come, one per round - a client that sends requests
 * without waiting for the answers gets its turn in a round as everybody else,
 * as by the poll, and holds no buffer of the ring meanwhile. Its receive is
 * cancelled until they are served, which leaves what it sends further in the
 * socket. Bounded per connection and per worker - beyond, the client does not
 * read its answers, see esdm_rpcs_write_data().
 */
struct esdm_rpcs_rx {
	struct esdm_rpcs_rx *next;
	size_t len;
	uint8_t data[];
};

/*
 * Per connection: the requests one multishot receive can take into the
 * buffers of the ring at a time, twice
 */
#define ESDM_RPCS_RX_DEFER_MAX 64
/* Per worker, in bytes */
#define ESDM_RPCS_RX_DEFER_BYTES (8U << 20)

static void esdm_rpcs_rx_free(struct esdm_rpcs_rx *rx)
{
	memset_secure(rx->data, 0, rx->len);
	free(rx);
}

/* Give up the requests not served yet of a connection that is closed */
static void esdm_rpcs_rx_drop(struct esdm_rpcs_connection *rpc_conn,
			      size_t *bytes)
{
	struct esdm_rpcs_rx *rx;

	while ((rx = rpc_conn->rx_defer_head)) {
		rpc_conn->rx_defer_head = rx->next;
		*bytes -= rx->len;
		esdm_rpcs_rx_free(rx);
	}
	rpc_conn->rx_defer_tail = NULL;
	rpc_conn->rx_defer_num = 0;
}
#endif

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
 * Do the workers waiting with io_uring receive and send through it? See
 * esdm_rpc_server_set_io_uring_multishot()
 */
static atomic_bool esdm_rpcs_io_uring_multishot = true;

void esdm_rpc_server_set_io_uring_multishot(bool enable)
{
	atomic_store(&esdm_rpcs_io_uring_multishot, enable);
}

#if defined(ESDM_FUZZING) && defined(ESDM_RPC_IO_URING_MULTISHOT)
/* Multishot receives that ran out of buffers, see esdm_rpcs_fuzz_uring_enobufs */
static atomic_uint esdm_rpcs_enobufs;

unsigned int esdm_rpcs_fuzz_uring_enobufs(void)
{
	return atomic_load(&esdm_rpcs_enobufs);
}
#elif defined(ESDM_FUZZING)
unsigned int esdm_rpcs_fuzz_uring_enobufs(void)
{
	return 0;
}

void esdm_rpcs_fuzz_uring_bufs(unsigned int bufs)
{
	(void)bufs;
}
#endif

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

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* Sent by the ring, from a buffer of its own - see esdm_rpcs_tx */
	if (rpc_conn->ring_io) {
		struct esdm_rpcs_tx *tx;

		if (len > sizeof(tx->buf))
			return -EINVAL;
		tx = esdm_rpcs_tx_get();
		if (!tx) {
			esdm_rpcs_conn_close(rpc_conn, false);
			return -ENOMEM;
		}
		memcpy(tx->buf, data, len);
		return esdm_rpcs_tx_queue(rpc_conn, tx, len);
	}
#endif

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

	/*
	 * The answer is packed into the request buffer of the worker - or, for
	 * a connection served through the ring, into one it holds until the
	 * answer is sent, see esdm_rpcs_tx.
	 */
	uint8_t *buf = esdm_rpcs_reqbuf;
	uint8_t *payload_buf;
	const size_t payload_max =
		sizeof(esdm_rpcs_reqbuf) - ESDM_RPCS_BUF_WRITE_HEADER_SZ;
	size_t message_length;
	int ret;
	struct esdm_rpc_proto_sc_header *sc_header;
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	struct esdm_rpcs_tx *tx = NULL;

	BUILD_BUG_ON(sizeof(tx->buf) != sizeof(esdm_rpcs_reqbuf));
	if (rpc_conn->ring_io) {
		tx = esdm_rpcs_tx_get();
		if (!tx) {
			ret = -ENOMEM;
			goto out_failure;
		}
		buf = tx->buf;
	}
#endif
	payload_buf = buf + ESDM_RPCS_BUF_WRITE_HEADER_SZ;

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

	sc_header = (struct esdm_rpc_proto_sc_header *)buf;
	sc_header->status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	sc_header->method_index = le_bswap32(rpc_conn->method_index);
	sc_header->message_length = le_bswap32(message_length);
	sc_header->request_id = le_bswap32(rpc_conn->request_id);

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_RPC,
		"Server sending: server status %u, message length %u, message index %u, request ID %u\n",
		sc_header->status_code, sc_header->message_length,
		sc_header->method_index, sc_header->request_id);

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* Handed over to the connection, which wipes it once it is sent */
	if (tx) {
		ret = esdm_rpcs_tx_queue(rpc_conn, tx,
					 ESDM_RPCS_BUF_WRITE_HEADER_SZ +
						 message_length);
		if (ret)
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_RPC,
				"Submission of message data failed with error %d\n",
				ret);
		return ret ? -EFAULT : 0;
	}
#endif

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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* Wiped in full, whatever was packed into it */
	esdm_rpcs_tx_put(tx);
#endif
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
 * Handle one request that was received in full into @buf - the per-worker
 * request buffer, or a buffer of the io_uring of the worker: validate its
 * header, then unpack and dispatch it. @buf is wiped.
 *
 * @received may exceed ESDM_RPC_MAX_MSG_SIZE, the size of the buffers, for a
 * message that was cut short to fit (MSG_TRUNC): the client sent more than a
 * request can be, and the connection is ended.
 */
static int esdm_rpcs_process(struct esdm_rpcs_connection *rpc_conn,
			     uint8_t *buf, ssize_t received)
{
	int ret = 0;

	if (received > (ssize_t)sizeof(esdm_rpcs_reqbuf)) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Request of %zd bytes on client FD %d exceeds %zu\n",
			    received, rpc_conn->child_fd,
			    sizeof(esdm_rpcs_reqbuf));
		received = (ssize_t)sizeof(esdm_rpcs_reqbuf);
		ret = -EMSGSIZE;
		goto out;
	}

	/* We insist on having at least a header received. */
	if (received < (ssize_t)sizeof(struct esdm_rpc_proto_cs_header)) {
		ret = -EINVAL;
		goto out;
	}

	/* Header is received, analyze it. */
	struct esdm_rpc_proto_cs_header *header =
		(struct esdm_rpc_proto_cs_header *)buf;

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
	CKINT(esdm_rpcs_unpack(rpc_conn, (struct esdm_rpc_proto_cs *)buf));

out:
	if (received > 0) {
		memset_secure(buf, 0, (size_t)received);
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
			 * operation. One larger than the buffer is cut short,
			 * MSG_TRUNC telling its full size, which ends the
			 * connection - as for the receive of the io_uring.
			 */
			received = recv(rpc_conn->child_fd, esdm_rpcs_reqbuf,
					sizeof(esdm_rpcs_reqbuf), MSG_TRUNC);
			if (received < 0)
				return -errno;
		}

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Read %zd bytes\n",
			    received);

		ret = esdm_rpcs_process(rpc_conn, esdm_rpcs_reqbuf, received);

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

	ret = esdm_rpcs_process(&rpc_conn, esdm_rpcs_reqbuf, (ssize_t)len);

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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	esdm_rpcs_tx_drop(rpc_conn);
#endif
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

static bool
esdm_rpcs_uring_input_queued(const struct esdm_rpcs_connection *rpc_conn);

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
	    (rpc_conn->dtls && esdm_dtls_pending(rpc_conn->dtls)) ||
	    esdm_rpcs_uring_input_queued(rpc_conn))
		return esdm_rpcs_conn_requested;
	if (ioctl(rpc_conn->child_fd, SIOCOUTQ, &outq) || outq > 0)
		return esdm_rpcs_conn_answered;
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* An answer the ring did not send yet */
	if (rpc_conn->tx_head)
		return esdm_rpcs_conn_answered;
#endif

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
 * io_uring receiving and sending (the default for io_uring where the kernel -
 * Linux 6.0 - and liburing 2.4 have it, see
 * esdm_rpc_server_set_io_uring_multishot()): a connection in the clear is not
 * polled, the ring reads and writes it. The worker registers a ring of
 * ESDM_RPCS_URING_BUFS buffers of ESDM_RPC_MAX_MSG_SIZE bytes - the request
 * buffer the read takes a request into -, and each connection has a multishot
 * IORING_OP_RECV selecting from them: one completion per message of the
 * SOCK_SEQPACKET socket, with the buffer that holds it, for as long as the
 * receive stays armed. A round serves the request from the buffer, wipes it
 * and hands it back to the ring right away, so no buffer is held from one
 * round to the next. A receive finding no buffer - more requests arrived since
 * the last round than there are buffers - ends with ENOBUFS, leaving the
 * request in the socket, and is armed again with the next wait, which finds
 * the buffers of the round given back. MSG_TRUNC has a message larger than a
 * buffer reported with its size, which ends the connection, as the read does.
 *
 * The answers leave by the ring as well, packed into a buffer the connection
 * holds until it is sent (esdm_rpcs_tx) and submitted as IORING_OP_SEND
 * together with the wait for the next round: the answers of a round and the
 * wait are one system call. A connection has at most one send in flight, the
 * next answer - of a client that sent a request before it read the answer of
 * the one before - waits for its completion, so the answers leave in order.
 * MSG_DONTWAIT: an answer that does not fit into the socket fails at once, and
 * the connection is closed, as with the write - see esdm_rpcs_write_data(). An
 * answer is one message, which SOCK_SEQPACKET takes whole or not at all:
 * there is no short send to continue and no parts of an answer to link or to
 * bundle; a send shorter than the answer all the same ends the connection.
 *
 * A request the ring received is no longer in the socket: whether a connection
 * has one not served yet - see esdm_rpcs_input_queued() - is told by the
 * completions of its receive, those of the round counted and those still in
 * the completion queue looked up. A connection closed while it has events left
 * in the round has them voided, its buffers given back.
 *
 * A round serves one request per connection, as with the poll: a multishot
 * receive takes what the socket holds into as many buffers as it finds, and a
 * client sending requests without waiting for the answers would otherwise
 * have all of them served in one round and leave no buffer to the others. See
 * esdm_rpcs_rx and esdm_rpcs_uring_recv().
 *
 * Connections with DTLS - from the answer to the probe that follows STARTDTLS
 * on - are polled as above: the TLS stack reads and writes their socket
 * itself. The receive of a connection switching to DTLS is cancelled, in the
 * submission ahead of the send of the answer to the probe, so that none of the
 * records of the handshake the client starts once it has the answer ends up
 * in a buffer of the ring. Where the kernel has no buffer rings, the worker
 * polls all of its connections; where it has no multishot receive (Linux
 * 5.19), each receive takes one request.
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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/* Receiving and sending through the ring, see above */
	bool multishot;
	/*
	 * Does the kernel take multishot receives (Linux 6.0)? Has one
	 * delivered a request? Without, the receives take one request each.
	 */
	bool mshot_ok;
	bool mshot_seen;
	struct io_uring_buf_ring *br;
	uint8_t *bufs;
	unsigned int nbufs;
	/*
	 * Sends submitted since the last wait, see esdm_rpcs_uring_wait() -
	 * counted where the ring submits all entries whatever fails
	 * (IORING_SETUP_SUBMIT_ALL)
	 */
	unsigned int sends;
	bool submit_all;
	/* Connections with an answer to be sent with the next wait */
	struct esdm_rpcs_connection_list txq;
	/* Connections with requests deferred, see esdm_rpcs_rx */
	struct esdm_rpcs_connection_list deferq;
	size_t defer_bytes;
	/* The rounds of the loop, counted */
	uint64_t round;
	/*
	 * The events of the current round, those from ev_next on still to be
	 * served, and of each request received its buffer of the ring - or,
	 * -1 there, the one deferred - and its size
	 */
	struct epoll_event *events;
	int ev_next, ev_num;
	int32_t rx_buf[512];
	uint32_t rx_len[512];
	struct esdm_rpcs_rx *rx_deferred[512];
#endif
};

/* Events a worker takes per round of its event loop */
#define ESDM_RPCS_MAX_EVENTS 512

#ifdef ESDM_RPC_IO_URING_MULTISHOT
/*
 * What else an event of a connection served through the ring can be, next to
 * EPOLLERR: a request received into the buffer rx_buf[] of its index, the end
 * of its receive - the client is gone, or the server's own SHUT_RD drained
 * it -, the last of the answers of a connection left to drain sent. None of
 * them is an event of epoll.
 */
#define ESDM_RPCS_EV_RX (1U << 26)
#define ESDM_RPCS_EV_EOF (1U << 25)
#define ESDM_RPCS_EV_TXDONE (1U << 24)

/*
 * The data of the completions of a connection: its address, tagged with what
 * completed - its poll (none), its receive or its send
 */
#define ESDM_RPCS_TAG_RECV 1
#define ESDM_RPCS_TAG_SEND 2
#define ESDM_RPCS_TAG_MASK 3
#endif

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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	TAILQ_INIT(&loop->txq);
	TAILQ_INIT(&loop->deferq);
#endif
}

/* The loop of the calling worker, for the answers it queues - see esdm_rpcs_tx */
static __thread struct esdm_rpcs_loop *esdm_rpcs_cur_loop;

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
 * Size of the rings. A round re-arms the polls or receives of at most
 * ESDM_RPCS_MAX_EVENTS connections and sends as many answers; should the
 * submission queue run full all the same, what it holds is submitted on the
 * way. Completions are in flight for at most one poll or receive and one send
 * per connection, a worker holding ESDM_RPCS_MAX_WORKER_CONNECTIONS, and for
 * the cancellations - the kernel keeps what does not fit in the queue
 * (IORING_FEAT_NODROP, which is required), as it does the further requests of
 * a client sending them without reading its answers.
 */
#define ESDM_RPCS_URING_SQ_ENTRIES ESDM_RPCS_MAX_EVENTS
#define ESDM_RPCS_URING_CQ_ENTRIES (4 * ESDM_RPCS_MAX_WORKER_CONNECTIONS)

/* The fallback, or the ring, is reported once per process */
static atomic_flag esdm_rpcs_uring_reported = ATOMIC_FLAG_INIT;

#ifdef ESDM_RPC_IO_URING_MULTISHOT

/*
 * Buffers of the ring of a worker, see esdm_rpcs_loop: a client has one
 * request in flight, so as many connections of a worker can have theirs
 * received between two rounds before a receive runs out of buffers and waits
 * for the next round. Of each, only what the requests took up is touched: 4
 * MiB of address space per worker, a page per buffer of it in memory for
 * requests of up to a page - the largest, of write_data, take more.
 */
#define ESDM_RPCS_URING_BUFS 64

/* The buffers of the rings set up from now on, a power of 2 */
static unsigned int esdm_rpcs_uring_bufs = ESDM_RPCS_URING_BUFS;

#ifdef ESDM_FUZZING
void esdm_rpcs_fuzz_uring_bufs(unsigned int bufs)
{
	if (bufs && !(bufs & (bufs - 1)) && bufs <= ESDM_RPCS_URING_BUFS)
		esdm_rpcs_uring_bufs = bufs;
}
#endif
#define ESDM_RPCS_URING_BGID 0

/* Polling instead of receiving through the ring is reported once per process */
static atomic_flag esdm_rpcs_multishot_reported = ATOMIC_FLAG_INIT;

static void esdm_rpcs_uring_no_multishot(int err)
{
	if (!atomic_flag_test_and_set(&esdm_rpcs_multishot_reported))
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_RPC,
			"io_uring of the RPC worker threads cannot receive multishot, polling the connections: %s\n",
			strerror(err));
}

static uint8_t *esdm_rpcs_uring_buf(struct esdm_rpcs_loop *loop,
				    unsigned int bid)
{
	return loop->bufs + (size_t)bid * ESDM_RPC_MAX_MSG_SIZE;
}

/* Wipe the first @used bytes of buffer @bid and hand it back to the ring */
static void esdm_rpcs_uring_buf_put(struct esdm_rpcs_loop *loop,
				    unsigned int bid, size_t used)
{
	uint8_t *buf = esdm_rpcs_uring_buf(loop, bid);

	if (used)
		memset_secure(buf, 0, min_size(used, ESDM_RPC_MAX_MSG_SIZE));
	io_uring_buf_ring_add(loop->br, buf, ESDM_RPC_MAX_MSG_SIZE,
			      (unsigned short)bid,
			      io_uring_buf_ring_mask(loop->nbufs), 0);
	io_uring_buf_ring_advance(loop->br, 1);
}

/* Register the buffers to receive into - polling the connections without */
static void esdm_rpcs_uring_bufs_open(struct esdm_rpcs_loop *loop)
{
	const unsigned int nbufs = esdm_rpcs_uring_bufs;
	const size_t size = (size_t)nbufs * ESDM_RPC_MAX_MSG_SIZE;
	unsigned int i;
	int ret = 0;

	BUILD_BUG_ON(ARRAY_SIZE(loop->rx_buf) < ESDM_RPCS_MAX_EVENTS ||
		     ARRAY_SIZE(loop->rx_len) < ESDM_RPCS_MAX_EVENTS ||
		     ESDM_RPCS_URING_BUFS > 65536 ||
		     (ESDM_RPCS_URING_BUFS & (ESDM_RPCS_URING_BUFS - 1)));

	if (!atomic_load(&esdm_rpcs_io_uring_multishot))
		return;

	loop->bufs = mmap(NULL, size, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (loop->bufs == MAP_FAILED) {
		loop->bufs = NULL;
		esdm_rpcs_uring_no_multishot(errno);
		return;
	}

	/* Buffer rings came with Linux 5.19 */
	loop->br = io_uring_setup_buf_ring(&loop->ring, nbufs,
					   ESDM_RPCS_URING_BGID, 0, &ret);
	if (!loop->br) {
		munmap(loop->bufs, size);
		loop->bufs = NULL;
		esdm_rpcs_uring_no_multishot(-ret);
		return;
	}

	loop->nbufs = nbufs;
	for (i = 0; i < nbufs; i++) {
		io_uring_buf_ring_add(
			loop->br, esdm_rpcs_uring_buf(loop, i),
			ESDM_RPC_MAX_MSG_SIZE, (unsigned short)i,
			io_uring_buf_ring_mask(nbufs), (int)i);
	}
	io_uring_buf_ring_advance(loop->br, (int)nbufs);

	loop->multishot = true;
	loop->mshot_ok = true;
}

static void esdm_rpcs_uring_bufs_close(struct esdm_rpcs_loop *loop)
{
	if (loop->br) {
		io_uring_free_buf_ring(&loop->ring, loop->br,
				       loop->nbufs,
				       ESDM_RPCS_URING_BGID);
		loop->br = NULL;
	}
	if (loop->bufs) {
		munmap(loop->bufs,
		       (size_t)loop->nbufs * ESDM_RPC_MAX_MSG_SIZE);
		loop->bufs = NULL;
	}
	loop->multishot = false;
}

#else /* ESDM_RPC_IO_URING_MULTISHOT */

static void esdm_rpcs_uring_bufs_open(struct esdm_rpcs_loop *loop)
{
	(void)loop;
}

static void esdm_rpcs_uring_bufs_close(struct esdm_rpcs_loop *loop)
{
	(void)loop;
}

#endif /* ESDM_RPC_IO_URING_MULTISHOT */

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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	loop->submit_all = IORING_SETUP_SUBMIT_ALL &&
			   (params.flags & IORING_SETUP_SUBMIT_ALL);
#endif

	esdm_rpcs_uring_bufs_open(loop);

	if (!atomic_flag_test_and_set(&esdm_rpcs_uring_reported)) {
		const char *how = "polling the connections";

#ifdef ESDM_RPC_IO_URING_MULTISHOT
		if (loop->multishot)
			how = "receiving and sending through it";
#endif
		esdm_logger(LOGGER_STATUS, LOGGER_C_RPC,
			    "RPC worker threads wait with io_uring, %s\n", how);
	}

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

/* Is @rpc_conn polled, or received from by the ring? */
static bool esdm_rpcs_uring_armed(const struct esdm_rpcs_connection *rpc_conn)
{
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	if (rpc_conn->ring_io)
		return rpc_conn->recv_armed;
#endif
	return rpc_conn->poll_armed;
}

/* Have the poll, or the receive, of @rpc_conn armed with the next wait */
static void esdm_rpcs_uring_rearm(struct esdm_rpcs_loop *loop,
				  struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->poll_queued || esdm_rpcs_uring_armed(rpc_conn))
		return;

	TAILQ_INSERT_TAIL(&loop->rearm, rpc_conn, poll_entry);
	rpc_conn->poll_queued = true;
}

/*
 * Have the receive of @rpc_conn, which found no buffer, armed with the next
 * wait ahead of those that had their requests - it waited longer
 */
static void esdm_rpcs_uring_rearm_first(struct esdm_rpcs_loop *loop,
					struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->poll_queued || esdm_rpcs_uring_armed(rpc_conn))
		return;

	TAILQ_INSERT_HEAD(&loop->rearm, rpc_conn, poll_entry);
	rpc_conn->poll_queued = true;
}

/*
 * May a closed connection be freed - is none of its operations in flight any
 * more? Then it is.
 */
static void esdm_rpcs_uring_release(struct esdm_rpcs_loop *loop,
				    struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->poll_armed)
		return;
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	if (rpc_conn->recv_armed || rpc_conn->tx_inflight)
		return;
#endif

	TAILQ_REMOVE(&loop->closed, rpc_conn, tailq);
	free(rpc_conn);
}

#ifdef ESDM_RPC_IO_URING_MULTISHOT

/* Submit a cancellation of the operation of the ring with data @data */
static bool esdm_rpcs_uring_cancel(struct esdm_rpcs_loop *loop, uint64_t data)
{
	struct io_uring_sqe *sqe = esdm_rpcs_uring_sqe(loop);

	if (!sqe)
		return false;

	io_uring_prep_cancel64(sqe, data, 0);
	io_uring_sqe_set_data64(sqe, ESDM_RPCS_EVENT_CANCEL);

	return true;
}

/*
 * Submit the receive of @rpc_conn: a multishot one, which stays armed, as a
 * client that waits for each answer has it - or one taking a single request
 * where more than one may wait in the socket: on a new connection, after a
 * receive that found no buffer or left more in the socket
 * (IORING_CQE_F_SOCK_NONEMPTY), after a client sent requests without waiting
 * for the answers, see esdm_rpcs_rx. A multishot receive takes what the socket
 * holds into as many buffers of the ring as it finds - leaving none to the
 * receives of the other connections of the worker, which then wait for the
 * next round, and the round to the requests of that one connection; a single
 * receive per round has those of each connection take their turn, as with
 * the poll.
 */
static bool esdm_rpcs_uring_recv(struct esdm_rpcs_loop *loop,
				 struct esdm_rpcs_connection *rpc_conn)
{
	struct io_uring_sqe *sqe = esdm_rpcs_uring_sqe(loop);

	if (!sqe)
		return false;

	/* The full size of a message cut short - see esdm_rpcs_process() */
	rpc_conn->recv_multishot = loop->mshot_ok && !rpc_conn->recv_single;
	if (rpc_conn->recv_multishot)
		io_uring_prep_recv_multishot(sqe, rpc_conn->child_fd, NULL, 0,
					     MSG_TRUNC);
	else
		io_uring_prep_recv(sqe, rpc_conn->child_fd, NULL, 0,
				   MSG_TRUNC);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = ESDM_RPCS_URING_BGID;
	io_uring_sqe_set_data64(sqe, (uint64_t)(uintptr_t)rpc_conn |
					     ESDM_RPCS_TAG_RECV);
	rpc_conn->recv_armed = true;

	return true;
}

/* Submit the send of the first answer of @rpc_conn */
static bool esdm_rpcs_uring_send(struct esdm_rpcs_loop *loop,
				 struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpcs_tx *tx = rpc_conn->tx_head;
	struct io_uring_sqe *sqe = esdm_rpcs_uring_sqe(loop);

	if (!sqe)
		return false;

	io_uring_prep_send(sqe, rpc_conn->child_fd, tx->buf, tx->len,
			   MSG_NOSIGNAL | MSG_DONTWAIT);
	io_uring_sqe_set_data64(sqe, (uint64_t)(uintptr_t)rpc_conn |
					     ESDM_RPCS_TAG_SEND);
	rpc_conn->tx_inflight = true;
	loop->sends++;

	return true;
}

/* Have the first answer of @rpc_conn sent with the next wait */
static void esdm_rpcs_uring_txq_add(struct esdm_rpcs_loop *loop,
				    struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->tx_queued || rpc_conn->tx_inflight || !rpc_conn->tx_head)
		return;

	TAILQ_INSERT_TAIL(&loop->txq, rpc_conn, tx_entry);
	rpc_conn->tx_queued = true;
}

static void esdm_rpcs_uring_txq_del(struct esdm_rpcs_loop *loop,
				    struct esdm_rpcs_connection *rpc_conn)
{
	if (!rpc_conn->tx_queued)
		return;

	TAILQ_REMOVE(&loop->txq, rpc_conn, tx_entry);
	rpc_conn->tx_queued = false;
}

/*
 * Cancel the receive of a connection going over to the poll, ahead of the send
 * of its answer, see esdm_rpcs_loop. The entries of a submission are issued in
 * their order, and the cancellation of a receive waiting for the socket is
 * done once it is issued - no record the client sends once it has the answer
 * reaches the receive. Not linked to the send: the send would be issued by the
 * task work of the cancellation, which a ring with IORING_SETUP_DEFER_TASKRUN
 * runs only once the worker waits for more than the completions already
 * posted - not while a client waits for the answer.
 */
static void esdm_rpcs_uring_recv_cancel(struct esdm_rpcs_loop *loop,
					struct esdm_rpcs_connection *rpc_conn)
{
	rpc_conn->recv_cancel = false;
	if (!rpc_conn->recv_armed || rpc_conn->recv_cancelled)
		return;

	if (esdm_rpcs_uring_cancel(loop,
				   (uint64_t)(uintptr_t)rpc_conn |
					   ESDM_RPCS_TAG_RECV))
		rpc_conn->recv_cancelled = true;
}

/*
 * Requests of @rpc_conn the ring received and the worker did not serve yet,
 * among the events of the round or still in the completion queue?
 */
static bool
esdm_rpcs_uring_input_queued(const struct esdm_rpcs_connection *rpc_conn)
{
	struct esdm_rpcs_loop *loop = esdm_rpcs_cur_loop;
	const uint64_t data = (uint64_t)(uintptr_t)rpc_conn |
			      ESDM_RPCS_TAG_RECV;
	struct io_uring_cqe *cqe;
	unsigned int head;

	if (rpc_conn->rx_pending || rpc_conn->rx_defer_head)
		return true;
	if (!loop || !loop->multishot)
		return false;

	io_uring_for_each_cqe(&loop->ring, head, cqe)
	{
		if (io_uring_cqe_get_data64(cqe) == data && cqe->res > 0)
			return true;
	}

	return false;
}

/* Give back the request of event @i of the round, wiping it */
static void esdm_rpcs_uring_rx_put(struct esdm_rpcs_loop *loop, int i)
{
	if (loop->rx_buf[i] >= 0) {
		esdm_rpcs_uring_buf_put(loop, (unsigned int)loop->rx_buf[i],
					loop->rx_len[i]);
	} else {
		loop->defer_bytes -= loop->rx_deferred[i]->len;
		esdm_rpcs_rx_free(loop->rx_deferred[i]);
	}
}

/*
 * Arm the receive of @rpc_conn again with the next wait, unless it has
 * requests deferred - see esdm_rpcs_rx - or its receive is being cancelled
 */
static void esdm_rpcs_uring_recv_again(struct esdm_rpcs_loop *loop,
				       struct esdm_rpcs_connection *rpc_conn)
{
	if (rpc_conn->rx_defer_head || rpc_conn->recv_cancel)
		return;

	esdm_rpcs_uring_rearm(loop, rpc_conn);
}

/*
 * Defer a request of @len bytes in @buf of @rpc_conn, which has one in the
 * round already, see esdm_rpcs_rx. Returns false if it cannot take it.
 */
static bool esdm_rpcs_uring_defer(struct esdm_rpcs_loop *loop,
				  struct esdm_rpcs_connection *rpc_conn,
				  const uint8_t *buf, size_t len)
{
	struct esdm_rpcs_rx *rx;

	len = min_size(len, ESDM_RPC_MAX_MSG_SIZE + 1);
	if (rpc_conn->rx_defer_num >= ESDM_RPCS_RX_DEFER_MAX ||
	    loop->defer_bytes + len > ESDM_RPCS_RX_DEFER_BYTES) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_RPC,
			"Client FD %d sends requests without reading the answers\n",
			rpc_conn->child_fd);
		return false;
	}

	rx = malloc(sizeof(*rx) + len);
	if (!rx)
		return false;
	rx->next = NULL;
	rx->len = len;
	/*
	 * A message cut short keeps a size beyond the buffer, which
	 * esdm_rpcs_process() refuses - one byte stands for the rest.
	 */
	memcpy(rx->data, buf, min_size(len, ESDM_RPC_MAX_MSG_SIZE));
	if (len > ESDM_RPC_MAX_MSG_SIZE)
		rx->data[ESDM_RPC_MAX_MSG_SIZE] = 0;

	if (rpc_conn->rx_defer_tail)
		rpc_conn->rx_defer_tail->next = rx;
	else
		rpc_conn->rx_defer_head = rx;
	rpc_conn->rx_defer_tail = rx;
	rpc_conn->rx_defer_num++;
	loop->defer_bytes += len;

	if (!rpc_conn->deferred) {
		TAILQ_INSERT_TAIL(&loop->deferq, rpc_conn, defer_entry);
		rpc_conn->deferred = true;
	}

	/* No more until they are served, and then one at a time */
	rpc_conn->recv_single = true;
	if (rpc_conn->recv_armed && !rpc_conn->recv_cancelled &&
	    !rpc_conn->recv_cancel) {
		rpc_conn->recv_cancel = true;
		if (!rpc_conn->poll_queued) {
			TAILQ_INSERT_TAIL(&loop->rearm, rpc_conn, poll_entry);
			rpc_conn->poll_queued = true;
		}
	}

	return true;
}

/*
 * The requests deferred as events of the round, one per connection without one
 * in the round, as far as @maxevents allows
 */
static void esdm_rpcs_uring_undefer(struct esdm_rpcs_loop *loop,
				    struct epoll_event *events, int *n,
				    int maxevents)
{
	struct esdm_rpcs_connection *rpc_conn, *tmp;

	TAILQ_FOREACH_SAFE(rpc_conn, &loop->deferq, defer_entry, tmp)
	{
		struct esdm_rpcs_rx *rx = rpc_conn->rx_defer_head;

		if (*n >= maxevents)
			break;
		if (rpc_conn->rx_round == loop->round)
			continue;

		rpc_conn->rx_defer_head = rx->next;
		if (!rpc_conn->rx_defer_head)
			rpc_conn->rx_defer_tail = NULL;
		rpc_conn->rx_defer_num--;

		rpc_conn->rx_round = loop->round;
		rpc_conn->rx_pending++;
		events[*n].events = ESDM_RPCS_EV_RX;
		events[*n].data.u64 = 0;
		events[*n].data.ptr = rpc_conn;
		loop->rx_buf[*n] = -1;
		loop->rx_len[*n] = (uint32_t)rx->len;
		loop->rx_deferred[*n] = rx;
		(*n)++;

		if (!rpc_conn->rx_defer_head) {
			TAILQ_REMOVE(&loop->deferq, rpc_conn, defer_entry);
			rpc_conn->deferred = false;
			/* Received from again, once its receive ended */
			if (!rpc_conn->recv_armed)
				esdm_rpcs_uring_recv_again(loop, rpc_conn);
		}
	}
}

/*
 * Void the events of the round left for @rpc_conn, which is closed, giving
 * back the buffers of the requests among them
 */
static void esdm_rpcs_uring_void(struct esdm_rpcs_loop *loop,
				 struct esdm_rpcs_connection *rpc_conn)
{
	int i;

	for (i = loop->ev_next; i < loop->ev_num; i++) {
		struct epoll_event *ev = &loop->events[i];

		if (ev->data.u64 <= ESDM_RPCS_EVENT_CANCEL ||
		    ev->data.ptr != rpc_conn)
			continue;
		if (ev->events & ESDM_RPCS_EV_RX) {
			esdm_rpcs_uring_rx_put(loop, i);
			rpc_conn->rx_pending--;
		}
		ev->data.u64 = ESDM_RPCS_EVENT_STALE;
	}
}

/*
 * A connection served through the ring is to be polled from now on - it
 * switched to DTLS, see esdm_rpcs_serve_ring()
 */
static void esdm_rpcs_uring_to_poll(struct esdm_rpcs_loop *loop,
				    struct esdm_rpcs_connection *rpc_conn)
{
	rpc_conn->ring_io = false;
	if (rpc_conn->recv_armed && !rpc_conn->recv_cancelled)
		rpc_conn->recv_cancel = true;

	/* Taken off the queue to arm its receive, if it was, to be polled */
	if (rpc_conn->poll_queued) {
		TAILQ_REMOVE(&loop->rearm, rpc_conn, poll_entry);
		rpc_conn->poll_queued = false;
	}
	esdm_rpcs_uring_rearm(loop, rpc_conn);
}

/*
 * The completion of the receive of @rpc_conn: a request into a buffer of the
 * ring - an event of the round -, or the end of the receive.
 */
static void esdm_rpcs_uring_recv_done(struct esdm_rpcs_loop *loop,
				      struct esdm_rpcs_connection *rpc_conn,
				      const struct io_uring_cqe *cqe,
				      struct epoll_event *events, int *n)
{
	int bid = (cqe->flags & IORING_CQE_F_BUFFER) ?
			  (int)(cqe->flags >> IORING_CQE_BUFFER_SHIFT) :
			  -1;
	int res = cqe->res;

	/* Without IORING_CQE_F_MORE, the receive ended */
	if (!(cqe->flags & IORING_CQE_F_MORE)) {
		rpc_conn->recv_armed = false;
		rpc_conn->recv_cancelled = false;
	}

	if (res > 0 && bid >= 0 && !rpc_conn->closed) {
		if (rpc_conn->recv_multishot) {
			loop->mshot_seen = true;
		} else {
			/* More in the socket: one request at a time */
			rpc_conn->recv_single =
				!!(cqe->flags & IORING_CQE_F_SOCK_NONEMPTY);
		}

		/*
		 * A request in the clear after STARTDTLS: the client did not
		 * wait for its answer, which is no client of the protocol.
		 */
		if (!rpc_conn->ring_io) {
			esdm_rpcs_uring_buf_put(loop, (unsigned int)bid,
						(size_t)res);
			events[*n].events = EPOLLERR;
		} else if (rpc_conn->rx_round == loop->round ||
			   rpc_conn->rx_defer_head) {
			/* One per round, see esdm_rpcs_rx */
			bool deferred = esdm_rpcs_uring_defer(
				loop, rpc_conn,
				esdm_rpcs_uring_buf(loop, (unsigned int)bid),
				(size_t)res);

			esdm_rpcs_uring_buf_put(loop, (unsigned int)bid,
						(size_t)res);
			if (deferred)
				return;
			events[*n].events = EPOLLERR;
		} else {
			/* Armed again for the next requests, if it ended */
			if (!rpc_conn->recv_armed)
				esdm_rpcs_uring_recv_again(loop, rpc_conn);
			rpc_conn->rx_round = loop->round;
			events[*n].events = ESDM_RPCS_EV_RX;
			loop->rx_buf[*n] = bid;
			loop->rx_len[*n] = (uint32_t)res;
			rpc_conn->rx_pending++;
		}
		events[*n].data.u64 = 0;
		events[*n].data.ptr = rpc_conn;
		(*n)++;
		return;
	}

	if (bid >= 0)
		esdm_rpcs_uring_buf_put(loop, (unsigned int)bid,
					res > 0 ? (size_t)res : 0);

	if (rpc_conn->closed) {
		esdm_rpcs_uring_release(loop, rpc_conn);
		return;
	}

	/* Going over to the poll, which tells the rest */
	if (!rpc_conn->ring_io)
		return;

	switch (res) {
	case -ENOBUFS:
		/* Left in the socket for the next round, see esdm_rpcs_loop */
#ifdef ESDM_FUZZING
		atomic_fetch_add(&esdm_rpcs_enobufs, 1);
#endif
		rpc_conn->recv_single = true;
		if (!rpc_conn->rx_defer_head && !rpc_conn->recv_cancel)
			esdm_rpcs_uring_rearm_first(loop, rpc_conn);
		return;
	case -ECANCELED:
		/* Cancelled for the requests deferred, see esdm_rpcs_rx */
		esdm_rpcs_uring_recv_again(loop, rpc_conn);
		return;
	case -EINVAL:
		/*
		 * The kernel has buffer rings but no multishot receive (Linux
		 * 5.19) - unless one delivered a request before: the receives
		 * take one request each from now on.
		 */
		if (!rpc_conn->recv_multishot || loop->mshot_seen)
			break;
		if (loop->mshot_ok) {
			loop->mshot_ok = false;
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_RPC,
				"io_uring of the RPC worker threads cannot receive multishot, receiving one request at a time\n");
		}
		esdm_rpcs_uring_recv_again(loop, rpc_conn);
		return;
	case 0:
		/* The end of the stream - or an empty message, no request */
		events[*n].events = ESDM_RPCS_EV_EOF;
		events[*n].data.u64 = 0;
		events[*n].data.ptr = rpc_conn;
		(*n)++;
		return;
	default:
		break;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
		    "Receiving on client FD %d failed: %s\n", rpc_conn->child_fd,
		    strerror(res < 0 ? -res : EIO));
	events[*n].events = EPOLLERR;
	events[*n].data.u64 = 0;
	events[*n].data.ptr = rpc_conn;
	(*n)++;
}

/* The completion of the send of the first answer of @rpc_conn */
static void esdm_rpcs_uring_send_done(struct esdm_rpcs_loop *loop,
				      struct esdm_rpcs_connection *rpc_conn,
				      int res, struct epoll_event *events,
				      int *n)
{
	struct esdm_rpcs_tx *tx = rpc_conn->tx_head;
	size_t len = 0;

	rpc_conn->tx_inflight = false;
	if (tx) {
		len = tx->len;
		rpc_conn->tx_head = tx->next;
		if (!rpc_conn->tx_head)
			rpc_conn->tx_tail = NULL;
		rpc_conn->tx_num--;
		esdm_rpcs_tx_put(tx);
	}

	if (rpc_conn->closed) {
		esdm_rpcs_uring_release(loop, rpc_conn);
		return;
	}

	/* See esdm_rpcs_write_data() */
	if (res < 0 || (size_t)res != len) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_RPC,
			    "Writing of data to file descriptor %d failed: %s\n",
			    rpc_conn->child_fd,
			    res >= 0 ? "partial send on SEQPACKET socket" :
			    (res == -EAGAIN || res == -EWOULDBLOCK) ?
				       "the client does not read its answers" :
				       strerror(-res));
		events[*n].events = EPOLLERR;
	} else if (rpc_conn->tx_head) {
		esdm_rpcs_uring_txq_add(loop, rpc_conn);
		return;
	} else if (rpc_conn->closing) {
		/* Left to drain, which it may be now */
		events[*n].events = ESDM_RPCS_EV_TXDONE;
	} else {
		esdm_logger(LOGGER_DEBUG2, LOGGER_C_ANY, "%zu bytes written\n",
			    len);
		return;
	}

	events[*n].data.u64 = 0;
	events[*n].data.ptr = rpc_conn;
	(*n)++;
}

/*
 * Queue the answer @tx of @len bytes of a connection served through the ring,
 * see esdm_rpcs_loop. @tx is the connection's from now on, whatever the
 * outcome. A connection that cannot take it is closed, as by a write that
 * fails - see esdm_rpcs_write_data().
 */
static int esdm_rpcs_tx_queue(struct esdm_rpcs_connection *rpc_conn,
			      struct esdm_rpcs_tx *tx, size_t len)
{
	struct esdm_rpcs_loop *loop = esdm_rpcs_cur_loop;

	tx->len = len;
	tx->next = NULL;

	if (!loop || rpc_conn->child_fd < 0 ||
	    rpc_conn->tx_num >= ESDM_RPCS_TX_MAX) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_RPC,
			"Writing of data to file descriptor %d failed: %s\n",
			rpc_conn->child_fd,
			rpc_conn->tx_num >= ESDM_RPCS_TX_MAX ?
				"the client does not read its answers" :
				"the connection is closed");
		esdm_rpcs_tx_put(tx);
		esdm_rpcs_conn_close(rpc_conn, false);
		return -EAGAIN;
	}

	if (rpc_conn->tx_tail)
		rpc_conn->tx_tail->next = tx;
	else
		rpc_conn->tx_head = tx;
	rpc_conn->tx_tail = tx;
	rpc_conn->tx_num++;

	esdm_rpcs_uring_txq_add(loop, rpc_conn);

	return 0;
}

#else /* ESDM_RPC_IO_URING_MULTISHOT */

static bool
esdm_rpcs_uring_input_queued(const struct esdm_rpcs_connection *rpc_conn)
{
	(void)rpc_conn;
	return false;
}

#endif /* ESDM_RPC_IO_URING_MULTISHOT */

/*
 * Submit what is to be polled or received from - every descriptor without a
 * poll in flight but the listening socket while it is not to be -, the answers
 * to be sent and the cancellations of the polls and receives of closed
 * connections. What finds no room in the submission queue is submitted with
 * the next wait.
 */
static void esdm_rpcs_uring_arm(struct esdm_rpcs_loop *loop)
{
	struct esdm_rpcs_connection *rpc_conn, *tmp;

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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		/* Ahead of its poll and of the sends below */
		if (rpc_conn->recv_cancel) {
			esdm_rpcs_uring_recv_cancel(loop, rpc_conn);
			/* Received from again once its requests are served */
			if (rpc_conn->ring_io) {
				TAILQ_REMOVE(&loop->rearm, rpc_conn,
					     poll_entry);
				rpc_conn->poll_queued = false;
				continue;
			}
		}

		if (rpc_conn->ring_io) {
			if (!esdm_rpcs_uring_recv(loop, rpc_conn))
				break;
			TAILQ_REMOVE(&loop->rearm, rpc_conn, poll_entry);
			rpc_conn->poll_queued = false;
			continue;
		}
#endif
		if (!esdm_rpcs_uring_poll(loop, rpc_conn->child_fd,
					  POLLIN | POLLRDHUP,
					  (uint64_t)(uintptr_t)rpc_conn, false))
			break;
		TAILQ_REMOVE(&loop->rearm, rpc_conn, poll_entry);
		rpc_conn->poll_queued = false;
		rpc_conn->poll_armed = true;
	}

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	TAILQ_FOREACH_SAFE(rpc_conn, &loop->txq, tx_entry, tmp)
	{
		if (!esdm_rpcs_uring_send(loop, rpc_conn))
			break;
		esdm_rpcs_uring_txq_del(loop, rpc_conn);
	}
#endif

	TAILQ_FOREACH(rpc_conn, &loop->closed, tailq)
	{
		if (rpc_conn->poll_armed && !rpc_conn->poll_cancelled) {
			struct io_uring_sqe *sqe = esdm_rpcs_uring_sqe(loop);

			if (!sqe)
				break;
			io_uring_prep_cancel64(sqe,
					       (uint64_t)(uintptr_t)rpc_conn,
					       0);
			io_uring_sqe_set_data64(sqe, ESDM_RPCS_EVENT_CANCEL);
			rpc_conn->poll_cancelled = true;
		}
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		if (rpc_conn->recv_armed && !rpc_conn->recv_cancelled) {
			if (!esdm_rpcs_uring_cancel(
				    loop, (uint64_t)(uintptr_t)rpc_conn |
						  ESDM_RPCS_TAG_RECV))
				break;
			rpc_conn->recv_cancelled = true;
		}
#endif
	}
}

/*
 * Wait for the completions of the polls, receives and sends, at most
 * @maxevents of which are taken as the events of the round - the others stay
 * in the completion queue for the next one. Returns the number of events, a
 * negative errno if the wait failed, or a poll of a descriptor but a
 * connection did.
 */
static int esdm_rpcs_uring_wait(struct esdm_rpcs_loop *loop,
				struct epoll_event *events, int maxevents)
{
	struct esdm_rpcs_connection *rpc_conn;
	struct io_uring_cqe *cqe;
	unsigned int head, seen = 0;
	int n = 0, ret;

	esdm_rpcs_uring_arm(loop);

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	/*
	 * With requests deferred, the round has events already. Otherwise,
	 * the wait is for one completion beyond those of the sends submitted
	 * with it: a send with MSG_DONTWAIT completes as it is submitted, and
	 * waiting for one completion only would have the worker go through a
	 * round of nothing but the completions of its sends - another system
	 * call per answer. No more than those is counted, so the wait never
	 * waits for a completion that does not come.
	 */
	loop->round++;
	ret = io_uring_submit_and_wait(
		&loop->ring,
		!TAILQ_EMPTY(&loop->deferq) ? 0 :
		loop->submit_all	    ? 1 + loop->sends :
					      1);
	loop->sends = 0;
#else
	ret = io_uring_submit_and_wait(&loop->ring, 1);
#endif
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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
			rpc_conn = (struct esdm_rpcs_connection *)(uintptr_t)(
				data & ~(uint64_t)ESDM_RPCS_TAG_MASK);
			switch (data & ESDM_RPCS_TAG_MASK) {
			case ESDM_RPCS_TAG_RECV:
				esdm_rpcs_uring_recv_done(loop, rpc_conn, cqe,
							  events, &n);
				continue;
			case ESDM_RPCS_TAG_SEND:
				esdm_rpcs_uring_send_done(loop, rpc_conn, res,
							  events, &n);
				continue;
			default:
				break;
			}
#else
			rpc_conn = (struct esdm_rpcs_connection *)(uintptr_t)
				data;
#endif
			rpc_conn->poll_armed = false;

			/* The poll was the last reference to it, maybe */
			if (rpc_conn->closed) {
				esdm_rpcs_uring_release(loop, rpc_conn);
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

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	if (!ret)
		esdm_rpcs_uring_undefer(loop, events, &n, maxevents);
#endif

	return ret ? ret : n;
}

#else /* ESDM_RPC_IO_URING */

static bool
esdm_rpcs_uring_input_queued(const struct esdm_rpcs_connection *rpc_conn)
{
	(void)rpc_conn;
	return false;
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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		/*
		 * Received from by the ring - until it switches to DTLS -, a
		 * single request first, which it may have sent already
		 */
		rpc_conn->ring_io = loop->multishot;
		rpc_conn->recv_single = true;
#endif
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
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		esdm_rpcs_uring_txq_del(loop, rpc_conn);
		if (rpc_conn->deferred) {
			TAILQ_REMOVE(&loop->deferq, rpc_conn, defer_entry);
			rpc_conn->deferred = false;
		}
		esdm_rpcs_rx_drop(rpc_conn, &loop->defer_bytes);
		if (loop->multishot)
			esdm_rpcs_uring_void(loop, rpc_conn);
		if (!rpc_conn->poll_armed && !rpc_conn->recv_armed &&
		    !rpc_conn->tx_inflight)
			return true;
#else
		if (!rpc_conn->poll_armed)
			return true;
#endif

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
		esdm_rpcs_uring_bufs_close(loop);
		io_uring_queue_exit(&loop->ring);
		loop->uring = false;

		TAILQ_FOREACH_SAFE(rpc_conn, &loop->closed, tailq, tmp)
		{
			TAILQ_REMOVE(&loop->closed, rpc_conn, tailq);
#ifdef ESDM_RPC_IO_URING_MULTISHOT
			/* The answer whose send was in flight */
			esdm_rpcs_tx_put(rpc_conn->tx_head);
#endif
			free(rpc_conn);
		}
	}
#endif
#ifdef ESDM_RPC_IO_URING_MULTISHOT
	esdm_rpcs_tx_cache_free();
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
 * Nothing counts as sent if the queue cannot be told. With the ring receiving,
 * it may have been taken off the socket already, waiting as a completion -
 * looked at after the socket, so that one the kernel takes off the socket
 * meanwhile is found there.
 */
static bool esdm_rpcs_input_queued(const struct esdm_rpcs_connection *rpc_conn)
{
	int inq = 0;

	if (!ioctl(rpc_conn->child_fd, SIOCINQ, &inq) && inq > 0)
		return true;

	return esdm_rpcs_uring_input_queued(rpc_conn);
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

	/*
	 * Not those of one served through the ring: they are not reported
	 * again - and one with a request among them is no victim. Closed, its
	 * events are voided as it is, see esdm_rpcs_loop_del().
	 */
	for (i = 0; i < num; i++) {
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		if (victim->ring_io)
			break;
#endif
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

#ifdef ESDM_RPC_IO_URING_MULTISHOT
/*
 * esdm_rpcs_serve() for a connection served through the ring, or with an event
 * of the ring left: answer the request the ring received, as event @ev of the
 * round, and close the connection if its client is gone or it failed - or, left
 * to drain, once the server's own SHUT_RD ended its receive and its last answer
 * is sent.
 */
static void esdm_rpcs_serve_ring(struct esdm_rpc_thread *thread,
				 struct esdm_rpcs_loop *loop,
				 struct esdm_rpcs_connection_list *list,
				 struct esdm_rpcs_connection *rpc_conn,
				 uint32_t revents, int ev, size_t *num,
				 bool *accept_paused)
{
	int ret = 0;

	if (revents & ESDM_RPCS_EV_RX) {
		int32_t bid = loop->rx_buf[ev];
		uint8_t *buf = bid >= 0 ?
			esdm_rpcs_uring_buf(loop, (unsigned int)bid) :
			loop->rx_deferred[ev]->data;
		ssize_t received = (ssize_t)loop->rx_len[ev];

		rpc_conn->rx_pending--;

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "Received %zd bytes\n",
			    received);

		/*
		 * After the probe, the client sends no request in the clear
		 * - its handshake follows the answer to the probe
		 */
		if (!rpc_conn->ring_io || rpc_conn->child_fd < 0) {
			memset_secure(buf, 0,
				      min_size((size_t)received,
					       ESDM_RPC_MAX_MSG_SIZE));
			ret = -EPROTO;
		} else {
			bool probe = rpc_conn->dtls_state ==
				     esdm_rpcs_dtls_probe;

			ret = esdm_rpcs_process(rpc_conn, buf, received);

			/* See esdm_rpcs_read() */
			if (!ret && probe)
				rpc_conn->dtls_state = esdm_rpcs_dtls_handshake;

			/* Idle from the answer on, see esdm_rpcs_read() */
			clock_gettime(CLOCK_MONOTONIC, &rpc_conn->last_used);
		}
		/* Wiped by esdm_rpcs_process() */
		if (bid >= 0) {
			esdm_rpcs_uring_buf_put(loop, (unsigned int)bid, 0);
		} else {
			loop->defer_bytes -= loop->rx_deferred[ev]->len;
			free(loop->rx_deferred[ev]);
		}

		/*
		 * The probe answered: the handshake follows, which the DTLS
		 * reads off the socket itself. Both answers leave by the ring,
		 * in order, after the cancellation of the receive.
		 */
		if (!ret && rpc_conn->ring_io &&
		    rpc_conn->dtls_state == esdm_rpcs_dtls_handshake)
			esdm_rpcs_uring_to_poll(loop, rpc_conn);
	}

	if (revents & ESDM_RPCS_EV_EOF)
		rpc_conn->rx_eof = true;

	if (ret || (revents & (EPOLLERR | EPOLLHUP)) ||
	    (rpc_conn->rx_eof && !rpc_conn->closing)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing client FD %d\n", rpc_conn->child_fd);
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		*accept_paused = false;
		return;
	}

	if (rpc_conn->closing && rpc_conn->rx_eof && !rpc_conn->rx_pending &&
	    !rpc_conn->rx_defer_head && !rpc_conn->tx_head) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,
			    "Closing drained connection for FD %d\n",
			    rpc_conn->child_fd);
		esdm_rpcs_conn_drop(thread, loop, list, rpc_conn, num);
		*accept_paused = false;
		return;
	}

	if (revents & ESDM_RPCS_EV_RX) {
		/* Keep the list in the order of use */
		TAILQ_REMOVE(list, rpc_conn, tailq);
		TAILQ_INSERT_TAIL(list, rpc_conn, tailq);
	}
}
#endif

/*
 * Serve an event of a connection of @thread, its connections @list: read and
 * answer the request of its client, or close it if its client is gone or it
 * failed. @revents are the events of the connection, 0 for one just accepted,
 * @ev the index of the event in the round, -1 for one just accepted.
 * @accept_paused is cleared when the connection is closed.
 */
static void esdm_rpcs_serve(struct esdm_rpc_thread *thread,
			    struct esdm_rpcs_loop *loop,
			    struct esdm_rpcs_connection_list *list,
			    struct esdm_rpcs_connection *rpc_conn,
			    uint32_t revents, int ev, size_t *num,
			    bool *accept_paused)
{
	int read_ret;

#ifdef ESDM_RPC_IO_URING_MULTISHOT
	if (rpc_conn->ring_io ||
	    (revents & (ESDM_RPCS_EV_RX | ESDM_RPCS_EV_EOF |
			ESDM_RPCS_EV_TXDONE))) {
		esdm_rpcs_serve_ring(thread, loop, list, rpc_conn, revents, ev,
				     num, accept_paused);
		return;
	}
#else
	(void)ev;
#endif

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
	esdm_rpcs_cur_loop = &loop;

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

#ifdef ESDM_RPC_IO_URING_MULTISHOT
		loop.events = events;
		loop.ev_num = nfds;
#endif
		for (int i = 0; i < nfds; i++) {
			struct esdm_rpcs_connection *rpc_conn = NULL;

#ifdef ESDM_RPC_IO_URING_MULTISHOT
			/* Those left to a connection closed are voided */
			loop.ev_next = i + 1;
#endif

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
							rpc_conn, 0, -1,
							&num_connections,
							&accept_paused);
				}
				continue;
			}

			rpc_conn = events[i].data.ptr;
			esdm_rpcs_serve(thread, &loop, &rpc_conn_list, rpc_conn,
					events[i].events, i, &num_connections,
					&accept_paused);
		}
#ifdef ESDM_RPC_IO_URING_MULTISHOT
		loop.ev_num = 0;
#endif

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
	esdm_rpcs_cur_loop = NULL;
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
