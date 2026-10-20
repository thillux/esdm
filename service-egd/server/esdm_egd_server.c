/*
 * EGD (Entropy Gathering Daemon) protocol compatibility interface
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "bitshift_be.h"
#include "build_bug_on.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_server.h"
#include "esdm_logger.h"
#include "esdm_peer_account.h"
#include "esdm_peer_limit.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_server_socket.h"
#include "helper.h"
#include "memset_secure.h"
#include "systemd_support.h"
#include "threading_support.h"

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                             \
	for ((var) = TAILQ_FIRST((head));                                      \
	     (var) && ((tvar) = TAILQ_NEXT((var), field), 1); (var) = (tvar))
#endif

/*
 * Room for one maximum sized command plus the beginning of the next one, so a
 * client pipelining its requests does not have to be read byte-wise.
 */
#define ESDM_EGD_BUFSIZE (2 * ESDM_EGD_MAX_CMD_SIZE)

/*
 * Input taken from one connection per round of the event loop. Insertions have
 * no response, so a client streaming them never fills its socket and never
 * stops being readable: without a bound, one sending faster than they are
 * inserted would keep the worker - and every other client on it - to itself.
 * Client sockets are level-triggered, so the rest is taken in the next round.
 */
#define ESDM_EGD_READ_BUDGET (4 * ESDM_EGD_BUFSIZE)

/*
 * Prediction resistant generations per connection and round, see the PR read
 * commands. One costs several reseeds - tens of milliseconds - for a two byte
 * request, so the read budget alone would let one client pipeline seconds of
 * work into a single round and hold up everybody else on the worker. The
 * ordinary generator is cheap enough for the read budget to bound it.
 *
 * This shares a round among the connections, but does not bound it: a client
 * with a request on each of a few hundred connections would still have the
 * worker generate for seconds per round, see ESDM_EGD_ROUND_BUDGET_NS.
 */
#define ESDM_EGD_PR_BUDGET 1

/*
 * Status reports per connection and round, see the status commands. A report
 * is asked for with a single byte, but rendering one takes tens of
 * microseconds: the read budget alone would let a client pipelining the
 * command and draining the answers have the worker render thousands of them
 * per round, and hold up everybody else on the worker for as long. A further
 * one is left for the next round, as a prediction resistant generation is.
 */
#define ESDM_EGD_STATUS_BUDGET 1

/*
 * Time a worker may spend per round of its event loop generating prediction
 * resistant bytes, over all of its connections - the same bound as
 * ESDM_RPCS_ROUND_BUDGET_NS of the RPC server, for the same reason: a worker
 * serves every client it accepted, and none of them is served
 * while it generates. Beyond it, a command is left for the next round - a
 * deferred request stays deferred, a new one waits in the input buffer - which
 * follows at once, after the events of the other clients were collected and
 * served, see deferred_progress in esdm_egd_handler().
 *
 * A time rather than a number of generations, as the cost of one depends on
 * the entropy sources. The first generation of a round is always made, so even
 * one longer than this makes progress - a round runs over by the generation
 * it is in at most, which for a request of ESDM_EGD_MAX_TRANSFER bytes may
 * take several reseeds. The next round begins where this one ran out of
 * budget, see esdm_egd_handler() - otherwise the connections at the head of
 * the list would get all of it.
 */
#define ESDM_EGD_ROUND_BUDGET_NS (25ULL * 1000 * 1000)

/*
 * Largest response of a run of reads answered together, see
 * esdm_egd_read_run(): that of a status report, the largest response a
 * connection holds anyway - so a connection holds no more than it did before.
 */
#define ESDM_EGD_RUN_MAX (4 + ESDM_EGD_MAX_STATUS)

/*
 * Upper bound of concurrently served clients. EGD clients may hold their
 * connection open for their entire lifetime, so this limits clients, not
 * requests; beyond it, connections stay queued in the listen backlog. Generous
 * because such consumers are typically idle long running daemons and nothing is
 * preallocated for them. Serving this many needs a RLIMIT_NOFILE above it; an
 * accept failing for want of a descriptor leaves the client queued, and the
 * server stops listening for a moment rather than being woken for it over and
 * over.
 *
 * Once all slots are taken, a new client is not left queued behind whoever
 * holds them - that would lock it out for as long as they care to - but a
 * connection is closed to make room for it, see esdm_egd_evict_candidate().
 */
#ifndef ESDM_EGD_MAX_CONNECTIONS
#define ESDM_EGD_MAX_CONNECTIONS 2048
#endif

/*
 * Concurrent connections of one unprivileged user - root is exempt. A process
 * that uses the EGD client library holds one connection, so this leaves room
 * for many such consumers per user.
 *
 * A user is its account, see esdm_peer_account.h, not the UID it connects
 * under: the UIDs of its /etc/subuid range it may map in a user namespace and
 * connect as count as its own. Spreading its connections over them gains it
 * nothing - eight of its UIDs would otherwise fill all ESDM_EGD_MAX_CONNECTIONS
 * slots, each holding fewer connections than the consumers of everybody else,
 * which then were the biggest holders and the first to be closed. Filling the
 * slots takes several users this way, and when connections have to be closed
 * - to make room for a new one, or because slots or descriptors run short -
 * those of the user holding the most are closed first, see
 * esdm_egd_evict_candidate() and esdm_egd_idle_reapable().
 */
#ifndef ESDM_EGD_MAX_CONNECTIONS_PER_UID
#define ESDM_EGD_MAX_CONNECTIONS_PER_UID 256
#endif

/*
 * Time a connection may sit idle - no command received, no response owed -
 * before it may be closed, so that abandoned clients do not hold their slot and
 * descriptor forever while others need them.
 *
 * Only then, though: an idle connection is closed only under pressure, see
 * esdm_egd_idle_reapable(). The consumers that hold a connection for their
 * whole lifetime and use it rarely are the ones that cannot reconnect - a
 * process confined by seccomp after connecting, OpenSSH's pre-authentication
 * child being the reference case, is killed for the connect(2). Closing their
 * connection after a minute of silence would trade an idle descriptor for a
 * dead consumer. As long as slots and descriptors are plentiful, the
 * connection costs nobody anything, and the protection against clients that
 * hog them takes effect exactly when they become scarce - and even then it is
 * aimed at those holding the most, so that a user filling the slots cannot have
 * the idle connections of everybody else closed.
 */
#ifndef ESDM_EGD_IDLE_TIMEOUT_MS
#define ESDM_EGD_IDLE_TIMEOUT_MS 60000
#endif

/*
 * Connections in use from which on idle ones are closed: once fewer slots are
 * left than a single unprivileged user may hold, so the slots are reclaimed
 * before a new client has to make room for itself.
 *
 * Reaching it says nothing about who is to blame - it takes several users. The
 * idle connections closed from here on are therefore only those of the users
 * holding the most connections, see esdm_egd_idle_reapable() - closing
 * everybody's would let whoever holds the most have the long lived consumers
 * of everybody else closed, the sandboxed ones among them that cannot connect
 * again.
 */
#ifndef ESDM_EGD_IDLE_REAP_CONNECTIONS
#define ESDM_EGD_IDLE_REAP_CONNECTIONS                                         \
	(ESDM_EGD_MAX_CONNECTIONS - ESDM_EGD_MAX_CONNECTIONS_PER_UID)
#endif

/* Interval of the scan for idle connections */
#define ESDM_EGD_IDLE_SCAN_MS 1000

/*
 * Connections that may wait to be accepted, matched to the number that may be
 * served: a backlog well below the limit above would turn a burst of clients
 * starting at once into connect failures long before that limit is reached.
 * The kernel silently caps this at net.core.somaxconn. A socket handed over by
 * systemd is already listening and unaffected - its depth is the Backlog= of
 * its .socket unit.
 */
#define ESDM_EGD_LISTEN_BACKLOG ESDM_EGD_MAX_CONNECTIONS

/* Number of events processed per epoll_wait call. */
#define ESDM_EGD_MAX_EVENTS 64

/*
 * Poll interval of the event loop while it is idle. It bounds how quickly the
 * worker notices a shutdown request, which is signaled by a plain atomic store
 * from a signal handler and therefore cannot wake the loop by itself.
 */
#define ESDM_EGD_IDLE_POLL_MS 250

/*
 * Poll interval while a blocking read request is deferred: it defines how
 * quickly such a request is answered once the ESDM turns operational.
 */
#define ESDM_EGD_DEFERRED_POLL_MS 50

/*
 * Time a response may stay undelivered before the connection is considered
 * stuck and torn down. Generous, because a client that does not read holds up
 * nothing but its own connection - the worker moved on the moment its socket
 * buffer was full. This only reclaims the slot of a peer that is not coming
 * back for its answer.
 */
#define ESDM_EGD_WRITE_TIMEOUT_MS 30000

struct esdm_egd_conn {
	int fd;

	/* Listener this connection arrived on */
	const struct esdm_egd_listener *listener;

	/* Credentials of the peer, obtained once when the client connected. */
	uid_t peer_uid;

	/* The user the peer is accounted to, see esdm_peer_account.h */
	uid_t peer_account;

	/*
	 * Accounted in esdm_egd_peer_limit, as peer_account. Never for root,
	 * which is not accounted - and none of whose connections is ever closed
	 * for somebody else's, see esdm_egd_can_make_room().
	 */
	bool peer_counted;

	/* Holds one of the ESDM_EGD_MAX_CONNECTIONS in esdm_egd_connections */
	bool slot_counted;

	/* Last time the client sent something or took a response, see
	 * ESDM_EGD_IDLE_TIMEOUT_MS. */
	uint64_t last_active;

	/* Events this connection is currently watched for, see
	 * esdm_egd_conn_arm(). */
	uint32_t armed;

	/* Command bytes received but not yet processed. */
	uint8_t in[ESDM_EGD_BUFSIZE];
	size_t in_len;

	/*
	 * The response of the command in flight, and how much of it the client
	 * has taken. Only ever one: the next command is processed once this is
	 * empty, so a client asking faster than it reads is backed up in its own
	 * socket rather than buffered for. Sized for the largest single response
	 * - a non-blocking read: its length byte and the data.
	 */
	uint8_t out[1 + ESDM_EGD_MAX_TRANSFER];
	/*
	 * A status report does not fit into out, nor do the answers of a run
	 * of reads, see esdm_egd_read_run(): they come in a buffer of their
	 * own, which the connection holds instead for as long as they are on
	 * their way out. NULL otherwise.
	 */
	uint8_t *out_heap;
	size_t out_len;
	size_t out_off;

	/* When the pending response was produced, for the stall timeout. */
	uint64_t out_since;

	/*
	 * Number of bytes owed to the client for a blocking read request that
	 * could not be served yet because the ESDM is not operational. Zero
	 * when no request is deferred. While a request is deferred, no further
	 * command of this connection is processed - the protocol has no
	 * request IDs, so responses must retain their order.
	 */
	uint8_t deferred;

	/* The deferred request asks for prediction resistant bytes */
	bool deferred_pr;

	/*
	 * Bytes of the deferred answer collected so far, see
	 * esdm_egd_cmd_read_block().
	 */
	uint8_t answer[ESDM_EGD_MAX_TRANSFER];
	uint8_t answer_len;

	/*
	 * Generations and status reports left in this round of the event loop,
	 * see ESDM_EGD_PR_BUDGET and ESDM_EGD_STATUS_BUDGET, and the round they
	 * were granted for.
	 */
	unsigned int pr_budget;
	unsigned int status_budget;
	uint64_t budget_round;

	/*
	 * A command is waiting in the input buffer for the next round's
	 * budget. It is served by the event loop without any event of its own:
	 * its bytes are no longer in the socket.
	 */
	bool yielded;

	/*
	 * The client takes no more responses - it hung up, or shut down its
	 * receiving side. What it sent before still counts, see
	 * esdm_egd_peer_gone().
	 */
	bool peer_gone;

	TAILQ_ENTRY(esdm_egd_conn) tailq;
};
TAILQ_HEAD(esdm_egd_conn_list, esdm_egd_conn);

/*
 * The served socket. It is kept in a table of listeners, which the event loop
 * tells apart from the connections by their address. Which generator answers
 * is a matter of the command, see the PR read commands.
 */
struct esdm_egd_listener {
	/* Name under which systemd hands this socket over. */
	const char *systemd_name;

	/*
	 * Socket path requested on the command line. Empty when this socket
	 * was not requested that way - it may still be activated by systemd,
	 * in which case the path lives in the .socket unit and is never known
	 * here.
	 */
	char socket_path[108];

	int listening_fd;

	/*
	 * Was the listening socket handed over by systemd? Its lifecycle is
	 * systemd's business then, and its path is unknown here.
	 */
	bool systemd_socket;
};

static struct esdm_egd_listener esdm_egd_listeners[] = {
	{
		.systemd_name = "ESDM_EGD_SOCKET",
		.listening_fd = -1,
	},
};

#define ESDM_EGD_LISTENER_REGULAR (&esdm_egd_listeners[0])

#define for_each_esdm_egd_listener(listener)                                   \
	for (listener = &esdm_egd_listeners[0];                                \
	     listener < &esdm_egd_listeners[ARRAY_SIZE(esdm_egd_listeners)];   \
	     listener++)

static atomic_int esdm_egd_exit = 0;

/*
 * Time this worker thread spent generating prediction resistant bytes in the
 * current round of its event loop, see ESDM_EGD_ROUND_BUDGET_NS, and whether a
 * generation was left for the next round for want of it (denied). Only bounded
 * inside a worker's event loop: the fuzz harness feeding a stream to a
 * connection of its own is not part of a round.
 *
 * Once a round ran out of budget, the generations of the next one are all left
 * to the pass over the connections that follows its events (hold), which
 * serves them in turn: connections with an event of their own would otherwise
 * take the budget of every round, with nothing left for a request deferred
 * before.
 */
static __thread struct {
	bool in_round;
	bool hold;
	bool denied;
	uint64_t spent_ns;
} esdm_egd_round;

/* PID reported by the get PID command, see esdm_egd_server_set_pid() */
static pid_t esdm_egd_pid = 0;

static struct esdm_peer_limit esdm_egd_peer_limit =
	ESDM_PEER_LIMIT_INIT("EGD server", ESDM_EGD_MAX_CONNECTIONS_PER_UID);
/* Workers serving the EGD sockets, see esdm_egd_server_start() */
static atomic_uint esdm_egd_workers_running = 0;

/*
 * Connections served by all workers together - each worker takes the clients it
 * accepts, and ESDM_EGD_MAX_CONNECTIONS bounds them all.
 */
static atomic_size_t esdm_egd_connections = 0;

/*
 * When an accept last failed for want of descriptors or memory, 0 once one
 * succeeded again. The RLIMIT_NOFILE is shared with the RPC interfaces, so this
 * can happen well below ESDM_EGD_MAX_CONNECTIONS. A time rather than a flag:
 * a client that gave up waiting in the backlog leaves no accept behind to clear
 * it, and the shortage must not be believed forever.
 */
static _Atomic uint64_t esdm_egd_starved_at = 0;

static int esdm_egd_listener_enable(struct esdm_egd_listener *listener,
				    const char *socket_path)
{
	struct sockaddr_un addr;

	if (!socket_path || !*socket_path)
		return -EINVAL;

	/*
	 * The path has to fit into sockaddr_un including its terminating NUL -
	 * the local buffer is sized identically, so one check covers both.
	 */
	BUILD_BUG_ON(sizeof(listener->socket_path) != sizeof(addr.sun_path));
	if (strlen(socket_path) >= sizeof(addr.sun_path)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD socket path is too long (max %zu characters)\n",
			    sizeof(addr.sun_path) - 1);
		return -ENAMETOOLONG;
	}

	snprintf(listener->socket_path, sizeof(listener->socket_path), "%s",
		 socket_path);

	return 0;
}

int esdm_egd_server_enable(const char *socket_path)
{
	return esdm_egd_listener_enable(ESDM_EGD_LISTENER_REGULAR, socket_path);
}

void esdm_egd_server_set_pid(pid_t pid)
{
	esdm_egd_pid = pid;
}

static bool esdm_egd_listener_enabled(const struct esdm_egd_listener *listener)
{
	return (listener->socket_path[0] != '\0');
}

/* Did any of the sockets actually come up? */
static bool esdm_egd_server_active(void)
{
	const struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd >= 0)
			return true;
	}

	return false;
}

bool esdm_egd_server_enabled(void)
{
	const struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (esdm_egd_listener_enabled(listener))
			return true;
	}

	return false;
}

/*
 * Use the EGD listening socket handed over by systemd socket activation.
 *
 * @return 0 when the socket was taken over, -ENOENT when systemd did not hand
 *	   one over (the caller binds it itself then), < 0 on all other errors
 */
static int esdm_egd_server_socket_systemd(struct esdm_egd_listener *listener)
{
#ifdef ESDM_SYSTEMD_SUPPORT
	socklen_t length;
	int fd, type;

	if (systemd_listen_fds() <= 0)
		return -ENOENT;

	fd = systemd_listen_fd_for_name(listener->systemd_name);
	if (fd < 0)
		return -ENOENT;

	/*
	 * The EGD protocol is a stream protocol, so the .socket unit has to use
	 * ListenStream=. Refuse anything else instead of misinterpreting the
	 * message boundaries of another socket type.
	 */
	length = sizeof(type);
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) < 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: cannot determine the type of the systemd provided socket: %s\n",
			strerror(errno));
		close(fd);
		return -errno;
	}

	if (type != SOCK_STREAM) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: the systemd provided socket is not a stream socket - use ListenStream= in the .socket unit\n");
		close(fd);
		return -EPROTOTYPE;
	}

	if (set_fd_nonblocking(fd) < 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SERVER,
			"EGD server: the systemd provided socket cannot be set non-blocking\n");
		close(fd);
		return -EINVAL;
	}

	listener->listening_fd = fd;
	listener->systemd_socket = true;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: using the systemd provided socket %s (FD %d)\n",
		    listener->systemd_name, fd);

	return 0;
#else
	(void)listener;
	return -ENOENT;
#endif
}

static int esdm_egd_listener_socket_init(struct esdm_egd_listener *listener)
{
	struct sockaddr_un addr;
	int errsv, fd, ret;

	/*
	 * Socket activation enables the interface on its own: an administrator
	 * who starts esdm-server-egd.socket wants the EGD interface, and the
	 * socket unit carries its path and access mode. --egd_socket is the
	 * alternative for setups without systemd.
	 */
	ret = esdm_egd_server_socket_systemd(listener);
	if (!ret)
		return 0;
	if (ret != -ENOENT)
		return ret;

	if (!esdm_egd_listener_enabled(listener))
		return 0;

	/*
	 * LISTEN_FDS may be set without any of the descriptors being ours - an
	 * environment inherited from an unrelated socket activated context.
	 * Binding the requested socket ourselves is then the right move, just
	 * as the RPC interfaces do it.
	 */
	esdm_server_remove_stale_socket(listener->socket_path, SOCK_STREAM);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 listener->socket_path);

	/*
	 * EGD is a stream protocol: its clients delimit the messages by the
	 * length information the protocol carries, not by datagram boundaries.
	 */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot create socket: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	/*
	 * EGD clients are ordinary applications, so the socket is available
	 * to everybody, like the unprivileged RPC socket, and everything
	 * reachable through it is equally unprivileged (data from unprivileged
	 * callers is inserted without entropy credit, see
	 * esdm_egd_cmd_write_entropy()). The mode
	 * is the file's from its creation on, as this runs as root and a
	 * chmod(2) of the path afterwards would follow whatever was swapped in
	 * for the socket meanwhile, see esdm_server_bind_unix(). A socket
	 * handed over by systemd never reaches this point: its mode comes from
	 * the SocketMode= of its .socket unit.
	 */
	ret = esdm_server_bind_unix(fd, &addr,
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
					    S_IROTH | S_IWOTH);
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot bind to socket %s: %s\n",
			    listener->socket_path, strerror(-ret));
		close(fd);
		return ret;
	}

	if (listen(fd, ESDM_EGD_LISTEN_BACKLOG) < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot listen on socket %s: %s\n",
			    listener->socket_path, strerror(errsv));
		close(fd);
		return -errsv;
	}

	listener->listening_fd = fd;

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: listening on %s\n", listener->socket_path);

	return 0;
}

int esdm_egd_server_socket_init(void)
{
	struct esdm_egd_listener *listener;
	int ret;

	/* While the privileges are still held, see esdm_peer_account.h. */
	esdm_peer_account_init();

	for_each_esdm_egd_listener (listener) {
		ret = esdm_egd_listener_socket_init(listener);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * Milliseconds on the monotonic clock.
 *
 * The coarse one: what is timed in milliseconds here - the idle and the write
 * timeout, the idle scan, the pause of the listener - is timed in seconds, and
 * the clock is read several times per request, for the activity of the
 * connection and the age of its response. The coarse clock is the time of the
 * last tick, which the vDSO reads from memory whatever the clocksource is,
 * while CLOCK_MONOTONIC reads the clocksource: a system call and a trap to the
 * hypervisor on one without a vDSO, such as acpi_pm or the HPET of a guest
 * whose TSC is not trusted. The acpi_pm of the VMs of the NixOS tests takes
 * 6.7 us per read, and a read of 32 bytes - 83 us - read it four times here.
 */
static uint64_t esdm_egd_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Nanoseconds on the monotonic clock. */
static uint64_t esdm_egd_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Is a response waiting to be accepted by the client? */
static bool esdm_egd_out_pending(const struct esdm_egd_conn *conn)
{
	return (conn->out_off < conn->out_len);
}

/* The buffer of the response in flight */
static uint8_t *esdm_egd_out_buf(struct esdm_egd_conn *conn)
{
	return conn->out_heap ? conn->out_heap : conn->out;
}

/* Wipe the response in flight, delivered or not, and free its buffer. */
static void esdm_egd_out_clear(struct esdm_egd_conn *conn)
{
	memset_secure(esdm_egd_out_buf(conn), 0, conn->out_len);
	free(conn->out_heap);
	conn->out_heap = NULL;
	conn->out_len = 0;
	conn->out_off = 0;
}

/*
 * The client takes no more responses.
 *
 * A client that writes and then exits - a feeder handing over its entropy and
 * closing right away is the textbook case - leaves its bytes readable behind
 * the hangup. They are processed nevertheless, but whatever needs answering is
 * dropped from here on: the response in flight and a deferred request, which
 * would otherwise keep collecting entropy for nobody, and every reply command
 * still in the stream, see esdm_egd_process(). The rest of the stream is thus
 * reduced to the insertions, which cannot block, so draining it cannot tie up
 * the worker.
 */
static void esdm_egd_peer_gone(struct esdm_egd_conn *conn)
{
	conn->peer_gone = true;

	esdm_egd_out_clear(conn);

	conn->deferred = 0;
	conn->deferred_pr = false;
	memset_secure(conn->answer, 0, sizeof(conn->answer));
	conn->answer_len = 0;
}

/*
 * Push out what is left of the response.
 *
 * A socket that cannot take it all is not waited for: the rest stays in the
 * connection, the event loop arms EPOLLOUT and it goes out once the client has
 * made room. Waiting here would hand every other client's latency to whichever
 * one is slowest to read.
 *
 * A client that does not take responses any more is no reason to drop what it
 * still sends - see esdm_egd_peer_gone() - so EPIPE leaves the connection open
 * for the rest of its stream, which ends at its EOF.
 *
 * @return 0 when the connection remains usable, whether or not everything went
 *	   out, < 0 when it has to be closed
 */
static int esdm_egd_flush(struct esdm_egd_conn *conn)
{
	while (esdm_egd_out_pending(conn)) {
		/*
		 * MSG_NOSIGNAL: a client closing its end between asking and
		 * being answered is an everyday event and must come back as an
		 * EPIPE for this connection, not a SIGPIPE for the whole daemon
		 * - the ESDM is a library as much as a daemon, and the host
		 * process owns that signal's disposition. The client library
		 * deliberately does not use this, as the sendto(2) it compiles
		 * to is killed by OpenSSH's pre-authentication sandbox.
		 */
		ssize_t ret = send(conn->fd,
				   esdm_egd_out_buf(conn) + conn->out_off,
				   conn->out_len - conn->out_off,
				   MSG_NOSIGNAL);

		if (ret > 0) {
			conn->out_off += (size_t)ret;
			conn->last_active = esdm_egd_now_ms();
			continue;
		}

		if (ret < 0 && errno == EINTR)
			continue;

		/* The client has not made room yet - EPOLLOUT tells us when. */
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return 0;

		if (ret < 0 && errno == EPIPE) {
			esdm_egd_peer_gone(conn);
			return 0;
		}

		return ret < 0 ? -errno : -EIO;
	}

	/* Delivered - and the buffer is free for the next response. */
	esdm_egd_out_clear(conn);

	return 0;
}

/*
 * Hand a complete response to the client.
 *
 * At most one response is outstanding per connection - a command is only
 * processed once its predecessor's response is gone - which bounds the buffer
 * below to the largest single response the protocol can express.
 *
 * @return 0 when the connection remains usable - the response may still be on
 *	   its way out then - < 0 when it has to be closed
 */
static int esdm_egd_write(struct esdm_egd_conn *conn, const uint8_t *buf,
			  size_t len)
{
	if (esdm_egd_out_pending(conn) || len > sizeof(conn->out)) {
		/*
		 * Both are broken invariants rather than anything a client can
		 * provoke, and continuing would put bytes on the wire that no
		 * request asked for.
		 */
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: response of %zu bytes cannot be queued on FD %d\n",
			    len, conn->fd);
		return -EOVERFLOW;
	}

	memcpy(conn->out, buf, len);
	conn->out_len = len;
	conn->out_off = 0;
	conn->out_since = esdm_egd_now_ms();

	return esdm_egd_flush(conn);
}

/*
 * Hand a complete response in the allocated buffer @buf of @len bytes to the
 * client, which the connection takes over - for the responses too large for
 * the connection's own buffer, see out_heap.
 *
 * @return as esdm_egd_write()
 */
static int esdm_egd_write_heap(struct esdm_egd_conn *conn, uint8_t *buf,
			       size_t len)
{
	if (esdm_egd_out_pending(conn)) {
		/* As in esdm_egd_write(), a broken invariant */
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: response of %zu bytes cannot be queued on FD %d\n",
			    len, conn->fd);
		memset_secure(buf, 0, len);
		free(buf);
		return -EOVERFLOW;
	}

	conn->out_heap = buf;
	conn->out_len = len;
	conn->out_off = 0;
	conn->out_since = esdm_egd_now_ms();

	return esdm_egd_flush(conn);
}

/*
 * Fill @buf with data from the fully seeded generator, or with @pr from the
 * prediction resistance one.
 *
 * Exactly one non-blocking generation is attempted. A request it does not cover
 * goes back to the event loop as a deferred request (see
 * esdm_egd_cmd_read_block()) rather than being retried here, which would tie the
 * worker - it serves every client it accepted - to a single
 * request for as long as the entropy sources need.
 *
 * @generated reports how much was produced, which matters for the prediction
 * resistance generator: it hands out no more than was just delivered, so a
 * short answer is normal, and discarding it to start over would waste entropy
 * and never converge on a large request. It is shared with the other workers
 * and the RPC server, which take turns at it: the generation waits for one
 * block of each request ahead of it rather than finding it taken, and hands
 * out one block where another request waits for its turn - see
 * esdm_get_random_bytes_pr_noblock(). Nothing generated thus means that the
 * entropy sources did not deliver, never that the generator was busy.
 *
 * @return 0 when @len bytes were produced, -EAGAIN when fewer were (the
 *	   caller decides whether to answer short or to come back for more),
 *	   < 0 on all other errors
 */
static int esdm_egd_get_random(struct esdm_egd_conn *conn, bool pr,
			       uint8_t *buf, size_t len, size_t *generated)
{
	ssize_t ret;

	*generated = 0;

	if (pr) {
		uint64_t start = esdm_egd_now_ns();

		if (conn->pr_budget)
			conn->pr_budget--;
		ret = esdm_get_random_bytes_pr_noblock(buf, len);
		esdm_egd_round.spent_ns += esdm_egd_now_ns() - start;
	} else
		ret = esdm_get_random_bytes_full_noblock(buf, len);

	/*
	 * The ESDM left the operational state on the way - its initial DRNG
	 * reached its limit without a reseed. A blocking read waits for it to
	 * return, as for one that never got there.
	 */
	if (ret == -EOPNOTSUPP && !esdm_state_operational())
		return -EAGAIN;

	if (ret < 0)
		return (ret == -EAGAIN) ? -EAGAIN : (int)ret;

	/*
	 * Nothing available: for the prediction resistance generator that means
	 * the entropy sources have not delivered yet, for the ordinary one it
	 * should not happen at all.
	 */
	if (ret == 0)
		return pr ? -EAGAIN : -EFAULT;

	*generated = (size_t)ret;

	return (*generated < len) ? -EAGAIN : 0;
}

/* Command 0x00: report the currently available amount of entropy in bits. */
static int esdm_egd_cmd_entropy_count(struct esdm_egd_conn *conn)
{
	uint32_t ent = esdm_avail_entropy();
	uint8_t resp[4];

	/* The count is transferred in big endian byte order. */
	be32_to_ptr(resp, ent);

	return esdm_egd_write(conn, resp, sizeof(resp));
}

/*
 * Command 0x01: deliver up to the requested number of bytes without blocking.
 * Command 0xe0 does the same from the prediction resistance generator (@pr).
 *
 * The response is prefixed with the number of delivered bytes, which allows
 * answering with zero bytes while the ESDM is not operational yet. Clients
 * treat that as "no entropy available right now" and fall back to the blocking
 * request.
 */
static int esdm_egd_cmd_read_nonblock(struct esdm_egd_conn *conn, bool pr,
				      uint8_t requested)
{
	uint8_t resp[1 + ESDM_EGD_MAX_TRANSFER];
	int ret;

	resp[0] = requested;

	if (requested) {
		size_t generated = 0;

		ret = esdm_egd_get_random(conn, pr, resp + 1, requested,
					  &generated);
		if (ret == -EAGAIN) {
			/* A short answer is what this command is for. */
			resp[0] = (uint8_t)generated;
		} else if (ret) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "EGD server: generation of %u bytes failed: %d\n",
				    requested, ret);
			resp[0] = 0;
		}
	}

	ret = esdm_egd_write(conn, resp, 1 + (size_t)resp[0]);

	memset_secure(resp, 0, sizeof(resp));

	return ret;
}

/*
 * Command 0x02: deliver exactly the requested number of bytes, waiting for the
 * ESDM to become operational if needed. Command 0xe1 does the same from the
 * prediction resistance generator (@pr), waiting for its entropy as well.
 *
 * @return 0 when the request was served, -EAGAIN when it has to be retried
 *	   later, < 0 on all other errors
 */
static int esdm_egd_cmd_read_block(struct esdm_egd_conn *conn, bool pr,
				   uint8_t requested)
{
	size_t generated = 0;
	int ret;

	if (!requested)
		return 0;

	/*
	 * Collect into the connection rather than into a local buffer: a
	 * request is assembled over as many rounds of the event loop as the
	 * available entropy needs - most visibly for the prediction resistance
	 * generator, which hands out no more than its entropy sources just
	 * delivered - and what came out so far must survive them.
	 */
	ret = esdm_egd_get_random(conn, pr, conn->answer + conn->answer_len,
				  requested - conn->answer_len, &generated);
	conn->answer_len += (uint8_t)generated;

	if (ret == -EAGAIN)
		return -EAGAIN;
	if (ret)
		goto out;

	ret = esdm_egd_write(conn, conn->answer, requested);

out:
	memset_secure(conn->answer, 0, sizeof(conn->answer));
	conn->answer_len = 0;

	return ret;
}

/*
 * Command 0x03: insert caller provided data into the auxiliary pool.
 *
 * The protocol lets the caller claim an entropy content for the data. Honoring
 * that from an arbitrary local user would let any of them drive the ESDM's
 * entropy accounting, so the claim is only accepted from a privileged caller -
 * the same rule the RPC interface applies. Unprivileged data is still mixed
 * into the auxiliary pool, just without entropy credit.
 *
 * The command has no response.
 */
static int esdm_egd_cmd_write_entropy(struct esdm_egd_conn *conn,
				      uint32_t entropy_bits, const uint8_t *data,
				      uint8_t len)
{
	int ret;

	if (!len)
		return 0;

	if (conn->peer_uid != 0) {
		if (entropy_bits) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD server: ignoring entropy claim of %u bits from unprivileged UID %u\n",
				entropy_bits, conn->peer_uid);
		}
		entropy_bits = 0;
	}

	/* The data cannot hold more entropy than it has bits. */
	if (entropy_bits > (uint32_t)len * 8)
		entropy_bits = (uint32_t)len * 8;

	ret = esdm_pool_insert_aux(data, len, entropy_bits);
	if (ret) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "EGD server: insertion of %u bytes into the auxiliary pool failed: %d\n",
			    len, ret);
	}

	/*
	 * An insertion failure is not a protocol error - the command has no
	 * response in which it could be reported, and the connection stays
	 * usable.
	 */
	return 0;
}

/* Command 0x04: report the PID of the daemon serving the socket. */
static int esdm_egd_cmd_get_pid(struct esdm_egd_conn *conn)
{
	uint8_t resp[1 + 20];
	int len;

	len = snprintf((char *)resp + 1, sizeof(resp) - 1, "%d",
		       esdm_egd_pid ? (int)esdm_egd_pid : (int)getpid());
	if (len < 0 || (size_t)len >= sizeof(resp))
		return -EFAULT;

	resp[0] = (uint8_t)len;

	return esdm_egd_write(conn, resp, 1 + (size_t)len);
}

/*
 * Command 0xe2: deliver up to the requested number of bytes from the DRNG
 * without waiting for all DRNGs to be fully seeded, the semantics of
 * /dev/urandom. Answered as command 0x01. Before the ESDM is operational it
 * hands out nothing at all - an empty answer then, which is no error - and
 * otherwise only an error answers short.
 */
static int esdm_egd_cmd_read_unseeded(struct esdm_egd_conn *conn,
				      uint8_t requested)
{
	uint8_t resp[1 + ESDM_EGD_MAX_TRANSFER];
	ssize_t ret;
	int rc;

	resp[0] = 0;

	if (requested) {
		ret = esdm_get_random_bytes(resp + 1, requested);
		if (ret < 0) {
			/* Not operational yet is a state, not a failure */
			esdm_logger(ret == -EOPNOTSUPP ? LOGGER_DEBUG :
							 LOGGER_ERR,
				    LOGGER_C_SERVER,
				    "EGD server: generation of %u bytes failed: %zd\n",
				    requested, ret);
		} else if (ret > requested) {
			/* Cannot happen, and is no reason to send more */
			resp[0] = requested;
		} else {
			resp[0] = (uint8_t)ret;
		}
	}

	rc = esdm_egd_write(conn, resp, 1 + (size_t)resp[0]);

	memset_secure(resp, 0, sizeof(resp));

	return rc;
}

/*
 * A run of reads: the same read command - 0x01, 0x02 or 0xe2 - several times
 * in a row at the head of the input, as a client pipelining a read beyond the
 * 255 bytes of one transfer sends it, the esdm_cdev module and
 * libesdm_egd_client among them. The run is answered by one response, and one
 * generation where the DRNGs allow, see max_piece, rather than one of each per
 * command: what a read of ESDM_EGD_MAX_TRANSFER bytes costs is mostly the
 * send(2) of its answer and the generator's cost per call, not the bytes.
 *
 * The answers are ones the commands get one by one where each is served in
 * full: the bytes asked for, preceded by their count where the command has
 * one. Only that case is taken here, the one of an operational ESDM.
 *
 * A generation may fall short. When a DRNG reaches the most it may generate
 * without a full reseed, it hands out what it had left - in a build for
 * SP800-90C after 2^17 bits, which a long run always reaches. The reads of the
 * run it covers in full are answered, the share of the next one is wiped, and
 * the rest of the run stays in the input for the next pass, which a DRNG with
 * output left serves - rather than the whole generation being wiped, which
 * would throw away all the DRNG had left and make it reseed that much sooner.
 * A generation that does not cover even the first read - the ESDM is not
 * operational, which the blocking read defers and the others answer short -
 * leaves the reads to the commands one by one, which ask the generator again,
 * see *@fallback.
 *
 * Nothing changes about the bounds of a connection. The run was in the input
 * buffer, so the work of a round stays within the read budget, as for the
 * commands one by one; its response is held in a buffer of its own of at most
 * ESDM_EGD_RUN_MAX bytes, as a status report is; and it is wiped once it went
 * out, as every response.
 *
 * @return the number of input bytes the run took, 0 when there is none - fewer
 *	   than two reads, or a generation that did not cover the first, see
 *	   *@fallback -, < 0 when the connection has to be closed
 */
static ssize_t esdm_egd_read_run(struct esdm_egd_conn *conn, bool *fallback)
{
	uint8_t cmd = conn->in[0];
	/* The non-blocking reads answer with a count byte, 0x02 without */
	size_t counted = (cmd == ESDM_EGD_CMD_READ_BLOCK) ? 0 : 1;
	size_t num = 0, data = 0, len = 0, generated, served, covered, off;
	size_t pos, i;
	/*
	 * The DRNG is asked for all of the run at once - unless a DRNG may
	 * generate only a bounded number of bits without a full reseed, as in
	 * a build for SP800-90C: then for the share of one command at a time,
	 * as before. Its reseed is triggered by the request that crosses three
	 * quarters of that bound and has to land in the quarter left; requests
	 * of several KiB use that quarter up at once, and the DRNGs ran dry
	 * before their reseeds landed - measured, 1.4 MB/s with calls of one
	 * transfer, 1.1 MB/s with calls of 4 KiB.
	 */
	size_t max_piece =
		(esdm_config_drng_max_wo_reseed_bits() == UINT32_MAX) ?
			ESDM_EGD_RUN_MAX :
			ESDM_EGD_MAX_TRANSFER;
	uint8_t *buf;
	ssize_t ret;

	/* Complete commands of the same read, as many as the bound allows */
	while (2 * (num + 1) <= conn->in_len && conn->in[2 * num] == cmd) {
		size_t requested = conn->in[2 * num + 1];

		if (len + counted + requested > ESDM_EGD_RUN_MAX)
			break;
		len += counted + requested;
		data += requested;
		num++;
	}

	if (num < 2 || !data)
		return 0;

	buf = malloc(len);
	if (!buf)
		return 0;

	/*
	 * All of it at the tail of the buffer, from where each command's share
	 * moves to the front behind its count byte.
	 */
	off = len - data;
	for (generated = 0; generated < data;) {
		size_t piece = data - generated;

		if (piece > max_piece)
			piece = max_piece;
		if (cmd == ESDM_EGD_CMD_ESDM_READ_UNSEEDED)
			ret = esdm_get_random_bytes(buf + off + generated, piece);
		else
			ret = esdm_get_random_bytes_full_noblock(
				buf + off + generated, piece);
		if (ret <= 0)
			break;
		if ((size_t)ret > piece)
			ret = (ssize_t)piece;
		generated += (size_t)ret;
		if ((size_t)ret < piece)
			break;
	}

	/* The reads the generation covers in full */
	for (served = 0, covered = 0; served < num; served++) {
		size_t requested = conn->in[2 * served + 1];

		if (covered + requested > generated)
			break;
		covered += requested;
	}

	if (!served) {
		memset_secure(buf, 0, len);
		free(buf);
		*fallback = true;
		return 0;
	}

	if (counted) {
		/*
		 * The share of command i moves from off to pos, which is
		 * ahead of it by the count bytes of the commands behind it,
		 * so no share is overwritten before it moved.
		 */
		for (i = 0, pos = 0; i < served; i++) {
			uint8_t requested = conn->in[2 * i + 1];

			buf[pos] = requested;
			memmove(buf + pos + 1, buf + off, requested);
			pos += 1 + (size_t)requested;
			off += requested;
		}
	}

	/*
	 * Behind the answers: nothing when all reads were served, otherwise
	 * the share of the first one that was not, and what the moves above
	 * left of the others.
	 */
	memset_secure(buf + served * counted + covered, 0,
		      len - served * counted - covered);

	ret = esdm_egd_write_heap(conn, buf, served * counted + covered);
	if (ret)
		return ret;

	return (ssize_t)(2 * served);
}

/* Command 0xe3: report the state, see ESDM_EGD_STATE_* */
static int esdm_egd_cmd_get_state(struct esdm_egd_conn *conn)
{
	uint8_t resp[1 + 4 * ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	unsigned int i;

	BUILD_BUG_ON(sizeof(resp) > 1 + ESDM_EGD_MAX_TRANSFER);

	fields[ESDM_EGD_STATE_FLAGS] =
		(esdm_state_operational() ? ESDM_EGD_STATE_FLAG_OPERATIONAL :
					    0) |
		(esdm_state_fully_seeded() ? ESDM_EGD_STATE_FLAG_FULLY_SEEDED :
					     0);
	fields[ESDM_EGD_STATE_ENT_CNT] = esdm_avail_entropy_aux();
	fields[ESDM_EGD_STATE_POOLSIZE] = esdm_avail_poolsize_aux();
	fields[ESDM_EGD_STATE_WRITE_WAKEUP] = esdm_get_write_wakeup_bits();
	fields[ESDM_EGD_STATE_MIN_RESEED_SECS] = esdm_get_reseed_max_time();

	resp[0] = ESDM_EGD_STATE_NUM_FIELDS;
	for (i = 0; i < ESDM_EGD_STATE_NUM_FIELDS; i++)
		be32_to_ptr(resp + 1 + 4 * i, fields[i]);

	return esdm_egd_write(conn, resp, sizeof(resp));
}

/*
 * Commands 0xe4 and 0xe5 (@json): report the status as text or as JSON
 * document, preceded by its length.
 *
 * A text report that does not fit is sent as far as it got, as the RPC
 * interface does - it stays readable. A JSON document that does not fit, and
 * any report that cannot be produced, is sent as an empty one.
 */
static int esdm_egd_cmd_status(struct esdm_egd_conn *conn, bool json)
{
	/* The length, the report and the NUL the status functions write */
	size_t alloc = 4 + ESDM_EGD_MAX_STATUS + 1;
	uint8_t *buf = calloc(1, alloc), *shrunk;
	size_t len = 0;
	int ret;

	if (conn->status_budget)
		conn->status_budget--;

	/* Without memory, an empty report is all there is to say */
	if (!buf) {
		uint8_t empty[4] = { 0 };

		return esdm_egd_write(conn, empty, sizeof(empty));
	}

	if (json)
		ret = esdm_status_json((char *)buf + 4, alloc - 4);
	else
		ret = esdm_status((char *)buf + 4, alloc - 4);

	if (!ret || (!json && ret == -EMSGSIZE))
		len = strnlen((char *)buf + 4, ESDM_EGD_MAX_STATUS);

	be32_to_ptr(buf, (uint32_t)len);

	/* Only what goes out is held while the client takes it */
	shrunk = realloc(buf, 4 + len);
	if (shrunk)
		buf = shrunk;

	return esdm_egd_write_heap(conn, buf, 4 + len);
}

/*
 * The commands changing the entropy accounting or the DRNGs, 0xe6 to 0xea,
 * with their argument @arg - zero for those without one. Only a privileged
 * peer has them carried out, just like the entropy claim of command 0x03; the
 * RPC interface applies the same rule. Answered with a status.
 *
 * Carried out also when the peer is gone - what it sent still counts, as for
 * an insertion - but then not answered.
 */
static int esdm_egd_cmd_priv(struct esdm_egd_conn *conn, uint8_t cmd,
			     uint32_t arg)
{
	uint8_t resp[4];
	int32_t ret = 0;

	if (conn->peer_uid != 0) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "EGD server: refusing command 0x%02x of unprivileged UID %u\n",
			    cmd, conn->peer_uid);
		ret = -EPERM;
		goto out;
	}

	switch (cmd) {
	case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
		/* As the RPC interface: never above the pool's digest size */
		esdm_pool_add_entropy(arg);
		break;
	case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
		esdm_pool_set_entropy(0);
		break;
	case ESDM_EGD_CMD_ESDM_RESEED:
		esdm_drng_force_reseed();
		break;
	case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
		esdm_set_write_wakeup_bits(arg);
		break;
	case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
		esdm_set_reseed_max_time(arg);
		break;
	default:
		/* Cannot happen - esdm_egd_process() only passes these */
		ret = -EINVAL;
		break;
	}

out:
	if (conn->peer_gone)
		return 0;

	be32_to_ptr(resp, (uint32_t)ret);

	return esdm_egd_write(conn, resp, sizeof(resp));
}

/*
 * May the connection generate once more in this round? Only prediction
 * resistant generations (@pr) are bounded: within the connection's own budget,
 * ESDM_EGD_PR_BUDGET, and within that of the worker, ESDM_EGD_ROUND_BUDGET_NS.
 */
static bool esdm_egd_may_generate(const struct esdm_egd_conn *conn, bool pr)
{
	if (!pr)
		return true;

	if (!conn->pr_budget)
		return false;

	if (!esdm_egd_round.in_round)
		return true;

	if (esdm_egd_round.hold)
		return false;

	if (esdm_egd_round.spent_ns >= ESDM_EGD_ROUND_BUDGET_NS) {
		esdm_egd_round.denied = true;
		return false;
	}

	return true;
}

/*
 * A new round of this worker's event loop begins - with its events held from
 * generating if the previous round ran out of budget, see esdm_egd_round.
 */
static void esdm_egd_round_start(void)
{
	esdm_egd_round.in_round = true;
	esdm_egd_round.hold = esdm_egd_round.denied;
	esdm_egd_round.denied = false;
	esdm_egd_round.spent_ns = 0;
}

/* Grant the connection its budget once per round of the event loop. */
static void esdm_egd_conn_round(struct esdm_egd_conn *conn, uint64_t round)
{
	if (conn->budget_round == round)
		return;

	conn->budget_round = round;
	conn->pr_budget = ESDM_EGD_PR_BUDGET;
	conn->status_budget = ESDM_EGD_STATUS_BUDGET;
}

/* Serve a deferred blocking read request, if there is one. */
static int esdm_egd_serve_deferred(struct esdm_egd_conn *conn)
{
	int ret;

	if (!conn->deferred)
		return 0;

	/* Still deferred - the next round continues it. */
	if (!esdm_egd_may_generate(conn, conn->deferred_pr))
		return -EAGAIN;

	ret = esdm_egd_cmd_read_block(conn, conn->deferred_pr, conn->deferred);
	if (ret)
		return ret;

	conn->deferred = 0;
	conn->deferred_pr = false;

	return 0;
}

/*
 * Watch the connection for what it can currently make progress on.
 *
 * A response on its way out is waited for with EPOLLOUT and nothing else: the
 * command behind it is not processed until it is delivered.
 *
 * A connection with a deferred request is watched for neither, since nothing of
 * it is read (see esdm_egd_read()) and a level-triggered EPOLLIN would spin the
 * worker on a pipelined client's unread bytes for as long as the request waits.
 * EPOLLERR and EPOLLHUP are reported regardless, so an unwatched connection is
 * still torn down when its peer goes away.
 */
static void esdm_egd_conn_arm(int epfd, struct esdm_egd_conn *conn)
{
	struct epoll_event ev = { .data.ptr = conn };

	if (esdm_egd_out_pending(conn))
		ev.events = EPOLLOUT;
	else if (!conn->deferred)
		ev.events = EPOLLIN | EPOLLRDHUP;

	if (conn->armed == ev.events)
		return;

	if (epoll_ctl(epfd, EPOLL_CTL_MOD, conn->fd, &ev) < 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "EGD server: cannot watch client FD %d for 0x%x: %s\n",
			    conn->fd, ev.events, strerror(errno));
		return;
	}

	conn->armed = ev.events;
}

/*
 * Consume @len bytes from the head of the connection's input buffer.
 *
 * The @len bytes behind what is left are wiped: client supplied entropy data
 * must not linger in the buffer, neither of the consumed command nor of what
 * follows it - the beginning of the next insertion, say - whose copy the move
 * leaves at its old offset.
 */
static void esdm_egd_consume(struct esdm_egd_conn *conn, size_t len)
{
	conn->in_len -= len;
	if (conn->in_len)
		memmove(conn->in, conn->in + len, conn->in_len);
	memset_secure(conn->in + conn->in_len, 0, len);
}

/* Does the command change something rather than only produce an answer? */
static bool esdm_egd_cmd_changes(uint8_t cmd)
{
	switch (cmd) {
	case ESDM_EGD_CMD_WRITE_ENTROPY:
	case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
	case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
	case ESDM_EGD_CMD_ESDM_RESEED:
	case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
	case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
		return true;
	default:
		return false;
	}
}

/*
 * Get the connection as far as it can go right now: deliver what is left of the

 * response in flight, then process as many complete commands as the input
 * buffer holds.
 *
 * It stops at the first command whose response the client did not take right
 * away, which is what makes one response buffer enough: a client asking faster
 * than it reads is slowed down by its own socket, not buffered for. It also
 * stops at a generation or a status report the round has no budget left for
 * (conn->yielded).
 *
 * @return 0 when the connection remains usable, < 0 when it has to be closed
 */
static int esdm_egd_process(struct esdm_egd_conn *conn)
{
	/* A run of reads was not served in full, see esdm_egd_read_run() */
	bool run_fallback = false;
	int ret;

	conn->yielded = false;

	/* Nothing new is started once shutdown is requested. */
	if (atomic_load(&esdm_egd_exit))
		return 0;

	/* The response of the previous command has to be out of the way. */
	ret = esdm_egd_flush(conn);
	if (ret)
		return ret;
	if (esdm_egd_out_pending(conn))
		return 0;

	/*
	 * A deferred request blocks the connection: its response must precede
	 * the responses of all commands received after it.
	 */
	ret = esdm_egd_serve_deferred(conn);
	if (ret)
		return (ret == -EAGAIN) ? 0 : ret;
	if (esdm_egd_out_pending(conn))
		return 0;

	while (conn->in_len) {
		size_t cmd_len;
		bool pr;

		switch (conn->in[0]) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
		case ESDM_EGD_CMD_GET_PID:
			cmd_len = 1;
			break;
		case ESDM_EGD_CMD_ESDM_GET_STATE:
		case ESDM_EGD_CMD_ESDM_STATUS:
		case ESDM_EGD_CMD_ESDM_STATUS_JSON:
		case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
		case ESDM_EGD_CMD_ESDM_RESEED:
			cmd_len = 1;
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
		case ESDM_EGD_CMD_READ_BLOCK:
		case ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK:
		case ESDM_EGD_CMD_ESDM_PR_READ_BLOCK:
		case ESDM_EGD_CMD_ESDM_READ_UNSEEDED:
			cmd_len = 2;
			break;
		case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
		case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
		case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
			cmd_len = 5;
			break;

		case ESDM_EGD_CMD_WRITE_ENTROPY:
			if (conn->in_len < 4)
				return 0;
			cmd_len = 4 + (size_t)conn->in[3];
			break;
		default:
			/*
			 * The protocol offers no way to report an error, and
			 * an unknown command byte means the stream is out of
			 * sync - the only sane reaction is to drop the client.
			 */
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
				    "EGD server: unknown command 0x%02x on FD %d\n",
				    conn->in[0], conn->fd);
			return -EPROTO;
		}

		/* Wait for the remainder of the command. */
		if (conn->in_len < cmd_len)
			return 0;

		/*
		 * Nobody is left to take an answer, so a command that does
		 * nothing but produce one is skipped - see
		 * esdm_egd_peer_gone(). Those changing something are carried
		 * out, like an insertion.
		 */
		if (conn->peer_gone && !esdm_egd_cmd_changes(conn->in[0])) {
			ret = 0;
			goto consume;
		}

		/* Left for the next round, see ESDM_EGD_PR_BUDGET. */
		pr = (conn->in[0] == ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK ||
		      conn->in[0] == ESDM_EGD_CMD_ESDM_PR_READ_BLOCK);
		if (pr && conn->in[1] && !esdm_egd_may_generate(conn, pr)) {
			conn->yielded = true;
			return 0;
		}

		/* The same for a status report, see ESDM_EGD_STATUS_BUDGET. */
		if ((conn->in[0] == ESDM_EGD_CMD_ESDM_STATUS ||
		     conn->in[0] == ESDM_EGD_CMD_ESDM_STATUS_JSON) &&
		    !conn->status_budget) {
			conn->yielded = true;
			return 0;
		}

		/*
		 * Several reads in a row are answered together, see
		 * esdm_egd_read_run(). Once a generation for them fell short,
		 * the rest of the input is served command by command: asking
		 * the generator for the run again at every command would
		 * mostly come up short again.
		 */
		if ((conn->in[0] == ESDM_EGD_CMD_READ_NONBLOCK ||
		     conn->in[0] == ESDM_EGD_CMD_READ_BLOCK ||
		     conn->in[0] == ESDM_EGD_CMD_ESDM_READ_UNSEEDED) &&
		    !run_fallback) {
			ssize_t taken = esdm_egd_read_run(conn, &run_fallback);

			if (taken < 0)
				return (int)taken;
			if (taken) {
				cmd_len = (size_t)taken;
				ret = 0;
				goto consume;
			}
		}

		switch (conn->in[0]) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
			ret = esdm_egd_cmd_entropy_count(conn);
			break;
		case ESDM_EGD_CMD_GET_PID:
			ret = esdm_egd_cmd_get_pid(conn);
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
		case ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK:
			ret = esdm_egd_cmd_read_nonblock(conn, pr, conn->in[1]);
			break;
		case ESDM_EGD_CMD_READ_BLOCK:
		case ESDM_EGD_CMD_ESDM_PR_READ_BLOCK:
			ret = esdm_egd_cmd_read_block(conn, pr, conn->in[1]);
			if (ret == -EAGAIN) {
				/*
				 * Remember the request and answer it once the
				 * ESDM turned operational. The command is
				 * consumed here so it is not processed twice.
				 */
				conn->deferred = conn->in[1];
				conn->deferred_pr = pr;
				esdm_egd_consume(conn, cmd_len);
				return 0;
			}
			break;
		case ESDM_EGD_CMD_WRITE_ENTROPY:
			/* Big endian entropy claim, see the protocol header. */
			ret = esdm_egd_cmd_write_entropy(
				conn, ptr_to_be16(conn->in + 1), conn->in + 4,
				conn->in[3]);
			break;
		case ESDM_EGD_CMD_ESDM_READ_UNSEEDED:
			ret = esdm_egd_cmd_read_unseeded(conn, conn->in[1]);
			break;
		case ESDM_EGD_CMD_ESDM_GET_STATE:
			ret = esdm_egd_cmd_get_state(conn);
			break;
		case ESDM_EGD_CMD_ESDM_STATUS:
			ret = esdm_egd_cmd_status(conn, false);
			break;
		case ESDM_EGD_CMD_ESDM_STATUS_JSON:
			ret = esdm_egd_cmd_status(conn, true);
			break;
		case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
		case ESDM_EGD_CMD_ESDM_RESEED:
			ret = esdm_egd_cmd_priv(conn, conn->in[0], 0);
			break;
		case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
		case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
		case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
			/* Big endian argument, see the protocol header. */
			ret = esdm_egd_cmd_priv(conn, conn->in[0],
						ptr_to_be32(conn->in + 1));
			break;
		default:
			/* Cannot happen - the switch above filtered it out. */
			ret = -EPROTO;
			break;
		}

consume:
		esdm_egd_consume(conn, cmd_len);

		if (ret)
			return ret;

		/*
		 * The response did not fit into the client's socket buffer. The
		 * command behind it has to wait for it to be delivered - its own
		 * response would otherwise be read as the answer to this one.
		 */
		if (esdm_egd_out_pending(conn))
			return 0;

		if (atomic_load(&esdm_egd_exit))
			return 0;
	}

	return 0;
}

#ifdef ESDM_FUZZING
/* Documented with its declaration in esdm_egd_server.h */
int esdm_egd_fuzz_stream(int out_fd, const uint8_t *data, size_t len)
{
	struct esdm_egd_conn conn;
	uint64_t round = 0;
	size_t pos = 0;
	int ret = 0;

	if (len && !data)
		return -EINVAL;

	memset(&conn, 0, sizeof(conn));
	conn.fd = out_fd;
	conn.listener = ESDM_EGD_LISTENER_REGULAR;
	/*
	 * Who the client is decides whether its entropy claim is believed, so
	 * it is the credentials of this process - the same answer the accept
	 * path gets from the socket, and root only where the harness runs as
	 * root.
	 */
	conn.peer_uid = getuid();

	/*
	 * The input is a sequence of records, each a length byte followed by
	 * that many bytes, and each record is one read() as the connection
	 * would see it.
	 */
	while (pos < len) {
		size_t chunk = data[pos++];

		if (chunk > len - pos)
			chunk = len - pos;

		if (chunk > sizeof(conn.in) - conn.in_len)
			chunk = sizeof(conn.in) - conn.in_len;

		if (chunk) {
			memcpy(conn.in + conn.in_len, data + pos, chunk);
			conn.in_len += chunk;
			pos += chunk;
		}

		/* Each record is a round, and as many follow as it needs. */
		do {
			esdm_egd_conn_round(&conn, ++round);
			ret = esdm_egd_process(&conn);
		} while (!ret && conn.yielded);
		if (ret)
			break;
	}

	esdm_egd_out_clear(&conn);
	memset_secure(conn.in, 0, sizeof(conn.in));
	memset_secure(conn.answer, 0, sizeof(conn.answer));
	memset_secure(conn.out, 0, sizeof(conn.out));

	return ret;
}
#endif /* ESDM_FUZZING */

/*
 * Read from the connection and process what became complete, up to
 * ESDM_EGD_READ_BUDGET bytes.
 *
 * @return 0 when the connection remains usable, 1 when it does and the budget
 *	   ran out with input possibly left, < 0 when it has to be closed
 */
static int esdm_egd_read(struct esdm_egd_conn *conn)
{
	size_t budget = ESDM_EGD_READ_BUDGET;
	int ret;

	/* What a previous round left for this one comes first. */
	if (conn->yielded) {
		ret = esdm_egd_process(conn);
		if (ret)
			return ret;
	}

	while (1) {
		ssize_t received;
		size_t room;

		/*
		 * While a request is deferred or waits for its budget, a
		 * response is on its way out or the buffer is full, do not read
		 * further: the pending data stays in the socket buffer, which
		 * applies backpressure to the client instead of requiring
		 * unbounded buffering here.
		 */
		if (conn->deferred || conn->yielded ||
		    esdm_egd_out_pending(conn) ||
		    conn->in_len >= sizeof(conn->in))
			return 0;

		/* Leave the rest to the next round, or to nobody at shutdown. */
		if (!budget)
			return 1;
		if (atomic_load(&esdm_egd_exit))
			return 0;

		/* recv() for symmetry with the send() of the response. */
		room = sizeof(conn->in) - conn->in_len;
		if (room > budget)
			room = budget;
		received = recv(conn->fd, conn->in + conn->in_len, room, 0);
		if (received == 0) {
			/* Orderly shutdown by the client. */
			return -EPIPE;
		}
		if (received < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				return 0;
			return -errno;
		}

		conn->in_len += (size_t)received;
		budget -= (size_t)received;
		conn->last_active = esdm_egd_now_ms();

		ret = esdm_egd_process(conn);
		if (ret)
			return ret;
	}
}

static void esdm_egd_release_conn(struct esdm_egd_conn *conn)
{
	if (!conn)
		return;

	if (conn->fd >= 0) {
		shutdown(conn->fd, SHUT_RDWR);
		close(conn->fd);
		conn->fd = -1;
	}

	if (conn->peer_counted)
		esdm_peer_limit_put(&esdm_egd_peer_limit, conn->peer_account);

	if (conn->slot_counted)
		atomic_fetch_sub(&esdm_egd_connections, 1);

	esdm_egd_out_clear(conn);
	memset_secure(conn->in, 0, sizeof(conn->in));
	memset_secure(conn->out, 0, sizeof(conn->out));
	memset_secure(conn->answer, 0, sizeof(conn->answer));
	free(conn);

}

/*
 * Did the client send something the server has not read yet? It waits in the
 * socket's receive queue, out of sight of conn->in_len, until the event loop
 * takes it - in the next round if it came after the events of this one were
 * collected. Nothing counts as sent if the queue cannot be told.
 */
static bool esdm_egd_input_queued(const struct esdm_egd_conn *conn)
{
	int queued = 0;

	if (ioctl(conn->fd, FIONREAD, &queued) < 0)
		return false;

	return queued > 0;
}

/*
 * Close a connection the server gives up on by itself - one idle for too long,
 * or one closed to make room for a new one. Unlike one whose client hung up,
 * its client may be writing to it right now: what it wrote last waits in the
 * socket's receive queue, and closing the socket would discard it although the
 * client's write succeeded. For an insertion, which has no answer, nothing
 * would ever tell the client that its data never arrived.
 *
 * So the reading side is shut down first. Every later write of the client
 * fails from then on, while what came before stays readable: if anything did,
 * the connection is not closed yet but drained as one whose client is gone,
 * see esdm_egd_peer_gone(). Its insertions are carried out, nothing is answered
 * any more, and the event loop closes it at the end of its input, see
 * esdm_egd_read(). Its slot and its account's count are given up right away
 * all the same, which also keeps it from being chosen to be closed once more.
 *
 * @return true if the connection was closed, false if it is left to drain
 */
static bool esdm_egd_reclaim(int epfd, struct esdm_egd_conn_list *list,
			     struct esdm_egd_conn *conn)
{
	shutdown(conn->fd, SHUT_RD);

	if (!esdm_egd_input_queued(conn)) {
		epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
		TAILQ_REMOVE(list, conn, tailq);
		esdm_egd_release_conn(conn);
		return true;
	}

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_SERVER,
		"EGD server: taking what the client on FD %d sent before closing its connection\n",
		conn->fd);

	esdm_egd_peer_gone(conn);

	if (conn->peer_counted) {
		esdm_peer_limit_put(&esdm_egd_peer_limit, conn->peer_account);
		conn->peer_counted = false;
	}
	if (conn->slot_counted) {
		atomic_fetch_sub(&esdm_egd_connections, 1);
		conn->slot_counted = false;
	}

	esdm_egd_conn_arm(epfd, conn);

	return false;
}

/*
 * Is something owed to the client, or is it in the middle of a command - or
 * did it send one the server has yet to read? Its connection is then closed to
 * make room only when no other one is left, see esdm_egd_evict_candidate().
 */
static bool esdm_egd_conn_busy(const struct esdm_egd_conn *conn)
{
	return conn->deferred || conn->yielded || conn->in_len ||
	       esdm_egd_out_pending(conn) || esdm_egd_input_queued(conn);
}

/*
 * May this worker close one of its connections for a new one? Only those of
 * the accounts holding the most connections over all workers are ever closed
 * for that, see esdm_egd_evict_candidate(): a worker serving none of them
 * would accept a new client only to turn it away, rather than leave it to a
 * worker that can make room. Only those of unprivileged users, too: root is
 * exempt from the per-user bound as it is the owner of the daemon, and a root
 * consumer is the last one to be turned into collateral damage.
 */
static bool esdm_egd_can_make_room(const struct esdm_egd_conn_list *list)
{
	unsigned int top = esdm_peer_limit_max_count(&esdm_egd_peer_limit);
	const struct esdm_egd_conn *conn;

	TAILQ_FOREACH (conn, list, tailq) {
		if (conn->peer_counted &&
		    esdm_peer_limit_count(&esdm_egd_peer_limit,
					  conn->peer_account) >= top)
			return true;
	}

	return false;
}

/*
 * The connection to close for a new one once all ESDM_EGD_MAX_CONNECTIONS slots
 * are taken, chosen among the connections of this worker - each worker owns its
 * connections, and closing one of another worker would race with that worker
 * serving it.
 *
 * It is a connection of an account holding the most connections over all
 * workers, @top as told by esdm_peer_limit_max_count() with the new connection
 * accounted already. Whoever fills the slots holds many, so this takes the
 * slots from that user and leaves the consumers of everybody else alone. If
 * the account of the new connection, @newcomer, is among those holding the
 * most, it pays for the new connection itself: a new connection of the user
 * filling the slots then only ever costs it one of its own, and service goes
 * on for everybody, at the price of churn under attack.
 *
 * A connection of an account holding fewer than @top is never closed, not even
 * by a worker that serves none of the accounts holding the most - it would
 * close the connection of somebody else whenever one of those connects again.
 * The new connection is turned away instead, at no cost to anybody but the
 * user holding the most, see esdm_egd_make_room().
 *
 * Among those, the least recently active connection with nothing owed to its
 * client is closed, else the least recently active one at all: sparing busy
 * connections altogether would let a client that always keeps a request in
 * flight hold its slots forever. Root's connections are never closed, see
 * esdm_egd_can_make_room().
 *
 * @return the connection to close, NULL if this worker holds none that may be
 */
static struct esdm_egd_conn *
esdm_egd_evict_candidate(struct esdm_egd_conn_list *list, uid_t newcomer,
			 unsigned int top)
{
	struct esdm_egd_conn *conn, *victim = NULL;
	bool victim_own = false, victim_busy = false;

	TAILQ_FOREACH (conn, list, tailq) {
		bool busy, own;

		if (!conn->peer_counted ||
		    esdm_peer_limit_count(&esdm_egd_peer_limit,
					  conn->peer_account) < top)
			continue;

		own = (conn->peer_account == newcomer);
		busy = esdm_egd_conn_busy(conn);

		if (victim) {
			if (!own && victim_own)
				continue;
			if (own == victim_own) {
				if (busy && !victim_busy)
					continue;
				if (busy == victim_busy &&
				    conn->last_active >= victim->last_active)
					continue;
			}
		}

		victim = conn;
		victim_own = own;
		victim_busy = busy;
	}

	return victim;
}

/*
 * Close a connection of this worker to make room for a new one of the account
 * @newcomer, see esdm_egd_evict_candidate(), once what its client sent is taken
 * - see esdm_egd_reclaim(). Its slot is handed on to the new connection rather
 * than given back: another worker would otherwise be free to take it in
 * between. The events still to be handled in this round, @num of @pending, are
 * voided for the closed connection - one left to drain is reported again in
 * the next round.
 *
 * @return true when a connection gave up its slot, which is the caller's now
 */
static bool esdm_egd_make_room(int epfd, struct esdm_egd_conn_list *list,
			       struct epoll_event *pending, int num,
			       uid_t newcomer)
{
	struct esdm_egd_conn *victim = esdm_egd_evict_candidate(
		list, newcomer, esdm_peer_limit_max_count(&esdm_egd_peer_limit));
	int i;

	if (!victim)
		return false;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_SERVER,
		"EGD server: closing connection on FD %d of UID %u (user %u) to make room\n",
		victim->fd, (unsigned int)victim->peer_uid,
		(unsigned int)victim->peer_account);

	for (i = 0; i < num; i++) {
		if (pending[i].data.ptr == victim)
			pending[i].data.ptr = NULL;
	}

	victim->slot_counted = false;
	esdm_egd_reclaim(epfd, list, victim);

	return true;
}

/*
 * Accept one client and register it with the event loop. @list holds the
 * connections of this worker, and the events of this round still to be handled
 * are @num of @pending - one of the connections may be closed to make room for
 * the new one.
 */
static struct esdm_egd_conn *
esdm_egd_accept(int epfd, const struct esdm_egd_listener *listener,
		bool *out_of_resources, struct esdm_egd_conn_list *list,
		struct epoll_event *pending, int num)
{
	struct esdm_egd_conn *conn;
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	struct epoll_event ev;
	int fd = accept4(listener->listening_fd, NULL, NULL,
			 SOCK_NONBLOCK | SOCK_CLOEXEC);

	if (fd < 0) {
		/* The client stays queued, see the caller */
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
		    errno == ENOMEM) {
			if (!*out_of_resources)
				esdm_logger(
					LOGGER_WARN, LOGGER_C_SERVER,
					"EGD server: cannot accept connections: %s\n",
					strerror(errno));
			*out_of_resources = true;
			atomic_store(&esdm_egd_starved_at, esdm_egd_now_ms());
		}
		return NULL;
	}

	atomic_store(&esdm_egd_starved_at, 0);

	conn = calloc(1, sizeof(struct esdm_egd_conn));
	if (!conn) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot allocate client connection\n");
		close(fd);
		return NULL;
	}

	conn->fd = fd;
	conn->listener = listener;

	/*
	 * Latch the peer's UID now: it decides whether an entropy claim of a
	 * write request is honored. A client dropping its privileges later
	 * keeps the credentials it connected with, which is the same property
	 * the RPC interface has for its long-lived connections.
	 */
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot obtain peer credentials: %s\n",
			    strerror(errno));
		esdm_egd_release_conn(conn);
		return NULL;
	}
	conn->peer_uid = cred.uid;
	conn->peer_account = esdm_peer_account(fd, &cred);

	/*
	 * A peer at its limit is refused right away rather than left queued:
	 * that would block the listen backlog for everybody else.
	 */
	if (!esdm_peer_limit_get(&esdm_egd_peer_limit, conn->peer_account)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_SERVER,
			"EGD server: refusing connection from UID %u (user %u)\n",
			conn->peer_uid, conn->peer_account);
		esdm_egd_release_conn(conn);
		return NULL;
	}
	/*
	 * Root's connection is admitted without being accounted. Taking it as
	 * accounted all the same would make it one holding the most - none -
	 * whenever nobody else holds any.
	 */
	conn->peer_counted = (conn->peer_account != 0);

	/*
	 * Several workers accept from the same listener - which one of them
	 * takes the last slot is decided here. Without a free one, this worker
	 * makes room by closing one of its connections, whose slot the new one
	 * takes over, see esdm_egd_make_room().
	 */
	if (atomic_fetch_add(&esdm_egd_connections, 1) >=
	    ESDM_EGD_MAX_CONNECTIONS) {
		atomic_fetch_sub(&esdm_egd_connections, 1);
		if (!esdm_egd_make_room(epfd, list, pending, num,
					conn->peer_account)) {
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_SERVER,
				"EGD server: no room for a connection on FD %d\n",
				fd);
			esdm_egd_release_conn(conn);
			return NULL;
		}
	}
	conn->slot_counted = true;
	conn->last_active = esdm_egd_now_ms();

	ev.events = EPOLLIN | EPOLLRDHUP;
	ev.data.ptr = conn;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot add client FD %d to epoll: %s\n",
			    fd, strerror(errno));
		esdm_egd_release_conn(conn);
		return NULL;
	}
	conn->armed = ev.events;

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_SERVER,
		"EGD server: new connection on FD %d from UID %u (user %u)\n",
		fd, conn->peer_uid, conn->peer_account);

	return conn;
}

/* Did an accept fail for want of descriptors within the last poll interval? */
static bool esdm_egd_starving(uint64_t now)
{
	uint64_t starved_at = atomic_load(&esdm_egd_starved_at);

	/* Another worker may have stored a time later than @now. */
	return starved_at && (now < starved_at ||
			      now - starved_at < ESDM_EGD_IDLE_POLL_MS);
}

/*
 * Is the server short of connection slots or descriptors? See
 * ESDM_EGD_IDLE_TIMEOUT_MS. A failed accept counts for as long as a connection
 * may idle - long enough for the reclaimed descriptors to be taken.
 */
static bool esdm_egd_scarce(uint64_t now)
{
	uint64_t starved_at = atomic_load(&esdm_egd_starved_at);

	if (atomic_load(&esdm_egd_connections) >= ESDM_EGD_IDLE_REAP_CONNECTIONS)
		return true;

	/* Another worker may have stored a time later than @now. */
	return starved_at &&
	       (now < starved_at ||
		now - starved_at <= ESDM_EGD_IDLE_TIMEOUT_MS);
}

/*
 * May the idle connection be closed? See ESDM_EGD_IDLE_TIMEOUT_MS.
 *
 * Only when nothing is owed to it, it was silent for the idle timeout - nothing
 * it sent waits to be read either, see esdm_egd_reclaim() - and its slot or
 * descriptor is wanted:
 *
 *   - the server is short of them (@scarce) and the connection's account is
 *     among those holding the most connections, @top as told by
 *     esdm_peer_limit_max_count(). Whoever fills the slots does so with many
 *     connections, so its idle ones go first, and the consumers of everybody
 *     else are left alone - a user keeping its own connections from ever
 *     being idle gains nothing but its own slots, and spreading them over the
 *     UIDs of its subordinate range does not hide them, see
 *     esdm_peer_account.h. Where no account stands out, all of them hold the
 *     most, and any idle connection may go - but none of root's, which is
 *     not accounted, as with esdm_egd_can_make_room().
 *   - the connection's own account is being refused further connections -
 *     which reclaims the slots of a client that abandons its connections
 *     without closing them for that client's own user, at no cost to anybody
 *     else's.
 */
static bool esdm_egd_idle_reapable(const struct esdm_egd_conn *conn,
				   uint64_t now, bool scarce, unsigned int top)
{
	if (!conn->peer_counted || conn->deferred || conn->yielded ||
	    esdm_egd_out_pending(conn) ||
	    now - conn->last_active <= ESDM_EGD_IDLE_TIMEOUT_MS)
		return false;

	if (!(scarce && esdm_peer_limit_count(&esdm_egd_peer_limit,
					      conn->peer_account) >= top) &&
	    !esdm_peer_limit_exhausted(&esdm_egd_peer_limit,
				       conn->peer_account))
		return false;

	/*
	 * Silent up to the events of this round - what came in after them is
	 * taken in the next one, and a connection just used again is not idle.
	 */
	return !esdm_egd_input_queued(conn);
}

/*
 * Thread main of one worker serving the EGD socket. The workers share the
 * listener, and each serves the clients it accepted.
 */
static int esdm_egd_handler(void *args)
{
	uint32_t id = (uint32_t)(uintptr_t)args;
	struct esdm_egd_conn_list conn_list;
	struct esdm_egd_conn *conn, *tmp, *rotate_at;
	struct esdm_egd_listener *listener;
	struct epoll_event events[ESDM_EGD_MAX_EVENTS];
	size_t deferred_requests = 0;
	/*
	 * Did a deferred request get any data in the last round, or does a
	 * command wait for the next round's budget? Then the next round follows
	 * immediately: the prediction resistance generator delivers a large
	 * request in chunks, and waiting the poll interval between them would
	 * multiply its latency. Other clients are still served in between.
	 */
	bool deferred_progress = false;
	/* Round of the event loop, see esdm_egd_conn_round() */
	uint64_t round = 0;
	/*
	 * The listening FD is level-triggered, so it has to be disarmed while
	 * no further client may be accepted - otherwise epoll_wait would
	 * report it readable over and over and spin the worker.
	 */
	bool listen_armed = true;
	/*
	 * accept() ran out of descriptors or memory. The client stays queued,
	 * so the level-triggered listener would wake us again at once: listen
	 * no more for a while, see below.
	 */
	bool accept_paused = false;
	size_t paused_connections = 0;
	uint64_t last_idle_scan = esdm_egd_now_ms();
	int epfd = -1;
	int ret = 0;

	thread_set_name(egd_server, id);
	TAILQ_INIT(&conn_list);

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "EGD server: cannot create epoll: %s\n",
			    strerror(errno));
		goto out;
	}

	/*
	 * The socket is served by every worker: a listener is identified
	 * by its own pointer in the epoll data, a connection by the pointer to
	 * its own structure, and the two can never collide.
	 */
	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd < 0)
			continue;

		if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener->listening_fd,
			      &(struct epoll_event){
				      .events = EPOLLIN,
				      .data.ptr = listener,
			      }) < 0) {
			ret = -errno;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"EGD server: cannot add listening FD to epoll: %s\n",
				strerror(errno));
			goto out;
		}

		/*
		 * The path is only known for a socket bound by us - a socket
		 * handed over by systemd carries its path in the .socket unit.
		 */
		esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
			    "EGD server: serving %s\n",
			    listener->systemd_socket ?
				    "the socket provided by systemd" :
				    listener->socket_path);
	}

	while (atomic_load(&esdm_egd_exit) == 0) {
		/*
		 * With all slots taken, a worker goes on accepting as long as
		 * it can make room by closing one of its connections, see
		 * esdm_egd_make_room(). One that cannot leaves the client to a
		 * worker that can, rather than taking it only to turn it away.
		 */
		bool want_armed = (atomic_load(&esdm_egd_connections) <
					   ESDM_EGD_MAX_CONNECTIONS ||
				   esdm_egd_can_make_room(&conn_list)) &&
				  !accept_paused;
		int nfds, i;

		round++;
		esdm_egd_round_start();

		if (want_armed != listen_armed) {
			bool armed_all = true;

			for_each_esdm_egd_listener (listener) {
				struct epoll_event lev = {
					.events = want_armed ? EPOLLIN : 0,
					.data.ptr = listener,
				};

				if (listener->listening_fd < 0)
					continue;
				if (epoll_ctl(epfd, EPOLL_CTL_MOD,
					      listener->listening_fd, &lev))
					armed_all = false;
			}

			if (armed_all)
				listen_armed = want_armed;
		}

		/*
		 * A deferred request is not tied to any descriptor event - it
		 * completes once entropy is available again. Poll more often
		 * while one is outstanding, and not at all while one is being
		 * filled round by round; the other clients' events are still
		 * collected in between, so the worker stays shared.
		 */
		nfds = epoll_wait(epfd, events, ESDM_EGD_MAX_EVENTS,
				  deferred_progress ?
					  0 :
					  (deferred_requests ?
						   ESDM_EGD_DEFERRED_POLL_MS :
						   ESDM_EGD_IDLE_POLL_MS));
		if (nfds < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "EGD server: epoll_wait failed: %s\n",
				    strerror(errno));
			goto out;
		}

		/*
		 * The pause ends with a quiet poll interval, a connection
		 * closed here, or a shortage older than the interval - the
		 * descriptors may have been freed elsewhere, and a client of
		 * this worker sending more often than the interval would
		 * otherwise keep it paused.
		 */
		if (accept_paused &&
		    (!nfds ||
		     atomic_load(&esdm_egd_connections) < paused_connections ||
		     !esdm_egd_starving(esdm_egd_now_ms())))
			accept_paused = false;

		for (i = 0; i < nfds; i++) {
			bool more_input;

			/* Closed to make room earlier in this round */
			if (!events[i].data.ptr)
				continue;

			/*
			 * Tell the two apart by the pointer itself: the
			 * listeners live in a static array of their own, so a
			 * connection can never be mistaken for one.
			 */
			if (events[i].data.ptr >= (void *)&esdm_egd_listeners[0] &&
			    events[i].data.ptr <
				    (void *)&esdm_egd_listeners[ARRAY_SIZE(
					    esdm_egd_listeners)]) {
				conn = esdm_egd_accept(epfd,
						       events[i].data.ptr,
						       &accept_paused,
						       &conn_list,
						       events + i + 1,
						       nfds - i - 1);
				if (!conn) {
					paused_connections = atomic_load(
						&esdm_egd_connections);
					continue;
				}

				TAILQ_INSERT_TAIL(&conn_list, conn, tailq);
				continue;
			}

			conn = events[i].data.ptr;
			esdm_egd_conn_round(conn, round);

			if (events[i].events & (EPOLLERR | EPOLLHUP)) {
				/*
				 * Gone for good - but on a stream socket what it
				 * sent before it closed is still readable, and a
				 * client writing and exiting right away raises
				 * the hangup together with EPOLLIN. EPOLLERR is
				 * no different: a Unix socket reports a client
				 * that closed with a response of ours unread as
				 * ECONNRESET, and still hands out the bytes it
				 * sent before that error. Take what is there,
				 * a read budget per round, and close once it
				 * ends at EOF or the error. Nothing is owed to
				 * the client any more, so the RDHUP rule below
				 * does not hold this up.
				 */
				esdm_egd_peer_gone(conn);
				ret = esdm_egd_read(conn);
				if (!ret)
					ret = -EPIPE;
			} else if (esdm_egd_out_pending(conn))
				/* Room was made - deliver the rest and go on. */
				ret = esdm_egd_process(conn);
			else
				ret = esdm_egd_read(conn);

			/*
			 * The read budget ran out with input left. Both the
			 * hangup and the input behind EPOLLRDHUP are reported
			 * again next round, so the rest is not lost by waiting.
			 */
			more_input = (ret > 0);
			if (more_input)
				ret = 0;

			/*
			 * EPOLLRDHUP only signals that the client will not send
			 * any more data - it may still be waiting for what it
			 * asked for before, be that a response on its way out or
			 * a request that has yet to find its entropy. Close only
			 * once nothing is owed to it any more.
			 */
			if (!ret && !more_input &&
			    (events[i].events & EPOLLRDHUP) && !conn->deferred &&
			    !conn->yielded && !esdm_egd_out_pending(conn))
				ret = -EPIPE;

			if (ret) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: closing connection on FD %d\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				continue;
			}

			/* The step above may have changed what to watch for. */
			esdm_egd_conn_arm(epfd, conn);
		}

		ret = 0;

		/*
		 * Whatever is not waiting for an event of its own: a deferred
		 * request, which completes when entropy arrives, a command
		 * waiting for its budget, and a response whose client has not
		 * made room, retried here so a missed EPOLLOUT cannot strand it.
		 * The deferred requests are recounted on the way, as the loop
		 * above may have changed their number.
		 */
		deferred_requests = 0;
		deferred_progress = false;
		rotate_at = NULL;
		/* The turn of what the events of this round were held from */
		esdm_egd_round.hold = false;
		TAILQ_FOREACH_SAFE (conn, &conn_list, tailq, tmp) {
			uint8_t collected, deferred;
			uint64_t out_since = conn->out_since;
			bool stuck, denied = esdm_egd_round.denied;

			if (atomic_load(&esdm_egd_exit))
				break;

			if (!conn->deferred && !conn->yielded &&
			    !esdm_egd_out_pending(conn))
				continue;

			esdm_egd_conn_round(conn, round);
			collected = conn->answer_len;
			deferred = conn->deferred;

			if (esdm_egd_process(conn)) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: closing connection on FD %d\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				continue;
			}

			/*
			 * A response the client never took. It holds up nobody
			 * else, but the connection is of no use to anyone until
			 * it is gone - reclaim it.
			 */
			stuck = (esdm_egd_out_pending(conn) &&
				 conn->out_since == out_since &&
				 esdm_egd_now_ms() - conn->out_since >
					 ESDM_EGD_WRITE_TIMEOUT_MS);
			if (stuck) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: client on FD %d is not reading its response\n",
					conn->fd);
				epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
				TAILQ_REMOVE(&conn_list, conn, tailq);
				esdm_egd_release_conn(conn);
				continue;
			}

			/*
			 * Only a request waiting for entropy sets the pace. A
			 * response waiting for its client is woken by EPOLLOUT,
			 * and hurrying for it would spin against a full socket.
			 * The answer is reset once sent, so a change of its
			 * length means this round produced something.
			 */
			if (deferred) {
				if (conn->answer_len != collected ||
				    conn->deferred != deferred)
					deferred_progress = true;

				if (conn->deferred)
					deferred_requests++;
			}

			if (conn->yielded)
				deferred_progress = true;

			/* The first one the worker's budget did not cover */
			if (!denied && esdm_egd_round.denied && !rotate_at)
				rotate_at = conn;

			esdm_egd_conn_arm(epfd, conn);
		}

		/*
		 * The budget of the round ran out: the next one starts with the
		 * connection it ran out at, see ESDM_EGD_ROUND_BUDGET_NS, and
		 * follows at once - a deferred request left without its turn
		 * made no progress, but has to have it.
		 */
		if (esdm_egd_round.denied)
			deferred_progress = true;
		while (rotate_at &&
		       (conn = TAILQ_FIRST(&conn_list)) != rotate_at) {
			TAILQ_REMOVE(&conn_list, conn, tailq);
			TAILQ_INSERT_TAIL(&conn_list, conn, tailq);
		}

		/*
		 * Close the connections that sat idle for too long while their
		 * slots are wanted: nothing owed to them, nothing heard from
		 * them. Without this, clients that went away without closing -
		 * or never meant to send anything - hold their slots and
		 * descriptors forever, and enough of them lock everybody else
		 * out.
		 */
		if (esdm_egd_now_ms() - last_idle_scan >= ESDM_EGD_IDLE_SCAN_MS) {
			uint64_t now = esdm_egd_now_ms();
			bool scarce = esdm_egd_scarce(now);
			unsigned int top =
				scarce ? esdm_peer_limit_max_count(
						 &esdm_egd_peer_limit) :
					 0;

			last_idle_scan = now;
			TAILQ_FOREACH_SAFE (conn, &conn_list, tailq, tmp) {
				if (!esdm_egd_idle_reapable(conn, now, scarce,
							    top))
					continue;

				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_SERVER,
					"EGD server: closing idle connection on FD %d of UID %u\n",
					conn->fd, (unsigned int)conn->peer_uid);
				esdm_egd_reclaim(epfd, &conn_list, conn);

				/*
				 * The slot may have been the one wanted, and
				 * the user has one connection less - it may no
				 * longer be alone at the top, or still be: the
				 * rest of its idle ones go in this same scan as
				 * long as it holds the most and slots are
				 * short. Neither is decided once for the whole
				 * scan, or the connections of the user next in
				 * line would follow as soon as it caught up.
				 */
				if (scarce) {
					scarce = esdm_egd_scarce(now);
					top = scarce ?
						      esdm_peer_limit_max_count(
							      &esdm_egd_peer_limit) :
						      0;
				}
			}
		}
	}

out:
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD server: exiting worker thread\n");

	TAILQ_FOREACH_SAFE (conn, &conn_list, tailq, tmp) {
		TAILQ_REMOVE(&conn_list, conn, tailq);
		if (epfd >= 0)
			epoll_ctl(epfd, EPOLL_CTL_DEL, conn->fd, NULL);
		esdm_egd_release_conn(conn);
	}

	if (epfd >= 0)
		close(epfd);

	atomic_fetch_sub(&esdm_egd_workers_running, 1);

	return ret;
}

int esdm_egd_server_start(void)
{
	uint32_t num_workers, t;
	int ret = 0;

	/*
	 * The interface is active exactly when esdm_egd_server_socket_init()
	 * obtained a listening socket - either from systemd or by binding the
	 * path requested on the command line. Every worker serves it.
	 */
	if (!esdm_egd_server_active())
		return 0;

	/*
	 * A worker serves its clients one request at a time, and a request may
	 * take as long as the DRNG it goes to needs for a reseed. More workers
	 * keep the other clients going meanwhile - up to one per CPU, within
	 * the thread slots reserved for them.
	 */
	num_workers = esdm_config_online_nodes();
	if (num_workers > ESDM_THREAD_EGD_SLOTS)
		num_workers = ESDM_THREAD_EGD_SLOTS;
	if (!num_workers)
		num_workers = 1;

	for (t = 0; t < num_workers; t++) {
		atomic_fetch_add(&esdm_egd_workers_running, 1);

		ret = thread_start(esdm_egd_handler, (void *)(uintptr_t)t,
				   ESDM_THREAD_EGD_GROUP, NULL);
		if (ret) {
			atomic_fetch_sub(&esdm_egd_workers_running, 1);
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SERVER,
				"EGD server: starting worker thread %u failed\n",
				t);

			/*
			 * The workers started so far serve the socket
			 * already - carry on with them, and fail only if there
			 * is none at all.
			 */
			if (t)
				ret = 0;
			break;
		}
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
		    "EGD server: %u worker thread(s)\n",
		    atomic_load(&esdm_egd_workers_running));

	return ret;
}

void esdm_egd_server_signal_exit_safe(void)
{
	atomic_store(&esdm_egd_exit, 1);
}

void esdm_egd_server_fini(void)
{
	struct esdm_egd_listener *listener;
	unsigned int i;

	if (!esdm_egd_server_active())
		return;

	esdm_egd_server_signal_exit_safe();

	/*
	 * Wait for the workers to leave their event loops before the ESDM is
	 * finalized - none may be inside esdm_get_random_bytes_full_noblock or
	 * esdm_pool_insert_aux by then. They are special threads and thus not
	 * covered by the RPC server's thread_wait_all(). The bound is generous
	 * against the poll interval and the one generation a worker may still
	 * be in - no further command is started once exit is requested - but
	 * shutdown must not hang either.
	 */
	for (i = 0; i < 100 && atomic_load(&esdm_egd_workers_running); i++) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };

		nanosleep(&ts, NULL);
	}

	for_each_esdm_egd_listener (listener) {
		if (listener->listening_fd < 0)
			continue;
		close(listener->listening_fd);
		listener->listening_fd = -1;
	}
}

void esdm_egd_server_cleanup(void)
{
	struct esdm_egd_listener *listener;

	for_each_esdm_egd_listener (listener) {
		if (!esdm_egd_listener_enabled(listener))
			continue;

		/*
		 * A systemd socket is created and removed by systemd -
		 * unlinking one it still listens on leaves its .socket unit
		 * bound to an unlinked inode. listener->systemd_socket alone
		 * does not answer this: the privileged PID namespace supervisor
		 * also runs here and forked before the sockets were set up, so
		 * fall back to the activation state latched before that fork.
		 * Conservative on purpose - at worst a self-bound socket is left
		 * behind, and the stale socket check removes it at the next
		 * start.
		 */
		if (listener->systemd_socket || systemd_listen_fds() > 0)
			continue;

		if (unlink(listener->socket_path) < 0) {
			if (errno != ENOENT) {
				esdm_logger(
					LOGGER_VERBOSE, LOGGER_C_SERVER,
					"EGD socket %s cannot be deleted: %s\n",
					listener->socket_path,
					strerror(errno));
			}
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
				    "EGD socket %s deleted\n",
				    listener->socket_path);
		}
	}
}
