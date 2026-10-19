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
 * esdm-es-ext-relay: a provider on another host, read by the ESDM of this one
 * - see esdm-es-ext-relay(8) and "Network" in esdm_es_ext.h.
 *
 * The esdm-server leaves the network namespace of its host as it starts: it
 * reaches no network, and parses no certificate. The relay serves it a local
 * provider socket instead, which the ESDM reads as any ExternalSocket source -
 * checking the uid of the relay as it checks that of any provider -, and
 * forwards each request to a provider served on SCTP with DTLS and
 * certificates, see esdm_es_ext_server_alloc_net().
 *
 * The messages are forwarded as they are, one to one - rather than served by
 * the provider server of libesdm_es_ext with a plugin forwarding them: what
 * the remote provider declares in its answer to INFO is to reach the ESDM as
 * declared, and declared anew on every connection, which a plugin declares
 * once as it is set up; its answer to STATUS is to reach the ESDM as it is,
 * up to the size of a status of a provider, which the status of a plugin is
 * no match for, and not wrapped into the status of a server of its own; and
 * the status and the entropy claimed of every answer are the remote
 * provider's. What the relay forwards back is checked as the ESDM checks it,
 * so that the remote side can do nothing a local provider could not.
 *
 * Every local connection has an upstream connection of its own, made when the
 * ESDM asks the first request beyond STARTDTLS, which has to be INFO: the
 * name and the rate the ESDM credits a connection with are the ones the
 * provider declared on it. The upstream connection lives as long as the local
 * one: an upstream connection lost while idle closes the local one - the ESDM
 * connects again at once on its next request, and asks INFO again -, and one
 * lost while a request is forwarded has the request answered with an errno,
 * and the local connection closed after it. Nothing waits for long: every step
 * upstream is bounded by --timeout_ms, which is shorter than the time the ESDM
 * gives a request.
 *
 * A local connection is served by a thread of its own. The main thread
 * accepts, and keeps house: it takes up renewed TLS files on SIGHUP and when
 * they change, closes the upstream connections of servers whose certificate
 * got revoked or expired, and reports CRLs about to expire.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_dtls.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "esdm_net.h"
#include "esdm_server_socket.h"
#include "esdm_tls.h"
#include "memset_secure.h"
#include "privileges.h"
#include "systemd_support.h"

/* Set by the build, see es-ext/meson.build */
#ifndef ESDM_ES_EXT_RELAY_VERSION
#define ESDM_ES_EXT_RELAY_VERSION "unknown"
#endif

#define RELAY_NAME "esdm-es-ext-relay"

/* Where the relay serves unless told otherwise - see its systemd unit */
#define RELAY_SOCKET "/run/esdm-es-ext-relay/esdm-es-ext-relay.socket"

#define RELAY_BACKLOG 8
#define RELAY_HOUSEKEEPING_SEC 30
#define RELAY_STOP_WAIT_MS 5000

/* Clients to be served next to root */
#define RELAY_MAX_CLIENT_UIDS 8

/* The largest answer of a provider, and what the ESDM sends */
#define RELAY_RSP_MAX (ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA)

struct relay_conn {
	int fd;
	pthread_t thread;
	bool root;
	/* Gone for another client, see relay_accept() */
	bool evicted;
	/* When it sent something last, monotonic milliseconds */
	_Atomic uint64_t active;
	char peer[64];

	/* The DTLS on the local socket, opportunistic - NULL while in the clear */
	struct esdm_dtls *dtls;
	bool info_done;

	/* The provider, while connected - see relay_upstream() */
	int up_fd;
	struct esdm_dtls *up;
	char up_fingerprint[ESDM_TLS_FINGERPRINT_HEX_LEN];

	TAILQ_ENTRY(relay_conn) tailq;
};
TAILQ_HEAD(relay_conn_list, relay_conn);

static struct {
	const char *socket_path;
	mode_t mode;
	uid_t client_uids[RELAY_MAX_CLIENT_UIDS];
	unsigned int client_uids_num;
	bool dtls;

	const char *connect;
	char *host;
	char *port;
	const char *server_name;
	struct esdm_net_tls_files files;
	unsigned int reload_interval;
	unsigned int timeout_ms;
	unsigned int max_connections;
} relay_cfg = {
	.socket_path = RELAY_SOCKET,
	.mode = 0666,
	.dtls = true,
	.reload_interval = 60,
	/* Shorter than the 2 seconds the ESDM gives a request */
	.timeout_ms = 1500,
	/*
	 * As many as a provider serves of one certificate by default - see
	 * max_per_client of esdm_es_ext_server_net_config. The ESDM holds one.
	 */
	.max_connections = 4,
};

/* The context new upstream connections are made with */
static pthread_mutex_t relay_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static struct esdm_tls_ctx *relay_ctx = NULL;
static uint8_t relay_stamp[ESDM_TLS_STAMP_LEN];

/* The DTLS context of the local socket, NULL without DTLS */
static struct esdm_dtls_ctx *relay_dtls_ctx = NULL;

/* The connections */
static pthread_mutex_t relay_conns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct relay_conn_list relay_conns = TAILQ_HEAD_INITIALIZER(relay_conns);
static unsigned int relay_conn_num = 0;

/* The threads, and the end of them */
static pthread_mutex_t relay_pool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t relay_pool_cond = PTHREAD_COND_INITIALIZER;
static unsigned int relay_threads = 0;
static atomic_bool relay_stop = false;

/*
 * The provider was not reachable: told once at a warning, until it is
 * reachable again - the ESDM tries every few seconds
 */
static atomic_bool relay_unreachable_told = false;

static uint64_t relay_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* What is left until @deadline, for a wait */
static int relay_left_ms(uint64_t deadline)
{
	uint64_t now = relay_now_ms();

	return now >= deadline ? 0 : (int)(deadline - now);
}

/******************************************************************************
 * Upstream: the provider on the network
 ******************************************************************************/

static void relay_upstream_close(struct relay_conn *conn)
{
	pthread_mutex_lock(&relay_conns_lock);
	esdm_dtls_free(conn->up);
	conn->up = NULL;
	if (conn->up_fd >= 0)
		close(conn->up_fd);
	conn->up_fd = -1;
	conn->up_fingerprint[0] = '\0';
	pthread_mutex_unlock(&relay_conns_lock);
}

/*
 * An SCTP association with SCTP-AUTH to one address of the provider, within
 * @deadline.
 *
 * @return the socket, non-blocking, or a negative errno
 */
static int relay_connect_addr(const struct addrinfo *ai, uint64_t deadline)
{
	struct pollfd pfd;
	socklen_t len = sizeof(int);
	int fd, err = 0, ret;

	fd = socket(ai->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
		    IPPROTO_SCTP);
	if (fd < 0)
		return -errno;

	ret = esdm_tls_sctp_prepare(fd);
	if (ret) {
		close(fd);
		return ret;
	}

	if (connect(fd, ai->ai_addr, ai->ai_addrlen) < 0 &&
	    errno != EINPROGRESS) {
		ret = -errno;
		close(fd);
		return ret;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;
	ret = poll(&pfd, 1, relay_left_ms(deadline));
	if (ret <= 0) {
		close(fd);
		return ret ? -errno : -ETIMEDOUT;
	}
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err) {
		close(fd);
		return -err;
	}

	return fd;
}

/*
 * Connect @conn to the provider and do the handshake, within @deadline.
 *
 * @return 0, or a negative errno
 */
static int relay_upstream(struct relay_conn *conn, uint64_t deadline)
{
	struct addrinfo hints, *res = NULL, *ai;
	struct esdm_tls_ctx *ctx, *cur;
	struct esdm_dtls *up = NULL;
	uint8_t fp[ESDM_TLS_FINGERPRINT_LEN];
	char why[256];
	bool revoked;
	int fd = -1, ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_SCTP;
	ret = getaddrinfo(relay_cfg.host, relay_cfg.port, &hints, &res);
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: cannot resolve %s: %s\n", RELAY_NAME,
			    relay_cfg.host, gai_strerror(ret));
		return -EHOSTUNREACH;
	}

	ret = -EHOSTUNREACH;
	for (ai = res; ai; ai = ai->ai_next) {
		fd = relay_connect_addr(ai, deadline);
		if (fd >= 0)
			break;
		ret = fd;
		if (!relay_left_ms(deadline))
			break;
	}
	freeaddrinfo(res);
	if (fd < 0)
		return ret;

	pthread_mutex_lock(&relay_ctx_lock);
	ctx = relay_ctx;
	esdm_tls_ctx_get(ctx);
	pthread_mutex_unlock(&relay_ctx_lock);

	/* Answers of the provider, nothing larger */
	ret = esdm_dtls_alloc_tls(ctx, fd, RELAY_RSP_MAX,
				  relay_cfg.server_name, &up);
	esdm_tls_ctx_put(ctx);
	if (ret) {
		close(fd);
		return ret;
	}

	while ((ret = esdm_dtls_handshake(up)) == -EAGAIN) {
		struct pollfd pfd = { .fd = fd, .events = esdm_dtls_want(up) };
		int left = relay_left_ms(deadline);

		if (!left || atomic_load(&relay_stop)) {
			ret = -ETIMEDOUT;
			break;
		}
		if (poll(&pfd, 1, left) < 0 && errno != EINTR) {
			ret = -errno;
			break;
		}
	}
	if (ret) {
		esdm_logger(ret == -EACCES ? LOGGER_ERR : LOGGER_DEBUG,
			    LOGGER_C_ANY, "%s: handshake with %s failed: %s\n",
			    RELAY_NAME, relay_cfg.connect,
			    esdm_tls_error(esdm_dtls_tls(up)));
		esdm_dtls_free(up);
		close(fd);
		return ret;
	}

	/*
	 * From here on the housekeeping looks at it, see relay_check_conns().
	 *
	 * A reload while the handshake ran put a context in place whose CRLs
	 * the handshake did not see, and checked the upstream connections
	 * against them - which this one was not yet. So it is checked here,
	 * under the lock that check takes: either the reload replaced the
	 * context before, which is seen here, or it checks this connection
	 * after. The context of the handshake is held by the connection, so
	 * the comparison is with one that is still there.
	 */
	pthread_mutex_lock(&relay_conns_lock);
	pthread_mutex_lock(&relay_ctx_lock);
	cur = relay_ctx;
	esdm_tls_ctx_get(cur);
	pthread_mutex_unlock(&relay_ctx_lock);
	revoked = cur != ctx && esdm_tls_peer_revoked(esdm_dtls_tls(up), cur,
						      why, sizeof(why)) == 1;
	if (!revoked) {
		conn->up_fd = fd;
		conn->up = up;
		esdm_tls_peer_fingerprint(esdm_dtls_tls(up), fp);
		esdm_tls_fingerprint_hex(fp, conn->up_fingerprint);
	}
	pthread_mutex_unlock(&relay_conns_lock);
	esdm_tls_ctx_put(cur);

	if (revoked) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
			    "%s: closing the connection to %s, revoked: %s\n",
			    RELAY_NAME,
			    esdm_tls_peer_subject(esdm_dtls_tls(up)), why);
		esdm_tls_close_notify(esdm_dtls_tls(up));
		esdm_dtls_free(up);
		close(fd);
		return -EKEYREVOKED;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "%s: connected to %s (SHA-256 %s) for %s, %s\n", RELAY_NAME,
		    esdm_tls_peer_subject(esdm_dtls_tls(up)),
		    conn->up_fingerprint, conn->peer, esdm_dtls_cipher(up));
	return 0;
}

/*
 * Forward the request @req to the provider and take its answer into @rsp,
 * checked as the ESDM checks it - within @deadline.
 *
 * @return the size of the answer, or a negative errno - the upstream
 *	   connection is gone then
 */
static ssize_t relay_forward(struct relay_conn *conn, const uint8_t *req,
			     uint16_t type, uint32_t length, uint8_t *rsp,
			     uint64_t deadline)
{
	const uint8_t *data;
	const char *text;
	size_t textlen;
	uint32_t bits, rate;
	int32_t status;
	ssize_t n;
	int ret;

	ret = esdm_dtls_send(conn->up, req, ESDM_ES_EXT_PROTO_REQ_LEN);
	if (ret)
		return ret == -EAGAIN ? -ETIMEDOUT : ret;

	for (;;) {
		struct pollfd pfd = { .fd = conn->up_fd, .events = POLLIN };
		int left;

		n = esdm_dtls_recv(conn->up, rsp, RELAY_RSP_MAX);
		if (n != -EAGAIN)
			break;
		left = relay_left_ms(deadline);
		if (!left || atomic_load(&relay_stop))
			return -ETIMEDOUT;
		if (poll(&pfd, 1, left) < 0 && errno != EINTR)
			return -errno;
	}
	if (n < 0)
		return n == -EMSGSIZE ? -EPROTO : n;

	/* Nothing the ESDM would not take from a local provider */
	switch (type) {
	case ESDM_ES_EXT_PROTO_STATUS:
		ret = esdm_es_ext_proto_status_unpack(rsp, (size_t)n, length,
						      &status, &text, &textlen);
		break;
	case ESDM_ES_EXT_PROTO_INFO:
		ret = esdm_es_ext_proto_info_unpack(rsp, (size_t)n, &status,
						    &rate, &text, &textlen);
		break;
	default:
		ret = esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n, type, length,
						   &status, &bits, &data);
		break;
	}
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: the provider answered what the protocol does not allow\n",
			    RELAY_NAME);
		return -EPROTO;
	}

	return n;
}

/******************************************************************************
 * The local connection
 ******************************************************************************/

/*
 * The next request of the local client into @req: in the clear, or as DTLS
 * application data.
 *
 * @return its size - larger than a request for one that is not -, -EAGAIN if
 *	   none is there yet, 0 if the client is gone
 */
static ssize_t relay_local_recv(struct relay_conn *conn, uint8_t *req,
				size_t len)
{
	ssize_t n;

	if (conn->dtls) {
		n = esdm_dtls_recv(conn->dtls, req, len);
		if (n == -EAGAIN)
			return -EAGAIN;
		return n < 0 ? 0 : n;
	}

	n = recv(conn->fd, req, len, MSG_DONTWAIT | MSG_TRUNC);
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return -EAGAIN;
	return n < 0 ? 0 : n;
}

/* An answer to the local client - which reads it, being the ESDM */
static bool relay_local_send(struct relay_conn *conn, const uint8_t *rsp,
			     size_t len)
{
	if (conn->dtls)
		return !esdm_dtls_send(conn->dtls, rsp, len);

	return send(conn->fd, rsp, len, MSG_DONTWAIT | MSG_NOSIGNAL) ==
	       (ssize_t)len;
}

/* Answer the request of @type with the status @status, and nothing else */
static bool relay_local_status(struct relay_conn *conn, uint16_t type,
			       int status)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN];
	size_t len;

	/* An errno, as the protocol has it */
	if (status < -ESDM_ES_EXT_PROTO_MAX_ERRNO || status > 0)
		status = -EIO;
	len = esdm_es_ext_proto_rsp_pack(rsp, type, status, 0, NULL, 0);
	return relay_local_send(conn, rsp, len);
}

/*
 * STARTDTLS of the local client, still in the clear: the DTLS of the local
 * socket, as the provider server has it, if the relay offers it.
 *
 * @return true if the client is still connected afterwards
 */
static bool relay_local_startdtls(struct relay_conn *conn)
{
	uint64_t deadline = relay_now_ms() + relay_cfg.timeout_ms;
	struct esdm_dtls *dtls = NULL;
	int ret;

	if (!relay_dtls_ctx ||
	    esdm_dtls_alloc(relay_dtls_ctx, conn->fd,
			    ESDM_ES_EXT_PROTO_REQ_LEN, &dtls))
		return relay_local_status(conn, ESDM_ES_EXT_PROTO_STARTDTLS,
					  -EOPNOTSUPP);

	/* The answer goes out in the clear, the handshake follows */
	if (!relay_local_status(conn, ESDM_ES_EXT_PROTO_STARTDTLS, 0)) {
		esdm_dtls_free(dtls);
		return false;
	}

	while ((ret = esdm_dtls_handshake(dtls)) == -EAGAIN) {
		struct pollfd pfd = { .fd = conn->fd, .events = POLLIN };
		int left = relay_left_ms(deadline);

		if (!left) {
			ret = -ETIMEDOUT;
			break;
		}
		if (poll(&pfd, 1, left) < 0 && errno != EINTR) {
			ret = -errno;
			break;
		}
	}
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: DTLS handshake with %s failed\n", RELAY_NAME,
			    conn->peer);
		esdm_dtls_free(dtls);
		return false;
	}

	conn->dtls = dtls;
	return true;
}

/*
 * Serve one request of the local client.
 *
 * @return true if the local connection goes on
 */
static bool relay_local_request(struct relay_conn *conn)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN + 1];
	uint8_t rsp[RELAY_RSP_MAX];
	uint64_t deadline = relay_now_ms() + relay_cfg.timeout_ms;
	uint32_t length;
	uint16_t type;
	ssize_t n;
	bool ret;
	int err;

	n = relay_local_recv(conn, req, sizeof(req));
	if (n == -EAGAIN)
		return true;
	if (n <= 0)
		return false;
	atomic_store(&conn->active, relay_now_ms());

	if ((size_t)n > ESDM_ES_EXT_PROTO_REQ_LEN ||
	    esdm_es_ext_proto_req_unpack(req, (size_t)n, &type, &length)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: invalid request of %s, disconnected\n",
			    RELAY_NAME, conn->peer);
		return false;
	}

	/* Each hop has its STARTDTLS: this one the local DTLS */
	if (type == ESDM_ES_EXT_PROTO_STARTDTLS) {
		if (conn->dtls || conn->info_done)
			return false;
		return relay_local_startdtls(conn);
	}

	/*
	 * INFO first, so that what the ESDM credits the connection with is
	 * what the provider declared on it - a client not asking is closed,
	 * and asks when it connects again
	 */
	if (!conn->info_done) {
		if (type != ESDM_ES_EXT_PROTO_INFO) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_ANY,
				"%s: %s did not ask INFO first, disconnected\n",
				RELAY_NAME, conn->peer);
			return false;
		}
		conn->info_done = true;

		err = relay_upstream(conn, deadline);
		if (err) {
			if (!atomic_exchange(&relay_unreachable_told, true))
				esdm_logger(
					LOGGER_WARN, LOGGER_C_ANY,
					"%s: the provider %s is not reachable (%s), no entropy until it is\n",
					RELAY_NAME, relay_cfg.connect,
					strerror(-err));
			/*
			 * The ESDM learns it declares nothing, and connects
			 * again for the next request
			 */
			relay_local_status(conn, type, err);
			return false;
		}
		if (atomic_exchange(&relay_unreachable_told, false))
			esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
				    "%s: the provider %s is reachable again\n",
				    RELAY_NAME, relay_cfg.connect);
	}

	if (!conn->up)
		return false;

	n = relay_forward(conn, req, type, length, rsp, deadline);
	if (n < 0) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			    "%s: the request of %s failed upstream: %s\n",
			    RELAY_NAME, conn->peer, strerror((int)-n));
		/* Not left waiting: an errno, and a connection anew */
		relay_local_status(conn, type, (int)n);
		return false;
	}

	ret = relay_local_send(conn, rsp, (size_t)n);
	memset_secure(rsp, 0, sizeof(rsp));
	return ret;
}

/*
 * Did the provider end the upstream connection while it was idle - it was
 * restarted, closed it as idle, or the relay closed it for a revoked
 * certificate? Nothing is to come from it between two requests.
 */
static bool relay_upstream_gone(struct relay_conn *conn)
{
	uint8_t rsp[RELAY_RSP_MAX];
	ssize_t n;

	if (!conn->up)
		return false;

	n = esdm_dtls_recv(conn->up, rsp, sizeof(rsp));
	memset_secure(rsp, 0, sizeof(rsp));
	return n != -EAGAIN;
}

static void relay_conn_release(struct relay_conn *conn)
{
	pthread_mutex_lock(&relay_conns_lock);
	TAILQ_REMOVE(&relay_conns, conn, tailq);
	relay_conn_num--;
	pthread_mutex_unlock(&relay_conns_lock);

	relay_upstream_close(conn);
	esdm_dtls_free(conn->dtls);
	close(conn->fd);
	free(conn);
}

static void *relay_conn_thread(void *arg)
{
	struct relay_conn *conn = arg;

	while (!atomic_load(&relay_stop)) {
		struct pollfd pfd[2] = {
			{ .fd = conn->fd, .events = POLLIN },
			{ .fd = conn->up ? conn->up_fd : -1, .events = POLLIN },
		};
		int timeout = -1;

		/* What the DTLS layers hold already is received as well */
		if (esdm_dtls_pending(conn->dtls) || esdm_dtls_pending(conn->up))
			timeout = 0;

		if (poll(pfd, 2, timeout) < 0 && errno != EINTR)
			break;

		if ((pfd[1].revents || esdm_dtls_pending(conn->up)) &&
		    relay_upstream_gone(conn)) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_ANY,
				"%s: the provider ended the connection of %s, closing it\n",
				RELAY_NAME, conn->peer);
			break;
		}

		if ((pfd[0].revents & POLLIN) || esdm_dtls_pending(conn->dtls)) {
			if (!relay_local_request(conn))
				break;
		} else if (pfd[0].revents) {
			break;
		}
	}

	relay_conn_release(conn);

	pthread_mutex_lock(&relay_pool_lock);
	relay_threads--;
	pthread_cond_broadcast(&relay_pool_cond);
	pthread_mutex_unlock(&relay_pool_lock);
	return NULL;
}

/* May the client on @fd be served? Root, and the users allowed */
static bool relay_client_allowed(int fd, bool *root, char *peer, size_t len)
{
	struct ucred cred;
	socklen_t clen = sizeof(cred);
	unsigned int i;

	*root = false;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) < 0)
		return false;

	snprintf(peer, len, "UID %u PID %d", (unsigned int)cred.uid,
		 (int)cred.pid);
	*root = cred.uid == 0;
	if (*root)
		return true;
	for (i = 0; i < relay_cfg.client_uids_num; i++) {
		if (cred.uid == relay_cfg.client_uids[i])
			return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY, "%s: %s refused\n", RELAY_NAME,
		    peer);
	return false;
}

/*
 * Accept a local client. With all slots taken, the client idle the longest
 * gives way - one running as root only for one running as root, as the ESDM
 * connects as root at start up: clients holding their slots without using
 * them must not lock the ESDM out, see the provider server of libesdm_es_ext.
 */
static void relay_accept(int lfd)
{
	struct relay_conn *conn, *c, *victim = NULL;
	char peer[64];
	bool root;
	int fd, ret;

	fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0)
		return;

	if (!relay_client_allowed(fd, &root, peer, sizeof(peer))) {
		close(fd);
		return;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		close(fd);
		return;
	}
	conn->fd = fd;
	conn->up_fd = -1;
	conn->root = root;
	atomic_init(&conn->active, relay_now_ms());
	snprintf(conn->peer, sizeof(conn->peer), "%s", peer);

	pthread_mutex_lock(&relay_conns_lock);
	if (relay_conn_num >= relay_cfg.max_connections) {
		TAILQ_FOREACH (c, &relay_conns, tailq) {
			if (c->evicted || (c->root && !root))
				continue;
			if (!victim || (victim->root && !c->root) ||
			    (victim->root == c->root &&
			     atomic_load(&c->active) <
				     atomic_load(&victim->active)))
				victim = c;
		}
		if (!victim) {
			pthread_mutex_unlock(&relay_conns_lock);
			esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
				    "%s: too many clients, %s refused\n",
				    RELAY_NAME, peer);
			free(conn);
			close(fd);
			return;
		}
		/* Its thread ends with the end of its socket */
		victim->evicted = true;
		shutdown(victim->fd, SHUT_RDWR);
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: too many clients, %s idle the longest disconnected\n",
			    RELAY_NAME, victim->peer);
	}
	TAILQ_INSERT_TAIL(&relay_conns, conn, tailq);
	relay_conn_num++;
	pthread_mutex_unlock(&relay_conns_lock);

	pthread_mutex_lock(&relay_pool_lock);
	relay_threads++;
	pthread_mutex_unlock(&relay_pool_lock);

	{
		pthread_attr_t attr;

		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		ret = -pthread_create(&conn->thread, &attr, relay_conn_thread,
				      conn);
		pthread_attr_destroy(&attr);
	}
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: cannot start a thread for %s: %s\n",
			    RELAY_NAME, peer, strerror(-ret));
		relay_conn_release(conn);
		pthread_mutex_lock(&relay_pool_lock);
		relay_threads--;
		pthread_mutex_unlock(&relay_pool_lock);
	}
}

/******************************************************************************
 * The TLS files
 ******************************************************************************/

/*
 * Close the upstream connections to a server revoked by the CRLs of @ctx -
 * NULL for none - or whose certificate expired: the thread of the connection
 * sees the end of its upstream socket, and closes the local one.
 */
static void relay_check_conns(struct esdm_tls_ctx *ctx)
{
	int64_t now = (int64_t)time(NULL);
	struct relay_conn *conn;
	char why[256];

	pthread_mutex_lock(&relay_conns_lock);
	TAILQ_FOREACH (conn, &relay_conns, tailq) {
		struct esdm_tls *tls = esdm_dtls_tls(conn->up);
		int64_t not_after;

		if (!tls)
			continue;

		if (ctx && esdm_tls_peer_revoked(tls, ctx, why, sizeof(why)) ==
				   1) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"%s: closing the connection to %s (SHA-256 %s), revoked: %s\n",
				RELAY_NAME, esdm_tls_peer_subject(tls),
				conn->up_fingerprint, why);
			shutdown(conn->up_fd, SHUT_RDWR);
			continue;
		}

		not_after = esdm_tls_peer_not_after(tls);
		if (not_after && now > not_after) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"%s: closing the connection to %s (SHA-256 %s), its certificate expired\n",
				RELAY_NAME, esdm_tls_peer_subject(tls),
				conn->up_fingerprint);
			shutdown(conn->up_fd, SHUT_RDWR);
		}
	}
	pthread_mutex_unlock(&relay_conns_lock);
}

/*
 * Take up the TLS files: a complete new context, or the old one stays. @force
 * builds even if they did not change - SIGHUP.
 *
 * @return 0, or the negative errno of files that do not load
 */
static int relay_reload(bool force)
{
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL, *old;
	int ret;

	esdm_net_tls_config(&relay_cfg.files, &cfg);
	cfg.transport = ESDM_TLS_TRANSPORT_SCTP;
	ret = esdm_net_tls_reload(RELAY_NAME, false, &cfg, force, relay_stamp,
				  &ctx);
	if (ret <= 0)
		return ret;

	pthread_mutex_lock(&relay_ctx_lock);
	old = relay_ctx;
	relay_ctx = ctx;
	pthread_mutex_unlock(&relay_ctx_lock);
	esdm_tls_ctx_put(old);

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "%s: loaded the TLS files of %s\n", RELAY_NAME,
		    relay_cfg.files.cert);
	esdm_tls_ctx_crl_report(ctx, true);

	/* A server revoked is no provider any more */
	relay_check_conns(ctx);
	return 0;
}

/******************************************************************************
 * The local socket
 ******************************************************************************/

/* A socket of an earlier relay that nobody serves any more is removed */
static int relay_stale_socket(const struct sockaddr_un *addr)
{
	struct stat sb;
	int fd, ret;

	if (lstat(addr->sun_path, &sb) < 0)
		return errno == ENOENT ? 0 : -errno;
	if (!S_ISSOCK(sb.st_mode)) {
		fprintf(stderr, "%s exists and is no socket\n", addr->sun_path);
		return -EEXIST;
	}

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	ret = connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
	close(fd);
	if (!ret) {
		fprintf(stderr, "%s is served by somebody else\n",
			addr->sun_path);
		return -EADDRINUSE;
	}

	if (unlink(addr->sun_path) < 0 && errno != ENOENT)
		return -errno;
	return 0;
}

static int relay_bind(int *lfd)
{
	struct sockaddr_un addr;
	int fd, ret;

	if (strlen(relay_cfg.socket_path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "The socket path is too long\n");
		return -ENAMETOOLONG;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, relay_cfg.socket_path,
	       strlen(relay_cfg.socket_path));

	ret = relay_stale_socket(&addr);
	if (ret)
		return ret;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	ret = esdm_server_bind_unix(fd, &addr, relay_cfg.mode);
	if (ret) {
		fprintf(stderr, "Cannot bind %s: %s\n", relay_cfg.socket_path,
			strerror(-ret));
		close(fd);
		return ret;
	}
	if (listen(fd, RELAY_BACKLOG) < 0) {
		ret = -errno;
		close(fd);
		unlink(relay_cfg.socket_path);
		return ret;
	}

	*lfd = fd;
	return 0;
}

/******************************************************************************
 * Main
 ******************************************************************************/

/* A uid, or the uid of a user name; (uid_t)-1 if it is neither */
static uid_t relay_parse_uid(const char *arg)
{
	struct passwd *pw;
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (arg[0] != '\0' && arg[0] != '-' && *end == '\0' && !errno &&
	    val < (unsigned long)(uid_t)-1)
		return (uid_t)val;

	pw = getpwnam(arg);
	return pw ? pw->pw_uid : (uid_t)-1;
}

static void usage(void)
{
	fprintf(stderr, "\nESDM external entropy source relay\n\n");
	fprintf(stderr, "%s %s, DTLS by %s\n\n", RELAY_NAME,
		ESDM_ES_EXT_RELAY_VERSION, esdm_tls_stack());
	fprintf(stderr, "Usage: %s --connect <HOST[:PORT]> [OPTIONS]\n\n",
		RELAY_NAME);
	fprintf(stderr,
		"\t-C --connect <HOST[:PORT]>\tThe provider on the network, SCTP;\n"
		"\t\t\t\t[IPv6]:PORT (default port %u)\n"
		"\t-s --socket <PATH>\tLocal provider socket for the ESDM\n"
		"\t\t\t\t(default: %s)\n"
		"\t-m --mode <MODE>\tAccess mode of the socket, octal (default 0666)\n"
		"\t-u --client_uid <USER>\tServe clients running as USER (uid or name)\n"
		"\t\t\t\tnext to root; may be repeated (default: nobody)\n"
		"\t   --no_dtls\t\tDo not offer DTLS on the local socket\n"
		"\t   --cert <FILE>\tCertificate of the relay, PEM\n"
		"\t   --key <FILE>\t\tIts private key, PEM, PKCS#8\n"
		"\t   --ca <FILE>\t\tTrust anchors the provider must chain to, PEM\n"
		"\t   --server_name <NAME>\tName the provider's certificate is issued\n"
		"\t\t\t\tfor (default: the host of --connect)\n"
		"\t   --crl <FILE>\t\tCRLs, PEM; may be repeated\n"
		"\t   --crl_check_all\tRequire CRLs of the CA certificates as well\n"
		"\t   --crl_allow_expired\tOnly warn of a CRL past its nextUpdate\n"
		"\t   --reload_interval <SEC>\tCheck the TLS files for a change\n"
		"\t\t\t\tthis often, 0 for never (default 60); SIGHUP\n"
		"\t\t\t\treloads them at once\n"
		"\t   --timeout_ms <MS>\tBound of a step upstream - the connection\n"
		"\t\t\t\twith its handshake, or one request (default 1500,\n"
		"\t\t\t\tless than the 2000 the ESDM gives a request)\n"
		"\t   --max_connections <N>\tLocal connections, each with one to\n"
		"\t\t\t\tthe provider (default 4)\n"
		"\t   --username <USER>\tUser to switch to when started as root\n"
		"\t\t\t\t(default: nobody)\n"
		"\t   --groupname <GROUP>\tGroup to switch to (default: none)\n"
		"\t-v --verbose\t\tMore verbose logging, may be repeated\n"
		"\t-h --help\t\tThis help information\n"
		"\t   --version\t\tPrint the version\n\n"
		"A file without a slash in its name is a credential of the service,\n"
		"taken from $CREDENTIALS_DIRECTORY (systemd LoadCredential=); without\n"
		"--cert, --key and --ca, the credentials cert, key and ca are used.\n",
		ESDM_ES_EXT_NET_PORT, RELAY_SOCKET);
}

enum {
	OPT_NO_DTLS = 256,
	OPT_CERT,
	OPT_KEY,
	OPT_CA,
	OPT_SERVER_NAME,
	OPT_CRL,
	OPT_CRL_CHECK_ALL,
	OPT_CRL_ALLOW_EXPIRED,
	OPT_RELOAD_INTERVAL,
	OPT_TIMEOUT_MS,
	OPT_MAX_CONNECTIONS,
	OPT_USERNAME,
	OPT_GROUPNAME,
	OPT_VERSION,
};

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "connect", required_argument, NULL, 'C' },
		{ "socket", required_argument, NULL, 's' },
		{ "mode", required_argument, NULL, 'm' },
		{ "client_uid", required_argument, NULL, 'u' },
		{ "no_dtls", no_argument, NULL, OPT_NO_DTLS },
		{ "cert", required_argument, NULL, OPT_CERT },
		{ "key", required_argument, NULL, OPT_KEY },
		{ "ca", required_argument, NULL, OPT_CA },
		{ "server_name", required_argument, NULL, OPT_SERVER_NAME },
		{ "crl", required_argument, NULL, OPT_CRL },
		{ "crl_check_all", no_argument, NULL, OPT_CRL_CHECK_ALL },
		{ "crl_allow_expired", no_argument, NULL,
		  OPT_CRL_ALLOW_EXPIRED },
		{ "reload_interval", required_argument, NULL,
		  OPT_RELOAD_INTERVAL },
		{ "timeout_ms", required_argument, NULL, OPT_TIMEOUT_MS },
		{ "max_connections", required_argument, NULL,
		  OPT_MAX_CONNECTIONS },
		{ "username", required_argument, NULL, OPT_USERNAME },
		{ "groupname", required_argument, NULL, OPT_GROUPNAME },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ NULL, 0, NULL, 0 }
	};
	static const char *const tls_opts[] = { "cert", "key", "ca", NULL,
						"crl", "crl_check_all",
						"crl_allow_expired" };
	const char *username = "nobody", *groupname = NULL;
	struct pollfd pfds[2];
	int lfd = -1, sfd = -1, c, ret = 1;
	uint64_t last_reload, last_housekeeping;
	sigset_t mask;

	/*
	 * Warnings and errors are shown without -v: a provider not reachable,
	 * a broken rotation and a CRL about to expire are for the
	 * administrator to see.
	 */
	esdm_logger_set_verbosity(LOGGER_WARN);

	while ((c = getopt_long(argc, argv, "C:s:m:u:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'C':
			relay_cfg.connect = optarg;
			break;
		case 's':
			relay_cfg.socket_path = optarg;
			break;
		case 'm': {
			unsigned long val;
			char *end;

			errno = 0;
			val = strtoul(optarg, &end, 8);
			if (errno || end == optarg || *end != '\0' ||
			    val > 0777) {
				fprintf(stderr,
					"--mode takes an octal access mode, not \"%s\"\n",
					optarg);
				return 1;
			}
			relay_cfg.mode = (mode_t)val;
			break;
		}
		case 'u': {
			uid_t uid = relay_parse_uid(optarg);

			if (uid == (uid_t)-1) {
				fprintf(stderr,
					"--client_uid takes a uid or a user name, not \"%s\"\n",
					optarg);
				return 1;
			}
			if (relay_cfg.client_uids_num >= RELAY_MAX_CLIENT_UIDS) {
				fprintf(stderr,
					"--client_uid may be given %u times at most\n",
					RELAY_MAX_CLIENT_UIDS);
				return 1;
			}
			relay_cfg.client_uids[relay_cfg.client_uids_num++] =
				uid;
			break;
		}
		case OPT_NO_DTLS:
			relay_cfg.dtls = false;
			break;
		case OPT_CERT:
		case OPT_KEY:
		case OPT_CA:
		case OPT_CRL:
		case OPT_CRL_CHECK_ALL:
		case OPT_CRL_ALLOW_EXPIRED:
			if (esdm_net_tls_option(&relay_cfg.files,
						tls_opts[c - OPT_CERT],
						optarg) != 1)
				return 1;
			break;
		case OPT_SERVER_NAME:
			relay_cfg.server_name = optarg;
			break;
		case OPT_RELOAD_INTERVAL:
			if (esdm_net_parse_uint("reload_interval", optarg,
						86400 * 365,
						&relay_cfg.reload_interval))
				return 1;
			break;
		case OPT_TIMEOUT_MS:
			if (esdm_net_parse_uint("timeout_ms", optarg, 600000,
						&relay_cfg.timeout_ms))
				return 1;
			break;
		case OPT_MAX_CONNECTIONS:
			if (esdm_net_parse_uint("max_connections", optarg, 1024,
						&relay_cfg.max_connections))
				return 1;
			break;
		case OPT_USERNAME:
			username = optarg;
			break;
		case OPT_GROUPNAME:
			groupname = optarg;
			break;
		case 'v':
			esdm_logger_inc_verbosity();
			break;
		case OPT_VERSION:
			printf("%s %s\n", RELAY_NAME, ESDM_ES_EXT_RELAY_VERSION);
			return 0;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	if (optind != argc || !relay_cfg.connect) {
		fprintf(stderr, "--connect is required\n");
		usage();
		return 1;
	}
	if (!relay_cfg.timeout_ms || !relay_cfg.max_connections) {
		fprintf(stderr,
			"--timeout_ms and --max_connections must not be 0\n");
		return 1;
	}

	if (esdm_net_split_connect(relay_cfg.connect, &relay_cfg.host,
				   &relay_cfg.port)) {
		fprintf(stderr,
			"--connect takes HOST, HOST:PORT or [IPv6]:PORT, not \"%s\"\n",
			relay_cfg.connect);
		return 1;
	}
	if (!relay_cfg.port &&
	    asprintf(&relay_cfg.port, "%u", ESDM_ES_EXT_NET_PORT) < 0)
		return 1;
	/* A client that does not check the name trusts any server */
	if (!relay_cfg.server_name)
		relay_cfg.server_name = relay_cfg.host;

	/*
	 * The ESDM runs as nobody unless told otherwise - see esdm-server
	 * --username. Without a user of that name, root alone is served.
	 */
	if (!relay_cfg.client_uids_num) {
		uid_t nobody = relay_parse_uid("nobody");

		if (nobody != (uid_t)-1)
			relay_cfg.client_uids[relay_cfg.client_uids_num++] =
				nobody;
	}

	if (esdm_net_tls_files_resolve(&relay_cfg.files, NULL))
		goto out;

	/* Loaded while the privileges still allow reading them */
	if (relay_reload(true) || !relay_ctx) {
		fprintf(stderr, "The TLS files do not load\n");
		goto out;
	}

#ifdef ESDM_DTLS
	/* Offered on the local socket, as the provider server offers it */
	if (relay_cfg.dtls && esdm_dtls_ctx_alloc(true, &relay_dtls_ctx))
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: DTLS cannot be set up, serving unencrypted\n",
			    RELAY_NAME);
#endif

	if (relay_bind(&lfd))
		goto out;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);
	if (pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
		fprintf(stderr, "Cannot block the signals\n");
		goto out;
	}
	sfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
	if (sfd < 0) {
		fprintf(stderr, "Cannot create the signal descriptor: %s\n",
			strerror(errno));
		goto out;
	}
	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	/*
	 * The socket listens already: what the ESDM sees of the relay is the
	 * user it listened as, see esdm-es-ext-relay(8)
	 */
	if (!getuid() && drop_privileges_permanent(username, groupname)) {
		fprintf(stderr, "Cannot drop the privileges to %s\n", username);
		goto out;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "%s: relaying %s to %s, DTLS over SCTP by %s\n", RELAY_NAME,
		    relay_cfg.socket_path, relay_cfg.connect, esdm_tls_stack());
	systemd_notify_ready();

	pfds[0].fd = lfd;
	pfds[0].events = POLLIN;
	pfds[1].fd = sfd;
	pfds[1].events = POLLIN;

	last_reload = last_housekeeping = relay_now_ms();
	for (;;) {
		bool stop = false, hup = false;
		uint64_t now;
		int r = poll(pfds, 2, 1000);

		if (r < 0 && errno != EINTR)
			break;

		if (r > 0 && (pfds[1].revents & POLLIN)) {
			struct signalfd_siginfo si;

			while (read(sfd, &si, sizeof(si)) == sizeof(si)) {
				if (si.ssi_signo == SIGHUP)
					hup = true;
				else
					stop = true;
			}
		}
		if (stop)
			break;

		if (r > 0 && (pfds[0].revents & POLLIN))
			relay_accept(lfd);

		now = relay_now_ms();
		if (hup) {
			esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
				    "%s: reloading the TLS files\n",
				    RELAY_NAME);
			relay_reload(true);
			last_reload = now;
		} else if (relay_cfg.reload_interval &&
			   now - last_reload >=
				   (uint64_t)relay_cfg.reload_interval * 1000) {
			relay_reload(false);
			last_reload = now;
		}
		if (now - last_housekeeping >= RELAY_HOUSEKEEPING_SEC * 1000) {
			last_housekeeping = now;
			esdm_tls_ctx_crl_report(relay_ctx, false);
			/* Expired; revocation is checked by the reload */
			relay_check_conns(NULL);
		}
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "%s: shutting down\n",
		    RELAY_NAME);
	systemd_notify_stopping();
	ret = 0;

	/* Wake every thread, and wait for them a while */
	atomic_store(&relay_stop, true);
	{
		struct relay_conn *conn;
		struct timespec until;

		pthread_mutex_lock(&relay_conns_lock);
		TAILQ_FOREACH (conn, &relay_conns, tailq)
			shutdown(conn->fd, SHUT_RDWR);
		pthread_mutex_unlock(&relay_conns_lock);

		clock_gettime(CLOCK_REALTIME, &until);
		until.tv_sec += RELAY_STOP_WAIT_MS / 1000;
		pthread_mutex_lock(&relay_pool_lock);
		while (relay_threads &&
		       !pthread_cond_timedwait(&relay_pool_cond,
					       &relay_pool_lock, &until))
			;
		if (relay_threads) {
			/*
			 * A thread still inside the TLS stack would have its
			 * state torn down under it by the handlers exit(3)
			 * runs: leave without them
			 */
			pthread_mutex_unlock(&relay_pool_lock);
			esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
				    "%s: connections still busy at exit\n",
				    RELAY_NAME);
			unlink(relay_cfg.socket_path);
			_exit(0);
		}
		pthread_mutex_unlock(&relay_pool_lock);
	}

out:
	if (lfd >= 0) {
		close(lfd);
		unlink(relay_cfg.socket_path);
	}
	if (sfd >= 0)
		close(sfd);
	esdm_tls_ctx_put(relay_ctx);
	esdm_dtls_ctx_free(relay_dtls_ctx);
	esdm_net_tls_files_free(&relay_cfg.files);
	free(relay_cfg.host);
	free(relay_cfg.port);
	return ret;
}
