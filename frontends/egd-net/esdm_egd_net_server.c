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
 * esdm-egd-net-server: the EGD protocol of the ESDM, served on TCP to the
 * hosts of a network - see esdm-egd-net-server(8).
 *
 * The daemon is a client of the ESDM like any other: it answers the EGD
 * commands through the unprivileged RPC interface of the esdm-server, and
 * nothing of the network reaches the esdm-server but those RPC calls. That
 * keeps the TLS stack and everything a remote peer can send out of the daemon
 * holding the entropy, and makes every client of the network unprivileged by
 * construction.
 *
 * Two modes: TLS 1.3 with mutual authentication by certificates, and plain TCP
 * for networks whose transport is protected underneath. The listener faces the
 * network and anybody may connect to it, so the connections are bounded: in
 * all, in probation - connected, but neither authenticated by a handshake nor
 * past a first command -, in probation per source address, per client (the
 * fingerprint of its certificate, or its source address in plain mode), and in
 * time - the probation, the silence between two commands, and the taking of
 * an answer.
 *
 * A connection is served by a thread of its own, see esdm_egd_serve.h. The
 * main thread accepts, and keeps house: it takes up renewed TLS files on
 * SIGHUP and when they change, closes the connections of clients whose
 * certificate got revoked or expired, and reports CRLs about to expire.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <json-c/json.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "config.h"
#include "egd_net_common.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_serve.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "esdm_tls.h"
#include "memset_secure.h"
#include "privileges.h"
#include "systemd_support.h"

/* Set by the build, see frontends/egd-net/meson.build */
#ifndef ESDM_EGD_NET_VERSION
#define ESDM_EGD_NET_VERSION "unknown"
#endif

#define SERVER_NAME "esdm-egd-net-server"

/* Longest subject of a certificate and reason of a revocation in the log */
#define SERVER_TEXT_LEN 256

/* Connections waiting to be accepted, unless the socket comes from systemd */
#define SERVER_BACKLOG 128

/*
 * A non-blocking read waits at most this long for the ESDM: what it has is
 * there at once, and nothing comes while it is not operational - the RPC
 * client polls a not operational ESDM, which only the deadline ends.
 */
#define SERVER_NONBLOCK_MS 250

/* Interval of the housekeeping: expired certificates, the CRL report */
#define SERVER_HOUSEKEEPING_SEC 30

/* How long the threads are given at shutdown */
#define SERVER_STOP_WAIT_MS 5000

struct server_conn {
	int fd;
	char addr[ESDM_NET_ADDR_STR_LEN];
	/* The peer for the log: its address, and who it authenticated as */
	char peer[ESDM_NET_ADDR_STR_LEN + 2 * SERVER_TEXT_LEN];

	/* Counted against the probation bounds, global and per source */
	bool probation;
	uint8_t source[ESDM_NET_KEY_LEN];
	size_t source_len;

	/* Counted against the bound per client */
	bool client_counted;
	uint8_t client[ESDM_NET_KEY_LEN];
	size_t client_len;

	/* TLS mode: the connection, and whether its handshake completed */
	struct esdm_tls *tls;
	bool established;
	char fingerprint[ESDM_TLS_FINGERPRINT_HEX_LEN];

	TAILQ_ENTRY(server_conn) tailq;
};
TAILQ_HEAD(server_conn_list, server_conn);

static struct {
	bool plain;
	struct esdm_net_tls_files files;
	unsigned int reload_interval;

	struct esdm_net_cidr allow[ESDM_NET_MAX_ALLOW];
	unsigned int allow_num;

	unsigned int max_connections;
	unsigned int max_probation;
	unsigned int max_probation_per_source;
	unsigned int max_per_client;
	unsigned int handshake_timeout;
	unsigned int idle_timeout;
	unsigned int io_timeout;
} server_cfg = {
	.reload_interval = 60,
	.max_connections = 512,
	.max_probation = 64,
	.max_probation_per_source = 8,
	/* As many as a relay opens at most by default, see its max_connections */
	.max_per_client = 64,
	.handshake_timeout = 10,
	.idle_timeout = 600,
	.io_timeout = 30,
};

/* The context new connections are made with, see server_reload() */
static pthread_mutex_t server_ctx_lock = PTHREAD_MUTEX_INITIALIZER;
static struct esdm_tls_ctx *server_ctx = NULL;
static uint8_t server_stamp[ESDM_TLS_STAMP_LEN];

/* The connections, and the counts of the bounds */
static pthread_mutex_t server_conns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct server_conn_list server_conns =
	TAILQ_HEAD_INITIALIZER(server_conns);
static unsigned int server_conn_num = 0;
static unsigned int server_probation_num = 0;
static struct esdm_net_limit server_probation_limit =
	ESDM_NET_LIMIT_INIT("source address in probation");
static struct esdm_net_limit server_client_limit =
	ESDM_NET_LIMIT_INIT("client");

static struct esdm_egd_serve_pool server_pool = ESDM_EGD_SERVE_POOL_INIT;

/******************************************************************************
 * The backend: the unprivileged RPC interface of the ESDM
 ******************************************************************************/

/*
 * Abandon a request of the RPC client? At shutdown, and once the client the
 * request is made for hung up - nobody is left to take its answer, and a
 * blocking read may wait long.
 */
static int server_rpc_interrupt(void *data)
{
	struct server_conn *conn = data;
	struct pollfd pfd;

	if (atomic_load(&server_pool.stop))
		return 1;
	if (!conn)
		return 0;

	pfd.fd = conn->fd;
	pfd.events = POLLRDHUP;
	pfd.revents = 0;
	if (poll(&pfd, 1, 0) > 0 &&
	    (pfd.revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)))
		return 1;

	return 0;
}

static int server_be_entropy_count(void *be, uint32_t *bits)
{
	unsigned int lvl = 0;
	int ret = esdm_rpcc_get_ent_lvl_int(&lvl, be);

	*bits = lvl;
	return ret;
}

static int server_be_get_random(void *be, enum esdm_egd_serve_read kind,
				uint8_t *buf, size_t len, size_t *generated)
{
	struct timespec ts = { .tv_sec = 0,
			       .tv_nsec = SERVER_NONBLOCK_MS * 1000000L };
	size_t got = 0;
	ssize_t n;

	/*
	 * Blocking reads in a row are read together, see esdm_egd_serve.h:
	 * in one RPC request, which carries that much
	 */
	BUILD_BUG_ON(ESDM_EGD_SERVE_RUN_LIMIT > ESDM_RPC_MAX_DATA);

	*generated = 0;

	switch (kind) {
	case ESDM_EGD_SERVE_FULL:
		n = esdm_rpcc_get_random_bytes_full_int(buf, len, be);
		if (n < 0)
			return (int)n;
		*generated = (size_t)n;
		return 0;

	case ESDM_EGD_SERVE_FULL_NONBLOCK:
		/*
		 * All or nothing within the bound - see SERVER_NONBLOCK_MS.
		 * The deadline passing is the answer "nothing right now".
		 */
		n = esdm_rpcc_get_random_bytes_full_timeout_int(buf, len, &ts,
								be);
		if (n == -ETIMEDOUT || n == -EAGAIN)
			return 0;
		if (n < 0)
			return (int)n;
		*generated = (size_t)n;
		return 0;

	case ESDM_EGD_SERVE_PR:
		/*
		 * The prediction resistance DRNG hands out no more than its
		 * entropy sources just delivered: as often as it takes.
		 */
		while (got < len) {
			if (atomic_load(&server_pool.stop))
				return -ESHUTDOWN;
			n = esdm_rpcc_get_random_bytes_pr_int(buf + got,
							      len - got, be);
			if (n < 0)
				return (int)n;
			got += (size_t)n;
		}
		*generated = got;
		return 0;

	case ESDM_EGD_SERVE_PR_NONBLOCK:
		n = esdm_rpcc_get_random_bytes_pr_nonblock_int(buf, len, be);
		if (n == -EAGAIN)
			return 0;
		if (n < 0)
			return (int)n;
		*generated = (size_t)n;
		return 0;

	case ESDM_EGD_SERVE_UNSEEDED:
		n = esdm_rpcc_get_random_bytes_int(buf, len, be);
		/* Not operational yet is a state, answered empty */
		if (n == -EOPNOTSUPP)
			return 0;
		if (n < 0)
			return (int)n;
		*generated = (size_t)n;
		return 0;

	default:
		return -EINVAL;
	}
}

/*
 * Is the ESDM operational? The RPC interface has no call for it, but the
 * ESDM is operational exactly while its initial DRNG is fully seeded, whose
 * state the DRNG status of node 0 tells.
 *
 * @return 1 or 0, or a negative errno
 */
static int server_be_operational(void *be)
{
	struct json_object *doc, *type, *seeded;
	char buf[4096];
	int ret;

	ret = esdm_rpcc_drng_status_json_int(0, buf, sizeof(buf), be);
	if (ret)
		return ret;

	doc = json_tokener_parse(buf);
	if (!doc)
		return -EPROTO;

	ret = -EPROTO;
	if (json_object_object_get_ex(doc, "type", &type) &&
	    json_object_object_get_ex(doc, "fully_seeded", &seeded) &&
	    json_object_is_type(type, json_type_string) &&
	    json_object_is_type(seeded, json_type_boolean))
		ret = !strcmp(json_object_get_string(type), "initial") &&
		      json_object_get_boolean(seeded);

	json_object_put(doc);
	return ret;
}

static int server_be_get_state(void *be, uint32_t *fields, unsigned int room,
			       unsigned int *num)
{
	unsigned int ent = 0, poolsize = 0, wakeup = 0, reseed = 0;
	bool fully_seeded = false;
	int ret, operational;

	if (room < ESDM_EGD_STATE_NUM_FIELDS)
		return -EINVAL;

	ret = esdm_rpcc_is_fully_seeded_int(&fully_seeded, be);
	if (!ret)
		ret = esdm_rpcc_rnd_get_ent_cnt_int(&ent, be);
	if (!ret)
		ret = esdm_rpcc_get_poolsize_int(&poolsize, be);
	if (!ret)
		ret = esdm_rpcc_get_write_wakeup_thresh_int(&wakeup, be);
	if (!ret)
		ret = esdm_rpcc_get_min_reseed_secs_int(&reseed, be);
	if (ret)
		return ret;

	/* All DRNGs fully seeded: the initial one is as well */
	operational = fully_seeded ? 1 : server_be_operational(be);
	if (operational == -EINTR || operational == -ESHUTDOWN)
		return operational;
	if (operational < 0)
		operational = 0;

	fields[ESDM_EGD_STATE_FLAGS] =
		(operational ? ESDM_EGD_STATE_FLAG_OPERATIONAL : 0) |
		(fully_seeded ? ESDM_EGD_STATE_FLAG_FULLY_SEEDED : 0);
	fields[ESDM_EGD_STATE_ENT_CNT] = ent;
	fields[ESDM_EGD_STATE_POOLSIZE] = poolsize;
	fields[ESDM_EGD_STATE_WRITE_WAKEUP] = wakeup;
	fields[ESDM_EGD_STATE_MIN_RESEED_SECS] = reseed;
	*num = ESDM_EGD_STATE_NUM_FIELDS;

	return 0;
}

static int server_be_status(void *be, bool json, char *buf, size_t buflen,
			    size_t *len)
{
	int ret;

	*len = 0;
	buf[0] = '\0';

	if (json) {
		/* One that does not fit is not sent at all, as by the server */
		ret = esdm_rpcc_status_json_int(buf, buflen, be);
		if (ret)
			return ret == -EMSGSIZE ? 0 : ret;
	} else {
		/* One that does not fit is sent as far as it got */
		ret = esdm_rpcc_status_int(buf, buflen, be);
		if (ret && ret != -EMSGSIZE)
			return ret;
	}

	*len = strnlen(buf, buflen - 1);
	if (*len > ESDM_EGD_MAX_STATUS)
		*len = ESDM_EGD_MAX_STATUS;
	return 0;
}

static int server_be_write_data(void *be, const uint8_t *buf, size_t len)
{
	/* The unprivileged interface credits nothing */
	return esdm_rpcc_write_data_int(buf, len, be);
}

static const struct esdm_egd_serve_ops server_ops = {
	.entropy_count = server_be_entropy_count,
	.get_random = server_be_get_random,
	.get_state = server_be_get_state,
	.status = server_be_status,
	.write_data = server_be_write_data,
};

/******************************************************************************
 * The connection: TLS, or plain TCP
 ******************************************************************************/

/* Milliseconds on the monotonic clock. */
static uint64_t server_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* What is left of @timeout_ms after @start, for a wait - -1 for no bound */
static int server_left_ms(uint64_t start, int timeout_ms)
{
	uint64_t now = server_now_ms();

	if (timeout_ms < 0)
		return -1;
	if (now - start >= (uint64_t)timeout_ms)
		return 0;
	return timeout_ms - (int)(now - start);
}

static ssize_t server_tls_read(void *io, uint8_t *buf, size_t len,
			       int timeout_ms)
{
	struct server_conn *conn = io;
	uint64_t start = server_now_ms();

	for (;;) {
		ssize_t n = esdm_tls_recv(conn->tls, buf, len);
		int left, ret;

		if (n != -EAGAIN)
			return n;

		left = server_left_ms(start, timeout_ms);
		if (!left)
			return -ETIMEDOUT;
		ret = esdm_tls_wait(conn->tls, left);
		if (ret)
			return ret;
	}
}

static int server_tls_write(void *io, const uint8_t *buf, size_t len,
			    int timeout_ms)
{
	struct server_conn *conn = io;
	uint64_t start = server_now_ms();
	size_t done = 0;
	int ret, left;

	for (;;) {
		if (done < len) {
			ssize_t n = esdm_tls_send(conn->tls, buf + done,
						  len - done);

			if (n > 0) {
				done += (size_t)n;
				continue;
			}
			if (n != -EAGAIN)
				return n ? (int)n : -EIO;
		} else {
			ret = esdm_tls_flush(conn->tls);
			if (ret != -EAGAIN)
				return ret;
		}

		left = server_left_ms(start, timeout_ms);
		if (!left)
			return -ETIMEDOUT;
		ret = esdm_tls_wait(conn->tls, left);
		if (ret)
			return ret;
	}
}

static const struct esdm_egd_serve_io server_tls_io = {
	.read = server_tls_read,
	.write = server_tls_write,
};

/* Wait for @events on @fd for at most @timeout_ms, -1 for no bound */
static int server_wait_fd(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	uint64_t start = server_now_ms();
	int ret;

	while ((ret = poll(&pfd, 1, server_left_ms(start, timeout_ms))) < 0 &&
	       errno == EINTR)
		;
	if (ret < 0)
		return -errno;
	return ret ? 0 : -ETIMEDOUT;
}

static ssize_t server_plain_read(void *io, uint8_t *buf, size_t len,
				 int timeout_ms)
{
	struct server_conn *conn = io;
	uint64_t start = server_now_ms();

	for (;;) {
		ssize_t n = recv(conn->fd, buf, len, MSG_DONTWAIT);
		int ret;

		if (n >= 0)
			return n;
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return -errno;

		ret = server_wait_fd(conn->fd, POLLIN,
				     server_left_ms(start, timeout_ms));
		if (ret)
			return ret;
	}
}

static int server_plain_write(void *io, const uint8_t *buf, size_t len,
			      int timeout_ms)
{
	struct server_conn *conn = io;
	uint64_t start = server_now_ms();
	size_t done = 0;

	while (done < len) {
		ssize_t n = send(conn->fd, buf + done, len - done,
				 MSG_DONTWAIT | MSG_NOSIGNAL);
		int ret;

		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
			return -errno;

		ret = server_wait_fd(conn->fd, POLLOUT,
				     server_left_ms(start, timeout_ms));
		if (ret)
			return ret;
	}

	return 0;
}

static const struct esdm_egd_serve_io server_plain_io = {
	.read = server_plain_read,
	.write = server_plain_write,
};

/******************************************************************************
 * Connections
 ******************************************************************************/

/* The end of the probation of a connection. */
static void server_conn_probation_end(struct server_conn *conn)
{
	pthread_mutex_lock(&server_conns_lock);
	if (conn->probation) {
		conn->probation = false;
		server_probation_num--;
		pthread_mutex_unlock(&server_conns_lock);
		esdm_net_limit_put(&server_probation_limit, conn->source,
				  conn->source_len);
		return;
	}
	pthread_mutex_unlock(&server_conns_lock);
}

/* The first command of a plain connection ends its probation */
static void server_first_command(void *be)
{
	server_conn_probation_end(be);
}

static void server_conn_release(struct server_conn *conn)
{
	server_conn_probation_end(conn);

	pthread_mutex_lock(&server_conns_lock);
	TAILQ_REMOVE(&server_conns, conn, tailq);
	server_conn_num--;
	pthread_mutex_unlock(&server_conns_lock);

	if (conn->client_counted)
		esdm_net_limit_put(&server_client_limit, conn->client,
				  conn->client_len);

	if (conn->tls) {
		esdm_tls_close_notify(conn->tls);
		esdm_tls_free(conn->tls);
	}
	close(conn->fd);
	free(conn);
}

/*
 * The TLS handshake, bounded by the handshake timeout. Ends the probation and
 * accounts the connection to the client it authenticated as.
 */
static int server_conn_handshake(struct server_conn *conn)
{
	uint8_t fp[ESDM_TLS_FINGERPRINT_LEN];
	struct esdm_tls_ctx *ctx, *cur;
	uint64_t start = server_now_ms();
	char why[SERVER_TEXT_LEN];
	bool revoked;
	int ret, left;

	pthread_mutex_lock(&server_ctx_lock);
	ctx = server_ctx;
	esdm_tls_ctx_get(ctx);
	pthread_mutex_unlock(&server_ctx_lock);

	/* The connection holds a reference of its own, see below */
	ret = esdm_tls_alloc(ctx, conn->fd, NULL, &conn->tls);
	esdm_tls_ctx_put(ctx);
	if (ret)
		return ret;

	while ((ret = esdm_tls_handshake(conn->tls)) == -EAGAIN) {
		if (atomic_load(&server_pool.stop))
			return -ESHUTDOWN;
		left = server_left_ms(start,
				      (int)server_cfg.handshake_timeout * 1000);
		if (!left) {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
				    "%s: no handshake from %s in time\n",
				    SERVER_NAME, conn->addr);
			return -ETIMEDOUT;
		}
		ret = esdm_tls_wait(conn->tls, left);
		if (ret)
			return ret;
	}
	if (ret) {
		esdm_logger(ret == -EACCES ? LOGGER_VERBOSE : LOGGER_DEBUG,
			    LOGGER_C_SERVER,
			    "%s: handshake with %s failed: %s\n", SERVER_NAME,
			    conn->addr, esdm_tls_error(conn->tls));
		return ret;
	}

	server_conn_probation_end(conn);

	esdm_tls_peer_fingerprint(conn->tls, fp);
	esdm_tls_fingerprint_hex(fp, conn->fingerprint);
	snprintf(conn->peer, sizeof(conn->peer), "%s (SHA-256 %s) from %s",
		 esdm_tls_peer_subject(conn->tls), conn->fingerprint,
		 conn->addr);

	/* The client is its certificate */
	conn->client[0] = 'c';
	memcpy(conn->client + 1, fp, sizeof(fp));
	conn->client_len = 1 + sizeof(fp);
	if (!esdm_net_limit_get(&server_client_limit, conn->client,
			       conn->client_len)) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "%s: refusing a further connection of %s\n",
			    SERVER_NAME, conn->peer);
		/* No certificate matter: an orderly end, not an alert */
		esdm_tls_close_notify(conn->tls);
		return -EUSERS;
	}
	conn->client_counted = true;

	/*
	 * From here on the housekeeping looks at it, see server_check_conns().
	 *
	 * A reload while the handshake ran put a context in place whose CRLs
	 * the handshake did not see, and checked the established connections
	 * against them - which this one was not yet. So it is checked here,
	 * under the lock that check takes: either the reload replaced the
	 * context before, which is seen here, or it checks this connection
	 * after. The context of the handshake is held by the connection, so
	 * the comparison is with one that is still there.
	 */
	pthread_mutex_lock(&server_conns_lock);
	pthread_mutex_lock(&server_ctx_lock);
	cur = server_ctx;
	esdm_tls_ctx_get(cur);
	pthread_mutex_unlock(&server_ctx_lock);
	revoked = cur != ctx &&
		  esdm_tls_peer_revoked(conn->tls, cur, why, sizeof(why)) == 1;
	if (!revoked)
		conn->established = true;
	pthread_mutex_unlock(&server_conns_lock);
	esdm_tls_ctx_put(cur);

	if (revoked) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
			    "%s: closing the connection of %s, revoked: %s\n",
			    SERVER_NAME, conn->peer, why);
		esdm_tls_close_notify(conn->tls);
		return -EKEYREVOKED;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "%s: client %s connected, %s, %s\n", SERVER_NAME,
		    conn->peer, esdm_tls_cipher(conn->tls),
		    esdm_tls_group(conn->tls));

	return 0;
}

static void *server_conn_thread(void *arg)
{
	struct server_conn *conn = arg;
	struct esdm_egd_serve_conn serve = {
		.ops = &server_ops,
		.be = conn,
		.peer = conn->peer,
		.idle_timeout_ms = server_cfg.idle_timeout * 1000,
		.io_timeout_ms = server_cfg.io_timeout * 1000,
		.stop = &server_pool.stop,
	};
	int ret;

	if (server_cfg.plain) {
		serve.io = &server_plain_io;
		/* The probation of a plain connection: its first command */
		serve.first_timeout_ms = server_cfg.handshake_timeout * 1000;
		serve.first_command = server_first_command;
	} else {
		ret = server_conn_handshake(conn);
		if (ret)
			goto out;
		serve.io = &server_tls_io;
	}
	serve.io_ctx = conn;

	ret = esdm_egd_serve(&serve);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "%s: connection of %s ended: %s\n", SERVER_NAME,
		    conn->peer, ret ? strerror(-ret) : "closed by the client");

out:
	server_conn_release(conn);
	return NULL;
}

/* Accept one client, if the bounds allow. */
static void server_accept(int lfd)
{
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	struct server_conn *conn;
	uint8_t source[ESDM_NET_KEY_LEN];
	size_t source_len;
	int fd, one = 1, ret;
	char addr[ESDM_NET_ADDR_STR_LEN];

	fd = accept4(lfd, (struct sockaddr *)&ss, &sslen,
		     SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
				    "%s: cannot accept: %s\n", SERVER_NAME,
				    strerror(errno));
		return;
	}

	esdm_net_addr_unmap(&ss);
	esdm_net_addr_str(&ss, addr, sizeof(addr));

	/* Not from the networks allowed: gone before anything else */
	if (!esdm_net_cidr_allowed(server_cfg.allow, server_cfg.allow_num,
				  &ss)) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "%s: refusing %s, which is not allowed\n",
			    SERVER_NAME, addr);
		close(fd);
		return;
	}

	source_len = esdm_net_source_key(&ss, source);

	pthread_mutex_lock(&server_conns_lock);
	if (server_conn_num >= server_cfg.max_connections ||
	    server_probation_num >= server_cfg.max_probation) {
		pthread_mutex_unlock(&server_conns_lock);
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "%s: refusing %s, all slots are taken\n",
			    SERVER_NAME, addr);
		close(fd);
		return;
	}
	server_conn_num++;
	server_probation_num++;
	pthread_mutex_unlock(&server_conns_lock);

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		ret = -ENOMEM;
		goto undo_slots;
	}
	conn->fd = fd;
	snprintf(conn->addr, sizeof(conn->addr), "%s", addr);
	snprintf(conn->peer, sizeof(conn->peer), "%s", addr);
	memcpy(conn->source, source, sizeof(source));
	conn->source_len = source_len;

	if (!esdm_net_limit_get(&server_probation_limit, source, source_len)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
			    "%s: refusing %s, its source has too many connections in probation\n",
			    SERVER_NAME, addr);
		ret = -EUSERS;
		goto undo_slots;
	}
	conn->probation = true;

	/* In plain mode, the client is its source */
	if (server_cfg.plain) {
		conn->client[0] = 's';
		memcpy(conn->client + 1, source, source_len);
		conn->client_len = 1 + source_len;
		if (!esdm_net_limit_get(&server_client_limit, conn->client,
				       conn->client_len)) {
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
				    "%s: refusing a further connection of %s\n",
				    SERVER_NAME, addr);
			ret = -EUSERS;
			goto undo_probation;
		}
		conn->client_counted = true;
	}

	/* The answers are small and wanted right away */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	pthread_mutex_lock(&server_conns_lock);
	TAILQ_INSERT_TAIL(&server_conns, conn, tailq);
	pthread_mutex_unlock(&server_conns_lock);

	ret = esdm_egd_serve_pool_spawn(&server_pool, server_conn_thread, conn);
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "%s: cannot start a thread for %s: %s\n",
			    SERVER_NAME, addr, strerror(-ret));
		server_conn_release(conn);
	}
	return;

undo_probation:
	esdm_net_limit_put(&server_probation_limit, source, source_len);
	conn->probation = false;
undo_slots:
	pthread_mutex_lock(&server_conns_lock);
	server_conn_num--;
	server_probation_num--;
	pthread_mutex_unlock(&server_conns_lock);
	free(conn);
	close(fd);
	(void)ret;
}

/*
 * Close the connections whose client is revoked by the CRLs of @ctx, or whose
 * certificate expired - each is shut down, which ends its thread.
 */
static void server_check_conns(struct esdm_tls_ctx *ctx)
{
	int64_t now = (int64_t)time(NULL);
	struct server_conn *conn;
	char why[SERVER_TEXT_LEN];

	pthread_mutex_lock(&server_conns_lock);
	TAILQ_FOREACH (conn, &server_conns, tailq) {
		int64_t not_after;

		if (!conn->established)
			continue;

		if (ctx && esdm_tls_peer_revoked(conn->tls, ctx, why,
						 sizeof(why)) == 1) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_SERVER,
				"%s: closing the connection of %s, revoked: %s\n",
				SERVER_NAME, conn->peer, why);
			shutdown(conn->fd, SHUT_RDWR);
			continue;
		}

		not_after = esdm_tls_peer_not_after(conn->tls);
		if (not_after && now > not_after) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_SERVER,
				"%s: closing the connection of %s, its certificate expired\n",
				SERVER_NAME, conn->peer);
			shutdown(conn->fd, SHUT_RDWR);
		}
	}
	pthread_mutex_unlock(&server_conns_lock);
}

/*
 * Take up the TLS files: build a complete new context, and only if that
 * succeeded, have new connections made with it and check the established ones
 * against its CRLs. A context that does not build leaves the old one in
 * service. @force builds even if the files did not change - SIGHUP.
 */
static void server_reload(bool force)
{
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL, *old;

	esdm_net_tls_config(&server_cfg.files, &cfg);
	if (esdm_net_tls_reload(SERVER_NAME, true, &cfg, force, server_stamp,
				&ctx) <= 0)
		return;

	pthread_mutex_lock(&server_ctx_lock);
	old = server_ctx;
	server_ctx = ctx;
	pthread_mutex_unlock(&server_ctx_lock);
	esdm_tls_ctx_put(old);

	esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
		    "%s: loaded the TLS files of %s\n", SERVER_NAME,
		    server_cfg.files.cert);
	esdm_tls_ctx_crl_report(ctx, true);

	/* Revocation has to bite on the connections that are there already */
	server_check_conns(ctx);
}

/******************************************************************************
 * Main
 ******************************************************************************/

static void usage(void)
{
	fprintf(stderr, "\nESDM EGD network server\n\n");
	fprintf(stderr, "%s %s, TLS by %s\n\n", SERVER_NAME,
		ESDM_EGD_NET_VERSION, esdm_tls_stack());
	fprintf(stderr, "Usage: %s [OPTIONS]\n\n", SERVER_NAME);
	fprintf(stderr,
		"\t-l --listen <[HOST]:PORT>\tListen on HOST, any address without,\n"
		"\t\t\t\tPORT; may be repeated (default: from socket activation)\n"
		"\t   --plain\t\tPlain TCP, no TLS - only on a network protected\n"
		"\t\t\t\tunderneath, never a default\n"
		"\t   --cert <FILE>\tCertificate of the server, PEM\n"
		"\t   --key <FILE>\t\tIts private key, PEM, PKCS#8\n"
		"\t   --ca <FILE>\t\tTrust anchors the client certificates must\n"
		"\t\t\t\tchain to, PEM; may be repeated, for the\n"
		"\t\t\t\trollover of a CA\n"
		"\t   --crl <FILE>\t\tCRLs, PEM; may be repeated\n"
		"\t   --crl_check_all\tRequire CRLs of the CA certificates as well\n"
		"\t   --crl_allow_expired\tOnly warn of a CRL past its nextUpdate\n"
		"\t   --reload_interval <SEC>\tCheck the TLS files for a change\n"
		"\t\t\t\tthis often, 0 for never (default 60); SIGHUP\n"
		"\t\t\t\treloads them at once\n"
		"\t   --allow <CIDR>\tServe only clients of the network CIDR;\n"
		"\t\t\t\tmay be repeated (default: any)\n"
		"\t   --max_connections <N>\tConnections in all (default 512)\n"
		"\t   --max_handshakes <N>\tConnections in probation - before\n"
		"\t\t\t\ttheir handshake, or in plain mode their first\n"
		"\t\t\t\tcommand (default 64)\n"
		"\t   --max_handshakes_per_source <N>\tThe same per source\n"
		"\t\t\t\taddress, per /64 for IPv6 (default 8)\n"
		"\t   --max_per_client <N>\tConnections per client certificate,\n"
		"\t\t\t\tin plain mode per source address (default 64)\n"
		"\t   --handshake_timeout <SEC>\tLength of the probation (default 10)\n"
		"\t   --idle_timeout <SEC>\tSilence after which a connection is\n"
		"\t\t\t\tclosed, 0 for never (default 600)\n"
		"\t   --io_timeout <SEC>\tBound of the rest of a command and of\n"
		"\t\t\t\tthe taking of an answer (default 30)\n"
		"\t-u --username <USER>\tUser to switch to when started as root\n"
		"\t\t\t\t(default: nobody)\n"
		"\t-g --groupname <GROUP>\tGroup to switch to (default: none)\n"
		"\t-S --syslog\t\tLog to syslog\n"
		"\t-v --verbose\t\tMore verbose logging, may be repeated\n"
		"\t-h --help\t\tThis help information\n"
		"\t   --version\t\tPrint the version\n\n"
		"A file without a slash in its name is a credential of the service,\n"
		"taken from $CREDENTIALS_DIRECTORY (systemd LoadCredential=); without\n"
		"--cert, --key and --ca, the credentials cert, key and ca are used.\n");
}

enum {
	OPT_PLAIN = 256,
	OPT_CERT,
	OPT_KEY,
	OPT_CA,
	OPT_CRL,
	OPT_CRL_CHECK_ALL,
	OPT_CRL_ALLOW_EXPIRED,
	OPT_RELOAD_INTERVAL,
	OPT_ALLOW,
	OPT_MAX_CONNECTIONS,
	OPT_MAX_HANDSHAKES,
	OPT_MAX_HANDSHAKES_PER_SOURCE,
	OPT_MAX_PER_CLIENT,
	OPT_HANDSHAKE_TIMEOUT,
	OPT_IDLE_TIMEOUT,
	OPT_IO_TIMEOUT,
	OPT_VERSION,
};

static int server_set_file(char **file, const char *arg)
{
	free(*file);
	*file = strdup(arg);
	return *file ? 0 : -ENOMEM;
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "listen", required_argument, NULL, 'l' },
		{ "plain", no_argument, NULL, OPT_PLAIN },
		{ "cert", required_argument, NULL, OPT_CERT },
		{ "key", required_argument, NULL, OPT_KEY },
		{ "ca", required_argument, NULL, OPT_CA },
		{ "crl", required_argument, NULL, OPT_CRL },
		{ "crl_check_all", no_argument, NULL, OPT_CRL_CHECK_ALL },
		{ "crl_allow_expired", no_argument, NULL,
		  OPT_CRL_ALLOW_EXPIRED },
		{ "reload_interval", required_argument, NULL,
		  OPT_RELOAD_INTERVAL },
		{ "allow", required_argument, NULL, OPT_ALLOW },
		{ "max_connections", required_argument, NULL,
		  OPT_MAX_CONNECTIONS },
		{ "max_handshakes", required_argument, NULL,
		  OPT_MAX_HANDSHAKES },
		{ "max_handshakes_per_source", required_argument, NULL,
		  OPT_MAX_HANDSHAKES_PER_SOURCE },
		{ "max_per_client", required_argument, NULL,
		  OPT_MAX_PER_CLIENT },
		{ "handshake_timeout", required_argument, NULL,
		  OPT_HANDSHAKE_TIMEOUT },
		{ "idle_timeout", required_argument, NULL, OPT_IDLE_TIMEOUT },
		{ "io_timeout", required_argument, NULL, OPT_IO_TIMEOUT },
		{ "username", required_argument, NULL, 'u' },
		{ "groupname", required_argument, NULL, 'g' },
		{ "syslog", no_argument, NULL, 'S' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ NULL, 0, NULL, 0 }
	};
	const char *listen_args[ESDM_NET_MAX_LISTEN];
	const char *username = "nobody", *groupname = NULL;
	struct pollfd pfds[ESDM_NET_MAX_LISTEN + 1];
	int lfds[ESDM_NET_MAX_LISTEN];
	unsigned int listen_num = 0, i;
	int lfd_num = 0, sfd = -1, c, ret = 1;
	bool tls_option = false;
	uint64_t last_reload, last_housekeeping;
	sigset_t mask;

	/*
	 * Warnings and errors are shown without -v: a broken rotation, a CRL
	 * about to expire and plain TCP are for the administrator to see.
	 */
	esdm_logger_set_verbosity(LOGGER_WARN);

	while ((c = getopt_long(argc, argv, "l:u:g:Svh", opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			if (listen_num >= ESDM_NET_MAX_LISTEN) {
				fprintf(stderr,
					"--listen may be given %u times at most\n",
					ESDM_NET_MAX_LISTEN);
				return 1;
			}
			listen_args[listen_num++] = optarg;
			break;
		case OPT_PLAIN:
			server_cfg.plain = true;
			break;
		case OPT_CERT:
			tls_option = true;
			if (server_set_file(&server_cfg.files.cert, optarg))
				return 1;
			break;
		case OPT_KEY:
			tls_option = true;
			if (server_set_file(&server_cfg.files.key, optarg))
				return 1;
			break;
		case OPT_CA:
			tls_option = true;
			if (esdm_net_tls_option(&server_cfg.files, "ca",
						optarg) < 0)
				return 1;
			break;
		case OPT_CRL:
			tls_option = true;
			if (server_cfg.files.crl_num >= ESDM_TLS_MAX_CRL_FILES) {
				fprintf(stderr,
					"--crl may be given %u times at most\n",
					ESDM_TLS_MAX_CRL_FILES);
				return 1;
			}
			server_cfg.files.crl[server_cfg.files.crl_num] =
				strdup(optarg);
			if (!server_cfg.files.crl[server_cfg.files.crl_num++])
				return 1;
			break;
		case OPT_CRL_CHECK_ALL:
			tls_option = true;
			server_cfg.files.crl_check_all = true;
			break;
		case OPT_CRL_ALLOW_EXPIRED:
			tls_option = true;
			server_cfg.files.crl_allow_expired = true;
			break;
		case OPT_RELOAD_INTERVAL:
			if (esdm_net_parse_uint("reload_interval", optarg,
					       86400 * 365,
					       &server_cfg.reload_interval))
				return 1;
			break;
		case OPT_ALLOW:
			if (server_cfg.allow_num >= ESDM_NET_MAX_ALLOW) {
				fprintf(stderr,
					"--allow may be given %u times at most\n",
					ESDM_NET_MAX_ALLOW);
				return 1;
			}
			if (esdm_net_cidr_parse(
				    optarg,
				    &server_cfg.allow[server_cfg.allow_num])) {
				fprintf(stderr,
					"--allow takes a network such as 192.0.2.0/24 or 2001:db8::/32, not \"%s\"\n",
					optarg);
				return 1;
			}
			server_cfg.allow_num++;
			break;
		case OPT_MAX_CONNECTIONS:
			if (esdm_net_parse_uint("max_connections", optarg,
					       1000000,
					       &server_cfg.max_connections))
				return 1;
			break;
		case OPT_MAX_HANDSHAKES:
			if (esdm_net_parse_uint("max_handshakes", optarg, 1000000,
					       &server_cfg.max_probation))
				return 1;
			break;
		case OPT_MAX_HANDSHAKES_PER_SOURCE:
			if (esdm_net_parse_uint(
				    "max_handshakes_per_source", optarg,
				    1000000,
				    &server_cfg.max_probation_per_source))
				return 1;
			break;
		case OPT_MAX_PER_CLIENT:
			if (esdm_net_parse_uint("max_per_client", optarg,
					       1000000,
					       &server_cfg.max_per_client))
				return 1;
			break;
		case OPT_HANDSHAKE_TIMEOUT:
			if (esdm_net_parse_uint("handshake_timeout", optarg,
					       3600,
					       &server_cfg.handshake_timeout))
				return 1;
			break;
		case OPT_IDLE_TIMEOUT:
			if (esdm_net_parse_uint("idle_timeout", optarg, 86400 * 7,
					       &server_cfg.idle_timeout))
				return 1;
			break;
		case OPT_IO_TIMEOUT:
			if (esdm_net_parse_uint("io_timeout", optarg, 3600,
					       &server_cfg.io_timeout))
				return 1;
			break;
		case 'u':
			username = optarg;
			break;
		case 'g':
			groupname = optarg;
			break;
		case 'S':
			esdm_logger_enable_syslog(SERVER_NAME);
			break;
		case 'v':
			esdm_logger_inc_verbosity();
			break;
		case OPT_VERSION:
			printf("%s %s\n", SERVER_NAME, ESDM_EGD_NET_VERSION);
			return 0;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	if (optind != argc) {
		usage();
		return 1;
	}

	if (!server_cfg.max_connections || !server_cfg.max_probation ||
	    !server_cfg.max_probation_per_source ||
	    !server_cfg.max_per_client || !server_cfg.handshake_timeout ||
	    !server_cfg.io_timeout) {
		fprintf(stderr,
			"The bounds of the connections and the handshake and I/O timeouts must not be 0\n");
		return 1;
	}
	server_probation_limit.max = server_cfg.max_probation_per_source;
	server_client_limit.max = server_cfg.max_per_client;

	/* Plain TCP only on request, TLS only with what it needs */
	if (egd_net_tls_files_resolve(&server_cfg.files, server_cfg.plain,
				      tls_option))
		return 1;

	if (server_cfg.plain) {
		egd_net_plain_warning(SERVER_NAME);
	} else {
		/* Loaded while the privileges still allow reading them */
		server_reload(true);
		if (!server_ctx) {
			fprintf(stderr, "The TLS files do not load\n");
			goto out;
		}
	}

	lfd_num = esdm_net_listen_fds(lfds, ESDM_NET_MAX_LISTEN);
	for (i = 0; i < listen_num; i++) {
		if (esdm_net_listen(listen_args[i], SERVER_BACKLOG, lfds,
				    &lfd_num, ESDM_NET_MAX_LISTEN))
			goto out;
	}
	if (!lfd_num) {
		fprintf(stderr,
			"Nothing to listen on: give --listen, or start through socket activation\n");
		goto out;
	}
	for (i = 0; i < (unsigned int)lfd_num; i++) {
		if (esdm_net_listener_check(lfds[i], ESDM_NET_LISTENER_TCP)) {
			fprintf(stderr,
				"Descriptor %d is no listening stream socket of TCP\n",
				lfds[i]);
			goto out;
		}
	}

	/*
	 * The signals are taken by the main thread alone, from a descriptor:
	 * blocked before any thread is started, so that every thread inherits
	 * the mask.
	 */
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

	if (!getuid()) {
		if (drop_privileges_permanent(username, groupname)) {
			fprintf(stderr, "Cannot drop the privileges to %s\n",
				username);
			goto out;
		}
	}

	/* Connected at the first request, so the ESDM need not be up yet */
	ret = esdm_rpcc_init_unpriv_service(server_rpc_interrupt);
	if (ret) {
		fprintf(stderr, "Cannot set up the RPC client: %s\n",
			strerror(-ret));
		ret = 1;
		goto out;
	}
	ret = 1;

	esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
		    "%s: serving the EGD protocol on %d socket(s), %s\n",
		    SERVER_NAME, lfd_num,
		    server_cfg.plain ? "plain TCP" : "TLS 1.3");
	systemd_notify_ready();

	for (i = 0; i < (unsigned int)lfd_num; i++) {
		pfds[i].fd = lfds[i];
		pfds[i].events = POLLIN;
	}
	pfds[lfd_num].fd = sfd;
	pfds[lfd_num].events = POLLIN;

	last_reload = last_housekeeping = server_now_ms();
	for (;;) {
		uint64_t now;
		bool stop = false, hup = false;
		int n = poll(pfds, (nfds_t)lfd_num + 1, 1000);

		if (n < 0 && errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "%s: poll failed: %s\n", SERVER_NAME,
				    strerror(errno));
			break;
		}

		if (n > 0 && (pfds[lfd_num].revents & POLLIN)) {
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

		for (i = 0; n > 0 && i < (unsigned int)lfd_num; i++) {
			if (pfds[i].revents & POLLIN)
				server_accept(pfds[i].fd);
		}

		if (server_cfg.plain)
			continue;

		now = server_now_ms();
		if (hup) {
			esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER,
				    "%s: reloading the TLS files\n",
				    SERVER_NAME);
			server_reload(true);
			last_reload = now;
		} else if (server_cfg.reload_interval &&
			   now - last_reload >=
				   (uint64_t)server_cfg.reload_interval * 1000) {
			server_reload(false);
			last_reload = now;
		}

		if (now - last_housekeeping >= SERVER_HOUSEKEEPING_SEC * 1000) {
			last_housekeeping = now;
			/* Only this thread replaces the context */
			esdm_tls_ctx_crl_report(server_ctx, false);
			/* Expired certificates; revocation is checked by reload */
			server_check_conns(NULL);
		}
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_SERVER, "%s: shutting down\n",
		    SERVER_NAME);
	systemd_notify_stopping();
	ret = 0;

	/* Wake every thread waiting for its client, and tell them all */
	atomic_store(&server_pool.stop, true);
	{
		struct server_conn *conn;

		pthread_mutex_lock(&server_conns_lock);
		TAILQ_FOREACH (conn, &server_conns, tailq)
			shutdown(conn->fd, SHUT_RDWR);
		pthread_mutex_unlock(&server_conns_lock);
	}
	if (esdm_egd_serve_pool_stop(&server_pool, SERVER_STOP_WAIT_MS)) {
		/*
		 * A thread still inside the TLS stack or the RPC client would
		 * have its state torn down under it by the handlers exit(3)
		 * runs: leave without them.
		 */
		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "%s: connections still busy at exit\n",
			    SERVER_NAME);
		_exit(0);
	}
	esdm_rpcc_fini_unpriv_service();

out:
	for (i = 0; i < (unsigned int)lfd_num; i++)
		close(lfds[i]);
	if (sfd >= 0)
		close(sfd);
	esdm_net_tls_files_free(&server_cfg.files);
	return ret;
}
