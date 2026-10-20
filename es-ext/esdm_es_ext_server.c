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
 * The provider side of the external entropy source protocol: a plugin served
 * on a Unix domain socket the ESDM connects to, or on the network - see
 * esdm_es_ext.h.
 *
 * The server is one thread polling the listening sockets and its clients, and
 * serving one request at a time. That is all the plugin API allows anyway, as
 * its callbacks are never called concurrently, and all the ESDM needs: it
 * sends one request at a time per connection.
 *
 * On the network, the DTLS of a connection - with certificates, on SCTP, see
 * esdm_tls.h - starts as it is accepted, its handshake a step at a time
 * whenever the socket is ready for it, so a client that is slow or silent in
 * its handshake holds up nobody but itself. The same thread keeps house: the
 * deadlines of the handshakes and of the silence of a connection, the TLS
 * files taken up again and the connections their CRLs revoke, the
 * certificates of clients that expire.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_es_ext.h"
#include "esdm_dtls.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "esdm_server_socket.h"
#include "helper.h"
#include "memset_secure.h"
#include "visibility.h"

#ifdef ESDM_ES_EXT_NET
#include "esdm_net.h"
#include "esdm_tls.h"
#endif

/*
 * Clients served at a time on a Unix domain socket. The ESDM holds one
 * connection; the room beyond is for a restarted ESDM whose old connection is
 * not closed yet, and for tools.
 *
 * A client beyond takes the slot of the client idle the longest, which is
 * disconnected: clients that hold their slots without using them - which any
 * process of an allowed user can open - must not lock the ESDM out, which
 * connects again whenever it lost its connection, and so gets its slot back.
 * A client running as root only gives way to another client running as root:
 * the ESDM connects as root at start up. A client that finds no slot that way
 * is accepted and closed at once, so that it does not wait in the backlog for
 * nothing.
 *
 * On the network, the clients are bounded by the configuration instead - see
 * struct esdm_es_ext_server_net_config.
 */
#define ESDM_ES_EXT_SERVER_MAX_CLIENTS 8

#define ESDM_ES_EXT_SERVER_BACKLOG 8

/* Connections waiting to be accepted on the network */
#define ESDM_ES_EXT_SERVER_NET_BACKLOG 64

/* Users that may be allowed with esdm_es_ext_server_allow_uid() */
#define ESDM_ES_EXT_SERVER_MAX_UIDS 8

/*
 * Interval of the housekeeping on the network: the CRL report, the
 * certificates of clients that expired
 */
#define ESDM_ES_EXT_SERVER_HOUSEKEEPING_SEC 30

/* Where a client is on its connection */
enum esdm_es_ext_client_state {
	/* Requests in the clear, as connected */
	ESDM_ES_EXT_CLIENT_PLAIN,
	/* STARTDTLS answered - or on the network, accepted -, the handshake */
	ESDM_ES_EXT_CLIENT_HANDSHAKE,
	/* Requests as DTLS application data */
	ESDM_ES_EXT_CLIENT_DTLS,
};

struct esdm_es_ext_client {
	int fd;
	enum esdm_es_ext_client_state state;
	struct esdm_dtls *dtls;

	/*
	 * When the client was accepted or sent something last, nanoseconds of
	 * the monotonic clock, and whether it runs as root - see above
	 */
	uint64_t active;
	bool root;

#ifdef ESDM_ES_EXT_NET
	/* The network: when it was accepted, from where, and who it is */
	uint64_t accepted;
	char addr[ESDM_NET_ADDR_STR_LEN];
	char fingerprint[ESDM_TLS_FINGERPRINT_HEX_LEN];

	/* Counted against the bounds of the handshakes, in all and per source */
	bool probation;
	uint8_t source[ESDM_NET_KEY_LEN];
	size_t source_len;

	/* Counted against the bound per client */
	bool counted;
	uint8_t client[ESDM_NET_KEY_LEN];
	size_t client_len;

	/* The context its handshake started with, see esdm_es_ext_server_net_established() */
	struct esdm_tls_ctx *ctx;
#endif
};

#ifdef ESDM_ES_EXT_NET
/* What a server on the network has beyond one on a Unix domain socket */
struct esdm_es_ext_server_net {
	/* The files of the TLS, and their configuration of the TLS layer */
	struct esdm_net_tls_files files;
	struct esdm_tls_config tls_cfg;
	unsigned int reload_interval;

	/* The context new connections are made with, and the stamp of its files */
	struct esdm_tls_ctx *ctx;
	uint8_t stamp[ESDM_TLS_STAMP_LEN];

	struct esdm_net_cidr allow[ESDM_NET_MAX_ALLOW];
	unsigned int allow_num;

	unsigned int max_handshakes;
	unsigned int handshake_timeout;
	unsigned int idle_timeout;

	/* Connections in their handshake, and the bounds per key */
	unsigned int probation_num;
	struct esdm_net_limit probation_limit;
	struct esdm_net_limit client_limit;

	/* Written to by esdm_es_ext_server_reload() */
	int reload_pipe[2];

	/* When the files were checked last, and the housekeeping ran */
	uint64_t last_reload;
	uint64_t last_housekeeping;
};
#endif

struct esdm_es_ext_server {
	const struct esdm_es_ext_plugin *plugin;
	void *ctx;
	bool initialized;

	/*
	 * The name INFO declares, empty for none: the one set with
	 * esdm_es_ext_server_set_name(), or that of the plugin
	 */
	char name[ESDM_ES_EXT_NAME_MAX + 1];

	/*
	 * The rate INFO declares: the one set with
	 * esdm_es_ext_server_set_entropy_rate(), else the one of the plugin,
	 * ESDM_ES_EXT_PROTO_RATE_NONE for none
	 */
	uint32_t rate;
	uint32_t plugin_rate;

	/*
	 * What the server answers STATUS with next to the status of the plugin:
	 * the requests served, the verdict of the last self test of the plugin
	 * - 0 passed, < 0 failed, 1 none yet - and when it was set up,
	 * monotonic nanoseconds
	 */
	uint64_t requests;
	int selftest;
	uint64_t started;

	/* The listening sockets: one on a Unix domain socket */
	int listen_fds[ESDM_ES_EXT_NET_MAX_LISTEN];
	unsigned int listen_num;

	/* Written to by esdm_es_ext_server_stop() */
	int stop_pipe[2];

	/* The clients, and their slots */
	struct esdm_es_ext_client *clients;
	unsigned int max_clients;
	struct pollfd *pfd;

	/* The DTLS context, NULL while not offered */
	struct esdm_dtls_ctx *dtls_ctx;

	/* Clients accepted next to root; none set accepts any client */
	uid_t allowed_uids[ESDM_ES_EXT_SERVER_MAX_UIDS];
	unsigned int allowed_uids_num;

	char *path;
	/* The socket file created, so that only that one is removed again */
	dev_t dev;
	ino_t ino;

#ifdef ESDM_ES_EXT_NET
	/* On the network, NULL on a Unix domain socket */
	struct esdm_es_ext_server_net *net;
#endif
};

static uint64_t esdm_es_ext_server_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static bool esdm_es_ext_server_is_net(const struct esdm_es_ext_server *server)
{
#ifdef ESDM_ES_EXT_NET
	return server->net != NULL;
#else
	(void)server;
	return false;
#endif
}

#ifdef ESDM_ES_EXT_NET
/* The end of the handshake of a client on the network, as to its bounds */
static void esdm_es_ext_server_probation_end(struct esdm_es_ext_server *server,
					     struct esdm_es_ext_client *c)
{
	if (!c->probation)
		return;

	c->probation = false;
	server->net->probation_num--;
	esdm_net_limit_put(&server->net->probation_limit, c->source,
			   c->source_len);
}
#endif

static void esdm_es_ext_server_close_client(struct esdm_es_ext_server *server,
					    unsigned int i)
{
	struct esdm_es_ext_client *c = &server->clients[i];

	if (c->fd < 0)
		return;

#ifdef ESDM_ES_EXT_NET
	if (server->net) {
		esdm_es_ext_server_probation_end(server, c);
		if (c->counted)
			esdm_net_limit_put(&server->net->client_limit,
					   c->client, c->client_len);
		c->counted = false;
		esdm_tls_ctx_put(c->ctx);
		c->ctx = NULL;
		c->fingerprint[0] = '\0';
	}
#endif

	esdm_dtls_free(c->dtls);
	c->dtls = NULL;
	c->state = ESDM_ES_EXT_CLIENT_PLAIN;

	close(c->fd);
	c->fd = -1;
}

/*
 * May the client on @fd be served? With users allowed, only those and root
 * are - anybody else who can connect could otherwise take the slots the ESDM
 * needs, and drain the noise source. *@root tells whether it runs as root.
 */
static bool esdm_es_ext_server_client_allowed(struct esdm_es_ext_server *server,
					      int fd, bool *root)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	unsigned int i;
	bool known;

	known = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);
	*root = known && cred.uid == 0;

	if (!server->allowed_uids_num)
		return true;

	if (!known)
		return false;
	if (*root)
		return true;
	for (i = 0; i < server->allowed_uids_num; i++) {
		if (cred.uid == server->allowed_uids[i])
			return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "External ES provider: client of uid %u refused\n",
		    (unsigned int)cred.uid);
	return false;
}

/*
 * The slot of the client idle the longest that gives way to a new client -
 * running as root if @root - or ESDM_ES_EXT_SERVER_MAX_CLIENTS if none does,
 * see ESDM_ES_EXT_SERVER_MAX_CLIENTS. All slots are taken.
 */
static unsigned int
esdm_es_ext_server_evictee(const struct esdm_es_ext_server *server, bool root)
{
	const struct esdm_es_ext_client *c = server->clients;
	unsigned int i, ret = ESDM_ES_EXT_SERVER_MAX_CLIENTS;

	for (i = 0; i < server->max_clients; i++) {
		if (c[i].root && !root)
			continue;

		/* Not root before root, then the one idle the longest */
		if (ret == ESDM_ES_EXT_SERVER_MAX_CLIENTS ||
		    (c[ret].root && !c[i].root) ||
		    (c[ret].root == c[i].root && c[i].active < c[ret].active))
			ret = i;
	}

	return ret;
}

/* Out of descriptors, the pending connection stays: pace the retries */
static void esdm_es_ext_server_accept_failed(void)
{
	if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
	    errno == ENOMEM) {
		const struct timespec pace = { .tv_nsec = 100000000 };

		nanosleep(&pace, NULL);
	}
}

static void esdm_es_ext_server_accept(struct esdm_es_ext_server *server,
				      int lfd)
{
	struct esdm_es_ext_client *c;
	unsigned int i;
	bool root;
	int fd;

	fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0) {
		/*
		 * poll(2) reports the pending connection again at once, see
		 * esdm_es_ext_server_accept_failed()
		 */
		esdm_es_ext_server_accept_failed();
		return;
	}

	/* Refused before it takes a slot */
	if (!esdm_es_ext_server_client_allowed(server, fd, &root)) {
		close(fd);
		return;
	}

	for (i = 0; i < server->max_clients; i++) {
		if (server->clients[i].fd < 0)
			break;
	}

	if (i == server->max_clients) {
		i = esdm_es_ext_server_evictee(server, root);
		if (i == ESDM_ES_EXT_SERVER_MAX_CLIENTS) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ANY,
				"External ES provider: too many clients, connection refused\n");
			close(fd);
			return;
		}

		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: too many clients, the one idle the longest disconnected\n");
		esdm_es_ext_server_close_client(server, i);
	}

	c = &server->clients[i];
	c->fd = fd;
	c->state = ESDM_ES_EXT_CLIENT_PLAIN;
	c->active = esdm_es_ext_server_now();
	c->root = root;
}

#ifdef ESDM_ES_EXT_NET

/******************************************************************************
 * The network
 ******************************************************************************/

/*
 * Accept one client on the network, if the allowlist and the bounds allow, and
 * start its handshake.
 */
static void esdm_es_ext_server_net_accept(struct esdm_es_ext_server *server,
					  int lfd)
{
	struct esdm_es_ext_server_net *net = server->net;
	struct sockaddr_storage ss;
	socklen_t sslen = sizeof(ss);
	struct esdm_es_ext_client *c;
	uint8_t source[ESDM_NET_KEY_LEN];
	char addr[ESDM_NET_ADDR_STR_LEN];
	size_t source_len;
	unsigned int i;
	int fd, ret;

	fd = accept4(lfd, (struct sockaddr *)&ss, &sslen,
		     SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0) {
		esdm_es_ext_server_accept_failed();
		return;
	}

	esdm_net_addr_unmap(&ss);
	esdm_net_addr_str(&ss, addr, sizeof(addr));

	/* Not from the networks allowed: gone before anything else */
	if (!esdm_net_cidr_allowed(net->allow, net->allow_num, &ss)) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ANY,
			"External ES provider: refusing %s, which is not allowed\n",
			addr);
		close(fd);
		return;
	}

	for (i = 0; i < server->max_clients; i++) {
		if (server->clients[i].fd < 0)
			break;
	}
	if (i == server->max_clients || net->probation_num >= net->max_handshakes) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"External ES provider: refusing %s, all slots are taken\n",
			addr);
		close(fd);
		return;
	}

	source_len = esdm_net_source_key(&ss, source);
	if (!esdm_net_limit_get(&net->probation_limit, source, source_len)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"External ES provider: refusing %s, its source has too many connections in their handshake\n",
			addr);
		close(fd);
		return;
	}

	c = &server->clients[i];
	memset(c, 0, sizeof(*c));
	c->fd = fd;
	c->state = ESDM_ES_EXT_CLIENT_HANDSHAKE;
	c->accepted = c->active = esdm_es_ext_server_now();
	snprintf(c->addr, sizeof(c->addr), "%s", addr);
	memcpy(c->source, source, sizeof(source));
	c->source_len = source_len;
	c->probation = true;
	net->probation_num++;

	/*
	 * DTLS from the first message on, see "Network" in esdm_es_ext.h -
	 * the requests of the client, nothing larger. An association without
	 * SCTP-AUTH is refused here.
	 */
	c->ctx = net->ctx;
	esdm_tls_ctx_get(c->ctx);
	ret = esdm_dtls_alloc_tls(net->ctx, fd, ESDM_ES_EXT_PROTO_REQ_LEN, NULL,
				  &c->dtls);
	if (ret) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ANY,
			"External ES provider: refusing %s: %s\n", addr,
			ret == -EPROTONOSUPPORT ?
				"its association has no SCTP-AUTH" :
				strerror(-ret));
		esdm_es_ext_server_close_client(server, i);
	}
}

/*
 * The handshake of client @i is complete: who it is, whether it may hold one
 * more connection - and whether a context taken up while the handshake ran
 * revokes it.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_net_established(struct esdm_es_ext_server *server,
					       unsigned int i)
{
	struct esdm_es_ext_server_net *net = server->net;
	struct esdm_es_ext_client *c = &server->clients[i];
	struct esdm_tls *tls = esdm_dtls_tls(c->dtls);
	uint8_t fp[ESDM_TLS_FINGERPRINT_LEN];
	char why[256];

	esdm_es_ext_server_probation_end(server, c);

	esdm_tls_peer_fingerprint(tls, fp);
	esdm_tls_fingerprint_hex(fp, c->fingerprint);

	/* The client is its certificate */
	c->client[0] = 'c';
	memcpy(c->client + 1, fp, sizeof(fp));
	c->client_len = 1 + sizeof(fp);
	if (!esdm_net_limit_get(&net->client_limit, c->client, c->client_len)) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ANY,
			"External ES provider: refusing a further connection of %s (SHA-256 %s) from %s\n",
			esdm_tls_peer_subject(tls), c->fingerprint, c->addr);
		/* No certificate matter: an orderly end, not an alert */
		esdm_tls_close_notify(tls);
		esdm_es_ext_server_close_client(server, i);
		return false;
	}
	c->counted = true;

	/*
	 * The CRLs of a context taken up while the handshake ran have not
	 * seen this client - the established connections were checked against
	 * them, this one was not yet
	 */
	if (c->ctx != net->ctx &&
	    esdm_tls_peer_revoked(tls, net->ctx, why, sizeof(why)) == 1) {
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_ANY,
			"External ES provider: closing the connection of %s (SHA-256 %s) from %s, revoked: %s\n",
			esdm_tls_peer_subject(tls), c->fingerprint, c->addr,
			why);
		esdm_tls_close_notify(tls);
		esdm_es_ext_server_close_client(server, i);
		return false;
	}

	c->state = ESDM_ES_EXT_CLIENT_DTLS;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "External ES provider: client %s (SHA-256 %s) from %s connected, %s\n",
		    esdm_tls_peer_subject(tls), c->fingerprint, c->addr,
		    esdm_dtls_cipher(c->dtls));
	return true;
}

/*
 * Close the connections whose client is revoked by the CRLs of @ctx - NULL for
 * none -, or whose certificate expired.
 */
static void esdm_es_ext_server_net_check(struct esdm_es_ext_server *server,
					 struct esdm_tls_ctx *ctx)
{
	int64_t now = (int64_t)time(NULL);
	unsigned int i;
	char why[256];

	for (i = 0; i < server->max_clients; i++) {
		struct esdm_es_ext_client *c = &server->clients[i];
		struct esdm_tls *tls;
		int64_t not_after;

		if (c->fd < 0 || c->state != ESDM_ES_EXT_CLIENT_DTLS)
			continue;
		tls = esdm_dtls_tls(c->dtls);

		if (ctx && esdm_tls_peer_revoked(tls, ctx, why, sizeof(why)) ==
				   1) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"External ES provider: closing the connection of %s (SHA-256 %s) from %s, revoked: %s\n",
				esdm_tls_peer_subject(tls), c->fingerprint,
				c->addr, why);
			esdm_es_ext_server_close_client(server, i);
			continue;
		}

		not_after = esdm_tls_peer_not_after(tls);
		if (not_after && now > not_after) {
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"External ES provider: closing the connection of %s (SHA-256 %s) from %s, its certificate expired\n",
				esdm_tls_peer_subject(tls), c->fingerprint,
				c->addr);
			esdm_es_ext_server_close_client(server, i);
		}
	}
}

/*
 * Take up the TLS files: build a complete new context, and only if that
 * succeeded, make new connections with it and check the established ones
 * against its CRLs. @force builds even if the files did not change.
 *
 * @return 0, or the negative errno of files that do not load
 */
static int esdm_es_ext_server_net_reload(struct esdm_es_ext_server *server,
					 bool force)
{
	struct esdm_es_ext_server_net *net = server->net;
	struct esdm_tls_ctx *ctx = NULL;
	int ret;

	ret = esdm_net_tls_reload("External ES provider", true, &net->tls_cfg,
				  force, net->stamp, &ctx);
	if (ret <= 0)
		return ret;

	esdm_tls_ctx_put(net->ctx);
	net->ctx = ctx;

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "External ES provider: loaded the TLS files of %s\n",
		    net->files.cert);
	esdm_tls_ctx_crl_report(ctx, true);

	/* Revocation has to bite on the connections that are there already */
	esdm_es_ext_server_net_check(server, ctx);
	return 0;
}

/*
 * The timeouts and the housekeeping of the network, and the milliseconds until
 * the next is due - for poll(2)
 */
static int esdm_es_ext_server_net_timers(struct esdm_es_ext_server *server)
{
	struct esdm_es_ext_server_net *net = server->net;
	const uint64_t ms = 1000000ULL;
	uint64_t now = esdm_es_ext_server_now(), next = UINT64_MAX, due;
	unsigned int i;

	for (i = 0; i < server->max_clients; i++) {
		struct esdm_es_ext_client *c = &server->clients[i];

		if (c->fd < 0)
			continue;

		if (c->state != ESDM_ES_EXT_CLIENT_DTLS) {
			due = c->accepted +
			      (uint64_t)net->handshake_timeout * 1000 * ms;
			if (now >= due) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_ANY,
					"External ES provider: no handshake from %s in time\n",
					c->addr);
				esdm_es_ext_server_close_client(server, i);
				continue;
			}
		} else if (net->idle_timeout) {
			due = c->active +
			      (uint64_t)net->idle_timeout * 1000 * ms;
			if (now >= due) {
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_ANY,
					"External ES provider: closing the connection of %s, idle for long\n",
					c->addr);
				esdm_es_ext_server_close_client(server, i);
				continue;
			}
		} else {
			continue;
		}
		if (due < next)
			next = due;
	}

	if (net->reload_interval) {
		due = net->last_reload +
		      (uint64_t)net->reload_interval * 1000 * ms;
		if (now >= due) {
			esdm_es_ext_server_net_reload(server, false);
			net->last_reload = now;
			due = now + (uint64_t)net->reload_interval * 1000 * ms;
		}
		if (due < next)
			next = due;
	}

	due = net->last_housekeeping +
	      (uint64_t)ESDM_ES_EXT_SERVER_HOUSEKEEPING_SEC * 1000 * ms;
	if (now >= due) {
		esdm_tls_ctx_crl_report(net->ctx, false);
		/* Expired certificates; revocation is checked by the reload */
		esdm_es_ext_server_net_check(server, NULL);
		net->last_housekeeping = now;
		due = now + (uint64_t)ESDM_ES_EXT_SERVER_HOUSEKEEPING_SEC *
				    1000 * ms;
	}
	if (due < next)
		next = due;

	/* Rounded up, so that the deadline has passed when poll(2) returns */
	return (int)((next - now + ms - 1) / ms);
}

#endif /* ESDM_ES_EXT_NET */

/*
 * Go on with the handshake of client @i.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_handshake(struct esdm_es_ext_server *server,
					 unsigned int i)
{
	struct esdm_es_ext_client *c = &server->clients[i];
	int ret = esdm_dtls_handshake(c->dtls);

	if (!ret) {
#ifdef ESDM_ES_EXT_NET
		if (server->net)
			return esdm_es_ext_server_net_established(server, i);
#endif
		c->state = ESDM_ES_EXT_CLIENT_DTLS;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ANY,
			"External ES provider: client switched to DTLS (%s)\n",
			esdm_dtls_cipher(c->dtls));
		return true;
	}

	if (ret == -EAGAIN)
		return true;

#ifdef ESDM_ES_EXT_NET
	if (server->net) {
		struct esdm_tls *tls = esdm_dtls_tls(c->dtls);

		esdm_logger(ret == -EACCES ? LOGGER_VERBOSE : LOGGER_DEBUG,
			    LOGGER_C_ANY,
			    "External ES provider: handshake with %s failed: %s\n",
			    c->addr, esdm_tls_error(tls));
		esdm_es_ext_server_close_client(server, i);
		return false;
	}
#endif

	esdm_logger(
		LOGGER_WARN, LOGGER_C_ANY,
		"External ES provider: DTLS handshake failed, client disconnected\n");
	esdm_es_ext_server_close_client(server, i);
	return false;
}

/*
 * Receive the next message of client @i into @buf of @len bytes - a request,
 * or one byte more than a request has to tell a longer message.
 *
 * @return the size of the message, which may exceed @len for a message in the
 *	   clear, -EAGAIN if none is there yet, 0 if the client is gone
 */
static ssize_t esdm_es_ext_server_recv(struct esdm_es_ext_server *server,
				       unsigned int i, uint8_t *buf, size_t len)
{
	struct esdm_es_ext_client *c = &server->clients[i];
	ssize_t n;

	if (c->state == ESDM_ES_EXT_CLIENT_DTLS) {
		/* A message longer than a request is -EMSGSIZE: closed */
		n = esdm_dtls_recv(c->dtls, buf, len);
		if (n == -EAGAIN)
			return -EAGAIN;
		return n < 0 ? 0 : n;
	}

	/*
	 * MSG_TRUNC for the real size of the message: a longer one is a
	 * protocol error, not a request cut to size.
	 */
	n = recv(c->fd, buf, len, MSG_DONTWAIT | MSG_TRUNC);
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return -EAGAIN;
	return n < 0 ? 0 : n;
}

/*
 * Send the response @rsp of @len bytes to client @i.
 *
 * The client sends one request at a time and reads the answer, so the answer
 * fits into its receive queue. One that does not read is not waited for.
 *
 * @return true if all of it was sent
 */
static bool esdm_es_ext_server_send(struct esdm_es_ext_server *server,
				    unsigned int i, const uint8_t *rsp,
				    size_t len)
{
	struct esdm_es_ext_client *c = &server->clients[i];

	if (c->state == ESDM_ES_EXT_CLIENT_DTLS)
		return !esdm_dtls_send(c->dtls, rsp, len);

	return send(c->fd, rsp, len, MSG_DONTWAIT | MSG_NOSIGNAL) ==
	       (ssize_t)len;
}

/*
 * Answer a STARTDTLS request of client @i, still in the clear: a handshake is
 * to follow if the server offers DTLS, the client goes on in the clear
 * otherwise.
 *
 * @return the status of the answer
 */
static int esdm_es_ext_server_startdtls(struct esdm_es_ext_server *server,
					unsigned int i)
{
	struct esdm_es_ext_client *c = &server->clients[i];

	if (!server->dtls_ctx)
		return -EOPNOTSUPP;

	/* The requests of the client, nothing larger */
	if (esdm_dtls_alloc(server->dtls_ctx, c->fd, ESDM_ES_EXT_PROTO_REQ_LEN,
			    &c->dtls))
		return -EOPNOTSUPP;

	return 0;
}

/*
 * The status of the plugin as JSON object, NULL for none: for a plugin without
 * one, one whose status fails, and one whose status is no JSON object of up to
 * ESDM_ES_EXT_STATUS_MAX bytes, nested no deeper than
 * ESDM_ES_EXT_STATUS_MAX_DEPTH - checked as the ESDM checks the status of a
 * plugin it loads.
 */
static struct json_object *
esdm_es_ext_server_plugin_status(struct esdm_es_ext_server *server)
{
	char text[ESDM_ES_EXT_STATUS_MAX + 1];
	ssize_t len;

	len = esdm_es_ext_plugin_status(server->plugin, server->ctx, text,
					sizeof(text));
	if (len < 0)
		return NULL;

	return esdm_es_ext_json_object(text, (size_t)len,
				       ESDM_ES_EXT_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH);
}

/* What the server knows itself, for client @i - see STATUS in esdm_es_ext.h */
static struct json_object *
esdm_es_ext_server_fields(struct esdm_es_ext_server *server, unsigned int i)
{
	struct json_object *obj = json_object_new_object();
	uint32_t rate = server->rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				server->rate :
				server->plugin_rate;
	unsigned int c, clients = 0;

	if (!obj)
		return NULL;

	for (c = 0; c < server->max_clients; c++) {
		if (server->clients[c].fd >= 0)
			clients++;
	}

	json_object_object_add(obj, "version", json_object_new_string(VERSION));
	json_object_object_add(obj, "plugin_api",
			       json_object_new_int64(server->plugin->version));
	json_object_object_add(
		obj, "name",
		server->name[0] ? json_object_new_string(server->name) : NULL);
	json_object_object_add(obj, "entropy_rate",
			       rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				       json_object_new_int64(rate) :
				       NULL);
	json_object_object_add(
		obj, "transport",
		json_object_new_string(esdm_es_ext_server_is_net(server) ?
					       "sctp" :
					       "unix"));
	json_object_object_add(
		obj, "dtls",
		json_object_new_boolean(server->clients[i].state ==
					ESDM_ES_EXT_CLIENT_DTLS));
#ifdef ESDM_ES_EXT_NET
	/* Who asks, by the SHA-256 of its certificate */
	if (server->net)
		json_object_object_add(
			obj, "peer",
			json_object_new_string(server->clients[i].fingerprint));
#endif
	json_object_object_add(obj, "clients", json_object_new_int64(clients));
	json_object_object_add(obj, "client_slots",
			       json_object_new_int64(server->max_clients));
	json_object_object_add(
		obj, "requests",
		json_object_new_int64((int64_t)server->requests));
	json_object_object_add(
		obj, "selftest",
		json_object_new_string(server->selftest > 0 ? "none" :
				       !server->selftest    ? "passed" :
							      "failed"));
	json_object_object_add(
		obj, "uptime_seconds",
		json_object_new_int64(
			(int64_t)((esdm_es_ext_server_now() - server->started) /
				  1000000000ULL)));

	return obj;
}

/*
 * Answer a STATUS request of client @i for at most @length bytes, the status
 * going into @data: the fields of the server, and the status of its plugin -
 * left out, as null, if both do not fit into @length together. The text is
 * never cut short: half a JSON object is none.
 *
 * @return the status of the answer, *@datalen holding the length of the text
 */
static int esdm_es_ext_server_status(struct esdm_es_ext_server *server,
				     unsigned int i, uint8_t *data,
				     uint32_t length, uint32_t *datalen)
{
	struct json_object *root = json_object_new_object();
	struct json_object *fields = esdm_es_ext_server_fields(server, i);
	const char *text;
	size_t len;
	int ret = -EMSGSIZE;

	*datalen = 0;
	if (!root || !fields) {
		json_object_put(root);
		json_object_put(fields);
		return -ENOMEM;
	}

	json_object_object_add(root, "server", fields);
	json_object_object_add(root, "plugin",
			       esdm_es_ext_server_plugin_status(server));

	text = json_object_to_json_string_ext(
		root, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	len = text ? strlen(text) : SIZE_MAX;
	if (len > length) {
		/* The fields of the server alone */
		json_object_object_add(root, "plugin", NULL);
		text = json_object_to_json_string_ext(
			root, JSON_C_TO_STRING_PLAIN |
				      JSON_C_TO_STRING_NOSLASHESCAPE);
		len = text ? strlen(text) : SIZE_MAX;
	}

	if (len <= length) {
		memcpy(data, text, len);
		*datalen = (uint32_t)len;
		ret = 0;
	}

	json_object_put(root);
	return ret;
}

/*
 * Take the name of the plugin as the name INFO declares, if it is a valid one
 * - see @name of struct esdm_es_ext_plugin.
 */
static void esdm_es_ext_server_plugin_name(struct esdm_es_ext_server *server)
{
	const char *name = esdm_es_ext_name_or_null(server->plugin->name);

	server->name[0] = '\0';
	if (name)
		snprintf(server->name, sizeof(server->name), "%s", name);
	else if (server->plugin->name)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: the name of the plugin is no name of 1 to %u bytes of UTF-8 without control characters, INFO declares none\n",
			ESDM_ES_EXT_NAME_MAX);
}

/*
 * Serve what client @i has sent: one request, or the next step of its DTLS
 * handshake.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_serve(struct esdm_es_ext_server *server,
				     unsigned int i)
{
	struct esdm_es_ext_client *c = &server->clients[i];
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN + 1];
	uint8_t data[ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint32_t length, datalen, entropy_bits = 0;
	uint16_t type;
	size_t rsp_len;
	ssize_t n;
	int status;
	bool ret = false;

	c->active = esdm_es_ext_server_now();

	if (c->state == ESDM_ES_EXT_CLIENT_HANDSHAKE)
		return esdm_es_ext_server_handshake(server, i);

	n = esdm_es_ext_server_recv(server, i, req, sizeof(req));
	if (n == -EAGAIN)
		return true;
	if (n <= 0)
		goto out;
	if ((size_t)n > sizeof(req) ||
	    esdm_es_ext_proto_req_unpack(req, (size_t)n, &type, &length) ||
	    /*
	     * Once, and in the clear - on the network, the DTLS is there from
	     * the first message on
	     */
	    (type == ESDM_ES_EXT_PROTO_STARTDTLS &&
	     (c->state != ESDM_ES_EXT_CLIENT_PLAIN ||
	      esdm_es_ext_server_is_net(server)))) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: invalid request, client disconnected\n");
		goto out;
	}

	datalen = length;
	switch (type) {
	case ESDM_ES_EXT_PROTO_GET_ENTROPY:
		status = esdm_es_ext_plugin_get(server->plugin, server->ctx,
						data, length, &entropy_bits);
		break;
	case ESDM_ES_EXT_PROTO_STARTDTLS:
		status = esdm_es_ext_server_startdtls(server, i);
		break;
	case ESDM_ES_EXT_PROTO_STATUS:
		status = esdm_es_ext_server_status(server, i, data, length,
						   &datalen);
		break;
	case ESDM_ES_EXT_PROTO_INFO:
		status = 0;
		datalen = esdm_es_ext_proto_info_pack(
			data,
			server->rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				server->rate :
				server->plugin_rate,
			server->name[0] ? server->name : NULL);
		break;
	default:
		status = server->plugin->selftest ?
				 server->plugin->selftest(server->ctx) :
				 0;
		/* An errno, or what it stands for */
		if (status > 0 || status < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
			status = -EIO;
		server->selftest = status;
		break;
	}

	rsp_len = esdm_es_ext_proto_rsp_pack(rsp, type, status, entropy_bits,
					     data, datalen);
	ret = esdm_es_ext_server_send(server, i, rsp, rsp_len);
	if (ret)
		server->requests++;

	/* The answer to STARTDTLS went out in the clear, the handshake follows */
	if (ret && type == ESDM_ES_EXT_PROTO_STARTDTLS && !status)
		c->state = ESDM_ES_EXT_CLIENT_HANDSHAKE;

out:
	memset_secure(data, 0, sizeof(data));
	memset_secure(rsp, 0, sizeof(rsp));
	if (!ret)
		esdm_es_ext_server_close_client(server, i);
	return ret;
}

/*
 * The server with nothing set up yet but its plugin and its slots - see
 * esdm_es_ext_server_free() for undoing it.
 */
static int esdm_es_ext_server_new(const struct esdm_es_ext_plugin *plugin,
				  unsigned int max_clients,
				  unsigned int max_listen,
				  struct esdm_es_ext_server **server)
{
	struct esdm_es_ext_server *s;
	unsigned int i;

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->plugin = plugin;
	s->rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	s->plugin_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	s->selftest = 1;
	s->started = esdm_es_ext_server_now();
	s->stop_pipe[0] = s->stop_pipe[1] = -1;
	for (i = 0; i < ESDM_ES_EXT_NET_MAX_LISTEN; i++)
		s->listen_fds[i] = -1;

	s->max_clients = max_clients;
	s->clients = calloc(max_clients, sizeof(*s->clients));
	/* The stop pipe, the reload pipe, the listeners and the clients */
	s->pfd = calloc(2 + max_listen + max_clients, sizeof(*s->pfd));
	if (!s->clients || !s->pfd) {
		free(s->clients);
		free(s->pfd);
		free(s);
		return -ENOMEM;
	}
	for (i = 0; i < max_clients; i++)
		s->clients[i].fd = -1;

	if (pipe2(s->stop_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
		int ret = -errno;

		esdm_es_ext_server_free(s);
		return ret;
	}

	*server = s;
	return 0;
}

/* Set the plugin up, and what it declares of itself */
static int esdm_es_ext_server_init_plugin(struct esdm_es_ext_server *s)
{
	const struct esdm_es_ext_plugin *plugin = s->plugin;
	int ret;

	if (plugin->init) {
		ret = plugin->init(&s->ctx);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: initialization of %s failed: %s\n",
				plugin->name ? plugin->name : "the plugin",
				strerror(-ret));
			return ret;
		}
	}
	s->initialized = true;
	/* After its init, which may find out what it is and what it has */
	esdm_es_ext_server_plugin_name(s);
	s->plugin_rate = esdm_es_ext_plugin_entropy_rate(plugin, s->ctx);

	/*
	 * Whether the ESDM credits the rate the plugin declares is its
	 * business - worth a line for whoever starts the provider all the same
	 */
	if (s->plugin_rate != ESDM_ES_EXT_PROTO_RATE_NONE)
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_ANY,
			"External ES provider: the plugin declares an entropy rate of %u bits per 256 bits\n",
			s->plugin_rate);

	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server)
{
	struct esdm_es_ext_server *s = NULL;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct stat sb;
	int ret;

	if (!server || !socket_path)
		return -EINVAL;
	*server = NULL;

	if (esdm_es_ext_plugin_check(plugin))
		return -EPROTO;

	if (strlen(socket_path) == 0 ||
	    strlen(socket_path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, socket_path, strlen(socket_path));

	ret = esdm_es_ext_server_new(plugin, ESDM_ES_EXT_SERVER_MAX_CLIENTS, 1,
				     &s);
	if (ret)
		return ret;

	s->path = strdup(socket_path);
	if (!s->path) {
		ret = -ENOMEM;
		goto err;
	}

	/* A socket left behind by an earlier instance, and nothing else */
	if (lstat(socket_path, &sb) == 0) {
		if (!S_ISSOCK(sb.st_mode)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: %s exists and is no socket\n",
				socket_path);
			ret = -EEXIST;
			goto err;
		}
		unlink(socket_path);
	}

	s->listen_fds[0] = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (s->listen_fds[0] < 0) {
		ret = -errno;
		goto err;
	}
	s->listen_num = 1;

	ret = esdm_server_bind_unix(s->listen_fds[0], &addr, mode);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "External ES provider: cannot bind to %s: %s\n",
			    socket_path, strerror(-ret));
		goto err;
	}

	if (lstat(socket_path, &sb) == 0) {
		s->dev = sb.st_dev;
		s->ino = sb.st_ino;
	}

	if (listen(s->listen_fds[0], ESDM_ES_EXT_SERVER_BACKLOG) < 0) {
		ret = -errno;
		goto err;
	}

	ret = esdm_es_ext_server_init_plugin(s);
	if (ret)
		goto err;

#ifdef ESDM_DTLS
	/* Offered by default; a server without it still serves in the clear */
	if (esdm_dtls_ctx_alloc(true, &s->dtls_ctx))
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: DTLS cannot be set up, serving unencrypted\n");
#endif

	*server = s;
	return 0;

err:
	esdm_es_ext_server_free(s);
	return ret;
}

DSO_PUBLIC
void esdm_es_ext_server_net_config_init(
	struct esdm_es_ext_server_net_config *cfg)
{
	if (!cfg)
		return;

	memset(cfg, 0, sizeof(*cfg));
	cfg->size = sizeof(*cfg);
	cfg->reload_interval = 60;
	cfg->max_connections = 64;
	cfg->max_handshakes = 16;
	cfg->max_handshakes_per_source = 4;
	cfg->max_per_client = 4;
	cfg->handshake_timeout = 10;
	cfg->idle_timeout = 600;
}

#ifdef ESDM_ES_EXT_NET

/* Copy a string of the configuration, NULL staying NULL */
static int esdm_es_ext_server_strdup(char **dst, const char *src)
{
	*dst = NULL;
	if (!src)
		return 0;
	*dst = strdup(src);
	return *dst ? 0 : -ENOMEM;
}

/*
 * The configuration of a server on the network, as far as @cfg of a caller
 * has it - the defaults beyond, see struct esdm_es_ext_server_net_config
 */
static void esdm_es_ext_server_net_copy(
	const struct esdm_es_ext_server_net_config *cfg,
	struct esdm_es_ext_server_net_config *full)
{
	esdm_es_ext_server_net_config_init(full);
	memcpy(full, cfg,
	       cfg->size < sizeof(*full) ? cfg->size : sizeof(*full));
	full->size = sizeof(*full);
}

/* Set up the network part of @s from @cfg: the files, the allowlist, bounds */
static int esdm_es_ext_server_net_setup(
	struct esdm_es_ext_server *s,
	const struct esdm_es_ext_server_net_config *cfg)
{
	struct esdm_es_ext_server_net *net;
	unsigned int i;
	int ret;

	net = calloc(1, sizeof(*net));
	if (!net)
		return -ENOMEM;
	s->net = net;
	net->reload_pipe[0] = net->reload_pipe[1] = -1;
	net->probation_limit = (struct esdm_net_limit)ESDM_NET_LIMIT_INIT(
		"source address in its handshake");
	net->client_limit =
		(struct esdm_net_limit)ESDM_NET_LIMIT_INIT("client");
	net->probation_limit.max = cfg->max_handshakes_per_source;
	net->client_limit.max = cfg->max_per_client;
	net->max_handshakes = cfg->max_handshakes;
	net->handshake_timeout = cfg->handshake_timeout;
	net->idle_timeout = cfg->idle_timeout;
	net->reload_interval = cfg->reload_interval;

	if (pipe2(net->reload_pipe, O_CLOEXEC | O_NONBLOCK) < 0)
		return -errno;

	ret = esdm_es_ext_server_strdup(&net->files.cert, cfg->cert_file);
	if (!ret)
		ret = esdm_es_ext_server_strdup(&net->files.key, cfg->key_file);
	if (!ret)
		ret = esdm_es_ext_server_strdup(&net->files.ca, cfg->ca_file);
	if (ret)
		return ret;
	for (i = 0; cfg->crl_files && cfg->crl_files[i]; i++) {
		if (i >= ESDM_ES_EXT_NET_MAX_CRL ||
		    i >= ESDM_TLS_MAX_CRL_FILES) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: more than %u CRL files\n",
				ESDM_ES_EXT_NET_MAX_CRL);
			return -EINVAL;
		}
		ret = esdm_es_ext_server_strdup(&net->files.crl[i],
						cfg->crl_files[i]);
		if (ret)
			return ret;
		net->files.crl_num++;
	}
	net->files.crl_check_all =
		!!(cfg->crl_flags & ESDM_ES_EXT_NET_CRL_CHECK_ALL);
	net->files.crl_allow_expired =
		!!(cfg->crl_flags & ESDM_ES_EXT_NET_CRL_ALLOW_EXPIRED);
	esdm_net_tls_config(&net->files, &net->tls_cfg);
	net->tls_cfg.transport = ESDM_TLS_TRANSPORT_SCTP;

	for (i = 0; cfg->allow && cfg->allow[i]; i++) {
		if (i >= ESDM_NET_MAX_ALLOW ||
		    esdm_net_cidr_parse(cfg->allow[i], &net->allow[i])) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: the allowlist takes up to %u networks such as 192.0.2.0/24 or 2001:db8::/32, not \"%s\"\n",
				ESDM_NET_MAX_ALLOW, cfg->allow[i]);
			return -EINVAL;
		}
		net->allow_num++;
	}

	/* Loaded while the privileges still allow reading them */
	ret = esdm_es_ext_server_net_reload(s, true);
	if (!ret && !net->ctx)
		ret = -EINVAL;
	if (ret)
		return ret;
	net->last_reload = net->last_housekeeping = esdm_es_ext_server_now();

	return 0;
}

/* The listeners of @cfg: those handed over, and those to bind */
static int
esdm_es_ext_server_net_listen(struct esdm_es_ext_server *s,
			      const struct esdm_es_ext_server_net_config *cfg)
{
	int num = 0, ret;
	unsigned int i;

	for (i = 0; i < cfg->listen_fds_num; i++) {
		if (num >= ESDM_ES_EXT_NET_MAX_LISTEN)
			return -EINVAL;
		ret = esdm_net_listener_check(cfg->listen_fds[i],
					      ESDM_NET_LISTENER_SCTP);
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: descriptor %d is no listening SCTP socket of the one-to-one style: %s\n",
				cfg->listen_fds[i], strerror(-ret));
			return ret;
		}
		/* For the associations set up from here on */
		ret = esdm_tls_sctp_prepare(cfg->listen_fds[i]);
		if (ret)
			return ret;
		s->listen_fds[num++] = cfg->listen_fds[i];
		s->listen_num = (unsigned int)num;
	}

	for (i = 0; cfg->listen && cfg->listen[i]; i++) {
		ret = esdm_net_listen(cfg->listen[i], IPPROTO_SCTP,
				      ESDM_ES_EXT_SERVER_NET_BACKLOG,
				      esdm_tls_sctp_prepare, s->listen_fds,
				      &num, ESDM_ES_EXT_NET_MAX_LISTEN);
		s->listen_num = (unsigned int)num;
		if (ret)
			return ret;
	}

	if (!num) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"External ES provider: nothing to listen on on the network\n");
		return -EINVAL;
	}

	return 0;
}

#endif /* ESDM_ES_EXT_NET */

DSO_PUBLIC
int esdm_es_ext_server_alloc_net(const struct esdm_es_ext_plugin *plugin,
				 const struct esdm_es_ext_server_net_config *cfg,
				 struct esdm_es_ext_server **server)
{
#ifdef ESDM_ES_EXT_NET
	struct esdm_es_ext_server_net_config full;
	struct esdm_es_ext_server *s = NULL;
	int ret;

	if (!server || !cfg || cfg->size < sizeof(size_t))
		return -EINVAL;
	*server = NULL;

	if (esdm_es_ext_plugin_check(plugin))
		return -EPROTO;

	esdm_es_ext_server_net_copy(cfg, &full);
	if (!full.max_connections || !full.max_handshakes ||
	    !full.max_handshakes_per_source || !full.max_per_client ||
	    !full.handshake_timeout || !full.cert_file || !full.key_file ||
	    !full.ca_file) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"External ES provider: the network takes a certificate, its key and the trust anchors, and bounds and a handshake timeout other than 0\n");
		return -EINVAL;
	}

	ret = esdm_es_ext_server_new(plugin, full.max_connections,
				     ESDM_ES_EXT_NET_MAX_LISTEN, &s);
	if (ret)
		return ret;

	ret = esdm_es_ext_server_net_setup(s, &full);
	if (!ret)
		ret = esdm_es_ext_server_net_listen(s, &full);
	if (!ret)
		ret = esdm_es_ext_server_init_plugin(s);
	if (ret) {
		esdm_es_ext_server_free(s);
		return ret;
	}

	*server = s;
	return 0;
#else
	(void)plugin;
	(void)cfg;
	if (server)
		*server = NULL;
	return -EOPNOTSUPP;
#endif
}

DSO_PUBLIC
int esdm_es_ext_server_reload(struct esdm_es_ext_server *server)
{
#ifdef ESDM_ES_EXT_NET
	int errsv = errno;
	ssize_t __unused ret;

	if (!server || !server->net)
		return -EINVAL;

	/* async-signal-safe: one write(2) to a non-blocking pipe */
	ret = write(server->net->reload_pipe[1], "", 1);
	errno = errsv;
	return 0;
#else
	(void)server;
	return -EINVAL;
#endif
}

DSO_PUBLIC
int esdm_es_ext_server_allow_uid(struct esdm_es_ext_server *server, uid_t uid)
{
	unsigned int i;

	if (!server || uid == (uid_t)-1 || esdm_es_ext_server_is_net(server))
		return -EINVAL;

	for (i = 0; i < server->allowed_uids_num; i++) {
		if (server->allowed_uids[i] == uid)
			return 0;
	}
	if (server->allowed_uids_num >= ESDM_ES_EXT_SERVER_MAX_UIDS)
		return -ENOSPC;

	server->allowed_uids[server->allowed_uids_num++] = uid;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_name(struct esdm_es_ext_server *server,
				const char *name)
{
	if (!server)
		return -EINVAL;

	if (!name) {
		esdm_es_ext_server_plugin_name(server);
		return 0;
	}

	if (!esdm_es_ext_name_or_null(name))
		return -EINVAL;
	snprintf(server->name, sizeof(server->name), "%s", name);
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_entropy_rate(struct esdm_es_ext_server *server,
					uint32_t rate)
{
	if (!server || (rate > ESDM_ES_EXT_ENTROPY_RATE_MAX &&
			rate != ESDM_ES_EXT_PROTO_RATE_NONE))
		return -EINVAL;

	server->rate = rate;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_dtls(struct esdm_es_ext_server *server, int enable)
{
	if (!server)
		return -EINVAL;

	/* The network has the DTLS with certificates, and nothing else */
	if (esdm_es_ext_server_is_net(server))
		return enable ? 0 : -EINVAL;

	if (!enable) {
		esdm_dtls_ctx_free(server->dtls_ctx);
		server->dtls_ctx = NULL;
		return 0;
	}
	if (server->dtls_ctx)
		return 0;
	return esdm_dtls_ctx_alloc(true, &server->dtls_ctx);
}

/* Drain a pipe of a request, so that it can be made again */
static void esdm_es_ext_server_drain(int fd)
{
	char c;

	while (read(fd, &c, 1) == 1)
		;
}

DSO_PUBLIC
int esdm_es_ext_server_run(struct esdm_es_ext_server *server)
{
	struct pollfd *pfd;
	unsigned int i, first;

	if (!server)
		return -EINVAL;
	pfd = server->pfd;

	for (;;) {
		unsigned int nfds = 0;
		int ret, timeout = -1;

		pfd[nfds++] = (struct pollfd){ .fd = server->stop_pipe[0],
					       .events = POLLIN };
#ifdef ESDM_ES_EXT_NET
		if (server->net) {
			pfd[nfds++] = (struct pollfd){
				.fd = server->net->reload_pipe[0],
				.events = POLLIN
			};
			/* The deadlines that passed, and the next one */
			timeout = esdm_es_ext_server_net_timers(server);
		}
#endif
		first = nfds;
		for (i = 0; i < server->listen_num; i++)
			pfd[nfds++] = (struct pollfd){
				.fd = server->listen_fds[i], .events = POLLIN
			};

		for (i = 0; i < server->max_clients; i++) {
			struct esdm_es_ext_client *c = &server->clients[i];

			pfd[nfds] = (struct pollfd){
				.fd = c->fd,
				/* A handshake may wait for room to send */
				.events = c->state ==
							  ESDM_ES_EXT_CLIENT_HANDSHAKE &&
						  c->dtls ?
						  esdm_dtls_want(c->dtls) :
						  POLLIN
			};
			nfds++;

			/*
			 * A record the DTLS layer holds already - taken off
			 * the socket together with the last step of the
			 * handshake, or with the request before - is not
			 * signaled by the socket any more: do not wait for it.
			 */
			if (c->fd >= 0 && esdm_dtls_pending(c->dtls))
				timeout = 0;
		}

		ret = poll(pfd, nfds, timeout);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (pfd[0].revents)
			break;

#ifdef ESDM_ES_EXT_NET
		if (server->net && pfd[1].revents) {
			esdm_es_ext_server_drain(server->net->reload_pipe[0]);
			esdm_logger(
				LOGGER_STATUS, LOGGER_C_ANY,
				"External ES provider: reloading the TLS files\n");
			esdm_es_ext_server_net_reload(server, true);
			server->net->last_reload = esdm_es_ext_server_now();
		}
#endif

		for (i = 0; i < server->max_clients; i++) {
			struct esdm_es_ext_client *c = &server->clients[i];
			short revents = pfd[first + server->listen_num + i]
						.revents;

			if (c->fd < 0)
				continue;
			/* What the DTLS layer holds is received as well */
			if (esdm_dtls_pending(c->dtls))
				revents |= POLLIN;
			if (!revents)
				continue;
			if (revents & (POLLIN | POLLOUT))
				esdm_es_ext_server_serve(server, i);
			else
				esdm_es_ext_server_close_client(server, i);
		}

		/* After the clients, so a new one is not served in this round */
		for (i = 0; i < server->listen_num; i++) {
			if (!(pfd[first + i].revents & POLLIN))
				continue;
#ifdef ESDM_ES_EXT_NET
			if (server->net) {
				esdm_es_ext_server_net_accept(
					server, server->listen_fds[i]);
				continue;
			}
#endif
			esdm_es_ext_server_accept(server,
						  server->listen_fds[i]);
		}
	}

	/* Drain the stop request, so that the server can be run again */
	esdm_es_ext_server_drain(server->stop_pipe[0]);

	return 0;
}

DSO_PUBLIC
void esdm_es_ext_server_stop(struct esdm_es_ext_server *server)
{
	int errsv = errno;
	ssize_t __unused ret;

	if (!server)
		return;

	/* async-signal-safe: one write(2) to a non-blocking pipe */
	ret = write(server->stop_pipe[1], "", 1);
	errno = errsv;
}

DSO_PUBLIC
void esdm_es_ext_server_free(struct esdm_es_ext_server *server)
{
	struct stat sb;
	unsigned int i;

	if (!server)
		return;

	for (i = 0; server->clients && i < server->max_clients; i++)
		esdm_es_ext_server_close_client(server, i);

	for (i = 0; i < server->listen_num; i++) {
		if (server->listen_fds[i] >= 0)
			close(server->listen_fds[i]);
	}

	/* Only the socket created here, not one another instance made */
	if (server->path && server->listen_num && lstat(server->path, &sb) == 0 &&
	    sb.st_dev == server->dev && sb.st_ino == server->ino)
		unlink(server->path);

	if (server->initialized && server->plugin->fini)
		server->plugin->fini(server->ctx);

	esdm_dtls_ctx_free(server->dtls_ctx);

#ifdef ESDM_ES_EXT_NET
	if (server->net) {
		struct esdm_es_ext_server_net *net = server->net;

		esdm_tls_ctx_put(net->ctx);
		esdm_net_tls_files_free(&net->files);
		esdm_net_limit_clear(&net->probation_limit);
		esdm_net_limit_clear(&net->client_limit);
		if (net->reload_pipe[0] >= 0)
			close(net->reload_pipe[0]);
		if (net->reload_pipe[1] >= 0)
			close(net->reload_pipe[1]);
		free(net);
	}
#endif

	if (server->stop_pipe[0] >= 0)
		close(server->stop_pipe[0]);
	if (server->stop_pipe[1] >= 0)
		close(server->stop_pipe[1]);

	free(server->clients);
	free(server->pfd);
	free(server->path);
	free(server);
}
