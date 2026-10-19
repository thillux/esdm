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
 * esdm-egd-net-relay: the EGD socket of a host without an ESDM, served by an
 * esdm-egd-net-server on another host - see esdm-egd-net-relay(8).
 *
 * The legacy consumers of the EGD protocol - libgcrypt's rndegd, OpenSSL's
 * RAND_egd(), the EGD provider of the ESDM - know nothing but a Unix domain
 * socket. The relay serves them one, where they look for it, and forwards
 * every command to the server over the network: TLS, or plain TCP on a
 * network protected underneath. A sandboxed consumer keeps its syscall
 * discipline this way, which the TLS mode of libesdm_egd_client does not.
 *
 * Every local connection has an upstream connection of its own - a client of
 * libesdm_egd_client in its network mode -, which keeps the order of the
 * answers as the consumer expects it, and lets the library's reconnect hide a
 * restart of the server between two commands. The local connections are
 * bounded per user, as those of the esdm-server's EGD socket are.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
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
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "egd_net_common.h"
#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_serve.h"
#include "esdm_logger.h"
#include "esdm_peer_account.h"
#include "esdm_peer_limit.h"
#include "esdm_server_socket.h"
#include "esdm_tls.h"
#include "privileges.h"
#include "systemd_support.h"

/* Set by the build, see frontends/egd-net/meson.build */
#ifndef ESDM_EGD_NET_VERSION
#define ESDM_EGD_NET_VERSION "unknown"
#endif

#define RELAY_NAME "esdm-egd-net-relay"

#define RELAY_BACKLOG 128
#define RELAY_HOUSEKEEPING_SEC 30
#define RELAY_STOP_WAIT_MS 5000

struct relay_conn {
	int fd;
	char peer[64];
	uid_t account;
	bool account_counted;
	struct esdm_egd_client *upstream;
	TAILQ_ENTRY(relay_conn) tailq;
};
TAILQ_HEAD(relay_conn_list, relay_conn);

static struct {
	const char *socket_path;
	const char *connect;
	bool plain;
	struct esdm_net_tls_files files;
	const char *server_name;
	unsigned int reload_interval;
	unsigned int timeout;
	unsigned int max_connections;
	unsigned int max_per_uid;
	unsigned int idle_timeout;
	unsigned int io_timeout;
} relay_cfg = {
	.socket_path = ESDM_SERVER_EGD_SOCKET_PATH,
	.reload_interval = 60,
	.timeout = 30,
	/*
	 * Each local connection takes one to the server, all of them with the
	 * one certificate: no more than the server serves per client by
	 * default, see its max_per_client.
	 */
	.max_connections = 64,
	.max_per_uid = 16,
	.idle_timeout = 0,
	.io_timeout = 30,
};

static pthread_mutex_t relay_conns_lock = PTHREAD_MUTEX_INITIALIZER;
static struct relay_conn_list relay_conns = TAILQ_HEAD_INITIALIZER(relay_conns);
static unsigned int relay_conn_num = 0;
static struct esdm_peer_limit relay_peer_limit =
	ESDM_PEER_LIMIT_INIT("EGD relay", 64);
static struct esdm_egd_serve_pool relay_pool = ESDM_EGD_SERVE_POOL_INIT;

/*
 * TLS mode: a context of the files, kept to report the state of the CRLs and
 * to check a rotation of the files as soon as it happens. The upstream
 * connections take the files up themselves, see the network modes of
 * esdm_egd_client.h.
 */
static struct esdm_tls_ctx *relay_ctx = NULL;
static uint8_t relay_stamp[ESDM_TLS_STAMP_LEN];

/******************************************************************************
 * The backend: the server of the network, by libesdm_egd_client
 ******************************************************************************/

static int relay_be_entropy_count(void *be, uint32_t *bits)
{
	struct relay_conn *conn = be;

	return esdm_egd_client_entropy_count(conn->upstream, bits);
}

static int relay_be_get_random(void *be, enum esdm_egd_serve_read kind,
			       uint8_t *buf, size_t len, size_t *generated)
{
	struct relay_conn *conn = be;
	int ret;

	*generated = 0;

	switch (kind) {
	case ESDM_EGD_SERVE_FULL:
		ret = esdm_egd_client_get_random(conn->upstream, buf, len);
		if (!ret)
			*generated = len;
		return ret;
	case ESDM_EGD_SERVE_PR:
		ret = esdm_egd_client_get_random_pr(conn->upstream, buf, len);
		if (!ret)
			*generated = len;
		return ret;
	case ESDM_EGD_SERVE_FULL_NONBLOCK:
		return esdm_egd_client_get_random_nonblock(conn->upstream, buf,
							   len, generated);
	case ESDM_EGD_SERVE_PR_NONBLOCK:
		return esdm_egd_client_get_random_pr_nonblock(
			conn->upstream, buf, len, generated);
	case ESDM_EGD_SERVE_UNSEEDED:
		return esdm_egd_client_get_random_unseeded(conn->upstream, buf,
							   len, generated);
	default:
		return -EINVAL;
	}
}

static int relay_be_get_state(void *be, uint32_t *fields, unsigned int room,
			      unsigned int *num)
{
	struct relay_conn *conn = be;
	unsigned int n = room;
	int ret;

	/* As many as the server reports, forwarded as they come */
	ret = esdm_egd_client_get_state(conn->upstream, fields, &n);
	if (ret)
		return ret;
	*num = n < room ? n : room;
	return 0;
}

static int relay_be_status(void *be, bool json, char *buf, size_t buflen,
			   size_t *len)
{
	struct relay_conn *conn = be;
	int ret = json ? esdm_egd_client_status_json(conn->upstream, buf,
						     buflen) :
			 esdm_egd_client_status(conn->upstream, buf, buflen);

	*len = 0;
	if (ret < 0)
		return ret;
	*len = (size_t)ret;
	return 0;
}

static int relay_be_write_data(void *be, const uint8_t *buf, size_t len)
{
	struct relay_conn *conn = be;

	/* The claim was dropped already, the server would drop it as well */
	return esdm_egd_client_write_entropy(conn->upstream, buf, len, 0);
}

static const struct esdm_egd_serve_ops relay_ops = {
	.entropy_count = relay_be_entropy_count,
	.get_random = relay_be_get_random,
	.get_state = relay_be_get_state,
	.status = relay_be_status,
	.write_data = relay_be_write_data,
};

/******************************************************************************
 * The local connection
 ******************************************************************************/

static uint64_t relay_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static int relay_left_ms(uint64_t start, int timeout_ms)
{
	uint64_t now = relay_now_ms();

	if (timeout_ms < 0)
		return -1;
	if (now - start >= (uint64_t)timeout_ms)
		return 0;
	return timeout_ms - (int)(now - start);
}

static int relay_wait_fd(int fd, short events, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	uint64_t start = relay_now_ms();
	int ret;

	while ((ret = poll(&pfd, 1, relay_left_ms(start, timeout_ms))) < 0 &&
	       errno == EINTR)
		;
	if (ret < 0)
		return -errno;
	return ret ? 0 : -ETIMEDOUT;
}

static ssize_t relay_read(void *io, uint8_t *buf, size_t len, int timeout_ms)
{
	struct relay_conn *conn = io;
	uint64_t start = relay_now_ms();

	for (;;) {
		ssize_t n = recv(conn->fd, buf, len, MSG_DONTWAIT);
		int ret;

		if (n >= 0)
			return n;
		if (errno == EINTR)
			continue;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			return -errno;

		ret = relay_wait_fd(conn->fd, POLLIN,
				    relay_left_ms(start, timeout_ms));
		if (ret)
			return ret;
	}
}

static int relay_write(void *io, const uint8_t *buf, size_t len,
		       int timeout_ms)
{
	struct relay_conn *conn = io;
	uint64_t start = relay_now_ms();
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

		ret = relay_wait_fd(conn->fd, POLLOUT,
				    relay_left_ms(start, timeout_ms));
		if (ret)
			return ret;
	}

	return 0;
}

static const struct esdm_egd_serve_io relay_io = {
	.read = relay_read,
	.write = relay_write,
};

/* The upstream client of a local connection */
static int relay_upstream(struct relay_conn *conn)
{
	struct esdm_egd_client_net_config cfg;
	const char *crls[ESDM_TLS_MAX_CRL_FILES + 1];
	unsigned int i;

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.address = relay_cfg.connect;
	cfg.timeout_ms = relay_cfg.timeout * 1000;

	if (relay_cfg.plain) {
		cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	} else {
		cfg.mode = ESDM_EGD_CLIENT_NET_TLS;
		cfg.cert_file = relay_cfg.files.cert;
		cfg.key_file = relay_cfg.files.key;
		cfg.ca_file = relay_cfg.files.ca;
		cfg.server_name = relay_cfg.server_name;
		for (i = 0; i < relay_cfg.files.crl_num; i++)
			crls[i] = relay_cfg.files.crl[i];
		crls[i] = NULL;
		cfg.crl_files = relay_cfg.files.crl_num ? crls : NULL;
		cfg.crl_flags =
			(relay_cfg.files.crl_check_all ?
				 ESDM_EGD_CLIENT_NET_CRL_CHECK_ALL :
				 0) |
			(relay_cfg.files.crl_allow_expired ?
				 ESDM_EGD_CLIENT_NET_CRL_ALLOW_EXPIRED :
				 0);
	}

	return esdm_egd_client_alloc_net(&conn->upstream, &cfg);
}

static void relay_conn_release(struct relay_conn *conn)
{
	pthread_mutex_lock(&relay_conns_lock);
	TAILQ_REMOVE(&relay_conns, conn, tailq);
	relay_conn_num--;
	pthread_mutex_unlock(&relay_conns_lock);

	if (conn->account_counted)
		esdm_peer_limit_put(&relay_peer_limit, conn->account);
	esdm_egd_client_free(conn->upstream);
	close(conn->fd);
	free(conn);
}

static void *relay_conn_thread(void *arg)
{
	struct relay_conn *conn = arg;
	struct esdm_egd_serve_conn serve = {
		.io = &relay_io,
		.io_ctx = conn,
		.ops = &relay_ops,
		.be = conn,
		.peer = conn->peer,
		.idle_timeout_ms = relay_cfg.idle_timeout * 1000,
		.io_timeout_ms = relay_cfg.io_timeout * 1000,
		.stop = &relay_pool.stop,
	};
	int ret;

	/*
	 * Made here rather than in the main thread: connecting takes a
	 * round trip, a handshake, and the files of the TLS when they changed.
	 */
	ret = relay_upstream(conn);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "%s: no upstream client for %s: %s\n", RELAY_NAME,
			    conn->peer, strerror(-ret));
		goto out;
	}

	ret = esdm_egd_serve(&serve);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "%s: connection of %s ended: %s\n", RELAY_NAME, conn->peer,
		    ret ? strerror(-ret) : "closed by the client");

out:
	relay_conn_release(conn);
	esdm_egd_serve_pool_done(&relay_pool);
	return NULL;
}

static void relay_accept(int lfd)
{
	struct relay_conn *conn;
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	int fd, ret;

	fd = accept4(lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (fd < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
				    "%s: cannot accept: %s\n", RELAY_NAME,
				    strerror(errno));
		return;
	}

	conn = calloc(1, sizeof(*conn));
	if (!conn) {
		close(fd);
		return;
	}
	conn->fd = fd;

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "%s: cannot obtain the peer credentials: %s\n",
			    RELAY_NAME, strerror(errno));
		free(conn);
		close(fd);
		return;
	}
	snprintf(conn->peer, sizeof(conn->peer), "UID %u PID %d",
		 (unsigned int)cred.uid, (int)cred.pid);

	pthread_mutex_lock(&relay_conns_lock);
	if (relay_conn_num >= relay_cfg.max_connections) {
		pthread_mutex_unlock(&relay_conns_lock);
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "%s: refusing %s, all slots are taken\n",
			    RELAY_NAME, conn->peer);
		free(conn);
		close(fd);
		return;
	}
	relay_conn_num++;
	TAILQ_INSERT_TAIL(&relay_conns, conn, tailq);
	pthread_mutex_unlock(&relay_conns_lock);

	/* The user the peer acts for, see esdm_peer_account.h */
	conn->account = esdm_peer_account(fd, &cred);
	if (!esdm_peer_limit_get(&relay_peer_limit, conn->account)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "%s: refusing %s (user %u)\n", RELAY_NAME,
			    conn->peer, (unsigned int)conn->account);
		relay_conn_release(conn);
		return;
	}
	conn->account_counted = true;

	ret = esdm_egd_serve_pool_spawn(&relay_pool, relay_conn_thread, conn);
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: cannot start a thread for %s: %s\n",
			    RELAY_NAME, conn->peer, strerror(-ret));
		relay_conn_release(conn);
	}
}

/*
 * TLS mode: check the files - at start, on SIGHUP and when they changed - so
 * a rotation that does not load is reported at once, rather than at the next
 * connection, and report the CRLs.
 */
static int relay_reload(bool force)
{
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL;
	int ret;

	esdm_net_tls_config(&relay_cfg.files, &cfg);
	ret = esdm_net_tls_reload(RELAY_NAME, false, &cfg, force, relay_stamp,
				  &ctx);
	if (ret <= 0)
		return ret;

	esdm_tls_ctx_put(relay_ctx);
	relay_ctx = ctx;
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "%s: the TLS files of %s load\n", RELAY_NAME,
		    relay_cfg.files.cert);
	esdm_tls_ctx_crl_report(ctx, true);

	return 0;
}

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

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

/* Bind the local socket, accessible to everybody - like the ESDM's */
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

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/*
	 * The mode is the file's from its creation on, see
	 * esdm_server_bind_unix(): the consumers are ordinary applications of
	 * every user, and nothing reachable is privileged.
	 */
	ret = esdm_server_bind_unix(fd, &addr, 0666);
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

static void usage(void)
{
	fprintf(stderr, "\nESDM EGD network relay\n\n");
	fprintf(stderr, "%s %s, TLS by %s\n\n", RELAY_NAME,
		ESDM_EGD_NET_VERSION, esdm_tls_stack());
	fprintf(stderr, "Usage: %s --connect <HOST[:PORT]> [OPTIONS]\n\n",
		RELAY_NAME);
	fprintf(stderr,
		"\t-C --connect <HOST[:PORT]>\tThe esdm-egd-net-server; [IPv6]:PORT\n"
		"\t-s --socket <PATH>\tLocal EGD socket (default: %s),\n"
		"\t\t\t\tunless one comes from socket activation\n"
		"\t   --plain\t\tPlain TCP, no TLS - only on a network protected\n"
		"\t\t\t\tunderneath, never a default\n"
		"\t   --cert <FILE>\tCertificate of the relay, PEM\n"
		"\t   --key <FILE>\t\tIts private key, PEM, PKCS#8\n"
		"\t   --ca <FILE>\t\tTrust anchors the server must chain to, PEM\n"
		"\t   --server_name <NAME>\tName the server's certificate is issued\n"
		"\t\t\t\tfor (default: the host of --connect)\n"
		"\t   --crl <FILE>\t\tCRLs, PEM; may be repeated\n"
		"\t   --crl_check_all\tRequire CRLs of the CA certificates as well\n"
		"\t   --crl_allow_expired\tOnly warn of a CRL past its nextUpdate\n"
		"\t   --reload_interval <SEC>\tCheck the TLS files for a change\n"
		"\t\t\t\tthis often, 0 for never (default 60)\n"
		"\t   --timeout <SEC>\tBound of a step upstream (default 30)\n"
		"\t   --max_connections <N>\tLocal connections, each with one to\n"
		"\t\t\t\tthe server (default 64)\n"
		"\t   --max_per_uid <N>\tLocal connections per user (default 16)\n"
		"\t   --idle_timeout <SEC>\tSilence after which a local connection\n"
		"\t\t\t\tis closed, 0 for never (default 0)\n"
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
		"--cert, --key and --ca, the credentials cert, key and ca are used.\n",
		ESDM_SERVER_EGD_SOCKET_PATH);
}

enum {
	OPT_PLAIN = 256,
	OPT_CERT,
	OPT_KEY,
	OPT_CA,
	OPT_SERVER_NAME,
	OPT_CRL,
	OPT_CRL_CHECK_ALL,
	OPT_CRL_ALLOW_EXPIRED,
	OPT_RELOAD_INTERVAL,
	OPT_TIMEOUT,
	OPT_MAX_CONNECTIONS,
	OPT_MAX_PER_UID,
	OPT_IDLE_TIMEOUT,
	OPT_IO_TIMEOUT,
	OPT_VERSION,
};

static int relay_set_file(char **file, const char *arg)
{
	free(*file);
	*file = strdup(arg);
	return *file ? 0 : -ENOMEM;
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "connect", required_argument, NULL, 'C' },
		{ "socket", required_argument, NULL, 's' },
		{ "plain", no_argument, NULL, OPT_PLAIN },
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
		{ "timeout", required_argument, NULL, OPT_TIMEOUT },
		{ "max_connections", required_argument, NULL,
		  OPT_MAX_CONNECTIONS },
		{ "max_per_uid", required_argument, NULL, OPT_MAX_PER_UID },
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
	const char *username = "nobody", *groupname = NULL;
	struct pollfd pfds[2];
	int lfds[ESDM_NET_MAX_LISTEN];
	int lfd = -1, sfd = -1, c, ret = 1, n;
	bool tls_option = false, bound = false, socket_given = false;
	uint64_t last_reload, last_housekeeping;
	sigset_t mask;

	/*
	 * Warnings and errors are shown without -v: a broken rotation, a CRL
	 * about to expire and plain TCP are for the administrator to see.
	 */
	esdm_logger_set_verbosity(LOGGER_WARN);

	while ((c = getopt_long(argc, argv, "C:s:u:g:Svh", opts, NULL)) !=
	       -1) {
		switch (c) {
		case 'C':
			relay_cfg.connect = optarg;
			break;
		case 's':
			relay_cfg.socket_path = optarg;
			socket_given = true;
			break;
		case OPT_PLAIN:
			relay_cfg.plain = true;
			break;
		case OPT_CERT:
			tls_option = true;
			if (relay_set_file(&relay_cfg.files.cert, optarg))
				return 1;
			break;
		case OPT_KEY:
			tls_option = true;
			if (relay_set_file(&relay_cfg.files.key, optarg))
				return 1;
			break;
		case OPT_CA:
			tls_option = true;
			if (relay_set_file(&relay_cfg.files.ca, optarg))
				return 1;
			break;
		case OPT_SERVER_NAME:
			tls_option = true;
			relay_cfg.server_name = optarg;
			break;
		case OPT_CRL:
			tls_option = true;
			if (relay_cfg.files.crl_num >= ESDM_TLS_MAX_CRL_FILES) {
				fprintf(stderr,
					"--crl may be given %u times at most\n",
					ESDM_TLS_MAX_CRL_FILES);
				return 1;
			}
			relay_cfg.files.crl[relay_cfg.files.crl_num] =
				strdup(optarg);
			if (!relay_cfg.files.crl[relay_cfg.files.crl_num++])
				return 1;
			break;
		case OPT_CRL_CHECK_ALL:
			tls_option = true;
			relay_cfg.files.crl_check_all = true;
			break;
		case OPT_CRL_ALLOW_EXPIRED:
			tls_option = true;
			relay_cfg.files.crl_allow_expired = true;
			break;
		case OPT_RELOAD_INTERVAL:
			if (esdm_net_parse_uint("reload_interval", optarg,
					       86400 * 365,
					       &relay_cfg.reload_interval))
				return 1;
			break;
		case OPT_TIMEOUT:
			if (esdm_net_parse_uint("timeout", optarg, 3600,
					       &relay_cfg.timeout))
				return 1;
			break;
		case OPT_MAX_CONNECTIONS:
			if (esdm_net_parse_uint("max_connections", optarg,
					       1000000,
					       &relay_cfg.max_connections))
				return 1;
			break;
		case OPT_MAX_PER_UID:
			if (esdm_net_parse_uint("max_per_uid", optarg, 1000000,
					       &relay_cfg.max_per_uid))
				return 1;
			break;
		case OPT_IDLE_TIMEOUT:
			if (esdm_net_parse_uint("idle_timeout", optarg, 86400 * 7,
					       &relay_cfg.idle_timeout))
				return 1;
			break;
		case OPT_IO_TIMEOUT:
			if (esdm_net_parse_uint("io_timeout", optarg, 3600,
					       &relay_cfg.io_timeout))
				return 1;
			break;
		case 'u':
			username = optarg;
			break;
		case 'g':
			groupname = optarg;
			break;
		case 'S':
			esdm_logger_enable_syslog(RELAY_NAME);
			break;
		case 'v':
			esdm_logger_inc_verbosity();
			break;
		case OPT_VERSION:
			printf("%s %s\n", RELAY_NAME, ESDM_EGD_NET_VERSION);
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
	if (!relay_cfg.timeout || !relay_cfg.max_connections ||
	    !relay_cfg.max_per_uid || !relay_cfg.io_timeout) {
		fprintf(stderr,
			"The bounds of the connections and the timeouts must not be 0\n");
		return 1;
	}
	relay_peer_limit.max_per_uid = relay_cfg.max_per_uid;

	/* Plain TCP only on request, TLS only with what it needs */
	if (egd_net_tls_files_resolve(&relay_cfg.files, relay_cfg.plain,
				      tls_option))
		return 1;

	if (relay_cfg.plain) {
		egd_net_plain_warning(RELAY_NAME);
	} else if (relay_reload(true)) {
		fprintf(stderr, "The TLS files do not load\n");
		goto out;
	}

	/* While the privileges are still held, see esdm_peer_account.h */
	esdm_peer_account_init();

	/* A socket of socket activation, unless one is asked for explicitly */
	n = socket_given ? 0 : esdm_net_listen_fds(lfds, ESDM_NET_MAX_LISTEN);
	if (n > 0) {
		if (esdm_net_listener_check(lfds[0], ESDM_NET_LISTENER_UNIX)) {
			fprintf(stderr,
				"The socket handed over is no listening Unix domain stream socket\n");
			goto out;
		}
		lfd = lfds[0];
		while (n-- > 1)
			close(lfds[n]);
	} else {
		if (relay_bind(&lfd))
			goto out;
		bound = true;
	}

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
	signal(SIGPIPE, SIG_IGN);

	if (!getuid()) {
		if (drop_privileges_permanent(username, groupname)) {
			fprintf(stderr, "Cannot drop the privileges to %s\n",
				username);
			goto out;
		}
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "%s: relaying %s to %s over %s\n", RELAY_NAME,
		    bound ? relay_cfg.socket_path :
			    "the socket of socket activation",
		    relay_cfg.connect,
		    relay_cfg.plain ? "plain TCP" : "TLS 1.3");
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

		if (relay_cfg.plain)
			continue;

		now = relay_now_ms();
		if (hup || (relay_cfg.reload_interval &&
			    now - last_reload >=
				    (uint64_t)relay_cfg.reload_interval * 1000)) {
			relay_reload(hup);
			last_reload = now;
		}
		if (now - last_housekeeping >= RELAY_HOUSEKEEPING_SEC * 1000) {
			last_housekeeping = now;
			esdm_tls_ctx_crl_report(relay_ctx, false);
		}
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "%s: shutting down\n",
		    RELAY_NAME);
	systemd_notify_stopping();
	ret = 0;

	atomic_store(&relay_pool.stop, true);
	{
		struct relay_conn *conn;

		pthread_mutex_lock(&relay_conns_lock);
		TAILQ_FOREACH (conn, &relay_conns, tailq)
			shutdown(conn->fd, SHUT_RDWR);
		pthread_mutex_unlock(&relay_conns_lock);
	}
	/*
	 * A thread waiting upstream finishes within its timeout; the process
	 * does not wait that long for it - and leaves without the handlers
	 * exit(3) runs, which would tear the state of the TLS stack down under
	 * the thread.
	 */
	if (esdm_egd_serve_pool_stop(&relay_pool, RELAY_STOP_WAIT_MS)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "%s: connections still busy at exit\n",
			    RELAY_NAME);
		if (bound)
			unlink(relay_cfg.socket_path);
		_exit(0);
	}

out:
	if (lfd >= 0) {
		close(lfd);
		/* A socket of socket activation is systemd's to remove */
		if (bound)
			unlink(relay_cfg.socket_path);
	}
	if (sfd >= 0)
		close(sfd);
	esdm_tls_ctx_put(relay_ctx);
	esdm_net_tls_files_free(&relay_cfg.files);
	return ret;
}
