/*
 * ESDM External Entropy Source: provider process connected over a Unix socket
 *
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
 * An external entropy source served by a process of its own on a Unix domain
 * socket - see the protocol in esdm_es_ext.h and libesdm_es_ext(3).
 *
 * The source holds one connection to the provider and sends one request at a
 * time on it, under the mutex of the source. Anything going wrong on the
 * connection - an error, a provider that does not answer in time, an answer
 * breaking the protocol - closes it: an answer arriving late would otherwise
 * be taken for the one to the next request. A new connection is made on
 * demand, at most every ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC seconds after a
 * failed attempt or a connection given up on. What the ESDM asks of the source
 * while a request may be in progress - the entropy available, its state in the
 * ESDM status - is taken from what the source publishes whenever it releases
 * its mutex, not waited for.
 *
 * The provider is asked what it declares of itself once per connection, with
 * the INFO request: the source is shown under the name it declares, if it is a
 * valid one, in place of its name in the ES table, and credited at the rate it
 * declares unless one is configured. A provider older than INFO is connected
 * to again without asking, and is used without a name and a rate.
 *
 * Whoever can create the socket file at the configured path could feed the
 * ESDM with data credited as entropy, so the credentials of the provider are
 * checked on every connection: root, or the one uid configured in addition.
 *
 * A block is credited with what the provider claims for it, at most with what
 * the rate of the source allows (esdm_config_es_ext_socket_entropy_rate()):
 * the one configured, else the one the provider declares in its answer to
 * INFO, else 0 - see esdm_es_extsock_rate(). A
 * provider that fails is credited with nothing until it delivers again, on a
 * seeding that asks it or on a probe of the ES monitor; one failing its self
 * test is credited with nothing until a self test passes. Nor is a provider
 * credited before its first self test since the source was set up: the self
 * test pass of the ESDM runs before its first seeding, and a provider that was
 * not connected then is tested on the first connection to it.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <limits.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_ext.h"
#include "esdm_dtls.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_ext_status.h"
#include "esdm_es_extsock.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "visibility.h"

/* The size of the path of a Unix domain socket, its NUL included */
#define ESDM_ES_EXTSOCK_PATH_SIZE sizeof(((struct sockaddr_un *)0)->sun_path)

/*
 * A provider socket source. All of its state is here: the ES manager calls the
 * source through callbacks that take no context, each of which hands the one
 * instance it belongs to to the functions below - see ESDM_ES_EXTSOCK_CB.
 */
struct esdm_es_extsock {
	/* Index of the source among the provider socket sources */
	unsigned int idx;

	/*
	 * How the log messages name the source: by its name in the ES table if
	 * it is one of several of its kind, not at all otherwise - and what
	 * they call it for its status
	 */
	const char *tag;
	const char *who;

	/* Held for every request to the provider, see above */
	mutex_t mutex;

	/*
	 * The compile-time default of the socket path, the entry of the source
	 * in the meson option es_ext_socket_path - and its override, as given
	 * on the command line of the server, NULL for none. Configuration like
	 * the entropy rates: it outlives esdm_fini().
	 */
	const char *default_path;
	char *runtime_path;

	/* The uid accepted next to root, -1 for none - configuration as well */
	int64_t peer_uid;

	int fd;
	/* The uid of the provider connected to */
	uid_t connected_uid;

	/*
	 * The name the provider declared on its last connection, if it is
	 * valid - empty for none
	 */
	char name[ESDM_ES_EXT_NAME_MAX + 1];

	/*
	 * The rate the provider declared on its last connection,
	 * ESDM_ES_EXT_PROTO_RATE_NONE for none
	 */
	uint32_t rate;

	/*
	 * The DTLS of the connection, NULL while it is unencrypted - see
	 * esdm_dtls.h and esdm_es_ext.h on the opportunistic DTLS. The context
	 * is set up on first use.
	 */
	struct esdm_dtls_ctx *dtls_ctx;
	struct esdm_dtls *dtls;

	/*
	 * The last request to the provider failed, or its last self test did.
	 * Kept apart as for the plugin source: only data delivered clears a
	 * failed request, only a self test that passes clears a failed self
	 * test - not a new connection either. Set and cleared under the write
	 * lock, read under the reader lock.
	 */
	bool read_failed;
	bool selftest_failed;

	/*
	 * No self test of the provider was answered since the source was set
	 * up, and the provider is credited with nothing until one was: the next
	 * connection runs one first. Under the same lock as the failures.
	 */
	bool selftest_due;

	/*
	 * Earliest time to connect again, and to probe a provider whose
	 * request failed, monotonic seconds
	 */
	time_t retry_at;
	time_t probe_at;

	/* Connected once since the source was set up - the first one is logged */
	bool was_connected;

	/*
	 * What was logged last, so that a provider away for long is not logged
	 * on every connection attempt
	 */
	int last_logged;

	/*
	 * The provider connected to refused STATUS - it closed the connection
	 * on it, as a provider does on a request it does not know - and is not
	 * asked again on this connection. The last status it sent was none and
	 * logged as such.
	 */
	bool status_refused;
	bool status_warned;

	/*
	 * The provider did not answer STATUS in time, and is not asked for its
	 * status before this time, monotonic seconds
	 */
	time_t status_backoff_until;

	/*
	 * What is read of the source without the mutex, which a request holds
	 * for up to ESDM_EXT_SOCKET_TIMEOUT_MS: the ESDM status, and the
	 * entropy available, are not to wait for that - see esdm_es_mgr_cb.h.
	 * Published by esdm_es_extsock_unlock() whenever the write lock is
	 * released; the state and the status of the provider under
	 * state_mutex, which is held for copying only.
	 */
	atomic_bool published_configured;
	atomic_bool published_credited;
	atomic_uint published_rate;
	mutex_t state_mutex;
	char state_path[ESDM_ES_EXTSOCK_PATH_SIZE];
	char state_status[64];
	char state_name[ESDM_ES_EXT_NAME_MAX + 1];
	int64_t state_peer_uid;
	struct esdm_es_ext_status_cache status;
};

#if ESDM_EXT_SOCKET_NUM > 1
#define ESDM_ES_EXTSOCK_TAG(i) " " ESDM_ES_EXTSOCK_NAME(i)
#else
#define ESDM_ES_EXTSOCK_TAG(i) ""
#endif

#define ESDM_ES_EXTSOCK_INSTANCE(i)                                            \
	[i] = {                                                                \
		.idx = i,                                                      \
		.tag = ESDM_ES_EXTSOCK_TAG(i),                                 \
		.who = "provider" ESDM_ES_EXTSOCK_TAG(i),                      \
		.mutex = MUTEX_UNLOCKED,                                       \
		.default_path = ESDM_EXT_SOCKET_PATH_##i,                      \
		.rate = ESDM_ES_EXT_PROTO_RATE_NONE,                           \
		.published_rate = ESDM_ES_EXT_PROTO_RATE_NONE,                 \
		.peer_uid = ESDM_EXT_SOCKET_PEER_UID_##i,                      \
		.fd = -1,                                                      \
		.state_mutex = MUTEX_UNLOCKED,                                 \
		.state_status = "not connected",                               \
		.state_peer_uid = ESDM_EXT_SOCKET_PEER_UID_##i,                \
	},

/* The provider socket sources, ESDM_EXT_SOCKET_NUM of them */
static struct esdm_es_extsock extsock[ESDM_EXT_SOCKET_NUM] = {
	ESDM_EXT_SOCKET_INSTANCES(ESDM_ES_EXTSOCK_INSTANCE)
};

/* Caller must hold the mutex of @sock. */
static const char *
esdm_es_extsock_path_locked(const struct esdm_es_extsock *sock)
{
	return sock->runtime_path ? sock->runtime_path : sock->default_path;
}

/* Caller must hold the mutex of @sock. */
static bool
esdm_es_extsock_configured_locked(const struct esdm_es_extsock *sock)
{
	return esdm_es_extsock_path_locked(sock)[0] != '\0';
}

/* Is the connection encrypted? Caller must hold the mutex of @sock. */
static bool esdm_es_extsock_encrypted_locked(const struct esdm_es_extsock *sock)
{
	return sock->dtls != NULL;
}

/* Is the provider credited at all? Caller must hold the mutex of @sock. */
static bool esdm_es_extsock_credited_locked(const struct esdm_es_extsock *sock)
{
	return sock->fd >= 0 && !sock->read_failed && !sock->selftest_failed &&
	       !sock->selftest_due;
}

/*
 * Publish what is read of the source without the lock, see above. Caller must
 * hold the mutex of @sock (write lock).
 */
static void esdm_es_extsock_publish_locked(struct esdm_es_extsock *sock)
{
	atomic_store(&sock->published_configured,
		     esdm_es_extsock_configured_locked(sock));
	atomic_store(&sock->published_credited,
		     esdm_es_extsock_credited_locked(sock));
	atomic_store(&sock->published_rate, sock->rate);

	mutex_lock(&sock->state_mutex);
	snprintf(sock->state_path, sizeof(sock->state_path), "%s",
		 esdm_es_extsock_path_locked(sock));
	if (sock->fd < 0)
		snprintf(sock->state_status, sizeof(sock->state_status),
			 "not connected");
	else
		snprintf(sock->state_status, sizeof(sock->state_status),
			 "connected (uid %u), %s%s",
			 (unsigned int)sock->connected_uid,
			 esdm_es_extsock_encrypted_locked(sock) ? "DTLS" :
								  "unencrypted",
			 sock->selftest_failed ? ", failing its self test" :
			 sock->read_failed     ? ", failing" :
						 "");
	snprintf(sock->state_name, sizeof(sock->state_name), "%s", sock->name);
	sock->state_peer_uid = sock->peer_uid;
	mutex_unlock(&sock->state_mutex);
}

/* The name of @sock in the ES table */
static const char *esdm_es_extsock_name(const struct esdm_es_extsock *sock)
{
	return esdm_es_extsock[sock->idx].name;
}

/*
 * How the log names the source: its tag, with the name the provider declares.
 * Caller must hold the mutex of @sock.
 */
static const char *
esdm_es_extsock_label_locked(const struct esdm_es_extsock *sock, char *buf,
			     size_t buflen)
{
	if (!sock->name[0])
		return sock->tag;
	snprintf(buf, buflen, "%s (%s)", sock->tag, sock->name);
	return buf;
}

/*
 * The rate @sock is credited at, its provider declaring @declared: the rate
 * configured for it takes precedence - the n-th --es_ext_socket_entropy_rate
 * of the server, esdm_config_es_ext_socket_entropy_rate_set(), or the meson
 * option es_ext_socket_entropy_rate - then the one the provider declares,
 * then 0. *@source, if not NULL, tells which it is.
 *
 * A provider is another process, trusted for the user it runs as: accepting
 * that user means trusting the rate the provider declares, an operator who
 * does not want that configures the rate.
 */
static uint32_t esdm_es_extsock_rate(const struct esdm_es_extsock *sock,
				     uint32_t declared, const char **source)
{
	uint32_t rate =
		esdm_config_es_ext_socket_entropy_rate_configured(sock->idx);
	const char *from = "config";

	if (rate == ESDM_ES_EXT_ENTROPY_RATE_AUTO) {
		if (declared != ESDM_ES_EXT_PROTO_RATE_NONE) {
			rate = declared;
			from = "provider";
		} else {
			rate = 0;
			from = "default";
		}
	}

	if (source)
		*source = from;
	return min_uint32(rate, ESDM_DRNG_SECURITY_STRENGTH_BITS);
}

/* Release the mutex of @sock (write lock), publishing what changed under it */
static void esdm_es_extsock_unlock(struct esdm_es_extsock *sock)
{
	esdm_es_extsock_publish_locked(sock);
	mutex_unlock(&sock->mutex);
}

/*
 * Forget the status of the provider, which may be another one now. Caller must
 * hold the mutex of @sock (write lock).
 */
static void esdm_es_extsock_status_forget_locked(struct esdm_es_extsock *sock)
{
	mutex_lock(&sock->state_mutex);
	esdm_es_ext_status_cache_set(&sock->status, NULL, 0);
	mutex_unlock(&sock->state_mutex);
}

/* Caller must hold the mutex of @sock (write lock). */
static void esdm_es_extsock_disconnect_locked(struct esdm_es_extsock *sock)
{
	esdm_dtls_free(sock->dtls);
	sock->dtls = NULL;
	if (sock->fd >= 0)
		close(sock->fd);
	sock->fd = -1;
}

static time_t esdm_es_extsock_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return now.tv_sec;
}

/*
 * Give up on a connection that failed. It is not made again before the retry
 * interval is over: a provider accepting and failing every request, or always
 * answering just too late, must not cost a connection - and a timeout - per
 * seeding. Caller must hold the mutex of @sock (write lock).
 */
static void esdm_es_extsock_drop_locked(struct esdm_es_extsock *sock)
{
	esdm_es_extsock_disconnect_locked(sock);
	sock->retry_at =
		esdm_es_extsock_now() + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
}

/* Log @msg unless it was the last thing logged about the connection */
static void esdm_es_extsock_log_once(struct esdm_es_extsock *sock, int what,
				     enum esdm_logger_verbosity level,
				     const char *msg, const char *path)
{
	if (sock->last_logged == what)
		return;
	sock->last_logged = what;
	esdm_logger(level, LOGGER_C_ES, "External ES provider%s %s: %s\n",
		    sock->tag, path, msg);
}

/*
 * Connect to the provider. Caller must hold the mutex of @sock (write lock).
 *
 * @return 0 when connected, a negative errno otherwise
 */
static int esdm_es_extsock_open_locked(struct esdm_es_extsock *sock)
{
	const char *path = esdm_es_extsock_path_locked(sock);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	int fd, ret;

	esdm_es_extsock_disconnect_locked(sock);

	if (path[0] == '\0')
		return -ENODEV;
	if (strlen(path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, path, strlen(path));

	/*
	 * Non-blocking: a connect(2) to a provider whose backlog is full fails
	 * with EAGAIN rather than waiting, and the requests bound their waits
	 * themselves.
	 */
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		return -errno;

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ret = -errno;
		esdm_es_extsock_log_once(
			sock, 1, LOGGER_WARN,
			"not reachable, no entropy until it is", path);
		goto err;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		ret = -errno;
		goto err;
	}

	if (cred.uid != 0 &&
	    (sock->peer_uid < 0 || cred.uid != (uid_t)sock->peer_uid)) {
		esdm_es_extsock_log_once(
			sock, 2, LOGGER_ERR,
			"refused - it runs neither as root nor as the uid configured to be accepted",
			path);
		ret = -EPERM;
		goto err;
	}

	sock->fd = fd;
	sock->connected_uid = cred.uid;
	/* A provider restarted may be one that knows STATUS now */
	sock->status_refused = false;
	return 0;

err:
	close(fd);
	return ret;
}

static ssize_t esdm_es_extsock_transact_locked(struct esdm_es_extsock *sock,
					       uint16_t type, uint32_t length,
					       uint8_t *rsp);
static int esdm_es_extsock_selftest_locked(struct esdm_es_extsock *sock);

/*
 * Connect to the provider again at once, rather than after the retry interval.
 * Caller must hold the mutex of @sock (write lock).
 */
static int esdm_es_extsock_reconnect_locked(struct esdm_es_extsock *sock);

#ifdef ESDM_DTLS

/* The milliseconds left until @deadline, 0 once it passed */
static int esdm_es_extsock_ms_left(const struct timespec *deadline)
{
	struct timespec now;
	int64_t ms;

	clock_gettime(CLOCK_MONOTONIC, &now);
	ms = (int64_t)(deadline->tv_sec - now.tv_sec) * 1000 +
	     (deadline->tv_nsec - now.tv_nsec) / 1000000;
	return ms > 0 ? (int)ms : 0;
}

/*
 * Ask the provider connected to for DTLS, and do the handshake if it agrees.
 * Caller must hold the mutex of @sock (write lock).
 *
 * @return 0 when the connection is encrypted now, -EOPNOTSUPP when it goes on
 *	   unencrypted, any other negative errno when the connection is gone - the
 *	   provider closed it, did not answer, or the handshake failed
 */
static int esdm_es_extsock_startdtls_locked(struct esdm_es_extsock *sock)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	struct timespec deadline;
	const uint8_t *data;
	struct esdm_dtls *dtls;
	uint32_t bits;
	int32_t status;
	ssize_t n;
	int ret;

	n = esdm_es_extsock_transact_locked(sock, ESDM_ES_EXT_PROTO_STARTDTLS,
					    0, rsp);
	if (n < 0)
		return (int)n;
	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					 &status, &bits, &data)) {
		esdm_es_extsock_disconnect_locked(sock);
		return -EPROTO;
	}
	if (status)
		return -EOPNOTSUPP;

	if (!sock->dtls_ctx) {
		ret = esdm_dtls_ctx_alloc(false, &sock->dtls_ctx);
		if (ret) {
			esdm_es_extsock_disconnect_locked(sock);
			return ret;
		}
	}

	ret = esdm_dtls_alloc(sock->dtls_ctx, sock->fd,
			      ESDM_ES_EXT_PROTO_RSP_LEN +
				      ESDM_ES_EXT_PROTO_MAX_RSP_DATA,
			      &dtls);
	if (ret) {
		esdm_es_extsock_disconnect_locked(sock);
		return ret;
	}

	/* The handshake is bound by the same time a request is */
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += ESDM_EXT_SOCKET_TIMEOUT_MS / 1000;
	deadline.tv_nsec += (ESDM_EXT_SOCKET_TIMEOUT_MS % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	for (;;) {
		struct pollfd pfd = { .fd = sock->fd, .events = POLLIN };
		int left;

		ret = esdm_dtls_handshake(dtls);
		if (!ret)
			break;
		if (ret != -EAGAIN)
			goto err;

		left = esdm_es_extsock_ms_left(&deadline);
		if (!left) {
			ret = -ETIMEDOUT;
			goto err;
		}
		if (poll(&pfd, 1, left) < 0 && errno != EINTR) {
			ret = -errno;
			goto err;
		}
	}

	sock->dtls = dtls;
	return 0;

err:
	esdm_dtls_free(dtls);
	esdm_es_extsock_disconnect_locked(sock);
	return ret;
}

#endif /* ESDM_DTLS */

/*
 * Open a connection to the provider, encrypted if it can be, and unencrypted if
 * not. Caller must hold the mutex of @sock (write lock).
 *
 * @return 0 when connected, a negative errno otherwise
 */
static int esdm_es_extsock_open_dtls_locked(struct esdm_es_extsock *sock)
{
	int ret = esdm_es_extsock_open_locked(sock);

	if (ret)
		return ret;

#ifdef ESDM_DTLS
	ret = esdm_es_extsock_startdtls_locked(sock);
	if (ret && ret != -EOPNOTSUPP) {
		/*
		 * A provider that does not know STARTDTLS closes the
		 * connection, and one whose handshake failed is gone with it:
		 * opportunistic as the DTLS is, the provider is used
		 * unencrypted then, on a new connection.
		 */
		esdm_es_extsock_log_once(
			sock, 3, LOGGER_WARN,
			"no DTLS with it, using the connection unencrypted",
			esdm_es_extsock_path_locked(sock));
		return esdm_es_extsock_open_locked(sock);
	}
#endif

	/* A provider refusing DTLS is used unencrypted, on this connection */
	return 0;
}

/*
 * Take the name the provider declares, @len bytes at @name, if it is one a
 * source may declare and not the name of another entropy source. Caller must
 * hold the mutex of @sock (write lock).
 */
static void esdm_es_extsock_name_locked(struct esdm_es_extsock *sock,
					const char *name, size_t len)
{
	const char *self = esdm_es_extsock_name(sock);

	sock->name[0] = '\0';
	if (!len)
		return;

	if (!esdm_es_ext_name_valid(name, len)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: the name it declares is no name of 1 to %u bytes of UTF-8 without control characters, it is shown as %s\n",
			sock->tag, ESDM_ES_EXT_NAME_MAX, self);
		return;
	}

	memcpy(sock->name, name, len);
	sock->name[len] = '\0';
	if (esdm_es_name_taken(sock->name, &esdm_es_extsock[sock->idx])) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: it declares the name %s of another entropy source, it is shown as %s\n",
			sock->tag, sock->name, self);
		sock->name[0] = '\0';
	}
}

/*
 * Ask the provider connected to what it declares of itself - see INFO in
 * esdm_es_ext.h. Caller must hold the mutex of @sock (write lock) with the
 * provider connected.
 *
 * @return 0 when it answered - whatever it declared; -ECONNRESET when it
 *	   closed the connection on the request, as a provider older than INFO
 *	   does, -EPROTO when it answered what the protocol does not allow, which
 *	   closes the connection as well; another negative errno when the request
 *	   failed otherwise, the connection given up on as for any request
 */
static int esdm_es_extsock_info_locked(struct esdm_es_extsock *sock)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	const char *name;
	size_t namelen;
	uint32_t rate;
	int32_t status;
	ssize_t n;

	sock->name[0] = '\0';
	sock->rate = ESDM_ES_EXT_PROTO_RATE_NONE;

	n = esdm_es_extsock_transact_locked(sock, ESDM_ES_EXT_PROTO_INFO, 0,
					    rsp);
	if (n < 0)
		return (int)n;

	if (esdm_es_ext_proto_info_unpack(rsp, (size_t)n, &status, &rate, &name,
					  &namelen)) {
		esdm_es_extsock_disconnect_locked(sock);
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: invalid answer to INFO, connecting again without asking\n",
			sock->tag);
		return -EPROTO;
	}

	/* A provider declaring nothing */
	if (status)
		return 0;

	esdm_es_extsock_name_locked(sock, name, namelen);
	sock->rate = esdm_es_ext_proto_rate(rate);
	if (sock->rate != rate)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: it declares an entropy rate of %u bits per 256 bits, taken as %u\n",
			sock->tag, rate, sock->rate);
	return 0;
}

/*
 * Connect to the provider, encrypted if it can be, and ask it what it
 * declares. Caller must hold the mutex of @sock (write lock).
 *
 * @return 0 when connected, a negative errno otherwise
 */
static int esdm_es_extsock_connect_locked(struct esdm_es_extsock *sock)
{
	const char *path = esdm_es_extsock_path_locked(sock);
	char label[ESDM_ES_EXT_LABEL_SIZE];
	const char *source;
	uint32_t rate;
	int ret = esdm_es_extsock_open_dtls_locked(sock);

	if (ret)
		return ret;

	ret = esdm_es_extsock_info_locked(sock);
	if (ret == -ECONNRESET || ret == -EPROTO) {
		/*
		 * A provider older than INFO closes the connection on it, and
		 * one that answered what the protocol does not allow is
		 * disconnected: either is used without what it would declare,
		 * on a new connection that does not ask.
		 */
		esdm_es_extsock_log_once(
			sock, 4, LOGGER_VERBOSE,
			"does not answer INFO, using it without a name", path);
		ret = esdm_es_extsock_open_dtls_locked(sock);
	}
	if (ret)
		return ret;

	sock->last_logged = 0;
	/* Its claims are not assessed by the ESDM, which is worth a line */
	rate = esdm_es_extsock_rate(sock, sock->rate, &source);
	esdm_logger(
		sock->was_connected ? LOGGER_VERBOSE : LOGGER_STATUS,
		LOGGER_C_ES,
		"External ES provider%s %s connected (uid %u, %s), its entropy claims credited with up to %u bits per 256 bits (rate of the %s)\n",
		esdm_es_extsock_label_locked(sock, label, sizeof(label)), path,
		(unsigned int)sock->connected_uid,
		esdm_es_extsock_encrypted_locked(sock) ? "DTLS" : "unencrypted",
		rate, source);
	sock->was_connected = true;

	/* A provider not tested yet is tested before it is asked for anything */
	if (sock->selftest_due) {
		(void)esdm_es_extsock_selftest_locked(sock);
		if (sock->fd < 0)
			return -ECONNRESET;
	}

	return 0;
}

/*
 * Did the provider close the connection while it was idle - it was restarted,
 * or made room for another client? Nothing is to be read on a connection
 * between two requests, so anything poll(2) reports on it is its end. Caller
 * must hold the mutex of @sock (write lock) with the provider connected.
 */
static bool esdm_es_extsock_closed_locked(struct esdm_es_extsock *sock)
{
	struct pollfd pfd = { .fd = sock->fd, .events = POLLIN };

	if (sock->dtls && esdm_dtls_pending(sock->dtls))
		return true;
	return poll(&pfd, 1, 0) > 0;
}

/*
 * Connected, or connected now if the time has come to try again. Caller must
 * hold the mutex of @sock (write lock).
 *
 * A connection the provider closed while it was idle is no failed attempt: it
 * is made again at once, so that the request about to be sent is not lost on
 * it.
 */
static bool esdm_es_extsock_ensure_locked(struct esdm_es_extsock *sock)
{
	time_t now;

	if (sock->fd >= 0) {
		if (!esdm_es_extsock_closed_locked(sock))
			return true;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider%s: connection closed by the provider, connecting again\n",
			sock->tag);
		esdm_es_extsock_disconnect_locked(sock);
		sock->retry_at = 0;
	}
	if (!esdm_es_extsock_configured_locked(sock))
		return false;

	now = esdm_es_extsock_now();
	if (now < sock->retry_at)
		return false;

	if (esdm_es_extsock_connect_locked(sock)) {
		sock->retry_at = now + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
		return false;
	}

	return true;
}

/*
 * Send a request of @type for @length bytes and receive the answer into @rsp,
 * which has room for ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA
 * bytes. *@sent tells whether the request went out - one that did not found
 * the connection gone before it. Caller must hold the mutex of @sock (write
 * lock) with the provider connected.
 *
 * @return the size of the answer, or a negative errno, in which case the
 *	   connection is closed: -ECONNRESET if the provider closed it, and
 *	   -ETIMEDOUT if it did not answer in time
 */
static ssize_t esdm_es_extsock_request_locked(struct esdm_es_extsock *sock,
					      uint16_t type, uint32_t length,
					      uint8_t *rsp, bool *sent)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	struct timespec start, now;
	ssize_t n;

	*sent = false;
	esdm_es_ext_proto_req_pack(req, type, length);

	/*
	 * One request at a time: the provider's answers are read before the
	 * next request goes out, so this fits into the socket buffer.
	 */
	if (sock->dtls) {
		n = esdm_dtls_send(sock->dtls, req, sizeof(req));
		if (n)
			goto err;
	} else {
		n = send(sock->fd, req, sizeof(req),
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n != (ssize_t)sizeof(req)) {
			n = n < 0 ? -errno : -EIO;
			goto err;
		}
	}
	*sent = true;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		struct pollfd pfd = { .fd = sock->fd, .events = POLLIN };
		int64_t elapsed_ms;
		int ret;

		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ms = (int64_t)(now.tv_sec - start.tv_sec) * 1000 +
			     (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed_ms >= ESDM_EXT_SOCKET_TIMEOUT_MS) {
			n = -ETIMEDOUT;
			goto err;
		}

		/* A record DTLS read already is not signalled by the socket */
		if (sock->dtls && esdm_dtls_pending(sock->dtls))
			ret = 1;
		else
			ret = poll(
				&pfd, 1,
				(int)(ESDM_EXT_SOCKET_TIMEOUT_MS - elapsed_ms));
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0) {
			n = -errno;
			goto err;
		}
		if (ret == 0)
			continue;

		if (sock->dtls) {
			/* A message larger than any answer is -EMSGSIZE */
			n = esdm_dtls_recv(
				sock->dtls, rsp,
				ESDM_ES_EXT_PROTO_RSP_LEN +
					ESDM_ES_EXT_PROTO_MAX_RSP_DATA);
			if (n == -EAGAIN)
				continue;
			if (n < 0)
				goto err;
			return n;
		}

		/*
		 * MSG_TRUNC reports the size of the message even when it does
		 * not fit, which is how one larger than any answer is told.
		 */
		n = recv(sock->fd, rsp,
			 ESDM_ES_EXT_PROTO_RSP_LEN +
				 ESDM_ES_EXT_PROTO_MAX_RSP_DATA,
			 MSG_DONTWAIT | MSG_TRUNC);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		if (n < 0) {
			n = -errno;
			goto err;
		}
		if (n == 0) {
			n = -ECONNRESET;
			goto err;
		}
		if ((size_t)n > ESDM_ES_EXT_PROTO_RSP_LEN +
					ESDM_ES_EXT_PROTO_MAX_RSP_DATA) {
			n = -EPROTO;
			goto err;
		}

		return n;
	}

err:
	esdm_es_extsock_drop_locked(sock);
	return n;
}

/* As above, for a caller that does not care whether the request went out */
static ssize_t esdm_es_extsock_transact_locked(struct esdm_es_extsock *sock,
					       uint16_t type, uint32_t length,
					       uint8_t *rsp)
{
	bool sent;

	return esdm_es_extsock_request_locked(sock, type, length, rsp, &sent);
}

static int esdm_es_extsock_reconnect_locked(struct esdm_es_extsock *sock)
{
	int ret = esdm_es_extsock_connect_locked(sock);

	if (ret)
		sock->retry_at = esdm_es_extsock_now() +
				 ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
	else
		sock->retry_at = 0;
	return ret;
}

/*
 * Set the source up anew, for a provider not connected to yet: the state of
 * the last connection, and of the last provider, is forgotten. Caller must
 * hold the mutex of @sock (write lock).
 */
static void esdm_es_extsock_reset_locked(struct esdm_es_extsock *sock)
{
	sock->retry_at = 0;
	sock->probe_at = 0;
	sock->last_logged = 0;
	sock->was_connected = false;
	sock->read_failed = false;
	sock->selftest_failed = false;
	sock->selftest_due = true;
	sock->status_warned = false;
	sock->status_backoff_until = 0;
	sock->name[0] = '\0';
	sock->rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	esdm_es_extsock_status_forget_locked(sock);
}

static int esdm_es_extsock_init(struct esdm_es_extsock *sock)
{
	/* What the provider delivers per request fits into a seed buffer */
	BUILD_BUG_ON(ESDM_DRNG_INIT_SEED_SIZE_BYTES >
		     ESDM_ES_EXT_PROTO_MAX_DATA);

	mutex_lock(&sock->mutex);
	esdm_es_extsock_reset_locked(sock);
	/* A provider not there yet is connected to on demand */
	if (esdm_es_extsock_configured_locked(sock))
		(void)esdm_es_extsock_connect_locked(sock);
	esdm_es_extsock_unlock(sock);

	return 0;
}

static void esdm_es_extsock_fini(struct esdm_es_extsock *sock)
{
	mutex_lock(&sock->mutex);
	esdm_es_extsock_disconnect_locked(sock);
	esdm_dtls_ctx_free(sock->dtls_ctx);
	sock->dtls_ctx = NULL;
	sock->read_failed = false;
	sock->selftest_failed = false;
	esdm_es_extsock_status_forget_locked(sock);
	esdm_es_extsock_unlock(sock);
}

/* As published: a request in progress is not waited for */
uint32_t esdm_es_extsock_entropy_rate(unsigned int idx, const char **source)
{
	struct esdm_es_extsock *sock = &extsock[idx];

	return esdm_es_extsock_rate(sock, atomic_load(&sock->published_rate),
				    source);
}

static uint32_t esdm_es_extsock_level(const struct esdm_es_extsock *sock,
				      bool credited, uint32_t declared,
				      uint32_t requested_bits)
{
	if (!credited)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_es_extsock_rate(sock, declared, NULL), requested_bits);
}

/* Caller must hold the mutex of @sock. */
static uint32_t
esdm_es_extsock_entropylevel_locked(const struct esdm_es_extsock *sock,
				    uint32_t requested_bits)
{
	return esdm_es_extsock_level(sock,
				     esdm_es_extsock_credited_locked(sock),
				     sock->rate, requested_bits);
}

/* As published: a request in progress is not waited for */
static uint32_t esdm_es_extsock_entropylevel(struct esdm_es_extsock *sock,
					     uint32_t requested_bits)
{
	return esdm_es_extsock_level(sock,
				     atomic_load(&sock->published_credited),
				     atomic_load(&sock->published_rate),
				     requested_bits);
}

static uint32_t esdm_es_extsock_poolsize(struct esdm_es_extsock *sock)
{
	return esdm_es_extsock_entropylevel(sock, esdm_security_strength());
}

static void esdm_es_extsock_get(struct esdm_es_extsock *sock,
				struct entropy_es *eb_es,
				uint32_t requested_bits)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint32_t claimed, len = requested_bits >> 3;
	char label[ESDM_ES_EXT_LABEL_SIZE];
	const uint8_t *data;
	const char *why = NULL;
	int32_t status;
	ssize_t n;

	eb_es->e_bits = 0;
	if (!len || len > sizeof(eb_es->e))
		return;

	/* Exclusive: one request at a time, and its outcome is recorded */
	mutex_lock(&sock->mutex);

	if (!esdm_es_extsock_ensure_locked(sock))
		goto out;

	n = esdm_es_extsock_transact_locked(sock, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					    len, rsp);
	if (n < 0) {
		why = strerror((int)-n);
		goto fail;
	}

	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY, len,
					 &status, &claimed, &data)) {
		/* A connection that brings such things is not used again */
		esdm_es_extsock_drop_locked(sock);
		why = "invalid answer, disconnected";
		goto fail;
	}

	if (status) {
		why = strerror(-status);
		goto fail;
	}

	memcpy(eb_es->e, data, len);
	sock->read_failed = false;
	eb_es->e_bits = min_uint32(claimed, esdm_es_extsock_entropylevel_locked(
						    sock, requested_bits));

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from external ES provider%s\n",
		    eb_es->e_bits, sock->tag);
	goto out;

fail:
	if (!sock->read_failed)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: no entropy delivered: %s\n",
			esdm_es_extsock_label_locked(sock, label,
						     sizeof(label)),
			why);
	sock->read_failed = true;

out:
	esdm_es_extsock_unlock(sock);
	memset_secure(rsp, 0, sizeof(rsp));
}

/*
 * A provider not connected, or whose request failed, is credited with
 * nothing, which keeps it out of what an unforced reseed waits for - and such
 * a reseed asks no source at all while too little entropy is available. The
 * monitor connects to it instead, at most every retry interval, and probes one
 * whose request failed by asking it for data it discards: data it delivers
 * again makes it credited again.
 */
static int esdm_es_extsock_monitor(struct esdm_es_extsock *sock)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	char label[ESDM_ES_EXT_LABEL_SIZE];
	const uint8_t *data;
	uint32_t claimed;
	int32_t status;
	time_t now;
	ssize_t n;

	mutex_lock(&sock->mutex);

	if (!esdm_es_extsock_ensure_locked(sock) || !sock->read_failed)
		goto out;

	now = esdm_es_extsock_now();
	if (now < sock->probe_at)
		goto out;
	sock->probe_at = now + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;

	n = esdm_es_extsock_transact_locked(sock, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					    ESDM_DRNG_SECURITY_STRENGTH_BYTES,
					    rsp);
	if (n < 0)
		goto out;
	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY,
					 ESDM_DRNG_SECURITY_STRENGTH_BYTES,
					 &status, &claimed, &data)) {
		esdm_es_extsock_drop_locked(sock);
		goto out;
	}
	if (!status) {
		sock->read_failed = false;
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "External ES provider%s: delivering again\n",
			    esdm_es_extsock_label_locked(sock, label,
							 sizeof(label)));
	}

out:
	esdm_es_extsock_unlock(sock);
	memset_secure(rsp, 0, sizeof(rsp));
	return 0;
}

/*
 * The status the provider reports of itself, NULL for none. Caller must hold
 * the mutex of @sock (write lock).
 *
 * A provider connected to only: the ESDM status does not wait for a provider
 * to be connected to. What a request that fails tells:
 *
 * - The request did not go out, the connection was gone before - the
 *   provider was restarted, say: connected to again at once, and asked on
 *   the new connection, once.
 * - The provider closed the connection on the request, as one older than
 *   STATUS does on a request it does not know: connected to again at once, as
 *   for STARTDTLS, and not asked again on that connection.
 * - No answer in time: given up on as for any request, and connected to again
 *   after the retry interval only - the provider may still be busy with the
 *   status, unable to take a new connection, whose STARTDTLS would time out
 *   and leave it unencrypted. Nor is it asked for its status again for
 *   ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC.
 */
static struct json_object *
esdm_es_extsock_status_locked(struct esdm_es_extsock *sock)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	struct json_object *obj = NULL;
	time_t now = esdm_es_extsock_now();
	bool retried = false, sent;
	const char *text;
	size_t textlen;
	int32_t status;
	ssize_t n;

	if (sock->fd < 0 || sock->status_refused ||
	    now < sock->status_backoff_until)
		return NULL;

again:
	n = esdm_es_extsock_request_locked(sock, ESDM_ES_EXT_PROTO_STATUS,
					   ESDM_ES_EXT_PROTO_STATUS_MAX, rsp,
					   &sent);
	if (n < 0 && !sent) {
		if (retried)
			goto out;
		retried = true;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider%s: connection gone (%s), connecting again\n",
			sock->tag, strerror((int)-n));
		if (esdm_es_extsock_reconnect_locked(sock))
			goto out;
		goto again;
	}
	if (n == -ECONNRESET) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider%s: STATUS refused, connecting again\n",
			sock->tag);
		(void)esdm_es_extsock_reconnect_locked(sock);
		sock->status_refused = true;
		goto out;
	}
	if (n == -ETIMEDOUT) {
		sock->status_backoff_until =
			now + ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC;
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: no answer to STATUS in time, disconnected - not asked for its status for %u seconds\n",
			sock->tag, ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC);
		goto out;
	}
	/* An answer larger than any: disconnected as for any other request */
	if (n == -EPROTO || n == -EMSGSIZE) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: invalid answer to STATUS, disconnected\n",
			sock->tag);
		goto out;
	}
	if (n < 0) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "External ES provider%s: no answer to STATUS: %s\n",
			    sock->tag, strerror((int)-n));
		goto out;
	}

	if (esdm_es_ext_proto_status_unpack(rsp, (size_t)n,
					    ESDM_ES_EXT_PROTO_STATUS_MAX,
					    &status, &text, &textlen)) {
		/* A connection that brings such things is not used again */
		esdm_es_extsock_drop_locked(sock);
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider%s: invalid answer to STATUS, disconnected\n",
			sock->tag);
		goto out;
	}

	if (status) {
		if (status != -EOPNOTSUPP)
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "External ES provider%s: no status: %s\n",
				    sock->tag, strerror(-status));
		goto out;
	}

	/* One level deeper than a plugin: the server may wrap that of its plugin */
	obj = esdm_es_ext_status_parse(text, textlen,
				       ESDM_ES_EXT_PROTO_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH + 1,
				       sock->who, &sock->status_warned);

out:
	memset_secure(rsp, 0, sizeof(rsp));
	return obj;
}

static void esdm_es_extsock_es_state(struct esdm_es_extsock *sock,
				     struct json_object *obj)
{
	uint32_t poolsize, entropy_rate, rate;
	char path[ESDM_ES_EXTSOCK_PATH_SIZE], status[64], accepted[48];
	const char *rate_source;
	char name[ESDM_ES_EXT_NAME_MAX + 1];
	struct json_object *provider;
	time_t now = esdm_es_extsock_now();
	int64_t peer_uid;
	bool due;

	mutex_lock(&sock->state_mutex);
	due = esdm_es_ext_status_cache_due(&sock->status, now);
	mutex_unlock(&sock->state_mutex);

	/*
	 * The status of the provider is asked for anew once the last one is
	 * older than ESDM_ES_EXT_STATUS_INTERVAL_SEC - unless a request is in
	 * progress on the connection, one of a seeding, which may take up to
	 * the timeout: the ESDM status is not to wait for it, and goes without
	 * the status of the provider then. Before the state of the connection
	 * is taken, which asking for it may change.
	 */
	if (due && mutex_trylock(&sock->mutex)) {
		provider = esdm_es_extsock_status_locked(sock);
		mutex_lock(&sock->state_mutex);
		esdm_es_ext_status_cache_set(&sock->status, provider, now);
		mutex_unlock(&sock->state_mutex);
		esdm_es_extsock_unlock(sock);
		due = false;
	}

	mutex_lock(&sock->state_mutex);
	provider = due ? NULL : esdm_es_ext_status_cache_get(&sock->status);
	snprintf(path, sizeof(path), "%s", sock->state_path);
	snprintf(status, sizeof(status), "%s", sock->state_status);
	snprintf(name, sizeof(name), "%s", sock->state_name);
	peer_uid = sock->state_peer_uid;
	mutex_unlock(&sock->state_mutex);

	poolsize = esdm_es_extsock_entropylevel(sock, esdm_security_strength());
	entropy_rate = esdm_es_extsock_entropylevel(sock, 256);
	rate = esdm_es_extsock_entropy_rate(sock->idx, &rate_source);

	if (peer_uid >= 0)
		snprintf(accepted, sizeof(accepted), "root and uid %" PRId64,
			 peer_uid);
	else
		snprintf(accepted, sizeof(accepted), "root");

	/* Its name, see esdm_es_mgr_cb.h, and its instance */
	esdm_es_ext_state_name(obj, name, esdm_es_extsock_name(sock));
	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(poolsize));
	json_object_object_add(obj, "entropy_rate_per_256_data_bits",
			       json_object_new_int64(entropy_rate));
	/* The rate it is credited at once it delivers, and whose it is */
	json_object_object_add(obj, "entropy_rate",
			       json_object_new_int64(rate));
	json_object_object_add(obj, "entropy_rate_source",
			       json_object_new_string(rate_source));
	json_object_object_add(obj, "provider_socket",
			       json_object_new_string(path[0] ? path :
								"(unset)"));
	json_object_object_add(obj, "provider_accepted",
			       json_object_new_string(accepted));
	json_object_object_add(obj, "status", json_object_new_string(status));
	if (provider)
		json_object_object_add(obj, "provider", provider);
}

/*
 * Active as long as a provider is configured: one that is not reachable at a
 * time is connected to again on demand.
 */
static bool esdm_es_extsock_active(struct esdm_es_extsock *sock)
{
	return atomic_load(&sock->published_configured);
}

/*
 * The self test of the provider connected to. Caller must hold the mutex of
 * @sock (write lock) with the provider connected.
 *
 * @return 0 if it passed, -EFAULT if it failed or was not answered - the
 *	   connection is closed then
 */
static int esdm_es_extsock_selftest_locked(struct esdm_es_extsock *sock)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	char label[ESDM_ES_EXT_LABEL_SIZE];
	uint32_t bits;
	const uint8_t *data;
	int32_t status;
	ssize_t n;

	n = esdm_es_extsock_transact_locked(sock, ESDM_ES_EXT_PROTO_SELFTEST, 0,
					    rsp);
	if (n < 0 || esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
						  ESDM_ES_EXT_PROTO_SELFTEST, 0,
						  &status, &bits, &data)) {
		/* No verdict on the noise source, but no working connection */
		esdm_es_extsock_drop_locked(sock);
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider%s: self test not answered\n",
			    sock->tag);
		sock->read_failed = true;
		return -EFAULT;
	}

	sock->selftest_due = false;

	if (status) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider%s: self test failed: %s\n",
			    esdm_es_extsock_label_locked(sock, label,
							 sizeof(label)),
			    strerror(-status));
		sock->selftest_failed = true;
		return -EFAULT;
	}
	sock->selftest_failed = false;

	return 0;
}

/*
 * The self test of the provider. One that is not connected is no failure:
 * it is credited with nothing until it is, and tested once connected to.
 */
static int esdm_es_extsock_selftest(struct esdm_es_extsock *sock)
{
	int ret = 0;

	mutex_lock(&sock->mutex);

	if (!esdm_es_extsock_ensure_locked(sock)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"External ES provider%s: not connected - nothing to test\n",
			sock->tag);
		goto out;
	}

	ret = esdm_es_extsock_selftest_locked(sock);

out:
	esdm_es_extsock_unlock(sock);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_socket_set_path(unsigned int idx, const char *path)
{
	struct esdm_es_extsock *sock;
	char *new_copy = NULL;
	char *old;

	if (idx >= ESDM_EXT_SOCKET_NUM || !path ||
	    strlen(path) >= ESDM_ES_EXTSOCK_PATH_SIZE)
		return -EINVAL;
	sock = &extsock[idx];

	if (path[0] != '\0') {
		new_copy = strdup(path);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&sock->mutex);
	old = sock->runtime_path;
	sock->runtime_path = new_copy;

	/* The provider of the new path is connected to on demand */
	esdm_es_extsock_disconnect_locked(sock);
	esdm_es_extsock_reset_locked(sock);
	esdm_es_extsock_unlock(sock);

	free(old);

	return 0;
}

DSO_PUBLIC
int esdm_es_ext_socket_set_peer_uid(unsigned int idx, int64_t uid)
{
	struct esdm_es_extsock *sock;

	/* (uid_t)-1 is no uid, see setreuid(2) */
	if (idx >= ESDM_EXT_SOCKET_NUM || uid < -1 ||
	    (uid >= 0 && (uint64_t)uid >= UINT32_MAX))
		return -EINVAL;
	sock = &extsock[idx];

	mutex_lock(&sock->mutex);
	sock->peer_uid = uid;
	esdm_es_extsock_unlock(sock);

	return 0;
}

/*
 * The callbacks of the ES manager take no context: each source has a set of
 * its own, handing its instance to the functions above.
 */
#define ESDM_ES_EXTSOCK_CB(i)                                                  \
	static int esdm_es_extsock_init_##i(void)                              \
	{                                                                      \
		return esdm_es_extsock_init(&extsock[i]);                      \
	}                                                                      \
	static void esdm_es_extsock_fini_##i(void)                             \
	{                                                                      \
		esdm_es_extsock_fini(&extsock[i]);                             \
	}                                                                      \
	static int esdm_es_extsock_monitor_##i(void)                           \
	{                                                                      \
		return esdm_es_extsock_monitor(&extsock[i]);                   \
	}                                                                      \
	static void esdm_es_extsock_get_##i(struct entropy_es *eb_es,          \
					    uint32_t requested_bits,           \
					    bool __unused allow_cached)        \
	{                                                                      \
		esdm_es_extsock_get(&extsock[i], eb_es, requested_bits);       \
	}                                                                      \
	static uint32_t esdm_es_extsock_entropylevel_##i(uint32_t bits)        \
	{                                                                      \
		return esdm_es_extsock_entropylevel(&extsock[i], bits);        \
	}                                                                      \
	static uint32_t esdm_es_extsock_poolsize_##i(void)                     \
	{                                                                      \
		return esdm_es_extsock_poolsize(&extsock[i]);                  \
	}                                                                      \
	static void esdm_es_extsock_es_state_##i(struct json_object *obj)      \
	{                                                                      \
		esdm_es_extsock_es_state(&extsock[i], obj);                    \
	}                                                                      \
	static bool esdm_es_extsock_active_##i(void)                           \
	{                                                                      \
		return esdm_es_extsock_active(&extsock[i]);                    \
	}                                                                      \
	static int esdm_es_extsock_selftest_##i(void)                          \
	{                                                                      \
		return esdm_es_extsock_selftest(&extsock[i]);                  \
	}

ESDM_EXT_SOCKET_INSTANCES(ESDM_ES_EXTSOCK_CB)

#define ESDM_ES_EXTSOCK_CB_ENTRY(i)                                            \
	[i] = {                                                                \
		.name = ESDM_ES_EXTSOCK_NAME(i),                               \
		.init = esdm_es_extsock_init_##i,                              \
		.fini = esdm_es_extsock_fini_##i,                              \
		.monitor_es = esdm_es_extsock_monitor_##i,                     \
		.get_ent = esdm_es_extsock_get_##i,                            \
		.curr_entropy = esdm_es_extsock_entropylevel_##i,              \
		.max_entropy = esdm_es_extsock_poolsize_##i,                   \
		.state = esdm_es_extsock_es_state_##i,                         \
		.reset = NULL,                                                 \
		.active = esdm_es_extsock_active_##i,                          \
		.selftest = esdm_es_extsock_selftest_##i,                      \
	},

struct esdm_es_cb esdm_es_extsock[ESDM_EXT_SOCKET_NUM] = {
	/* The callbacks of the instances, see ESDM_ES_EXTSOCK_CB */
	ESDM_EXT_SOCKET_INSTANCES(ESDM_ES_EXTSOCK_CB_ENTRY)
};
