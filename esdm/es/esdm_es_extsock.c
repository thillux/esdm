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
 * time on it, under extsock_mutex. Anything going wrong on the connection - an
 * error, a provider that does not answer in time, an answer breaking the
 * protocol - closes it: an answer arriving late would otherwise be taken for
 * the one to the next request. A new connection is made on demand, at most
 * every ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC seconds after a failed attempt or a
 * connection given up on. What the ESDM asks of the source while a request may
 * be in progress - the entropy available, its state in the ESDM status - is
 * taken from what the source publishes whenever it releases extsock_mutex, not
 * waited for.
 *
 * Whoever can create the socket file at the configured path could feed the
 * ESDM with data credited as entropy, so the credentials of the provider are
 * checked on every connection: root, or the one uid configured in addition.
 *
 * A block is credited with what the provider claims for it, at most with what
 * the configured rate allows (esdm_config_es_ext_socket_entropy_rate()). A
 * provider that fails is credited with nothing until it delivers again, on a
 * seeding that asks it or on a probe of the ES monitor; one failing its self
 * test is credited with nothing until a self test passes. Nor is a provider
 * credited before its first self test since the source was set up: the self
 * test pass of the ESDM runs before its first seeding, and a provider that was
 * not connected then is tested on the first connection to it.
 */

#define _GNU_SOURCE
#include <errno.h>
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

static DEFINE_MUTEX_UNLOCKED(extsock_mutex);

/*
 * Override of the socket path, as given on the command line of the server.
 * NULL means "use the compile-time default ESDM_EXT_SOCKET_PATH".
 * Configuration like the entropy rates: it outlives esdm_fini().
 */
static char *extsock_runtime_path = NULL;

/* The uid accepted next to root, -1 for none */
static long extsock_peer_uid = ESDM_EXT_SOCKET_PEER_UID;

static int extsock_fd = -1;
/* The uid of the provider connected to */
static uid_t extsock_connected_uid = 0;

/*
 * The DTLS of the connection, NULL while it is unencrypted - see esdm_dtls.h
 * and esdm_es_ext.h on the opportunistic DTLS. The context is set up on first
 * use.
 */
static struct esdm_dtls_ctx *extsock_dtls_ctx = NULL;
static struct esdm_dtls *extsock_dtls = NULL;

/*
 * The last request to the provider failed, or its last self test did. Kept
 * apart as for the plugin source: only data delivered clears a failed request,
 * only a self test that passes clears a failed self test - not a new
 * connection either. Set and cleared under the write lock, read under the
 * reader lock.
 */
static bool extsock_read_failed = false;
static bool extsock_selftest_failed = false;

/*
 * No self test of the provider was answered since the source was set up, and
 * the provider is credited with nothing until one was: the next connection
 * runs one first. Under the same lock as the failures.
 */
static bool extsock_selftest_due = false;

/*
 * Earliest time to connect again, and to probe a provider whose request
 * failed, monotonic seconds
 */
static time_t extsock_retry_at = 0;
static time_t extsock_probe_at = 0;

/* Connected once since the source was set up - the first one is logged */
static bool extsock_was_connected = false;

/*
 * What was logged last, so that a provider away for long is not logged on
 * every connection attempt
 */
static int extsock_last_logged = 0;

/*
 * The provider connected to refused STATUS - it closed the connection on it,
 * as a provider does on a request it does not know - and is not asked again
 * on this connection. The last status it sent was none and logged as such.
 */
static bool extsock_status_refused = false;
static bool extsock_status_warned = false;

/*
 * The provider did not answer STATUS in time, and is not asked for its status
 * before this time, monotonic seconds
 */
static time_t extsock_status_backoff_until = 0;

/*
 * What is read of the source without extsock_mutex, which a request holds for
 * up to ESDM_EXT_SOCKET_TIMEOUT_MS: the ESDM status, and the entropy
 * available, are not to wait for that - see esdm_es_mgr_cb.h. Published by
 * esdm_es_extsock_unlock() whenever the write lock is released; the state and
 * the status of the provider under extsock_state_mutex, which is held for
 * copying only.
 */
static atomic_bool extsock_published_configured = false;
static atomic_bool extsock_published_credited = false;
static DEFINE_MUTEX_UNLOCKED(extsock_state_mutex);
static char extsock_state_path[sizeof(((struct sockaddr_un *)0)->sun_path)] =
	ESDM_EXT_SOCKET_PATH;
static char extsock_state_status[64] = "not connected";
static long extsock_state_peer_uid = ESDM_EXT_SOCKET_PEER_UID;
static struct esdm_es_ext_status_cache extsock_status = { NULL, 0 };

/* Caller must hold extsock_mutex. */
static const char *esdm_es_extsock_path_locked(void)
{
	return extsock_runtime_path ? extsock_runtime_path :
				      ESDM_EXT_SOCKET_PATH;
}

/* Caller must hold extsock_mutex. */
static bool esdm_es_extsock_configured_locked(void)
{
	return esdm_es_extsock_path_locked()[0] != '\0';
}

/* Is the connection encrypted? Caller must hold extsock_mutex. */
static bool esdm_es_extsock_encrypted_locked(void)
{
	return extsock_dtls != NULL;
}

/* Is the provider credited at all? Caller must hold extsock_mutex. */
static bool esdm_es_extsock_credited_locked(void)
{
	return extsock_fd >= 0 && !extsock_read_failed &&
	       !extsock_selftest_failed && !extsock_selftest_due;
}

/*
 * Publish what is read of the source without the lock, see above. Caller must
 * hold extsock_mutex (write lock).
 */
static void esdm_es_extsock_publish_locked(void)
{
	atomic_store(&extsock_published_configured,
		     esdm_es_extsock_configured_locked());
	atomic_store(&extsock_published_credited,
		     esdm_es_extsock_credited_locked());

	mutex_lock(&extsock_state_mutex);
	snprintf(extsock_state_path, sizeof(extsock_state_path), "%s",
		 esdm_es_extsock_path_locked());
	if (extsock_fd < 0)
		snprintf(extsock_state_status, sizeof(extsock_state_status),
			 "not connected");
	else
		snprintf(extsock_state_status, sizeof(extsock_state_status),
			 "connected (uid %u), %s%s",
			 (unsigned int)extsock_connected_uid,
			 esdm_es_extsock_encrypted_locked() ? "DTLS" :
							      "unencrypted",
			 extsock_selftest_failed ? ", failing its self test" :
			 extsock_read_failed	 ? ", failing" :
						   "");
	extsock_state_peer_uid = extsock_peer_uid;
	mutex_unlock(&extsock_state_mutex);
}

/* Release extsock_mutex (write lock), publishing what changed under it */
static void esdm_es_extsock_unlock(void)
{
	esdm_es_extsock_publish_locked();
	mutex_unlock(&extsock_mutex);
}

/*
 * Forget the status of the provider, which may be another one now. Caller must
 * hold extsock_mutex (write lock).
 */
static void esdm_es_extsock_status_forget_locked(void)
{
	mutex_lock(&extsock_state_mutex);
	esdm_es_ext_status_cache_set(&extsock_status, NULL, 0);
	mutex_unlock(&extsock_state_mutex);
}

/* Caller must hold extsock_mutex (write lock). */
static void esdm_es_extsock_disconnect_locked(void)
{
	esdm_dtls_free(extsock_dtls);
	extsock_dtls = NULL;
	if (extsock_fd >= 0)
		close(extsock_fd);
	extsock_fd = -1;
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
 * seeding. Caller must hold extsock_mutex (write lock).
 */
static void esdm_es_extsock_drop_locked(void)
{
	esdm_es_extsock_disconnect_locked();
	extsock_retry_at =
		esdm_es_extsock_now() + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
}

/* Log @msg unless it was the last thing logged about the connection */
static void esdm_es_extsock_log_once(int what, enum esdm_logger_verbosity level,
				     const char *msg, const char *path)
{
	if (extsock_last_logged == what)
		return;
	extsock_last_logged = what;
	esdm_logger(level, LOGGER_C_ES, "External ES provider %s: %s\n", path,
		    msg);
}

/*
 * Connect to the provider. Caller must hold extsock_mutex (write lock).
 *
 * @return 0 when connected, a negative errno otherwise
 */
static int esdm_es_extsock_open_locked(void)
{
	const char *path = esdm_es_extsock_path_locked();
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct ucred cred;
	socklen_t cred_len = sizeof(cred);
	int fd, ret;

	esdm_es_extsock_disconnect_locked();

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
			1, LOGGER_WARN, "not reachable, no entropy until it is",
			path);
		goto err;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
		ret = -errno;
		goto err;
	}

	if (cred.uid != 0 &&
	    (extsock_peer_uid < 0 || cred.uid != (uid_t)extsock_peer_uid)) {
		esdm_es_extsock_log_once(
			2, LOGGER_ERR,
			"refused - it runs neither as root nor as the uid configured to be accepted",
			path);
		ret = -EPERM;
		goto err;
	}

	extsock_fd = fd;
	extsock_connected_uid = cred.uid;
	/* A provider restarted may be one that knows STATUS now */
	extsock_status_refused = false;
	return 0;

err:
	close(fd);
	return ret;
}

static ssize_t esdm_es_extsock_transact_locked(uint16_t type, uint32_t length,
					       uint8_t *rsp);
static int esdm_es_extsock_selftest_locked(void);

/*
 * Connect to the provider again at once, rather than after the retry interval.
 * Caller must hold extsock_mutex (write lock).
 */
static int esdm_es_extsock_reconnect_locked(void);

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
 * Caller must hold extsock_mutex (write lock).
 *
 * @return 0 when the connection is encrypted now, -EOPNOTSUPP when it goes on
 *	   unencrypted, any other negative errno when the connection is gone - the
 *	   provider closed it, did not answer, or the handshake failed
 */
static int esdm_es_extsock_startdtls_locked(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	struct timespec deadline;
	const uint8_t *data;
	struct esdm_dtls *dtls;
	uint32_t bits;
	int32_t status;
	ssize_t n;
	int ret;

	n = esdm_es_extsock_transact_locked(ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					    rsp);
	if (n < 0)
		return (int)n;
	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					 &status, &bits, &data)) {
		esdm_es_extsock_disconnect_locked();
		return -EPROTO;
	}
	if (status)
		return -EOPNOTSUPP;

	if (!extsock_dtls_ctx) {
		ret = esdm_dtls_ctx_alloc(false, &extsock_dtls_ctx);
		if (ret) {
			esdm_es_extsock_disconnect_locked();
			return ret;
		}
	}

	ret = esdm_dtls_alloc(
		extsock_dtls_ctx, extsock_fd,
		ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA, &dtls);
	if (ret) {
		esdm_es_extsock_disconnect_locked();
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
		struct pollfd pfd = { .fd = extsock_fd, .events = POLLIN };
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

	extsock_dtls = dtls;
	return 0;

err:
	esdm_dtls_free(dtls);
	esdm_es_extsock_disconnect_locked();
	return ret;
}

#endif /* ESDM_DTLS */

/*
 * Connect to the provider, encrypted if it can be, and unencrypted if not.
 * Caller must hold extsock_mutex (write lock).
 *
 * @return 0 when connected, a negative errno otherwise
 */
static int esdm_es_extsock_connect_locked(void)
{
	const char *path = esdm_es_extsock_path_locked();
	int ret = esdm_es_extsock_open_locked();

	if (ret)
		return ret;

#ifdef ESDM_DTLS
	ret = esdm_es_extsock_startdtls_locked();
	if (ret && ret != -EOPNOTSUPP) {
		/*
		 * A provider that does not know STARTDTLS closes the
		 * connection, and one whose handshake failed is gone with it:
		 * opportunistic as the DTLS is, the provider is used
		 * unencrypted then, on a new connection.
		 */
		esdm_es_extsock_log_once(
			3, LOGGER_WARN,
			"no DTLS with it, using the connection unencrypted",
			path);
		ret = esdm_es_extsock_open_locked();
		if (ret)
			return ret;
	}
#endif

	extsock_last_logged = 0;
	/* Its claims are not assessed by the ESDM, which is worth a line */
	esdm_logger(
		extsock_was_connected ? LOGGER_VERBOSE : LOGGER_STATUS,
		LOGGER_C_ES,
		"External ES provider %s connected (uid %u, %s), its entropy claims credited with up to %u bits per 256 bits\n",
		path, (unsigned int)extsock_connected_uid,
		esdm_es_extsock_encrypted_locked() ? "DTLS" : "unencrypted",
		esdm_config_es_ext_socket_entropy_rate());
	extsock_was_connected = true;

	/* A provider not tested yet is tested before it is asked for anything */
	if (extsock_selftest_due) {
		(void)esdm_es_extsock_selftest_locked();
		if (extsock_fd < 0)
			return -ECONNRESET;
	}

	return 0;
}

/*
 * Did the provider close the connection while it was idle - it was restarted,
 * or made room for another client? Nothing is to be read on a connection
 * between two requests, so anything poll(2) reports on it is its end. Caller
 * must hold extsock_mutex (write lock) with the provider connected.
 */
static bool esdm_es_extsock_closed_locked(void)
{
	struct pollfd pfd = { .fd = extsock_fd, .events = POLLIN };

	if (extsock_dtls && esdm_dtls_pending(extsock_dtls))
		return true;
	return poll(&pfd, 1, 0) > 0;
}

/*
 * Connected, or connected now if the time has come to try again. Caller must
 * hold extsock_mutex (write lock).
 *
 * A connection the provider closed while it was idle is no failed attempt: it
 * is made again at once, so that the request about to be sent is not lost on
 * it.
 */
static bool esdm_es_extsock_ensure_locked(void)
{
	time_t now;

	if (extsock_fd >= 0) {
		if (!esdm_es_extsock_closed_locked())
			return true;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider: connection closed by the provider, connecting again\n");
		esdm_es_extsock_disconnect_locked();
		extsock_retry_at = 0;
	}
	if (!esdm_es_extsock_configured_locked())
		return false;

	now = esdm_es_extsock_now();
	if (now < extsock_retry_at)
		return false;

	if (esdm_es_extsock_connect_locked()) {
		extsock_retry_at = now + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
		return false;
	}

	return true;
}

/*
 * Send a request of @type for @length bytes and receive the answer into @rsp,
 * which has room for ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA
 * bytes. *@sent tells whether the request went out - one that did not found
 * the connection gone before it. Caller must hold extsock_mutex (write lock)
 * with the provider connected.
 *
 * @return the size of the answer, or a negative errno, in which case the
 *	   connection is closed: -ECONNRESET if the provider closed it, and
 *	   -ETIMEDOUT if it did not answer in time
 */
static ssize_t esdm_es_extsock_request_locked(uint16_t type, uint32_t length,
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
	if (extsock_dtls) {
		n = esdm_dtls_send(extsock_dtls, req, sizeof(req));
		if (n)
			goto err;
	} else {
		n = send(extsock_fd, req, sizeof(req),
			 MSG_DONTWAIT | MSG_NOSIGNAL);
		if (n != (ssize_t)sizeof(req)) {
			n = n < 0 ? -errno : -EIO;
			goto err;
		}
	}
	*sent = true;

	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		struct pollfd pfd = { .fd = extsock_fd, .events = POLLIN };
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
		if (extsock_dtls && esdm_dtls_pending(extsock_dtls))
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

		if (extsock_dtls) {
			/* A message larger than any answer is -EMSGSIZE */
			n = esdm_dtls_recv(extsock_dtls, rsp,
					   ESDM_ES_EXT_PROTO_RSP_LEN +
						   ESDM_ES_EXT_PROTO_MAX_DATA);
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
		n = recv(extsock_fd, rsp,
			 ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA,
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
		if ((size_t)n >
		    ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA) {
			n = -EPROTO;
			goto err;
		}

		return n;
	}

err:
	esdm_es_extsock_drop_locked();
	return n;
}

/* As above, for a caller that does not care whether the request went out */
static ssize_t esdm_es_extsock_transact_locked(uint16_t type, uint32_t length,
					       uint8_t *rsp)
{
	bool sent;

	return esdm_es_extsock_request_locked(type, length, rsp, &sent);
}

static int esdm_es_extsock_reconnect_locked(void)
{
	int ret = esdm_es_extsock_connect_locked();

	if (ret)
		extsock_retry_at = esdm_es_extsock_now() +
				   ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;
	else
		extsock_retry_at = 0;
	return ret;
}

static int esdm_es_extsock_init(void)
{
	/* What the provider delivers per request fits into a seed buffer */
	BUILD_BUG_ON(ESDM_DRNG_INIT_SEED_SIZE_BYTES >
		     ESDM_ES_EXT_PROTO_MAX_DATA);

	mutex_lock(&extsock_mutex);
	extsock_retry_at = 0;
	extsock_probe_at = 0;
	extsock_last_logged = 0;
	extsock_was_connected = false;
	extsock_read_failed = false;
	extsock_selftest_failed = false;
	extsock_selftest_due = true;
	extsock_status_warned = false;
	extsock_status_backoff_until = 0;
	esdm_es_extsock_status_forget_locked();
	/* A provider not there yet is connected to on demand */
	if (esdm_es_extsock_configured_locked())
		(void)esdm_es_extsock_connect_locked();
	esdm_es_extsock_unlock();

	return 0;
}

static void esdm_es_extsock_fini(void)
{
	mutex_lock(&extsock_mutex);
	esdm_es_extsock_disconnect_locked();
	esdm_dtls_ctx_free(extsock_dtls_ctx);
	extsock_dtls_ctx = NULL;
	extsock_read_failed = false;
	extsock_selftest_failed = false;
	esdm_es_extsock_status_forget_locked();
	esdm_es_extsock_unlock();
}

static uint32_t esdm_es_extsock_level(bool credited, uint32_t requested_bits)
{
	if (!credited)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_ext_socket_entropy_rate(), requested_bits);
}

/* Caller must hold extsock_mutex. */
static uint32_t esdm_es_extsock_entropylevel_locked(uint32_t requested_bits)
{
	return esdm_es_extsock_level(esdm_es_extsock_credited_locked(),
				     requested_bits);
}

/* As published: a request in progress is not waited for */
static uint32_t esdm_es_extsock_entropylevel(uint32_t requested_bits)
{
	return esdm_es_extsock_level(atomic_load(&extsock_published_credited),
				     requested_bits);
}

static uint32_t esdm_es_extsock_poolsize(void)
{
	return esdm_es_extsock_entropylevel(esdm_security_strength());
}

static void esdm_es_extsock_get(struct entropy_es *eb_es,
				uint32_t requested_bits,
				bool __unused allow_cached)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	uint32_t claimed, len = requested_bits >> 3;
	const uint8_t *data;
	const char *why = NULL;
	int32_t status;
	ssize_t n;

	eb_es->e_bits = 0;
	if (!len || len > sizeof(eb_es->e))
		return;

	/* Exclusive: one request at a time, and its outcome is recorded */
	mutex_lock(&extsock_mutex);

	if (!esdm_es_extsock_ensure_locked())
		goto out;

	n = esdm_es_extsock_transact_locked(ESDM_ES_EXT_PROTO_GET_ENTROPY, len,
					    rsp);
	if (n < 0) {
		why = strerror((int)-n);
		goto fail;
	}

	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY, len,
					 &status, &claimed, &data)) {
		/* A connection that brings such things is not used again */
		esdm_es_extsock_drop_locked();
		why = "invalid answer, disconnected";
		goto fail;
	}

	if (status) {
		why = strerror(-status);
		goto fail;
	}

	memcpy(eb_es->e, data, len);
	extsock_read_failed = false;
	eb_es->e_bits = min_uint32(
		claimed, esdm_es_extsock_entropylevel_locked(requested_bits));

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from external ES provider\n",
		    eb_es->e_bits);
	goto out;

fail:
	if (!extsock_read_failed)
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "External ES provider: no entropy delivered: %s\n",
			    why);
	extsock_read_failed = true;

out:
	esdm_es_extsock_unlock();
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
static int esdm_es_extsock_monitor(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t claimed;
	int32_t status;
	time_t now;
	ssize_t n;

	mutex_lock(&extsock_mutex);

	if (!esdm_es_extsock_ensure_locked() || !extsock_read_failed)
		goto out;

	now = esdm_es_extsock_now();
	if (now < extsock_probe_at)
		goto out;
	extsock_probe_at = now + ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC;

	n = esdm_es_extsock_transact_locked(ESDM_ES_EXT_PROTO_GET_ENTROPY,
					    ESDM_DRNG_SECURITY_STRENGTH_BYTES,
					    rsp);
	if (n < 0)
		goto out;
	if (esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY,
					 ESDM_DRNG_SECURITY_STRENGTH_BYTES,
					 &status, &claimed, &data)) {
		esdm_es_extsock_drop_locked();
		goto out;
	}
	if (!status) {
		extsock_read_failed = false;
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "External ES provider: delivering again\n");
	}

out:
	esdm_es_extsock_unlock();
	memset_secure(rsp, 0, sizeof(rsp));
	return 0;
}

/*
 * The status the provider reports of itself, NULL for none. Caller must hold
 * extsock_mutex (write lock).
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
static struct json_object *esdm_es_extsock_status_locked(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	struct json_object *obj = NULL;
	time_t now = esdm_es_extsock_now();
	bool retried = false, sent;
	const char *text;
	size_t textlen;
	int32_t status;
	ssize_t n;

	if (extsock_fd < 0 || extsock_status_refused ||
	    now < extsock_status_backoff_until)
		return NULL;

again:
	n = esdm_es_extsock_request_locked(ESDM_ES_EXT_PROTO_STATUS,
					   ESDM_ES_EXT_STATUS_MAX, rsp, &sent);
	if (n < 0 && !sent) {
		if (retried)
			goto out;
		retried = true;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider: connection gone (%s), connecting again\n",
			strerror((int)-n));
		if (esdm_es_extsock_reconnect_locked())
			goto out;
		goto again;
	}
	if (n == -ECONNRESET) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"External ES provider: STATUS refused, connecting again\n");
		(void)esdm_es_extsock_reconnect_locked();
		extsock_status_refused = true;
		goto out;
	}
	if (n == -ETIMEDOUT) {
		extsock_status_backoff_until =
			now + ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC;
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider: no answer to STATUS in time, disconnected - not asked for its status for %u seconds\n",
			ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC);
		goto out;
	}
	/* An answer larger than any: disconnected as for any other request */
	if (n == -EPROTO || n == -EMSGSIZE) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider: invalid answer to STATUS, disconnected\n");
		goto out;
	}
	if (n < 0) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
			    "External ES provider: no answer to STATUS: %s\n",
			    strerror((int)-n));
		goto out;
	}

	if (esdm_es_ext_proto_status_unpack(rsp, (size_t)n,
					    ESDM_ES_EXT_STATUS_MAX, &status,
					    &text, &textlen)) {
		/* A connection that brings such things is not used again */
		esdm_es_extsock_drop_locked();
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"External ES provider: invalid answer to STATUS, disconnected\n");
		goto out;
	}

	if (status) {
		if (status != -EOPNOTSUPP)
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "External ES provider: no status: %s\n",
				    strerror(-status));
		goto out;
	}

	obj = esdm_es_ext_status_parse(text, textlen, "provider",
				       &extsock_status_warned);

out:
	memset_secure(rsp, 0, sizeof(rsp));
	return obj;
}

static void esdm_es_extsock_es_state(struct json_object *obj)
{
	uint32_t poolsize, entropy_rate;
	char path[sizeof(extsock_state_path)], status[64], accepted[48];
	struct json_object *provider;
	time_t now = esdm_es_extsock_now();
	long peer_uid;
	bool due;

	mutex_lock(&extsock_state_mutex);
	due = esdm_es_ext_status_cache_due(&extsock_status, now);
	mutex_unlock(&extsock_state_mutex);

	/*
	 * The status of the provider is asked for anew once the last one is
	 * older than ESDM_ES_EXT_STATUS_INTERVAL_SEC - unless a request is in
	 * progress on the connection, one of a seeding, which may take up to
	 * the timeout: the ESDM status is not to wait for it, and goes without
	 * the status of the provider then. Before the state of the connection
	 * is taken, which asking for it may change.
	 */
	if (due && mutex_trylock(&extsock_mutex)) {
		provider = esdm_es_extsock_status_locked();
		mutex_lock(&extsock_state_mutex);
		esdm_es_ext_status_cache_set(&extsock_status, provider, now);
		mutex_unlock(&extsock_state_mutex);
		esdm_es_extsock_unlock();
		due = false;
	}

	mutex_lock(&extsock_state_mutex);
	provider = due ? NULL : esdm_es_ext_status_cache_get(&extsock_status);
	snprintf(path, sizeof(path), "%s", extsock_state_path);
	snprintf(status, sizeof(status), "%s", extsock_state_status);
	peer_uid = extsock_state_peer_uid;
	mutex_unlock(&extsock_state_mutex);

	poolsize = esdm_es_extsock_entropylevel(esdm_security_strength());
	entropy_rate = esdm_es_extsock_entropylevel(256);

	if (peer_uid >= 0)
		snprintf(accepted, sizeof(accepted), "root and uid %ld",
			 peer_uid);
	else
		snprintf(accepted, sizeof(accepted), "root");

	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(poolsize));
	json_object_object_add(obj, "entropy_rate_per_256_data_bits",
			       json_object_new_int64(entropy_rate));
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
static bool esdm_es_extsock_active(void)
{
	return atomic_load(&extsock_published_configured);
}

/*
 * The self test of the provider connected to. Caller must hold extsock_mutex
 * (write lock) with the provider connected.
 *
 * @return 0 if it passed, -EFAULT if it failed or was not answered - the
 *	   connection is closed then
 */
static int esdm_es_extsock_selftest_locked(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	uint32_t bits;
	const uint8_t *data;
	int32_t status;
	ssize_t n;

	n = esdm_es_extsock_transact_locked(ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp);
	if (n < 0 || esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
						  ESDM_ES_EXT_PROTO_SELFTEST, 0,
						  &status, &bits, &data)) {
		/* No verdict on the noise source, but no working connection */
		esdm_es_extsock_drop_locked();
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider: self test not answered\n");
		extsock_read_failed = true;
		return -EFAULT;
	}

	extsock_selftest_due = false;

	if (status) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider: self test failed: %s\n",
			    strerror(-status));
		extsock_selftest_failed = true;
		return -EFAULT;
	}
	extsock_selftest_failed = false;

	return 0;
}

/*
 * The self test of the provider. One that is not connected is no failure:
 * it is credited with nothing until it is, and tested once connected to.
 */
static int esdm_es_extsock_selftest(void)
{
	int ret = 0;

	mutex_lock(&extsock_mutex);

	if (!esdm_es_extsock_ensure_locked()) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"External ES provider: not connected - nothing to test\n");
		goto out;
	}

	ret = esdm_es_extsock_selftest_locked();

out:
	esdm_es_extsock_unlock();
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_socket_set_path(const char *path)
{
	struct sockaddr_un addr;
	char *new_copy = NULL;
	char *old;

	if (!path || strlen(path) >= sizeof(addr.sun_path))
		return -EINVAL;

	if (path[0] != '\0') {
		new_copy = strdup(path);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&extsock_mutex);
	old = extsock_runtime_path;
	extsock_runtime_path = new_copy;

	/* The provider of the new path is connected to on demand */
	esdm_es_extsock_disconnect_locked();
	extsock_retry_at = 0;
	extsock_probe_at = 0;
	extsock_last_logged = 0;
	extsock_was_connected = false;
	extsock_read_failed = false;
	extsock_selftest_failed = false;
	extsock_selftest_due = true;
	extsock_status_warned = false;
	extsock_status_backoff_until = 0;
	esdm_es_extsock_status_forget_locked();
	esdm_es_extsock_unlock();

	free(old);

	return 0;
}

DSO_PUBLIC
int esdm_es_ext_socket_set_peer_uid(long uid)
{
	/* (uid_t)-1 is no uid, see setreuid(2) */
	if (uid < -1 || (uid >= 0 && (unsigned long)uid >= UINT32_MAX))
		return -EINVAL;

	mutex_lock(&extsock_mutex);
	extsock_peer_uid = uid;
	esdm_es_extsock_unlock();

	return 0;
}

struct esdm_es_cb esdm_es_extsock = {
	.name = "ExternalSocket",
	.init = esdm_es_extsock_init,
	.fini = esdm_es_extsock_fini,
	.monitor_es = esdm_es_extsock_monitor,
	.get_ent = esdm_es_extsock_get,
	.curr_entropy = esdm_es_extsock_entropylevel,
	.max_entropy = esdm_es_extsock_poolsize,
	.state = esdm_es_extsock_es_state,
	.reset = NULL,
	.active = esdm_es_extsock_active,
	.selftest = esdm_es_extsock_selftest,
};
