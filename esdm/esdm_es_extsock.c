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
 * connection given up on.
 *
 * Whoever can create the socket file at the configured path could feed the
 * ESDM with data credited as entropy, so the credentials of the provider are
 * checked on every connection: root, or the one uid configured in addition.
 *
 * A block is credited with what the provider claims for it, at most with what
 * the configured rate allows (esdm_config_es_ext_socket_entropy_rate()). A
 * provider that fails is credited with nothing until it delivers again, on a
 * seeding that asks it or on a probe of the ES monitor; one failing its self
 * test is credited with nothing until a self test passes.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <poll.h>
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
#include "esdm_es_ext_proto.h"
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
 * The last request to the provider failed, or its last self test did. Kept
 * apart as for the plugin source: only data delivered clears a failed request,
 * only a self test that passes clears a failed self test - not a new
 * connection either. Set and cleared under the write lock, read under the
 * reader lock.
 */
static bool extsock_read_failed = false;
static bool extsock_selftest_failed = false;

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

/* Caller must hold extsock_mutex (write lock). */
static void esdm_es_extsock_disconnect_locked(void)
{
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
static int esdm_es_extsock_connect_locked(void)
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
	extsock_last_logged = 0;
	/* Its claims are not assessed by the ESDM, which is worth a line */
	esdm_logger(
		extsock_was_connected ? LOGGER_VERBOSE : LOGGER_STATUS,
		LOGGER_C_ES,
		"External ES provider %s connected (uid %u), its entropy claims credited with up to %u bits per 256 bits\n",
		path, (unsigned int)cred.uid,
		esdm_config_es_ext_socket_entropy_rate());
	extsock_was_connected = true;
	return 0;

err:
	close(fd);
	return ret;
}

/*
 * Connected, or connected now if the time has come to try again. Caller must
 * hold extsock_mutex (write lock).
 */
static bool esdm_es_extsock_ensure_locked(void)
{
	time_t now;

	if (extsock_fd >= 0)
		return true;
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
 * bytes. Caller must hold extsock_mutex (write lock) with the provider
 * connected.
 *
 * @return the size of the answer, or a negative errno, in which case the
 *	   connection is closed
 */
static ssize_t esdm_es_extsock_transact_locked(uint16_t type, uint32_t length,
					       uint8_t *rsp)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	struct timespec start, now;
	ssize_t n;

	esdm_es_ext_proto_req_pack(req, type, length);

	/*
	 * One request at a time: the provider's answers are read before the
	 * next request goes out, so this fits into the socket buffer.
	 */
	n = send(extsock_fd, req, sizeof(req), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n != (ssize_t)sizeof(req)) {
		n = n < 0 ? -errno : -EIO;
		goto err;
	}

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

		ret = poll(&pfd, 1,
			   (int)(ESDM_EXT_SOCKET_TIMEOUT_MS - elapsed_ms));
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0) {
			n = -errno;
			goto err;
		}
		if (ret == 0)
			continue;

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
	/* A provider not there yet is connected to on demand */
	if (esdm_es_extsock_configured_locked())
		(void)esdm_es_extsock_connect_locked();
	mutex_unlock(&extsock_mutex);

	return 0;
}

static void esdm_es_extsock_fini(void)
{
	mutex_lock(&extsock_mutex);
	esdm_es_extsock_disconnect_locked();
	extsock_read_failed = false;
	extsock_selftest_failed = false;
	mutex_unlock(&extsock_mutex);
}

/* Caller must hold extsock_mutex. */
static uint32_t esdm_es_extsock_entropylevel_locked(uint32_t requested_bits)
{
	if (extsock_fd < 0 || extsock_read_failed || extsock_selftest_failed)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_ext_socket_entropy_rate(), requested_bits);
}

static uint32_t esdm_es_extsock_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&extsock_mutex);
	ret = esdm_es_extsock_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&extsock_mutex);

	return ret;
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
	mutex_unlock(&extsock_mutex);
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
	mutex_unlock(&extsock_mutex);
	memset_secure(rsp, 0, sizeof(rsp));
	return 0;
}

static void esdm_es_extsock_es_state(char *buf, size_t buflen)
{
	uint32_t poolsize, entropy_rate;
	char path[PATH_MAX], status[64];
	long peer_uid;

	mutex_reader_lock(&extsock_mutex);
	poolsize =
		esdm_es_extsock_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_es_extsock_entropylevel_locked(256);
	snprintf(path, sizeof(path), "%s", esdm_es_extsock_path_locked());
	if (extsock_fd < 0)
		snprintf(status, sizeof(status), "not connected");
	else
		snprintf(status, sizeof(status), "connected (uid %u)%s",
			 (unsigned int)extsock_connected_uid,
			 extsock_selftest_failed ? ", failing its self test" :
			 extsock_read_failed	 ? ", failing" :
						   "");
	peer_uid = extsock_peer_uid;
	mutex_reader_unlock(&extsock_mutex);

	snprintf(buf, buflen,
		 " Available entropy: %u\n"
		 " Entropy Rate per 256 data bits: %u\n"
		 " Provider socket: %s\n"
		 " Provider accepted: root%s%ld\n"
		 " Status: %s\n",
		 poolsize, entropy_rate, path[0] ? path : "(unset)",
		 peer_uid >= 0 ? " and uid " : "", peer_uid >= 0 ? peer_uid : 0,
		 status);
}

/*
 * Active as long as a provider is configured: one that is not reachable at a
 * time is connected to again on demand.
 */
static bool esdm_es_extsock_active(void)
{
	bool ret;

	mutex_reader_lock(&extsock_mutex);
	ret = esdm_es_extsock_configured_locked();
	mutex_reader_unlock(&extsock_mutex);

	return ret;
}

/*
 * The self test of the provider. One that is not connected is no failure:
 * it is credited with nothing until it is, and connected to on demand.
 */
static int esdm_es_extsock_selftest(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	uint32_t bits;
	const uint8_t *data;
	int32_t status;
	ssize_t n;
	int ret = 0;

	mutex_lock(&extsock_mutex);

	if (!esdm_es_extsock_ensure_locked()) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"External ES provider: not connected - nothing to test\n");
		goto out;
	}

	n = esdm_es_extsock_transact_locked(ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp);
	if (n < 0 || esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
						  ESDM_ES_EXT_PROTO_SELFTEST, 0,
						  &status, &bits, &data)) {
		/* No verdict on the noise source, but no working connection */
		esdm_es_extsock_drop_locked();
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider: self test not answered\n");
		extsock_read_failed = true;
		ret = -EFAULT;
		goto out;
	}

	if (status) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "External ES provider: self test failed: %s\n",
			    strerror(-status));
		extsock_selftest_failed = true;
		ret = -EFAULT;
		goto out;
	}
	extsock_selftest_failed = false;

out:
	mutex_unlock(&extsock_mutex);
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
	mutex_unlock(&extsock_mutex);

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
	mutex_unlock(&extsock_mutex);

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
