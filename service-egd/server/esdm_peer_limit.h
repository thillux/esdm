/*
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

/*
 * Per-UID connection accounting of the server sockets.
 *
 * All interfaces of the esdm-server share one RLIMIT_NOFILE. Without a bound
 * per peer, a single unprivileged user could open connections until the
 * interface's own connection cap - or the descriptor limit - is reached and
 * shut everybody else out. Each interface therefore admits only so many
 * concurrent connections per peer UID, as told by SO_PEERCRED. Root is exempt:
 * it can take the daemon down anyway, and the privileged interface is its
 * alone.
 *
 * Interfaces served by several threads share one accounting instance, which is
 * thread safe.
 */

#ifndef ESDM_PEER_LIMIT_H
#define ESDM_PEER_LIMIT_H

#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ESDM_PEER_LIMIT_BUCKETS 64

struct esdm_peer_limit_entry;

struct esdm_peer_limit {
	pthread_mutex_t lock;
	/* Name of the interface for the log */
	const char *name;
	/* Concurrent connections admitted per unprivileged UID */
	unsigned int max_per_uid;
	struct esdm_peer_limit_entry *buckets[ESDM_PEER_LIMIT_BUCKETS];
};

#define ESDM_PEER_LIMIT_INIT(_name, _max)                                      \
	{ .lock = PTHREAD_MUTEX_INITIALIZER,                                   \
	  .name = _name,                                                       \
	  .max_per_uid = _max }

/**
 * @brief Account one more connection of @uid
 *
 * @return true when the connection is admitted - and then has to be released
 *	   with esdm_peer_limit_put() -, false when @uid is at its limit (or the
 *	   accounting is out of memory) and the connection has to be refused
 */
bool esdm_peer_limit_get(struct esdm_peer_limit *limit, uid_t uid);

/**
 * @brief Release a connection admitted by esdm_peer_limit_get()
 */
void esdm_peer_limit_put(struct esdm_peer_limit *limit, uid_t uid);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_PEER_LIMIT_H */
