/*
 * Client for the EGD (Entropy Gathering Daemon) interface of the ESDM
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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "bitshift_be.h"
#include "config.h"
#include "esdm_egd_client.h"
#include "esdm_egd_client_tls.h"
#include "esdm_egd_protocol.h"
#include "esdm_logger.h"
#include "esdm_tls.h"
#include "memset_secure.h"
#include "mutex_w.h"
#include "visibility.h"

/*
 * The TLS layer of esdm_tls.h: linked in for the daemons, and for the
 * library loaded as a module of its own when the first client in TLS mode is
 * allocated - see esdm_egd_client_tls.h. Every call goes through EGDC_TLS(),
 * and a call is only ever made for a client in TLS mode, which exists once the
 * module is loaded.
 */
/* Built with the thread sanitizer, which the fork handler tells about a lock */
#if defined(__SANITIZE_THREAD__)
#define ESDM_EGD_CLIENT_TSAN
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define ESDM_EGD_CLIENT_TSAN
#endif
#endif

#ifdef ESDM_EGD_CLIENT_TSAN
#include <sanitizer/tsan_interface.h>
#endif

#if defined(ESDM_EGD_NET_TLS) && defined(ESDM_EGD_CLIENT_TLS_MODULE)
#include <dlfcn.h>

static const struct esdm_egd_tls_module *esdm_egd_tls_mod = NULL;
#define EGDC_TLS(fn) (esdm_egd_tls_mod->fn)
#elif defined(ESDM_EGD_NET_TLS)
#define EGDC_TLS(fn) esdm_tls_##fn
#else
/*
 * No TLS mode: no client ever has a TLS, and none of these is called. The TLS
 * layer may still be built - for es-ext-net -, but it is not for this library
 * to link it, and with it the TLS stack: the library needs the C library and
 * nothing else.
 */
#define EGDC_TLS(fn) esdm_egd_notls_##fn

static inline void esdm_egd_notls_free(struct esdm_tls *tls)
{
	(void)tls;
}

static inline void esdm_egd_notls_close_notify(struct esdm_tls *tls)
{
	(void)tls;
}

static inline ssize_t esdm_egd_notls_send(struct esdm_tls *tls,
					  const void *buf, size_t len)
{
	(void)tls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline int esdm_egd_notls_flush(struct esdm_tls *tls)
{
	(void)tls;
	return -EOPNOTSUPP;
}

static inline ssize_t esdm_egd_notls_recv(struct esdm_tls *tls, void *buf,
					  size_t len)
{
	(void)tls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline int esdm_egd_notls_wait(struct esdm_tls *tls, int timeout_ms)
{
	(void)tls;
	(void)timeout_ms;
	return -EOPNOTSUPP;
}

static inline const char *esdm_egd_notls_error(struct esdm_tls *tls)
{
	(void)tls;
	return "no TLS";
}
#endif

/*
 * Attempts per operation: the initial one plus a single retry on a freshly
 * opened connection. A second retry would not add anything - if a brand new
 * connection cannot carry the request either, the peer is not merely gone
 * since the last one.
 */
#define ESDM_EGD_CLIENT_ATTEMPTS 2

/*
 * Default bound, in milliseconds, on how long the client waits for the peer in
 * one step - the connection setup, or one transfer. Generous, because the
 * blocking read waits for the ESDM to become operational, which right after
 * boot takes a moment: this is a backstop against a wedged daemon, not a
 * latency target.
 */
#define ESDM_EGD_CLIENT_DEFAULT_TIMEOUT_MS 30000

/*
 * How long to wait before retrying a connect that found the peer's listen
 * backlog full. There is nothing to poll for in that case - the connection was
 * never initiated - so this is a plain retry interval, kept short because a
 * full backlog clears as soon as the peer accepts.
 */
#define ESDM_EGD_CLIENT_BACKLOG_RETRY_MS 20

/*
 * Upper bound of the configurable timeout. poll(2) takes its timeout as an
 * int, so an unreasonable value has to be capped rather than overflowed into a
 * nonsensical - possibly negative, i.e. infinite - one.
 */
#define ESDM_EGD_CLIENT_MAX_TIMEOUT_MS 3600000

/*
 * Read commands of a blocking read sent at once, see
 * esdm_egd_client_get_random_op(): 512 bytes of commands, 64 KiB of answers.
 */
#define ESDM_EGD_CLIENT_PIPELINE 256

/* Environment variable overriding the compiled in socket path. */
#define ESDM_EGD_CLIENT_SOCKET_ENV "ESDM_EGD_SOCKET"

/* Longest address of a server of the network, "[" host "]:" port */
#define ESDM_EGD_CLIENT_MAX_ADDRESS 300

/* How the client reaches the EGD */
enum esdm_egd_client_transport {
	/* The Unix domain socket of the esdm-server */
	ESDM_EGD_CLIENT_UNIX,
	/* Plain TCP to an esdm-egd-net-server */
	ESDM_EGD_CLIENT_TCP,
	/* TLS on TCP to an esdm-egd-net-server */
	ESDM_EGD_CLIENT_TLS,
};

struct esdm_egd_client_tls_cache;

struct esdm_egd_client {
	enum esdm_egd_client_transport transport;

	/*
	 * The Unix domain socket - or, in a network mode, the address of the
	 * server as it was given, which is what the log and
	 * esdm_egd_client_socket_path() tell.
	 */
	char socket_path[ESDM_EGD_CLIENT_MAX_ADDRESS];
	unsigned int timeout_ms;

	/* Network modes: the server as getaddrinfo(3) takes it */
	char *host;
	char *port;

	/* TLS mode: the name the server's certificate must be issued for */
	char *server_name;
	/* What the files of the configuration loaded, see the cache below */
	struct esdm_egd_client_tls_cache *tls_cache;
	/*
	 * The TLS of the connection on @fd. One inherited across fork() is left
	 * to leak, see esdm_egd_client_atfork_child().
	 */
	struct esdm_tls *tls;

	/*
	 * Serializes the command stream - see the header. Robust, because it is
	 * held across the whole request / response exchange, bounded by nothing
	 * but the client's timeout: a caller killed in that window - shot while
	 * waiting for an ESDM that is not operational yet - would leave a plain
	 * mutex locked for the rest of the process' lifetime. A robust mutex
	 * hands the lock to the next taker instead.
	 */
	mutex_w_t lock;

	int fd;
	/*
	 * Process that opened @fd. The fork handler below normally deals with
	 * an inherited connection, but it only runs for fork(3); this is the
	 * backstop for the ways around it - a direct clone(2), or a child of a
	 * process that was already forked before this library was loaded.
	 */
	pid_t owner_pid;

	/*
	 * Identity of the connection behind @fd, taken right after it was
	 * established - see esdm_egd_client_fd_is_ours_locked(). The socket
	 * cookie when the kernel has one, otherwise the peer's address - of a
	 * Unix domain or a TCP socket alike.
	 */
	bool have_cookie;
	uint64_t cookie;
	struct sockaddr_storage peer;
	socklen_t peer_len;

	/* SIGPIPE was ignored at connect time, see esdm_egd_client_write(). */
	bool sigpipe_ignored;

	/* Registry entry, see esdm_egd_client_atfork_child(). */
	TAILQ_ENTRY(esdm_egd_client) tailq;
};

/*
 * Every live client, so that the fork handler can reach them. The lock is only
 * ever held to walk or edit this list - never across I/O - which is what makes
 * it safe to take in the prepare handler: fork() is delayed by no more than a
 * list operation.
 */
static TAILQ_HEAD(esdm_egd_client_list, esdm_egd_client) esdm_egd_clients =
	TAILQ_HEAD_INITIALIZER(esdm_egd_clients);
/*
 * Statically initialized so it is a usable lock even before the one time
 * initialization below turns it into a robust one - and the fallback should
 * that ever fail.
 */
static DEFINE_MUTEX_W_UNLOCKED(esdm_egd_clients_lock);
static pthread_once_t esdm_egd_client_init_once = PTHREAD_ONCE_INIT;

/*
 * Take the registry lock.
 *
 * EOWNERDEAD reports that the previous owner died while holding it. The lock is
 * recovered by the wrapper and the list is used as found - a TAILQ operation is
 * not atomic, so an owner that died inside one may have left it inconsistent,
 * with no way to tell from here. Still better than the alternative, where every
 * later alloc and free waits forever for a lock nobody can release.
 */
static void esdm_egd_clients_lock_acquire(void)
{
	if (mutex_w_lock(&esdm_egd_clients_lock) == EOWNERDEAD) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: the client registry was left behind by a died owner - continuing with it as found\n");
	}
}

/****************************
 * TLS contexts
 ****************************/

/*
 * What the files of a TLS configuration loaded, shared by every client of the
 * process configured with the same files: a relay serving many local
 * connections loads them once, and all of its clients take up a rotation
 * together.
 *
 * Each new connection compares the stamp of the files - see esdm_tls_stamp()
 * - with the one they were loaded with, and loads them anew once it changed.
 * Only a context that loaded completely replaces the one in use; a broken
 * rotation is logged and leaves the clients with what they had. The stamp is
 * taken over either way, so that the broken files are not loaded again by
 * every connection - the next change of them is.
 *
 * The list and the members of an entry but its configuration are guarded by
 * the cache lock, which is never held across the loading of files, let alone
 * across I/O.
 */
struct esdm_egd_client_tls_cache {
	TAILQ_ENTRY(esdm_egd_client_tls_cache) tailq;
	unsigned int refcnt;

	/* The configuration, its strings owned by the entry */
	struct esdm_tls_config cfg;

	uint8_t stamp[ESDM_TLS_STAMP_LEN];
	struct esdm_tls_ctx *ctx;
};

static DEFINE_MUTEX_W_UNLOCKED(esdm_egd_tls_cache_lock);

#ifdef ESDM_EGD_NET_TLS

static TAILQ_HEAD(esdm_egd_client_tls_cache_list,
		  esdm_egd_client_tls_cache) esdm_egd_tls_caches =
	TAILQ_HEAD_INITIALIZER(esdm_egd_tls_caches);

static pthread_once_t esdm_egd_tls_load_once = PTHREAD_ONCE_INIT;
static int esdm_egd_tls_load_ret = -EOPNOTSUPP;

/*
 * Load the TLS module, once per process and for good - see
 * esdm_egd_client_tls.h. Linked in, there is nothing to load.
 */
static void esdm_egd_tls_load_module(void)
{
#ifdef ESDM_EGD_CLIENT_TLS_MODULE
	const struct esdm_egd_tls_module *(*entry)(void);
	const struct esdm_egd_tls_module *mod;
	const char *path = secure_getenv(ESDM_EGD_TLS_MODULE_ENV);
	void *handle, *sym;

	if (!path || !*path)
		path = ESDM_EGD_TLS_MODULE_PATH;

	handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: cannot load the TLS module %s: %s\n",
			    path, dlerror());
		return;
	}

	/* ISO C has no conversion of an object to a function pointer */
	sym = dlsym(handle, ESDM_EGD_TLS_MODULE_SYMBOL);
	memcpy(&entry, &sym, sizeof(entry));
	mod = entry ? entry() : NULL;
	if (!mod || mod->version != ESDM_EGD_TLS_MODULE_VERSION) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"EGD client: %s is no TLS module of this library\n",
			path);
		dlclose(handle);
		return;
	}

	esdm_egd_tls_mod = mod;
#endif
	esdm_egd_tls_load_ret = 0;
}

/* @return 0 once the TLS layer can be used, -EOPNOTSUPP if it cannot */
static int esdm_egd_tls_load(void)
{
	pthread_once(&esdm_egd_tls_load_once, esdm_egd_tls_load_module);
	return esdm_egd_tls_load_ret;
}

static void esdm_egd_tls_cache_lock_acquire(void)
{
	/* Nothing it guards is left inconsistent by a died owner */
	mutex_w_lock(&esdm_egd_tls_cache_lock);
}

static bool esdm_egd_tls_str_eq(const char *a, const char *b)
{
	if (!a || !b)
		return a == b;
	return !strcmp(a, b);
}

static bool esdm_egd_tls_cfg_eq(const struct esdm_tls_config *a,
				const struct esdm_tls_config *b)
{
	unsigned int i;

	if (!esdm_egd_tls_str_eq(a->cert_file, b->cert_file) ||
	    !esdm_egd_tls_str_eq(a->key_file, b->key_file) ||
	    !esdm_egd_tls_str_eq(a->ca_file, b->ca_file) ||
	    a->crl_files_num != b->crl_files_num ||
	    a->crl_check_all != b->crl_check_all ||
	    a->crl_allow_expired != b->crl_allow_expired)
		return false;

	for (i = 0; i < a->crl_files_num; i++) {
		if (!esdm_egd_tls_str_eq(a->crl_files[i], b->crl_files[i]))
			return false;
	}

	return true;
}

static void esdm_egd_tls_cache_free(struct esdm_egd_client_tls_cache *cache)
{
	unsigned int i;

	if (!cache)
		return;

	EGDC_TLS(ctx_put)(cache->ctx);
	free((char *)cache->cfg.cert_file);
	free((char *)cache->cfg.key_file);
	free((char *)cache->cfg.ca_file);
	for (i = 0; i < cache->cfg.crl_files_num; i++)
		free((char *)cache->cfg.crl_files[i]);
	free(cache);
}

static char *esdm_egd_tls_strdup(const char *s, bool *failed)
{
	char *copy;

	if (!s)
		return NULL;
	copy = strdup(s);
	if (!copy)
		*failed = true;
	return copy;
}

/*
 * The entry of the configuration @cfg, with a reference of the caller: an
 * existing one, or a new one whose files loaded.
 */
static int esdm_egd_tls_cache_get(const struct esdm_tls_config *cfg,
				  struct esdm_egd_client_tls_cache **out)
{
	struct esdm_egd_client_tls_cache *cache;
	bool failed = false;
	unsigned int i;
	int ret;

	esdm_egd_tls_cache_lock_acquire();
	TAILQ_FOREACH (cache, &esdm_egd_tls_caches, tailq) {
		if (esdm_egd_tls_cfg_eq(&cache->cfg, cfg)) {
			cache->refcnt++;
			mutex_w_unlock(&esdm_egd_tls_cache_lock);
			*out = cache;
			return 0;
		}
	}
	mutex_w_unlock(&esdm_egd_tls_cache_lock);

	cache = calloc(1, sizeof(*cache));
	if (!cache)
		return -ENOMEM;
	cache->refcnt = 1;

	cache->cfg.cert_file = esdm_egd_tls_strdup(cfg->cert_file, &failed);
	cache->cfg.key_file = esdm_egd_tls_strdup(cfg->key_file, &failed);
	cache->cfg.ca_file = esdm_egd_tls_strdup(cfg->ca_file, &failed);
	for (i = 0; i < cfg->crl_files_num; i++) {
		cache->cfg.crl_files[i] =
			esdm_egd_tls_strdup(cfg->crl_files[i], &failed);
		cache->cfg.crl_files_num++;
	}
	cache->cfg.crl_check_all = cfg->crl_check_all;
	cache->cfg.crl_allow_expired = cfg->crl_allow_expired;
	if (failed) {
		esdm_egd_tls_cache_free(cache);
		return -ENOMEM;
	}

	/* The stamp first: a change while loading is taken up next time */
	EGDC_TLS(stamp)(&cache->cfg, cache->stamp);
	ret = EGDC_TLS(ctx_alloc)(false, &cache->cfg, &cache->ctx);
	if (ret) {
		esdm_egd_tls_cache_free(cache);
		return ret;
	}
	EGDC_TLS(ctx_crl_report)(cache->ctx, true);

	/*
	 * Another thread may have added the same configuration meanwhile -
	 * two entries of it only load the files twice.
	 */
	esdm_egd_tls_cache_lock_acquire();
	TAILQ_INSERT_TAIL(&esdm_egd_tls_caches, cache, tailq);
	mutex_w_unlock(&esdm_egd_tls_cache_lock);

	*out = cache;
	return 0;
}

static void esdm_egd_tls_cache_put(struct esdm_egd_client_tls_cache *cache)
{
	bool last;

	if (!cache)
		return;

	esdm_egd_tls_cache_lock_acquire();
	last = !--cache->refcnt;
	if (last)
		TAILQ_REMOVE(&esdm_egd_tls_caches, cache, tailq);
	mutex_w_unlock(&esdm_egd_tls_cache_lock);

	if (last)
		esdm_egd_tls_cache_free(cache);
}

/*
 * The context for a new connection, with a reference of the caller - loaded
 * anew if the files changed since, see struct esdm_egd_client_tls_cache.
 */
static struct esdm_tls_ctx *
esdm_egd_tls_cache_ctx(struct esdm_egd_client_tls_cache *cache)
{
	struct esdm_tls_ctx *ctx = NULL, *old = NULL;
	uint8_t stamp[ESDM_TLS_STAMP_LEN];
	int ret;

	esdm_egd_tls_cache_lock_acquire();
	EGDC_TLS(stamp)(&cache->cfg, stamp);
	if (!memcmp(stamp, cache->stamp, sizeof(stamp))) {
		EGDC_TLS(ctx_get)(cache->ctx);
		ctx = cache->ctx;
		mutex_w_unlock(&esdm_egd_tls_cache_lock);
		return ctx;
	}
	/* Claimed: the other clients go on with what is loaded meanwhile */
	memcpy(cache->stamp, stamp, sizeof(stamp));
	mutex_w_unlock(&esdm_egd_tls_cache_lock);

	ret = EGDC_TLS(ctx_alloc)(false, &cache->cfg, &ctx);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"EGD client: the changed TLS files of %s do not load (%s) - keeping the ones loaded before\n",
			cache->cfg.cert_file ? cache->cfg.cert_file :
					       cache->cfg.ca_file,
			strerror(-ret));
		ctx = NULL;
	} else {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			    "EGD client: reloaded the TLS files of %s\n",
			    cache->cfg.cert_file ? cache->cfg.cert_file :
						   cache->cfg.ca_file);
		EGDC_TLS(ctx_crl_report)(ctx, true);
	}

	esdm_egd_tls_cache_lock_acquire();
	if (ctx) {
		old = cache->ctx;
		cache->ctx = ctx;
	}
	EGDC_TLS(ctx_get)(cache->ctx);
	ctx = cache->ctx;
	mutex_w_unlock(&esdm_egd_tls_cache_lock);

	/* Connections made with it keep their own reference */
	EGDC_TLS(ctx_put)(old);

	return ctx;
}

#endif /* ESDM_EGD_NET_TLS */

/****************************
 * Connection handling
 ****************************/

static bool esdm_egd_client_fd_is_ours_locked(struct esdm_egd_client *client);

/*
 * Let go of the connection. Caller holds the lock.
 *
 * The descriptor is only closed while it still is the connection: one the
 * application closed behind the client's back - see
 * esdm_egd_client_fd_is_ours_locked() - may carry whatever it opened since
 * under that number, and closing that would take it away from under the
 * application, and hand its number to the next connection of this client.
 *
 * @notify tells a TLS peer that the client goes, with a closing alert - only
 * for a connection that is in order, and never in the fork child.
 */
static void esdm_egd_client_disconnect_locked(struct esdm_egd_client *client,
					      bool notify)
{
	bool ours;

	if (client->fd < 0)
		return;

	ours = esdm_egd_client_fd_is_ours_locked(client);
	if (client->tls) {
		if (ours && notify)
			EGDC_TLS(close_notify)(client->tls);
		EGDC_TLS(free)(client->tls);
		client->tls = NULL;
	}

	if (ours)
		close(client->fd);
	client->fd = -1;
}

/****************************
 * fork handling
 ****************************/

/*
 * Hold the registry across the fork, so the child cannot inherit it mid-edit
 * and walk a half-linked list. The TLS cache lock is held for the same reason.
 */
static void esdm_egd_client_atfork_prepare(void)
{
	esdm_egd_clients_lock_acquire();
	mutex_w_lock(&esdm_egd_tls_cache_lock);
}

static void esdm_egd_client_atfork_parent(void)
{
	mutex_w_unlock(&esdm_egd_tls_cache_lock);
	mutex_w_unlock(&esdm_egd_clients_lock);
}

/*
 * Recreate a lock in the fork child, see esdm_egd_client_atfork_child() for
 * why that is what has to happen to every lock reachable from there. @held
 * tells that the prepare handler took it, in the very thread the child is a
 * copy of.
 */
static void esdm_egd_client_recreate_lock(mutex_w_t *lock, int robust,
					  bool held)
{
#ifdef ESDM_EGD_CLIENT_TSAN
	/*
	 * Held by the parent's thread as the thread sanitizer sees it, which
	 * goes by the thread, not by its ID: told the lock is released first,
	 * it does not take the recreation for the destruction of a lock in use.
	 */
	if (held) {
		__tsan_mutex_pre_unlock(&lock->lock, 0);
		__tsan_mutex_post_unlock(&lock->lock, 0);
	}
#else
	(void)held;
#endif

	/*
	 * The destroy fails with EBUSY for a lock that is still held - which is
	 * precisely the state this cleans up after. Nothing can be done about
	 * that, and the initialization below replaces the lock either way.
	 */
	mutex_w_destroy(lock);

	if (mutex_w_init(lock, 0, robust)) {
		static const mutex_w_t lock_init = MUTEX_W_UNLOCKED;

		/*
		 * A fork handler has nowhere to report to, and leaving the lock
		 * behind as it was found would hang the child. A plain mutex is
		 * still a working lock - only the recovery from a died owner is
		 * lost with it.
		 */
		*lock = lock_init;
	}
}

/*
 * Give up every inherited connection right here in the child.
 *
 * A child's duplicated descriptors refer to the parent's connections, and two
 * processes issuing commands on one EGD stream would desynchronize it. Closing
 * at the fork rather than at the next use also releases them immediately.
 *
 * The TLS of a connection is not released, ever, and no closing alert is sent:
 * the connection is the parent's, and a parent thread may have been in the
 * middle of using the TLS - or of freeing it - at the fork, which leaves it in
 * whatever state that was in, the pointer to it included. The child leaks it
 * instead: one TLS object per connection inherited.
 *
 * The locks are recreated rather than unlocked, robustness notwithstanding: it
 * only hands over a lock when a thread of *this* process dies, and a lock held
 * by a parent thread that does not exist here would hang the child forever.
 * That includes the registry lock the prepare handler took - a robust mutex
 * records its owner by thread ID and fork(2) gave this thread a new one, so to
 * the lock its owner no longer exists. The child is single threaded here, so
 * recreating is safe. The TLS cache lock is no robust mutex, and nothing but
 * the prepare handler can hold it at the fork: it is released as usual.
 *
 * pthread_mutex_destroy()/_init() are not formally async-signal-safe, but they
 * neither allocate nor lock in the implementations at hand, and a robust mutex
 * cannot be reset by assigning a static initializer over it.
 */
static void esdm_egd_client_atfork_child(void)
{
	struct esdm_egd_client *client;

	TAILQ_FOREACH (client, &esdm_egd_clients, tailq) {
		/*
		 * Not under the client's lock, which a parent thread may have
		 * held - the child is single threaded, and the lock is
		 * recreated right below. The TLS is not touched: leaked.
		 */
		client->tls = NULL;
		esdm_egd_client_disconnect_locked(client, false);

		esdm_egd_client_recreate_lock(&client->lock, 1, false);
	}

	mutex_w_unlock(&esdm_egd_tls_cache_lock);
	esdm_egd_client_recreate_lock(&esdm_egd_clients_lock, 1, true);
}

/* Process wide setup, run once from esdm_egd_client_alloc(). */
static void esdm_egd_client_init(void)
{
	/*
	 * Make the registry lock robust. It is only held for a list operation,
	 * but the prepare handler above holds it across the fork(2) itself, and
	 * a caller killed in that window would leave every later allocation and
	 * release waiting for a lock with no owner. A static initializer cannot
	 * express this, hence the one time initialization here.
	 */
	if (mutex_w_init(&esdm_egd_clients_lock, 0, 1)) {
		static const mutex_w_t lock_init = MUTEX_W_UNLOCKED;

		/*
		 * Restore the plain lock: a failed initialization may have left
		 * the mutex half set up, and the registry needs *a* lock.
		 */
		esdm_egd_clients_lock = lock_init;
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot create a robust registry lock - a caller dying while it is held then wedges the client registry\n");
	}

	if (pthread_atfork(esdm_egd_client_atfork_prepare,
			   esdm_egd_client_atfork_parent,
			   esdm_egd_client_atfork_child)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot install the fork handler - an inherited connection is then only dropped at its next use\n");
	}
}

/* Milliseconds on the monotonic clock. */
static uint64_t esdm_egd_client_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Milliseconds left until @deadline_ms, 0 once it passed. */
static int esdm_egd_client_remaining_ms(uint64_t deadline_ms)
{
	uint64_t now = esdm_egd_client_now_ms();
	uint64_t remaining;

	if (now >= deadline_ms)
		return 0;

	remaining = deadline_ms - now;

	return (remaining > INT_MAX) ? INT_MAX : (int)remaining;
}

/*
 * Wait for @events on @fd, bounded by @timeout_ms.
 *
 * A signal interrupting the wait does not start it over: the wait goes on for
 * what is left of @timeout_ms. A periodic signal - an interval timer, a stream
 * of SIGCHLD - would otherwise keep a wait for a wedged peer from ever running
 * out.
 *
 * @return 0 when the descriptor is ready, -ETIMEDOUT when the wait ran out,
 *	   negative errno otherwise. @revents, when given, reports what poll
 *	   found - an error condition is not turned into a failure here, as the
 *	   caller decides whether it matters.
 */
static int esdm_egd_client_wait(int fd, short events, int timeout_ms,
				short *revents)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = events,
	};
	uint64_t deadline = esdm_egd_client_now_ms() + (uint64_t)timeout_ms;
	int ret;

	while ((ret = poll(&pfd, 1, timeout_ms)) < 0 && errno == EINTR)
		timeout_ms = esdm_egd_client_remaining_ms(deadline);

	if (revents)
		*revents = pfd.revents;

	if (ret < 0)
		return -errno;
	if (ret == 0)
		return -ETIMEDOUT;

	return 0;
}

/*
 * Connect @fd to @addr, bounded by @deadline.
 *
 * The socket is non-blocking, which is what makes the bound possible in the
 * first place: a blocking connect() to a Unix domain socket whose peer has a
 * full listen backlog waits for as long as it takes, with no way to limit it,
 * and one over TCP for as long as the SYN is retransmitted.
 */
static int esdm_egd_client_connect_fd(int fd, const struct sockaddr *addr,
				      socklen_t addrlen, uint64_t deadline)
{
	while (1) {
		int remaining, ret;

		if (connect(fd, addr, addrlen) == 0)
			return 0;

		if (errno == EINTR)
			continue;

		/*
		 * A Unix domain socket reports a full listen backlog this way
		 * instead of blocking. The connection was never initiated, so
		 * there is nothing to poll for - wait a moment and try again
		 * until the deadline.
		 */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct timespec retry = {
				.tv_sec = 0,
				.tv_nsec = ESDM_EGD_CLIENT_BACKLOG_RETRY_MS *
					   1000L * 1000L,
			};

			remaining = esdm_egd_client_remaining_ms(deadline);
			if (remaining <= 0)
				return -ETIMEDOUT;
			if (remaining < ESDM_EGD_CLIENT_BACKLOG_RETRY_MS)
				retry.tv_nsec = (long)remaining * 1000L * 1000L;

			nanosleep(&retry, NULL);
			continue;
		}

		/* What a TCP socket does: the connection completes later */
		if (errno == EINPROGRESS || errno == EALREADY) {
			int err = 0;
			socklen_t errlen = sizeof(err);

			remaining = esdm_egd_client_remaining_ms(deadline);
			if (remaining <= 0)
				return -ETIMEDOUT;

			ret = esdm_egd_client_wait(fd, POLLOUT, remaining, NULL);
			if (ret)
				return ret;

			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err,
				       &errlen) < 0)
				return -errno;

			return err ? -err : 0;
		}

		return -errno;
	}
}

#ifdef SO_COOKIE
/* The cookie of the socket @fd - never shared by two sockets until reboot. */
static int esdm_egd_client_cookie(int fd, uint64_t *cookie)
{
	socklen_t len = sizeof(*cookie);

	if (getsockopt(fd, SOL_SOCKET, SO_COOKIE, cookie, &len) < 0)
		return -errno;

	return (len == sizeof(*cookie)) ? 0 : -EINVAL;
}
#endif

/* The address family of the connections of the client */
static bool esdm_egd_client_family_ok(const struct esdm_egd_client *client,
				      sa_family_t family)
{
	if (client->transport == ESDM_EGD_CLIENT_UNIX)
		return family == AF_UNIX;
	return family == AF_INET || family == AF_INET6;
}

/* The address of the socket @fd is connected to. */
static int esdm_egd_client_peer(const struct esdm_egd_client *client, int fd,
				struct sockaddr_storage *addr,
				socklen_t *addrlen)
{
	memset(addr, 0, sizeof(*addr));
	*addrlen = sizeof(*addr);

	if (getpeername(fd, (struct sockaddr *)addr, addrlen) < 0)
		return -errno;

	if (!esdm_egd_client_family_ok(client, addr->ss_family) ||
	    *addrlen > sizeof(*addr))
		return -EAFNOSUPPORT;

	return 0;
}

/*
 * Record the identity of the freshly established connection, for
 * esdm_egd_client_fd_is_ours_locked(). Caller holds the lock.
 *
 * Taken from the connection itself rather than from the configured path: the
 * server reports the address it bound, which need not be the path this client
 * was given - a symlink such as /var/run, a bind mount or chroot, a relative
 * path. Comparing against the configured path would take every one of those
 * for a foreign descriptor and reconnect before each operation. The same holds
 * for the address of a server of the network, which the name resolves to.
 */
static int esdm_egd_client_identify_locked(struct esdm_egd_client *client)
{
	client->have_cookie = false;

#ifdef SO_COOKIE
	if (!esdm_egd_client_cookie(client->fd, &client->cookie)) {
		client->have_cookie = true;
		return 0;
	}
#endif

	return esdm_egd_client_peer(client, client->fd, &client->peer,
				    &client->peer_len);
}

/* Connect to the Unix domain socket, see esdm_egd_client_connect_locked(). */
static int esdm_egd_client_connect_unix(struct esdm_egd_client *client)
{
	struct sockaddr_un addr;
	int errsv, fd, ret;

	/*
	 * SOCK_NONBLOCK: every wait of this client is bounded by a poll of its
	 * own, starting with the connect below.
	 *
	 * SOCK_CLOEXEC: the connection belongs to this process - an exec'd
	 * child must not inherit a descriptor into the middle of our command
	 * stream.
	 */
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/* Its length was checked by esdm_egd_client_alloc() */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, client->socket_path,
	       strnlen(client->socket_path, sizeof(addr.sun_path) - 1));

	ret = esdm_egd_client_connect_fd(
		fd, (const struct sockaddr *)&addr, sizeof(addr),
		esdm_egd_client_now_ms() + client->timeout_ms);
	if (ret) {
		errsv = -ret;
		close(fd);
		return -errsv;
	}

	client->fd = fd;
	return 0;
}

#ifdef ESDM_EGD_NET

/*
 * Make the TLS handshake on the connection just made, bounded by @deadline.
 * Caller holds the lock.
 */
static int esdm_egd_client_handshake(struct esdm_egd_client *client,
				     uint64_t deadline)
{
#ifdef ESDM_EGD_NET_TLS
	struct esdm_tls_ctx *ctx;
	int ret;

	ctx = esdm_egd_tls_cache_ctx(client->tls_cache);
	ret = EGDC_TLS(alloc)(ctx, client->fd, client->server_name,
			     &client->tls);
	/* The connection holds a reference of its own */
	EGDC_TLS(ctx_put)(ctx);
	if (ret)
		return ret;

	while ((ret = EGDC_TLS(handshake)(client->tls)) == -EAGAIN) {
		int remaining = esdm_egd_client_remaining_ms(deadline);

		if (remaining <= 0)
			return -ETIMEDOUT;
		ret = EGDC_TLS(wait)(client->tls, remaining);
		if (ret)
			return ret;
	}

	/*
	 * A refusal is a matter of the configuration on either side: worth
	 * more than the debug message of a failed connection.
	 */
	if (ret == -EACCES || ret == -EPROTO) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: the TLS handshake with %s failed: %s\n",
			    client->socket_path, EGDC_TLS(error)(client->tls));
	} else if (!ret) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "EGD client: %s authenticated as %s, %s\n",
			    client->socket_path,
			    EGDC_TLS(peer_subject)(client->tls),
			    EGDC_TLS(cipher)(client->tls));
	}

	return ret;
#else
	(void)client;
	(void)deadline;
	return -EOPNOTSUPP;
#endif
}

/*
 * Connect to a server of the network, see esdm_egd_client_connect_locked():
 * each address the host resolves to in turn, until one takes the connection.
 */
static int esdm_egd_client_connect_net(struct esdm_egd_client *client)
{
	struct addrinfo hints, *res = NULL, *ai;
	uint64_t deadline = esdm_egd_client_now_ms() + client->timeout_ms;
	int ret, fd = -1, one = 1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ret = getaddrinfo(client->host, client->port, &hints, &res);
	if (ret) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "EGD client: cannot resolve %s: %s\n",
			    client->socket_path, gai_strerror(ret));
		return (ret == EAI_SYSTEM && errno) ? -errno : -EHOSTUNREACH;
	}

	ret = -EHOSTUNREACH;
	for (ai = res; ai; ai = ai->ai_next) {
		/* See esdm_egd_client_connect_unix() on the flags */
		fd = socket(ai->ai_family,
			    ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0) {
			ret = -errno;
			continue;
		}

		ret = esdm_egd_client_connect_fd(fd, ai->ai_addr,
						 ai->ai_addrlen, deadline);
		if (!ret)
			break;

		close(fd);
		fd = -1;
		if (ret == -ETIMEDOUT)
			break;
	}
	freeaddrinfo(res);

	if (fd < 0)
		return ret;

	/*
	 * A request is written in parts - the header of an insertion before
	 * its data -, and each is a request of its own on the wire: no
	 * waiting for an acknowledgement that a delayed ACK holds back.
	 */
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	client->fd = fd;

	if (client->transport == ESDM_EGD_CLIENT_TLS) {
		ret = esdm_egd_client_handshake(client, deadline);
		if (ret) {
			if (client->tls)
				EGDC_TLS(free)(client->tls);
			client->tls = NULL;
			close(fd);
			client->fd = -1;
			return ret;
		}
	}

	return 0;
}

#else /* ESDM_EGD_NET */

static int esdm_egd_client_connect_net(struct esdm_egd_client *client)
{
	(void)client;
	return -EOPNOTSUPP;
}

#endif /* ESDM_EGD_NET */

/* Caller holds the lock. */
static int esdm_egd_client_connect_locked(struct esdm_egd_client *client)
{
	struct sigaction sa;
	int ret;

	if (client->transport == ESDM_EGD_CLIENT_UNIX)
		ret = esdm_egd_client_connect_unix(client);
	else
		ret = esdm_egd_client_connect_net(client);
	if (ret)
		return ret;

	client->owner_pid = getpid();

	/*
	 * Asked here because a sandboxed process may no longer ask, just as it
	 * may no longer connect - see esdm_egd_client_write().
	 */
	client->sigpipe_ignored = !sigaction(SIGPIPE, NULL, &sa) &&
				  sa.sa_handler == SIG_IGN;

	/*
	 * A connection that cannot be recognized again would be taken for a
	 * foreign descriptor at its first use - it is no connection to keep.
	 */
	ret = esdm_egd_client_identify_locked(client);
	if (ret) {
		/* Ours for certain, if unrecognizable */
		if (client->tls)
			EGDC_TLS(free)(client->tls);
		client->tls = NULL;
		close(client->fd);
		client->fd = -1;
		return ret;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "EGD client: connected to %s\n", client->socket_path);

	return 0;
}

/*
 * Is the descriptor still our connection? Caller holds the lock.
 *
 * Applications do close descriptor ranges they did not open - OpenSSH's
 * privilege separation runs closefrom() on its way into the pre-authentication
 * child. Landing after this client connected, that frees the descriptor number
 * for reuse, and reading "random" data out of whatever took its place would be
 * a silent and serious failure.
 *
 * The descriptor is compared against what it was when the connection was set
 * up, see esdm_egd_client_identify_locked(). The socket cookie is unique to
 * that one socket, so it also tells apart another connection to the same
 * server that took the number. Without one, the peer's address still tells
 * apart anything but that - of a TCP connection, the address and port of the
 * server. getsockopt(2) and getpeername(2) are permitted inside OpenSSH's
 * pre-auth sandbox, so confirming costs one allowed syscall.
 */
static bool esdm_egd_client_fd_is_ours_locked(struct esdm_egd_client *client)
{
	struct sockaddr_storage addr;
	socklen_t addrlen;

#ifdef SO_COOKIE
	if (client->have_cookie) {
		uint64_t cookie;

		/* Gone, not a socket any more, or another one. */
		return !esdm_egd_client_cookie(client->fd, &cookie) &&
		       cookie == client->cookie;
	}
#endif

	if (esdm_egd_client_peer(client, client->fd, &addr, &addrlen))
		return false;

	return addrlen == client->peer_len &&
	       !memcmp(&addr, &client->peer, addrlen);
}

/*
 * Is the connection to a server of the network still up? Caller holds the
 * lock.
 *
 * A server sends nothing unasked, and closes a connection that was idle for
 * long. A Unix domain socket whose peer went away reports a hangup, which the
 * write of a request runs into, see esdm_egd_client_write_all_locked(). A TCP
 * connection the server closed reports no more than the end of its stream, as
 * readable - and a write into it still succeeds: an insertion, which is not
 * answered, would be lost silently. So a network connection with anything to
 * read before a request is done with. Over TLS, that may be a record without
 * data, which the TLS stack takes - the connection is up then.
 */
static bool esdm_egd_client_net_alive_locked(struct esdm_egd_client *client)
{
	short revents = 0;
	int ret;

	if (client->transport == ESDM_EGD_CLIENT_UNIX)
		return true;

	ret = esdm_egd_client_wait(client->fd, POLLIN | POLLRDHUP, 0,
				   &revents);
	if (ret == -ETIMEDOUT)
		return true;
	if (ret || (revents & (POLLRDHUP | POLLHUP | POLLERR | POLLNVAL)))
		return false;

#ifdef ESDM_EGD_NET_TLS
	if (client->tls) {
		uint8_t byte;
		ssize_t n = EGDC_TLS(recv)(client->tls, &byte, 1);

		/* The closing alert, an error, or data nobody asked for */
		byte = 0;
		return n == -EAGAIN;
	}
#endif

	return false;
}

/* Caller holds the lock. */
static int esdm_egd_client_ensure_connected_locked(struct esdm_egd_client *client)
{
	if (client->fd >= 0 && client->owner_pid == getpid() &&
	    esdm_egd_client_fd_is_ours_locked(client)) {
		if (esdm_egd_client_net_alive_locked(client))
			return 0;

		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "EGD client: %s closed the connection, reconnecting\n",
			    client->socket_path);
		esdm_egd_client_disconnect_locked(client, false);
		return esdm_egd_client_connect_locked(client);
	}

	/*
	 * Either never connected, inherited across a fork() - see the comment
	 * on owner_pid - or the descriptor is no longer ours.
	 */
	esdm_egd_client_disconnect_locked(client, false);

	return esdm_egd_client_connect_locked(client);
}

/****************************
 * Raw transfers
 ****************************/

/*
 * write(2) without letting a peer that went away raise SIGPIPE, which would
 * kill the application this library is linked into.
 *
 * send(2) with MSG_NOSIGNAL is deliberately not used - it is sendto(2), which
 * OpenSSH's pre-auth sandbox answers with SECCOMP_RET_KILL (see the header).
 * SIGPIPE is blocked around the write instead, which takes rt_sigprocmask(2)
 * only, and one the write raised is taken off before the mask is restored.
 * That takes sigtimedwait(2), which the sandbox kills for as well - but
 * OpenSSH ignores SIGPIPE, and an ignored signal is discarded on delivery, so
 * it is not needed then. A signal the caller blocked itself is left alone: a
 * pending one may be the caller's, and ours merged into it.
 *
 * This holds for plain TCP alike: a reset connection raises SIGPIPE just as a
 * Unix domain socket whose peer went away does.
 */
static ssize_t esdm_egd_client_write(struct esdm_egd_client *client,
				     const uint8_t *buf, size_t len)
{
	const struct timespec nowait = { 0, 0 };
	sigset_t sigpipe, old;
	ssize_t ret;
	int errsv;

	sigemptyset(&sigpipe);
	sigaddset(&sigpipe, SIGPIPE);
	errsv = pthread_sigmask(SIG_BLOCK, &sigpipe, &old);
	if (errsv) {
		errno = errsv;
		return -1;
	}

	ret = write(client->fd, buf, len);
	errsv = errno;

	/* Raised for this thread, which is where sigtimedwait looks first. */
	if (ret < 0 && errsv == EPIPE && !sigismember(&old, SIGPIPE) &&
	    !client->sigpipe_ignored) {
		while (sigtimedwait(&sigpipe, NULL, &nowait) < 0 &&
		       errno == EINTR)
			;
	}

	pthread_sigmask(SIG_SETMASK, &old, NULL);
	errno = errsv;

	return ret;
}

/* Send all of @buf over TLS. Caller holds the lock. */
static int esdm_egd_client_tls_write_all_locked(struct esdm_egd_client *client,
						const uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t written = 0;
	int ret;

	while (written < len) {
		ssize_t n = EGDC_TLS(send)(client->tls, buf + written,
					  len - written);

		if (n > 0) {
			written += (size_t)n;
			continue;
		}
		if (n != -EAGAIN)
			return n ? (int)n : -EIO;

		ret = EGDC_TLS(wait)(client->tls, timeout_ms);
		if (ret)
			return ret;
	}

	while ((ret = EGDC_TLS(flush)(client->tls)) == -EAGAIN) {
		ret = EGDC_TLS(wait)(client->tls, timeout_ms);
		if (ret)
			return ret;
	}

	return ret;
}

/* Caller holds the lock. */
static int esdm_egd_client_write_all_locked(struct esdm_egd_client *client,
					    const uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t written = 0;

	if (client->tls)
		return esdm_egd_client_tls_write_all_locked(client, buf, len);

	while (written < len) {
		short revents = 0;
		ssize_t ret;
		int wret;

		/*
		 * Establish writability before writing rather than after an
		 * EAGAIN: poll reports the hangup of a peer that went away, so
		 * the write is not even tried. The peer may still close right
		 * after the poll, see esdm_egd_client_write().
		 */
		wret = esdm_egd_client_wait(client->fd, POLLOUT, timeout_ms,
					    &revents);
		if (wret)
			return wret;
		if (revents & (POLLERR | POLLHUP | POLLNVAL))
			return -EPIPE;

		ret = esdm_egd_client_write(client, buf + written,
					    len - written);

		if (ret > 0) {
			written += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			continue;

		return (ret < 0) ? -errno : -EIO;
	}

	return 0;
}

/* Receive exactly @len bytes over TLS. Caller holds the lock. */
static int esdm_egd_client_tls_read_all_locked(struct esdm_egd_client *client,
					       uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t received = 0;
	int ret;

	while (received < len) {
		ssize_t n = EGDC_TLS(recv)(client->tls, buf + received,
					  len - received);

		if (n > 0) {
			received += (size_t)n;
			continue;
		}
		/* The peer closed the connection mid-response. */
		if (n == 0)
			return -EPIPE;
		if (n != -EAGAIN) {
			/*
			 * A TLS 1.3 server refuses the certificate of the
			 * client after the client's handshake completed: here.
			 */
			if (n == -EACCES)
				esdm_logger(
					LOGGER_ERR, LOGGER_C_ANY,
					"EGD client: %s refused the connection: %s\n",
					client->socket_path,
					EGDC_TLS(error)(client->tls));
			return (int)n;
		}

		ret = EGDC_TLS(wait)(client->tls, timeout_ms);
		if (ret)
			return ret;
	}

	return 0;
}

/* Caller holds the lock. */
static int esdm_egd_client_read_all_locked(struct esdm_egd_client *client,
					   uint8_t *buf, size_t len)
{
	int timeout_ms = (int)client->timeout_ms;
	size_t received = 0;

	if (client->tls)
		return esdm_egd_client_tls_read_all_locked(client, buf, len);

	while (received < len) {
		ssize_t ret = read(client->fd, buf + received, len - received);

		if (ret > 0) {
			received += (size_t)ret;
			continue;
		}
		/* The peer closed the connection mid-response. */
		if (ret == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			int wret = esdm_egd_client_wait(client->fd, POLLIN,
							timeout_ms, NULL);

			if (wret)
				return wret;
			continue;
		}

		return -errno;
	}

	return 0;
}

/*
 * Run one operation, retrying it once on a fresh connection.
 *
 * @op is invoked with the lock held and a connection established; it performs
 * the whole request / response exchange and returns 0 or a negative errno.
 */
static int esdm_egd_client_invoke(struct esdm_egd_client *client,
				  int (*op)(struct esdm_egd_client *, void *),
				  void *arg)
{
	unsigned int attempt;
	int ret = -EIO;

	if (client == NULL)
		return -EINVAL;

	/*
	 * EOWNERDEAD means the lock was taken over from a caller that died mid
	 * exchange. The lock is consistent again, the connection is not: a half
	 * written command leaves the peer's parser at an unknown offset, and an
	 * unconsumed response would be handed to the next request. The
	 * descriptor is still valid, so nothing below would notice - drop it
	 * here and let the loop open a fresh one.
	 */
	if (mutex_w_lock(&client->lock) == EOWNERDEAD) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"EGD client: recovered the lock of %s from a died owner, dropping the connection\n",
			client->socket_path);
		esdm_egd_client_disconnect_locked(client, false);
	}

	for (attempt = 0; attempt < ESDM_EGD_CLIENT_ATTEMPTS; attempt++) {
		ret = esdm_egd_client_ensure_connected_locked(client);
		if (ret)
			continue;

		ret = op(client, arg);
		if (!ret)
			break;

		/*
		 * Where in the command stream the failure left the peer is
		 * unknowable from here - a half written command would make it
		 * misread the next one - so the connection is not reusable.
		 * Drop it; the next attempt opens a fresh one.
		 */
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"EGD client: transfer on %s failed (%s), dropping the connection\n",
			client->socket_path, strerror(-ret));
		esdm_egd_client_disconnect_locked(client, false);
	}

	mutex_w_unlock(&client->lock);

	return ret;
}

/****************************
 * Operations
 ****************************/

struct esdm_egd_random_op {
	uint8_t *buf;
	size_t buflen;
	size_t generated;
	/* Command of the read: standard, or prediction resistant */
	uint8_t cmd;
};

/*
 * Blocking read, split into protocol sized transfers.
 *
 * The commands of up to ESDM_EGD_CLIENT_PIPELINE transfers go out with one
 * write, and their answers are read after: a blocking read is answered with
 * exactly the bytes asked for, so the answers of the commands are the bytes
 * of the read in order, and the reads take whatever of them is there. One
 * round trip per 64 KiB rather than per 255 bytes - over the network that was
 * the time of a large read - and the server answers the commands together,
 * see esdm_egd_read_run(). It is still the plain protocol, which a server
 * reads command by command from the stream: any EGD serves it.
 *
 * The commands fit into any socket buffer, so the write never waits for the
 * server to take answers that nobody reads yet.
 *
 * A prediction resistant read goes out in transfers of a multiple of what the
 * ESDM generates per seed, see ESDM_EGD_MAX_PR_TRANSFER: n bytes cost the seeds
 * of n bytes then, not one more for each transfer.
 */
static int esdm_egd_client_get_random_op(struct esdm_egd_client *client,
					 void *arg)
{
	struct esdm_egd_random_op *op = arg;
	uint8_t request[2 * ESDM_EGD_CLIENT_PIPELINE];
	size_t done = 0;
	uint8_t max_chunk = (op->cmd == ESDM_EGD_CMD_ESDM_PR_READ_BLOCK) ?
				    ESDM_EGD_MAX_PR_TRANSFER :
				    ESDM_EGD_MAX_TRANSFER;

	while (done < op->buflen) {
		size_t num, batch = 0;
		int ret;

		for (num = 0; num < ESDM_EGD_CLIENT_PIPELINE &&
			      done + batch < op->buflen;
		     num++) {
			size_t remaining = op->buflen - done - batch;
			uint8_t chunk = (remaining > max_chunk) ?
						max_chunk :
						(uint8_t)remaining;

			request[2 * num] = op->cmd;
			request[2 * num + 1] = chunk;
			batch += chunk;
		}

		ret = esdm_egd_client_write_all_locked(client, request,
						       2 * num);
		if (ret)
			return ret;

		ret = esdm_egd_client_read_all_locked(client, op->buf + done,
						      batch);
		if (ret)
			return ret;

		done += batch;
	}

	op->generated = done;

	return 0;
}

static int esdm_egd_client_get_random_cmd(struct esdm_egd_client *client,
					  uint8_t cmd, uint8_t *buf,
					  size_t buflen)
{
	struct esdm_egd_random_op op = {
		.buf = buf,
		.buflen = buflen,
		.generated = 0,
		.cmd = cmd,
	};
	int ret;

	if (buf == NULL)
		return -EINVAL;
	if (buflen == 0)
		return 0;

	ret = esdm_egd_client_invoke(client, esdm_egd_client_get_random_op,
				     &op);
	if (ret) {
		/*
		 * A partial transfer must never be mistaken for a complete
		 * one - leave nothing behind that looks like random data.
		 */
		memset_secure(buf, 0, buflen);
	}

	return ret;
}

DSO_PUBLIC
int esdm_egd_client_get_random(struct esdm_egd_client *client, uint8_t *buf,
			       size_t buflen)
{
	return esdm_egd_client_get_random_cmd(client, ESDM_EGD_CMD_READ_BLOCK,
					      buf, buflen);
}

DSO_PUBLIC
int esdm_egd_client_get_random_pr(struct esdm_egd_client *client, uint8_t *buf,
				  size_t buflen)
{
	return esdm_egd_client_get_random_cmd(
		client, ESDM_EGD_CMD_ESDM_PR_READ_BLOCK, buf, buflen);
}

static int esdm_egd_client_get_random_nonblock_op(struct esdm_egd_client *client,
						  void *arg)
{
	struct esdm_egd_random_op *op = arg;
	uint8_t request[2] = { op->cmd, (uint8_t)op->buflen };
	uint8_t delivered;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, &delivered,
					      sizeof(delivered));
	if (ret)
		return ret;

	/*
	 * More data than asked for would mean the peer is not speaking this
	 * protocol - reading it would desynchronize the stream for good.
	 */
	if (delivered > op->buflen)
		return -EPROTO;

	if (delivered) {
		ret = esdm_egd_client_read_all_locked(client, op->buf,
						      delivered);
		if (ret)
			return ret;
	}

	op->generated = delivered;

	return 0;
}

static int esdm_egd_client_get_random_nonblock_cmd(
	struct esdm_egd_client *client, uint8_t cmd, uint8_t *buf,
	size_t buflen, size_t *generated)
{
	struct esdm_egd_random_op op = {
		.buf = buf,
		.buflen = buflen,
		.generated = 0,
		.cmd = cmd,
	};
	int ret;

	if (buf == NULL || generated == NULL)
		return -EINVAL;
	if (buflen > ESDM_EGD_MAX_TRANSFER)
		return -EINVAL;

	*generated = 0;
	if (buflen == 0)
		return 0;

	ret = esdm_egd_client_invoke(
		client, esdm_egd_client_get_random_nonblock_op, &op);
	if (ret) {
		memset_secure(buf, 0, buflen);
		return ret;
	}

	*generated = op.generated;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_random_nonblock(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated)
{
	return esdm_egd_client_get_random_nonblock_cmd(
		client, ESDM_EGD_CMD_READ_NONBLOCK, buf, buflen, generated);
}

DSO_PUBLIC
int esdm_egd_client_get_random_pr_nonblock(struct esdm_egd_client *client,
					   uint8_t *buf, size_t buflen,
					   size_t *generated)
{
	return esdm_egd_client_get_random_nonblock_cmd(
		client, ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK, buf, buflen,
		generated);
}

/* Answered as the non-blocking read - see esdm_egd_protocol.h */
DSO_PUBLIC
int esdm_egd_client_get_random_unseeded(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated)
{
	return esdm_egd_client_get_random_nonblock_cmd(
		client, ESDM_EGD_CMD_ESDM_READ_UNSEEDED, buf, buflen,
		generated);
}

struct esdm_egd_state_op {
	uint32_t *fields;
	unsigned int room;
	unsigned int num;
};

static int esdm_egd_client_get_state_op(struct esdm_egd_client *client,
					void *arg)
{
	const uint8_t request = ESDM_EGD_CMD_ESDM_GET_STATE;
	struct esdm_egd_state_op *op = arg;
	uint8_t count, field[4];
	unsigned int i;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, &count, sizeof(count));
	if (ret)
		return ret;

	/* All of them, to stay in step - the ones beyond the room are dropped */
	for (i = 0; i < count; i++) {
		ret = esdm_egd_client_read_all_locked(client, field,
						      sizeof(field));
		if (ret)
			return ret;
		if (i < op->room)
			op->fields[i] = ptr_to_be32(field);
	}

	op->num = count;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_state(struct esdm_egd_client *client, uint32_t *fields,
			      unsigned int *num_fields)
{
	struct esdm_egd_state_op op;
	int ret;

	if (num_fields == NULL || (fields == NULL && *num_fields))
		return -EINVAL;

	op.fields = fields;
	op.room = *num_fields;
	op.num = 0;

	ret = esdm_egd_client_invoke(client, esdm_egd_client_get_state_op,
				     &op);
	if (!ret)
		*num_fields = op.num;

	return ret;
}

struct esdm_egd_status_op {
	uint8_t cmd;
	char *buf;
	size_t buflen;
	size_t len;
};

static int esdm_egd_client_status_op(struct esdm_egd_client *client, void *arg)
{
	struct esdm_egd_status_op *op = arg;
	uint8_t hdr[4], *rest = NULL;
	size_t fits;
	uint32_t len;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &op->cmd,
					       sizeof(op->cmd));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, hdr, sizeof(hdr));
	if (ret)
		return ret;

	/* More would not be this protocol, and is no allocation to make */
	len = ptr_to_be32(hdr);
	if (len > ESDM_EGD_MAX_STATUS)
		return -EPROTO;

	fits = (len < op->buflen) ? len : op->buflen - 1;
	if (fits) {
		ret = esdm_egd_client_read_all_locked(
			client, (uint8_t *)op->buf, fits);
		if (ret)
			return ret;
	}
	op->buf[fits] = '\0';

	/* What does not fit is read all the same, to stay in step */
	if (len > fits) {
		rest = malloc(len - fits);
		if (!rest)
			return -ENOMEM;
		ret = esdm_egd_client_read_all_locked(client, rest, len - fits);
		free(rest);
		if (ret)
			return ret;
	}

	op->len = len;

	return 0;
}

static int esdm_egd_client_status_cmd(struct esdm_egd_client *client,
				      uint8_t cmd, char *buf, size_t buflen)
{
	struct esdm_egd_status_op op = {
		.cmd = cmd,
		.buf = buf,
		.buflen = buflen,
		.len = 0,
	};
	int ret;

	if (buf == NULL || buflen == 0)
		return -EINVAL;
	buf[0] = '\0';

	ret = esdm_egd_client_invoke(client, esdm_egd_client_status_op, &op);
	if (ret) {
		buf[0] = '\0';
		return ret;
	}

	if (op.len >= buflen) {
		/* A JSON document cut short is none - see the header */
		if (cmd == ESDM_EGD_CMD_ESDM_STATUS_JSON)
			buf[0] = '\0';
		return -EMSGSIZE;
	}

	return (int)op.len;
}

DSO_PUBLIC
int esdm_egd_client_status(struct esdm_egd_client *client, char *buf,
			   size_t buflen)
{
	return esdm_egd_client_status_cmd(client, ESDM_EGD_CMD_ESDM_STATUS, buf,
					  buflen);
}

DSO_PUBLIC
int esdm_egd_client_status_json(struct esdm_egd_client *client, char *buf,
				size_t buflen)
{
	return esdm_egd_client_status_cmd(client, ESDM_EGD_CMD_ESDM_STATUS_JSON,
					  buf, buflen);
}

static int esdm_egd_client_entropy_count_op(struct esdm_egd_client *client,
					    void *arg)
{
	const uint8_t request = ESDM_EGD_CMD_ENTROPY_COUNT;
	uint32_t *entropy_bits = arg;
	uint8_t response[4];
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, response,
					      sizeof(response));
	if (ret)
		return ret;

	/* The count is transferred in big endian byte order. */
	*entropy_bits = ptr_to_be32(response);

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_entropy_count(struct esdm_egd_client *client,
				  uint32_t *entropy_bits)
{
	if (entropy_bits == NULL)
		return -EINVAL;

	return esdm_egd_client_invoke(client, esdm_egd_client_entropy_count_op,
				      entropy_bits);
}

struct esdm_egd_write_op {
	const uint8_t *buf;
	uint8_t buflen;
	uint32_t entropy_bits;
};

static int esdm_egd_client_write_entropy_op(struct esdm_egd_client *client,
					    void *arg)
{
	struct esdm_egd_write_op *op = arg;
	uint8_t header[4];
	int ret;

	header[0] = ESDM_EGD_CMD_WRITE_ENTROPY;
	/* The entropy claim is transferred in big endian byte order. */
	be16_to_ptr(header + 1, (uint16_t)op->entropy_bits);
	header[3] = op->buflen;

	ret = esdm_egd_client_write_all_locked(client, header, sizeof(header));
	if (ret)
		return ret;

	/* The command has no response. */
	return esdm_egd_client_write_all_locked(client, op->buf, op->buflen);
}

DSO_PUBLIC
int esdm_egd_client_write_entropy(struct esdm_egd_client *client,
				  const uint8_t *buf, size_t buflen,
				  uint32_t entropy_bits)
{
	struct esdm_egd_write_op op;

	if (buf == NULL)
		return -EINVAL;
	if (buflen == 0)
		return 0;
	if (buflen > ESDM_EGD_MAX_TRANSFER)
		return -EINVAL;

	/* The protocol carries the claim in two bytes. */
	if (entropy_bits > UINT16_MAX)
		entropy_bits = UINT16_MAX;

	op.buf = buf;
	op.buflen = (uint8_t)buflen;
	op.entropy_bits = entropy_bits;

	return esdm_egd_client_invoke(client, esdm_egd_client_write_entropy_op,
				      &op);
}

static int esdm_egd_client_get_pid_op(struct esdm_egd_client *client, void *arg)
{
	const uint8_t request = ESDM_EGD_CMD_GET_PID;
	pid_t *pid = arg;
	/* The PID arrives as a string, without a terminating NUL. */
	char response[UINT8_MAX + 1];
	uint8_t len;
	char *end;
	long value;
	int ret;

	ret = esdm_egd_client_write_all_locked(client, &request,
					       sizeof(request));
	if (ret)
		return ret;

	ret = esdm_egd_client_read_all_locked(client, &len, sizeof(len));
	if (ret)
		return ret;

	if (len == 0)
		return -EPROTO;

	ret = esdm_egd_client_read_all_locked(client, (uint8_t *)response, len);
	if (ret)
		return ret;
	response[len] = '\0';

	errno = 0;
	value = strtol(response, &end, 10);

	/*
	 * The length prefix covers the digits and nothing else, so a response
	 * carrying anything besides them - or no digit at all - is not this
	 * protocol and its number is not to be believed.
	 */
	if (errno || end == response || end != response + len)
		return -EPROTO;

	/*
	 * A PID does not have to fit into a pid_t just because it arrived as
	 * text: the peer decides how many digits it sends, and a number beyond
	 * the type truncates on the way in - to a value naming a different
	 * process as often as to a negative one, which is what a caller passing
	 * it to kill(2) turns into a whole process group.
	 */
	if (value <= 0 || (long)(pid_t)value != value)
		return -EPROTO;

	*pid = (pid_t)value;

	return 0;
}

DSO_PUBLIC
int esdm_egd_client_get_pid(struct esdm_egd_client *client, pid_t *pid)
{
	if (pid == NULL)
		return -EINVAL;

	return esdm_egd_client_invoke(client, esdm_egd_client_get_pid_op, pid);
}

/****************************
 * Lifecycle
 ****************************/

/* Release what a client holds besides its connection - not published yet. */
static void esdm_egd_client_release(struct esdm_egd_client *client)
{
#ifdef ESDM_EGD_NET_TLS
	esdm_egd_tls_cache_put(client->tls_cache);
#endif
	free(client->host);
	free(client->port);
	free(client->server_name);
	free(client);
}

/*
 * Publish the client and connect it - the end of every allocation. A failure
 * to connect is not fatal, see esdm_egd_client_alloc().
 */
static int esdm_egd_client_publish(struct esdm_egd_client *new_client,
				   struct esdm_egd_client **client)
{
	int ret;

	/*
	 * Robust, see the struct. This has to succeed before the client is
	 * published: one that is reachable through the registry, or handed to
	 * the caller, without a lock that serializes and can be destroyed again
	 * is worse than no client at all.
	 */
	ret = mutex_w_init(&new_client->lock, 0, 1);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: cannot create the client lock (%s)\n",
			    strerror(-ret));
		esdm_egd_client_release(new_client);
		return ret;
	}

	/*
	 * Publish the client before connecting: from here on the fork handler
	 * knows about it, so no window exists in which a fork could leave a
	 * connection behind in a child.
	 */
	esdm_egd_clients_lock_acquire();
	TAILQ_INSERT_TAIL(&esdm_egd_clients, new_client, tailq);
	mutex_w_unlock(&esdm_egd_clients_lock);

	/*
	 * Connect right away: a consumer serving a process that later confines
	 * itself must hold its connection by then, since opening one is exactly
	 * what such a process can no longer do (see the header). A failure is
	 * not fatal - the operations reconnect, so a consumer set up before the
	 * ESDM is running keeps working once it arrives.
	 */
	ret = esdm_egd_client_connect_locked(new_client);
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"EGD client: cannot connect to %s yet (%s) - retrying on first use\n",
			new_client->socket_path, strerror(-ret));
	}

	*client = new_client;

	return 0;
}

/* The bound of a step, see esdm_egd_client_alloc() */
static unsigned int esdm_egd_client_timeout(unsigned int timeout_ms)
{
	if (!timeout_ms)
		timeout_ms = ESDM_EGD_CLIENT_DEFAULT_TIMEOUT_MS;
	if (timeout_ms > ESDM_EGD_CLIENT_MAX_TIMEOUT_MS)
		timeout_ms = ESDM_EGD_CLIENT_MAX_TIMEOUT_MS;
	return timeout_ms;
}

DSO_PUBLIC
int esdm_egd_client_alloc(struct esdm_egd_client **client,
			  const char *socket_path, unsigned int timeout_ms)
{
	struct esdm_egd_client *new_client;

	if (client == NULL)
		return -EINVAL;
	*client = NULL;

	if (socket_path == NULL || *socket_path == '\0')
		socket_path = secure_getenv(ESDM_EGD_CLIENT_SOCKET_ENV);
	if (socket_path == NULL || *socket_path == '\0')
		socket_path = ESDM_SERVER_EGD_SOCKET_PATH;

	if (strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"EGD client: the socket path is %zu characters long, at most %zu are possible\n",
			strlen(socket_path),
			sizeof(((struct sockaddr_un *)0)->sun_path) - 1);
		return -ENAMETOOLONG;
	}

	new_client = calloc(1, sizeof(struct esdm_egd_client));
	if (new_client == NULL)
		return -ENOMEM;

	new_client->transport = ESDM_EGD_CLIENT_UNIX;
	snprintf(new_client->socket_path, sizeof(new_client->socket_path), "%s",
		 socket_path);
	new_client->timeout_ms = esdm_egd_client_timeout(timeout_ms);
	new_client->fd = -1;

	pthread_once(&esdm_egd_client_init_once, esdm_egd_client_init);

	return esdm_egd_client_publish(new_client, client);
}

#ifdef ESDM_EGD_NET

/*
 * Split "host:port", "[v6]:port", "host", "[v6]" or a bare IPv6 address into
 * host and port, the port of the build when there is none.
 */
static int esdm_egd_client_parse_address(const char *address, char **host,
					 char **port)
{
	char defport[8];
	const char *h, *p = NULL, *colon;
	size_t hlen;

	snprintf(defport, sizeof(defport), "%u", (unsigned int)ESDM_EGD_NET_PORT);

	if (address[0] == '[') {
		const char *close = strchr(address, ']');

		if (!close || close == address + 1)
			return -EINVAL;
		h = address + 1;
		hlen = (size_t)(close - h);
		if (close[1] == ':')
			p = close + 2;
		else if (close[1] != '\0')
			return -EINVAL;
	} else {
		h = address;
		colon = strchr(address, ':');
		if (colon && !strchr(colon + 1, ':')) {
			/* host:port */
			hlen = (size_t)(colon - address);
			p = colon + 1;
		} else {
			/* A host, or an IPv6 address without a port */
			hlen = strlen(address);
		}
	}

	if (!hlen || (p && !*p))
		return -EINVAL;

	*host = strndup(h, hlen);
	*port = strdup(p ? p : defport);
	if (!*host || !*port) {
		free(*host);
		free(*port);
		*host = *port = NULL;
		return -ENOMEM;
	}

	return 0;
}

#endif /* ESDM_EGD_NET */

DSO_PUBLIC
int esdm_egd_client_alloc_net(struct esdm_egd_client **client,
			      const struct esdm_egd_client_net_config *cfg)
{
#ifdef ESDM_EGD_NET
	struct esdm_egd_client_net_config c;
	struct esdm_egd_client *new_client;
	bool tls_given;
	int ret;

	if (client == NULL || cfg == NULL)
		return -EINVAL;
	*client = NULL;

	/*
	 * What the caller's structure has, zero for what it has not - see the
	 * header. Up to the address it must have.
	 */
	if (cfg->size < offsetof(struct esdm_egd_client_net_config, timeout_ms))
		return -EINVAL;
	memset(&c, 0, sizeof(c));
	memcpy(&c, cfg, cfg->size < sizeof(c) ? cfg->size : sizeof(c));

	if (!c.address || !*c.address ||
	    strlen(c.address) >= ESDM_EGD_CLIENT_MAX_ADDRESS) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: no usable server address given\n");
		return -EINVAL;
	}

	tls_given = c.cert_file || c.key_file || c.ca_file || c.server_name ||
		    c.crl_files || c.crl_flags;

	switch (c.mode) {
	case ESDM_EGD_CLIENT_NET_PLAIN:
		/* Plain TCP is chosen explicitly, never by accident */
		if (tls_given) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"EGD client: TLS settings given for the plain TCP connection to %s\n",
				c.address);
			return -EINVAL;
		}
		break;
	case ESDM_EGD_CLIENT_NET_TLS:
#ifndef ESDM_EGD_NET_TLS
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"EGD client: built without TLS - the TLS stack of the crypto backend is needed for it\n");
		return -EOPNOTSUPP;
#else
		if (!c.cert_file || !c.key_file || !c.ca_file) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"EGD client: TLS to %s needs a certificate, its key and the trust anchors\n",
				c.address);
			return -EINVAL;
		}
		break;
#endif
	default:
		return -EINVAL;
	}

	new_client = calloc(1, sizeof(struct esdm_egd_client));
	if (new_client == NULL)
		return -ENOMEM;
	new_client->fd = -1;
	new_client->transport = (c.mode == ESDM_EGD_CLIENT_NET_TLS) ?
					ESDM_EGD_CLIENT_TLS :
					ESDM_EGD_CLIENT_TCP;
	snprintf(new_client->socket_path, sizeof(new_client->socket_path), "%s",
		 c.address);
	new_client->timeout_ms = esdm_egd_client_timeout(c.timeout_ms);

	ret = esdm_egd_client_parse_address(c.address, &new_client->host,
					    &new_client->port);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "EGD client: the server address %s does not parse\n",
			    c.address);
		esdm_egd_client_release(new_client);
		return ret;
	}

	pthread_once(&esdm_egd_client_init_once, esdm_egd_client_init);

#ifdef ESDM_EGD_NET_TLS
	if (new_client->transport == ESDM_EGD_CLIENT_TLS) {
		struct esdm_tls_config tcfg;
		unsigned int i;

		memset(&tcfg, 0, sizeof(tcfg));
		tcfg.cert_file = c.cert_file;
		tcfg.key_file = c.key_file;
		tcfg.ca_file = c.ca_file;
		tcfg.crl_check_all =
			!!(c.crl_flags & ESDM_EGD_CLIENT_NET_CRL_CHECK_ALL);
		tcfg.crl_allow_expired =
			!!(c.crl_flags & ESDM_EGD_CLIENT_NET_CRL_ALLOW_EXPIRED);
		for (i = 0; c.crl_files && c.crl_files[i]; i++) {
			if (i >= ESDM_EGD_CLIENT_NET_MAX_CRL ||
			    i >= ESDM_TLS_MAX_CRL_FILES) {
				esdm_logger(
					LOGGER_ERR, LOGGER_C_ANY,
					"EGD client: more than %u CRL files given\n",
					ESDM_EGD_CLIENT_NET_MAX_CRL);
				esdm_egd_client_release(new_client);
				return -EINVAL;
			}
			tcfg.crl_files[i] = c.crl_files[i];
			tcfg.crl_files_num++;
		}

		ret = esdm_egd_tls_load();
		if (ret) {
			esdm_egd_client_release(new_client);
			return ret;
		}

		new_client->server_name =
			strdup(c.server_name ? c.server_name :
					       new_client->host);
		if (!new_client->server_name) {
			esdm_egd_client_release(new_client);
			return -ENOMEM;
		}

		ret = esdm_egd_tls_cache_get(&tcfg, &new_client->tls_cache);
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"EGD client: the TLS files for %s do not load (%s)\n",
				c.address, strerror(-ret));
			esdm_egd_client_release(new_client);
			return ret;
		}
	}
#endif

	return esdm_egd_client_publish(new_client, client);
#else /* ESDM_EGD_NET */
	(void)cfg;
	if (client)
		*client = NULL;
	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "EGD client: built without the network modes (egd-net)\n");
	return -EOPNOTSUPP;
#endif /* ESDM_EGD_NET */
}

DSO_PUBLIC
void esdm_egd_client_free(struct esdm_egd_client *client)
{
	if (client == NULL)
		return;

	esdm_egd_clients_lock_acquire();
	TAILQ_REMOVE(&esdm_egd_clients, client, tailq);
	mutex_w_unlock(&esdm_egd_clients_lock);

	/*
	 * No client lock: the caller guarantees nobody uses the client any more,
	 * which it must, as the lock itself goes away here. Destroying it fails
	 * with EBUSY when a died owner left it held and nobody recovered it
	 * since. Nothing can be done about that and nothing leaks - the memory
	 * the mutex lives in is released right below.
	 *
	 * A connection still in use by this process says goodbye properly; one
	 * inherited from the parent was closed by the fork handler already.
	 */
	esdm_egd_client_disconnect_locked(client,
					  client->owner_pid == getpid());
	mutex_w_destroy(&client->lock);
	esdm_egd_client_release(client);
}

DSO_PUBLIC
const char *esdm_egd_client_socket_path(const struct esdm_egd_client *client)
{
	return client ? client->socket_path : NULL;
}
