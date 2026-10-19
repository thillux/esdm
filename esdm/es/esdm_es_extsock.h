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

#ifndef _ESDM_ES_EXTSOCK_H
#define _ESDM_ES_EXTSOCK_H

#include <errno.h>
#include <stdint.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"
#include "visibility.h"

/*
 * The provider socket sources: ESDM_EXT_SOCKET_NUM of them (meson option
 * es_ext_socket_num), each an entry of the ES table of its own, from
 * esdm_ext_es_extsock_first to esdm_ext_es_extsock_last. Its name in the ES
 * table, and in the ESDM status, carries the index of the source - unless the
 * source is the only one, which is ExternalSocket, as it ever was.
 */
#if ESDM_EXT_SOCKET_NUM > 1
#define ESDM_ES_EXTSOCK_NAME(i) "ExternalSocket" #i
#else
#define ESDM_ES_EXTSOCK_NAME(i) "ExternalSocket"
#endif

#if ESDM_EXT_SOCKET_NUM > 0

/*
 * A provider not connected, or lost, is connected to again on demand, at most
 * once per this many seconds - a provider that is not there must not cost a
 * connection attempt per seeding, nor must a restarted one stay unused.
 */
#ifndef ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC
#define ESDM_EXT_SOCKET_RETRY_INTERVAL_SEC 5
#endif

/*
 * How long a request may take until the provider has answered. The request
 * runs while a DRNG waits for its seed, so a stalled provider must not hold
 * it up for long; it is treated as failed, like an error, and disconnected.
 */
#ifndef ESDM_EXT_SOCKET_TIMEOUT_MS
#define ESDM_EXT_SOCKET_TIMEOUT_MS 2000
#endif

/*
 * A provider that does not answer STATUS in time is disconnected as for any
 * request - and not asked for its status again for this many seconds: a
 * status taking that long would cost the connection, and hold up the
 * seedings for the timeout, whenever the ESDM status is asked for.
 */
#ifndef ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC
#define ESDM_EXT_SOCKET_STATUS_BACKOFF_SEC 60
#endif

extern struct esdm_es_cb esdm_es_extsock[ESDM_EXT_SOCKET_NUM];

/**
 * @brief Select the socket of an external entropy source provider
 *
 * The path replaces the compile-time default of the provider socket source
 * @idx (its entry in the meson option es_ext_socket_path). Set before
 * esdm_init(), as the server does for its --es_ext_socket option, the provider
 * is connected to by the initialization of the source; set later, the
 * connection is replaced right away. Pass an empty string to go back to the
 * compile-time default. The path is kept across esdm_fini().
 *
 * @param [in] idx Index of the provider socket source, below
 *		   ESDM_EXT_SOCKET_NUM
 * @param [in] path NUL-terminated path of the socket, must not be NULL.
 *
 * @return 0 on success, -EINVAL if there is no source @idx, or path is NULL or
 *	   too long for a Unix domain socket, -ENOMEM on allocation failure.
 */
DSO_PUBLIC
int esdm_es_ext_socket_set_path(unsigned int idx, const char *path);

/**
 * @brief Accept a provider running as another user than root
 *
 * The ESDM checks the credentials of the provider it connects to: by default
 * only a provider running as root is accepted, as anybody who can create the
 * socket file could otherwise feed the ESDM with data credited as entropy. The
 * uid given here is accepted in addition by the provider socket source @idx
 * (compile-time default: its entry in the meson option es_ext_socket_peer_uid).
 * Pass -1 to accept root only. Applies from the next connection on.
 *
 * @param [in] idx Index of the provider socket source, below
 *		   ESDM_EXT_SOCKET_NUM
 * @param [in] uid The uid accepted in addition to root, or -1 - any uid_t but
 *		   (uid_t)-1, see setreuid(2)
 *
 * @return 0 on success, -EINVAL if there is no source @idx or for a uid out of
 *	   range.
 */
DSO_PUBLIC
int esdm_es_ext_socket_set_peer_uid(unsigned int idx, int64_t uid);

#else /* ESDM_EXT_SOCKET_NUM */

/* No such source: -ENOENT without external sources, -EINVAL without this kind */
#ifdef ESDM_ES_EXT
#define ESDM_ES_EXTSOCK_NONE -EINVAL
#else
#define ESDM_ES_EXTSOCK_NONE -ENOENT
#endif

static inline int esdm_es_ext_socket_set_path(unsigned int idx,
					      const char *path)
{
	(void)idx;
	(void)path;
	return ESDM_ES_EXTSOCK_NONE;
}

static inline int esdm_es_ext_socket_set_peer_uid(unsigned int idx,
						  int64_t uid)
{
	(void)idx;
	(void)uid;
	return ESDM_ES_EXTSOCK_NONE;
}

#endif /* ESDM_EXT_SOCKET_NUM */

#endif /* _ESDM_ES_EXTSOCK_H */
