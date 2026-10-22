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
 * The sessions of the local DTLS to be resumed, see esdm_dtls_backend.h: what a
 * context of every backend keeps of them - a server under the session ID it
 * issued, a client under the socket path of its server. A session lives
 * ESDM_DTLS_SESSION_LIFETIME_S from the full handshake that made it, resumed or
 * not: what a compromise of its master secret reveals ends with it. An expired
 * session is wiped and freed by the next call that looks at the cache, and one
 * more than the cache holds evicts the oldest.
 *
 * The cache is only ever tried for: a call finding it locked - by another
 * thread, or in the child of a fork() taken while one held it - finds or keeps
 * nothing, and the connection runs a full handshake. Nothing waits for it.
 */

#ifndef _ESDM_DTLS_SESSION_H
#define _ESDM_DTLS_SESSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Seconds a session may be resumed after its full handshake */
#define ESDM_DTLS_SESSION_LIFETIME_S 60

/* Sessions a server keeps, and a client - a few servers at most */
#define ESDM_DTLS_SESSIONS_SERVER 1024
#define ESDM_DTLS_SESSIONS_CLIENT 16

/* The longest key: a session ID of 32 bytes, a socket path of 108 */
#define ESDM_DTLS_SESSION_KEY_MAX 128

struct esdm_dtls_sessions;

/* @return 0 or a negative errno */
int esdm_dtls_sessions_alloc(size_t max, struct esdm_dtls_sessions **sessions);
void esdm_dtls_sessions_free(struct esdm_dtls_sessions *sessions);

/*
 * Keep @len bytes of @data, the serialized session, under @key - in place of
 * one under it already, its lifetime starting now
 */
void esdm_dtls_sessions_put(struct esdm_dtls_sessions *sessions,
			    const void *key, size_t keylen, const void *data,
			    size_t len);

/*
 * A copy of the session under @key, to be released with
 * esdm_dtls_sessions_release()
 *
 * @return 0, or -ENOENT if there is none - also expired, or the cache locked
 */
int esdm_dtls_sessions_get(struct esdm_dtls_sessions *sessions, const void *key,
			   size_t keylen, uint8_t **data, size_t *len);

/* Wipe and free a copy of esdm_dtls_sessions_get() */
void esdm_dtls_sessions_release(uint8_t *data, size_t len);

/* Forget the session under @key, if there is one */
void esdm_dtls_sessions_del(struct esdm_dtls_sessions *sessions,
			    const void *key, size_t keylen);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_DTLS_SESSION_H */
