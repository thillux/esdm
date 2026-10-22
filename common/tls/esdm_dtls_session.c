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

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esdm_dtls_session.h"
#include "memset_secure.h"

struct esdm_dtls_session {
	uint8_t key[ESDM_DTLS_SESSION_KEY_MAX];
	size_t keylen;
	/* The serialized session, its master secret in it; NULL if unused */
	uint8_t *data;
	size_t len;
	/* Of the full handshake, see esdm_dtls_session_now() */
	int64_t born;
};

struct esdm_dtls_sessions {
	pthread_mutex_t lock;
	size_t max;
	struct esdm_dtls_session s[];
};

/* Seconds that go on while the machine is suspended, where there are such */
static int64_t esdm_dtls_session_now(void)
{
	struct timespec ts;

#ifdef CLOCK_BOOTTIME
	if (!clock_gettime(CLOCK_BOOTTIME, &ts))
		return (int64_t)ts.tv_sec;
#endif
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec;
}

static void esdm_dtls_session_wipe(struct esdm_dtls_session *s)
{
	if (!s->data)
		return;
	memset_secure(s->data, 0, s->len);
	free(s->data);
	s->data = NULL;
	s->len = 0;
	s->keylen = 0;
}

/* Under the lock: drop the expired ones, see esdm_dtls_session.h */
static void esdm_dtls_sessions_expire(struct esdm_dtls_sessions *sessions,
				      int64_t now)
{
	size_t i;

	for (i = 0; i < sessions->max; i++) {
		if (sessions->s[i].data &&
		    now - sessions->s[i].born >= ESDM_DTLS_SESSION_LIFETIME_S)
			esdm_dtls_session_wipe(&sessions->s[i]);
	}
}

/* Under the lock: the session under @key, NULL if none */
static struct esdm_dtls_session *
esdm_dtls_sessions_find(struct esdm_dtls_sessions *sessions, const void *key,
			size_t keylen)
{
	size_t i;

	for (i = 0; i < sessions->max; i++) {
		struct esdm_dtls_session *s = &sessions->s[i];

		if (s->data && s->keylen == keylen &&
		    !memcmp(s->key, key, keylen))
			return s;
	}
	return NULL;
}

int esdm_dtls_sessions_alloc(size_t max, struct esdm_dtls_sessions **sessions)
{
	struct esdm_dtls_sessions *s;

	*sessions = NULL;
	if (!max)
		return -EINVAL;
	s = calloc(1, sizeof(*s) + max * sizeof(s->s[0]));
	if (!s)
		return -ENOMEM;
	if (pthread_mutex_init(&s->lock, NULL)) {
		free(s);
		return -ENOMEM;
	}
	s->max = max;
	*sessions = s;
	return 0;
}

void esdm_dtls_sessions_free(struct esdm_dtls_sessions *sessions)
{
	size_t i;

	if (!sessions)
		return;
	for (i = 0; i < sessions->max; i++)
		esdm_dtls_session_wipe(&sessions->s[i]);
	pthread_mutex_destroy(&sessions->lock);
	free(sessions);
}

void esdm_dtls_sessions_put(struct esdm_dtls_sessions *sessions,
			    const void *key, size_t keylen, const void *data,
			    size_t len)
{
	struct esdm_dtls_session *s, *oldest = NULL;
	int64_t now = esdm_dtls_session_now();
	uint8_t *copy;
	size_t i;

	if (!sessions || !keylen || keylen > ESDM_DTLS_SESSION_KEY_MAX ||
	    !data || !len)
		return;
	copy = malloc(len);
	if (!copy)
		return;
	memcpy(copy, data, len);

	if (pthread_mutex_trylock(&sessions->lock)) {
		memset_secure(copy, 0, len);
		free(copy);
		return;
	}

	esdm_dtls_sessions_expire(sessions, now);
	s = esdm_dtls_sessions_find(sessions, key, keylen);
	for (i = 0; !s && i < sessions->max; i++) {
		if (!sessions->s[i].data)
			s = &sessions->s[i];
		else if (!oldest || sessions->s[i].born < oldest->born)
			oldest = &sessions->s[i];
	}
	if (!s)
		s = oldest;

	esdm_dtls_session_wipe(s);
	memcpy(s->key, key, keylen);
	s->keylen = keylen;
	s->data = copy;
	s->len = len;
	s->born = now;

	pthread_mutex_unlock(&sessions->lock);
}

int esdm_dtls_sessions_get(struct esdm_dtls_sessions *sessions, const void *key,
			   size_t keylen, uint8_t **data, size_t *len)
{
	struct esdm_dtls_session *s;
	int ret = -ENOENT;

	*data = NULL;
	*len = 0;
	if (!sessions || !keylen || keylen > ESDM_DTLS_SESSION_KEY_MAX)
		return -ENOENT;
	if (pthread_mutex_trylock(&sessions->lock))
		return -ENOENT;

	esdm_dtls_sessions_expire(sessions, esdm_dtls_session_now());
	s = esdm_dtls_sessions_find(sessions, key, keylen);
	if (s) {
		*data = malloc(s->len);
		if (*data) {
			memcpy(*data, s->data, s->len);
			*len = s->len;
			ret = 0;
		}
	}

	pthread_mutex_unlock(&sessions->lock);
	return ret;
}

void esdm_dtls_sessions_release(uint8_t *data, size_t len)
{
	if (!data)
		return;
	memset_secure(data, 0, len);
	free(data);
}

void esdm_dtls_sessions_del(struct esdm_dtls_sessions *sessions,
			    const void *key, size_t keylen)
{
	struct esdm_dtls_session *s;

	if (!sessions || !keylen || keylen > ESDM_DTLS_SESSION_KEY_MAX)
		return;
	if (pthread_mutex_trylock(&sessions->lock))
		return;
	s = esdm_dtls_sessions_find(sessions, key, keylen);
	if (s)
		esdm_dtls_session_wipe(s);
	pthread_mutex_unlock(&sessions->lock);
}
