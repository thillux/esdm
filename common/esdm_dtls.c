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
 * The backend independent part of esdm_dtls.h: messages of any size on top of
 * the records of the backend - or of the DTLS with certificates, see
 * esdm_dtls_tls.c -, and the busy marker of the thread.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
#include "leak_check.h"
#include "memset_secure.h"
#include "visibility.h"

/* The leading byte of a record: more parts of the message follow */
#define ESDM_DTLS_MORE 1
#define ESDM_DTLS_LAST 0

/* A record as received: one byte more than one can be, to tell a longer one */
#define ESDM_DTLS_RECORD_BUF (ESDM_DTLS_PART_SIZE + 2)

/*
 * The record buffers are allocated per call rather than placed on the stack:
 * the getrandom(2) shim may call in from any thread of an application, and a
 * thread may have a small stack.
 */

struct esdm_dtls_ctx {
	void *backend;
	bool server;

	/* The next one left behind at the exit, see esdm_dtls_exiting() */
	struct esdm_dtls_ctx *left_next;
};

struct esdm_dtls {
	void *backend;

	/* The next one left behind at the exit, see esdm_dtls_exiting() */
	struct esdm_dtls *left_next;

	/* The records of the connection, NULL for the ones of the backend */
	const struct esdm_dtls_ops *ops;

	/* The largest message the peer may send */
	size_t max_msg;

	/*
	 * The parts of a message received so far, allocated for a message of
	 * several parts only: a connection mostly carries messages of one
	 * record, and a server holds many connections. Its size is the limit
	 * of the call receiving the first part.
	 */
	uint8_t *partial;
	size_t partial_len;
	size_t partial_size;
};

static __thread unsigned int esdm_dtls_busy_depth = 0;

static void esdm_dtls_enter(void)
{
	esdm_dtls_busy_depth++;
}

static void esdm_dtls_leave(void)
{
	esdm_dtls_busy_depth--;
}

DSO_PUBLIC
bool esdm_dtls_busy(void)
{
	return esdm_dtls_busy_depth > 0;
}

/*
 * The exit of the process. The TLS stack may be gone by the time the last
 * connection or context is released: by the destructor of a library, or by an
 * atexit handler registered before the TLS stack was set up - OPENSSL_cleanup()
 * tearing down an OpenSSL provider that uses the RPC client, for one. Both run
 * after the static destructors of the TLS stack, and Botan unmaps the memory
 * its secure allocator handed out there, so the destructor of every object
 * still holding some crashes the process. The connection is no use to anybody
 * at the exit either.
 *
 * So nothing goes into the TLS stack any more once the process exits: what is
 * released then wipes what this file holds of it, and leaves the objects of the
 * TLS stack to the end of the process - kept reachable on the lists below for
 * leak checkers, and LeakSanitizer is told, as the lists go with the library
 * when it is unloaded at the exit. The exit is told by an atexit handler, registered once the
 * first context of the TLS stack exists: the handlers of the exit run in the
 * reverse order of their registration, so the static destructors the TLS stack
 * registered while the backend set up the context - it sets up what it frees
 * at the exit, see esdm_dtls_botan.cpp - run after the handler.
 */
static atomic_bool esdm_dtls_exit_started = false;
static _Atomic(struct esdm_dtls *) esdm_dtls_left = NULL;

static bool esdm_dtls_exiting(void)
{
	return atomic_load(&esdm_dtls_exit_started);
}

static void esdm_dtls_leave_behind(struct esdm_dtls *dtls)
{
	struct esdm_dtls *head = atomic_load(&esdm_dtls_left);

	esdm_leak_intended(dtls);
	do {
		dtls->left_next = head;
	} while (!atomic_compare_exchange_weak(&esdm_dtls_left, &head, dtls));
}

#ifdef ESDM_DTLS
static pthread_once_t esdm_dtls_exit_once = PTHREAD_ONCE_INIT;
static _Atomic(struct esdm_dtls_ctx *) esdm_dtls_ctx_left = NULL;

static void esdm_dtls_at_exit(void)
{
	atomic_store(&esdm_dtls_exit_started, true);
}

static void esdm_dtls_exit_register(void)
{
	/*
	 * Should it fail, the TLS stack is called at the exit as before - no
	 * reason to refuse the connection.
	 */
	(void)atexit(esdm_dtls_at_exit);
}

static void esdm_dtls_ctx_leave_behind(struct esdm_dtls_ctx *ctx)
{
	struct esdm_dtls_ctx *head = atomic_load(&esdm_dtls_ctx_left);

	esdm_leak_intended(ctx);
	do {
		ctx->left_next = head;
	} while (
		!atomic_compare_exchange_weak(&esdm_dtls_ctx_left, &head, ctx));
}
#endif /* ESDM_DTLS */

DSO_PUBLIC
int esdm_dtls_ctx_alloc(bool server, struct esdm_dtls_ctx **ctx)
{
#ifdef ESDM_DTLS
	struct esdm_dtls_ctx *c;
	int ret;
#endif

	if (!ctx)
		return -EINVAL;
	*ctx = NULL;

#ifndef ESDM_DTLS
	/* No opportunistic DTLS in this build, only the one of esdm_tls.h */
	(void)server;
	return -EOPNOTSUPP;
#else
	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;
	c->server = server;

	esdm_dtls_enter();
	ret = esdm_dtls_backend_ctx_new(server, &c->backend);
	esdm_dtls_leave();
	if (ret) {
		free(c);
		return ret;
	}

	/* After the TLS stack set itself up, see esdm_dtls_exiting() */
	pthread_once(&esdm_dtls_exit_once, esdm_dtls_exit_register);

	*ctx = c;
	return 0;
#endif
}

DSO_PUBLIC
void esdm_dtls_ctx_free(struct esdm_dtls_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef ESDM_DTLS
	if (esdm_dtls_exiting()) {
		esdm_dtls_ctx_leave_behind(ctx);
		return;
	}

	esdm_dtls_enter();
	esdm_dtls_backend_ctx_free(ctx->backend);
	esdm_dtls_leave();
#endif
	free(ctx);
}

DSO_PUBLIC
int esdm_dtls_alloc(struct esdm_dtls_ctx *ctx, int fd, size_t max_msg,
		    struct esdm_dtls **dtls)
{
#ifdef ESDM_DTLS
	struct esdm_dtls *d;
	int ret;
#endif

	if (!ctx || !dtls || fd < 0 || !max_msg)
		return -EINVAL;
	*dtls = NULL;

#ifndef ESDM_DTLS
	return -EOPNOTSUPP;
#else
	d = calloc(1, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->max_msg = max_msg;

	esdm_dtls_enter();
	ret = esdm_dtls_backend_conn_new(ctx->backend, ctx->server, fd,
					 &d->backend);
	esdm_dtls_leave();
	if (ret) {
		free(d);
		return ret;
	}

	*dtls = d;
	return 0;
#endif
}

int esdm_dtls_new_ops(const struct esdm_dtls_ops *ops, void *conn,
		      size_t max_msg, struct esdm_dtls **dtls)
{
	struct esdm_dtls *d = calloc(1, sizeof(*d));

	if (!d) {
		ops->free(conn);
		return -ENOMEM;
	}
	d->ops = ops;
	d->backend = conn;
	d->max_msg = max_msg;

	*dtls = d;
	return 0;
}

void *esdm_dtls_ops_conn(struct esdm_dtls *dtls,
			 const struct esdm_dtls_ops *ops)
{
	return (dtls && dtls->ops == ops) ? dtls->backend : NULL;
}

/* The records of the connection, of the backend or of its ops */
static int esdm_dtls_rec_handshake(struct esdm_dtls *dtls)
{
	if (dtls->ops)
		return dtls->ops->handshake(dtls->backend);
#ifdef ESDM_DTLS
	return esdm_dtls_backend_handshake(dtls->backend);
#else
	return -EOPNOTSUPP;
#endif
}

static int esdm_dtls_rec_send(struct esdm_dtls *dtls, const uint8_t *buf,
			      size_t len)
{
	if (dtls->ops)
		return dtls->ops->send(dtls->backend, buf, len);
#ifdef ESDM_DTLS
	return esdm_dtls_backend_send(dtls->backend, buf, len);
#else
	return -EOPNOTSUPP;
#endif
}

static ssize_t esdm_dtls_rec_recv(struct esdm_dtls *dtls, uint8_t *buf,
				  size_t len)
{
	if (dtls->ops)
		return dtls->ops->recv(dtls->backend, buf, len);
#ifdef ESDM_DTLS
	return esdm_dtls_backend_recv(dtls->backend, buf, len);
#else
	return -EOPNOTSUPP;
#endif
}

static void esdm_dtls_drop_partial(struct esdm_dtls *dtls)
{
	if (dtls->partial) {
		memset_secure(dtls->partial, 0, dtls->partial_len);
		free(dtls->partial);
	}
	dtls->partial = NULL;
	dtls->partial_len = 0;
	dtls->partial_size = 0;
}

DSO_PUBLIC
void esdm_dtls_free(struct esdm_dtls *dtls)
{
	if (!dtls)
		return;

	esdm_dtls_drop_partial(dtls);

	/* Not into the TLS stack at the exit, see esdm_dtls_exiting() */
	if (esdm_dtls_exiting()) {
		esdm_dtls_leave_behind(dtls);
		return;
	}

	esdm_dtls_enter();
	if (dtls->ops)
		dtls->ops->free(dtls->backend);
#ifdef ESDM_DTLS
	else
		esdm_dtls_backend_conn_free(dtls->backend);
#endif
	esdm_dtls_leave();
	free(dtls);
}

DSO_PUBLIC
int esdm_dtls_handshake(struct esdm_dtls *dtls)
{
	int ret;

	if (!dtls)
		return -EINVAL;

	esdm_dtls_enter();
	ret = esdm_dtls_rec_handshake(dtls);
	esdm_dtls_leave();

	return ret;
}

DSO_PUBLIC
short esdm_dtls_want(struct esdm_dtls *dtls)
{
	if (dtls && dtls->ops)
		return dtls->ops->want(dtls->backend);
	return POLLIN;
}

DSO_PUBLIC
int esdm_dtls_send(struct esdm_dtls *dtls, const void *buf, size_t len)
{
	const size_t recsize = ESDM_DTLS_PART_SIZE + 1;
	const uint8_t *p = buf;
	/* The bytes of rec the parts were copied to */
	size_t used = 0;
	uint8_t *rec;
	int ret = 0;

	if (!dtls || (!buf && len))
		return -EINVAL;

	rec = malloc(recsize);
	if (!rec)
		return -ENOMEM;

	esdm_dtls_enter();
	do {
		size_t part =
			len > ESDM_DTLS_PART_SIZE ? ESDM_DTLS_PART_SIZE : len;

		rec[0] = len > part ? ESDM_DTLS_MORE : ESDM_DTLS_LAST;
		if (part)
			memcpy(rec + 1, p, part);
		if (part + 1 > used)
			used = part + 1;
		ret = esdm_dtls_rec_send(dtls, rec, part + 1);
		p += part;
		len -= part;
	} while (!ret && len);
	/* What the records of the ops hold of it goes out now */
	if (!ret && dtls->ops)
		ret = dtls->ops->flush(dtls->backend);
	esdm_dtls_leave();

	/*
	 * Only what the parts were copied to - nothing else of the buffer ever
	 * held a byte of the message. Most messages are a few dozen bytes, and
	 * the 16 KiB wiped for each of them were a share of every request.
	 */
	memset_secure(rec, 0, used);
	free(rec);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_dtls_recv(struct esdm_dtls *dtls, void *buf, size_t len)
{
	uint8_t *rec;
	ssize_t n, ret;
	/* The bytes of rec the records were received into */
	size_t part, limit, filled = 0;

	if (!dtls || !buf)
		return -EINVAL;

	limit = len < dtls->max_msg ? len : dtls->max_msg;
	/* The rest of a message must fit where its first parts went */
	if (dtls->partial && limit > dtls->partial_size)
		limit = dtls->partial_size;

	rec = malloc(ESDM_DTLS_RECORD_BUF);
	if (!rec)
		return -ENOMEM;

	esdm_dtls_enter();
	for (;;) {
		n = esdm_dtls_rec_recv(dtls, rec, ESDM_DTLS_RECORD_BUF);
		if (n < 0) {
			ret = n;
			goto out;
		}
		if ((size_t)n > filled)
			filled = (size_t)n;
		/* Empty, or longer than a part can be: no record of ours */
		if (n < 1 || (size_t)n > ESDM_DTLS_PART_SIZE + 1 ||
		    (rec[0] != ESDM_DTLS_MORE && rec[0] != ESDM_DTLS_LAST)) {
			ret = -EPROTO;
			goto out;
		}
		part = (size_t)n - 1;

		if (dtls->partial_len + part > limit) {
			ret = -EMSGSIZE;
			goto out;
		}

		/* The common case: a message of one record */
		if (rec[0] == ESDM_DTLS_LAST && !dtls->partial) {
			memcpy(buf, rec + 1, part);
			ret = (ssize_t)part;
			goto out;
		}

		if (!dtls->partial) {
			dtls->partial = malloc(limit);
			if (!dtls->partial) {
				ret = -ENOMEM;
				goto out;
			}
			dtls->partial_size = limit;
		}
		memcpy(dtls->partial + dtls->partial_len, rec + 1, part);
		dtls->partial_len += part;

		if (rec[0] == ESDM_DTLS_LAST) {
			memcpy(buf, dtls->partial, dtls->partial_len);
			ret = (ssize_t)dtls->partial_len;
			esdm_dtls_drop_partial(dtls);
			goto out;
		}
	}

out:
	esdm_dtls_leave();
	/*
	 * Only what a record was received into: a backend writes a record of
	 * the size it returns, and nothing when it fails - and a caller waiting
	 * for its answer looks for it, and finds nothing, often.
	 */
	memset_secure(rec, 0, filled);
	free(rec);
	if (ret < 0 && ret != -EAGAIN)
		esdm_dtls_drop_partial(dtls);
	return ret;
}

DSO_PUBLIC
bool esdm_dtls_pending(struct esdm_dtls *dtls)
{
	bool ret;

	if (!dtls)
		return false;

	esdm_dtls_enter();
	if (dtls->ops)
		ret = dtls->ops->pending(dtls->backend);
	else
#ifdef ESDM_DTLS
		ret = esdm_dtls_backend_pending(dtls->backend);
#else
		ret = false;
#endif
	esdm_dtls_leave();

	return ret;
}

DSO_PUBLIC
const char *esdm_dtls_cipher(struct esdm_dtls *dtls)
{
	if (!dtls)
		return "none";
	if (dtls->ops)
		return dtls->ops->cipher(dtls->backend);
#ifdef ESDM_DTLS
	return esdm_dtls_backend_cipher(dtls->backend);
#else
	return "none";
#endif
}
