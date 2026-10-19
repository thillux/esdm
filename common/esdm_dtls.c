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
 * the records of the backend, and the busy marker of the thread.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
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
};

struct esdm_dtls {
	void *backend;

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

DSO_PUBLIC
int esdm_dtls_ctx_alloc(bool server, struct esdm_dtls_ctx **ctx)
{
	struct esdm_dtls_ctx *c;
	int ret;

	if (!ctx)
		return -EINVAL;
	*ctx = NULL;

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

	*ctx = c;
	return 0;
}

DSO_PUBLIC
void esdm_dtls_ctx_free(struct esdm_dtls_ctx *ctx)
{
	if (!ctx)
		return;

	esdm_dtls_enter();
	esdm_dtls_backend_ctx_free(ctx->backend);
	esdm_dtls_leave();
	free(ctx);
}

DSO_PUBLIC
int esdm_dtls_alloc(struct esdm_dtls_ctx *ctx, int fd, size_t max_msg,
		    struct esdm_dtls **dtls)
{
	struct esdm_dtls *d;
	int ret;

	if (!ctx || !dtls || fd < 0 || !max_msg)
		return -EINVAL;
	*dtls = NULL;

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
	esdm_dtls_enter();
	esdm_dtls_backend_conn_free(dtls->backend);
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
	ret = esdm_dtls_backend_handshake(dtls->backend);
	esdm_dtls_leave();

	return ret;
}

DSO_PUBLIC
int esdm_dtls_send(struct esdm_dtls *dtls, const void *buf, size_t len)
{
	const size_t recsize = ESDM_DTLS_PART_SIZE + 1;
	const uint8_t *p = buf;
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
		ret = esdm_dtls_backend_send(dtls->backend, rec, part + 1);
		p += part;
		len -= part;
	} while (!ret && len);
	esdm_dtls_leave();

	memset_secure(rec, 0, recsize);
	free(rec);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_dtls_recv(struct esdm_dtls *dtls, void *buf, size_t len)
{
	uint8_t *rec;
	ssize_t n, ret;
	size_t part, limit;

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
		n = esdm_dtls_backend_recv(dtls->backend, rec,
					   ESDM_DTLS_RECORD_BUF);
		if (n < 0) {
			ret = n;
			goto out;
		}
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
	memset_secure(rec, 0, ESDM_DTLS_RECORD_BUF);
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
	ret = esdm_dtls_backend_pending(dtls->backend);
	esdm_dtls_leave();

	return ret;
}

DSO_PUBLIC
const char *esdm_dtls_cipher(struct esdm_dtls *dtls)
{
	return dtls ? esdm_dtls_backend_cipher(dtls->backend) : "none";
}
