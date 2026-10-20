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
 * The messages of esdm_dtls.h on the TLS with certificates of esdm_tls.h on
 * TCP - see "TLS with certificates" in esdm_dtls.h. Built into the static
 * common library with the TLS layer, for es-ext-net.
 *
 * TCP keeps no boundaries, and neither does TLS - a TLS stack may cut what is
 * written into records as it likes: every record of the messages goes as a
 * frame of its own, its length in front, two bytes, big endian. The receiver
 * takes the length, then as many bytes - collected across calls here, as the
 * stream hands them out.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_dtls.h"
#include "esdm_tls.h"
#include "esdm_tls_backend.h"
#include "memset_secure.h"

/* The length in front of a record */
#define ESDM_DTLS_TLS_HDR 2

struct esdm_dtls_tls {
	struct esdm_tls *tls;

	/* The frame being received: its length, then the record */
	uint8_t hdr[ESDM_DTLS_TLS_HDR];
	size_t hdr_len;
	uint8_t *rec;
	size_t rec_len;
	size_t rec_got;
};

static void esdm_dtls_tls_drop_rec(struct esdm_dtls_tls *t)
{
	if (t->rec) {
		memset_secure(t->rec, 0, t->rec_got);
		free(t->rec);
	}
	t->rec = NULL;
	t->rec_len = t->rec_got = t->hdr_len = 0;
}

/* @ret of the TLS connection, and what it waits for if it does */
static ssize_t esdm_dtls_tls_wait(struct esdm_dtls_tls *t, ssize_t ret,
				  short *want)
{
	if (ret == -EAGAIN)
		*want = esdm_tls_want(t->tls);
	return ret;
}

static int esdm_dtls_tls_handshake(void *conn, short *want)
{
	struct esdm_dtls_tls *t = conn;

	return (int)esdm_dtls_tls_wait(t, esdm_tls_handshake(t->tls), want);
}

/* One frame, taken whole - or the connection is no use any more */
static ssize_t esdm_dtls_tls_send(void *conn, const uint8_t *buf, size_t len,
				  short *want)
{
	struct esdm_dtls_tls *t = conn;
	size_t flen = ESDM_DTLS_TLS_HDR + len;
	uint8_t *frame;
	ssize_t n;

	if (len > UINT16_MAX)
		return -EMSGSIZE;
	frame = malloc(flen);
	if (!frame)
		return -ENOMEM;
	frame[0] = (uint8_t)(len >> 8);
	frame[1] = (uint8_t)len;
	memcpy(frame + ESDM_DTLS_TLS_HDR, buf, len);

	n = esdm_tls_send(t->tls, frame, flen);

	memset_secure(frame, 0, flen);
	free(frame);
	if (n == (ssize_t)flen)
		return (ssize_t)len;
	return n < 0 ? esdm_dtls_tls_wait(t, n, want) : -EIO;
}

/* Receive @len bytes at most, collected in @dst from *@got on */
static ssize_t esdm_dtls_tls_fill(struct esdm_dtls_tls *t, uint8_t *dst,
				  size_t *got, size_t len)
{
	while (*got < len) {
		ssize_t n = esdm_tls_recv(t->tls, dst + *got, len - *got);

		/* The closing alert ends the connection, as the end of it does */
		if (n == 0)
			return -ECONNRESET;
		if (n < 0)
			return n;
		*got += (size_t)n;
	}

	return 0;
}

static ssize_t esdm_dtls_tls_recv(void *conn, uint8_t *buf, size_t len,
				  short *want)
{
	struct esdm_dtls_tls *t = conn;
	size_t rec_len;
	ssize_t ret;

	ret = esdm_dtls_tls_fill(t, t->hdr, &t->hdr_len, ESDM_DTLS_TLS_HDR);
	if (ret)
		return esdm_dtls_tls_wait(t, ret, want);

	if (!t->rec) {
		rec_len = (size_t)t->hdr[0] << 8 | t->hdr[1];
		/* No record of ours: the caller has room for every one */
		if (!rec_len || rec_len > len)
			return -EPROTO;
		t->rec = malloc(rec_len);
		if (!t->rec)
			return -ENOMEM;
		t->rec_len = rec_len;
	}

	ret = esdm_dtls_tls_fill(t, t->rec, &t->rec_got, t->rec_len);
	if (ret)
		return esdm_dtls_tls_wait(t, ret, want);
	if (t->rec_len > len)
		return -EPROTO;

	memcpy(buf, t->rec, t->rec_len);
	ret = (ssize_t)t->rec_len;
	esdm_dtls_tls_drop_rec(t);
	return ret;
}

static bool esdm_dtls_tls_pending(void *conn)
{
	struct esdm_dtls_tls *t = conn;

	return esdm_tls_pending(t->tls);
}

static const char *esdm_dtls_tls_cipher(void *conn)
{
	struct esdm_dtls_tls *t = conn;

	return esdm_tls_cipher(t->tls);
}

static int esdm_dtls_tls_flush(void *conn, short *want)
{
	struct esdm_dtls_tls *t = conn;

	return (int)esdm_dtls_tls_wait(t, esdm_tls_flush(t->tls), want);
}

static void esdm_dtls_tls_free(void *conn)
{
	struct esdm_dtls_tls *t = conn;

	esdm_tls_free(t->tls);
	esdm_dtls_tls_drop_rec(t);
	memset_secure(t, 0, sizeof(*t));
	free(t);
}

static const struct esdm_dtls_ops esdm_dtls_tls_ops = {
	.handshake = esdm_dtls_tls_handshake,
	.send = esdm_dtls_tls_send,
	.flush = esdm_dtls_tls_flush,
	.recv = esdm_dtls_tls_recv,
	.pending = esdm_dtls_tls_pending,
	.cipher = esdm_dtls_tls_cipher,
	.free = esdm_dtls_tls_free,
};

int esdm_dtls_alloc_tls(struct esdm_tls_ctx *ctx, int fd, size_t max_msg,
			const char *server_name, struct esdm_dtls **dtls)
{
	struct esdm_dtls_tls *t;
	int ret;

	if (!ctx || !dtls || fd < 0 || !max_msg)
		return -EINVAL;
	*dtls = NULL;

	t = calloc(1, sizeof(*t));
	if (!t)
		return -ENOMEM;

	ret = esdm_tls_alloc(ctx, fd, server_name, &t->tls);
	if (ret) {
		free(t);
		return ret;
	}

	return esdm_dtls_new_ops(&esdm_dtls_tls_ops, t, max_msg, dtls);
}

struct esdm_tls *esdm_dtls_tls(struct esdm_dtls *dtls)
{
	struct esdm_dtls_tls *t = esdm_dtls_ops_conn(dtls, &esdm_dtls_tls_ops);

	return t ? t->tls : NULL;
}
