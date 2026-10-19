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
 * The messages of esdm_dtls.h on the DTLS with certificates of esdm_tls.h on
 * SCTP - see "DTLS with certificates" in esdm_dtls.h. Built into the static
 * common library with the TLS layer, for es-ext-net.
 */

#include <errno.h>
#include <stdint.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
#include "esdm_tls.h"

static int esdm_dtls_tls_handshake(void *conn)
{
	return esdm_tls_handshake(conn);
}

static int esdm_dtls_tls_send(void *conn, const uint8_t *buf, size_t len)
{
	ssize_t n = esdm_tls_send(conn, buf, len);

	/* A record is taken whole on SCTP */
	if (n == (ssize_t)len)
		return 0;
	return n < 0 ? (int)n : -EIO;
}

static ssize_t esdm_dtls_tls_recv(void *conn, uint8_t *buf, size_t len)
{
	ssize_t n = esdm_tls_recv(conn, buf, len);

	/* The closing alert ends the connection, as the end of it does */
	return n == 0 ? -ECONNRESET : n;
}

static bool esdm_dtls_tls_pending(void *conn)
{
	return esdm_tls_pending(conn);
}

static const char *esdm_dtls_tls_cipher(void *conn)
{
	return esdm_tls_cipher(conn);
}

static short esdm_dtls_tls_want(void *conn)
{
	return esdm_tls_want(conn);
}

static int esdm_dtls_tls_flush(void *conn)
{
	return esdm_tls_flush(conn);
}

static void esdm_dtls_tls_free(void *conn)
{
	esdm_tls_free(conn);
}

static const struct esdm_dtls_ops esdm_dtls_tls_ops = {
	.handshake = esdm_dtls_tls_handshake,
	.send = esdm_dtls_tls_send,
	.recv = esdm_dtls_tls_recv,
	.pending = esdm_dtls_tls_pending,
	.cipher = esdm_dtls_tls_cipher,
	.want = esdm_dtls_tls_want,
	.flush = esdm_dtls_tls_flush,
	.free = esdm_dtls_tls_free,
};

int esdm_dtls_alloc_tls(struct esdm_tls_ctx *ctx, int fd, size_t max_msg,
			const char *server_name, struct esdm_dtls **dtls)
{
	struct esdm_tls *tls;
	int ret;

	if (!ctx || !dtls || fd < 0 || !max_msg)
		return -EINVAL;
	*dtls = NULL;

	ret = esdm_tls_alloc(ctx, fd, server_name, &tls);
	if (ret)
		return ret;

	return esdm_dtls_new_ops(&esdm_dtls_tls_ops, tls, max_msg, dtls);
}

struct esdm_tls *esdm_dtls_tls(struct esdm_dtls *dtls)
{
	return esdm_dtls_ops_conn(dtls, &esdm_dtls_tls_ops);
}
