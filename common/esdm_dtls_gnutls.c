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
 * DTLS of esdm_dtls_backend.h by GnuTLS, for crypto_backend=gnutls.
 *
 * GnuTLS reaches the socket through push and pull functions of its own, one
 * send(2) or recv(2) of one message each on the non-blocking socket; the
 * session is a non-blocking datagram one, so that every call returns
 * GNUTLS_E_AGAIN rather than waiting for the peer.
 */

#include <errno.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"

/* DTLS 1.2 exactly, ECDHE with ECDSA, AEAD ciphers only, no tickets */
#define ESDM_DTLS_GNUTLS_PRIORITY                                              \
	"NONE:+VERS-DTLS1.2:+ECDHE-ECDSA:+AES-256-GCM:+CHACHA20-POLY1305:"     \
	"+AES-128-GCM:+AEAD:+SIGN-ECDSA-SECP256R1-SHA256:+SIGN-ECDSA-SHA256:"  \
	"+GROUP-SECP256R1:+GROUP-X25519:+COMP-NULL:+CTYPE-X509:%NO_TICKETS"

struct esdm_dtls_gnutls_ctx {
	gnutls_certificate_credentials_t cred;
	gnutls_priority_t prio;
};

struct esdm_dtls_gnutls_conn {
	gnutls_session_t session;
	int fd;
};

static ssize_t esdm_dtls_gnutls_push(gnutls_transport_ptr_t ptr,
				     const void *buf, size_t len)
{
	struct esdm_dtls_gnutls_conn *c = ptr;
	ssize_t n = send(c->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);

	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

static ssize_t esdm_dtls_gnutls_pull(gnutls_transport_ptr_t ptr, void *buf,
				     size_t len)
{
	struct esdm_dtls_gnutls_conn *c = ptr;
	ssize_t n = recv(c->fd, buf, len, MSG_DONTWAIT);

	/*
	 * 0: the peer is gone. To a datagram session that would be an empty
	 * datagram to be waited past, so it is an error here.
	 */
	if (n == 0) {
		gnutls_transport_set_errno(c->session, ECONNRESET);
		return -1;
	}
	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

/* Is a message there? The session never waits, see the file header */
static int esdm_dtls_gnutls_pull_timeout(gnutls_transport_ptr_t ptr,
					 unsigned int ms)
{
	struct esdm_dtls_gnutls_conn *c = ptr;
	struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
	int ret;

	(void)ms;
	ret = poll(&pfd, 1, 0);
	if (ret < 0)
		gnutls_transport_set_errno(c->session, errno);

	return ret;
}

/* The result @ret of a GnuTLS operation that did not complete */
static int esdm_dtls_gnutls_error(int ret)
{
	switch (ret) {
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		return -EAGAIN;
	case GNUTLS_E_PREMATURE_TERMINATION:
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PUSH_ERROR:
		return -ECONNRESET;
	default:
		/* An alert of a warning, a datagram dropped: go on */
		return gnutls_error_is_fatal(ret) ? -EPROTO : -EAGAIN;
	}
}

/******************************************************************************
 * esdm_dtls_backend.h
 ******************************************************************************/

const char *esdm_dtls_backend_name(void)
{
	return "GnuTLS";
}

/*
 * An ephemeral key and a self-signed certificate for it: the DTLS is
 * unauthenticated - see esdm_dtls.h - so the certificate is only what DTLS
 * needs to carry the key, and nobody verifies it.
 */
static int esdm_dtls_gnutls_server_key(gnutls_certificate_credentials_t cred)
{
	gnutls_x509_privkey_t key = NULL;
	gnutls_x509_crt_t crt = NULL;
	const unsigned char serial = 1;
	time_t now = time(NULL);
	int ret = -ENOMEM;

	if (gnutls_x509_privkey_init(&key) < 0 ||
	    gnutls_x509_privkey_generate(
		    key, GNUTLS_PK_ECDSA,
		    GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0) < 0 ||
	    gnutls_x509_crt_init(&crt) < 0)
		goto out;

	if (gnutls_x509_crt_set_version(crt, 3) < 0 ||
	    gnutls_x509_crt_set_serial(crt, &serial, sizeof(serial)) < 0 ||
	    gnutls_x509_crt_set_activation_time(crt, now - 3600) < 0 ||
	    gnutls_x509_crt_set_expiration_time(crt, now + 3600L * 24 * 3650) <
		    0 ||
	    gnutls_x509_crt_set_key(crt, key) < 0 ||
	    gnutls_x509_crt_set_dn(crt, "CN=esdm", NULL) < 0 ||
	    gnutls_x509_crt_set_issuer_dn(crt, "CN=esdm", NULL) < 0 ||
	    gnutls_x509_crt_sign2(crt, crt, key, GNUTLS_DIG_SHA256, 0) < 0 ||
	    /* Copied into the credentials */
	    gnutls_certificate_set_x509_key(cred, &crt, 1, key) < 0)
		goto out;

	ret = 0;

out:
	if (crt)
		gnutls_x509_crt_deinit(crt);
	if (key)
		gnutls_x509_privkey_deinit(key);
	return ret;
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	struct esdm_dtls_gnutls_ctx *c = calloc(1, sizeof(*c));

	if (!c)
		return -ENOMEM;

	if (gnutls_certificate_allocate_credentials(&c->cred) < 0) {
		free(c);
		return -ENOMEM;
	}
	if (gnutls_priority_init(&c->prio, ESDM_DTLS_GNUTLS_PRIORITY, NULL) < 0)
		goto err;

	/* A client verifies nothing: unauthenticated, see esdm_dtls.h */
	if (server && esdm_dtls_gnutls_server_key(c->cred))
		goto err;

	*ctx = c;
	return 0;

err:
	esdm_dtls_backend_ctx_free(c);
	return -ENOMEM;
}

void esdm_dtls_backend_ctx_free(void *ctx)
{
	struct esdm_dtls_gnutls_ctx *c = ctx;

	if (!c)
		return;
	if (c->prio)
		gnutls_priority_deinit(c->prio);
	if (c->cred)
		gnutls_certificate_free_credentials(c->cred);
	free(c);
}

int esdm_dtls_backend_conn_new(void *ctx, bool server, int fd, void **conn)
{
	struct esdm_dtls_gnutls_ctx *c = ctx;
	struct esdm_dtls_gnutls_conn *d = calloc(1, sizeof(*d));

	if (!d)
		return -ENOMEM;
	d->fd = fd;

	if (gnutls_init(&d->session, (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
					     GNUTLS_DATAGRAM | GNUTLS_NONBLOCK |
					     GNUTLS_NO_TICKETS) < 0) {
		free(d);
		return -ENOMEM;
	}

	if (gnutls_priority_set(d->session, c->prio) < 0 ||
	    gnutls_credentials_set(d->session, GNUTLS_CRD_CERTIFICATE,
				   c->cred) < 0) {
		esdm_dtls_backend_conn_free(d);
		return -ENOMEM;
	}

	gnutls_transport_set_ptr(d->session, d);
	gnutls_transport_set_push_function(d->session, esdm_dtls_gnutls_push);
	gnutls_transport_set_pull_function(d->session, esdm_dtls_gnutls_pull);
	gnutls_transport_set_pull_timeout_function(
		d->session, esdm_dtls_gnutls_pull_timeout);

	/* No MTU to discover on the connection, and no record to fragment */
	gnutls_dtls_set_mtu(d->session, ESDM_DTLS_LINK_MTU);

	*conn = d;
	return 0;
}

void esdm_dtls_backend_conn_free(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;

	if (!d)
		return;
	gnutls_deinit(d->session);
	free(d);
}

int esdm_dtls_backend_handshake(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	int ret = gnutls_handshake(d->session);

	return ret == GNUTLS_E_SUCCESS ? 0 : esdm_dtls_gnutls_error(ret);
}

int esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	ssize_t ret = gnutls_record_send(d->session, buf, len);

	if (ret == (ssize_t)len)
		return 0;
	if (ret >= 0)
		return -EIO;
	return esdm_dtls_gnutls_error((int)ret);
}

ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	ssize_t ret = gnutls_record_recv(d->session, buf, len);

	if (ret > 0)
		return ret;
	/* 0: the peer closed the session */
	if (ret == 0)
		return -ECONNRESET;
	return esdm_dtls_gnutls_error((int)ret);
}

bool esdm_dtls_backend_pending(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;

	return gnutls_record_check_pending(d->session) > 0;
}

const char *esdm_dtls_backend_cipher(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	const char *name =
		gnutls_cipher_get_name(gnutls_cipher_get(d->session));

	return name ? name : "unknown";
}
