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
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"
#include "memset_secure.h"

/*
 * DTLS 1.2 exactly, TLS_ECDHE_PSK_AES_256_CBC_SHA384 on P-521, no tickets.
 * GnuTLS has no ECDHE-PSK suite with AES-GCM - RFC 8442's - and its one with
 * an AEAD cipher is ChaCha20-Poly1305, which neither NIST SP 800-52r2 nor
 * BSI TR-02102-2 allows. Encrypt-then-MAC is on by default, and required:
 * see esdm_dtls_backend_handshake(). Nothing is signed - GnuTLS only wants a
 * signature algorithm in the priorities, and the hello carries it.
 */
#define ESDM_DTLS_GNUTLS_PRIORITY                                              \
	"NONE:+VERS-DTLS1.2:+ECDHE-PSK:+AES-256-CBC:+SHA384:"                  \
	"+GROUP-SECP521R1:+SIGN-ECDSA-SHA512:+COMP-NULL:%NO_TICKETS"

struct esdm_dtls_gnutls_ctx {
	gnutls_psk_client_credentials_t client_cred;
	gnutls_psk_server_credentials_t server_cred;
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
 * The pre-shared key of a server, see esdm_dtls_backend.h: it knows no other
 * identity, and refuses a client with another one.
 */
static int esdm_dtls_gnutls_psk_server(gnutls_session_t session,
				       const char *username,
				       gnutls_datum_t *key)
{
	(void)session;

	if (!username || strcmp(username, ESDM_DTLS_PSK_IDENTITY))
		return -1;

	/* GnuTLS frees it */
	key->data = gnutls_malloc(sizeof(esdm_dtls_psk));
	if (!key->data)
		return -1;
	memcpy(key->data, esdm_dtls_psk, sizeof(esdm_dtls_psk));
	key->size = sizeof(esdm_dtls_psk);
	return 0;
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	struct esdm_dtls_gnutls_ctx *c = calloc(1, sizeof(*c));
	/* Copied into the credentials */
	const gnutls_datum_t key = { .data = (unsigned char *)esdm_dtls_psk,
				     .size = sizeof(esdm_dtls_psk) };

	if (!c)
		return -ENOMEM;

	if (server) {
		if (gnutls_psk_allocate_server_credentials(&c->server_cred) < 0)
			goto err;
		gnutls_psk_set_server_credentials_function(
			c->server_cred, esdm_dtls_gnutls_psk_server);
	} else {
		if (gnutls_psk_allocate_client_credentials(&c->client_cred) <
			    0 ||
		    gnutls_psk_set_client_credentials(
			    c->client_cred, ESDM_DTLS_PSK_IDENTITY, &key,
			    GNUTLS_PSK_KEY_RAW) < 0)
			goto err;
	}
	if (gnutls_priority_init(&c->prio, ESDM_DTLS_GNUTLS_PRIORITY, NULL) < 0)
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
	if (c->server_cred)
		gnutls_psk_free_server_credentials(c->server_cred);
	if (c->client_cred)
		gnutls_psk_free_client_credentials(c->client_cred);
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
	    gnutls_credentials_set(d->session, GNUTLS_CRD_PSK,
				   server ? (void *)c->server_cred :
					    (void *)c->client_cred) < 0) {
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

/*
 * A session without Encrypt-then-MAC (RFC 7366) is refused: MAC-then-encrypt
 * of CBC is what Lucky Thirteen reads records from, and DTLS lets an attacker
 * try again after every record it broke. Every peer of the ESDM offers and
 * agrees to it, whichever its TLS stack.
 */
int esdm_dtls_backend_handshake(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	int ret = gnutls_handshake(d->session);

	if (ret != GNUTLS_E_SUCCESS)
		return esdm_dtls_gnutls_error(ret);

	return gnutls_session_etm_status(d->session) ? 0 : -EPROTO;
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

/*
 * GnuTLS decrypts a record into a buffer of its own, which gnutls_record_recv()
 * frees without wiping it: the packet is taken from GnuTLS instead, and wiped
 * here before it is freed.
 */
ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	gnutls_packet_t packet = NULL;
	gnutls_datum_t data;
	ssize_t ret = gnutls_record_recv_packet(d->session, &packet);

	if (packet) {
		gnutls_packet_get(packet, &data, NULL);
		/* A record larger than @len: its size tells the caller */
		if (ret > 0) {
			ret = data.size < len ? (ssize_t)data.size :
						(ssize_t)len;
			memcpy(buf, data.data, (size_t)ret);
		}
		memset_secure(data.data, 0, data.size);
		gnutls_packet_deinit(packet);
	}

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
		gnutls_cipher_suite_get_name(gnutls_kx_get(d->session),
					     gnutls_cipher_get(d->session),
					     gnutls_mac_get(d->session));

	return name ? name : "unknown";
}
