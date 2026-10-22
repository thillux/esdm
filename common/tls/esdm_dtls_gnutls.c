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
 * message of esdm_dtls_io.h each on the non-blocking socket, which makes every
 * call return GNUTLS_E_AGAIN rather than wait for the peer. The session is a
 * datagram one with the replay detection of DTLS, and with timeouts too long
 * to ever retransmit: the connection is reliable.
 *
 * GnuTLS decrypts a record into a buffer of its own, which gnutls_record_recv()
 * frees without wiping it: the packet is taken from GnuTLS instead, handed out
 * whole, and wiped once it is used up.
 *
 * GnuTLS sends no alert of its own for a failed handshake: the one the failure
 * calls for is sent here.
 */

#include <errno.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_dtls_backend.h"
#include "esdm_dtls_session.h"
#include "memset_secure.h"

/*
 * The secure minimal mode of esdm_dtls_backend.h - a connection lives as long
 * as it does, with the one handshake it started with. It is in three places,
 * as GnuTLS takes it:
 *
 *  - The priorities, ESDM_DTLS_GNUTLS_MINIMAL: no tickets, and
 *    Encrypt-then-MAC required for a CBC suite. The extended master secret is
 *    not turned off (%NO_SESSION_HASH), and is required by
 *    esdm_dtls_gnutls_minimal_check() - %FORCE_SESSION_HASH is no keyword of
 *    every GnuTLS the ESDM builds with.
 *  - The flags of a session, ESDM_DTLS_GNUTLS_MINIMAL_FLAGS: no tickets
 *    either. Neither GNUTLS_ENABLE_EARLY_DATA nor GNUTLS_ENABLE_EARLY_START,
 *    so no early data is taken.
 *  - The session: resumed by ID from the cache of esdm_dtls_session.h alone,
 *    see esdm_dtls_gnutls_sessions(). A renegotiation either way ends the
 *    connection, see esdm_dtls_gnutls_error(). GnuTLS has no compression any
 *    more, and sends no heartbeat unless told to.
 */
#define ESDM_DTLS_GNUTLS_MINIMAL ":%NO_TICKETS:%FORCE_ETM"
#define ESDM_DTLS_GNUTLS_MINIMAL_FLAGS GNUTLS_NO_TICKETS

/*
 * DTLS 1.2 exactly, TLS_ECDHE_PSK_AES_256_CBC_SHA384 on P-521, in the minimal
 * mode. GnuTLS has no ECDHE-PSK suite with AES-GCM - RFC 8442's - and its one
 * with an AEAD cipher is ChaCha20-Poly1305, which neither NIST SP 800-52r2 nor
 * BSI TR-02102-2 allows. Encrypt-then-MAC is required - by %FORCE_ETM, and
 * checked by esdm_dtls_gnutls_minimal_check(). Nothing is signed - GnuTLS only
 * wants a signature algorithm in the priorities, and the hello carries it.
 */
#define ESDM_DTLS_GNUTLS_PSK_PRIORITY                                          \
	"NONE:+VERS-DTLS1.2:+ECDHE-PSK:+AES-256-CBC:+SHA384:"                  \
	"+GROUP-SECP521R1:+SIGN-ECDSA-SHA512:+COMP-NULL" ESDM_DTLS_GNUTLS_MINIMAL

/*
 * The retransmission and the total timeout of the DTLS handshake, in
 * milliseconds: long enough to never run out - the connection is reliable, and
 * the callers bound the handshake themselves
 */
#define ESDM_DTLS_GNUTLS_TIMEOUT_MS (600 * 1000)

struct esdm_dtls_gnutls_ctx {
	gnutls_priority_t prio;
	/* The pre-shared key */
	gnutls_psk_client_credentials_t psk_client;
	gnutls_psk_server_credentials_t psk_server;
	/* The sessions to resume, see esdm_dtls_session.h */
	struct esdm_dtls_sessions *sessions;
};

struct esdm_dtls_gnutls_conn {
	gnutls_session_t session;
	struct esdm_dtls_gnutls_ctx *ctx;
	struct esdm_dtls_io *io;
	/* A client: the socket path its session is kept under */
	uint8_t session_key[ESDM_DTLS_SESSION_KEY_MAX];
	size_t session_keylen;

	/* The alert a failed handshake calls for, sent once */
	bool alert_set;
	bool alert_sent;
	gnutls_alert_description_t alert;
};

/******************************************************************************
 * The transport
 ******************************************************************************/

static ssize_t esdm_dtls_gnutls_push(gnutls_transport_ptr_t ptr,
				     const void *buf, size_t len)
{
	struct esdm_dtls_gnutls_conn *c = ptr;
	ssize_t n = esdm_dtls_io_send(c->io, buf, len);

	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

static ssize_t esdm_dtls_gnutls_pull(gnutls_transport_ptr_t ptr, void *buf,
				     size_t len)
{
	struct esdm_dtls_gnutls_conn *c = ptr;
	ssize_t n = esdm_dtls_io_recv(c->io, buf, len);

	/*
	 * 0 is to a datagram session an empty datagram to be waited past: the
	 * peer gone is an error here
	 */
	if (n == 0) {
		gnutls_transport_set_errno(c->session, ECONNRESET);
		return -1;
	}
	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

/*
 * Is a message there? Always, to the DTLS of GnuTLS - and the pull tells
 * whether one really is. The answer only decides whether it retransmits its
 * flight, which it need not on a reliable connection. And it asks before it
 * reads the Finished of the peer even when it parsed that Finished already,
 * with the ChangeCipherSpec before it, which a peer may well have sent in a
 * message of its own: an answer by the socket would have the handshake wait
 * for a message that is not to come.
 */
static int esdm_dtls_gnutls_pull_timeout(gnutls_transport_ptr_t ptr,
					 unsigned int ms)
{
	(void)ptr;
	(void)ms;
	return 1;
}

/******************************************************************************
 * The errors
 ******************************************************************************/

/*
 * The result @ret of a GnuTLS operation of @c that did not complete: -EAGAIN
 * if it waits for the socket, with *want telling for what, or if it is to be
 * called again right away (*want is POLLOUT then, which a connected socket
 * signals at once), -ECONNRESET if the peer is gone, -EPROTO for anything
 * else.
 */
static int esdm_dtls_gnutls_error(struct esdm_dtls_gnutls_conn *c, int ret,
				  short *want)
{
	switch (ret) {
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		*want = gnutls_record_get_direction(c->session) ? POLLOUT :
								  POLLIN;
		return -EAGAIN;
	case GNUTLS_E_PREMATURE_TERMINATION:
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PUSH_ERROR:
		return -ECONNRESET;
	case GNUTLS_E_REHANDSHAKE:
		/*
		 * A peer asking for a renegotiation, which none of the ESDM
		 * does: see ESDM_DTLS_GNUTLS_MINIMAL
		 */
		return -EPROTO;
	default:
		if (!gnutls_error_is_fatal(ret)) {
			/* A warning alert, a datagram dropped: try again */
			*want = POLLOUT;
			return -EAGAIN;
		}
		return -EPROTO;
	}
}

/*
 * Tell the peer why the handshake failed with @ret, best effort: once, and
 * not for a failure the peer caused by going away or by an alert of its own.
 */
static void esdm_dtls_gnutls_alert(struct esdm_dtls_gnutls_conn *d, int ret)
{
	if (d->alert_sent || ret == GNUTLS_E_FATAL_ALERT_RECEIVED ||
	    ret == GNUTLS_E_PREMATURE_TERMINATION ||
	    ret == GNUTLS_E_PULL_ERROR || ret == GNUTLS_E_PUSH_ERROR)
		return;
	d->alert_sent = true;

	if (d->alert_set)
		gnutls_alert_send(d->session, GNUTLS_AL_FATAL, d->alert);
	else
		gnutls_alert_send_appropriate(d->session, ret);
}

/******************************************************************************
 * The context
 ******************************************************************************/

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

/* The pre-shared key of either side */
static int esdm_dtls_gnutls_psk(struct esdm_dtls_gnutls_ctx *c, bool server)
{
	/* Copied into the credentials */
	const gnutls_datum_t key = { .data = (unsigned char *)esdm_dtls_psk,
				     .size = sizeof(esdm_dtls_psk) };

	if (server) {
		if (gnutls_psk_allocate_server_credentials(&c->psk_server) < 0)
			return -ENOMEM;
		gnutls_psk_set_server_credentials_function(
			c->psk_server, esdm_dtls_gnutls_psk_server);
	} else {
		if (gnutls_psk_allocate_client_credentials(&c->psk_client) <
			    0 ||
		    gnutls_psk_set_client_credentials(
			    c->psk_client, ESDM_DTLS_PSK_IDENTITY, &key,
			    GNUTLS_PSK_KEY_RAW) < 0)
			return -ENOMEM;
	}

	return gnutls_priority_init(&c->prio, ESDM_DTLS_GNUTLS_PSK_PRIORITY,
				    NULL) < 0 ?
		       -ENOMEM :
		       0;
}
/*
 * The sessions of a server, kept in the cache of
 * esdm_dtls_session.h under their ID, as GnuTLS serialized them
 */
static int esdm_dtls_gnutls_db_store(void *ptr, gnutls_datum_t key,
				     gnutls_datum_t data)
{
	struct esdm_dtls_gnutls_ctx *c = ptr;

	esdm_dtls_sessions_put(c->sessions, key.data, key.size, data.data,
			       data.size);
	return 0;
}

static gnutls_datum_t esdm_dtls_gnutls_db_retrieve(void *ptr,
						   gnutls_datum_t key)
{
	struct esdm_dtls_gnutls_ctx *c = ptr;
	gnutls_datum_t ret = { NULL, 0 };
	uint8_t *data;
	size_t len;

	if (esdm_dtls_sessions_get(c->sessions, key.data, key.size, &data,
				   &len))
		return ret;
	/* GnuTLS frees what it is handed */
	ret.data = gnutls_malloc(len);
	if (ret.data) {
		memcpy(ret.data, data, len);
		ret.size = (unsigned int)len;
	}
	esdm_dtls_sessions_release(data, len);
	return ret;
}

static int esdm_dtls_gnutls_db_remove(void *ptr, gnutls_datum_t key)
{
	struct esdm_dtls_gnutls_ctx *c = ptr;

	esdm_dtls_sessions_del(c->sessions, key.data, key.size);
	return 0;
}

/*
 * The sessions are resumed by ID, see esdm_dtls_backend.h, still without
 * tickets: a server keeps them in the cache of esdm_dtls_session.h, a
 * client the one of the full handshake with its server under the socket path,
 * see esdm_dtls_gnutls_keep(), and offers it.
 */
static int esdm_dtls_gnutls_sessions(struct esdm_dtls_gnutls_conn *d,
				     bool server, const uint8_t *key,
				     size_t keylen)
{
	struct esdm_dtls_gnutls_ctx *c = d->ctx;
	uint8_t *data;
	size_t len;

	if (server) {
		gnutls_db_set_retrieve_function(d->session,
						esdm_dtls_gnutls_db_retrieve);
		gnutls_db_set_store_function(d->session,
					     esdm_dtls_gnutls_db_store);
		gnutls_db_set_remove_function(d->session,
					      esdm_dtls_gnutls_db_remove);
		gnutls_db_set_ptr(d->session, c);
		gnutls_db_set_cache_expiration(d->session,
					       ESDM_DTLS_SESSION_LIFETIME_S);
		return 0;
	}

	if (!key || !keylen || keylen > sizeof(d->session_key))
		return 0;
	memcpy(d->session_key, key, keylen);
	d->session_keylen = keylen;

	if (esdm_dtls_sessions_get(c->sessions, key, keylen, &data, &len))
		return 0;
	/* One GnuTLS does not take is not offered: a full handshake */
	(void)gnutls_session_set_data(d->session, data, len);
	esdm_dtls_sessions_release(data, len);
	return 0;
}

/* A client: keep the session of a full handshake with its server */
static void esdm_dtls_gnutls_keep(struct esdm_dtls_gnutls_conn *d)
{
	gnutls_datum_t data;

	if (!d->session_keylen || gnutls_session_is_resumed(d->session) ||
	    gnutls_session_get_data2(d->session, &data) < 0)
		return;
	esdm_dtls_sessions_put(d->ctx->sessions, d->session_key,
			       d->session_keylen, data.data, data.size);
	memset_secure(data.data, 0, data.size);
	gnutls_free(data.data);
}
/******************************************************************************
 * esdm_dtls_backend.h
 ******************************************************************************/

const char *esdm_dtls_backend_name(void)
{
	return "GnuTLS";
}

void esdm_dtls_backend_ctx_free(void *ctx)
{
	struct esdm_dtls_gnutls_ctx *c = ctx;

	if (!c)
		return;
	if (c->prio)
		gnutls_priority_deinit(c->prio);
	if (c->psk_server)
		gnutls_psk_free_server_credentials(c->psk_server);
	if (c->psk_client)
		gnutls_psk_free_client_credentials(c->psk_client);
	esdm_dtls_sessions_free(c->sessions);
	free(c);
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	struct esdm_dtls_gnutls_ctx *c = calloc(1, sizeof(*c));
	int ret;

	if (!c)
		return -ENOMEM;

	ret = esdm_dtls_gnutls_psk(c, server);
	if (!ret)
		ret = esdm_dtls_sessions_alloc(
			server ? ESDM_DTLS_SESSIONS_SERVER :
				 ESDM_DTLS_SESSIONS_CLIENT,
			&c->sessions);
	if (ret) {
		esdm_dtls_backend_ctx_free(c);
		return ret;
	}

	*ctx = c;
	return 0;
}

int esdm_dtls_backend_conn_new(void *ctx, bool server, struct esdm_dtls_io *io,
			       const uint8_t *session_key,
			       size_t session_keylen, void **conn)
{
	struct esdm_dtls_gnutls_ctx *c = ctx;
	struct esdm_dtls_gnutls_conn *d;
	/* With the replay detection of DTLS, see the file header */
	unsigned int flags = (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
			     GNUTLS_NONBLOCK | GNUTLS_DATAGRAM |
			     ESDM_DTLS_GNUTLS_MINIMAL_FLAGS;

	d = calloc(1, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->io = io;
	d->ctx = c;

	if (gnutls_init(&d->session, flags) < 0) {
		free(d);
		return -ENOMEM;
	}

	if (gnutls_priority_set(d->session, c->prio) < 0 ||
	    gnutls_credentials_set(d->session, GNUTLS_CRD_PSK,
				   server ? (void *)c->psk_server :
					    (void *)c->psk_client) < 0 ||
	    esdm_dtls_gnutls_sessions(d, server, session_key, session_keylen))
		goto err;

	gnutls_transport_set_ptr(d->session, d);
	gnutls_transport_set_push_function(d->session, esdm_dtls_gnutls_push);
	gnutls_transport_set_pull_function(d->session, esdm_dtls_gnutls_pull);
	/*
	 * No MTU to discover and no record to fragment, and no retransmission
	 * of DTLS
	 */
	gnutls_transport_set_pull_timeout_function(
		d->session, esdm_dtls_gnutls_pull_timeout);
	gnutls_dtls_set_mtu(d->session, ESDM_DTLS_LINK_MTU);
	gnutls_dtls_set_timeouts(d->session, ESDM_DTLS_GNUTLS_TIMEOUT_MS,
				 ESDM_DTLS_GNUTLS_TIMEOUT_MS);

	*conn = d;
	return 0;

err:
	gnutls_deinit(d->session);
	free(d);
	return -ENOMEM;
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
 * The minimal mode on a session the handshake completed, see
 * ESDM_DTLS_GNUTLS_MINIMAL - a resumed session keeps what its full handshake
 * had: the extended master secret (RFC 7627), which binds the master secret to
 * the handshake it came from, and Encrypt-then-MAC (RFC 7366) -
 * MAC-then-encrypt of CBC is what Lucky Thirteen reads records from, and DTLS
 * lets an attacker try again after every record it broke. Every peer of the
 * ESDM offers and agrees to both, whichever its TLS stack.
 *
 * @return NULL, or what is missing
 */
static const char *
esdm_dtls_gnutls_minimal_check(struct esdm_dtls_gnutls_conn *d)
{
	if (!gnutls_session_ext_master_secret_status(d->session))
		return "no extended master secret";
	if (!gnutls_session_etm_status(d->session))
		return "CBC without Encrypt-then-MAC";
	return NULL;
}

int esdm_dtls_backend_handshake(void *conn, short *want)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	int ret = gnutls_handshake(d->session), err;

	if (ret != GNUTLS_E_SUCCESS) {
		err = esdm_dtls_gnutls_error(d, ret, want);
		if (err != -EAGAIN)
			esdm_dtls_gnutls_alert(d, ret);
		return err;
	}

	if (esdm_dtls_gnutls_minimal_check(d)) {
		d->alert = GNUTLS_A_INSUFFICIENT_SECURITY;
		d->alert_set = true;
		esdm_dtls_gnutls_alert(d, GNUTLS_E_INSUFFICIENT_SECURITY);
		return -EPROTO;
	}
	esdm_dtls_gnutls_keep(d);
	return 0;
}

ssize_t esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len,
			       short *want)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	ssize_t ret = gnutls_record_send(d->session, buf, len);

	if (ret > 0)
		return ret;
	if (ret == 0)
		return -EIO;
	return esdm_dtls_gnutls_error(d, (int)ret, want);
}

/* What GnuTLS could not send it keeps until the send is repeated */
int esdm_dtls_backend_flush(void *conn, short *want)
{
	(void)conn;
	(void)want;
	return 0;
}

/* A record whole, or none - its packet wiped as it is released */
ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len,
			       short *want)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	gnutls_packet_t pkt = NULL;
	gnutls_datum_t data;
	ssize_t ret = gnutls_record_recv_packet(d->session, &pkt);

	if (ret <= 0) {
		/* A packet comes with data only */
		if (pkt)
			gnutls_packet_deinit(pkt);
		/* 0: the closing alert */
		if (ret == 0)
			return 0;
		return esdm_dtls_gnutls_error(d, (int)ret, want);
	}

	gnutls_packet_get(pkt, &data, NULL);
	if (data.size > len) {
		ret = -EMSGSIZE;
	} else {
		memcpy(buf, data.data, data.size);
		ret = (ssize_t)data.size;
	}
	memset_secure(data.data, 0, data.size);
	gnutls_packet_deinit(pkt);

	return ret;
}

bool esdm_dtls_backend_pending(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;

	return gnutls_record_check_pending(d->session) > 0;
}

/* The name of the suite, as the other TLS stacks tell it */
const char *esdm_dtls_backend_cipher(void *conn)
{
	struct esdm_dtls_gnutls_conn *d = conn;
	const char *name =
		gnutls_cipher_suite_get_name(gnutls_kx_get(d->session),
					     gnutls_cipher_get(d->session),
					     gnutls_mac_get(d->session));

	return name ? name : "unknown";
}
