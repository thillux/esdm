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
 * (D)TLS of esdm_tls_backend.h by GnuTLS, for crypto_backend=gnutls: TLS 1.3
 * on a stream socket, with the files, the verification and the revocation
 * policy of esdm_tls_gnutls_files() and esdm_tls_gnutls_verify(), and the
 * DTLS 1.2 with the pre-shared key of the local DTLS on SOCK_SEQPACKET.
 *
 * GnuTLS reaches the socket through push and pull functions of its own, one
 * send(2) with MSG_NOSIGNAL or recv(2) each on the non-blocking socket - a
 * message of the socket each on SOCK_SEQPACKET -, which makes every call
 * return GNUTLS_E_AGAIN rather than wait for the peer. The session of the
 * local DTLS is a datagram one with the replay detection of DTLS, and with
 * timeouts too long to ever retransmit: the connection is reliable.
 *
 * GnuTLS decrypts a record into a buffer of its own, which gnutls_record_recv()
 * frees without wiping it: the packet is taken from GnuTLS instead, handed out
 * in as many parts as the caller asks for, and wiped once it is used up.
 *
 * The peer is verified by a verify function of its own, which has GnuTLS
 * verify the chain, rebuilds the chain GnuTLS verified - GnuTLS does not hand
 * it out - and runs the revocation policy of esdm_tls.c on it. GnuTLS sends no
 * alert of its own for a failed handshake: the one the failure calls for is
 * sent here.
 *
 * TLS 1.3 takes the algorithms of BSI TR-02102-2 alone, the hybrid key
 * exchange of ML-KEM - which GnuTLS has only when built with leancrypto - ahead
 * of the conventional one: see esdm_tls_gnutls_stream_priority() and
 * "Algorithms" in esdm_tls.h.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <gnutls/abstract.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>

#include "esdm_logger.h"
#include "esdm_tls.h"
#include "esdm_tls_backend.h"
#include "helper.h"
#include "memset_secure.h"

/*
 * The secure minimal mode of esdm_tls_backend.h, the same on every transport -
 * a connection lives as long as it does, with the one full handshake it
 * started with. It is in three places, as GnuTLS takes it:
 *
 *  - The priorities, ESDM_TLS_GNUTLS_MINIMAL: no tickets of TLS 1.2 or
 *    TLS 1.3, and Encrypt-then-MAC required for a CBC suite. The extended
 *    master secret is not turned off (%NO_SESSION_HASH), and is required by
 *    esdm_tls_gnutls_minimal_check() - %FORCE_SESSION_HASH is no keyword of
 *    every GnuTLS the ESDM builds with.
 *  - The flags of a session, ESDM_TLS_GNUTLS_MINIMAL_FLAGS: no tickets
 *    either. Neither GNUTLS_ENABLE_EARLY_DATA nor GNUTLS_ENABLE_EARLY_START,
 *    so no early data (0-RTT) is taken, nor GNUTLS_POST_HANDSHAKE_AUTH, so
 *    there is no post-handshake authentication of TLS 1.3.
 *  - The session: no session cache - no database functions on a server, no
 *    session data on a client -, so nothing is resumed and a client offers
 *    no session and no pre-shared key of resumption. A server of DTLS 1.2
 *    sends a session ID nevertheless, which GnuTLS gives no way to leave out.
 *    A renegotiation either way ends the connection, see
 *    esdm_tls_gnutls_error(). GnuTLS has no compression any more, and sends no
 *    heartbeat unless told to.
 */
#define ESDM_TLS_GNUTLS_MINIMAL ":%NO_TICKETS:%FORCE_ETM"
#define ESDM_TLS_GNUTLS_MINIMAL_FLAGS GNUTLS_NO_TICKETS

/*
 * TLS 1.3 exactly, in the minimal mode, with the suites of esdm_tls.h - not
 * TLS_CHACHA20_POLY1305_SHA256 - and the security level of BSI TR-02102 for
 * the certificates of either side: RSA and finite field groups of 3072 bits
 * and more, elliptic curves of 256 bits and more. The groups and the signature
 * algorithms are set in esdm_tls_gnutls_stream_priority().
 */
#define ESDM_TLS_GNUTLS_PRIORITY                                               \
	"NORMAL:-VERS-ALL:+VERS-TLS1.3:-CHACHA20-POLY1305:%PROFILE_HIGH"       \
	ESDM_TLS_GNUTLS_MINIMAL

/* Room for the priority of TLS 1.3 with its groups and signatures */
#define ESDM_TLS_GNUTLS_PRIORITY_LEN 1024

/*
 * The local DTLS: DTLS 1.2 exactly, TLS_ECDHE_PSK_AES_256_CBC_SHA384 on P-521,
 * in the minimal mode. GnuTLS has no ECDHE-PSK suite with AES-GCM - RFC 8442's
 * - and its one with an AEAD cipher is ChaCha20-Poly1305, which neither NIST
 * SP 800-52r2 nor BSI TR-02102-2 allows. Encrypt-then-MAC is required - by
 * %FORCE_ETM, and checked by esdm_tls_gnutls_minimal_check(). Nothing is
 * signed - GnuTLS only wants a signature algorithm in the priorities, and the
 * hello carries it.
 */
#define ESDM_TLS_GNUTLS_PSK_PRIORITY                                           \
	"NONE:+VERS-DTLS1.2:+ECDHE-PSK:+AES-256-CBC:+SHA384:"                  \
	"+GROUP-SECP521R1:+SIGN-ECDSA-SHA512:+COMP-NULL" ESDM_TLS_GNUTLS_MINIMAL

/*
 * The retransmission and the total timeout of the DTLS handshake, in
 * milliseconds: long enough to never run out - the connection is reliable, and
 * the callers bound the handshake themselves
 */
#define ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS (600 * 1000)

/* The extensions of a CRL that is no complete one, see esdm_tls_crl_info */
#define ESDM_TLS_GNUTLS_OID_DELTA_CRL "2.5.29.27"
#define ESDM_TLS_GNUTLS_OID_IDP "2.5.29.28"

struct esdm_tls_gnutls_ctx {
	gnutls_priority_t prio;
	enum esdm_tls_transport transport;
#ifdef ESDM_DTLS
	/* The pre-shared key of the local DTLS */
	gnutls_psk_client_credentials_t psk_client;
	gnutls_psk_server_credentials_t psk_server;
#endif
#ifdef ESDM_TLS_AUTH
	gnutls_certificate_credentials_t cred;
	gnutls_x509_crl_t *crls;
	unsigned int crl_num;
	/* The trust anchors of cred, for esdm_tls_gnutls_chain() */
	gnutls_x509_crt_t *cas;
	unsigned int ca_num;
#endif
};

struct esdm_tls_gnutls_conn {
	gnutls_session_t session;
	struct esdm_tls_gnutls_ctx *ctx;
	int fd;
	/* SOCK_SEQPACKET: a record of the connection is a message of its own */
	bool dgram;

	/* The packet being handed out, and how much of it is */
	gnutls_packet_t pkt;
	size_t pkt_off;

	/* What the peer's certificate is verified for, see esdm_tls_gnutls_verify() */
	esdm_tls_backend_check check;
	void *check_arg;
	gnutls_typed_vdata_st vdata[2];
	unsigned int vdata_num;
	char server_name[256];

	/* The alert a failed handshake calls for, sent once */
	bool alert_set;
	bool alert_sent;
	gnutls_alert_description_t alert;

	char error[ESDM_TLS_TEXT_LEN];
};

/******************************************************************************
 * The transports
 ******************************************************************************/

static ssize_t esdm_tls_gnutls_push(gnutls_transport_ptr_t ptr, const void *buf,
				    size_t len)
{
	struct esdm_tls_gnutls_conn *c = ptr;
	ssize_t n = send(c->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);

	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

static ssize_t esdm_tls_gnutls_pull(gnutls_transport_ptr_t ptr, void *buf,
				    size_t len)
{
	struct esdm_tls_gnutls_conn *c = ptr;
	ssize_t n = recv(c->fd, buf, len, MSG_DONTWAIT);

	/*
	 * 0 is the end of the stream, which GnuTLS tells apart itself - but to
	 * a datagram session an empty datagram to be waited past: the peer
	 * gone is an error there
	 */
	if (n == 0 && c->dgram) {
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
static int esdm_tls_gnutls_pull_timeout(gnutls_transport_ptr_t ptr,
					unsigned int ms)
{
	(void)ptr;
	(void)ms;
	return 1;
}

/******************************************************************************
 * The errors
 ******************************************************************************/

/* An alert that is about a certificate: refused, or not presented */
static bool esdm_tls_gnutls_cert_alert(gnutls_alert_description_t alert)
{
	return alert == GNUTLS_A_BAD_CERTIFICATE ||
	       alert == GNUTLS_A_UNSUPPORTED_CERTIFICATE ||
	       alert == GNUTLS_A_CERTIFICATE_REVOKED ||
	       alert == GNUTLS_A_CERTIFICATE_EXPIRED ||
	       alert == GNUTLS_A_CERTIFICATE_UNKNOWN ||
	       alert == GNUTLS_A_UNKNOWN_CA || alert == GNUTLS_A_ACCESS_DENIED ||
	       alert == GNUTLS_A_CERTIFICATE_REQUIRED;
}

/*
 * The result @ret of a GnuTLS operation of @c that did not complete: -EAGAIN
 * if it waits for the socket, with *want telling for what, or if it is to be
 * called again right away (*want is POLLOUT then, which a connected socket
 * signals at once), -ECONNRESET if the peer is gone, -EACCES for a certificate
 * that was refused, -EPROTO for anything else.
 */
static int esdm_tls_gnutls_error(struct esdm_tls_gnutls_conn *c, int ret,
				 short *want)
{
	gnutls_alert_description_t alert;
	unsigned int status;
	gnutls_datum_t out;

	switch (ret) {
	case GNUTLS_E_AGAIN:
	case GNUTLS_E_INTERRUPTED:
		*want = gnutls_record_get_direction(c->session) ? POLLOUT :
								  POLLIN;
		return -EAGAIN;
	case GNUTLS_E_PREMATURE_TERMINATION:
	case GNUTLS_E_PULL_ERROR:
	case GNUTLS_E_PUSH_ERROR:
		snprintf(c->error, sizeof(c->error),
			 "connection closed by the peer");
		return -ECONNRESET;
	case GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR:
	case GNUTLS_E_CERTIFICATE_ERROR:
		/* Told by esdm_tls_gnutls_verify() already */
		if (c->error[0])
			return -EACCES;
		status = gnutls_session_get_verify_cert_status(c->session);
		if (gnutls_certificate_verification_status_print(
			    status, GNUTLS_CRT_X509, &out, 0) >= 0) {
			snprintf(c->error, sizeof(c->error),
				 "certificate verify failed: %s",
				 (const char *)out.data);
			gnutls_free(out.data);
		} else {
			snprintf(c->error, sizeof(c->error),
				 "certificate verify failed");
		}
		return -EACCES;
	case GNUTLS_E_NO_CERTIFICATE_FOUND:
	case GNUTLS_E_CERTIFICATE_REQUIRED:
		snprintf(c->error, sizeof(c->error), "%s",
			 gnutls_strerror(ret));
		return -EACCES;
	case GNUTLS_E_FATAL_ALERT_RECEIVED:
		alert = gnutls_alert_get(c->session);
		snprintf(c->error, sizeof(c->error), "alert received: %s",
			 gnutls_alert_get_name(alert));
		return esdm_tls_gnutls_cert_alert(alert) ? -EACCES : -EPROTO;
	case GNUTLS_E_REHANDSHAKE:
	case GNUTLS_E_REAUTH_REQUEST:
		/*
		 * A peer asking for a new handshake - a renegotiation of
		 * DTLS 1.2, or a post-handshake authentication of TLS 1.3 -,
		 * which none of the ESDM does: see ESDM_TLS_GNUTLS_MINIMAL
		 */
		snprintf(c->error, sizeof(c->error), "renegotiation refused");
		return -EPROTO;
	default:
		if (!gnutls_error_is_fatal(ret)) {
			/* A warning alert, a datagram dropped: try again */
			*want = POLLOUT;
			return -EAGAIN;
		}
		snprintf(c->error, sizeof(c->error), "%s",
			 gnutls_strerror(ret));
		return -EPROTO;
	}
}

/*
 * Tell the peer why the handshake failed with @ret, best effort: once, and
 * not for a failure the peer caused by going away or by an alert of its own.
 */
static void esdm_tls_gnutls_alert(struct esdm_tls_gnutls_conn *d, int ret)
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
 * The contexts of the transports
 ******************************************************************************/

#ifdef ESDM_DTLS
/*
 * The pre-shared key of a server, see esdm_tls_backend.h: it knows no other
 * identity, and refuses a client with another one.
 */
static int esdm_tls_gnutls_psk_server(gnutls_session_t session,
				      const char *username, gnutls_datum_t *key)
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

/* The local DTLS: the pre-shared key of either side */
static int esdm_tls_gnutls_psk(struct esdm_tls_gnutls_ctx *c, bool server)
{
	/* Copied into the credentials */
	const gnutls_datum_t key = { .data = (unsigned char *)esdm_dtls_psk,
				     .size = sizeof(esdm_dtls_psk) };

	if (server) {
		if (gnutls_psk_allocate_server_credentials(&c->psk_server) < 0)
			return -ENOMEM;
		gnutls_psk_set_server_credentials_function(
			c->psk_server, esdm_tls_gnutls_psk_server);
	} else {
		if (gnutls_psk_allocate_client_credentials(&c->psk_client) <
			    0 ||
		    gnutls_psk_set_client_credentials(
			    c->psk_client, ESDM_DTLS_PSK_IDENTITY, &key,
			    GNUTLS_PSK_KEY_RAW) < 0)
			return -ENOMEM;
	}

	return gnutls_priority_init(&c->prio, ESDM_TLS_GNUTLS_PSK_PRIORITY,
				    NULL) < 0 ?
		       -ENOMEM :
		       0;
}
#else
static int esdm_tls_gnutls_psk(struct esdm_tls_gnutls_ctx *c, bool server)
{
	(void)c;
	(void)server;
	return -EOPNOTSUPP;
}
#endif /* ESDM_DTLS */

#ifdef ESDM_TLS_AUTH

/*
 * The groups of esdm_tls.h in its order, as GnuTLS names them: the hybrid of
 * ML-KEM - not X25519-MLKEM768 and SECP256R1-MLKEM768, of 128 bits, nor
 * ML-KEM alone -, then the conventional ones GnuTLS has for TLS 1.3, which
 * are no curves of Brainpool
 */
#define ESDM_TLS_GNUTLS_HYBRID "SECP384R1-MLKEM1024"
static const char *const esdm_tls_gnutls_groups[] = {
	ESDM_TLS_GNUTLS_HYBRID,
	"SECP384R1",
	"SECP256R1",
	"SECP521R1",
	"FFDHE3072",
	"FFDHE4096",
};

/*
 * The signature algorithms of NORMAL taken out, see esdm_tls.h: those with
 * SHA-1 and SHA-224, which NORMAL lists for the signatures of certificates,
 * EdDSA, and ML-DSA - a post-quantum signature on its own -, which NORMAL
 * lists where GnuTLS is built with leancrypto
 */
static const char *const esdm_tls_gnutls_signs_out[] = {
	"RSA-SHA1",	"ECDSA-SHA1", "DSA-SHA1",   "RSA-SHA224",
	"ECDSA-SHA224", "DSA-SHA224", "DSA-SHA256", "EdDSA-Ed25519",
	"EdDSA-Ed448",	"ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
};

/* Append ":<what><name>" to the priority @prio of @len bytes so far */
static int esdm_tls_gnutls_prio_add(char *prio, size_t *len, const char *what,
				    const char *name)
{
	int n = snprintf(prio + *len, ESDM_TLS_GNUTLS_PRIORITY_LEN - *len,
			 ":%s%s", what, name);

	if (n < 0 || (size_t)n >= ESDM_TLS_GNUTLS_PRIORITY_LEN - *len)
		return -ENOSPC;
	*len += (size_t)n;
	return 0;
}

/*
 * The priority of TLS 1.3, ESDM_TLS_GNUTLS_PRIORITY with the groups of
 * esdm_tls.h alone - "+" appends, so the groups are listed anew - and without
 * the signature algorithms of esdm_tls_gnutls_signs_out. GnuTLS refuses a
 * priority naming a group or an algorithm it does not know: the string names
 * only what GnuTLS reports.
 */
static int esdm_tls_gnutls_stream_priority(gnutls_priority_t *prio)
{
	char str[ESDM_TLS_GNUTLS_PRIORITY_LEN];
	size_t len, i;
	int ret = 0;

	len = (size_t)snprintf(str, sizeof(str), "%s:-GROUP-ALL",
			       ESDM_TLS_GNUTLS_PRIORITY);
	for (i = 0; i < ARRAY_SIZE(esdm_tls_gnutls_groups) && !ret; i++) {
		if (gnutls_group_get_id(esdm_tls_gnutls_groups[i]) !=
		    GNUTLS_GROUP_INVALID)
			ret = esdm_tls_gnutls_prio_add(
				str, &len, "+GROUP-",
				esdm_tls_gnutls_groups[i]);
	}
	for (i = 0; i < ARRAY_SIZE(esdm_tls_gnutls_signs_out) && !ret; i++) {
		if (gnutls_sign_get_id(esdm_tls_gnutls_signs_out[i]) !=
		    GNUTLS_SIGN_UNKNOWN)
			ret = esdm_tls_gnutls_prio_add(
				str, &len, "-SIGN-",
				esdm_tls_gnutls_signs_out[i]);
	}
	if (ret)
		return ret;

	ret = gnutls_priority_init(prio, str, NULL);
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: GnuTLS refused the priority %s: %s\n", str,
			    gnutls_strerror(ret));
		return -EINVAL;
	}
	return 0;
}

/* The TLS with certificates: their credentials, and the priority */
static int esdm_tls_gnutls_certs(struct esdm_tls_gnutls_ctx *c)
{
	if (gnutls_certificate_allocate_credentials(&c->cred) < 0) {
		c->cred = NULL;
		return -ENOMEM;
	}
	return esdm_tls_gnutls_stream_priority(&c->prio);
}
#else
static int esdm_tls_gnutls_certs(struct esdm_tls_gnutls_ctx *c)
{
	(void)c;
	return -EOPNOTSUPP;
}
#endif /* ESDM_TLS_AUTH */

/******************************************************************************
 * esdm_tls_backend.h: the core
 ******************************************************************************/

const char *esdm_tls_backend_name(void)
{
	return "GnuTLS";
}

void esdm_tls_backend_ctx_free(void *ctx)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
#ifdef ESDM_TLS_AUTH
	unsigned int i;
#endif

	if (!c)
		return;
	if (c->prio)
		gnutls_priority_deinit(c->prio);
#ifdef ESDM_DTLS
	if (c->psk_server)
		gnutls_psk_free_server_credentials(c->psk_server);
	if (c->psk_client)
		gnutls_psk_free_client_credentials(c->psk_client);
#endif
#ifdef ESDM_TLS_AUTH
	if (c->cred)
		gnutls_certificate_free_credentials(c->cred);
	for (i = 0; i < c->crl_num; i++)
		gnutls_x509_crl_deinit(c->crls[i]);
	free(c->crls);
	for (i = 0; i < c->ca_num; i++)
		gnutls_x509_crt_deinit(c->cas[i]);
	free(c->cas);
#endif
	free(c);
}

int esdm_tls_backend_ctx_new(bool server, enum esdm_tls_transport transport,
			     void **ctx)
{
	struct esdm_tls_gnutls_ctx *c = calloc(1, sizeof(*c));
	int ret;

	if (!c)
		return -ENOMEM;
	c->transport = transport;

	ret = transport == ESDM_TLS_TRANSPORT_SEQPACKET ?
		      esdm_tls_gnutls_psk(c, server) :
		      esdm_tls_gnutls_certs(c);
	if (ret) {
		esdm_tls_backend_ctx_free(c);
		return ret;
	}

	*ctx = c;
	return 0;
}

int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
	struct esdm_tls_gnutls_conn *d;
	unsigned char addr[sizeof(struct in6_addr)];
	bool psk = c->transport == ESDM_TLS_TRANSPORT_SEQPACKET;
	unsigned int flags = (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
			     GNUTLS_NONBLOCK | ESDM_TLS_GNUTLS_MINIMAL_FLAGS;
	void *cred = NULL;

	d = calloc(1, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->fd = fd;
	d->ctx = c;
	d->check = check;
	d->check_arg = arg;
	d->dgram = psk;

	/* With the replay detection of DTLS, see the file header */
	if (d->dgram)
		flags |= GNUTLS_DATAGRAM;

	if (gnutls_init(&d->session, flags) < 0) {
		free(d);
		return -ENOMEM;
	}

#ifdef ESDM_DTLS
	if (psk)
		cred = server ? (void *)c->psk_server : (void *)c->psk_client;
#endif
#ifdef ESDM_TLS_AUTH
	if (!psk)
		cred = c->cred;
#endif
	if (gnutls_priority_set(d->session, c->prio) < 0 ||
	    gnutls_credentials_set(
		    d->session, psk ? GNUTLS_CRD_PSK : GNUTLS_CRD_CERTIFICATE,
		    cred) < 0)
		goto err;

	if (psk) {
		/* The local DTLS, which has no certificate */
	} else if (server) {
		/* Mutual authentication: no certificate, no connection */
		gnutls_certificate_server_set_request(d->session,
						      GNUTLS_CERT_REQUIRE);
		d->vdata[d->vdata_num].type = GNUTLS_DT_KEY_PURPOSE_OID;
		d->vdata[d->vdata_num++].data =
			(unsigned char *)GNUTLS_KP_TLS_WWW_CLIENT;
	} else {
		/*
		 * The name the certificate of the server has to be issued for:
		 * an address literal is checked against the IP addresses of
		 * its subject alternative name, and is no server name to
		 * indicate - only a DNS name is.
		 */
		if (!server_name ||
		    strlen(server_name) >= sizeof(d->server_name))
			goto err;
		strcpy(d->server_name, server_name);
		d->vdata[d->vdata_num].type = GNUTLS_DT_DNS_HOSTNAME;
		d->vdata[d->vdata_num++].data = (unsigned char *)d->server_name;
		d->vdata[d->vdata_num].type = GNUTLS_DT_KEY_PURPOSE_OID;
		d->vdata[d->vdata_num++].data =
			(unsigned char *)GNUTLS_KP_TLS_WWW_SERVER;
		if (inet_pton(AF_INET, server_name, addr) != 1 &&
		    inet_pton(AF_INET6, server_name, addr) != 1 &&
		    gnutls_server_name_set(d->session, GNUTLS_NAME_DNS,
					   server_name,
					   strlen(server_name)) < 0)
			goto err;
	}

	/* For the verify function of the credentials */
	gnutls_session_set_ptr(d->session, d);

	gnutls_transport_set_ptr(d->session, d);
	gnutls_transport_set_push_function(d->session, esdm_tls_gnutls_push);
	gnutls_transport_set_pull_function(d->session, esdm_tls_gnutls_pull);
	if (d->dgram) {
		/*
		 * No MTU to discover and no record to fragment, and no
		 * retransmission of DTLS
		 */
		gnutls_transport_set_pull_timeout_function(
			d->session, esdm_tls_gnutls_pull_timeout);
		gnutls_dtls_set_mtu(d->session, ESDM_DTLS_LINK_MTU);
		gnutls_dtls_set_timeouts(d->session,
					 ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS,
					 ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS);
	}

	*conn = d;
	return 0;

err:
	gnutls_deinit(d->session);
	free(d);
	return -ENOMEM;
}

static void esdm_tls_gnutls_drop_pkt(struct esdm_tls_gnutls_conn *d)
{
	gnutls_datum_t data;

	if (!d->pkt)
		return;

	gnutls_packet_get(d->pkt, &data, NULL);
	memset_secure(data.data, 0, data.size);
	gnutls_packet_deinit(d->pkt);
	d->pkt = NULL;
	d->pkt_off = 0;
}

void esdm_tls_backend_conn_free(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;

	if (!d)
		return;
	esdm_tls_gnutls_drop_pkt(d);
	gnutls_deinit(d->session);
	free(d);
}

/*
 * The minimal mode on a session the handshake completed, see
 * ESDM_TLS_GNUTLS_MINIMAL: nothing resumed, and DTLS 1.2 with the extended
 * master secret (RFC 7627), which binds the master secret to the handshake it
 * came from, and with Encrypt-then-MAC (RFC 7366) - MAC-then-encrypt of CBC is
 * what Lucky Thirteen reads records from, and DTLS lets an attacker try again
 * after every record it broke. Every peer of the ESDM offers and agrees to
 * both, whichever its TLS stack; TLS 1.3 has them built in, or needs none.
 *
 * @return NULL, or what is missing
 */
static const char *esdm_tls_gnutls_minimal_check(struct esdm_tls_gnutls_conn *d)
{
	if (gnutls_session_is_resumed(d->session))
		return "a resumed session";
	if (!d->dgram)
		return NULL;
	if (!gnutls_session_ext_master_secret_status(d->session))
		return "no extended master secret";
	if (!gnutls_session_etm_status(d->session))
		return "CBC without Encrypt-then-MAC";
	return NULL;
}

int esdm_tls_backend_handshake(void *conn, short *want)
{
	struct esdm_tls_gnutls_conn *d = conn;
	int ret = gnutls_handshake(d->session), err;
	const char *missing;

	if (ret != GNUTLS_E_SUCCESS) {
		err = esdm_tls_gnutls_error(d, ret, want);
		if (err != -EAGAIN)
			esdm_tls_gnutls_alert(d, ret);
		return err;
	}

	missing = esdm_tls_gnutls_minimal_check(d);
	if (missing) {
		snprintf(d->error, sizeof(d->error), "%s", missing);
		d->alert = GNUTLS_A_INSUFFICIENT_SECURITY;
		d->alert_set = true;
		esdm_tls_gnutls_alert(d, GNUTLS_E_INSUFFICIENT_SECURITY);
		return -EPROTO;
	}
	return 0;
}

ssize_t esdm_tls_backend_send(void *conn, const uint8_t *buf, size_t len,
			      short *want)
{
	struct esdm_tls_gnutls_conn *d = conn;
	ssize_t ret = gnutls_record_send(d->session, buf, len);

	if (ret > 0)
		return ret;
	if (ret == 0)
		return -EIO;
	return esdm_tls_gnutls_error(d, (int)ret, want);
}

/* What GnuTLS could not send it keeps until the send is repeated */
int esdm_tls_backend_flush(void *conn, short *want)
{
	(void)conn;
	(void)want;
	return 0;
}

ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len, short *want)
{
	struct esdm_tls_gnutls_conn *d = conn;
	gnutls_datum_t data;
	size_t n;

	if (!d->pkt) {
		ssize_t ret = gnutls_record_recv_packet(d->session, &d->pkt);

		if (ret <= 0) {
			/* A packet comes with data only */
			if (d->pkt)
				esdm_tls_gnutls_drop_pkt(d);
			/* 0: the closing alert */
			if (ret == 0)
				return 0;
			return esdm_tls_gnutls_error(d, (int)ret, want);
		}
		d->pkt_off = 0;
	}

	gnutls_packet_get(d->pkt, &data, NULL);

	/* A record of SOCK_SEQPACKET whole, or none */
	if (d->dgram && data.size > len) {
		esdm_tls_gnutls_drop_pkt(d);
		snprintf(d->error, sizeof(d->error),
			 "a record larger than %zu bytes", len);
		return -EMSGSIZE;
	}
	n = data.size - d->pkt_off;
	if (n > len)
		n = len;
	memcpy(buf, data.data + d->pkt_off, n);
	d->pkt_off += n;

	if (d->pkt_off >= data.size)
		esdm_tls_gnutls_drop_pkt(d);

	return (ssize_t)n;
}

bool esdm_tls_backend_pending(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;

	return d->pkt || gnutls_record_check_pending(d->session) > 0;
}

void esdm_tls_backend_close_notify(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;

	gnutls_bye(d->session, GNUTLS_SHUT_WR);
}

/*
 * The name of the suite of DTLS 1.2, as the other TLS stacks tell it; TLS 1.3
 * names the cipher alone
 */
const char *esdm_tls_backend_cipher(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;
	gnutls_cipher_algorithm_t cipher = gnutls_cipher_get(d->session);
	const char *name = d->dgram ? gnutls_cipher_suite_get_name(
					      gnutls_kx_get(d->session), cipher,
					      gnutls_mac_get(d->session)) :
				      gnutls_cipher_get_name(cipher);

	return name ? name : "unknown";
}

const char *esdm_tls_backend_group(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;
	gnutls_group_t group = gnutls_group_get(d->session);

	return group == GNUTLS_GROUP_INVALID ? NULL :
					       gnutls_group_get_name(group);
}

const char *esdm_tls_backend_error(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;

	return d->error;
}

#ifdef ESDM_TLS_AUTH

/******************************************************************************
 * The certificates
 ******************************************************************************/

static void esdm_tls_gnutls_datum_str(const gnutls_datum_t *d, char *buf,
				      size_t len)
{
	snprintf(buf, len, "%.*s", (int)d->size, (const char *)d->data);
}

static int esdm_tls_gnutls_import(const struct esdm_tls_der *der,
				  gnutls_x509_crt_t *crt)
{
	gnutls_datum_t d = { .data = der->data, .size = (unsigned int)der->len };

	if (der->len > UINT32_MAX || gnutls_x509_crt_init(crt) < 0)
		return -ENOMEM;
	if (gnutls_x509_crt_import(*crt, &d, GNUTLS_X509_FMT_DER) < 0) {
		gnutls_x509_crt_deinit(*crt);
		*crt = NULL;
		return -EINVAL;
	}

	return 0;
}

static int esdm_tls_gnutls_export(gnutls_x509_crt_t crt,
				  struct esdm_tls_der *der)
{
	gnutls_datum_t d;

	if (gnutls_x509_crt_export2(crt, GNUTLS_X509_FMT_DER, &d) < 0)
		return -EINVAL;

	der->data = malloc(d.size);
	if (!der->data) {
		gnutls_free(d.data);
		return -ENOMEM;
	}
	memcpy(der->data, d.data, d.size);
	der->len = d.size;
	gnutls_free(d.data);

	return 0;
}

/*
 * Is the status of the verification of a CRL nothing but the times, if
 * anything?
 */
static bool esdm_tls_gnutls_crl_signed(unsigned int verify)
{
	const unsigned int times = GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED |
				   GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE;

	if (verify & ~(times | (unsigned int)GNUTLS_CERT_INVALID))
		return false;

	/* Invalid for a reason other than the times */
	return !(verify & GNUTLS_CERT_INVALID) || (verify & times);
}

/* Does @crl have the extension @oid? */
static bool esdm_tls_gnutls_crl_has_ext(gnutls_x509_crl_t crl, const char *oid)
{
	unsigned int i, critical;
	char buf[128];
	size_t len;
	int ret;

	for (i = 0;; i++) {
		len = sizeof(buf);
		ret = gnutls_x509_crl_get_extension_info(crl, i, buf, &len,
							 &critical);
		/* An OID that long is none of the ones looked for */
		if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER)
			continue;
		if (ret < 0)
			return false;
		if (!strcmp(buf, oid))
			return true;
	}
}

/* The trust anchors of the credentials, as GnuTLS holds them */
static int esdm_tls_gnutls_load_cas(struct esdm_tls_gnutls_ctx *c)
{
	gnutls_x509_trust_list_iter_t iter = NULL;
	gnutls_x509_trust_list_t tl;
	gnutls_x509_crt_t crt, *all;
	int ret;

	gnutls_certificate_get_trust_list(c->cred, &tl);
	while ((ret = gnutls_x509_trust_list_iter_get_ca(tl, &iter, &crt)) >=
	       0) {
		all = realloc(c->cas, (c->ca_num + 1) * sizeof(*all));
		if (!all) {
			gnutls_x509_crt_deinit(crt);
			gnutls_x509_trust_list_iter_deinit(iter);
			return -ENOMEM;
		}
		c->cas = all;
		c->cas[c->ca_num++] = crt;
	}
	gnutls_x509_trust_list_iter_deinit(iter);

	return ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE ? 0 : -ENOMEM;
}

/* Load the CRLs of @path, every one it holds. */
static int esdm_tls_gnutls_load_crls(struct esdm_tls_gnutls_ctx *c,
				     const char *path)
{
	gnutls_x509_crl_t *list = NULL, *all;
	gnutls_datum_t data;
	unsigned int num = 0, i;
	int ret;

	ret = gnutls_load_file(path, &data);
	if (ret < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot read the CRL file %s: %s\n", path,
			    gnutls_strerror(ret));
		return -EINVAL;
	}

	ret = gnutls_x509_crl_list_import2(&list, &num, &data,
					   GNUTLS_X509_FMT_PEM, 0);
	gnutls_free(data.data);
	if (ret < 0 || !num) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: the CRL file %s does not parse: %s\n", path,
			    ret < 0 ? gnutls_strerror(ret) : "no CRL in it");
		for (i = 0; i < num; i++)
			gnutls_x509_crl_deinit(list[i]);
		gnutls_free(list);
		return -EINVAL;
	}

	all = realloc(c->crls, (c->crl_num + num) * sizeof(*all));
	if (!all) {
		for (i = 0; i < num; i++)
			gnutls_x509_crl_deinit(list[i]);
		gnutls_free(list);
		return -ENOMEM;
	}
	memcpy(all + c->crl_num, list, num * sizeof(*list));
	c->crls = all;
	c->crl_num += num;
	gnutls_free(list);

	return 0;
}

static int esdm_tls_gnutls_walk(struct esdm_tls_gnutls_ctx *ctx,
				gnutls_x509_crt_t *given, unsigned int given_num,
				gnutls_x509_crt_t *certs, unsigned int *num);

/*
 * Does the own certificate chain to the trust anchors - to a self-issued one,
 * see esdm_tls_gnutls_walk()?
 */
static int esdm_tls_gnutls_check_own(struct esdm_tls_gnutls_ctx *c,
				     const char *cert_file,
				     const char *ca_file)
{
	gnutls_x509_crt_t chain[ESDM_TLS_MAX_CHAIN];
	gnutls_x509_trust_list_t tl;
	gnutls_x509_crt_t *crts = NULL;
	unsigned int num = 0, verify = 0, n = 0, i;
	gnutls_datum_t out;
	int ret;

	ret = gnutls_certificate_get_x509_crt(c->cred, 0, &crts, &num);
	if (ret < 0 || !num)
		return -EINVAL;

	/* The chain, not the time - see "Contexts" in esdm_tls.h */
	gnutls_certificate_get_trust_list(c->cred, &tl);
	ret = gnutls_x509_trust_list_verify_crt2(
		tl, crts, num, NULL, 0,
		GNUTLS_VERIFY_DISABLE_TIME_CHECKS |
			GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS,
		&verify, NULL);
	if (ret < 0 || verify) {
		if (ret >= 0 && gnutls_certificate_verification_status_print(
					verify, GNUTLS_CRT_X509, &out, 0) >= 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the certificate %s does not chain to the trust anchors %s: %s\n",
				cert_file, ca_file, (const char *)out.data);
			gnutls_free(out.data);
		} else {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the certificate %s does not chain to the trust anchors %s\n",
				cert_file, ca_file);
		}
		ret = -EINVAL;
	} else if (esdm_tls_gnutls_walk(c, crts, num, chain, &n)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"TLS: the certificate %s does not chain to a self-issued trust anchor of %s - a CA certificate that is not self-issued needs the one that issued it there as well\n",
			cert_file, ca_file);
		ret = -EINVAL;
	} else {
		ret = 0;
	}

	for (i = 0; i < num; i++)
		gnutls_x509_crt_deinit(crts[i]);
	gnutls_free(crts);

	return ret;
}

/*
 * Did @issuer, as a CA, sign @cert? Everything GnuTLS verifies of a certificate
 * against its issuer, but the times - the chain this is for was verified
 * with them already.
 */
static bool esdm_tls_gnutls_signed_by(gnutls_x509_crt_t cert,
				      gnutls_x509_crt_t issuer)
{
	unsigned int verify = 0;

	if (gnutls_x509_crt_check_issuer(cert, issuer) != 1)
		return false;

	return gnutls_x509_crt_verify(
		       cert, &issuer, 1,
		       GNUTLS_VERIFY_DISABLE_TIME_CHECKS |
			       GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS |
			       GNUTLS_VERIFY_DO_NOT_ALLOW_SAME,
		       &verify) >= 0 &&
	       !verify;
}

static bool esdm_tls_gnutls_in_chain(gnutls_x509_crt_t *certs, unsigned int n,
				     gnutls_x509_crt_t crt)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (gnutls_x509_crt_equals(certs[i], crt))
			return true;
	}
	return false;
}

/*
 * The chain of @given[0] - the certificates of the peer, or the own ones - as
 * GnuTLS builds it, into @certs of ESDM_TLS_MAX_CHAIN, with the signature of
 * each issuer checked: the issuer of a certificate is looked for among the
 * own trust anchors first, among the others of @given only if none of them
 * signed it. Once at a trust anchor, the chain goes on through the trust
 * anchors only, up to a self-issued one - an intermediate CA among the trust
 * anchors is checked against the CRL of its own issuer just as with the other
 * TLS stacks. A certificate of @given is never taken for a trust anchor,
 * whatever its name: a chain that does not end in one of the own ones is
 * refused.
 *
 * Nor is one that ends in a trust anchor that is not self-issued, which GnuTLS
 * alone takes for an anchor: OpenSSL and Botan take a CA certificate of the
 * trust anchors that is not self-issued for an intermediate one, which has to
 * chain on to a self-issued one. So a file of trust anchors holding an
 * intermediate CA without its issuer serves no chain through it, on every TLS
 * stack, rather than one whose intermediate CA no CRL covers on one of them.
 *
 * @return 0, -EINVAL if the chain does not end in a self-issued trust anchor
 */
static int esdm_tls_gnutls_walk(struct esdm_tls_gnutls_ctx *ctx,
				gnutls_x509_crt_t *given, unsigned int given_num,
				gnutls_x509_crt_t *certs, unsigned int *num)
{
	unsigned int n = 0, i;
	bool anchored = false;

	certs[n++] = given[0];
	while (n < ESDM_TLS_MAX_CHAIN) {
		gnutls_x509_crt_t cur = certs[n - 1], iss = NULL;

		for (i = 0; i < ctx->ca_num && !iss; i++) {
			if (!esdm_tls_gnutls_in_chain(certs, n, ctx->cas[i]) &&
			    esdm_tls_gnutls_signed_by(cur, ctx->cas[i]))
				iss = ctx->cas[i];
		}
		if (iss) {
			certs[n++] = iss;
			anchored = true;
			if (gnutls_x509_crt_check_issuer(iss, iss) == 1) {
				*num = n;
				return 0;
			}
			continue;
		}
		if (anchored)
			break;

		for (i = 1; i < given_num && !iss; i++) {
			if (!esdm_tls_gnutls_in_chain(certs, n, given[i]) &&
			    esdm_tls_gnutls_signed_by(cur, given[i]))
				iss = given[i];
		}
		if (!iss)
			break;
		certs[n++] = iss;
	}

	/*
	 * Not anchored, which GnuTLS still verified: the certificate is a
	 * trust anchor itself - a self-issued one, see above -, or the chain
	 * is not the one GnuTLS verified, which is refused.
	 */
	if (!anchored && gnutls_x509_crt_check_issuer(given[0], given[0]) == 1) {
		for (i = 0; i < ctx->ca_num; i++) {
			if (gnutls_x509_crt_equals(given[0], ctx->cas[i])) {
				*num = 1;
				return 0;
			}
		}
	}

	return -EINVAL;
}

/*
 * The chain GnuTLS verified, for the revocation policy - which GnuTLS does not
 * hand out. Rebuilt as GnuTLS builds it, see esdm_tls_gnutls_walk().
 *
 * @return 0, -EINVAL if the chain does not end in a self-issued trust anchor,
 *	   -ENOMEM
 */
static int esdm_tls_gnutls_chain(struct esdm_tls_gnutls_conn *d,
				 struct esdm_tls_der **chain, size_t *num)
{
	struct esdm_tls_gnutls_ctx *ctx = d->ctx;
	gnutls_x509_crt_t peers[ESDM_TLS_MAX_CHAIN];
	gnutls_x509_crt_t certs[ESDM_TLS_MAX_CHAIN];
	const gnutls_datum_t *raw;
	struct esdm_tls_der *ders = NULL;
	unsigned int raw_num = 0, peer_num = 0, n = 0, i;
	int ret = 0;

	*chain = NULL;
	*num = 0;

	raw = gnutls_certificate_get_peers(d->session, &raw_num);
	if (!raw || !raw_num)
		return -EINVAL;
	if (raw_num > ESDM_TLS_MAX_CHAIN)
		raw_num = ESDM_TLS_MAX_CHAIN;

	for (i = 0; i < raw_num; i++) {
		struct esdm_tls_der der = { .data = raw[i].data,
					    .len = raw[i].size };

		ret = esdm_tls_gnutls_import(&der, &peers[peer_num]);
		if (ret)
			goto out;
		peer_num++;
	}

	ret = esdm_tls_gnutls_walk(ctx, peers, peer_num, certs, &n);
	if (ret)
		goto out;

	ders = calloc(n, sizeof(*ders));
	if (!ders) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < n; i++) {
		ret = esdm_tls_gnutls_export(certs[i], &ders[i]);
		if (ret) {
			while (i-- > 0)
				free(ders[i].data);
			free(ders);
			goto out;
		}
	}

	*chain = ders;
	*num = n;

out:
	for (i = 0; i < peer_num; i++)
		gnutls_x509_crt_deinit(peers[i]);
	return ret;
}

/* The alert for the verification status @status, as OpenSSL would send it */
static gnutls_alert_description_t esdm_tls_gnutls_status_alert(
	unsigned int status)
{
	if (status & GNUTLS_CERT_REVOKED)
		return GNUTLS_A_CERTIFICATE_REVOKED;
	if (status & GNUTLS_CERT_EXPIRED)
		return GNUTLS_A_CERTIFICATE_EXPIRED;
	if (status & (GNUTLS_CERT_SIGNER_NOT_FOUND | GNUTLS_CERT_SIGNER_NOT_CA))
		return GNUTLS_A_UNKNOWN_CA;
	if (status & GNUTLS_CERT_PURPOSE_MISMATCH)
		return GNUTLS_A_UNSUPPORTED_CERTIFICATE;
	return GNUTLS_A_BAD_CERTIFICATE;
}

static int esdm_tls_gnutls_refuse(struct esdm_tls_gnutls_conn *d,
				  gnutls_alert_description_t alert, int ret)
{
	d->alert = alert;
	d->alert_set = true;
	return ret;
}

/*
 * The verify function of the credentials: the chain and the names and the key
 * usage it was asked for, by GnuTLS, then the revocation policy.
 */
static int esdm_tls_gnutls_verify(gnutls_session_t session)
{
	struct esdm_tls_gnutls_conn *d = gnutls_session_get_ptr(session);
	struct esdm_tls_der *chain = NULL;
	unsigned int status = 0;
	gnutls_datum_t out;
	size_t num = 0;
	int ret;

	/* No connection with a policy: fail closed */
	if (!d || !d->check)
		return GNUTLS_E_CERTIFICATE_ERROR;

	ret = gnutls_certificate_verify_peers(session, d->vdata, d->vdata_num,
					      &status);
	if (ret < 0) {
		snprintf(d->error, sizeof(d->error),
			 "certificate verify failed: %s", gnutls_strerror(ret));
		return esdm_tls_gnutls_refuse(d, GNUTLS_A_BAD_CERTIFICATE,
					      GNUTLS_E_CERTIFICATE_ERROR);
	}
	if (status) {
		if (gnutls_certificate_verification_status_print(
			    status, GNUTLS_CRT_X509, &out, 0) >= 0) {
			snprintf(d->error, sizeof(d->error),
				 "certificate verify failed: %s",
				 (const char *)out.data);
			gnutls_free(out.data);
		} else {
			snprintf(d->error, sizeof(d->error),
				 "certificate verify failed");
		}
		return esdm_tls_gnutls_refuse(
			d, esdm_tls_gnutls_status_alert(status),
			GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR);
	}

	ret = esdm_tls_gnutls_chain(d, &chain, &num);
	if (ret) {
		snprintf(d->error, sizeof(d->error),
			 "certificate verify failed: %s",
			 ret == -ENOMEM ?
				 "out of memory" :
				 "the chain does not end in a self-issued trust anchor");
		return esdm_tls_gnutls_refuse(
			d,
			ret == -ENOMEM ? GNUTLS_A_INTERNAL_ERROR :
					 GNUTLS_A_UNKNOWN_CA,
			GNUTLS_E_CERTIFICATE_ERROR);
	}

	/* The policy takes the chain over, and tells why it refuses */
	switch (d->check(d->check_arg, chain, num)) {
	case esdm_tls_verdict_accepted:
		return 0;
	case esdm_tls_verdict_revoked:
		return esdm_tls_gnutls_refuse(d, GNUTLS_A_CERTIFICATE_REVOKED,
					      GNUTLS_E_CERTIFICATE_ERROR);
	case esdm_tls_verdict_crl_expired:
		return esdm_tls_gnutls_refuse(d, GNUTLS_A_CERTIFICATE_EXPIRED,
					      GNUTLS_E_CERTIFICATE_ERROR);
	case esdm_tls_verdict_no_crl:
		return esdm_tls_gnutls_refuse(d, GNUTLS_A_UNKNOWN_CA,
					      GNUTLS_E_CERTIFICATE_ERROR);
	case esdm_tls_verdict_bad_chain:
	default:
		return esdm_tls_gnutls_refuse(d, GNUTLS_A_BAD_CERTIFICATE,
					      GNUTLS_E_CERTIFICATE_ERROR);
	}
}

/*
 * The files of one side: the trust anchors, the own certificate with its key -
 * which has to chain to them - and the CRLs - see "Contexts" in esdm_tls.h.
 */
static int esdm_tls_gnutls_files(struct esdm_tls_gnutls_ctx *c,
				 const struct esdm_tls_config *cfg)
{
	unsigned int i;
	int ret;

	ret = gnutls_certificate_set_x509_trust_file(c->cred, cfg->ca_file,
						     GNUTLS_X509_FMT_PEM);
	if (ret <= 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot load the trust anchors %s: %s\n",
			    cfg->ca_file,
			    ret < 0 ? gnutls_strerror(ret) :
				      "no certificate in it");
		return -EINVAL;
	}
	ret = esdm_tls_gnutls_load_cas(c);
	if (ret)
		return ret;

	if (cfg->cert_file) {
		/* Checks that the key belongs to the certificate as well */
		ret = gnutls_certificate_set_x509_key_file2(
			c->cred, cfg->cert_file, cfg->key_file,
			GNUTLS_X509_FMT_PEM, NULL, 0);
		if (ret < 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: cannot load the certificate %s with the key %s: %s\n",
				cfg->cert_file, cfg->key_file,
				gnutls_strerror(ret));
			return -EINVAL;
		}
		ret = esdm_tls_gnutls_check_own(c, cfg->cert_file,
						cfg->ca_file);
		if (ret)
			return ret;
	}

	for (i = 0; i < cfg->crl_files_num; i++) {
		ret = esdm_tls_gnutls_load_crls(c, cfg->crl_files[i]);
		if (ret)
			return ret;
	}

	gnutls_certificate_set_verify_function(c->cred, esdm_tls_gnutls_verify);

	return 0;
}

/******************************************************************************
 * esdm_tls_backend.h: the certificates
 ******************************************************************************/

int esdm_tls_backend_ctx_files(void *ctx, bool server,
			       const struct esdm_tls_config *cfg)
{
	(void)server;
	return esdm_tls_gnutls_files(ctx, cfg);
}

size_t esdm_tls_backend_crl_count(void *ctx)
{
	struct esdm_tls_gnutls_ctx *c = ctx;

	return c->crl_num;
}

int esdm_tls_backend_crl_info(void *ctx, size_t idx,
			      struct esdm_tls_crl_info *info)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
	gnutls_datum_t dn;
	time_t next;

	if (idx >= c->crl_num)
		return -ENOENT;

	snprintf(info->issuer, sizeof(info->issuer), "unknown");
	if (gnutls_x509_crl_get_issuer_dn3(c->crls[idx], &dn, 0) >= 0) {
		esdm_tls_gnutls_datum_str(&dn, info->issuer,
					  sizeof(info->issuer));
		gnutls_free(dn.data);
	}

	/* None, or none GnuTLS can tell - see esdm_tls_backend_cert_info() */
	next = gnutls_x509_crl_get_next_update(c->crls[idx]);
	info->next_update = next < 0 ? 0 : (int64_t)next;

	info->delta = esdm_tls_gnutls_crl_has_ext(c->crls[idx],
						  ESDM_TLS_GNUTLS_OID_DELTA_CRL);
	info->scoped = esdm_tls_gnutls_crl_has_ext(c->crls[idx],
						   ESDM_TLS_GNUTLS_OID_IDP);

	return 0;
}

int esdm_tls_backend_crl_lookup(void *ctx, const struct esdm_tls_der *cert,
				const struct esdm_tls_der *issuer,
				struct esdm_tls_crl_result *res)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
	gnutls_x509_crt_t x = NULL, iss = NULL;
	gnutls_x509_crl_t best = NULL;
	time_t best_this = 0, next;
	unsigned int i;
	int ret;

	memset(res, 0, sizeof(res[0]));

	ret = esdm_tls_gnutls_import(cert, &x);
	if (!ret)
		ret = esdm_tls_gnutls_import(issuer, &iss);
	if (ret)
		goto out;

	for (i = 0; i < c->crl_num; i++) {
		unsigned int verify = 0;
		time_t this_update;

		if (gnutls_x509_crl_check_issuer(c->crls[i], iss) != 1)
			continue;

		/*
		 * The signature only: the times are judged by the policy of
		 * esdm_tls.c, as with the other TLS stacks. GnuTLS judges
		 * them all the same, and marks a CRL invalid for them.
		 */
		if (gnutls_x509_crl_verify(c->crls[i], &iss, 1,
					   GNUTLS_VERIFY_DISABLE_TIME_CHECKS,
					   &verify) < 0 ||
		    !esdm_tls_gnutls_crl_signed(verify))
			continue;

		/* Of several, the one issued last */
		this_update = gnutls_x509_crl_get_this_update(c->crls[i]);
		if (best && this_update <= best_this)
			continue;
		best = c->crls[i];
		best_this = this_update;
	}

	if (!best)
		goto out;

	res->found = true;
	next = gnutls_x509_crl_get_next_update(best);
	res->next_update = next < 0 ? 0 : (int64_t)next;
	ret = gnutls_x509_crt_check_revocation(x, &best, 1);
	if (ret < 0) {
		ret = -EINVAL;
		goto out;
	}
	res->revoked = (ret == 1);
	ret = 0;

out:
	if (x)
		gnutls_x509_crt_deinit(x);
	if (iss)
		gnutls_x509_crt_deinit(iss);
	return ret;
}

int esdm_tls_backend_cert_info(const struct esdm_tls_der *cert,
			       struct esdm_tls_cert_info *info)
{
	gnutls_x509_crt_t x = NULL;
	unsigned char serial[40];
	size_t serial_len = sizeof(serial), oid_len, i;
	gnutls_datum_t dn;
	int ret;

	ret = esdm_tls_gnutls_import(cert, &x);
	if (ret)
		return ret;

	snprintf(info->subject, sizeof(info->subject), "unknown");
	if (gnutls_x509_crt_get_dn3(x, &dn, 0) >= 0) {
		esdm_tls_gnutls_datum_str(&dn, info->subject,
					  sizeof(info->subject));
		gnutls_free(dn.data);
	}

	snprintf(info->serial, sizeof(info->serial), "unknown");
	if (gnutls_x509_crt_get_serial(x, serial, &serial_len) >= 0 &&
	    2 * serial_len < sizeof(info->serial)) {
		for (i = 0; i < serial_len; i++)
			snprintf(info->serial + 2 * i, 3, "%02X", serial[i]);
	}

	oid_len = sizeof(info->key_oid);
	if (gnutls_x509_crt_get_pk_oid(x, info->key_oid, &oid_len) < 0)
		info->key_oid[0] = '\0';

	/*
	 * A time_t of 32 bits ends in 2038: what GnuTLS cannot tell beyond is
	 * no time at all, not one in the past.
	 */
	info->not_after = (int64_t)gnutls_x509_crt_get_expiration_time(x);
	if (info->not_after < 0)
		info->not_after = 0;

	gnutls_x509_crt_deinit(x);
	return 0;
}

/* The hybrid of ML-KEM, if GnuTLS has it */
const char *esdm_tls_backend_mlkem_group(void)
{
	return gnutls_group_get_id(ESDM_TLS_GNUTLS_HYBRID) !=
			       GNUTLS_GROUP_INVALID ?
		       ESDM_TLS_GNUTLS_HYBRID :
		       NULL;
}

/* The name check of GnuTLS takes an address of either family */
bool esdm_tls_backend_ip6_name(void)
{
	return true;
}

#endif /* ESDM_TLS_AUTH */
