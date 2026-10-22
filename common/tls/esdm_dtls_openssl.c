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
 * DTLS of esdm_dtls_backend.h by OpenSSL, for crypto_backend=openssl.
 *
 * The socket is reached through a BIO of its own: the one of OpenSSL
 * write(2)s - and with that raises SIGPIPE in the process the library is
 * linked into for a peer that went away -, and OpenSSL's datagram BIO expects
 * an address family of the Internet. One message of esdm_dtls_io.h per call
 * on the non-blocking socket.
 *
 * Everything is created in one library context of its own with the default
 * provider: the DTLS must not take its random numbers from a RAND provider
 * the application configured - which in a client of the ESDM may well be the
 * ESDM's own OpenSSL provider, asking over the connection being set up.
 */

#include <errno.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_dtls_backend.h"
#include "esdm_dtls_session.h"
#include "memset_secure.h"

/*
 * TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 on P-521. OpenSSL has no ECDHE-PSK
 * suite with AES-GCM - RFC 8442's - and its one with an AEAD cipher is
 * ChaCha20-Poly1305, which neither NIST SP 800-52r2 nor BSI TR-02102-2 allows.
 * Encrypt-then-MAC is on by default, and required, see
 * esdm_dtls_openssl_client_hello().
 */
#define ESDM_DTLS_OPENSSL_PSK_CIPHERS "ECDHE-PSK-AES256-CBC-SHA384"
#define ESDM_DTLS_OPENSSL_PSK_GROUPS "secp521r1"

/*
 * The timer of the DTLS handshake, in microseconds: long enough to never run
 * out - the connection is reliable, and the callers bound the handshake
 * themselves
 */
#define ESDM_DTLS_OPENSSL_TIMER_US 600000000U

struct esdm_dtls_openssl_ctx {
	SSL_CTX *ssl_ctx;
	/* The sessions to resume, see esdm_dtls_session.h */
	struct esdm_dtls_sessions *sessions;
};

struct esdm_dtls_openssl_conn {
	SSL *ssl;
	struct esdm_dtls_openssl_ctx *ctx;
	struct esdm_dtls_io *io;
	/* A client: the socket path its session is kept under */
	uint8_t session_key[ESDM_DTLS_SESSION_KEY_MAX];
	size_t session_keylen;
};

/******************************************************************************
 * The library context and the BIO, both set up once per process
 ******************************************************************************/

static OSSL_LIB_CTX *esdm_dtls_openssl_libctx = NULL;
static BIO_METHOD *esdm_dtls_openssl_bio_meth = NULL;
static pthread_once_t esdm_dtls_openssl_once = PTHREAD_ONCE_INIT;

static int esdm_dtls_openssl_bio_write(BIO *bio, const char *buf, int len)
{
	struct esdm_dtls_openssl_conn *c = BIO_get_data(bio);
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = esdm_dtls_io_send(c->io, buf, (size_t)len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_write(bio);
		return -1;
	}

	return (int)n;
}

static int esdm_dtls_openssl_bio_read(BIO *bio, char *buf, int len)
{
	struct esdm_dtls_openssl_conn *c = BIO_get_data(bio);
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = esdm_dtls_io_recv(c->io, buf, (size_t)len);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_read(bio);
		return -1;
	}

	/*
	 * 0: the end of the stream, which OpenSSL tells by the retry flags -
	 * the peer gone, not an empty record
	 */
	return (int)n;
}

static long esdm_dtls_openssl_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	(void)bio;
	(void)num;
	(void)ptr;

	switch (cmd) {
	case BIO_CTRL_FLUSH:
		/* Everything is sent as it is written */
		return 1;
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return ESDM_DTLS_LINK_MTU;
	default:
		/*
		 * Peer addresses, timers, MTU overhead: nothing a connected
		 * socket has
		 */
		return 0;
	}
}

static int esdm_dtls_openssl_bio_create(BIO *bio)
{
	BIO_set_init(bio, 1);
	return 1;
}

static void esdm_dtls_openssl_init(void)
{
	BIO_METHOD *meth;
	OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

	if (!libctx)
		return;
	if (!OSSL_PROVIDER_load(libctx, "default")) {
		OSSL_LIB_CTX_free(libctx);
		return;
	}

	meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
			    "esdm_dtls_socket");
	if (!meth || !BIO_meth_set_write(meth, esdm_dtls_openssl_bio_write) ||
	    !BIO_meth_set_read(meth, esdm_dtls_openssl_bio_read) ||
	    !BIO_meth_set_ctrl(meth, esdm_dtls_openssl_bio_ctrl) ||
	    !BIO_meth_set_create(meth, esdm_dtls_openssl_bio_create)) {
		BIO_meth_free(meth);
		OSSL_LIB_CTX_free(libctx);
		return;
	}

	esdm_dtls_openssl_bio_meth = meth;
	esdm_dtls_openssl_libctx = libctx;
}

/* The library context of this file, NULL if it cannot be set up */
static OSSL_LIB_CTX *esdm_dtls_openssl_lib(void)
{
	pthread_once(&esdm_dtls_openssl_once, esdm_dtls_openssl_init);
	return esdm_dtls_openssl_libctx;
}

/*
 * The result @ret of an SSL operation on @c that did not complete: -EAGAIN if
 * it waits for the socket, with *want telling for what, -ECONNRESET if the
 * peer is gone - the end of the connection with or without a closing alert,
 * or a send(2) or recv(2) telling so -, -EIO for another error of the socket,
 * -EPROTO for anything else. The error queue of the thread is cleared - errors
 * are per connection here, not per thread.
 *
 * SSL_get_error() reports any error on the queue of the thread as one of the
 * operation it is asked about. The handshake clears the queue as it starts, a
 * read or a write does not: every SSL operation below starts on an empty queue,
 * as a client runs on the threads of the application, which may have left an
 * error there, and a read waiting for the peer would fail with -EPROTO.
 */
static int esdm_dtls_openssl_error(struct esdm_dtls_openssl_conn *c, int ret,
				   short *want)
{
	/* That of the socket call of the BIO, for SSL_ERROR_SYSCALL */
	int sock_err = errno;
	int err = SSL_get_error(c->ssl, ret);
	unsigned long e = ERR_peek_last_error();

	ERR_clear_error();

	switch (err) {
	case SSL_ERROR_WANT_READ:
		*want = POLLIN;
		return -EAGAIN;
	case SSL_ERROR_WANT_WRITE:
		*want = POLLOUT;
		return -EAGAIN;
	case SSL_ERROR_ZERO_RETURN:
		return -ECONNRESET;
	case SSL_ERROR_SYSCALL:
		if (ret == 0 || sock_err == ECONNRESET || sock_err == EPIPE ||
		    sock_err == ENOTCONN || sock_err == 0)
			return -ECONNRESET;
		return -EIO;
	case SSL_ERROR_SSL:
		if (ERR_GET_LIB(e) == ERR_LIB_SSL &&
		    ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING)
			return -ECONNRESET;
		return -EPROTO;
	default:
		return -EPROTO;
	}
}

/******************************************************************************
 * The context
 ******************************************************************************/

/*
 * The secure minimal mode of esdm_dtls_backend.h - a connection lives as long
 * as it does, with the one handshake it started with:
 *
 *  - no session cache of OpenSSL's own on either side, and no tickets, none
 *    issued and none asked for: the sessions are resumed by ID from the cache
 *    of esdm_dtls_session.h alone, see esdm_dtls_openssl_sessions();
 *  - no early data, sent or taken;
 *  - no renegotiation either way - the insecure legacy one, which
 *    SSL_OP_LEGACY_SERVER_CONNECT would allow with an old server, included;
 *  - no compression; OpenSSL 3 has no heartbeat;
 *  - the extended master secret and Encrypt-then-MAC stay offered and taken,
 *    and are required, see esdm_dtls_openssl_client_hello() and
 *    esdm_dtls_backend_handshake().
 *
 * A server holds many connections, most of them idle between the requests: no
 * record buffers for those. A record is decrypted in place, in the read buffer:
 * wipe what was handed out, and the buffer as it is released or freed.
 */
static int esdm_dtls_openssl_minimal(SSL_CTX *c)
{
	SSL_CTX_set_options(c, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION |
				       SSL_OP_NO_COMPRESSION |
				       SSL_OP_CLEANSE_PLAINTEXT);
	SSL_CTX_clear_options(c,
			      SSL_OP_ALLOW_CLIENT_RENEGOTIATION |
				      SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
				      SSL_OP_LEGACY_SERVER_CONNECT |
				      SSL_OP_NO_EXTENDED_MASTER_SECRET |
				      SSL_OP_NO_ENCRYPT_THEN_MAC);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_mode(c, SSL_MODE_RELEASE_BUFFERS);

	if (!SSL_CTX_set_num_tickets(c, 0) ||
	    !SSL_CTX_set_max_early_data(c, 0) ||
	    !SSL_CTX_set_recv_max_early_data(c, 0))
		return -ENOMEM;
	return 0;
}

/*
 * The pre-shared key of either side, see esdm_dtls_backend.h. A server knows
 * no other identity - returning 0 refuses a client with another one.
 */
static unsigned int esdm_dtls_openssl_psk_client(SSL *ssl, const char *hint,
						 char *identity,
						 unsigned int max_identity_len,
						 unsigned char *psk,
						 unsigned int max_psk_len)
{
	(void)ssl;
	(void)hint;

	/* max_identity_len leaves out the terminating NUL */
	if (sizeof(ESDM_DTLS_PSK_IDENTITY) - 1 > max_identity_len ||
	    sizeof(esdm_dtls_psk) > max_psk_len)
		return 0;

	memcpy(identity, ESDM_DTLS_PSK_IDENTITY,
	       sizeof(ESDM_DTLS_PSK_IDENTITY));
	memcpy(psk, esdm_dtls_psk, sizeof(esdm_dtls_psk));
	return sizeof(esdm_dtls_psk);
}

static unsigned int esdm_dtls_openssl_psk_server(SSL *ssl, const char *identity,
						 unsigned char *psk,
						 unsigned int max_psk_len)
{
	(void)ssl;

	if (!identity || strcmp(identity, ESDM_DTLS_PSK_IDENTITY) ||
	    sizeof(esdm_dtls_psk) > max_psk_len)
		return 0;

	memcpy(psk, esdm_dtls_psk, sizeof(esdm_dtls_psk));
	return sizeof(esdm_dtls_psk);
}

/*
 * A client has to offer Encrypt-then-MAC (RFC 7366), which the server agrees
 * to for a CBC suite: MAC-then-encrypt is what Lucky Thirteen reads records
 * from, and DTLS lets an attacker try again after every record it broke. A
 * client of OpenSSL cannot tell whether its server agreed - every server of
 * the ESDM does, whichever its TLS stack.
 *
 * And it has to offer the extended master secret (RFC 7627), which binds the
 * master secret to the handshake it came from - the client checks that the
 * server agreed, see esdm_dtls_backend_handshake(). OpenSSL has no option to
 * require either.
 */
static int esdm_dtls_openssl_client_hello(SSL *ssl, int *alert, void *arg)
{
	const unsigned char *ext;
	size_t len;

	(void)arg;

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_encrypt_then_mac, &ext,
				      &len) &&
	    SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_extended_master_secret,
				      &ext, &len))
		return SSL_CLIENT_HELLO_SUCCESS;

	*alert = SSL_AD_INSUFFICIENT_SECURITY;
	return SSL_CLIENT_HELLO_ERROR;
}

/*
 * DTLS 1.2 exactly, the one suite of ECDHE with the pre-shared key on the one
 * curve. No MTU is queried: the link MTU is set per connection.
 */
static int esdm_dtls_openssl_suites(SSL_CTX *c, bool server)
{
	if (!SSL_CTX_set_min_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_max_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_cipher_list(c, ESDM_DTLS_OPENSSL_PSK_CIPHERS) ||
	    !SSL_CTX_set1_groups_list(c, ESDM_DTLS_OPENSSL_PSK_GROUPS))
		return -ENOMEM;
	SSL_CTX_set_options(c, SSL_OP_NO_QUERY_MTU);

	if (server) {
		SSL_CTX_set_psk_server_callback(c,
						esdm_dtls_openssl_psk_server);
		SSL_CTX_set_client_hello_cb(c, esdm_dtls_openssl_client_hello,
					    NULL);
	} else {
		SSL_CTX_set_psk_client_callback(c,
						esdm_dtls_openssl_psk_client);
	}
	return 0;
}

/*
 * The sessions of a server, kept in the cache of
 * esdm_dtls_session.h under their ID, serialized - OpenSSL keeps none itself
 */
static int esdm_dtls_openssl_sess_new(SSL *ssl, SSL_SESSION *sess)
{
	struct esdm_dtls_openssl_ctx *oc =
		SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
	const unsigned char *id;
	unsigned int idlen;
	unsigned char *der, *p;
	int len = i2d_SSL_SESSION(sess, NULL);

	id = SSL_SESSION_get_id(sess, &idlen);
	if (len <= 0 || !idlen)
		return 0;
	der = malloc((size_t)len);
	if (!der)
		return 0;
	p = der;
	if (i2d_SSL_SESSION(sess, &p) == len)
		esdm_dtls_sessions_put(oc->sessions, id, idlen, der,
				       (size_t)len);
	memset_secure(der, 0, (size_t)len);
	free(der);

	/* No reference kept */
	return 0;
}

static SSL_SESSION *esdm_dtls_openssl_sess_get(SSL *ssl,
					       const unsigned char *id,
					       int idlen, int *copy)
{
	struct esdm_dtls_openssl_ctx *oc =
		SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl));
	SSL_SESSION *sess = NULL;
	const unsigned char *p;
	uint8_t *der;
	size_t len;

	*copy = 0;
	if (idlen <= 0 ||
	    esdm_dtls_sessions_get(oc->sessions, id, (size_t)idlen, &der, &len))
		return NULL;
	p = der;
	sess = d2i_SSL_SESSION(NULL, &p, (long)len);
	esdm_dtls_sessions_release(der, len);
	return sess;
}

static void esdm_dtls_openssl_sess_remove(SSL_CTX *ctx, SSL_SESSION *sess)
{
	struct esdm_dtls_openssl_ctx *oc = SSL_CTX_get_app_data(ctx);
	const unsigned char *id;
	unsigned int idlen;

	id = SSL_SESSION_get_id(sess, &idlen);
	esdm_dtls_sessions_del(oc->sessions, id, idlen);
}

/*
 * The sessions are resumed by ID, see esdm_dtls_backend.h: a server keeps them
 * in the cache of esdm_dtls_session.h - none in OpenSSL's own, and still no
 * ticket -, a client the one of the full handshake with its server under the
 * socket path, see esdm_dtls_openssl_resume() and
 * esdm_dtls_backend_handshake().
 */
static int esdm_dtls_openssl_sessions(struct esdm_dtls_openssl_ctx *oc,
				      bool server)
{
	static const unsigned char sid_ctx[] = "esdm-dtls";
	SSL_CTX *c = oc->ssl_ctx;

	if (esdm_dtls_sessions_alloc(server ? ESDM_DTLS_SESSIONS_SERVER :
					      ESDM_DTLS_SESSIONS_CLIENT,
				     &oc->sessions))
		return -ENOMEM;
	if (!server)
		return 0;

	SSL_CTX_set_app_data(c, oc);
	if (!SSL_CTX_set_session_id_context(c, sid_ctx, sizeof(sid_ctx) - 1))
		return -ENOMEM;
	SSL_CTX_set_timeout(c, ESDM_DTLS_SESSION_LIFETIME_S);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_SERVER |
						  SSL_SESS_CACHE_NO_INTERNAL);
	SSL_CTX_sess_set_new_cb(c, esdm_dtls_openssl_sess_new);
	SSL_CTX_sess_set_get_cb(c, esdm_dtls_openssl_sess_get);
	SSL_CTX_sess_set_remove_cb(c, esdm_dtls_openssl_sess_remove);
	return 0;
}

/* A client: offer the session kept under the socket path of its server */
static int esdm_dtls_openssl_resume(struct esdm_dtls_openssl_ctx *oc,
				    struct esdm_dtls_openssl_conn *c,
				    const uint8_t *key, size_t keylen)
{
	SSL_SESSION *sess;
	const unsigned char *p;
	uint8_t *der;
	size_t len;
	int ret = 0;

	if (!oc->sessions || !key || !keylen || keylen > sizeof(c->session_key))
		return 0;
	memcpy(c->session_key, key, keylen);
	c->session_keylen = keylen;

	if (esdm_dtls_sessions_get(oc->sessions, key, keylen, &der, &len))
		return 0;
	p = der;
	sess = d2i_SSL_SESSION(NULL, &p, (long)len);
	esdm_dtls_sessions_release(der, len);
	if (sess) {
		if (SSL_set_session(c->ssl, sess) != 1)
			ret = -ENOMEM;
		SSL_SESSION_free(sess);
	}
	return ret;
}

/* A client: keep the session of a full handshake with its server */
static void esdm_dtls_openssl_keep(struct esdm_dtls_openssl_ctx *oc,
				   struct esdm_dtls_openssl_conn *c)
{
	SSL_SESSION *sess;
	unsigned char *der, *p;
	int len;

	if (!oc->sessions || !c->session_keylen || SSL_session_reused(c->ssl))
		return;
	sess = SSL_get1_session(c->ssl);
	if (!sess)
		return;
	len = i2d_SSL_SESSION(sess, NULL);
	der = len > 0 ? malloc((size_t)len) : NULL;
	if (der) {
		p = der;
		if (i2d_SSL_SESSION(sess, &p) == len)
			esdm_dtls_sessions_put(oc->sessions, c->session_key,
					       c->session_keylen, der,
					       (size_t)len);
		memset_secure(der, 0, (size_t)len);
		free(der);
	}
	SSL_SESSION_free(sess);
}

/* The timer of the DTLS handshake, never to run out - see above */
static unsigned int esdm_dtls_openssl_timer(SSL *ssl, unsigned int timer_us)
{
	(void)ssl;
	(void)timer_us;
	return ESDM_DTLS_OPENSSL_TIMER_US;
}

/******************************************************************************
 * esdm_dtls_backend.h
 ******************************************************************************/

const char *esdm_dtls_backend_name(void)
{
	return "OpenSSL";
}

void esdm_dtls_backend_ctx_free(void *ctx)
{
	struct esdm_dtls_openssl_ctx *c = ctx;

	if (!c)
		return;
	SSL_CTX_free(c->ssl_ctx);
	esdm_dtls_sessions_free(c->sessions);
	free(c);
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	OSSL_LIB_CTX *libctx = esdm_dtls_openssl_lib();
	struct esdm_dtls_openssl_ctx *oc;
	int ret;

	if (!libctx)
		return -ENOMEM;

	oc = calloc(1, sizeof(*oc));
	if (!oc)
		return -ENOMEM;

	oc->ssl_ctx = SSL_CTX_new_ex(libctx, NULL,
				     server ? DTLS_server_method() :
					      DTLS_client_method());
	if (!oc->ssl_ctx) {
		ret = -ENOMEM;
		goto err;
	}

	ret = esdm_dtls_openssl_minimal(oc->ssl_ctx);
	if (!ret)
		ret = esdm_dtls_openssl_suites(oc->ssl_ctx, server);
	if (!ret)
		ret = esdm_dtls_openssl_sessions(oc, server);
	if (ret)
		goto err;

	*ctx = oc;
	return 0;

err:
	ERR_clear_error();
	esdm_dtls_backend_ctx_free(oc);
	return ret;
}

int esdm_dtls_backend_conn_new(void *ctx, bool server, struct esdm_dtls_io *io,
			       const uint8_t *session_key,
			       size_t session_keylen, void **conn)
{
	struct esdm_dtls_openssl_ctx *oc = ctx;
	struct esdm_dtls_openssl_conn *c = calloc(1, sizeof(*c));
	BIO *bio;

	if (!c)
		return -ENOMEM;
	c->ctx = oc;
	c->io = io;

	c->ssl = SSL_new(oc->ssl_ctx);
	if (!c->ssl)
		goto err;

	bio = BIO_new(esdm_dtls_openssl_bio_meth);
	if (!bio)
		goto err;
	BIO_set_data(bio, c);
	/* The SSL owns the BIO from here on, for reading and writing */
	SSL_set_bio(c->ssl, bio, bio);

	/*
	 * No MTU to discover and no record to fragment on SOCK_SEQPACKET, and
	 * no retransmission of DTLS
	 */
	if (!DTLS_set_link_mtu(c->ssl, ESDM_DTLS_LINK_MTU))
		goto err;
	DTLS_set_timer_cb(c->ssl, esdm_dtls_openssl_timer);

	if (server) {
		SSL_set_accept_state(c->ssl);
	} else {
		if (esdm_dtls_openssl_resume(oc, c, session_key,
					     session_keylen))
			goto err;
		SSL_set_connect_state(c->ssl);
	}

	*conn = c;
	return 0;

err:
	ERR_clear_error();
	SSL_free(c->ssl);
	free(c);
	return -ENOMEM;
}

void esdm_dtls_backend_conn_free(void *conn)
{
	struct esdm_dtls_openssl_conn *c = conn;

	if (!c)
		return;
	SSL_free(c->ssl);
	free(c);
}

/*
 * The extended master secret is required, see
 * esdm_dtls_openssl_client_hello(). A resumed session has the one of the full
 * handshake it was resumed from. A client keeps the session of a full
 * handshake, see esdm_dtls_openssl_keep().
 */
int esdm_dtls_backend_handshake(void *conn, short *want)
{
	struct esdm_dtls_openssl_conn *c = conn;
	int ret;

	ERR_clear_error();
	ret = SSL_do_handshake(c->ssl);
	if (ret != 1)
		return esdm_dtls_openssl_error(c, ret, want);

	if (SSL_get_extms_support(c->ssl) != 1)
		return -EPROTO;
	if (!SSL_is_server(c->ssl))
		esdm_dtls_openssl_keep(c->ctx, c);
	return 0;
}

ssize_t esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len,
			       short *want)
{
	struct esdm_dtls_openssl_conn *c = conn;
	int ret;

	if (len > INT32_MAX)
		len = INT32_MAX;

	ERR_clear_error();
	ret = SSL_write(c->ssl, buf, (int)len);

	return ret > 0 ? ret : esdm_dtls_openssl_error(c, ret, want);
}

/* A record is written to the socket as a whole before SSL_write() returns */
int esdm_dtls_backend_flush(void *conn, short *want)
{
	(void)conn;
	(void)want;
	return 0;
}

ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len,
			       short *want)
{
	struct esdm_dtls_openssl_conn *c = conn;
	int ret;

	if (len > INT32_MAX)
		len = INT32_MAX;

	ERR_clear_error();
	ret = SSL_read(c->ssl, buf, (int)len);

	/* A record whole: what is left of it is none of ours */
	if (ret > 0 && (size_t)ret == len && SSL_pending(c->ssl) > 0)
		return -EMSGSIZE;
	if (ret > 0)
		return ret;

	/* The closing alert is the end of the connection, not an error */
	if (SSL_get_error(c->ssl, ret) == SSL_ERROR_ZERO_RETURN) {
		ERR_clear_error();
		return 0;
	}

	return esdm_dtls_openssl_error(c, ret, want);
}

/*
 * OpenSSL reads a message whole, which may hold several records: those not
 * yet decrypted as well
 */
bool esdm_dtls_backend_pending(void *conn)
{
	struct esdm_dtls_openssl_conn *c = conn;

	return SSL_has_pending(c->ssl) == 1;
}

const char *esdm_dtls_backend_cipher(void *conn)
{
	struct esdm_dtls_openssl_conn *c = conn;

	return SSL_get_cipher_name(c->ssl);
}
