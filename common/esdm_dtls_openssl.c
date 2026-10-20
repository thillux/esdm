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
 * OpenSSL's datagram BIO expects an address family of the Internet, so the
 * records go through a BIO of their own: one send(2) or recv(2) of one message
 * each on the non-blocking socket.
 *
 * The contexts are created in a library context of their own with the default
 * provider: the DTLS must not take its random numbers from a RAND provider the
 * application configured - which in a client of the ESDM may well be the
 * ESDM's own OpenSSL provider, asking over the connection being set up.
 */

#include <errno.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "esdm_dtls.h"
#include "esdm_dtls_backend.h"

/*
 * TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 on P-521. OpenSSL has no ECDHE-PSK
 * suite with AES-GCM - RFC 8442's - and its one with an AEAD cipher is
 * ChaCha20-Poly1305, which neither NIST SP 800-52r2 nor BSI TR-02102-2
 * allows. Encrypt-then-MAC is on by default, see
 * esdm_dtls_openssl_client_hello().
 */
#define ESDM_DTLS_OPENSSL_CIPHERS "ECDHE-PSK-AES256-CBC-SHA384"
#define ESDM_DTLS_OPENSSL_GROUPS "secp521r1"

/******************************************************************************
 * The library context and the BIO, both set up once per process
 ******************************************************************************/

static OSSL_LIB_CTX *esdm_dtls_openssl_libctx = NULL;
static BIO_METHOD *esdm_dtls_openssl_bio_meth = NULL;
static pthread_once_t esdm_dtls_openssl_once = PTHREAD_ONCE_INIT;

static int esdm_dtls_openssl_bio_fd(BIO *bio)
{
	return (int)(intptr_t)BIO_get_data(bio);
}

static int esdm_dtls_openssl_bio_write(BIO *bio, const char *buf, int len)
{
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = send(esdm_dtls_openssl_bio_fd(bio), buf, (size_t)len,
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_write(bio);
		return -1;
	}

	return (int)n;
}

static int esdm_dtls_openssl_bio_read(BIO *bio, char *buf, int len)
{
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = recv(esdm_dtls_openssl_bio_fd(bio), buf, (size_t)len, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_read(bio);
		return -1;
	}

	/* 0: the peer is gone - the end of the connection, not an empty record */
	return (int)n;
}

static long esdm_dtls_openssl_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	(void)bio;
	(void)num;
	(void)ptr;

	switch (cmd) {
	case BIO_CTRL_FLUSH:
		/* Every record is sent as it is written */
		return 1;
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return ESDM_DTLS_LINK_MTU;
	default:
		/*
		 * Peer addresses, timers, MTU overhead: nothing a connected
		 * Unix domain socket has
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
			    "esdm_dtls_seqpacket");
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

/*
 * The result @ret of an SSL operation on @ssl that did not complete: -EAGAIN
 * if it waits for the peer, -ECONNRESET if the peer is gone - the end of the
 * connection or a send(2) or recv(2) telling so -, -EIO for another error of
 * the socket, -EPROTO for anything else. The error queue of the thread is
 * cleared - errors are per connection here, not per thread.
 *
 * SSL_get_error() reports any error on the queue of the thread as one of the
 * operation it is asked about. The handshake clears the queue as it starts, a
 * read or a write does not: every SSL operation below starts on an empty queue,
 * as the client runs on the threads of the application, which may have left an
 * error there, and a read waiting for the peer would fail with -EPROTO.
 */
static int esdm_dtls_openssl_error(SSL *ssl, int ret)
{
	/* That of the socket call of the BIO, for SSL_ERROR_SYSCALL */
	int sock_err = errno;
	int err = SSL_get_error(ssl, ret);

	ERR_clear_error();

	switch (err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		return -EAGAIN;
	case SSL_ERROR_ZERO_RETURN:
		return -ECONNRESET;
	case SSL_ERROR_SYSCALL:
		if (ret == 0 || sock_err == ECONNRESET || sock_err == EPIPE ||
		    sock_err == ENOTCONN)
			return -ECONNRESET;
		return -EIO;
	default:
		return -EPROTO;
	}
}

/******************************************************************************
 * esdm_dtls_backend.h
 ******************************************************************************/

const char *esdm_dtls_backend_name(void)
{
	return "OpenSSL";
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
 */
static int esdm_dtls_openssl_client_hello(SSL *ssl, int *alert, void *arg)
{
	const unsigned char *ext;
	size_t len;

	(void)arg;

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_encrypt_then_mac, &ext,
				      &len))
		return SSL_CLIENT_HELLO_SUCCESS;

	*alert = SSL_AD_INSUFFICIENT_SECURITY;
	return SSL_CLIENT_HELLO_ERROR;
}

int esdm_dtls_backend_ctx_new(bool server, void **ctx)
{
	SSL_CTX *c;

	pthread_once(&esdm_dtls_openssl_once, esdm_dtls_openssl_init);
	if (!esdm_dtls_openssl_libctx)
		return -ENOMEM;

	c = SSL_CTX_new_ex(esdm_dtls_openssl_libctx, NULL,
			   server ? DTLS_server_method() :
				    DTLS_client_method());
	if (!c)
		goto err;

	/*
	 * DTLS 1.2 exactly, the one suite on the one curve, and neither
	 * renegotiation nor session tickets - a connection lives as long as it
	 * does, with the one handshake it started with.
	 */
	if (!SSL_CTX_set_min_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_max_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_cipher_list(c, ESDM_DTLS_OPENSSL_CIPHERS) ||
	    !SSL_CTX_set1_groups_list(c, ESDM_DTLS_OPENSSL_GROUPS))
		goto err;
	SSL_CTX_set_options(c, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET |
				       SSL_OP_NO_QUERY_MTU);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);
	/*
	 * A server holds many connections, most of them idle between the
	 * requests: no record buffers for those
	 */
	SSL_CTX_set_mode(c, SSL_MODE_RELEASE_BUFFERS);
	/*
	 * A record is decrypted in place, in the read buffer: wipe what was
	 * handed out, and the buffer as it is released - after every record,
	 * see above - or freed.
	 */
	SSL_CTX_set_options(c, SSL_OP_CLEANSE_PLAINTEXT);

	if (server) {
		SSL_CTX_set_psk_server_callback(c,
						esdm_dtls_openssl_psk_server);
		SSL_CTX_set_client_hello_cb(c, esdm_dtls_openssl_client_hello,
					    NULL);
	} else {
		SSL_CTX_set_psk_client_callback(c,
						esdm_dtls_openssl_psk_client);
	}

	*ctx = c;
	return 0;

err:
	ERR_clear_error();
	SSL_CTX_free(c);
	return -ENOMEM;
}

void esdm_dtls_backend_ctx_free(void *ctx)
{
	SSL_CTX_free(ctx);
}

int esdm_dtls_backend_conn_new(void *ctx, bool server, int fd, void **conn)
{
	SSL *ssl = SSL_new(ctx);
	BIO *bio;

	if (!ssl)
		goto err;

	bio = BIO_new(esdm_dtls_openssl_bio_meth);
	if (!bio)
		goto err;
	BIO_set_data(bio, (void *)(intptr_t)fd);
	/* The SSL owns the BIO from here on, for reading and writing */
	SSL_set_bio(ssl, bio, bio);

	/* No MTU to discover on the connection, and no record to fragment */
	SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
	DTLS_set_link_mtu(ssl, ESDM_DTLS_LINK_MTU);

	if (server)
		SSL_set_accept_state(ssl);
	else
		SSL_set_connect_state(ssl);

	*conn = ssl;
	return 0;

err:
	ERR_clear_error();
	SSL_free(ssl);
	return -ENOMEM;
}

void esdm_dtls_backend_conn_free(void *conn)
{
	SSL_free(conn);
}

int esdm_dtls_backend_handshake(void *conn)
{
	int ret;

	ERR_clear_error();
	ret = SSL_do_handshake(conn);

	return ret == 1 ? 0 : esdm_dtls_openssl_error(conn, ret);
}

int esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len)
{
	int ret;

	ERR_clear_error();
	ret = SSL_write(conn, buf, (int)len);

	if (ret == (int)len)
		return 0;
	if (ret > 0)
		return -EIO;
	return esdm_dtls_openssl_error(conn, ret);
}

ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len)
{
	int ret;

	ERR_clear_error();
	ret = SSL_read(conn, buf, (int)len);

	return ret > 0 ? ret : esdm_dtls_openssl_error(conn, ret);
}

bool esdm_dtls_backend_pending(void *conn)
{
	return SSL_has_pending(conn) == 1;
}

const char *esdm_dtls_backend_cipher(void *conn)
{
	return SSL_get_cipher_name((SSL *)conn);
}
