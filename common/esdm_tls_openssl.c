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
 * TLS of esdm_tls_backend.h by OpenSSL, for crypto_backend=openssl: TLS 1.3 on
 * a stream socket, DTLS 1.2 on SCTP - with the same files, the same
 * verification and the same revocation policy, see esdm_tls_openssl_files()
 * and esdm_tls_openssl_verify().
 *
 * The socket is reached through a BIO of its own, as the one of OpenSSL
 * write(2)s - and with that raises SIGPIPE in the process the client library is
 * linked into for a peer that went away: one send(2) with MSG_NOSIGNAL or one
 * recv(2) per call, on the non-blocking socket. On SCTP, the BIO hands each
 * record to the association of esdm_tls_sctp.h and takes each from it - not
 * OpenSSL's own SCTP BIO, which only an OpenSSL built with SCTP support has,
 * and which would make OpenSSL handle the keys of SCTP-AUTH itself: the other
 * TLS stacks need the code of esdm_tls_sctp.c, and so all three use it.
 *
 * Everything is created in a library context of its own with the default
 * provider, like the DTLS - see esdm_dtls_openssl.c: the TLS must not take its
 * random numbers from a RAND provider the application configured, which may be
 * the ESDM's own.
 *
 * The revocation policy of esdm_tls.c runs in the verify callback, on the
 * chain OpenSSL verified - see esdm_tls_openssl_verify().
 *
 * TLS 1.3 offers the groups of ML-KEM ahead of OpenSSL's default ones, see
 * ESDM_TLS_OPENSSL_GROUPS, and takes the signature schemes of ML-DSA with
 * OpenSSL's default ones, which list them first from OpenSSL 3.5 on - see
 * "Post-quantum algorithms" in esdm_tls.h.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "esdm_logger.h"
#include "esdm_tls.h"
#include "esdm_tls_backend.h"
#include "helper.h"

/*
 * TLS 1.3: the groups of ML-KEM in the order of esdm_tls.h, as a tuple of
 * their own ahead of the (EC)DHE groups. A server takes a group of the first
 * tuple the client has one of - by a HelloRetryRequest if the client sent no
 * key share of it -, and so prefers ML-KEM to any (EC)DHE group. The client
 * sends key shares of SecP384r1MLKEM1024 ("*") and of X25519 for a server
 * without ML-KEM. A group OpenSSL does not have is left out ("?").
 *
 * The (EC)DHE groups are the DEFAULT of OpenSSL 3.5 without its hybrid
 * X25519MLKEM768, whose X25519 falls short of 192 bits - see esdm_tls.h -,
 * spelled out rather than taken from DEFAULT, which takes that hybrid along.
 * OpenSSL before 3.5 has no ML-KEM and knows neither the tuples nor the key
 * shares, refuses the list and keeps its default groups.
 */
#define ESDM_TLS_OPENSSL_GROUPS                                                \
	"?*SecP384r1MLKEM1024:?MLKEM1024/?*X25519:?secp256r1/"                 \
	"?X448:?secp384r1:?secp521r1/?ffdhe2048:?ffdhe3072"

/*
 * DTLS 1.2 on SCTP: ECDHE with the key of the certificate, ECDSA or RSA, and
 * AEAD ciphers only - none of ML-KEM nor ML-DSA, which are for TLS 1.3 only
 */
#define ESDM_TLS_OPENSSL_DTLS_CIPHERS                                          \
	"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"           \
	"ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"           \
	"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"

/*
 * The timer of the DTLS handshake, in microseconds: long enough to never run
 * out - SCTP retransmits, DTLS must not (RFC 6083 section 3.5)
 */
#define ESDM_TLS_OPENSSL_DTLS_TIMER_US 600000000U

struct esdm_tls_openssl_ctx {
	SSL_CTX *ssl_ctx;
	STACK_OF(X509_CRL) *crls;
	bool sctp;
};

struct esdm_tls_openssl_conn {
	SSL *ssl;
	struct esdm_tls_sctp *sctp;
	/*
	 * SCTP: a record OpenSSL wrote a part of, collected until it is
	 * complete - see esdm_tls_openssl_sctp_write()
	 */
	uint8_t *wpart;
	size_t wpart_len;
	esdm_tls_backend_check check;
	void *check_arg;
	char error[ESDM_TLS_TEXT_LEN];
};

/******************************************************************************
 * The library context and the BIO, both set up once per process
 ******************************************************************************/

static OSSL_LIB_CTX *esdm_tls_openssl_libctx = NULL;
static BIO_METHOD *esdm_tls_openssl_bio_meth = NULL;
static BIO_METHOD *esdm_tls_openssl_sctp_meth = NULL;
static pthread_once_t esdm_tls_openssl_once = PTHREAD_ONCE_INIT;

static int esdm_tls_openssl_bio_fd(BIO *bio)
{
	return (int)(intptr_t)BIO_get_data(bio);
}

static int esdm_tls_openssl_bio_write(BIO *bio, const char *buf, int len)
{
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = send(esdm_tls_openssl_bio_fd(bio), buf, (size_t)len,
		 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_write(bio);
		return -1;
	}

	return (int)n;
}

static int esdm_tls_openssl_bio_read(BIO *bio, char *buf, int len)
{
	ssize_t n;

	BIO_clear_retry_flags(bio);
	n = recv(esdm_tls_openssl_bio_fd(bio), buf, (size_t)len, MSG_DONTWAIT);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			BIO_set_retry_read(bio);
		return -1;
	}

	/* 0: the end of the stream, which OpenSSL tells by the retry flags */
	return (int)n;
}

static long esdm_tls_openssl_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	(void)bio;
	(void)num;
	(void)ptr;

	switch (cmd) {
	case BIO_CTRL_FLUSH:
		/* Everything is sent as it is written */
		return 1;
	default:
		/* Nothing else is buffered here, and nothing else is known */
		return 0;
	}
}

static int esdm_tls_openssl_bio_create(BIO *bio)
{
	BIO_set_init(bio, 1);
	return 1;
}

/* The header of a DTLS record, its length in the last two bytes */
#define ESDM_TLS_OPENSSL_DTLS_HDR 13

/* The length of the DTLS record whose header is at @hdr */
static size_t esdm_tls_openssl_rec_len(const uint8_t *hdr)
{
	return ESDM_TLS_OPENSSL_DTLS_HDR + ((size_t)hdr[11] << 8 | hdr[12]);
}

/*
 * SCTP: the records written, through the association - see esdm_tls_sctp.h.
 * Each is queued as a whole, never refused for want of room in the socket.
 *
 * A record may come in parts: OpenSSL collects a flight of the handshake in a
 * buffering BIO of 4 KiB in front of this one, and writes it whenever it is
 * full, cutting a record where the 4 KiB end. A flight beyond - long chains,
 * large keys and signatures, ML-DSA among them - has records in parts, which
 * are collected here until complete. Every byte is taken.
 */
static int esdm_tls_openssl_sctp_write(BIO *bio, const char *buf, int len)
{
	struct esdm_tls_openssl_conn *c = BIO_get_data(bio);
	const uint8_t *in = (const uint8_t *)buf;
	size_t left, want, n;
	int ret;

	BIO_clear_retry_flags(bio);
	if (len < 0)
		return -1;
	left = (size_t)len;

	while (left) {
		/* Whole records, while none is in parts */
		if (!c->wpart_len && left >= ESDM_TLS_OPENSSL_DTLS_HDR &&
		    esdm_tls_openssl_rec_len(in) <= left) {
			n = esdm_tls_openssl_rec_len(in);
			ret = esdm_tls_sctp_queue(c->sctp, in, n);
			if (ret)
				goto err;
			in += n;
			left -= n;
			continue;
		}

		if (!c->wpart) {
			c->wpart = malloc(ESDM_TLS_SCTP_MSG_MAX);
			if (!c->wpart) {
				ret = -ENOMEM;
				goto err;
			}
		}

		/* The header first, then the rest of the record it tells */
		want = c->wpart_len < ESDM_TLS_OPENSSL_DTLS_HDR ?
			       ESDM_TLS_OPENSSL_DTLS_HDR :
			       esdm_tls_openssl_rec_len(c->wpart);
		if (want > ESDM_TLS_SCTP_MSG_MAX) {
			ret = -EPROTO;
			goto err;
		}
		n = want - c->wpart_len;
		if (n > left)
			n = left;
		memcpy(c->wpart + c->wpart_len, in, n);
		c->wpart_len += n;
		in += n;
		left -= n;

		if (c->wpart_len < ESDM_TLS_OPENSSL_DTLS_HDR ||
		    c->wpart_len < esdm_tls_openssl_rec_len(c->wpart))
			continue;

		ret = esdm_tls_sctp_queue(c->sctp, c->wpart, c->wpart_len);
		c->wpart_len = 0;
		if (ret)
			goto err;
	}

	return len;

err:
	c->wpart_len = 0;
	errno = -ret;
	return -1;
}

static int esdm_tls_openssl_sctp_read(BIO *bio, char *buf, int len)
{
	struct esdm_tls_openssl_conn *c = BIO_get_data(bio);
	ssize_t n;

	BIO_clear_retry_flags(bio);
	if (len <= 0)
		return -1;

	n = esdm_tls_sctp_recv(c->sctp, (uint8_t *)buf, (size_t)len);
	if (n == -EAGAIN) {
		BIO_set_retry_read(bio);
		return -1;
	}
	/* The end of the association, as the one of a stream */
	if (n == -ECONNRESET)
		return 0;
	if (n < 0) {
		errno = (int)-n;
		return -1;
	}

	return (int)n;
}

static long esdm_tls_openssl_sctp_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
	(void)bio;
	(void)num;
	(void)ptr;

	switch (cmd) {
	case BIO_CTRL_FLUSH:
		/* esdm_tls.c sends what is queued */
		return 1;
	case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
	case BIO_CTRL_DGRAM_QUERY_MTU:
		return ESDM_TLS_SCTP_MTU;
	default:
		/*
		 * Peer addresses, timers, MTU overhead: nothing DTLS needs
		 * on SCTP
		 */
		return 0;
	}
}

/* The timer of the DTLS handshake, never to run out - see above */
static unsigned int esdm_tls_openssl_dtls_timer(SSL *ssl, unsigned int timer_us)
{
	(void)ssl;
	(void)timer_us;
	return ESDM_TLS_OPENSSL_DTLS_TIMER_US;
}

static void esdm_tls_openssl_init(void)
{
	BIO_METHOD *meth, *sctp_meth;
	OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

	if (!libctx)
		return;
	if (!OSSL_PROVIDER_load(libctx, "default")) {
		OSSL_LIB_CTX_free(libctx);
		return;
	}

	meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
			    "esdm_tls_stream");
	if (!meth || !BIO_meth_set_write(meth, esdm_tls_openssl_bio_write) ||
	    !BIO_meth_set_read(meth, esdm_tls_openssl_bio_read) ||
	    !BIO_meth_set_ctrl(meth, esdm_tls_openssl_bio_ctrl) ||
	    !BIO_meth_set_create(meth, esdm_tls_openssl_bio_create)) {
		BIO_meth_free(meth);
		OSSL_LIB_CTX_free(libctx);
		return;
	}

	sctp_meth = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK,
				 "esdm_tls_sctp");
	if (!sctp_meth ||
	    !BIO_meth_set_write(sctp_meth, esdm_tls_openssl_sctp_write) ||
	    !BIO_meth_set_read(sctp_meth, esdm_tls_openssl_sctp_read) ||
	    !BIO_meth_set_ctrl(sctp_meth, esdm_tls_openssl_sctp_ctrl) ||
	    !BIO_meth_set_create(sctp_meth, esdm_tls_openssl_bio_create)) {
		BIO_meth_free(sctp_meth);
		BIO_meth_free(meth);
		OSSL_LIB_CTX_free(libctx);
		return;
	}

	esdm_tls_openssl_bio_meth = meth;
	esdm_tls_openssl_sctp_meth = sctp_meth;
	esdm_tls_openssl_libctx = libctx;
}

/* The last error on the queue of the thread as text, the queue cleared */
static void esdm_tls_openssl_errstr(char *buf, size_t len)
{
	unsigned long e = ERR_peek_last_error();

	if (e)
		ERR_error_string_n(e, buf, len);
	else
		snprintf(buf, len, "unknown error");
	ERR_clear_error();
}

/*
 * Reasons of a failed handshake that are about a certificate: one the peer
 * refused, or one it did not present.
 */
static bool esdm_tls_openssl_cert_reason(int reason)
{
	switch (reason) {
	case SSL_R_CERTIFICATE_VERIFY_FAILED:
	case SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE:
	case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:
	case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE:
	case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:
	case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:
	case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:
	case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
	case SSL_R_TLSV1_ALERT_ACCESS_DENIED:
	case SSL_R_TLSV13_ALERT_CERTIFICATE_REQUIRED:
		return true;
	default:
		return false;
	}
}

/*
 * The result @ret of an SSL operation on @c that did not complete: -EAGAIN if
 * it waits for the socket, with *want telling for what, -ECONNRESET if the
 * peer is gone - the end of the stream with or without a closing alert, or a
 * send(2) or recv(2) telling so -, -EACCES for a certificate that was refused,
 * -EIO for another error of the socket, -EPROTO for anything else. The error
 * queue of the thread is cleared - errors are per connection here, not per
 * thread, and the client runs on the threads of the application.
 */
static int esdm_tls_openssl_error(struct esdm_tls_openssl_conn *c, int ret,
				  short *want)
{
	/* That of the socket call of the BIO, for SSL_ERROR_SYSCALL */
	int sock_err = errno;
	int err = SSL_get_error(c->ssl, ret);
	unsigned long e = ERR_peek_last_error();
	long verify;

	switch (err) {
	case SSL_ERROR_WANT_READ:
		ERR_clear_error();
		*want = POLLIN;
		return -EAGAIN;
	case SSL_ERROR_WANT_WRITE:
		ERR_clear_error();
		*want = POLLOUT;
		return -EAGAIN;
	case SSL_ERROR_ZERO_RETURN:
		ERR_clear_error();
		snprintf(c->error, sizeof(c->error),
			 "connection closed by the peer");
		return -ECONNRESET;
	case SSL_ERROR_SYSCALL:
		ERR_clear_error();
		if (ret == 0 || sock_err == ECONNRESET || sock_err == EPIPE ||
		    sock_err == ENOTCONN || sock_err == 0) {
			snprintf(c->error, sizeof(c->error),
				 "connection closed by the peer");
			return -ECONNRESET;
		}
		snprintf(c->error, sizeof(c->error), "%s", strerror(sock_err));
		return -EIO;
	case SSL_ERROR_SSL:
		verify = SSL_get_verify_result(c->ssl);
		if (verify != X509_V_OK) {
			ERR_clear_error();
			snprintf(c->error, sizeof(c->error),
				 "certificate verify failed: %s",
				 X509_verify_cert_error_string(verify));
			return -EACCES;
		}
		if (ERR_GET_LIB(e) == ERR_LIB_SSL &&
		    ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING) {
			ERR_clear_error();
			snprintf(c->error, sizeof(c->error),
				 "connection closed by the peer without a closing alert");
			return -ECONNRESET;
		}
		esdm_tls_openssl_errstr(c->error, sizeof(c->error));
		if (ERR_GET_LIB(e) == ERR_LIB_SSL &&
		    esdm_tls_openssl_cert_reason(ERR_GET_REASON(e)))
			return -EACCES;
		return -EPROTO;
	default:
		esdm_tls_openssl_errstr(c->error, sizeof(c->error));
		return -EPROTO;
	}
}

/*
 * @t in seconds since the epoch, 0 if it cannot be told. Counted from the
 * epoch by OpenSSL rather than converted with timegm(3): a time_t of 32 bits
 * ends in 2038, which certificates and CRLs are valid beyond.
 */
static int64_t esdm_tls_openssl_time(const ASN1_TIME *t)
{
	ASN1_TIME *epoch;
	int days = 0, secs = 0;
	int64_t ret = 0;

	if (!t)
		return 0;

	epoch = ASN1_TIME_set(NULL, 0);
	if (epoch && ASN1_TIME_diff(&days, &secs, epoch, t) == 1)
		ret = (int64_t)days * 86400 + secs;

	ASN1_TIME_free(epoch);
	ERR_clear_error();
	return ret;
}

static void esdm_tls_openssl_name(const X509_NAME *name, char *buf, size_t len)
{
	BIO *mem = BIO_new(BIO_s_mem());
	int n;

	snprintf(buf, len, "unknown");
	if (!mem) {
		ERR_clear_error();
		return;
	}

	if (X509_NAME_print_ex(mem, name, 0, XN_FLAG_RFC2253) >= 0) {
		n = BIO_read(mem, buf, (int)(len - 1));
		if (n > 0)
			buf[n] = '\0';
	}

	BIO_free(mem);
	ERR_clear_error();
}

/* A certificate from DER, in the library context of this file */
static X509 *esdm_tls_openssl_x509(const struct esdm_tls_der *der)
{
	const unsigned char *p = der->data;
	X509 *x = X509_new_ex(esdm_tls_openssl_libctx, NULL);

	if (!x)
		return NULL;

	if (der->len > LONG_MAX || !d2i_X509(&x, &p, (long)der->len)) {
		X509_free(x);
		ERR_clear_error();
		return NULL;
	}

	return x;
}

static int esdm_tls_openssl_der(X509 *x, struct esdm_tls_der *der)
{
	unsigned char *p;
	int len = i2d_X509(x, NULL);

	if (len <= 0) {
		ERR_clear_error();
		return -EINVAL;
	}

	der->data = malloc((size_t)len);
	if (!der->data)
		return -ENOMEM;

	p = der->data;
	if (i2d_X509(x, &p) != len) {
		ERR_clear_error();
		free(der->data);
		der->data = NULL;
		return -EINVAL;
	}
	der->len = (size_t)len;

	return 0;
}

/*
 * The verify callback: once OpenSSL verified the whole chain - it signals the
 * certificate of the peer, at depth 0, last -, the revocation policy of
 * esdm_tls.c judges it. Its refusal is a verification error whose alert
 * OpenSSL sends: certificate_revoked, certificate_expired for an expired CRL,
 * unknown_ca for a missing one.
 */
static int esdm_tls_openssl_verify(int ok, X509_STORE_CTX *store)
{
	SSL *ssl = X509_STORE_CTX_get_ex_data(
		store, SSL_get_ex_data_X509_STORE_CTX_idx());
	struct esdm_tls_openssl_conn *c = ssl ? SSL_get_app_data(ssl) : NULL;
	STACK_OF(X509) *sk;
	struct esdm_tls_der *chain;
	int i, n, err = X509_V_ERR_CERT_REJECTED;

	if (!ok || X509_STORE_CTX_get_error_depth(store) != 0)
		return ok;

	/* No connection of ours: fail closed */
	if (!c)
		goto refuse;

	sk = X509_STORE_CTX_get0_chain(store);
	n = sk ? sk_X509_num(sk) : 0;
	if (n <= 0 || n > ESDM_TLS_MAX_CHAIN)
		goto refuse;

	chain = calloc((size_t)n, sizeof(*chain));
	if (!chain) {
		err = X509_V_ERR_OUT_OF_MEM;
		goto refuse;
	}
	for (i = 0; i < n; i++) {
		if (esdm_tls_openssl_der(sk_X509_value(sk, i), &chain[i])) {
			while (i-- > 0)
				free(chain[i].data);
			free(chain);
			goto refuse;
		}
	}

	/* The policy takes the chain over */
	switch (c->check(c->check_arg, chain, (size_t)n)) {
	case esdm_tls_verdict_accepted:
		return 1;
	case esdm_tls_verdict_revoked:
		err = X509_V_ERR_CERT_REVOKED;
		break;
	case esdm_tls_verdict_crl_expired:
		err = X509_V_ERR_CRL_HAS_EXPIRED;
		break;
	case esdm_tls_verdict_no_crl:
		err = X509_V_ERR_UNABLE_TO_GET_CRL;
		break;
	case esdm_tls_verdict_bad_chain:
	default:
		break;
	}

refuse:
	X509_STORE_CTX_set_error(store, err);
	return 0;
}

/*
 * Load the CRLs of @path, every one it holds.
 *
 * @return 0, -EINVAL if it holds none or one that does not parse, -ENOMEM
 */
static int esdm_tls_openssl_load_crls(STACK_OF(X509_CRL) *crls,
				      const char *path)
{
	char err[ESDM_TLS_TEXT_LEN];
	BIO *bio = BIO_new_file(path, "r");
	unsigned int num = 0;
	unsigned long e;

	if (!bio) {
		esdm_tls_openssl_errstr(err, sizeof(err));
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot open the CRL file %s: %s\n", path,
			    err);
		return -EINVAL;
	}

	ERR_clear_error();
	for (;;) {
		X509_CRL *crl = X509_CRL_new_ex(esdm_tls_openssl_libctx, NULL);

		if (!crl) {
			BIO_free(bio);
			ERR_clear_error();
			return -ENOMEM;
		}

		if (!PEM_read_bio_X509_CRL(bio, &crl, NULL, NULL)) {
			X509_CRL_free(crl);
			break;
		}

		if (!sk_X509_CRL_push(crls, crl)) {
			X509_CRL_free(crl);
			BIO_free(bio);
			ERR_clear_error();
			return -ENOMEM;
		}
		num++;
	}
	BIO_free(bio);

	/* The end of the file is no PEM block, anything else is an error */
	e = ERR_peek_last_error();
	if (e && !(ERR_GET_LIB(e) == ERR_LIB_PEM &&
		   ERR_GET_REASON(e) == PEM_R_NO_START_LINE)) {
		esdm_tls_openssl_errstr(err, sizeof(err));
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: the CRL file %s does not parse: %s\n", path,
			    err);
		return -EINVAL;
	}
	ERR_clear_error();

	if (!num) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: the CRL file %s holds no CRL\n", path);
		return -EINVAL;
	}

	return 0;
}

/* The parameter sets of ML-DSA, as OpenSSL names its keys */
static const char *const esdm_tls_openssl_mldsa[] = {
	"ML-DSA-44",
	"ML-DSA-65",
	"ML-DSA-87",
};

/*
 * Is @key one of ML-DSA? Which DTLS 1.2 has no signature for - see
 * "Post-quantum algorithms" in esdm_tls.h. OpenSSL before 3.5 knows no such
 * key, and loads no certificate with one.
 */
static bool esdm_tls_openssl_mldsa_key(const EVP_PKEY *key)
{
	size_t i;

	if (!key)
		return false;
	for (i = 0; i < ARRAY_SIZE(esdm_tls_openssl_mldsa); i++) {
		if (EVP_PKEY_is_a(key, esdm_tls_openssl_mldsa[i]))
			return true;
	}
	return false;
}

/*
 * Does the own certificate chain to the trust anchors? See "Contexts" in
 * esdm_tls.h.
 */
static int esdm_tls_openssl_check_own(SSL_CTX *c, const char *cert_file,
				      const char *ca_file)
{
	X509_STORE_CTX *sctx = X509_STORE_CTX_new_ex(esdm_tls_openssl_libctx,
						     NULL);
	STACK_OF(X509) *chain = NULL;
	int ret = -EINVAL;

	if (!sctx) {
		ERR_clear_error();
		return -ENOMEM;
	}

	SSL_CTX_get0_chain_certs(c, &chain);
	if (X509_STORE_CTX_init(sctx, SSL_CTX_get_cert_store(c),
				SSL_CTX_get0_certificate(c), chain) != 1) {
		ret = -ENOMEM;
		goto out;
	}
	/* The chain, not the time - see "Contexts" in esdm_tls.h */
	X509_STORE_CTX_set_flags(sctx, X509_V_FLAG_NO_CHECK_TIME);

	if (X509_verify_cert(sctx) == 1) {
		ret = 0;
		goto out;
	}

	esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
		    "TLS: the certificate %s does not chain to the trust anchors %s: %s\n",
		    cert_file, ca_file,
		    X509_verify_cert_error_string(
			    X509_STORE_CTX_get_error(sctx)));

out:
	X509_STORE_CTX_free(sctx);
	ERR_clear_error();
	return ret;
}

/******************************************************************************
 * esdm_tls_backend.h
 ******************************************************************************/

const char *esdm_tls_backend_name(void)
{
	return "OpenSSL";
}

void esdm_tls_backend_ctx_free(void *ctx)
{
	struct esdm_tls_openssl_ctx *c = ctx;

	if (!c)
		return;
	SSL_CTX_free(c->ssl_ctx);
	sk_X509_CRL_pop_free(c->crls, X509_CRL_free);
	free(c);
}

/*
 * The files of one side, the same on either transport: the trust anchors, the
 * own certificate with its key - which has to chain to them - and the CRLs,
 * and the verification of the peer - see "Contexts" in esdm_tls.h.
 */
static int esdm_tls_openssl_files(struct esdm_tls_openssl_ctx *oc, bool server,
				  const struct esdm_tls_config *cfg)
{
	char err[ESDM_TLS_TEXT_LEN];
	SSL_CTX *c = oc->ssl_ctx;
	unsigned int i;
	int ret;

	if (SSL_CTX_load_verify_file(c, cfg->ca_file) != 1) {
		esdm_tls_openssl_errstr(err, sizeof(err));
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: cannot load the trust anchors %s: %s\n",
			    cfg->ca_file, err);
		return -EINVAL;
	}

	if (cfg->cert_file) {
		if (SSL_CTX_use_certificate_chain_file(c, cfg->cert_file) !=
		    1) {
			esdm_tls_openssl_errstr(err, sizeof(err));
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "TLS: cannot load the certificate %s: %s\n",
				    cfg->cert_file, err);
			return -EINVAL;
		}
		if (oc->sctp && esdm_tls_openssl_mldsa_key(X509_get0_pubkey(
					SSL_CTX_get0_certificate(c)))) {
			ERR_clear_error();
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the certificate %s is one of ML-DSA, which DTLS 1.2 has no signature for - ML-DSA is for TLS 1.3 only\n",
				cfg->cert_file);
			return -EINVAL;
		}
		if (SSL_CTX_use_PrivateKey_file(c, cfg->key_file,
						SSL_FILETYPE_PEM) != 1) {
			esdm_tls_openssl_errstr(err, sizeof(err));
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "TLS: cannot load the key %s: %s\n",
				    cfg->key_file, err);
			return -EINVAL;
		}
		if (SSL_CTX_check_private_key(c) != 1) {
			esdm_tls_openssl_errstr(err, sizeof(err));
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"TLS: the key %s does not belong to the certificate %s: %s\n",
				cfg->key_file, cfg->cert_file, err);
			return -EINVAL;
		}
		ret = esdm_tls_openssl_check_own(c, cfg->cert_file,
						 cfg->ca_file);
		if (ret)
			return ret;
	}

	for (i = 0; i < cfg->crl_files_num; i++) {
		ret = esdm_tls_openssl_load_crls(oc->crls, cfg->crl_files[i]);
		if (ret)
			return ret;
	}

	if (server) {
		STACK_OF(X509_NAME) *names = SSL_load_client_CA_file_ex(
			cfg->ca_file, esdm_tls_openssl_libctx, NULL);

		/* The CAs the client may choose its certificate by */
		if (names)
			SSL_CTX_set_client_CA_list(c, names);
		ERR_clear_error();

		/* Mutual authentication: no certificate, no connection */
		SSL_CTX_set_verify(c,
				   SSL_VERIFY_PEER |
					   SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
				   esdm_tls_openssl_verify);
	} else {
		SSL_CTX_set_verify(c, SSL_VERIFY_PEER,
				   esdm_tls_openssl_verify);
	}

	return 0;
}

/*
 * TLS 1.3 exactly on a stream socket, and neither tickets nor a session cache:
 * a connection lives as long as it does, with the one handshake it started
 * with.
 */
static int esdm_tls_openssl_stream(SSL_CTX *c)
{
	if (!SSL_CTX_set_min_proto_version(c, TLS1_3_VERSION) ||
	    !SSL_CTX_set_max_proto_version(c, TLS1_3_VERSION) ||
	    !SSL_CTX_set_num_tickets(c, 0))
		return -ENOMEM;
	SSL_CTX_set_options(c, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);

	/*
	 * A write the socket only took part of is continued with the rest, from
	 * wherever the caller keeps it. A server holds many connections, most
	 * of them idle between the requests: no record buffers for those.
	 */
	SSL_CTX_set_mode(c, SSL_MODE_ENABLE_PARTIAL_WRITE |
				    SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
				    SSL_MODE_RELEASE_BUFFERS);
	/* Wipe the plaintext of a record once it is handed out */
	SSL_CTX_set_options(c, SSL_OP_CLEANSE_PLAINTEXT);

	/* ML-KEM first, as far as OpenSSL has it, see above */
	if (SSL_CTX_set1_groups_list(c, ESDM_TLS_OPENSSL_GROUPS) != 1) {
		ERR_clear_error();
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"TLS: OpenSSL %s refused the groups of ML-KEM, its default groups serve\n",
			OpenSSL_version(OPENSSL_VERSION_STRING));
	}

	return 0;
}

/*
 * DTLS 1.2 exactly on SCTP, AEAD ciphers only, and neither renegotiation nor
 * tickets nor a session cache - one handshake, and one key of SCTP-AUTH, per
 * association. No MTU is queried: the one of RFC 6083 is set per connection.
 */
static int esdm_tls_openssl_dtls(SSL_CTX *c)
{
	if (!SSL_CTX_set_min_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_max_proto_version(c, DTLS1_2_VERSION) ||
	    !SSL_CTX_set_cipher_list(c, ESDM_TLS_OPENSSL_DTLS_CIPHERS))
		return -ENOMEM;
	SSL_CTX_set_options(c, SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION |
				       SSL_OP_NO_QUERY_MTU);
	SSL_CTX_set_session_cache_mode(c, SSL_SESS_CACHE_OFF);

	/* As above, a record being one write of its own */
	SSL_CTX_set_mode(c, SSL_MODE_RELEASE_BUFFERS);
	SSL_CTX_set_options(c, SSL_OP_CLEANSE_PLAINTEXT);

	return 0;
}

int esdm_tls_backend_ctx_new(bool server, const struct esdm_tls_config *cfg,
			     void **ctx)
{
	struct esdm_tls_openssl_ctx *oc;
	bool sctp = cfg->transport == ESDM_TLS_TRANSPORT_SCTP;
	SSL_CTX *c;
	int ret;

	pthread_once(&esdm_tls_openssl_once, esdm_tls_openssl_init);
	if (!esdm_tls_openssl_libctx)
		return -ENOMEM;

	oc = calloc(1, sizeof(*oc));
	if (!oc)
		return -ENOMEM;
	oc->sctp = sctp;
	oc->crls = sk_X509_CRL_new_null();
	if (!oc->crls) {
		free(oc);
		return -ENOMEM;
	}

	if (sctp)
		c = SSL_CTX_new_ex(esdm_tls_openssl_libctx, NULL,
				   server ? DTLS_server_method() :
					    DTLS_client_method());
	else
		c = SSL_CTX_new_ex(esdm_tls_openssl_libctx, NULL,
				   server ? TLS_server_method() :
					    TLS_client_method());
	if (!c) {
		ret = -ENOMEM;
		goto err;
	}
	oc->ssl_ctx = c;

	ret = sctp ? esdm_tls_openssl_dtls(c) : esdm_tls_openssl_stream(c);
	if (!ret)
		ret = esdm_tls_openssl_files(oc, server, cfg);
	if (ret)
		goto err;

	*ctx = oc;
	return 0;

err:
	ERR_clear_error();
	esdm_tls_backend_ctx_free(oc);
	return ret;
}

size_t esdm_tls_backend_crl_count(void *ctx)
{
	struct esdm_tls_openssl_ctx *c = ctx;

	return (size_t)sk_X509_CRL_num(c->crls);
}

int esdm_tls_backend_crl_info(void *ctx, size_t idx,
			      struct esdm_tls_crl_info *info)
{
	struct esdm_tls_openssl_ctx *c = ctx;
	X509_CRL *crl;

	if (idx >= (size_t)sk_X509_CRL_num(c->crls))
		return -ENOENT;

	crl = sk_X509_CRL_value(c->crls, (int)idx);
	esdm_tls_openssl_name(X509_CRL_get_issuer(crl), info->issuer,
			      sizeof(info->issuer));
	info->next_update =
		esdm_tls_openssl_time(X509_CRL_get0_nextUpdate(crl));
	info->delta = X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0;
	info->scoped = X509_CRL_get_ext_by_NID(
			       crl, NID_issuing_distribution_point, -1) >= 0;

	return 0;
}

int esdm_tls_backend_crl_lookup(void *ctx, const struct esdm_tls_der *cert,
				const struct esdm_tls_der *issuer,
				struct esdm_tls_crl_result *res)
{
	struct esdm_tls_openssl_ctx *c = ctx;
	X509 *x = esdm_tls_openssl_x509(cert);
	X509 *iss = esdm_tls_openssl_x509(issuer);
	X509_CRL *best = NULL;
	X509_REVOKED *rev = NULL;
	EVP_PKEY *key;
	int i, ret = 0;

	memset(res, 0, sizeof(*res));

	if (!x || !iss) {
		ret = -EINVAL;
		goto out;
	}

	key = X509_get0_pubkey(iss);
	if (!key) {
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < sk_X509_CRL_num(c->crls); i++) {
		X509_CRL *crl = sk_X509_CRL_value(c->crls, i);

		if (X509_NAME_cmp(X509_CRL_get_issuer(crl),
				  X509_get_subject_name(iss)))
			continue;
		if (X509_CRL_verify(crl, key) != 1) {
			ERR_clear_error();
			continue;
		}

		/* Of several, the one issued last */
		if (best && ASN1_TIME_compare(X509_CRL_get0_lastUpdate(crl),
					      X509_CRL_get0_lastUpdate(best)) <=
				    0)
			continue;
		best = crl;
	}

	if (!best)
		goto out;

	res->found = true;
	res->next_update =
		esdm_tls_openssl_time(X509_CRL_get0_nextUpdate(best));
	/* 2 is an entry removeFromCRL, of a delta CRL - which is no CRL here */
	res->revoked = (X509_CRL_get0_by_cert(best, &rev, x) == 1);

out:
	ERR_clear_error();
	X509_free(x);
	X509_free(iss);
	return ret;
}

int esdm_tls_backend_cert_info(const struct esdm_tls_der *cert,
			       struct esdm_tls_cert_info *info)
{
	X509 *x;
	BIGNUM *bn;
	char *hex;

	pthread_once(&esdm_tls_openssl_once, esdm_tls_openssl_init);

	x = esdm_tls_openssl_x509(cert);
	if (!x)
		return -EINVAL;

	esdm_tls_openssl_name(X509_get_subject_name(x), info->subject,
			      sizeof(info->subject));
	info->not_after = esdm_tls_openssl_time(X509_get0_notAfter(x));

	snprintf(info->serial, sizeof(info->serial), "unknown");
	bn = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x), NULL);
	if (bn) {
		hex = BN_bn2hex(bn);
		if (hex) {
			snprintf(info->serial, sizeof(info->serial), "%s", hex);
			OPENSSL_free(hex);
		}
		BN_free(bn);
	}

	ERR_clear_error();
	X509_free(x);
	return 0;
}

int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      struct esdm_tls_sctp *sctp,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn)
{
	struct esdm_tls_openssl_ctx *oc = ctx;
	struct esdm_tls_openssl_conn *c = calloc(1, sizeof(*c));
	unsigned char addr[sizeof(struct in6_addr)];
	BIO *bio;

	if (!c)
		return -ENOMEM;
	c->check = check;
	c->check_arg = arg;
	c->sctp = sctp;

	c->ssl = SSL_new(oc->ssl_ctx);
	if (!c->ssl)
		goto err;
	/* For esdm_tls_openssl_verify() */
	SSL_set_app_data(c->ssl, c);

	if (oc->sctp) {
		if (!sctp)
			goto err;
		bio = BIO_new(esdm_tls_openssl_sctp_meth);
		if (!bio)
			goto err;
		BIO_set_data(bio, c);
		SSL_set_bio(c->ssl, bio, bio);

		/*
		 * The MTU of RFC 6083, and no retransmission of DTLS - see
		 * esdm_tls_openssl_dtls()
		 */
		SSL_set_options(c->ssl, SSL_OP_NO_QUERY_MTU);
		if (!DTLS_set_link_mtu(c->ssl, ESDM_TLS_SCTP_MTU))
			goto err;
		DTLS_set_timer_cb(c->ssl, esdm_tls_openssl_dtls_timer);
	} else {
		bio = BIO_new(esdm_tls_openssl_bio_meth);
		if (!bio)
			goto err;
		BIO_set_data(bio, (void *)(intptr_t)fd);
		/* The SSL owns the BIO from here on, for reading and writing */
		SSL_set_bio(c->ssl, bio, bio);
	}

	if (server) {
		SSL_set_accept_state(c->ssl);
	} else {
		/*
		 * The name the certificate of the server has to be issued for:
		 * an address literal is checked against the IP addresses of
		 * its subject alternative name, and is no server name to
		 * indicate - only a DNS name is.
		 */
		if (inet_pton(AF_INET, server_name, addr) == 1 ||
		    inet_pton(AF_INET6, server_name, addr) == 1) {
			if (X509_VERIFY_PARAM_set1_ip_asc(
				    SSL_get0_param(c->ssl), server_name) != 1)
				goto err;
		} else {
			if (SSL_set1_host(c->ssl, server_name) != 1 ||
			    SSL_set_tlsext_host_name(c->ssl, server_name) != 1)
				goto err;
		}
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

void esdm_tls_backend_conn_free(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;

	if (!c)
		return;
	SSL_free(c->ssl);
	free(c->wpart);
	free(c);
}

int esdm_tls_backend_handshake(void *conn, short *want)
{
	struct esdm_tls_openssl_conn *c = conn;
	int ret;

	ERR_clear_error();
	ret = SSL_do_handshake(c->ssl);

	return ret == 1 ? 0 : esdm_tls_openssl_error(c, ret, want);
}

ssize_t esdm_tls_backend_send(void *conn, const uint8_t *buf, size_t len,
			      short *want)
{
	struct esdm_tls_openssl_conn *c = conn;
	int ret;

	if (len > INT32_MAX)
		len = INT32_MAX;

	ERR_clear_error();
	ret = SSL_write(c->ssl, buf, (int)len);

	return ret > 0 ? ret : esdm_tls_openssl_error(c, ret, want);
}

/* A record is written to the socket as a whole before SSL_write() returns */
int esdm_tls_backend_flush(void *conn, short *want)
{
	(void)conn;
	(void)want;
	return 0;
}

ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len,
			      short *want)
{
	struct esdm_tls_openssl_conn *c = conn;
	int ret;

	if (len > INT32_MAX)
		len = INT32_MAX;

	ERR_clear_error();
	ret = SSL_read(c->ssl, buf, (int)len);

	/* On SCTP, a record whole: what is left of it is no message of ours */
	if (c->sctp && ret > 0 && (size_t)ret == len &&
	    SSL_pending(c->ssl) > 0) {
		snprintf(c->error, sizeof(c->error),
			 "a record larger than %zu bytes", len);
		return -EMSGSIZE;
	}
	if (ret > 0)
		return ret;

	/* The closing alert is the end of the stream, not an error */
	if (SSL_get_error(c->ssl, ret) == SSL_ERROR_ZERO_RETURN) {
		ERR_clear_error();
		return 0;
	}

	return esdm_tls_openssl_error(c, ret, want);
}

bool esdm_tls_backend_pending(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;

	/* Decrypted data only - a record not yet complete is in the socket */
	return SSL_pending(c->ssl) > 0;
}

void esdm_tls_backend_close_notify(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;

	ERR_clear_error();
	SSL_shutdown(c->ssl);
	ERR_clear_error();
}

const char *esdm_tls_backend_cipher(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;

	return SSL_get_cipher_name(c->ssl);
}

const char *esdm_tls_backend_group(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;
	int nid = (int)SSL_get_negotiated_group(c->ssl);

	/* A NID, or the id of TLS of a group of a provider, as OpenSSL has it */
	return nid ? SSL_group_to_name(c->ssl, nid) : NULL;
}

/* The groups of ML-KEM of ESDM_TLS_OPENSSL_GROUPS, in its order */
static const char *const esdm_tls_openssl_mlkem[] = {
	"SecP384r1MLKEM1024",
	"MLKEM1024",
};

/* The first of them OpenSSL takes, in the library context of this file */
const char *esdm_tls_backend_mlkem_group(void)
{
	const char *group = NULL;
	SSL_CTX *c;
	size_t i;

	pthread_once(&esdm_tls_openssl_once, esdm_tls_openssl_init);
	if (!esdm_tls_openssl_libctx)
		return NULL;

	c = SSL_CTX_new_ex(esdm_tls_openssl_libctx, NULL, TLS_method());
	if (!c) {
		ERR_clear_error();
		return NULL;
	}
	for (i = 0; i < ARRAY_SIZE(esdm_tls_openssl_mlkem) && !group; i++) {
		if (SSL_CTX_set1_groups_list(c, esdm_tls_openssl_mlkem[i]) == 1)
			group = esdm_tls_openssl_mlkem[i];
	}
	SSL_CTX_free(c);
	ERR_clear_error();

	return group;
}

/*
 * ML-DSA for certificates and CRLs where its signatures are there, for the
 * handshake where OpenSSL knows its signature schemes of TLS as well - both
 * from 3.5 on
 */
unsigned int esdm_tls_backend_mldsa(void)
{
	unsigned int ret = ESDM_TLS_MLDSA_CA;
	EVP_SIGNATURE *sig;
	SSL_CTX *c;
	size_t i;

	pthread_once(&esdm_tls_openssl_once, esdm_tls_openssl_init);
	if (!esdm_tls_openssl_libctx)
		return 0;

	for (i = 0; i < ARRAY_SIZE(esdm_tls_openssl_mldsa); i++) {
		sig = EVP_SIGNATURE_fetch(esdm_tls_openssl_libctx,
					  esdm_tls_openssl_mldsa[i], NULL);
		if (!sig) {
			ERR_clear_error();
			return 0;
		}
		EVP_SIGNATURE_free(sig);
	}

	c = SSL_CTX_new_ex(esdm_tls_openssl_libctx, NULL, TLS_method());
	if (c && SSL_CTX_set1_sigalgs_list(c, "mldsa44:mldsa65:mldsa87") == 1)
		ret |= ESDM_TLS_MLDSA_AUTH;
	SSL_CTX_free(c);
	ERR_clear_error();

	return ret;
}

const char *esdm_tls_backend_error(void *conn)
{
	struct esdm_tls_openssl_conn *c = conn;

	return c->error;
}

/*
 * The exporter of OpenSSL takes the master secret as soon as it is known,
 * before the handshake is complete - as OpenSSL's own DTLS over SCTP does
 */
int esdm_tls_backend_export(void *conn, const uint8_t *label,
			    size_t label_len, uint8_t *out, size_t out_len)
{
	struct esdm_tls_openssl_conn *c = conn;
	int ret;

	ERR_clear_error();
	ret = SSL_export_keying_material(c->ssl, out, out_len,
					 (const char *)label, label_len, NULL,
					 0, 0);
	ERR_clear_error();

	return ret == 1 ? 0 : -EINVAL;
}
