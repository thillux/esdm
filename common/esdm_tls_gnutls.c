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
 * TLS of esdm_tls_backend.h by GnuTLS, for crypto_backend=gnutls: TLS 1.3 on a
 * stream socket, DTLS 1.2 on SCTP - with the same files, the same verification
 * and the same revocation policy, see esdm_tls_gnutls_files() and
 * esdm_tls_gnutls_verify().
 *
 * GnuTLS reaches the socket through push and pull functions of its own, one
 * send(2) with MSG_NOSIGNAL or recv(2) each on the non-blocking socket, which
 * makes every call return GNUTLS_E_AGAIN rather than wait for the peer. On
 * SCTP, they hand the records - several of a flight in one push - to the
 * association of esdm_tls_sctp.h and take each from it; the session is a
 * datagram one without the replay detection of DTLS, which RFC 6083 rules out
 * (GNUTLS_NO_REPLAY_PROTECTION), and with timeouts too long to ever retransmit.
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
 * TLS 1.3 offers the groups of ML-KEM GnuTLS has ahead of those of NORMAL, and
 * the signature algorithm of ML-DSA-87 where it signs TLS with it, not those
 * of ML-DSA-44 and ML-DSA-65 - see esdm_tls_gnutls_stream_priority() and
 * "Post-quantum algorithms" in esdm_tls.h. GnuTLS has them only when built
 * with leancrypto.
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
 * TLS 1.3 exactly; the tickets are turned off with the session flags. The
 * groups and the signature algorithms are added to it, see
 * esdm_tls_gnutls_stream_priority().
 */
#define ESDM_TLS_GNUTLS_PRIORITY "NORMAL:-VERS-ALL:+VERS-TLS1.3"

/* Room for the priority of TLS 1.3 with its groups and signatures */
#define ESDM_TLS_GNUTLS_PRIORITY_LEN 1024

/*
 * The groups of ML-KEM in the order of esdm_tls.h, as GnuTLS names them -
 * not its hybrids X25519-MLKEM768 and SECP256R1-MLKEM768, of 128 bits. GnuTLS
 * 3.8 knows MLKEM1024, but uses ML-KEM-1024 in TLS only in the hybrid, and
 * leaves it out of what it offers - until it does.
 */
static const char *const esdm_tls_gnutls_mlkem[] = {
	"SECP384R1-MLKEM1024",
	"MLKEM1024",
};

/*
 * The signature algorithms of ML-DSA in the priority: ML-DSA-87 alone, see
 * esdm_tls.h - the NORMAL of 3.8.13 lists the others as well
 */
static const char *const esdm_tls_gnutls_mldsa[] = {
	"-SIGN-ML-DSA-44",
	"-SIGN-ML-DSA-65",
	"+SIGN-ML-DSA-87",
};

/*
 * DTLS 1.2 exactly on SCTP: ECDHE with the key of the certificate, ECDSA or
 * RSA, and AEAD ciphers only - none of ML-KEM nor ML-DSA, which are for TLS 1.3
 * only
 */
#define ESDM_TLS_GNUTLS_DTLS_PRIORITY                                          \
	"NORMAL:-VERS-ALL:+VERS-DTLS1.2:-CIPHER-ALL:+AES-256-GCM:"             \
	"+CHACHA20-POLY1305:+AES-128-GCM:-MAC-ALL:+AEAD:-KX-ALL:"              \
	"+ECDHE-ECDSA:+ECDHE-RSA"

/*
 * The retransmission and the total timeout of the DTLS handshake, in
 * milliseconds: long enough to never run out - SCTP retransmits, DTLS must not
 * (RFC 6083 section 3.5), and the callers bound the handshake themselves
 */
#define ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS (600 * 1000)

/* The extensions of a CRL that is no complete one, see esdm_tls_crl_info */
#define ESDM_TLS_GNUTLS_OID_DELTA_CRL "2.5.29.27"
#define ESDM_TLS_GNUTLS_OID_IDP "2.5.29.28"

struct esdm_tls_gnutls_ctx {
	gnutls_certificate_credentials_t cred;
	gnutls_priority_t prio;
	bool sctp;
	gnutls_x509_crl_t *crls;
	unsigned int crl_num;
	/* The trust anchors of cred, for esdm_tls_gnutls_chain() */
	gnutls_x509_crt_t *cas;
	unsigned int ca_num;
};

struct esdm_tls_gnutls_conn {
	gnutls_session_t session;
	struct esdm_tls_gnutls_ctx *ctx;
	int fd;
	/* The association on SCTP, NULL on a stream socket */
	struct esdm_tls_sctp *sctp;

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

static ssize_t esdm_tls_gnutls_push(gnutls_transport_ptr_t ptr,
				    const void *buf, size_t len)
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

	/* 0 is the end of the stream, which GnuTLS tells apart itself */
	if (n < 0)
		gnutls_transport_set_errno(c->session, errno);

	return n;
}

/* SCTP: the records of a push queued, see esdm_tls_sctp.h */
static ssize_t esdm_tls_gnutls_sctp_push(gnutls_transport_ptr_t ptr,
					 const void *buf, size_t len)
{
	struct esdm_tls_gnutls_conn *c = ptr;
	int ret = esdm_tls_sctp_queue(c->sctp, buf, len);

	if (ret) {
		gnutls_transport_set_errno(c->session, -ret);
		return -1;
	}

	return (ssize_t)len;
}

static ssize_t esdm_tls_gnutls_sctp_pull(gnutls_transport_ptr_t ptr, void *buf,
					 size_t len)
{
	struct esdm_tls_gnutls_conn *c = ptr;
	ssize_t n = esdm_tls_sctp_recv(c->sctp, buf, len);

	/*
	 * The end of the association is an error to a datagram session, which
	 * would take 0 for an empty datagram
	 */
	if (n < 0) {
		gnutls_transport_set_errno(c->session, (int)-n);
		return -1;
	}

	return n;
}

/*
 * Is a message there? Always, to the DTLS of GnuTLS - and the pull tells
 * whether one really is. The answer only decides whether it retransmits its
 * flight, which it must not on SCTP. And it asks before it reads the Finished
 * of the peer even when it parsed that Finished already, with the
 * ChangeCipherSpec before it - on UDP the two come in one datagram, on SCTP
 * each in a user message of its own: an answer by the socket would have the
 * handshake wait for a message that is not to come.
 */
static int esdm_tls_gnutls_sctp_pull_timeout(gnutls_transport_ptr_t ptr,
					     unsigned int ms)
{
	(void)ptr;
	(void)ms;
	return 1;
}

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
	default:
		if (!gnutls_error_is_fatal(ret)) {
			/* A warning alert and the like: try again */
			*want = POLLOUT;
			return -EAGAIN;
		}
		snprintf(c->error, sizeof(c->error), "%s",
			 gnutls_strerror(ret));
		return -EPROTO;
	}
}

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
 * Does GnuTLS have the public key algorithm @name - of ML-DSA, which is the
 * name of its signature algorithm as well? Asked of the public key algorithms
 * it has, as the signature algorithms it reports having (gnutls_sign_list())
 * leave those of ML-DSA out, 3.8.13 included, whether it has them or not.
 */
static bool esdm_tls_gnutls_has_pk(const char *name)
{
	const gnutls_pk_algorithm_t *pk;
	const char *n;

	/* The ones it has, not all it knows the name of */
	for (pk = gnutls_pk_list(); pk && *pk; pk++) {
		n = gnutls_pk_get_name(*pk);
		if (n && !strcasecmp(n, name))
			return true;
	}
	return false;
}

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
 * The priority of TLS 1.3, ESDM_TLS_GNUTLS_PRIORITY with the groups in the
 * order of esdm_tls.h: those of ML-KEM GnuTLS has, then those of NORMAL but
 * any of ML-KEM it may list - for "+" appends, the groups are listed anew.
 * Of the signature algorithms of ML-DSA, ML-DSA-87 is added where GnuTLS signs
 * TLS with it, ML-DSA-44 and ML-DSA-65 taken out. GnuTLS refuses a priority
 * naming a group it does not have, and one built without leancrypto has none
 * of ML-KEM: the string names only what GnuTLS reports - and should it be
 * refused nevertheless, NORMAL's groups serve.
 */
static int esdm_tls_gnutls_stream_priority(gnutls_priority_t *prio)
{
	char str[ESDM_TLS_GNUTLS_PRIORITY_LEN];
	gnutls_priority_t normal;
	const unsigned int *groups;
	const char *name;
	size_t len, i;
	int n, ret = 0;

	len = (size_t)snprintf(str, sizeof(str), "%s:-GROUP-ALL",
			       ESDM_TLS_GNUTLS_PRIORITY);
	for (i = 0; i < ARRAY_SIZE(esdm_tls_gnutls_mlkem) && !ret; i++) {
		if (gnutls_group_get_id(esdm_tls_gnutls_mlkem[i]) !=
		    GNUTLS_GROUP_INVALID)
			ret = esdm_tls_gnutls_prio_add(
				str, &len, "+GROUP-", esdm_tls_gnutls_mlkem[i]);
	}

	if (gnutls_priority_init(&normal, ESDM_TLS_GNUTLS_PRIORITY, NULL) < 0)
		return -ENOMEM;
	n = gnutls_priority_group_list(normal, &groups);
	for (i = 0; n > 0 && i < (size_t)n && !ret; i++) {
		name = gnutls_group_get_name((gnutls_group_t)groups[i]);
		/* Hybrids of 128 bits as well, see esdm_tls_gnutls_mlkem */
		if (name && !strstr(name, "MLKEM") && !strstr(name, "KYBER"))
			ret = esdm_tls_gnutls_prio_add(str, &len, "+GROUP-",
						       name);
	}
	gnutls_priority_deinit(normal);

	if (esdm_tls_backend_mldsa() & ESDM_TLS_MLDSA_AUTH) {
		for (i = 0; i < ARRAY_SIZE(esdm_tls_gnutls_mldsa) && !ret; i++)
			ret = esdm_tls_gnutls_prio_add(
				str, &len, "", esdm_tls_gnutls_mldsa[i]);
	}

	if (!ret) {
		ret = gnutls_priority_init(prio, str, NULL);
		if (ret >= 0)
			return 0;
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "TLS: GnuTLS refused the priority %s: %s\n", str,
			    gnutls_strerror(ret));
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "TLS: the groups of NORMAL serve, without ML-KEM\n");
	if (gnutls_priority_init(prio, ESDM_TLS_GNUTLS_PRIORITY, NULL) < 0)
		return -ENOMEM;
	return 0;
}

/*
 * Of ML-DSA, a certificate on ML-DSA-87 alone, and on a stream socket alone -
 * DTLS 1.2 has no signature for it, see "Post-quantum algorithms" in
 * esdm_tls.h
 */
static int esdm_tls_gnutls_check_key(struct esdm_tls_gnutls_ctx *c,
				     const char *cert_file)
{
	gnutls_x509_crt_t *crts = NULL;
	unsigned int num = 0, i;
	const char *name = NULL;
	int ret, pk;

	ret = gnutls_certificate_get_x509_crt(c->cred, 0, &crts, &num);
	if (ret < 0 || !num)
		return -EINVAL;

	pk = gnutls_x509_crt_get_pk_algorithm(crts[0], NULL);
	if (pk > 0)
		name = gnutls_pk_get_name((gnutls_pk_algorithm_t)pk);
	ret = 0;
	if (name && !strncasecmp(name, "ML-DSA", 6) &&
	    (c->sctp || strcasecmp(name, "ML-DSA-87"))) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"TLS: the certificate %s is one of %s, %s\n", cert_file,
			name,
			c->sctp ?
				"which DTLS 1.2 has no signature for - ML-DSA is for TLS 1.3 only" :
				"which is not taken - of ML-DSA, only ML-DSA-87 is");
		ret = -EINVAL;
	}

	for (i = 0; i < num; i++)
		gnutls_x509_crt_deinit(crts[i]);
	gnutls_free(crts);

	return ret;
}

/*
 * Does the key of the credentials belong to their certificate, when that is
 * one of ML-DSA? GnuTLS checks a key by a signature of it the certificate
 * verifies, but finds no signature algorithm of ML-DSA for that check (3.8.13)
 * and takes any key of the algorithm of the certificate then: the check is
 * made here, with the signature algorithm of the name of the key's.
 *
 * @return 0, -EINVAL if it does not belong
 */
static int esdm_tls_gnutls_check_match(struct esdm_tls_gnutls_ctx *c,
				       const struct esdm_tls_config *cfg)
{
	static const char text[] = "a key of esdm_tls and its certificate";
	gnutls_datum_t data = { (unsigned char *)text, sizeof(text) - 1 };
	gnutls_datum_t sig = { NULL, 0 };
	gnutls_x509_privkey_t x509key = NULL;
	gnutls_x509_crt_t *crts = NULL;
	gnutls_privkey_t key = NULL;
	gnutls_pubkey_t pub = NULL;
	gnutls_sign_algorithm_t sign;
	unsigned int num = 0, i;
	const char *name = NULL;
	int pk, ret = -EINVAL;

	if (gnutls_certificate_get_x509_crt(c->cred, 0, &crts, &num) < 0 ||
	    !num)
		return -EINVAL;

	pk = gnutls_x509_crt_get_pk_algorithm(crts[0], NULL);
	if (pk > 0)
		name = gnutls_pk_get_name((gnutls_pk_algorithm_t)pk);
	if (!name || strncasecmp(name, "ML-DSA", 6)) {
		ret = 0;
		goto out;
	}

	sign = gnutls_sign_get_id(name);
	if (sign == GNUTLS_SIGN_UNKNOWN ||
	    gnutls_certificate_get_x509_key(c->cred, 0, &x509key) < 0 ||
	    gnutls_privkey_init(&key) < 0 ||
	    gnutls_privkey_import_x509(key, x509key, 0) < 0 ||
	    gnutls_pubkey_init(&pub) < 0 ||
	    gnutls_pubkey_import_x509(pub, crts[0], 0) < 0 ||
	    gnutls_privkey_sign_data2(key, sign, 0, &data, &sig) < 0 ||
	    gnutls_pubkey_verify_data2(pub, sign, 0, &data, &sig) < 0) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "TLS: the key %s does not belong to the certificate %s\n",
			    cfg->key_file, cfg->cert_file);
		goto out;
	}
	ret = 0;

out:
	gnutls_free(sig.data);
	if (pub)
		gnutls_pubkey_deinit(pub);
	if (key)
		gnutls_privkey_deinit(key);
	if (x509key)
		gnutls_x509_privkey_deinit(x509key);
	for (i = 0; i < num; i++)
		gnutls_x509_crt_deinit(crts[i]);
	gnutls_free(crts);

	return ret;
}

/******************************************************************************
 * esdm_tls_backend.h
 ******************************************************************************/

const char *esdm_tls_backend_name(void)
{
	return "GnuTLS";
}

/* The first group of ML-KEM GnuTLS has */
const char *esdm_tls_backend_mlkem_group(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(esdm_tls_gnutls_mlkem); i++) {
		if (gnutls_group_get_id(esdm_tls_gnutls_mlkem[i]) !=
		    GNUTLS_GROUP_INVALID)
			return esdm_tls_gnutls_mlkem[i];
	}
	return NULL;
}

/*
 * ML-DSA-87 for certificates and CRLs where GnuTLS has its signatures - when
 * built with leancrypto, 3.8.9 and later -, for the handshake of TLS from
 * 3.8.10 on
 */
unsigned int esdm_tls_backend_mldsa(void)
{
	if (!esdm_tls_gnutls_has_pk("ML-DSA-87"))
		return 0;

	return ESDM_TLS_MLDSA_CA |
	       (gnutls_check_version("3.8.10") ? ESDM_TLS_MLDSA_AUTH : 0);
}

void esdm_tls_backend_ctx_free(void *ctx)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
	unsigned int i;

	if (!c)
		return;
	if (c->prio)
		gnutls_priority_deinit(c->prio);
	if (c->cred)
		gnutls_certificate_free_credentials(c->cred);
	for (i = 0; i < c->crl_num; i++)
		gnutls_x509_crl_deinit(c->crls[i]);
	free(c->crls);
	for (i = 0; i < c->ca_num; i++)
		gnutls_x509_crt_deinit(c->cas[i]);
	free(c->cas);
	free(c);
}

/*
 * The files of one side, the same on either transport: the trust anchors, the
 * own certificate with its key - which has to chain to them - and the CRLs -
 * see "Contexts" in esdm_tls.h.
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
		ret = esdm_tls_gnutls_check_key(c, cfg->cert_file);
		if (!ret)
			ret = esdm_tls_gnutls_check_match(c, cfg);
		if (ret)
			return ret;
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

	return 0;
}

int esdm_tls_backend_ctx_new(bool server, const struct esdm_tls_config *cfg,
			     void **ctx)
{
	struct esdm_tls_gnutls_ctx *c = calloc(1, sizeof(*c));
	int ret;

	(void)server;

	if (!c)
		return -ENOMEM;
	c->sctp = cfg->transport == ESDM_TLS_TRANSPORT_SCTP;

	if (gnutls_certificate_allocate_credentials(&c->cred) < 0) {
		c->cred = NULL;
		ret = -ENOMEM;
		goto err;
	}
	if (c->sctp) {
		if (gnutls_priority_init(&c->prio,
					 ESDM_TLS_GNUTLS_DTLS_PRIORITY,
					 NULL) < 0) {
			c->prio = NULL;
			ret = -ENOMEM;
			goto err;
		}
	} else {
		ret = esdm_tls_gnutls_stream_priority(&c->prio);
		if (ret) {
			c->prio = NULL;
			goto err;
		}
	}

	ret = esdm_tls_gnutls_files(c, cfg);
	if (ret)
		goto err;

	*ctx = c;
	return 0;

err:
	esdm_tls_backend_ctx_free(c);
	return ret;
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
 * The verify function of the session: the chain and the names and the key
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

int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      struct esdm_tls_sctp *sctp,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn)
{
	struct esdm_tls_gnutls_ctx *c = ctx;
	struct esdm_tls_gnutls_conn *d;
	unsigned char addr[sizeof(struct in6_addr)];
	unsigned int flags = (server ? GNUTLS_SERVER : GNUTLS_CLIENT) |
			     GNUTLS_NONBLOCK | GNUTLS_NO_TICKETS;

	if (c->sctp != !!sctp)
		return -EINVAL;

	d = calloc(1, sizeof(*d));
	if (!d)
		return -ENOMEM;
	d->fd = fd;
	d->ctx = c;
	d->sctp = sctp;
	d->check = check;
	d->check_arg = arg;

	/* No replay detection of DTLS on SCTP, see the file header */
	if (sctp)
		flags |= GNUTLS_DATAGRAM | GNUTLS_NO_REPLAY_PROTECTION;

	if (gnutls_init(&d->session, flags) < 0) {
		free(d);
		return -ENOMEM;
	}

	if (gnutls_priority_set(d->session, c->prio) < 0 ||
	    gnutls_credentials_set(d->session, GNUTLS_CRD_CERTIFICATE,
				   c->cred) < 0)
		goto err;

	if (server) {
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
		if (strlen(server_name) >= sizeof(d->server_name))
			goto err;
		strcpy(d->server_name, server_name);
		d->vdata[d->vdata_num].type = GNUTLS_DT_DNS_HOSTNAME;
		d->vdata[d->vdata_num++].data =
			(unsigned char *)d->server_name;
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

	gnutls_session_set_ptr(d->session, d);
	gnutls_session_set_verify_function(d->session, esdm_tls_gnutls_verify);

	gnutls_transport_set_ptr(d->session, d);
	if (sctp) {
		gnutls_transport_set_push_function(d->session,
						   esdm_tls_gnutls_sctp_push);
		gnutls_transport_set_pull_function(d->session,
						   esdm_tls_gnutls_sctp_pull);
		gnutls_transport_set_pull_timeout_function(
			d->session, esdm_tls_gnutls_sctp_pull_timeout);

		/* The MTU of RFC 6083, and no retransmission of DTLS */
		gnutls_dtls_set_mtu(d->session, ESDM_TLS_SCTP_MTU);
		gnutls_dtls_set_timeouts(d->session,
					 ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS,
					 ESDM_TLS_GNUTLS_DTLS_TIMEOUT_MS);
	} else {
		gnutls_transport_set_push_function(d->session,
						   esdm_tls_gnutls_push);
		gnutls_transport_set_pull_function(d->session,
						   esdm_tls_gnutls_pull);
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

int esdm_tls_backend_handshake(void *conn, short *want)
{
	struct esdm_tls_gnutls_conn *d = conn;
	int ret = gnutls_handshake(d->session), err;

	if (ret == GNUTLS_E_SUCCESS)
		return 0;

	err = esdm_tls_gnutls_error(d, ret, want);
	if (err != -EAGAIN)
		esdm_tls_gnutls_alert(d, ret);
	return err;
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

ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len,
			      short *want)
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

	/* On SCTP, a record whole, or none */
	if (d->sctp && data.size > len) {
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

const char *esdm_tls_backend_cipher(void *conn)
{
	struct esdm_tls_gnutls_conn *d = conn;
	const char *name =
		gnutls_cipher_get_name(gnutls_cipher_get(d->session));

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

/*
 * The exporter of GnuTLS takes the master secret of the security parameters
 * of the session being negotiated, which it holds from the key exchange on -
 * before the handshake is complete. A context of NULL is no context, unlike
 * an empty one.
 */
int esdm_tls_backend_export(void *conn, const uint8_t *label,
			    size_t label_len, uint8_t *out, size_t out_len)
{
	struct esdm_tls_gnutls_conn *d = conn;
	int ret = gnutls_prf_rfc5705(d->session, label_len, (const char *)label,
				     0, NULL, out_len, (char *)out);

	if (ret < 0) {
		snprintf(d->error, sizeof(d->error), "exporter: %s",
			 gnutls_strerror(ret));
		return -EINVAL;
	}

	return 0;
}
