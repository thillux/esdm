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
 * What a crypto backend provides for esdm_tls.h: TLS 1.3 with certificates
 * from PEM files on a connected, non-blocking stream socket, DTLS 1.2 with the
 * same certificates on an SCTP association, and the parsing of certificates
 * and CRLs the revocation check needs. The reference counting of the
 * contexts, the revocation policy, the fingerprint and the waiting are backend
 * independent - esdm_tls.c -, and so is everything of SCTP - esdm_tls_sctp.c.
 *
 * The files and their checks, the verification of the peer and the revocation
 * policy are the same for either transport: a backend differs in the protocol
 * version, the ciphers, the groups and the signature schemes it sets up - the
 * ones of ML-KEM and ML-DSA on a stream socket only, see "Post-quantum
 * algorithms" in esdm_tls.h -, and in how it reaches the socket.
 *
 * Every function that has to wait for the socket returns -EAGAIN and stores
 * what it waits for, POLLIN or POLLOUT, in *want. A stream socket is reached
 * with send(2) with MSG_NOSIGNAL and recv(2) only. On SCTP, the backend hands
 * every record it writes to esdm_tls_sctp_queue() and reads every one with
 * esdm_tls_sctp_recv(), whole - see esdm_tls_sctp.h; the TLS stack is told a
 * path MTU of ESDM_TLS_SCTP_MTU, sends no retransmissions of its own, and
 * neither renegotiates nor resumes.
 *
 * The TLS stack's own revocation checks stay off: the CRLs are loaded into the
 * context next to the TLS configuration, not into it. The revocation policy of
 * esdm_tls.c is run from the verification of the TLS stack instead, see
 * esdm_tls_backend_check, so that a peer it refuses is refused in the
 * handshake, with the alert of the reason - as one the TLS stack refuses.
 */

#ifndef _ESDM_TLS_BACKEND_H
#define _ESDM_TLS_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "esdm_tls.h"
#include "esdm_tls_sctp.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Longest text of an error, a subject or a cipher name kept for the log,
 * terminating NUL included
 */
#define ESDM_TLS_TEXT_LEN 256

/* Longest chain a peer is held to */
#define ESDM_TLS_MAX_CHAIN 16

/* A certificate in DER */
struct esdm_tls_der {
	uint8_t *data;
	size_t len;
};

/* What the revocation check needs to know about a certificate */
struct esdm_tls_cert_info {
	char subject[ESDM_TLS_TEXT_LEN];
	/* Serial number in hex, for the log */
	char serial[80];
	/* Seconds since the epoch, 0 if the TLS stack cannot tell */
	int64_t not_after;
};

/* The CRL of a certificate, see esdm_tls_backend_crl_lookup() */
struct esdm_tls_crl_result {
	/* A CRL of the issuer, correctly signed by it, was found */
	bool found;
	/*
	 * Its nextUpdate in seconds since the epoch, 0 if it has none - or the
	 * TLS stack cannot tell it, as with a time_t of 32 bits beyond 2038
	 */
	int64_t next_update;
	/* It lists the certificate */
	bool revoked;
};

/* A CRL of a context, see esdm_tls_backend_crl_info() */
struct esdm_tls_crl_info {
	char issuer[ESDM_TLS_TEXT_LEN];
	int64_t next_update;
	/*
	 * A delta CRL (extension deltaCRLIndicator, 2.5.29.27), or one whose
	 * issuing distribution point (2.5.29.28) limits what it covers: no
	 * complete list of the revoked certificates of its issuer, which the
	 * policy of esdm_tls.c needs - see esdm_tls_ctx_alloc().
	 */
	bool delta;
	bool scoped;
};

/* What the revocation policy makes of the chain of a peer */
enum esdm_tls_verdict {
	esdm_tls_verdict_accepted = 0,
	/* A certificate of the chain is revoked: alert certificate_revoked */
	esdm_tls_verdict_revoked,
	/* The CRL covering a certificate expired: alert certificate_expired */
	esdm_tls_verdict_crl_expired,
	/* No CRL covers a certificate that needs one: alert unknown_ca */
	esdm_tls_verdict_no_crl,
	/* A certificate of the chain does not parse: alert bad_certificate */
	esdm_tls_verdict_bad_chain,
};

/*
 * The revocation policy of esdm_tls.c, which a backend runs on the chain of
 * the peer once the TLS stack verified it - in the verification of the TLS
 * stack, so that the handshake fails with the alert of the verdict otherwise.
 * @arg is what esdm_tls_backend_conn_new() was handed.
 *
 * @chain is the chain as the TLS stack verified it: the certificate of the
 * peer first, each following one the issuer of the one before, the trust
 * anchor last. At most ESDM_TLS_MAX_CHAIN, each allocated with malloc(3), as
 * is the array - all of which the check takes over, whatever its verdict.
 */
typedef enum esdm_tls_verdict (*esdm_tls_backend_check)(
	void *arg, struct esdm_tls_der *chain, size_t num);

/* Name of the TLS stack, for logging */
const char *esdm_tls_backend_name(void);

/*
 * @return 0 or a negative errno; *ctx is the context of one side, see
 *	   esdm_tls_ctx_alloc(), for the transport cfg->transport. A failure is
 *	   logged here, with what the TLS stack said about it.
 */
int esdm_tls_backend_ctx_new(bool server, const struct esdm_tls_config *cfg,
			     void **ctx);
void esdm_tls_backend_ctx_free(void *ctx);

/* Number of CRLs the context loaded */
size_t esdm_tls_backend_crl_count(void *ctx);

/* @return 0, or -ENOENT for an @idx past the CRLs of the context */
int esdm_tls_backend_crl_info(void *ctx, size_t idx,
			      struct esdm_tls_crl_info *info);

/*
 * The CRL of the certificate @cert issued by @issuer, both in DER: the most
 * recently issued one of the CRLs of the context whose issuer is the subject
 * of @issuer and whose signature verifies with its key.
 *
 * @return 0 - with res->found telling whether there is one -, a negative errno
 *	   if a certificate does not parse
 */
int esdm_tls_backend_crl_lookup(void *ctx, const struct esdm_tls_der *cert,
				const struct esdm_tls_der *issuer,
				struct esdm_tls_crl_result *res);

/* @return 0, or a negative errno if @cert does not parse */
int esdm_tls_backend_cert_info(const struct esdm_tls_der *cert,
			       struct esdm_tls_cert_info *info);

/*
 * @return 0 or a negative errno; *conn is the TLS of the connection on @fd -
 *	   on SCTP, of the association @sctp, NULL on a stream socket. A
 *	   client is handed the name it expects the server to have, which the
 *	   backend keeps a copy of. @check with @arg is run on the chain of the
 *	   peer, see esdm_tls_backend_check - a peer whose chain is not handed
 *	   to it is refused.
 */
int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      struct esdm_tls_sctp *sctp,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn);
void esdm_tls_backend_conn_free(void *conn);

/* @return 0 when complete, -EAGAIN while waiting, a negative errno */
int esdm_tls_backend_handshake(void *conn, short *want);

/* @return bytes taken, -EAGAIN if none, a negative errno */
ssize_t esdm_tls_backend_send(void *conn, const uint8_t *buf, size_t len,
			      short *want);

/* @return 0 when everything is out, -EAGAIN while not, a negative errno */
int esdm_tls_backend_flush(void *conn, short *want);

/*
 * @return bytes received, 0 after a closing alert, -EAGAIN if none yet,
 *	   -ECONNRESET at the end of the connection without a closing alert,
 *	   another negative errno
 */
ssize_t esdm_tls_backend_recv(void *conn, uint8_t *buf, size_t len,
			      short *want);

/* Is data decrypted already that the socket will not signal any more? */
bool esdm_tls_backend_pending(void *conn);

/* Send the closing alert if the socket takes it right away */
void esdm_tls_backend_close_notify(void *conn);

/* Name of the cipher suite in use */
const char *esdm_tls_backend_cipher(void *conn);

/* Name of the key exchange group in use, NULL if there is none yet */
const char *esdm_tls_backend_group(void *conn);

/*
 * The ML-KEM group of TLS 1.3 two sides of the TLS stack agree on, NULL if it
 * has none - see esdm_tls_mlkem_group()
 */
const char *esdm_tls_backend_mlkem_group(void);

/* ESDM_TLS_MLDSA_CA and ESDM_TLS_MLDSA_AUTH - see esdm_tls_mldsa() */
unsigned int esdm_tls_backend_mldsa(void);

/*
 * The keying material exporter of RFC 5705 - DTLS 1.2 - with the label @label
 * of @label_len bytes and no context, into @out of @out_len bytes. Called on
 * SCTP only, and as soon as the master secret is known on either side: when
 * the first ChangeCipherSpec of the connection goes out - in the middle of the
 * handshake, see esdm_tls_sctp.h.
 *
 * @return 0, or a negative errno
 */
int esdm_tls_backend_export(void *conn, const uint8_t *label,
			    size_t label_len, uint8_t *out, size_t out_len);

/* Why the connection failed, NULL or empty if the backend does not know */
const char *esdm_tls_backend_error(void *conn);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_TLS_BACKEND_H */
