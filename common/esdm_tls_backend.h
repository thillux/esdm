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
 * What a crypto backend provides: the (D)TLS of its TLS stack on each
 * transport of enum esdm_tls_transport -
 *
 *  - TLS 1.3 with certificates from PEM files on a connected, non-blocking
 *    stream socket: the TLS of esdm_tls.h,
 *  - DTLS 1.2 with the pre-shared key below on a connected, non-blocking
 *    SOCK_SEQPACKET socket, one record per message of the socket: the local
 *    DTLS of esdm_dtls.h, which needs no files -
 *
 * and the parsing of certificates and CRLs the revocation check needs. One
 * backend per TLS stack, with one set-up of the library, one error mapping
 * and one connection for both: a transport differs in the protocol version,
 * the ciphers, the groups and the signature schemes it sets up, and in how it
 * reaches the socket.
 *
 * Two layers sit on top, both backend independent: esdm_dtls.c, the messages
 * of the local DTLS on top of the records of the core functions below, which
 * it calls with the busy marker of the thread set (esdm_dtls_busy()), so that
 * the randomness the TLS stack draws cannot loop back into the connection;
 * and esdm_tls.c, the TLS with certificates: the reference counting of the
 * contexts, the revocation policy, the fingerprint and the waiting.
 *
 * The core functions are all a library with the local DTLS alone needs, and
 * they reach nothing of the certificates: those are loaded, and the
 * verification of the peer installed, by esdm_tls_backend_ctx_files(). A build
 * without esdm_tls.h (ESDM_TLS_AUTH) does not compile the functions of the
 * certificates, and in a build with it the linker drops them from a library
 * that does not call them.
 *
 * The secure minimal mode: every context of every transport is set up so that
 * a connection carries the one full handshake it started with, and nothing of
 * it outlives the connection - in one place per backend, see there:
 *
 *  - no session cache, no session ID and no ticket of TLS 1.2 or TLS 1.3 to
 *    resume a session with, issued or asked for, and no pre-shared key of
 *    resumption - the only pre-shared key is the one of the local DTLS, the
 *    key exchange of its suites;
 *  - no early data (0-RTT);
 *  - no renegotiation either way, and no post-handshake authentication;
 *  - no compression and no heartbeat;
 *  - DTLS 1.2 with the extended master secret (RFC 7627) and, for a CBC suite,
 *    Encrypt-then-MAC (RFC 7366) - both required: a session without them is
 *    refused. TLS 1.3 has the one built in and no CBC suite.
 *
 * What a TLS stack sends nevertheless, with nothing to resume: a client of
 * Botan an empty session_ticket extension in its ClientHello of DTLS 1.2, and
 * a server of GnuTLS or Botan a session ID in its ServerHello of DTLS 1.2 - a
 * session no session cache keeps. The ClientHello of TLS 1.3 carries the random
 * legacy session ID of the middlebox compatibility. The tests read all of it
 * off the wire, see tests/test_tls_wire.h.
 *
 * Every function that has to wait for the socket returns -EAGAIN and stores
 * what it waits for, POLLIN or POLLOUT, in *want. The socket is reached with
 * send(2) with MSG_NOSIGNAL and recv(2) only. On SOCK_SEQPACKET, the TLS stack
 * is told a link MTU no record exceeds, does not retransmit - the connection
 * is reliable - and has no cookie exchange: a connected Unix domain socket has
 * no address to spoof.
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

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_dtls;

/*
 * Longest text of an error, a subject or a cipher name kept for the log,
 * terminating NUL included
 */
#define ESDM_TLS_TEXT_LEN 256

/* Longest chain a peer is held to */
#define ESDM_TLS_MAX_CHAIN 16

/*
 * The local DTLS: DTLS 1.2, ECDHE-PSK with AES-256 on curves of 256 bits of
 * security or more, see esdm_dtls.h.
 *
 * The pre-shared key and its identity are constants of the ESDM, the same in
 * every build and every process, and no secret: the key is the SHA-256 of the
 * identity, printf %s esdm-opportunistic-dtls | sha256sum. They only let the
 * TLS stacks run the key exchange without a certificate - what a peer is
 * trusted for is still what the kernel says about it.
 */
#define ESDM_DTLS_PSK_IDENTITY "esdm-opportunistic-dtls"
#define ESDM_DTLS_PSK_LEN 32
extern const uint8_t esdm_dtls_psk[ESDM_DTLS_PSK_LEN];

/*
 * The link MTU of the local DTLS: a record of ESDM_DTLS_PART_SIZE + 1 bytes
 * plus its overhead fits without fragmentation. A SOCK_SEQPACKET message is not
 * bound by an MTU, the DTLS layer would not know that.
 */
#define ESDM_DTLS_LINK_MTU 16700

/* A certificate in DER */
struct esdm_tls_der {
	uint8_t *data;
	size_t len;
};

/* What the checks of a chain need to know about a certificate */
struct esdm_tls_cert_info {
	char subject[ESDM_TLS_TEXT_LEN];
	/* Serial number in hex, for the log */
	char serial[80];
	/* Seconds since the epoch, 0 if the TLS stack cannot tell */
	int64_t not_after;
	/*
	 * The OID of the algorithm of its key, dotted - empty if the TLS stack
	 * cannot tell -, for the keys taken, see "Algorithms" in esdm_tls.h
	 */
	char key_oid[64];
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
	/*
	 * A certificate of the chain does not parse, or is on a key that is not
	 * taken - ML-DSA or EdDSA, say: alert bad_certificate
	 */
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

/******************************************************************************
 * The core: either transport
 ******************************************************************************/

/* Name of the TLS stack, for logging */
const char *esdm_tls_backend_name(void);

/*
 * The context of one side for @transport, its protocol set up: complete for
 * the local DTLS, to be completed with esdm_tls_backend_ctx_files() for the
 * TLS with certificates.
 *
 * @return 0 or a negative errno
 */
int esdm_tls_backend_ctx_new(bool server, enum esdm_tls_transport transport,
			     void **ctx);
void esdm_tls_backend_ctx_free(void *ctx);

/*
 * @return 0 or a negative errno; *conn is the (D)TLS of the connection on @fd.
 *	   A client of the TLS with certificates is handed the name it expects
 *	   the server to have, which the backend keeps a copy of, and @check
 *	   with @arg is run on the chain of the peer, see esdm_tls_backend_check
 *	   - a peer whose chain is not handed to it is refused. The local DTLS
 *	   has neither: NULL.
 */
int esdm_tls_backend_conn_new(void *ctx, bool server, int fd,
			      const char *server_name,
			      esdm_tls_backend_check check, void *arg,
			      void **conn);
void esdm_tls_backend_conn_free(void *conn);

/* @return 0 when complete, -EAGAIN while waiting, a negative errno */
int esdm_tls_backend_handshake(void *conn, short *want);

/*
 * On SOCK_SEQPACKET, @len bytes are one record, taken whole or not at all.
 *
 * @return bytes taken, -EAGAIN if none, a negative errno
 */
ssize_t esdm_tls_backend_send(void *conn, const uint8_t *buf, size_t len,
			      short *want);

/* @return 0 when everything is out, -EAGAIN while not, a negative errno */
int esdm_tls_backend_flush(void *conn, short *want);

/*
 * On SOCK_SEQPACKET, one record, whole - a record larger than @len is
 * -EMSGSIZE.
 *
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

/* Why the connection failed, NULL or empty if the backend does not know */
const char *esdm_tls_backend_error(void *conn);

/******************************************************************************
 * The certificates: the TLS of esdm_tls.h alone
 ******************************************************************************/

/*
 * The files of @cfg into a context of esdm_tls_backend_ctx_new(), and the
 * verification of the peer, see esdm_tls_ctx_alloc().
 *
 * @return 0 or a negative errno - a failure is logged here, with what the TLS
 *	   stack said about it
 */
int esdm_tls_backend_ctx_files(void *ctx, bool server,
			       const struct esdm_tls_config *cfg);

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
 * The hybrid group of ML-KEM of TLS 1.3, NULL if the TLS stack does not have
 * it - see esdm_tls_mlkem_group()
 */
const char *esdm_tls_backend_mlkem_group(void);

/* An IPv6 address as server name is checked, see esdm_tls_ip6_name() */
bool esdm_tls_backend_ip6_name(void);

/******************************************************************************
 * The records under the messages of esdm_dtls.h
 ******************************************************************************/

/*
 * The records of a connection of esdm_dtls.h: those of the core functions
 * above for the local DTLS - the very functions -, those of the TLS of
 * esdm_tls.h on TCP for es-ext-net, see esdm_dtls_tls.c. Each is the core
 * function of its name; free releases the connection.
 */
struct esdm_dtls_ops {
	int (*handshake)(void *conn, short *want);
	ssize_t (*send)(void *conn, const uint8_t *buf, size_t len,
			short *want);
	int (*flush)(void *conn, short *want);
	ssize_t (*recv)(void *conn, uint8_t *buf, size_t len, short *want);
	bool (*pending)(void *conn);
	const char *(*cipher)(void *conn);
	void (*free)(void *conn);
};

/*
 * A connection of the records of @ops on @conn, which it takes over.
 *
 * @return 0, or -ENOMEM - @conn is released then
 */
int esdm_dtls_new_ops(const struct esdm_dtls_ops *ops, void *conn,
		      size_t max_msg, struct esdm_dtls **dtls);

/* The connection of @dtls if its records are those of @ops, NULL otherwise */
void *esdm_dtls_ops_conn(struct esdm_dtls *dtls,
			 const struct esdm_dtls_ops *ops);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_TLS_BACKEND_H */
