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
 * Mutually authenticated TLS between hosts, on one of two transports:
 *
 *  - TLS 1.3 on a connected stream socket: the TLS mode of the EGD protocol
 *    between hosts (meson options egd-net and egd-net-tls) - the
 *    esdm-egd-net-server on the host of an ESDM, and the network mode of
 *    libesdm_egd_client used by the esdm-egd-net-relay on a host without one.
 *
 *  - DTLS 1.2 on an SCTP association, as RFC 6083 has it: the external
 *    entropy sources served on the network (meson option es-ext-net) - the
 *    network mode of the provider server of libesdm_es_ext, and the
 *    esdm-es-ext-relay on the host of the ESDM. See "DTLS over SCTP" below.
 *
 * Unlike the DTLS of esdm_dtls.h on its own, which only keeps the data of a
 * local connection from being read and leaves the trust to SO_PEERCRED,
 * nothing but the TLS tells here who is at the other end. So both sides
 * authenticate with a certificate, verified against the trust anchors each side
 * is configured with - on either transport, by the same code:
 *
 *  - The server always requires a client certificate. A client that presents
 *    none, or one that does not chain to the trust anchors of the server, is
 *    expired or not yet valid, or whose extended key usage, if it has one,
 *    does not include TLS client authentication, fails the handshake.
 *
 *  - The client verifies the chain of the server and that the server's
 *    certificate is issued for the name it expects - a DNS name of the subject
 *    alternative name, or an IP address of it for a name that is an IPv4 or
 *    IPv6 address literal -, and for TLS server authentication if it has an
 *    extended key usage.
 *
 *  - Either side may be given certificate revocation lists, see "Revocation"
 *    below.
 *
 * No session tickets and no resumption, and on DTLS no renegotiation: a
 * connection is long-lived and carries exactly the one handshake it started
 * with.
 *
 * The TLS is provided by the TLS stack of the crypto backend the ESDM is built
 * with: OpenSSL, GnuTLS or Botan. The builtin and the leancrypto backend have
 * none, a build with them has no egd-net-tls and no es-ext-net, and every
 * function here reports -EOPNOTSUPP.
 *
 * Contexts
 * --------
 * A context is everything a side loaded from its files. Building one checks
 * them as a whole: the certificate and the key parse, the key belongs to the
 * certificate, the certificate chains to one of the trust anchors - the own
 * certificate and the certificates of the peers are issued in one trust domain
 * - and every CRL parses. A chain ends in a self-issued trust anchor, on every
 * TLS stack: a CA certificate of the trust anchors that is not self-issued is
 * an intermediate one, which needs the one that issued it among them as well -
 * an intermediate CA alone is no trust anchor. The own certificate is not
 * checked for its time: an expired one is the peers' to refuse. A context is
 * shared by the connections made with it, each holding a reference: a server
 * that takes up renewed files builds a new context, and only once that
 * succeeded, it replaces its own reference to the old one - which the
 * connections still using it keep until they close. A rotation that went
 * wrong thus leaves the old context in service.
 *
 * Revocation
 * ----------
 * The CRLs are checked by the code here, identically for every TLS stack, on
 * the chain the TLS stack verified - the TLS stacks' own revocation checks are
 * not used, as no two of them agree on what a missing or an expired CRL means.
 * The check runs within the verification of the TLS stack, so a peer it
 * refuses fails the handshake as one the TLS stack refuses, with an alert
 * telling why: certificate_revoked, certificate_expired for an expired CRL,
 * unknown_ca for a missing one. Not so a server of Botan on DTLS 1.2 - a
 * provider on the network: Botan 3 replaces whatever the verification of a
 * client certificate throws in its DTLS 1.2 server with bad_certificate, and
 * offers no earlier point to verify it. Its clients are told bad_certificate
 * for each of these refusals; the log of the server tells why. The chain
 * checked ends in one of the own trust anchors - never in a certificate the
 * peer sent claiming to be one. With CRLs configured, for the certificate of
 * the peer and each CA certificate above it up to - not including - the trust
 * anchor:
 *
 *  - the CRL of a certificate is a CRL whose issuer is the subject of the next
 *    certificate of the chain and whose signature verifies with that
 *    certificate's key. Of several, the one issued last counts.
 *  - the certificate of the peer must have one: without, the handshake fails
 *    (fail closed). A CA certificate is checked against its CRL if there is
 *    one, and must have one as well with crl_check_all.
 *  - a CRL past its nextUpdate fails the handshake, unless crl_allow_expired
 *    is set, which only logs a warning then.
 *  - a certificate the CRL lists is revoked, and fails the handshake.
 *
 * A CRL is taken for the complete list of what its issuer revoked. Delta CRLs
 * and CRLs with an issuing distribution point, which limits what they cover,
 * are no such list: a context with one is not built.
 *
 * A connection is established for as long as it lives. esdm_tls_peer_revoked()
 * lets a server check its connections against the CRLs of a new context, and
 * esdm_tls_peer_not_after() tells when the certificate of the peer expires.
 *
 * Non-blocking: every operation on a connection returns -EAGAIN instead of
 * waiting, with esdm_tls_want() telling whether the socket has to become
 * readable (POLLIN) or writable (POLLOUT) for it to make progress. Data the
 * TLS stack decrypted already is not signaled by the socket any more - see
 * esdm_tls_pending(). The caller does all the waiting, which is what lets a
 * client bound every step by its timeout and a server bound its handshakes.
 *
 * DTLS over SCTP
 * --------------
 * The SCTP association is of the one-to-one style - a socket of type
 * SOCK_STREAM and protocol IPPROTO_SCTP, connected, or accepted from a
 * listening one -, and RFC 6083 maps DTLS onto it:
 *
 *  - Every user message of the association is exactly one DTLS record, every
 *    DTLS record one user message - SCTP keeps their boundaries, and a record
 *    is only ever taken whole: a user message is received until SCTP marks
 *    its end (MSG_EOR). All of them go on stream 0, ordered and reliable, with
 *    the payload protocol identifier 0.
 *  - DTLS sees a path MTU of 2^14 and fragments nothing, sends no
 *    retransmissions of its own and needs no cookie exchange: SCTP delivers
 *    what is sent, and its own handshake of four messages, cookie included,
 *    keeps an address that is spoofed from setting up an association.
 *
 * The DATA chunks of the association - which carry the records - are
 * authenticated by SCTP itself, with SCTP-AUTH (RFC 4895): DTLS protects what
 * a record holds, SCTP-AUTH which records arrive. Without it, a party on the
 * path - which sees the verification tag of the association - could inject
 * DATA chunks the receiving SCTP stack takes for the next ones, so that it
 * discards the real ones as duplicates: records would go missing silently, or
 * a FORWARD-TSN chunk would skip them. With it, a chunk that does not carry
 * the HMAC of the key of the association is dropped by the kernel before it
 * counts, and what is not delivered is sent again. The keys, as RFC 6083
 * section 4.8 has them:
 *
 *	client (esdm-es-ext-relay)          server (provider of libesdm_es_ext)
 *	  |-- INIT: RANDOM, CHUNKS (DATA, FORWARD-TSN), HMAC-ALGO --------->|
 *	  |<------------------------------------ INIT ACK: the same, COOKIE |
 *	  |-- COOKIE ECHO / COOKIE ACK: SCTP-AUTH negotiated -------------->|
 *	  |   every DATA chunk authenticated, with key 0 - the empty key    |
 *	  |                                                                 |
 *	  |== ClientHello ================================== key 0 ========>|
 *	  |<== ServerHello, Certificate, ServerKeyExchange, CertificateRequest,
 *	  |<== ServerHelloDone ============================== key 0 =========|
 *	  |== Certificate, ClientKeyExchange, CertificateVerify == key 0 ===>|
 *	  |   - all of it acknowledged by SCTP ("sender dry") -             |
 *	  |   key 1 = DTLS exporter "EXPORTER_DTLS_OVER_SCTP", 64 bytes,    |
 *	  |   no context - installed, not yet active                        |
 *	  |== ChangeCipherSpec, Finished ===================== key 0 ======>|
 *	  |   key 1 active                       key 1 installed - after    |
 *	  |                                      the master secret, sender  |
 *	  |                                      dry - and active before:   |
 *	  |<===================================== ChangeCipherSpec, key 0 ===|
 *	  |<===================================== Finished,         key 1 ==|
 *	  |   key 0 deleted                                  key 0 deleted  |
 *	  |                                                                 |
 *	  |== application data ================================ key 1 =====>|
 *	  |<============================================== key 1 ===========|
 *
 * The client switches after its Finished and the server before its own, as
 * OpenSSL's implementation of RFC 6083 does, and as the update of RFC 6083,
 * draft-ietf-tsvwg-dtls-over-sctp-bis, has it for DTLS 1.2: the server learns
 * the master secret only from the ClientKeyExchange, and its kernel drops a
 * client Finished authenticated with a key it does not hold yet - RFC 6083
 * asks for the switch before the client Finished. Either way, an
 * implementation of RFC 6083 takes the Finished: it holds both keys then. No
 * user data travels before the handshake is complete, and so none with key 0.
 * Renegotiation is off on every TLS stack, so the key is set once per
 * association.
 *
 * SCTP-AUTH is off in Linux by default (sysctl net.sctp.auth_enable). Linux
 * 5.4 and later turn it on for a socket of their own with SCTP_AUTH_SUPPORTED,
 * which esdm_tls_sctp_prepare() does before the socket connects or listens; a
 * kernel before needs the sysctl. A peer that does not authenticate DATA and
 * FORWARD-TSN chunks is refused: the connection is not set up, see
 * esdm_tls_alloc() - there is no association without SCTP-AUTH.
 *
 * The HMAC is SHA-256, which the update of RFC 6083 requires: it is listed
 * first, SHA-1 after it as RFC 4895 demands, and Linux takes no list without.
 * Linux authenticates what it sends with the first HMAC of the peer's list it
 * supports, and takes either of its own list from the peer: two ends of this
 * code use SHA-256 both ways, a peer listing SHA-1 first is sent SHA-1. Linux
 * does not tell which HMAC an association uses, so it is not checked.
 *
 * What RFC 6083 asks and the TLS stacks do not all offer: DTLS shall not
 * detect replays (section 3.3), as SCTP may deliver the records of several
 * streams, and unordered ones, out of their order. GnuTLS has it turned off;
 * OpenSSL does so only for its own SCTP BIO, which needs the TLS stack built
 * with SCTP support, and Botan not at all. On the one ordered stream used here
 * every record arrives in the order of its sequence number, and the window of
 * the replay detection never discards one.
 *
 * Randomness: the TLS stacks take their random numbers from the operating
 * system. The OpenSSL backend uses a library context of its own with the
 * default provider, so that a RAND provider configured by the application -
 * which may be one of the ESDM's own OpenSSL providers - is not used for the
 * TLS, as it is not for the DTLS.
 *
 * SIGPIPE: every backend reaches the socket through send(2) with MSG_NOSIGNAL
 * and recv(2), so a peer gone between two writes is an error of the call, not
 * a signal to the process the library is linked into.
 */

#ifndef _ESDM_TLS_H
#define _ESDM_TLS_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Size of the fingerprint of a certificate: SHA-256 of its DER encoding */
#define ESDM_TLS_FINGERPRINT_LEN 32

/* Room for the fingerprint as printed by esdm_tls_fingerprint_hex() */
#define ESDM_TLS_FINGERPRINT_HEX_LEN (2 * ESDM_TLS_FINGERPRINT_LEN + 1)

/* Most CRL files a configuration may name */
#define ESDM_TLS_MAX_CRL_FILES 16

/* Size of the stamp of the files of a configuration, see esdm_tls_stamp() */
#define ESDM_TLS_STAMP_LEN 32

/*
 * The exporter label RFC 6083 derives the SCTP-AUTH key with, without a
 * terminating NUL - see "DTLS over SCTP" above
 */
#define ESDM_TLS_SCTP_EXPORTER_LABEL "EXPORTER_DTLS_OVER_SCTP"

/* Size of the SCTP-AUTH key RFC 6083 derives */
#define ESDM_TLS_SCTP_KEY_LEN 64

/*
 * The largest record a connection on SCTP sends: what esdm_tls_send() takes
 * at a time - the path MTU of DTLS on SCTP, 2^14, less what a record of an
 * AEAD cipher adds, 37 bytes at most, rounded down
 */
#define ESDM_TLS_SCTP_RECORD_MAX 16320

struct esdm_tls_ctx;
struct esdm_tls;

/**
 * @brief The transport of a context, see the top of this header
 */
enum esdm_tls_transport {
	/* TLS 1.3 on a connected stream socket */
	ESDM_TLS_TRANSPORT_STREAM = 0,
	/* DTLS 1.2 on an SCTP association, RFC 6083 */
	ESDM_TLS_TRANSPORT_SCTP = 1,
};

/**
 * @brief The files of one side
 */
struct esdm_tls_config {
	/*
	 * Own certificate, optionally followed by the intermediate certificates
	 * of its chain. A server needs one; a client without one is rejected
	 * by every server - which is what the test suite needs it for.
	 */
	const char *cert_file;
	/*
	 * Private key of the certificate, unencrypted, in PKCS#8 - Botan reads
	 * no other format. NULL if and only if cert_file is NULL.
	 */
	const char *key_file;
	/*
	 * Trust anchors the certificate of the peer has to chain to - to a
	 * self-issued one of them, see "Contexts" above
	 */
	const char *ca_file;
	/* CRLs in PEM, each file may hold several - see "Revocation" above */
	const char *crl_files[ESDM_TLS_MAX_CRL_FILES];
	unsigned int crl_files_num;
	/* CA certificates of the peer's chain need a CRL as well */
	bool crl_check_all;
	/* A CRL past its nextUpdate only causes a warning */
	bool crl_allow_expired;
	/* ESDM_TLS_TRANSPORT_STREAM, the default, or ESDM_TLS_TRANSPORT_SCTP */
	enum esdm_tls_transport transport;
};

#ifdef ESDM_TLS_AUTH

/**
 * @brief Set up the TLS of one side
 *
 * @param [in] server true for the server side, false for the client side
 * @param [in] cfg The files, see struct esdm_tls_config - the context keeps
 *		   nothing of it but what it loaded
 * @param [out] ctx The context, with one reference held by the caller
 *
 * What is wrong with a file is logged, with what the TLS stack said about it.
 *
 * @return 0 on success, a negative errno otherwise: -ENOENT or -EACCES for a
 *	   file that cannot be read, -EINVAL for one that holds nothing usable,
 *	   a key not matching the certificate, a certificate not chaining to
 *	   the trust anchors, or a delta CRL or one with an issuing
 *	   distribution point - see "Revocation" above
 */
int esdm_tls_ctx_alloc(bool server, const struct esdm_tls_config *cfg,
		       struct esdm_tls_ctx **ctx);

/**
 * @brief Take one more reference of a context
 */
void esdm_tls_ctx_get(struct esdm_tls_ctx *ctx);

/**
 * @brief Drop a reference of a context, may be NULL - the last one frees it
 */
void esdm_tls_ctx_put(struct esdm_tls_ctx *ctx);

/**
 * @brief Log the state of the CRLs of a context
 *
 * A warning for a CRL whose nextUpdate is less than a day away, an error for
 * one past it. Each CRL is reported once per state it reaches, so this is to
 * be called periodically; @all reports every CRL in a state worth reporting
 * again, as after building the context.
 */
void esdm_tls_ctx_crl_report(struct esdm_tls_ctx *ctx, bool all);

/**
 * @brief Start the TLS of a connection
 *
 * @param [in] ctx The context of the side. The connection takes a reference
 *		   of its own.
 * @param [in] fd The connected, non-blocking socket of the transport of
 *		  @ctx: a stream socket, or an SCTP socket of the one-to-one
 *		  style set up with esdm_tls_sctp_prepare() before it connected
 *		  or listened. It stays owned by the caller and must stay open
 *		  until esdm_tls_free().
 * @param [in] server_name A client's expectation of the server's name: a DNS
 *			   name, or an IPv4 or IPv6 address literal. Mandatory
 *			   for a client - a client that does not check the name
 *			   would be served by any server the trust anchors
 *			   vouch for. Ignored by a server.
 * @param [out] tls The TLS of the connection
 *
 * On SCTP, the association has to have SCTP-AUTH for its DATA and
 * FORWARD-TSN chunks, both ways - see "DTLS over SCTP" above.
 *
 * @return 0 on success, a negative errno otherwise: -EPROTONOSUPPORT for an
 *	   association on SCTP whose peer does not authenticate its chunks
 *	   with SCTP-AUTH, -EINVAL for one whose socket was not set up for it
 *	   - both logged
 */
int esdm_tls_alloc(struct esdm_tls_ctx *ctx, int fd, const char *server_name,
		   struct esdm_tls **tls);

/**
 * @brief Release the TLS of a connection, may be NULL
 *
 * The socket is not closed, and no closing alert is sent - see
 * esdm_tls_close_notify().
 */
void esdm_tls_free(struct esdm_tls *tls);

/**
 * @brief Make progress with the handshake
 *
 * The handshake is complete once the TLS stack verified the peer and its chain
 * passed the revocation check, see "Revocation" above.
 *
 * @return 0 once the handshake is complete, -EAGAIN while it waits for the
 *	   socket (see esdm_tls_want()), -EACCES if the certificate of the peer
 *	   was refused or the peer refused ours, -ECONNRESET if the peer went
 *	   away, -EPROTO for any other failure of the TLS. After any error but
 *	   -EAGAIN, the connection is not to be used any more;
 *	   esdm_tls_error() tells why it failed.
 */
int esdm_tls_handshake(struct esdm_tls *tls);

/**
 * @brief Send data
 *
 * After -EAGAIN, the next call has to offer the same data again.
 *
 * On SCTP, @len bytes are one record, of at most ESDM_TLS_SCTP_RECORD_MAX
 * bytes - all of them are taken, or none.
 *
 * @return the number of bytes taken, which may be fewer than @len, -EAGAIN if
 *	   none could be taken right now (see esdm_tls_want()), -ECONNRESET if
 *	   the peer is gone, another negative errno on a failure of the TLS.
 *	   Bytes taken may still wait in the connection - see esdm_tls_flush().
 */
ssize_t esdm_tls_send(struct esdm_tls *tls, const void *buf, size_t len);

/**
 * @brief Push out what the connection holds of the data sent
 *
 * To be called after the last esdm_tls_send() of a message, before waiting
 * for an answer to it.
 *
 * @return 0 when nothing is left, -EAGAIN while something is (see
 *	   esdm_tls_want()), another negative errno on a failure
 */
int esdm_tls_flush(struct esdm_tls *tls);

/**
 * @brief Receive data
 *
 * On SCTP, the data of one record, all of it - a record larger than @len is
 * -EMSGSIZE.
 *
 * @return the number of bytes received, at most @len, 0 once the peer closed
 *	   the connection with a closing alert, -EAGAIN if no data is there yet
 *	   (see esdm_tls_want() and esdm_tls_pending()), -ECONNRESET if the
 *	   connection ended without a closing alert, -EACCES if the peer refused
 *	   our certificate - a TLS 1.3 server tells so only after the handshake
 *	   completed for the client -, another negative errno on a failure of
 *	   the TLS. After 0 or an error but -EAGAIN, the connection is not to be
 *	   used any more.
 */
ssize_t esdm_tls_recv(struct esdm_tls *tls, void *buf, size_t len);

/**
 * @brief What the operation that returned -EAGAIN waits for
 *
 * @return POLLIN or POLLOUT
 */
short esdm_tls_want(struct esdm_tls *tls);

/**
 * @brief Is data received already that the socket will not signal any more?
 */
bool esdm_tls_pending(struct esdm_tls *tls);

/**
 * @brief Tell the peer that no more data follows, best effort
 *
 * The closing alert is sent if the socket takes it right away; nothing is
 * waited for. On SCTP, it is sent only if SCTP has nothing unacknowledged
 * left to send, as RFC 6083 section 4.9 has it - not at all otherwise.
 */
void esdm_tls_close_notify(struct esdm_tls *tls);

/**
 * @brief The fingerprint of the certificate the peer authenticated with
 *
 * The SHA-256 of its DER encoding - what "openssl x509 -fingerprint -sha256"
 * prints. Available once the handshake is complete.
 *
 * @return 0 on success, -ENODATA before the handshake is complete
 */
int esdm_tls_peer_fingerprint(struct esdm_tls *tls,
			      uint8_t fp[ESDM_TLS_FINGERPRINT_LEN]);

/**
 * @brief The subject of the certificate the peer authenticated with, for
 *	  logging; "unknown" before the handshake is complete
 */
const char *esdm_tls_peer_subject(struct esdm_tls *tls);

/**
 * @brief When the certificate of the peer expires, in seconds since the epoch;
 *	  0 before the handshake is complete
 */
int64_t esdm_tls_peer_not_after(struct esdm_tls *tls);

/**
 * @brief Is the chain of the peer revoked by a CRL of @ctx?
 *
 * The chain verified during the handshake is checked against the CRLs of
 * @ctx, which need not be the context of the connection: a server checks its
 * established connections against the CRLs it just loaded. Only a listed
 * certificate counts - a CRL missing or expired in @ctx does not end a
 * connection that was established while it was not.
 *
 * Safe to call while another thread uses the connection: it only reads what
 * the handshake left behind.
 *
 * @return 1 if revoked - esdm_tls_error() does not tell, @why does -, 0 if
 *	   not, a negative errno if the check failed
 */
int esdm_tls_peer_revoked(struct esdm_tls *tls, struct esdm_tls_ctx *ctx,
			  char *why, size_t whylen);

/**
 * @brief Name of the cipher suite of the connection, for logging
 */
const char *esdm_tls_cipher(struct esdm_tls *tls);

/**
 * @brief Name of the key exchange group of the connection as the TLS stack
 *	  names it, for logging; "none" before the handshake is complete
 */
const char *esdm_tls_group(struct esdm_tls *tls);

/**
 * @brief Why the connection failed, for logging; "none" if it did not
 */
const char *esdm_tls_error(struct esdm_tls *tls);

/**
 * @brief Wait for the socket of a connection, for what it waits for
 *
 * @param [in] timeout_ms Bound of the wait, < 0 for none
 *
 * A signal interrupting the wait does not start it over.
 *
 * @return 0 when the socket is ready - or the connection has data pending -,
 *	   -ETIMEDOUT when the wait ran out, another negative errno
 */
int esdm_tls_wait(struct esdm_tls *tls, int timeout_ms);

/**
 * @brief The stamp of the files of a configuration
 *
 * A digest over the path, device, inode, size and modification time of every
 * file, as stat(2) tells them - following symbolic links, so that replacing a
 * file by renaming another one into its place and switching a symbolic link
 * to another directory (the "..data" of a Kubernetes secret) are told apart
 * from the state before. A file that cannot be stat(2)ed contributes its
 * error. Two equal stamps mean nothing changed that a reload would see.
 */
void esdm_tls_stamp(const struct esdm_tls_config *cfg,
		    uint8_t stamp[ESDM_TLS_STAMP_LEN]);

/**
 * @brief Set an SCTP socket up for DTLS over SCTP
 *
 * To be called before the socket connects or listens - a socket handed over
 * by socket activation listens already, and takes the setting for the
 * associations set up after the call only. SCTP-AUTH on for the socket,
 * authentication required for the DATA and FORWARD-TSN chunks the peer sends,
 * HMAC SHA-256 first; the partial delivery of SCTP for no record, and no delay
 * of small messages - see "DTLS over SCTP" above.
 *
 * @return 0, or a negative errno - logged, with what the kernel lacks: -EACCES
 *	   if SCTP-AUTH is off for the socket, which a kernel before Linux 5.4
 *	   needs the sysctl net.sctp.auth_enable for
 */
int esdm_tls_sctp_prepare(int fd);

/**
 * @brief Name of the TLS stack, for logging
 */
const char *esdm_tls_stack(void);

#else /* ESDM_TLS_AUTH */

static inline const char *esdm_tls_stack(void)
{
	return "none";
}

static inline int esdm_tls_ctx_alloc(bool server,
				     const struct esdm_tls_config *cfg,
				     struct esdm_tls_ctx **ctx)
{
	(void)server;
	(void)cfg;
	*ctx = NULL;
	return -EOPNOTSUPP;
}

static inline void esdm_tls_ctx_get(struct esdm_tls_ctx *ctx)
{
	(void)ctx;
}

static inline void esdm_tls_ctx_put(struct esdm_tls_ctx *ctx)
{
	(void)ctx;
}

static inline void esdm_tls_ctx_crl_report(struct esdm_tls_ctx *ctx, bool all)
{
	(void)ctx;
	(void)all;
}

static inline int esdm_tls_alloc(struct esdm_tls_ctx *ctx, int fd,
				 const char *server_name, struct esdm_tls **tls)
{
	(void)ctx;
	(void)fd;
	(void)server_name;
	*tls = NULL;
	return -EOPNOTSUPP;
}

static inline void esdm_tls_free(struct esdm_tls *tls)
{
	(void)tls;
}

static inline int esdm_tls_handshake(struct esdm_tls *tls)
{
	(void)tls;
	return -EOPNOTSUPP;
}

static inline ssize_t esdm_tls_send(struct esdm_tls *tls, const void *buf,
				    size_t len)
{
	(void)tls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline int esdm_tls_flush(struct esdm_tls *tls)
{
	(void)tls;
	return -EOPNOTSUPP;
}

static inline ssize_t esdm_tls_recv(struct esdm_tls *tls, void *buf, size_t len)
{
	(void)tls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline short esdm_tls_want(struct esdm_tls *tls)
{
	(void)tls;
	return 0;
}

static inline bool esdm_tls_pending(struct esdm_tls *tls)
{
	(void)tls;
	return false;
}

static inline void esdm_tls_close_notify(struct esdm_tls *tls)
{
	(void)tls;
}

static inline int esdm_tls_peer_fingerprint(struct esdm_tls *tls,
					    uint8_t fp[ESDM_TLS_FINGERPRINT_LEN])
{
	(void)tls;
	(void)fp;
	return -EOPNOTSUPP;
}

static inline const char *esdm_tls_peer_subject(struct esdm_tls *tls)
{
	(void)tls;
	return "unknown";
}

static inline int64_t esdm_tls_peer_not_after(struct esdm_tls *tls)
{
	(void)tls;
	return 0;
}

static inline int esdm_tls_peer_revoked(struct esdm_tls *tls,
					struct esdm_tls_ctx *ctx, char *why,
					size_t whylen)
{
	(void)tls;
	(void)ctx;
	(void)why;
	(void)whylen;
	return -EOPNOTSUPP;
}

static inline const char *esdm_tls_cipher(struct esdm_tls *tls)
{
	(void)tls;
	return "none";
}

static inline const char *esdm_tls_group(struct esdm_tls *tls)
{
	(void)tls;
	return "none";
}

static inline const char *esdm_tls_error(struct esdm_tls *tls)
{
	(void)tls;
	return "none";
}

static inline int esdm_tls_wait(struct esdm_tls *tls, int timeout_ms)
{
	(void)tls;
	(void)timeout_ms;
	return -EOPNOTSUPP;
}

static inline void esdm_tls_stamp(const struct esdm_tls_config *cfg,
				  uint8_t stamp[ESDM_TLS_STAMP_LEN])
{
	(void)cfg;
	memset(stamp, 0, ESDM_TLS_STAMP_LEN);
}

static inline int esdm_tls_sctp_prepare(int fd)
{
	(void)fd;
	return -EOPNOTSUPP;
}

#endif /* ESDM_TLS_AUTH */

/**
 * @brief Print a fingerprint as lower case hex digits, NUL terminated
 */
static inline void
esdm_tls_fingerprint_hex(const uint8_t fp[ESDM_TLS_FINGERPRINT_LEN],
			 char hex[ESDM_TLS_FINGERPRINT_HEX_LEN])
{
	static const char digits[] = "0123456789abcdef";
	unsigned int i;

	for (i = 0; i < ESDM_TLS_FINGERPRINT_LEN; i++) {
		hex[2 * i] = digits[fp[i] >> 4];
		hex[2 * i + 1] = digits[fp[i] & 0x0f];
	}
	hex[2 * ESDM_TLS_FINGERPRINT_LEN] = '\0';
}

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_TLS_H */
