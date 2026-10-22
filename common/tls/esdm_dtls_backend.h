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
 * What a crypto backend provides for esdm_dtls.h: DTLS 1.2 with the pre-shared
 * key below on a connected, non-blocking SOCK_SEQPACKET socket, one record per
 * message of the socket. The messages on top are backend independent -
 * esdm_dtls.c, which calls every function here with the busy marker of the
 * thread set (esdm_dtls_busy()), so that the randomness the TLS stack draws
 * cannot loop back into the connection.
 *
 * The secure minimal mode: every context is set up so that nothing of a
 * connection outlives it but the session the local DTLS resumes - in one
 * place per backend, see there:
 *
 *  - no ticket, issued or asked for; a session is resumed by its ID alone,
 *    from the cache of esdm_dtls_session.h, and the only pre-shared key is
 *    the one below, the key exchange of the suites;
 *  - no early data (0-RTT);
 *  - no renegotiation either way;
 *  - no compression and no heartbeat;
 *  - the extended master secret (RFC 7627) and, for a CBC suite,
 *    Encrypt-then-MAC (RFC 7366) - both required: a session without them is
 *    refused.
 *
 * What a TLS stack sends nevertheless: a client of Botan an empty
 * session_ticket extension in its ClientHello. The tests read it off the
 * wire, see tests/test_dtls_wire.h.
 *
 * Every function that has to wait for the socket returns -EAGAIN and stores
 * what it waits for, POLLIN or POLLOUT, in *want. The socket is reached through
 * esdm_dtls_io.h alone - send(2) with MSG_NOSIGNAL and recv(2). The TLS stack
 * is told a link MTU no record exceeds, does not retransmit - the connection
 * is reliable - and has no cookie exchange: a connected Unix domain socket has
 * no address to spoof.
 */

#ifndef _ESDM_DTLS_BACKEND_H
#define _ESDM_DTLS_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "esdm_dtls_io.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DTLS 1.2, ECDHE-PSK with AES-256 on curves of 256 bits of security or more,
 * see esdm_dtls.h.
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
 * The link MTU the backends set: a record of ESDM_DTLS_PART_SIZE + 1 bytes
 * plus its overhead fits without fragmentation. A SOCK_SEQPACKET message is not
 * bound by an MTU, the DTLS layer would not know that.
 */
#define ESDM_DTLS_LINK_MTU 16700

/* Name of the TLS stack, for logging */
const char *esdm_dtls_backend_name(void);

/* @return 0 or a negative errno; *ctx is the context of one side */
int esdm_dtls_backend_ctx_new(bool server, void **ctx);
void esdm_dtls_backend_ctx_free(void *ctx);

/*
 * @return 0 or a negative errno; *conn is the DTLS of the connection on @io,
 *	   its socket - see esdm_dtls_io.h -, which stays the caller's and must
 *	   outlive the connection.
 *	   A client is handed the @session_keylen bytes of @session_key, the
 *	   socket path of its server, under which it resumes the session of its
 *	   context and keeps the one of a full handshake - NULL for none, see
 *	   esdm_dtls_session.h.
 */
int esdm_dtls_backend_conn_new(void *ctx, bool server, struct esdm_dtls_io *io,
			       const uint8_t *session_key,
			       size_t session_keylen, void **conn);
void esdm_dtls_backend_conn_free(void *conn);

/* @return 0 when complete, -EAGAIN while waiting, a negative errno */
int esdm_dtls_backend_handshake(void *conn, short *want);

/*
 * @len bytes are one record, taken whole or not at all.
 *
 * @return bytes taken, -EAGAIN if none, a negative errno
 */
ssize_t esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len,
			       short *want);

/* @return 0 when everything is out, -EAGAIN while not, a negative errno */
int esdm_dtls_backend_flush(void *conn, short *want);

/*
 * One record, whole - a record larger than @len is -EMSGSIZE.
 *
 * @return bytes received, 0 after a closing alert, -EAGAIN if none yet,
 *	   -ECONNRESET at the end of the connection without a closing alert,
 *	   another negative errno
 */
ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len,
			       short *want);

/* Is a record received that the socket will not signal any more? */
bool esdm_dtls_backend_pending(void *conn);

/* Name of the cipher suite in use */
const char *esdm_dtls_backend_cipher(void *conn);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_DTLS_BACKEND_H */
