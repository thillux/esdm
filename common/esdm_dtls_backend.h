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
 * What a crypto backend provides for esdm_dtls.h: DTLS 1.2 records on a
 * connected, non-blocking SOCK_SEQPACKET socket, one record per message of the
 * socket. The message framing on top is backend independent - esdm_dtls.c.
 *
 * Every function of a backend is called with the busy marker of the thread set
 * (esdm_dtls_busy()), so the randomness its TLS stack draws cannot loop back
 * into the connection.
 */

#ifndef _ESDM_DTLS_BACKEND_H
#define _ESDM_DTLS_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The link MTU the backends set: a record of ESDM_DTLS_PART_SIZE + 1 bytes
 * plus its overhead fits without fragmentation. A SOCK_SEQPACKET message is not
 * bound by an MTU, the DTLS layer would not know that.
 */
#define ESDM_DTLS_LINK_MTU 16700

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

/* Name of the TLS stack, for logging */
const char *esdm_dtls_backend_name(void);

/* @return 0 or a negative errno; *ctx is the context of one side */
int esdm_dtls_backend_ctx_new(bool server, void **ctx);
void esdm_dtls_backend_ctx_free(void *ctx);

/* @return 0 or a negative errno; *conn is the DTLS of the connection on @fd */
int esdm_dtls_backend_conn_new(void *ctx, bool server, int fd, void **conn);
void esdm_dtls_backend_conn_free(void *conn);

/* @return 0 when complete, -EAGAIN while waiting, a negative errno */
int esdm_dtls_backend_handshake(void *conn);

/*
 * Send one record of @len bytes, at most ESDM_DTLS_PART_SIZE + 1.
 *
 * @return 0 or a negative errno
 */
int esdm_dtls_backend_send(void *conn, const uint8_t *buf, size_t len);

/*
 * Receive one record into @buf of @len bytes, at least ESDM_DTLS_PART_SIZE + 2
 * so that a longer record is told.
 *
 * @return its size, -EAGAIN if none is there yet, -ECONNRESET if the peer is
 *	   gone, another negative errno on a failure
 */
ssize_t esdm_dtls_backend_recv(void *conn, uint8_t *buf, size_t len);

/* Is a record received that the socket will not signal any more? */
bool esdm_dtls_backend_pending(void *conn);

/* Name of the cipher suite in use */
const char *esdm_dtls_backend_cipher(void *conn);

/*
 * The records of a connection that are not the ones of the backend above: the
 * TLS with certificates of esdm_tls.h, see esdm_dtls_tls.c. Its functions are
 * those of the backend, and:
 *
 *  - want: what a step that returned -EAGAIN waits for, POLLIN or POLLOUT
 *  - flush: send what a connection holds of the records sent - 0, -EAGAIN,
 *    or a negative errno
 *  - free: release the connection
 */
struct esdm_dtls_ops {
	int (*handshake)(void *conn);
	int (*send)(void *conn, const uint8_t *buf, size_t len);
	ssize_t (*recv)(void *conn, uint8_t *buf, size_t len);
	bool (*pending)(void *conn);
	const char *(*cipher)(void *conn);
	short (*want)(void *conn);
	int (*flush)(void *conn);
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

#endif /* _ESDM_DTLS_BACKEND_H */
