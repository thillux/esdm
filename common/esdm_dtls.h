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
 * Opportunistic DTLS on the SOCK_SEQPACKET connections of the ESDM: the RPC
 * interface and the external entropy source channel.
 *
 * The DTLS is provided by the TLS stack of the crypto backend the ESDM is
 * built with (meson options dtls and crypto_backend): OpenSSL, GnuTLS or
 * Botan. The builtin and the leancrypto backend have none, so a build with
 * them has no DTLS, and every function here reports -EOPNOTSUPP.
 *
 * It is DTLS 1.2 with an ephemeral ECDH key exchange and AEAD ciphers only,
 * unauthenticated: the server presents an ephemeral self-signed certificate
 * the client does not verify. What a peer is trusted for is what the kernel
 * says about the other end of the Unix domain socket (SO_PEERCRED), as without
 * DTLS. The DTLS keeps the data - random numbers and seed material - from
 * being read off the connection by whoever can observe it.
 *
 * Messages: SOCK_SEQPACKET keeps message boundaries, and every DTLS record
 * travels as one message of the socket. A message of the protocol on top may
 * be larger than a record can hold (2^14 bytes), so it is sent as a sequence of
 * records, each carrying one byte in front of its part of the message: 1 if
 * more parts follow, 0 for the last one. The connection is reliable and in
 * order, so the parts arrive as they were sent.
 *
 * Randomness: the TLS stack needs random numbers, and it takes them from the
 * operating system - getrandom(2) or getentropy(3). In a process whose
 * getrandom(3) is served by the ESDM (libesdm_getrandom), or whose OpenSSL
 * takes its random numbers from the ESDM, that would ask the ESDM over the very
 * connection being set up. esdm_dtls_busy() tells a caller about to use the
 * connection that the thread is inside the DTLS layer already: the RPC client
 * then fails the nested call, and its caller falls back to the kernel. The
 * OpenSSL backend uses a library context of its own as well, so that a RAND
 * provider of the application - the ESDM's - is not used for the DTLS.
 */

#ifndef _ESDM_DTLS_H
#define _ESDM_DTLS_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The part of a message one record carries, the leading byte excluded */
#define ESDM_DTLS_PART_SIZE 16000

struct esdm_dtls_ctx;
struct esdm_dtls;

#ifdef ESDM_DTLS

/**
 * @brief Set up the DTLS of one side
 *
 * A server context generates its ephemeral key and certificate. Contexts are
 * meant to be allocated once and shared by the connections of a process; they
 * are not freed while a connection uses them.
 *
 * @param [in] server true for the server side, false for the client side
 * @param [out] ctx The context
 *
 * @return 0 on success, a negative errno otherwise
 */
int esdm_dtls_ctx_alloc(bool server, struct esdm_dtls_ctx **ctx);

/**
 * @brief Release a context, may be NULL
 */
void esdm_dtls_ctx_free(struct esdm_dtls_ctx *ctx);

/**
 * @brief Start the DTLS of a connection
 *
 * @param [in] ctx The context of the side
 * @param [in] fd The connected, non-blocking SOCK_SEQPACKET socket. It stays
 *		  owned by the caller and must stay open until esdm_dtls_free().
 * @param [in] max_msg The largest message the peer may send - a message beyond
 *		       is a protocol error
 * @param [out] dtls The DTLS of the connection
 *
 * @return 0 on success, a negative errno otherwise
 */
int esdm_dtls_alloc(struct esdm_dtls_ctx *ctx, int fd, size_t max_msg,
		    struct esdm_dtls **dtls);

/**
 * @brief Release the DTLS of a connection, may be NULL
 *
 * The socket is not closed, and no closing alert is sent: the connection is
 * closed by the caller anyway.
 */
void esdm_dtls_free(struct esdm_dtls *dtls);

/**
 * @brief Make progress with the handshake
 *
 * @return 0 once the handshake is complete, -EAGAIN while it waits for the peer
 *	   (poll the socket for reading), a negative errno if it failed
 */
int esdm_dtls_handshake(struct esdm_dtls *dtls);

/**
 * @brief Send a message
 *
 * @return 0 when all of it was sent, a negative errno otherwise - -EAGAIN if
 *	   the socket is full, which the protocols here treat as a peer that
 *	   does not read
 */
int esdm_dtls_send(struct esdm_dtls *dtls, const void *buf, size_t len);

/**
 * @brief Receive a message
 *
 * The parts of a message are collected across calls.
 *
 * @param [out] buf Room for the message
 * @param [in] len Size of @buf
 *
 * @return the size of the message once it is complete, -EAGAIN while it is not
 *	   (poll the socket for reading - but see esdm_dtls_pending()),
 *	   -EMSGSIZE for a message larger than @len or the max_msg of
 *	   esdm_dtls_alloc(), -ECONNRESET if the peer is gone, another negative
 *	   errno on a failure of the DTLS. After any error but -EAGAIN, the
 *	   connection is not to be used any more.
 */
ssize_t esdm_dtls_recv(struct esdm_dtls *dtls, void *buf, size_t len);

/**
 * @brief Is data received already that the socket will not signal any more?
 */
bool esdm_dtls_pending(struct esdm_dtls *dtls);

/**
 * @brief Name of the cipher suite of the connection, for logging
 */
const char *esdm_dtls_cipher(struct esdm_dtls *dtls);

/**
 * @brief Is the calling thread inside the DTLS layer?
 *
 * See the randomness note at the top of this header.
 */
bool esdm_dtls_busy(void);

#else /* ESDM_DTLS */

static inline int esdm_dtls_ctx_alloc(bool server, struct esdm_dtls_ctx **ctx)
{
	(void)server;
	*ctx = NULL;
	return -EOPNOTSUPP;
}

static inline void esdm_dtls_ctx_free(struct esdm_dtls_ctx *ctx)
{
	(void)ctx;
}

static inline int esdm_dtls_alloc(struct esdm_dtls_ctx *ctx, int fd,
				  size_t max_msg, struct esdm_dtls **dtls)
{
	(void)ctx;
	(void)fd;
	(void)max_msg;
	*dtls = NULL;
	return -EOPNOTSUPP;
}

static inline void esdm_dtls_free(struct esdm_dtls *dtls)
{
	(void)dtls;
}

static inline int esdm_dtls_handshake(struct esdm_dtls *dtls)
{
	(void)dtls;
	return -EOPNOTSUPP;
}

static inline int esdm_dtls_send(struct esdm_dtls *dtls, const void *buf,
				 size_t len)
{
	(void)dtls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline ssize_t esdm_dtls_recv(struct esdm_dtls *dtls, void *buf,
				     size_t len)
{
	(void)dtls;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline bool esdm_dtls_pending(struct esdm_dtls *dtls)
{
	(void)dtls;
	return false;
}

static inline const char *esdm_dtls_cipher(struct esdm_dtls *dtls)
{
	(void)dtls;
	return "none";
}

static inline bool esdm_dtls_busy(void)
{
	return false;
}

#endif /* ESDM_DTLS */

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_DTLS_H */
