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
 * The transport of a (D)TLS connection of esdm_tls_backend.h: what the TLS
 * stack of every backend reads its records from and writes them to - in its
 * BIO (OpenSSL), its push and pull functions (GnuTLS) or its callbacks
 * (Botan). Either
 *
 *  - the socket of the connection, non-blocking: one send(2) with
 *    MSG_NOSIGNAL or recv(2) per call - on SOCK_SEQPACKET a message each -;
 *    or
 *  - buffers of the caller, who receives and sends the messages itself, with
 *    io_uring say: what it received it hands in with esdm_tls_io_feed(), what
 *    the TLS stack wrote it takes with esdm_tls_io_take(). A read finding
 *    nothing fed fails with EAGAIN, as the socket would.
 *
 * Both send and receive what the socket would: messages of their own on
 * SOCK_SEQPACKET (@dgram), a stream of bytes on a stream socket. They fail as
 * send(2) and recv(2) do, with -1 and errno, so that a backend calls them in
 * place of those. The records are ciphertext: nothing here is wiped.
 */

#ifndef _ESDM_TLS_IO_H
#define _ESDM_TLS_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_tls_io;
struct esdm_tls_io_msg;

/*
 * The layout is the C files' business - a backend in C++ (Botan) reaches the
 * transport through the functions below alone
 */
#ifndef __cplusplus

/* A message - or a part of the stream - held for the caller or the TLS stack */
struct esdm_tls_io_msg {
	struct esdm_tls_io_msg *next;
	size_t len;
	/* What a stream read handed out of it already */
	size_t off;
	uint8_t data[];
};

struct esdm_tls_io {
	/* The socket, -1 for the buffers of the caller */
	int fd;
	/* SOCK_SEQPACKET: a message each */
	bool dgram;
	/* The peer ended the connection, see esdm_tls_io_feed_eof() */
	bool eof;
	/* Fed, to be read */
	struct esdm_tls_io_msg *in_head, *in_tail;
	/* Written, to be sent or taken */
	struct esdm_tls_io_msg *out_head, *out_tail;
	size_t out_num;
};

#endif /* __cplusplus */

/* The socket @fd, or with @fd -1 the buffers of the caller */
void esdm_tls_io_init(struct esdm_tls_io *io, int fd, bool dgram);

/* Release what it holds */
void esdm_tls_io_clear(struct esdm_tls_io *io);

/* As send(2) with MSG_DONTWAIT | MSG_NOSIGNAL */
ssize_t esdm_tls_io_send(struct esdm_tls_io *io, const void *buf, size_t len);

/* As recv(2) with MSG_DONTWAIT: 0 at the end of the connection */
ssize_t esdm_tls_io_recv(struct esdm_tls_io *io, void *buf, size_t len);

/* Is something fed that was not read yet? */
bool esdm_tls_io_pending(const struct esdm_tls_io *io);

/*
 * Hand in what the caller received: a message on SOCK_SEQPACKET, a part of the
 * stream otherwise. Copied.
 *
 * @return 0 or -ENOMEM
 */
int esdm_tls_io_feed(struct esdm_tls_io *io, const void *buf, size_t len);

/* The peer ended the connection: a read finding nothing fed returns 0 */
void esdm_tls_io_feed_eof(struct esdm_tls_io *io);

/*
 * Take what the TLS stack wrote, NULL if nothing: the messages in order, linked
 * by next, each to be sent as a message of its own on SOCK_SEQPACKET - the
 * caller's, each to be released with free(3).
 */
struct esdm_tls_io_msg *esdm_tls_io_take(struct esdm_tls_io *io);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_TLS_IO_H */
