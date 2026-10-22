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
 * The transport of a DTLS connection of esdm_dtls_backend.h: what the TLS
 * stack of every backend reads its records from and writes them to - in its
 * BIO (OpenSSL), its push and pull functions (GnuTLS) or its callbacks
 * (Botan): the SOCK_SEQPACKET socket of the connection, non-blocking, one
 * send(2) with MSG_NOSIGNAL or recv(2) of a message per call. They
 * fail as send(2) and recv(2) do, with -1 and errno, so that a backend calls
 * them in place of those. The records are ciphertext: nothing here is wiped.
 */

#ifndef _ESDM_DTLS_IO_H
#define _ESDM_DTLS_IO_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct esdm_dtls_io;

/*
 * The layout is the C files' business - a backend in C++ (Botan) reaches the
 * transport through the functions below alone
 */
#ifndef __cplusplus

struct esdm_dtls_io {
	/* The socket */
	int fd;
};

#endif /* __cplusplus */

/* The socket @fd */
void esdm_dtls_io_init(struct esdm_dtls_io *io, int fd);

/* As send(2) with MSG_DONTWAIT | MSG_NOSIGNAL */
ssize_t esdm_dtls_io_send(struct esdm_dtls_io *io, const void *buf, size_t len);

/* As recv(2) with MSG_DONTWAIT: 0 at the end of the connection */
ssize_t esdm_dtls_io_recv(struct esdm_dtls_io *io, void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_DTLS_IO_H */
