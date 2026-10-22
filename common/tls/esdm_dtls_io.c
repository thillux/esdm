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

/* The transport of a DTLS connection, see esdm_dtls_io.h */

#define _GNU_SOURCE
#include <errno.h>
#include <sys/socket.h>

#include "esdm_dtls_io.h"

void esdm_dtls_io_init(struct esdm_dtls_io *io, int fd)
{
	io->fd = fd;
}

ssize_t esdm_dtls_io_send(struct esdm_dtls_io *io, const void *buf, size_t len)
{
	ssize_t n;

	do {
		n = send(io->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
	} while (n < 0 && errno == EINTR);

	return n;
}

ssize_t esdm_dtls_io_recv(struct esdm_dtls_io *io, void *buf, size_t len)
{
	ssize_t n;

	do {
		n = recv(io->fd, buf, len, MSG_DONTWAIT);
	} while (n < 0 && errno == EINTR);

	return n;
}
