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

/* The transport of a (D)TLS connection, see esdm_tls_io.h */

#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "esdm_tls_io.h"

void esdm_tls_io_init(struct esdm_tls_io *io, int fd, bool dgram)
{
	memset(io, 0, sizeof(*io));
	io->fd = fd;
	io->dgram = dgram;
}

static void esdm_tls_io_free_list(struct esdm_tls_io_msg *m)
{
	while (m) {
		struct esdm_tls_io_msg *next = m->next;

		free(m);
		m = next;
	}
}

void esdm_tls_io_clear(struct esdm_tls_io *io)
{
	if (!io)
		return;
	esdm_tls_io_free_list(io->in_head);
	esdm_tls_io_free_list(io->out_head);
	io->in_head = io->in_tail = NULL;
	io->out_head = io->out_tail = NULL;
	io->out_num = 0;
}

static struct esdm_tls_io_msg *esdm_tls_io_msg_new(const void *buf, size_t len)
{
	struct esdm_tls_io_msg *m = malloc(sizeof(*m) + len);

	if (!m)
		return NULL;
	m->next = NULL;
	m->len = len;
	m->off = 0;
	if (len)
		memcpy(m->data, buf, len);
	return m;
}

ssize_t esdm_tls_io_send(struct esdm_tls_io *io, const void *buf, size_t len)
{
	struct esdm_tls_io_msg *m;
	ssize_t n;

	if (io->fd >= 0) {
		do {
			n = send(io->fd, buf, len, MSG_DONTWAIT | MSG_NOSIGNAL);
		} while (n < 0 && errno == EINTR);
		return n;
	}

	m = esdm_tls_io_msg_new(buf, len);
	if (!m) {
		errno = ENOMEM;
		return -1;
	}
	if (io->out_tail)
		io->out_tail->next = m;
	else
		io->out_head = m;
	io->out_tail = m;
	io->out_num++;

	return (ssize_t)len;
}

ssize_t esdm_tls_io_recv(struct esdm_tls_io *io, void *buf, size_t len)
{
	struct esdm_tls_io_msg *m = io->in_head;
	size_t n;
	ssize_t r;

	if (io->fd >= 0) {
		do {
			r = recv(io->fd, buf, len, MSG_DONTWAIT);
		} while (r < 0 && errno == EINTR);
		return r;
	}

	if (!m) {
		if (io->eof)
			return 0;
		errno = EAGAIN;
		return -1;
	}

	/*
	 * A message as a read of SOCK_SEQPACKET hands it out: cut short to
	 * @len, the rest dropped - a stream as far as @len allows
	 */
	n = m->len - m->off;
	if (n > len)
		n = len;
	memcpy(buf, m->data + m->off, n);
	m->off += n;
	if (io->dgram || m->off == m->len) {
		io->in_head = m->next;
		if (!io->in_head)
			io->in_tail = NULL;
		free(m);
	}

	return (ssize_t)n;
}

bool esdm_tls_io_pending(const struct esdm_tls_io *io)
{
	return io && io->in_head;
}

int esdm_tls_io_feed(struct esdm_tls_io *io, const void *buf, size_t len)
{
	struct esdm_tls_io_msg *m = esdm_tls_io_msg_new(buf, len);

	if (!m)
		return -ENOMEM;
	if (io->in_tail)
		io->in_tail->next = m;
	else
		io->in_head = m;
	io->in_tail = m;

	return 0;
}

void esdm_tls_io_feed_eof(struct esdm_tls_io *io)
{
	io->eof = true;
}

struct esdm_tls_io_msg *esdm_tls_io_take(struct esdm_tls_io *io)
{
	struct esdm_tls_io_msg *m = io->out_head;

	io->out_head = io->out_tail = NULL;
	io->out_num = 0;

	return m;
}
