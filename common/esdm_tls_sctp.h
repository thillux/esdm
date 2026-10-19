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
 * The SCTP association under DTLS, as RFC 6083 has it - see "DTLS over SCTP"
 * in esdm_tls.h. Backend independent: the TLS stacks hand the records they
 * write to esdm_tls_sctp_queue() and take what they read from
 * esdm_tls_sctp_recv(); the TLS layer of esdm_tls.c sends the queue with
 * esdm_tls_sctp_flush(), which is where the keys of SCTP-AUTH change: a
 * record is seen by type and epoch - its header is in the clear - on its way
 * out, outside of the TLS stack, so that the switch happens at the record the
 * RFC names whatever the TLS stack.
 *
 *  - Before the first ChangeCipherSpec goes out, everything sent before is to
 *    be acknowledged by the peer (RFC 6083 section 4.7): the queue waits for
 *    the "sender dry" notification of SCTP. Then the key is exported from the
 *    DTLS session - the master secret is known on either side by then - and
 *    installed under the next key identifier, not yet active.
 *  - A server makes it active right after its ChangeCipherSpec, before its
 *    Finished; a client right after its Finished, the first record of the new
 *    epoch it sends.
 *  - Once the handshake is complete, the old key is deleted.
 */

#ifndef _ESDM_TLS_SCTP_H
#define _ESDM_TLS_SCTP_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The largest record received: 2^14 bytes and what a record adds at most,
 * 2048 bytes of expansion and the header of 13 (RFC 6083 section 4.1)
 */
#define ESDM_TLS_SCTP_MSG_MAX (16384 + 2048 + 13)

/* The path MTU a TLS stack is told on SCTP (RFC 6083 section 3.2) */
#define ESDM_TLS_SCTP_MTU 16384

struct esdm_tls_sctp;

/*
 * Export the key of SCTP-AUTH from the DTLS session - what the backend of the
 * TLS stack does for esdm_tls_sctp_flush(), see esdm_tls_backend_export().
 */
typedef int (*esdm_tls_sctp_export)(void *arg, uint8_t *key, size_t len);

#ifdef ESDM_TLS_SCTP

/*
 * The association on @fd: checks that it authenticates its DATA and
 * FORWARD-TSN chunks both ways. @server is the side of DTLS.
 *
 * @return 0, -EPROTONOSUPPORT if the peer does not, -EINVAL if the socket
 *	   was not set up for SCTP-AUTH - either with the reason in @why
 */
int esdm_tls_sctp_new(int fd, bool server, struct esdm_tls_sctp **sctp,
		      char *why, size_t whylen);

void esdm_tls_sctp_free(struct esdm_tls_sctp *sctp);

/*
 * Take what a TLS stack writes: one or more complete DTLS records, each of
 * which becomes a user message of its own. Nothing is sent here.
 *
 * @return 0, -EPROTO for what is no sequence of complete records, -ENOBUFS if
 *	   the queue holds too much already, -ENOMEM
 */
int esdm_tls_sctp_queue(struct esdm_tls_sctp *sctp, const uint8_t *buf,
			size_t len);

/*
 * One user message - one DTLS record, whole - into @buf of @len bytes, the
 * notifications of SCTP taken on the way.
 *
 * @return its size, -EAGAIN if none is there yet, -ECONNRESET at the end of
 *	   the association, -EMSGSIZE for a message larger than @len, another
 *	   negative errno
 */
ssize_t esdm_tls_sctp_recv(struct esdm_tls_sctp *sctp, uint8_t *buf,
			   size_t len);

/*
 * Send what is queued, as far as SCTP takes it and the keys allow - see the
 * top of this file. *@want tells what to wait for if not all of it went out:
 * POLLIN for the notification of SCTP that all is acknowledged, POLLOUT for
 * room in the socket.
 *
 * @return 0 when the queue is empty, -EAGAIN if not, another negative errno -
 *	   the reason in esdm_tls_sctp_error()
 */
int esdm_tls_sctp_flush(struct esdm_tls_sctp *sctp, esdm_tls_sctp_export exp,
			void *arg, short *want);

/* Is something queued still? */
bool esdm_tls_sctp_queued(struct esdm_tls_sctp *sctp);

/*
 * The handshake is complete: the new key has to be the active one - and the
 * one the DTLS session exports now -, and the old one is deleted.
 *
 * @return 0, or a negative errno - the reason in esdm_tls_sctp_error()
 */
int esdm_tls_sctp_established(struct esdm_tls_sctp *sctp,
			      esdm_tls_sctp_export exp, void *arg);

/*
 * Is the association "dry" - all data sent acknowledged by the peer? Asks SCTP
 * for the notification the first time, and looks for it afterwards.
 *
 * @return 1 if so, 0 if not yet, a negative errno
 */
int esdm_tls_sctp_dry(struct esdm_tls_sctp *sctp);

/* Why the association failed, NULL or empty if it did not */
const char *esdm_tls_sctp_error(struct esdm_tls_sctp *sctp);

/* The descriptor of the association */
int esdm_tls_sctp_fd(struct esdm_tls_sctp *sctp);

#else /* ESDM_TLS_SCTP */

/* No association ever exists - a connection on a stream socket has none */

static inline void esdm_tls_sctp_free(struct esdm_tls_sctp *sctp)
{
	(void)sctp;
}

static inline int esdm_tls_sctp_queue(struct esdm_tls_sctp *sctp,
				      const uint8_t *buf, size_t len)
{
	(void)sctp;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline ssize_t esdm_tls_sctp_recv(struct esdm_tls_sctp *sctp,
					 uint8_t *buf, size_t len)
{
	(void)sctp;
	(void)buf;
	(void)len;
	return -EOPNOTSUPP;
}

static inline int esdm_tls_sctp_flush(struct esdm_tls_sctp *sctp,
				      esdm_tls_sctp_export exp, void *arg,
				      short *want)
{
	(void)sctp;
	(void)exp;
	(void)arg;
	(void)want;
	return 0;
}

static inline bool esdm_tls_sctp_queued(struct esdm_tls_sctp *sctp)
{
	(void)sctp;
	return false;
}

static inline const char *esdm_tls_sctp_error(struct esdm_tls_sctp *sctp)
{
	(void)sctp;
	return NULL;
}

static inline int esdm_tls_sctp_fd(struct esdm_tls_sctp *sctp)
{
	(void)sctp;
	return -1;
}

#endif /* ESDM_TLS_SCTP */

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_TLS_SCTP_H */
