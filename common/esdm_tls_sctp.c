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
 * DTLS over SCTP, RFC 6083: the association with SCTP-AUTH and its keys - see
 * esdm_tls_sctp.h and "DTLS over SCTP" in esdm_tls.h.
 *
 * The socket interface is the one of RFC 6458 as Linux has it, taken from the
 * kernel's own header rather than from lksctp-tools: nothing of the library
 * is needed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/sctp.h>

#include "esdm_logger.h"
#include "esdm_tls.h"
#include "esdm_tls_sctp.h"
#include "memset_secure.h"

/* The content types of DTLS records, and the size of their header */
#define ESDM_TLS_SCTP_CCS 20
#define ESDM_TLS_SCTP_HANDSHAKE 22
#define ESDM_TLS_SCTP_APPDATA 23
#define ESDM_TLS_SCTP_HDR 13

/* The chunks SCTP-AUTH has to cover: DATA, and FORWARD-TSN of PR-SCTP */
#define ESDM_TLS_SCTP_CHUNK_DATA 0
#define ESDM_TLS_SCTP_CHUNK_FWD_TSN 192

/*
 * The most the queue holds: a flight of the handshake, certificate chains
 * included, with plenty of room - a TLS stack writing beyond is broken
 */
#define ESDM_TLS_SCTP_QUEUE_MAX (256 * 1024)

/* Room for a notification of SCTP: the ones subscribed to are small */
#define ESDM_TLS_SCTP_NOTIFICATION_MAX 512

/* A record waiting to be sent */
struct esdm_tls_sctp_rec {
	struct esdm_tls_sctp_rec *next;
	size_t len;
	uint8_t type;
	uint16_t epoch;
	uint8_t data[];
};

struct esdm_tls_sctp {
	int fd;
	bool server;

	/* What the TLS stack wrote and SCTP did not take yet */
	struct esdm_tls_sctp_rec *head, **tail;
	size_t queued;

	/*
	 * The keys of SCTP-AUTH: the one the association started with, the
	 * one exported from the DTLS session, and how far the switch got
	 */
	uint16_t old_key;
	uint16_t new_key;
	bool key_added;
	bool key_active;

	/*
	 * The key installed, until the handshake is complete: exported once
	 * more then, it has to be the same - see esdm_tls_sctp_established()
	 */
	uint8_t key[ESDM_TLS_SCTP_KEY_LEN];

	/* Waiting for the notification that all data is acknowledged */
	bool dry_subscribed;
	bool dry;

	/*
	 * A user message SCTP delivered in parts - which it does not for a
	 * record, see esdm_tls_sctp_prepare(), but may - collected until its
	 * end
	 */
	uint8_t *part;
	size_t part_len;

	char error[256];
};

/******************************************************************************
 * Setting up
 ******************************************************************************/

int esdm_tls_sctp_prepare(int fd)
{
	struct sctp_assoc_value av = { .assoc_id = 0, .assoc_value = 1 };
	const uint8_t chunks[] = { ESDM_TLS_SCTP_CHUNK_DATA,
				   ESDM_TLS_SCTP_CHUNK_FWD_TSN };
	union {
		struct sctp_hmacalgo algo;
		uint8_t buf[sizeof(struct sctp_hmacalgo) + 2 * sizeof(__u16)];
	} hmac;
	int one = 1, pd = ESDM_TLS_SCTP_MSG_MAX + 1;
	unsigned int i;

	/*
	 * Per socket since Linux 5.4; before, the sysctl decides for all of
	 * them, and the chunks below tell whether it is on
	 */
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_SUPPORTED, &av,
		       sizeof(av)) < 0 &&
	    errno != ENOPROTOOPT) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "DTLS over SCTP: cannot turn SCTP-AUTH on: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	for (i = 0; i < sizeof(chunks); i++) {
		struct sctp_authchunk ac = { .sauth_chunk = chunks[i] };

		if (setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &ac,
			       sizeof(ac)) < 0) {
			int errsv = errno;

			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"DTLS over SCTP: SCTP-AUTH is off for the socket (%s) - a kernel before Linux 5.4 needs the sysctl net.sctp.auth_enable=1\n",
				strerror(errsv));
			return errsv == EACCES ? -EACCES : -errsv;
		}
	}

	/* SHA-256 first, SHA-1 as RFC 4895 requires it in the list */
	memset(&hmac, 0, sizeof(hmac));
	hmac.algo.shmac_num_idents = 2;
	hmac.algo.shmac_idents[0] = SCTP_AUTH_HMAC_ID_SHA256;
	hmac.algo.shmac_idents[1] = SCTP_AUTH_HMAC_ID_SHA1;
	if (setsockopt(fd, IPPROTO_SCTP, SCTP_HMAC_IDENT, &hmac,
		       sizeof(hmac)) < 0)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"DTLS over SCTP: the kernel takes no HMAC SHA-256 for SCTP-AUTH (%s), SHA-1 is used\n",
			strerror(errno));

	/* The records are small and wanted at once */
	setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof(one));

	/*
	 * No record is delivered in parts as long as the receive buffer holds
	 * it (RFC 6083 section 4.1): what is received in parts still is
	 * collected, see esdm_tls_sctp_recv()
	 */
	setsockopt(fd, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT, &pd,
		   sizeof(pd));

	return 0;
}

/* Does the list of chunks @opt of @fd hold DATA and FORWARD-TSN? */
static int esdm_tls_sctp_chunks(int fd, int opt)
{
	union {
		struct sctp_authchunks chunks;
		uint8_t buf[sizeof(struct sctp_authchunks) + 256];
	} u;
	socklen_t len = sizeof(u);
	bool data = false, fwd = false;
	unsigned int i;

	memset(&u, 0, sizeof(u));
	if (getsockopt(fd, IPPROTO_SCTP, opt, &u, &len) < 0)
		return -errno;

	for (i = 0; i < u.chunks.gauth_number_of_chunks && i < 256; i++) {
		if (u.chunks.gauth_chunks[i] == ESDM_TLS_SCTP_CHUNK_DATA)
			data = true;
		else if (u.chunks.gauth_chunks[i] ==
			 ESDM_TLS_SCTP_CHUNK_FWD_TSN)
			fwd = true;
	}

	return (data && fwd) ? 0 : -EPROTONOSUPPORT;
}

int esdm_tls_sctp_new(int fd, bool server, struct esdm_tls_sctp **sctp,
		      char *why, size_t whylen)
{
	struct sctp_authkeyid active = { 0 };
	socklen_t len = sizeof(active);
	struct esdm_tls_sctp *s;
	int one = 1, ret;

	*sctp = NULL;

	/*
	 * An association without SCTP-AUTH answers neither list: the peer
	 * has none, or the socket was not set up before it connected
	 */
	ret = esdm_tls_sctp_chunks(fd, SCTP_PEER_AUTH_CHUNKS);
	if (ret == -EACCES || ret == -EPROTONOSUPPORT) {
		snprintf(why, whylen,
			 ret == -EACCES ?
				 "the association has no SCTP-AUTH - the peer does not support it, or has it off" :
				 "the peer does not require SCTP-AUTH for DATA and FORWARD-TSN chunks");
		return -EPROTONOSUPPORT;
	}
	if (ret) {
		snprintf(why, whylen, "no SCTP association: %s",
			 strerror(-ret));
		return ret;
	}

	ret = esdm_tls_sctp_chunks(fd, SCTP_LOCAL_AUTH_CHUNKS);
	if (ret) {
		snprintf(why, whylen,
			 "the socket does not require SCTP-AUTH for DATA and FORWARD-TSN chunks - it was not set up with esdm_tls_sctp_prepare() before it connected or listened");
		return -EINVAL;
	}

	if (getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &active,
		       &len) < 0) {
		ret = -errno;
		snprintf(why, whylen, "no active key of SCTP-AUTH: %s",
			 strerror(-ret));
		return ret;
	}

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->fd = fd;
	s->server = server;
	s->tail = &s->head;
	s->old_key = active.scact_keynumber;
	/* The next identifier, past 65535 on to 1 (RFC 6083 section 4.8) */
	s->new_key = s->old_key == 65535 ? 1 : (uint16_t)(s->old_key + 1);

	/* An accepted socket may not have what the listening one had */
	setsockopt(fd, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof(one));

	*sctp = s;
	return 0;
}

static void esdm_tls_sctp_drop_part(struct esdm_tls_sctp *s)
{
	free(s->part);
	s->part = NULL;
	s->part_len = 0;
}

void esdm_tls_sctp_free(struct esdm_tls_sctp *sctp)
{
	struct esdm_tls_sctp_rec *r;

	if (!sctp)
		return;

	while ((r = sctp->head)) {
		sctp->head = r->next;
		free(r);
	}
	esdm_tls_sctp_drop_part(sctp);
	memset_secure(sctp, 0, sizeof(*sctp));
	free(sctp);
}

int esdm_tls_sctp_fd(struct esdm_tls_sctp *sctp)
{
	return sctp->fd;
}

const char *esdm_tls_sctp_error(struct esdm_tls_sctp *sctp)
{
	return sctp ? sctp->error : NULL;
}

bool esdm_tls_sctp_queued(struct esdm_tls_sctp *sctp)
{
	return sctp && sctp->head;
}

/******************************************************************************
 * Notifications
 ******************************************************************************/

/* A notification of SCTP, received whole */
static void esdm_tls_sctp_notification(struct esdm_tls_sctp *s,
				       const uint8_t *buf, size_t len)
{
	__u16 type;

	/* The type leads every notification, see union sctp_notification */
	if (len < sizeof(type))
		return;
	memcpy(&type, buf, sizeof(type));

	/* No other one is subscribed to */
	if (type == SCTP_SENDER_DRY_EVENT && s->dry_subscribed)
		s->dry = true;
}

/*
 * Take the notifications waiting at the head of the receive queue - but no
 * user message: those are for the TLS stack to read.
 */
static void esdm_tls_sctp_take_notifications(struct esdm_tls_sctp *s)
{
	uint8_t buf[ESDM_TLS_SCTP_NOTIFICATION_MAX];

	/* The rest of a user message is next, nothing else */
	if (s->part)
		return;

	for (;;) {
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
		ssize_t n = recvmsg(s->fd, &msg, MSG_PEEK | MSG_DONTWAIT);

		if (n <= 0 || !(msg.msg_flags & MSG_NOTIFICATION))
			return;

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		n = recvmsg(s->fd, &msg, MSG_DONTWAIT);
		if (n <= 0)
			return;
		esdm_tls_sctp_notification(s, buf, (size_t)n);
	}
}

static int esdm_tls_sctp_subscribe_dry(struct esdm_tls_sctp *s, bool on)
{
	struct sctp_event ev = { .se_assoc_id = 0,
				 .se_type = SCTP_SENDER_DRY_EVENT,
				 .se_on = on ? 1 : 0 };

	if (setsockopt(s->fd, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev)) < 0)
		return -errno;
	return 0;
}

int esdm_tls_sctp_dry(struct esdm_tls_sctp *sctp)
{
	int ret;

	/*
	 * Subscribed to, SCTP notifies at once if nothing is unacknowledged,
	 * as soon as that is so otherwise
	 */
	if (!sctp->dry_subscribed) {
		ret = esdm_tls_sctp_subscribe_dry(sctp, true);
		if (ret) {
			snprintf(sctp->error, sizeof(sctp->error),
				 "cannot ask SCTP whether all is acknowledged: %s",
				 strerror(-ret));
			return ret;
		}
		sctp->dry_subscribed = true;
		sctp->dry = false;
	}

	esdm_tls_sctp_take_notifications(sctp);
	if (!sctp->dry)
		return 0;

	(void)esdm_tls_sctp_subscribe_dry(sctp, false);
	sctp->dry_subscribed = false;
	sctp->dry = false;
	return 1;
}

/******************************************************************************
 * Receiving
 ******************************************************************************/

ssize_t esdm_tls_sctp_recv(struct esdm_tls_sctp *sctp, uint8_t *buf,
			   size_t len)
{
	for (;;) {
		uint8_t *dst = sctp->part ? sctp->part + sctp->part_len : buf;
		size_t room = sctp->part ?
				      ESDM_TLS_SCTP_MSG_MAX + 1 -
					      sctp->part_len :
				      len;
		struct iovec iov = { .iov_base = dst, .iov_len = room };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
		ssize_t n;

		if (!room) {
			esdm_tls_sctp_drop_part(sctp);
			return -EMSGSIZE;
		}

		n = recvmsg(sctp->fd, &msg, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
			    errno == EINTR)
				return -EAGAIN;
			if (errno == ECONNRESET || errno == EPIPE ||
			    errno == ENOTCONN)
				return -ECONNRESET;
			return -errno;
		}
		/* The peer shut the association down */
		if (n == 0)
			return -ECONNRESET;

		/*
		 * No notification arrives within a message delivered in parts:
		 * SCTP holds it back until the message is complete
		 */
		if (msg.msg_flags & MSG_NOTIFICATION) {
			esdm_tls_sctp_notification(sctp, dst, (size_t)n);
			continue;
		}

		if (sctp->part)
			sctp->part_len += (size_t)n;

		if (msg.msg_flags & MSG_EOR) {
			size_t msglen;

			if (!sctp->part)
				return n;

			msglen = sctp->part_len;
			if (msglen > len) {
				esdm_tls_sctp_drop_part(sctp);
				return -EMSGSIZE;
			}
			memcpy(buf, sctp->part, msglen);
			esdm_tls_sctp_drop_part(sctp);
			return (ssize_t)msglen;
		}

		/*
		 * Not the end of the message: the buffer of the caller is full
		 * - a message larger than it -, or SCTP delivers it in parts
		 */
		if (!sctp->part) {
			if ((size_t)n >= len)
				return -EMSGSIZE;
			sctp->part = malloc(ESDM_TLS_SCTP_MSG_MAX + 1);
			if (!sctp->part)
				return -ENOMEM;
			memcpy(sctp->part, buf, (size_t)n);
			sctp->part_len = (size_t)n;
		}
	}
}

/******************************************************************************
 * Sending, and the keys
 ******************************************************************************/

int esdm_tls_sctp_queue(struct esdm_tls_sctp *sctp, const uint8_t *buf,
			size_t len)
{
	size_t off = 0;

	while (off < len) {
		struct esdm_tls_sctp_rec *r;
		size_t rlen;

		/* One complete record after the other, nothing else */
		if (len - off < ESDM_TLS_SCTP_HDR)
			return -EPROTO;
		rlen = ESDM_TLS_SCTP_HDR +
		       ((size_t)buf[off + 11] << 8 | (size_t)buf[off + 12]);
		if (rlen > len - off)
			return -EPROTO;
		if (sctp->queued + rlen > ESDM_TLS_SCTP_QUEUE_MAX)
			return -ENOBUFS;

		r = malloc(sizeof(*r) + rlen);
		if (!r)
			return -ENOMEM;
		r->next = NULL;
		r->len = rlen;
		r->type = buf[off];
		r->epoch = (uint16_t)(buf[off + 3] << 8 | buf[off + 4]);
		memcpy(r->data, buf + off, rlen);

		*sctp->tail = r;
		sctp->tail = &r->next;
		sctp->queued += rlen;
		off += rlen;
	}

	return 0;
}

/*
 * One record as one user message: stream 0, ordered, payload protocol
 * identifier 0 - and what is no application data acknowledged by the peer
 * right away (RFC 7053), which is what the wait before the ChangeCipherSpec
 * waits for.
 */
static int esdm_tls_sctp_send_rec(struct esdm_tls_sctp *s,
				  const struct esdm_tls_sctp_rec *r)
{
	struct sctp_sndinfo info = { 0 };
	union {
		struct cmsghdr hdr;
		uint8_t buf[CMSG_SPACE(sizeof(struct sctp_sndinfo))];
	} control;
	struct iovec iov = { .iov_base = (void *)r->data, .iov_len = r->len };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	struct cmsghdr *cmsg;
	ssize_t n;

	if (r->type != ESDM_TLS_SCTP_APPDATA)
		info.snd_flags = SCTP_SACK_IMMEDIATELY;

	memset(&control, 0, sizeof(control));
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_SCTP;
	cmsg->cmsg_type = SCTP_SNDINFO;
	cmsg->cmsg_len = CMSG_LEN(sizeof(info));
	memcpy(CMSG_DATA(cmsg), &info, sizeof(info));

	n = sendmsg(s->fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n == (ssize_t)r->len)
		return 0;
	if (n >= 0) {
		/* A user message of SCTP is taken whole or not at all */
		snprintf(s->error, sizeof(s->error),
			 "SCTP took a part of a record only");
		return -EIO;
	}
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
		return -EAGAIN;
	if (errno == ECONNRESET || errno == EPIPE || errno == ENOTCONN) {
		snprintf(s->error, sizeof(s->error),
			 "connection closed by the peer");
		return -ECONNRESET;
	}

	n = -errno;
	snprintf(s->error, sizeof(s->error), "%s", strerror((int)-n));
	return (int)n;
}

/* Export the key from the DTLS session and install it, not yet active */
static int esdm_tls_sctp_key_add(struct esdm_tls_sctp *s,
				 esdm_tls_sctp_export exp, void *arg)
{
	union {
		struct sctp_authkey key;
		uint8_t buf[sizeof(struct sctp_authkey) +
			    ESDM_TLS_SCTP_KEY_LEN];
	} u;
	int ret;

	memset(&u, 0, sizeof(u));
	ret = exp(arg, u.key.sca_key, ESDM_TLS_SCTP_KEY_LEN);
	if (ret) {
		snprintf(s->error, sizeof(s->error),
			 "cannot export the key of SCTP-AUTH from the DTLS session: %s",
			 strerror(-ret));
		goto out;
	}

	u.key.sca_assoc_id = 0;
	u.key.sca_keynumber = s->new_key;
	u.key.sca_keylength = ESDM_TLS_SCTP_KEY_LEN;
	if (setsockopt(s->fd, IPPROTO_SCTP, SCTP_AUTH_KEY, &u, sizeof(u)) <
	    0) {
		ret = -errno;
		snprintf(s->error, sizeof(s->error),
			 "cannot install the key of SCTP-AUTH: %s",
			 strerror(-ret));
		goto out;
	}

	s->key_added = true;
	memcpy(s->key, u.key.sca_key, sizeof(s->key));

out:
	memset_secure(&u, 0, sizeof(u));
	return ret;
}

static int esdm_tls_sctp_key_activate(struct esdm_tls_sctp *s)
{
	struct sctp_authkeyid id = { .scact_assoc_id = 0,
				     .scact_keynumber = s->new_key };

	if (setsockopt(s->fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &id,
		       sizeof(id)) < 0) {
		int ret = -errno;

		snprintf(s->error, sizeof(s->error),
			 "cannot make the key of SCTP-AUTH the active one: %s",
			 strerror(-ret));
		return ret;
	}

	s->key_active = true;
	return 0;
}

int esdm_tls_sctp_flush(struct esdm_tls_sctp *sctp, esdm_tls_sctp_export exp,
			void *arg, short *want)
{
	struct esdm_tls_sctp_rec *r;
	int ret;

	while ((r = sctp->head)) {
		if (r->type == ESDM_TLS_SCTP_CCS) {
			/* One key per association, see esdm_tls.h */
			if (sctp->key_added) {
				snprintf(sctp->error, sizeof(sctp->error),
					 "a second ChangeCipherSpec - DTLS renegotiates, which DTLS over SCTP does not here");
				return -EPROTO;
			}

			/*
			 * All sent before is acknowledged first (RFC 6083
			 * section 4.7), then the key comes
			 */
			ret = esdm_tls_sctp_dry(sctp);
			if (ret < 0)
				return ret;
			if (!ret) {
				*want = POLLIN;
				return -EAGAIN;
			}

			ret = esdm_tls_sctp_key_add(sctp, exp, arg);
			if (ret)
				return ret;
		}

		ret = esdm_tls_sctp_send_rec(sctp, r);
		if (ret == -EAGAIN) {
			*want = POLLOUT;
			return -EAGAIN;
		}
		if (ret)
			return ret;

		sctp->head = r->next;
		if (!sctp->head)
			sctp->tail = &sctp->head;
		sctp->queued -= r->len;

		/*
		 * The server switches before its Finished, the client after
		 * its own - see "DTLS over SCTP" in esdm_tls.h
		 */
		if (sctp->key_added && !sctp->key_active &&
		    ((sctp->server && r->type == ESDM_TLS_SCTP_CCS) ||
		     (!sctp->server && r->type == ESDM_TLS_SCTP_HANDSHAKE &&
		      r->epoch > 0)))
			ret = esdm_tls_sctp_key_activate(sctp);

		free(r);
		if (ret)
			return ret;
	}

	return 0;
}

int esdm_tls_sctp_established(struct esdm_tls_sctp *sctp,
			       esdm_tls_sctp_export exp, void *arg)
{
	uint8_t key[ESDM_TLS_SCTP_KEY_LEN];
	struct sctp_authkeyid id = { 0 };
	socklen_t len = sizeof(id);
	int ret;

	/* No handshake completes without its ChangeCipherSpec and Finished */
	if (!sctp->key_added || !sctp->key_active) {
		snprintf(sctp->error, sizeof(sctp->error),
			 "the handshake completed without the key switch of SCTP-AUTH");
		return -EPROTO;
	}

	/*
	 * Exported in the middle of the handshake, the key is the one the
	 * complete session exports - a TLS stack that told otherwise would
	 * have the peer drop every chunk of ours. Botan computes it here, see
	 * esdm_tls_botan.cpp.
	 */
	ret = exp(arg, key, sizeof(key));
	if (!ret && memcmp(key, sctp->key, sizeof(key)))
		ret = -EPROTO;
	memset_secure(key, 0, sizeof(key));
	memset_secure(sctp->key, 0, sizeof(sctp->key));
	if (ret) {
		snprintf(sctp->error, sizeof(sctp->error),
			 "the key of SCTP-AUTH is not the one the DTLS session exports");
		return ret;
	}

	if (getsockopt(sctp->fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &id,
		       &len) < 0 ||
	    id.scact_keynumber != sctp->new_key) {
		snprintf(sctp->error, sizeof(sctp->error),
			 "the key of SCTP-AUTH from the DTLS session is not the active one");
		return -EPROTO;
	}

	/*
	 * The peer's Finished is received, and nothing of the peer with the
	 * old key is to come (RFC 6083 section 4.8). What is in flight still
	 * holds the key for its own retransmission.
	 */
	id.scact_assoc_id = 0;
	id.scact_keynumber = sctp->old_key;
	if (setsockopt(sctp->fd, IPPROTO_SCTP, SCTP_AUTH_DELETE_KEY, &id,
		       sizeof(id)) < 0) {
		ret = -errno;
		snprintf(sctp->error, sizeof(sctp->error),
			 "cannot delete the old key of SCTP-AUTH: %s",
			 strerror(-ret));
		return ret;
	}

	return 0;
}
