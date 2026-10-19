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
 * A client of the external entropy source protocol for the tests, speaking
 * to a provider as the ESDM does: in the clear, or inside a DTLS session it
 * asks for with STARTDTLS - see esdm_es_ext.h. A test using it links the
 * common library of the ESDM, which has the DTLS.
 */

#ifndef _ES_EXT_TEST_CLIENT_H
#define _ES_EXT_TEST_CLIENT_H

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_dtls.h"
#include "esdm_es_ext_proto.h"

/* How long the client waits for an answer, or the handshake */
#define ES_EXT_TEST_CLIENT_TIMEOUT_MS 5000

/* The largest answer there is */
#define ES_EXT_TEST_CLIENT_RSP_MAX                                            \
	(ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA)

struct es_ext_test_client {
	int fd;
	/* NULL in the clear */
	struct esdm_dtls *dtls;
};

#ifdef ESDM_DTLS
static struct esdm_dtls_ctx *es_ext_test_client_dtls_ctx;
#endif

/* Wait up to the timeout for something to read on @fd */
static inline bool es_ext_test_client_wait(int fd)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	return poll(&pfd, 1, ES_EXT_TEST_CLIENT_TIMEOUT_MS) > 0;
}

/* Send the message @buf of @len bytes, in the clear or as DTLS */
static inline int es_ext_test_client_send(struct es_ext_test_client *c,
					  const void *buf, size_t len)
{
#ifdef ESDM_DTLS
	if (c->dtls)
		return esdm_dtls_send(c->dtls, buf, len);
#endif
	return send(c->fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -EIO;
}

/*
 * Receive the next message into @buf of @len bytes
 *
 * @return its size, 0 if the provider closed the connection, a negative errno
 */
static inline ssize_t es_ext_test_client_recv(struct es_ext_test_client *c,
					      void *buf, size_t len)
{
	ssize_t n;

	for (;;) {
#ifdef ESDM_DTLS
		if (c->dtls) {
			if (!esdm_dtls_pending(c->dtls) &&
			    !es_ext_test_client_wait(c->fd))
				return -ETIMEDOUT;
			n = esdm_dtls_recv(c->dtls, buf, len);
			if (n == -EAGAIN)
				continue;
			return n == -ECONNRESET ? 0 : n;
		}
#endif
		if (!es_ext_test_client_wait(c->fd))
			return -ETIMEDOUT;
		n = recv(c->fd, buf, len, MSG_DONTWAIT);
		if (n < 0 && (errno == EAGAIN || errno == EINTR))
			continue;
		return n < 0 ? -errno : n;
	}
}

/*
 * Send a request of @type for @length bytes and receive the answer into @rsp
 * of @rsplen bytes
 *
 * @return the size of the answer, 0 if the provider closed the connection on
 *	   the request, a negative errno
 */
static inline ssize_t es_ext_test_client_request(struct es_ext_test_client *c,
						 uint16_t type,
						 uint32_t length, uint8_t *rsp,
						 size_t rsplen)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	int ret;

	esdm_es_ext_proto_req_pack(req, type, length);
	ret = es_ext_test_client_send(c, req, sizeof(req));
	if (ret)
		return ret;
	return es_ext_test_client_recv(c, rsp, rsplen);
}

static inline void es_ext_test_client_close(struct es_ext_test_client *c)
{
#ifdef ESDM_DTLS
	esdm_dtls_free(c->dtls);
#endif
	c->dtls = NULL;
	if (c->fd >= 0)
		close(c->fd);
	c->fd = -1;
}

/*
 * Connect to the provider on @path, with DTLS if @dtls - which the provider
 * has to agree to
 *
 * @return 0 when connected, a negative errno otherwise
 */
static inline int es_ext_test_client_open(struct es_ext_test_client *c,
					  const char *path, bool dtls)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };

	c->dtls = NULL;
	c->fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
		       0);
	if (c->fd < 0)
		return -errno;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int ret = -errno;

		es_ext_test_client_close(c);
		return ret;
	}

	if (!dtls)
		return 0;

#ifdef ESDM_DTLS
	{
		uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
		const uint8_t *data;
		uint32_t bits;
		int32_t status;
		ssize_t n;
		int ret;

		n = es_ext_test_client_request(c, ESDM_ES_EXT_PROTO_STARTDTLS,
					       0, rsp, sizeof(rsp));
		if (n <= 0 ||
		    esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
						 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
						 &status, &bits, &data) ||
		    status) {
			es_ext_test_client_close(c);
			return -EOPNOTSUPP;
		}

		if (!es_ext_test_client_dtls_ctx &&
		    esdm_dtls_ctx_alloc(false, &es_ext_test_client_dtls_ctx)) {
			es_ext_test_client_close(c);
			return -ENOMEM;
		}
		ret = esdm_dtls_alloc(es_ext_test_client_dtls_ctx, c->fd,
				      ES_EXT_TEST_CLIENT_RSP_MAX, &c->dtls);
		while (!ret) {
			ret = esdm_dtls_handshake(c->dtls);
			if (ret != -EAGAIN)
				break;
			ret = es_ext_test_client_wait(c->fd) ? 0 : -ETIMEDOUT;
		}
		if (ret) {
			es_ext_test_client_close(c);
			return ret;
		}
		return 0;
	}
#else
	es_ext_test_client_close(c);
	return -EOPNOTSUPP;
#endif
}

#endif /* _ES_EXT_TEST_CLIENT_H */
