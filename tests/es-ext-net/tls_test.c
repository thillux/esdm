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
 * The messages of common/tls/esdm_dtls.h on the TLS of common/tls/esdm_tls.h over TCP,
 * for the TLS stack of the build, on loopback - what the external entropy
 * sources on the network speak. Both ends run in this one thread, each step of
 * the one made whenever the other waits, so no timing decides anything.
 *
 *  - Messages of one record and of several, both ways, on IPv4 and IPv6.
 *  - A record whose frame arrives in pieces - its length apart, then the rest
 *    - is taken once it is complete.
 *  - A frame no record of the messages has - of length 0, or longer than a
 *    part can be - ends the connection.
 *
 * The certificates, the server name and the revocation on TLS over a stream
 * socket are those of the EGD network tests, tests/egd-net/tls_test.c.
 *
 * Skips (77) in a build without es-ext-net.
 */

#define _GNU_SOURCE
#include "config.h"

#include "es_ext_net_test.h"

#include "esdm_dtls.h"
#include "esdm_logger.h"
#include "esdm_tls.h"

#ifdef ESDM_ES_EXT_NET

static struct esdm_tls_ctx *ctx_of(bool server, const char *cert,
				   const char *key)
{
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_files[0] = PKI("ca.crt");
	cfg.ca_files_num = 1;
	cfg.transport = ESDM_TLS_TRANSPORT_STREAM;
	ret = esdm_tls_ctx_alloc(server, &cfg, &ctx);
	CHECK(!ret, "%s context: %s", server ? "server" : "client",
	      strerror(-ret));
	return ctx;
}

/* One connection between the two ends, and the messages of each */
struct pair {
	int lfd, sfd, cfd;
	struct esdm_dtls *s, *c;
};

static void pair_close(struct pair *p)
{
	esdm_dtls_free(p->s);
	esdm_dtls_free(p->c);
	if (p->sfd >= 0)
		close(p->sfd);
	if (p->cfd >= 0)
		close(p->cfd);
	if (p->lfd >= 0)
		close(p->lfd);
	memset(p, 0, sizeof(*p));
	p->lfd = p->sfd = p->cfd = -1;
}

/* Wait until one of the ends can make progress */
static void pair_wait(struct pair *p)
{
	struct pollfd pfd[2] = {
		{ .fd = p->sfd, .events = esdm_dtls_want(p->s) },
		{ .fd = p->cfd, .events = esdm_dtls_want(p->c) },
	};

	if (esdm_dtls_pending(p->s) || esdm_dtls_pending(p->c))
		return;
	poll(pfd, 2, 20);
}

/*
 * Connect on @addr and run both handshakes to their end.
 *
 * @return 0 if both completed, 1 if @addr cannot be bound, -1 otherwise
 */
static int pair_open(struct pair *p, const char *addr,
		     struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx,
		     size_t max_msg)
{
	int sret = -EAGAIN, cret = -EAGAIN;
	unsigned int i;
	uint16_t port;

	memset(p, 0, sizeof(*p));
	p->lfd = p->sfd = p->cfd = -1;
	p->lfd = test_tcp_listener(addr, &port);
	if (p->lfd < 0)
		return 1;
	p->cfd = test_tcp_connect_from(addr, port, NULL);
	if (p->cfd < 0)
		return -1;
	p->sfd = accept4(p->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (p->sfd < 0 || !sctx || !cctx ||
	    esdm_dtls_alloc_tls(sctx, p->sfd, max_msg, NULL, &p->s) ||
	    esdm_dtls_alloc_tls(cctx, p->cfd, max_msg, "localhost", &p->c))
		return -1;
	CHECK(esdm_dtls_tls(p->s) && esdm_dtls_tls(p->c),
	      "no TLS connection under the messages");

	for (i = 0; i < 2000 && (sret == -EAGAIN || cret == -EAGAIN); i++) {
		if (sret == -EAGAIN)
			sret = esdm_dtls_handshake(p->s);
		if (cret == -EAGAIN)
			cret = esdm_dtls_handshake(p->c);
		pair_wait(p);
	}
	CHECK(!sret && !cret, "handshake on %s: %d (%s) / %d (%s)", addr, sret,
	      esdm_tls_error(esdm_dtls_tls(p->s)), cret,
	      esdm_tls_error(esdm_dtls_tls(p->c)));
	return (sret || cret) ? -1 : 0;
}

/* Receive a message on @to, for @tries waits at most */
static ssize_t recv_tries(struct pair *p, struct esdm_dtls *to, uint8_t *buf,
			  size_t len, unsigned int tries)
{
	unsigned int i;
	ssize_t n = -EAGAIN;

	for (i = 0; i < tries && n == -EAGAIN; i++) {
		n = esdm_dtls_recv(to, buf, len);
		if (n == -EAGAIN)
			pair_wait(p);
	}
	return n;
}

static ssize_t recv_msg(struct pair *p, struct esdm_dtls *to, uint8_t *buf,
			size_t len)
{
	return recv_tries(p, to, buf, len, 500);
}

static void test_messages_on(const char *addr, struct esdm_tls_ctx *sctx,
			     struct esdm_tls_ctx *cctx)
{
	static uint8_t big[40000], out[40001];
	struct pair p;
	unsigned int i;
	ssize_t n;
	int ret;

	ret = pair_open(&p, addr, sctx, cctx, sizeof(big));
	if (ret > 0) {
		printf("  no %s on loopback - skipped\n", addr);
		pair_close(&p);
		return;
	}
	if (ret)
		goto out;
	printf("  %s: %s, %s\n", addr, esdm_dtls_cipher(p.c),
	       esdm_tls_group(esdm_dtls_tls(p.c)));

	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i ^ (i >> 8));

	/* One record, and one of three - a part has 16000 bytes - both ways */
	CHECK(!esdm_dtls_send(p.c, "request", 7), "send");
	n = recv_msg(&p, p.s, out, sizeof(out));
	CHECK(n == 7 && !memcmp(out, "request", 7), "small message: %zd", n);

	CHECK(!esdm_dtls_send(p.s, big, sizeof(big)), "send a large message");
	n = recv_msg(&p, p.c, out, sizeof(out));
	CHECK(n == (ssize_t)sizeof(big) && !memcmp(out, big, sizeof(big)),
	      "large message: %zd", n);

	CHECK(!esdm_dtls_send(p.c, big, sizeof(big)), "send a large message");
	n = recv_msg(&p, p.s, out, sizeof(out));
	CHECK(n == (ssize_t)sizeof(big) && !memcmp(out, big, sizeof(big)),
	      "large message of the client: %zd", n);

	/* An empty message is one too */
	CHECK(!esdm_dtls_send(p.s, big, 0), "send an empty message");
	CHECK(recv_msg(&p, p.c, out, sizeof(out)) == 0, "empty message");

out:
	pair_close(&p);
}

/*
 * Send @len bytes of a frame on the TLS under @from - in pieces of the stream,
 * as TCP may hand them over
 */
static void send_raw(struct pair *p, struct esdm_dtls *from, const void *buf,
		     size_t len)
{
	struct esdm_tls *tls = esdm_dtls_tls(from);
	unsigned int i;
	ssize_t n;

	n = esdm_tls_send(tls, buf, len);
	CHECK(n == (ssize_t)len, "raw send: %zd", n);
	for (i = 0; i < 100 && esdm_tls_flush(tls) == -EAGAIN; i++)
		pair_wait(p);
}

static void test_frames(struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx)
{
	/* A frame of the record "\0hello": the last part of "hello" */
	static const uint8_t frame[] = { 0, 6, 0, 'h', 'e', 'l', 'l', 'o' };
	static const uint8_t empty[] = { 0, 0 };
	static const uint8_t huge[] = { 0xff, 0xff };
	uint8_t out[64];
	struct pair p;
	ssize_t n;

	printf("Messages on TLS over TCP (%s): frames\n", esdm_tls_stack());

	/* The length apart, then the record in two pieces */
	if (pair_open(&p, "127.0.0.1", sctx, cctx, 1024))
		goto out;
	send_raw(&p, p.c, frame, 1);
	CHECK(recv_tries(&p, p.s, out, sizeof(out), 5) == -EAGAIN,
	      "a frame was taken without its length");
	send_raw(&p, p.c, frame + 1, 3);
	CHECK(recv_tries(&p, p.s, out, sizeof(out), 5) == -EAGAIN,
	      "a frame was taken in parts");
	send_raw(&p, p.c, frame + 4, sizeof(frame) - 4);
	n = recv_msg(&p, p.s, out, sizeof(out));
	CHECK(n == 5 && !memcmp(out, "hello", 5),
	      "the frame in pieces did not arrive: %zd", n);
	pair_close(&p);

	/* A frame of no record, empty or too long: the end of the connection */
	if (pair_open(&p, "127.0.0.1", sctx, cctx, 1024))
		goto out;
	send_raw(&p, p.c, empty, sizeof(empty));
	n = recv_msg(&p, p.s, out, sizeof(out));
	CHECK(n == -EPROTO, "an empty frame was taken: %zd", n);
	pair_close(&p);

	if (pair_open(&p, "127.0.0.1", sctx, cctx, 1024))
		goto out;
	send_raw(&p, p.c, huge, sizeof(huge));
	n = recv_msg(&p, p.s, out, sizeof(out));
	CHECK(n == -EPROTO, "a frame longer than a part was taken: %zd", n);

out:
	pair_close(&p);
}

int main(void)
{
	struct esdm_tls_ctx *sctx, *cctx;

	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);
	signal(SIGPIPE, SIG_IGN);

	sctx = ctx_of(true, PKI("server.crt"), PKI("server.key"));
	cctx = ctx_of(false, PKI("client1.crt"), PKI("client1.key"));

	printf("Messages on TLS over TCP (%s): messages\n", esdm_tls_stack());
	test_messages_on("127.0.0.1", sctx, cctx);
	test_messages_on("::1", sctx, cctx);
	test_frames(sctx, cctx);

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);

	printf("Messages on TLS over TCP (%s): %s\n", esdm_tls_stack(),
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else /* ESDM_ES_EXT_NET */

int main(void)
{
	printf("Built without es-ext-net\n");
	return 77;
}

#endif /* ESDM_ES_EXT_NET */
