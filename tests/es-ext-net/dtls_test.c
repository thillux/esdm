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
 * DTLS over SCTP of common/esdm_tls.h - RFC 6083 with SCTP-AUTH - and the
 * messages of common/esdm_dtls.h on it, for the TLS stack of the build, over
 * SCTP on loopback. Both ends run in this one thread, each step of the one
 * made whenever the other waits, so no timing decides anything.
 *
 *  - SCTP-AUTH: negotiated for DATA and FORWARD-TSN chunks both ways, the key
 *    of the DTLS session the active one on either end once the handshake is
 *    complete and the empty key 0 gone - and no data before. A peer without
 *    SCTP-AUTH, or one not requiring it for DATA, is refused on either side.
 *  - The certificates as on the stream transport: mutual authentication, no
 *    client certificate, an untrusted CA, an expired client, a wrong server
 *    name, a revoked client and a revoked intermediate CA with crl_check_all,
 *    the rotation of the server certificate, a rotation that does not load,
 *    and the revocation of an established connection.
 *  - Messages of one record and of several, both ways, IPv4 and IPv6.
 *  - A record sent once more on the association is dropped by the replay
 *    detection of DTLS, which is on with every TLS stack.
 *
 * Skips (77) in a build without es-ext-net, and on a kernel without SCTP.
 */

#define _GNU_SOURCE
#include "config.h"

#include "es_ext_net_test.h"

#include "esdm_dtls.h"
#include "esdm_logger.h"
#include "esdm_tls.h"

#ifdef ESDM_TLS_SCTP

static struct esdm_tls_config cfg_of(const char *cert, const char *key,
				     const char *ca)
{
	struct esdm_tls_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_file = ca;
	cfg.transport = ESDM_TLS_TRANSPORT_SCTP;
	return cfg;
}

static void cfg_add_crl(struct esdm_tls_config *cfg, const char *crl)
{
	cfg->crl_files[cfg->crl_files_num++] = crl;
}

static struct esdm_tls_ctx *ctx_of(bool server,
				   const struct esdm_tls_config *cfg)
{
	struct esdm_tls_ctx *ctx = NULL;
	int ret = esdm_tls_ctx_alloc(server, cfg, &ctx);

	CHECK(!ret, "%s context: %s", server ? "server" : "client",
	      strerror(-ret));
	return ctx;
}

/* One association between the two ends, and the DTLS of each */
struct pair {
	int lfd, sfd, cfd;
	struct esdm_tls *s, *c;
	int sret, cret;
};

/*
 * Associate on @addr, each end set up for SCTP-AUTH if asked to.
 *
 * @return 0, or -1
 */
static int pair_connect(struct pair *p, const char *addr, bool sauth,
			bool cauth)
{
	uint16_t port;

	memset(p, 0, sizeof(*p));
	p->lfd = p->sfd = p->cfd = -1;

	p->lfd = test_sctp_listener(addr, sauth, &port);
	if (p->lfd < 0)
		return -1;
	p->cfd = test_sctp_connect(addr, port, cauth);
	if (p->cfd < 0)
		return -1;
	p->sfd = accept4(p->lfd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
	return p->sfd < 0 ? -1 : 0;
}

static int pair_open_on(struct pair *p, const char *addr,
			struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx,
			const char *name)
{
	if (!sctx || !cctx || pair_connect(p, addr, true, true))
		return -1;

	if (esdm_tls_alloc(sctx, p->sfd, NULL, &p->s) ||
	    esdm_tls_alloc(cctx, p->cfd, name, &p->c))
		return -1;

	p->sret = p->cret = -EAGAIN;
	return 0;
}

static int pair_open(struct pair *p, struct esdm_tls_ctx *sctx,
		     struct esdm_tls_ctx *cctx, const char *name)
{
	return pair_open_on(p, "127.0.0.1", sctx, cctx, name);
}

static void pair_close(struct pair *p)
{
	esdm_tls_free(p->s);
	esdm_tls_free(p->c);
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
		{ .fd = p->sfd, .events = esdm_tls_want(p->s) },
		{ .fd = p->cfd, .events = esdm_tls_want(p->c) },
	};

	if (esdm_tls_pending(p->s) || esdm_tls_pending(p->c))
		return;
	poll(pfd, 2, 20);
}

/*
 * Run both handshakes to their end. An end that fails has its association
 * aborted, which is what the other one sees of it.
 *
 * @return 0 if both completed
 */
static int pair_handshake(struct pair *p)
{
	unsigned int i;

	for (i = 0; i < 2000 && (p->sret == -EAGAIN || p->cret == -EAGAIN);
	     i++) {
		if (p->sret == -EAGAIN) {
			p->sret = esdm_tls_handshake(p->s);
			if (p->sret && p->sret != -EAGAIN)
				shutdown(p->sfd, SHUT_RDWR);
		}
		if (p->cret == -EAGAIN) {
			p->cret = esdm_tls_handshake(p->c);
			if (p->cret && p->cret != -EAGAIN)
				shutdown(p->cfd, SHUT_RDWR);
		}
		pair_wait(p);
	}

	return (p->sret || p->cret) ? -1 : 0;
}

/* One record of @len bytes from @from to @to */
static int pair_record(struct pair *p, struct esdm_tls *from,
		       struct esdm_tls *to, const uint8_t *data, uint8_t *out,
		       size_t len)
{
	unsigned int i;
	ssize_t n;

	n = esdm_tls_send(from, data, len);
	if (n != (ssize_t)len)
		return n < 0 ? (int)n : -EIO;

	for (i = 0; i < 500; i++) {
		int ret = esdm_tls_flush(from);

		if (ret && ret != -EAGAIN)
			return ret;
		n = esdm_tls_recv(to, out, len + 1);
		if (n >= 0)
			return n == (ssize_t)len ? 0 : -EMSGSIZE;
		if (n != -EAGAIN)
			return (int)n;
		pair_wait(p);
	}

	return -ETIMEDOUT;
}

/* Receive until something other than -EAGAIN comes, for a while */
static ssize_t recv_result(struct pair *p, struct esdm_tls *t)
{
	uint8_t buf[64];
	unsigned int i;
	ssize_t n = -EAGAIN;

	for (i = 0; i < 500 && n == -EAGAIN; i++) {
		n = esdm_tls_recv(t, buf, sizeof(buf));
		if (n == -EAGAIN)
			pair_wait(p);
	}
	return n;
}

/* The keys of SCTP-AUTH of an end whose handshake is complete */
static void check_keys(int fd, const char *who)
{
	CHECK(test_sctp_auth_chunks(fd, SCTP_LOCAL_AUTH_CHUNKS),
	      "%s: SCTP-AUTH is not required for DATA and FORWARD-TSN", who);
	CHECK(test_sctp_auth_chunks(fd, SCTP_PEER_AUTH_CHUNKS),
	      "%s: the peer does not require SCTP-AUTH for DATA and FORWARD-TSN",
	      who);
	CHECK(test_sctp_active_key(fd) == 1,
	      "%s: the active key is %d, not the one of the DTLS session (1)",
	      who, test_sctp_active_key(fd));
	CHECK(!test_sctp_has_key(fd, 0),
	      "%s: the empty key 0 was not deleted", who);
}

static void test_auth(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config ccfg = cfg_of(PKI("client1.crt"),
					     PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = ctx_of(true, &scfg),
			    *cctx = ctx_of(false, &ccfg);
	uint8_t data[ESDM_TLS_SCTP_RECORD_MAX], out[sizeof(data) + 1];
	uint8_t fp[ESDM_TLS_FINGERPRINT_LEN];
	char hex[ESDM_TLS_FINGERPRINT_HEX_LEN];
	struct esdm_tls *t = NULL;
	struct pair p;
	unsigned int i;

	printf("DTLS over SCTP (%s): SCTP-AUTH and its keys\n",
	       esdm_tls_stack());

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	/* Key 0 and no data before the handshake */
	CHECK(test_sctp_active_key(p.sfd) == 0 &&
		      test_sctp_active_key(p.cfd) == 0,
	      "an association starts with key %d / %d, not the empty key 0",
	      test_sctp_active_key(p.sfd), test_sctp_active_key(p.cfd));
	CHECK(esdm_tls_send(p.c, "x", 1) == -ENOTCONN,
	      "data was taken before the handshake");
	CHECK(!pair_handshake(&p), "handshake: server %d (%s), client %d (%s)",
	      p.sret, esdm_tls_error(p.s), p.cret, esdm_tls_error(p.c));
	check_keys(p.sfd, "server");
	check_keys(p.cfd, "client");

	CHECK(!esdm_tls_peer_fingerprint(p.s, fp), "no fingerprint");
	esdm_tls_fingerprint_hex(fp, hex);
	printf("  client: %s, SHA-256 %s, cipher %s\n",
	       esdm_tls_peer_subject(p.s), hex, esdm_tls_cipher(p.s));
	CHECK(strstr(esdm_tls_peer_subject(p.s), "Client 1"),
	      "the server sees the subject %s", esdm_tls_peer_subject(p.s));
	CHECK(strstr(esdm_tls_peer_subject(p.c), "Test Server"),
	      "the client sees the subject %s", esdm_tls_peer_subject(p.c));

	/* Records both ways, the largest one, and one too large to send */
	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7);
	CHECK(!pair_record(&p, p.c, p.s, data, out, 10) &&
		      !memcmp(data, out, 10),
	      "a record from the client");
	CHECK(!pair_record(&p, p.s, p.c, data, out, 10) &&
		      !memcmp(data, out, 10),
	      "a record from the server");
	CHECK(!pair_record(&p, p.s, p.c, data, out, sizeof(data)) &&
		      !memcmp(data, out, sizeof(data)),
	      "the largest record");
	CHECK(esdm_tls_send(p.c, data, sizeof(data) + 1) == -EMSGSIZE,
	      "a record too large was taken");
	pair_close(&p);

	/* A peer without SCTP-AUTH, on either side */
	printf("  refusals of a peer without SCTP-AUTH follow:\n");
	CHECK(!pair_connect(&p, "127.0.0.1", true, false), "pair");
	CHECK(esdm_tls_alloc(sctx, p.sfd, NULL, &t) == -EPROTONOSUPPORT,
	      "the server took a client without SCTP-AUTH");
	esdm_tls_free(t);
	t = NULL;
	pair_close(&p);
	CHECK(!pair_connect(&p, "127.0.0.1", false, true), "pair");
	CHECK(esdm_tls_alloc(cctx, p.cfd, "localhost", &t) ==
		      -EPROTONOSUPPORT,
	      "the client took a server without SCTP-AUTH");
	esdm_tls_free(t);
	t = NULL;
	pair_close(&p);

	/*
	 * A peer requiring SCTP-AUTH for other chunks only: the association
	 * has SCTP-AUTH, but not for the DATA of the client
	 */
	{
		struct sctp_assoc_value av = { .assoc_value = 1 };
		struct sctp_authchunk ac = { .sauth_chunk = 0x80 /* ASCONF */ };
		struct sockaddr_storage ss;
		uint16_t port;
		int lfd = test_sctp_listener("127.0.0.1", true, &port);
		int cfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC,
				 IPPROTO_SCTP), sfd = -1;
		socklen_t len = test_sockaddr("127.0.0.1", port, &ss);

		setsockopt(cfd, IPPROTO_SCTP, SCTP_AUTH_SUPPORTED, &av,
			   sizeof(av));
		setsockopt(cfd, IPPROTO_SCTP, SCTP_AUTH_CHUNK, &ac, sizeof(ac));
		CHECK(lfd >= 0 && cfd >= 0 &&
			      !connect(cfd, (struct sockaddr *)&ss, len),
		      "connect");
		sfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
		CHECK(sfd >= 0 && esdm_tls_alloc(sctx, sfd, NULL, &t) ==
					  -EPROTONOSUPPORT,
		      "the server took a client authenticating no DATA chunks");
		esdm_tls_free(t);
		t = NULL;
		if (sfd >= 0)
			close(sfd);
		if (cfd >= 0)
			close(cfd);
		if (lfd >= 0)
			close(lfd);
	}

	/* IPv6, where the host has it */
	if (!pair_open_on(&p, "::1", sctx, cctx, "::1")) {
		CHECK(!pair_handshake(&p), "handshake on IPv6: %s / %s",
		      esdm_tls_error(p.s), esdm_tls_error(p.c));
		check_keys(p.sfd, "server on IPv6");
		check_keys(p.cfd, "client on IPv6");
	} else {
		printf("  no IPv6 on loopback - skipped\n");
	}
	pair_close(&p);

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

/*
 * The handshake fails on the server - which refused the client, or was refused
 * by it -, and the client learns it by the alert of the server: in its
 * handshake, or by its first receive, as the handshake of DTLS 1.2 may
 * complete for the client before the server judged its certificate. Which
 * alert depends on the TLS stack - a missing certificate is a handshake
 * failure to some -, so any error tells.
 */
static void expect_refused(struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx,
			   const char *name, const char *what)
{
	struct pair p;
	ssize_t n;

	CHECK(!pair_open(&p, sctx, cctx, name), "pair");
	CHECK(pair_handshake(&p), "%s: the handshake completed", what);
	CHECK(p.sret == -EACCES, "%s: the server's handshake returned %d (%s)",
	      what, p.sret, esdm_tls_error(p.s));
	printf("  %s, the server says: %s\n", what, esdm_tls_error(p.s));
	n = p.cret;
	if (!n)
		n = recv_result(&p, p.c);
	CHECK(n < 0 && n != -EAGAIN, "%s: the client did not notice: %zd",
	      what, n);
	if (n < 0)
		printf("  %s, the client is told: %s\n", what,
		       esdm_tls_error(p.c));
	pair_close(&p);
}

static void expect_accepted(struct esdm_tls_ctx *sctx,
			    struct esdm_tls_ctx *cctx, const char *what)
{
	struct pair p;

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "%s: server %d (%s), client %d (%s)", what,
	      p.sret, esdm_tls_error(p.s), p.cret, esdm_tls_error(p.c));
	pair_close(&p);
}

static void test_refusals(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config none = cfg_of(NULL, NULL, PKI("ca.crt"));
	struct esdm_tls_config rogue = cfg_of(PKI("rogue-client.crt"),
					      PKI("rogue-client.key"),
					      PKI("rogue-ca.crt"));
	struct esdm_tls_config expired = cfg_of(PKI("client-expired.crt"),
						PKI("client-expired.key"),
						PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config wrong = cfg_of(PKI("server-wrongname.crt"),
					      PKI("server-wrongname.key"),
					      PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = ctx_of(true, &scfg),
			    *cnone = ctx_of(false, &none),
			    *crogue = ctx_of(false, &rogue),
			    *cexpired = ctx_of(false, &expired),
			    *cc1 = ctx_of(false, &c1),
			    *swrong = ctx_of(true, &wrong);

	printf("DTLS over SCTP (%s): refused peers\n", esdm_tls_stack());

	expect_refused(sctx, cnone, "localhost", "no client certificate");
	/* The rogue client does not trust the server either: both fail */
	expect_refused(sctx, crogue, "localhost", "an untrusted CA");
	expect_refused(sctx, cexpired, "localhost", "an expired client");
	expect_refused(swrong, cc1, "localhost",
		       "a server of another name");
	expect_refused(sctx, cc1, "wrong.example", "a name not of the server");
	expect_accepted(sctx, cc1, "client 1");

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cnone);
	esdm_tls_ctx_put(crogue);
	esdm_tls_ctx_put(cexpired);
	esdm_tls_ctx_put(cc1);
	esdm_tls_ctx_put(swrong);
}

/*
 * DTLS 1.2 has no signature of ML-DSA: a context with a certificate on ML-DSA
 * is not built - see "Post-quantum algorithms" in esdm_tls.h. Certificates on
 * ECDSA of a CA on ML-DSA-87 serve where the TLS stack verifies ML-DSA, those
 * of a CA on ML-DSA-65 are refused.
 */
static void test_mldsa(void)
{
	struct esdm_tls_config mldsa =
		cfg_of(PKI("mldsa-server.crt"), PKI("mldsa-server.key"),
		       PKI("mldsa-ca.crt"));
	struct esdm_tls_config scfg =
		cfg_of(PKI("mldsa-ec-server.crt"), PKI("mldsa-ec-server.key"),
		       PKI("mldsa-ca.crt"));
	struct esdm_tls_config ccfg =
		cfg_of(PKI("mldsa-ec-client.crt"), PKI("mldsa-ec-client.key"),
		       PKI("mldsa-ca.crt"));
	struct esdm_tls_config c65 =
		cfg_of(PKI("mldsa65-ec-client.crt"),
		       PKI("mldsa65-ec-client.key"), PKI("mldsa-ca.crt"));
	struct esdm_tls_ctx *ctx = NULL, *sctx, *cctx;
	int ret;

	printf("DTLS over SCTP (%s): ML-DSA\n", esdm_tls_stack());

	ret = esdm_tls_ctx_alloc(true, &mldsa, &ctx);
	CHECK(ret == -EINVAL,
	      "a context with a certificate on ML-DSA was not refused: %d",
	      ret);
	esdm_tls_ctx_put(ctx);

	if (!(esdm_tls_mldsa() & ESDM_TLS_MLDSA_CA)) {
		printf("  the TLS stack verifies no ML-DSA, no CA on it\n");
		return;
	}
	sctx = ctx_of(true, &scfg);
	cctx = ctx_of(false, &ccfg);
	expect_accepted(sctx, cctx, "ECDSA certificates of a CA on ML-DSA");
	esdm_tls_ctx_put(cctx);
	cctx = ctx_of(false, &c65);
	expect_refused(sctx, cctx, "localhost",
		       "an ECDSA client of a CA on ML-DSA-65");
	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

/* Receive the next record - or what is no -EAGAIN -, for a while */
static ssize_t recv_record(struct pair *p, struct esdm_tls *t, uint8_t *buf,
			   size_t len)
{
	unsigned int i;
	ssize_t n = -EAGAIN;

	for (i = 0; i < 100 && n == -EAGAIN; i++) {
		n = esdm_tls_recv(t, buf, len);
		if (n == -EAGAIN)
			pair_wait(p);
	}
	return n;
}

/*
 * A record of the client sent once more on the association, as a user message
 * of its own - authenticated with the key of SCTP-AUTH, as the peer itself
 * could send it: the replay detection of DTLS drops it, with every TLS stack,
 * and the connection goes on - see "DTLS over SCTP" in esdm_tls.h
 */
static void test_replay(void)
{
	struct esdm_tls_config scfg =
		cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config ccfg =
		cfg_of(PKI("client1.crt"), PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = ctx_of(true, &scfg),
			    *cctx = ctx_of(false, &ccfg);
	static const uint8_t first[] = "the record sent twice";
	static const uint8_t second[] = "the record after it";
	static uint8_t rec[20000];
	uint8_t out[64];
	struct iovec iov = { .iov_base = rec, .iov_len = sizeof(rec) };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	struct pollfd pfd;
	struct pair p;
	ssize_t len, n;

	printf("DTLS over SCTP (%s): a record replayed\n", esdm_tls_stack());

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake: server %d (%s), client %d (%s)",
	      p.sret, esdm_tls_error(p.s), p.cret, esdm_tls_error(p.c));

	/* A record each way: what SCTP notifies of the handshake is taken */
	CHECK(!pair_record(&p, p.c, p.s, first, out, sizeof(first)),
	      "a record of the client");
	CHECK(!pair_record(&p, p.s, p.c, first, out, sizeof(first)),
	      "a record of the server");

	/* The record, looked at on the socket of the server before it is taken */
	CHECK(esdm_tls_send(p.c, first, sizeof(first)) ==
		      (ssize_t)sizeof(first),
	      "send");
	CHECK(!esdm_tls_flush(p.c), "flush");
	pfd.fd = p.sfd;
	pfd.events = POLLIN;
	CHECK(poll(&pfd, 1, 2000) == 1, "the record did not arrive");
	len = recvmsg(p.sfd, &msg, MSG_PEEK | MSG_DONTWAIT);
	CHECK(len > 0 && !(msg.msg_flags & MSG_NOTIFICATION) &&
		      (msg.msg_flags & MSG_EOR),
	      "no record to replay: %zd, flags %x", len, msg.msg_flags);
	n = recv_record(&p, p.s, out, sizeof(out));
	CHECK(n == (ssize_t)sizeof(first) && !memcmp(out, first, sizeof(first)),
	      "the record was not received: %zd (%s)", n, esdm_tls_error(p.s));

	/* Sent again, then a new one */
	if (len > 0)
		CHECK(send(p.cfd, rec, (size_t)len, MSG_NOSIGNAL) == len,
		      "replay: %s", strerror(errno));
	CHECK(esdm_tls_send(p.c, second, sizeof(second)) ==
		      (ssize_t)sizeof(second),
	      "send");
	CHECK(!esdm_tls_flush(p.c), "flush");

	n = recv_record(&p, p.s, out, sizeof(out));
	CHECK(n == (ssize_t)sizeof(second) &&
		      !memcmp(out, second, sizeof(second)),
	      "the replayed record was delivered, or the next one not: %zd (%s)",
	      n, esdm_tls_error(p.s));
	/* On the one ordered stream, nothing can follow the second record */
	CHECK(esdm_tls_recv(p.s, out, sizeof(out)) == -EAGAIN,
	      "more than the two records arrived");
	if (n == (ssize_t)sizeof(second))
		printf("  the replayed record was dropped, the next one taken\n");

	pair_close(&p);
	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

static void test_crl(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config crev = cfg_of(PKI("client-revoked.crt"),
					     PKI("client-revoked.key"),
					     PKI("ca.crt"));
	struct esdm_tls_ctx *sctx, *cc1 = ctx_of(false, &c1),
				   *ccrev = ctx_of(false, &crev);
	struct esdm_tls_ctx *srev;
	char why[256];
	struct pair p;

	printf("DTLS over SCTP (%s): revocation\n", esdm_tls_stack());

	/* The CRL of the intermediate CA lists client-revoked */
	cfg_add_crl(&scfg, PKI("int.crl"));
	sctx = ctx_of(true, &scfg);
	expect_refused(sctx, ccrev, "localhost", "a revoked client");
	expect_accepted(sctx, cc1, "client 1, not revoked");
	esdm_tls_ctx_put(sctx);

	/* The intermediate CA revoked, which crl_check_all looks at */
	scfg.crl_files_num = 0;
	cfg_add_crl(&scfg, PKI("int-empty.crl"));
	cfg_add_crl(&scfg, PKI("ca-revoked-int.crl"));
	scfg.crl_check_all = true;
	sctx = ctx_of(true, &scfg);
	expect_refused(sctx, cc1, "localhost",
		       "a client of a revoked intermediate CA");
	esdm_tls_ctx_put(sctx);
	scfg.crl_files_num = 0;
	cfg_add_crl(&scfg, PKI("int-empty.crl"));
	cfg_add_crl(&scfg, PKI("ca.crl"));
	sctx = ctx_of(true, &scfg);
	expect_accepted(sctx, cc1, "client 1 with crl_check_all");

	/*
	 * An established connection checked against the CRLs of a context
	 * loaded after it: revoked then
	 */
	scfg.crl_files_num = 0;
	scfg.crl_check_all = false;
	cfg_add_crl(&scfg, PKI("int.crl"));
	srev = ctx_of(true, &scfg);
	CHECK(!pair_open(&p, sctx, ccrev, "localhost"), "pair");
	CHECK(!pair_handshake(&p),
	      "the client revoked later was refused at once: %s",
	      esdm_tls_error(p.s));
	CHECK(esdm_tls_peer_revoked(p.s, sctx, why, sizeof(why)) == 0,
	      "revoked by the CRLs it was accepted with");
	CHECK(esdm_tls_peer_revoked(p.s, srev, why, sizeof(why)) == 1,
	      "not revoked by the CRL loaded after: %s", why);
	printf("  established, then revoked: %s\n", why);
	pair_close(&p);

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(srev);
	esdm_tls_ctx_put(cc1);
	esdm_tls_ctx_put(ccrev);
}

static void test_rotation(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config renewed = cfg_of(PKI("server-renewed.crt"),
						PKI("server-renewed.key"),
						PKI("ca.crt"));
	struct esdm_tls_config broken = cfg_of(PKI("server-renewed.crt"),
					       PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sold = ctx_of(true, &scfg),
			    *snew = ctx_of(true, &renewed),
			    *cc1 = ctx_of(false, &c1), *sbroken = NULL;
	uint8_t fp_old[ESDM_TLS_FINGERPRINT_LEN],
		fp_new[ESDM_TLS_FINGERPRINT_LEN];
	uint8_t data[64], out[65];
	struct pair p_old, p_new;

	printf("DTLS over SCTP (%s): rotation\n", esdm_tls_stack());

	memset(data, 0x5a, sizeof(data));
	CHECK(!pair_open(&p_old, sold, cc1, "localhost"), "pair");
	CHECK(!pair_handshake(&p_old), "handshake with the old certificate");
	CHECK(!esdm_tls_peer_fingerprint(p_old.c, fp_old), "fingerprint");

	/* The renewed one for new connections, the old one goes on */
	CHECK(!pair_open(&p_new, snew, cc1, "localhost"), "pair");
	CHECK(!pair_handshake(&p_new), "handshake with the renewed one");
	CHECK(!esdm_tls_peer_fingerprint(p_new.c, fp_new) &&
		      memcmp(fp_old, fp_new, sizeof(fp_old)),
	      "the renewed certificate is not the one presented");
	CHECK(!pair_record(&p_old, p_old.c, p_old.s, data, out, sizeof(data)),
	      "the connection of the old certificate stopped working");

	/* A rotation that does not load leaves the old context in service */
	printf("  an error about a key not of its certificate follows:\n");
	CHECK(esdm_tls_ctx_alloc(true, &broken, &sbroken) == -EINVAL,
	      "a key of another certificate was taken");
	esdm_tls_ctx_put(sbroken);
	pair_close(&p_new);
	expect_accepted(sold, cc1, "the old context after a broken rotation");
	CHECK(!pair_record(&p_old, p_old.s, p_old.c, data, out, sizeof(data)),
	      "the connection of the old certificate stopped working");
	pair_close(&p_old);

	esdm_tls_ctx_put(sold);
	esdm_tls_ctx_put(snew);
	esdm_tls_ctx_put(cc1);
}

/* The messages of esdm_dtls.h on DTLS over SCTP */
static void test_messages(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config ccfg = cfg_of(PKI("client1.crt"),
					     PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = ctx_of(true, &scfg),
			    *cctx = ctx_of(false, &ccfg);
	static uint8_t big[40000], out[40001];
	struct esdm_dtls *s = NULL, *c = NULL;
	int sret = -EAGAIN, cret = -EAGAIN;
	struct pair p;
	unsigned int i;
	ssize_t n;

	printf("DTLS over SCTP (%s): messages of esdm_dtls.h\n",
	       esdm_tls_stack());

	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i ^ (i >> 8));

	CHECK(!pair_connect(&p, "127.0.0.1", true, true), "pair");
	CHECK(!esdm_dtls_alloc_tls(sctx, p.sfd, sizeof(big), NULL, &s),
	      "server");
	CHECK(!esdm_dtls_alloc_tls(cctx, p.cfd, sizeof(big), "localhost", &c),
	      "client");
	CHECK(esdm_dtls_tls(s) && esdm_dtls_tls(c),
	      "no TLS connection under the messages");
	for (i = 0; i < 2000 && (sret == -EAGAIN || cret == -EAGAIN); i++) {
		struct pollfd pfd[2] = {
			{ .fd = p.sfd, .events = esdm_dtls_want(s) },
			{ .fd = p.cfd, .events = esdm_dtls_want(c) },
		};

		if (sret == -EAGAIN)
			sret = esdm_dtls_handshake(s);
		if (cret == -EAGAIN)
			cret = esdm_dtls_handshake(c);
		poll(pfd, 2, 20);
	}
	CHECK(!sret && !cret, "handshake: %d / %d", sret, cret);

	/* One record, and one of three - a part has 16000 bytes */
	CHECK(!esdm_dtls_send(c, "request", 7), "send");
	for (i = 0, n = -EAGAIN; i < 500 && n == -EAGAIN; i++) {
		n = esdm_dtls_recv(s, out, sizeof(out));
		if (n == -EAGAIN)
			test_sleep_ms(2);
	}
	CHECK(n == 7 && !memcmp(out, "request", 7), "small message: %zd", n);

	CHECK(!esdm_dtls_send(s, big, sizeof(big)), "send a large message");
	for (i = 0, n = -EAGAIN; i < 500 && n == -EAGAIN; i++) {
		n = esdm_dtls_recv(c, out, sizeof(out));
		if (n == -EAGAIN)
			test_sleep_ms(2);
	}
	CHECK(n == (ssize_t)sizeof(big) && !memcmp(out, big, sizeof(big)),
	      "large message: %zd", n);

	esdm_dtls_free(s);
	esdm_dtls_free(c);
	pair_close(&p);
	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);

	if (!test_sctp_available())
		return 77;

	test_auth();
	test_refusals();
	test_mldsa();
	test_replay();
	test_crl();
	test_rotation();
	test_messages();

	printf("DTLS over SCTP (%s): %s\n", esdm_tls_stack(),
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else /* ESDM_TLS_SCTP */

int main(void)
{
	printf("Built without es-ext-net\n");
	return 77;
}

#endif /* ESDM_TLS_SCTP */
