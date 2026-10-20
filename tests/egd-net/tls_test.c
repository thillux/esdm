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
 * The TLS layer of the EGD network mode, common/esdm_tls.h, against the test
 * PKI of tests/egd-net/pki - for whichever TLS stack the build uses: the
 * mutual authentication, several CAs trusted for their rollover, the server
 * name, the revocation policy, the transfers and the end of a connection, and
 * the secure minimal mode and the algorithms on the wire. Both ends run in this one thread on a socket pair,
 * each step of the one made whenever the other waits, so no timing decides
 * anything. Skips (77) in a build without egd-net-tls.
 *
 * The post-quantum algorithms are parts of their own, run with an argument:
 * "mlkem" the key exchange by the hybrid of ML-KEM, which skips (77) where the
 * TLS stack lacks it, "mldsa" certificates on ML-DSA - a post-quantum
 * signature on its own - refused by every context.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../test_tls_wire.h"
#include "config.h"
#include "esdm_logger.h"
#include "esdm_tls.h"

#ifndef ESDM_TEST_PKI
#error "ESDM_TEST_PKI must name the directory of the test PKI"
#endif

#ifdef ESDM_EGD_NET_TLS

static int failures = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL (line %d): ", __LINE__);                \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			failures++;                                            \
		}                                                              \
	} while (0)

#define PKI(name) ESDM_TEST_PKI "/" name

/* The path of the file @name of the test PKI, which is no literal */
static const char *pki_file(const char *name)
{
	static char paths[8][512];
	static unsigned int next;
	char *path = paths[next++ % 8];

	snprintf(path, sizeof(paths[0]), "%s/%s", ESDM_TEST_PKI, name);
	return path;
}

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* A configuration of PKI files: cert and key by their base name */
static struct esdm_tls_config cfg_of(const char *cert, const char *key,
				     const char *ca)
{
	struct esdm_tls_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_files[0] = ca;
	cfg.ca_files_num = 1;
	return cfg;
}

static void cfg_add_crl(struct esdm_tls_config *cfg, const char *crl)
{
	cfg->crl_files[cfg->crl_files_num++] = crl;
}

static struct esdm_tls_ctx *server_ctx(const struct esdm_tls_config *cfg)
{
	struct esdm_tls_ctx *ctx = NULL;
	int ret = esdm_tls_ctx_alloc(true, cfg, &ctx);

	CHECK(!ret, "server context: %s", strerror(-ret));
	return ctx;
}

static struct esdm_tls_ctx *client_ctx(const struct esdm_tls_config *cfg)
{
	struct esdm_tls_ctx *ctx = NULL;
	int ret = esdm_tls_ctx_alloc(false, cfg, &ctx);

	CHECK(!ret, "client context: %s", strerror(-ret));
	return ctx;
}

/* One connection between the two ends */
struct pair {
	int sfd, cfd;
	struct esdm_tls *s, *c;
	int sret, cret;
};

static int pair_open(struct pair *p, struct esdm_tls_ctx *sctx,
		     struct esdm_tls_ctx *cctx, const char *name)
{
	int sv[2];

	memset(p, 0, sizeof(*p));
	p->sfd = p->cfd = -1;
	if (!sctx || !cctx)
		return -1;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
		       sv))
		return -1;
	p->sfd = sv[0];
	p->cfd = sv[1];

	if (esdm_tls_alloc(sctx, p->sfd, NULL, &p->s) ||
	    esdm_tls_alloc(cctx, p->cfd, name, &p->c))
		return -1;

	p->sret = p->cret = -EAGAIN;
	return 0;
}

static void pair_close(struct pair *p)
{
	esdm_tls_free(p->s);
	esdm_tls_free(p->c);
	if (p->sfd >= 0)
		close(p->sfd);
	if (p->cfd >= 0)
		close(p->cfd);
	memset(p, 0, sizeof(*p));
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
 * Run both handshakes to their end. An end that fails has its socket shut
 * down, which is what the other one sees of it, as it would of a peer closing
 * the connection.
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

/*
 * Move @len bytes from @from to @to - both ends make progress in turn, as
 * neither may block.
 */
static int transfer(struct pair *p, struct esdm_tls *from, struct esdm_tls *to,
		    const uint8_t *data, uint8_t *out, size_t len)
{
	size_t sent = 0, got = 0;
	bool flushed = false;
	unsigned int idle = 0;

	while (got < len && idle < 500) {
		bool progress = false;
		ssize_t n;

		if (sent < len) {
			n = esdm_tls_send(from, data + sent, len - sent);
			if (n > 0) {
				sent += (size_t)n;
				progress = true;
			} else if (n != -EAGAIN) {
				return (int)n;
			}
		} else if (!flushed) {
			int ret = esdm_tls_flush(from);

			if (!ret)
				flushed = true;
			else if (ret != -EAGAIN)
				return ret;
		}

		n = esdm_tls_recv(to, out + got, len - got);
		if (n > 0) {
			got += (size_t)n;
			progress = true;
		} else if (n != -EAGAIN) {
			return n ? (int)n : -EPIPE;
		}

		if (progress) {
			idle = 0;
		} else {
			idle++;
			pair_wait(p);
		}
	}

	return got == len ? 0 : -ETIMEDOUT;
}

/* Receive until something other than -EAGAIN comes, for a while */
static ssize_t recv_result(struct pair *p, struct esdm_tls *t)
{
	uint8_t byte;
	unsigned int i;
	ssize_t n = -EAGAIN;

	for (i = 0; i < 500 && n == -EAGAIN; i++) {
		n = esdm_tls_recv(t, &byte, 1);
		if (n == -EAGAIN)
			pair_wait(p);
	}
	return n;
}


/*
 * A server name to try: an IPv6 address only where the TLS stack checks one,
 * see esdm_tls_ip6_name()
 */
static bool name_usable(const char *name)
{
	if (!strchr(name, ':') || esdm_tls_ip6_name())
		return true;
	printf("  %s: no IPv6 address as server name with this TLS stack - skipped\n",
	       name);
	return false;
}
static void test_mutual(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config c2 = cfg_of(PKI("client2.crt"),
					   PKI("client2.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = server_ctx(&scfg), *cctx1 = client_ctx(&c1),
			    *cctx2 = client_ctx(&c2);
	static const char *const names[] = { "localhost", "127.0.0.1", "::1" };
	uint8_t fp1[ESDM_TLS_FINGERPRINT_LEN], fp1b[ESDM_TLS_FINGERPRINT_LEN];
	uint8_t fp2[ESDM_TLS_FINGERPRINT_LEN], fps[ESDM_TLS_FINGERPRINT_LEN];
	char hex[ESDM_TLS_FINGERPRINT_HEX_LEN];
	struct pair p;
	unsigned int i;

	printf("TLS (%s): mutual authentication\n", esdm_tls_stack());

	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (!name_usable(names[i]))
			continue;
		CHECK(!pair_open(&p, sctx, cctx1, names[i]), "pair");
		CHECK(!pair_handshake(&p),
		      "handshake with server name %s: server %d (%s), client %d (%s)",
		      names[i], p.sret, esdm_tls_error(p.s), p.cret,
		      esdm_tls_error(p.c));
		pair_close(&p);
	}

	CHECK(!pair_open(&p, sctx, cctx1, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake of client 1");
	CHECK(!esdm_tls_peer_fingerprint(p.s, fp1), "no fingerprint");
	CHECK(!esdm_tls_peer_fingerprint(p.c, fps), "no server fingerprint");
	CHECK(strstr(esdm_tls_peer_subject(p.s), "Client 1"),
	      "the server sees the subject %s", esdm_tls_peer_subject(p.s));
	CHECK(strstr(esdm_tls_peer_subject(p.c), "Test Server"),
	      "the client sees the subject %s", esdm_tls_peer_subject(p.c));
	CHECK(esdm_tls_peer_not_after(p.s) > (int64_t)time(NULL),
	      "the certificate of client 1 expired at %lld",
	      (long long)esdm_tls_peer_not_after(p.s));
	esdm_tls_fingerprint_hex(fp1, hex);
	printf("  client 1: %s, SHA-256 %s, cipher %s\n",
	       esdm_tls_peer_subject(p.s), hex, esdm_tls_cipher(p.s));
	pair_close(&p);

	CHECK(!pair_open(&p, sctx, cctx1, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "second handshake of client 1");
	CHECK(!esdm_tls_peer_fingerprint(p.s, fp1b) &&
		      !memcmp(fp1, fp1b, sizeof(fp1)),
	      "the fingerprint of client 1 changed between connections");
	pair_close(&p);

	CHECK(!pair_open(&p, sctx, cctx2, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake of client 2");
	CHECK(!esdm_tls_peer_fingerprint(p.s, fp2) &&
		      memcmp(fp1, fp2, sizeof(fp1)),
	      "clients 1 and 2 have the same fingerprint");
	pair_close(&p);

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx1);
	esdm_tls_ctx_put(cctx2);
}

/*
 * The client of a server that refused it learns so by the alert of the server:
 * its handshake fails, or - a TLS 1.3 handshake may complete for the client
 * before the server judged its certificate - its first receive does.
 */
static void expect_told(struct pair *p, const char *what)
{
	ssize_t n = p->cret;

	if (!n)
		n = recv_result(p, p->c);
	CHECK(n == -EACCES, "%s: the client was not told it is refused: %zd",
	      what, n);
	if (n == -EACCES)
		printf("  %s, the client is told: %s\n", what,
		       esdm_tls_error(p->c));
}

/* A client the server must refuse */
static void expect_refused(struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx,
			   const char *what)
{
	struct pair p;

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	pair_handshake(&p);
	CHECK(p.sret == -EACCES, "%s: the server's handshake returned %d (%s)",
	      what, p.sret, esdm_tls_error(p.s));
	printf("  %s: %s\n", what, esdm_tls_error(p.s));
	expect_told(&p, what);
	pair_close(&p);
}

/* A handshake of @sctx and @cctx, which has to succeed */
static void expect_accepted(struct esdm_tls_ctx *sctx,
			    struct esdm_tls_ctx *cctx, const char *what)
{
	struct pair p;

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "%s: pair", what);
	CHECK(!pair_handshake(&p),
	      "%s: handshake: server %d (%s), client %d (%s)", what, p.sret,
	      esdm_tls_error(p.s), p.cret, esdm_tls_error(p.c));
	if (!p.sret && !p.cret)
		printf("  %s: the server sees %s\n", what,
		       esdm_tls_peer_subject(p.s));
	pair_close(&p);
}

/*
 * The rollover of a CA, see esdm_tls.h: trust anchors of several files, every
 * CA of which is trusted alike - here the CA of the test PKI and the rogue
 * CA, standing in for the old and the new CA. A side taking up a further file
 * tells by its stamp.
 */
static void test_ca_rollover(void)
{
	struct esdm_tls_config scfg =
		cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 =
		cfg_of(PKI("client1.crt"), PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config rogue =
		cfg_of(PKI("rogue-client.crt"), PKI("rogue-client.key"),
		       PKI("rogue-ca.crt"));
	uint8_t one[ESDM_TLS_STAMP_LEN], two[ESDM_TLS_STAMP_LEN],
		swapped[ESDM_TLS_STAMP_LEN];
	struct esdm_tls_ctx *sctx, *cctx1, *cctxr, *ctx = NULL;
	unsigned int i;

	printf("TLS (%s): several CAs, for their rollover\n", esdm_tls_stack());

	/* The rogue client trusts the CA of the server next to its own */
	rogue.ca_files[rogue.ca_files_num++] = PKI("ca.crt");
	cctx1 = client_ctx(&c1);
	cctxr = client_ctx(&rogue);

	/* Before: the one CA */
	esdm_tls_stamp(&scfg, one);
	sctx = server_ctx(&scfg);
	expect_accepted(sctx, cctx1, "client of the one CA");
	expect_refused(sctx, cctxr, "client of the other CA, not yet trusted");
	esdm_tls_ctx_put(sctx);

	/* During: both, either client is taken */
	scfg.ca_files[scfg.ca_files_num++] = PKI("rogue-ca.crt");
	esdm_tls_stamp(&scfg, two);
	CHECK(memcmp(one, two, sizeof(one)),
	      "the stamp did not change with a further file of trust anchors");
	sctx = server_ctx(&scfg);
	expect_accepted(sctx, cctx1, "client of the old CA, both trusted");
	expect_accepted(sctx, cctxr, "client of the new CA, both trusted");
	esdm_tls_ctx_put(sctx);

	/* The files are told apart by their place as well */
	scfg.ca_files[0] = PKI("rogue-ca.crt");
	scfg.ca_files[1] = PKI("ca.crt");
	esdm_tls_stamp(&scfg, swapped);
	CHECK(memcmp(two, swapped, sizeof(two)),
	      "the stamp did not change with the order of the trust anchors");

	/* None, or more than there is room for, is no configuration */
	scfg.ca_files_num = 0;
	CHECK(esdm_tls_ctx_alloc(true, &scfg, &ctx) == -EINVAL,
	      "a context without trust anchors was built");
	for (i = 0; i < ESDM_TLS_MAX_CA_FILES; i++)
		scfg.ca_files[i] = PKI("ca.crt");
	scfg.ca_files_num = ESDM_TLS_MAX_CA_FILES + 1;
	CHECK(esdm_tls_ctx_alloc(true, &scfg, &ctx) == -EINVAL,
	      "a context with %u files of trust anchors was built",
	      ESDM_TLS_MAX_CA_FILES + 1);
	scfg.ca_files_num = ESDM_TLS_MAX_CA_FILES;
	CHECK(!esdm_tls_ctx_alloc(true, &scfg, &ctx),
	      "a context with %u files of trust anchors was refused",
	      ESDM_TLS_MAX_CA_FILES);
	esdm_tls_ctx_put(ctx);

	esdm_tls_ctx_put(cctx1);
	esdm_tls_ctx_put(cctxr);
}

static void test_refused_clients(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config none = cfg_of(NULL, NULL, PKI("ca.crt"));
	struct esdm_tls_config rogue = cfg_of(PKI("rogue-client.crt"),
					      PKI("rogue-client.key"),
					      PKI("rogue-ca.crt"));
	struct esdm_tls_ctx *sctx = server_ctx(&scfg), *cctx;
	struct esdm_tls_config expired, usage;

	printf("TLS (%s): refused clients\n", esdm_tls_stack());

	cctx = client_ctx(&none);
	expect_refused(sctx, cctx, "client without a certificate");
	esdm_tls_ctx_put(cctx);

	/*
	 * The rogue client trusts its own CA only, which the server does not
	 * chain to - its own certificate does, so the context is built.
	 */
	rogue.ca_files[0] = PKI("ca.crt");
	rogue.ca_files_num = 1;
	CHECK(esdm_tls_ctx_alloc(false, &rogue, &cctx) == -EINVAL,
	      "a context whose certificate does not chain to its trust anchors was built");
	rogue.ca_files[0] = PKI("rogue-ca.crt");
	rogue.ca_files_num = 1;
	cctx = client_ctx(&rogue);
	if (cctx) {
		/* It does not trust the server either, so pretend it did */
		struct pair p;

		CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
		pair_handshake(&p);
		CHECK(p.sret && p.cret,
		      "an untrusted client and server shook hands");
		pair_close(&p);
		esdm_tls_ctx_put(cctx);
	}

	/*
	 * The expired client: a context with it is built - the own certificate
	 * is checked for its chain, not for its time, see esdm_tls.h -, and the
	 * server refuses it.
	 */
	expired = cfg_of(PKI("client-expired.crt"), PKI("client-expired.key"),
			 PKI("ca.crt"));
	cctx = client_ctx(&expired);
	expect_refused(sctx, cctx, "expired client");
	esdm_tls_ctx_put(cctx);

	/* A certificate for TLS server authentication only */
	usage = cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	cctx = client_ctx(&usage);
	expect_refused(sctx, cctx, "client with a server certificate");
	esdm_tls_ctx_put(cctx);

	esdm_tls_ctx_put(sctx);
}

static void test_server_name(void)
{
	struct esdm_tls_config wrong = cfg_of(PKI("server-wrongname.crt"),
					      PKI("server-wrongname.key"),
					      PKI("ca.crt"));
	struct esdm_tls_config usage = cfg_of(PKI("server-wrongusage.crt"),
					      PKI("server-wrongusage.key"),
					      PKI("ca.crt"));
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config rogue_trust = cfg_of(PKI("client1.crt"),
						    PKI("client1.key"),
						    PKI("ca.crt"));
	struct esdm_tls_ctx *wctx = server_ctx(&wrong), *sctx = server_ctx(&scfg);
	struct esdm_tls_ctx *cctx = client_ctx(&c1), *rctx, *uctx;
	static const char *const bad[] = { "wrong.example", "127.0.0.2", "::2",
					   "otherhost" };
	struct pair p;
	unsigned int i;

	printf("TLS (%s): server names\n", esdm_tls_stack());

	CHECK(!pair_open(&p, wctx, cctx, "localhost"), "pair");
	pair_handshake(&p);
	CHECK(p.cret == -EACCES,
	      "a server not issued for localhost was accepted: %d (%s)",
	      p.cret, esdm_tls_error(p.c));
	printf("  wrong name: %s\n", esdm_tls_error(p.c));
	pair_close(&p);

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		if (!name_usable(bad[i]))
			continue;
		CHECK(!pair_open(&p, sctx, cctx, bad[i]), "pair");
		pair_handshake(&p);
		CHECK(p.cret == -EACCES,
		      "the server was accepted for %s: %d (%s)", bad[i],
		      p.cret, esdm_tls_error(p.c));
		pair_close(&p);
	}

	CHECK(!pair_open(&p, wctx, cctx, "wrong.example"), "pair");
	CHECK(!pair_handshake(&p), "the server was refused for its own name");
	pair_close(&p);

	/* Issued for localhost, but for TLS client authentication only */
	uctx = server_ctx(&usage);
	CHECK(!pair_open(&p, uctx, cctx, "localhost"), "pair");
	pair_handshake(&p);
	CHECK(p.cret == -EACCES,
	      "a server with a client certificate was accepted: %d (%s)",
	      p.cret, esdm_tls_error(p.c));
	printf("  client certificate: %s\n", esdm_tls_error(p.c));
	pair_close(&p);
	esdm_tls_ctx_put(uctx);

	/* A client trusting another CA than the server's */
	rogue_trust.cert_file = NULL;
	rogue_trust.key_file = NULL;
	rogue_trust.ca_files[0] = PKI("rogue-ca.crt");
	rogue_trust.ca_files_num = 1;
	rctx = client_ctx(&rogue_trust);
	CHECK(!pair_open(&p, sctx, rctx, "localhost"), "pair");
	pair_handshake(&p);
	CHECK(p.cret == -EACCES, "an untrusted server was accepted: %d (%s)",
	      p.cret, esdm_tls_error(p.c));
	pair_close(&p);

	esdm_tls_ctx_put(rctx);
	esdm_tls_ctx_put(wctx);
	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

static void test_transfer_and_eof(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = server_ctx(&scfg), *cctx = client_ctx(&c1);
	const size_t len = 1024 * 1024 + 17;
	uint8_t *data = malloc(len), *out = malloc(len);
	struct pair p;
	size_t i;
	ssize_t n;

	printf("TLS (%s): transfers and the end of a connection\n",
	       esdm_tls_stack());

	if (!data || !out) {
		CHECK(0, "no memory");
		goto out;
	}
	for (i = 0; i < len; i++)
		data[i] = (uint8_t)(i * 7 + (i >> 8));

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake");
	memset(out, 0, len);
	CHECK(!transfer(&p, p.c, p.s, data, out, len) && !memcmp(data, out, len),
	      "1 MiB from the client did not arrive intact");
	memset(out, 0, len);
	CHECK(!transfer(&p, p.s, p.c, data, out, len) && !memcmp(data, out, len),
	      "1 MiB from the server did not arrive intact");

	/* A small message, then the closing alert */
	CHECK(!transfer(&p, p.c, p.s, data, out, 3), "small transfer");
	esdm_tls_close_notify(p.c);
	n = recv_result(&p, p.s);
	CHECK(n == 0, "the closing alert was received as %zd", n);
	pair_close(&p);

	/* The end of the stream without a closing alert */
	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake");
	shutdown(p.cfd, SHUT_RDWR);
	n = recv_result(&p, p.s);
	CHECK(n == -ECONNRESET, "the end without a closing alert came as %zd",
	      n);
	pair_close(&p);

out:
	free(data);
	free(out);
	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

/*
 * The secure minimal mode on the wire, see common/esdm_tls_backend.h: the
 * client on cs[0], the server on ss[1], and every byte moved by the test
 * between cs[1] and ss[0], read on the way - see tests/test_tls_wire.h.
 */
struct wire {
	int cs[2], ss[2];
	struct esdm_tls *c, *s;
	/* What the client sends, and what the server does */
	struct test_tls_wire c2s, s2c;
};

static void wire_close(struct wire *w)
{
	unsigned int i;

	esdm_tls_free(w->c);
	esdm_tls_free(w->s);
	w->c = w->s = NULL;
	for (i = 0; i < 2; i++) {
		if (w->cs[i] >= 0)
			close(w->cs[i]);
		if (w->ss[i] >= 0)
			close(w->ss[i]);
		w->cs[i] = w->ss[i] = -1;
	}
}

/* Move what @from has to @to, reading it into @t; @return the bytes */
static size_t wire_move(int from, int to, struct test_tls_wire *t)
{
	uint8_t buf[4096];
	size_t moved = 0;
	ssize_t n;

	while ((n = recv(from, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		test_tls_wire_stream(t, buf, (size_t)n);
		/* The relay ends block: the socket of the other end takes it */
		if (send(to, buf, (size_t)n, MSG_NOSIGNAL) != n) {
			CHECK(0, "the relay lost %zd bytes", n);
			break;
		}
		moved += (size_t)n;
	}
	return moved;
}

/* Move what there is both ways, or wait for an end to send something */
static void wire_step(struct wire *w)
{
	struct pollfd pfd[2] = { { .fd = w->cs[1], .events = POLLIN },
				 { .fd = w->ss[0], .events = POLLIN } };

	if (!wire_move(w->cs[1], w->ss[0], &w->c2s) &&
	    !wire_move(w->ss[0], w->cs[1], &w->s2c))
		poll(pfd, 2, 20);
}

/*
 * The algorithms of TLS 1.3 of esdm_tls.h, by their codes of TLS: the suites
 * of AES-GCM - and AES-128-CCM, which GnuTLS has -, the groups -
 * SecP384r1MLKEM1024, secp384r1, secp256r1, secp521r1, the three curves of
 * Brainpool, ffdhe3072 and ffdhe4096 -, and the signatures of ECDSA, RSA-PSS
 * and, for certificates, RSA with PKCS#1 v1.5. Nothing of X25519, X448,
 * ChaCha20-Poly1305, EdDSA, ML-KEM or ML-DSA alone.
 */
static const uint16_t bsi_suites[] = { 0x1301, 0x1302, 0x1304 };
static const uint16_t bsi_groups[] = { 0x11ed, 23, 24,	25, 31,
				       32,     33, 257, 258 };
static const uint16_t bsi_sigalgs[] = { 0x0403, 0x0503, 0x0603, 0x081a,
					0x081b, 0x081c, 0x0804, 0x0805,
					0x0806, 0x0809, 0x080a, 0x080b,
					0x0401, 0x0501, 0x0601 };

/* Is every one of @num values at @vals among the @nok at @ok? */
static bool wire_all_in(const uint16_t *vals, unsigned int num,
			const uint16_t *ok, size_t nok, uint16_t *bad)
{
	unsigned int i;
	size_t j;

	for (i = 0; i < num; i++) {
		for (j = 0; j < nok && ok[j] != vals[i]; j++)
			;
		if (j == nok) {
			*bad = vals[i];
			return false;
		}
	}
	return true;
}

/*
 * One connection between @sctx and @cctx through the relay: its ClientHello
 * offers no session ticket, no pre-shared key - which TLS 1.3 resumes with -
 * and no early data, and asks for no heartbeat and no post-handshake
 * authentication; its ServerHello takes no pre-shared key, so the handshake is
 * a full one; and once the client is through, the server sends nothing but its
 * data - no NewSessionTicket, which TLS 1.3 sends after the handshake,
 * encrypted: the records are counted. The legacy session ID of a ClientHello
 * of TLS 1.3 is the random one of the middlebox compatibility, nothing to
 * resume.
 */
static void wire_connection(struct esdm_tls_ctx *sctx,
			    struct esdm_tls_ctx *cctx, unsigned int nr)
{
	static struct wire w;
	int cret = -EAGAIN, sret = -EAGAIN;
	unsigned int i, before = 0, after;
	uint16_t bad = 0;
	uint8_t got[4];
	ssize_t n = -EAGAIN;

	memset(&w, 0, sizeof(w));
	w.cs[0] = w.cs[1] = w.ss[0] = w.ss[1] = -1;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, w.cs) ||
	    socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, w.ss) ||
	    fcntl(w.cs[0], F_SETFL, O_NONBLOCK) ||
	    fcntl(w.ss[1], F_SETFL, O_NONBLOCK) ||
	    esdm_tls_alloc(sctx, w.ss[1], NULL, &w.s) ||
	    esdm_tls_alloc(cctx, w.cs[0], "localhost", &w.c)) {
		CHECK(0, "connection %u: no relay", nr);
		goto out;
	}

	for (i = 0; i < 2000 && (cret == -EAGAIN || sret == -EAGAIN); i++) {
		if (cret == -EAGAIN) {
			cret = esdm_tls_handshake(w.c);
			/* What the server sent so far was its handshake */
			if (!cret)
				before = w.s2c.records;
		}
		if (sret == -EAGAIN)
			sret = esdm_tls_handshake(w.s);
		wire_step(&w);
	}
	CHECK(!cret && !sret, "connection %u: handshake %d (%s) / %d (%s)", nr,
	      cret, esdm_tls_error(w.c), sret, esdm_tls_error(w.s));
	if (cret || sret)
		goto out;

	/* Whatever the server sent once through, moved and counted */
	for (i = 0; i < 5; i++)
		wire_step(&w);
	after = w.s2c.records - before;

	/* The data of the server is the next record */
	CHECK(esdm_tls_send(w.s, "data", 4) == 4, "connection %u: send", nr);
	for (i = 0; i < 100 && esdm_tls_flush(w.s) == -EAGAIN; i++)
		wire_step(&w);
	for (i = 0; i < 200 && n == -EAGAIN; i++) {
		wire_step(&w);
		n = esdm_tls_recv(w.c, got, sizeof(got));
	}
	CHECK(n == 4 && !memcmp(got, "data", 4),
	      "connection %u: the data of the server came as %zd", nr, n);

	printf("  connection %u: ClientHello with %u extensions and a legacy session ID of %u bytes, %u records of the server's handshake, %u after it, %u with its data\n",
	       nr, w.c2s.nexts, w.c2s.session_id_len, before, after,
	       w.s2c.records - before - after);
	CHECK(!w.c2s.malformed && !w.s2c.malformed,
	      "connection %u: a record not understood", nr);
	CHECK(test_tls_has_hs(&w.c2s, TEST_TLS_HS_CLIENT_HELLO) &&
		      test_tls_has_hs(&w.s2c, TEST_TLS_HS_SERVER_HELLO),
	      "connection %u: no hellos on the wire", nr);
	CHECK(test_tls_has_ext(&w.c2s, TEST_TLS_EXT_SUPPORTED_VERSIONS) &&
		      test_tls_has_ext(&w.s2c, TEST_TLS_EXT_SUPPORTED_VERSIONS),
	      "connection %u: no TLS 1.3", nr);
	CHECK(!test_tls_has_ext(&w.c2s, TEST_TLS_EXT_SESSION_TICKET),
	      "connection %u: the client asks for a ticket", nr);
	CHECK(!test_tls_has_ext(&w.c2s, TEST_TLS_EXT_PRE_SHARED_KEY),
	      "connection %u: the client offers a pre-shared key", nr);
	CHECK(!test_tls_has_ext(&w.c2s, TEST_TLS_EXT_EARLY_DATA),
	      "connection %u: the client offers early data", nr);
	CHECK(!test_tls_has_ext(&w.c2s, TEST_TLS_EXT_HEARTBEAT),
	      "connection %u: the client asks for the heartbeat", nr);
	CHECK(!test_tls_has_ext(&w.c2s, TEST_TLS_EXT_POST_HANDSHAKE_AUTH),
	      "connection %u: the client offers post-handshake authentication",
	      nr);
	CHECK(!test_tls_has_ext(&w.s2c, TEST_TLS_EXT_PRE_SHARED_KEY),
	      "connection %u: the server takes a pre-shared key - no full handshake",
	      nr);
	CHECK(!test_tls_has_ext(&w.s2c, TEST_TLS_EXT_EARLY_DATA),
	      "connection %u: the server takes early data", nr);
	CHECK(before > 0 && !after,
	      "connection %u: the server sent %u records after its handshake - a NewSessionTicket",
	      nr, after);
	CHECK(w.s2c.records - before - after == 1,
	      "connection %u: the data of the server took %u records", nr,
	      w.s2c.records - before - after);

	/* The algorithms, offered and taken */
	printf("  connection %u: suite 0x%04x, group 0x%04x, %u suites, %u groups, %u key shares and %u signatures offered\n",
	       nr, w.s2c.suite, w.s2c.nshares ? w.s2c.shares[w.s2c.nshares - 1] : 0,
	       w.c2s.nsuites, w.c2s.ngroups, w.c2s.nshares, w.c2s.nsigalgs);
	CHECK(wire_all_in(w.c2s.suites, w.c2s.nsuites, bsi_suites,
			  ARRAY_SIZE(bsi_suites), &bad),
	      "connection %u: the client offers the suite 0x%04x", nr, bad);
	CHECK(wire_all_in(&w.s2c.suite, 1, bsi_suites, ARRAY_SIZE(bsi_suites),
			  &bad),
	      "connection %u: the server takes the suite 0x%04x", nr, bad);
	CHECK(w.c2s.ngroups &&
		      wire_all_in(w.c2s.groups, w.c2s.ngroups, bsi_groups,
				  ARRAY_SIZE(bsi_groups), &bad),
	      "connection %u: the client offers the group 0x%04x", nr, bad);
	CHECK(w.c2s.nshares &&
		      wire_all_in(w.c2s.shares, w.c2s.nshares, bsi_groups,
				  ARRAY_SIZE(bsi_groups), &bad),
	      "connection %u: the client sends a key share of 0x%04x", nr,
	      bad);
	CHECK(w.s2c.nshares &&
		      wire_all_in(w.s2c.shares, w.s2c.nshares, bsi_groups,
				  ARRAY_SIZE(bsi_groups), &bad),
	      "connection %u: the server takes the group 0x%04x", nr, bad);
	CHECK(w.c2s.nsigalgs &&
		      wire_all_in(w.c2s.sigalgs, w.c2s.nsigalgs, bsi_sigalgs,
				  ARRAY_SIZE(bsi_sigalgs), &bad),
	      "connection %u: the client offers the signature 0x%04x", nr,
	      bad);
	if (esdm_tls_mlkem_group())
		CHECK(w.s2c.nshares && w.s2c.shares[w.s2c.nshares - 1] == 0x11ed,
		      "connection %u: the hybrid of ML-KEM was not taken", nr);

out:
	wire_close(&w);
}

/*
 * The secure minimal mode and the algorithms on the wire: two connections
 * between the same contexts, the second a full handshake as the first
 */
static void test_minimal(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = server_ctx(&scfg), *cctx = client_ctx(&c1);

	printf("TLS (%s): the secure minimal mode and the algorithms on the wire\n",
	       esdm_tls_stack());

	if (sctx && cctx) {
		wire_connection(sctx, cctx, 1);
		wire_connection(sctx, cctx, 2);
	}

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);
}

/* A server context with CRLs: NULL-terminated list - the trust anchors @ca */
static struct esdm_tls_ctx *crl_server_ca(const char *ca, bool check_all,
					  bool allow_expired, const char *crl,
					  va_list ap)
{
	struct esdm_tls_config cfg = cfg_of(PKI("server.crt"),
					    PKI("server.key"), ca);
	const char *c;

	cfg.crl_check_all = check_all;
	cfg.crl_allow_expired = allow_expired;
	for (c = crl; c; c = va_arg(ap, const char *))
		cfg_add_crl(&cfg, c);

	return server_ctx(&cfg);
}

static struct esdm_tls_ctx *crl_server(bool check_all, bool allow_expired,
				       const char *crl, ...)
{
	struct esdm_tls_ctx *ctx;
	va_list ap;

	va_start(ap, crl);
	ctx = crl_server_ca(PKI("ca.crt"), check_all, allow_expired, crl, ap);
	va_end(ap);
	return ctx;
}

/* The same, with the intermediate CA among the trust anchors */
static struct esdm_tls_ctx *crl_server_int(const char *crl, ...)
{
	struct esdm_tls_ctx *ctx;
	va_list ap;

	va_start(ap, crl);
	ctx = crl_server_ca(PKI("ca-int.crt"), false, false, crl, ap);
	va_end(ap);
	return ctx;
}

static void expect_crl(struct esdm_tls_ctx *sctx, struct esdm_tls_ctx *cctx,
		       bool accepted, const char *what)
{
	struct pair p;

	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	pair_handshake(&p);
	if (accepted) {
		CHECK(!p.sret && !p.cret, "%s: refused: server %d (%s)", what,
		      p.sret, esdm_tls_error(p.s));
	} else {
		CHECK(p.sret == -EACCES, "%s: accepted (%d)", what, p.sret);
		printf("  %s: %s\n", what, esdm_tls_error(p.s));
		expect_told(&p, what);
	}
	pair_close(&p);
}

static void test_crl(void)
{
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config cr = cfg_of(PKI("client-revoked.crt"),
					   PKI("client-revoked.key"),
					   PKI("ca.crt"));
	struct esdm_tls_config cf = cfg_of(PKI("client-fakeroot.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config cl = cfg_of(PKI("client1-leaf.crt"),
					   PKI("client1.key"),
					   PKI("ca-int.crt"));
	struct esdm_tls_ctx *cctx1 = client_ctx(&c1), *cctxr = client_ctx(&cr);
	struct esdm_tls_ctx *cctxf = client_ctx(&cf), *cctxl = client_ctx(&cl);
	struct esdm_tls_ctx *sctx;

	printf("TLS (%s): revocation\n", esdm_tls_stack());

	sctx = crl_server(false, false, PKI("int.crl"), NULL);
	expect_crl(sctx, cctx1, true, "unrevoked client");
	expect_crl(sctx, cctxr, false, "revoked client");
	esdm_tls_ctx_put(sctx);

	sctx = crl_server(false, false, PKI("ca.crl"), NULL);
	expect_crl(sctx, cctx1, false, "no CRL of the leaf's issuer");
	esdm_tls_ctx_put(sctx);

	sctx = crl_server(false, false, PKI("int-expired.crl"), NULL);
	expect_crl(sctx, cctx1, false, "expired CRL");
	esdm_tls_ctx_put(sctx);
	sctx = crl_server(false, true, PKI("int-expired.crl"), NULL);
	expect_crl(sctx, cctx1, true, "expired CRL allowed");
	esdm_tls_ctx_put(sctx);

	/* A newer CRL next to the expired one counts */
	sctx = crl_server(false, false, PKI("int-expired.crl"),
			  PKI("int-empty.crl"), NULL);
	expect_crl(sctx, cctx1, true, "expired and fresh CRL");
	esdm_tls_ctx_put(sctx);

	sctx = crl_server(true, false, PKI("int.crl"), NULL);
	expect_crl(sctx, cctx1, false,
		   "crl_check_all without a CRL of the root CA");
	esdm_tls_ctx_put(sctx);
	sctx = crl_server(true, false, PKI("int.crl"), PKI("ca.crl"), NULL);
	expect_crl(sctx, cctx1, true, "crl_check_all with all CRLs");
	esdm_tls_ctx_put(sctx);

	/* The CRL of an intermediate is checked where it is present */
	sctx = crl_server(false, false, PKI("int.crl"),
			  PKI("ca-revoked-int.crl"), NULL);
	expect_crl(sctx, cctx1, false, "revoked intermediate CA");

	/*
	 * A certificate the client sends claiming to be the root - its name
	 * and key identifier, not its key - is no trust anchor: the CRL of
	 * the root, which the claimed one cannot verify, covers the
	 * intermediate all the same.
	 */
	expect_crl(sctx, cctxf, false,
		   "revoked intermediate CA, a fake root sent along");
	esdm_tls_ctx_put(sctx);
	sctx = crl_server(false, false, PKI("int.crl"), PKI("ca.crl"), NULL);
	expect_crl(sctx, cctxf, true, "a fake root sent along");
	esdm_tls_ctx_put(sctx);

	/*
	 * An intermediate CA among the trust anchors is checked against the
	 * CRL of its issuer, as the client sends no chain to find it in.
	 */
	sctx = crl_server_int(PKI("int.crl"), PKI("ca.crl"), NULL);
	expect_crl(sctx, cctxl, true, "intermediate CA among the trust anchors");
	esdm_tls_ctx_put(sctx);
	sctx = crl_server_int(PKI("int.crl"), PKI("ca-revoked-int.crl"), NULL);
	expect_crl(sctx, cctxl, false,
		   "revoked intermediate CA among the trust anchors");
	esdm_tls_ctx_put(sctx);

	esdm_tls_ctx_put(cctx1);
	esdm_tls_ctx_put(cctxr);
	esdm_tls_ctx_put(cctxf);
	esdm_tls_ctx_put(cctxl);
}

/* A client checking the server's chain */
static void test_crl_client(void)
{
	struct esdm_tls_config scfg = cfg_of(PKI("server.crt"),
					     PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_ctx *sctx = server_ctx(&scfg), *cctx;
	struct pair p;

	printf("TLS (%s): revocation checked by the client\n",
	       esdm_tls_stack());

	cfg_add_crl(&c1, PKI("ca.crl"));
	cctx = client_ctx(&c1);
	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "the server covered by ca.crl was refused: %s",
	      esdm_tls_error(p.c));
	pair_close(&p);
	esdm_tls_ctx_put(cctx);

	c1.crl_files_num = 0;
	cfg_add_crl(&c1, PKI("int.crl"));
	cctx = client_ctx(&c1);
	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	pair_handshake(&p);
	CHECK(p.cret == -EACCES,
	      "the server without a CRL of its issuer was accepted: %d", p.cret);
	pair_close(&p);
	esdm_tls_ctx_put(cctx);

	esdm_tls_ctx_put(sctx);
}

/* An established connection checked against the CRLs of a new context */
static void test_crl_established(void)
{
	struct esdm_tls_config c1 = cfg_of(PKI("client1.crt"),
					   PKI("client1.key"), PKI("ca.crt"));
	struct esdm_tls_config cr = cfg_of(PKI("client-revoked.crt"),
					   PKI("client-revoked.key"),
					   PKI("ca.crt"));
	struct esdm_tls_ctx *cctx1 = client_ctx(&c1), *cctxr = client_ctx(&cr);
	struct esdm_tls_ctx *old = crl_server(false, false,
					      PKI("int-empty.crl"), NULL);
	struct esdm_tls_ctx *newer = crl_server(false, false, PKI("int.crl"),
						NULL);
	struct esdm_tls_ctx *none = crl_server(false, false, PKI("ca.crl"),
					       NULL);
	char why[256];
	struct pair p1, pr;

	printf("TLS (%s): established connections against new CRLs\n",
	       esdm_tls_stack());

	CHECK(!pair_open(&p1, old, cctx1, "localhost"), "pair");
	CHECK(!pair_handshake(&p1), "client 1 under the empty CRL");
	CHECK(!pair_open(&pr, old, cctxr, "localhost"), "pair");
	CHECK(!pair_handshake(&pr), "the revoked client under the empty CRL");

	CHECK(esdm_tls_peer_revoked(p1.s, newer, why, sizeof(why)) == 0,
	      "client 1 counts as revoked: %s", why);
	CHECK(esdm_tls_peer_revoked(pr.s, newer, why, sizeof(why)) == 1,
	      "the revoked client does not count as revoked");
	printf("  %s\n", why);
	/* No CRL of the issuer is no reason to end a connection */
	CHECK(esdm_tls_peer_revoked(pr.s, none, why, sizeof(why)) == 0,
	      "a missing CRL ended a connection");

	pair_close(&p1);
	pair_close(&pr);
	esdm_tls_ctx_put(old);
	esdm_tls_ctx_put(newer);
	esdm_tls_ctx_put(none);
	esdm_tls_ctx_put(cctx1);
	esdm_tls_ctx_put(cctxr);
}

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, text, strlen(text));
	close(fd);
	return n == (ssize_t)strlen(text) ? 0 : -1;
}

static void test_contexts(void)
{
	char dir[] = "/tmp/esdm-tls-test-XXXXXX";
	char garbage[sizeof(dir) + 16], missing[sizeof(dir) + 16];
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL;
	uint8_t s1[ESDM_TLS_STAMP_LEN], s2[ESDM_TLS_STAMP_LEN];
	struct timespec times[2];

	printf("TLS (%s): contexts and their files\n", esdm_tls_stack());

	if (!mkdtemp(dir)) {
		CHECK(0, "no temporary directory");
		return;
	}
	snprintf(garbage, sizeof(garbage), "%s/garbage", dir);
	snprintf(missing, sizeof(missing), "%s/missing", dir);
	CHECK(!write_file(garbage, "-----BEGIN X509 CRL-----\nnope\n"
				   "-----END X509 CRL-----\n"),
	      "cannot write %s", garbage);

	cfg = cfg_of(PKI("server.crt"), PKI("server-renewed.key"),
		     PKI("ca.crt"));
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a key not belonging to the certificate was accepted");

	cfg = cfg_of(PKI("server.crt"), PKI("server.key"),
		     PKI("rogue-ca.crt"));
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a certificate not chaining to the trust anchors was accepted");

	/*
	 * An intermediate CA alone is no trust anchor, with any TLS stack: a
	 * chain ends in a self-issued one. Next to the root, it is an
	 * intermediate one.
	 */
	cfg = cfg_of(PKI("client1.crt"), PKI("client1.key"), PKI("int.crt"));
	CHECK(esdm_tls_ctx_alloc(false, &cfg, &ctx) == -EINVAL,
	      "an intermediate CA alone was taken for a trust anchor");
	cfg.ca_files[0] = PKI("ca-int.crt");
	cfg.ca_files_num = 1;
	CHECK(!esdm_tls_ctx_alloc(false, &cfg, &ctx),
	      "the intermediate CA next to the root was refused");
	esdm_tls_ctx_put(ctx);
	ctx = NULL;

	cfg = cfg_of(missing, PKI("server.key"), PKI("ca.crt"));
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -ENOENT,
	      "a missing certificate was not reported as such");

	cfg = cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	cfg_add_crl(&cfg, garbage);
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a CRL that does not parse was accepted");

	cfg.crl_files[0] = PKI("server.crt");
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a CRL file without a CRL was accepted");

	cfg.crl_files[0] = PKI("int.crl");
	CHECK(!esdm_tls_ctx_alloc(true, &cfg, &ctx), "the context was refused");
	esdm_tls_ctx_crl_report(ctx, true);
	esdm_tls_ctx_put(ctx);

	cfg.crl_files[0] = PKI("int-expired.crl");
	CHECK(!esdm_tls_ctx_alloc(true, &cfg, &ctx),
	      "a context with an expired CRL was refused");
	printf("  an error about the expired CRL follows:\n");
	esdm_tls_ctx_crl_report(ctx, true);
	esdm_tls_ctx_put(ctx);

	/* No complete CRLs: a delta CRL, one of a distribution point */
	printf("  errors about a delta CRL and a CRL of a distribution point follow:\n");
	cfg.crl_files[0] = PKI("int-delta.crl");
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a delta CRL was accepted");
	cfg.crl_files[0] = PKI("int-idp.crl");
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a CRL with an issuing distribution point was accepted");
	cfg.crl_files[0] = PKI("int-empty.crl");
	cfg_add_crl(&cfg, PKI("int-delta.crl"));
	CHECK(esdm_tls_ctx_alloc(true, &cfg, &ctx) == -EINVAL,
	      "a delta CRL next to a complete one was accepted");

	/* The stamp tells a change of a file */
	cfg = cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	cfg_add_crl(&cfg, garbage);
	esdm_tls_stamp(&cfg, s1);
	esdm_tls_stamp(&cfg, s2);
	CHECK(!memcmp(s1, s2, sizeof(s1)), "the stamp changed by itself");
	times[0].tv_sec = 1000000000;
	times[0].tv_nsec = 0;
	times[1] = times[0];
	CHECK(!utimensat(AT_FDCWD, garbage, times, 0), "utimensat");
	esdm_tls_stamp(&cfg, s2);
	CHECK(memcmp(s1, s2, sizeof(s1)),
	      "the stamp did not change with the modification time");

	unlink(garbage);
	rmdir(dir);
}

/*
 * The key exchange of two sides of the TLS stack of the build: the hybrid of
 * ML-KEM, see "Algorithms" in esdm_tls.h
 */
static int test_mlkem(void)
{
	struct esdm_tls_config scfg =
		cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	struct esdm_tls_config c1 =
		cfg_of(PKI("client1.crt"), PKI("client1.key"), PKI("ca.crt"));
	const char *group = esdm_tls_mlkem_group();
	struct esdm_tls_ctx *sctx, *cctx;
	uint8_t data[1000], out[sizeof(data)];
	struct pair p;
	size_t i;

	if (!group) {
		printf("TLS (%s): the TLS stack has no hybrid of ML-KEM - skipped\n",
		       esdm_tls_stack());
		return 77;
	}
	printf("TLS (%s): key exchange by the hybrid %s\n", esdm_tls_stack(),
	       group);

	sctx = server_ctx(&scfg);
	cctx = client_ctx(&c1);
	CHECK(!pair_open(&p, sctx, cctx, "localhost"), "pair");
	CHECK(!pair_handshake(&p), "handshake: server %d (%s), client %d (%s)",
	      p.sret, esdm_tls_error(p.s), p.cret, esdm_tls_error(p.c));
	CHECK(!strcasecmp(esdm_tls_group(p.s), group),
	      "the server negotiated %s rather than %s", esdm_tls_group(p.s),
	      group);
	CHECK(!strcasecmp(esdm_tls_group(p.c), group),
	      "the client negotiated %s rather than %s", esdm_tls_group(p.c),
	      group);
	printf("  negotiated: server %s, client %s, cipher %s\n",
	       esdm_tls_group(p.s), esdm_tls_group(p.c), esdm_tls_cipher(p.s));

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7);
	CHECK(!transfer(&p, p.c, p.s, data, out, sizeof(data)) &&
		      !memcmp(data, out, sizeof(data)),
	      "the data did not arrive");
	pair_close(&p);

	esdm_tls_ctx_put(sctx);
	esdm_tls_ctx_put(cctx);

	printf("TLS (%s): ML-KEM %s\n", esdm_tls_stack(),
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

/*
 * Certificates on ML-DSA - a post-quantum signature on its own - are not
 * taken, see "Algorithms" in esdm_tls.h: neither as the own certificate, nor
 * in its chain, nor among the trust anchors. Every context with one is
 * refused, with every TLS stack - by the check of esdm_tls.c, or by the TLS
 * stack where it cannot even parse them.
 */
static int test_mldsa(void)
{
	static const struct {
		const char *cert, *key, *ca, *what;
		bool server;
	} cases[] = {
		{ "mldsa-server.crt", "mldsa-server.key", "mldsa-ca.crt",
		  "a server on ML-DSA-87", true },
		{ "mldsa-client.crt", "mldsa-client.key", "mldsa-ca.crt",
		  "a client on ML-DSA-87", false },
		{ "mldsa65-client.crt", "mldsa65-client.key", "mldsa-ca.crt",
		  "a client on ML-DSA-65", false },
		{ "mldsa-ec-server.crt", "mldsa-ec-server.key", "mldsa-ca.crt",
		  "a server on ECDSA of a CA on ML-DSA-87", true },
		{ "mldsa-ec-client.crt", "mldsa-ec-client.key", "ca-mldsa.crt",
		  "a client on ECDSA with an intermediate CA on ML-DSA-87",
		  false },
		/* The chain of the own certificate is a conventional one */
		{ "server.crt", "server.key", "ca-mldsa.crt",
		  "a server on ECDSA trusting a CA on ML-DSA-87 as well",
		  true },
	};
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx;
	unsigned int i;
	int ret;

	printf("TLS (%s): certificates on ML-DSA refused\n", esdm_tls_stack());

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		cfg = cfg_of(pki_file(cases[i].cert), pki_file(cases[i].key),
			     pki_file(cases[i].ca));
		ctx = NULL;
		ret = esdm_tls_ctx_alloc(cases[i].server, &cfg, &ctx);
		CHECK(ret == -EINVAL, "%s: a context was built (%d)",
		      cases[i].what, ret);
		esdm_tls_ctx_put(ctx);
		printf("  %s: refused\n", cases[i].what);
	}

	/* And the conventional one alone is taken */
	cfg = cfg_of(PKI("server.crt"), PKI("server.key"), PKI("ca.crt"));
	ctx = NULL;
	CHECK(!esdm_tls_ctx_alloc(true, &cfg, &ctx),
	      "the conventional server was refused");
	esdm_tls_ctx_put(ctx);

	printf("TLS (%s): ML-DSA %s\n", esdm_tls_stack(),
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);

	/* The parts of the post-quantum algorithms, each a test of its own */
	if (argc > 1) {
		if (!strcmp(argv[1], "mlkem"))
			return test_mlkem();
		if (!strcmp(argv[1], "mldsa"))
			return test_mldsa();
		printf("unknown part %s\n", argv[1]);
		return 1;
	}

	test_mutual();
	test_refused_clients();
	test_ca_rollover();
	test_server_name();
	test_transfer_and_eof();
	test_minimal();
	test_crl();
	test_crl_client();
	test_crl_established();
	test_contexts();

	printf("TLS (%s): %s\n", esdm_tls_stack(),
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else /* ESDM_EGD_NET_TLS */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	printf("Built without egd-net-tls\n");
	return 77;
}

#endif /* ESDM_EGD_NET_TLS */
