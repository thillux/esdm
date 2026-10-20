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
 * The DTLS of esdm_dtls.h, by whichever TLS stack the crypto backend has, on a
 * SOCK_SEQPACKET socket pair:
 *
 * - the handshake of a client and a server, both non-blocking;
 * - messages of one record, of several, and of none at all, both ways, and
 *   none of them readable on the socket;
 * - a message larger than allowed, a record that is not one of ours, and a
 *   peer that is gone end the connection;
 * - a message whose records arrive apart is kept until it is complete - in
 *   the room the call receiving its start had;
 * - an error the application left with the TLS stack is none of the DTLS;
 * - what the TLS stack frees holds no plaintext;
 * - the handshake, read off the wire, is ECDHE-PSK with the suites and the
 *   curves of the backend, with Encrypt-then-MAC for CBC, and no certificate;
 * - a record sent again - a replay - is dropped by the replay detection of
 *   DTLS, also after a newer one: the message comes once.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_dtls.h"
#include "helper.h"

#ifdef ESDM_DTLS

#if defined(ESDM_OPENSSL)
#include <openssl/crypto.h>
#include <openssl/err.h>
#elif defined(ESDM_GNUTLS)
#include <gnutls/gnutls.h>
#endif

#define TEST_MAX_MSG (64 * 1024)

/*
 * What the handshake of each backend offers and takes, see the backends:
 * ECDHE-PSK with AES-256 - GCM, then CBC for Botan, CBC for the others - on
 * brainpoolP512r1, then secp521r1 for Botan, on secp521r1 for the others.
 * Against itself, Botan takes GCM, which has no Encrypt-then-MAC.
 */
#define TEST_SUITE_GCM 0xD002 /* TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 */
#define TEST_SUITE_CBC 0xC038 /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
#define TEST_GROUP_BP512 28 /* brainpoolP512r1 */
#define TEST_GROUP_P521 25 /* secp521r1 */

#if defined(ESDM_BOTAN)
static const uint16_t test_suites[] = { TEST_SUITE_GCM, TEST_SUITE_CBC };
static const uint16_t test_groups[] = { TEST_GROUP_BP512, TEST_GROUP_P521 };
#define TEST_SUITE TEST_SUITE_GCM
#define TEST_GROUP TEST_GROUP_BP512
#define TEST_ETM false
#define TEST_CIPHER "ECDHE_PSK_WITH_AES_256_GCM_SHA384"
#else
static const uint16_t test_suites[] = { TEST_SUITE_CBC };
static const uint16_t test_groups[] = { TEST_GROUP_P521 };
#define TEST_SUITE TEST_SUITE_CBC
#define TEST_GROUP TEST_GROUP_P521
#define TEST_ETM true
#if defined(ESDM_OPENSSL)
#define TEST_CIPHER "ECDHE-PSK-AES256-CBC-SHA384"
#else
#define TEST_CIPHER "ECDHE_PSK_AES_256_CBC_SHA384"
#endif
#endif

/*
 * What the TLS stack frees must not hold the plaintext of a record: the test
 * sends a message carrying a marker both ways, and looks for it in every
 * buffer the TLS stack frees. OpenSSL and GnuTLS let their free be replaced;
 * Botan keeps the plaintext in vectors wiping themselves.
 */
static const char test_marker[] = "ESDM DTLS plaintext marker";
static unsigned int test_freed_plaintext = 0;

#if defined(ESDM_OPENSSL) || defined(ESDM_GNUTLS)
static void test_look_at_freed(void *ptr)
{
	if (ptr && memmem(ptr, malloc_usable_size(ptr), test_marker,
			  sizeof(test_marker) - 1))
		test_freed_plaintext++;
}
#endif

#if defined(ESDM_OPENSSL)
static void *test_ossl_malloc(size_t num, const char *file, int line)
{
	(void)file;
	(void)line;
	return malloc(num);
}

static void test_ossl_free(void *ptr, const char *file, int line)
{
	(void)file;
	(void)line;
	test_look_at_freed(ptr);
	free(ptr);
}

static void *test_ossl_realloc(void *ptr, size_t num, const char *file,
			       int line)
{
	if (!num) {
		test_ossl_free(ptr, file, line);
		return NULL;
	}
	return realloc(ptr, num);
}
#elif defined(ESDM_GNUTLS)
static gnutls_free_function test_gnutls_free_orig;

static void test_gnutls_free(void *ptr)
{
	test_look_at_freed(ptr);
	test_gnutls_free_orig(ptr);
}
#endif

/* Before the TLS stack allocates anything */
static void test_watch_frees(void)
{
#if defined(ESDM_OPENSSL)
	CHECK_EQ(CRYPTO_set_mem_functions(test_ossl_malloc, test_ossl_realloc,
					  test_ossl_free),
		 1);
#elif defined(ESDM_GNUTLS)
	test_gnutls_free_orig = gnutls_free;
	gnutls_free = test_gnutls_free;
#endif
}

/*
 * An error the application left on the error queue of the thread, which
 * OpenSSL keeps per thread rather than per connection: a call of the DTLS
 * waiting for the peer must not take it for one of its own.
 */
static void test_app_error(void)
{
#ifdef ESDM_OPENSSL
	ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
#endif
}

/* Drive both handshakes until neither waits any more */
static int test_handshake(struct esdm_dtls *client, struct esdm_dtls *server,
			  int cfd, int sfd)
{
	int c = -EAGAIN, s = -EAGAIN;
	unsigned int i;

	for (i = 0; i < 1000 && (c || s); i++) {
		struct pollfd pfd[2] = { { .fd = cfd, .events = POLLIN },
					 { .fd = sfd, .events = POLLIN } };

		if (c == -EAGAIN) {
			test_app_error();
			c = esdm_dtls_handshake(client);
		}
		if (s == -EAGAIN) {
			test_app_error();
			s = esdm_dtls_handshake(server);
		}
		if (c && c != -EAGAIN)
			return c;
		if (s && s != -EAGAIN)
			return s;
		if (c || s)
			poll(pfd, 2, 100);
	}

	return c ? c : s;
}

/* Receive a message, waiting for its records */
static ssize_t test_recv(struct esdm_dtls *dtls, int fd, void *buf, size_t len)
{
	unsigned int i;

	for (i = 0; i < 100; i++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;

		test_app_error();
		n = esdm_dtls_recv(dtls, buf, len);

		if (n != -EAGAIN)
			return n;
		if (!esdm_dtls_pending(dtls))
			poll(&pfd, 1, 100);
	}

	return -ETIMEDOUT;
}

/* A run of 16 equal bytes - what the plaintext below consists of */
static bool test_has_run(const uint8_t *buf, size_t len)
{
	size_t i, run = 1;

	for (i = 1; i < len; i++) {
		run = buf[i] == buf[i - 1] ? run + 1 : 1;
		if (run >= 16)
			return true;
	}
	return false;
}

/*
 * The handshake on the wire, which is in the clear up to the ChangeCipherSpec:
 * the suites and groups a ClientHello offers, the suite and the group the
 * server takes, Encrypt-then-MAC offered and agreed to, and any certificate.
 */
#define TEST_HS_CLIENT_HELLO 1
#define TEST_HS_SERVER_HELLO 2
#define TEST_HS_CERTIFICATE 11
#define TEST_HS_SERVER_KEY_EXCHANGE 12
#define TEST_EXT_GROUPS 10
#define TEST_EXT_ETM 22
#define TEST_SCSV 0x00ff

struct test_wire {
	uint16_t suites[16];
	unsigned int nsuites;
	uint16_t groups[16];
	unsigned int ngroups;
	/* Of the ServerHello and the ServerKeyExchange, 0 without */
	uint16_t suite;
	uint16_t group;
	bool etm;
	bool certificate;
	bool malformed;
};

struct test_reader {
	const uint8_t *p;
	size_t len, off;
	bool bad;
};

/* A big-endian number of @n bytes, 0 and bad past the end */
static uint32_t test_get(struct test_reader *r, size_t n)
{
	uint32_t v = 0;

	if (r->bad || n > r->len - r->off) {
		r->bad = true;
		return 0;
	}
	while (n--)
		v = (v << 8) | r->p[r->off++];
	return v;
}

static void test_skip(struct test_reader *r, size_t n)
{
	if (r->bad || n > r->len - r->off)
		r->bad = true;
	else
		r->off += n;
}

/* The extensions of a hello, the rest of @r */
static void test_wire_exts(struct test_reader *r, struct test_wire *w)
{
	struct test_reader exts = { .p = r->p + r->off };

	/* A hello without any */
	if (r->off == r->len)
		return;
	exts.len = test_get(r, 2);
	test_skip(r, exts.len);
	if (r->bad)
		return;
	exts.p += 2;

	while (!exts.bad && exts.off < exts.len) {
		uint32_t type = test_get(&exts, 2);
		struct test_reader ext = { .len = test_get(&exts, 2) };

		ext.p = exts.p + exts.off;
		test_skip(&exts, ext.len);

		if (type == TEST_EXT_ETM)
			w->etm = true;
		if (type != TEST_EXT_GROUPS || exts.bad)
			continue;

		/* The list of the groups is all of the extension */
		if (test_get(&ext, 2) + 2 != ext.len || ext.len % 2) {
			w->malformed = true;
			continue;
		}
		while (ext.off < ext.len && w->ngroups < ARRAY_SIZE(w->groups))
			w->groups[w->ngroups++] = (uint16_t)test_get(&ext, 2);
	}
	w->malformed |= exts.bad;
}

/* A handshake message of @type, its body in @r */
static void test_wire_hs(uint8_t type, struct test_reader *r,
			 struct test_wire *w)
{
	uint32_t n;

	switch (type) {
	case TEST_HS_CLIENT_HELLO:
		/* version, random, session ID, cookie */
		test_skip(r, 34);
		test_skip(r, test_get(r, 1));
		test_skip(r, test_get(r, 1));
		n = test_get(r, 2);
		if (n % 2)
			r->bad = true;
		for (; n >= 2 && !r->bad; n -= 2) {
			uint16_t suite = (uint16_t)test_get(r, 2);

			if (suite != TEST_SCSV &&
			    w->nsuites < ARRAY_SIZE(w->suites))
				w->suites[w->nsuites++] = suite;
		}
		test_skip(r, test_get(r, 1));
		test_wire_exts(r, w);
		break;
	case TEST_HS_SERVER_HELLO:
		/* version, random, session ID */
		test_skip(r, 34);
		test_skip(r, test_get(r, 1));
		w->suite = (uint16_t)test_get(r, 2);
		test_skip(r, 1);
		test_wire_exts(r, w);
		break;
	case TEST_HS_CERTIFICATE:
		w->certificate = true;
		break;
	case TEST_HS_SERVER_KEY_EXCHANGE:
		/* The PSK identity hint, then a named curve (3) and its ID */
		test_skip(r, test_get(r, 2));
		if (test_get(r, 1) == 3)
			w->group = (uint16_t)test_get(r, 2);
		else
			r->bad = true;
		break;
	default:
		break;
	}
	w->malformed |= r->bad;
}

/* The records of one message of the socket */
static void test_wire_parse(const uint8_t *msg, size_t len, struct test_wire *w)
{
	struct test_reader rec = { .p = msg, .len = len };

	while (!rec.bad && rec.off < rec.len) {
		/* type, version, epoch, sequence number, length */
		uint32_t ctype = test_get(&rec, 1), epoch;
		struct test_reader frag = { 0 };

		test_skip(&rec, 2);
		epoch = test_get(&rec, 2);
		test_skip(&rec, 6);
		frag.len = test_get(&rec, 2);
		frag.p = rec.p + rec.off;
		test_skip(&rec, frag.len);
		if (rec.bad || ctype != 22 || epoch)
			continue;

		while (!frag.bad && frag.off < frag.len) {
			/* type, length, sequence, fragment offset and length */
			uint8_t type = (uint8_t)test_get(&frag, 1);
			uint32_t hlen = test_get(&frag, 3), foff, flen;
			struct test_reader body = { 0 };

			test_skip(&frag, 2);
			foff = test_get(&frag, 3);
			flen = test_get(&frag, 3);
			body.p = frag.p + frag.off;
			body.len = flen;
			test_skip(&frag, flen);
			/* Nothing is fragmented with the MTU of the backends */
			if (frag.bad || foff || flen != hlen) {
				w->malformed = true;
				break;
			}
			test_wire_hs(type, &body, w);
		}
		w->malformed |= frag.bad;
	}
	w->malformed |= rec.bad;
}

/* Move what @from has to @to, reading it into @w; @return the messages */
static unsigned int test_wire_move(int from, int to, struct test_wire *w)
{
	static uint8_t buf[32 * 1024];
	unsigned int moved = 0;
	ssize_t n;

	while ((n = recv(from, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
		test_wire_parse(buf, (size_t)n, w);
		CHECK_EQ(send(to, buf, (size_t)n, MSG_NOSIGNAL), n);
		moved++;
	}

	return moved;
}

/*
 * A handshake through the test, which reads it off the wire: the client on
 * cs[0], the server on ss[1], and every message moved between cs[1] and ss[0].
 */
static void test_wire(struct esdm_dtls_ctx *cctx, struct esdm_dtls_ctx *sctx)
{
	struct test_wire hello = { 0 }, reply = { 0 };
	struct esdm_dtls *client = NULL, *server = NULL;
	int cs[2] = { -1, -1 }, ss[2] = { -1, -1 };
	int c = -EAGAIN, s = -EAGAIN;
	unsigned int i;
	uint8_t got[16], rec[512];
	ssize_t n;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, cs) ||
	    socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, ss)) {
		CHECK(0, "socketpair: %s", strerror(errno));
		goto out;
	}
	CHECK_EQ(esdm_dtls_alloc(cctx, cs[0], TEST_MAX_MSG, &client), 0);
	CHECK_EQ(esdm_dtls_alloc(sctx, ss[1], TEST_MAX_MSG, &server), 0);
	if (!client || !server)
		goto out;

	for (i = 0; i < 1000 && (c || s); i++) {
		struct pollfd pfd[2] = { { .fd = cs[1], .events = POLLIN },
					 { .fd = ss[0], .events = POLLIN } };
		unsigned int moved;

		if (c == -EAGAIN)
			c = esdm_dtls_handshake(client);
		if (s == -EAGAIN)
			s = esdm_dtls_handshake(server);
		if ((c && c != -EAGAIN) || (s && s != -EAGAIN))
			break;
		moved = test_wire_move(cs[1], ss[0], &hello);
		moved += test_wire_move(ss[0], cs[1], &reply);
		if (!moved && (c || s))
			poll(pfd, 2, 100);
	}
	CHECK_EQ(c, 0);
	CHECK_EQ(s, 0);
	printf("handshake on the wire: suite 0x%04x, group %u, "
	       "Encrypt-then-MAC %s, %s\n",
	       reply.suite, reply.group, reply.etm ? "yes" : "no",
	       esdm_dtls_cipher(client));

	CHECK(!hello.malformed && !reply.malformed,
	      "a handshake message not understood");
	/* The client offers what its backend has, and Encrypt-then-MAC */
	CHECK_EQ(hello.nsuites, ARRAY_SIZE(test_suites));
	for (i = 0; i < hello.nsuites && i < ARRAY_SIZE(test_suites); i++)
		CHECK_EQ(hello.suites[i], test_suites[i]);
	CHECK_EQ(hello.ngroups, ARRAY_SIZE(test_groups));
	for (i = 0; i < hello.ngroups && i < ARRAY_SIZE(test_groups); i++)
		CHECK_EQ(hello.groups[i], test_groups[i]);
	CHECK(hello.etm, "the client does not offer Encrypt-then-MAC");
	/* The server takes the first of them */
	CHECK_EQ(reply.suite, TEST_SUITE);
	CHECK_EQ(reply.group, TEST_GROUP);
	CHECK_EQ(reply.etm, TEST_ETM);
	/* The pre-shared key, no certificate of either side */
	CHECK(!hello.certificate && !reply.certificate,
	      "a certificate was sent");
	CHECK_STR_EQ(esdm_dtls_cipher(client), TEST_CIPHER);
	CHECK_STR_EQ(esdm_dtls_cipher(server), TEST_CIPHER);

	/* And the connection works through the test */
	if (c || s)
		goto out;
	CHECK_EQ(esdm_dtls_send(client, "wire", 4), 0);
	test_wire_move(cs[1], ss[0], &hello);
	CHECK_EQ(test_recv(server, ss[1], got, sizeof(got)), 4);
	CHECK_MEM_EQ(got, "wire", 4);

	/*
	 * The record of a message moved twice, as one recorded on the way and
	 * sent again: the replay detection of DTLS drops the second one. It is
	 * taken off the socket all the same, the message comes once.
	 */
	CHECK_EQ(esdm_dtls_send(client, "once", 4), 0);
	n = recv(cs[1], rec, sizeof(rec), MSG_DONTWAIT);
	CHECK(n > 0, "no record of the message: %zd", n);
	if (n <= 0)
		goto out;
	CHECK_EQ(send(ss[0], rec, (size_t)n, MSG_NOSIGNAL), n);
	CHECK_EQ(send(ss[0], rec, (size_t)n, MSG_NOSIGNAL), n);
	CHECK_EQ(test_recv(server, ss[1], got, sizeof(got)), 4);
	CHECK_MEM_EQ(got, "once", 4);
	CHECK_EQ(esdm_dtls_recv(server, got, sizeof(got)), -EAGAIN);
	CHECK(recv(ss[1], got, sizeof(got), MSG_DONTWAIT | MSG_PEEK) < 0,
	      "the replayed record is left on the socket");

	/* Sent again after a newer one, and the connection goes on */
	CHECK_EQ(esdm_dtls_send(client, "next", 4), 0);
	test_wire_move(cs[1], ss[0], &hello);
	CHECK_EQ(test_recv(server, ss[1], got, sizeof(got)), 4);
	CHECK_MEM_EQ(got, "next", 4);
	CHECK_EQ(send(ss[0], rec, (size_t)n, MSG_NOSIGNAL), n);
	CHECK_EQ(esdm_dtls_recv(server, got, sizeof(got)), -EAGAIN);
	CHECK_EQ(esdm_dtls_send(client, "last", 4), 0);
	test_wire_move(cs[1], ss[0], &hello);
	CHECK_EQ(test_recv(server, ss[1], got, sizeof(got)), 4);
	CHECK_MEM_EQ(got, "last", 4);

out:
	esdm_dtls_free(client);
	esdm_dtls_free(server);
	for (i = 0; i < 2; i++) {
		if (cs[i] >= 0)
			close(cs[i]);
		if (ss[i] >= 0)
			close(ss[i]);
	}
}

/*
 * A message of three records whose first one arrives alone: the receiver keeps
 * it, with a buffer of @first_len, and takes the others with a buffer of
 * TEST_MAX_MSG - expecting @exp. The records are taken off the socket of the
 * receiver and sent on it again, the first one before the others.
 */
static void test_split(struct esdm_dtls_ctx *cctx, struct esdm_dtls_ctx *sctx,
		       size_t first_len, ssize_t exp)
{
	static uint8_t msg[3 * ESDM_DTLS_PART_SIZE], got[TEST_MAX_MSG];
	static uint8_t held[3][ESDM_DTLS_PART_SIZE + 1024];
	struct esdm_dtls *client = NULL, *server = NULL;
	ssize_t held_len[3];
	unsigned int i;
	uint8_t more;
	int sv[2];

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, sv)) {
		CHECK(0, "socketpair: %s", strerror(errno));
		return;
	}
	CHECK_EQ(esdm_dtls_alloc(cctx, sv[0], TEST_MAX_MSG, &client), 0);
	CHECK_EQ(esdm_dtls_alloc(sctx, sv[1], TEST_MAX_MSG, &server), 0);
	if (!client || !server)
		goto out;
	CHECK_EQ(test_handshake(client, server, sv[0], sv[1]), 0);

	memset(msg, 0x24, sizeof(msg));
	CHECK_EQ(esdm_dtls_send(client, msg, sizeof(msg)), 0);
	for (i = 0; i < 3; i++) {
		held_len[i] =
			recv(sv[1], held[i], sizeof(held[i]), MSG_DONTWAIT);
		/* A record per message of the socket */
		CHECK(held_len[i] > ESDM_DTLS_PART_SIZE, "record %u: %zd", i,
		      held_len[i]);
		if (held_len[i] <= ESDM_DTLS_PART_SIZE)
			goto out;
	}
	CHECK(recv(sv[1], &more, 1, MSG_DONTWAIT) < 0, "a fourth record");

	CHECK_EQ(send(sv[0], held[0], (size_t)held_len[0], MSG_NOSIGNAL),
		 held_len[0]);
	CHECK_EQ(esdm_dtls_recv(server, got, first_len), -EAGAIN);
	for (i = 1; i < 3; i++)
		CHECK_EQ(send(sv[0], held[i], (size_t)held_len[i],
			      MSG_NOSIGNAL),
			 held_len[i]);
	CHECK_EQ(esdm_dtls_recv(server, got, sizeof(got)), exp);
	if (exp == (ssize_t)sizeof(msg))
		CHECK_MEM_EQ(got, msg, sizeof(msg));

out:
	esdm_dtls_free(client);
	esdm_dtls_free(server);
	close(sv[0]);
	close(sv[1]);
}

static void test_dtls(void)
{
	static uint8_t msg[TEST_MAX_MSG], got[TEST_MAX_MSG + 16];
	struct esdm_dtls_ctx *cctx = NULL, *sctx = NULL;
	struct esdm_dtls *client = NULL, *server = NULL;
	static const size_t sizes[] = { 1,
					100,
					ESDM_DTLS_PART_SIZE,
					ESDM_DTLS_PART_SIZE + 1,
					3 * ESDM_DTLS_PART_SIZE,
					TEST_MAX_MSG };
	int sv[2], peek[2];
	unsigned int i;
	ssize_t n;

	CHECK_EQ(esdm_dtls_busy(), false);
	CHECK_EQ(esdm_dtls_ctx_alloc(false, &cctx), 0);
	CHECK_EQ(esdm_dtls_ctx_alloc(true, &sctx), 0);
	if (!cctx || !sctx)
		goto out;

	CHECK_EQ(socketpair(AF_UNIX,
			    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			    sv),
		 0);
	CHECK_EQ(esdm_dtls_alloc(cctx, sv[0], TEST_MAX_MSG, &client), 0);
	CHECK_EQ(esdm_dtls_alloc(sctx, sv[1], TEST_MAX_MSG, &server), 0);
	if (!client || !server)
		goto out;

	CHECK_EQ(test_handshake(client, server, sv[0], sv[1]), 0);
	printf("handshake complete, %s\n", esdm_dtls_cipher(client));

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		memset(msg, (int)(0x30 + i), sizes[i]);

		/* Client to server */
		CHECK_EQ(esdm_dtls_send(client, msg, sizes[i]), 0);
		n = test_recv(server, sv[1], got, sizeof(got));
		CHECK_EQ(n, (ssize_t)sizes[i]);
		if (n == (ssize_t)sizes[i])
			CHECK_MEM_EQ(got, msg, sizes[i]);

		/* And back */
		CHECK_EQ(esdm_dtls_send(server, msg, sizes[i]), 0);
		n = test_recv(client, sv[0], got, sizeof(got));
		CHECK_EQ(n, (ssize_t)sizes[i]);
		if (n == (ssize_t)sizes[i])
			CHECK_MEM_EQ(got, msg, sizes[i]);
	}

	/* A message carrying the marker both ways, see test_look_at_freed() */
	for (i = 0; i < 2 * ESDM_DTLS_PART_SIZE; i += sizeof(test_marker))
		memcpy(msg + i, test_marker, sizeof(test_marker));
	CHECK_EQ(esdm_dtls_send(client, msg, i), 0);
	CHECK_EQ(test_recv(server, sv[1], got, sizeof(got)), (ssize_t)i);
	CHECK_EQ(esdm_dtls_send(server, msg, i), 0);
	CHECK_EQ(test_recv(client, sv[0], got, sizeof(got)), (ssize_t)i);
	CHECK_MEM_EQ(got, msg, i);
	memset(got, 0, sizeof(got));

	/* An empty message is one too */
	CHECK_EQ(esdm_dtls_send(client, msg, 0), 0);
	CHECK_EQ(test_recv(server, sv[1], got, sizeof(got)), 0);

	/* What the socket carries is not the plaintext */
	memset(msg, 0x55, 64);
	CHECK_EQ(esdm_dtls_send(client, msg, 64), 0);
	{
		uint8_t raw[ESDM_DTLS_PART_SIZE + 512];

		n = recv(sv[1], raw, sizeof(raw), MSG_PEEK);
		CHECK(n > 64, "no record on the socket");
		if (n > 0)
			CHECK(!test_has_run(raw, (size_t)n),
			      "the record carries the plaintext");
	}
	CHECK_EQ(test_recv(server, sv[1], got, sizeof(got)), 64);

	/* Larger than the buffer of the receiver */
	memset(msg, 0x42, 4096);
	CHECK_EQ(esdm_dtls_send(client, msg, 4096), 0);
	CHECK_EQ(test_recv(server, sv[1], got, 1024), -EMSGSIZE);

	/* A record of the socket that DTLS does not know - dropped by DTLS */
	CHECK_EQ(send(sv[0], "not a record", 12, MSG_NOSIGNAL), 12);
	test_app_error();
	CHECK_EQ(esdm_dtls_recv(server, got, sizeof(got)), -EAGAIN);

	/* The peer gone */
	esdm_dtls_free(client);
	client = NULL;
	close(sv[0]);
	sv[0] = -1;
	n = test_recv(server, sv[1], got, sizeof(got));
	CHECK(n < 0 && n != -EAGAIN && n != -ETIMEDOUT,
	      "a peer gone is not noticed (%zd)", n);

	/* A message too large for the max_msg of the receiver */
	CHECK_EQ(socketpair(AF_UNIX,
			    SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
			    peek),
		 0);
	esdm_dtls_free(server);
	server = NULL;
	CHECK_EQ(esdm_dtls_alloc(cctx, peek[0], TEST_MAX_MSG, &client), 0);
	CHECK_EQ(esdm_dtls_alloc(sctx, peek[1], 100, &server), 0);
	if (client && server) {
		CHECK_EQ(test_handshake(client, server, peek[0], peek[1]), 0);
		CHECK_EQ(esdm_dtls_send(client, msg, 2 * ESDM_DTLS_PART_SIZE),
			 0);
		CHECK_EQ(test_recv(server, peek[1], got, sizeof(got)),
			 -EMSGSIZE);
	}
	close(peek[0]);
	close(peek[1]);

	/* A message whose records arrive apart */
	test_split(cctx, sctx, TEST_MAX_MSG, 3 * ESDM_DTLS_PART_SIZE);
	/*
	 * Its start went into a buffer for the first part only: what follows
	 * does not fit there, larger as the buffer of the call taking it is
	 */
	test_split(cctx, sctx, ESDM_DTLS_PART_SIZE + 100, -EMSGSIZE);

	/* The suite, the curve and Encrypt-then-MAC on the wire, and replays */
	test_wire(cctx, sctx);

out:
	CHECK_EQ(esdm_dtls_busy(), false);
	esdm_dtls_free(client);
	esdm_dtls_free(server);
	if (sv[0] >= 0)
		close(sv[0]);
	close(sv[1]);
	esdm_dtls_ctx_free(cctx);
	esdm_dtls_ctx_free(sctx);

	CHECK_EQ(test_freed_plaintext, 0);
}

#endif /* ESDM_DTLS */

int main(void)
{
#ifdef ESDM_DTLS
	test_watch_frees();
	test_dtls();
	return common_test_result("esdm_dtls");
#else
	printf("built without DTLS - skipping\n");
	return 77;
#endif
}
