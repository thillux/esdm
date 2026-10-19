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
 * - what the TLS stack frees holds no plaintext.
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

#ifdef ESDM_DTLS

#if defined(ESDM_OPENSSL)
#include <openssl/crypto.h>
#include <openssl/err.h>
#elif defined(ESDM_GNUTLS)
#include <gnutls/gnutls.h>
#endif

#define TEST_MAX_MSG (64 * 1024)

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
