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
 * The DTLS of esdm_dtls.h released at the exit of the process, by an atexit
 * handler registered before the TLS stack was set up - as OpenSSL registers its
 * cleanup, which tears down an OpenSSL provider using the RPC client. The
 * handler runs after the static destructors the TLS stack registered when it
 * set itself up: with Botan, the connections released there crashed the
 * process, their secure memory unmapped already.
 *
 * Released at the exit, nothing may go into the TLS stack any more - which
 * this test cannot see but by the process ending the way it should: with the
 * exit code of main(), rather than killed by a signal - and, with the address
 * sanitizer, without a leak: what is left stays reachable. Linked with the TLS
 * stack, this program has it set up its static state as it starts, before the
 * handler is registered, which Botan does: the crash itself is the test of an
 * OpenSSL provider loaded at run time, see
 * tests/openssl-rand-provider/openssl_dtls_exit_test.c. This one runs for
 * every TLS stack, also without the providers.
 */

#define _GNU_SOURCE
#include <errno.h>
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

#define TEST_MAX_MSG 4096

/* What the exit handler releases */
static struct esdm_dtls_ctx *test_cctx, *test_sctx;
static struct esdm_dtls *test_client, *test_server;

/* Drive both handshakes until neither waits any more */
static int test_handshake(int cfd, int sfd)
{
	int c = -EAGAIN, s = -EAGAIN;
	unsigned int i;

	for (i = 0; i < 1000 && (c || s); i++) {
		struct pollfd pfd[2] = { { .fd = cfd, .events = POLLIN },
					 { .fd = sfd, .events = POLLIN } };

		if (c == -EAGAIN)
			c = esdm_dtls_handshake(test_client);
		if (s == -EAGAIN)
			s = esdm_dtls_handshake(test_server);
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
		ssize_t n = esdm_dtls_recv(dtls, buf, len);

		if (n != -EAGAIN)
			return n;
		if (!esdm_dtls_pending(dtls))
			poll(&pfd, 1, 100);
	}

	return -ETIMEDOUT;
}

/*
 * Registered before the TLS stack is set up, so it runs after the destructors
 * the TLS stack registers.
 */
static void test_release_at_exit(void)
{
	esdm_dtls_free(test_client);
	esdm_dtls_free(test_server);
	esdm_dtls_ctx_free(test_cctx);
	esdm_dtls_ctx_free(test_sctx);

	printf("released at the exit\n");
	fflush(stdout);
}

int main(void)
{
	static uint8_t msg[TEST_MAX_MSG], got[TEST_MAX_MSG];
	int sv[2];

	if (atexit(test_release_at_exit)) {
		printf("cannot register the exit handler\n");
		return 99;
	}

	CHECK_EQ(esdm_dtls_ctx_alloc(false, &test_cctx), 0);
	CHECK_EQ(esdm_dtls_ctx_alloc(true, &test_sctx), 0);
	if (!test_cctx || !test_sctx)
		return 1;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
		       0, sv)) {
		CHECK(0, "socketpair: %s", strerror(errno));
		return 1;
	}
	CHECK_EQ(esdm_dtls_alloc(test_cctx, sv[0], TEST_MAX_MSG, &test_client),
		 0);
	CHECK_EQ(esdm_dtls_alloc(test_sctx, sv[1], TEST_MAX_MSG, &test_server),
		 0);
	if (!test_client || !test_server)
		return 1;
	CHECK_EQ(test_handshake(sv[0], sv[1]), 0);

	/* A connection in use, both ways */
	memset(msg, 0x5a, sizeof(msg));
	CHECK_EQ(esdm_dtls_send(test_client, msg, sizeof(msg)), 0);
	CHECK_EQ(test_recv(test_server, sv[1], got, sizeof(got)),
		 (ssize_t)sizeof(msg));
	CHECK_EQ(esdm_dtls_send(test_server, msg, 100), 0);
	CHECK_EQ(test_recv(test_client, sv[0], got, sizeof(got)), 100);

	printf("connection set up, %s\n", esdm_dtls_cipher(test_client));

	/* The connections are released by test_release_at_exit() */
	return common_test_result("esdm_dtls at the exit");
}

#else /* ESDM_DTLS */

int main(void)
{
	printf("built without DTLS - skipping\n");
	return 77;
}

#endif /* ESDM_DTLS */
