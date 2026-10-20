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
 * The TLS layer of common/tls/esdm_tls.h released at the exit of the process, as
 * libesdm_egd_client uses it in TLS mode: from its module, esdm-egd-tls.so,
 * loaded with the TLS stack once the first client in TLS mode is allocated.
 * A program that releases its client at the exit, with an atexit handler it
 * registered before - or OpenSSL with its cleanup - does so after the static
 * destructors the TLS stack registered when it was loaded: with Botan, the
 * connection released there - with its closing alert - crashed the process.
 *
 * Released at the exit, nothing may go into the TLS stack any more - which
 * this test cannot see but by the process ending with the exit code of
 * main(), rather than killed by a signal. Its argument is the module; the test
 * is not linked with the TLS stack, as a program using the library is not.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esdm_egd_client_tls.h"

#ifndef ESDM_TEST_PKI
#error "ESDM_TEST_PKI must name the directory of the test PKI"
#endif

#define PKI(name) ESDM_TEST_PKI "/" name

static const struct esdm_egd_tls_module *tls;

/* What the exit handler releases */
static struct esdm_tls_ctx *test_sctx, *test_cctx;
static struct esdm_tls *test_server, *test_client;

static struct esdm_tls_config test_cfg(const char *cert, const char *key)
{
	struct esdm_tls_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_files[0] = PKI("ca.crt");
	cfg.ca_files_num = 1;
	return cfg;
}

/* Both ends in turn, each waiting a moment for the other */
static int test_handshake(void)
{
	int s = -EAGAIN, c = -EAGAIN;
	unsigned int i;

	for (i = 0; i < 2000 && (s == -EAGAIN || c == -EAGAIN); i++) {
		if (s == -EAGAIN) {
			s = tls->handshake(test_server);
			if (s == -EAGAIN)
				(void)tls->wait(test_server, 5);
		}
		if (c == -EAGAIN) {
			c = tls->handshake(test_client);
			if (c == -EAGAIN)
				(void)tls->wait(test_client, 5);
		}
	}

	return (s || c) ? -1 : 0;
}

/* A message from the client to the server */
static int test_transfer(void)
{
	static const uint8_t msg[] = "ESDM TLS released at the exit";
	uint8_t got[sizeof(msg)];
	size_t sent = 0, recvd = 0;
	unsigned int i;

	for (i = 0; i < 1000 && recvd < sizeof(msg); i++) {
		ssize_t n;

		if (sent < sizeof(msg)) {
			n = tls->send(test_client, msg + sent,
				      sizeof(msg) - sent);
			if (n > 0)
				sent += (size_t)n;
		} else {
			(void)tls->flush(test_client);
		}

		n = tls->recv(test_server, got + recvd, sizeof(got) - recvd);
		if (n > 0)
			recvd += (size_t)n;
		else if (n != -EAGAIN)
			return -1;
		else
			(void)tls->wait(test_server, 5);
	}

	return (recvd == sizeof(msg) && !memcmp(got, msg, sizeof(msg))) ? 0 :
									  -1;
}

/*
 * Registered before the module is loaded, so it runs after the destructors
 * the TLS stack registers: as a client going away does, the closing alert,
 * then the connections and the contexts.
 */
static void test_release_at_exit(void)
{
	if (!tls)
		return;

	tls->close_notify(test_client);
	tls->free(test_client);
	tls->free(test_server);
	tls->ctx_put(test_cctx);
	tls->ctx_put(test_sctx);

	printf("released at the exit\n");
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	struct esdm_tls_config scfg =
		test_cfg(PKI("server.crt"), PKI("server.key"));
	struct esdm_tls_config ccfg =
		test_cfg(PKI("client1.crt"), PKI("client1.key"));
	const struct esdm_egd_tls_module *(*entry)(void);
	void *handle, *sym;
	int sv[2], ret;

	if (argc != 2) {
		printf("usage: %s <TLS module>\n", argv[0]);
		return 99;
	}

	if (atexit(test_release_at_exit)) {
		printf("cannot register the exit handler\n");
		return 99;
	}

	/* As libesdm_egd_client loads it, see esdm_egd_tls_load_module() */
	handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		printf("FAIL: cannot load %s: %s\n", argv[1], dlerror());
		return 1;
	}
	sym = dlsym(handle, ESDM_EGD_TLS_MODULE_SYMBOL);
	memcpy(&entry, &sym, sizeof(entry));
	if (!entry || !entry() ||
	    entry()->version != ESDM_EGD_TLS_MODULE_VERSION) {
		printf("FAIL: %s is no TLS module\n", argv[1]);
		return 1;
	}

	ret = entry()->ctx_alloc(true, &scfg, &test_sctx);
	if (!ret)
		ret = entry()->ctx_alloc(false, &ccfg, &test_cctx);
	if (ret) {
		printf("FAIL: the contexts: %s\n", strerror(-ret));
		return 1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0,
		       sv)) {
		printf("FAIL: socketpair: %s\n", strerror(errno));
		return 1;
	}
	if (entry()->alloc(test_sctx, sv[0], NULL, &test_server) ||
	    entry()->alloc(test_cctx, sv[1], "localhost", &test_client)) {
		printf("FAIL: the connections\n");
		return 1;
	}

	/* From here on, the exit handler releases what there is */
	tls = entry();

	if (test_handshake()) {
		printf("FAIL: the handshake: %s / %s\n",
		       tls->error(test_server), tls->error(test_client));
		return 1;
	}
	if (test_transfer()) {
		printf("FAIL: the transfer\n");
		return 1;
	}

	printf("connection set up, %s\n", tls->cipher(test_client));

	/* The connections are released by test_release_at_exit() */
	return 0;
}
