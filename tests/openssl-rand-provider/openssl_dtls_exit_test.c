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
 * An OpenSSL RAND provider of the RPC interface, its connection encrypted with
 * DTLS, at the exit of the process.
 *
 * OpenSSL registers its cleanup with atexit(3) when it is set up, before it
 * loads the provider - and with it the RPC client and the TLS stack of its
 * DTLS. The cleanup tears the provider down, which releases the connection of
 * the RPC client - after the static destructors of the TLS stack ran: with
 * Botan, every process using the provider crashed in its exit(3).
 *
 * The process using the provider is a child of the test, so that how it ends
 * is told. The server is rpc_dtls_test serving its stand-in services, as for
 * rpc_dtls_getrandom_test.c: it answers a request for random numbers with its
 * pattern only on an encrypted connection, so the pattern arriving tells that
 * the provider uses DTLS. Needs no privileges.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm_rpc_service.h"
#include "../test_env.h"
#include "../test_wait.h"

/* The pattern rpc_dtls_test serves, see test_fill() there */
static void test_fill(uint8_t *buf, size_t len, uint64_t state)
{
	size_t i;

	for (i = 0; i < len; i++) {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		buf[i] = (uint8_t)(state >> 24);
	}
}

static bool test_socket_taken(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	bool taken;

	if (fd < 0)
		return false;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	taken = !connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);

	return taken;
}

/*
 * The process using the provider: random numbers of its SEED-SRC, which are
 * the server's, then the exit. The program lets go of the provider when done
 * with it, as openssl_rng_tester.c does, but the algorithm of it OpenSSL keeps
 * in its store holds it on until OPENSSL_cleanup() at the exit tears it down.
 */
static int test_provider(const char *dir, const char *name)
{
	uint8_t pattern[64], buf[64];
	OSSL_PROVIDER *prov;
	EVP_RAND_CTX *ctx;
	EVP_RAND *rand;
	int ret = 1;

	test_fill(pattern, sizeof(pattern), 0x9e3779b97f4a7c15ULL);

	if (OSSL_PROVIDER_set_default_search_path(NULL, dir) != 1 ||
	    !(prov = OSSL_PROVIDER_load(NULL, name))) {
		fprintf(stderr, "cannot load %s from %s\n", name, dir);
		return 1;
	}

	rand = EVP_RAND_fetch(NULL, "SEED-SRC", "provider=esdm");
	if (!rand) {
		fprintf(stderr, "no SEED-SRC of the provider\n");
		return 1;
	}
	ctx = EVP_RAND_CTX_new(rand, NULL);
	EVP_RAND_free(rand);
	if (!ctx) {
		fprintf(stderr, "no RAND context\n");
		return 1;
	}

	memset(buf, 0, sizeof(buf));
	if (EVP_RAND_instantiate(ctx, 0, 0, NULL, 0, NULL) != 1 ||
	    EVP_RAND_generate(ctx, buf, sizeof(buf), 0, 0, NULL, 0) != 1)
		fprintf(stderr, "no random numbers from the provider\n");
	else if (memcmp(buf, pattern, sizeof(buf)))
		fprintf(stderr, "not the bytes of the server - no DTLS?\n");
	else
		ret = 0;

	EVP_RAND_CTX_free(ctx);
	OSSL_PROVIDER_unload(prov);

	return ret;
}

int main(int argc, char *argv[])
{
	const char *server = getenv("ESDM_RPC_DTLS_SERVER");
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	pid_t pid, user;
	int status, ret = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <provider directory> <provider>\n",
			argv[0]);
		return 99;
	}

#ifndef ESDM_DTLS
	printf("No DTLS in this build\n");
	return 77;
#endif

	if (test_env_check_file(server))
		return 99;

	if (test_socket_taken(ESDM_RPC_UNPRIV_SOCKET) ||
	    test_socket_taken(ESDM_RPC_PRIV_SOCKET)) {
		printf("The RPC sockets belong to somebody else - skipping\n");
		return 77;
	}

	/* Built before the fork, see test_env.h */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 99;
	}
	if (!pid) {
		char *server_argv[] = { (char *)server, "serve", NULL };

		/* Not to outlive a test that ended early */
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		execve(server, server_argv, server_envp);
		_exit(127);
	}

	if (!test_wait_for_listener(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET,
				    TEST_WAIT_TIMEOUT_MS)) {
		fprintf(stderr, "the server did not come up\n");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return 99;
	}

	user = fork();
	if (user < 0) {
		perror("fork");
		ret = 99;
		goto out;
	}
	if (!user)
		exit(test_provider(argv[1], argv[2]));

	if (waitpid(user, &status, 0) != user) {
		perror("waitpid");
		ret = 99;
	} else if (WIFSIGNALED(status)) {
		printf("FAIL: the process using %s was killed by signal %d\n",
		       argv[2], WTERMSIG(status));
		ret = 1;
	} else if (WEXITSTATUS(status)) {
		printf("FAIL: the process using %s failed: %d\n", argv[2],
		       WEXITSTATUS(status));
		ret = 1;
	}

out:
	kill(pid, SIGTERM);
	if (test_env_reap_daemon(pid, "rpc_dtls_test"))
		ret = 1;

	if (!ret)
		printf("PASS\n");

	return ret;
}
