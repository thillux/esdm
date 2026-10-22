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
 * libesdm_getrandom and the DTLS of the RPC connections, preloaded into this
 * process as the library is meant to be used.
 *
 * The TLS stack of the RPC client asks the operating system for random numbers
 * when it does the handshake of a connection - getentropy(3), which in this
 * process is the one of libesdm_getrandom, served by the very RPC client whose
 * handshake is under way. That inner call has to fail at once, so that the
 * library hands it to the kernel: with the one connection libesdm_getrandom
 * uses, it would otherwise wait for the connection the outer call holds,
 * forever - the alarm below ends such a test.
 *
 * The server is rpc_dtls_test serving its stand-in services, in a process of
 * its own and without the library: it answers a request for random numbers
 * with its pattern only on an encrypted connection, so the pattern arriving
 * tells that the handshake completed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "esdm_rpc_service.h"
#include "../test_env.h"
#include "../test_wait.h"

#define TEST_ALARM_SEC 60

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

int main(void)
{
	const char *server = getenv("ESDM_RPC_DTLS_SERVER");
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	uint8_t pattern[64], buf[64];
	pid_t pid;
	int status;

#ifndef ESDM_DTLS
	printf("No DTLS in this build\n");
	return 77;
#endif

	if (test_env_check_file(server))
		return 1;

	if (test_socket_taken(ESDM_RPC_UNPRIV_SOCKET) ||
	    test_socket_taken(ESDM_RPC_PRIV_SOCKET)) {
		printf("The RPC sockets belong to somebody else - skipping\n");
		return 77;
	}

	test_fill(pattern, sizeof(pattern), 0x9e3779b97f4a7c15ULL);

	/* Without the library: built before the fork, see test_env.h */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	fflush(stdout);
	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (!pid) {
		char *server_argv[] = { (char *)server, "serve", NULL };

		/* Not to outlive a test ended by the alarm */
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		execve(server, server_argv, server_envp);
		_exit(127);
	}

	if (!test_wait_for_listener(ESDM_RPC_UNPRIV_SOCKET, SOCK_SEQPACKET,
				    TEST_WAIT_TIMEOUT_MS) ||
	    !test_wait_for_listener(ESDM_RPC_PRIV_SOCKET, SOCK_SEQPACKET,
				    TEST_WAIT_TIMEOUT_MS)) {
		fprintf(stderr, "the server did not come up\n");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return 1;
	}

	/* A call waiting for itself does not return */
	alarm(TEST_ALARM_SEC);

	printf("getrandom(3) over an encrypted connection\n");
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(getrandom(buf, sizeof(buf), 0), (ssize_t)sizeof(buf));
	CHECK(!memcmp(buf, pattern, sizeof(buf)),
	      "not the bytes of the server - no DTLS?");

	printf("getentropy(3) over an encrypted connection\n");
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(getentropy(buf, 32), 0);
	CHECK(!memcmp(buf, pattern, 32),
	      "not the bytes of the server - no DTLS?");

	alarm(0);

	kill(pid, SIGTERM);
	CHECK(waitpid(pid, &status, 0) == pid, "cannot wait for the server");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status), "the server failed");

	if (!common_test_failures)
		printf("PASS\n");

	return common_test_failures ? 1 : 0;
}
