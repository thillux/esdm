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
 * esdm-es-ext-serve against a client speaking the protocol: it serves the
 * plugin library it is given on the socket it is given, with the mode asked
 * for, until it is terminated, and removes the socket then. What it cannot
 * serve - no plugin, a plugin that does not fit, a mode that is none - it
 * refuses to start with.
 *
 * Usage: es_ext_serve_test <esdm-es-ext-serve> <test plugin> <bad version>
 */

#define _GNU_SOURCE
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_es_ext_proto.h"

static char test_dir[] = "/tmp/esdm-es-ext-serve-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

/* Started with an empty environment, as the test suite runs its daemons */
static pid_t test_spawn(char *const argv[])
{
	char *const envp[] = { NULL };
	pid_t pid;

	if (posix_spawn(&pid, argv[0], NULL, NULL, argv, envp))
		return -1;
	return pid;
}

static int test_wait(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

/* Run to completion, the exit status */
static int test_run(char *const argv[])
{
	pid_t pid = test_spawn(argv);

	return pid < 0 ? -1 : test_wait(pid);
}

static bool test_wait_socket(void)
{
	const struct timespec ts = { .tv_nsec = 20000000 };
	struct stat sb;
	unsigned int i;

	for (i = 0; i < 500; i++) {
		if (lstat(test_socket, &sb) == 0 && S_ISSOCK(sb.st_mode))
			return true;
		nanosleep(&ts, NULL);
	}

	return false;
}

static int test_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval tv = { .tv_sec = 5 };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_socket);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static void test_serve(const char *serve, const char *plugin)
{
	char *const argv[] = { (char *)serve,  "--plugin",  (char *)plugin,
			       "--socket",     test_socket, "--mode",
			       (char *)"0640", NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t bits = 0;
	int32_t status = -1;
	struct stat sb;
	pid_t pid;
	ssize_t n;
	int fd;

	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;

	CHECK(test_wait_socket(), "the provider did not create its socket");
	CHECK_EQ(lstat(test_socket, &sb), 0);
	CHECK_EQ(sb.st_mode & 0777, 0640);

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   32);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 32);
		if (n > 0) {
			CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
					 rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY, 32,
					 &status, &bits, &data),
				 0);
			CHECK_EQ(status, 0);
			/* The test plugin claims all bits by default */
			CHECK_EQ(bits, 256);
		}

		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_SELFTEST, 0);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		close(fd);
	}

	/* Terminated, it ends cleanly and removes its socket */
	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
	CHECK(lstat(test_socket, &sb) < 0, "the socket was left behind");
}

static void test_refusals(const char *serve, const char *plugin,
			  const char *bad_version)
{
	char *const no_args[] = { (char *)serve, NULL };
	char *const no_socket[] = { (char *)serve, "--plugin", (char *)plugin,
				    NULL };
	char *const bad_plugin[] = { (char *)serve,	  "--plugin",
				     (char *)bad_version, "--socket",
				     test_socket,	  NULL };
	char *const missing[] = {
		(char *)serve, "--plugin",  "/nonexistent/libnothing.so",
		"--socket",    test_socket, NULL
	};
	char *const bad_mode[] = { (char *)serve, "--plugin",  (char *)plugin,
				   "--socket",	  test_socket, "--mode",
				   "0999",	  NULL };
	char *const version[] = { (char *)serve, "--version", NULL };
	struct stat sb;

	CHECK_EQ(test_run(no_args), 1);
	CHECK_EQ(test_run(no_socket), 1);
	CHECK_EQ(test_run(bad_plugin), 1);
	CHECK_EQ(test_run(missing), 1);
	CHECK_EQ(test_run(bad_mode), 1);
	CHECK(lstat(test_socket, &sb) < 0,
	      "a refused start left a socket behind");
	CHECK_EQ(test_run(version), 0);
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		printf("usage: %s <esdm-es-ext-serve> <test plugin> <bad version>\n",
		       argv[0]);
		return 1;
	}

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	test_refusals(argv[1], argv[2], argv[3]);
	test_serve(argv[1], argv[2]);

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_serve");
}
