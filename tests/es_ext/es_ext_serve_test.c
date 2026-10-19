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
 * It answers INFO with the name of its plugin, or the one of --name, and
 * refuses to start with a --name that is no valid name. A request that breaks
 * the protocol closes the connection.
 *
 * Usage: es_ext_serve_test <esdm-es-ext-serve> <test plugin> <bad version>
 *			    <rated plugin>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "es_ext_test_client.h"
#include "es_ext_test_plugin.h"
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
	char uid[16];
	char *const argv[] = { (char *)serve, "--plugin",	(char *)plugin,
			       "--socket",    test_socket,	"--mode",
			       "0640",	      "--client_uid", uid,
			       NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t bits = 0;
	int32_t status = -1;
	struct stat sb;
	pid_t pid;
	ssize_t n;
	int fd;

	/* The test's own user is served */
	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
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

/*
 * Without --client_uid, root and nobody are served - the ESDM as it runs by
 * default - and nobody else.
 */
static void test_default_clients(const char *serve, const char *plugin)
{
	char *const argv[] = { (char *)serve, "--plugin", (char *)plugin,
			       "--socket", test_socket, NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN], rsp[64];
	struct passwd *pw = getpwnam("nobody");
	pid_t pid;
	int fd;

	if (!getuid() || (pw && pw->pw_uid == getuid())) {
		printf("running as root or nobody - skipping the client check\n");
		return;
	}

	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;
	CHECK(test_wait_socket(), "the provider did not create its socket");

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   16);
		(void)send(fd, req, sizeof(req), MSG_NOSIGNAL);
		CHECK(recv(fd, rsp, sizeof(rsp), 0) <= 0,
		      "a client of another user was served by default");
		close(fd);
	}

	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
}

/* With --no_dtls, a STARTDTLS is refused and the client goes on in the clear */
static void test_no_dtls(const char *serve, const char *plugin)
{
	char uid[16];
	char *const argv[] = { (char *)serve, "--plugin",  (char *)plugin,
			       "--socket",    test_socket, "--client_uid",
			       uid,	      "--no_dtls", NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t bits = 0;
	int32_t status = 0;
	pid_t pid;
	ssize_t n;
	int fd;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;
	CHECK(test_wait_socket(), "the provider did not create its socket");

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STARTDTLS, 0);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		if (n > 0)
			CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
					 rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					 &status, &bits, &data),
				 0);
		CHECK_EQ(status, -EOPNOTSUPP);
		close(fd);
	}

	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
}

/*
 * INFO, byte for byte, in the clear and inside the DTLS session: the name of
 * the plugin without its NUL - or the one of --name - and the rate its
 * entropy_rate callback declares - or the one of --entropy_rate - or none, no
 * entropy. A request that breaks the protocol closes the connection.
 */
static void test_info(const char *serve, const char *plugin,
		      const char *rated)
{
	static const struct {
		const char *plugin_of;
		const char *name_opt;
		const char *rate_opt;
		const char *name;
		uint32_t rate;
	} rounds[] = {
		/* The name of the plugin, no rate */
		{ "test", NULL, NULL, ES_EXT_TEST_NAME,
		  ESDM_ES_EXT_PROTO_RATE_NONE },
		/* Both of the options */
		{ "test", "Quelle \xc3\xa4", "100", "Quelle \xc3\xa4", 100 },
		/* A plugin of version 3 declaring both */
		{ "rated", NULL, NULL, ES_EXT_TEST_RATED_NAME,
		  ES_EXT_TEST_RATED_RATE },
		/* The options take precedence */
		{ "rated", "anders", "0", "anders", 0 },
	};
	static const char *const bad_names[] = {
		"", "0123456789abcdef0123456789abcdef0", "tab\there",
		"\xff", "esc\x1b[0m",
	};
	static const char *const bad_rates[] = { "257", "-1", "12x", "", "auto" };
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	struct es_ext_test_client c;
	char uid[16];
	const char *argv[16], *name;
	size_t namelen;
	uint32_t rate;
	int32_t status = -1;
	unsigned int i, n_args, dtls;
	pid_t pid;
	ssize_t n;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());

	for (i = 0; i < sizeof(rounds) / sizeof(rounds[0]); i++) {
		n_args = 0;
		argv[n_args++] = serve;
		argv[n_args++] = "--plugin";
		argv[n_args++] = strcmp(rounds[i].plugin_of, "rated") ? plugin :
									rated;
		argv[n_args++] = "--socket";
		argv[n_args++] = test_socket;
		argv[n_args++] = "--client_uid";
		argv[n_args++] = uid;
		if (rounds[i].name_opt) {
			argv[n_args++] = "--name";
			argv[n_args++] = rounds[i].name_opt;
		}
		if (rounds[i].rate_opt) {
			argv[n_args++] = "--entropy_rate";
			argv[n_args++] = rounds[i].rate_opt;
		}
		argv[n_args] = NULL;

		pid = test_spawn((char *const *)argv);
		CHECK(pid > 0, "cannot start %s", serve);
		if (pid <= 0)
			return;
		CHECK(test_wait_socket(), "the provider did not create its socket");

		/* In the clear, then inside the DTLS session where there is one */
		for (dtls = 0; dtls < 2; dtls++) {
			int ret = es_ext_test_client_open(&c, test_socket,
							  dtls);

#ifndef ESDM_DTLS
			if (dtls) {
				CHECK_EQ(ret, -EOPNOTSUPP);
				continue;
			}
#endif
			CHECK_EQ(ret, 0);
			if (ret)
				continue;

			n = es_ext_test_client_request(&c,
						       ESDM_ES_EXT_PROTO_INFO,
						       0, rsp, sizeof(rsp));
			CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 4 +
					    (ssize_t)strlen(rounds[i].name));
			/* The header: magic, version, type, status, no bits */
			CHECK(n >= ESDM_ES_EXT_PROTO_RSP_LEN + 4 &&
				      !memcmp(rsp, "ESEX\x01\x00\x05\x00", 8) &&
				      !memcmp(rsp + 8, "\0\0\0\0\0\0\0\0", 8),
			      "the header of the answer is not INFO's");
			/* The rate, little endian */
			CHECK(n >= ESDM_ES_EXT_PROTO_RSP_LEN + 4 &&
				      esdm_es_ext_get_le32(
					      rsp + ESDM_ES_EXT_PROTO_RSP_LEN) ==
					      rounds[i].rate,
			      "round %u: the provider declares another rate", i);
			CHECK_EQ(esdm_es_ext_proto_info_unpack(
					 rsp, n > 0 ? (size_t)n : 0, &status,
					 &rate, &name, &namelen),
				 0);
			CHECK_EQ(status, 0);
			CHECK_EQ(rate, rounds[i].rate);
			CHECK_EQ(namelen, strlen(rounds[i].name));
			CHECK(name && !memcmp(name, rounds[i].name, namelen) &&
				      !memchr(name, '\0', namelen),
			      "round %u: the provider declares another name", i);

			/* An INFO with a length breaks the protocol: closed */
			n = es_ext_test_client_request(&c,
						       ESDM_ES_EXT_PROTO_INFO,
						       1, rsp, sizeof(rsp));
			CHECK(n <= 0, "an INFO of length 1 is answered");
			es_ext_test_client_close(&c);

			/* A type unknown to it closes the connection as well */
			CHECK_EQ(es_ext_test_client_open(&c, test_socket,
							 dtls),
				 0);
			n = es_ext_test_client_request(
				&c, ESDM_ES_EXT_PROTO_INFO + 1, 0, rsp,
				sizeof(rsp));
			CHECK(n <= 0, "an unknown type is answered");
			es_ext_test_client_close(&c);
		}

		CHECK_EQ(kill(pid, SIGTERM), 0);
		CHECK_EQ(test_wait(pid), 0);
	}

	/* A --name or an --entropy_rate that is none: refused at start up */
	argv[7] = "--name";
	argv[9] = NULL;
	for (i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
		struct stat sb;

		argv[8] = bad_names[i];
		CHECK_EQ(test_run((char *const *)argv), 1);
		CHECK(lstat(test_socket, &sb) < 0,
		      "a refused --name %u left a socket behind", i);
	}
	argv[7] = "--entropy_rate";
	for (i = 0; i < sizeof(bad_rates) / sizeof(bad_rates[0]); i++) {
		struct stat sb;

		argv[8] = bad_rates[i];
		CHECK_EQ(test_run((char *const *)argv), 1);
		CHECK(lstat(test_socket, &sb) < 0,
		      "a refused --entropy_rate %u left a socket behind", i);
	}
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
	char *const bad_uid[] = { (char *)serve,  "--plugin", (char *)plugin,
				  "--socket",	  test_socket, "--client_uid",
				  "no-such-user-esdm-test", NULL };
	struct stat sb;

	CHECK_EQ(test_run(no_args), 1);
	CHECK_EQ(test_run(no_socket), 1);
	CHECK_EQ(test_run(bad_plugin), 1);
	CHECK_EQ(test_run(missing), 1);
	CHECK_EQ(test_run(bad_mode), 1);
	CHECK_EQ(test_run(bad_uid), 1);
	CHECK(lstat(test_socket, &sb) < 0,
	      "a refused start left a socket behind");
	CHECK_EQ(test_run(version), 0);
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		printf("usage: %s <esdm-es-ext-serve> <test plugin> <bad version> <rated plugin>\n",
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
	test_default_clients(argv[1], argv[2]);
	test_no_dtls(argv[1], argv[2]);
	test_info(argv[1], argv[2], argv[4]);

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_serve");
}
