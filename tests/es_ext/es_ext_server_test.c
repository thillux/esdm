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
 * The external entropy sources of the esdm-server, as configured on its
 * command line.
 *
 * - --es_ext_lib loads the plugin library while the daemon has its
 *   privileges, and the plugin delivers once they are dropped.
 * - --es_ext_socket connects to a provider served by esdm-es-ext-serve. Once
 *   the provider was restarted, the daemon - its privileges dropped by then -
 *   connects to it again on demand.
 *
 * Skipped (77) unless run as root, as the esdm-server refuses to start
 * otherwise. The daemon claims the fixed socket, semaphore and IPC names, so
 * the test puts itself in namespaces of its own.
 *
 * Usage: es_ext_server_test <esdm-server> <esdm-es-ext-serve> <test plugin>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test_env.h"
#include "../test_namespace.h"
#include "common_test.h"
#include "esdm_rpc_client.h"

/* How long the daemon and the provider are given to come up */
#define TEST_START_SEC 30

static char test_dir[] = "/tmp/esdm-es-ext-server-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];
static char *test_envp[TEST_ENV_MAX_VARS + 1];

static void test_sleep_ms(long ms)
{
	const struct timespec ts = { .tv_sec = ms / 1000,
				     .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static pid_t test_spawn(char *const argv[])
{
	pid_t pid;

	if (posix_spawn(&pid, argv[0], NULL, NULL, argv, test_envp))
		return -1;
	return pid;
}

static void test_terminate(pid_t pid)
{
	if (pid <= 0)
		return;
	kill(pid, SIGTERM);
	waitpid(pid, NULL, 0);
}

/* The status of the daemon, once it answers */
static bool test_status(char *buf, size_t buflen)
{
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 10; i++) {
		memset(buf, 0, buflen);
		if (!esdm_rpcc_status(buf, buflen))
			return true;
		test_sleep_ms(100);
	}

	return false;
}

/* The section of the status about the entropy source @name */
static const char *test_es_section(const char *status, const char *name)
{
	char needle[64];

	snprintf(needle, sizeof(needle), " Name: %s", name);
	return strstr(status, needle);
}

static bool test_wait_socket(void)
{
	struct stat sb;
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 50; i++) {
		if (lstat(test_socket, &sb) == 0 && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(20);
	}

	return false;
}

static void test_plugin(const char *server, const char *plugin)
{
	char *const argv[] = { (char *)server, "-f", "--es_ext_lib",
			       (char *)plugin, NULL };
	static char status[65536];
	const char *es;
	uint8_t seed[512];
	pid_t pid;

	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		return;

	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, "ExternalLib");
	CHECK(es != NULL, "the status lists no ExternalLib source");
	if (es) {
		CHECK(strstr(es, "Plugin: es-ext-test") != NULL,
		      "the plugin was not loaded (%.400s)", es);
		CHECK(strstr(es, "Status: delivering") != NULL,
		      "the plugin does not deliver (%.400s)", es);
	}

	/* Asked for its data with the privileges of the daemon dropped */
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the plugin loaded");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, "ExternalLib");
	CHECK(es && strstr(es, "Status: delivering") != NULL,
	      "the plugin does not deliver after the privilege drop (%.400s)",
	      es ? es : "");

	test_terminate(pid);
}

static void test_socket_provider(const char *server, const char *serve,
				 const char *plugin)
{
	char *const serve_argv[] = { (char *)serve, "--plugin",	 (char *)plugin,
				     "--socket",    test_socket, NULL };
	char *const server_argv[] = { (char *)server, "-f", "--es_ext_socket",
				      test_socket, NULL };
	static char status[65536];
	const char *es;
	uint8_t seed[512];
	pid_t provider, pid;

	provider = test_spawn(serve_argv);
	CHECK(provider > 0, "cannot start %s", serve);
	CHECK(test_wait_socket(), "the provider did not create its socket");

	pid = test_spawn(server_argv);
	CHECK(pid > 0, "cannot start %s", server);
	if (pid <= 0)
		goto out;

	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, "ExternalSocket");
	CHECK(es && strstr(es, "Status: connected (uid 0)") != NULL,
	      "the provider was not connected to (%.400s)", es ? es : "");

	/* The provider goes, and comes back */
	test_terminate(provider);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider gone");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, "ExternalSocket");
	CHECK(es && strstr(es, "Status: not connected") != NULL,
	      "a provider gone is still connected (%.400s)", es ? es : "");

	provider = test_spawn(serve_argv);
	CHECK(provider > 0, "cannot restart %s", serve);
	CHECK(test_wait_socket(), "the provider did not create its socket");

	/*
	 * After the retry interval of the source, a seeding connects again -
	 * from the daemon with its privileges dropped.
	 */
	test_sleep_ms(6000);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the provider back");
	CHECK(test_status(status, sizeof(status)),
	      "the server does not answer");
	es = test_es_section(status, "ExternalSocket");
	CHECK(es && strstr(es, "Status: connected (uid 0)") != NULL,
	      "the provider back was not connected to again (%.400s)",
	      es ? es : "");

	test_terminate(pid);

out:
	test_terminate(provider);
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 4) {
		printf("usage: %s <esdm-server> <esdm-es-ext-serve> <test plugin>\n",
		       argv[0]);
		return 1;
	}

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	/* Traversable for the daemon once it dropped its privileges */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("Cannot create the directory: %s\n", strerror(errno));
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	test_env_daemon_envp(test_envp, TEST_ENV_MAX_VARS + 1);

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot set up the RPC client\n");
		return 1;
	}

	test_plugin(argv[1], argv[3]);
	test_socket_provider(argv[1], argv[2], argv[3]);

	esdm_rpcc_fini_unpriv_service();
	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_server");
}
