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
 * esdm-server --pid_namespace when its supervisor is killed.
 *
 * The supervisor forwards the signals it is sent and removes the IPC objects
 * once the daemon ended, but SIGKILL ends it without a word. The daemon must
 * not serve on behind a supervisor that is gone: nothing would forward a
 * signal to it, and a service manager that saw its main process die would
 * start a second server next to it. It has the kernel send it SIGTERM at the
 * death of its parent - a setting the kernel clears when the daemon drops its
 * privileges, which is why the test kills the supervisor only after the drop:
 * before it, the daemon ended at all times.
 *
 * Skipped (77) unless run as root, which starting the server needs.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "esdm_rpc_service.h"

#include "../test_env.h"
#include "../test_namespace.h"
#include "../test_orphan.h"
#include "../test_wait.h"

/* The socket the server is up with */
#ifdef ESDM_SERVER_RPC
#define TEST_SERVER_SOCKET ESDM_RPC_UNPRIV_SOCKET
#else
#define TEST_SERVER_SOCKET ESDM_EGD_DEFAULT_SOCKET
#endif

/* Below the timeout of the harness, so that a hang is this test's failure */
#define TEST_WATCHDOG_SEC 100

/* How long the daemon is given to shut down */
#define TEST_END_TIMEOUT_MS 30000

/* The real user ID of @pid, -1 if it cannot be read */
static long uid_of(pid_t pid)
{
	char path[64], line[128];
	long uid = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	f = fopen(path, "re");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "Uid: %ld", &uid) == 1)
			break;
	}
	fclose(f);

	return uid;
}

/* The drop comes after the sockets: wait for it on its own */
static int wait_for_drop(pid_t pid)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 5 * 1000L * 1000L };
	unsigned int waited;

	for (waited = 0; waited < TEST_WAIT_TIMEOUT_MS; waited += 5) {
		if (uid_of(pid) > 0)
			return 1;
		nanosleep(&pause, NULL);
	}

	return 0;
}

static void test_supervisor_killed(const char *server)
{
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	pid_t supervisor, daemon;
	int status = 0, ended;

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	supervisor = fork();
	if (supervisor < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}
	if (!supervisor) {
		char buf[FILENAME_MAX];
		char *argv[] = { buf, (char *)"-f", (char *)"--pid_namespace",
				 NULL };

		snprintf(buf, sizeof(buf), "%s", server);
		execve(server, argv, server_envp);
		_exit(127);
	}

	daemon = test_orphan_wait_child_of(supervisor, TEST_WAIT_TIMEOUT_MS);
	CHECK(daemon > 0, "the supervisor did not fork the daemon");
	if (daemon <= 0 ||
	    !test_wait_for_type(TEST_SERVER_SOCKET, S_IFSOCK,
				TEST_WAIT_TIMEOUT_MS) ||
	    !wait_for_drop(daemon)) {
		CHECK(0, "the esdm-server did not come up");
		kill(supervisor, SIGTERM);
		waitpid(supervisor, NULL, 0);
		return;
	}

	kill(supervisor, SIGKILL);
	CHECK_EQ(waitpid(supervisor, &status, 0), supervisor);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "the supervisor did not die by SIGKILL (status %#x)", status);

	/* Ours now, see test_orphan_adopt() */
	ended = test_orphan_reap(daemon, &status, TEST_END_TIMEOUT_MS);
	CHECK(ended == 1, "the daemon serves on without its supervisor (%d)",
	      ended);
	if (ended == 1) {
		/* The shutdown of a server that was sent SIGTERM */
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		      "the daemon did not shut down cleanly (status %#x)",
		      status);
	} else if (ended == 0) {
		kill(daemon, SIGKILL);
		waitpid(daemon, NULL, 0);
	}
}

int main(int argc, char *argv[])
{
	struct stat sb;
	int ret;

	if (argc < 2 || stat(argv[1], &sb) || !S_ISREG(sb.st_mode)) {
		printf("usage: %s <path to esdm-server>\n", argv[0]);
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	/*
	 * The server claims the fixed socket, semaphore and IPC names, and
	 * what its supervisor would have removed stays behind here. Run in
	 * namespaces of our own - see tests/test_namespace.h.
	 */
	setenv("ESDM_SERVER", argv[1], 1);
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	if (test_orphan_adopt()) {
		printf("Cannot become a subreaper: %s\n", strerror(errno));
		return 1;
	}

	test_supervisor_killed(argv[1]);

	return common_test_result("server_supervisor");
}
