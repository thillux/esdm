/*
 * Tests of the PID file of the esdm-server
 *
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
 * What the esdm-server leaves of its PID file once it terminated.
 *
 * The daemon writes the file as root and gives up its privileges afterwards,
 * so it can no longer remove the file from a directory only root writes to -
 * which /run is, and so is the directory of this test. A file left behind with
 * the PID in it names whatever process gets that PID next. So the daemon
 * empties it, and in PID namespace mode the supervisor, which kept the
 * privileges, removes it.
 *
 * The server refuses to run unprivileged, so this skips (77) when not started
 * as root.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
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

/* How long the server is given to come up, and to go down */
#define TEST_SERVER_START_SEC 30

/* Backstop below the timeout the test harness applies to the whole run */
#define TEST_WATCHDOG_SEC 150

static char tmpdir[] = "/tmp/esdm-server-pidfile-test-XXXXXX";
static char pidpath[sizeof(tmpdir) + 32];
static int ret;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

/* The effective uid of @pid, -1 if it cannot be told */
static long proc_euid(pid_t pid)
{
	char path[64], line[256];
	long euid = -1;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	f = fopen(path, "re");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		long ruid;

		if (sscanf(line, "Uid: %ld %ld", &ruid, &euid) == 2)
			break;
		euid = -1;
	}
	fclose(f);

	return euid;
}

/* The first child of @pid, 0 if there is none (yet) */
static pid_t proc_child(pid_t pid)
{
	char path[64];
	int child = 0;
	FILE *f;

	snprintf(path, sizeof(path), "/proc/%d/task/%d/children", (int)pid,
		 (int)pid);
	f = fopen(path, "re");
	if (!f)
		return 0;
	if (fscanf(f, "%d", &child) != 1)
		child = 0;
	fclose(f);

	return (pid_t)child;
}

/* The PID the file names, 0 if it is empty, -1 if it cannot be read */
static long pidfile_pid(void)
{
	char buf[32] = { 0 };
	FILE *f = fopen(pidpath, "re");
	size_t len;

	if (!f)
		return -1;
	len = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);

	return len ? strtol(buf, NULL, 10) : 0;
}

/*
 * Start the server with the PID file, wait until the daemon dropped its
 * privileges - the point from which it cannot remove the file any more - and
 * terminate it again.
 */
static int server_run(bool pid_namespace, char **envp)
{
	const char *server = getenv("ESDM_SERVER");
	struct timespec wait = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	pid_t server_pid, daemon_pid = 0;
	unsigned int i;
	int status;

	server_pid = fork();
	if (server_pid < 0)
		return 1;

	if (server_pid == 0) {
		char binary[FILENAME_MAX];
		char pid_arg[sizeof(pidpath)];
		char *argv[] = { binary,
				 (char *)"-f",
				 (char *)"--pid",
				 pid_arg,
				 pid_namespace ? (char *)"--pid_namespace" :
						 NULL,
				 NULL };

		snprintf(binary, sizeof(binary), "%s", server);
		snprintf(pid_arg, sizeof(pid_arg), "%s", pidpath);
		execve(server, argv, envp);

		/* NOTREACHED */
		_exit(1);
	}

	for (i = 0; i < TEST_SERVER_START_SEC * 5; i++) {
		if (waitpid(server_pid, NULL, WNOHANG) == server_pid) {
			printf("The esdm-server terminated during its start\n");
			return 1;
		}

		daemon_pid =
			pid_namespace ? proc_child(server_pid) : server_pid;
		if (daemon_pid > 0 && proc_euid(daemon_pid) > 0)
			break;
		daemon_pid = 0;
		nanosleep(&wait, NULL);
	}

	if (!daemon_pid) {
		printf("The esdm-server did not drop its privileges\n");
		kill(server_pid, SIGKILL);
		waitpid(server_pid, NULL, 0);
		return 1;
	}

	/* The process to signal is the one started here, in either mode */
	CHECK(pidfile_pid() == (long)server_pid,
	      "the running server's PID file names %ld, not %d", pidfile_pid(),
	      (int)server_pid);

	kill(server_pid, SIGTERM);
	alarm(TEST_SERVER_START_SEC);
	waitpid(server_pid, &status, 0);
	alarm(TEST_WATCHDOG_SEC);

	return 0;
}

int main(int argc, char *argv[])
{
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	const char *server = getenv("ESDM_SERVER");
	struct stat sb;
	long pid;

	(void)argc;
	(void)argv;

	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	if (server == NULL || stat(server, &sb) < 0 || !S_ISREG(sb.st_mode)) {
		printf("ESDM_SERVER does not point at the esdm-server binary\n");
		return 1;
	}

	/*
	 * The server claims the fixed RPC socket, semaphore and IPC names. Run
	 * in namespaces of our own so those cannot collide with another test
	 * using the same ones - see tests/test_namespace.h.
	 */
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	/* Writable for root only, as /run is */
	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(pidpath, sizeof(pidpath), "%s/esdm-server.pid", tmpdir);

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	/*
	 * Without a privileged process left, the file stays. Emptied, it names
	 * no process any more.
	 */
	printf("PID file: plain daemon\n");
	if (!server_run(false, server_envp)) {
		pid = pidfile_pid();
		CHECK(pid <= 0,
		      "the terminated daemon left its PID file naming %ld",
		      pid);
	} else {
		ret = 1;
	}
	unlink(pidpath);

	/* The supervisor kept its privileges and removes the file */
	printf("PID file: PID namespace supervisor\n");
	if (!server_run(true, server_envp)) {
		CHECK(stat(pidpath, &sb) < 0 && errno == ENOENT,
		      "the supervisor left its PID file behind (naming %ld)",
		      pidfile_pid());
	} else {
		ret = 1;
	}
	unlink(pidpath);

	rmdir(tmpdir);

	printf("PID file: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
