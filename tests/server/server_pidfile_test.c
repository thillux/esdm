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
 * An instance that removes the file while another one starts must not leave
 * the latter with a lock on a file at no path: a third one would create the
 * file anew and run alongside it. A preloaded lockf() removes the file before
 * the server takes the lock, and the server has to open the path again.
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
#define TEST_WATCHDOG_SEC 210

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

/* How often the start of the server is looked at, per second */
#define TEST_SERVER_POLL_HZ 200

/*
 * Start the server with the PID file, wait until the daemon dropped its
 * privileges - the point from which it cannot remove the file any more - and
 * terminate it again.
 *
 * With @suspend, the process the PID file names is sent SIGUSR1, as
 * esdm-server-signal-helper --suspend does, from the moment the file names it
 * until the daemon dropped its privileges. That covers the start-up up to the
 * installation of the suspend handler, which the daemon has to survive.
 */
static int server_run(bool pid_namespace, bool suspend, char **envp)
{
	const char *server = getenv("ESDM_SERVER");
	struct timespec wait = { .tv_sec = 0,
				 .tv_nsec = 1000000000L / TEST_SERVER_POLL_HZ };
	pid_t server_pid, daemon_pid = 0;
	unsigned int i, signalled = 0;
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

	for (i = 0; i < TEST_SERVER_START_SEC * TEST_SERVER_POLL_HZ; i++) {
		if (waitpid(server_pid, &status, WNOHANG) == server_pid) {
			printf("The esdm-server terminated during its start%s\n",
			       WIFSIGNALED(status) &&
					       WTERMSIG(status) == SIGUSR1 ?
				       ", killed by SIGUSR1" :
				       "");
			return 1;
		}

		if (suspend && pidfile_pid() == (long)server_pid &&
		    !kill(server_pid, SIGUSR1))
			signalled++;

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

	if (suspend)
		CHECK(signalled > 0,
		      "the PID file did not name the server before it dropped its privileges");

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
	/* Those of server_envp, the preload and the sanitizer options */
	char *unlink_envp[TEST_ENV_MAX_VARS + 3];
	char preload_var[FILENAME_MAX + 16], asan_var[4096];
	const char *server = getenv("ESDM_SERVER");
	const char *preload = getenv("ESDM_PIDFILE_UNLINK_PRELOAD");
	unsigned int i, j;
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

	if (test_env_check_file(preload)) {
		printf("ESDM_PIDFILE_UNLINK_PRELOAD does not point at the preload library\n");
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
	 * The preload is built without the sanitizers and comes ahead of their
	 * runtime, which ASan refuses unless told otherwise - in the options
	 * the test passes on to the daemon, if any, as only the first of two
	 * variables of a name counts.
	 */
	snprintf(asan_var, sizeof(asan_var), "ASAN_OPTIONS=%s",
		 "verify_asan_link_order=0");
	for (i = 0, j = 0; server_envp[i]; i++) {
		if (!strncmp(server_envp[i], "ASAN_OPTIONS=", 13)) {
			snprintf(asan_var, sizeof(asan_var),
				 "%s:verify_asan_link_order=0", server_envp[i]);
			continue;
		}
		unlink_envp[j++] = server_envp[i];
	}
	snprintf(preload_var, sizeof(preload_var), "LD_PRELOAD=%s", preload);
	unlink_envp[j++] = preload_var;
	unlink_envp[j++] = asan_var;
	unlink_envp[j] = NULL;

	/*
	 * Without a privileged process left, the file stays. Emptied, it names
	 * no process any more.
	 */
	printf("PID file: plain daemon\n");
	if (!server_run(false, false, server_envp)) {
		pid = pidfile_pid();
		CHECK(pid <= 0,
		      "the terminated daemon left its PID file naming %ld",
		      pid);
	} else {
		ret = 1;
	}
	unlink(pidpath);

	/*
	 * The file removed between its open and its lock: the server locks
	 * and writes the file at the path, not the one it opened first -
	 * server_run() checks that the file names it.
	 */
	printf("PID file: removed while the daemon opens it\n");
	if (!server_run(false, false, unlink_envp)) {
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
	if (!server_run(true, false, server_envp)) {
		CHECK(stat(pidpath, &sb) < 0 && errno == ENOENT,
		      "the supervisor left its PID file behind (naming %ld)",
		      pidfile_pid());
	} else {
		ret = 1;
	}
	unlink(pidpath);

	/*
	 * The PID file is there before the suspend handler: a suspend signalled
	 * in between must not terminate the server.
	 */
	printf("PID file: SIGUSR1 while the daemon starts\n");
	if (server_run(false, true, server_envp))
		ret = 1;
	unlink(pidpath);

	printf("PID file: SIGUSR1 while the supervised daemon starts\n");
	if (server_run(true, true, server_envp))
		ret = 1;
	unlink(pidpath);

	rmdir(tmpdir);

	printf("PID file: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
