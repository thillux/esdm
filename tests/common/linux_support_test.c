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
 * Tests for the part of common/linux_support.c that does not need privileges:
 * the personalization string the server derives from the DMI product UUID, and
 * the PID namespace supervisor, inside a user namespace where one can be had.
 *
 * Whether that file can be read depends on the machine - it is root only and a
 * VM may expose it empty - so the test asserts the contract rather than a
 * value. The caller tells "got a string" from "did not" by the return code
 * alone, so a failure leaving *ptr NULL while reporting success feeds a NULL
 * personalization string into the DRNG. An empty product_uuid used to do just
 * that: fgets() returns NULL at end of file without setting errno.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"
#include "linux_support.h"

static void check_personalization_string(const char *what)
{
	char *ptr = NULL;
	size_t length = 0;
	int ret = linux_personalization_string(&ptr, &length);

	if (ret) {
		/*
		 * On failure nothing is handed out - neither a pointer the
		 * caller would have to free nor a length it might trust.
		 */
		CHECK(ret < 0, "%s: failed with a positive return code %d",
		      what, ret);
		CHECK(ptr == NULL, "%s: failed but still returned a string",
		      what);
		CHECK(length == 0, "%s: failed but reported a length of %zu",
		      what, length);
		return;
	}

	CHECK(ptr != NULL, "%s: reported success without a string", what);
	if (!ptr)
		return;

	CHECK(length == strlen(ptr),
	      "%s: reported a length of %zu for a string of %zu characters",
	      what, length, strlen(ptr));
	CHECK(length > 0, "%s: reported success with an empty string", what);

	/* The trailing newline of the sysfs file is not part of the string */
	CHECK(strchr(ptr, '\n') == NULL,
	      "%s: the string still carries a newline", what);

	free(ptr);
}

#define PREFORK_EXIT_CODE 42

static volatile sig_atomic_t prefork_signalled;
static int prefork_pipe[2];

static void prefork_sig(int sig)
{
	(void)sig;
	prefork_signalled = 1;
}

static void prefork_supervisor_exit(void)
{
	if (write(prefork_pipe[1], "c", 1) != 1)
		_exit(2);
}

/*
 * Becomes the supervisor, whose daemon exits once a signal of the caller's set
 * reached it. Inherits an ignored SIGCHLD, which made the kernel reap the
 * daemon in place of the supervisor.
 */
static void prefork_process(void)
{
	static const int fwd_signals[] = { SIGUSR2 };
	struct sigaction sa;
	unsigned int i;

	if (unshare(CLONE_NEWUSER) == -1)
		_exit(77);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = prefork_sig;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGUSR2, &sa, NULL);
	signal(SIGCHLD, SIG_IGN);

	if (linux_isolate_namespace_prefork(fwd_signals, 1,
					    prefork_supervisor_exit))
		_exit(77);

	/* Daemon */
	if (write(prefork_pipe[1], "r", 1) != 1)
		_exit(3);
	for (i = 0; i < 100 && !prefork_signalled; i++)
		usleep(50000);
	_exit(prefork_signalled ? PREFORK_EXIT_CODE : 4);
}

static void check_prefork(void)
{
	char c = 0;
	int status = 0;
	pid_t pid;

	if (pipe(prefork_pipe)) {
		CHECK(0, "pipe: %s", strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork: %s", strerror(errno));
		return;
	}
	if (pid == 0)
		prefork_process();

	close(prefork_pipe[1]);

	/*
	 * The daemon is up, the supervisor may still be installing its
	 * forwarders - the signal has to reach the daemon either way.
	 */
	if (read(prefork_pipe[0], &c, 1) == 1) {
		CHECK_EQ(c, 'r');
		CHECK_EQ(kill(pid, SIGUSR2), 0);
		CHECK_EQ(read(prefork_pipe[0], &c, 1), 1);
		CHECK(c == 'c', "the supervisor skipped its exit callback");
	}
	close(prefork_pipe[0]);

	CHECK_EQ(waitpid(pid, &status, 0), pid);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
		printf("PID namespace supervisor: no user namespace, skipped\n");
		return;
	}
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == PREFORK_EXIT_CODE,
	      "the supervisor did not mirror the daemon's exit, status %#x",
	      status);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	check_prefork();

	check_personalization_string("first call");

	/*
	 * Nothing about it is cached, so a second caller - the server asks once
	 * per DRNG instance - has to get the same answer rather than a stale or
	 * half-released one.
	 */
	check_personalization_string("second call");

	return common_test_result("linux_support");
}
