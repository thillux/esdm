/*
 * Environment of a daemon a test forks
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

#ifndef TEST_ENV_H
#define TEST_ENV_H

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

extern char **environ;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The daemons are exec'd with an environment built here rather than with the
 * test's own, which would hand them things meant for the test alone - the
 * getrandom tests LD_PRELOAD the interposition library, and a server loading it
 * too would interpose the very calls it is meant to answer.
 *
 * A few variables have to survive that isolation nonetheless: they configure
 * libraries the daemon loads, not the test. SOFTHSM2_CONF is one - a daemon
 * loading SoftHSM logs three errors per load when it finds no configuration.
 * The ESDM daemons no longer do since the PKCS#11 entropy source became
 * esdm-es-pkcs11, which its tests start with an environment of their own, but
 * a setup pointing the ESDM at a provider loading it still may.
 *
 * The options of the sanitizers are the other ones: without them, a daemon of
 * a sanitized build runs with the defaults - UBSan reports and goes on, ASan
 * exits with 1 -, and a finding in it fails no test. With the options of the
 * test, as meson and the CI set them, it aborts on its first finding, or exits
 * with 66 for TSan, which test_env_reap_daemon() below fails the test on, as
 * it does a crash.
 */
static const char *const test_env_pass[] = {
	"SOFTHSM2_CONF=", "ASAN_OPTIONS=", "UBSAN_OPTIONS=", "TSAN_OPTIONS=",
	"LSAN_OPTIONS=",  "MSAN_OPTIONS=",
};

/* Slots a caller has to provide, terminator excluded */
#define TEST_ENV_MAX_VARS (sizeof(test_env_pass) / sizeof(test_env_pass[0]))

/*
 * Fill @envp with the passed-through variables, NULL terminated. @nmemb counts
 * the terminator, so TEST_ENV_MAX_VARS + 1 always suffices. Call before the
 * fork - it is not async-signal-safe, and the strings it hands out are the ones
 * of the caller's own environment.
 */
static inline void test_env_daemon_envp(char **envp, size_t nmemb)
{
	size_t used = 0, i, j;

	for (i = 0; environ && environ[i] && used + 1 < nmemb; i++) {
		for (j = 0; j < TEST_ENV_MAX_VARS; j++) {
			if (!strncmp(environ[i], test_env_pass[j],
				     strlen(test_env_pass[j]))) {
				envp[used++] = environ[i];
				break;
			}
		}
	}

	envp[used] = NULL;
}

/*
 * Check that @path - a daemon or library the test was handed through its own
 * environment - names a regular file before the test forks anything around it.
 * Returns 0 or a positive errno value.
 */
static inline int test_env_check_file(const char *path)
{
	struct stat sb;
	int ret;

	if (!path) {
		printf("No file provided\n");
		return ENOENT;
	}

	if (stat(path, &sb)) {
		ret = errno;
		printf("File %s not found: %s\n", path, strerror(ret));
		return ret;
	}

	if (!S_ISREG(sb.st_mode)) {
		printf("File %s not regular file\n", path);
		return EPERM;
	}

	return 0;
}

/* The exit code of a process TSan found something in, its exitcode option */
#define TEST_ENV_SANITIZER_EXIT 66

/*
 * Wait for the daemon @pid the test started, and tell whether a sanitizer
 * found something in it - an abort, as ASan and UBSan do with abort_on_error,
 * or the exit code of TSan -, or whether it crashed. @name says which daemon
 * in the message.
 *
 * Returns 0, or 1 if the daemon ended so; the caller fails the test then.
 */
static inline int test_env_reap_daemon(pid_t pid, const char *name)
{
	int status;

	if (pid <= 0 || waitpid(pid, &status, 0) != pid)
		return 0;

	if (WIFSIGNALED(status) &&
	    (WTERMSIG(status) == SIGABRT || WTERMSIG(status) == SIGSEGV ||
	     WTERMSIG(status) == SIGBUS || WTERMSIG(status) == SIGILL ||
	     WTERMSIG(status) == SIGFPE)) {
		printf("FAIL: %s (PID %d) was killed by signal %d - %s\n",
		       name, (int)pid, WTERMSIG(status),
		       WTERMSIG(status) == SIGABRT ?
			       "a sanitizer finding?" :
			       "it crashed");
		return 1;
	}
	if (WIFEXITED(status) &&
	    WEXITSTATUS(status) == TEST_ENV_SANITIZER_EXIT) {
		printf("FAIL: %s (PID %d) exited with %d - a sanitizer finding?\n",
		       name, (int)pid, TEST_ENV_SANITIZER_EXIT);
		return 1;
	}

	return 0;
}

/*
 * test_env_reap_daemon() for a helper that cannot hand a failure back: the
 * test ends at once with a failure - exit(3), so that what the test wrote,
 * its coverage counters included, is kept.
 */
static inline void test_env_reap_daemon_or_fail(pid_t pid, const char *name)
{
	if (test_env_reap_daemon(pid, name)) {
		fflush(stdout);
		exit(1);
	}
}

#ifdef __cplusplus
}
#endif

#endif /* TEST_ENV_H */
