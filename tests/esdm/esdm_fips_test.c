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
 * Tests for fips_enabled() in esdm/fips.c - the single decision that puts the
 * whole ESDM into FIPS mode.
 *
 * Two things decide it: the ESDM_SERVER_FORCE_FIPS environment variable and the
 * kernel's /proc/sys/crypto/fips_enabled. The answer is latched for the process
 * lifetime so nothing can flip the mode underneath a running daemon, which is
 * also why every case below needs a process of its own. The environment is only
 * honoured when it cannot have been planted by a less privileged caller
 * (secure_getenv(), or an explicit privilege check where it does not exist);
 * these tests run unprivileged, where both variants let the variable count.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"
#include "fips.h"
#include "fips_integrity.h"

/* Set in the re-executed child that is meant to run the self test */
#define POST_ENV "ESDM_TEST_RUN_FIPS_POST"

/*
 * fips.c runs a power-on self test from a constructor when the build is
 * configured for FIPS. That happens before main(), so whether it runs can only
 * be decided by the environment this process was started with: the tests of the
 * runtime decision below want it out of the way, while the self test itself is
 * covered by re-executing this binary with POST_ENV set.
 */
int esdm_config_fips_enabled(void);
int esdm_config_fips_enabled(void)
{
	return getenv(POST_ENV) ? 1 : 0;
}

/*
 * The flag file as fips.c sees it. fopen() is interposed for the whole
 * process - fips.c is compiled into it - so a child can make the file fail to
 * open with a given errno, or read from another file in its place. Every other
 * open goes to the C library.
 */
#define FIPS_FLAG_FILE "/proc/sys/crypto/fips_enabled"
static int test_flag_errno;
static const char *test_flag_file;

FILE *fopen(const char *path, const char *mode)
{
	static FILE *(*libc_fopen)(const char *, const char *);

	if (!libc_fopen) {
		/* ISO C knows no conversion of dlsym()'s answer */
		void *sym = dlsym(RTLD_NEXT, "fopen");

		memcpy(&libc_fopen, &sym, sizeof(libc_fopen));
	}
	if (!libc_fopen) {
		errno = ENOSYS;
		return NULL;
	}

	if (path && !strcmp(path, FIPS_FLAG_FILE)) {
		if (test_flag_errno) {
			errno = test_flag_errno;
			return NULL;
		}
		if (test_flag_file)
			path = test_flag_file;
	}

	return libc_fopen(path, mode);
}

/* What the kernel says, independently of what fips.c makes of it. */
static int kernel_fips_flag(void)
{
	FILE *f = fopen("/proc/sys/crypto/fips_enabled", "r");
	char c = 0;

	if (!f)
		return -1; /* not exposed by this kernel */

	if (fread(&c, 1, 1, f) != 1)
		c = 0;
	fclose(f);

	return c == '1';
}

static void run_child(void (*fn)(void), const char *name)
{
	pid_t pid = fork();
	int status;

	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	if (!pid) {
		common_test_failures = 0;
		fn();
		/* exit(), not _exit(): an instrumented build has to flush */
		exit(common_test_failures > 200 ?
			     200 :
			     (int)common_test_failures);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() for %s failed: %s", name, strerror(errno));
		return;
	}

	if (!WIFEXITED(status)) {
		CHECK(0, "%s died abnormally (status %d)", name, status);
		return;
	}

	if (WEXITSTATUS(status))
		common_test_failures += (unsigned int)WEXITSTATUS(status);
}

static void child_forced(void)
{
	setenv("ESDM_SERVER_FORCE_FIPS", "1", 1);

	CHECK(fips_enabled(), "the forced FIPS mode was not honoured");

	/* and it stays on for every later query */
	CHECK(fips_enabled(), "the forced FIPS mode was not latched");
}

static void child_forced_empty(void)
{
	/*
	 * The variable is a flag, not a value: its mere presence forces the
	 * mode, so an empty setting counts as well.
	 */
	setenv("ESDM_SERVER_FORCE_FIPS", "", 1);

	CHECK(fips_enabled(), "an empty force setting was not honoured");
}

static void child_kernel(void)
{
	int kernel = kernel_fips_flag();

	unsetenv("ESDM_SERVER_FORCE_FIPS");

	if (kernel < 0) {
		/* A kernel without the knob means the mode stays off */
		CHECK(!fips_enabled(),
		      "FIPS mode is on although the kernel does not expose it");
		return;
	}

	CHECK(fips_enabled() == (kernel == 1),
	      "FIPS mode is %s while the kernel reports %d",
	      fips_enabled() ? "on" : "off", kernel);
}

static void child_latched_after_set(void)
{
	unsetenv("ESDM_SERVER_FORCE_FIPS");

	/* Take the decision once ... */
	bool first = fips_enabled();

	/* ... then try to change it from the environment afterwards */
	setenv("ESDM_SERVER_FORCE_FIPS", "1", 1);

	CHECK(fips_enabled() == first,
	      "the FIPS mode changed after it had already been decided");
}

/* A kernel without FIPS support has no flag file: no FIPS mode */
static void child_flag_absent(void)
{
	unsetenv("ESDM_SERVER_FORCE_FIPS");
	test_flag_errno = ENOENT;

	CHECK(!fips_enabled(), "FIPS mode is on without a flag file");
}

/*
 * A flag file that is there but cannot be opened leaves the mode open, and the
 * ESDM must not run outside FIPS mode on a kernel that may be in it. The answer
 * is the one kept, too: a later call that could read the flag must not change
 * the mode the ESDM was set up in.
 */
static void child_flag_unreadable(void)
{
	unsetenv("ESDM_SERVER_FORCE_FIPS");
	test_flag_errno = EACCES;

	CHECK(fips_enabled(), "an unreadable FIPS flag was taken for no FIPS");

	test_flag_errno = 0;
	test_flag_file = "/dev/null";
	CHECK(fips_enabled(),
	      "the FIPS mode changed once the flag was readable");
}

/* The same for a flag file that opens but yields nothing */
static void child_flag_empty(void)
{
	unsetenv("ESDM_SERVER_FORCE_FIPS");
	test_flag_file = "/dev/null";

	CHECK(fips_enabled(), "an empty FIPS flag was taken for no FIPS");
}

static void child_latched_after_unset(void)
{
	setenv("ESDM_SERVER_FORCE_FIPS", "1", 1);
	CHECK(fips_enabled(), "the forced FIPS mode was not honoured");

	/* Removing the variable does not turn the mode off again */
	unsetenv("ESDM_SERVER_FORCE_FIPS");
	CHECK(fips_enabled(),
	      "the FIPS mode was turned off by removing the environment");
}

/*
 * Run the power-on self test by starting this binary again with the
 * configuration probe answering "FIPS". Its constructor then performs the
 * HMAC known answer test and the integrity test of the running binary before
 * main() is reached, and exits with the errno of whatever failed - so the exit
 * status of the child is the verdict. Returns that status, or -1 if the child
 * could not be run at all.
 */
static int run_post_child(const char *self)
{
	pid_t pid = fork();
	int status;

	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return -1;
	}

	if (!pid) {
		setenv(POST_ENV, "1", 1);
		execl(self, self, (char *)NULL);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() for the self test failed: %s",
		      strerror(errno));
		return -1;
	}

	CHECK(WIFEXITED(status), "the self test died abnormally (status %d)",
	      status);

	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void test_post(void)
{
	char self[4096], hmacfile[4200];
	const char *slash;
	ssize_t len;
	int ret;

	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len <= 0) {
		CHECK(0, "cannot read /proc/self/exe: %s", strerror(errno));
		return;
	}
	self[len] = '\0';

	/* Where the integrity test looks for the reference value */
	slash = strrchr(self, '/');
	if (slash)
		snprintf(hmacfile, sizeof(hmacfile), "%.*s.%s.hmac",
			 (int)(slash - self + 1), self, slash + 1);
	else
		snprintf(hmacfile, sizeof(hmacfile), ".%s.hmac", self);
	unlink(hmacfile);

	/* A binary that was never attested does not start. */
	ret = run_post_child(self);
	if (ret < 0)
		return;
	CHECK(ret == ENOENT,
	      "an unattested binary passed the self test (exit %d)", ret);

	/*
	 * With the reference value in place - written the way an installation
	 * writes it - the self test passes. Creating it needs a writable
	 * directory, which the build tree is but an installed tree need not be,
	 * so a failure to write it skips the rest.
	 */
	if (fips_create_checkfile(hmacfile, self))
		return;

	ret = run_post_child(self);
	if (ret >= 0)
		CHECK(ret == 0, "the power-on self test failed with %d", ret);

	unlink(hmacfile);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/*
	 * The re-executed self test child has done its work in the constructor
	 * by the time it gets here - it must not run the test suite again.
	 */
	if (getenv(POST_ENV))
		return 0;

	run_child(child_forced, "forced by the environment");
	run_child(child_forced_empty, "forced by an empty setting");
	run_child(child_kernel, "decided by the kernel");
	run_child(child_latched_after_set, "latched against a later set");
	run_child(child_latched_after_unset, "latched against a later unset");
	run_child(child_flag_absent, "no flag file");
	run_child(child_flag_unreadable, "an unreadable flag file");
	run_child(child_flag_empty, "an empty flag file");

	test_post();

	return common_test_result("esdm_fips");
}
