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
 * Tests for the PID namespace supervisor of common/linux_support.c: what
 * becomes of the daemon when the supervisor is killed with SIGKILL, which no
 * handler of the supervisor can forward.
 *
 * Each case forks a process that calls linux_isolate_namespace_prefork() and
 * so becomes the supervisor of a stand-in for the daemon: a process that does
 * with its user ID what a daemon does and then waits for SIGTERM. The test
 * kills the supervisor and, as subreaper, inherits the daemon and learns how
 * it ended. The cases follow the daemons:
 *
 * - esdm-server drops its privileges for good and arms the parent-death
 *   signal again: the daemon ends. Without arming it again it lives on - the
 *   kernel cleared the setting - which is what the code did before and what
 *   the model tests/tla/EsdmSupervisor.tla assumes of the kernel.
 * - A supervisor that is gone before the daemon arms the signal sends
 *   nothing; the daemon notices at the arming.
 * - The CUSE daemons keep changing their effective user ID and have a thread
 *   wait for the supervisor's end instead.
 *
 * Creating a PID namespace needs CAP_SYS_ADMIN, so everything but the calls
 * without a supervisor is skipped (77) unless run as root; the root of a user
 * namespace that maps the user ID dropped to will do.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "linux_support.h"

#include "../test_orphan.h"

/* nobody: any user ID but 0 that a user namespace around the test maps */
#define TEST_UNPRIV_ID 65534

/* How the stand-in for the daemon ends */
#define TEST_EXIT_TERM 42 /* SIGTERM reached its handler */
#define TEST_EXIT_ALIVE 43 /* nothing arrived until it gave up */
#define TEST_EXIT_SETUP 44 /* it could not get as far as waiting */

/* How long a daemon that is told nothing waits before it gives up */
#define TEST_DAEMON_GIVES_UP_MS 20000
/* How long the daemon is given to end */
#define TEST_END_TIMEOUT_MS 10000
/* How long a daemon is watched that is expected to live on */
#define TEST_SURVIVE_MS 300

enum test_case {
	/* permanent drop, then linux_pidns_arm_parent_death() */
	TEST_DROP_REARM,
	/* permanent drop only: the code before */
	TEST_DROP_ONLY,
	/* linux_pidns_arm_parent_death() once the supervisor is gone */
	TEST_ARM_LATE,
	/* linux_pidns_watch_supervisor() in a thread, the user ID changing */
	TEST_WATCH,
};

static volatile sig_atomic_t got_term;

static void on_term(int sig)
{
	(void)sig;
	got_term = 1;
}

static void *watch_thread(void *unused)
{
	(void)unused;
	linux_pidns_watch_supervisor();
	return NULL;
}

static int drop_for_good(void)
{
	return setresgid(TEST_UNPRIV_ID, TEST_UNPRIV_ID, TEST_UNPRIV_ID) ||
	       setresuid(TEST_UNPRIV_ID, TEST_UNPRIV_ID, TEST_UNPRIV_ID);
}

/*
 * The process the test forks: the supervisor up to the prefork, which returns
 * in the daemon only. @ready_fd tells the test that the daemon waits, @go_fd
 * the daemon that the supervisor is gone.
 */
static void supervisor_and_daemon(enum test_case tc, int ready_fd, int go_fd)
{
	static const int fwd_signals[] = { SIGTERM };
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 5 * 1000L * 1000L };
	struct sigaction sa;
	unsigned int waited;
	pthread_t tid;
	char c = 'r';

	/* Before the prefork: a namespace init needs the handler to get it */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_term;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);

	if (linux_isolate_namespace_prefork(fwd_signals, 1, NULL))
		_exit(TEST_EXIT_SETUP);

	switch (tc) {
	case TEST_DROP_REARM:
		if (drop_for_good())
			_exit(TEST_EXIT_SETUP);
		linux_pidns_arm_parent_death();
		break;
	case TEST_DROP_ONLY:
		if (drop_for_good())
			_exit(TEST_EXIT_SETUP);
		break;
	case TEST_ARM_LATE:
		/* Nothing armed while the supervisor dies */
		if (drop_for_good())
			_exit(TEST_EXIT_SETUP);
		if (write(ready_fd, &c, 1) != 1 || read(go_fd, &c, 1) != 1)
			_exit(TEST_EXIT_SETUP);
		linux_pidns_arm_parent_death();
		break;
	case TEST_WATCH:
		if (pthread_create(&tid, NULL, watch_thread, NULL))
			_exit(TEST_EXIT_SETUP);
		/* As a CUSE daemon: drop, a privileged ioctl, drop again */
		if (seteuid(TEST_UNPRIV_ID) || seteuid(0) ||
		    seteuid(TEST_UNPRIV_ID))
			_exit(TEST_EXIT_SETUP);
		break;
	}

	if (tc != TEST_ARM_LATE && write(ready_fd, &c, 1) != 1)
		_exit(TEST_EXIT_SETUP);

	for (waited = 0; !got_term && waited < TEST_DAEMON_GIVES_UP_MS;
	     waited += 5)
		nanosleep(&pause, NULL);

	_exit(got_term ? TEST_EXIT_TERM : TEST_EXIT_ALIVE);
}

/* Wait for the byte the daemon writes once it is set up */
static int daemon_ready(int ready_fd)
{
	struct pollfd pfd = { .fd = ready_fd, .events = POLLIN };
	char c;

	return poll(&pfd, 1, TEST_END_TIMEOUT_MS) == 1 &&
	       read(ready_fd, &c, 1) == 1;
}

static void kill_supervisor_of(enum test_case tc, const char *what)
{
	int ready[2], go[2], status = 0, ended;
	pid_t supervisor, daemon;
	char c = 'g';

	if (pipe(ready) || pipe(go)) {
		CHECK(0, "%s: pipe() failed: %s", what, strerror(errno));
		return;
	}

	supervisor = fork();
	if (supervisor < 0) {
		CHECK(0, "%s: fork() failed: %s", what, strerror(errno));
		return;
	}
	if (!supervisor) {
		close(ready[0]);
		close(go[1]);
		supervisor_and_daemon(tc, ready[1], go[0]);
	}
	close(ready[1]);
	close(go[0]);

	if (!daemon_ready(ready[0])) {
		CHECK(0, "%s: the daemon did not get ready", what);
		kill(supervisor, SIGTERM);
		waitpid(supervisor, NULL, 0);
		goto out;
	}

	daemon = test_orphan_child_of(supervisor);
	CHECK(daemon > 0, "%s: the supervisor has no child", what);

	kill(supervisor, SIGKILL);
	CHECK_EQ(waitpid(supervisor, &status, 0), supervisor);
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "%s: the supervisor did not die by SIGKILL (status %#x)", what,
	      status);
	if (daemon <= 0)
		goto out;

	if (tc == TEST_ARM_LATE)
		CHECK_EQ(write(go[1], &c, 1), 1);

	if (tc == TEST_DROP_ONLY) {
		/*
		 * The kernel cleared the parent-death signal with the change
		 * of the user ID: nobody tells this daemon.
		 */
		ended = test_orphan_reap(daemon, &status, TEST_SURVIVE_MS);
		CHECK(ended == 0,
		      "%s: the daemon ended although nothing was armed (%d, status %#x)",
		      what, ended, status);
		if (ended == 0) {
			kill(daemon, SIGKILL);
			waitpid(daemon, NULL, 0);
		}
		goto out;
	}

	ended = test_orphan_reap(daemon, &status, TEST_END_TIMEOUT_MS);
	CHECK(ended == 1, "%s: the daemon outlives its supervisor (%d)", what,
	      ended);
	if (ended == 1) {
		CHECK(WIFEXITED(status) &&
			      WEXITSTATUS(status) == TEST_EXIT_TERM,
		      "%s: the daemon did not end by its SIGTERM handler (status %#x)",
		      what, status);
	} else if (ended == 0) {
		kill(daemon, SIGKILL);
		waitpid(daemon, NULL, 0);
	}

out:
	close(ready[0]);
	close(go[1]);
}

/* A daemon started without --pid_namespace: both calls leave it alone */
static void test_no_supervisor(void)
{
	int sig = -1;

	linux_pidns_arm_parent_death();
	CHECK_EQ(prctl(PR_GET_PDEATHSIG, &sig), 0);
	CHECK_EQ(sig, 0);

	CHECK_EQ(linux_pidns_watch_supervisor(), -ENOENT);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	alarm(120);

	test_no_supervisor();

	if (geteuid()) {
		printf("The PID namespace needs root: skipped\n");
		return common_test_failures ? 1 : 77;
	}

	if (test_orphan_adopt()) {
		printf("Cannot become a subreaper: %s\n", strerror(errno));
		return 1;
	}

	kill_supervisor_of(TEST_DROP_REARM, "armed again after the drop");
	kill_supervisor_of(TEST_DROP_ONLY, "not armed again");
	kill_supervisor_of(TEST_ARM_LATE, "armed after the supervisor ended");
	kill_supervisor_of(TEST_WATCH, "watched by a thread");

	return common_test_result("linux_pidns");
}
