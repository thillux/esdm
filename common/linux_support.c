/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "linux_support.h"
#include "memset_secure.h"

/*
 * PID of the namespace init child the supervisor waits for. Written before
 * the forwarding signal handlers are installed and cleared, with them
 * blocked, before the child is reaped.
 */
static volatile pid_t linux_pidns_child;

/*
 * The daemon's end of the lifeline, a pipe only the supervisor holds the write
 * end of: it reports a hang-up once the supervisor ended, whatever ended it.
 * Other than the parent-death signal it is no setting the kernel clears, and
 * it can be asked at any time. -1 in a process without supervisor.
 */
static int linux_pidns_lifeline = -1;

static void linux_pidns_forward_signal(int sig)
{
	pid_t child = linux_pidns_child;

	if (child > 0)
		kill(child, sig);
}

/*
 * The signals a handler can catch that end a process by default and are not
 * among linux_term_signals(). Sent to the supervisor, one would end it and
 * leave the daemon unsupervised, so the supervisor forwards them as well. The
 * daemon, as namespace init, drops a signal it has no handler for.
 */
static const int linux_pidns_sent_signals[] = {
	SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGTRAP,
#ifdef SIGEMT
	SIGEMT,
#endif
};
#define LINUX_PIDNS_SENT_SIGNALS                                              \
	(sizeof(linux_pidns_sent_signals) / sizeof(linux_pidns_sent_signals[0]))

static void linux_pidns_forward_sent(int sig, siginfo_t *info, void *ucontext)
{
	(void)ucontext;

	/*
	 * Raised by the kernel for a fault of the supervisor itself: take the
	 * default action once the handler returned.
	 */
	if (info->si_code > 0) {
		signal(sig, SIG_DFL);
		raise(sig);
		return;
	}

	linux_pidns_forward_signal(sig);
}

/* Nothing is ever written to the lifeline: an event on it is the hang-up */
static bool linux_pidns_supervisor_ended(int timeout)
{
	struct pollfd pfd = { .fd = linux_pidns_lifeline, .events = POLLIN };
	int ret;

	do {
		ret = poll(&pfd, 1, timeout);
	} while (ret < 0 && errno == EINTR);

	return ret > 0;
}

void linux_pidns_arm_parent_death(void)
{
	if (linux_pidns_lifeline < 0)
		return;

	if (prctl(PR_SET_PDEATHSIG, SIGTERM) == -1)
		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Cannot set parent-death signal: %s\n",
			    strerror(errno));

	/*
	 * The kernel sends the signal at the death of the supervisor only: for
	 * one that ended before the prctl() nothing arrives. getppid() cannot
	 * tell, it is 0 for a parent outside the PID namespace all along.
	 */
	if (linux_pidns_supervisor_ended(0))
		kill(getpid(), SIGTERM);
}

int linux_pidns_watch_supervisor(void)
{
	if (linux_pidns_lifeline < 0)
		return -ENOENT;

	while (!linux_pidns_supervisor_ended(-1))
		;

	kill(getpid(), SIGTERM);
	return 0;
}

unsigned int linux_term_signals(int *sigs)
{
	static const int term_signals[] = {
		SIGHUP,	   SIGINT,    SIGQUIT, SIGTERM, SIGALRM,
		SIGIO,	   SIGPOLL,   SIGPROF, SIGPWR,	SIGUSR1,
		SIGUSR2,   SIGVTALRM, SIGXCPU, SIGXFSZ,
#ifdef SIGSTKFLT
		SIGSTKFLT,
#endif
	};
	unsigned int i, n = 0;
	int sig;

	for (i = 0; i < sizeof(term_signals) / sizeof(term_signals[0]); i++)
		sigs[n++] = term_signals[i];

	/* No constants: the C library keeps the lowest for itself */
	for (sig = SIGRTMIN; sig <= SIGRTMAX && n < LINUX_TERM_SIGNALS_MAX;
	     sig++)
		sigs[n++] = sig;

	return n;
}

int linux_isolate_namespace_prefork(const int *fwd_signals,
				    unsigned int nr_fwd_signals,
				    void (*supervisor_exit_cb)(void))
{
	struct sigaction sa, sa_chld;
	sigset_t fwd_set, old_mask;
	siginfo_t info;
	unsigned int i;
	pid_t pid;
	int errsv, status, nsfd, lifeline[2];

	sigemptyset(&fwd_set);
	for (i = 0; i < nr_fwd_signals; i++)
		sigaddset(&fwd_set, fwd_signals[i]);
	for (i = 0; i < LINUX_PIDNS_SENT_SIGNALS; i++)
		sigaddset(&fwd_set, linux_pidns_sent_signals[i]);

	/*
	 * Unshare the PID namespace before the first fork and before any
	 * thread exists: the kernel rejects unshare(CLONE_NEWPID) in a
	 * multi-threaded process and rejects thread creation in a process
	 * whose PID namespace for children differs from its own. Hence this
	 * must run before thread_init() and only the child below may create
	 * threads afterwards.
	 */
	if (unshare(CLONE_NEWPID) == -1) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot create PID namespace: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "Successfully entered isolating PID namespace\n");

	/* See linux_pidns_lifeline */
	if (pipe2(lifeline, O_CLOEXEC) == -1) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot create the supervisor lifeline: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	/*
	 * Block the forwarded signals until the supervisor's forwarders are
	 * installed. In between, one would run the caller's handler in the
	 * supervisor, or kill it, instead of reaching the daemon.
	 */
	sigprocmask(SIG_BLOCK, &fwd_set, &old_mask);

	/*
	 * An inherited SIG_IGN of SIGCHLD makes the kernel reap the daemon
	 * itself, and the supervisor could neither wait for it nor mirror its
	 * exit status or clean up after it.
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGCHLD, &sa, &sa_chld);

	pid = fork();
	if (pid < 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot fork into PID namespace: %s\n",
			    strerror(errsv));
		sigaction(SIGCHLD, &sa_chld, NULL);
		sigprocmask(SIG_SETMASK, &old_mask, NULL);
		close(lifeline[0]);
		close(lifeline[1]);
		return -errsv;
	}

	if (pid == 0) {
		sigaction(SIGCHLD, &sa_chld, NULL);
		sigprocmask(SIG_SETMASK, &old_mask, NULL);

		/*
		 * Child: PID 1 of the new namespace, continues as the actual
		 * daemon. Tie its lifetime to the supervisor so a SIGKILLed
		 * supervisor does not leak an unreachable daemon. The kernel
		 * clears the parent-death signal in every thread when the
		 * daemon changes its user or group ID: the caller arms it
		 * again after that, or watches the lifeline.
		 */
		close(lifeline[1]);
		linux_pidns_lifeline = lifeline[0];
		linux_pidns_arm_parent_death();
		return 0;
	}

	/*
	 * Parent: act as supervisor only and never return to the caller.
	 * External parties (systemd via PIDFile=, esdm-server-signal-helper,
	 * test harnesses) address the daemon by this PID, so relay the
	 * daemon control signals to the namespace init and mirror its exit
	 * status. A signal is only delivered to a PID namespace init from an
	 * ancestor namespace if the init installed a handler for it.
	 */
	linux_pidns_child = pid;

	/*
	 * The write end stays open, unused, for as long as the supervisor
	 * lives: the kernel closes it at its end, which the daemon is told.
	 */
	close(lifeline[0]);

	/* Name must fit the 15 character kernel limit on thread names */
	pthread_setname_np(pthread_self(), "ESDM supervisor");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = linux_pidns_forward_signal;
	sa.sa_mask = fwd_set;
	/* SA_RESTART: resume the waitid() below after forwarding */
	sa.sa_flags = SA_RESTART;
	for (i = 0; i < nr_fwd_signals; i++)
		sigaction(fwd_signals[i], &sa, NULL);

	sa.sa_sigaction = linux_pidns_forward_sent;
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	for (i = 0; i < LINUX_PIDNS_SENT_SIGNALS; i++)
		sigaction(linux_pidns_sent_signals[i], &sa, NULL);

	/* Forward what arrived since the signals were blocked */
	sigprocmask(SIG_UNBLOCK, &fwd_set, NULL);

	/*
	 * Wait without reaping: the daemon stays a zombie, so its PID cannot
	 * be handed out again while a forwarded signal may still target it.
	 * Stop forwarding before reaping it.
	 */
	while (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOWAIT) < 0) {
		if (errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot wait for PID namespace init: %s\n",
				    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	sigprocmask(SIG_BLOCK, &fwd_set, NULL);
	linux_pidns_child = 0;
	while (waitpid(pid, &status, 0) < 0) {
		if (errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
				    "Cannot reap PID namespace init: %s\n",
				    strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * A child of the supervisor would be placed in the namespace of the
	 * daemon, which ended with it: the kernel refuses every fork from now
	 * on with ENOMEM - also one made at the exit, as LeakSanitizer forks
	 * to check for leaks, which then fails the supervisor. Its children
	 * go into its own namespace again. Best effort, nothing else forks.
	 */
	nsfd = open("/proc/self/ns/pid", O_RDONLY | O_CLOEXEC);
	if (nsfd >= 0) {
		(void)setns(nsfd, CLONE_NEWPID);
		close(nsfd);
	}

	/*
	 * The daemon is gone - let the caller perform teardown work that
	 * needs the supervisor's retained privileges (e.g. removing
	 * root-owned IPC resources after the daemon dropped privileges).
	 */
	if (supervisor_exit_cb)
		supervisor_exit_cb();

	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);

		/*
		 * Die by the same signal so the wait status observed by our
		 * own parent (e.g. systemd Restart=on-failure) matches the
		 * daemon's fate.
		 */
		signal(sig, SIG_DFL);
		sigemptyset(&fwd_set);
		sigaddset(&fwd_set, sig);
		sigprocmask(SIG_UNBLOCK, &fwd_set, NULL);
		raise(sig);
		/* Reached only if the signal did not terminate us */
		exit(128 + sig);
	}

	exit(WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE);
}

static int linux_unshare(int flags)
{
	/*
	 * Unshare from the following namespaces - the ESDM process cannot
	 * re-establish connection to those resources. Hence, the ESDM process
	 * is effectively jailed with respect to those resources.
	 */
	if (unshare(flags) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Cannot enter namespaces: %s\n", strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "Successfully entered isolating namespaces\n");

	return 0;
}

int linux_isolate_namespace(void)
{
	/* The ESDM server only needs shared IPC and Semaphores. */
	return linux_unshare(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWNET);
}

int linux_isolate_namespace_keep_mounts(void)
{
	return linux_unshare(CLONE_NEWCGROUP | CLONE_NEWNET);
}

/* Whether @path reads the same as @ref, which a shorter read cannot */
static int linux_same_content(const char *path, const char *ref)
{
	FILE *a = fopen(path, "re"), *b;
	int ret = 1, ca, cb;

	if (!a)
		return -errno;
	b = fopen(ref, "re");
	if (!b) {
		ret = -errno;
		fclose(a);
		return ret;
	}

	do {
		ca = fgetc(a);
		cb = fgetc(b);
		if (ca != cb) {
			ret = 0;
			break;
		}
	} while (ca != EOF);

	if (ferror(a) || ferror(b))
		ret = -EIO;

	fclose(a);
	fclose(b);
	return ret;
}

int linux_task_has_cap_sys_admin(pid_t pid)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = pid,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
	char path[64];
	int ret;

	if (pid <= 0)
		return -EINVAL;

	/*
	 * capget(2), not CapEff of /proc/<pid>/status: like capable(), it
	 * honors LSM denials, e.g. AppArmor's on Ubuntu user namespaces.
	 */
	if (syscall(SYS_capget, &hdr, data))
		return -errno;
	if (!(data[CAP_TO_INDEX(CAP_SYS_ADMIN)].effective &
	      CAP_TO_MASK(CAP_SYS_ADMIN)))
		return 0;

	/*
	 * Capabilities count only in the task's user namespace, which anybody
	 * may create. A task in another user namespace sees another uid_map,
	 * unless one privileged over all our uids created it.
	 */
	snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)pid);
	ret = linux_same_content(path, "/proc/self/uid_map");

	return ret;
}

int linux_personalization_string(char **ptr, size_t *length)
{
	FILE *f = fopen("/sys/class/dmi/id/product_uuid", "r");
	char buf[128] = { 0 };
	int ret;

	assert(*ptr == NULL);
	assert(*length == 0);

	if (!f) {
		int errsv = errno;

		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Unable to open product_uuid file: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out;
	}

	if (!fgets(buf, sizeof(buf), f)) {
		/*
		 * fgets() returns NULL without setting errno at EOF (empty
		 * product_uuid, e.g. restricted DMI in a VM or container).
		 * Map that to ENODATA: returning -errno would yield 0
		 * (success with *ptr == NULL, violating the contract) or a
		 * stale error code.
		 */
		int errsv = ferror(f) && errno ? errno : ENODATA;

		esdm_logger(LOGGER_WARN, LOGGER_C_SERVER,
			    "Unable to read product_uuid file: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out_close;
	}

	/* Remove trailing newline */
	for (char *p = buf; *p; p++) {
		if (*p == '\n')
			*p = '\0';
	}

	*length = strnlen(buf, 128 - 1);
	*ptr = strndup(buf, *length);
	if (!*ptr) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_SERVER,
			    "Unable to duplicate string: %s\n",
			    strerror(errsv));
		ret = -errsv;
		goto out_close;
	}

	ret = 0;

out_close:
	fclose(f);
out:
	memset_secure(buf, 0, sizeof(buf));
	return ret;
}
