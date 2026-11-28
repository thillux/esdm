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

#ifndef TEST_ORPHAN_H
#define TEST_ORPHAN_H

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

/*
 * What a test needs to follow a daemon behind its PID namespace supervisor
 * once the supervisor is gone. The test knows the supervisor, which it forked;
 * the daemon is the supervisor's child, in a PID namespace of its own but
 * visible from here under a PID of ours. As a subreaper the test inherits the
 * daemon when the supervisor dies and can wait for it like for a child.
 */

/* Inherit the descendants whose parents end */
static inline int test_orphan_adopt(void)
{
	return prctl(PR_SET_CHILD_SUBREAPER, 1) ? -errno : 0;
}

/*
 * The one child of @parent, 0 while it has none. /proc/<pid>/task/<tid>/children
 * would say it at once, but is not part of every kernel configuration.
 */
static inline pid_t test_orphan_child_of(pid_t parent)
{
	DIR *proc = opendir("/proc");
	struct dirent *de;
	pid_t child = 0;

	if (!proc)
		return 0;

	while (!child && (de = readdir(proc))) {
		char path[64], buf[512], *p;
		long pid = strtol(de->d_name, &p, 10);
		int ppid = 0;
		size_t len;
		FILE *f;

		if (*p || pid <= 0)
			continue;

		snprintf(path, sizeof(path), "/proc/%ld/stat", pid);
		f = fopen(path, "re");
		if (!f)
			continue;
		len = fread(buf, 1, sizeof(buf) - 1, f);
		fclose(f);
		buf[len] = '\0';

		/* "pid (comm) state ppid": comm may hold anything, also ')' */
		p = strrchr(buf, ')');
		if (p && sscanf(p + 1, " %*c %d", &ppid) == 1 &&
		    ppid == (int)parent)
			child = (pid_t)pid;
	}

	closedir(proc);
	return child;
}

/* Poll for the child of @parent to appear, 0 if it did not in time */
static inline pid_t test_orphan_wait_child_of(pid_t parent,
					      unsigned int timeout_ms)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 5 * 1000L * 1000L };
	unsigned int waited;
	pid_t child = 0;

	for (waited = 0; !child && waited < timeout_ms; waited += 5) {
		child = test_orphan_child_of(parent);
		if (!child)
			nanosleep(&pause, NULL);
	}

	return child;
}

/*
 * Wait for @pid to end. Returns 1 with its wait status in @status, 0 if it
 * still runs after @timeout_ms, < 0 if it cannot be waited for.
 */
static inline int test_orphan_reap(pid_t pid, int *status,
				   unsigned int timeout_ms)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 5 * 1000L * 1000L };
	unsigned int waited;

	for (waited = 0;; waited += 5) {
		pid_t ret = waitpid(pid, status, WNOHANG);

		if (ret == pid)
			return 1;
		if (ret < 0 && errno != EINTR)
			return -errno;
		if (waited >= timeout_ms)
			return 0;
		nanosleep(&pause, NULL);
	}
}

#endif /* TEST_ORPHAN_H */
