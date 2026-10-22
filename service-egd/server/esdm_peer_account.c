/*
 * The user a peer of the server sockets is accounted to
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/nsfs.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<sys/pidfd.h>)
/* PIDFD_GET_USER_NAMESPACE, without the clash of <linux/pidfd.h> */
#include <sys/pidfd.h>
#endif
#endif

#include "esdm_logger.h"
#include "esdm_peer_account.h"

/* The subordinate UID ranges, see esdm_peer_account_subuid() */
#ifndef ESDM_PEER_ACCOUNT_SUBUID
#define ESDM_PEER_ACCOUNT_SUBUID "/etc/subuid"
#endif

/* How often a change of the subordinate UID ranges is looked for */
#define ESDM_PEER_ACCOUNT_SUBUID_RECHECK_SEC 1

/*
 * The kernel nests user namespaces 32 deep at most - a chain longer than that
 * is not one the walk below finishes.
 */
#define ESDM_PEER_ACCOUNT_MAX_DEPTH 33

/****************************
 * The user namespace of the peer
 ****************************/

/* The user namespace of the server, see esdm_peer_account_userns() */
static struct {
	bool known;
	dev_t dev;
	ino_t ino;
} esdm_peer_account_self;

static pthread_once_t esdm_peer_account_once = PTHREAD_ONCE_INIT;

/* Is a process still there, the one @pidfd refers to? */
static bool esdm_peer_account_alive(int pidfd)
{
#ifdef SYS_pidfd_send_signal
	/*
	 * Signal 0 checks for the process only. Whether it may be signaled
	 * does not matter - EPERM is the answer of one that is there.
	 */
	return syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == 0 ||
	       errno == EPERM;
#else
	(void)pidfd;
	return false;
#endif
}

/*
 * Open the user namespace of the peer of @fd, without letting the peer pass
 * off the namespace of another process as its own.
 *
 * SO_PEERPIDFD (Linux 6.5) refers to the process that connected, whatever
 * became of its PID since, and PIDFD_GET_USER_NAMESPACE (Linux 6.11) asks that
 * very process. Without the latter, the namespace is opened through /proc and
 * its PID, and the pidfd confirms afterwards that the process is still alive:
 * a PID is only handed out again once its process is gone, so /proc showed that
 * process. Without SO_PEERPIDFD, the pidfd comes from the PID SO_PEERCRED
 * tells, before /proc is consulted: what remains is a peer that exited before
 * then and whose PID was handed out again, which the peer cannot time to a
 * process of its liking. A peer that is gone when SO_PEERPIDFD is asked is
 * not looked up by its PID at all.
 *
 * The kernel only hands out the user namespace of a process the caller may
 * ptrace(2) - which, once the daemon dropped its privileges, is none of
 * another user. The caller falls back to the subordinate UID ranges then.
 *
 * @return the namespace file descriptor, < 0 when it cannot be had
 */
static int esdm_peer_account_open_userns(int fd, const struct ucred *cred)
{
	int pidfd = -1, ns = -1;
	char path[64];

#ifdef SO_PEERPIDFD
	socklen_t len = sizeof(pidfd);

	if (getsockopt(fd, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &len) < 0) {
		pidfd = -1;
		/* Only a kernel without it may be asked by the PID instead. */
		if (errno != ENOPROTOOPT)
			return -1;
	}
#else
	(void)fd;
#endif

#if defined(SO_PEERPIDFD) && defined(PIDFD_GET_USER_NAMESPACE)
	if (pidfd >= 0) {
		ns = ioctl(pidfd, PIDFD_GET_USER_NAMESPACE, 0);
		/* A kernel that cannot be asked this way - try /proc. */
		if (ns >= 0 || (errno != ENOTTY && errno != EINVAL))
			goto out;
	}
#endif

	if (cred->pid <= 0)
		goto out;

#ifdef SYS_pidfd_open
	if (pidfd < 0)
		pidfd = (int)syscall(SYS_pidfd_open, cred->pid, 0);
#endif
	if (pidfd < 0)
		goto out;

	snprintf(path, sizeof(path), "/proc/%d/ns/user", (int)cred->pid);
	ns = open(path, O_RDONLY | O_CLOEXEC);
	if (ns >= 0 && !esdm_peer_account_alive(pidfd)) {
		close(ns);
		ns = -1;
	}

out:
	if (pidfd >= 0)
		close(pidfd);
	return ns;
}

/* Is @ns the user namespace of the server? */
static bool esdm_peer_account_is_self(int ns, bool *self)
{
	struct stat st;

	if (fstat(ns, &st) < 0)
		return false;

	*self = (st.st_dev == esdm_peer_account_self.dev &&
		 st.st_ino == esdm_peer_account_self.ino);

	return true;
}

/*
 * Account the peer by its user namespace, see esdm_peer_account.h.
 *
 * The walk goes from the peer's namespace up the chain of parents until it
 * reaches the server's, remembering the owner of each one passed that is not
 * root - the last one remembered is the outermost. NS_GET_PARENT answers EPERM
 * for a namespace whose parent is not the server's namespace or below it, so a
 * peer in a namespace above or beside the server's - the server may well run
 * in a container itself - ends the walk without an answer.
 *
 * @return true when @account was found, false when the caller has to fall back
 */
static bool esdm_peer_account_userns(int fd, const struct ucred *cred,
				     uid_t *account)
{
	unsigned int depth;
	uid_t found = 0;
	bool done = false;
	int ns;

	if (!esdm_peer_account_self.known)
		return false;

	ns = esdm_peer_account_open_userns(fd, cred);
	if (ns < 0)
		return false;

	for (depth = 0; depth < ESDM_PEER_ACCOUNT_MAX_DEPTH; depth++) {
		uid_t owner;
		bool self;
		int parent;

		if (!esdm_peer_account_is_self(ns, &self))
			break;

		if (self) {
			*account = found ? found : cred->uid;
			done = true;
			break;
		}

		/*
		 * As seen from the server. A namespace of root's is root's to
		 * share out, see esdm_peer_account.h.
		 */
		if (ioctl(ns, NS_GET_OWNER_UID, &owner) == 0 && owner != 0 &&
		    owner != (uid_t)-1)
			found = owner;

		parent = ioctl(ns, NS_GET_PARENT);
		if (parent < 0)
			break;

		close(ns);
		ns = parent;
	}

	close(ns);

	return done;
}

/****************************
 * The subordinate UID ranges
 ****************************/

struct esdm_peer_account_range {
	uid_t first;
	uid_t count;
	uid_t owner;
};

/*
 * The ranges of ESDM_PEER_ACCOUNT_SUBUID, and what identifies the file they were
 * loaded from - a change of it is picked up without a restart, as useradd(8)
 * hands out a range with every new user.
 */
static struct {
	pthread_mutex_t lock;
	struct esdm_peer_account_range *ranges;
	size_t num;
	bool loaded;
	struct stat st;
	uint64_t checked;
} esdm_peer_account_subuid_table = { .lock = PTHREAD_MUTEX_INITIALIZER };

static uint64_t esdm_peer_account_now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec;
}

/* Parse a decimal UID or count of the file, all of the string. */
static bool esdm_peer_account_number(const char *str, uid_t *val)
{
	unsigned long long v;
	char *end;

	if (*str < '0' || *str > '9')
		return false;

	errno = 0;
	v = strtoull(str, &end, 10);
	if (errno || *end || v >= (uid_t)-1)
		return false;

	*val = (uid_t)v;

	return true;
}

/* The UID of the owner field of a line - a name or a UID. */
static bool esdm_peer_account_owner(const char *name, uid_t *uid)
{
	struct passwd pwd, *result = NULL;
	char buf[4096];

	if (esdm_peer_account_number(name, uid))
		return true;

	if (getpwnam_r(name, &pwd, buf, sizeof(buf), &result) || !result)
		return false;

	*uid = result->pw_uid;

	return true;
}

/*
 * Parse one line "owner:first:count" into @range.
 *
 * A range of root's, or of an owner that does not resolve to a UID, is left
 * out: only an unprivileged user acting for itself is of interest here, and a
 * range nobody may log in as is not mapped by newuidmap(1) - root, who may map
 * any, then decided, and its UIDs are accounted by themselves.
 */
static bool esdm_peer_account_parse(char *line,
				    struct esdm_peer_account_range *range)
{
	char *first, *count, *nl;

	nl = strchr(line, '\n');
	if (nl)
		*nl = '\0';

	if (!*line || *line == '#')
		return false;

	first = strchr(line, ':');
	if (!first)
		return false;
	*first++ = '\0';
	count = strchr(first, ':');
	if (!count)
		return false;
	*count++ = '\0';

	if (!esdm_peer_account_number(first, &range->first) ||
	    !esdm_peer_account_number(count, &range->count) || !range->count ||
	    range->count > (uid_t)-1 - range->first)
		return false;

	return esdm_peer_account_owner(line, &range->owner) &&
	       range->owner != 0 && range->owner != (uid_t)-1;
}

/* Replace the table with the ranges of @path. Called with the lock held. */
static void esdm_peer_account_subuid_load(const char *path)
{
	struct esdm_peer_account_range *ranges = NULL, range;
	size_t num = 0, alloc = 0;
	char *line = NULL;
	size_t line_len = 0;
	struct stat st;
	FILE *f;

	f = fopen(path, "re");
	if (!f || fstat(fileno(f), &st) < 0) {
		if (f)
			fclose(f);
		/* No file, no ranges - and nothing to be noticed changing. */
		free(esdm_peer_account_subuid_table.ranges);
		esdm_peer_account_subuid_table.ranges = NULL;
		esdm_peer_account_subuid_table.num = 0;
		esdm_peer_account_subuid_table.loaded = false;
		return;
	}

	while (getline(&line, &line_len, f) >= 0) {
		if (!esdm_peer_account_parse(line, &range))
			continue;

		if (num == alloc) {
			size_t n = alloc ? 2 * alloc : 16;
			struct esdm_peer_account_range *tmp =
				realloc(ranges, n * sizeof(*ranges));

			/* Keep what was there rather than half of the file. */
			if (!tmp) {
				free(ranges);
				free(line);
				fclose(f);
				return;
			}
			ranges = tmp;
			alloc = n;
		}

		ranges[num++] = range;
	}

	free(line);
	fclose(f);

	free(esdm_peer_account_subuid_table.ranges);
	esdm_peer_account_subuid_table.ranges = ranges;
	esdm_peer_account_subuid_table.num = num;
	esdm_peer_account_subuid_table.st = st;
	esdm_peer_account_subuid_table.loaded = true;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
		    "Loaded %zu subordinate UID ranges from %s\n", num, path);
}

/* Has @path changed since it was loaded? Called with the lock held. */
static bool esdm_peer_account_subuid_changed(const char *path)
{
	const struct stat *old = &esdm_peer_account_subuid_table.st;
	struct stat st;

	if (stat(path, &st) < 0)
		return esdm_peer_account_subuid_table.loaded;

	return !esdm_peer_account_subuid_table.loaded ||
	       st.st_dev != old->st_dev || st.st_ino != old->st_ino ||
	       st.st_size != old->st_size ||
	       st.st_mtim.tv_sec != old->st_mtim.tv_sec ||
	       st.st_mtim.tv_nsec != old->st_mtim.tv_nsec;
}

/*
 * The owner of the subordinate UID range @uid falls into, @uid itself if none
 * does - see esdm_peer_account.h. Ranges of different users must not overlap,
 * and the first one listed wins if they do.
 */
static uid_t esdm_peer_account_subuid(uid_t uid)
{
	uint64_t now = esdm_peer_account_now_sec();
	uid_t account = uid;
	size_t i;

	pthread_mutex_lock(&esdm_peer_account_subuid_table.lock);

	if (now - esdm_peer_account_subuid_table.checked >=
	    ESDM_PEER_ACCOUNT_SUBUID_RECHECK_SEC) {
		esdm_peer_account_subuid_table.checked = now;
		if (esdm_peer_account_subuid_changed(ESDM_PEER_ACCOUNT_SUBUID))
			esdm_peer_account_subuid_load(ESDM_PEER_ACCOUNT_SUBUID);
	}

	for (i = 0; i < esdm_peer_account_subuid_table.num; i++) {
		const struct esdm_peer_account_range *range =
			&esdm_peer_account_subuid_table.ranges[i];

		if (uid >= range->first && uid - range->first < range->count) {
			account = range->owner;
			break;
		}
	}

	pthread_mutex_unlock(&esdm_peer_account_subuid_table.lock);

	return account;
}

/****************************
 * Interface
 ****************************/

static void esdm_peer_account_init_once(void)
{
	struct stat st;
	int fd = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC);

	/* Without it, no namespace can be told from the server's. */
	if (fd >= 0) {
		if (fstat(fd, &st) == 0) {
			esdm_peer_account_self.dev = st.st_dev;
			esdm_peer_account_self.ino = st.st_ino;
			esdm_peer_account_self.known = true;
		}
		close(fd);
	}

	pthread_mutex_lock(&esdm_peer_account_subuid_table.lock);
	esdm_peer_account_subuid_table.checked = esdm_peer_account_now_sec();
	esdm_peer_account_subuid_load(ESDM_PEER_ACCOUNT_SUBUID);
	pthread_mutex_unlock(&esdm_peer_account_subuid_table.lock);
}

void esdm_peer_account_init(void)
{
	pthread_once(&esdm_peer_account_once, esdm_peer_account_init_once);
}

uid_t esdm_peer_account(int fd, const struct ucred *cred)
{
	uid_t account;

	/* Root is root, whatever it runs in. */
	if (!cred->uid)
		return 0;

	esdm_peer_account_init();

	if (esdm_peer_account_userns(fd, cred, &account))
		return account;

	return esdm_peer_account_subuid(cred->uid);
}
