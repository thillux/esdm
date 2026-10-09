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

#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "privileges.h"
#include "visibility.h"

int drop_privileges_transient(const char *user)
{
	const struct passwd *pwd;
	static uid_t uid = 0;
	static gid_t gid = 0;
	static bool initialized = false;
	int ret = 0;

	if (!user)
		return -EINVAL;

	if (!initialized) {
		pwd = getpwnam(user);
		if (pwd == NULL) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "User %s unknown\n", user);
			return -ENOENT;
		}

		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
		initialized = true;
	}

	/* Drop privileged group */
	if (setegid(gid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged group: %s\n",
			    strerror(errno));
		return ret;
	}

	/* Drop privileged user */
	if (seteuid(uid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged user: %s\n",
			    strerror(errno));
		return ret;
	}

	esdm_logger(
		LOGGER_VERBOSE, LOGGER_C_ANY,
		"Successfully dropped privileges to user %s (UID %u, GID %u)\n",
		user, uid, gid);

	return ret;
}

int drop_supplemental_groups(void)
{
	/*
	 * Clear all supplemental groups. This must be called once during
	 * start-up while the effective UID is still 0: setgroups(2) requires
	 * CAP_SETGID in the *effective* capability set, which the kernel clears
	 * as soon as the effective UID transitions from 0 to a non-zero value
	 * (as happens during the transient drop to the unprivileged worker
	 * user). Doing it lazily inside the transient drop races with concurrent
	 * request handlers that may already have dropped the euid process-wide.
	 */
	if (setgroups(0, NULL) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot clear supplemental groups: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "Successfully cleared supplemental groups\n");

	return 0;
}

int raise_privilege_transient(uid_t uid, gid_t gid)
{
	/* Raise privileged group */
	if (setegid(gid) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot raise to group %u: %s\n", gid,
			    strerror(errsv));
		return -errsv;
	}

	/* Drop privileged user */
	if (seteuid(uid) == -1) {
		int errsv = errno;

		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to user %u: %s\n", uid,
			    strerror(errsv));
		return -errsv;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		    "Successfully raised privileges to UID %u, GID %u\n", uid,
		    gid);

	return 0;
}

/* Read a /proc file of at most buflen - 1 bytes into buf, NUL-terminated */
static int read_proc_file(const char *path, char *buf, size_t buflen)
{
	size_t len = 0;
	ssize_t rc;
	int fd;

	/* Room for at least one byte and the terminating NUL */
	if (buflen < 2)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	do {
		rc = read(fd, buf + len, buflen - 1 - len);
		if (rc > 0)
			len += (size_t)rc;
	} while ((rc > 0 || (rc < 0 && errno == EINTR)) && len < buflen - 1);

	close(fd);

	if (rc < 0)
		return -EIO;

	/* A file that does not fit is not one this parser understands */
	if (len >= buflen - 1)
		return -EFBIG;

	buf[len] = '\0';

	return 0;
}

int caller_status_cap_sys_admin(const char *status, uid_t fsuid)
{
	unsigned int ruid, euid, suid, fs;
	unsigned long long capeff;
	const char *p;
	char *end;

	/* The UIDs are real, effective, saved and file system UID */
	p = strstr(status, "\nUid:");
	if (!p || sscanf(p + 5, "%u %u %u %u", &ruid, &euid, &suid, &fs) != 4)
		return 0;

	/*
	 * The FUSE request carries the file system UID of the caller. A
	 * different one means the PID no longer names the caller.
	 */
	if ((uid_t)fs != fsuid)
		return 0;

	p = strstr(status, "\nCapEff:");
	if (!p)
		return 0;

	errno = 0;
	capeff = strtoull(p + 8, &end, 16);
	if (errno || end == p + 8)
		return 0;

	return !!(capeff & (1ULL << CAP_SYS_ADMIN));
}

/*
 * A /proc entry of the caller that cannot be opened says nothing about its
 * capabilities: with /proc mounted with hidepid=, that is what every process
 * but our own looks like to the unprivileged user.
 */
static int caller_proc_err(int ret)
{
	if (ret == -EACCES || ret == -EPERM || ret == -ENOENT)
		return -EACCES;

	return 0;
}

int caller_cap_sys_admin(pid_t pid, uid_t fsuid)
{
	char path[64], buf[8192], own_map[256], caller_map[256];
	int ret;

	/* A caller outside of our PID namespace is not identifiable */
	if (pid <= 0)
		return 0;

	/*
	 * Capabilities count in the user namespace they are held in, and only
	 * those in ours are the kernel's capable(CAP_SYS_ADMIN). Reading the
	 * namespace itself needs ptrace access to the caller, its UID map does
	 * not - the caller has to have the map we have.
	 */
	if (read_proc_file("/proc/self/uid_map", own_map, sizeof(own_map)))
		return 0;

	snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)pid);
	ret = read_proc_file(path, caller_map, sizeof(caller_map));
	if (ret)
		return caller_proc_err(ret);
	if (strcmp(own_map, caller_map))
		return 0;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	ret = read_proc_file(path, buf, sizeof(buf));
	if (ret)
		return caller_proc_err(ret);

	return caller_status_cap_sys_admin(buf, fsuid);
}

int caller_has_cap_sys_admin(pid_t pid, uid_t fsuid)
{
	return caller_cap_sys_admin(pid, fsuid) > 0;
}

/* Whether the calling thread has these file system IDs */
static bool thread_fsids_are(uid_t uid, gid_t gid)
{
	return (uid_t)setfsuid((uid_t)-1) == uid &&
	       (gid_t)setfsgid((gid_t)-1) == gid;
}

int caller_cap_sys_admin_fsroot(pid_t pid, uid_t fsuid)
{
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3,
						0 };
	struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3];
	struct __user_cap_data_struct raised[_LINUX_CAPABILITY_U32S_3];
	uid_t old_fsuid;
	gid_t old_fsgid;
	unsigned int i;
	int ret = 0;

	/*
	 * Opening a /proc entry is decided on the file system IDs and the
	 * effective capabilities of the opening thread. A transient raise to
	 * root sets the former to 0 and the latter to the permitted ones, so
	 * that is what this thread gets. Unlike that raise, which glibc applies
	 * to every thread of the process, setfs[ug]id() and capset() only
	 * change the calling thread.
	 */
	if (syscall(SYS_capget, &hdr, caps))
		return 0;
	memcpy(raised, caps, sizeof(raised));
	for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++)
		raised[i].effective = raised[i].permitted;

	old_fsuid = (uid_t)setfsuid((uid_t)-1);
	old_fsgid = (gid_t)setfsgid((gid_t)-1);

	setfsgid(0);
	setfsuid(0);
	if (thread_fsids_are(0, 0) && !syscall(SYS_capset, &hdr, raised))
		ret = caller_cap_sys_admin(pid, fsuid);

	/* Leaving file system UID 0 drops the capabilities it raised, too */
	setfsuid(old_fsuid);
	setfsgid(old_fsgid);
	if (syscall(SYS_capset, &hdr, caps) ||
	    !thread_fsids_are(old_fsuid, old_fsgid)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot restore the file system IDs and capabilities\n");
		return -ENOTRECOVERABLE;
	}

	return ret > 0;
}
