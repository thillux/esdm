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
#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "privileges.h"
#include "visibility.h"

/* Does LeakSanitizer check this process for leaks when it exits? */
#if defined(__SANITIZE_ADDRESS__)
#define PRIV_LEAK_CHECK_AT_EXIT
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(leak_sanitizer)
#define PRIV_LEAK_CHECK_AT_EXIT
#endif
#endif

int drop_privileges_permanent(const char *user, const char *group)
{
	const struct group *grp;
	const struct passwd *pwd;

	uid_t uid;
	gid_t gid;
	int ret = 0, dumpable;

	if (!user)
		return -EINVAL;

	if (group != NULL) {
		grp = getgrnam(group);
		if (!grp) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Group %s unknown\n", group);
			return -ENOENT;
		}
	} else {
		grp = NULL;
	}

	pwd = getpwnam(user);
	if (pwd == NULL) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY, "User %s unknown\n",
			    user);
		return -ENOENT;
	}

	uid = pwd->pw_uid;
	gid = pwd->pw_gid;

	/*
	 * Changing the UID or GID below makes the kernel reset the dumpable
	 * attribute of the process to fs.suid_dumpable - which systemd sets to
	 * 2 - and with it undoes a PR_SET_DUMPABLE 0 the caller applied, e.g.
	 * the server for --memlock. Remember it to restore it afterwards.
	 */
	dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);

	if (grp) {
		if (setgroups(1, &grp->gr_gid) == -1) {
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Cannot set supplemental groups: %s\n",
				    strerror(errno));
			return ret;
		}
	} else {
		/* Drop all supplemental groups */
		if (setgroups(0, NULL) == -1) {
			ret = -errno;
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "Cannot clear supplemental groups: %s\n",
				    strerror(errno));
			return ret;
		}
	}

	/* Drop privileged group */
	if (setgid(gid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged group: %s\n",
			    strerror(errno));
		return ret;
	}

	/* Drop privileged user */
	if (setuid(uid) == -1) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot drop to unprivileged user: %s\n",
			    strerror(errno));
		return ret;
	}

	if (dumpable == 0 && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot keep core dumps disabled: %s\n",
			    strerror(errno));
		return ret;
	}

#ifdef PRIV_LEAK_CHECK_AT_EXIT
	/*
	 * The leak check at exit stops all threads by ptrace()ing them from a
	 * helper task running with the credentials of the process. That only
	 * works while the process is dumpable for its user (1): the sanitizer
	 * runtime turns a non-dumpable process (0) dumpable for the check, but
	 * leaves 2 alone - which is what the drop above leaves behind with
	 * fs.suid_dumpable = 2. The attach then fails, the runtime reports a
	 * "fatal error" instead of leaks and, as meson's ASAN_OPTIONS ask
	 * for, aborts the server on its way out. Turn 2 into 0 so the check
	 * runs; only sanitizer builds do this.
	 */
	if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 2)
		prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif

	if ((chdir("/")) < 0) {
		ret = -errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Cannot change directory: %s\n", strerror(errno));
		return ret;
	}

	esdm_logger(
		LOGGER_VERBOSE, LOGGER_C_ANY,
		"Successfully dropped privileges to user %s (UID %u, GID %u)\n",
		user, uid, gid);

	return 0;
}
