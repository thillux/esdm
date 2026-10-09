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

#ifndef PRIVILEGES_H
#define PRIVILEGES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Clear all supplemental groups
 *
 * Must be called once during start-up while the effective UID is still 0,
 * before privileges are dropped transiently for the first time.
 */
int drop_supplemental_groups(void);

/**
 * @brief Transiently dropping privileges
 */
int drop_privileges_transient(const char *user);

/**
 * @brief Transiently raise privilege to a different set of IDs
 */
int raise_privilege_transient(uid_t uid, gid_t gid);

/**
 * @brief Whether the caller of a FUSE request holds CAP_SYS_ADMIN
 *
 * The kernel checks capable(CAP_SYS_ADMIN) for the privileged random ioctls,
 * irrespective of the caller's UID. A FUSE request carries the PID and the file
 * system UID of the caller, so its effective capabilities are looked up via
 * /proc. The UID has to match as well, which guards against the PID naming
 * another process by then - the caller is blocked in its request until it is
 * answered, unless it is killed.
 *
 * @param [in] pid PID of the caller as given by the FUSE request
 * @param [in] fsuid file system UID of the caller as given by the FUSE request
 *
 * @return 1 if the caller holds CAP_SYS_ADMIN in our user namespace, 0 if not
 *	   or if that cannot be determined
 */
int caller_has_cap_sys_admin(pid_t pid, uid_t fsuid);

/**
 * @brief caller_has_cap_sys_admin(), telling an unreadable caller apart
 *
 * With /proc mounted with hidepid=, the /proc entries of every process but our
 * own cannot be opened by the unprivileged user, which says nothing about the
 * caller.
 *
 * @param [in] pid PID of the caller as given by the FUSE request
 * @param [in] fsuid file system UID of the caller as given by the FUSE request
 *
 * @return 1 if the caller holds CAP_SYS_ADMIN in our user namespace, 0 if not,
 *	   -EACCES if its /proc entries cannot be opened
 */
int caller_cap_sys_admin(pid_t pid, uid_t fsuid);

/**
 * @brief caller_cap_sys_admin() with the /proc access of root
 *
 * The calling thread opens the caller's /proc entries with the file system IDs
 * of root and its permitted capabilities raised to effective - the access a
 * transient raise to root has, but for this thread only. Both are put back
 * before returning, so nothing may change the credentials of the process
 * meanwhile.
 *
 * @param [in] pid PID of the caller as given by the FUSE request
 * @param [in] fsuid file system UID of the caller as given by the FUSE request
 *
 * @return 1 if the caller holds CAP_SYS_ADMIN in our user namespace, 0 if not
 *	   or if that cannot be determined, -ENOTRECOVERABLE if the credentials
 *	   of the thread could not be put back
 */
int caller_cap_sys_admin_fsroot(pid_t pid, uid_t fsuid);

/**
 * @brief The parser of caller_has_cap_sys_admin for /proc/<pid>/status
 *
 * @param [in] status NUL-terminated content of /proc/<pid>/status
 * @param [in] fsuid file system UID the status has to report
 *
 * @return 1 if the status reports CAP_SYS_ADMIN as effective, 0 if not
 */
int caller_status_cap_sys_admin(const char *status, uid_t fsuid);

#ifdef __cplusplus
}
#endif

#endif /* PRIVILEGES_H */
