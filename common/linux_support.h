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

#ifndef LINUX_SUPPORT_H
#define LINUX_SUPPORT_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Leave the mount, cgroup and network namespaces of the host.
 *
 * unshare(2) moves the calling thread only: call before creating threads.
 */
int linux_isolate_namespace(void);
/**
 * @brief As linux_isolate_namespace, but keeping the host's mount namespace.
 *
 * For a daemon that publishes mounts to the host, as the CUSE frontends do.
 */
int linux_isolate_namespace_keep_mounts(void);
/**
 * @brief Whether a task holds CAP_SYS_ADMIN in our user namespace.
 *
 * @param [in] pid Thread or process ID in the PID namespace of our /proc.
 *
 * @return 1 if it does, 0 if not, < 0 where that cannot be told.
 */
int linux_task_has_cap_sys_admin(pid_t pid);
/* Room for every signal linux_term_signals() returns */
#define LINUX_TERM_SIGNALS_MAX 64

/**
 * @brief The asynchronous signals that terminate a process by default.
 *
 * What a daemon handles to shut down cleanly and its PID namespace supervisor
 * forwards. Not the synchronous faults, which a handler returning would only
 * raise again, nor SIGPIPE, the control mechanism of Protobuf-C-RPC.
 *
 * @param [out] sigs Array of LINUX_TERM_SIGNALS_MAX entries to fill.
 *
 * @return Number of signals written.
 */
unsigned int linux_term_signals(int *sigs);

/**
 * @brief Fork the daemon into an isolating PID namespace.
 *
 * The calling process becomes a pure supervisor that forwards signals and
 * mirrors the daemon's exit status; only the child returns from this call.
 *
 * @param [in] fwd_signals Signals the supervisor forwards to the daemon -
 *	       every signal the daemon handles. The daemon must install its
 *	       handlers for them before this call: the kernel drops a signal
 *	       sent to a PID namespace init from outside that has no handler
 *	       for it. The supervisor forwards the remaining signals a handler
 *	       can catch and a process ends by as well, as it would die from
 *	       one it does not forward and leave the daemon unsupervised. Only
 *	       a signal it cannot catch, as SIGKILL, ends it before the daemon:
 *	       the daemon then receives SIGTERM, the parent-death signal. A
 *	       change of its user or group ID clears that setting: the daemon
 *	       calls linux_pidns_arm_parent_death() after its last one, or
 *	       keeps a thread in linux_pidns_watch_supervisor() if it goes on
 *	       changing them.
 * @param [in] nr_fwd_signals Number of entries in fwd_signals.
 * @param [in] supervisor_exit_cb Optional callback (may be NULL) the
 *	       supervisor invokes - with its retained privileges - after the
 *	       daemon terminated and before it exits itself.
 */
int linux_isolate_namespace_prefork(const int *fwd_signals,
				    unsigned int nr_fwd_signals,
				    void (*supervisor_exit_cb)(void));
/**
 * @brief Have the kernel send SIGTERM when the PID namespace supervisor ends.
 *
 * For the daemon linux_isolate_namespace_prefork() returned in, which armed
 * the signal once; nothing is done in a process without supervisor. To be
 * called again after a change of the user or group ID, which clears the
 * setting in every thread, and by a thread that lives as long as the daemon:
 * the setting ends with the thread that made it. A supervisor that ended
 * before the call is noticed, the daemon then sends the signal to itself. As
 * init of its namespace the daemon receives SIGTERM only with a handler for
 * it installed.
 */
void linux_pidns_arm_parent_death(void);
/**
 * @brief Wait for the PID namespace supervisor to end, then send SIGTERM to
 *	  the calling process.
 *
 * For a thread of a daemon that changes its user or group ID while it serves,
 * in which the parent-death signal does not stay armed. Blocks in poll(2), a
 * cancellation point.
 *
 * @return 0 once the supervisor ended, -ENOENT without a supervisor.
 */
int linux_pidns_watch_supervisor(void);
int linux_personalization_string(char **ptr, size_t *length);

#ifdef __cplusplus
}
#endif

#endif /* LINUX_SUPPORT_H */
