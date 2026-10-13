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
#include <errno.h>
#include <linux/random.h>
#include <poll.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <time.h>
#include <unistd.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "cuse_device.h"
#include "cuse_helper.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "linux_support.h"
#include "esdm_logger.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "mutex_w.h"
#include "privileges.h"
#include "queue.h"
#include "ret_checkers.h"
#include "threading_support.h"

/******************************************************************************
 * Bind mount handling code
 ******************************************************************************/

static char *mount_src = NULL;
static char *mount_dst = NULL;

/******************************************************************************
 * Shared memory segment
 ******************************************************************************/

/*
 * The status segment and the semaphore belong to the ESDM server: it creates
 * them, and it removes a segment or a semaphore another user created, which is
 * how a planted one is kept from steering the poll path. So the daemon never
 * creates either - one it created before the server started would be the
 * server's to remove, and removing a segment nobody was attached to yet could
 * take one away that the server had just created. It attaches to what the
 * server created instead, see esdm_cuse_shm_status_attach().
 *
 * A segment attached before stays mapped when the server replaced it, and so
 * does its semaphore stay open: the request handlers on the other threads read
 * the segment without a lock, and the termination posts the semaphore. That
 * only happens when somebody removed the server's segment while the daemon was
 * attached to it, which the server itself does not do.
 */
static struct esdm_shm_status *_Atomic esdm_cuse_shm_status = NULL;
static int esdm_cuse_shmid = -1;

/*
 * The suspend_gen of the attached segment the pollers were last woken for. Kept
 * here rather than cleared in the segment: the /dev/random and the /dev/urandom
 * daemon share it, and the one done first would take the event from the other.
 */
static atomic_uint esdm_cuse_suspend_seen = 0;
static atomic_llong next_fh = 1;

static int esdm_cuse_shm_status_avail(void)
{
	static int initialized = 0;
	int ret = (esdm_cuse_shm_status &&
		   esdm_cuse_shm_status->version == ESDM_SHM_STATUS_VERSION);

	if (ret && !initialized)
		initialized = 1;

	return ret;
}

static void esdm_cuse_shm_status_close_shm(void)
{
	struct esdm_shm_status *status =
		atomic_exchange(&esdm_cuse_shm_status, NULL);

	if (status)
		shmdt(status);
	esdm_cuse_shmid = -1;
}

/*
 * The identifier of a segment of the server that is not the one attached to,
 * -1 if there is none. Needs no privileges: the server's segment is readable to
 * everybody, and nothing is attached here.
 */
static int esdm_cuse_shm_status_new_shmid(void)
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	struct shmid_ds buf;
	int shmid;

	/* No IPC_CREAT: there is no segment until the server created it */
	shmid = shmget(key, sizeof(struct esdm_shm_status), 0);
	if (shmid < 0 || shmid == esdm_cuse_shmid)
		return -1;

	/*
	 * Nobody is attached to it, so no server writes it: it is what a server
	 * that died left behind, and its contents tell nothing about the
	 * current state. Removing it is up to the next server, which attaches
	 * to it or replaces it.
	 */
	if (shmctl(shmid, IPC_STAT, &buf) < 0 || buf.shm_nattch == 0)
		return -1;

	return shmid;
}

/*
 * Attach to the server's segment @shmid. Events the server signalled on it
 * before are no news to the pollers, which are evaluated against it anew.
 *
 * The server creates the semaphores before it publishes the segment's version,
 * so a segment without the version is not taken yet: the semaphore may not be
 * there either. It is tried again on the next round.
 */
static int esdm_cuse_shm_status_attach_shm(int shmid)
{
	struct esdm_shm_status *status = shmat(shmid, NULL, 0);
	int errsv;

	if (status == (void *)-1) {
		errsv = errno;
		esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
			    "Attaching to shared memory segment failed: %s\n",
			    strerror(errsv));
		return -errsv;
	}

	if (status->version != ESDM_SHM_STATUS_VERSION) {
		shmdt(status);
		return -EAGAIN;
	}

	atomic_store(&esdm_cuse_suspend_seen,
		     atomic_load(&status->suspend_gen));
	atomic_store(&esdm_cuse_shm_status, status);
	esdm_cuse_shmid = shmid;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "ESDM shared memory segment successfully attached to\n");

	return 0;
}

/******************************************************************************
 * Semaphore for shared memory segment
 ******************************************************************************/

static atomic_bool esdm_cuse_poll_thread_shutdown = false;
/*
 * Predicate for the init handshake below: without it, the checker's
 * thread_wake_all() can fire before esdm_cuse_init() reaches its wait, losing
 * the wakeup and hanging startup.
 */
static atomic_bool esdm_cuse_poll_checker_ready = false;

/*
 * Active FUSE session, published by main_common() while the session loop runs.
 * The termination signal handler reads it to request a clean loop exit via the
 * async-signal-safe fuse_session_exit(). volatile so the handler sees the
 * current value; pointer-sized loads/stores are atomic on supported platforms.
 */
static struct fuse_session *volatile esdm_cuse_session;
static sem_t *_Atomic esdm_cuse_semid = SEM_FAILED;
static const char *esdm_sem_name = NULL;

static void esdm_cuse_shm_status_close_sem(void)
{
	sem_t *tmp = atomic_exchange(&esdm_cuse_semid, SEM_FAILED);

	if (tmp != SEM_FAILED)
		sem_close(tmp);
}

/*
 * Open the semaphore the server created with the segment just attached to.
 * Opening it takes write access, which the server grants its own user only.
 * Without it, the poll checker watches the segment instead.
 */
static int esdm_cuse_shm_status_open_sem(void)
{
	sem_t *tmp;
	int errsv;

	if (!esdm_sem_name)
		return -EFAULT;

	/* No O_CREAT, for the same reason as for the segment */
	tmp = sem_open(esdm_sem_name, 0);
	if (tmp == SEM_FAILED) {
		errsv = errno;
		esdm_logger(LOGGER_WARN, LOGGER_C_CUSE,
			    "ESDM change indicator semaphore not usable: %s\n",
			    strerror(errsv));
		/* One of a previous segment stays open, see above */
		atomic_store(&esdm_cuse_semid, SEM_FAILED);
		return -errsv;
	}

	/* The previous one stays open, see above */
	atomic_store(&esdm_cuse_semid, tmp);

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "ESDM change indicator semaphore initialized\n");

	return 0;
}

/******************************************************************************
 * Signal handler
 ******************************************************************************/

static DECLARE_WAIT_QUEUE(esdm_cuse_poll_checker_wait);

static void esdm_cuse_term(void)
{
	sem_t *sem;

	atomic_store(&esdm_cuse_poll_thread_shutdown, true);
	thread_wake_all(&esdm_cuse_poll_checker_wait);
	sem = atomic_load(&esdm_cuse_semid);
	if (sem != SEM_FAILED)
		sem_post(sem);

	thread_stop_spawning();

	/*
	 * We forcefully kill the SHM monitor thread as most likely it is
	 * waiting in sem_wait.
	 */
	thread_release(true, true);

	esdm_rpcc_fini_priv_service();
	esdm_rpcc_fini_unpriv_service();

	esdm_cuse_shm_status_close_shm();
	esdm_cuse_shm_status_close_sem();

	/* Return code is irrelevant here */
	esdm_cuse_bind_unmount(&mount_src, &mount_dst);
}

/* terminate the daemon cleanly */
static void esdm_cuse_sig_handler(int sig)
{
	struct fuse_session *se = esdm_cuse_session;

	(void)sig;

	/*
	 * Async-signal-safe only. fuse_session_exit() merely sets the session's
	 * exit flag, which makes fuse_session_loop() return so the real teardown
	 * (esdm_cuse_term) runs in normal context in main_common(). We must NOT
	 * call esdm_cuse_term(), esdm_logger(), free(), thread join/cancel,
	 * shmdt/sem_close, umount, or exit() from here: none are
	 * async-signal-safe and several could self-deadlock against an
	 * interrupted worker (e.g. holding the malloc arena or a mutex).
	 */
	if (se)
		fuse_session_exit(se);
}

static int esdm_cuse_install_sig_handler(void)
{
	/*
	 * Only asynchronous termination signals get the graceful handler: it
	 * makes the FUSE loop return so teardown (incl. bind-unmount) runs in
	 * normal context. Synchronous fault signals (SIGSEGV/SIGBUS/SIGILL/
	 * SIGFPE/SIGABRT/SIGSYS/SIGTRAP) are deliberately left at their default
	 * disposition - a "set flag and return" handler would loop forever on
	 * the faulting instruction, and running teardown from a fault context is
	 * unsafe; a core dump is more useful there.
	 */
	static const int term_signals[] = {
		SIGHUP,	  SIGINT,  SIGQUIT,   SIGTERM, SIGALRM,
		SIGIO,	  SIGPOLL, SIGPROF,   SIGPWR,  SIGUSR1,
		SIGUSR2,  SIGVTALRM, SIGXCPU, SIGXFSZ,
	};
	struct sigaction sa;
	size_t i;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
		    "Install termination signal handler\n");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = esdm_cuse_sig_handler;
	sigemptyset(&sa.sa_mask);
	/*
	 * No SA_RESTART: the FUSE loop's read() must return EINTR so the loop
	 * observes the exit flag set by fuse_session_exit() above. (glibc's
	 * signal() defaults to SA_RESTART, which would suppress that.)
	 * SIGPIPE is intentionally left untouched (control mechanism for
	 * Protobuf-C-RPC).
	 */
	sa.sa_flags = 0;

	for (i = 0; i < sizeof(term_signals) / sizeof(term_signals[0]); i++)
		sigaction(term_signals[i], &sa, NULL);

	return 0;
}

/******************************************************************************
 * CUSE helper
 ******************************************************************************/

#if 0
static bool esdm_cuse_fips_enabled(void)
{
	static char fipsflag[1] = { 'A' };
	size_t n = 0;

	if (fipsflag[0] == 'A') {
#ifdef HAVE_SECURE_GETENV
		if (secure_getenv("ESDM_SERVER_FORCE_FIPS")) {
#else
		if (getenv("ESDM_SERVER_FORCE_FIPS")) {
#endif
			fipsflag[0] = 1;
		} else {
			FILE *fipsfile = NULL;

			fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
			if (!fipsfile) {
				if (errno == ENOENT) {
					/* FIPS support not enabled in kernel */
					return 0;
				} else {
					esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
						"FIPS: Cannot open fips_enabled file: %s\n",
						strerror(errno));
					return -EIO;
				}
			}

			n = fread((void *)fipsflag, 1, 1, fipsfile);
			fclose(fipsfile);
			if (n != 1) {
				esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
				       "FIPS: Cannot read FIPS flag\n");
				return false;
			}
		}
	}

	return (fipsflag[0] == '1');
}
#endif

static const char *esdm_cuse_unprivileged_user = "nobody";

/* Whether the daemon runs as the unprivileged user and can raise back to root */
static bool esdm_cuse_dropped = false;

/*
 * Whether esdm_cuse_init_done() completed. The device accepts requests from
 * any user before that - libfuse serves them on other threads already, and the
 * device is made world-writeable before the privileges are dropped.
 */
static atomic_bool esdm_cuse_ready = false;

/*
 * The namespaces of linux_isolate_namespace(), but for the mount namespace.
 *
 * The daemon owns the bind mount over the kernel device, made in the mount
 * namespace it was started in, and has to remove it from there when it
 * terminates. In a mount namespace of its own, that umount would only reach its
 * copy of the mount table: with private mount propagation, the bind mount stays
 * behind and keeps covering the kernel device with one no daemon serves any
 * more. Going back for the umount is no way out either - setns() into a mount
 * namespace takes CAP_SYS_CHROOT, which the shipped units do not grant, and is
 * refused to a process with more than one thread.
 *
 * The shipped units do not give the daemon a mount namespace for the same
 * reason.
 */
static void esdm_cuse_isolate_namespace(void)
{
	if (unshare(CLONE_NEWCGROUP | CLONE_NEWNET) == -1) {
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot enter namespaces: %s\n", strerror(errno));
		return;
	}

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_CUSE,
		    "Successfully entered isolating namespaces\n");
}

static int esdm_cuse_drop_privileges(void)
{
	int ret;

	if (esdm_cuse_dropped)
		return 0;

	/*
	 * The namespaces are hardening on top of the privilege drop, a failure
	 * to enter them is logged. It must not keep the daemon from dropping
	 * its privileges.
	 */
	esdm_cuse_isolate_namespace();

	/* Without root, there is nothing to drop */
	if (geteuid() != 0)
		return 0;

	ret = drop_privileges_transient(esdm_cuse_unprivileged_user);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot drop privileges: %s\n", strerror(-ret));
		return ret;
	}

	esdm_cuse_dropped = true;

	return 0;
}

/*
 * When a privilege level is changed, the write lock must be taken to ensure
 * that no other caller is executing at the same time. If the privilege level
 * remains, a reader lock can be taken allowing concurrent unprivileged
 * operations.
 */
/*
 * Writer-preferring: the unprivileged read/write paths hold the reader lock
 * across a full server RPC, so with the default reader-preferring rwlock a
 * flood of concurrent unprivileged read()/write() calls could starve the
 * writer lock indefinitely and block every privileged ioctl (RNDADDENTROPY,
 * RNDRESEEDCRNG, RNDCLEARPOOL) - an unprivileged denial of service against the
 * admin control path.
 */
static mutex_t esdm_cuse_priv = MUTEX_UNLOCKED_PREFER_WRITER;

/*
 * The privileged requests waiting for the write lock.
 *
 * A read of /dev/random waits in its RPC until the ESDM is seeded, holding the
 * reader lock all along. A privileged request would wait for the write lock as
 * long, and every read and write after it with it, queued behind the writer.
 * The ESDM may well wait for exactly that request, e.g. for rngd to credit
 * entropy with RNDADDENTROPY. Such a read gives way to the privileged request
 * instead, see esdm_cuse_interrupt().
 */
static atomic_uint esdm_cuse_priv_waiting = 0;

/*
 * Whether the RPC this thread runs gives way to a privileged request, and
 * whether it did. The RPC client calls esdm_cuse_interrupt() on the thread that
 * runs the RPC.
 */
static __thread bool esdm_cuse_rpc_gives_way;
static __thread bool esdm_cuse_rpc_gave_way;

static void esdm_cuse_unpriv_call_start(void)
{
	mutex_reader_lock(&esdm_cuse_priv);
}

static void esdm_cuse_unpriv_call_end(void)
{
	mutex_reader_unlock(&esdm_cuse_priv);
}

static bool esdm_cuse_client_privileged(fuse_req_t req)
{
	const struct fuse_ctx *ctx = fuse_req_ctx(req);
	int ret;

	/*
	 * The kernel requires CAP_SYS_ADMIN for the privileged ioctls, not a
	 * UID: a root process without it is refused, a non-root one holding it
	 * is not.
	 *
	 * WARNING: as documented for struct fuse_ctx, the CUSE daemon
	 * MUST NOT run in a PID or user namespace - a caller outside of it is
	 * not identifiable and thus refused. That is every caller with
	 * --pid_namespace.
	 */
	ret = caller_cap_sys_admin(ctx->pid, ctx->uid);

	/*
	 * With /proc mounted with hidepid=, the unprivileged user cannot open
	 * the caller's entries, which root can. They are opened with the /proc
	 * access of root then, for this thread only, so that every other
	 * request keeps running and none has to wait for a caller that is
	 * refused in the end. The reader lock keeps a privileged request from
	 * changing the credentials of the process meanwhile.
	 */
	if (ret == -EACCES && esdm_cuse_dropped) {
		esdm_cuse_unpriv_call_start();
		ret = caller_cap_sys_admin_fsroot(ctx->pid, ctx->uid);
		esdm_cuse_unpriv_call_end();

		/*
		 * This thread would serve every request that follows with the
		 * /proc access of root. Not recoverable, as below.
		 */
		if (ret == -ENOTRECOVERABLE) {
			struct fuse_session *se = esdm_cuse_session;

			esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
				    "Cannot drop privileges after checking a caller, terminating\n");
			if (se)
				fuse_session_exit(se);
		}
	}

	if (ret > 0) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE,
			    "CUSE caller privileged\n");
		return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_CUSE, "CUSE caller unprivileged\n");
	return false;
}

static void esdm_cuse_drop_privilege_transient(void)
{
	/*
	 * Only what esdm_cuse_priv_call_start() raised is dropped. A daemon
	 * that never dropped its privileges, e.g. one not started as root,
	 * has nothing to drop - and dropping it to the unprivileged user here
	 * would leave it there, unable to raise again.
	 *
	 * Still being root after the drop would run every request that follows
	 * with the privileges of this one. That is not recoverable, so stop
	 * serving requests.
	 */
	if (esdm_cuse_dropped &&
	    drop_privileges_transient(esdm_cuse_unprivileged_user) &&
	    geteuid() == 0) {
		struct fuse_session *se = esdm_cuse_session;

		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot drop privileges after a privileged request, terminating\n");
		if (se)
			fuse_session_exit(se);
	}
	mutex_unlock(&esdm_cuse_priv);
}

/*
 * Take the write lock and raise the privileges a daemon that dropped them had,
 * both undone by esdm_cuse_drop_privilege_transient(). A read waiting for the
 * ESDM with the reader lock held gives way meanwhile, see esdm_cuse_interrupt().
 */
static void esdm_cuse_raise_privilege_transient(void)
{
	atomic_fetch_add(&esdm_cuse_priv_waiting, 1);
	mutex_lock(&esdm_cuse_priv);
	atomic_fetch_sub(&esdm_cuse_priv_waiting, 1);
	if (esdm_cuse_dropped)
		raise_privilege_transient(0, 0);
}

/*
 * Start a privileged request: check the caller, then raise the privileges with
 * the write lock held so that no other request runs while they are raised.
 *
 * The caller is checked before the write lock is taken. A writer waiting for it
 * keeps every new read and write of the device waiting as well, which a caller
 * that is refused anyway must not be able to cause.
 *
 * Until esdm_cuse_init_done() completed, whether the daemon has dropped its
 * privileges - and so whether they are to be raised and dropped again - is not
 * settled yet. A privileged request is answered with EAGAIN meanwhile: the
 * caller may well be entitled to it, and is so in a moment, which EPERM would
 * tell it otherwise. It is what the status ioctl answers while the ESDM is not
 * there yet as well.
 *
 * Returns 0 with the privileges raised and the lock held, both released by
 * esdm_cuse_drop_privilege_transient(); the error to reply with neither.
 */
static int esdm_cuse_priv_call_start(fuse_req_t req)
{
	if (!atomic_load(&esdm_cuse_ready))
		return EAGAIN;

	if (!esdm_cuse_client_privileged(req))
		return EPERM;

	esdm_cuse_raise_privilege_transient();

	return 0;
}

/*
 * Attach to the status segment and the semaphore of the server, unless they
 * are the ones attached to already. See esdm_cuse_shm_status for why the
 * daemon never creates them.
 *
 * At startup the daemon is still root. Later on, the poll checker does this
 * with the privileges raised the way a privileged request has them, as the
 * server grants write access to both to its own user only. They are only
 * raised once a new segment of a running server is there, so not on every
 * round of the checker while there is no server.
 *
 * Returns true when a new segment was attached to.
 */
static bool esdm_cuse_shm_status_attach(void)
{
	int ret, shmid = esdm_cuse_shm_status_new_shmid();

	if (shmid < 0)
		return false;

	esdm_cuse_raise_privilege_transient();
	ret = esdm_cuse_shm_status_attach_shm(shmid);
	if (!ret)
		esdm_cuse_shm_status_open_sem();
	esdm_cuse_drop_privilege_transient();

	return !ret;
}

static void esdm_cuse_shm_status_down(void)
{
	/*
	 * How long one wait lasts at most before the segment is checked again:
	 * waiting for a server that is not there yet, watching a segment
	 * without its semaphore, and on the semaphore, which a replaced segment
	 * would never post again.
	 */
	static const struct timespec no_server = { .tv_sec = 1 };
	static const struct timespec no_sem = { .tv_nsec = 100 * 1000 * 1000 };
	static const time_t sem_sec = 5;
	struct timespec ts;
	sem_t *sem;

	/* The server is terminating, do not block any more */
	if (atomic_load(&esdm_cuse_poll_thread_shutdown))
		return;

	/* A new segment: the pollers are evaluated against it right away */
	if (esdm_cuse_shm_status_attach())
		return;

	if (!esdm_cuse_shm_status) {
		nanosleep(&no_server, NULL);
		return;
	}

	sem = atomic_load(&esdm_cuse_semid);
	if (sem == SEM_FAILED) {
		nanosleep(&no_sem, NULL);
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += sem_sec;
	if (sem_clockwait(sem, CLOCK_MONOTONIC, &ts) && errno != ETIMEDOUT &&
	    errno != EINTR)
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "Cannot use semaphore: %s\n", strerror(errno));
}

/******************************************************************************
 * CUSE callback handler
 ******************************************************************************/
void esdm_cuse_open(fuse_req_t req, struct fuse_file_info *fi)
{
	fi->fh = (uint64_t)(atomic_fetch_add(&next_fh, 1) + 1);
	fuse_reply_open(req, fi);
}

/*
 * Whether the RPC is to be abandoned. The RPC client asks before it sends a
 * request and while it waits for the answer - so also between the requests of
 * a call that asks the ESDM again and again until it is seeded.
 */
static int esdm_cuse_interrupt(void *data)
{
	fuse_req_t req = (fuse_req_t)data;

	if (esdm_cuse_rpc_gives_way && atomic_load(&esdm_cuse_priv_waiting)) {
		esdm_cuse_rpc_gave_way = true;
		return 1;
	}

	if (!req)
		return 0;
	return !!fuse_req_interrupted(req);
}

/*
 * A read gave way to a privileged request: wait without the reader lock until
 * no privileged request waits for the write lock any more.
 *
 * With the writer-preferring lock, taking the reader lock again would wait for
 * the writer on its own. A lock that prefers readers would let the read take it
 * again right away, though, only to give way once more, so that the writer gets
 * no chance between the two.
 *
 * Returns 0 when the read is to go on, -EINTR when the reader was interrupted
 * meanwhile.
 */
static int esdm_cuse_read_after_giving_way(fuse_req_t req)
{
	static const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };

	while (atomic_load(&esdm_cuse_priv_waiting)) {
		if (fuse_req_interrupted(req))
			return -EINTR;
		nanosleep(&ts, NULL);
	}

	return fuse_req_interrupted(req) ? -EINTR : 0;
}

/*
 * Whether a read of seeded randomness would block. The status segment answers
 * that without a round trip and is what poll() reports as well; without it, the
 * ESDM is asked. If neither can tell, the read goes ahead and ends up at the
 * fallback.
 */
static bool esdm_cuse_read_would_block(fuse_req_t req)
{
	bool fully_seeded = false;
	int ret;

	if (esdm_cuse_shm_status_avail())
		return !atomic_load(&esdm_cuse_shm_status->operational);

	esdm_cuse_unpriv_call_start();
	esdm_invoke(esdm_rpcc_is_fully_seeded_int(&fully_seeded, req));
	esdm_cuse_unpriv_call_end();

	return !ret && !fully_seeded;
}

void esdm_cuse_read_internal(fuse_req_t req, size_t size, off_t off,
			     struct fuse_file_info *fi, get_func_t get,
			     int fallback_fd)
{
	uint8_t tmpbuf_s[64] = { 0 }, *tmpbuf_p = tmpbuf_s, *tmpbuf = NULL;
	size_t read_bytes = 0;
	ssize_t ret = 0;

	(void)off;

	/*
	 * size is limited by fuse to its maximum request size, mostly
	 * 131072 byte
	 */
	if (size > sizeof(tmpbuf_s)) {
		tmpbuf = calloc(1, size);
		CKNULL(tmpbuf, -ENOMEM);
		tmpbuf_p = tmpbuf;
	}

	fallback_fd = esdm_test_fallback_fd(fallback_fd);

	/*
	 * The blocking PR call waits for as long as the PR DRNG is busy or not
	 * operational, which an O_NONBLOCK reader must not.
	 */
	if (fi->flags & O_SYNC)
		get = (fi->flags & O_NONBLOCK) ?
			      esdm_rpcc_get_random_bytes_pr_nonblock_int :
			      esdm_rpcc_get_random_bytes_pr_int;

	/*
	 * Everything but the plain urandom read blocks until the ESDM is
	 * seeded, which a reader asking for O_NONBLOCK is told with EAGAIN
	 * instead, as the kernel's /dev/random does.
	 */
	if ((fi->flags & O_NONBLOCK) && get != esdm_rpcc_get_random_bytes_int &&
	    esdm_cuse_read_would_block(req)) {
		ret = -EAGAIN;
		goto out;
	}

	/*
	 * fuse automatically chunks requests, e.g. for a 1MB read
	 * multiple <= 131072 byte reads are typically performed, try to fill
	 * them up.
	 */
	while (read_bytes < size) {
		size_t todo = min_size(ESDM_RPC_MAX_DATA, size - read_bytes);

		/*
		 * Waiting for the ESDM - to be seeded, or the prediction
		 * resistant DRNG to be ready - the call holds the reader lock.
		 * It gives way to a privileged request, which would wait for
		 * the read otherwise, and every request after it as well.
		 */
		esdm_cuse_unpriv_call_start();
		esdm_cuse_rpc_gives_way = true;
		esdm_cuse_rpc_gave_way = false;
		esdm_invoke(get(tmpbuf_p + read_bytes, todo, req));
		esdm_cuse_rpc_gives_way = false;
		esdm_cuse_unpriv_call_end();

		/*
		 * Whatever the abandoned call returned, it is no answer of the
		 * ESDM, so it is neither covered by the fallback nor returned.
		 * Ask again once the privileged request is through. A reader
		 * interrupted meanwhile gets what was read, if anything.
		 */
		if (esdm_cuse_rpc_gave_way && ret < 0) {
			ret = esdm_cuse_read_after_giving_way(req);
			if (!ret)
				continue;
			if (read_bytes)
				break;
			goto out;
		}

		/*
		 * The ESDM cannot serve without blocking: that is its answer,
		 * not a failure to cover for. What was read is returned as a
		 * short read, nothing read is EAGAIN.
		 */
		if (ret == -EAGAIN &&
		    get == esdm_rpcc_get_random_bytes_pr_nonblock_int) {
			if (read_bytes)
				break;
			goto out;
		}

		/*
		 * If call to the ESDM server failed, let us fall back to the
		 * fallback file descriptor. Yet, we do not cover for short
		 * reads as this entire CUSE handling is prone to short reads
		 * as outlined below. Thus, the caller needs to handle this
		 * appropriately.
		 */
		if (ret < 0 && fallback_fd > -1) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_CUSE,
				"Use fallback to provide data due to RPC error code %zd\n",
				ret);
			ret = read(fallback_fd, tmpbuf_p + read_bytes, todo);

			/*
			 * A 0-byte read (EOF - e.g. a regular-file fallback in
			 * test setups; a device never EOFs) would loop forever
			 * as read_bytes stops advancing. Fail the request
			 * instead.
			 */
			if (ret < 0)
				ret = -errno;
			else if (ret == 0)
				ret = -EIO;
		}

		if (ret < 0)
			goto out;
		read_bytes += (size_t)ret;
	}

	/*
	 * Every request is answered exactly once. libfuse frees the request
	 * when it sends the reply, whether the sending succeeds or not: an
	 * error reply after a failed fuse_reply_buf() would send and free the
	 * request a second time. Nor would it reach anybody: the send fails
	 * when the kernel no longer waits for the request, e.g. because the
	 * reader was interrupted.
	 */
	fuse_reply_buf(req, (const char *)tmpbuf_p, read_bytes);
	ret = 0;

out:
	if (tmpbuf) {
		memset_secure(tmpbuf, 0, size);
		free(tmpbuf);
	} else {
		memset_secure(tmpbuf_s, 0, sizeof(tmpbuf_s));
	}

	if (ret < 0)
		fuse_reply_err(req, (int)-ret);
}

void esdm_cuse_write_internal(fuse_req_t req, const char *buf, size_t size,
			      off_t off, struct fuse_file_info *fi,
			      int fallback_fd)
{
	size_t written = 0;
	/*
	 * Default to success so a zero-length write (size == 0, loop body never
	 * runs) is reported as a successful 0-byte write rather than EFAULT.
	 */
	ssize_t ret = 0;

	(void)fi;
	(void)off;

	fallback_fd = esdm_test_fallback_fd(fallback_fd);

	while (written < size) {
		size_t todo = min_size(ESDM_RPC_MAX_DATA, size - written);

		esdm_cuse_unpriv_call_start();
		esdm_invoke(esdm_rpcc_write_data_int(
			(const uint8_t *)buf + written, todo, req));
		esdm_cuse_unpriv_call_end();
		if (ret == 0)
			written += todo;
		else
			goto err;
	}

	goto out;

err:
	/*
	 * If call to the ESDM server failed, let us fall back to the
	 * fallback file descriptor. It writes the entire buffer into the
	 * fallback as we do not consider a mix-n-match of data written to
	 * ESDM and data written to the fallback as appropriate.
	 */
	if (ret < 0 && fallback_fd > -1) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_CUSE,
			"Use fallback to provide data due to RPC error code %zd\n",
			ret);
		written = 0;
		do {
			ret = write(fallback_fd, buf + written, size - written);
			if (ret > 0)
				written += (size_t)ret;
		} while (ret > 0 && written < size);

		/*
		 * A short fallback write (e.g. write() returning 0) must not be
		 * reported to the caller as a successful full write.
		 */
		if (ret < 0)
			ret = -errno;
		else if (written < size)
			ret = -EIO;
	}

out:
	if (ret < 0)
		fuse_reply_err(req, (int)-ret);
	else
		fuse_reply_write(req, written);
}

/*
 * Whether a privileged RPC was interrupted after its request went out
 * (-EINPROGRESS): the ESDM may apply it all the same, so it must not be
 * followed by the kernel fallback, which would credit the entropy a second
 * time. Its effect is unknown then, as that of an interrupted ioctl of the
 * kernel can be, whose caller is told EINTR - and is gone anyway, as the
 * RPC is only interrupted when the caller interrupted its request.
 */
static bool esdm_cuse_priv_in_progress(int *ret)
{
	if (*ret != -EINPROGRESS)
		return false;

	*ret = -EINTR;
	return true;
}

void esdm_cuse_ioctl(int backend_fd, fuse_req_t req, unsigned long cmd,
		     void *arg, struct fuse_file_info *fi, unsigned flags,
		     const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
	const struct rand_pool_info *rpi;
	uint32_t ent_count_bits;
	int ret;

	(void)fi;

	/*
	 * A 32 bit caller (FUSE_IOCTL_COMPAT) is served like any other: the
	 * commands are encoded the same, they transfer an int, a struct
	 * rand_pool_info made of ints only, or plain bytes, and the transfers
	 * requested by a retry are encoded independently of the caller's word
	 * size by the FUSE protocol.
	 */
	(void)flags;

	backend_fd = esdm_test_fallback_fd(backend_fd);

	switch (cmd) {
	case RNDGETENTCNT:
		if (!out_bufsz) {
			struct iovec iov = { arg, sizeof(ent_count_bits) };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
		} else {
			esdm_cuse_unpriv_call_start();
			esdm_invoke(esdm_rpcc_rnd_get_ent_cnt_int(
				&ent_count_bits, req));
			esdm_cuse_unpriv_call_end();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, &ent_count_bits,
						 sizeof(ent_count_bits));
		}
		break;
	case RNDADDTOENTCNT:
		if (!in_bufsz || in_bufsz < sizeof(ent_count_bits)) {
			struct iovec iov = { arg, sizeof(ent_count_bits) };
			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			int ent_count;

			memcpy(&ent_count, in_buf, sizeof(ent_count));

			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			ret = esdm_cuse_priv_call_start(req);
			if (ret) {
				fuse_reply_err(req, ret);
				return;
			}

			/*
			 * The kernel takes an int and refuses a negative
			 * count. As unsigned value, it would claim the
			 * largest entropy count possible instead.
			 */
			if (ent_count < 0) {
				esdm_cuse_drop_privilege_transient();
				fuse_reply_err(req, EINVAL);
				return;
			}
			ent_count_bits = (uint32_t)ent_count;

			esdm_invoke(esdm_rpcc_rnd_add_to_ent_cnt_int(
				ent_count_bits, req));
			/* In case of an error, update the kernel */
			if (ret && !esdm_cuse_priv_in_progress(&ret)) {
				if (backend_fd >= 0 &&
				    ioctl(backend_fd, RNDADDTOENTCNT,
					  &ent_count_bits) == -1)
					ret = -errno;
				else
					ret = 0;
			}
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;
	case RNDADDENTROPY:
		rpi = (const struct rand_pool_info *)in_buf;

		if (in_bufsz < sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->buf_size < 0) {
			fuse_reply_err(req, EINVAL);
		} else if ((size_t)rpi->buf_size !=
			   in_bufsz - sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) +
						     (size_t)rpi->buf_size };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->entropy_count < 0 ||
			   (uint64_t)rpi->entropy_count >
				   (uint64_t)rpi->buf_size * 8) {
			/*
			 * Reject a negative entropy_count (which would otherwise
			 * become a huge value once cast to uint32_t) and any
			 * claim of more entropy bits than the supplied buffer
			 * can hold, mirroring the kernel's RNDADDENTROPY check.
			 */
			fuse_reply_err(req, EINVAL);
		} else {
			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			ret = esdm_cuse_priv_call_start(req);
			if (ret) {
				fuse_reply_err(req, ret);
				return;
			}

			esdm_invoke(esdm_rpcc_rnd_add_entropy_int(
				(const uint8_t *)rpi->buf,
				(size_t)rpi->buf_size,
				(uint32_t)rpi->entropy_count, req));

			/* In case of an error, update the kernel */
			if (ret && !esdm_cuse_priv_in_progress(&ret)) {
				if (backend_fd >= 0 &&
				    ioctl(backend_fd, RNDADDENTROPY, rpi) == -1)
					ret = -errno;
				else
					ret = 0;
			}
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;
	case RNDZAPENTCNT:
	case RNDCLEARPOOL:
		/*
		 * This operation requires privileges. Thus, raise the
		 * privilege level to the same level as the caller has.
		 */
		ret = esdm_cuse_priv_call_start(req);
		if (ret) {
			fuse_reply_err(req, ret);
			return;
		}
		esdm_invoke(esdm_rpcc_rnd_clear_pool_int(req));
		if (!ret) {
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDCLEARPOOL) == -1)
				ret = -errno;
		} else {
			esdm_cuse_priv_in_progress(&ret);
		}
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;
	case RNDRESEEDCRNG:
		/*
		 * This operation requires privileges. Thus, raise the
		 * privilege level to the same level as the caller has.
		 */
		ret = esdm_cuse_priv_call_start(req);
		if (ret) {
			fuse_reply_err(req, ret);
			return;
		}
		esdm_invoke(esdm_rpcc_rnd_reseed_crng_int(req));
		if (!ret) {
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDRESEEDCRNG) == -1)
				ret = -errno;
		} else {
			esdm_cuse_priv_in_progress(&ret);
		}
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;

	/* ESDM-specific IOCTL: get ESDM information */
	case 42: {
		char info[ESDM_SHM_STATUS_INFO_SIZE];
		size_t infolen;

		/*
		 * The server writes the report before it publishes the
		 * segment's version, and withdraws the version before writing
		 * it anew when it restarts. So the report is only complete
		 * while the version is there - before the copy, and still
		 * after it.
		 */
		if (!esdm_cuse_shm_status_avail()) {
			fuse_reply_err(req, EAGAIN);
			break;
		}
		atomic_thread_fence(memory_order_acquire);

		/* Clamp infolen to buffer bounds to prevent overread */
		infolen = esdm_cuse_shm_status->infolen;
		if (infolen > ESDM_SHM_STATUS_INFO_SIZE)
			infolen = ESDM_SHM_STATUS_INFO_SIZE;

		if (out_bufsz < infolen) {
			struct iovec iov = { arg, infolen };

			fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
			break;
		}

		memcpy(info, esdm_cuse_shm_status->info, infolen);
		atomic_thread_fence(memory_order_acquire);
		if (!esdm_cuse_shm_status_avail())
			fuse_reply_err(req, EAGAIN);
		else
			fuse_reply_ioctl(req, 0, info, infolen);
		break;
	}

	/* ESDM-specific IOCTL: Reseed kernel directly */
	case 43:
		rpi = (const struct rand_pool_info *)in_buf;

		if (in_bufsz < sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else if (rpi->buf_size < 0) {
			fuse_reply_err(req, EINVAL);
		} else if ((size_t)rpi->buf_size !=
			   in_bufsz - sizeof(struct rand_pool_info)) {
			struct iovec iov = { arg,
					     sizeof(struct rand_pool_info) +
						     (size_t)rpi->buf_size };

			fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
		} else {
			/*
			 * This operation requires privileges. Thus, raise the
			 * privilege level to the same level as the caller has.
			 */
			ret = esdm_cuse_priv_call_start(req);
			if (ret) {
				fuse_reply_err(req, ret);
				return;
			}
			if (backend_fd >= 0 &&
			    ioctl(backend_fd, RNDADDENTROPY, rpi) == -1)
				ret = -errno;
			else
				ret = 0;
			esdm_cuse_drop_privilege_transient();
			if (ret)
				fuse_reply_err(req, -ret);
			else
				fuse_reply_ioctl(req, 0, NULL, 0);
		}
		break;

	/* ESDM-specific IOCTL: force reseed of kernel CRNG directly */
	case 44:
		/*
		* This operation requires privileges. Thus, raise the
		* privilege level to the same level as the caller has.
		*/
		ret = esdm_cuse_priv_call_start(req);
		if (ret) {
			fuse_reply_err(req, ret);
			return;
		}
		if (backend_fd >= 0 && ioctl(backend_fd, RNDRESEEDCRNG) == -1)
			ret = -errno;
		else
			ret = 0;
		esdm_cuse_drop_privilege_transient();
		if (ret)
			fuse_reply_err(req, -ret);
		else
			fuse_reply_ioctl(req, 0, NULL, 0);
		break;

	default:
		/*
		 * A command the device does not know. The kernel's
		 * random_ioctl() answers it with EINVAL - not with the ENOTTY
		 * of most other drivers - on /dev/random and /dev/urandom
		 * alike, and a program probing for a command sees the device
		 * the kernel has.
		 */
		fuse_reply_err(req, EINVAL);
	}
}

/******************************************************************************
 * Poll system call handler
 ******************************************************************************/

/*
 * Registered poll handles are kept in a dynamically grown singly-linked list
 * rather than a fixed global array: a fixed cap was shared across all clients,
 * so a single process could pin every slot and make poll() silently block
 * forever for every other user (a cross-user denial of service). The list is
 * bounded only by the number of file descriptors currently polling, which the
 * OS already limits per process. All access is serialized by esdm_cuse_ph_lock.
 */
struct esdm_cuse_poll {
	uint64_t fh;
	/* NULL once woken for a suspend, see esdm_cuse_poll_check() */
	struct fuse_pollhandle *ph;
	uint32_t poll_events;
	struct esdm_cuse_poll *next;
};
static struct esdm_cuse_poll *esdm_cuse_poll_list;
static DEFINE_MUTEX_W_UNLOCKED(esdm_cuse_ph_lock);

/*
 * Unlink and free every registration for fh; caller holds esdm_cuse_ph_lock.
 * Returns whether one was woken for a suspend.
 */
static bool esdm_cuse_poll_remove_fh(uint64_t fh, bool notify)
{
	struct esdm_cuse_poll **pp = &esdm_cuse_poll_list;
	bool suspend_woken = false;

	while (*pp) {
		struct esdm_cuse_poll *node = *pp;

		if (node->fh == fh) {
			if (!node->ph) {
				suspend_woken = true;
			} else {
				if (notify)
					fuse_notify_poll(node->ph);
				fuse_pollhandle_destroy(node->ph);
			}
			*pp = node->next;
			free(node);
		} else {
			pp = &node->next;
		}
	}

	return suspend_woken;
}

static void esdm_cuse_get_pollmask(unsigned int *outmask)
{
#define ESDM_POLL_READER (POLLIN | POLLRDNORM)
#define ESDM_POLL_WRITER (POLLOUT | POLLWRNORM)

	struct esdm_shm_status *status = esdm_cuse_shm_status;

	*outmask = 0;

	/* Simply wake the poller no matter what it waits for. */
	if (atomic_load(&esdm_cuse_poll_thread_shutdown))
		*outmask |= ESDM_POLL_READER | ESDM_POLL_WRITER;

	/*
	 * Until the server created its status segment, there is nothing to
	 * tell, see esdm_cuse_shm_status_attach().
	 */
	if (!status)
		return;

	if (atomic_load(&status->operational))
		*outmask |= ESDM_POLL_READER;
	if (atomic_load(&status->need_entropy))
		*outmask |= ESDM_POLL_WRITER;

	/*
	 * Simply wake the poller no matter what it waits for, until the checker
	 * has woken every registered poll handle for the event - which their
	 * next poll is told then, see esdm_cuse_poll_check().
	 */
	if (atomic_load(&status->suspend_gen) !=
	    atomic_load(&esdm_cuse_suspend_seen))
		*outmask |= ESDM_POLL_READER | ESDM_POLL_WRITER;
}

/* *outmask is already filled with output of esdm_cuse_get_pollmask */
static void esdm_cuse_set_pollmask(unsigned int request_events,
				   unsigned int *outmask)
{
	*outmask &= request_events;
}

/* when extending this function, always check and return error
 * codes first, as they may originate from an interrupted poll/select
 * which causes many bogus events if answered with notify_poll or reply_poll
 */
void esdm_cuse_poll(fuse_req_t req, struct fuse_file_info *fi,
		    struct fuse_pollhandle *ph)
{
	unsigned int mask;
	int err_code;

	if (!fi->poll_events) {
		err_code = EINVAL;
		goto err;
	}

	mutex_w_lock(&esdm_cuse_ph_lock);
	{
		/*
		 * Drop any stale registration for this fh, as we may have an
		 * interrupted poll/select.
		 */
		bool suspend_woken = esdm_cuse_poll_remove_fh(fi->fh, false);

		/*
		 * Check current status and return it if it complies with
		 * requested status.
		 */
		esdm_cuse_get_pollmask(&mask);
		if (suspend_woken)
			mask |= ESDM_POLL_READER | ESDM_POLL_WRITER;
		esdm_cuse_set_pollmask(fi->poll_events, &mask);
		fuse_reply_poll(req, mask);

		if (mask) {
			/* Event already available (replied above). */
			fuse_notify_poll(ph);
			fuse_pollhandle_destroy(ph);
		} else {
			struct esdm_cuse_poll *node = calloc(1, sizeof(*node));

			if (!node) {
				/*
				 * Cannot register the handle. Wake the client so
				 * it re-polls rather than blocking forever on an
				 * event it would never be notified of.
				 */
				fuse_notify_poll(ph);
				fuse_pollhandle_destroy(ph);
			} else {
				unsigned int recheck;

				node->fh = fi->fh;
				node->ph = ph;
				node->poll_events = fi->poll_events;
				node->next = esdm_cuse_poll_list;
				esdm_cuse_poll_list = node;

				/*
				 * Close the register-after-reply window: if the
				 * state became ready between the mask snapshot
				 * above and this registration, deliver it now
				 * instead of waiting for the next state change.
				 */
				esdm_cuse_get_pollmask(&recheck);
				esdm_cuse_set_pollmask(fi->poll_events, &recheck);
				if (recheck) {
					fuse_notify_poll(node->ph);
					fuse_pollhandle_destroy(node->ph);
					esdm_cuse_poll_list = node->next;
					free(node);
				}
			}
		}
	}
	mutex_w_unlock(&esdm_cuse_ph_lock);

	return;

err:
	fuse_reply_err(req, err_code);
}

/*
 * poll() of /dev/urandom. The kernel's urandom_fops have no poll handler, so the
 * device is always readable and writable: a read never waits for the seeding,
 * and a write is always taken. A program that polls the device before reading
 * from it must not wait for the ESDM here, during boot it may wait for good.
 */
void esdm_cuse_poll_urandom(fuse_req_t req, struct fuse_file_info *fi,
			    struct fuse_pollhandle *ph)
{
	(void)fi;

	fuse_reply_poll(req, ESDM_POLL_READER | ESDM_POLL_WRITER);

	/* Nothing will change, so there is nothing to notify about */
	if (ph)
		fuse_pollhandle_destroy(ph);
}

/* Wake the registered pollers whose event came */
static void esdm_cuse_poll_check(void)
{
	struct esdm_shm_status *status;
	unsigned int sysmask, mask, gen = 0;
	bool sysmask_set = false, suspend = false;
	struct esdm_cuse_poll **pp;

	mutex_w_lock(&esdm_cuse_ph_lock);

	/*
	 * Only this thread attaches to another segment. The suspend event is
	 * sampled before the handles are evaluated: one that comes during the
	 * pass leaves the sample behind and is delivered on the next pass.
	 */
	status = esdm_cuse_shm_status;
	if (status) {
		gen = atomic_load(&status->suspend_gen);
		suspend = gen != atomic_load(&esdm_cuse_suspend_seen);
	}

	pp = &esdm_cuse_poll_list;
	while (*pp) {
		struct esdm_cuse_poll *node = *pp;

		/* Woken already, waiting for its next poll */
		if (!node->ph) {
			pp = &node->next;
			continue;
		}

		/* Get the mask once for this loop */
		if (!sysmask_set) {
			esdm_cuse_get_pollmask(&sysmask);
			sysmask_set = true;
		}

		mask = sysmask;
		esdm_cuse_set_pollmask(node->poll_events, &mask);

		if (!mask) {
			pp = &node->next;
			continue;
		}

		fuse_notify_poll(node->ph);
		fuse_pollhandle_destroy(node->ph);

		/*
		 * The kernel answers the notification with another poll, which
		 * finds the event marked seen below and would go back to sleep.
		 * So the registration stays behind without its handle, to tell
		 * that poll, see esdm_cuse_poll().
		 */
		if (suspend) {
			node->ph = NULL;
			pp = &node->next;
			continue;
		}

		*pp = node->next;
		free(node);
	}

	/* Every poll handle in the list has just been woken for it */
	if (status)
		atomic_store(&esdm_cuse_suspend_seen, gen);

	mutex_w_unlock(&esdm_cuse_ph_lock);
}

/* Poll checker handler executed in separate thread */
static int esdm_cuse_poll_checker(void __unused *unused)
{
	thread_set_name(cuse_poll, 0);

	atomic_store(&esdm_cuse_poll_checker_ready, true);
	thread_wake_all(&esdm_cuse_poll_checker_wait);

	while (!atomic_load(&esdm_cuse_poll_thread_shutdown)) {
		esdm_cuse_poll_check();
		esdm_cuse_shm_status_down();
	}

	return 0;
}

void esdm_cuse_release(fuse_req_t req, struct fuse_file_info *fi)
{
	mutex_w_lock(&esdm_cuse_ph_lock);
	esdm_cuse_poll_remove_fh(fi->fh, true);
	mutex_w_unlock(&esdm_cuse_ph_lock);

	fuse_reply_err(req, 0);
}

/******************************************************************************
 * CUSE daemon
 ******************************************************************************/

void esdm_cuse_init_done(void *userdata)
{
	int ret;

	(void)userdata;

	if (mount_src) {
		if (chmod(mount_src, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP |
					     S_IROTH | S_IWOTH) < 0) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_CUSE,
				"Changing permissions to world-writeable failed: %s",
				strerror(errno));
		}
	}

	CKINT(esdm_cuse_bind_mount(mount_src, mount_dst));

	/*
	 * The server's, if it runs already - otherwise the poll checker
	 * attaches to them once it created them.
	 */
	esdm_cuse_shm_status_attach();

	CKINT(esdm_cuse_drop_privileges());

	CKINT_LOG(thread_start(esdm_cuse_poll_checker, NULL,
			       ESDM_THREAD_CUSE_POLL_GROUP, NULL),
		  "Starting poll-in-reset thread failed: %d\n", ret);

	/* Wait until thread is fully initialized */
	thread_wait_event(&esdm_cuse_poll_checker_wait,
			  atomic_load(&esdm_cuse_poll_checker_ready) ||
				  atomic_load(
					  &esdm_cuse_poll_thread_shutdown));

	/* From here on, esdm_cuse_dropped stays as it is */
	atomic_store(&esdm_cuse_ready, true);

	return;

out:
	esdm_cuse_term();
	exit(-ret);
}

struct esdm_cuse_param {
	unsigned int major;
	unsigned int minor;
	char *dev_name;
	char *username;
	unsigned int verbosity;
	int is_help;
	int disable_fallback;
	int syslog;
	int pid_namespace;
	unsigned int max_threads;
};

#define ESDM_CUSE_OPT(t, p) { t, offsetof(struct esdm_cuse_param, p), 1 }

/*
 * How many worker threads libfuse may start to serve the device. A request
 * waiting for the ESDM - a /dev/random read before the seeding, an O_SYNC read
 * - holds its worker for the whole RPC, and every other request, a privileged
 * ioctl included, waits for a free one. The default of libfuse 3.12, 10, let a
 * handful of such readers stall the device, at boot possibly with the ESDM
 * waiting for the RNDADDENTROPY of rngd stuck behind them. Workers are started
 * on demand, so the limit only bounds what a flood of such readers costs.
 *
 * Workers beyond ESDM_CUSE_IDLE_THREADS idle ones end again, as before libfuse
 * 3.12, rather than keeping the memory of such a flood for good.
 */
#define ESDM_CUSE_MAX_THREADS 1024
#define ESDM_CUSE_IDLE_THREADS 10
#define _ESDM_CUSE_STR(x) #x
#define ESDM_CUSE_STR(x) _ESDM_CUSE_STR(x)

static const char *usage =
	"usage: esdm_cuse [options]\n"
	"\n"
	"options:\n"
	"    --help|-h               print this help message\n"
	"    --maj=MAJ|-M MAJ        device major number\n"
	"    --min=MIN|-m MIN        device minor number\n"
	"    --name=NAME|-n NAME     device name (mandatory)\n"
	"    --verbosity=NUM|-v NUM  verbosity level\n"
	"    --username=USER|-u USER unprivileged user name (default: \"nobody\")\n"
	"    --pid_namespace         fork the daemon into an isolating PID namespace\n"
	"                            (refuses the privileged ioctls to every caller)\n"
	"    -d   -o debug           enable debug output (implies -f)\n"
	"    -f                      foreground operation\n"
	"    -s                      disable multi-threaded operation\n"
	"    -o max_threads=NUM      maximum number of worker threads (default: "
	ESDM_CUSE_STR(ESDM_CUSE_MAX_THREADS) ")\n"
	"    -S                      log via syslog\n"
	"\n";

/* The CUSE code seems to have a conversion issue with FUSE_OPT_KEY */
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wimplicit-int-conversion"
#endif
static const struct fuse_opt esdm_cuse_opts[] = {
	ESDM_CUSE_OPT("-M %u", major),
	ESDM_CUSE_OPT("--maj=%u", major),
	ESDM_CUSE_OPT("-m %u", minor),
	ESDM_CUSE_OPT("--min=%u", minor),
	ESDM_CUSE_OPT("-n %s", dev_name),
	ESDM_CUSE_OPT("--name=%s", dev_name),
	ESDM_CUSE_OPT("-v %u", verbosity),
	ESDM_CUSE_OPT("--verbosity=%u", verbosity),
	ESDM_CUSE_OPT("-u %s", username),
	ESDM_CUSE_OPT("--username %s", username),
	ESDM_CUSE_OPT("--pid_namespace", pid_namespace),
	/* cuse_lowlevel_setup() ignores it, see esdm_cuse_session_loop() */
	ESDM_CUSE_OPT("max_threads=%u", max_threads),
#ifdef ESDM_TESTMODE
	ESDM_CUSE_OPT("--disable_fallback=%d", disable_fallback),
#endif
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	FUSE_OPT_KEY("-S", 1),
	FUSE_OPT_KEY("--syslog", 1),
	FUSE_OPT_END
};
#pragma GCC diagnostic pop

static int esdm_cuse_process_arg(void *data, const char *arg, int key,
				 struct fuse_args *outargs)
{
	struct esdm_cuse_param *param = data;

	(void)outargs;
	(void)arg;

	switch (key) {
	case 0:
		param->is_help = 1;
		fprintf(stderr, "%s", usage);
		return fuse_opt_add_arg(outargs, "-ho");
	case 1:
		param->syslog = 1;
		return 0;
	default:
		return 1;
	}
}

static int esdm_cuse_session_loop(struct fuse_session *se,
				  unsigned int max_threads)
{
#ifdef ESDM_FUSE_LOOP_CONFIG
	struct fuse_loop_config *cfg = fuse_loop_cfg_create();
	int ret;

	if (!cfg)
		return -ENOMEM;

	fuse_loop_cfg_set_max_threads(cfg, max_threads ? max_threads :
							ESDM_CUSE_MAX_THREADS);
	fuse_loop_cfg_set_idle_threads(cfg, ESDM_CUSE_IDLE_THREADS);
	ret = fuse_session_loop_mt(se, cfg);
	fuse_loop_cfg_destroy(cfg);

	return ret;
#else
	/*
	 * Before 3.12, libfuse starts a worker whenever none is idle, there is
	 * no limit to set.
	 */
	if (max_threads)
		esdm_logger(LOGGER_WARN, LOGGER_C_CUSE,
			    "max_threads needs libfuse 3.12, ignored\n");

	return fuse_session_loop_mt(se, 0);
#endif
}

/*
 * Daemonize unless -f or -d asks otherwise, and have cuse_lowlevel_setup() run
 * in the foreground from then on.
 *
 * For --pid_namespace: daemonizing there would leave the namespace's PID 1 to
 * exit, which kills the namespace and the daemon in it, while the supervisor
 * reports success. So the process is daemonized before the fork into the
 * namespace, as esdm-server does, and the supervisor is what stays behind.
 */
static int esdm_cuse_daemonize(struct fuse_args *args)
{
	/* A copy, cuse_lowlevel_setup() parses the arguments as well */
	struct fuse_args tmp = FUSE_ARGS_INIT(args->argc, args->argv);
	struct fuse_cmdline_opts opts;
	int foreground;

	if (fuse_parse_cmdline(&tmp, &opts)) {
		fuse_opt_free_args(&tmp);
		return -EINVAL;
	}
	foreground = opts.foreground;
	free(opts.mountpoint);
	fuse_opt_free_args(&tmp);

	if (!foreground && fuse_daemonize(0))
		return -EFAULT;

	return fuse_opt_add_arg(args, "-f") ? -ENOMEM : 0;
}

int main_common(const char *_devname, const char *target, const char *semname,
		const struct cuse_lowlevel_ops *clop, int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct esdm_cuse_param param = { 0, 0, NULL, NULL, 1, 0, 0, 0, 0, 0 };
	char dev_name[128] = "DEVNAME=";
	char devname[20];
	const char *dev_info_argv[] = { dev_name };
	struct cuse_info ci;
	int ret = 1;

	if (fuse_opt_parse(&args, &param, esdm_cuse_opts,
			   esdm_cuse_process_arg)) {
		esdm_logger(LOGGER_ERR, LOGGER_C_CUSE,
			    "failed to parse option\n");
		free(param.dev_name);
		goto out;
	}

	esdm_logger_set_verbosity(param.verbosity);

	if (param.syslog) {
		esdm_logger_enable_syslog("esdm-cuse");
	}

	esdm_test_disable_fallback(param.disable_fallback);

	CKINT(esdm_cuse_file_name(devname, sizeof(devname), _devname));

	if (!param.is_help) {
		const char *dev_name_p = param.dev_name;

		/*
		 * The param.username is not freed - we allow this slight
		 * imprecise programming for now as the user name must be
		 * available for the duration of this process. Thus, let the
		 * kernel clean it up during program termination. Yet, we
		 * do not leak memory.
		 */
		if (param.username)
			esdm_cuse_unprivileged_user = param.username;

		if (!param.dev_name)
			dev_name_p = devname;

		strncat(dev_name, dev_name_p,
			sizeof(dev_name) - sizeof("DEVNAME="));

		if (target) {
			char devfile[128] = "/dev/";

			strncat(devfile, dev_name_p,
				sizeof(devfile) - sizeof("/dev/"));
			mount_src = strndup(devfile, sizeof(devfile));
			if (!mount_src)
				return -errno;
			mount_dst = strdup(target);
			if (!mount_dst) {
				int errsv = errno;

				free(mount_src);
				mount_src = NULL;
				return -errsv;
			}
		}

		if (param.dev_name)
			free(param.dev_name);
	}

	/*
	 * Clear supplemental groups once, while still running as (e)uid 0 and
	 * before the CUSE device is reachable by clients. See
	 * drop_supplemental_groups() for why this cannot be done during the
	 * transient privilege drop.
	 */
	if (geteuid() == 0)
		drop_supplemental_groups();

	CKINT_LOG(esdm_rpcc_init_unpriv_service(esdm_cuse_interrupt),
		  "Initialization of dispatcher failed\n");
	CKINT_LOG(esdm_rpcc_init_priv_service(esdm_cuse_interrupt),
		  "Initialization of dispatcher failed\n");

	/*
	 * Enter PID namespace (opt-in via --pid_namespace)
	 *
	 * The kernel reports the PID of a caller in the PID namespace that
	 * opens /dev/cuse, which libfuse does after this fork. A caller outside
	 * of it has no PID there, so none can be checked for CAP_SYS_ADMIN and
	 * the privileged ioctls are refused to every caller.
	 */
	if (param.pid_namespace && !param.is_help) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_CUSE,
			"PID namespace requested: the privileged ioctls (RNDADDTOENTCNT, RNDADDENTROPY, RNDCLEARPOOL, RNDZAPENTCNT, RNDRESEEDCRNG) are refused to every caller\n");
		CKINT(esdm_cuse_daemonize(&args));
		CKINT(linux_isolate_namespace_prefork(NULL));
	}

	/* One thread group */
	CKINT(thread_init(1));

	esdm_sem_name = semname;

	memset(&ci, 0, sizeof(ci));
	ci.dev_major = 0;
	ci.dev_minor = 0;
	ci.dev_info_argc = 1;
	ci.dev_info_argv = dev_info_argv;
	ci.flags = CUSE_UNRESTRICTED_IOCTL;

	esdm_cuse_install_sig_handler();

	/*
	 * Open-code cuse_lowlevel_main() so the session handle is reachable by
	 * the signal handler (via esdm_cuse_session), which exits the loop
	 * cleanly instead of running teardown from signal context. On loop
	 * return the ESDM-specific teardown runs below at out: in normal
	 * context.
	 */
	{
		int multithreaded = 0;
		struct fuse_session *se = cuse_lowlevel_setup(
			args.argc, args.argv, &ci, clop, &multithreaded, NULL);

		if (se == NULL) {
			ret = 1;
		} else {
			esdm_cuse_session = se;

			if (multithreaded)
				ret = esdm_cuse_session_loop(se,
							     param.max_threads);
			else
				ret = fuse_session_loop(se);

			esdm_cuse_session = NULL;
			cuse_lowlevel_teardown(se);
			ret = ret ? 1 : 0;
		}
	}

out:
	esdm_cuse_term();
	fuse_opt_free_args(&args);
	return ret;
}
