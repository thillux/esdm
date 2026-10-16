/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <semaphore.h>
#include <stdbool.h>
#include <string.h>
#include <sys/shm.h>
#include <time.h>

#include "esdm_aux_client.h"
#include "esdm_logger.h"
#include "helper.h"
#include "esdm_rpc_service.h"
#include "visibility.h"

/******************************************************************************
 * Shared memory segment
 *
 * The status segment and the semaphore belong to the ESDM server: it creates
 * them, and it removes a segment that another user created, which is how a
 * planted one is kept from steering the clients. So a client never creates
 * either - one it created before the server started would be removed under it,
 * and it would wait on a segment nobody writes any more. It attaches to what
 * the server created instead, and does so again whenever the server removed or
 * replaced it, e.g. when it was restarted.
 ******************************************************************************/
static struct esdm_shm_status *esdm_cuse_shm_status = NULL;
static int esdm_cuse_shmid = -1;
static sem_t *esdm_semid_need_entropy_level = SEM_FAILED;
static bool esdm_semid_need_entropy_level_tried = false;
static bool esdm_aux_initialized = false;

static int esdm_cuse_shm_status_avail(void)
{
	static int initialized = 0;
	int ret = (esdm_cuse_shm_status &&
		   esdm_cuse_shm_status->version == ESDM_SHM_STATUS_VERSION);

	if (ret && !initialized) {
		initialized = 1;
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_CUSE,
			"A client started detected ESDM server with properties:\n%.*s\n",
			(int)sizeof(esdm_cuse_shm_status->info),
			esdm_cuse_shm_status->info);
	}

	return ret;
}

static void esdm_cuse_shm_status_close_sem(void)
{
	if (esdm_semid_need_entropy_level != SEM_FAILED) {
		sem_t *tmp = esdm_semid_need_entropy_level;

		esdm_semid_need_entropy_level = SEM_FAILED;
		sem_close(tmp);
	}
}

static void esdm_cuse_shm_status_close_shm(void)
{
	if (esdm_cuse_shm_status) {
		shmdt(esdm_cuse_shm_status);
		esdm_cuse_shm_status = NULL;
	}
	esdm_cuse_shmid = -1;

	/* The semaphore goes with the segment the server created it with */
	esdm_cuse_shm_status_close_sem();
	esdm_semid_need_entropy_level_tried = false;
}

/*
 * Attach to the segment the server created, unless it is the one attached to
 * already. A segment that is gone, or that is another one now, is let go of.
 */
static void esdm_cuse_shm_status_attach_shm(void)
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	struct shmid_ds buf;
	int shmid;
	void *tmp;

	/* No IPC_CREAT: there is no segment until the server created it */
	shmid = shmget(key, sizeof(struct esdm_shm_status), 0);

	/*
	 * Removing a segment takes its key away at once, and a segment created
	 * anew under the key gets an identifier of its own.
	 */
	if (shmid >= 0 && shmid == esdm_cuse_shmid)
		return;

	esdm_cuse_shm_status_close_shm();

	if (shmid < 0)
		return;

	/*
	 * Nobody is attached to it, so no server writes it: it is what a server
	 * that died left behind. Its contents tell nothing about the current
	 * state, and removing it is up to the next server.
	 */
	if (shmctl(shmid, IPC_STAT, &buf) < 0 || buf.shm_nattch == 0)
		return;

	/*
	 * Somebody else may have created the segment while the server does
	 * not run, and stay attached to it - the server only removes it once
	 * it starts. Its contents would tell the client whatever its creator
	 * likes. It is checked again on the next call, when the server may
	 * have replaced it.
	 */
	if (!esdm_shm_created_by_server(&buf, ESDM_RPC_UNPRIV_SOCKET)) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ANY,
			"Shared memory segment not created by the ESDM server ignored\n");
		return;
	}

	/*
	 * Read-only: a client only reads the segment, and the server creates it
	 * writable for its own user only.
	 */
	tmp = shmat(shmid, NULL, SHM_RDONLY);
	if (tmp == (void *)-1) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "Attaching to shared memory segment failed: %s\n",
			    strerror(errno));
		return;
	}

	esdm_cuse_shm_status = tmp;
	esdm_cuse_shmid = shmid;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM shared memory segment successfully attached to\n");
}

/******************************************************************************
 * Semaphore for shared memory segment
 ******************************************************************************/

/*
 * Open the semaphore the server created with the segment. It is there once the
 * server published its status, which it does only after it created both - so
 * it is tried once per segment.
 *
 * Opening it takes write access, which the server grants its own user only. A
 * client running as another one waits by watching the segment instead.
 */
static void esdm_cuse_shm_status_open_sem(void)
{
	if (esdm_semid_need_entropy_level_tried ||
	    !esdm_cuse_shm_status_avail())
		return;
	esdm_semid_need_entropy_level_tried = true;

	/* No O_CREAT, for the same reason as for the segment */
	esdm_semid_need_entropy_level =
		sem_open(ESDM_SEM_NEED_ENTROPY_LEVEL, 0);
	if (esdm_semid_need_entropy_level == SEM_FAILED) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
			    "ESDM change indicator semaphore not usable: %s\n",
			    strerror(errno));
		return;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "ESDM change indicator semaphore initialized\n");
}

/* Whether a is before b */
static bool esdm_cuse_ts_before(const struct timespec *a,
				const struct timespec *b)
{
	return a->tv_sec < b->tv_sec ||
	       (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec);
}

static int esdm_cuse_shm_status_down(struct timespec *ts)
{
	/*
	 * How long one wait lasts at most before the segment is checked
	 * again. Without the semaphore, the segment is all there is to watch.
	 */
	static const long poll_nsec = 50 * 1000 * 1000;
	static const time_t sem_sec = 1;

	if (!esdm_aux_initialized) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY, "Cannot use semaphore\n");
		errno = EINVAL;
		return -1;
	}

	/*
	 * Wait for a server to publish its status in the SHM segment, but no
	 * longer than the caller allowed: an unbounded wait would make the
	 * documented timeout unreachable while no server runs, which is exactly
	 * when a caller needs it. @ts is the absolute CLOCK_MONOTONIC deadline
	 * of the sem_clockwait() below, so the same deadline applies here and
	 * the timeout is reported the same way.
	 *
	 * The wait is cut into slices, between which the segment is attached
	 * anew should the server have replaced it: the semaphore of the server
	 * that is gone would never fire again.
	 */
	for (;;) {
		struct timespec now, until;

		esdm_cuse_shm_status_attach_shm();
		esdm_cuse_shm_status_open_sem();

		/*
		 * If the ESDM server already indicates it needs entropy,
		 * return immediately.
		 */
		if (esdm_cuse_shm_status_avail() &&
		    atomic_load(&esdm_cuse_shm_status->need_entropy))
			return 0;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (!esdm_cuse_ts_before(&now, ts)) {
			errno = ETIMEDOUT;
			return -1;
		}

		until = now;
		if (esdm_semid_need_entropy_level != SEM_FAILED) {
			until.tv_sec += sem_sec;
		} else {
			until.tv_nsec += poll_nsec;
			if (until.tv_nsec >= 1000000000) {
				until.tv_sec++;
				until.tv_nsec -= 1000000000;
			}
		}
		if (esdm_cuse_ts_before(ts, &until))
			until = *ts;

		if (esdm_semid_need_entropy_level == SEM_FAILED) {
			clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until,
					NULL);
			continue;
		}

		/*
		 * sem_timedwait uses CLOCK_REALTIME, which is subject to
		 * clock adjustments, use sem_clockwait instead here.
		 */
		if (!sem_clockwait(esdm_semid_need_entropy_level,
				   CLOCK_MONOTONIC, &until))
			return 0;
		if (errno != ETIMEDOUT)
			return -1;
	}
}

DSO_PUBLIC
int esdm_aux_init_wait_for_need_entropy(void)
{
	/*
	 * Nothing to create: what the server has not created yet is attached
	 * to by the wait, once it has.
	 */
	esdm_aux_initialized = true;
	esdm_cuse_shm_status_attach_shm();
	esdm_cuse_shm_status_open_sem();

	return 0;
}

DSO_PUBLIC
void esdm_aux_fini_wait_for_need_entropy(void)
{
	esdm_cuse_shm_status_close_shm();
	esdm_aux_initialized = false;
}

DSO_PUBLIC
int esdm_aux_timedwait_for_need_entropy(struct timespec *ts)
{
	return esdm_cuse_shm_status_down(ts);
}
