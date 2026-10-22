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
 * Tests for the ESDM auxiliary client library.
 *
 * This is the interface an external entropy provider uses: attach, sleep until
 * the ESDM wants entropy, insert some, repeat. It needs neither privileges nor
 * a running server, so what is covered here is the behaviour a provider meets
 * before and without a server, which is what its documented timeout exists
 * for - and how it finds the server's semaphore and shared memory segment,
 * which this test creates the way the server does.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "esdm_aux_client.h"
#include "esdm_rpc_service.h"

static double elapsed_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return ((double)now.tv_sec - (double)start->tv_sec) +
	       ((double)now.tv_nsec - (double)start->tv_nsec) / 1e9;
}

/* Build the absolute CLOCK_MONOTONIC deadline the API takes */
static void deadline_in(struct timespec *ts, time_t sec)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
	ts->tv_sec += sec;
}

static void test_wait_without_init(void)
{
	struct timespec ts;
	int rc;

	deadline_in(&ts, 1);

	/*
	 * Waiting before attaching is a caller error, and it is reported as one
	 * rather than blocking on a semaphore that was never opened.
	 */
	errno = 0;
	rc = esdm_aux_timedwait_for_need_entropy(&ts);
	CHECK_EQ(rc, -1);
	CHECK_EQ(errno, EINVAL);
}

static void test_init_fini(void)
{
	/* Detaching without attaching first is a no-op, not a crash */
	esdm_aux_fini_wait_for_need_entropy();

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	esdm_aux_fini_wait_for_need_entropy();

	/* and detaching twice does not take the second one down either */
	esdm_aux_fini_wait_for_need_entropy();

	/* The whole cycle can be repeated - a provider may reconnect */
	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	esdm_aux_fini_wait_for_need_entropy();
}

/*
 * The documented contract: the call returns at the timeout even though the
 * semaphore did not fire. A provider started before the ESDM server - the
 * ordinary case under one service manager - depends on that to notice and
 * retry. Run in a child with a hard bound, so a wait that never returns fails
 * the test instead of hanging it.
 */
static void test_wait_honours_timeout(void)
{
	static const unsigned int bound_sec = 10;
	struct timespec start;
	int status;
	pid_t pid;

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);

	clock_gettime(CLOCK_MONOTONIC, &start);

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	if (!pid) {
		struct timespec ts;
		int rc;

		deadline_in(&ts, 1);
		alarm(bound_sec);
		errno = 0;
		rc = esdm_aux_timedwait_for_need_entropy(&ts);
		/* No server, so nothing can have signalled: it must time out */
		_exit(rc == -1 && errno == ETIMEDOUT ? 0 : 1);
	}

	if (waitpid(pid, &status, 0) != pid) {
		CHECK(0, "waitpid() failed: %s", strerror(errno));
		return;
	}

	if (!WIFEXITED(status)) {
		CHECK(0,
		      "the timed wait did not return within %u s although a 1 s timeout was given - it blocks until an ESDM server shows up (elapsed %.1f s)",
		      bound_sec, elapsed_since(&start));
	} else {
		CHECK(elapsed_since(&start) < (double)bound_sec,
		      "the timed wait took %.1f s for a 1 s timeout",
		      elapsed_since(&start));
		CHECK_EQ(WEXITSTATUS(status), 0);
	}

	esdm_aux_fini_wait_for_need_entropy();
}

/*
 * What the server creates: the status segment, attached to for as long as it
 * runs, and the semaphore it posts when it wants entropy.
 */
struct test_server {
	int shmid;
	struct esdm_shm_status *status;
	sem_t *sem;
};

static int test_server_start(struct test_server *srv, bool need_entropy)
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	void *tmp;

	srv->shmid = shmget(key, sizeof(struct esdm_shm_status),
			    IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IRGRP |
				    S_IROTH);
	if (srv->shmid < 0) {
		CHECK(0, "cannot create the status segment: %s",
		      strerror(errno));
		return 1;
	}

	tmp = shmat(srv->shmid, NULL, 0);
	if (tmp == (void *)-1) {
		CHECK(0, "cannot attach the status segment: %s",
		      strerror(errno));
		shmctl(srv->shmid, IPC_RMID, NULL);
		return 1;
	}
	srv->status = tmp;

	srv->sem = sem_open(ESDM_SEM_NEED_ENTROPY_LEVEL, O_CREAT | O_EXCL,
			    0644, 0);
	if (srv->sem == SEM_FAILED) {
		CHECK(0, "cannot create the semaphore: %s", strerror(errno));
		shmdt(srv->status);
		shmctl(srv->shmid, IPC_RMID, NULL);
		return 1;
	}

	atomic_store(&srv->status->need_entropy, need_entropy);
	srv->status->version = ESDM_SHM_STATUS_VERSION;

	return 0;
}

/* A server that exits and removes what it created */
static void test_server_stop(struct test_server *srv)
{
	srv->status->version = 0;
	atomic_store(&srv->status->need_entropy, false);
	shmdt(srv->status);
	shmctl(srv->shmid, IPC_RMID, NULL);
	sem_close(srv->sem);
	sem_unlink(ESDM_SEM_NEED_ENTROPY_LEVEL);
}

/* Wait for at most msec, returning what the wait returned and its errno */
static int timedwait_ms(long msec, int *errsv)
{
	struct timespec ts;
	int rc;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	ts.tv_sec += msec / 1000;
	ts.tv_nsec += (msec % 1000) * 1000000;
	if (ts.tv_nsec >= 1000000000) {
		ts.tv_sec++;
		ts.tv_nsec -= 1000000000;
	}

	errno = 0;
	rc = esdm_aux_timedwait_for_need_entropy(&ts);
	*errsv = errno;

	return rc;
}

/*
 * A provider started before the server creates nothing: the server would
 * remove a segment of another user as one planted on it, and the provider
 * would keep waiting on that one.
 */
static void test_creates_nothing(void)
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	sem_t *sem;
	int errsv;

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	CHECK_EQ(timedwait_ms(100, &errsv), -1);
	CHECK_EQ(errsv, ETIMEDOUT);

	CHECK(shmget(key, sizeof(struct esdm_shm_status), 0) < 0 &&
		      errno == ENOENT,
	      "the client created the status segment");

	sem = sem_open(ESDM_SEM_NEED_ENTROPY_LEVEL, 0);
	CHECK(sem == SEM_FAILED && errno == ENOENT,
	      "the client created the semaphore");
	if (sem != SEM_FAILED) {
		sem_close(sem);
		sem_unlink(ESDM_SEM_NEED_ENTROPY_LEVEL);
	}

	esdm_aux_fini_wait_for_need_entropy();
}

/*
 * The server starts after the provider, and is restarted later on. Either
 * time, the provider finds what the server created.
 */
static void test_finds_server(void)
{
	struct test_server srv;
	int errsv;

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);

	if (test_server_start(&srv, false))
		goto out;

	/* Attached now, and the server does not want entropy */
	CHECK_EQ(timedwait_ms(200, &errsv), -1);
	CHECK_EQ(errsv, ETIMEDOUT);

	/* The semaphore wakes the provider */
	sem_post(srv.sem);
	CHECK_EQ(timedwait_ms(2000, &errsv), 0);

	/* And so does the flag in the segment */
	atomic_store(&srv.status->need_entropy, true);
	CHECK_EQ(timedwait_ms(2000, &errsv), 0);

	/*
	 * The server restarts, removing the segment and the semaphore and
	 * creating both anew. Only the new semaphore is posted, which the
	 * provider only sees when it let go of the old ones.
	 */
	test_server_stop(&srv);
	if (test_server_start(&srv, false))
		goto out;
	sem_post(srv.sem);
	CHECK_EQ(timedwait_ms(3000, &errsv), 0);

	/* The same with the flag of the new segment */
	atomic_store(&srv.status->need_entropy, true);
	CHECK_EQ(timedwait_ms(3000, &errsv), 0);

	test_server_stop(&srv);

out:
	esdm_aux_fini_wait_for_need_entropy();
}

/*
 * A segment nobody is attached to is what a server that died left behind.
 * Whatever it says is not the state of a running server.
 */
static void test_ignores_leftover(void)
{
	struct test_server srv;
	int errsv;

	if (test_server_start(&srv, true))
		return;
	shmdt(srv.status);

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	CHECK_EQ(timedwait_ms(200, &errsv), -1);
	CHECK_EQ(errsv, ETIMEDOUT);
	esdm_aux_fini_wait_for_need_entropy();

	shmctl(srv.shmid, IPC_RMID, NULL);
	sem_close(srv.sem);
	sem_unlink(ESDM_SEM_NEED_ENTROPY_LEVEL);
}

/*
 * A segment another user created while no server runs, and keeps attached to,
 * telling that the ESDM wants entropy. The server removes it once it starts,
 * until then the client must not take it for the server's. Creating it as
 * another user needs root: in the user namespace of an unprivileged run, no
 * other uid is mapped.
 */
static void test_ignores_planted(void)
{
	key_t key = esdm_ftok(ESDM_SHM_NAME, ESDM_SHM_STATUS);
	struct esdm_shm_status *status;
	int shmid, errsv, wstatus;
	pid_t pid;

	if (geteuid()) {
		printf("aux_client: planted segment not covered, needs root\n");
		return;
	}

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		return;
	}

	/* The other user, who creates the segment writable for everybody */
	if (!pid) {
		if (setgid(65534) || setuid(65534))
			_exit(1);
		_exit(shmget(key, sizeof(struct esdm_shm_status),
			     IPC_CREAT | IPC_EXCL | 0666) < 0 ?
			      2 :
			      0);
	}

	if (waitpid(pid, &wstatus, 0) != pid || !WIFEXITED(wstatus) ||
	    WEXITSTATUS(wstatus)) {
		CHECK(0, "cannot create the segment as another user");
		return;
	}

	shmid = shmget(key, sizeof(struct esdm_shm_status), 0);
	if (shmid < 0) {
		CHECK(0, "the planted segment is gone: %s", strerror(errno));
		return;
	}

	/* Attached to, so it looks like a running server's */
	status = shmat(shmid, NULL, 0);
	if (status == (void *)-1) {
		CHECK(0, "cannot attach the segment: %s", strerror(errno));
		shmctl(shmid, IPC_RMID, NULL);
		return;
	}
	atomic_store(&status->need_entropy, true);
	status->version = ESDM_SHM_STATUS_VERSION;

	CHECK_EQ(esdm_aux_init_wait_for_need_entropy(), 0);
	CHECK_EQ(timedwait_ms(200, &errsv), -1);
	CHECK_EQ(errsv, ETIMEDOUT);
	esdm_aux_fini_wait_for_need_entropy();

	shmdt(status);
	shmctl(shmid, IPC_RMID, NULL);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	test_wait_without_init();
	test_init_fini();
	test_wait_honours_timeout();
	test_creates_nothing();
	test_finds_server();
	test_ignores_leftover();
	test_ignores_planted();

	return common_test_result("aux_client");
}
