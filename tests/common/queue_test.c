/*
 * Test that a wakeup cannot be lost between the predicate check and the wait
 *
 * thread_wait_queue_wait_pred() checks the predicate of its caller under the
 * lock of the queue, right before the wait it decides on, and
 * thread_wake_all_locked() wakes the queue under that lock. A waker that sets
 * the predicate and wakes the queue while the waiter is between its check and
 * its wait must therefore still reach it. The check is made slow here so the
 * waker runs exactly in that window: a wakeup lost there would leave the
 * waiter sitting out its whole timeout.
 *
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

#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "queue.h"

/* Seconds the waiter waits at most - what a lost wakeup costs it */
#define QT_TIMEOUT 10

/* Seconds within which a delivered wakeup has to end the wait */
#define QT_WOKEN 5

static DECLARE_WAIT_QUEUE(qt_queue);

/* The predicate of the waiter */
static atomic_bool qt_flag = false;

/* The waiter is in its first check of the predicate */
static atomic_bool qt_checking = false;

static bool qt_pred(void *arg)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	static bool first = true;

	(void)arg;

	/*
	 * The first check finds the predicate false and takes its time, which
	 * is when the waker comes along.
	 */
	if (first) {
		first = false;
		atomic_store(&qt_checking, true);
		nanosleep(&ts, NULL);
		return false;
	}

	return atomic_load(&qt_flag);
}

static void *qt_waiter(void *arg)
{
	struct timespec deadline;
	int *ret = arg;

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += QT_TIMEOUT;

	do {
		*ret = thread_wait_queue_wait_pred(&qt_queue, &deadline,
						   qt_pred, NULL);
	} while (!*ret && !atomic_load(&qt_flag));

	return NULL;
}

int main(int argc, char *argv[])
{
	struct timespec start, end,
		slice = { .tv_sec = 0, .tv_nsec = 1000 * 1000 };
	pthread_t thread;
	int ret = -1;

	(void)argc;
	(void)argv;

	clock_gettime(CLOCK_MONOTONIC, &start);

	if (pthread_create(&thread, NULL, qt_waiter, &ret))
		return 1;

	while (!atomic_load(&qt_checking))
		nanosleep(&slice, NULL);

	/* The waiter found the predicate false and is not waiting yet */
	atomic_store(&qt_flag, true);
	thread_wake_all_locked(&qt_queue);

	pthread_join(thread, NULL);
	clock_gettime(CLOCK_MONOTONIC, &end);

	if (ret) {
		printf("the waiter timed out (%d) - the wakeup was lost\n",
		       ret);
		return 1;
	}

	if (end.tv_sec - start.tv_sec >= QT_WOKEN) {
		printf("the waiter took %lld seconds to see the wakeup\n",
		       (long long)(end.tv_sec - start.tv_sec));
		return 1;
	}

	printf("a wakeup between the check and the wait reached the waiter\n");

	/* A predicate that holds already is no reason to wait at all */
	clock_gettime(CLOCK_MONOTONIC, &end);
	end.tv_sec += QT_TIMEOUT;
	ret = thread_wait_queue_wait_pred(&qt_queue, &end, qt_pred, NULL);
	if (ret) {
		printf("the waiter waited (%d) with its predicate holding\n",
		       ret);
		return 1;
	}

	return 0;
}
