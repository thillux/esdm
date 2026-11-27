/*
 * ESDM: system events reported by the kernel module esdm_es
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
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_events.h"
#include "esdm_es_ioctl.h"
#include "esdm_logger.h"
#include "esdm_shm_status.h"
#include "mutex.h"

/*
 * The descriptor of /dev/esdm_es, the eventfd that ends the thread and the
 * thread. The lock covers start and stop only: the thread owns its copies.
 */
static DEFINE_MUTEX_UNLOCKED(esdm_es_events_lock);
static int esdm_es_events_fd = -1;
static int esdm_es_events_stop_fd = -1;
static pthread_t esdm_es_events_thread;
static bool esdm_es_events_running = false;

static const char *const esdm_es_events_names[ESDM_ES_EVENT_LAST] = {
	[ESDM_ES_EVENT_VM_GENERATION] = "VM generation change",
	[ESDM_ES_EVENT_SUSPEND] = "suspend",
	[ESDM_ES_EVENT_RESUME] = "resume",
	[ESDM_ES_EVENT_SHUTDOWN] = "shutdown",
};

static bool esdm_es_events_occurred(uint32_t supported, const uint32_t *seen,
				    const uint32_t *now, unsigned int event)
{
	return (supported & (1U << event)) && seen[event] != now[event];
}

unsigned int esdm_es_events_handle(uint32_t supported, const uint32_t *seen,
				   const uint32_t *now)
{
	unsigned int i, handled = 0;

	for (i = 0; i < ESDM_ES_EVENT_LAST; i++) {
		if (!esdm_es_events_occurred(supported, seen, now, i))
			continue;

		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Kernel reports %s (count %u)\n",
			    esdm_es_events_names[i], now[i]);
		handled++;
	}

	/*
	 * Suspend and shutdown: tell the waiters of the status segment, as
	 * the suspend trigger of esdm-server-signal-helper does.
	 */
	if (esdm_es_events_occurred(supported, seen, now,
				    ESDM_ES_EVENT_SUSPEND) ||
	    esdm_es_events_occurred(supported, seen, now,
				    ESDM_ES_EVENT_SHUTDOWN))
		esdm_shm_status_suspend();

	/*
	 * A changed VM generation: this ESDM exists a second time, with every
	 * DRNG state, pool and entropy estimate. Nothing collected before is
	 * worth its credit any more: drop the entropy, take every DRNG back to
	 * not fully seeded and seed all of them anew. The kernel module reset
	 * its entropy sources before it counted the event, and the other ones
	 * deliver new data on request.
	 */
	if (esdm_es_events_occurred(supported, seen, now,
				    ESDM_ES_EVENT_VM_GENERATION)) {
		esdm_reset();
		esdm_force_fully_seeded_all_drbgs();
	} else if (esdm_es_events_occurred(supported, seen, now,
					   ESDM_ES_EVENT_RESUME)) {
		/*
		 * A resume: the state is still this ESDM's alone, but the
		 * time away is unknown. Reseed every DRNG before its next
		 * output, as esdm-server-signal-helper --resume does. Not
		 * needed after the reset above, which leaves nothing to
		 * reseed.
		 */
		esdm_drng_force_reseed();
	}

	return handled;
}

static int esdm_es_events_read(int fd, uint32_t *supported, uint32_t *counts)
{
	uint32_t words[ESDM_ES_EVENTS_WORDS];

	if (ioctl(fd, ESDM_ES_EVENTS, words) < 0)
		return -errno;

	*supported = words[0];
	memcpy(counts, &words[1], sizeof(words) - sizeof(words[0]));

	return 0;
}

struct esdm_es_events_arg {
	int fd;
	int stop_fd;
	uint32_t seen[ESDM_ES_EVENT_LAST];
};

static struct esdm_es_events_arg esdm_es_events_arg;

static void *esdm_es_events_worker(void *data)
{
	struct esdm_es_events_arg *arg = data;
	struct pollfd fds[2] = {
		{ .fd = arg->fd, .events = POLLIN },
		{ .fd = arg->stop_fd, .events = POLLIN },
	};

	pthread_setname_np(pthread_self(), "esdm-events");

	for (;;) {
		uint32_t supported, now[ESDM_ES_EVENT_LAST];
		int ret = poll(fds, 2, -1);

		if (ret < 0 && errno == EINTR)
			continue;
		if (ret < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ES,
				    "Waiting for kernel events failed: %s\n",
				    strerror(errno));
			break;
		}

		if (fds[1].revents)
			break;

		/* The module is gone */
		if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
			esdm_logger(LOGGER_WARN, LOGGER_C_ES,
				    "Kernel no longer reports system events\n");
			break;
		}

		ret = esdm_es_events_read(arg->fd, &supported, now);
		if (ret) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ES,
				    "Reading the kernel events failed: %s\n",
				    strerror(-ret));
			break;
		}

		esdm_es_events_handle(supported, arg->seen, now);
		memcpy(arg->seen, now, sizeof(now));
	}

	return NULL;
}

void esdm_es_events_start(void)
{
	struct esdm_es_events_arg *arg = &esdm_es_events_arg;
	sigset_t all, old;
	uint32_t supported;
	int fd = -1, stop_fd = -1, ret;

	mutex_lock(&esdm_es_events_lock);

	if (esdm_es_events_running)
		goto out;

	/*
	 * A descriptor kept from an earlier start is used again: opening the
	 * device takes CAP_SYS_ADMIN, which is gone after the privilege drop.
	 */
	fd = esdm_es_events_fd;
	if (fd < 0)
		fd = open("/dev/esdm_es", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"Kernel module esdm_es not present: no system events from the kernel\n");
		goto out;
	}

	/* The counts at the start: only what follows is an event */
	ret = esdm_es_events_read(fd, &supported, arg->seen);
	if (ret) {
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ES,
			"Kernel module esdm_es does not report system events: %s\n",
			strerror(-ret));
		goto err;
	}

	stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (stop_fd < 0) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "No eventfd for the kernel event thread: %s\n",
			    strerror(errno));
		goto err;
	}

	arg->fd = fd;
	arg->stop_fd = stop_fd;

	/*
	 * No signal in this thread: the handlers of the process belong to the
	 * threads that expect them.
	 */
	sigfillset(&all);
	pthread_sigmask(SIG_BLOCK, &all, &old);
	ret = pthread_create(&esdm_es_events_thread, NULL,
			     esdm_es_events_worker, arg);
	pthread_sigmask(SIG_SETMASK, &old, NULL);
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Cannot start the kernel event thread: %s\n",
			    strerror(ret));
		goto err;
	}

	esdm_es_events_fd = fd;
	esdm_es_events_stop_fd = stop_fd;
	esdm_es_events_running = true;

	esdm_logger(
		LOGGER_VERBOSE, LOGGER_C_ES,
		"Kernel module esdm_es reports system events:%s%s%s%s\n",
		(supported & (1U << ESDM_ES_EVENT_VM_GENERATION)) ?
			" VM generation" :
			"",
		(supported & (1U << ESDM_ES_EVENT_SUSPEND)) ? " suspend" : "",
		(supported & (1U << ESDM_ES_EVENT_RESUME)) ? " resume" : "",
		(supported & (1U << ESDM_ES_EVENT_SHUTDOWN)) ? " shutdown" :
							       "");
	goto out;

err:
	if (stop_fd >= 0)
		close(stop_fd);
	/* Kept if it was kept before: it cannot be opened again */
	if (fd >= 0 && fd != esdm_es_events_fd)
		close(fd);
out:
	mutex_unlock(&esdm_es_events_lock);
}

void esdm_es_events_stop(void)
{
	uint64_t one = 1;

	mutex_lock(&esdm_es_events_lock);

	if (!esdm_es_events_running)
		goto out;

	if (write(esdm_es_events_stop_fd, &one, sizeof(one)) ==
	    (ssize_t)sizeof(one)) {
		pthread_join(esdm_es_events_thread, NULL);
	} else {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "Cannot stop the kernel event thread: %s\n",
			    strerror(errno));
	}

	close(esdm_es_events_stop_fd);
	esdm_es_events_stop_fd = -1;
	esdm_es_events_running = false;

	/*
	 * The device stays open: a later start, after esdm_reinit(), may run
	 * without the privilege to open it.
	 */
out:
	mutex_unlock(&esdm_es_events_lock);
}
