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

#ifndef TEST_MONITOR_H
#define TEST_MONITOR_H

#include <time.h>

#include "esdm.h"
#include "esdm_es_mgr.h"
#include "threading_support.h"

static int test_monitor_thread(void *unused)
{
	(void)unused;

	thread_set_name(es_monitor, 0);
	return esdm_init_monitor(NULL);
}

/*
 * Run the ES monitor as the server does: esdm_init_monitor() on a thread of
 * the ESDM_THREAD_ES_MONITOR group, after esdm_init(). It brings up the DRNGs
 * that are not fully seeded and runs until esdm_fini().
 *
 * Returns 0 once the monitor runs its rounds, 1 if it did not start.
 */
static inline int test_monitor_start(void)
{
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
	unsigned int i;

	if (!thread_available() && thread_init(1))
		return 1;
	if (thread_start(test_monitor_thread, NULL, ESDM_THREAD_ES_MONITOR,
			 NULL))
		return 1;

	for (i = 0; i < 30 * 100 && !esdm_es_mgr_monitor_active(); i++)
		nanosleep(&pause, NULL);

	return esdm_es_mgr_monitor_active() ? 0 : 1;
}

#endif /* TEST_MONITOR_H */
