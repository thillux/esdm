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

#ifndef TEST_WAIT_SEEDED_H
#define TEST_WAIT_SEEDED_H

#include <time.h>

#include "esdm.h"

/*
 * Generous: seeding normally takes a fraction of a second, but under a
 * sanitizer or an emulated CPU it can take many times that, and the timeout
 * only matters when the ESDM does not get there at all.
 */
#define TEST_SEED_WAIT_SECONDS 60

/*
 * Wait for the ESDM to reach the fully seeded state, which the seeding
 * thread a request kicks off reaches asynchronously. Polls rather than
 * sleeping a fixed time, which is both slower than needed on a fast machine
 * and too short on a slow one.
 *
 * Returns 0 once fully seeded, 1 if that did not happen within the timeout.
 */
static inline int test_wait_fully_seeded(void)
{
	static const long poll_ms = 10;
	struct timespec pause = { .tv_sec = 0,
				  .tv_nsec = poll_ms * 1000L * 1000L };
	long waited;

	for (waited = 0; waited < TEST_SEED_WAIT_SECONDS * 1000L;
	     waited += poll_ms) {
		if (esdm_state_fully_seeded())
			return 0;
		nanosleep(&pause, NULL);
	}

	return esdm_state_fully_seeded() ? 0 : 1;
}

#endif /* TEST_WAIT_SEEDED_H */
