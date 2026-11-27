/*
 * System events reported by the kernel module esdm_es
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

/*
 * The system events the kernel module esdm_es reports: a resume has every
 * DRNG reseed before its next output, a changed VM generation drops the
 * entropy and seeds every DRNG anew, an event the kernel does not report or
 * that did not occur changes nothing. The events are handed to
 * esdm_es_events_handle() as the thread reading /dev/esdm_es would.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_events.h"
#include "esdm_es_ioctl.h"
#include "esdm_logger.h"

#ifdef ESDM_TESTMODE

#define EV_MAX_DRNGS 16
#define EV_ALL ((1U << ESDM_ES_EVENT_LAST) - 1)

struct ev_state {
	long long seed_generation[EV_MAX_DRNGS];
	bool fully_seeded[EV_MAX_DRNGS];
	bool force_reseed[EV_MAX_DRNGS];
	bool pr[EV_MAX_DRNGS];
	unsigned int n;
};

static void ev_state_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct ev_state *state = priv;

	if (state->n >= EV_MAX_DRNGS || !stats->drng_name)
		return;

	state->seed_generation[state->n] = stats->seed_generation;
	state->fully_seeded[state->n] = stats->fully_seeded;
	state->force_reseed[state->n] = stats->force_reseed;
	state->pr[state->n] = !strcmp(stats->type, "prediction resistance");
	state->n++;
}

static void ev_state_get(struct ev_state *state)
{
	memset(state, 0, sizeof(*state));
	esdm_drng_stats_foreach(ev_state_cb, state);
}

static int ev_unchanged(const char *what, const struct ev_state *a,
			const struct ev_state *b)
{
	if (a->n != b->n || memcmp(a->seed_generation, b->seed_generation,
				   sizeof(a->seed_generation)) ||
	    memcmp(a->force_reseed, b->force_reseed, sizeof(a->force_reseed))) {
		printf("FAIL: %s changed the DRNGs\n", what);
		return 1;
	}

	return 0;
}

static int ev_test(void)
{
	uint32_t seen[ESDM_ES_EVENT_LAST] = { 0 }, now[ESDM_ES_EVENT_LAST];
	struct ev_state before, after;
	uint8_t buf[32];
	unsigned int i, forced = 0;
	int ret = 0;

	if (esdm_init()) {
		printf("FAIL: esdm_init failed\n");
		return 1;
	}

	esdm_force_fully_seeded_all_drbgs();
	if (!esdm_state_operational()) {
		printf("SKIP: the ESDM does not get operational here\n");
		ret = 77;
		goto out;
	}

	/* Nothing occurred */
	ev_state_get(&before);
	memcpy(now, seen, sizeof(now));
	if (esdm_es_events_handle(EV_ALL, seen, now)) {
		printf("FAIL: an event handled although none occurred\n");
		ret = 1;
	}
	ev_state_get(&after);
	ret |= ev_unchanged("no event", &before, &after);

	/* A count the kernel does not vouch for */
	now[ESDM_ES_EVENT_VM_GENERATION] = 1;
	now[ESDM_ES_EVENT_RESUME] = 1;
	if (esdm_es_events_handle(0, seen, now)) {
		printf("FAIL: an unsupported event was handled\n");
		ret = 1;
	}
	ev_state_get(&after);
	ret |= ev_unchanged("an unsupported event", &before, &after);

	/* Suspend and shutdown reseed nothing */
	memcpy(now, seen, sizeof(now));
	now[ESDM_ES_EVENT_SUSPEND] = 1;
	now[ESDM_ES_EVENT_SHUTDOWN] = 1;
	if (esdm_es_events_handle(EV_ALL, seen, now) != 2) {
		printf("FAIL: suspend and shutdown not handled\n");
		ret = 1;
	}
	ev_state_get(&after);
	ret |= ev_unchanged("suspend and shutdown", &before, &after);

	/* Resume: every fully seeded DRNG but the PR one is to reseed */
	memcpy(now, seen, sizeof(now));
	now[ESDM_ES_EVENT_RESUME] = 1;
	if (esdm_es_events_handle(EV_ALL, seen, now) != 1) {
		printf("FAIL: resume not handled\n");
		ret = 1;
	}
	ev_state_get(&after);
	for (i = 0; i < after.n; i++)
		forced += after.force_reseed[i];
	if (!forced) {
		printf("FAIL: resume forces no DRNG to reseed\n");
		ret = 1;
	}
	if (esdm_get_random_bytes_full(buf, sizeof(buf)) !=
	    (ssize_t)sizeof(buf)) {
		printf("FAIL: no data after resume\n");
		ret = 1;
	}

	/* VM generation: every DRNG starts over and is seeded anew */
	ev_state_get(&before);
	memcpy(now, seen, sizeof(now));
	now[ESDM_ES_EVENT_VM_GENERATION] = 1;
	now[ESDM_ES_EVENT_RESUME] = 2;
	if (esdm_es_events_handle(EV_ALL, seen, now) != 2) {
		printf("FAIL: VM generation change not handled\n");
		ret = 1;
	}
	ev_state_get(&after);
	for (i = 0; i < after.n && i < before.n; i++) {
		/* The PR DRNG is seeded by its next request only */
		if (after.pr[i]) {
			if (after.fully_seeded[i]) {
				printf("FAIL: PR DRNG still fully seeded after a VM generation change\n");
				ret = 1;
			}
			continue;
		}

		printf("DRNG %u: seed generation %lld -> %lld, fully seeded %d\n",
		       i, before.seed_generation[i], after.seed_generation[i],
		       after.fully_seeded[i]);
		if (after.seed_generation[i] <= before.seed_generation[i] ||
		    !after.fully_seeded[i]) {
			printf("FAIL: DRNG %u not seeded anew after a VM generation change\n",
			       i);
			ret = 1;
		}
	}
	if (!esdm_state_operational()) {
		printf("FAIL: not operational after the reseed following a VM generation change\n");
		ret = 1;
	}
	if (esdm_get_random_bytes_full(buf, sizeof(buf)) !=
	    (ssize_t)sizeof(buf) ||
	    esdm_get_random_bytes_pr(buf, sizeof(buf)) <= 0) {
		printf("FAIL: no data after a VM generation change\n");
		ret = 1;
	}

out:
	esdm_fini();
	return ret;
}

#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	esdm_logger_set_verbosity(LOGGER_NONE);
	return ev_test();
#else
	return 77;
#endif
}
