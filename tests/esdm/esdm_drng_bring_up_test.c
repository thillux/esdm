/*
 * Test of the bring-up of the DRNGs by the ES monitor
 *
 * All without a single request being made: every DRNG that is not fully
 * seeded is brought up by the monitor - nothing else does that for an instance
 * no request lands on -, the prediction resistance instance is instantiated
 * and left alone after that, since each of its outputs collects the seed it is
 * generated from in the request, and after a reset all of them are brought up
 * again. The seed times of the node DRNGs are spread, and that spread stays
 * within the reseed interval.
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

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "ret_checkers.h"
#include "test_monitor.h"

#ifdef ESDM_TESTMODE

/* Number of DRNG instances asked for - the ESDM caps this to its node count */
#define ESDM_BU_NODES 4

/* Wait for the monitor at most this many 100ms slices */
#define ESDM_BU_SLICES 200

/*
 * Slices the prediction resistance DRNG is watched over: several rounds of the
 * monitor, any of which could have reseeded it.
 */
#define ESDM_BU_PR_SLICES 30

/*
 * Reseed interval the spread of the seed times is observed with: a tenth of it
 * is what the spread draws from.
 */
#define ESDM_BU_STAGGER_INTERVAL 600

/* What the statistics say about the DRNGs, as one snapshot */
struct bu_state {
	/* Instances serving ordinary requests */
	unsigned int nodes;
	unsigned int nodes_unseeded;
	/* The prediction resistance instance */
	bool pr_found;
	bool pr_initiated;
	long long pr_seed_generation;
	/* The node DRNGs besides the initial one */
	unsigned int node_drngs;
	/* The latest reseed any of those reports */
	long long latest_node_reseed;
};

static void bu_state_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct bu_state *state = (struct bu_state *)priv;

	if (stats->pr) {
		state->pr_found = true;
		state->pr_initiated = stats->initiated;
		state->pr_seed_generation = stats->seed_generation;
		return;
	}

	state->nodes++;
	if (!stats->fully_seeded)
		state->nodes_unseeded++;

	if (!strcmp(stats->type, "node")) {
		state->node_drngs++;
		if (stats->seconds_until_reseed > state->latest_node_reseed)
			state->latest_node_reseed = stats->seconds_until_reseed;
	}
}

static struct bu_state bu_state_get(void)
{
	struct bu_state state;

	memset(&state, 0, sizeof(state));
	esdm_drng_stats_foreach(bu_state_cb, &state);

	return state;
}

static void bu_sleep_slice(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* Wait until the monitor brought up every DRNG */
static int bu_wait_up(const char *when)
{
	struct bu_state state;
	unsigned int i;

	for (i = 0; i < ESDM_BU_SLICES; i++) {
		state = bu_state_get();
		if (!state.nodes_unseeded && state.pr_initiated)
			break;
		bu_sleep_slice();
	}

	state = bu_state_get();
	if (state.nodes_unseeded || !state.pr_initiated) {
		printf("%s: %u of %u DRNG instances not seeded, the prediction resistance DRNG %sinstantiated\n",
		       when, state.nodes_unseeded, state.nodes,
		       state.pr_initiated ? "" : "not ");
		return 1;
	}

	printf("%s: the monitor brought up every DRNG instance after %u slice(s)\n",
	       when, i + 1);
	return 0;
}

static int esdm_drng_bring_up_test(void)
{
	struct bu_state before, after;
	unsigned int i;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * Ask for more than one instance: what is under test is what happens
	 * to the ones no request ever lands on, and with a single DRNG there
	 * are none of those. The ESDM caps this to the nodes it sees.
	 */
	esdm_config_max_nodes_set(ESDM_BU_NODES);

	CKINT(esdm_init());

	before = bu_state_get();
	if (!before.nodes || !before.pr_found) {
		printf("the statistics report %u DRNGs and %s prediction resistance instance\n",
		       before.nodes, before.pr_found ? "a" : "no");
		goto err;
	}

	printf("%u DRNG instance(s), %u of them not seeded yet\n", before.nodes,
	       before.nodes_unseeded);

	esdm_set_reseed_max_time(ESDM_BU_STAGGER_INTERVAL);

	/* Nothing is requested from here on */
	if (test_monitor_start()) {
		printf("the ES monitor did not start\n");
		goto err;
	}

	if (bu_wait_up("start up"))
		goto err;

	/*
	 * And the prediction resistance instance is left alone. Each of its
	 * outputs is generated from a seed collected for it in the request, so
	 * a seed the monitor put in would either be replaced unused or - had
	 * the request gone with it - be output from entropy collected for no
	 * request at all.
	 */
	before = bu_state_get();
	for (i = 0; i < ESDM_BU_PR_SLICES; i++)
		bu_sleep_slice();
	after = bu_state_get();

	if (after.pr_seed_generation != before.pr_seed_generation) {
		printf("the prediction resistance DRNG was reseeded without a request: seed generation %lld -> %lld\n",
		       before.pr_seed_generation, after.pr_seed_generation);
		goto err;
	}

	printf("the prediction resistance DRNG was not reseeded without a request over %u slices\n",
	       ESDM_BU_PR_SLICES);

	/* All entropy gone: the monitor brings every DRNG up anew */
	esdm_reset();
	if (bu_wait_up("after a reset"))
		goto err;

	/*
	 * The seed times of the node DRNGs are spread over a tenth of the
	 * reseed interval. The interval is the longest a seed may serve, so the
	 * spread has to come out of it.
	 */
	after = bu_state_get();
	if (after.node_drngs &&
	    after.latest_node_reseed > ESDM_BU_STAGGER_INTERVAL) {
		printf("a node DRNG falls due for its reseed in %lld seconds, past the reseed interval of %u seconds\n",
		       after.latest_node_reseed, ESDM_BU_STAGGER_INTERVAL);
		goto err;
	}
	printf("%u node DRNG(s), the latest falls due for its reseed in %lld seconds\n",
	       after.node_drngs, after.latest_node_reseed);

	ret = 0;

out:
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif /* ESDM_TESTMODE */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef ESDM_TESTMODE
	return esdm_drng_bring_up_test();
#else
	printf("test mode not compiled in\n");
	return 77;
#endif
}
