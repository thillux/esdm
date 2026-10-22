/*
 * Test of the bound on the per-node DRNG array
 *
 * The array is sized once, from the node count the configuration yields at
 * that time. esdm_config_max_nodes_set() is public and may raise that count
 * afterwards, and nothing indexing the array may follow it past the end: the
 * node the caller runs on, a forced reseed, the seeding of all DRNGs and a
 * reset all have to stay within what was allocated.
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
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"

/* Number of DRNG instances the array is allocated with */
#define ESDM_NB_NODES 2

int main(int argc, char *argv[])
{
	uint8_t buf[64];
	struct esdm_drng *drng;
	cpu_set_t set;
	long cpus = sysconf(_SC_NPROCESSORS_ONLN);
	int ret;

	(void)argc;
	(void)argv;

	/*
	 * The node the caller runs on has to lie past the array, which takes a
	 * CPU numbered at least as high as the array is long.
	 */
	if (cpus <= ESDM_NB_NODES) {
		printf("Need more than %d CPUs\n", ESDM_NB_NODES);
		return 77;
	}

	CPU_ZERO(&set);
	CPU_SET(ESDM_NB_NODES, &set);
	if (sched_setaffinity(0, sizeof(set), &set) ||
	    sched_getcpu() != ESDM_NB_NODES) {
		printf("Cannot pin process to CPU %d\n", ESDM_NB_NODES);
		return 77;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	esdm_config_max_nodes_set(ESDM_NB_NODES);

	ret = esdm_init();
	if (ret)
		return ret;

	if (esdm_drng_node_count_get() != ESDM_NB_NODES) {
		printf("Unexpected number of DRNG instances: %u\n",
		       esdm_drng_node_count_get());
		ret = 1;
		goto out;
	}

	esdm_force_fully_seeded_all_drbgs();

	/* Every CPU of the machine is a node of its own from now on */
	esdm_config_max_nodes_set(UINT32_MAX);

	/*
	 * The node this runs on has no DRNG of its own, so it is served by the
	 * initial DRNG like any caller without a node DRNG.
	 */
	drng = esdm_drng_node_instance();
	esdm_drng_put_instances();
	if (drng != esdm_drng_init_instance()) {
		printf("Node %u served by a DRNG outside the array\n",
		       esdm_config_curr_node());
		ret = 1;
		goto out;
	}

	esdm_drng_force_reseed();
	esdm_reset();
	esdm_force_fully_seeded_all_drbgs();

	if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
		printf("Generating random bytes failed\n");
		ret = 1;
		goto out;
	}

	ret = 0;

out:
	esdm_fini();
	return ret;
}
