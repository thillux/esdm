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
 * A node DRNG must be reseeded even when there is no reseed worker.
 *
 * Node DRNGs hand their reseeds to the reseed worker. A library user that sets
 * the ESDM up with esdm_init() alone has none, and the request was dropped
 * without anything taking its place: a node DRNG then generated forever on its
 * first seed. Without a worker the request itself has to reseed the DRNG.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"

int main(void)
{
	struct esdm_drng *drng;
	cpu_set_t set;
	uint8_t buf[32];
	long long gen;
	int ret = 0;

	if (sysconf(_SC_NPROCESSORS_ONLN) < 2) {
		printf("Two CPUs are needed for a node DRNG\n");
		return 77;
	}

	/* On CPU 1 the requests go to the node DRNG, not the initial one */
	CPU_ZERO(&set);
	CPU_SET(1, &set);
	if (sched_setaffinity(0, sizeof(set), &set) || sched_getcpu() != 1) {
		printf("Cannot pin process to CPU 1\n");
		return 77;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	esdm_config_max_nodes_set(2);

	/* No esdm_init_monitor(), so no reseed worker */
	if (esdm_init())
		return 1;

	if (esdm_drng_mgr_reseed_worker_running()) {
		printf("A reseed worker is running, nothing to test\n");
		ret = 77;
		goto out;
	}

	/* The first request brings the node DRNG up */
	esdm_get_random_bytes(buf, sizeof(buf));

	/*
	 * The instance stays valid until esdm_fini() below; the reference is
	 * dropped right away so that esdm_fini() is not held up by it.
	 */
	drng = esdm_drng_node_instance();
	esdm_drng_put_instances();
	if (drng == esdm_drng_init_instance()) {
		printf("No node DRNG in use\n");
		ret = 77;
		goto out;
	}

	gen = atomic_load(&drng->seed_generation);
	atomic_store(&drng->force_reseed, true);

	if (esdm_get_random_bytes(buf, sizeof(buf)) != sizeof(buf)) {
		printf("Cannot obtain random data\n");
		ret = 1;
		goto out;
	}

	if (atomic_load(&drng->seed_generation) <= gen) {
		printf("FAIL: the node DRNG was not reseeded (generation %lld)\n",
		       gen);
		ret = 1;
	} else {
		printf("PASS: the node DRNG was reseeded without a worker\n");
	}

out:
	esdm_fini();
	return ret;
}
