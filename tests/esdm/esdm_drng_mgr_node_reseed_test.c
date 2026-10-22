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
 * A node DRNG due for a reseed is reseeded by the request that runs into it.
 *
 * Nothing else reseeds a fully seeded DRNG: a reseed handed to anybody else
 * that is not there - a library user sets the ESDM up with esdm_init() alone,
 * without the ES monitor - leaves the node DRNG generating forever on its
 * first seed. Checked without the monitor, and with it (argument "monitor").
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
#include "test_monitor.h"

int main(int argc, char *argv[])
{
	struct esdm_drng *drng;
	cpu_set_t set;
	uint8_t buf[32];
	long long gen;
	int ret = 0;

	(void)argv;

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

	if (esdm_init())
		return 1;

	if (argc > 1 && test_monitor_start()) {
		printf("The ES monitor did not start\n");
		ret = 1;
		goto out;
	}

	/*
	 * The first request allocates the node DRNG. Bring it up as the monitor
	 * would: without one, a request seeds it only once the entropy sources
	 * report enough for a seed at once, which under the NTG.1 seeding
	 * strategy they never do - its two sources of 240 bits each are
	 * collected over several passes.
	 */
	esdm_get_random_bytes(buf, sizeof(buf));
	esdm_force_fully_seeded_all_drbgs();

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

	/* Not seeded, it serves no request, and the request below misses it */
	if (!atomic_load(&drng->fully_seeded)) {
		printf("FAIL: the node DRNG cannot be seeded\n");
		ret = 1;
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
		printf("PASS: the request reseeded the node DRNG\n");
	}

out:
	esdm_fini();
	return ret;
}
