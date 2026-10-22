/*
 * Test that a non-blocking esdm_get_seed() leaves the bring-up to the monitor
 *
 * esdm_get_seed() hands out seed material only once all DRNGs are seeded. A
 * caller asking without blocking - the unprivileged RPC interface does - used
 * to seed every DRNG that was not right there, in its own thread, with the
 * emergency reseeding. With the ES monitor running that is the monitor's job:
 * the caller is told to come back, at once.
 *
 * A node DRNG is taken out of the fully seeded state with no entropy around to
 * bring it back, and this test holds the lock of that DRNG while the request
 * is made: a request seeding it itself would wait for that lock, or for the
 * bring-up lock of the monitor waiting for it.
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
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "es_rates.h"
#include "test_monitor.h"
#include "threading_support.h"

#if defined(ESDM_TESTMODE) && defined(ESDM_NODE)

/* The initial DRNG and one node DRNG */
#define ESDM_GSN_NODES 2

/* Seconds the request gets to return */
#define ESDM_GSN_TIMEOUT 5

struct esdm_gsn_req {
	uint64_t *buf;
	size_t buflen;
	ssize_t rc;
};

static void *esdm_gsn_get_seed(void *arg)
{
	struct esdm_gsn_req *req = arg;

	req->rc = esdm_get_seed(req->buf, req->buflen, ESDM_GET_SEED_NONBLOCK);
	return NULL;
}

static int esdm_gsn_test(void)
{
	struct esdm_gsn_req req = { .buf = NULL, .buflen = 0, .rc = 0 };
	struct esdm_drng **drngs, *node_drng = NULL;
	struct timespec deadline;
	pthread_t thread;
	uint64_t size;
	int ret;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (sysconf(_SC_NPROCESSORS_ONLN) < ESDM_GSN_NODES) {
		printf("Need %d CPUs\n", ESDM_GSN_NODES);
		return 77;
	}

	esdm_config_max_nodes_set(ESDM_GSN_NODES);

	ret = esdm_init();
	if (ret)
		return ret;

	esdm_force_fully_seeded_all_drbgs();
	if (!esdm_pool_all_nodes_seeded_get() || !esdm_state_operational()) {
		printf("DRNGs cannot be seeded fully\n");
		ret = 77;
		goto out;
	}

	if (esdm_get_seed(&size, sizeof(size), ESDM_GET_SEED_NONBLOCK) !=
	    -EMSGSIZE) {
		printf("esdm_get_seed does not report its buffer size\n");
		ret = 1;
		goto out;
	}
	req.buflen = (size_t)size;
	req.buf = malloc(req.buflen);
	if (!req.buf) {
		ret = 1;
		goto out;
	}

	if (test_monitor_start()) {
		printf("the ES monitor did not start\n");
		ret = 1;
		goto out;
	}

	/* No entropy from here on that could bring a DRNG back */
	esdm_test_es_rates_zero();
	esdm_pool_set_entropy(0);

	drngs = esdm_drng_get_instances();
	if (drngs && esdm_drng_node_count_get() >= ESDM_GSN_NODES)
		node_drng = drngs[1];
	esdm_drng_put_instances();
	if (!node_drng || node_drng == esdm_drng_init_instance()) {
		printf("no node DRNG next to the initial one\n");
		ret = 77;
		goto out;
	}

	/* The node DRNG loses its seed, the ESDM stays operational */
	esdm_unset_fully_seeded(node_drng);
	if (esdm_pool_all_nodes_seeded_get() || !esdm_state_operational()) {
		printf("unexpected seeding state after unseeding the node DRNG\n");
		ret = 1;
		goto out;
	}

	mutex_w_lock(&node_drng->lock);

	if (pthread_create(&thread, NULL, esdm_gsn_get_seed, &req)) {
		mutex_w_unlock(&node_drng->lock);
		ret = 1;
		goto out;
	}

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += ESDM_GSN_TIMEOUT;
	ret = pthread_timedjoin_np(thread, NULL, &deadline);

	mutex_w_unlock(&node_drng->lock);

	if (ret) {
		pthread_join(thread, NULL);
		printf("the non-blocking esdm_get_seed() waited for the node DRNG - it brought the DRNGs up itself\n");
		ret = 1;
		goto out;
	}

	if (req.rc != -EAGAIN) {
		printf("the non-blocking esdm_get_seed() returned %zd instead of -EAGAIN with a DRNG not seeded\n",
		       req.rc);
		ret = 1;
		goto out;
	}

	printf("the non-blocking esdm_get_seed() returned -EAGAIN at once and left the bring-up to the monitor\n");
	ret = 0;

out:
	esdm_fini();
	free(req.buf);
	return ret;
}

#endif

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#if defined(ESDM_TESTMODE) && defined(ESDM_NODE)
	return esdm_gsn_test();
#else
	return 77;
#endif
}
