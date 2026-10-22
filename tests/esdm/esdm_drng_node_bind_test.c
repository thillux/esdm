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
 * Threads mapped to a node DRNG each, as the workers of the esdm-server are -
 * see esdm_drng_node_bind():
 *
 *   - thread i is mapped to node i + 1 - never to node 0, whose DRNG is the
 *     initial one -, from the last node downwards on request, wrapping around,
 *   - a mapped thread is served by its node DRNG alone, no other DRNG
 *     generates for it, and no two threads get the same bytes,
 *   - while its node DRNG is busy - its lock taken, as a seeding of it does -
 *     the requests of the thread are served by the other DRNGs rather than
 *     waiting,
 *   - once its node DRNG reached its maximum output without full reseed, the
 *     request of the thread reseeds it in place and is served by it still,
 *   - the child of a fork() of a mapped thread is not served the bytes of its
 *     parent,
 *   - after a reset, the requests of a mapped thread are served, and by its
 *     node DRNG again once the ES monitor seeded that anew,
 *   - esdm_fini() returns once the threads unbound.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "ret_checkers.h"
#include "test_monitor.h"
#include "threading_support.h"
#include "wait_seeded.h"

#ifdef ESDM_TESTMODE

/* Node DRNGs asked for: the initial one and three to map threads to */
#define TEST_NODES 4
#define TEST_THREADS (TEST_NODES - 1)
/* Requests each thread makes while the DRNGs are watched */
#define TEST_REQUESTS 256
/*
 * Requests a thread makes while its node DRNG is busy - few, so that the node
 * DRNGs serving them keep room for the requests after
 */
#define TEST_BUSY_REQUESTS 16
#define TEST_REQUEST_BYTES 32
/* Wait at most this many 100 ms slices for the ES monitor */
#define TEST_SLICES 600
/*
 * The maximum output without full reseed a node DRNG is spent with: that of
 * SP800-90C and AIS 20/31 DRG.4, 2^17 bits
 */
#define TEST_MAX_WO_RESEED_BITS (1U << 17)
/* Requests made once the node DRNG is spent */
#define TEST_SPENT_REQUESTS 16

/* What the statistics say about the node DRNGs, by node */
struct test_state {
	unsigned int nodes;
	unsigned int seeded;
	long long bits[TEST_NODES];
	long long gen[TEST_NODES];
};

static void test_state_cb(const struct esdm_drng_stats *stats, void *priv)
{
	struct test_state *state = priv;

	if (!stats->node_valid || stats->node >= TEST_NODES)
		return;

	state->nodes++;
	if (stats->fully_seeded)
		state->seeded++;
	state->bits[stats->node] = stats->bits_since_fully_seeded;
	state->gen[stats->node] = stats->seed_generation;
}

static struct test_state test_state_get(void)
{
	struct test_state state;

	memset(&state, 0, sizeof(state));
	esdm_drng_stats_foreach(test_state_cb, &state);

	return state;
}

static void test_sleep_slice(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* Wait until every node DRNG is fully seeded */
static int test_wait_nodes_seeded(void)
{
	struct test_state state;
	unsigned int i;

	for (i = 0; i < TEST_SLICES; i++) {
		state = test_state_get();
		if (state.nodes == TEST_NODES && state.seeded == TEST_NODES)
			return 0;
		test_sleep_slice();
	}

	printf("%u of %u node DRNGs seeded after %u slices\n", state.seeded,
	       state.nodes, TEST_SLICES);
	return 1;
}

/****************************
 * Mapped threads
 ****************************/

enum test_cmd {
	TEST_CMD_NONE,
	/* Make TEST_REQUESTS requests */
	TEST_CMD_REQUESTS,
	/* Make TEST_BUSY_REQUESTS requests */
	TEST_CMD_BUSY_REQUESTS,
	/* Request past the maximum output of the node DRNG */
	TEST_CMD_SPEND,
	/* fork(), and compare the bytes of the child with those of the parent */
	TEST_CMD_FORK,
	TEST_CMD_UNBIND,
};

struct test_thread {
	pthread_t thread;
	unsigned int idx;
	int node;
	atomic_int cmd;
	/* Commands completed, and the result of the last one */
	atomic_uint done;
	atomic_int result;
	/* Requests of TEST_CMD_SPEND */
	unsigned int spend;
	uint8_t last[TEST_REQUEST_BYTES];
};

static struct test_thread test_threads[TEST_THREADS];

static int test_requests(struct test_thread *t, unsigned int n)
{
	uint8_t buf[TEST_REQUEST_BYTES];
	unsigned int i;

	for (i = 0; i < n; i++) {
		ssize_t ret = esdm_get_random_bytes_full(buf, sizeof(buf));

		if (ret != (ssize_t)sizeof(buf)) {
			printf("thread %u: request %u returned %zd\n", t->idx,
			       i, ret);
			return 1;
		}
	}
	memcpy(t->last, buf, sizeof(buf));

	return 0;
}

/*
 * Generate past the maximum output without full reseed of the node DRNG: every
 * request is served without blocking, the one that runs into it included.
 */
static int test_spend(struct test_thread *t)
{
	uint8_t buf[TEST_REQUEST_BYTES];
	unsigned int i;

	for (i = 0; i < t->spend; i++) {
		ssize_t ret = esdm_get_random_bytes_full_noblock(buf,
								  sizeof(buf));

		if (ret != (ssize_t)sizeof(buf)) {
			printf("thread %u: request %u past the maximum output returned %zd\n",
			       t->idx, i, ret);
			return 1;
		}
	}

	return 0;
}

/*
 * The child of a fork() of a mapped thread inherits the node DRNG with its state
 * - and must not hand out what the parent hands out next.
 */
static int test_fork(struct test_thread *t)
{
	uint8_t parent[TEST_REQUEST_BYTES], child[TEST_REQUEST_BYTES];
	int pipefd[2], status;
	pid_t pid;

	if (pipe(pipefd))
		return 1;

	pid = fork();
	if (pid < 0)
		return 1;
	if (!pid) {
		ssize_t ret = esdm_get_random_bytes(child, sizeof(child));

		close(pipefd[0]);
		if (ret != (ssize_t)sizeof(child) ||
		    write(pipefd[1], child, sizeof(child)) !=
			    (ssize_t)sizeof(child))
			_exit(1);
		_exit(0);
	}

	close(pipefd[1]);
	if (esdm_get_random_bytes(parent, sizeof(parent)) !=
	    (ssize_t)sizeof(parent)) {
		printf("thread %u: no bytes in the parent of the fork\n",
		       t->idx);
		close(pipefd[0]);
		waitpid(pid, NULL, 0);
		return 1;
	}

	if (read(pipefd[0], child, sizeof(child)) != (ssize_t)sizeof(child) ||
	    waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status)) {
		printf("thread %u: no bytes from the child of the fork\n",
		       t->idx);
		close(pipefd[0]);
		return 1;
	}
	close(pipefd[0]);

	if (!memcmp(parent, child, sizeof(parent))) {
		printf("thread %u: the child of the fork got the bytes of its parent\n",
		       t->idx);
		return 1;
	}

	return 0;
}

static void *test_thread_main(void *arg)
{
	struct test_thread *t = arg;
	int ret;

	t->node = esdm_drng_node_bind(t->idx, false);
	atomic_store(&t->result, t->node < 0 ? t->node : 0);
	atomic_fetch_add(&t->done, 1);
	if (t->node < 0)
		return NULL;

	for (;;) {
		int cmd = atomic_exchange(&t->cmd, TEST_CMD_NONE);

		switch (cmd) {
		case TEST_CMD_NONE:
			test_sleep_slice();
			continue;
		case TEST_CMD_REQUESTS:
			ret = test_requests(t, TEST_REQUESTS);
			break;
		case TEST_CMD_BUSY_REQUESTS:
			ret = test_requests(t, TEST_BUSY_REQUESTS);
			break;
		case TEST_CMD_SPEND:
			ret = test_spend(t);
			break;
		case TEST_CMD_FORK:
			ret = test_fork(t);
			break;
		case TEST_CMD_UNBIND:
		default:
			esdm_drng_node_unbind();
			atomic_store(&t->result, 0);
			atomic_fetch_add(&t->done, 1);
			return NULL;
		}

		atomic_store(&t->result, ret);
		atomic_fetch_add(&t->done, 1);
	}
}

/* Have the threads @first to @last - 1 carry out @cmd, return failures */
static int test_command(unsigned int first, unsigned int last, int cmd)
{
	unsigned int i, before[TEST_THREADS];
	int failed = 0;

	for (i = first; i < last; i++) {
		before[i] = atomic_load(&test_threads[i].done);
		atomic_store(&test_threads[i].cmd, cmd);
	}
	for (i = first; i < last; i++) {
		while (atomic_load(&test_threads[i].done) == before[i])
			test_sleep_slice();
		if (atomic_load(&test_threads[i].result))
			failed++;
	}

	return failed;
}

/* Bind, report the node, unbind - in a thread of its own */
struct test_probe {
	uint32_t worker;
	bool from_last;
	int node;
};

static void *test_probe_main(void *arg)
{
	struct test_probe *p = arg;

	p->node = esdm_drng_node_bind(p->worker, p->from_last);
	if (p->node >= 0)
		esdm_drng_node_unbind();

	return NULL;
}

static int test_probe(uint32_t worker, bool from_last)
{
	struct test_probe p = { .worker = worker, .from_last = from_last };
	pthread_t thread;

	if (pthread_create(&thread, NULL, test_probe_main, &p))
		return -EFAULT;
	pthread_join(thread, NULL);

	return p.node;
}

static int esdm_drng_node_bind_test(void)
{
	struct test_state before, after;
	struct esdm_drng **drngs;
	uint8_t rnd[TEST_REQUEST_BYTES];
	uint32_t max_wo_reseed_bits;
	unsigned int i, j, started = 0;
	long long others;
	int ret;

	esdm_config_max_nodes_set(TEST_NODES);

	CKINT(esdm_init());
	if (test_monitor_start()) {
		printf("the ES monitor did not start\n");
		goto err;
	}

	if (esdm_drng_node_count_get() != TEST_NODES) {
		printf("%u node DRNGs on this machine, the test wants %u\n",
		       esdm_drng_node_count_get(), TEST_NODES);
		ret = 77;
		goto out;
	}

	esdm_get_random_bytes(rnd, sizeof(rnd));
	if (test_wait_fully_seeded() || test_wait_nodes_seeded()) {
		printf("the ESDM is not fully seeded\n");
		goto err;
	}

	/* The mapping: past node 0, in both directions, wrapping around */
	if (test_probe(0, false) != 1 || test_probe(TEST_THREADS, false) != 1 ||
	    test_probe(0, true) != TEST_NODES - 1 ||
	    test_probe(1, true) != TEST_NODES - 2) {
		printf("the threads are mapped to the wrong nodes\n");
		goto err;
	}

	for (i = 0; i < TEST_THREADS; i++) {
		test_threads[i].idx = i;
		if (pthread_create(&test_threads[i].thread, NULL,
				   test_thread_main, &test_threads[i])) {
			printf("cannot start thread %u\n", i);
			goto err;
		}
		started++;
	}
	for (i = 0; i < TEST_THREADS; i++) {
		while (!atomic_load(&test_threads[i].done))
			test_sleep_slice();
		if (test_threads[i].node != (int)i + 1) {
			printf("thread %u is mapped to node %d\n", i,
			       test_threads[i].node);
			goto err;
		}
	}

	/* Each thread is served by its node DRNG alone */
	before = test_state_get();
	if (test_command(0, TEST_THREADS, TEST_CMD_REQUESTS))
		goto err;
	after = test_state_get();
	if (after.bits[0] != before.bits[0]) {
		printf("the initial DRNG generated %lld bits for the mapped threads\n",
		       after.bits[0] - before.bits[0]);
		goto err;
	}
	for (i = 0; i < TEST_THREADS; i++) {
		if (after.bits[i + 1] - before.bits[i + 1] !=
		    TEST_REQUESTS * TEST_REQUEST_BYTES * 8) {
			printf("node DRNG %u generated %lld bits for the %u requests of its thread\n",
			       i + 1, after.bits[i + 1] - before.bits[i + 1],
			       TEST_REQUESTS);
			goto err;
		}
		for (j = 0; j < i; j++) {
			if (!memcmp(test_threads[i].last, test_threads[j].last,
				    TEST_REQUEST_BYTES)) {
				printf("threads %u and %u got the same bytes\n",
				       i, j);
				goto err;
			}
		}
	}
	printf("each thread was served by its node DRNG alone\n");

	/*
	 * Its node DRNG busy - its lock taken, as a seeding of it does -, the
	 * thread is served by the others, and does not wait for it
	 */
	drngs = esdm_drng_get_instances();
	before = test_state_get();
	mutex_w_lock(&drngs[1]->lock);
	ret = test_command(0, 1, TEST_CMD_BUSY_REQUESTS);
	mutex_w_unlock(&drngs[1]->lock);
	esdm_drng_put_instances();
	if (ret)
		goto err;
	after = test_state_get();
	for (i = 0, others = 0; i < TEST_NODES; i++) {
		if (i != 1)
			others += after.bits[i] - before.bits[i];
	}
	if (after.bits[1] != before.bits[1] ||
	    others != TEST_BUSY_REQUESTS * TEST_REQUEST_BYTES * 8) {
		printf("with its node DRNG busy, the thread was served by it (%lld bits) and by the others (%lld bits)\n",
		       after.bits[1] - before.bits[1], others);
		goto err;
	}
	printf("with its node DRNG busy, the thread was served by the others\n");

	/*
	 * Spent: the request running into the maximum output reseeds the node
	 * DRNG in place, under its lock, so neither the initial nor another
	 * node DRNG generates for the thread, and all stay seeded.
	 */
	before = test_state_get();
	max_wo_reseed_bits = esdm_config_drng_max_wo_reseed_bits();
	esdm_config_drng_max_wo_reseed_bits_set(TEST_MAX_WO_RESEED_BITS);
	test_threads[0].spend = (unsigned int)((TEST_MAX_WO_RESEED_BITS -
						before.bits[1]) /
					       (TEST_REQUEST_BYTES * 8)) +
				TEST_SPENT_REQUESTS;
	ret = test_command(0, 1, TEST_CMD_SPEND);
	after = test_state_get();
	esdm_config_drng_max_wo_reseed_bits_set(max_wo_reseed_bits);
	if (ret)
		goto err;
	for (i = 0, others = 0; i < TEST_NODES; i++) {
		if (i != 1)
			others += after.bits[i] - before.bits[i];
	}
	if (others) {
		printf("past the maximum output, the other DRNGs generated %lld bits for the thread\n",
		       others);
		goto err;
	}
	if (after.gen[1] <= before.gen[1] || after.seeded != TEST_NODES) {
		printf("the spent node DRNG was not reseeded in place (generation %lld to %lld, %u of %u DRNGs seeded)\n",
		       before.gen[1], after.gen[1], after.seeded, TEST_NODES);
		goto err;
	}
	printf("past the maximum output, the node DRNG was reseeded in place and served the thread still\n");

	/* Not the bytes of the parent in the child of a fork */
	if (test_command(1, 2, TEST_CMD_FORK))
		goto err;
	printf("the child of a fork got bytes of its own\n");

	/* After a reset, served - and by the node DRNGs again once seeded */
	esdm_reset();
	if (test_command(0, TEST_THREADS, TEST_CMD_REQUESTS))
		goto err;
	if (test_wait_fully_seeded() || test_wait_nodes_seeded())
		goto err;
	before = test_state_get();
	if (test_command(0, TEST_THREADS, TEST_CMD_REQUESTS))
		goto err;
	/*
	 * A node DRNG may reach its reseed threshold on the way in a build for
	 * SP800-90C, whose reseed restarts its count: told by its generation
	 */
	after = test_state_get();
	if (after.bits[0] != before.bits[0]) {
		printf("after the reset, the initial DRNG generated %lld bits for the mapped threads\n",
		       after.bits[0] - before.bits[0]);
		goto err;
	}
	for (i = 0; i < TEST_THREADS; i++) {
		if (after.bits[i + 1] == before.bits[i + 1] &&
		    after.gen[i + 1] == before.gen[i + 1]) {
			printf("after the reset, node DRNG %u generated nothing for its thread\n",
			       i + 1);
			goto err;
		}
	}
	printf("after the reset, the threads were served by their node DRNGs again\n");

	ret = 0;
out:
	/* esdm_fini() returns only once the threads unbound */
	for (i = 0; i < started; i++) {
		if (test_threads[i].node >= 0)
			atomic_store(&test_threads[i].cmd, TEST_CMD_UNBIND);
		pthread_join(test_threads[i].thread, NULL);
	}
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}
#endif

int main(void)
{
#ifdef ESDM_TESTMODE
	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								  LOGGER_WARN);
	return esdm_drng_node_bind_test();
#else
	return 77;
#endif
}
