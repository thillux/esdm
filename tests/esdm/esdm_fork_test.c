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
 * A process using libesdm forks, and parent and child both ask for random
 * numbers. The child inherits the states of the parent's DRNGs - without
 * anything setting them apart, the two hand out the same bytes.
 *
 * Both read from the DRNG the request goes to - the initial one (argument
 * "initial", a single node), or that of a node (argument "node", pinned to a
 * CPU other than the first) - and from the prediction resistance DRNG, a few
 * times each, and every answer of the child must differ from the parent's
 * answer to the same request. The child must not depend on the threads of the
 * parent either, the reseed worker among them, which a fork() does not copy:
 * its requests are to be answered within the watchdog's time.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "wait_seeded.h"

/*
 * The thread sanitizer does not let a child of a process with threads start
 * threads of its own, which the reseed in the child does when it collects
 * from the entropy sources in parallel.
 */
#if defined(__SANITIZE_THREAD__)
#define TEST_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define TEST_TSAN 1
#endif
#endif

/* Requests of each kind both processes make */
#define TEST_ROUNDS 3

/* Bytes per request: one block of the prediction resistance DRNG */
#define TEST_LEN 32

/* Seconds the child gets for its requests */
#define TEST_CHILD_WATCHDOG 60

struct test_answers {
	uint8_t regular[TEST_ROUNDS][TEST_LEN];
	uint8_t pr[TEST_ROUNDS][TEST_LEN];
	ssize_t regular_rc[TEST_ROUNDS];
	ssize_t pr_rc[TEST_ROUNDS];
};

static void test_ask(struct test_answers *a)
{
	unsigned int i;

	memset(a, 0, sizeof(*a));
	for (i = 0; i < TEST_ROUNDS; i++) {
		a->regular_rc[i] =
			esdm_get_random_bytes_full(a->regular[i], TEST_LEN);
		a->pr_rc[i] = esdm_get_random_bytes_pr(a->pr[i], TEST_LEN);
	}
}

static int test_compare(const char *what, const uint8_t *parent,
			ssize_t parent_rc, const uint8_t *child,
			ssize_t child_rc, unsigned int round)
{
	if (parent_rc <= 0 || child_rc <= 0) {
		printf("FAIL: %s request %u answered %zd in the parent, %zd in the child\n",
		       what, round, parent_rc, child_rc);
		return 1;
	}

	if (!memcmp(parent, child,
		    (size_t)((parent_rc < child_rc) ? parent_rc : child_rc))) {
		printf("FAIL: %s request %u answered with the same bytes in parent and child\n",
		       what, round);
		return 1;
	}

	return 0;
}

static int esdm_fork_test(void)
{
	struct test_answers parent, child;
	unsigned int i;
	int pipefd[2] = { -1, -1 }, status, ret = 0;
	uint8_t buf[TEST_LEN];
	size_t got = 0;
	pid_t pid;

	esdm_logger_set_verbosity(LOGGER_WARN);

	CKINT(esdm_init());

	/* A reseed worker in the parent, which the child has to do without */
	if (thread_init(1) || !esdm_drng_mgr_reseed_worker_start()) {
		printf("The reseed worker is not on duty\n");
		goto err;
	}

	esdm_get_random_bytes(buf, sizeof(buf));
	if (test_wait_fully_seeded()) {
		printf("The ESDM did not reach the fully seeded state\n");
		ret = 77;
		goto out;
	}

	/* Every DRNG holds a seed of its own, the PR DRNG's included */
	for (i = 0; i < 60 * 100 && !esdm_pool_all_nodes_seeded_get(); i++) {
		struct timespec ten_ms = { .tv_sec = 0,
					   .tv_nsec = 10 * 1000 * 1000 };

		nanosleep(&ten_ms, NULL);
	}
	if (!esdm_pool_all_nodes_seeded_get()) {
		printf("Not all DRNGs became fully seeded\n");
		ret = 77;
		goto out;
	}

	printf("DRNG node instances: %u\n", esdm_drng_node_count_get());

	if (pipe(pipefd)) {
		printf("Cannot create a pipe: %s\n", strerror(errno));
		goto err;
	}

	pid = fork();
	if (pid < 0) {
		printf("Cannot fork: %s\n", strerror(errno));
		goto err;
	}

	if (!pid) {
		const uint8_t *p = (const uint8_t *)&child;
		size_t sent = 0;

		alarm(TEST_CHILD_WATCHDOG);
		close(pipefd[0]);
		test_ask(&child);
		while (sent < sizeof(child)) {
			ssize_t rc = write(pipefd[1], p + sent,
					   sizeof(child) - sent);

			if (rc <= 0)
				_exit(1);
			sent += (size_t)rc;
		}
		/* Not esdm_fini(): it would wait for the parent's threads */
		_exit(0);
	}

	close(pipefd[1]);
	pipefd[1] = -1;
	test_ask(&parent);

	while (got < sizeof(child)) {
		ssize_t rc = read(pipefd[0], (uint8_t *)&child + got,
				  sizeof(child) - got);

		if (rc <= 0)
			break;
		got += (size_t)rc;
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) || got != sizeof(child)) {
		printf("FAIL: the child did not answer its requests (%s %d)\n",
		       WIFSIGNALED(status) ? "signal" : "exit status",
		       WIFSIGNALED(status) ? WTERMSIG(status) :
					     WEXITSTATUS(status));
		goto err;
	}

	for (i = 0; i < TEST_ROUNDS; i++) {
		ret |= test_compare("regular", parent.regular[i],
				    parent.regular_rc[i], child.regular[i],
				    child.regular_rc[i], i);
		ret |= test_compare("prediction resistant", parent.pr[i],
				    parent.pr_rc[i], child.pr[i],
				    child.pr_rc[i], i);
	}

	if (!ret)
		printf("Parent and child of a fork() hand out different random numbers\n");

out:
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	esdm_drng_mgr_reseed_worker_stop();
	esdm_fini();
	return ret;
err:
	ret = 1;
	goto out;
}

int main(int argc, char *argv[])
{
	cpu_set_t set;

	if (argc != 2)
		return 1;

#ifdef TEST_TSAN
	printf("SKIPPED: no threads in a forked child under the thread sanitizer\n");
	return 77;
#endif

	CPU_ZERO(&set);
	if (!strcmp(argv[1], "initial")) {
		/* A single node: every request goes to the initial DRNG */
		esdm_config_max_nodes_set(1);
		CPU_SET(0, &set);
	} else if (!strcmp(argv[1], "node")) {
		/*
		 * The requests of a process on CPU 1 go to the DRNG of node 1,
		 * see esdm_drng_get_sleep() - with two nodes, there is only
		 * that one besides the initial DRNG.
		 */
		esdm_config_max_nodes_set(2);
		CPU_SET(1, &set);
	} else {
		return 1;
	}

	/* Parent and child on the same CPU, so they go to the same DRNG */
	if (sched_setaffinity(0, sizeof(set), &set) == -1) {
		printf("Cannot pin the process to its CPU\n");
		return 77;
	}

	if (!strcmp(argv[1], "node") && sched_getcpu() < 1) {
		printf("Cannot pin the process to CPU 1\n");
		return 77;
	}

	return esdm_fork_test();
}
