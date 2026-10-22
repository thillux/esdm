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
 * esdm-server-signal-helper --resume, which the resume unit runs once the
 * system woke up, has the server reseed its DRNGs: the seeds they hold are
 * from before the suspend, and the reseed interval alone would leave them in
 * service for up to its whole length afterwards.
 *
 * The helper is run against a server of the test's own. A reseed is carried
 * out by the request that runs into it, so right after the helper every DRNG
 * the server reports is to be marked for a forced reseed, and stays marked
 * until it is reseeded: requests are served after that only by DRNGs seeded
 * anew.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "esdm_rpc_client.h"

#include "../test_env.h"

/* DRNG instances looked at */
#define TEST_MAX_NODES 256

/* How long the DRNGs get to come up */
#define TEST_SEEDED_SECONDS 60

/* Requests made after the helper */
#define TEST_REQUESTS 64

static char test_buf[65536];

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* The integer, or boolean as 0 or 1, of member @key in test_buf */
static int test_member(const char *key, long long *val)
{
	const char *p = strstr(test_buf, key);
	char *end;

	if (!p)
		return -EINVAL;
	p += strlen(key);
	while (*p == ' ' || *p == ':')
		p++;
	if (!strncmp(p, "true", 4)) {
		*val = 1;
		return 0;
	}
	if (!strncmp(p, "false", 5)) {
		*val = 0;
		return 0;
	}
	*val = strtoll(p, &end, 10);

	return (end == p) ? -EINVAL : 0;
}

/*
 * The seed generations of the DRNG instances into @gen, one per node, and
 * whether they are marked for a forced reseed into @force.
 *
 * @return the number of nodes, < 0 on error
 */
static int test_generations(long long *gen, long long *force)
{
	unsigned int node;

	for (node = 0; node < TEST_MAX_NODES; node++) {
		int ret = esdm_rpcc_drng_status_json(node, test_buf,
						     sizeof(test_buf));

		if (ret == -ENODEV)
			break;
		if (ret < 0)
			return ret;

		if (test_member("\"seed_generation\"", &gen[node]) ||
		    test_member("\"force_reseed\"", &force[node]))
			return -EINVAL;
	}

	return (int)node;
}

/*
 * Has every DRNG been reseeded since @before, or is it marked for that?
 *
 * @return the number of DRNGs neither is true for, < 0 on error
 */
static int test_stale(const long long *before, int nodes, long long *after,
		      unsigned int *reseeded)
{
	static long long force[TEST_MAX_NODES];
	unsigned int i;
	int stale = 0;

	if (test_generations(after, force) != nodes) {
		printf("The DRNG instances changed under the test\n");
		return -EFAULT;
	}

	for (i = 0, *reseeded = 0; i < (unsigned int)nodes; i++) {
		printf("DRNG of node %u: seed generation %lld -> %lld, forced reseed %s\n",
		       i, before[i], after[i], force[i] ? "pending" : "none");
		if (after[i] > before[i])
			(*reseeded)++;
		else if (!force[i])
			stale++;
	}

	return stale;
}

static int test_run_helper(const char *helper)
{
	char *helper_envp[TEST_ENV_MAX_VARS + 1];
	char *argv[] = { (char *)helper, (char *)"--resume", NULL };
	int status;
	pid_t pid;

	test_env_daemon_envp(helper_envp, TEST_ENV_MAX_VARS + 1);

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		execve(helper, argv, helper_envp);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) != pid)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		printf("%s --resume exited with %d\n", helper,
		       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		return -EFAULT;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static long long before[TEST_MAX_NODES], after[TEST_MAX_NODES];
	static long long force[TEST_MAX_NODES];
	const char *helper = getenv("ESDM_SIGNAL_HELPER");
	unsigned int i, waited, reseeded;
	uint8_t buf[32];
	int nodes = 0, ret, stale;
	bool seeded = false;

	(void)argc;
	(void)argv;

	ret = test_env_check_file(helper);
	if (ret)
		return ret;

	ret = env_init();
	if (ret)
		return ret;

	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret) {
		printf("Cannot reach the unprivileged service: %d\n", ret);
		ret = 1;
		goto out;
	}

	/* Every DRNG instance holds a seed */
	for (waited = 0; waited < TEST_SEEDED_SECONDS * 10 && !seeded;
	     waited++) {
		nodes = test_generations(before, force);
		seeded = nodes > 0;
		for (i = 0; seeded && i < (unsigned int)nodes; i++)
			seeded = before[i] > 0;
		if (!seeded)
			test_sleep_ms(100);
	}
	if (!seeded) {
		printf("Not every DRNG instance was seeded (%d nodes)\n",
		       nodes);
		ret = 77;
		goto out;
	}

	ret = test_run_helper(helper);
	if (ret) {
		ret = 1;
		goto out;
	}

	/* No DRNG keeps the seed from before the suspend unmarked */
	stale = test_stale(before, nodes, after, &reseeded);
	if (stale) {
		if (stale > 0)
			printf("FAIL: %d of %d DRNG instances keep their seed after the resume\n",
			       stale, nodes);
		ret = 1;
		goto out;
	}

	/* The requests after it are served from seeds collected for them */
	for (i = 0; i < TEST_REQUESTS; i++) {
		if (esdm_rpcc_get_random_bytes_full(buf, sizeof(buf)) !=
		    (ssize_t)sizeof(buf)) {
			printf("FAIL: request %u after the resume not served\n",
			       i);
			ret = 1;
			goto out;
		}
	}

	stale = test_stale(before, nodes, after, &reseeded);
	if (stale || !reseeded) {
		if (stale >= 0)
			printf("FAIL: %d of %d DRNG instances serve their old seed, %u reseeded after %u requests\n",
			       stale, nodes, reseeded, TEST_REQUESTS);
		ret = 1;
		goto out;
	}

	printf("The resume marked every DRNG instance for a reseed, %u reseeded by the requests\n",
	       reseeded);
	ret = 0;

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
