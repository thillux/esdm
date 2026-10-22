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
 * The helper is run against a server of the test's own, and every DRNG the
 * server reports is to be seeded anew within a few seconds after it - the
 * reseed worker carries out what the helper asked for - without any request
 * asking for random numbers in between.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
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

/* How long the DRNGs get to come up, and to be reseeded after the helper */
#define TEST_SEEDED_SECONDS 60
#define TEST_RESEED_SECONDS 20

static char test_buf[65536];

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/*
 * The seed generations of the DRNG instances into @gen, one per node.
 *
 * @return the number of nodes, < 0 on error
 */
static int test_generations(long long *gen)
{
	unsigned int node;

	for (node = 0; node < TEST_MAX_NODES; node++) {
		const char *p;
		char *end;
		int ret = esdm_rpcc_drng_status_json(node, test_buf,
						     sizeof(test_buf));

		if (ret == -ENODEV)
			break;
		if (ret < 0)
			return ret;

		p = strstr(test_buf, "\"seed_generation\"");
		if (!p)
			return -EINVAL;
		p += strlen("\"seed_generation\"");
		while (*p == ' ' || *p == ':')
			p++;
		gen[node] = strtoll(p, &end, 10);
		if (end == p)
			return -EINVAL;
	}

	return (int)node;
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
	const char *helper = getenv("ESDM_SIGNAL_HELPER");
	unsigned int i, waited, stale = 0;
	int nodes = 0, ret;
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
		nodes = test_generations(before);
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

	for (waited = 0; waited < TEST_RESEED_SECONDS * 10; waited++) {
		if (test_generations(after) != nodes) {
			printf("The DRNG instances changed under the test\n");
			ret = 1;
			goto out;
		}

		for (i = 0, stale = 0; i < (unsigned int)nodes; i++)
			stale += (after[i] <= before[i]);
		if (!stale)
			break;
		test_sleep_ms(100);
	}

	for (i = 0; i < (unsigned int)nodes; i++)
		printf("DRNG of node %u: seed generation %lld -> %lld\n", i,
		       before[i], after[i]);

	if (stale) {
		printf("FAIL: %u of %d DRNG instances not reseeded %u s after the resume\n",
		       stale, nodes, TEST_RESEED_SECONDS);
		ret = 1;
	} else {
		printf("The resume reseeded every DRNG instance\n");
	}

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
