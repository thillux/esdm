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
 * Assess 1 MiB of esdm_get_random_bytes_full() output with the SP800-90B
 * non-IID estimators (ea_non_iid from NIST's SP800-90B_EntropyAssessment) and
 * require more than 6 bits of min-entropy per byte. A sanity bound, not a
 * claim: full entropy output scores close to 8, so anything at or below 6
 * points at a broken DRNG rather than at estimator noise. Skips when
 * ea_non_iid is not installed.
 */

#include <fcntl.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "esdm.h"
#include "esdm_logger.h"
#include "test_pertubation.h"

#define MIN_ENTROPY_BYTES (1024 * 1024)
#define MIN_ENTROPY_LIMIT 6.0

static char workdir[400];

/*
 * Run ea_non_iid on the sample file in workdir. It is run from there with
 * relative paths, as its usage text asks for. Returns its exit status, or -1
 * if it could not be run at all.
 */
static int run_ea_non_iid(void)
{
	char *argv[] = { (char *)"ea_non_iid", (char *)"-q", (char *)"-o",
			 (char *)"result.json", (char *)"random.bin",
			 (char *)"8", NULL };
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;

	if (pid == 0) {
		/* Its report goes to the JSON file, the log stays readable */
		int devnull = open("/dev/null", O_WRONLY);

		if (devnull >= 0) {
			dup2(devnull, STDOUT_FILENO);
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		if (chdir(workdir) < 0)
			_exit(126);
		execvp("ea_non_iid", argv);
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

static int write_samples(void)
{
	char path[sizeof(workdir) + 16];
	uint8_t *buf;
	ssize_t rc;
	FILE *f;
	int ret = 1;

	buf = malloc(MIN_ENTROPY_BYTES);
	if (!buf)
		return 1;

	rc = esdm_get_random_bytes_full(buf, MIN_ENTROPY_BYTES);
	if (rc != MIN_ENTROPY_BYTES) {
		printf("esdm_get_random_bytes_full returned %zd\n", rc);
		goto out;
	}

	snprintf(path, sizeof(path), "%s/random.bin", workdir);
	f = fopen(path, "wb");
	if (!f) {
		printf("cannot create %s\n", path);
		goto out;
	}
	if (fwrite(buf, 1, MIN_ENTROPY_BYTES, f) != MIN_ENTROPY_BYTES) {
		printf("cannot write %s\n", path);
		fclose(f);
		goto out;
	}
	if (fclose(f)) {
		printf("cannot write %s\n", path);
		goto out;
	}

	ret = 0;

out:
	free(buf);
	return ret;
}

/*
 * Returns the assessed min-entropy per sample - "hAssessed" of the "Overall"
 * test case - or a negative value if the report does not carry it.
 */
static double assessed_min_entropy(void)
{
	char path[sizeof(workdir) + 16];
	struct json_object *root, *cases, *tc, *desc, *h;
	double ret = -1.0;
	size_t i, n;

	snprintf(path, sizeof(path), "%s/result.json", workdir);
	root = json_object_from_file(path);
	if (!root) {
		printf("cannot parse %s: %s\n", path, json_util_get_last_err());
		return -1.0;
	}

	if (!json_object_object_get_ex(root, "testCases", &cases) ||
	    !json_object_is_type(cases, json_type_array)) {
		printf("report carries no testCases array\n");
		goto out;
	}

	n = json_object_array_length(cases);
	for (i = 0; i < n; i++) {
		tc = json_object_array_get_idx(cases, i);

		if (!json_object_object_get_ex(tc, "testCaseDesc", &desc) ||
		    strcmp(json_object_get_string(desc), "Overall"))
			continue;

		if (!json_object_object_get_ex(tc, "hAssessed", &h) ||
		    !json_object_is_type(h, json_type_double)) {
			printf("Overall test case carries no hAssessed\n");
			goto out;
		}

		ret = json_object_get_double(h);
		goto out;
	}

	printf("report carries no Overall test case\n");

out:
	json_object_put(root);
	return ret;
}

static void cleanup(void)
{
	char path[sizeof(workdir) + 16];

	snprintf(path, sizeof(path), "%s/random.bin", workdir);
	unlink(path);
	snprintf(path, sizeof(path), "%s/result.json", workdir);
	unlink(path);
	rmdir(workdir);
}

int main(int argc, char *argv[])
{
	const char *tmpdir = getenv("TMPDIR");
	double h;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	snprintf(workdir, sizeof(workdir), "%s/esdm-output-min-entropy-XXXXXX",
		 tmpdir && *tmpdir ? tmpdir : "/tmp");
	if (!mkdtemp(workdir)) {
		printf("cannot create a working directory\n");
		return 1;
	}

	esdm_logger_set_verbosity(LOGGER_DEBUG);
	ret = esdm_init();
	if (ret)
		goto out;

	ret = write_samples();
	esdm_fini();
	if (ret)
		goto out;

	ret = run_ea_non_iid();
	if (ret == 127 || ret < 0) {
		printf("ea_non_iid is not available - skipping\n");
		ret = 77;
		goto out;
	}
	if (ret) {
		printf("ea_non_iid failed with %d\n", ret);
		ret = 1;
		goto out;
	}

	h = assessed_min_entropy();
	if (h < 0) {
		ret = 1;
		goto out;
	}

	printf("assessed min-entropy: %f bits per byte\n", h);
	if (h <= MIN_ENTROPY_LIMIT) {
		printf("min-entropy %f is not above %f\n", h,
		       MIN_ENTROPY_LIMIT);
		ret = 1;
	}

out:
	cleanup();
	return ret;
}
