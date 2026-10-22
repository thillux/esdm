/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "env.h"
#include "esdm_rpc_client.h"

#include "../status_json_check.h"

/*
 * How long a status call below may try to reach a server that is gone. The
 * client retries a connection its socket file refuses, as often as
 * client-reconnect-attempts says - at its largest, for seconds per call, and
 * the test timed out. The interrupt function ends the attempts once this
 * time passed, as a caller bounding its call does.
 */
#define TEST_STALE_CALL_MS 500

/* The interrupt function: has the CLOCK_MONOTONIC time @int_data passed? */
static int test_deadline_passed(void *int_data)
{
	const struct timespec *deadline = int_data;
	struct timespec now;

	if (!deadline)
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &now);

	return now.tv_sec > deadline->tv_sec ||
	       (now.tv_sec == deadline->tv_sec &&
		now.tv_nsec >= deadline->tv_nsec);
}

/*
 * Every status call fails while there is no server to answer it, and leaves
 * @buf empty rather than holding what an earlier call put there.
 */
static int esdm_rpcc_status_stale_check(char *buf, size_t buflen,
					const char *what)
{
	static const char stale[] = "{\"stale\":true}";
	static const struct {
		const char *name;
		int (*call)(char *buf, size_t buflen, void *int_data);
	} calls[] = {
		{ "esdm_rpcc_status", esdm_rpcc_status_int },
		{ "esdm_rpcc_status_json", esdm_rpcc_status_json_int },
		{ "esdm_rpcc_jent_status", esdm_rpcc_jent_status_int },
		{ "esdm_rpcc_drng_status_pr_json",
		  esdm_rpcc_drng_status_pr_json_int },
	};
	struct timespec deadline;
	unsigned int i;
	int ret;

	for (i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
		snprintf(buf, buflen, "%s", stale);

		clock_gettime(CLOCK_MONOTONIC, &deadline);
		deadline.tv_nsec += (TEST_STALE_CALL_MS % 1000) * 1000000L;
		deadline.tv_sec += TEST_STALE_CALL_MS / 1000 +
				   deadline.tv_nsec / 1000000000L;
		deadline.tv_nsec %= 1000000000L;

		ret = calls[i].call(buf, buflen, &deadline);
		if (ret >= 0) {
			printf("%s succeeded with %s: %d\n", calls[i].name,
			       what, ret);
			return 1;
		}

		if (buf[0]) {
			printf("%s with %s (%d) left a stale document: %s\n",
			       calls[i].name, what, ret, buf);
			return 1;
		}
	}

	printf("Status calls with %s leave the buffer empty\n", what);
	return 0;
}

int main(int argc, char *argv[])
{
	/*
	 * Large enough to hold the full status / JSON document for all
	 * entropy sources without truncation - matching the buffer the
	 * esdm-tool frontend uses. A short buffer would clip the JSON
	 * mid-document and fail esdm_status_json_check().
	 */
	char buf[65536];
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	ret = esdm_rpcc_init_unpriv_service(test_deadline_passed);
	if (ret) {
		ret = 1;
		goto out;
	}

	ret = esdm_rpcc_status(buf, sizeof(buf));
	if (ret < 0) {
		printf("RPC status returned error %d\n", ret);
		ret = 1;
		goto out;
	}

	if (!strstr(buf, "DRNG name") ||
	    !strstr(buf, "ESDM security strength") ||
	    !strstr(buf, "Number of DRNG instances") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "ESDM fully seeded")) {
		printf("Unexpected status: %s\n", buf);
		ret = 1;
		goto out;
	}

	ret = esdm_rpcc_status_json(buf, sizeof(buf));
	if (ret < 0) {
		printf("RPC JSON status returned error %d\n", ret);
		ret = 1;
		goto out;
	}

	if (esdm_status_json_check(buf)) {
		ret = 1;
		goto out;
	}

	/*
	 * A caller reusing its buffer must not take the document of an
	 * earlier call for the answer of a failed one: once the server is
	 * gone, and once the client has no connection to ask it with, every
	 * status call leaves the buffer empty.
	 */
	env_fini();
	ret = esdm_rpcc_status_stale_check(buf, sizeof(buf), "server gone");
	if (ret)
		goto out;

	esdm_rpcc_fini_unpriv_service();
	ret = esdm_rpcc_status_stale_check(buf, sizeof(buf), "no connection");
	if (ret)
		goto out;

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
