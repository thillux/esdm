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

#include "env.h"
#include "esdm_rpc_client.h"

#include "../status_json_check.h"

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
		int (*call)(char *buf, size_t buflen);
	} calls[] = {
		{ "esdm_rpcc_status", esdm_rpcc_status },
		{ "esdm_rpcc_status_json", esdm_rpcc_status_json },
		{ "esdm_rpcc_jent_status", esdm_rpcc_jent_status },
		{ "esdm_rpcc_drng_status_pr_json",
		  esdm_rpcc_drng_status_pr_json },
	};
	unsigned int i;
	int ret;

	for (i = 0; i < sizeof(calls) / sizeof(calls[0]); i++) {
		snprintf(buf, buflen, "%s", stale);

		ret = calls[i].call(buf, buflen);
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

	ret = esdm_rpcc_init_unpriv_service(NULL);
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
