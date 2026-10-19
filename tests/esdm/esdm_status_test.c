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

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"
#include "test_pertubation.h"

#include "../status_json_check.h"

/*
 * The ESDM claims NTG.1(2024) exactly when it seeds under the NTG.1 seeding
 * strategy - a Jitter RNG in its own NTG.1 mode does not make it so, as
 * without the strategy the ESDM seeds from 256/384 bits of any sources. That
 * mode is reported in the section of the Jitter RNG instead.
 *
 * Checked on the text report's first "Standards compliance" line (the one of
 * the ESDM, before those of the entropy sources), or on the top level array of
 * the JSON document.
 */
static int esdm_status_ntg1_2024_check(const char *buf, bool json)
{
	bool claimed = false, expected = !!esdm_ntg1_2024_compliant();

	if (json) {
		struct json_object *root = json_tokener_parse(buf), *compliance;
		size_t i;

		if (!root)
			return 1;
		if (!json_object_object_get_ex(root, "standards_compliance",
					       &compliance)) {
			json_object_put(root);
			return 1;
		}
		for (i = 0; i < json_object_array_length(compliance); i++) {
			const char *str = json_object_get_string(
				json_object_array_get_idx(compliance, i));

			if (str && !strcmp(str, "NTG.1(2024)"))
				claimed = true;
		}
		json_object_put(root);
	} else {
		const char *line = strstr(buf, "Standards compliance:");
		const char *end = line ? strchr(line, '\n') : NULL;
		const char *ntg1 = line ? strstr(line, "NTG.1(2024)") : NULL;

		if (!line || !end)
			return 1;
		claimed = ntg1 && ntg1 < end;
	}

	if (claimed != expected) {
		printf("%s status %s NTG.1(2024) with the NTG.1 seeding strategy %s\n",
		       json ? "JSON" : "Text",
		       claimed ? "claims" : "does not claim",
		       expected ? "enabled" : "disabled");
		return 1;
	}

	return 0;
}

/*
 * The prediction resistance DRNG is seeded for every request, so its counters
 * and seeding times would tell any local user about the requests of others:
 * its section of the text report has them as not available. It is the last
 * DRNG section, followed by the one of the reseed worker.
 */
static int esdm_status_pr_withheld_check(const char *buf)
{
	static const char *const withheld[] = {
		"\n Seconds until reseed: N/A\n",
		"\n Requests since fully seeded: N/A\n",
		"\n Generated bits since fully seeded: N/A\n",
		"\n Seed generation: N/A\n",
		"\n Last seeding time: N/A\n",
		"\n Seconds since last reseed: N/A\n",
	};
	const char *pr = strstr(buf, " Type: prediction resistance");
	const char *end = pr ? strstr(pr, "\nReseed worker properties") : NULL;
	unsigned int i;

	for (i = 0; i < sizeof(withheld) / sizeof(withheld[0]); i++) {
		const char *line = pr ? strstr(pr, withheld[i]) : NULL;

		if (!line || !end || line > end) {
			printf("The prediction resistance DRNG section lacks the line:%s",
			       withheld[i]);
			return 1;
		}
	}

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
	uint32_t node, nodes;
	int ret;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	/*
	 * Ask for several DRNG instances: what is under test below is that the
	 * status document does not carry them - with a single instance there
	 * would be nothing to leave out.
	 */
	esdm_config_max_nodes_set(4);

	/*
	 * Before esdm_init() there is no DRNG behind the status yet, which
	 * the status has to say instead of crashing on it.
	 */
	if (esdm_status(buf, sizeof(buf)) ||
	    esdm_status_json(buf, sizeof(buf))) {
		printf("Status report before esdm_init() could not be created\n");
		return 1;
	}

	ret = esdm_init();
	if (ret)
		return ret;

	ret = esdm_status(buf, sizeof(buf));
	if (ret) {
		printf("Status report could not be created: %d\n", ret);
		ret = 1;
		goto out;
	}

	/*
	 * The text is printed from the JSON status: these are the labels and
	 * section headers it has had all along, which readers of it look for.
	 */
	if (strncmp(buf, "ESDM library version: ", 22) ||
	    !strstr(buf, "\nDRNG name: ") ||
	    !strstr(buf, "\nESDM security strength in bits: ") ||
	    !strstr(buf, "\nESDM fully seeded: ") ||
	    !strstr(buf, "\nESDM entropy level: ") ||
	    !strstr(buf, "\nEntropy Source 0 properties:\n Name: ") ||
	    !strstr(buf, "\n Available entropy: ") ||
	    !strstr(buf, "\nReseed worker properties:\n Running: ") ||
	    !strstr(buf, "\nPeriodic self test properties:\n State: ") ||
	    !strstr(buf, "\n Reseed interval in seconds: ") ||
	    !strstr(buf, "\n Self test interval in seconds: ") ||
	    /* The index of an entropy source is its section's */
	    strstr(buf, " Id: ")) {
		printf("Unexpected status labels: %s\n", buf);
		ret = 1;
		goto out;
	}

	if (!strstr(buf, "DRNG name") ||
	    !strstr(buf, "ESDM security strength") ||
	    !strstr(buf, "Number of DRNG instances") ||
	    !strstr(buf, "Standards compliance") ||
	    !strstr(buf, "ESDM fully seeded") ||
	    !strstr(buf, "DRNG instance 0 properties") ||
	    !strstr(buf, " Type: initial") ||
	    !strstr(buf, " Type: prediction resistance") ||
	    !strstr(buf, "Requests until reseed") ||
	    !strstr(buf, "Seed generation") ||
	    !strstr(buf, "Last seeding time") ||
	    !strstr(buf, "Reseed worker properties") ||
	    !strstr(buf, "Periodic self test properties") ||
	    !strstr(buf, "Entropy sources tested") ||
	    /* The ESDM only hands out a status when its self tests passed */
	    !strstr(buf, " State: passed")) {
		printf("Unexpected status: %s\n", buf);
		ret = 1;
		goto out;
	}

	if (esdm_status_pr_withheld_check(buf)) {
		ret = 1;
		goto out;
	}

	/*
	 * The node instances are not in there: there is one per CPU, so a
	 * report carrying them grows with the size of the machine and runs
	 * into the buffers it travels in.
	 */
	if (strstr(buf, " Type: node")) {
		printf("Status reports a node DRNG instance: %s\n", buf);
		ret = 1;
		goto out;
	}

	printf("Status information:\n%s\n", buf);

	if (esdm_status_ntg1_2024_check(buf, false)) {
		ret = 1;
		goto out;
	}

	ret = esdm_status_json(buf, sizeof(buf));
	if (ret) {
		printf("JSON status could not be created: %d\n", ret);
		ret = 1;
		goto out;
	}

	if (esdm_status_json_check(buf) ||
	    esdm_status_ntg1_2024_check(buf, true)) {
		ret = 1;
		goto out;
	}

	printf("JSON status information:\n%s\n", buf);

	/*
	 * The node instances are reported one at a time instead - one per
	 * node, which without node support is the initial DRNG alone, whatever
	 * number of nodes is configured.
	 */
#ifdef ESDM_NODE
	nodes = esdm_config_online_nodes();
#else
	nodes = 1;
#endif
	for (node = 0; node < nodes; node++) {
		ret = esdm_status_drng_json(node, buf, sizeof(buf));
		if (ret) {
			printf("No status for node %u: %d\n", node, ret);
			ret = 1;
			goto out;
		}

		if (esdm_status_drng_json_check(buf)) {
			ret = 1;
			goto out;
		}

		printf("DRNG status of node %u: %s", node, buf);
	}

	/* And a node that has none says so, which is how a caller stops */
	ret = esdm_status_drng_json(nodes, buf, sizeof(buf));
	if (ret != -ENODEV) {
		printf("Status of a node without a DRNG instance: %d\n", ret);
		ret = 1;
		goto out;
	}

	/* The prediction resistance instance is not addressed by a node */
	ret = esdm_status_drng_pr_json(buf, sizeof(buf));
	if (ret || esdm_status_drng_json_check(buf)) {
		printf("No status for the prediction resistance DRNG: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	if (!strstr(buf, "\"type\":\"prediction resistance\"")) {
		printf("Unexpected prediction resistance DRNG status: %s\n",
		       buf);
		ret = 1;
		goto out;
	}

	printf("DRNG status of the prediction resistance instance: %s", buf);

	/*
	 * A document that does not fit is reported rather than cut in half: a
	 * consumer handed half a JSON document cannot tell it from a whole
	 * one, so the buffer comes back empty with -EMSGSIZE.
	 */
	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_drng_json(0, buf, 32);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("A DRNG status was truncated into 32 bytes: %d, %.32s\n",
		       ret, buf);
		ret = 1;
		goto out;
	}

	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_drng_pr_json(buf, 32);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("The PR DRNG status was truncated into 32 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	/* The text report is reported as incomplete, and stays readable */
	memset(buf, 0, sizeof(buf));
	ret = esdm_status(buf, 512);
	if (ret != -EMSGSIZE || !strstr(buf, "library version")) {
		printf("The status report was truncated into 512 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	memset(buf, 'x', sizeof(buf));
	ret = esdm_status_json(buf, 512);
	if (ret != -EMSGSIZE || buf[0]) {
		printf("The status document was truncated into 512 bytes: %d\n",
		       ret);
		ret = 1;
		goto out;
	}

	printf("Documents that do not fit are reported, not truncated\n");
	ret = 0;

out:
	esdm_fini();
	return ret;
}
