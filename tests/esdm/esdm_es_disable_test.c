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
 * esdm_config_es_disable(): a disabled source stays in the status, marked
 * disabled and credited with nothing, and the ESDM serves without it. The
 * auxiliary pool and names the build does not have are refused.
 */

#include <errno.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"

#define TEST_ES "JitterRNG"

/* Is the source named @name in the JSON status @buf disabled? */
static int test_es_disabled(const char *buf, const char *name)
{
	struct json_object *root = json_tokener_parse(buf), *sources;
	int ret = -1;
	size_t i;

	if (!root)
		return -1;
	if (!json_object_object_get_ex(root, "entropy_sources", &sources))
		goto out;

	for (i = 0; i < json_object_array_length(sources); i++) {
		struct json_object *es = json_object_array_get_idx(sources, i);
		struct json_object *n, *d;

		if (!json_object_object_get_ex(es, "name", &n) ||
		    strcmp(json_object_get_string(n), name))
			continue;

		ret = json_object_object_get_ex(es, "disabled", &d) &&
		      json_object_get_boolean(d);
		break;
	}

out:
	json_object_put(root);
	return ret;
}

int main(void)
{
	char buf[65536];
	uint8_t out[32];
	int ret;

#ifndef ESDM_ES_JENT
	printf("The build has no Jitter RNG to disable\n");
	return 77;
#endif

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	if (esdm_config_es_disable("Auxiliary") != -EINVAL) {
		printf("The auxiliary pool was disabled\n");
		return 1;
	}
	if (esdm_config_es_disable("no-such-source") != -ENOENT) {
		printf("A source the build does not have was disabled\n");
		return 1;
	}
	/* In any case, as the status names it */
	if (esdm_config_es_disable("jitterrng")) {
		printf("The Jitter RNG could not be disabled\n");
		return 1;
	}

	ret = esdm_init();
	if (ret)
		return ret;

	if (esdm_status_json(buf, sizeof(buf))) {
		printf("No JSON status\n");
		ret = 1;
		goto out;
	}
	ret = test_es_disabled(buf, TEST_ES);
	if (ret != 1) {
		printf("%s is %s in the status\n", TEST_ES,
		       ret < 0 ? "missing" : "not disabled");
		ret = 1;
		goto out;
	}
	if (test_es_disabled(buf, "Auxiliary") != 0) {
		printf("The auxiliary pool is disabled in the status\n");
		ret = 1;
		goto out;
	}

	/* Unseeded output does not wait for any source */
	if (esdm_get_random_bytes(out, sizeof(out)) != (ssize_t)sizeof(out)) {
		printf("No output without the disabled source\n");
		ret = 1;
		goto out;
	}

	ret = 0;

out:
	esdm_fini();
	return ret;
}
