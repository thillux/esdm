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
 * An external entropy source for the tests, steered by the test through
 * esdm_es_ext_test_control. Its data is a counter, one byte value per call, so
 * that a test can tell which call delivered a buffer.
 *
 * Compiled into a test that serves it in process, or - with
 * ES_EXT_TEST_PROVIDER defined - into a provider program of its own, which
 * serves it with esdm_es_ext_provider_main() and is steered through the
 * environment, see ES_EXT_TEST_PLUGIN_ENV. With ES_EXT_TEST_PLUGIN_BARE
 * defined, it has neither a status nor an entropy rate callback - the members
 * are NULL.
 *
 * It declares no entropy rate unless the test sets one, which the source of
 * ES_EXT_TEST_PLUGIN_RATED does by default: a source declaring its name,
 * es-ext-rated, and a rate of 128 bits per 256 bits.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "es_ext_test_plugin.h"
#include "esdm_es_ext.h"

static void es_ext_test_sleep(unsigned int ms)
{
	const struct timespec ts = { .tv_sec = ms / 1000,
				     .tv_nsec = (long)(ms % 1000) * 1000000L };

	nanosleep(&ts, NULL);
}

struct esdm_es_ext_test_control esdm_es_ext_test_control = {
	.claim_bits = UINT32_MAX,
#ifdef ES_EXT_TEST_PLUGIN_RATED
	.name = ES_EXT_TEST_RATED_NAME,
	.entropy_rate = ES_EXT_TEST_RATED_RATE,
#else
	.name = ES_EXT_TEST_NAME,
	.entropy_rate = ES_EXT_TEST_RATE_NONE,
#endif
};

#ifndef ES_EXT_TEST_PLUGIN_BARE
static uint32_t es_ext_test_entropy_rate(void *ctx);
#endif

/*
 * The source, not const: a test sets the name it declares, @name of the
 * control by default - or NULL for none.
 */
extern struct esdm_es_ext_plugin es_ext_test_plugin;

/* Take the settings of ES_EXT_TEST_PLUGIN_ENV, if there are any */
static void es_ext_test_env(struct esdm_es_ext_test_control *ctl)
{
	const char *env = getenv(ES_EXT_TEST_PLUGIN_ENV);
	char settings[1024], *setting, *save = NULL;

	if (!env || strlen(env) >= sizeof(settings))
		return;
	memcpy(settings, env, strlen(env) + 1);

	for (setting = strtok_r(settings, ";", &save); setting;
	     setting = strtok_r(NULL, ";", &save)) {
		char *val = strchr(setting, '=');
		long n;

		if (!val)
			continue;
		*val++ = '\0';
		n = strtol(val, NULL, 0);

		if (!strcmp(setting, "name")) {
			/* An empty one declares none */
			snprintf(ctl->name, sizeof(ctl->name), "%s", val);
			es_ext_test_plugin.name = val[0] ? ctl->name : NULL;
		} else if (!strcmp(setting, "init_ret"))
			ctl->init_ret = (int)n;
		else if (!strcmp(setting, "selftest_ret"))
			ctl->selftest_ret = (int)n;
		else if (!strcmp(setting, "get_ret"))
			ctl->get_ret = (int)n;
		else if (!strcmp(setting, "claim_bits"))
			ctl->claim_bits = (uint32_t)n;
		else if (!strcmp(setting, "get_delay_ms"))
			ctl->get_delay_ms = (unsigned int)n;
		else if (!strcmp(setting, "status_delay_ms"))
			ctl->status_delay_ms = (unsigned int)n;
		else if (!strcmp(setting, "rate"))
			ctl->entropy_rate = (uint32_t)n;
		else if (!strcmp(setting, "status_ret"))
			ctl->status_ret = (int)n;
		else if (!strcmp(setting, "status")) {
			snprintf(ctl->status_buf, sizeof(ctl->status_buf), "%s",
				 val);
			ctl->status_text = ctl->status_buf;
		} else if (!strcmp(setting, "status_size")) {
			/* A status of this many bytes: {"x":"aaa..."} */
			size_t size = (size_t)n;

			if (size < 8 || size >= sizeof(ctl->status_buf))
				continue;
			memset(ctl->status_buf, 'a', size);
			memcpy(ctl->status_buf, "{\"x\":\"", 6);
			memcpy(ctl->status_buf + size - 2, "\"}", 3);
			ctl->status_text = ctl->status_buf;
		}
	}
}

static int es_ext_test_init(void **ctx)
{
	struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

	es_ext_test_env(ctl);
	ctl->init_calls++;
	*ctx = ctl;

#ifndef ES_EXT_TEST_PLUGIN_BARE
	/* Asked after the init: the rate the test set, or none */
	es_ext_test_plugin.entropy_rate =
		ctl->entropy_rate == ES_EXT_TEST_RATE_NONE ?
			NULL :
			es_ext_test_entropy_rate;
#endif

	return ctl->init_ret;
}

static void es_ext_test_fini(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->fini_calls++;
}

static int es_ext_test_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
				   uint32_t *entropy_bits)
{
	struct esdm_es_ext_test_control *ctl = ctx;
	unsigned int calls = ++ctl->get_calls, delay = ctl->get_delay_ms;
	uint32_t claim;
	int ret;

	ctl->last_buflen = buflen;

	if (delay)
		es_ext_test_sleep(delay);

	/* Filled in any case, so that a test sees whether the data is wiped */
	memset(buf, (int)(calls & 0xff), buflen);

	ret = ctl->get_ret;
	if (ret)
		return ret;

	claim = ctl->claim_bits;
	*entropy_bits = claim == UINT32_MAX ? (uint32_t)buflen * 8 : claim;
	return 0;
}

static int es_ext_test_selftest(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->selftest_calls++;

	return ctl->selftest_ret;
}

#ifndef ES_EXT_TEST_PLUGIN_BARE
static uint32_t es_ext_test_entropy_rate(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->rate_calls++;
	return ctl->entropy_rate;
}

static int es_ext_test_status_json(void *ctx, char *buf, size_t buflen)
{
	struct esdm_es_ext_test_control *ctl = ctx;
	unsigned int delay = ctl->status_delay_ms;
	const char *text;
	int len, ret;

	ctl->status_calls++;
	ctl->last_status_buflen = buflen;

	if (delay)
		es_ext_test_sleep(delay);

	if (ctl->status_unterminated) {
		memset(buf, '{', buflen);
		return 0;
	}

	ret = ctl->status_ret;
	if (ret)
		return ret;

	text = ctl->status_text;
	len = snprintf(buf, buflen, "%s", text ? text : ES_EXT_TEST_STATUS);
	return len >= 0 && (size_t)len < buflen ? 0 : -EMSGSIZE;
}
#endif /* ES_EXT_TEST_PLUGIN_BARE */

struct esdm_es_ext_plugin es_ext_test_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = esdm_es_ext_test_control.name,
	.init = es_ext_test_init,
	.fini = es_ext_test_fini,
	.get_entropy = es_ext_test_get_entropy,
	.selftest = es_ext_test_selftest,
#ifndef ES_EXT_TEST_PLUGIN_BARE
	.status_json = es_ext_test_status_json,
	.entropy_rate = es_ext_test_entropy_rate,
#endif
};

#ifdef ES_EXT_TEST_PROVIDER
/* A provider program, as one of its own making is - see the file header */
int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_main(&es_ext_test_plugin, argc, argv);
}
#endif
