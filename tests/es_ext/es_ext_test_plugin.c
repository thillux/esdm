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
 * An external entropy source plugin for the tests, steered by the test through
 * esdm_es_ext_test_control, which the plugin exports next to the plugin
 * itself. Its data is a counter, one byte value per call, so that a test can
 * tell which call delivered a buffer.
 *
 * Built as a plugin library (shared_module) and, with ES_EXT_TEST_PLUGIN_STATIC
 * defined, compiled into a test that serves it in process. With
 * ES_EXT_TEST_PLUGIN_V1 defined, it is a plugin of version 1, which has no
 * status - the status callback it sets all the same stands for whatever lies
 * beyond the struct of such a plugin, which must not be called.
 */

#include <errno.h>
#include <stdio.h>
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

ESDM_ES_EXT_PLUGIN_EXPORT
struct esdm_es_ext_test_control esdm_es_ext_test_control = {
	.claim_bits = UINT32_MAX,
};

static int es_ext_test_init(void **ctx)
{
	struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

	ctl->init_calls++;
	*ctx = ctl;

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

	ctl->get_calls++;
	ctl->last_buflen = buflen;

	if (ctl->get_delay_ms)
		es_ext_test_sleep(ctl->get_delay_ms);

	/* Filled in any case, so that a test sees whether the data is wiped */
	memset(buf, (int)(ctl->get_calls & 0xff), buflen);

	if (ctl->get_ret)
		return ctl->get_ret;

	*entropy_bits = ctl->claim_bits == UINT32_MAX ? (uint32_t)buflen * 8 :
							ctl->claim_bits;
	return 0;
}

static int es_ext_test_selftest(void *ctx)
{
	struct esdm_es_ext_test_control *ctl = ctx;

	ctl->selftest_calls++;

	return ctl->selftest_ret;
}

static int es_ext_test_status_json(void *ctx, char *buf, size_t buflen)
{
	struct esdm_es_ext_test_control *ctl = ctx;
	int len;

	ctl->status_calls++;
	ctl->last_status_buflen = buflen;

	if (ctl->status_delay_ms)
		es_ext_test_sleep(ctl->status_delay_ms);

	if (ctl->status_unterminated) {
		memset(buf, '{', buflen);
		return 0;
	}

	if (ctl->status_ret)
		return ctl->status_ret;

	len = snprintf(buf, buflen, "%s",
		       ctl->status_text ? ctl->status_text :
					  ES_EXT_TEST_STATUS);
	return len >= 0 && (size_t)len < buflen ? 0 : -EMSGSIZE;
}

#ifdef ES_EXT_TEST_PLUGIN_STATIC
const struct esdm_es_ext_plugin es_ext_test_plugin = {
#else
ESDM_ES_EXT_PLUGIN_EXPORT
const struct esdm_es_ext_plugin esdm_es_ext_plugin = {
#endif
#ifdef ES_EXT_TEST_PLUGIN_V1
	.version = 1,
#else
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
#endif
	.name = "es-ext-test",
	.init = es_ext_test_init,
	.fini = es_ext_test_fini,
	.get_entropy = es_ext_test_get_entropy,
	.selftest = es_ext_test_selftest,
	.status_json = es_ext_test_status_json,
};
