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

#ifndef _ES_EXT_TEST_PLUGIN_H
#define _ES_EXT_TEST_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

/* The name the test plugin exports its control under */
#define ES_EXT_TEST_CONTROL_SYMBOL "esdm_es_ext_test_control"

/* The name it declares unless the test sets another one */
#define ES_EXT_TEST_NAME "es-ext-test"

/*
 * What the test plugin does, set by the test, and what was asked of it.
 *
 * @claim_bits: Entropy claimed for a buffer; UINT32_MAX claims all its bits
 * @init_ret: Return value of init
 * @get_ret: Return value of get_entropy; the buffer is filled anyway
 * @selftest_ret: Return value of selftest
 * @status_ret: Return value of status_json
 * @status_text: What status_json writes, NULL for ES_EXT_TEST_STATUS
 * @status_unterminated: status_json fills its buffer without a NUL
 * @get_delay_ms: get_entropy takes this long, a request in progress meanwhile
 * @status_delay_ms: status_json takes this long
 * @name: The name the plugin declares, "es-ext-test" unless the test sets
 *	  another one - see the plugin, which may declare none
 *
 * The delays and the counters are atomic: a test changes and reads them while
 * the plugin runs in the thread of a provider it started.
 */
struct esdm_es_ext_test_control {
	uint32_t claim_bits;
	int init_ret;
	int get_ret;
	int selftest_ret;
	int status_ret;
	const char *status_text;
	int status_unterminated;
	_Atomic unsigned int get_delay_ms;
	_Atomic unsigned int status_delay_ms;
	char name[64];

	_Atomic unsigned int init_calls;
	_Atomic unsigned int fini_calls;
	_Atomic unsigned int get_calls;
	_Atomic unsigned int selftest_calls;
	_Atomic unsigned int status_calls;
	size_t last_buflen;
	size_t last_status_buflen;
};

/*
 * A plugin served by esdm-es-ext-serve runs in a process of its own, out of
 * reach of the control of the test: the test hands its settings over in this
 * environment variable instead, which the plugin reads in its init - a comma
 * separated list of selftest_ret=N, get_ret=N, claim_bits=N, get_delay_ms=N,
 * status_delay_ms=N and name=NAME - an empty NAME declares no name.
 */
#define ES_EXT_TEST_PLUGIN_ENV "ESDM_ES_EXT_TEST_PLUGIN"

/* The status of the test plugin unless the test sets another one */
#define ES_EXT_TEST_STATUS "{\"plugin\":\"es-ext-test\",\"healthy\":true}"

#endif /* _ES_EXT_TEST_PLUGIN_H */
