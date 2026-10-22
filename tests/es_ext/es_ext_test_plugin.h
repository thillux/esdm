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

/* The name it declares unless the test sets another one */
#define ES_EXT_TEST_NAME "es-ext-test"

/* No entropy rate declared */
#define ES_EXT_TEST_RATE_NONE UINT32_MAX

/* What the source of ES_EXT_TEST_PLUGIN_RATED declares */
#define ES_EXT_TEST_RATED_NAME "es-ext-rated"
#define ES_EXT_TEST_RATED_RATE 128

/*
 * What the test source does, set by the test, and what was asked of it.
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
 * @name: The name the source declares, "es-ext-test" unless the test sets
 *	  another one - see the source, which may declare none
 * @entropy_rate: The rate the source declares, taken by its init:
 *		  ES_EXT_TEST_RATE_NONE for none
 * @status_buf: Room for a status of the environment, see below
 *
 * What a test changes or reads while the source runs in the thread of a
 * provider it started is atomic: what the callbacks do, the delays, the
 * counters and what the callbacks were asked for - a status the test hands
 * over at @status_text is written before the pointer is stored. The rest is
 * set before the provider starts: @init_ret, @name and @entropy_rate, which
 * the init takes, and @status_buf, which the init fills from the environment.
 */
struct esdm_es_ext_test_control {
	_Atomic uint32_t claim_bits;
	int init_ret;
	_Atomic int get_ret;
	_Atomic int selftest_ret;
	_Atomic int status_ret;
	const char *_Atomic status_text;
	_Atomic int status_unterminated;
	_Atomic unsigned int get_delay_ms;
	_Atomic unsigned int status_delay_ms;
	char name[64];
	uint32_t entropy_rate;
	char status_buf[1024];

	_Atomic unsigned int init_calls;
	_Atomic unsigned int fini_calls;
	_Atomic unsigned int get_calls;
	_Atomic unsigned int selftest_calls;
	_Atomic unsigned int status_calls;
	_Atomic unsigned int rate_calls;
	_Atomic size_t last_buflen;
	_Atomic size_t last_status_buflen;
};

/*
 * A source served by a provider program of the test runs in a process of its
 * own, out of reach of the control of the test: the test hands its settings
 * over in this environment variable instead, which the source reads in its
 * init - a list separated by semicolons of init_ret=N, selftest_ret=N,
 * get_ret=N, claim_bits=N, get_delay_ms=N, status_delay_ms=N, name=NAME - an
 * empty NAME declares no name - rate=N, the entropy rate it declares,
 * status_ret=N, status=TEXT, the status it reports, and status_size=N, a
 * status of N bytes.
 */
#define ES_EXT_TEST_PLUGIN_ENV "ESDM_ES_EXT_TEST_PLUGIN"

/* The status of the test source unless the test sets another one */
#define ES_EXT_TEST_STATUS "{\"plugin\":\"es-ext-test\",\"healthy\":true}"

#endif /* _ES_EXT_TEST_PLUGIN_H */
