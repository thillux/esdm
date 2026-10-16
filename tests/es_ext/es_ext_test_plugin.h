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

/*
 * What the test plugin does, set by the test, and what was asked of it.
 *
 * @claim_bits: Entropy claimed for a buffer; UINT32_MAX claims all its bits
 * @init_ret: Return value of init
 * @get_ret: Return value of get_entropy; the buffer is filled anyway
 * @selftest_ret: Return value of selftest
 */
struct esdm_es_ext_test_control {
	uint32_t claim_bits;
	int init_ret;
	int get_ret;
	int selftest_ret;

	unsigned int init_calls;
	unsigned int fini_calls;
	unsigned int get_calls;
	unsigned int selftest_calls;
	size_t last_buflen;
};

#endif /* _ES_EXT_TEST_PLUGIN_H */
