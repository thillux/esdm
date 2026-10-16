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
 * Plugin libraries the loader has to refuse, one per build:
 * ES_EXT_BAD_VERSION exports a plugin of a version this API does not know,
 * ES_EXT_BAD_NO_GET one without get_entropy, and without either the library
 * exports no plugin at all.
 */

#include "esdm_es_ext.h"

#if defined(ES_EXT_BAD_VERSION) || defined(ES_EXT_BAD_NO_GET)

static int es_ext_bad_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
				  uint32_t *entropy_bits)
{
	(void)ctx;
	(void)buf;
	(void)buflen;
	*entropy_bits = 0;
	return 0;
}

ESDM_ES_EXT_PLUGIN_EXPORT
const struct esdm_es_ext_plugin esdm_es_ext_plugin = {
#ifdef ES_EXT_BAD_VERSION
	.version = ESDM_ES_EXT_PLUGIN_VERSION + 1,
	.get_entropy = es_ext_bad_get_entropy,
#else
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.get_entropy = NULL,
#endif
	.name = "es-ext-bad",
};

/* Keeps the compiler quiet where the callback is not referenced */
ESDM_ES_EXT_PLUGIN_EXPORT
int (*es_ext_bad_unused)(void *, uint8_t *, size_t,
			 uint32_t *) = es_ext_bad_get_entropy;

#else

ESDM_ES_EXT_PLUGIN_EXPORT
int esdm_es_ext_not_a_plugin = 1;

#endif
