/*
 * ESDM External Entropy Source: the status a plugin or a provider reports
 *
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
 * The status comes from code that is not part of the ESDM, and from another
 * process for a provider: it is taken as the JSON object it has to be, or not
 * at all, before it becomes a part of the ESDM status.
 *
 * json-c is not strict enough for that on its own, even in its strict mode: it
 * takes NaN, Infinity and -Infinity for numbers and writes them out again as
 * they came, and it takes a member name of any bytes. Either would make the
 * ESDM status JSON that a strict parser refuses.
 */

#include <json-c/json.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_status.h"
#include "esdm_logger.h"

/*
 * Is @text of @len bytes UTF-8 as RFC 3629 has it - no overlong form, no
 * surrogate, nothing beyond U+10FFFF? All of a JSON text is, not only its
 * strings.
 */
static bool esdm_es_ext_status_utf8(const unsigned char *text, size_t len)
{
	size_t i = 0;

	while (i < len) {
		uint32_t cp;
		size_t n, j;

		if (text[i] < 0x80) {
			i++;
			continue;
		}

		/* The lead byte tells how many continuation bytes follow */
		if (text[i] >= 0xc2 && text[i] <= 0xdf) {
			n = 1;
			cp = text[i] & 0x1f;
		} else if (text[i] >= 0xe0 && text[i] <= 0xef) {
			n = 2;
			cp = text[i] & 0x0f;
		} else if (text[i] >= 0xf0 && text[i] <= 0xf4) {
			n = 3;
			cp = text[i] & 0x07;
		} else {
			return false;
		}

		if (len - i <= n)
			return false;
		for (j = 1; j <= n; j++) {
			if ((text[i + j] & 0xc0) != 0x80)
				return false;
			cp = (cp << 6) | (text[i + j] & 0x3f);
		}

		if ((n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) ||
		    (cp >= 0xd800 && cp <= 0xdfff) || cp > 0x10ffff)
			return false;

		i += n + 1;
	}

	return true;
}

/*
 * Are all numbers in @obj finite? JSON has none for NaN and the infinities,
 * and a number too large for a double is one of them by now. The nesting is
 * bounded by the parser.
 */
static bool esdm_es_ext_status_finite(struct json_object *obj)
{
	size_t i, n;

	switch (json_object_get_type(obj)) {
	case json_type_double:
		return isfinite(json_object_get_double(obj));
	case json_type_array:
		n = json_object_array_length(obj);
		for (i = 0; i < n; i++) {
			if (!esdm_es_ext_status_finite(
				    json_object_array_get_idx(obj, i)))
				return false;
		}
		return true;
	case json_type_object: {
		json_object_object_foreach(obj, key, val)
		{
			(void)key;
			if (!esdm_es_ext_status_finite(val))
				return false;
		}
		return true;
	}
	case json_type_null:
	case json_type_boolean:
	case json_type_int:
	case json_type_string:
	default:
		return true;
	}
}

static struct json_object *esdm_es_ext_status_obj(const char *text, size_t len)
{
	struct json_tokener *tok;
	struct json_object *obj = NULL;
	size_t end;

	if (!len || len > ESDM_ES_EXT_STATUS_MAX || memchr(text, '\0', len) ||
	    !esdm_es_ext_status_utf8((const unsigned char *)text, len))
		return NULL;

	/* json-c takes one level less than the depth it is given */
	tok = json_tokener_new_ex(ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
	if (!tok)
		return NULL;
	json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

	obj = json_tokener_parse_ex(tok, text, (int)len);
	if (!obj || json_tokener_get_error(tok) != json_tokener_success ||
	    !json_object_is_type(obj, json_type_object) ||
	    !esdm_es_ext_status_finite(obj))
		goto err;

	/* One object, and nothing after it */
	for (end = json_tokener_get_parse_end(tok); end < len; end++) {
		if (text[end] != ' ' && text[end] != '\t' &&
		    text[end] != '\n' && text[end] != '\r')
			goto err;
	}

	json_tokener_free(tok);
	return obj;

err:
	json_object_put(obj);
	json_tokener_free(tok);
	return NULL;
}

struct json_object *esdm_es_ext_status_parse(const char *text, size_t len,
					     const char *who, bool *warned)
{
	struct json_object *obj = esdm_es_ext_status_obj(text, len);

	if (!obj) {
		if (!*warned)
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES %s: its status is no JSON object of up to %u bytes, left out\n",
				who, ESDM_ES_EXT_STATUS_MAX);
		*warned = true;
		return NULL;
	}

	*warned = false;
	return obj;
}
