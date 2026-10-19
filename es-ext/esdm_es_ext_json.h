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
 * The status of an external entropy source as JSON, taken the way both sides
 * take it: the ESDM, which shows the status of a plugin or a provider in its
 * own status, and the provider server of libesdm_es_ext, which wraps the
 * status of its plugin into the one it answers STATUS with. Both link json-c.
 *
 * The status comes from code that is not part of the ESDM, and from another
 * process for a provider: it is taken as the JSON object it has to be, or not
 * at all. json-c is not strict enough for that on its own, even in its strict
 * mode: it takes NaN, Infinity and -Infinity for numbers and writes them out
 * again as they came, and it takes a member name of any bytes. Either would
 * make a status JSON that a strict parser refuses.
 *
 * Everything here is static inline, as in esdm_es_ext_proto.h.
 */

#ifndef _ESDM_ES_EXT_JSON_H
#define _ESDM_ES_EXT_JSON_H

#include <json-c/json.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>

#include "esdm_es_ext_proto.h"

/*
 * The deepest nesting the status of a plugin may have, in objects and arrays
 * one in the other, the status object itself counted. The status becomes a
 * part of the ESDM status, which is no place for a document nested without
 * bounds. The status of a provider may be nested one level deeper: the
 * provider server of libesdm_es_ext wraps the status of its plugin.
 */
#define ESDM_ES_EXT_STATUS_MAX_DEPTH 8

/*
 * Are all numbers in @obj finite? JSON has none for NaN and the infinities,
 * and a number too large for a double is one of them by now. The nesting is
 * bounded by the parser.
 */
static inline bool esdm_es_ext_json_finite(struct json_object *obj)
{
	size_t i, n;

	switch (json_object_get_type(obj)) {
	case json_type_double:
		return isfinite(json_object_get_double(obj));
	case json_type_array:
		n = json_object_array_length(obj);
		for (i = 0; i < n; i++) {
			if (!esdm_es_ext_json_finite(
				    json_object_array_get_idx(obj, i)))
				return false;
		}
		return true;
	case json_type_object: {
		json_object_object_foreach(obj, key, val)
		{
			(void)key;
			if (!esdm_es_ext_json_finite(val))
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

/*
 * The JSON object of the @len bytes of text at @text - well formed, UTF-8,
 * with nothing but white space after it, no NUL in it, no number that is NaN
 * or infinite, no longer than @max bytes and nested no deeper than @depth.
 *
 * @return the object, to be released with json_object_put(), NULL for a text
 *	   that is no such object
 */
static inline struct json_object *esdm_es_ext_json_object(const char *text,
							  size_t len,
							  size_t max,
							  unsigned int depth)
{
	struct json_tokener *tok;
	struct json_object *obj = NULL;
	size_t end;

	/* All of a JSON text is UTF-8, not only its strings */
	if (!len || len > max || memchr(text, '\0', len) ||
	    !esdm_es_ext_utf8_valid(text, len))
		return NULL;

	/* json-c takes one level less than the depth it is given */
	tok = json_tokener_new_ex((int)depth + 1);
	if (!tok)
		return NULL;
	json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

	obj = json_tokener_parse_ex(tok, text, (int)len);
	if (!obj || json_tokener_get_error(tok) != json_tokener_success ||
	    !json_object_is_type(obj, json_type_object) ||
	    !esdm_es_ext_json_finite(obj))
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

#endif /* _ESDM_ES_EXT_JSON_H */
