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
 * Does the code point @cp steer the terminal of whoever reads the status,
 * rather than show as text? A C1 control does - U+009B is the CSI of a
 * terminal taking UTF-8 - and so does a bidirectional control, which reorders
 * the text around it, see esdm_es_ext_bidi_control(). The C0 controls are
 * none of these: JSON escapes them in what it writes, and the text form of the
 * status replaces them.
 */
static inline bool esdm_es_ext_json_steers(uint32_t cp)
{
	return (cp >= 0x80 && cp <= 0x9f) || esdm_es_ext_bidi_control(cp);
}

/*
 * Is the string @str of @len bytes UTF-8 with nothing in it that steers a
 * terminal, see esdm_es_ext_json_steers()?
 */
static inline bool esdm_es_ext_json_shown(const char *str, size_t len)
{
	size_t i = 0;
	uint32_t cp;

	while (i < len) {
		if (!esdm_es_ext_utf8_next((const unsigned char *)str, len, &i,
					   &cp) ||
		    esdm_es_ext_json_steers(cp))
			return false;
	}

	return true;
}

/*
 * Are all numbers in @obj finite, and are all its strings - the names of its
 * members as well - shown as text, see esdm_es_ext_json_shown()? JSON has no
 * number for NaN and the infinities, and a number too large for a double is
 * one of them by now. A string may carry any code point as an escape, which
 * the text of the status checked before parsing does not show. The nesting is
 * bounded by the parser.
 */
static inline bool esdm_es_ext_json_clean(struct json_object *obj)
{
	size_t i, n;

	switch (json_object_get_type(obj)) {
	case json_type_double:
		return isfinite(json_object_get_double(obj));
	case json_type_string:
		return esdm_es_ext_json_shown(
			json_object_get_string(obj),
			(size_t)json_object_get_string_len(obj));
	case json_type_array:
		n = json_object_array_length(obj);
		for (i = 0; i < n; i++) {
			if (!esdm_es_ext_json_clean(
				    json_object_array_get_idx(obj, i)))
				return false;
		}
		return true;
	case json_type_object: {
		json_object_object_foreach(obj, key, val)
		{
			if (!esdm_es_ext_json_shown(key, strlen(key)) ||
			    !esdm_es_ext_json_clean(val))
				return false;
		}
		return true;
	}
	case json_type_null:
	case json_type_boolean:
	case json_type_int:
	default:
		return true;
	}
}

/*
 * The JSON object of the @len bytes of text at @text - well formed, UTF-8,
 * with nothing but white space after it, no NUL in it, no number that is NaN
 * or infinite, no string with a C1 control or a bidirectional control in it
 * - as an escape either - no longer than @max bytes and nested no deeper than
 * @depth.
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
	    !esdm_es_ext_json_clean(obj))
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
