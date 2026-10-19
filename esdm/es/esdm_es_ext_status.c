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
#include "esdm_es_ext_proto.h"
#include "esdm_es_ext_status.h"
#include "esdm_logger.h"

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

	/* All of a JSON text is UTF-8, not only its strings */
	if (!len || len > ESDM_ES_EXT_STATUS_MAX || memchr(text, '\0', len) ||
	    !esdm_es_ext_utf8_valid(text, len))
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

void esdm_es_ext_state_name(struct json_object *obj, const char *declared,
			    const char *instance)
{
	/* Replacing the name the status put there, in its place */
	json_object_object_add(
		obj, "name",
		json_object_new_string(declared[0] ? declared : instance));
	json_object_object_add(obj, "instance",
			       json_object_new_string(instance));
}

bool esdm_es_ext_status_cache_due(const struct esdm_es_ext_status_cache *cache,
				  time_t now)
{
	return !cache->at || now < cache->at ||
	       now - cache->at >= ESDM_ES_EXT_STATUS_INTERVAL_SEC;
}

void esdm_es_ext_status_cache_set(struct esdm_es_ext_status_cache *cache,
				  struct json_object *obj, time_t now)
{
	json_object_put(cache->obj);
	cache->obj = now ? obj : NULL;
	cache->at = now;
	if (!now)
		json_object_put(obj);
}

/*
 * A copy rather than another reference: the count of references of json-c is
 * not safe for threads, and the copy goes into an ESDM status of its own.
 */
struct json_object *
esdm_es_ext_status_cache_get(const struct esdm_es_ext_status_cache *cache)
{
	struct json_object *copy = NULL;

	if (!cache->obj || json_object_deep_copy(cache->obj, &copy, NULL))
		return NULL;
	return copy;
}
