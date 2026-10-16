/*
 * The state an entropy source reports through its state callback, for the
 * tests of the entropy sources: a JSON object, whose members are checked by
 * name and type.
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

#ifndef ESDM_TEST_ES_STATE_CHECK_H
#define ESDM_TEST_ES_STATE_CHECK_H

#include <json-c/json.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esdm_es_mgr_cb.h"

/*
 * The state of @es, to be released with json_object_put(); NULL if it has no
 * state callback.
 */
static inline struct json_object *es_state_get(const struct esdm_es_cb *es)
{
	struct json_object *obj;

	if (!es->state)
		return NULL;

	obj = json_object_new_object();
	if (obj)
		es->state(obj);

	return obj;
}

/* Does @obj have a member @key of @type? */
static inline bool es_state_has(struct json_object *obj, const char *key,
				json_type type)
{
	struct json_object *val;

	if (!obj || !json_object_object_get_ex(obj, key, &val))
		return false;

	/* A member of type null is NULL */
	if (type == json_type_null)
		return val == NULL;

	return val && json_object_is_type(val, type);
}

/* The string member @key of @obj, NULL if there is none */
static inline const char *es_state_str(struct json_object *obj, const char *key)
{
	struct json_object *val;

	if (!es_state_has(obj, key, json_type_string) ||
	    !json_object_object_get_ex(obj, key, &val))
		return NULL;

	return json_object_get_string(val);
}

/* Is the string member @key of @obj @expected? */
static inline bool es_state_str_is(struct json_object *obj, const char *key,
				   const char *expected)
{
	const char *val = es_state_str(obj, key);

	return val && !strcmp(val, expected);
}

/* Does the string member @key of @obj contain @needle? */
static inline bool es_state_str_has(struct json_object *obj, const char *key,
				    const char *needle)
{
	const char *val = es_state_str(obj, key);

	return val && strstr(val, needle);
}

/* The integer member @key of @obj, @dflt if there is none */
static inline int64_t es_state_int(struct json_object *obj, const char *key,
				   int64_t dflt)
{
	struct json_object *val;

	if (!es_state_has(obj, key, json_type_int) ||
	    !json_object_object_get_ex(obj, key, &val))
		return dflt;

	return json_object_get_int64(val);
}

/* The state as text, for the log of a test */
static inline const char *es_state_print(struct json_object *obj)
{
	if (!obj)
		return "(none)";

	return json_object_to_json_string_ext(
		obj, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
}

#endif /* ESDM_TEST_ES_STATE_CHECK_H */
