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
 * at all, before it becomes a part of the ESDM status - see
 * esdm_es_ext_json.h, whose checks the provider server of libesdm_es_ext
 * shares.
 */

#include <json-c/json.h>
#include <stdint.h>
#include <string.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_ext_status.h"
#include "esdm_logger.h"

struct json_object *esdm_es_ext_status_parse(const char *text, size_t len,
					     size_t max, unsigned int depth,
					     const char *who, bool *warned)
{
	struct json_object *obj =
		esdm_es_ext_json_object(text, len, max, depth);

	if (!obj) {
		if (!*warned)
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES %s: its status is no JSON object of up to %zu bytes, left out\n",
				who, max);
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
	json_object_object_add(obj, "name",
			       json_object_new_string(declared[0] ? declared :
								    instance));
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
