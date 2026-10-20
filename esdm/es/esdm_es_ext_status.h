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

#ifndef _ESDM_ES_EXT_STATUS_H
#define _ESDM_ES_EXT_STATUS_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include "esdm_es_ext_json.h"

struct json_object;

/*
 * Parse the status a provider reported: @len bytes of text at @text, which
 * have to be one JSON object - see esdm_es_ext_json_object() - of no more than
 * @max bytes, nested no deeper than @depth: ESDM_ES_EXT_PROTO_STATUS_MAX and
 * one level more than ESDM_ES_EXT_STATUS_MAX_DEPTH, as the provider server of
 * libesdm_es_ext wraps the status its source reports.
 *
 * A status that is none is logged once, *@warned remembering that it was
 * until a valid status comes along; @who names the source in the log.
 *
 * @return the object, to be released with json_object_put(), NULL for a text
 *	   that is no such object
 */
struct json_object *esdm_es_ext_status_parse(const char *text, size_t len,
					     size_t max, unsigned int depth,
					     const char *who, bool *warned);

/*
 * Room for how a log message names an external source: its name in the ES
 * table and the name it declares, see esdm_es_extsock.c
 */
#define ESDM_ES_EXT_LABEL_SIZE 64

/*
 * Add the name of an external source to its state @obj: the name it declares,
 * @declared - empty for none - in place of the name of its entry in the ES
 * table, @instance, which it keeps as "instance". See struct esdm_es_cb.
 */
void esdm_es_ext_state_name(struct json_object *obj, const char *declared,
			    const char *instance);

/*
 * The status of a provider is asked for at most once per this many
 * seconds, and the last one obtained shown in between: it is asked for with
 * the source held, a request of a seeding waiting meanwhile - and whoever may
 * ask for the ESDM status is not to make the seedings wait at will.
 */
#ifndef ESDM_ES_EXT_STATUS_INTERVAL_SEC
#define ESDM_ES_EXT_STATUS_INTERVAL_SEC 5
#endif

/*
 * The status a source reported last. The source guards it with a lock of its
 * own, which is never held while the source is asked for a status.
 *
 * @obj: The status, NULL for none
 * @at: When it was obtained, monotonic seconds - 0 for not yet
 */
struct esdm_es_ext_status_cache {
	struct json_object *obj;
	time_t at;
};

/* Is the status to be asked for anew at @now, monotonic seconds? */
bool esdm_es_ext_status_cache_due(const struct esdm_es_ext_status_cache *cache,
				  time_t now);

/*
 * Keep @obj, which the cache takes over - NULL for none - as the status
 * obtained at @now. @now 0 forgets the status kept.
 */
void esdm_es_ext_status_cache_set(struct esdm_es_ext_status_cache *cache,
				  struct json_object *obj, time_t now);

/* A copy of the status kept, to be released with json_object_put(), or NULL */
struct json_object *
esdm_es_ext_status_cache_get(const struct esdm_es_ext_status_cache *cache);

#endif /* _ESDM_ES_EXT_STATUS_H */
