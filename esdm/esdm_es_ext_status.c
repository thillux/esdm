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
 */

#include <json-c/json.h>
#include <string.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_status.h"
#include "esdm_logger.h"

static struct json_object *esdm_es_ext_status_obj(const char *text, size_t len)
{
	struct json_tokener *tok;
	struct json_object *obj = NULL;
	size_t end;

	if (!len || len > ESDM_ES_EXT_STATUS_MAX || memchr(text, '\0', len))
		return NULL;

	/* json-c takes one level less than the depth it is given */
	tok = json_tokener_new_ex(ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
	if (!tok)
		return NULL;
	json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

	obj = json_tokener_parse_ex(tok, text, (int)len);
	if (!obj || json_tokener_get_error(tok) != json_tokener_success ||
	    !json_object_is_type(obj, json_type_object))
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
