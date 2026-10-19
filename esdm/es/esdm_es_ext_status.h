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

struct json_object;

/*
 * The deepest nesting a status of an external entropy source may have, in
 * objects and arrays one in the other, the status object itself counted. The
 * status becomes a part of the ESDM status, which is no place for a document
 * nested without bounds.
 */
#define ESDM_ES_EXT_STATUS_MAX_DEPTH 8

/*
 * Parse the status a plugin or a provider reported: @len bytes of text at
 * @text, which have to be one JSON object - well formed, UTF-8, with nothing
 * but white space after it, no NUL in it, no number that is NaN or infinite,
 * no longer than ESDM_ES_EXT_STATUS_MAX bytes and nested no deeper than
 * ESDM_ES_EXT_STATUS_MAX_DEPTH.
 *
 * A status that is none is logged once, *@warned remembering that it was
 * until a valid status comes along; @who names the source in the log.
 *
 * @return the object, to be released with json_object_put(), NULL for a text
 *	   that is no such object
 */
struct json_object *esdm_es_ext_status_parse(const char *text, size_t len,
					     const char *who, bool *warned);

#endif /* _ESDM_ES_EXT_STATUS_H */
