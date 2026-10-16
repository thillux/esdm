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

#ifndef _ESDM_STATUS_TXT_H
#define _ESDM_STATUS_TXT_H

#include <json-c/json.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The label a member is printed with.
 *
 * @parent: Name of the member holding the object the member is in - for the
 *	    members of the objects of an array the name of the array -, "" for
 *	    a member of the top level object, NULL for a member anywhere.
 * @key: Name of the member.
 * @label: What the member is printed as, NULL to leave it out.
 */
struct esdm_status_txt_label {
	const char *parent;
	const char *key;
	const char *label;
};

/*
 * Print the JSON object @obj as human-readable text into @buf of @buflen bytes.
 *
 * Every member is a line of its own, "Label: value". A member that is an
 * object is a section, "Label properties:", followed by its members indented
 * by one more space; an array of objects is one such section per object,
 * "Label <index> properties:". An array of anything else is one line with its
 * values separated by commas. null is printed as N/A.
 *
 * The label of a member is the one @labels holds for it - an array terminated
 * by an entry with a NULL @key, an entry for the parent of the member taking
 * precedence over one for any parent. A member without one is labelled with
 * its name, the underscores turned into spaces and the first letter
 * capitalized. Control characters in names and values are printed as '?',
 * so that no value can add a line of its own.
 *
 * @return 0 on success, -EMSGSIZE if the text does not fit into the buffer -
 *	   which then holds as much of it as fits, terminated -, -EINVAL for
 *	   invalid arguments
 */
int esdm_status_txt(struct json_object *obj,
		    const struct esdm_status_txt_label *labels, char *buf,
		    size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_STATUS_TXT_H */
