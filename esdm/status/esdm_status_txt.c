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
 * The text form of a JSON status document - see esdm_status_txt.h. The ESDM
 * keeps its status as JSON only, and every text interface prints it from
 * there, so the two cannot tell different stories.
 */

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "esdm_status_txt.h"

/* The text printed so far */
struct esdm_status_txt_out {
	char *buf;
	size_t buflen;
	size_t len;
	bool truncated;
};

/*
 * Append @len bytes of @str, every control character replaced by '?' - a
 * value of a provider or the kernel must not be able to start a line of its
 * own, or a status that is no status at all.
 */
static void esdm_status_txt_putn(struct esdm_status_txt_out *out,
				 const char *str, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned char c = (unsigned char)str[i];

		/* Room for the terminating NUL */
		if (out->len + 1 >= out->buflen) {
			out->truncated = true;
			break;
		}

		out->buf[out->len++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
	}

	out->buf[out->len] = '\0';
}

static void esdm_status_txt_puts(struct esdm_status_txt_out *out,
				 const char *str)
{
	esdm_status_txt_putn(out, str, strlen(str));
}

/* Newlines are the one control character printed as such */
static void esdm_status_txt_newline(struct esdm_status_txt_out *out)
{
	if (out->len + 1 >= out->buflen) {
		out->truncated = true;
		return;
	}

	out->buf[out->len++] = '\n';
	out->buf[out->len] = '\0';
}

static void esdm_status_txt_indent(struct esdm_status_txt_out *out,
				   unsigned int depth)
{
	while (depth--)
		esdm_status_txt_puts(out, " ");
}

static void esdm_status_txt_index(struct esdm_status_txt_out *out, size_t idx)
{
	char num[24];
	size_t i = sizeof(num);

	num[--i] = '\0';
	do {
		num[--i] = (char)('0' + idx % 10);
		idx /= 10;
	} while (idx && i);

	esdm_status_txt_puts(out, num + i);
}

/*
 * The label of member @key in the object held by member @parent: the entry of
 * @labels for that parent, else the one for any parent.
 *
 * @return true if the table holds one, which is in *@label then - NULL for a
 *	   member to leave out
 */
static bool esdm_status_txt_lookup(const struct esdm_status_txt_label *labels,
				   const char *parent, const char *key,
				   const char **label)
{
	const struct esdm_status_txt_label *any = NULL;

	if (!labels)
		return false;

	for (; labels->key; labels++) {
		if (strcmp(labels->key, key))
			continue;

		if (!labels->parent) {
			if (!any)
				any = labels;
			continue;
		}

		if (!strcmp(labels->parent, parent)) {
			*label = labels->label;
			return true;
		}
	}

	if (any) {
		*label = any->label;
		return true;
	}

	return false;
}

/* The name of a member as its label: "foo_bar" turns into "Foo bar" */
static void esdm_status_txt_derived(struct esdm_status_txt_out *out,
				    const char *key)
{
	bool first = true;

	for (; *key; key++) {
		char c = *key;

		if (c == '_')
			c = ' ';
		else if (first && c >= 'a' && c <= 'z')
			c = (char)(c - 'a' + 'A');
		first = false;

		esdm_status_txt_putn(out, &c, 1);
	}
}

static void esdm_status_txt_label(struct esdm_status_txt_out *out,
				  const char *label, const char *key)
{
	if (label)
		esdm_status_txt_puts(out, label);
	else
		esdm_status_txt_derived(out, key);
}

/* A value that is no object: a nested array is printed as JSON */
static void esdm_status_txt_value(struct esdm_status_txt_out *out,
				  struct json_object *val)
{
	if (!val) {
		esdm_status_txt_puts(out, "N/A");
		return;
	}

	if (json_object_is_type(val, json_type_string)) {
		esdm_status_txt_putn(out, json_object_get_string(val),
				     (size_t)json_object_get_string_len(val));
		return;
	}

	esdm_status_txt_puts(
		out, json_object_to_json_string_ext(
			     val, JSON_C_TO_STRING_PLAIN |
					  JSON_C_TO_STRING_NOSLASHESCAPE));
}

static bool esdm_status_txt_scalar(struct json_object *val)
{
	return !json_object_is_type(val, json_type_object) &&
	       !json_object_is_type(val, json_type_array);
}

static void esdm_status_txt_object(struct esdm_status_txt_out *out,
				   const struct esdm_status_txt_label *labels,
				   const char *parent, struct json_object *obj,
				   unsigned int depth);

/* An array of anything but objects only: one line */
static void esdm_status_txt_array_line(struct esdm_status_txt_out *out,
				       struct json_object *arr)
{
	size_t i, n = json_object_array_length(arr);

	esdm_status_txt_puts(out, ":");
	for (i = 0; i < n; i++) {
		esdm_status_txt_puts(out, i ? ", " : " ");
		esdm_status_txt_value(out, json_object_array_get_idx(arr, i));
	}
	esdm_status_txt_newline(out);
}

static void esdm_status_txt_array(struct esdm_status_txt_out *out,
				  const struct esdm_status_txt_label *labels,
				  const char *label, const char *key,
				  struct json_object *arr, unsigned int depth)
{
	size_t i, n = json_object_array_length(arr);
	bool scalars = true;

	for (i = 0; i < n; i++) {
		struct json_object *elem = json_object_array_get_idx(arr, i);

		if (elem && json_object_is_type(elem, json_type_object))
			scalars = false;
	}

	if (scalars) {
		esdm_status_txt_indent(out, depth);
		esdm_status_txt_label(out, label, key);
		esdm_status_txt_array_line(out, arr);
		return;
	}

	/* One section per object, one line per anything else */
	for (i = 0; i < n; i++) {
		struct json_object *elem = json_object_array_get_idx(arr, i);

		esdm_status_txt_indent(out, depth);
		esdm_status_txt_label(out, label, key);
		esdm_status_txt_puts(out, " ");
		esdm_status_txt_index(out, i);

		if (elem && json_object_is_type(elem, json_type_object)) {
			esdm_status_txt_puts(out, " properties:");
			esdm_status_txt_newline(out);
			esdm_status_txt_object(out, labels, key, elem,
					       depth + 1);
			continue;
		}

		esdm_status_txt_puts(out, ": ");
		esdm_status_txt_value(out, elem);
		esdm_status_txt_newline(out);
	}
}

static void esdm_status_txt_member(struct esdm_status_txt_out *out,
				   const struct esdm_status_txt_label *labels,
				   const char *parent, const char *key,
				   struct json_object *val, unsigned int depth)
{
	const char *label = NULL;

	if (esdm_status_txt_lookup(labels, parent, key, &label) && !label)
		return;

	if (val && json_object_is_type(val, json_type_array)) {
		esdm_status_txt_array(out, labels, label, key, val, depth);
		return;
	}

	esdm_status_txt_indent(out, depth);
	esdm_status_txt_label(out, label, key);

	if (val && !esdm_status_txt_scalar(val)) {
		esdm_status_txt_puts(out, " properties:");
		esdm_status_txt_newline(out);
		esdm_status_txt_object(out, labels, key, val, depth + 1);
		return;
	}

	esdm_status_txt_puts(out, ": ");
	esdm_status_txt_value(out, val);
	esdm_status_txt_newline(out);
}

static void esdm_status_txt_object(struct esdm_status_txt_out *out,
				   const struct esdm_status_txt_label *labels,
				   const char *parent, struct json_object *obj,
				   unsigned int depth)
{
	json_object_object_foreach(obj, key, val)
	{
		if (out->truncated)
			return;
		esdm_status_txt_member(out, labels, parent, key, val, depth);
	}
}

int esdm_status_txt(struct json_object *obj,
		    const struct esdm_status_txt_label *labels, char *buf,
		    size_t buflen)
{
	struct esdm_status_txt_out out = { .buf = buf, .buflen = buflen };

	if (!buf || !buflen)
		return -EINVAL;
	buf[0] = '\0';

	if (!obj || !json_object_is_type(obj, json_type_object))
		return -EINVAL;

	esdm_status_txt_object(&out, labels, "", obj, 0);

	return out.truncated ? -EMSGSIZE : 0;
}
