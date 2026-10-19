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
 * The external entropy source protocol and plugin checks, shared by the two
 * sides: the ESDM (esdm_es_extlib.c, esdm_es_extsock.c) and libesdm_es_ext.
 *
 * Everything here is static inline. The ESDM does not link against
 * libesdm_es_ext, and a program linking both - a test - must not see two
 * definitions of one symbol.
 */

#ifndef _ESDM_ES_EXT_PROTO_H
#define _ESDM_ES_EXT_PROTO_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "esdm_es_ext.h"
#include "memset_secure.h"

/*
 * The largest errno a status may carry, as the kernel bounds them (MAX_ERRNO):
 * a status beyond is no errno, and negating INT32_MIN is undefined.
 */
#define ESDM_ES_EXT_PROTO_MAX_ERRNO 4095

/*
 * The largest data an answer carries: the data of a GET_ENTROPY, or a status -
 * what the buffers of an answer have room for
 */
#define ESDM_ES_EXT_PROTO_MAX_RSP_DATA                                         \
	(ESDM_ES_EXT_PROTO_STATUS_MAX > ESDM_ES_EXT_PROTO_MAX_DATA ?           \
		 ESDM_ES_EXT_PROTO_STATUS_MAX :                                \
		 ESDM_ES_EXT_PROTO_MAX_DATA)

/* The status of a plugin fits into the one of its provider */
#if ESDM_ES_EXT_STATUS_MAX > ESDM_ES_EXT_PROTO_STATUS_MAX
#error "The status of a plugin has to fit into the status of a provider"
#endif

static inline void esdm_es_ext_put_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static inline void esdm_es_ext_put_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static inline uint16_t esdm_es_ext_get_le16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (uint16_t)p[1] << 8);
}

static inline uint32_t esdm_es_ext_get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

/*
 * The code point of the UTF-8 sequence at @text[*@i] of @len bytes, *@i moved
 * past it. UTF-8 as RFC 3629 has it: no overlong form, no surrogate, nothing
 * beyond U+10FFFF.
 *
 * @return false for what is no such sequence
 */
static inline bool esdm_es_ext_utf8_next(const unsigned char *text, size_t len,
					 size_t *i, uint32_t *cp)
{
	size_t n, j;

	if (text[*i] < 0x80) {
		*cp = text[(*i)++];
		return true;
	}

	/* The lead byte tells how many continuation bytes follow */
	if (text[*i] >= 0xc2 && text[*i] <= 0xdf) {
		n = 1;
		*cp = text[*i] & 0x1f;
	} else if (text[*i] >= 0xe0 && text[*i] <= 0xef) {
		n = 2;
		*cp = text[*i] & 0x0f;
	} else if (text[*i] >= 0xf0 && text[*i] <= 0xf4) {
		n = 3;
		*cp = text[*i] & 0x07;
	} else {
		return false;
	}

	if (len - *i <= n)
		return false;
	for (j = 1; j <= n; j++) {
		if ((text[*i + j] & 0xc0) != 0x80)
			return false;
		*cp = (*cp << 6) | (text[*i + j] & 0x3f);
	}

	if ((n == 2 && *cp < 0x800) || (n == 3 && *cp < 0x10000) ||
	    (*cp >= 0xd800 && *cp <= 0xdfff) || *cp > 0x10ffff)
		return false;

	*i += n + 1;
	return true;
}

/* Is @text of @len bytes UTF-8 as RFC 3629 has it? */
static inline bool esdm_es_ext_utf8_valid(const char *text, size_t len)
{
	size_t i = 0;
	uint32_t cp;

	while (i < len) {
		if (!esdm_es_ext_utf8_next((const unsigned char *)text, len, &i,
					   &cp))
			return false;
	}

	return true;
}

/*
 * Is @name of @len bytes one a source may declare: 1 to ESDM_ES_EXT_NAME_MAX
 * bytes of UTF-8 without control characters - neither C0 nor DEL nor C1, and
 * so no NUL either?
 */
static inline bool esdm_es_ext_name_valid(const char *name, size_t len)
{
	size_t i = 0;
	uint32_t cp;

	if (!name || !len || len > ESDM_ES_EXT_NAME_MAX)
		return false;

	while (i < len) {
		if (!esdm_es_ext_utf8_next((const unsigned char *)name, len, &i,
					   &cp) ||
		    cp < 0x20 || (cp >= 0x7f && cp <= 0x9f))
			return false;
	}

	return true;
}

/*
 * The name @name, NUL-terminated, if it is one a source may declare - see
 * esdm_es_ext_name_valid(); NULL otherwise
 */
static inline const char *esdm_es_ext_name_or_null(const char *name)
{
	if (!name || !esdm_es_ext_name_valid(
			     name, strnlen(name, ESDM_ES_EXT_NAME_MAX + 1)))
		return NULL;
	return name;
}

/* Is @type one this version of the protocol knows? */
static inline bool esdm_es_ext_proto_type_valid(uint16_t type)
{
	return type == ESDM_ES_EXT_PROTO_GET_ENTROPY ||
	       type == ESDM_ES_EXT_PROTO_SELFTEST ||
	       type == ESDM_ES_EXT_PROTO_STARTDTLS ||
	       type == ESDM_ES_EXT_PROTO_STATUS ||
	       type == ESDM_ES_EXT_PROTO_INFO;
}

/* Is @length what a request of @type may ask for? */
static inline bool esdm_es_ext_proto_length_valid(uint16_t type,
						  uint32_t length)
{
	if (type == ESDM_ES_EXT_PROTO_STATUS)
		return length >= 1 && length <= ESDM_ES_EXT_PROTO_STATUS_MAX;

	if (type != ESDM_ES_EXT_PROTO_GET_ENTROPY)
		return length == 0;

	return length >= 1 && length <= ESDM_ES_EXT_PROTO_MAX_DATA;
}

/* Encode a request into the ESDM_ES_EXT_PROTO_REQ_LEN bytes of @out */
static inline void esdm_es_ext_proto_req_pack(uint8_t *out, uint16_t type,
					      uint32_t length)
{
	esdm_es_ext_put_le32(out, ESDM_ES_EXT_PROTO_MAGIC);
	esdm_es_ext_put_le16(out + 4, ESDM_ES_EXT_PROTO_VERSION);
	esdm_es_ext_put_le16(out + 6, type);
	esdm_es_ext_put_le32(out + 8, length);
}

/*
 * Decode the request of @len bytes at @in.
 *
 * @return 0 on success, -EPROTO for a message that is no valid request
 */
static inline int esdm_es_ext_proto_req_unpack(const uint8_t *in, size_t len,
					       uint16_t *type, uint32_t *length)
{
	if (len != ESDM_ES_EXT_PROTO_REQ_LEN ||
	    esdm_es_ext_get_le32(in) != ESDM_ES_EXT_PROTO_MAGIC ||
	    esdm_es_ext_get_le16(in + 4) != ESDM_ES_EXT_PROTO_VERSION)
		return -EPROTO;

	*type = esdm_es_ext_get_le16(in + 6);
	*length = esdm_es_ext_get_le32(in + 8);
	if (!esdm_es_ext_proto_type_valid(*type) ||
	    !esdm_es_ext_proto_length_valid(*type, *length))
		return -EPROTO;

	return 0;
}

/* Does a response of @type with @status carry data? */
static inline bool esdm_es_ext_proto_rsp_has_data(uint16_t type, int32_t status)
{
	return !status && (type == ESDM_ES_EXT_PROTO_GET_ENTROPY ||
			   type == ESDM_ES_EXT_PROTO_STATUS ||
			   type == ESDM_ES_EXT_PROTO_INFO);
}

/* The data of an INFO answer: its rate, and its name, up to the maximum */
#define ESDM_ES_EXT_PROTO_INFO_MIN 4
#define ESDM_ES_EXT_PROTO_INFO_MAX (4 + ESDM_ES_EXT_NAME_MAX)

/*
 * Encode the data of an INFO answer into @out of ESDM_ES_EXT_PROTO_INFO_MAX
 * bytes: the rate @rate - ESDM_ES_EXT_PROTO_RATE_NONE for none - and the name
 * @name, NULL for none, which has to be valid (esdm_es_ext_name_valid()).
 *
 * @return the size of the data
 */
static inline uint32_t esdm_es_ext_proto_info_pack(uint8_t *out, uint32_t rate,
						   const char *name)
{
	size_t len = name ? strlen(name) : 0;

	esdm_es_ext_put_le32(out, rate);
	memcpy(out + 4, name ? name : "", len);
	return (uint32_t)(4 + len);
}

/*
 * Encode a response into @out, which has room for ESDM_ES_EXT_PROTO_RSP_LEN +
 * ESDM_ES_EXT_PROTO_MAX_RSP_DATA bytes. @data of @datalen bytes is appended for a
 * GET_ENTROPY or a STATUS answered with @status 0 only - for a STATUS, the JSON
 * text without its NUL. @entropy_bits is sent for a GET_ENTROPY only.
 *
 * @return the size of the message
 */
static inline size_t esdm_es_ext_proto_rsp_pack(uint8_t *out, uint16_t type,
						int32_t status,
						uint32_t entropy_bits,
						const uint8_t *data,
						uint32_t datalen)
{
	esdm_es_ext_put_le32(out, ESDM_ES_EXT_PROTO_MAGIC);
	esdm_es_ext_put_le16(out + 4, ESDM_ES_EXT_PROTO_VERSION);
	esdm_es_ext_put_le16(out + 6, type);
	esdm_es_ext_put_le32(out + 8, (uint32_t)status);
	if (!esdm_es_ext_proto_rsp_has_data(type, status)) {
		esdm_es_ext_put_le32(out + 12, 0);
		return ESDM_ES_EXT_PROTO_RSP_LEN;
	}

	esdm_es_ext_put_le32(out + 12, type == ESDM_ES_EXT_PROTO_GET_ENTROPY ?
					       entropy_bits :
					       0);
	memcpy(out + ESDM_ES_EXT_PROTO_RSP_LEN, data, datalen);
	return ESDM_ES_EXT_PROTO_RSP_LEN + datalen;
}

/*
 * Decode the response of @len bytes at @in to a request of @type for @length
 * bytes. On success *@status holds the status of the provider; for a
 * GET_ENTROPY with status 0, *@data points to the @length bytes of data in @in
 * and *@entropy_bits holds their entropy. The response to a STATUS is decoded
 * with esdm_es_ext_proto_status_unpack(), the one to an INFO with
 * esdm_es_ext_proto_info_unpack().
 *
 * @return 0 on success, -EPROTO for a message that is no valid response to the
 *	   request
 */
static inline int esdm_es_ext_proto_rsp_unpack(const uint8_t *in, size_t len,
					       uint16_t type, uint32_t length,
					       int32_t *status,
					       uint32_t *entropy_bits,
					       const uint8_t **data)
{
	int32_t st;
	uint32_t bits;

	*data = NULL;
	*entropy_bits = 0;

	if (type == ESDM_ES_EXT_PROTO_STATUS ||
	    type == ESDM_ES_EXT_PROTO_INFO || len < ESDM_ES_EXT_PROTO_RSP_LEN ||
	    esdm_es_ext_get_le32(in) != ESDM_ES_EXT_PROTO_MAGIC ||
	    esdm_es_ext_get_le16(in + 4) != ESDM_ES_EXT_PROTO_VERSION ||
	    esdm_es_ext_get_le16(in + 6) != type)
		return -EPROTO;

	st = (int32_t)esdm_es_ext_get_le32(in + 8);
	bits = esdm_es_ext_get_le32(in + 12);

	/* A status is 0 or a negative errno - which is what a caller negates */
	if (st > 0 || st < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		return -EPROTO;

	if (st || type != ESDM_ES_EXT_PROTO_GET_ENTROPY) {
		if (len != ESDM_ES_EXT_PROTO_RSP_LEN || bits)
			return -EPROTO;
		*status = st;
		return 0;
	}

	/* Exactly the data asked for, with no more entropy than it can hold */
	if (len != ESDM_ES_EXT_PROTO_RSP_LEN + (size_t)length ||
	    bits > length * 8)
		return -EPROTO;

	*status = 0;
	*entropy_bits = bits;
	*data = in + ESDM_ES_EXT_PROTO_RSP_LEN;
	return 0;
}

/*
 * Decode the response of @len bytes at @in to a STATUS asking for at most
 * @length bytes. On success *@status holds the status of the provider; with
 * status 0, *@text points to the *@textlen bytes of the status in @in - not
 * terminated, and not checked to be JSON, which is the business of the caller.
 *
 * @return 0 on success, -EPROTO for a message that is no valid response to the
 *	   request
 */
static inline int esdm_es_ext_proto_status_unpack(const uint8_t *in, size_t len,
						  uint32_t length,
						  int32_t *status,
						  const char **text,
						  size_t *textlen)
{
	int32_t st;

	*text = NULL;
	*textlen = 0;

	if (len < ESDM_ES_EXT_PROTO_RSP_LEN ||
	    esdm_es_ext_get_le32(in) != ESDM_ES_EXT_PROTO_MAGIC ||
	    esdm_es_ext_get_le16(in + 4) != ESDM_ES_EXT_PROTO_VERSION ||
	    esdm_es_ext_get_le16(in + 6) != ESDM_ES_EXT_PROTO_STATUS ||
	    /* No entropy in a status */
	    esdm_es_ext_get_le32(in + 12))
		return -EPROTO;

	st = (int32_t)esdm_es_ext_get_le32(in + 8);
	if (st > 0 || st < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		return -EPROTO;

	if (st) {
		if (len != ESDM_ES_EXT_PROTO_RSP_LEN)
			return -EPROTO;
		*status = st;
		return 0;
	}

	/* Some status, and no more of it than asked for */
	if (len == ESDM_ES_EXT_PROTO_RSP_LEN ||
	    len > ESDM_ES_EXT_PROTO_RSP_LEN + (size_t)length)
		return -EPROTO;

	*status = 0;
	*text = (const char *)(in + ESDM_ES_EXT_PROTO_RSP_LEN);
	*textlen = len - ESDM_ES_EXT_PROTO_RSP_LEN;
	return 0;
}

/*
 * Decode the response of @len bytes at @in to an INFO. On success *@status
 * holds the status of the provider; with status 0, *@rate holds the rate it
 * declares, ESDM_ES_EXT_PROTO_RATE_NONE for none, and *@name points to the
 * *@namelen bytes of its name in @in - not terminated, and not checked to be a
 * valid name, which is the business of the caller.
 *
 * @return 0 on success, -EPROTO for a message that is no valid response to the
 *	   request
 */
static inline int esdm_es_ext_proto_info_unpack(const uint8_t *in, size_t len,
						int32_t *status, uint32_t *rate,
						const char **name,
						size_t *namelen)
{
	int32_t st;

	*rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	*name = NULL;
	*namelen = 0;

	if (len < ESDM_ES_EXT_PROTO_RSP_LEN ||
	    esdm_es_ext_get_le32(in) != ESDM_ES_EXT_PROTO_MAGIC ||
	    esdm_es_ext_get_le16(in + 4) != ESDM_ES_EXT_PROTO_VERSION ||
	    esdm_es_ext_get_le16(in + 6) != ESDM_ES_EXT_PROTO_INFO ||
	    /* No entropy in an INFO */
	    esdm_es_ext_get_le32(in + 12))
		return -EPROTO;

	st = (int32_t)esdm_es_ext_get_le32(in + 8);
	if (st > 0 || st < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		return -EPROTO;

	if (st) {
		if (len != ESDM_ES_EXT_PROTO_RSP_LEN)
			return -EPROTO;
		*status = st;
		return 0;
	}

	if (len < ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_INFO_MIN ||
	    len > ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_INFO_MAX)
		return -EPROTO;

	*status = 0;
	*rate = esdm_es_ext_get_le32(in + ESDM_ES_EXT_PROTO_RSP_LEN);
	*namelen = len - ESDM_ES_EXT_PROTO_RSP_LEN - 4;
	*name = *namelen ? (const char *)(in + ESDM_ES_EXT_PROTO_RSP_LEN + 4) :
			   NULL;
	return 0;
}

/*
 * Is the struct a plugin library exports one this version of the API can use?
 * Any version up to the one of this header is.
 *
 * @return 0 if so, -EPROTO otherwise
 */
static inline int
esdm_es_ext_plugin_check(const struct esdm_es_ext_plugin *plugin)
{
	if (!plugin || plugin->version < 1 ||
	    plugin->version > ESDM_ES_EXT_PLUGIN_VERSION ||
	    !plugin->get_entropy)
		return -EPROTO;

	return 0;
}

/*
 * Does @plugin report a status? Only a plugin of version 2 or later has the
 * member at all: the struct of one of version 1 ends before it.
 */
static inline bool
esdm_es_ext_plugin_has_status(const struct esdm_es_ext_plugin *plugin)
{
	return plugin->version >= 2 && plugin->status_json;
}

/*
 * Does @plugin declare an entropy rate? Only a plugin of version 3 or later
 * has the member at all.
 */
static inline bool
esdm_es_ext_plugin_has_entropy_rate(const struct esdm_es_ext_plugin *plugin)
{
	return plugin->version >= 3 && plugin->entropy_rate;
}

/*
 * The entropy rate @plugin declares, the way both sides take it: at most
 * ESDM_ES_EXT_ENTROPY_RATE_MAX, ESDM_ES_EXT_PROTO_RATE_NONE for none. Called
 * after its init, with its context @ctx.
 */
static inline uint32_t
esdm_es_ext_plugin_entropy_rate(const struct esdm_es_ext_plugin *plugin,
				void *ctx)
{
	uint32_t rate;

	if (!esdm_es_ext_plugin_has_entropy_rate(plugin))
		return ESDM_ES_EXT_PROTO_RATE_NONE;

	rate = plugin->entropy_rate(ctx);
	return rate > ESDM_ES_EXT_ENTROPY_RATE_MAX ?
		       ESDM_ES_EXT_ENTROPY_RATE_MAX :
		       rate;
}

/*
 * The rate a provider declares in its answer to INFO, the way the ESDM takes
 * it: at most ESDM_ES_EXT_ENTROPY_RATE_MAX, ESDM_ES_EXT_PROTO_RATE_NONE for
 * none
 */
static inline uint32_t esdm_es_ext_proto_rate(uint32_t rate)
{
	if (rate == ESDM_ES_EXT_PROTO_RATE_NONE)
		return rate;
	return rate > ESDM_ES_EXT_ENTROPY_RATE_MAX ?
		       ESDM_ES_EXT_ENTROPY_RATE_MAX :
		       rate;
}

/*
 * Ask @plugin for its status, the way both sides do: the JSON text, terminated,
 * into @buf of @buflen bytes. A text that is not terminated within the buffer,
 * or empty, counts as a failure. Whether it is JSON is left to the ESDM, which
 * parses it.
 *
 * @return the length of the text, -EOPNOTSUPP for a plugin without a status,
 *	   another negative errno if it failed
 */
static inline ssize_t
esdm_es_ext_plugin_status(const struct esdm_es_ext_plugin *plugin, void *ctx,
			  char *buf, size_t buflen)
{
	size_t len;
	int ret;

	if (!buflen)
		return -EINVAL;
	buf[0] = '\0';

	if (!esdm_es_ext_plugin_has_status(plugin))
		return -EOPNOTSUPP;

	ret = plugin->status_json(ctx, buf, buflen);
	/* An errno, or what it stands for */
	if (ret > 0 || ret < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		ret = -EIO;

	len = strnlen(buf, buflen);
	if (!ret && len >= buflen)
		ret = -EMSGSIZE;
	else if (!ret && !len)
		ret = -ENODATA;
	if (ret) {
		buf[0] = '\0';
		return ret;
	}

	return (ssize_t)len;
}

/*
 * Ask @plugin for @buflen bytes, the way both sides do: the buffer is wiped
 * when the plugin fails, and a claim beyond the size of the data counts as a
 * failure - a plugin that cannot count its bits is not to be believed on the
 * bits either.
 *
 * @return 0 on success, a negative errno otherwise
 */
static inline int
esdm_es_ext_plugin_get(const struct esdm_es_ext_plugin *plugin, void *ctx,
		       uint8_t *buf, size_t buflen, uint32_t *entropy_bits)
{
	uint32_t bits = 0;
	int ret = plugin->get_entropy(ctx, buf, buflen, &bits);

	if (!ret && (uint64_t)bits > (uint64_t)buflen * 8)
		ret = -EINVAL;
	/* An errno, or what it stands for */
	if (ret > 0 || ret < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
		ret = -EIO;
	if (ret) {
		memset_secure(buf, 0, buflen);
		bits = 0;
	}

	*entropy_bits = bits;
	return ret;
}

#endif /* _ESDM_ES_EXT_PROTO_H */
