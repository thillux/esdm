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

#include "esdm_es_ext.h"
#include "memset_secure.h"

/*
 * The largest errno a status may carry, as the kernel bounds them (MAX_ERRNO):
 * a status beyond is no errno, and negating INT32_MIN is undefined.
 */
#define ESDM_ES_EXT_PROTO_MAX_ERRNO 4095

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

/* Is @type one this version of the protocol knows? */
static inline bool esdm_es_ext_proto_type_valid(uint16_t type)
{
	return type == ESDM_ES_EXT_PROTO_GET_ENTROPY ||
	       type == ESDM_ES_EXT_PROTO_SELFTEST ||
	       type == ESDM_ES_EXT_PROTO_STARTDTLS;
}

/* Is @length what a request of @type may ask for? */
static inline bool esdm_es_ext_proto_length_valid(uint16_t type,
						  uint32_t length)
{
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

/*
 * Encode a response into @out, which has room for ESDM_ES_EXT_PROTO_RSP_LEN +
 * ESDM_ES_EXT_PROTO_MAX_DATA bytes. @data of @datalen bytes is appended for a
 * GET_ENTROPY answered with @status 0 only.
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
	if (status || type != ESDM_ES_EXT_PROTO_GET_ENTROPY) {
		esdm_es_ext_put_le32(out + 12, 0);
		return ESDM_ES_EXT_PROTO_RSP_LEN;
	}

	esdm_es_ext_put_le32(out + 12, entropy_bits);
	memcpy(out + ESDM_ES_EXT_PROTO_RSP_LEN, data, datalen);
	return ESDM_ES_EXT_PROTO_RSP_LEN + datalen;
}

/*
 * Decode the response of @len bytes at @in to a request of @type for @length
 * bytes. On success *@status holds the status of the provider; for a
 * GET_ENTROPY with status 0, *@data points to the @length bytes of data in @in
 * and *@entropy_bits holds their entropy.
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

	if (len < ESDM_ES_EXT_PROTO_RSP_LEN ||
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
 * Is the struct a plugin library exports one this version of the API can use?
 *
 * @return 0 if so, -EPROTO otherwise
 */
static inline int
esdm_es_ext_plugin_check(const struct esdm_es_ext_plugin *plugin)
{
	if (!plugin || plugin->version != ESDM_ES_EXT_PLUGIN_VERSION ||
	    !plugin->get_entropy)
		return -EPROTO;

	return 0;
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
