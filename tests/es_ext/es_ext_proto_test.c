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
 * The messages of the external entropy source protocol, as esdm_es_ext.h
 * documents them byte for byte, and everything either side has to refuse.
 */

#include <stdio.h>

#include "common_test.h"
#include "esdm_es_ext_proto.h"

static void test_request(void)
{
	static const uint8_t expected[ESDM_ES_EXT_PROTO_REQ_LEN] = {
		'E', 'S', 'E', 'X', 1, 0, 1, 0, 0x30, 0, 0, 0
	};
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint32_t length;
	uint16_t type;

	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY, 48);
	CHECK_MEM_EQ(req, expected, sizeof(req));

	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);
	CHECK_EQ(type, ESDM_ES_EXT_PROTO_GET_ENTROPY);
	CHECK_EQ(length, 48);

	/* One byte short or long, as a SOCK_SEQPACKET message tells */
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req) - 1, &type,
					      &length),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req) + 1, &type,
					      &length),
		 -EPROTO);

	/* Magic and version */
	req[0] ^= 1;
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	req[0] ^= 1;
	req[4] = 2;
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);

	/* Lengths a GET_ENTROPY may not ask for */
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
				   ESDM_ES_EXT_PROTO_MAX_DATA + 1);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
				   ESDM_ES_EXT_PROTO_MAX_DATA);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);

	/* A self test asks for nothing */
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_SELFTEST, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);
	CHECK_EQ(type, ESDM_ES_EXT_PROTO_SELFTEST);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_SELFTEST, 1);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);

	/* STARTDTLS asks for nothing either */
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STARTDTLS, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);
	CHECK_EQ(type, ESDM_ES_EXT_PROTO_STARTDTLS);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STARTDTLS, 4);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);

	/* STATUS asks for the largest status it takes */
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STATUS,
				   ESDM_ES_EXT_PROTO_STATUS_MAX);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);
	CHECK_EQ(type, ESDM_ES_EXT_PROTO_STATUS);
	CHECK_EQ(length, ESDM_ES_EXT_PROTO_STATUS_MAX);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STATUS, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STATUS,
				   ESDM_ES_EXT_PROTO_STATUS_MAX + 1);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);

	/* Unknown types */
	esdm_es_ext_proto_req_pack(req, 0, 16);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_INFO + 1, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
}

/*
 * The answer to STATUS: the JSON text, without its NUL, no entropy, and no
 * more than asked for.
 */
static void test_status_response(void)
{
	static const char doc[] = "{\"a\":1}";
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	const uint8_t *data;
	const char *text;
	size_t len, textlen;
	int32_t status;
	uint32_t bits;

	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_STATUS, 0, 99,
					 (const uint8_t *)doc, sizeof(doc) - 1);
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN + sizeof(doc) - 1);
	/* No entropy is sent, whatever is handed in */
	CHECK_EQ(esdm_es_ext_get_le32(rsp + 12), 0);
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 0);
	CHECK_EQ(status, 0);
	CHECK(text && textlen == sizeof(doc) - 1 && !memcmp(text, doc, textlen),
	      "the status is not what was sent");

	/* Not more than asked for, if just as much */
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len, sizeof(doc) - 1,
						 &status, &text, &textlen),
		 0);
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len, sizeof(doc) - 2,
						 &status, &text, &textlen),
		 -EPROTO);

	/* No status at all is no answer */
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, ESDM_ES_EXT_PROTO_RSP_LEN,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 -EPROTO);

	/* Entropy in it, or the answer to another type, is none either */
	esdm_es_ext_put_le32(rsp + 12, 8);
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 -EPROTO);
	esdm_es_ext_put_le32(rsp + 12, 0);
	esdm_es_ext_put_le16(rsp + 6, ESDM_ES_EXT_PROTO_SELFTEST);
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 -EPROTO);

	/* An error without a status, the way an old one is not */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_STATUS,
					 -EOPNOTSUPP, 0, (const uint8_t *)doc,
					 sizeof(doc) - 1);
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 0);
	CHECK_EQ(status, -EOPNOTSUPP);
	CHECK(!text && !textlen, "an error carries a status");
	CHECK_EQ(esdm_es_ext_proto_status_unpack(rsp, len + 1,
						 ESDM_ES_EXT_STATUS_MAX,
						 &status, &text, &textlen),
		 -EPROTO);

	/* The decoder of the other answers takes none of STATUS */
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_STATUS,
			 ESDM_ES_EXT_STATUS_MAX, &status, &bits, &data),
		 -EPROTO);
}

static void test_response(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	uint8_t data[32];
	const uint8_t *got;
	uint32_t bits = 0;
	int32_t status = -1;
	size_t len;

	memset(data, 0x5a, sizeof(data));

	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_GET_ENTROPY, 0,
					 200, data, sizeof(data));
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN + sizeof(data));
	CHECK_EQ(esdm_es_ext_get_le32(rsp + 12), 200);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_GET_ENTROPY, sizeof(data),
			 &status, &bits, &got),
		 0);
	CHECK_EQ(status, 0);
	CHECK_EQ(bits, 200);
	CHECK(got == rsp + ESDM_ES_EXT_PROTO_RSP_LEN, "data not located");

	/* The answer to another request, or of another size */
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_SELFTEST, sizeof(data),
			 &status, &bits, &got),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			 sizeof(data) + 1, &status, &bits, &got),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len - 1, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			 sizeof(data), &status, &bits, &got),
		 -EPROTO);

	/* More entropy than the data holds */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_GET_ENTROPY, 0,
					 sizeof(data) * 8 + 1, data,
					 sizeof(data));
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_GET_ENTROPY, sizeof(data),
			 &status, &bits, &got),
		 -EPROTO);
	CHECK_EQ(bits, 0);
	CHECK(got == NULL, "data handed out of a refused response");

	/* A failure carries no data, and no entropy */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					 -EIO, 256, data, sizeof(data));
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_GET_ENTROPY, sizeof(data),
			 &status, &bits, &got),
		 0);
	CHECK_EQ(status, -EIO);
	CHECK_EQ(bits, 0);
	CHECK(got == NULL, "data handed out of a failure");
	esdm_es_ext_put_le32(rsp + 12, 8);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
			 rsp, len, ESDM_ES_EXT_PROTO_GET_ENTROPY, sizeof(data),
			 &status, &bits, &got),
		 -EPROTO);

	/* A status is never positive */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_SELFTEST, 0, 0,
					 NULL, 0);
	esdm_es_ext_put_le32(rsp + 8, 5);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, len,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &got),
		 -EPROTO);

	/* Nor beyond what an errno can be - negating INT32_MIN is undefined */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_SELFTEST,
					 -ESDM_ES_EXT_PROTO_MAX_ERRNO, 0, NULL,
					 0);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, len,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &got),
		 0);
	esdm_es_ext_put_le32(rsp + 8, (uint32_t)INT32_MIN);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, len,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &got),
		 -EPROTO);
	esdm_es_ext_put_le32(rsp + 8,
			     (uint32_t)(-ESDM_ES_EXT_PROTO_MAX_ERRNO - 1));
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, len,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &got),
		 -EPROTO);

	/* A self test answer */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_SELFTEST,
					 -EFAULT, 0, NULL, 0);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, len,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &got),
		 0);
	CHECK_EQ(status, -EFAULT);
}

/* What the plugin returns, next to the claim of @ctx */
static int test_plugin_ret;

/* What the status callback writes, and returns */
static const char *test_status_text = "{}";
static int test_status_ret;
static unsigned int test_status_calls;

static int test_plugin_status_json(void *ctx, char *buf, size_t buflen)
{
	(void)ctx;

	test_status_calls++;
	if (!test_status_text)
		memset(buf, 'x', buflen);
	else
		snprintf(buf, buflen, "%s", test_status_text);
	return test_status_ret;
}

static int test_plugin_get_entropy(void *ctx, uint8_t *buf, size_t buflen,
				   uint32_t *entropy_bits)
{
	uint32_t *claim = ctx;

	memset(buf, 0xa5, buflen);
	*entropy_bits = *claim;
	return test_plugin_ret;
}

static void test_plugin_helpers(void)
{
	struct esdm_es_ext_plugin plugin = {
		.version = ESDM_ES_EXT_PLUGIN_VERSION,
		.get_entropy = test_plugin_get_entropy,
	};
	uint8_t buf[16], zero[16] = { 0 };
	uint32_t claim, bits;

	CHECK_EQ(esdm_es_ext_plugin_check(&plugin), 0);
	CHECK_EQ(esdm_es_ext_plugin_check(NULL), -EPROTO);
	plugin.version++;
	CHECK_EQ(esdm_es_ext_plugin_check(&plugin), -EPROTO);
	plugin.version--;
	/* Every version up to the one of the header */
	plugin.version = 1;
	CHECK_EQ(esdm_es_ext_plugin_check(&plugin), 0);
	plugin.version = 0;
	CHECK_EQ(esdm_es_ext_plugin_check(&plugin), -EPROTO);
	plugin.version = ESDM_ES_EXT_PLUGIN_VERSION;
	plugin.get_entropy = NULL;
	CHECK_EQ(esdm_es_ext_plugin_check(&plugin), -EPROTO);
	plugin.get_entropy = test_plugin_get_entropy;

	claim = 100;
	CHECK_EQ(esdm_es_ext_plugin_get(&plugin, &claim, buf, sizeof(buf),
					&bits),
		 0);
	CHECK_EQ(bits, 100);

	/* Claiming more than the data holds discards it */
	claim = sizeof(buf) * 8 + 1;
	CHECK_EQ(esdm_es_ext_plugin_get(&plugin, &claim, buf, sizeof(buf),
					&bits),
		 -EINVAL);
	CHECK_EQ(bits, 0);
	CHECK_MEM_EQ(buf, zero, sizeof(buf));

	/* What a plugin returns is an errno, or stands for one */
	claim = 8;
	test_plugin_ret = -ENODEV;
	CHECK_EQ(esdm_es_ext_plugin_get(&plugin, &claim, buf, sizeof(buf),
					&bits),
		 -ENODEV);
	test_plugin_ret = INT32_MIN;
	CHECK_EQ(esdm_es_ext_plugin_get(&plugin, &claim, buf, sizeof(buf),
					&bits),
		 -EIO);
	test_plugin_ret = 1;
	CHECK_EQ(esdm_es_ext_plugin_get(&plugin, &claim, buf, sizeof(buf),
					&bits),
		 -EIO);
	CHECK_MEM_EQ(buf, zero, sizeof(buf));
	test_plugin_ret = 0;
}

static void test_plugin_status(void)
{
	struct esdm_es_ext_plugin plugin = {
		.version = ESDM_ES_EXT_PLUGIN_VERSION,
		.get_entropy = test_plugin_get_entropy,
	};
	char buf[16];

	/* None without the callback */
	CHECK(!esdm_es_ext_plugin_has_status(&plugin), "a status without one");
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)),
		 -EOPNOTSUPP);

	plugin.status_json = test_plugin_status_json;

	/* The length of the text */
	test_status_text = "{\"a\":1}";
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)), 7);
	CHECK_STR_EQ(buf, "{\"a\":1}");

	/* Not terminated, or empty: no status */
	test_status_text = NULL;
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)),
		 -EMSGSIZE);
	CHECK_EQ(buf[0], '\0');
	test_status_text = "";
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)),
		 -ENODATA);

	/* An errno, or what it stands for */
	test_status_text = "{}";
	test_status_ret = -ENODEV;
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)),
		 -ENODEV);
	CHECK_EQ(buf[0], '\0');
	test_status_ret = 7;
	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, sizeof(buf)),
		 -EIO);
	test_status_ret = 0;

	CHECK_EQ(esdm_es_ext_plugin_status(&plugin, NULL, buf, 0), -EINVAL);
}

/*
 * INFO, byte for byte: a request of length 0, answered with the rate and the
 * name the provider declares, or with an errno and nothing
 */
static void test_info(void)
{
	static const uint8_t expected_req[ESDM_ES_EXT_PROTO_REQ_LEN] = {
		'E', 'S', 'E', 'X', 1, 0, 5, 0, 0, 0, 0, 0
	};
	static const uint8_t expected_rsp[] = {
		'E', 'S', 'E', 'X', 1, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xff, 0xff, 0xff, 0xff, 'n', 'o', 'i', 's', 'e'
	};
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_INFO_MAX + 1];
	uint8_t data[ESDM_ES_EXT_PROTO_INFO_MAX];
	char name[ESDM_ES_EXT_NAME_MAX + 2];
	const char *got;
	uint32_t length, datalen, rate;
	int32_t status;
	uint16_t type;
	size_t len, namelen;

	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_INFO, 0);
	CHECK_MEM_EQ(req, expected_req, sizeof(req));
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 0);
	CHECK_EQ(type, ESDM_ES_EXT_PROTO_INFO);

	/* A length is no INFO, nor is a type beyond it */
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_INFO, 1);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_INFO + 1, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);

	/* The answer: no rate, a name of 5 bytes without its NUL */
	datalen = esdm_es_ext_proto_info_pack(data, ESDM_ES_EXT_PROTO_RATE_NONE,
					      "noise");
	CHECK_EQ(datalen, 4 + 5);
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 0, 0,
					 data, datalen);
	CHECK_EQ(len, sizeof(expected_rsp));
	CHECK_MEM_EQ(rsp, expected_rsp, sizeof(expected_rsp));
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 0);
	CHECK_EQ(status, 0);
	CHECK_EQ(rate, ESDM_ES_EXT_PROTO_RATE_NONE);
	CHECK_EQ(namelen, 5);
	CHECK(got && !memcmp(got, "noise", 5), "the name is not decoded");

	/* No name */
	datalen = esdm_es_ext_proto_info_pack(data, 128, NULL);
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 0, 0,
					 data, datalen);
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN + 4);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 0);
	CHECK_EQ(rate, 128);
	CHECK(got == NULL && namelen == 0, "a name is decoded from none");

	/* An errno and nothing: nothing declared */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO,
					 -EOPNOTSUPP, 0, data, datalen);
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 0);
	CHECK_EQ(status, -EOPNOTSUPP);
	CHECK_EQ(rate, ESDM_ES_EXT_PROTO_RATE_NONE);

	/* Too short for a rate, longer than any name, data with an errno */
	memset(name, 'x', sizeof(name));
	name[ESDM_ES_EXT_NAME_MAX] = '\0';
	datalen = esdm_es_ext_proto_info_pack(data, 0, name);
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 0, 0,
					 data, datalen);
	CHECK_EQ(len, ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_INFO_MAX);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 0);
	CHECK_EQ(namelen, ESDM_ES_EXT_NAME_MAX);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len + 1, &status, &rate,
					       &got, &namelen),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp,
					       ESDM_ES_EXT_PROTO_RSP_LEN + 3,
					       &status, &rate, &got, &namelen),
		 -EPROTO);
	esdm_es_ext_put_le32(rsp + 8, (uint32_t)-EIO);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 -EPROTO);

	/* Entropy, another type, a status that is no errno */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 0, 0,
					 data, 4);
	esdm_es_ext_put_le32(rsp + 12, 1);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 -EPROTO);
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_STATUS, 0, 0,
					 data, 4);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 -EPROTO);
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 1, 0,
					 data, 4);
	CHECK_EQ(esdm_es_ext_proto_info_unpack(rsp, len, &status, &rate, &got,
					       &namelen),
		 -EPROTO);

	/* Not to be taken for the answer to another request */
	len = esdm_es_ext_proto_rsp_pack(rsp, ESDM_ES_EXT_PROTO_INFO, 0, 0,
					 data, 4);
	{
		const uint8_t *d;
		uint32_t bits;

		CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
				 rsp, len, ESDM_ES_EXT_PROTO_INFO, 0, &status,
				 &bits, &d),
			 -EPROTO);
	}
}

/* The names a source may declare */
static void test_names(void)
{
	static const char *const valid[] = {
		"a", "es-ext-test", "Rauschquelle \xc3\xa4\xc3\xb6\xc3\xbc",
		"\xe2\x82\xac \xf0\x9f\x8e\xb2",
		"0123456789abcdef0123456789abcdef",
		/* Next to the bidirectional controls: NBSP, ZWJ, U+202F, U+206A */
		"\xc2\xa0\xe2\x80\x8d\xe2\x80\xaf\xe2\x81\xaa",
	};
	static const char *const invalid[] = {
		"",
		"0123456789abcdef0123456789abcdef0",
		"tab\there", "new\nline", "esc\x1b[0m", "del\x7f",
		/* C1, overlong, a surrogate, a lone continuation, cut short */
		"c1\xc2\x85", "\xc0\xaf", "\xed\xa0\x80", "\x80", "\xe2\x82",
		"\xff",
		/* Bidirectional controls: RLO, LRI, PDI, LRM, RLM, ALM, LRE */
		"rlo\xe2\x80\xae", "\xe2\x81\xa6lri", "pdi\xe2\x81\xa9",
		"lrm\xe2\x80\x8e", "rlm\xe2\x80\x8f", "alm\xd8\x9c",
		"lre\xe2\x80\xaa",
	};
	unsigned int i;

	for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
		CHECK(esdm_es_ext_name_valid(valid[i], strlen(valid[i])),
		      "the name %u is refused", i);
		CHECK(esdm_es_ext_name_or_null(valid[i]) == valid[i],
		      "the name %u is not taken", i);
	}
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		CHECK(!esdm_es_ext_name_valid(invalid[i], strlen(invalid[i])),
		      "the name %u is taken", i);
		CHECK(esdm_es_ext_name_or_null(invalid[i]) == NULL,
		      "the name %u is taken as string", i);
	}

	/* No NUL within, no NULL */
	CHECK(!esdm_es_ext_name_valid("a\0b", 3), "a NUL is taken");
	CHECK(!esdm_es_ext_name_valid(NULL, 3), "NULL is taken");
	CHECK(esdm_es_ext_name_or_null(NULL) == NULL, "NULL is a name");
}

int main(void)
{
	test_request();
	test_response();
	test_status_response();
	test_plugin_helpers();
	test_plugin_status();
	test_info();
	test_names();

	return common_test_result("es_ext_proto");
}
