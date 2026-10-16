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

	/* Unknown types */
	esdm_es_ext_proto_req_pack(req, 0, 16);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
		 -EPROTO);
	esdm_es_ext_proto_req_pack(req, 4, 0);
	CHECK_EQ(esdm_es_ext_proto_req_unpack(req, sizeof(req), &type, &length),
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

int main(void)
{
	test_request();
	test_response();
	test_plugin_helpers();

	return common_test_result("es_ext_proto");
}
