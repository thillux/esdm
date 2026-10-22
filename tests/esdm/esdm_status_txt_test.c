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
 * The text the status is printed as from its JSON form - esdm_status_txt():
 *
 * - Scalars are "Label: value" lines - strings as they are, numbers and
 *   booleans as JSON has them, null as N/A.
 * - Objects are sections indented one space deeper, arrays of objects one
 *   numbered section per object, other arrays one line of comma separated
 *   values.
 * - The label table renames and hides members, an entry for the parent taking
 *   precedence over one for any parent; anything else is named after its key.
 * - A value cannot start a line of its own.
 * - A text that does not fit is reported, and what fits is kept, terminated.
 */

#include <errno.h>
#include <json-c/json.h>
#include <string.h>

#include "common_test.h"
#include "esdm_status_txt.h"

static const struct esdm_status_txt_label test_labels[] = {
	{ "", "drngs", "DRNG instance" },
	{ "", "fully_seeded", "ESDM fully seeded" },
	{ "drngs", "id", NULL },
	{ NULL, "rate_per_256_bits", "Rate per 256 bits" },
	{ "special", "rate_per_256_bits", "Special rate" },
	{ NULL, NULL, NULL }
};

static const char test_doc[] =
	"{"
	"\"fully_seeded\":true,"
	"\"entropy_level\":384,"
	"\"ratio\":0.5,"
	"\"drng_name\":\"Hash DRBG\","
	"\"node\":null,"
	"\"standards_compliance\":[\"FIPS 140\",\"DRG.3\"],"
	"\"none\":[],"
	"\"drngs\":[{\"id\":0,\"fully_seeded\":false},"
	"{\"id\":1,\"rate_per_256_bits\":8}],"
	"\"mixed\":[1,{\"a\":2},[3,4]],"
	"\"worker\":{\"running\":false,"
	"\"nested\":{\"depth_two\":\"x\"}},"
	"\"special\":{\"rate_per_256_bits\":16}"
	"}";

static const char test_txt[] = "ESDM fully seeded: true\n"
			       "Entropy level: 384\n"
			       "Ratio: 0.5\n"
			       "Drng name: Hash DRBG\n"
			       "Node: N/A\n"
			       "Standards compliance: FIPS 140, DRG.3\n"
			       "None:\n"
			       "DRNG instance 0 properties:\n"
			       " Fully seeded: false\n"
			       "DRNG instance 1 properties:\n"
			       " Rate per 256 bits: 8\n"
			       "Mixed 0: 1\n"
			       "Mixed 1 properties:\n"
			       " A: 2\n"
			       "Mixed 2: [3,4]\n"
			       "Worker properties:\n"
			       " Running: false\n"
			       " Nested properties:\n"
			       "  Depth two: x\n"
			       "Special properties:\n"
			       " Special rate: 16\n";

static void test_print(void)
{
	struct json_object *obj = json_tokener_parse(test_doc);
	char buf[2048];

	CHECK(obj != NULL, "the test document does not parse");
	if (!obj)
		return;

	CHECK_EQ(esdm_status_txt(obj, test_labels, buf, sizeof(buf)), 0);
	CHECK_STR_EQ(buf, test_txt);

	/* Without labels, every member is named after its key */
	CHECK_EQ(esdm_status_txt(obj, NULL, buf, sizeof(buf)), 0);
	CHECK(strstr(buf, "Fully seeded: true\n") == buf,
	      "unlabelled top level member: %s", buf);
	CHECK(strstr(buf, "Drngs 0 properties:\n Id: 0\n") != NULL,
	      "unlabelled array of objects: %s", buf);

	json_object_put(obj);
}

/* A value with a line break must not be able to fake a line of the status */
static void test_control_characters(void)
{
	struct json_object *obj = json_tokener_parse(
		"{\"status\":\"ok\\nESDM fully seeded: true\","
		"\"bad\\u0001key\":1}");
	char buf[256];

	CHECK(obj != NULL, "the test document does not parse");
	if (!obj)
		return;

	CHECK_EQ(esdm_status_txt(obj, NULL, buf, sizeof(buf)), 0);
	CHECK_STR_EQ(buf, "Status: ok?ESDM fully seeded: true\n"
			  "Bad?key: 1\n");

	json_object_put(obj);
}

static void test_truncation(void)
{
	struct json_object *obj = json_tokener_parse(test_doc);
	char buf[2048];
	size_t len;

	if (!obj)
		return;

	/* What fits stays, terminated */
	memset(buf, 'x', sizeof(buf));
	CHECK_EQ(esdm_status_txt(obj, test_labels, buf, 30), -EMSGSIZE);
	len = strnlen(buf, sizeof(buf));
	CHECK_EQ(len, 29);
	CHECK(!strncmp(buf, test_txt, len), "truncated text differs: %s", buf);
	CHECK_EQ(buf[30], 'x');

	/* Exactly the size of the text does not fit its terminating NUL */
	CHECK_EQ(esdm_status_txt(obj, test_labels, buf, strlen(test_txt)),
		 -EMSGSIZE);
	CHECK_EQ(esdm_status_txt(obj, test_labels, buf, strlen(test_txt) + 1),
		 0);
	CHECK_STR_EQ(buf, test_txt);

	CHECK_EQ(esdm_status_txt(obj, test_labels, buf, 1), -EMSGSIZE);
	CHECK_EQ(buf[0], '\0');

	json_object_put(obj);
}

static void test_arguments(void)
{
	struct json_object *arr = json_object_new_array();
	char buf[16];

	CHECK_EQ(esdm_status_txt(NULL, NULL, buf, sizeof(buf)), -EINVAL);
	CHECK_EQ(esdm_status_txt(arr, NULL, buf, sizeof(buf)), -EINVAL);
	CHECK_EQ(esdm_status_txt(arr, NULL, NULL, sizeof(buf)), -EINVAL);
	CHECK_EQ(esdm_status_txt(arr, NULL, buf, 0), -EINVAL);

	json_object_put(arr);
}

int main(void)
{
	test_print();
	test_control_characters();
	test_truncation();
	test_arguments();

	return common_test_result("esdm_status_txt");
}
