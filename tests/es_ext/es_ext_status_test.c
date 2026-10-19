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
 * The status of an external entropy source as the ESDM takes it -
 * esdm_es_ext_status_parse(): one JSON object of up to ESDM_ES_EXT_STATUS_MAX
 * bytes and ESDM_ES_EXT_STATUS_MAX_DEPTH levels, or nothing at all.
 */

#include <json-c/json.h>
#include <string.h>

#include "common_test.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_status.h"

static bool test_taken(const char *text, size_t len)
{
	struct json_object *obj;
	bool warned = false;

	obj = esdm_es_ext_status_parse(text, len, "test", &warned);
	CHECK(warned == !obj, "warned %d for %.40s", warned, text);
	json_object_put(obj);

	return obj != NULL;
}

static bool test_taken_str(const char *text)
{
	return test_taken(text, strlen(text));
}

/* @depth objects one in the other */
static void test_nested(char *buf, size_t buflen, unsigned int depth)
{
	size_t len = 0;
	unsigned int i;

	for (i = 0; i < depth && len + 5 < buflen; i++) {
		memcpy(buf + len, "{\"a\":", 5);
		len += 5;
	}
	buf[len++] = '1';
	for (i = 0; i < depth && len + 1 < buflen; i++)
		buf[len++] = '}';
	buf[len] = '\0';
}

static void test_objects(void)
{
	char buf[ESDM_ES_EXT_STATUS_MAX + 2];
	static const char all[] = "{\"s\":\"x\",\"i\":-3,\"b\":false,"
				  "\"n\":null,\"a\":[1,2],\"o\":{\"d\":1.5}}";
	static const char utf8_name[] =
		"\x7f\xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80"
		"\xf4\x8f\xbf\xbf";
	static const char utf8[] = "{\"\x7f\xc3\xa4\xe2\x82\xac\xf0\x9f\x98\x80"
				   "\xf4\x8f\xbf\xbf\":null}";
	struct json_object *obj, *val;
	bool warned = false;

	/* Members of every type, as they are */
	obj = esdm_es_ext_status_parse(all, strlen(all), "test", &warned);
	CHECK(obj != NULL, "a status with every type is not taken");
	if (obj) {
		CHECK(json_object_object_get_ex(obj, "i", &val) &&
			      json_object_get_int(val) == -3,
		      "the integer is gone");
		CHECK(json_object_object_get_ex(obj, "o", &val) &&
			      json_object_is_type(val, json_type_object),
		      "the nested object is gone");
		json_object_put(obj);
	}

	CHECK(test_taken_str("{}"), "the empty object is not taken");

	/*
	 * UTF-8 of every length, as it is - in a member name: json-c 0.18
	 * refuses any byte beyond ASCII in a string in its strict mode
	 */
	obj = esdm_es_ext_status_parse(utf8, strlen(utf8), "test", &warned);
	CHECK(obj != NULL, "a status in UTF-8 is not taken");
	if (obj) {
		CHECK(json_object_object_get_ex(obj, utf8_name, &val),
		      "the UTF-8 of the status changed");
		json_object_put(obj);
	}

	/* Numbers as large as they get */
	CHECK(test_taken_str("{\"a\":1.7976931348623157e308,\"b\":-0.0}"),
	      "the largest finite number is not taken");
	CHECK(test_taken_str("{\"a\":1}\n"),
	      "white space after the object is not taken");

	test_nested(buf, sizeof(buf), ESDM_ES_EXT_STATUS_MAX_DEPTH);
	CHECK(test_taken_str(buf), "the deepest status is not taken: %s", buf);

	/* The largest one */
	memset(buf, 'a', sizeof(buf));
	memcpy(buf, "{\"x\":\"", 6);
	memcpy(buf + ESDM_ES_EXT_STATUS_MAX - 2, "\"}", 2);
	CHECK(test_taken(buf, ESDM_ES_EXT_STATUS_MAX),
	      "the largest status is not taken");
}

static void test_refused(void)
{
	static const char *const bad[] = {
		"",
		"[1]",
		"\"x\"",
		"1",
		"null",
		"{",
		"{\"a\":1",
		"{\"a\":1}}",
		"{\"a\":1} x",
		"{\"a\":1}{}",
		"{\"a\":1,}",
		"{a:1}",
		"{\"a\":01}",
		"{\"a\":tru}",
		/* Numbers JSON has none for, which json-c takes all the same */
		"{\"a\":NaN}",
		"{\"a\":Infinity}",
		"{\"a\":-Infinity}",
		"{\"a\":[1,NaN]}",
		"{\"o\":{\"p\":{\"q\":-Infinity}}}",
		"{\"a\":1e999}",
		"{\"a\":-1e999}",
		/*
		 * No UTF-8 - in a member name, which json-c takes as it is, or
		 * in a string: a byte that never is, a lone continuation
		 */
		"{\"\xff\":1}",
		"{\"\x80\":1}",
		"{\"a\":\"\xfe\"}",
		/* Cut short by the end of the name */
		"{\"\xc3\":1}",
		"{\"\xe2\x82\":1}",
		"{\"\xf0\x9f\x98\":1}",
		/* Overlong forms of '/' and of U+20AC */
		"{\"\xc0\xaf\":1}",
		"{\"\xe0\x82\xac\":1}",
		"{\"\xf0\x82\x82\xac\":1}",
		/* A surrogate, and beyond U+10FFFF */
		"{\"\xed\xa0\x80\":1}",
		"{\"\xf4\x90\x80\x80\":1}",
		"{\"\xf5\x80\x80\x80\":1}",
	};
	char buf[ESDM_ES_EXT_STATUS_MAX + 2];
	bool warned = false;
	unsigned int i;

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
		CHECK(!test_taken_str(bad[i]), "%s is taken", bad[i]);

	/* Too deep */
	test_nested(buf, sizeof(buf), ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
	CHECK(!test_taken_str(buf), "a status too deep is taken: %s", buf);

	/* A NUL in it, before or after the object */
	CHECK(!test_taken("{\"a\":\"\0\"}", 9), "a NUL in a string is taken");
	CHECK(!test_taken("{\"a\":1}\0", 8), "a NUL after the object is taken");

	/* Too long, if only by white space */
	memset(buf, ' ', sizeof(buf));
	memcpy(buf, "{}", 2);
	CHECK(!test_taken(buf, ESDM_ES_EXT_STATUS_MAX + 1),
	      "a status beyond the largest is taken");

	/* Logged once, until a valid one comes along */
	CHECK(!esdm_es_ext_status_parse("[", 1, "test", &warned), "[ taken");
	CHECK(warned, "an invalid status is not remembered as logged");
	CHECK(!esdm_es_ext_status_parse("[", 1, "test", &warned), "[ taken");
	CHECK(warned, "an invalid status is not remembered as logged");
	json_object_put(esdm_es_ext_status_parse("{}", 2, "test", &warned));
	CHECK(!warned, "a valid status does not clear the warning");
}

int main(void)
{
	test_objects();
	test_refused();

	return common_test_result("es_ext_status");
}
