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
 * esdm-es-pkcs11 against a client speaking the protocol of the external
 * entropy sources, as the ESDM does.
 *
 * - What it cannot run with, it refuses to start with: no module, a rate or a
 *   name that is none, a PIN on the command line, a PIN file that is missing,
 *   empty, no file or more than a line, a credential asked for by name that is
 *   not there or whose name is a path.
 * - A module that cannot be loaded is no reason to refuse to serve: the
 *   daemon answers, credits nothing and says why in its status.
 * - Against a SoftHSM token: the token of the configured label is used and
 *   logged in to with the PIN of a file or of a systemd credential; INFO
 *   declares "PKCS#11" and the label as the name - another one with --name, or
 *   "PKCS#11" alone for a label that makes no valid name - and the configured
 *   rate; GET_ENTROPY delivers data of the token credited at that rate; STATUS
 *   reports the module, the label, the token, its slot, whether it is present
 *   and logged in to, the PIN and the last error, as valid JSON whatever bytes
 *   the token label holds.
 * - A PIN the token refuses is tried once and never again - not when the token
 *   is looked for again, not when it is opened anew after a failed read. The
 *   token is used without a login then.
 * - A failed C_GenerateRandom drops the token, which is looked for again on
 *   the next request, and logged in to again.
 * - A token repeating its output fails the self test and is credited with
 *   nothing until a self test passes again.
 * - A token that is not there at start up is looked for on demand, at most
 *   every ESDM_PKCS11_RETRY_INTERVAL_SEC, and used once it turns up.
 *
 * SoftHSM needs no hardware: the test creates its tokens in a directory of its
 * own with softhsm2-util, which has to be on the path - the token part is
 * skipped without it. The daemon loads the PKCS#11 module of the test in front
 * of SoftHSM, es_pkcs11_shim.c, which counts the logins, and fails
 * C_GenerateRandom or repeats its output on demand.
 *
 * Usage: es_pkcs11_test <esdm-es-pkcs11> <es_pkcs11_shim module>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <json-c/json.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "es_ext_test_client.h"
#include "es_ext_test_util.h"
#include "es_pkcs11_test_util.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"

#define TOKEN_LABEL PK_TOKEN_LABEL
#define TOKEN_PIN PK_TOKEN_PIN
/* A token created only after the daemon looked for it */
#define LATE_TOKEN_LABEL "esdm-late-token"
/* A token whose label is no UTF-8, with a control character */
#define ODD_TOKEN_LABEL "\xff\x1b-esdm"
/* "\?" as "??-" would be a trigraph */
#define ODD_TOKEN_LABEL_SHOWN "?\?-esdm"
/* A label too long to make a name next to "PKCS#11 " */
#define LONG_LABEL "a-token-label-of-thirty-bytes-x"

/*
 * Run the daemon with @args, which it has to refuse: exit status 1 within 10
 * seconds, without serving
 */
static void test_refused(const char *what, const char *const *args,
			 const char *const *env)
{
	unsigned int i;
	int status = 0;
	pid_t pid = pk_spawn(args, env);

	CHECK(pid > 0, "cannot start esdm-es-pkcs11");
	if (pid <= 0)
		return;

	for (i = 0; i < 1000; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
		es_ext_test_sleep_ms(10);
	}
	if (i == 1000) {
		CHECK(0, "%s: esdm-es-pkcs11 did not refuse to start", what);
		es_ext_test_terminate(pid);
		return;
	}

	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1,
	      "%s: esdm-es-pkcs11 ended with %d instead of refusing to start",
	      what, status);
	CHECK(access(pk.socket, F_OK), "%s: a socket was created", what);
}

static void test_stop(void)
{
	CHECK(pk_stop(),
	      "esdm-es-pkcs11 did not end cleanly on SIGTERM, removing its socket");
}

/******************************************************************************
 * The protocol
 ******************************************************************************/

static struct es_ext_test_client test_client = { .fd = -1 };

static bool test_connect(void)
{
	es_ext_test_client_close(&test_client);
	return !es_ext_test_client_open(&test_client, pk.socket, false);
}

/* INFO: the name - empty for none - and the rate the daemon declares */
static int test_info(char *name, size_t namelen, uint32_t *rate)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	const char *text;
	size_t textlen;
	int32_t status;
	ssize_t n;

	name[0] = '\0';
	n = es_ext_test_client_request(&test_client, ESDM_ES_EXT_PROTO_INFO, 0,
				       rsp, sizeof(rsp));
	if (n <= 0 ||
	    esdm_es_ext_proto_info_unpack(rsp, (size_t)n, &status, rate, &text,
					  &textlen) ||
	    status || textlen >= namelen)
		return -1;
	memcpy(name, text, textlen);
	name[textlen] = '\0';
	return 0;
}

/*
 * GET_ENTROPY of @len bytes into @data: the status of the answer, 1 for no
 * valid answer
 */
static int test_get(uint32_t len, uint8_t *data, uint32_t *bits)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	const uint8_t *payload;
	int32_t status;
	ssize_t n;

	*bits = 0;
	n = es_ext_test_client_request(&test_client,
				       ESDM_ES_EXT_PROTO_GET_ENTROPY, len, rsp,
				       sizeof(rsp));
	if (n <= 0 || esdm_es_ext_proto_rsp_unpack(
			      rsp, (size_t)n, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			      len, &status, bits, &payload))
		return 1;
	if (!status && data)
		memcpy(data, payload, len);
	return status;
}

/* SELFTEST: the status of the answer, 1 for no valid answer */
static int test_selftest(void)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	const uint8_t *payload;
	uint32_t bits;
	int32_t status;
	ssize_t n;

	n = es_ext_test_client_request(&test_client, ESDM_ES_EXT_PROTO_SELFTEST,
				       0, rsp, sizeof(rsp));
	if (n <= 0 || esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
						   ESDM_ES_EXT_PROTO_SELFTEST,
						   0, &status, &bits, &payload))
		return 1;
	return status;
}

/* STATUS: the status the daemon answers with, NULL for none */
static struct json_object *test_status(void)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	char text[ESDM_ES_EXT_PROTO_STATUS_MAX + 1];
	const char *payload;
	size_t len;
	int32_t status;
	ssize_t n;

	n = es_ext_test_client_request(&test_client, ESDM_ES_EXT_PROTO_STATUS,
				       ESDM_ES_EXT_PROTO_STATUS_MAX, rsp,
				       sizeof(rsp));
	if (n <= 0 ||
	    esdm_es_ext_proto_status_unpack(rsp, (size_t)n,
					    ESDM_ES_EXT_PROTO_STATUS_MAX,
					    &status, &payload, &len) ||
	    status)
		return NULL;
	memcpy(text, payload, len);
	text[len] = '\0';
	return json_tokener_parse(text);
}

/* The member @key of the "plugin" part of the status @status */
static struct json_object *test_plugin(struct json_object *status,
				       const char *key)
{
	struct json_object *plugin, *val;

	if (!json_object_object_get_ex(status, "plugin", &plugin) ||
	    !json_object_object_get_ex(plugin, key, &val))
		return NULL;
	return val;
}

static const char *test_plugin_str(struct json_object *status, const char *key)
{
	struct json_object *val = test_plugin(status, key);

	return json_object_is_type(val, json_type_string) ?
		       json_object_get_string(val) :
		       NULL;
}

/* Is the boolean @key of the plugin part of @status @expected? */
static bool test_plugin_bool(struct json_object *status, const char *key,
			     bool expected)
{
	struct json_object *val = test_plugin(status, key);

	return json_object_is_type(val, json_type_boolean) &&
	       json_object_get_boolean(val) == expected;
}

static bool test_plugin_null(struct json_object *status, const char *key)
{
	struct json_object *plugin;

	return json_object_object_get_ex(status, "plugin", &plugin) &&
	       json_object_object_get_ex(plugin, key, NULL) &&
	       !test_plugin(status, key);
}

static const char *test_print(struct json_object *status)
{
	return status ? json_object_to_json_string(status) : "(none)";
}

/* Is a token in use, according to the status? */
static bool test_token_present(void)
{
	struct json_object *status = test_status();
	bool ret = test_plugin_bool(status, "token_present", true);

	json_object_put(status);
	return ret;
}

/******************************************************************************
 * The tests
 ******************************************************************************/

/* What the daemon cannot run with, it refuses to start with */
static void test_options(void)
{
	char missing[PATH_MAX + 16], empty[PATH_MAX + 16];
	char lines[PATH_MAX + 16], cred_env[PATH_MAX + 32];
	const char *const cred[] = { cred_env, NULL };

	snprintf(missing, sizeof(missing), "%s/no-such-pin", pk.dir);
	snprintf(empty, sizeof(empty), "%s/empty-pin", pk.dir);
	snprintf(lines, sizeof(lines), "%s/two-lines", pk.dir);
	snprintf(cred_env, sizeof(cred_env), "CREDENTIALS_DIRECTORY=%s",
		 pk.cred_dir);
	CHECK(!pk_write_file(empty, "", 0600), "cannot write %s", empty);
	CHECK(!pk_write_file(lines, TOKEN_PIN "\n" TOKEN_PIN "\n", 0600),
	      "cannot write %s", lines);

	{
		const char *const args[] = { "--module", "", NULL };

		test_refused("no module", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim,
					     "--entropy_rate", "257", NULL };

		test_refused("rate beyond 256", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim, "--name",
					     "a\x01name", NULL };

		test_refused("name with a control character", args, NULL);
	}
	{
		/* The PIN never goes on the command line */
		const char *const args[] = { "--module", pk.shim, TOKEN_PIN,
					     NULL };

		test_refused("PIN on the command line", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim, "--pin_file",
					     missing, NULL };

		test_refused("missing PIN file", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim, "--pin_file",
					     empty, NULL };

		test_refused("empty PIN file", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim, "--pin_file",
					     pk.dir, NULL };

		test_refused("PIN file that is a directory", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim, "--pin_file",
					     lines, NULL };

		test_refused("PIN file of two lines", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim,
					     "--pin_credential", "pkcs11-pin",
					     NULL };

		test_refused("credential without credentials", args, NULL);
	}
	{
		const char *const args[] = { "--module", pk.shim,
					     "--pin_credential", "../pin",
					     NULL };

		test_refused("credential name that is a path", args, cred);
	}
	{
		const char *const args[] = { "--module", pk.shim,
					     "--pin_credential", "no-such-pin",
					     NULL };

		test_refused("credential that is not there", args, cred);
	}
}

/*
 * A module that cannot be loaded: the daemon serves, credits nothing and says
 * why - and declares the default name and rate, or those it is given
 */
static void test_no_module(void)
{
	const char *const args[] = { "--module",
				     "/nonexistent/libesdm-pkcs11-test.so",
				     "--token_label", LONG_LABEL, NULL };
	const char *const named[] = { "--module",
				      "/nonexistent/libesdm-pkcs11-test.so",
				      "--name",
				      "my token",
				      "--entropy_rate",
				      "0",
				      NULL };
	struct json_object *status;
	char name[64];
	uint32_t rate, bits;

	if (!pk_start(args, NULL))
		goto err;
	CHECK(test_connect(), "cannot connect");

	CHECK(!test_info(name, sizeof(name), &rate), "no answer to INFO");
	/* "PKCS#11 " and the label make no name of up to 32 bytes */
	CHECK_STR_EQ(name, "PKCS#11");
	CHECK_EQ(rate, ESDM_PKCS11_ENTROPY_RATE);

	CHECK_EQ(test_get(32, NULL, &bits), -ENODEV);
	CHECK_EQ(bits, 0);
	/* No token to test is no failure */
	CHECK_EQ(test_selftest(), 0);

	status = test_status();
	CHECK(status, "no answer to STATUS");
	CHECK_STR_EQ(test_plugin_str(status, "module"),
		     "/nonexistent/libesdm-pkcs11-test.so");
	CHECK_STR_EQ(test_plugin_str(status, "token_label"), LONG_LABEL);
	CHECK(test_plugin_bool(status, "token_present", false) &&
		      test_plugin_bool(status, "logged_in", false) &&
		      test_plugin_null(status, "token") &&
		      test_plugin_null(status, "slot"),
	      "a token reported without a module: %s", test_print(status));
	CHECK_STR_EQ(test_plugin_str(status, "pin"), "none");
	CHECK(test_plugin_str(status, "last_error") &&
		      strstr(test_plugin_str(status, "last_error"),
			     "cannot be loaded"),
	      "the status does not tell why: %s", test_print(status));
	json_object_put(status);

	es_ext_test_client_close(&test_client);
	test_stop();

	if (!pk_start(named, NULL))
		goto err;
	CHECK(test_connect(), "cannot connect");
	CHECK(!test_info(name, sizeof(name), &rate), "no answer to INFO");
	CHECK_STR_EQ(name, "my token");
	CHECK_EQ(rate, 0);
	es_ext_test_client_close(&test_client);
	test_stop();
	return;

err:
	CHECK(0, "esdm-es-pkcs11 does not serve without a module");
}

/*
 * The token of the configured label, logged in to with the PIN of @args or
 * @env: what INFO, GET_ENTROPY, SELFTEST and STATUS answer, and a token lost
 * to a failed C_GenerateRandom found and logged in to again
 */
static void test_token(const char *what, const char *const *args,
		       const char *const *env)
{
	uint8_t first[64], second[64];
	struct json_object *status, *slot;
	char name[64];
	uint32_t rate, bits;
	unsigned int i, zero = 0;

	if (!pk_start(args, env)) {
		CHECK(0, "%s: esdm-es-pkcs11 does not serve the token", what);
		return;
	}
	CHECK(test_connect(), "%s: cannot connect", what);

	CHECK(!test_info(name, sizeof(name), &rate), "no answer to INFO");
	CHECK_STR_EQ(name, "PKCS#11 " TOKEN_LABEL);
	CHECK_EQ(rate, 200);

	/* Data of the token, credited at the rate declared */
	CHECK_EQ(test_get(sizeof(first), first, &bits), 0);
	CHECK_EQ(bits, sizeof(first) * 8 * 200 / 256);
	CHECK_EQ(test_get(sizeof(second), second, &bits), 0);
	CHECK(memcmp(first, second, sizeof(first)),
	      "%s: two reads of the token returned the same data", what);
	for (i = 0; i < sizeof(first); i++)
		zero += !first[i];
	CHECK(zero < sizeof(first), "%s: the token delivered zeros", what);
	CHECK_EQ(test_selftest(), 0);

	status = test_status();
	CHECK(status, "%s: no answer to STATUS", what);
	CHECK_STR_EQ(test_plugin_str(status, "token"), TOKEN_LABEL);
	CHECK_STR_EQ(test_plugin_str(status, "token_label"), TOKEN_LABEL);
	CHECK_STR_EQ(test_plugin_str(status, "module"), pk.shim);
	CHECK(test_plugin_bool(status, "token_present", true) &&
		      test_plugin_bool(status, "logged_in", true),
	      "%s: the token is not in use and logged in to: %s", what,
	      test_print(status));
	slot = test_plugin(status, "slot");
	CHECK(json_object_is_type(slot, json_type_int), "%s: no slot: %s", what,
	      test_print(status));
	CHECK_STR_EQ(test_plugin_str(status, "pin"), "set");
	CHECK_STR_EQ(test_plugin_str(status, "repetition_test"), "passed");
	CHECK(test_plugin_null(status, "last_error"),
	      "%s: an error is reported: %s", what, test_print(status));
	json_object_put(status);

	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login user 1 rv 0x0"), 1);
	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login"), 1);

	/* A failed read drops the token */
	CHECK(!pk_write_file(pk.fail, "", 0600), "cannot fail the token");
	CHECK(test_get(32, NULL, &bits) == -EIO,
	      "%s: a failed C_GenerateRandom was not reported", what);
	status = test_status();
	CHECK(test_plugin_bool(status, "token_present", false) &&
		      test_plugin_str(status, "last_error") &&
		      strstr(test_plugin_str(status, "last_error"),
			     "C_GenerateRandom failed"),
	      "%s: the token is still in use after a failed read: %s", what,
	      test_print(status));
	json_object_put(status);
	unlink(pk.fail);

	/* ... and the next request finds it, and logs in to it, again */
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	status = test_status();
	CHECK(test_plugin_bool(status, "token_present", true) &&
		      test_plugin_bool(status, "logged_in", true),
	      "%s: the token was not found again: %s", what,
	      test_print(status));
	json_object_put(status);
	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login user 1 rv 0x0"), 2);

	es_ext_test_client_close(&test_client);
	test_stop();
}

/* The PIN of a file */
/*
 * The PIN of a file - one that every user can read is used, but warned about,
 * one that a group can read, as a file of root the group of the daemon reads,
 * is not
 */
static void test_pin_file(void)
{
	const char *const args[] = {
		"--module",	  pk.shim,	"--token_label",
		TOKEN_LABEL,	  "--pin_file", pk.pin_good,
		"--entropy_rate", "200",	NULL
	};

	test_token("PIN file", args, NULL);
	CHECK_EQ(pk_count_lines(pk.daemon_log, "open to every user"), 0);

	CHECK(!chmod(pk.pin_good, 0640), "cannot open the PIN file to a group");
	test_token("PIN file of a group", args, NULL);
	CHECK_EQ(pk_count_lines(pk.daemon_log, "open to every user"), 0);

	CHECK(!chmod(pk.pin_good, 0644), "cannot open the PIN file to all");
	test_token("PIN file open to every user", args, NULL);
	CHECK_EQ(pk_count_lines(pk.daemon_log, "open to every user"), 1);

	CHECK(!chmod(pk.pin_good, 0600), "cannot close the PIN file again");
}

/* The PIN of a systemd credential, of the default name and of another one */
static void test_pin_credential(void)
{
	char cred_env[PATH_MAX + 32], path[PATH_MAX + 32];
	const char *const env[] = { cred_env, NULL };
	const char *const args[] = {
		"--module",  pk.shim,	       "--token_label",
		TOKEN_LABEL, "--entropy_rate", "200",
		NULL
	};
	const char *const named[] = {
		"--module",	    pk.shim,	      "--token_label",
		TOKEN_LABEL,	    "--entropy_rate", "200",
		"--pin_credential", "my-pin",	      NULL
	};

	snprintf(cred_env, sizeof(cred_env), "CREDENTIALS_DIRECTORY=%s",
		 pk.cred_dir);

	snprintf(path, sizeof(path), "%s/pkcs11-pin", pk.cred_dir);
	CHECK(!pk_write_file(path, TOKEN_PIN, 0400), "cannot write %s", path);
	test_token("credential", args, env);
	unlink(path);

	snprintf(path, sizeof(path), "%s/my-pin", pk.cred_dir);
	CHECK(!pk_write_file(path, TOKEN_PIN "\n", 0400), "cannot write %s",
	      path);
	test_token("named credential", named, env);
	unlink(path);
}

/*
 * A PIN the token refuses is tried once and never again: the token is used
 * without a login, found again after a failed read without a login, and looked
 * for again after the retry interval without a login
 */
static void test_wrong_pin(void)
{
	const char *const args[] = { "--module",  pk.shim,	"--token_label",
				     TOKEN_LABEL, "--pin_file", pk.pin_wrong,
				     NULL };
	struct json_object *status;
	uint32_t bits;

	if (!pk_start(args, NULL)) {
		CHECK(0, "esdm-es-pkcs11 does not serve with a wrong PIN");
		return;
	}
	CHECK(test_connect(), "cannot connect");

	status = test_status();
	CHECK_STR_EQ(test_plugin_str(status, "pin"), "refused");
	CHECK(test_plugin_bool(status, "logged_in", false) &&
		      test_plugin_str(status, "last_error") &&
		      strstr(test_plugin_str(status, "last_error"),
			     "refused the PIN"),
	      "the refusal is not reported: %s", test_print(status));
	json_object_put(status);
	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login"), 1);
	CHECK_EQ(pk_count_lines(pk.login_log, "rv 0x0"), 0);

	/* SoftHSM hands out random numbers without a login */
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	status = test_status();
	CHECK(test_plugin_bool(status, "token_present", true) &&
		      test_plugin_bool(status, "logged_in", false),
	      "the token is not used without the PIN: %s", test_print(status));
	CHECK_STR_EQ(test_plugin_str(status, "pin"), "refused");
	json_object_put(status);

	/* Lost to a failed read, and not found within the retry interval */
	CHECK(!pk_write_file(pk.fail, "", 0600), "cannot fail the token");
	CHECK_EQ(test_get(32, NULL, &bits), -EIO);
	unlink(pk.fail);
	CHECK_EQ(test_get(32, NULL, &bits), -ENODEV);

	/* Found again after it */
	sleep(PK_RETRY_INTERVAL_SEC + 1);
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK(test_token_present(), "the token was not found again");

	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login"), 1);
	CHECK_EQ(pk_count_lines(pk.daemon_log, "refused the PIN"), 1);

	es_ext_test_client_close(&test_client);
	test_stop();
}

/*
 * A token repeating its output fails the self test and is credited with
 * nothing - its data still handed out - until a self test passes again
 */
static void test_repetition(void)
{
	const char *const args[] = { "--module", pk.shim, "--token_label",
				     TOKEN_LABEL, NULL };
	const uint32_t credited = 32 * 8 * ESDM_PKCS11_ENTROPY_RATE / 256;
	struct json_object *status;
	uint32_t bits;

	if (!pk_start(args, NULL)) {
		CHECK(0, "esdm-es-pkcs11 does not serve the token");
		return;
	}
	CHECK(test_connect(), "cannot connect");
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK_EQ(bits, credited);

	CHECK(!pk_write_file(pk.repeat, "", 0600), "cannot repeat the token");
	CHECK_EQ(test_selftest(), -EFAULT);
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK_EQ(bits, 0);
	status = test_status();
	CHECK_STR_EQ(test_plugin_str(status, "repetition_test"), "failed");
	CHECK(test_plugin_str(status, "last_error") &&
		      strstr(test_plugin_str(status, "last_error"), "repeated"),
	      "the repetition is not reported: %s", test_print(status));
	json_object_put(status);

	/* Delivering again is not enough, a test has to pass */
	unlink(pk.repeat);
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK_EQ(bits, 0);
	CHECK_EQ(test_selftest(), 0);
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK_EQ(bits, credited);
	status = test_status();
	CHECK_STR_EQ(test_plugin_str(status, "repetition_test"), "passed");
	CHECK(test_plugin_null(status, "last_error"),
	      "the repetition is still reported: %s", test_print(status));
	json_object_put(status);

	es_ext_test_client_close(&test_client);
	test_stop();
}

/*
 * A token not there at start up is looked for on demand, at most every retry
 * interval, and used once it is there
 */
static void test_token_appears(void)
{
	const char *const args[] = { "--module", pk.shim, "--token_label",
				     LATE_TOKEN_LABEL, NULL };
	struct json_object *status;
	char name[64];
	uint32_t rate, bits;

	if (!pk_start(args, NULL)) {
		CHECK(0, "esdm-es-pkcs11 does not serve without its token");
		return;
	}
	CHECK(test_connect(), "cannot connect");

	CHECK(!test_info(name, sizeof(name), &rate), "no answer to INFO");
	CHECK_STR_EQ(name, "PKCS#11 " LATE_TOKEN_LABEL);

	status = test_status();
	CHECK(test_plugin_bool(status, "token_present", false) &&
		      test_plugin_str(status, "last_error") &&
		      strstr(test_plugin_str(status, "last_error"),
			     "configured label"),
	      "a token reported that is not there: %s", test_print(status));
	CHECK_STR_EQ(test_plugin_str(status, "pin"), "none");
	json_object_put(status);

	/* Spends the first look-up, which finds nothing */
	CHECK_EQ(test_get(32, NULL, &bits), -ENODEV);

	CHECK(!pk_init_token(LATE_TOKEN_LABEL),
	      "cannot create the second token");

	/* Within the retry interval it is not looked for */
	CHECK_EQ(test_get(32, NULL, &bits), -ENODEV);
	CHECK(!test_token_present(),
	      "the token was looked for within the retry interval");

	sleep(PK_RETRY_INTERVAL_SEC + 1);

	CHECK_EQ(test_get(32, NULL, &bits), 0);
	CHECK_EQ(bits, 32 * 8 * ESDM_PKCS11_ENTROPY_RATE / 256);
	status = test_status();
	CHECK_STR_EQ(test_plugin_str(status, "token"), LATE_TOKEN_LABEL);
	CHECK(test_plugin_bool(status, "logged_in", false) &&
		      test_plugin_null(status, "last_error"),
	      "the token that turned up is not used: %s", test_print(status));
	json_object_put(status);
	CHECK_EQ(pk_count_lines(pk.login_log, "C_Login"), 0);

	es_ext_test_client_close(&test_client);
	test_stop();
}

/*
 * Without a label, the first token with a random number generator is used.
 * A label that is no UTF-8 and holds a control character makes no name, and
 * goes into the status as valid JSON.
 */
static void test_labels(void)
{
	const char *const first[] = { "--module", pk.shim, NULL };
	const char *const odd[] = { "--module", pk.shim, "--token_label",
				    ODD_TOKEN_LABEL, NULL };
	struct json_object *status;
	char name[64];
	uint32_t rate, bits;

	/* A build with a default label looks for that one */
	if (ESDM_PKCS11_TOKEN_LABEL[0]) {
		printf("the build has a default token label - skipping the first token\n");
	} else if (pk_start(first, NULL)) {
		CHECK(test_connect(), "cannot connect");
		CHECK(!test_info(name, sizeof(name), &rate),
		      "no answer to INFO");
		CHECK_STR_EQ(name, "PKCS#11");
		CHECK_EQ(test_get(32, NULL, &bits), 0);
		status = test_status();
		CHECK(test_plugin_str(status, "token") &&
			      test_plugin_null(status, "token_label"),
		      "no token in use without a label: %s",
		      test_print(status));
		json_object_put(status);
		es_ext_test_client_close(&test_client);
		test_stop();
	} else {
		CHECK(0, "esdm-es-pkcs11 does not serve without a label");
	}

	if (pk_init_token(ODD_TOKEN_LABEL)) {
		printf("softhsm2-util refuses the label of the odd token - skipping that part\n");
		return;
	}

	if (!pk_start(odd, NULL)) {
		CHECK(0, "esdm-es-pkcs11 does not serve the odd token");
		return;
	}
	CHECK(test_connect(), "cannot connect");
	CHECK(!test_info(name, sizeof(name), &rate), "no answer to INFO");
	CHECK_STR_EQ(name, "PKCS#11");
	CHECK_EQ(test_get(32, NULL, &bits), 0);
	status = test_status();
	CHECK_STR_EQ(test_plugin_str(status, "token"), ODD_TOKEN_LABEL_SHOWN);
	CHECK_STR_EQ(test_plugin_str(status, "token_label"),
		     ODD_TOKEN_LABEL_SHOWN);
	json_object_put(status);
	es_ext_test_client_close(&test_client);
	test_stop();
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 3) {
		printf("Usage: %s <esdm-es-pkcs11> <shim module>\n", argv[0]);
		return 1;
	}

	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	if (pk_setup(argv[1], argv[2])) {
		printf("cannot set up the test directory\n");
		return 1;
	}

	test_options();
	test_no_module();

	if (!pk_find_softhsm()) {
		printf("SoftHSM (softhsm2-util) is not available - skipping the token part\n");
		ret = common_test_failures ? 1 : 77;
		goto out;
	}
	if (pk_softhsm_setup()) {
		printf("cannot create a SoftHSM token\n");
		ret = 1;
		goto out;
	}
	printf("SoftHSM: %s\n", pk.softhsm);

	test_pin_file();
	test_pin_credential();
	test_wrong_pin();
	test_repetition();
	test_labels();
	/* Last: it creates the token it looks for */
	test_token_appears();

	ret = common_test_result("es_pkcs11");

out:
	es_ext_test_client_close(&test_client);
	pk_cleanup();
	return ret;
}
