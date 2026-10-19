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
 * esdm-es-ext-serve against a client speaking the protocol: it serves the
 * plugin library it is given on the socket it is given, with the mode asked
 * for, until it is terminated, and removes the socket then. What it cannot
 * serve - no plugin, a plugin that does not fit, a mode that is none - it
 * refuses to start with.
 *
 * It answers INFO with the name of its plugin, or the one of --name, and
 * refuses to start with a --name that is no valid name. A request that breaks
 * the protocol closes the connection.
 *
 * It answers STATUS with fields of its own next to the status of its plugin,
 * in the clear and inside a DTLS session: its version, the plugin API, the
 * name and the rate it declares, the DTLS of the connection, its clients and
 * slots, the requests served, the self test verdict and its uptime - and the
 * status of the plugin as it reports it, or null for none, an error, a status
 * that is no valid JSON object and one that is too large, never cut short.
 *
 * Usage: es_ext_serve_test <esdm-es-ext-serve> <test plugin> <bad version>
 *			    <rated plugin>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>
#include <time.h>
#include <unistd.h>

#include <json-c/json.h>

#include "common_test.h"
#include "es_ext_test_client.h"
#include "es_ext_test_util.h"
#include "es_ext_test_plugin.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_ext_proto.h"

static char test_dir[] = "/tmp/esdm-es-ext-serve-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

/* Started with an empty environment, as the test suite runs its daemons */
static pid_t test_spawn(char *const argv[])
{
	char *const envp[] = { NULL };
	pid_t pid;

	if (posix_spawn(&pid, argv[0], NULL, NULL, argv, envp))
		return -1;
	return pid;
}

static int test_wait(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

/* Run to completion, the exit status */
static int test_run(char *const argv[])
{
	pid_t pid = test_spawn(argv);

	return pid < 0 ? -1 : test_wait(pid);
}

static bool test_wait_socket(void)
{
	return es_ext_test_wait_socket(test_socket);
}

static int test_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct timeval tv = { .tv_sec = 5 };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_socket);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

static void test_serve(const char *serve, const char *plugin)
{
	char uid[16];
	char *const argv[] = { (char *)serve, "--plugin",	(char *)plugin,
			       "--socket",    test_socket,	"--mode",
			       "0640",	      "--client_uid", uid,
			       NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t bits = 0;
	int32_t status = -1;
	struct stat sb;
	pid_t pid;
	ssize_t n;
	int fd;

	/* The test's own user is served */
	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;

	CHECK(test_wait_socket(), "the provider did not create its socket");
	CHECK_EQ(lstat(test_socket, &sb), 0);
	CHECK_EQ(sb.st_mode & 0777, 0640);

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   32);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 32);
		if (n > 0) {
			CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
					 rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_GET_ENTROPY, 32,
					 &status, &bits, &data),
				 0);
			CHECK_EQ(status, 0);
			/* The test plugin claims all bits by default */
			CHECK_EQ(bits, 256);
		}

		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_SELFTEST, 0);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		close(fd);
	}

	/* Terminated, it ends cleanly and removes its socket */
	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
	CHECK(lstat(test_socket, &sb) < 0, "the socket was left behind");
}

/*
 * Without --client_uid, root and nobody are served - the ESDM as it runs by
 * default - and nobody else.
 */
static void test_default_clients(const char *serve, const char *plugin)
{
	char *const argv[] = { (char *)serve, "--plugin", (char *)plugin,
			       "--socket", test_socket, NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN], rsp[64];
	struct passwd *pw = getpwnam("nobody");
	pid_t pid;
	int fd;

	if (!getuid() || (pw && pw->pw_uid == getuid())) {
		printf("running as root or nobody - skipping the client check\n");
		return;
	}

	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;
	CHECK(test_wait_socket(), "the provider did not create its socket");

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   16);
		(void)send(fd, req, sizeof(req), MSG_NOSIGNAL);
		CHECK(recv(fd, rsp, sizeof(rsp), 0) <= 0,
		      "a client of another user was served by default");
		close(fd);
	}

	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
}

/* With --no_dtls, a STARTDTLS is refused and the client goes on in the clear */
static void test_no_dtls(const char *serve, const char *plugin)
{
	char uid[16];
	char *const argv[] = { (char *)serve, "--plugin",  (char *)plugin,
			       "--socket",    test_socket, "--client_uid",
			       uid,	      "--no_dtls", NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	const uint8_t *data;
	uint32_t bits = 0;
	int32_t status = 0;
	pid_t pid;
	ssize_t n;
	int fd;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	pid = test_spawn(argv);
	CHECK(pid > 0, "cannot start %s", serve);
	if (pid <= 0)
		return;
	CHECK(test_wait_socket(), "the provider did not create its socket");

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd >= 0) {
		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_STARTDTLS, 0);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		n = recv(fd, rsp, sizeof(rsp), 0);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		if (n > 0)
			CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
					 rsp, (size_t)n,
					 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					 &status, &bits, &data),
				 0);
		CHECK_EQ(status, -EOPNOTSUPP);
		close(fd);
	}

	CHECK_EQ(kill(pid, SIGTERM), 0);
	CHECK_EQ(test_wait(pid), 0);
}

/*
 * INFO, byte for byte, in the clear and inside the DTLS session: the name of
 * the plugin without its NUL - or the one of --name - and the rate its
 * entropy_rate callback declares - or the one of --entropy_rate - or none, no
 * entropy. A request that breaks the protocol closes the connection.
 */
static void test_info(const char *serve, const char *plugin,
		      const char *rated)
{
	static const struct {
		const char *plugin_of;
		const char *name_opt;
		const char *rate_opt;
		const char *name;
		uint32_t rate;
	} rounds[] = {
		/* The name of the plugin, no rate */
		{ "test", NULL, NULL, ES_EXT_TEST_NAME,
		  ESDM_ES_EXT_PROTO_RATE_NONE },
		/* Both of the options */
		{ "test", "Quelle \xc3\xa4", "100", "Quelle \xc3\xa4", 100 },
		/* A plugin declaring both */
		{ "rated", NULL, NULL, ES_EXT_TEST_RATED_NAME,
		  ES_EXT_TEST_RATED_RATE },
		/* The options take precedence */
		{ "rated", "anders", "0", "anders", 0 },
	};
	static const char *const bad_names[] = {
		"", "0123456789abcdef0123456789abcdef0", "tab\there",
		"\xff", "esc\x1b[0m",
	};
	static const char *const bad_rates[] = { "257", "-1", "12x", "", "auto" };
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	struct es_ext_test_client c;
	char uid[16];
	const char *argv[16], *name;
	size_t namelen;
	uint32_t rate;
	int32_t status = -1;
	unsigned int i, n_args, dtls;
	pid_t pid;
	ssize_t n;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());

	for (i = 0; i < sizeof(rounds) / sizeof(rounds[0]); i++) {
		n_args = 0;
		argv[n_args++] = serve;
		argv[n_args++] = "--plugin";
		argv[n_args++] = strcmp(rounds[i].plugin_of, "rated") ? plugin :
									rated;
		argv[n_args++] = "--socket";
		argv[n_args++] = test_socket;
		argv[n_args++] = "--client_uid";
		argv[n_args++] = uid;
		if (rounds[i].name_opt) {
			argv[n_args++] = "--name";
			argv[n_args++] = rounds[i].name_opt;
		}
		if (rounds[i].rate_opt) {
			argv[n_args++] = "--entropy_rate";
			argv[n_args++] = rounds[i].rate_opt;
		}
		argv[n_args] = NULL;

		pid = test_spawn((char *const *)argv);
		CHECK(pid > 0, "cannot start %s", serve);
		if (pid <= 0)
			return;
		CHECK(test_wait_socket(), "the provider did not create its socket");

		/* In the clear, then inside the DTLS session where there is one */
		for (dtls = 0; dtls < 2; dtls++) {
			int ret = es_ext_test_client_open(&c, test_socket,
							  dtls);

#ifndef ESDM_DTLS
			if (dtls) {
				CHECK_EQ(ret, -EOPNOTSUPP);
				continue;
			}
#endif
			CHECK_EQ(ret, 0);
			if (ret)
				continue;

			n = es_ext_test_client_request(&c,
						       ESDM_ES_EXT_PROTO_INFO,
						       0, rsp, sizeof(rsp));
			CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 4 +
					    (ssize_t)strlen(rounds[i].name));
			/* The header: magic, version, type, status, no bits */
			CHECK(n >= ESDM_ES_EXT_PROTO_RSP_LEN + 4 &&
				      !memcmp(rsp, "ESEX\x01\x00\x05\x00", 8) &&
				      !memcmp(rsp + 8, "\0\0\0\0\0\0\0\0", 8),
			      "the header of the answer is not INFO's");
			/* The rate, little endian */
			CHECK(n >= ESDM_ES_EXT_PROTO_RSP_LEN + 4 &&
				      esdm_es_ext_get_le32(
					      rsp + ESDM_ES_EXT_PROTO_RSP_LEN) ==
					      rounds[i].rate,
			      "round %u: the provider declares another rate", i);
			CHECK_EQ(esdm_es_ext_proto_info_unpack(
					 rsp, n > 0 ? (size_t)n : 0, &status,
					 &rate, &name, &namelen),
				 0);
			CHECK_EQ(status, 0);
			CHECK_EQ(rate, rounds[i].rate);
			CHECK_EQ(namelen, strlen(rounds[i].name));
			CHECK(name && !memcmp(name, rounds[i].name, namelen) &&
				      !memchr(name, '\0', namelen),
			      "round %u: the provider declares another name", i);

			/* An INFO with a length breaks the protocol: closed */
			n = es_ext_test_client_request(&c,
						       ESDM_ES_EXT_PROTO_INFO,
						       1, rsp, sizeof(rsp));
			CHECK(n <= 0, "an INFO of length 1 is answered");
			es_ext_test_client_close(&c);

			/* A type unknown to it closes the connection as well */
			CHECK_EQ(es_ext_test_client_open(&c, test_socket,
							 dtls),
				 0);
			n = es_ext_test_client_request(
				&c, ESDM_ES_EXT_PROTO_INFO + 1, 0, rsp,
				sizeof(rsp));
			CHECK(n <= 0, "an unknown type is answered");
			es_ext_test_client_close(&c);
		}

		CHECK_EQ(kill(pid, SIGTERM), 0);
		CHECK_EQ(test_wait(pid), 0);
	}

	/* A --name or an --entropy_rate that is none: refused at start up */
	argv[7] = "--name";
	argv[9] = NULL;
	for (i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); i++) {
		struct stat sb;

		argv[8] = bad_names[i];
		CHECK_EQ(test_run((char *const *)argv), 1);
		CHECK(lstat(test_socket, &sb) < 0,
		      "a refused --name %u left a socket behind", i);
	}
	argv[7] = "--entropy_rate";
	for (i = 0; i < sizeof(bad_rates) / sizeof(bad_rates[0]); i++) {
		struct stat sb;

		argv[8] = bad_rates[i];
		CHECK_EQ(test_run((char *const *)argv), 1);
		CHECK(lstat(test_socket, &sb) < 0,
		      "a refused --entropy_rate %u left a socket behind", i);
	}
}

/* The answer to STATUS on @c as JSON object, NULL if it is none */
static struct json_object *test_status_of(struct es_ext_test_client *c)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	const char *text = NULL;
	size_t textlen = 0;
	int32_t status = 1;
	ssize_t n;

	n = es_ext_test_client_request(c, ESDM_ES_EXT_PROTO_STATUS,
				       ESDM_ES_EXT_PROTO_STATUS_MAX, rsp,
				       sizeof(rsp));
	if (n <= 0 ||
	    esdm_es_ext_proto_status_unpack(rsp, (size_t)n,
					    ESDM_ES_EXT_PROTO_STATUS_MAX,
					    &status, &text, &textlen) ||
	    status) {
		printf("no status: answer of %zd bytes, status %d\n", n,
		       (int)status);
		return NULL;
	}
	return esdm_es_ext_json_object(text, textlen,
				       ESDM_ES_EXT_PROTO_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
}

static struct json_object *test_field(struct json_object *obj, const char *key)
{
	struct json_object *server = NULL, *val = NULL;

	if (!json_object_object_get_ex(obj, "server", &server) ||
	    !json_object_object_get_ex(server, key, &val))
		return NULL;
	return val;
}

static int64_t test_field_int(struct json_object *obj, const char *key)
{
	struct json_object *val = test_field(obj, key);

	return val && json_object_is_type(val, json_type_int) ?
		       json_object_get_int64(val) :
		       -1;
}

static bool test_field_is(struct json_object *obj, const char *key,
			  const char *want)
{
	struct json_object *val = test_field(obj, key);

	return val && json_object_is_type(val, json_type_string) &&
	       !strcmp(json_object_get_string(val), want);
}

static bool test_field_bool(struct json_object *obj, const char *key,
			    bool want)
{
	struct json_object *val = test_field(obj, key);

	return val && json_object_is_type(val, json_type_boolean) &&
	       json_object_get_boolean(val) == want;
}

/* The "plugin" part: its member @key is @want - or it is null for NULL */
static bool test_plugin_part(struct json_object *obj, const char *key,
			     const char *want)
{
	struct json_object *plugin = (struct json_object *)1, *val = NULL;

	if (!obj || !json_object_object_get_ex(obj, "plugin", &plugin))
		return false;
	if (!want)
		return plugin == NULL;
	return plugin && json_object_object_get_ex(plugin, key, &val) && val &&
	       !strcmp(json_object_get_string(val), want);
}

static void test_print(const char *what, struct json_object *obj)
{
	printf("%s: %s\n", what,
	       obj ? json_object_to_json_string_ext(obj,
						    JSON_C_TO_STRING_PLAIN) :
		     "(none)");
}

/*
 * The fields of the server, as --name, --entropy_rate and the plugin have
 * them, in the clear and inside the DTLS session the server offers, and in the
 * clear with --no_dtls: the DTLS of the connection asking, the clients coming
 * and going, the requests, the self test verdict, the uptime growing.
 */
static void test_status_fields(const char *serve, const char *plugin,
			       const char *rated)
{
	const char *const named[] = { "--name", "Feld", "--entropy_rate", "77",
				      NULL };
	const char *const no_dtls[] = { "--no_dtls", NULL };
	struct es_ext_test_client c, c2;
	struct json_object *obj;
	int64_t requests, uptime;
	unsigned int round;
	pid_t pid;

	/* Offering DTLS - asked for or not - and with --no_dtls */
	for (round = 0; round < 3; round++) {
		bool ask = round == 1, dtls = false;
		uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];

#ifdef ESDM_DTLS
		dtls = ask;
#endif
		pid = es_ext_test_serve(serve, plugin, test_socket,
					round == 2 ? no_dtls : named, NULL);
		CHECK(pid > 0, "the provider did not come up");
		if (pid <= 0)
			continue;

		/* --no_dtls: asked for, refused - in the clear */
		if (round == 2)
			CHECK(es_ext_test_client_open(&c, test_socket, true) ==
				      -EOPNOTSUPP,
			      "DTLS is offered with --no_dtls");
		CHECK_EQ(es_ext_test_client_open(&c, test_socket, dtls), 0);

		obj = test_status_of(&c);
		CHECK(obj != NULL, "round %u: no status", round);
		test_print("status", obj);
		CHECK(test_field_is(obj, "version", VERSION),
		      "the server reports another version");
		CHECK_EQ(test_field_int(obj, "plugin_api"),
			 ESDM_ES_EXT_PLUGIN_VERSION);
		CHECK(test_field_is(obj, "name",
				    round == 2 ? ES_EXT_TEST_NAME : "Feld"),
		      "round %u: the server reports another name", round);
		if (round == 2)
			CHECK(test_field(obj, "entropy_rate") == NULL,
			      "the server reports a rate without one");
		else
			CHECK_EQ(test_field_int(obj, "entropy_rate"), 77);
		CHECK(test_field_bool(obj, "dtls", dtls),
		      "round %u: the DTLS of the connection is not reported",
		      round);
		CHECK_EQ(test_field_int(obj, "clients"), 1);
		CHECK_EQ(test_field_int(obj, "client_slots"), 8);
		CHECK(test_field_is(obj, "selftest", "none"),
		      "a self test is reported before one");
		CHECK(test_plugin_part(obj, "plugin", ES_EXT_TEST_NAME),
		      "the status of the plugin is not in it");
		requests = test_field_int(obj, "requests");
		uptime = test_field_int(obj, "uptime_seconds");
		CHECK(requests >= 0 && uptime >= 0,
		      "no requests or uptime reported");
		json_object_put(obj);

		/* Requests, a self test, another client, time */
		es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   32, rsp, sizeof(rsp));
		es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   32, rsp, sizeof(rsp));
		es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_SELFTEST, 0,
					   rsp, sizeof(rsp));
		CHECK_EQ(es_ext_test_client_open(&c2, test_socket, false), 0);
		es_ext_test_client_request(&c2, ESDM_ES_EXT_PROTO_SELFTEST, 0,
					   rsp, sizeof(rsp));
		es_ext_test_sleep_ms(1100);
		obj = test_status_of(&c);
		CHECK_EQ(test_field_int(obj, "requests"), requests + 5);
		CHECK_EQ(test_field_int(obj, "clients"), 2);
		CHECK(test_field_is(obj, "selftest", "passed"),
		      "the self test is not reported");
		CHECK(test_field_int(obj, "uptime_seconds") > uptime,
		      "the uptime does not grow");
		CHECK(test_field_bool(obj, "dtls", dtls),
		      "the DTLS of the connection changed");
		json_object_put(obj);

		/* The other client gone: noticed by the next round */
		es_ext_test_client_close(&c2);
		es_ext_test_sleep_ms(100);
		obj = test_status_of(&c);
		CHECK_EQ(test_field_int(obj, "clients"), 1);
		json_object_put(obj);

		es_ext_test_client_close(&c);
		es_ext_test_terminate(pid);
	}

	/* The name and the rate of the plugin, a self test failing */
	pid = es_ext_test_serve(serve, rated, test_socket, NULL,
				"selftest_ret=-19");
	CHECK(pid > 0, "the provider of the rated plugin did not come up");
	if (pid > 0) {
		uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];

		CHECK_EQ(es_ext_test_client_open(&c, test_socket, false), 0);
		es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_SELFTEST, 0,
					   rsp, sizeof(rsp));
		obj = test_status_of(&c);
		CHECK(test_field_is(obj, "name", ES_EXT_TEST_RATED_NAME) &&
			      test_field_int(obj, "entropy_rate") ==
				      ES_EXT_TEST_RATED_RATE,
		      "the name and the rate of the plugin are not reported");
		CHECK(test_field_is(obj, "selftest", "failed"),
		      "the failed self test is not reported");
		json_object_put(obj);
		es_ext_test_client_close(&c);
		es_ext_test_terminate(pid);
	}
}

/*
 * The status of the plugin within the one of the server, in the clear and
 * inside a DTLS session: a JSON object as it reports it - the largest one of
 * ESDM_ES_EXT_STATUS_MAX bytes included - and null for none, an error, a
 * status with NaN or that is no UTF-8, and one too large.
 */
static void test_status_plugin(const char *serve, const char *plugin)
{
	static const struct {
		const char *settings;
		const char *want;
	} cases[] = {
		{ NULL, ES_EXT_TEST_NAME },
		{ "status={\"plugin\":\"anders\",\"n\":[1,2]}", "anders" },
		{ "status_size=512", "" },
		{ "status_ret=-95", NULL },
		{ "status_ret=-5", NULL },
		{ "status={\"plugin\":NaN}", NULL },
		{ "status={\"plugin\":\"\xff\"}", NULL },
		{ "status={\"plugin\":1} x", NULL },
		{ "status_size=513", NULL },
	};
	struct es_ext_test_client c;
	struct json_object *obj, *val;
	unsigned int i, dtls;
	pid_t pid;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		pid = es_ext_test_serve(serve, plugin, test_socket, NULL,
					cases[i].settings);
		CHECK(pid > 0, "the provider of case %u did not come up", i);
		if (pid <= 0)
			continue;

		for (dtls = 0; dtls < 2; dtls++) {
#ifndef ESDM_DTLS
			if (dtls)
				continue;
#endif
			CHECK_EQ(es_ext_test_client_open(&c, test_socket,
							 dtls),
				 0);
			obj = test_status_of(&c);
			CHECK(obj && test_field_bool(obj, "dtls", dtls),
			      "case %u: the fields of the server are missing",
			      i);
			if (!cases[i].want)
				CHECK(test_plugin_part(obj, NULL, NULL),
				      "case %u: a status that is none is taken",
				      i);
			else if (!cases[i].want[0])
				CHECK(json_object_object_get_ex(obj, "plugin",
								&val) &&
					      json_object_is_type(
						      val, json_type_object),
				      "case %u: the largest status is not taken",
				      i);
			else
				CHECK(test_plugin_part(obj, "plugin",
						       cases[i].want),
				      "case %u: the status of the plugin is not taken",
				      i);
			json_object_put(obj);
			es_ext_test_client_close(&c);
		}

		es_ext_test_terminate(pid);
	}
}

static void test_refusals(const char *serve, const char *plugin,
			  const char *bad_version)
{
	char *const no_args[] = { (char *)serve, NULL };
	char *const no_socket[] = { (char *)serve, "--plugin", (char *)plugin,
				    NULL };
	char *const bad_plugin[] = { (char *)serve,	  "--plugin",
				     (char *)bad_version, "--socket",
				     test_socket,	  NULL };
	char *const missing[] = {
		(char *)serve, "--plugin",  "/nonexistent/libnothing.so",
		"--socket",    test_socket, NULL
	};
	char *const bad_mode[] = { (char *)serve, "--plugin",  (char *)plugin,
				   "--socket",	  test_socket, "--mode",
				   "0999",	  NULL };
	char *const version[] = { (char *)serve, "--version", NULL };
	char *const bad_uid[] = { (char *)serve,  "--plugin", (char *)plugin,
				  "--socket",	  test_socket, "--client_uid",
				  "no-such-user-esdm-test", NULL };
	struct stat sb;

	CHECK_EQ(test_run(no_args), 1);
	CHECK_EQ(test_run(no_socket), 1);
	CHECK_EQ(test_run(bad_plugin), 1);
	CHECK_EQ(test_run(missing), 1);
	CHECK_EQ(test_run(bad_mode), 1);
	CHECK_EQ(test_run(bad_uid), 1);
	CHECK(lstat(test_socket, &sb) < 0,
	      "a refused start left a socket behind");
	CHECK_EQ(test_run(version), 0);
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		printf("usage: %s <esdm-es-ext-serve> <test plugin> <bad version> <rated plugin>\n",
		       argv[0]);
		return 1;
	}

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	test_refusals(argv[1], argv[2], argv[3]);
	test_serve(argv[1], argv[2]);
	test_default_clients(argv[1], argv[2]);
	test_no_dtls(argv[1], argv[2]);
	test_info(argv[1], argv[2], argv[4]);
	test_status_fields(argv[1], argv[2], argv[4]);
	test_status_plugin(argv[1], argv[2]);

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_serve");
}
