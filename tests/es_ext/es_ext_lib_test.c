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
 * libesdm_es_ext: the provider server against a client speaking the protocol
 * by hand - correctly and not - serving the test source, compiled into the
 * test, and the same without the callbacks a source may leave out; and the
 * callbacks it refuses to serve.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "es_ext_test_plugin.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_ext_proto.h"

static char test_dir[] = "/tmp/esdm-es-ext-lib-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

extern struct esdm_es_ext_plugin es_ext_test_plugin;
extern struct esdm_es_ext_test_control esdm_es_ext_test_control;

/*
 * The control of the test source, as it is before a test sets anything - each
 * test starts from there, as the counters tell what it asked of the source
 */
static struct esdm_es_ext_test_control *test_reset(void)
{
	struct esdm_es_ext_test_control *ctl = &esdm_es_ext_test_control;

	memset(ctl, 0, sizeof(*ctl));
	ctl->claim_bits = UINT32_MAX;
	snprintf(ctl->name, sizeof(ctl->name), "%s", ES_EXT_TEST_NAME);
	ctl->entropy_rate = ES_EXT_TEST_RATE_NONE;
	es_ext_test_plugin.name = ctl->name;

	return ctl;
}

/*
 * Callbacks the server cannot serve: of a version it does not know, or
 * without get_entropy. It refuses them before it calls anything of them, and
 * leaves no socket behind.
 */
static void test_server_refused(void)
{
	struct esdm_es_ext_test_control *ctl = test_reset();
	struct esdm_es_ext_plugin bad = es_ext_test_plugin;
	struct esdm_es_ext_server *server = NULL;
	struct stat sb;

	bad.version = 0;
	CHECK_EQ(esdm_es_ext_server_alloc(&bad, test_socket, 0600, &server),
		 -EPROTO);
	bad.version = ESDM_ES_EXT_PLUGIN_VERSION + 1;
	CHECK_EQ(esdm_es_ext_server_alloc(&bad, test_socket, 0600, &server),
		 -EPROTO);
	bad.version = ESDM_ES_EXT_PLUGIN_VERSION;
	bad.get_entropy = NULL;
	CHECK_EQ(esdm_es_ext_server_alloc(&bad, test_socket, 0600, &server),
		 -EPROTO);
	CHECK_EQ(esdm_es_ext_server_alloc(NULL, test_socket, 0600, &server),
		 -EPROTO);
	CHECK(server == NULL, "a server was handed out");
	CHECK_EQ(ctl->init_calls, 0);
	CHECK(lstat(test_socket, &sb) < 0, "a refused source left a socket");
}

static void *test_server_thread(void *arg)
{
	struct esdm_es_ext_server *server = arg;

	return (void *)(intptr_t)esdm_es_ext_server_run(server);
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

/* Send a request, receive the answer; the size of the answer, -1 if none */
static ssize_t test_request(int fd, uint16_t type, uint32_t length,
			    uint8_t *rsp, size_t rsp_size)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];

	esdm_es_ext_proto_req_pack(req, type, length);
	if (send(fd, req, sizeof(req), MSG_NOSIGNAL) != (ssize_t)sizeof(req))
		return -1;

	return recv(fd, rsp, rsp_size, 0);
}

/* Is the connection closed by the server? */
static bool test_closed(int fd)
{
	uint8_t buf[1];

	return recv(fd, buf, sizeof(buf), 0) == 0;
}

static void test_server(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	const struct esdm_es_ext_plugin *plugin = &es_ext_test_plugin;
	struct esdm_es_ext_test_control *ctl = test_reset();
	struct esdm_es_ext_server *server;
	const uint8_t *data;
	pthread_t thread;
	struct stat sb;
	uint32_t bits = 0;
	int32_t status = -1;
	ssize_t n;
	void *res;
	int fd, fd2;

	/* An init that fails refuses to serve, and leaves no socket */
	ctl->init_ret = -ENODEV;
	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600, &server),
		 -ENODEV);
	CHECK(server == NULL, "a server was handed out");
	CHECK(lstat(test_socket, &sb) < 0, "the socket was left behind");
	ctl->init_ret = 0;

	/* A file that is no socket is not replaced */
	fd = open(test_socket, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	CHECK(fd >= 0, "cannot create %s", test_socket);
	if (fd >= 0)
		close(fd);
	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600, &server),
		 -EEXIST);
	unlink(test_socket);

	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0640, &server),
		 0);
	if (!server)
		return;
	CHECK_EQ(ctl->init_calls, 2);

	/* The mode asked for, whatever the umask */
	CHECK_EQ(lstat(test_socket, &sb), 0);
	CHECK_EQ(sb.st_mode & 0777, 0640);
	CHECK(S_ISSOCK(sb.st_mode), "%s is no socket", test_socket);

	CHECK_EQ(pthread_create(&thread, NULL, test_server_thread, server), 0);

	fd = test_connect();
	CHECK(fd >= 0, "cannot connect to the provider");
	if (fd < 0)
		goto stop;

	/* Entropy, as much as asked for, with the entropy claimed */
	ctl->claim_bits = 300;
	n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 48, rsp,
			 sizeof(rsp));
	CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 48);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					      ESDM_ES_EXT_PROTO_GET_ENTROPY, 48,
					      &status, &bits, &data),
		 0);
	CHECK_EQ(status, 0);
	CHECK_EQ(bits, 300);
	CHECK_EQ(ctl->last_buflen, 48);
	CHECK(data && data[0] == (ctl->get_calls & 0xff),
	      "the data is not the plugin's");

	/* The largest request there is */
	ctl->claim_bits = UINT32_MAX;
	n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			 ESDM_ES_EXT_PROTO_MAX_DATA, rsp, sizeof(rsp));
	CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA);

	/* A plugin claiming more than it delivered delivers nothing */
	ctl->claim_bits = 48 * 8 + 1;
	n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 48, rsp,
			 sizeof(rsp));
	CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					      ESDM_ES_EXT_PROTO_GET_ENTROPY, 48,
					      &status, &bits, &data),
		 0);
	CHECK_EQ(status, -EINVAL);
	ctl->claim_bits = UINT32_MAX;

	/* A plugin that fails, too */
	ctl->get_ret = -EIO;
	n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 48, rsp,
			 sizeof(rsp));
	CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					      ESDM_ES_EXT_PROTO_GET_ENTROPY, 48,
					      &status, &bits, &data),
		 0);
	CHECK_EQ(status, -EIO);
	ctl->get_ret = 0;

	/* The self test of the plugin */
	ctl->selftest_ret = -EFAULT;
	n = test_request(fd, ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp, sizeof(rsp));
	CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
	CHECK_EQ(esdm_es_ext_proto_rsp_unpack(rsp, (size_t)n,
					      ESDM_ES_EXT_PROTO_SELFTEST, 0,
					      &status, &bits, &data),
		 0);
	CHECK_EQ(status, -EFAULT);
	CHECK_EQ(ctl->selftest_calls, 1);
	ctl->selftest_ret = 0;

	/* A second client is served as well */
	fd2 = test_connect();
	CHECK(fd2 >= 0, "cannot connect a second client");
	if (fd2 >= 0) {
		n = test_request(fd2, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16, rsp,
				 sizeof(rsp));
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);

		/* A request of the wrong size closes the connection */
		CHECK_EQ(send(fd2, "x", 1, MSG_NOSIGNAL), 1);
		CHECK(test_closed(fd2),
		      "a short request did not close the connection");
		close(fd2);
	}

	/* So does a request for too much */
	n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			 ESDM_ES_EXT_PROTO_MAX_DATA + 1, rsp, sizeof(rsp));
	CHECK(n <= 0, "a request for too much was answered");
	close(fd);

	/* And a message longer than a request */
	fd = test_connect();
	CHECK(fd >= 0, "cannot connect again");
	if (fd >= 0) {
		uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN + 4];

		esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_GET_ENTROPY,
					   16);
		CHECK_EQ(send(fd, req, sizeof(req), MSG_NOSIGNAL),
			 (ssize_t)sizeof(req));
		CHECK(test_closed(fd),
		      "an overlong request did not close the connection");
		close(fd);
	}

stop:
	esdm_es_ext_server_stop(server);
	CHECK_EQ(pthread_join(thread, &res), 0);
	CHECK_EQ((intptr_t)res, 0);

	esdm_es_ext_server_free(server);
	CHECK_EQ(ctl->fini_calls, 1);
	CHECK(lstat(test_socket, &sb) < 0, "the socket was not removed");

	/* A socket left behind is replaced */
	{
		int s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
		struct sockaddr_un addr = { .sun_family = AF_UNIX };

		snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
			 test_socket);
		CHECK_EQ(bind(s, (struct sockaddr *)&addr, sizeof(addr)), 0);
		close(s);
	}
	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600, &server),
		 0);
	esdm_es_ext_server_free(server);
}

/*
 * The answer to STATUS of @n bytes in @rsp as JSON object, NULL if it is none -
 * checked as the ESDM checks the status of a provider
 */
static struct json_object *test_status_obj(const uint8_t *rsp, ssize_t n,
					   uint32_t length)
{
	const char *text = NULL;
	size_t textlen = 0;
	int32_t status = 1;

	if (n <= 0 || esdm_es_ext_proto_status_unpack(rsp, (size_t)n, length,
						      &status, &text,
						      &textlen) ||
	    status)
		return NULL;
	return esdm_es_ext_json_object(text, textlen,
				       ESDM_ES_EXT_PROTO_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH + 1);
}

/* The member @key of @obj, NULL if there is none or it is null */
static struct json_object *test_member(struct json_object *obj,
				       const char *key)
{
	struct json_object *val = NULL;

	if (!obj || !json_object_object_get_ex(obj, key, &val))
		return NULL;
	return val;
}

/* Does @obj have a member @key that is null? */
static bool test_member_null(struct json_object *obj, const char *key)
{
	struct json_object *val = (struct json_object *)1;

	return obj && json_object_object_get_ex(obj, key, &val) && !val;
}

static int64_t test_member_int(struct json_object *obj, const char *key)
{
	struct json_object *val = test_member(obj, key);

	return val && json_object_is_type(val, json_type_int) ?
		       json_object_get_int64(val) :
		       -1;
}

static const char *test_member_str(struct json_object *obj, const char *key)
{
	struct json_object *val = test_member(obj, key);

	return val && json_object_is_type(val, json_type_string) ?
		       json_object_get_string(val) :
		       "(none)";
}

/* Ask for the status, the server fields of it in *@server */
static struct json_object *test_status_ask(int fd, uint32_t length,
					   struct json_object **server)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA +
		    1];
	ssize_t n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS, length, rsp,
				 sizeof(rsp));
	struct json_object *obj = test_status_obj(rsp, n, length);

	*server = test_member(obj, "server");
	return obj;
}

/*
 * STATUS: the fields of the server - its version, the plugin API version, the
 * name and the rate it declares, the DTLS of the connection, the clients and
 * the slots, the requests served, the verdict of the last self test, the
 * uptime - and the status of the plugin as it reports it, null for none, for a
 * failing one and for one that is no JSON object of up to
 * ESDM_ES_EXT_STATUS_MAX bytes; none of a plugin without the callback. A
 * status that does not fit what is asked for drops the part
 * of the plugin, never cuts the text short.
 */
static void test_server_status(void)
{
	static const char *const bad_status[] = {
		"{\"a\":NaN}", "{\"a\":1e999}", "{\"\xff\":1}", "[1]",
		"{\"a\":1} x",
	};
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA +
		    1];
	char big[ESDM_ES_EXT_STATUS_MAX + 2];
	/* The test source, and the same without status and rate */
	struct esdm_es_ext_plugin bare = es_ext_test_plugin;
	const struct esdm_es_ext_plugin *plugins[] = { &es_ext_test_plugin,
						       &bare };
	unsigned int i, j;

	bare.status_json = NULL;
	bare.entropy_rate = NULL;

	memset(big, 'a', sizeof(big));
	memcpy(big, "{\"x\":\"", 6);
	memcpy(big + ESDM_ES_EXT_STATUS_MAX - 2, "\"}", 3);

	for (i = 0; i < 2; i++) {
		const struct esdm_es_ext_plugin *plugin = plugins[i];
		struct esdm_es_ext_test_control *ctl = test_reset();
		struct esdm_es_ext_server *server;
		struct json_object *obj, *fields, *part;
		int64_t requests, uptime;
		size_t len_null;
		pthread_t thread;
		ssize_t n;
		int fd;

		CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600,
						  &server),
			 0);
		if (!server)
			continue;
		CHECK_EQ(pthread_create(&thread, NULL, test_server_thread,
					server),
			 0);

		fd = test_connect();
		CHECK(fd >= 0, "cannot connect to the provider");
		if (fd < 0)
			goto stop;

		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(obj && fields, "the status has no fields of the server");
		CHECK(!strcmp(test_member_str(fields, "version"), VERSION),
		      "the server reports another version");
		CHECK_EQ(test_member_int(fields, "plugin_api"),
			 ESDM_ES_EXT_PLUGIN_VERSION);
		CHECK(!strcmp(test_member_str(fields, "name"),
			      ES_EXT_TEST_NAME),
		      "the server reports another name");
		CHECK(test_member_null(fields, "entropy_rate"),
		      "the server reports a rate without one");
		CHECK(json_object_is_type(test_member(fields, "dtls"),
					  json_type_boolean) &&
			      !json_object_get_boolean(
				      test_member(fields, "dtls")),
		      "the server reports DTLS in the clear");
		CHECK_EQ(test_member_int(fields, "clients"), 1);
		CHECK_EQ(test_member_int(fields, "client_slots"), 8);
		CHECK_EQ(test_member_int(fields, "requests"), 0);
		CHECK(!strcmp(test_member_str(fields, "selftest"), "none"),
		      "the server reports a self test before one");
		CHECK(test_member_int(fields, "uptime_seconds") >= 0,
		      "the server reports no uptime");

		if (i) {
			/* No callback, no status */
			CHECK(test_member_null(obj, "plugin"),
			      "a plugin without a status callback reports one");
			json_object_put(obj);
			close(fd);
			goto stop;
		}

		/* The status as the plugin writes it */
		part = test_member(obj, "plugin");
		CHECK(part && !strcmp(test_member_str(part, "plugin"),
				      "es-ext-test"),
		      "the status of the plugin is not in it");
		CHECK_EQ(ctl->last_status_buflen, ESDM_ES_EXT_STATUS_MAX + 1);
		json_object_put(obj);

		/* Requests counted, a self test passed and failed */
		n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16, rsp,
				 sizeof(rsp));
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);
		n = test_request(fd, ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp,
				 sizeof(rsp));
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		requests = test_member_int(fields, "requests");
		CHECK_EQ(requests, 3);
		CHECK(!strcmp(test_member_str(fields, "selftest"), "passed"),
		      "the passed self test is not reported");
		uptime = test_member_int(fields, "uptime_seconds");
		json_object_put(obj);
		ctl->selftest_ret = -ENODEV;
		n = test_request(fd, ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp,
				 sizeof(rsp));
		ctl->selftest_ret = 0;
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(!strcmp(test_member_str(fields, "selftest"), "failed"),
		      "the failed self test is not reported");
		CHECK_EQ(test_member_int(fields, "requests"), requests + 2);
		json_object_put(obj);

		/* The uptime grows */
		usleep(1100000);
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(test_member_int(fields, "uptime_seconds") > uptime,
		      "the uptime does not grow");
		json_object_put(obj);

		/* No status of the plugin: the fields of the server alone */
		ctl->status_ret = -ENODEV;
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(fields && test_member_null(obj, "plugin"),
		      "a failing plugin reports a status");
		len_null = strlen(json_object_to_json_string_ext(
			obj, JSON_C_TO_STRING_PLAIN |
				     JSON_C_TO_STRING_NOSLASHESCAPE));
		json_object_put(obj);
		ctl->status_ret = 0;

		/* What is no status: null, the fields there all the same */
		ctl->status_unterminated = 1;
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(fields && test_member_null(obj, "plugin"),
		      "an unterminated status is taken");
		json_object_put(obj);
		ctl->status_unterminated = 0;
		for (j = 0; j < sizeof(bad_status) / sizeof(bad_status[0]);
		     j++) {
			ctl->status_text = bad_status[j];
			obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
					      &fields);
			CHECK(fields && test_member_null(obj, "plugin"),
			      "the status %u that is none is taken", j);
			json_object_put(obj);
		}

		/* The largest status of a plugin fits, one byte more does not */
		ctl->status_text = big;
		big[ESDM_ES_EXT_STATUS_MAX + 1] = '\0';
		memcpy(big + ESDM_ES_EXT_STATUS_MAX - 2, "\"}", 3);
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(json_object_is_type(test_member(obj, "plugin"),
					  json_type_object),
		      "the largest status of a plugin does not fit");
		json_object_put(obj);
		memcpy(big + ESDM_ES_EXT_STATUS_MAX - 2, "a\"}", 4);
		obj = test_status_ask(fd, ESDM_ES_EXT_PROTO_STATUS_MAX,
				      &fields);
		CHECK(fields && test_member_null(obj, "plugin"),
		      "an oversized status of a plugin is taken");
		json_object_put(obj);
		ctl->status_text = NULL;

		/*
		 * Room for the fields of the server only: the plugin left out
		 * rather than cut short - and not even them: none at all
		 */
		obj = test_status_ask(fd, (uint32_t)len_null + 2, &fields);
		CHECK(fields && test_member_null(obj, "plugin"),
		      "the status of the plugin is not left out");
		json_object_put(obj);
		n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS, 8, rsp,
				 sizeof(rsp));
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		{
			const char *text;
			size_t textlen;
			int32_t status = 0;

			if (n > 0)
				esdm_es_ext_proto_status_unpack(
					rsp, (size_t)n, 8, &status, &text,
					&textlen);
			CHECK_EQ(status, -EMSGSIZE);
		}

		/* The connection serves entropy as before */
		n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16, rsp,
				 sizeof(rsp));
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);

		/* A STATUS for more than there can be closes the connection */
		n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS,
				 ESDM_ES_EXT_PROTO_STATUS_MAX + 1, rsp,
				 sizeof(rsp));
		CHECK(n <= 0, "a STATUS for too much was answered");
		close(fd);

		/* So does one for nothing */
		fd = test_connect();
		CHECK(fd >= 0, "cannot connect again");
		if (fd >= 0) {
			n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS, 0, rsp,
					 sizeof(rsp));
			CHECK(n <= 0, "a STATUS for nothing was answered");
			close(fd);
		}

stop:
		esdm_es_ext_server_stop(server);
		pthread_join(thread, NULL);
		esdm_es_ext_server_free(server);
	}
}

/*
 * With users allowed, only those and root are served: anybody else who can
 * connect is disconnected before taking a slot.
 */
static void test_server_allow(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	const struct esdm_es_ext_plugin *plugin = &es_ext_test_plugin;
	struct esdm_es_ext_server *server;
	unsigned int round, i;
	pthread_t thread;
	int fd;

	test_reset();

	/* Round 0 allows another user than the test's, round 1 the test's */
	for (round = 0; round < 2; round++) {
		/* As root, the client is always allowed */
		if (!round && !getuid())
			continue;

		CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0666,
						  &server),
			 0);
		if (!server)
			break;

		CHECK_EQ(esdm_es_ext_server_allow_uid(server, (uid_t)-1),
			 -EINVAL);
		CHECK_EQ(esdm_es_ext_server_allow_uid(
				 server, round ? getuid() : getuid() + 1),
			 0);

		CHECK_EQ(pthread_create(&thread, NULL, test_server_thread,
					server),
			 0);
		fd = test_connect();
		CHECK(fd >= 0, "cannot connect to the provider");
		if (fd >= 0) {
			ssize_t n = test_request(fd,
						 ESDM_ES_EXT_PROTO_GET_ENTROPY,
						 16, rsp, sizeof(rsp));

			if (round)
				CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);
			else
				CHECK(n <= 0,
				      "a client of a user not allowed was served");
			close(fd);
		}
		esdm_es_ext_server_stop(server);
		pthread_join(thread, NULL);

		/* Up to 8 users, allowing one twice takes no room */
		for (i = 0; i < 7; i++)
			CHECK_EQ(esdm_es_ext_server_allow_uid(server, 5000 + i),
				 0);
		CHECK_EQ(esdm_es_ext_server_allow_uid(server, 5000), 0);
		CHECK_EQ(esdm_es_ext_server_allow_uid(server, 6000), -ENOSPC);

		esdm_es_ext_server_free(server);
	}
}

/*
 * STARTDTLS, as the ESDM sends it first: answered in the clear with -EOPNOTSUPP
 * by a server that does not offer DTLS - the connection goes on unencrypted -
 * and with 0 by one that does, after which the server takes the next message
 * for the handshake: anything else ends the connection.
 */
static void test_server_startdtls(void)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	const struct esdm_es_ext_plugin *plugin = &es_ext_test_plugin;
	struct esdm_es_ext_server *server;
	const uint8_t *data;
	unsigned int round;
	pthread_t thread;
	uint32_t bits = 0;
	int32_t status = -1;
	ssize_t n;
	int fd;

	test_reset();

	/* Round 0 without DTLS offered, round 1 with it, where it can be */
	for (round = 0; round < 2; round++) {
		CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600,
						  &server),
			 0);
		if (!server)
			break;
#ifdef ESDM_DTLS
		CHECK_EQ(esdm_es_ext_server_set_dtls(server, (int)round), 0);
#else
		CHECK_EQ(esdm_es_ext_server_set_dtls(server, 1), -EOPNOTSUPP);
		CHECK_EQ(esdm_es_ext_server_set_dtls(server, 0), 0);
#endif
		CHECK_EQ(pthread_create(&thread, NULL, test_server_thread,
					server),
			 0);

		fd = test_connect();
		CHECK(fd >= 0, "cannot connect to the provider");
		if (fd >= 0) {
			n = test_request(fd, ESDM_ES_EXT_PROTO_STARTDTLS, 0,
					 rsp, sizeof(rsp));
			CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
			if (n > 0)
				CHECK_EQ(esdm_es_ext_proto_rsp_unpack(
						 rsp, (size_t)n,
						 ESDM_ES_EXT_PROTO_STARTDTLS, 0,
						 &status, &bits, &data),
					 0);
#ifdef ESDM_DTLS
			if (round) {
				/* DTLS drops what is no record: no answer */
				struct timeval tv = { .tv_usec = 200000 };

				CHECK_EQ(status, 0);
				setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv,
					   sizeof(tv));
				/* No handshake but a request */
				n = test_request(fd,
						 ESDM_ES_EXT_PROTO_GET_ENTROPY,
						 16, rsp, sizeof(rsp));
				CHECK(n <= 0,
				      "a request in the clear was answered after STARTDTLS");
				close(fd);
				goto next;
			}
#endif
			CHECK_EQ(status, -EOPNOTSUPP);

			/* Unencrypted, and STARTDTLS only once */
			n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16,
					 rsp, sizeof(rsp));
			CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);
			close(fd);
		}
#ifdef ESDM_DTLS
	next:
#endif
		esdm_es_ext_server_stop(server);
		pthread_join(thread, NULL);
		esdm_es_ext_server_free(server);
	}

	CHECK_EQ(esdm_es_ext_server_set_dtls(NULL, 0), -EINVAL);
}

/* The clients the server of the library serves at a time */
#define TEST_SERVER_SLOTS 8

/* Apart in time, as the server tells which client was idle the longest */
static void test_pause(void)
{
	const struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000 };

	nanosleep(&ts, NULL);
}

/* Is the client on @fd served? */
static bool test_served(int fd)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + 16];

	return test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16, rsp,
			    sizeof(rsp)) == (ssize_t)sizeof(rsp);
}

/*
 * With all slots taken, a client connecting takes the slot of the client idle
 * the longest: clients that only hold their slots do not lock out another
 * one - the ESDM connecting again.
 */
static void test_server_slots(void)
{
	const struct esdm_es_ext_plugin *plugin = &es_ext_test_plugin;
	struct esdm_es_ext_server *server;
	int fds[TEST_SERVER_SLOTS], fd;
	pthread_t thread;
	unsigned int i;

	test_reset();
	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600, &server),
		 0);
	if (!server)
		return;
	CHECK_EQ(pthread_create(&thread, NULL, test_server_thread, server), 0);

	/* All slots taken, the first client idle the longest */
	for (i = 0; i < TEST_SERVER_SLOTS; i++) {
		fds[i] = test_connect();
		CHECK(fds[i] >= 0 && test_served(fds[i]),
		      "client %u is not served", i);
		test_pause();
	}

	/* A client used meanwhile is not the one idle the longest */
	CHECK(test_served(fds[0]), "the first client is not served");
	test_pause();

	fd = test_connect();
	CHECK(fd >= 0 && test_served(fd),
	      "a client is refused while others only hold their slots");
	CHECK(test_closed(fds[1]), "the client idle the longest kept its slot");
	close(fds[1]);
	fds[1] = fd;
	for (i = 0; i < TEST_SERVER_SLOTS; i++)
		CHECK(test_served(fds[i]), "client %u lost its slot", i);

	for (i = 0; i < TEST_SERVER_SLOTS; i++)
		close(fds[i]);
	esdm_es_ext_server_stop(server);
	pthread_join(thread, NULL);
	esdm_es_ext_server_free(server);
}

int main(void)
{
	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	/* The mode is set by the library, not left to the umask */
	umask(0077);

	test_server_refused();
	test_server();
	test_server_status();
	test_server_allow();
	test_server_slots();
	test_server_startdtls();

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_lib");
}
