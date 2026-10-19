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
 * libesdm_es_ext: the plugin loader against good and broken plugin libraries,
 * and the provider server against a client speaking the protocol by hand -
 * correctly and not.
 *
 * Usage: es_ext_lib_test <test plugin> <bad version> <no get_entropy>
 *	  <no plugin> <example plugin> <test plugin of version 1>
 */

#define _GNU_SOURCE
#include <dlfcn.h>
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
#include "esdm_es_ext_proto.h"

static char test_dir[] = "/tmp/esdm-es-ext-lib-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

static struct esdm_es_ext_test_control *test_control(const char *path)
{
	/* The library the loader opened, not a second copy */
	void *dl = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
	struct esdm_es_ext_test_control *ctl;

	if (!dl)
		return NULL;
	ctl = dlsym(dl, ES_EXT_TEST_CONTROL_SYMBOL);
	dlclose(dl);

	return ctl;
}

static void test_loader(const char *good, const char *bad_version,
			const char *no_get, const char *no_plugin,
			const char *v1)
{
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;

	CHECK_EQ(esdm_es_ext_plugin_load(good, &handle, &plugin), 0);
	CHECK(plugin && plugin->name && !strcmp(plugin->name, "es-ext-test"),
	      "the test plugin was not found");
	esdm_es_ext_plugin_unload(handle);

	CHECK_EQ(esdm_es_ext_plugin_load(bad_version, &handle, &plugin),
		 -EPROTO);
	CHECK(handle == NULL && plugin == NULL,
	      "a refused plugin was handed out");
	CHECK_EQ(esdm_es_ext_plugin_load(no_get, &handle, &plugin), -EPROTO);
	CHECK_EQ(esdm_es_ext_plugin_load(no_plugin, &handle, &plugin),
		 -ENOEXEC);
	CHECK_EQ(esdm_es_ext_plugin_load("/nonexistent/libnothing.so", &handle,
					 &plugin),
		 -ENOENT);
	CHECK_EQ(esdm_es_ext_plugin_load(NULL, &handle, &plugin), -EINVAL);

	/* A plugin of version 1, without a status, is loaded all the same */
	CHECK_EQ(esdm_es_ext_plugin_load(v1, &handle, &plugin), 0);
	CHECK(plugin && plugin->version == 1 &&
		      !esdm_es_ext_plugin_has_status(plugin),
	      "the plugin of version 1 is not taken as one");
	esdm_es_ext_plugin_unload(handle);

	/* Unloading nothing is fine */
	esdm_es_ext_plugin_unload(NULL);
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

static void test_server(const char *good)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;
	struct esdm_es_ext_test_control *ctl;
	struct esdm_es_ext_server *server;
	const uint8_t *data;
	pthread_t thread;
	struct stat sb;
	uint32_t bits = 0;
	int32_t status = -1;
	ssize_t n;
	void *res;
	int fd, fd2;

	CHECK_EQ(esdm_es_ext_plugin_load(good, &handle, &plugin), 0);
	if (!plugin)
		return;
	ctl = test_control(good);
	CHECK(ctl != NULL, "the control of the test plugin was not found");
	if (!ctl) {
		esdm_es_ext_plugin_unload(handle);
		return;
	}

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
		goto out;
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

out:
	esdm_es_ext_plugin_unload(handle);
}

/* Ask for the status, at most @length bytes of it */
static ssize_t test_status(int fd, uint32_t length, uint8_t *rsp,
			   size_t rsp_size, int32_t *status, const char **text,
			   size_t *textlen)
{
	ssize_t n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS, length, rsp,
				 rsp_size);

	*status = 1;
	if (n > 0 && esdm_es_ext_proto_status_unpack(rsp, (size_t)n, length,
						     status, text, textlen))
		return -EPROTO;
	return n;
}

/*
 * STATUS: the status of the plugin as it reports it, or the error it reports
 * instead - and none of a plugin of version 1, whose struct has no callback.
 */
static void test_server_status(const char *good, const char *v1)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	const char *paths[] = { good, v1 };
	unsigned int i;

	for (i = 0; i < 2; i++) {
		struct esdm_es_ext_plugin_handle *handle;
		const struct esdm_es_ext_plugin *plugin;
		struct esdm_es_ext_test_control *ctl;
		struct esdm_es_ext_server *server;
		const char *text = NULL;
		size_t textlen = 0;
		pthread_t thread;
		int32_t status;
		ssize_t n;
		int fd;

		CHECK_EQ(esdm_es_ext_plugin_load(paths[i], &handle, &plugin),
			 0);
		if (!plugin)
			continue;
		ctl = test_control(paths[i]);
		CHECK(ctl != NULL, "the control of %s was not found", paths[i]);
		if (!ctl || esdm_es_ext_server_alloc(plugin, test_socket, 0600,
						     &server)) {
			esdm_es_ext_plugin_unload(handle);
			continue;
		}
		CHECK_EQ(pthread_create(&thread, NULL, test_server_thread,
					server),
			 0);

		fd = test_connect();
		CHECK(fd >= 0, "cannot connect to the provider");
		if (fd < 0)
			goto stop;

		n = test_status(fd, ESDM_ES_EXT_STATUS_MAX, rsp, sizeof(rsp),
				&status, &text, &textlen);
		if (i) {
			/* Version 1: the callback beyond its struct is not */
			CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
			CHECK_EQ(status, -EOPNOTSUPP);
			CHECK_EQ(ctl->status_calls, 0);
			close(fd);
			goto stop;
		}

		/* The status as the plugin writes it, without the NUL */
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN +
				    strlen(ES_EXT_TEST_STATUS));
		CHECK_EQ(status, 0);
		CHECK(text && textlen == strlen(ES_EXT_TEST_STATUS) &&
			      !memcmp(text, ES_EXT_TEST_STATUS, textlen),
		      "the status is not the plugin's");
		CHECK_EQ(ctl->last_status_buflen, ESDM_ES_EXT_STATUS_MAX + 1);

		/* One that does not fit what is asked for is not cut short */
		n = test_status(fd, 8, rsp, sizeof(rsp), &status, &text,
				&textlen);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		CHECK_EQ(status, -EMSGSIZE);

		/* The error of the plugin */
		ctl->status_ret = -ENODEV;
		n = test_status(fd, ESDM_ES_EXT_STATUS_MAX, rsp, sizeof(rsp),
				&status, &text, &textlen);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		CHECK_EQ(status, -ENODEV);
		ctl->status_ret = 0;

		/* A status without its NUL is no status */
		ctl->status_unterminated = 1;
		n = test_status(fd, ESDM_ES_EXT_STATUS_MAX, rsp, sizeof(rsp),
				&status, &text, &textlen);
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN);
		CHECK_EQ(status, -EMSGSIZE);
		ctl->status_unterminated = 0;

		/* Nor is an empty one */
		ctl->status_text = "";
		n = test_status(fd, ESDM_ES_EXT_STATUS_MAX, rsp, sizeof(rsp),
				&status, &text, &textlen);
		CHECK_EQ(status, -ENODATA);
		ctl->status_text = NULL;

		/* The connection serves entropy as before */
		n = test_request(fd, ESDM_ES_EXT_PROTO_GET_ENTROPY, 16, rsp,
				 sizeof(rsp));
		CHECK_EQ(n, ESDM_ES_EXT_PROTO_RSP_LEN + 16);

		/* A STATUS for more than there can be closes the connection */
		n = test_request(fd, ESDM_ES_EXT_PROTO_STATUS,
				 ESDM_ES_EXT_STATUS_MAX + 1, rsp, sizeof(rsp));
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
		esdm_es_ext_plugin_unload(handle);
	}
}

/*
 * With users allowed, only those and root are served: anybody else who can
 * connect is disconnected before taking a slot.
 */
static void test_server_allow(const char *good)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;
	struct esdm_es_ext_server *server;
	unsigned int round, i;
	pthread_t thread;
	int fd;

	CHECK_EQ(esdm_es_ext_plugin_load(good, &handle, &plugin), 0);
	if (!plugin)
		return;

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

	esdm_es_ext_plugin_unload(handle);
}

/*
 * STARTDTLS, as the ESDM sends it first: answered in the clear with -EOPNOTSUPP
 * by a server that does not offer DTLS - the connection goes on unencrypted -
 * and with 0 by one that does, after which the server takes the next message
 * for the handshake: anything else ends the connection.
 */
static void test_server_startdtls(const char *good)
{
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA + 1];
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;
	struct esdm_es_ext_server *server;
	const uint8_t *data;
	unsigned int round;
	pthread_t thread;
	uint32_t bits = 0;
	int32_t status = -1;
	ssize_t n;
	int fd;

	CHECK_EQ(esdm_es_ext_plugin_load(good, &handle, &plugin), 0);
	if (!plugin)
		return;

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
	esdm_es_ext_plugin_unload(handle);
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
static void test_server_slots(const char *good)
{
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;
	struct esdm_es_ext_server *server;
	int fds[TEST_SERVER_SLOTS], fd;
	pthread_t thread;
	unsigned int i;

	CHECK_EQ(esdm_es_ext_plugin_load(good, &handle, &plugin), 0);
	if (!plugin)
		return;
	CHECK_EQ(esdm_es_ext_server_alloc(plugin, test_socket, 0600, &server),
		 0);
	if (!server)
		goto out;
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

out:
	esdm_es_ext_plugin_unload(handle);
}

/* The example plugin of es-ext/example, built to read /dev/urandom */
static void test_example(const char *path)
{
	struct esdm_es_ext_plugin_handle *handle;
	const struct esdm_es_ext_plugin *plugin;
	char status[ESDM_ES_EXT_STATUS_MAX + 1];
	uint8_t buf[32];
	uint32_t bits;
	void *ctx = NULL;

	CHECK_EQ(esdm_es_ext_plugin_load(path, &handle, &plugin), 0);
	if (!plugin)
		return;

	CHECK_EQ(plugin->init(&ctx), 0);
	CHECK_EQ(plugin->selftest(ctx), 0);
	CHECK_EQ(esdm_es_ext_plugin_get(plugin, ctx, buf, sizeof(buf), &bits),
		 0);
	CHECK_EQ(bits, sizeof(buf));

	/* Its status names the device, and counts the read */
	CHECK_EQ(esdm_es_ext_plugin_status(plugin, ctx, status, sizeof(status)),
		 (ssize_t)strlen(status));
	CHECK(!strcmp(status,
		      "{\"device\":\"/dev/urandom\",\"reads\":1,\"failures\":0}"),
	      "unexpected status of the example: %s", status);
	plugin->fini(ctx);

	esdm_es_ext_plugin_unload(handle);
}

int main(int argc, char *argv[])
{
	if (argc != 7) {
		printf("usage: %s <test plugin> <bad version> <no get_entropy> <no plugin> <example plugin> <test plugin of version 1>\n",
		       argv[0]);
		return 1;
	}

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/provider.socket",
		 test_dir);

	/* The mode is set by the library, not left to the umask */
	umask(0077);

	test_loader(argv[1], argv[2], argv[3], argv[4], argv[6]);
	test_server(argv[1]);
	test_server_status(argv[1], argv[6]);
	test_server_allow(argv[1]);
	test_server_slots(argv[1]);
	test_server_startdtls(argv[1]);
	test_example(argv[5]);

	unlink(test_socket);
	rmdir(test_dir);

	return common_test_result("es_ext_lib");
}
