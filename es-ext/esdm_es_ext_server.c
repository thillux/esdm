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
 * The provider side of the external entropy source protocol: a plugin served
 * on a Unix domain socket the ESDM connects to - see esdm_es_ext.h.
 *
 * The server is one thread polling the listening socket and its clients, and
 * serving one request at a time. That is all the plugin API allows anyway, as
 * its callbacks are never called concurrently, and all the ESDM needs: it
 * sends one request at a time per connection.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_es_ext.h"
#include "esdm_dtls.h"
#include "esdm_es_ext_json.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "esdm_server_socket.h"
#include "helper.h"
#include "memset_secure.h"
#include "visibility.h"

/*
 * Clients served at a time. The ESDM holds one connection; the room beyond is
 * for a restarted ESDM whose old connection is not closed yet, and for tools.
 *
 * A client beyond takes the slot of the client idle the longest, which is
 * disconnected: clients that hold their slots without using them - which any
 * process of an allowed user can open - must not lock the ESDM out, which
 * connects again whenever it lost its connection, and so gets its slot back.
 * A client running as root only gives way to another client running as root:
 * the ESDM connects as root at start up. A client that finds no slot that way
 * is accepted and closed at once, so that it does not wait in the backlog for
 * nothing.
 */
#define ESDM_ES_EXT_SERVER_MAX_CLIENTS 8

#define ESDM_ES_EXT_SERVER_BACKLOG 8

/* Users that may be allowed with esdm_es_ext_server_allow_uid() */
#define ESDM_ES_EXT_SERVER_MAX_UIDS 8

/* Where a client is on its connection */
enum esdm_es_ext_client_state {
	/* Requests in the clear, as connected */
	ESDM_ES_EXT_CLIENT_PLAIN,
	/* STARTDTLS answered, the handshake in progress */
	ESDM_ES_EXT_CLIENT_HANDSHAKE,
	/* Requests as DTLS application data */
	ESDM_ES_EXT_CLIENT_DTLS,
};

struct esdm_es_ext_server {
	const struct esdm_es_ext_plugin *plugin;
	void *ctx;
	bool initialized;

	/*
	 * The name INFO declares, empty for none: the one set with
	 * esdm_es_ext_server_set_name(), or that of the plugin
	 */
	char name[ESDM_ES_EXT_NAME_MAX + 1];

	/*
	 * The rate INFO declares: the one set with
	 * esdm_es_ext_server_set_entropy_rate(), else the one of the plugin,
	 * ESDM_ES_EXT_PROTO_RATE_NONE for none
	 */
	uint32_t rate;
	uint32_t plugin_rate;

	/*
	 * What the server answers STATUS with next to the status of the plugin:
	 * the requests served, the verdict of the last self test of the plugin
	 * - 0 passed, < 0 failed, 1 none yet - and when it was set up,
	 * monotonic nanoseconds
	 */
	uint64_t requests;
	int selftest;
	uint64_t started;

	int listen_fd;
	/* Written to by esdm_es_ext_server_stop() */
	int stop_pipe[2];
	int clients[ESDM_ES_EXT_SERVER_MAX_CLIENTS];
	enum esdm_es_ext_client_state
		client_state[ESDM_ES_EXT_SERVER_MAX_CLIENTS];
	/*
	 * When the client was accepted or sent something last, nanoseconds of
	 * the monotonic clock, and whether it runs as root - see above
	 */
	uint64_t client_active[ESDM_ES_EXT_SERVER_MAX_CLIENTS];
	bool client_root[ESDM_ES_EXT_SERVER_MAX_CLIENTS];

	/* The DTLS context with the ephemeral key, NULL while not offered */
	struct esdm_dtls_ctx *dtls_ctx;
	struct esdm_dtls *client_dtls[ESDM_ES_EXT_SERVER_MAX_CLIENTS];

	/* Clients accepted next to root; none set accepts any client */
	uid_t allowed_uids[ESDM_ES_EXT_SERVER_MAX_UIDS];
	unsigned int allowed_uids_num;

	char *path;
	/* The socket file created, so that only that one is removed again */
	dev_t dev;
	ino_t ino;
};

static uint64_t esdm_es_ext_server_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void esdm_es_ext_server_close_client(struct esdm_es_ext_server *server,
					    unsigned int i)
{
	if (server->clients[i] < 0)
		return;

	esdm_dtls_free(server->client_dtls[i]);
	server->client_dtls[i] = NULL;
	server->client_state[i] = ESDM_ES_EXT_CLIENT_PLAIN;

	close(server->clients[i]);
	server->clients[i] = -1;
}

/*
 * May the client on @fd be served? With users allowed, only those and root
 * are - anybody else who can connect could otherwise take the slots the ESDM
 * needs, and drain the noise source. *@root tells whether it runs as root.
 */
static bool esdm_es_ext_server_client_allowed(struct esdm_es_ext_server *server,
					      int fd, bool *root)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	unsigned int i;
	bool known;

	known = !getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);
	*root = known && cred.uid == 0;

	if (!server->allowed_uids_num)
		return true;

	if (!known)
		return false;
	if (*root)
		return true;
	for (i = 0; i < server->allowed_uids_num; i++) {
		if (cred.uid == server->allowed_uids[i])
			return true;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ANY,
		    "External ES provider: client of uid %u refused\n",
		    (unsigned int)cred.uid);
	return false;
}

/*
 * The slot of the client idle the longest that gives way to a new client -
 * running as root if @root - or ESDM_ES_EXT_SERVER_MAX_CLIENTS if none does,
 * see ESDM_ES_EXT_SERVER_MAX_CLIENTS. All slots are taken.
 */
static unsigned int
esdm_es_ext_server_evictee(const struct esdm_es_ext_server *server, bool root)
{
	unsigned int i, ret = ESDM_ES_EXT_SERVER_MAX_CLIENTS;

	for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++) {
		if (server->client_root[i] && !root)
			continue;

		/* Not root before root, then the one idle the longest */
		if (ret == ESDM_ES_EXT_SERVER_MAX_CLIENTS ||
		    (server->client_root[ret] && !server->client_root[i]) ||
		    (server->client_root[ret] == server->client_root[i] &&
		     server->client_active[i] < server->client_active[ret]))
			ret = i;
	}

	return ret;
}

static void esdm_es_ext_server_accept(struct esdm_es_ext_server *server)
{
	unsigned int i;
	bool root;
	int fd;

	fd = accept4(server->listen_fd, NULL, NULL,
		     SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (fd < 0) {
		/*
		 * Out of descriptors, the pending connection stays and poll(2)
		 * reports it again at once: pace the retries rather than spin.
		 */
		if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
		    errno == ENOMEM) {
			const struct timespec pace = { .tv_nsec = 100000000 };

			nanosleep(&pace, NULL);
		}
		return;
	}

	/* Refused before it takes a slot */
	if (!esdm_es_ext_server_client_allowed(server, fd, &root)) {
		close(fd);
		return;
	}

	for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++) {
		if (server->clients[i] < 0)
			break;
	}

	if (i == ESDM_ES_EXT_SERVER_MAX_CLIENTS) {
		i = esdm_es_ext_server_evictee(server, root);
		if (i == ESDM_ES_EXT_SERVER_MAX_CLIENTS) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ANY,
				"External ES provider: too many clients, connection refused\n");
			close(fd);
			return;
		}

		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: too many clients, the one idle the longest disconnected\n");
		esdm_es_ext_server_close_client(server, i);
	}

	server->clients[i] = fd;
	server->client_state[i] = ESDM_ES_EXT_CLIENT_PLAIN;
	server->client_active[i] = esdm_es_ext_server_now();
	server->client_root[i] = root;
}

/*
 * Go on with the handshake of client @i.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_handshake(struct esdm_es_ext_server *server,
					 unsigned int i)
{
	int ret = esdm_dtls_handshake(server->client_dtls[i]);

	if (!ret) {
		server->client_state[i] = ESDM_ES_EXT_CLIENT_DTLS;
		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_ANY,
			"External ES provider: client switched to DTLS (%s)\n",
			esdm_dtls_cipher(server->client_dtls[i]));
		return true;
	}

	if (ret == -EAGAIN)
		return true;

	esdm_logger(
		LOGGER_WARN, LOGGER_C_ANY,
		"External ES provider: DTLS handshake failed, client disconnected\n");
	esdm_es_ext_server_close_client(server, i);
	return false;
}

/*
 * Receive the next message of client @i into @buf of @len bytes - a request,
 * or one byte more than a request has to tell a longer message.
 *
 * @return the size of the message, which may exceed @len for a message in the
 *	   clear, -EAGAIN if none is there yet, 0 if the client is gone
 */
static ssize_t esdm_es_ext_server_recv(struct esdm_es_ext_server *server,
				       unsigned int i, uint8_t *buf, size_t len)
{
	ssize_t n;

	if (server->client_state[i] == ESDM_ES_EXT_CLIENT_DTLS) {
		/* A message longer than a request is -EMSGSIZE: closed */
		n = esdm_dtls_recv(server->client_dtls[i], buf, len);
		if (n == -EAGAIN)
			return -EAGAIN;
		return n < 0 ? 0 : n;
	}

	/*
	 * MSG_TRUNC for the real size of the message: a longer one is a
	 * protocol error, not a request cut to size.
	 */
	n = recv(server->clients[i], buf, len, MSG_DONTWAIT | MSG_TRUNC);
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return -EAGAIN;
	return n < 0 ? 0 : n;
}

/*
 * Send the response @rsp of @len bytes to client @i.
 *
 * The client sends one request at a time and reads the answer, so the answer
 * fits into its receive queue. One that does not read is not waited for.
 *
 * @return true if all of it was sent
 */
static bool esdm_es_ext_server_send(struct esdm_es_ext_server *server,
				    unsigned int i, const uint8_t *rsp,
				    size_t len)
{
	if (server->client_state[i] == ESDM_ES_EXT_CLIENT_DTLS)
		return !esdm_dtls_send(server->client_dtls[i], rsp, len);

	return send(server->clients[i], rsp, len,
		    MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t)len;
}

/*
 * Answer a STARTDTLS request of client @i, still in the clear: a handshake is
 * to follow if the server offers DTLS, the client goes on in the clear
 * otherwise.
 *
 * @return the status of the answer
 */
static int esdm_es_ext_server_startdtls(struct esdm_es_ext_server *server,
					unsigned int i)
{
	if (!server->dtls_ctx)
		return -EOPNOTSUPP;

	/* The requests of the client, nothing larger */
	if (esdm_dtls_alloc(server->dtls_ctx, server->clients[i],
			    ESDM_ES_EXT_PROTO_REQ_LEN, &server->client_dtls[i]))
		return -EOPNOTSUPP;

	return 0;
}

/*
 * The status of the plugin as JSON object, NULL for none: for a plugin without
 * one, one whose status fails, and one whose status is no JSON object of up to
 * ESDM_ES_EXT_STATUS_MAX bytes, nested no deeper than
 * ESDM_ES_EXT_STATUS_MAX_DEPTH - checked as the ESDM checks the status of a
 * plugin it loads.
 */
static struct json_object *
esdm_es_ext_server_plugin_status(struct esdm_es_ext_server *server)
{
	char text[ESDM_ES_EXT_STATUS_MAX + 1];
	ssize_t len;

	len = esdm_es_ext_plugin_status(server->plugin, server->ctx, text,
					sizeof(text));
	if (len < 0)
		return NULL;

	return esdm_es_ext_json_object(text, (size_t)len,
				       ESDM_ES_EXT_STATUS_MAX,
				       ESDM_ES_EXT_STATUS_MAX_DEPTH);
}

/* What the server knows itself, for client @i - see STATUS in esdm_es_ext.h */
static struct json_object *
esdm_es_ext_server_fields(struct esdm_es_ext_server *server, unsigned int i)
{
	struct json_object *obj = json_object_new_object();
	uint32_t rate = server->rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				server->rate :
				server->plugin_rate;
	unsigned int c, clients = 0;

	if (!obj)
		return NULL;

	for (c = 0; c < ESDM_ES_EXT_SERVER_MAX_CLIENTS; c++) {
		if (server->clients[c] >= 0)
			clients++;
	}

	json_object_object_add(obj, "version", json_object_new_string(VERSION));
	json_object_object_add(obj, "plugin_api",
			       json_object_new_int64(server->plugin->version));
	json_object_object_add(
		obj, "name",
		server->name[0] ? json_object_new_string(server->name) : NULL);
	json_object_object_add(obj, "entropy_rate",
			       rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				       json_object_new_int64(rate) :
				       NULL);
	json_object_object_add(
		obj, "dtls",
		json_object_new_boolean(server->client_state[i] ==
					ESDM_ES_EXT_CLIENT_DTLS));
	json_object_object_add(obj, "clients", json_object_new_int64(clients));
	json_object_object_add(
		obj, "client_slots",
		json_object_new_int64(ESDM_ES_EXT_SERVER_MAX_CLIENTS));
	json_object_object_add(
		obj, "requests",
		json_object_new_int64((int64_t)server->requests));
	json_object_object_add(
		obj, "selftest",
		json_object_new_string(server->selftest > 0 ? "none" :
				       !server->selftest    ? "passed" :
							      "failed"));
	json_object_object_add(
		obj, "uptime_seconds",
		json_object_new_int64(
			(int64_t)((esdm_es_ext_server_now() - server->started) /
				  1000000000ULL)));

	return obj;
}

/*
 * Answer a STATUS request of client @i for at most @length bytes, the status
 * going into @data: the fields of the server, and the status of its plugin -
 * left out, as null, if both do not fit into @length together. The text is
 * never cut short: half a JSON object is none.
 *
 * @return the status of the answer, *@datalen holding the length of the text
 */
static int esdm_es_ext_server_status(struct esdm_es_ext_server *server,
				     unsigned int i, uint8_t *data,
				     uint32_t length, uint32_t *datalen)
{
	struct json_object *root = json_object_new_object();
	struct json_object *fields = esdm_es_ext_server_fields(server, i);
	const char *text;
	size_t len;
	int ret = -EMSGSIZE;

	*datalen = 0;
	if (!root || !fields) {
		json_object_put(root);
		json_object_put(fields);
		return -ENOMEM;
	}

	json_object_object_add(root, "server", fields);
	json_object_object_add(root, "plugin",
			       esdm_es_ext_server_plugin_status(server));

	text = json_object_to_json_string_ext(
		root, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	len = text ? strlen(text) : SIZE_MAX;
	if (len > length) {
		/* The fields of the server alone */
		json_object_object_add(root, "plugin", NULL);
		text = json_object_to_json_string_ext(
			root, JSON_C_TO_STRING_PLAIN |
				      JSON_C_TO_STRING_NOSLASHESCAPE);
		len = text ? strlen(text) : SIZE_MAX;
	}

	if (len <= length) {
		memcpy(data, text, len);
		*datalen = (uint32_t)len;
		ret = 0;
	}

	json_object_put(root);
	return ret;
}

/*
 * Take the name of the plugin as the name INFO declares, if it is a valid one
 * - see @name of struct esdm_es_ext_plugin.
 */
static void esdm_es_ext_server_plugin_name(struct esdm_es_ext_server *server)
{
	const char *name = esdm_es_ext_name_or_null(server->plugin->name);

	server->name[0] = '\0';
	if (name)
		snprintf(server->name, sizeof(server->name), "%s", name);
	else if (server->plugin->name)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: the name of the plugin is no name of 1 to %u bytes of UTF-8 without control characters, INFO declares none\n",
			ESDM_ES_EXT_NAME_MAX);
}

/*
 * Serve what client @i has sent: one request, or the next step of its DTLS
 * handshake.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_serve(struct esdm_es_ext_server *server,
				     unsigned int i)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN + 1];
	uint8_t data[ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint32_t length, datalen, entropy_bits = 0;
	uint16_t type;
	size_t rsp_len;
	ssize_t n;
	int status;
	bool ret = false;

	server->client_active[i] = esdm_es_ext_server_now();

	if (server->client_state[i] == ESDM_ES_EXT_CLIENT_HANDSHAKE)
		return esdm_es_ext_server_handshake(server, i);

	n = esdm_es_ext_server_recv(server, i, req, sizeof(req));
	if (n == -EAGAIN)
		return true;
	if (n <= 0)
		goto out;
	if ((size_t)n > sizeof(req) ||
	    esdm_es_ext_proto_req_unpack(req, (size_t)n, &type, &length) ||
	    /* Once, and in the clear */
	    (type == ESDM_ES_EXT_PROTO_STARTDTLS &&
	     server->client_state[i] != ESDM_ES_EXT_CLIENT_PLAIN)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: invalid request, client disconnected\n");
		goto out;
	}

	datalen = length;
	switch (type) {
	case ESDM_ES_EXT_PROTO_GET_ENTROPY:
		status = esdm_es_ext_plugin_get(server->plugin, server->ctx,
						data, length, &entropy_bits);
		break;
	case ESDM_ES_EXT_PROTO_STARTDTLS:
		status = esdm_es_ext_server_startdtls(server, i);
		break;
	case ESDM_ES_EXT_PROTO_STATUS:
		status = esdm_es_ext_server_status(server, i, data, length,
						   &datalen);
		break;
	case ESDM_ES_EXT_PROTO_INFO:
		status = 0;
		datalen = esdm_es_ext_proto_info_pack(
			data,
			server->rate != ESDM_ES_EXT_PROTO_RATE_NONE ?
				server->rate :
				server->plugin_rate,
			server->name[0] ? server->name : NULL);
		break;
	default:
		status = server->plugin->selftest ?
				 server->plugin->selftest(server->ctx) :
				 0;
		/* An errno, or what it stands for */
		if (status > 0 || status < -ESDM_ES_EXT_PROTO_MAX_ERRNO)
			status = -EIO;
		server->selftest = status;
		break;
	}

	rsp_len = esdm_es_ext_proto_rsp_pack(rsp, type, status, entropy_bits,
					     data, datalen);
	ret = esdm_es_ext_server_send(server, i, rsp, rsp_len);
	if (ret)
		server->requests++;

	/* The answer to STARTDTLS went out in the clear, the handshake follows */
	if (ret && type == ESDM_ES_EXT_PROTO_STARTDTLS && !status)
		server->client_state[i] = ESDM_ES_EXT_CLIENT_HANDSHAKE;

out:
	memset_secure(data, 0, sizeof(data));
	memset_secure(rsp, 0, sizeof(rsp));
	if (!ret)
		esdm_es_ext_server_close_client(server, i);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_server_alloc(const struct esdm_es_ext_plugin *plugin,
			     const char *socket_path, mode_t mode,
			     struct esdm_es_ext_server **server)
{
	struct esdm_es_ext_server *s;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct stat sb;
	unsigned int i;
	int ret;

	if (!server || !socket_path)
		return -EINVAL;
	*server = NULL;

	if (esdm_es_ext_plugin_check(plugin))
		return -EPROTO;

	if (strlen(socket_path) == 0 ||
	    strlen(socket_path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, socket_path, strlen(socket_path));

	s = calloc(1, sizeof(*s));
	if (!s)
		return -ENOMEM;
	s->plugin = plugin;
	s->rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	s->plugin_rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	s->selftest = 1;
	s->started = esdm_es_ext_server_now();
	s->listen_fd = -1;
	s->stop_pipe[0] = s->stop_pipe[1] = -1;
	for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++)
		s->clients[i] = -1;

	s->path = strdup(socket_path);
	if (!s->path) {
		ret = -ENOMEM;
		goto err;
	}

	if (pipe2(s->stop_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
		ret = -errno;
		goto err;
	}

	/* A socket left behind by an earlier instance, and nothing else */
	if (lstat(socket_path, &sb) == 0) {
		if (!S_ISSOCK(sb.st_mode)) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: %s exists and is no socket\n",
				socket_path);
			ret = -EEXIST;
			goto err;
		}
		unlink(socket_path);
	}

	s->listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (s->listen_fd < 0) {
		ret = -errno;
		goto err;
	}

	ret = esdm_server_bind_unix(s->listen_fd, &addr, mode);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "External ES provider: cannot bind to %s: %s\n",
			    socket_path, strerror(-ret));
		goto err;
	}

	if (lstat(socket_path, &sb) == 0) {
		s->dev = sb.st_dev;
		s->ino = sb.st_ino;
	}

	if (listen(s->listen_fd, ESDM_ES_EXT_SERVER_BACKLOG) < 0) {
		ret = -errno;
		goto err;
	}

	if (plugin->init) {
		ret = plugin->init(&s->ctx);
		if (ret) {
			if (ret > 0)
				ret = -EIO;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ANY,
				"External ES provider: initialization of %s failed: %s\n",
				plugin->name ? plugin->name : "the plugin",
				strerror(-ret));
			goto err;
		}
	}
	s->initialized = true;
	/* After its init, which may find out what it is and what it has */
	esdm_es_ext_server_plugin_name(s);
	s->plugin_rate = esdm_es_ext_plugin_entropy_rate(plugin, s->ctx);

	/*
	 * Whether the ESDM credits the rate the plugin declares is its
	 * business - worth a line for whoever starts the provider all the same
	 */
	if (s->plugin_rate != ESDM_ES_EXT_PROTO_RATE_NONE)
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_ANY,
			"External ES provider: the plugin declares an entropy rate of %u bits per 256 bits\n",
			s->plugin_rate);

#ifdef ESDM_DTLS
	/* Offered by default; a server without it still serves in the clear */
	if (esdm_dtls_ctx_alloc(true, &s->dtls_ctx))
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: DTLS cannot be set up, serving unencrypted\n");
#endif

	*server = s;
	return 0;

err:
	esdm_es_ext_server_free(s);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_server_allow_uid(struct esdm_es_ext_server *server, uid_t uid)
{
	unsigned int i;

	if (!server || uid == (uid_t)-1)
		return -EINVAL;

	for (i = 0; i < server->allowed_uids_num; i++) {
		if (server->allowed_uids[i] == uid)
			return 0;
	}
	if (server->allowed_uids_num >= ESDM_ES_EXT_SERVER_MAX_UIDS)
		return -ENOSPC;

	server->allowed_uids[server->allowed_uids_num++] = uid;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_name(struct esdm_es_ext_server *server,
				const char *name)
{
	if (!server)
		return -EINVAL;

	if (!name) {
		esdm_es_ext_server_plugin_name(server);
		return 0;
	}

	if (!esdm_es_ext_name_or_null(name))
		return -EINVAL;
	snprintf(server->name, sizeof(server->name), "%s", name);
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_entropy_rate(struct esdm_es_ext_server *server,
					uint32_t rate)
{
	if (!server || (rate > ESDM_ES_EXT_ENTROPY_RATE_MAX &&
			rate != ESDM_ES_EXT_PROTO_RATE_NONE))
		return -EINVAL;

	server->rate = rate;
	return 0;
}

DSO_PUBLIC
int esdm_es_ext_server_set_dtls(struct esdm_es_ext_server *server, int enable)
{
	if (!server)
		return -EINVAL;

	if (!enable) {
		esdm_dtls_ctx_free(server->dtls_ctx);
		server->dtls_ctx = NULL;
		return 0;
	}
	if (server->dtls_ctx)
		return 0;
	return esdm_dtls_ctx_alloc(true, &server->dtls_ctx);
}

DSO_PUBLIC
int esdm_es_ext_server_run(struct esdm_es_ext_server *server)
{
	struct pollfd pfd[ESDM_ES_EXT_SERVER_MAX_CLIENTS + 2];
	unsigned int i;

	if (!server)
		return -EINVAL;

	for (;;) {
		unsigned int nfds = 2;
		int ret;

		pfd[0] = (struct pollfd){ .fd = server->stop_pipe[0],
					  .events = POLLIN };
		pfd[1] = (struct pollfd){ .fd = server->listen_fd,
					  .events = POLLIN };
		for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++) {
			pfd[nfds] = (struct pollfd){ .fd = server->clients[i],
						     .events = POLLIN };
			nfds++;
		}

		ret = poll(pfd, nfds, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}

		if (pfd[0].revents)
			break;

		for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++) {
			short revents = pfd[i + 2].revents;

			if (server->clients[i] < 0 || !revents)
				continue;
			if (revents & POLLIN)
				esdm_es_ext_server_serve(server, i);
			else
				esdm_es_ext_server_close_client(server, i);
		}

		/* After the clients, so a new one is not served in this round */
		if (pfd[1].revents & POLLIN)
			esdm_es_ext_server_accept(server);
	}

	/* Drain the stop request, so that the server can be run again */
	{
		char c;

		while (read(server->stop_pipe[0], &c, 1) == 1)
			;
	}

	return 0;
}

DSO_PUBLIC
void esdm_es_ext_server_stop(struct esdm_es_ext_server *server)
{
	int errsv = errno;
	ssize_t __unused ret;

	if (!server)
		return;

	/* async-signal-safe: one write(2) to a non-blocking pipe */
	ret = write(server->stop_pipe[1], "", 1);
	errno = errsv;
}

DSO_PUBLIC
void esdm_es_ext_server_free(struct esdm_es_ext_server *server)
{
	struct stat sb;
	unsigned int i;

	if (!server)
		return;

	for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++)
		esdm_es_ext_server_close_client(server, i);

	if (server->listen_fd >= 0) {
		close(server->listen_fd);

		/* Only the socket created here, not one another instance made */
		if (server->path && lstat(server->path, &sb) == 0 &&
		    sb.st_dev == server->dev && sb.st_ino == server->ino)
			unlink(server->path);
	}

	if (server->initialized && server->plugin->fini)
		server->plugin->fini(server->ctx);

	esdm_dtls_ctx_free(server->dtls_ctx);

	if (server->stop_pipe[0] >= 0)
		close(server->stop_pipe[0]);
	if (server->stop_pipe[1] >= 0)
		close(server->stop_pipe[1]);

	free(server->path);
	free(server);
}
