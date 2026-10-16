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
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "esdm_server_socket.h"
#include "helper.h"
#include "memset_secure.h"
#include "visibility.h"

/*
 * Clients served at a time. The ESDM holds one connection; the room beyond is
 * for a restarted ESDM whose old connection is not closed yet, and for tools.
 * A client beyond is accepted and closed at once, so that it does not wait in
 * the backlog for nothing.
 */
#define ESDM_ES_EXT_SERVER_MAX_CLIENTS 8

#define ESDM_ES_EXT_SERVER_BACKLOG 8

struct esdm_es_ext_server {
	const struct esdm_es_ext_plugin *plugin;
	void *ctx;
	bool initialized;

	int listen_fd;
	/* Written to by esdm_es_ext_server_stop() */
	int stop_pipe[2];
	int clients[ESDM_ES_EXT_SERVER_MAX_CLIENTS];

	char *path;
	/* The socket file created, so that only that one is removed again */
	dev_t dev;
	ino_t ino;
};

static void esdm_es_ext_server_close_client(struct esdm_es_ext_server *server,
					    unsigned int i)
{
	if (server->clients[i] < 0)
		return;

	close(server->clients[i]);
	server->clients[i] = -1;
}

static void esdm_es_ext_server_accept(struct esdm_es_ext_server *server)
{
	unsigned int i;
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

	for (i = 0; i < ESDM_ES_EXT_SERVER_MAX_CLIENTS; i++) {
		if (server->clients[i] < 0) {
			server->clients[i] = fd;
			return;
		}
	}

	esdm_logger(
		LOGGER_WARN, LOGGER_C_ANY,
		"External ES provider: too many clients, connection refused\n");
	close(fd);
}

/*
 * Serve one request of client @i.
 *
 * @return true if the client is still connected afterwards
 */
static bool esdm_es_ext_server_serve(struct esdm_es_ext_server *server,
				     unsigned int i)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN + 1];
	uint8_t data[ESDM_ES_EXT_PROTO_MAX_DATA];
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_DATA];
	uint32_t length, entropy_bits = 0;
	int fd = server->clients[i];
	uint16_t type;
	size_t rsp_len;
	ssize_t n;
	int status;
	bool ret = false;

	/*
	 * One byte more than a request has, and MSG_TRUNC for the real size of
	 * the message: a longer one is a protocol error, not a request cut to
	 * size.
	 */
	n = recv(fd, req, sizeof(req), MSG_DONTWAIT | MSG_TRUNC);
	if (n < 0 &&
	    (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return true;
	if (n <= 0)
		goto out;
	if ((size_t)n > sizeof(req) ||
	    esdm_es_ext_proto_req_unpack(req, (size_t)n, &type, &length)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"External ES provider: invalid request, client disconnected\n");
		goto out;
	}

	if (type == ESDM_ES_EXT_PROTO_GET_ENTROPY) {
		status = esdm_es_ext_plugin_get(server->plugin, server->ctx,
						data, length, &entropy_bits);
	} else {
		status = server->plugin->selftest ?
				 server->plugin->selftest(server->ctx) :
				 0;
		if (status > 0)
			status = -EIO;
	}

	rsp_len = esdm_es_ext_proto_rsp_pack(rsp, type, status, entropy_bits,
					     data, length);

	/*
	 * The client sends one request at a time and reads the answer, so the
	 * answer fits into its receive queue. One that does not read is not
	 * waited for.
	 */
	n = send(fd, rsp, rsp_len, MSG_DONTWAIT | MSG_NOSIGNAL);
	ret = n == (ssize_t)rsp_len;

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

	*server = s;
	return 0;

err:
	esdm_es_ext_server_free(s);
	return ret;
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

	if (server->stop_pipe[0] >= 0)
		close(server->stop_pipe[0]);
	if (server->stop_pipe[1] >= 0)
		close(server->stop_pipe[1]);

	free(server->path);
	free(server);
}
