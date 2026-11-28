/*
 * Test peer speaking the EGD wire protocol
 *
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

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "egd_peer.h"
#include "esdm_egd_protocol.h"
#include "esdm_ppoll.h"

/*
 * One connection per client, plus room for the ones a forked child of a test
 * opens - a handful is all any test needs.
 */
#define EGD_PEER_MAX_CONN 8

/* How long the accept loop waits before it looks at the stop flag again. */
#define EGD_PEER_POLL_MS 50

struct egd_peer {
	enum egd_peer_mode mode;
	int listen_fd;
	pthread_t accept_thread;
	atomic_int stop;

	pthread_mutex_t lock;
	unsigned int connections;
	unsigned int requests;
	unsigned int nconn;
	int conn_fds[EGD_PEER_MAX_CONN];
	pthread_t conn_threads[EGD_PEER_MAX_CONN];

	unsigned int writes;
	uint8_t write_buf[ESDM_EGD_MAX_TRANSFER];
	size_t write_len;
	uint32_t write_bits;

	unsigned int privs;
	uint8_t priv_cmd;
	uint32_t priv_arg;
	uint32_t write_wakeup;
	uint32_t min_reseed_secs;

	unsigned int inserts;
	size_t insert_len;
	uint32_t insert_sum;

	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

struct egd_peer_conn {
	struct egd_peer *peer;
	int fd;
	/* Bytes delivered on this connection, the read answers count from it. */
	size_t sent;
};

/****************************
 * Blocking transfers
 ****************************/

static int peer_read_all(int fd, uint8_t *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = read(fd, buf + done, len - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret == 0)
			return -EPIPE;
		if (errno == EINTR)
			continue;

		return -errno;
	}

	return 0;
}

static int peer_write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		ssize_t ret = write(fd, buf + done, len - done);

		if (ret > 0) {
			done += (size_t)ret;
			continue;
		}
		if (ret < 0 && errno == EINTR)
			continue;

		return (ret < 0) ? -errno : -EIO;
	}

	return 0;
}

/****************************
 * The commands
 ****************************/

/* Deliver @len bytes of the connection's counter sequence. */
static int peer_send_data(struct egd_peer_conn *conn, size_t len)
{
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	size_t i;

	while (len) {
		size_t chunk = (len < sizeof(buf)) ? len : sizeof(buf);
		int ret;

		for (i = 0; i < chunk; i++)
			buf[i] = egd_peer_data_byte(conn->sent + i);
		conn->sent += chunk;

		ret = peer_write_all(conn->fd, buf, chunk);
		if (ret)
			return ret;
		len -= chunk;
	}

	return 0;
}

static void peer_be32(uint8_t *p, uint32_t value)
{
	p[0] = (uint8_t)(value >> 24);
	p[1] = (uint8_t)(value >> 16);
	p[2] = (uint8_t)(value >> 8);
	p[3] = (uint8_t)value;
}

static uint32_t peer_from_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int peer_cmd_entropy_count(struct egd_peer_conn *conn)
{
	uint8_t response[4] = {
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 24),
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 16),
		(uint8_t)(EGD_PEER_ENTROPY_BITS >> 8),
		(uint8_t)EGD_PEER_ENTROPY_BITS,
	};

	return peer_write_all(conn->fd, response, sizeof(response));
}

/*
 * The state of an operational ESDM, with one field more than the protocol
 * defines, as a newer server would append it.
 */
static int peer_cmd_get_state(struct egd_peer_conn *conn)
{
	uint8_t response[1 + 4 * (ESDM_EGD_STATE_NUM_FIELDS + 1)] = { 0 };
	struct egd_peer *peer = conn->peer;

	response[0] = ESDM_EGD_STATE_NUM_FIELDS + 1;
	response[1 + 4 * ESDM_EGD_STATE_FLAGS + 3] =
		ESDM_EGD_STATE_FLAG_OPERATIONAL |
		ESDM_EGD_STATE_FLAG_FULLY_SEEDED;
	peer_be32(response + 1 + 4 * ESDM_EGD_STATE_ENT_CNT,
		  EGD_PEER_STATE_ENT_CNT);
	peer_be32(response + 1 + 4 * ESDM_EGD_STATE_POOLSIZE,
		  EGD_PEER_STATE_POOLSIZE);

	/* The two a privileged command sets */
	pthread_mutex_lock(&peer->lock);
	peer_be32(response + 1 + 4 * ESDM_EGD_STATE_WRITE_WAKEUP,
		  peer->write_wakeup);
	peer_be32(response + 1 + 4 * ESDM_EGD_STATE_MIN_RESEED_SECS,
		  peer->min_reseed_secs);
	pthread_mutex_unlock(&peer->lock);

	return peer_write_all(conn->fd, response, sizeof(response));
}

static int peer_cmd_read_nonblock(struct egd_peer_conn *conn)
{
	uint8_t requested, delivered;
	int ret;

	ret = peer_read_all(conn->fd, &requested, sizeof(requested));
	if (ret)
		return ret;

	switch (conn->peer->mode) {
	case EGD_PEER_SHORT:
		/* Half of it, and nothing at all for a single byte. */
		delivered = (uint8_t)(requested / 2);
		break;
	case EGD_PEER_OVERLONG:
		/*
		 * One byte more than was asked for. The client has to reject
		 * that on the length byte alone - reading the data would
		 * desynchronize the stream for good.
		 */
		if (requested == ESDM_EGD_MAX_TRANSFER)
			return -EINVAL;
		delivered = (uint8_t)(requested + 1);
		break;
	case EGD_PEER_NORMAL:
	case EGD_PEER_SILENT:
	case EGD_PEER_HANGUP:
	case EGD_PEER_SHUT_RD:
	case EGD_PEER_UNPRIVILEGED:
	case EGD_PEER_LEGACY:
		delivered = requested;
		break;
	}

	ret = peer_write_all(conn->fd, &delivered, sizeof(delivered));
	if (ret)
		return ret;

	return peer_send_data(conn, delivered);
}

static int peer_cmd_read_block(struct egd_peer_conn *conn)
{
	uint8_t requested;
	int ret;

	ret = peer_read_all(conn->fd, &requested, sizeof(requested));
	if (ret)
		return ret;

	/* The blocking command is answered in full, whatever it takes. */
	return peer_send_data(conn, requested);
}

static int peer_cmd_write_entropy(struct egd_peer_conn *conn)
{
	struct egd_peer *peer = conn->peer;
	uint8_t header[3];
	uint8_t buf[ESDM_EGD_MAX_TRANSFER];
	int ret;

	/* Two big endian entropy bytes and the length. */
	ret = peer_read_all(conn->fd, header, sizeof(header));
	if (ret)
		return ret;

	ret = peer_read_all(conn->fd, buf, header[2]);
	if (ret)
		return ret;

	pthread_mutex_lock(&peer->lock);
	peer->write_bits = ((uint32_t)header[0] << 8) | (uint32_t)header[1];
	peer->write_len = header[2];
	memcpy(peer->write_buf, buf, header[2]);
	peer->writes++;
	pthread_mutex_unlock(&peer->lock);

	/* This command has no answer. */
	return 0;
}

static int peer_cmd_get_pid(struct egd_peer_conn *conn)
{
	char pid[32];
	uint8_t len;
	int ret;

	/* The PID goes out as a string, without a terminating NUL. */
	ret = snprintf(pid, sizeof(pid), "%d", EGD_PEER_PID);
	if (ret <= 0)
		return -EFAULT;
	len = (uint8_t)ret;

	ret = peer_write_all(conn->fd, &len, sizeof(len));
	if (ret)
		return ret;

	return peer_write_all(conn->fd, (const uint8_t *)pid, len);
}

/*
 * The bulk read of the ESDM: answered as the non-blocking read it names, with
 * a 4 byte length.
 */
static int peer_cmd_bulk_read(struct egd_peer_conn *conn)
{
	uint8_t request[5], response[4];
	uint32_t requested, delivered;
	int ret;

	ret = peer_read_all(conn->fd, request, sizeof(request));
	if (ret)
		return ret;

	requested = peer_from_be32(request + 1);
	if ((request[0] != ESDM_EGD_CMD_READ_NONBLOCK &&
	     request[0] != ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK &&
	     request[0] != ESDM_EGD_CMD_ESDM_READ_UNSEEDED) ||
	    requested > ESDM_EGD_MAX_BULK)
		return -EPROTO;

	if (conn->peer->mode == EGD_PEER_SHORT)
		delivered = requested / 2;
	else if (conn->peer->mode == EGD_PEER_OVERLONG)
		delivered = requested + 1;
	else
		delivered = requested;

	peer_be32(response, delivered);
	ret = peer_write_all(conn->fd, response, sizeof(response));
	if (ret)
		return ret;

	return peer_send_data(conn, delivered);
}

/* The status reports of the ESDM, preceded by their 4 byte length */
static int peer_cmd_status(struct egd_peer_conn *conn, int json)
{
	const char *report = json ? EGD_PEER_STATUS_JSON : EGD_PEER_STATUS;
	size_t len = (conn->peer->mode == EGD_PEER_SHORT) ? 0 : strlen(report);
	uint8_t response[4];
	int ret;

	peer_be32(response, (uint32_t)len);
	ret = peer_write_all(conn->fd, response, sizeof(response));
	if (ret)
		return ret;

	return peer_write_all(conn->fd, (const uint8_t *)report, len);
}

/*
 * The privileged commands of the ESDM: recorded and answered with a status -
 * with -EPERM, and without any effect, by the unprivileged peer.
 */
static int peer_cmd_priv(struct egd_peer_conn *conn, uint8_t cmd, int has_arg)
{
	struct egd_peer *peer = conn->peer;
	uint8_t arg[4] = { 0 }, response[4];
	int status = (peer->mode == EGD_PEER_UNPRIVILEGED) ? -EPERM : 0;
	int ret;

	if (has_arg) {
		ret = peer_read_all(conn->fd, arg, sizeof(arg));
		if (ret)
			return ret;
	}

	pthread_mutex_lock(&peer->lock);
	peer->privs++;
	peer->priv_cmd = cmd;
	peer->priv_arg = peer_from_be32(arg);
	if (!status && cmd == ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP)
		peer->write_wakeup = peer->priv_arg;
	if (!status && cmd == ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS)
		peer->min_reseed_secs = peer->priv_arg;
	pthread_mutex_unlock(&peer->lock);

	peer_be32(response, (uint32_t)status);

	return peer_write_all(conn->fd, response, sizeof(response));
}

/* The bulk insert of the ESDM: answered with a status once all data is in */
static int peer_cmd_bulk_insert(struct egd_peer_conn *conn)
{
	struct egd_peer *peer = conn->peer;
	uint8_t header[4], buf[256], response[4] = { 0 };
	uint32_t sum = 0;
	size_t len, left, chunk, i;
	int ret;

	ret = peer_read_all(conn->fd, header, sizeof(header));
	if (ret)
		return ret;

	len = peer_from_be32(header);
	if (len > ESDM_EGD_MAX_BULK)
		return -EPROTO;

	for (left = len; left; left -= chunk) {
		chunk = (left < sizeof(buf)) ? left : sizeof(buf);

		ret = peer_read_all(conn->fd, buf, chunk);
		if (ret)
			return ret;
		for (i = 0; i < chunk; i++)
			sum += buf[i];
	}

	pthread_mutex_lock(&peer->lock);
	peer->inserts++;
	peer->insert_len += len;
	peer->insert_sum += sum;
	pthread_mutex_unlock(&peer->lock);

	return peer_write_all(conn->fd, response, sizeof(response));
}

/****************************
 * Connection and accept loop
 ****************************/

static void *peer_conn_thread(void *arg)
{
	struct egd_peer_conn *conn = arg;
	struct egd_peer *peer = conn->peer;
	struct timespec nowait = { 0, 0 };
	sigset_t sigpipe;

	/*
	 * A client giving up on an answer - which several tests make it do -
	 * closes its end mid-write, and an unhandled SIGPIPE would take the test
	 * process down. The peer writes plainly rather than with MSG_NOSIGNAL,
	 * as this has to stay reachable from where sendto(2) is not.
	 *
	 * Blocked here rather than ignored process wide: the client library
	 * promises never to let a vanished peer raise SIGPIPE, and ignoring it
	 * globally would take that promise out of the test. A blocked SIGPIPE
	 * only makes this thread's write report EPIPE, while every other thread
	 * keeps the default disposition.
	 */
	sigemptyset(&sigpipe);
	sigaddset(&sigpipe, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &sigpipe, NULL);

	while (!atomic_load(&peer->stop)) {
		uint8_t cmd;
		int ret;

		/*
		 * A silent peer reads nothing at all: the client's request fits
		 * into the socket buffer, so it gets as far as waiting for an
		 * answer that never comes - which is the point of this mode.
		 */
		if (peer->mode == EGD_PEER_SILENT) {
			struct pollfd pfd = { .fd = conn->fd, .events = 0 };

			esdm_ppoll_ms(&pfd, 1, EGD_PEER_POLL_MS);
			continue;
		}

		/* Nothing to read either - until the client is gone. */
		if (peer->mode == EGD_PEER_SHUT_RD) {
			struct pollfd pfd = { .fd = conn->fd, .events = 0 };

			if (esdm_ppoll_ms(&pfd, 1, EGD_PEER_POLL_MS) > 0 &&
			    (pfd.revents & (POLLHUP | POLLERR)))
				break;
			continue;
		}

		ret = peer_read_all(conn->fd, &cmd, sizeof(cmd));
		if (ret)
			break;

		/*
		 * Counted on receipt, before the answer goes out. Counting a
		 * served request would race with the client it was served to:
		 * it returns as soon as it read the answer, so it can be back
		 * looking at this counter while the thread that wrote that
		 * answer has not incremented it yet.
		 */
		pthread_mutex_lock(&peer->lock);
		peer->requests++;
		pthread_mutex_unlock(&peer->lock);

		/* Not a command of EGD: unknown to a peer that is no ESDM */
		if (peer->mode == EGD_PEER_LEGACY &&
		    cmd > ESDM_EGD_CMD_GET_PID) {
			shutdown(conn->fd, SHUT_RDWR);
			break;
		}

		switch (cmd) {
		case ESDM_EGD_CMD_ENTROPY_COUNT:
			ret = peer_cmd_entropy_count(conn);
			break;
		case ESDM_EGD_CMD_READ_NONBLOCK:
			ret = peer_cmd_read_nonblock(conn);
			break;
		case ESDM_EGD_CMD_READ_BLOCK:
			ret = peer_cmd_read_block(conn);
			break;
		case ESDM_EGD_CMD_WRITE_ENTROPY:
			ret = peer_cmd_write_entropy(conn);
			break;
		case ESDM_EGD_CMD_GET_PID:
			ret = peer_cmd_get_pid(conn);
			break;
		case ESDM_EGD_CMD_ESDM_GET_STATE:
			ret = peer_cmd_get_state(conn);
			break;
		case ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK:
		case ESDM_EGD_CMD_ESDM_READ_UNSEEDED:
			ret = peer_cmd_read_nonblock(conn);
			break;
		case ESDM_EGD_CMD_ESDM_PR_READ_BLOCK:
			ret = peer_cmd_read_block(conn);
			break;
		case ESDM_EGD_CMD_ESDM_BULK_READ:
			ret = peer_cmd_bulk_read(conn);
			break;
		case ESDM_EGD_CMD_ESDM_STATUS:
			ret = peer_cmd_status(conn, 0);
			break;
		case ESDM_EGD_CMD_ESDM_STATUS_JSON:
			ret = peer_cmd_status(conn, 1);
			break;
		case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
		case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
		case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
			ret = peer_cmd_priv(conn, cmd, 1);
			break;
		case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
		case ESDM_EGD_CMD_ESDM_RESEED:
			ret = peer_cmd_priv(conn, cmd, 0);
			break;
		case ESDM_EGD_CMD_ESDM_BULK_INSERT:
			ret = peer_cmd_bulk_insert(conn);
			break;
		default:
			printf("EGD peer: unknown command 0x%02x\n", cmd);
			ret = -EPROTO;
			break;
		}

		if (ret)
			break;
	}

	/*
	 * Blocking the signal keeps the write from being fatal but does not make
	 * it go away: a SIGPIPE raised above stays pending on this thread, and
	 * whoever unblocks it first gets it delivered. The exit path does exactly
	 * that - the sanitizer runtime's TSD destructor takes the mask apart - so
	 * an ASan build dies in __nptl_deallocate_tsd(), long after the write
	 * that raised it. So take the signal off here, while it is still blocked
	 * and this is the only thread that could receive it. The zero timeout
	 * returns right away in the common case, where nothing is pending.
	 */
	while (sigtimedwait(&sigpipe, NULL, &nowait) < 0 && errno == EINTR)
		;

	free(conn);

	return NULL;
}

static void *peer_accept_thread(void *arg)
{
	struct egd_peer *peer = arg;

	while (!atomic_load(&peer->stop)) {
		struct pollfd pfd = {
			.fd = peer->listen_fd,
			.events = POLLIN,
		};
		struct egd_peer_conn *conn;
		unsigned int connections;
		int fd;

		if (esdm_ppoll_ms(&pfd, 1, EGD_PEER_POLL_MS) <= 0)
			continue;

		fd = accept(peer->listen_fd, NULL, NULL);
		if (fd < 0)
			continue;

		if (peer->mode == EGD_PEER_SHUT_RD)
			shutdown(fd, SHUT_RD);

		pthread_mutex_lock(&peer->lock);
		peer->connections++;
		connections = peer->connections;
		pthread_mutex_unlock(&peer->lock);

		/* A daemon that went away between two requests. */
		if (peer->mode == EGD_PEER_HANGUP && connections == 1) {
			close(fd);
			continue;
		}

		conn = calloc(1, sizeof(*conn));
		if (conn == NULL || peer->nconn >= EGD_PEER_MAX_CONN) {
			printf("EGD peer: cannot serve the connection\n");
			free(conn);
			close(fd);
			continue;
		}
		conn->peer = peer;
		conn->fd = fd;

		/*
		 * Only the accept thread touches these two, and stopping joins
		 * it before it looks at them.
		 */
		peer->conn_fds[peer->nconn] = fd;
		if (pthread_create(&peer->conn_threads[peer->nconn], NULL,
				   peer_conn_thread, conn)) {
			printf("EGD peer: cannot create the connection thread\n");
			free(conn);
			close(fd);
			continue;
		}
		peer->nconn++;
	}

	return NULL;
}

/****************************
 * Lifecycle
 ****************************/

int egd_peer_start(struct egd_peer **peer, const char *path,
		   enum egd_peer_mode mode)
{
	struct egd_peer *new_peer;
	struct sockaddr_un addr;
	int ret;

	if (peer == NULL || path == NULL)
		return -EINVAL;
	*peer = NULL;

	new_peer = calloc(1, sizeof(struct egd_peer));
	if (new_peer == NULL)
		return -ENOMEM;

	new_peer->mode = mode;
	new_peer->listen_fd = -1;
	new_peer->write_wakeup = EGD_PEER_STATE_WRITE_WAKEUP;
	new_peer->min_reseed_secs = EGD_PEER_STATE_MIN_RESEED_SECS;
	atomic_init(&new_peer->stop, 0);
	pthread_mutex_init(&new_peer->lock, NULL);

	if (strlen(path) >= sizeof(new_peer->path)) {
		free(new_peer);
		return -ENAMETOOLONG;
	}
	snprintf(new_peer->path, sizeof(new_peer->path), "%s", path);

	new_peer->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (new_peer->listen_fd < 0) {
		ret = -errno;
		goto err;
	}

	/* A leftover of a previous run would make the bind fail. */
	unlink(path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	if (bind(new_peer->listen_fd, (struct sockaddr *)&addr,
		 sizeof(addr)) < 0) {
		ret = -errno;
		goto err;
	}

	if (listen(new_peer->listen_fd, EGD_PEER_MAX_CONN) < 0) {
		ret = -errno;
		goto err;
	}

	if (pthread_create(&new_peer->accept_thread, NULL, peer_accept_thread,
			   new_peer)) {
		ret = -EFAULT;
		goto err;
	}

	*peer = new_peer;

	return 0;

err:
	if (new_peer->listen_fd >= 0)
		close(new_peer->listen_fd);
	pthread_mutex_destroy(&new_peer->lock);
	free(new_peer);

	return ret;
}

void egd_peer_stop(struct egd_peer *peer)
{
	unsigned int i;

	if (peer == NULL)
		return;

	atomic_store(&peer->stop, 1);
	pthread_join(peer->accept_thread, NULL);

	/*
	 * Shut the connections down before joining: a connection thread sits in
	 * a blocking read, which only returns once the other end is gone.
	 */
	for (i = 0; i < peer->nconn; i++)
		shutdown(peer->conn_fds[i], SHUT_RDWR);
	for (i = 0; i < peer->nconn; i++) {
		pthread_join(peer->conn_threads[i], NULL);
		close(peer->conn_fds[i]);
	}

	close(peer->listen_fd);
	unlink(peer->path);
	pthread_mutex_destroy(&peer->lock);
	free(peer);
}

unsigned int egd_peer_connections(struct egd_peer *peer)
{
	unsigned int connections;

	pthread_mutex_lock(&peer->lock);
	connections = peer->connections;
	pthread_mutex_unlock(&peer->lock);

	return connections;
}

unsigned int egd_peer_requests(struct egd_peer *peer)
{
	unsigned int requests;

	pthread_mutex_lock(&peer->lock);
	requests = peer->requests;
	pthread_mutex_unlock(&peer->lock);

	return requests;
}

unsigned int egd_peer_last_write(struct egd_peer *peer, uint8_t *buf,
				 size_t buflen, size_t *len,
				 uint32_t *entropy_bits)
{
	unsigned int writes;

	pthread_mutex_lock(&peer->lock);
	writes = peer->writes;
	if (len)
		*len = peer->write_len;
	if (entropy_bits)
		*entropy_bits = peer->write_bits;
	if (buf)
		memcpy(buf, peer->write_buf,
		       (buflen < peer->write_len) ? buflen : peer->write_len);
	pthread_mutex_unlock(&peer->lock);

	return writes;
}

unsigned int egd_peer_last_priv(struct egd_peer *peer, uint8_t *cmd,
				uint32_t *arg)
{
	unsigned int privs;

	pthread_mutex_lock(&peer->lock);
	privs = peer->privs;
	if (cmd)
		*cmd = peer->priv_cmd;
	if (arg)
		*arg = peer->priv_arg;
	pthread_mutex_unlock(&peer->lock);

	return privs;
}

unsigned int egd_peer_inserted(struct egd_peer *peer, size_t *len,
			       uint32_t *sum)
{
	unsigned int inserts;

	pthread_mutex_lock(&peer->lock);
	inserts = peer->inserts;
	if (len)
		*len = peer->insert_len;
	if (sum)
		*sum = peer->insert_sum;
	pthread_mutex_unlock(&peer->lock);

	return inserts;
}
