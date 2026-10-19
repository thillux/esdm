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

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"
#include "rpc_standin_startdtls.h"
#include "vu_frontend.h"
#include "vu_standin.h"

/* Bytes one answer carries at most - the client asks again for the rest */
#define STANDIN_MAX_ANSWER 1024
#define STANDIN_MAX_CONNS 32

/* Method indices of the service UnprivAccess in unpriv_access.proto */
#define STANDIN_GET_RANDOM_BYTES_FULL 3
#define STANDIN_GET_RANDOM_BYTES_PR 4

static atomic_bool standin_seeded = true;
static atomic_bool standin_stopping;
/* 32 bits, so that no 32-bit target needs libatomic for it */
static atomic_uint standin_stream;
static atomic_uint standin_full;
static atomic_uint standin_pr;
static int standin_fd = -1;
static pthread_t standin_thread;

uint8_t standin_stream_byte(uint64_t pos)
{
	uint8_t v = (uint8_t)((pos * 0x9e3779b97f4a7c15ULL) >> 56);

	return v == FE_CANARY ? 0x33 : v;
}

uint64_t standin_pos(void)
{
	return atomic_load(&standin_stream);
}

unsigned int standin_full_requests(void)
{
	return atomic_load(&standin_full);
}

unsigned int standin_pr_requests(void)
{
	return atomic_load(&standin_pr);
}

void standin_set_seeded(bool seeded)
{
	atomic_store(&standin_seeded, seeded);
}

static size_t standin_varint(uint8_t *buf, uint64_t val)
{
	size_t i = 0;

	do {
		buf[i] = (uint8_t)(val & 0x7f);
		val >>= 7;
		if (val)
			buf[i] |= 0x80;
		i++;
	} while (val);

	return i;
}

/* The len field (1) of a GetRandomBytesRequest, 0 if it has none */
static uint64_t standin_request_len(const uint8_t *data, size_t len)
{
	uint64_t val = 0;
	unsigned int shift = 0;
	size_t i;

	if (len < 2 || data[0] != 0x08)
		return 0;

	for (i = 1; i < len && shift < 64; i++, shift += 7) {
		val |= (uint64_t)(data[i] & 0x7f) << shift;
		if (!(data[i] & 0x80))
			return val;
	}

	return 0;
}

/* Answer one request on @fd; false when the connection is gone */
static bool standin_serve(int fd)
{
	uint8_t resp[sizeof(struct esdm_rpc_proto_sc_header) + 32 +
		     STANDIN_MAX_ANSWER];
	struct esdm_rpc_proto_cs_header cs;
	struct esdm_rpc_proto_sc_header sc;
	uint8_t *msg = resp + sizeof(sc);
	uint8_t req[512];
	size_t msglen = 0;
	uint64_t len, pos, i;
	ssize_t rc;

	rc = recv(fd, req, sizeof(req), 0);
	if (rc <= 0 || (size_t)rc < sizeof(cs))
		return false;

	memcpy(&cs, req, sizeof(cs));
	if (test_standin_startdtls(fd, &cs))
		return true;

	len = standin_request_len(req + sizeof(cs), (size_t)rc - sizeof(cs));
	if (len > STANDIN_MAX_ANSWER)
		len = STANDIN_MAX_ANSWER;

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg[msglen++] = 0x08;
	if (cs.method_index != STANDIN_GET_RANDOM_BYTES_FULL &&
	    cs.method_index != STANDIN_GET_RANDOM_BYTES_PR) {
		msglen += standin_varint(msg + msglen,
					 (uint64_t)(int64_t)-EOPNOTSUPP);
	} else if (!atomic_load(&standin_seeded) || !len) {
		msglen += standin_varint(msg + msglen,
					 (uint64_t)(int64_t)-EAGAIN);
	} else {
		atomic_fetch_add(cs.method_index ==
						 STANDIN_GET_RANDOM_BYTES_FULL ?
					 &standin_full :
					 &standin_pr,
				 1);
		pos = atomic_fetch_add(&standin_stream, (unsigned int)len);

		msglen += standin_varint(msg + msglen, len);
		msg[msglen++] = 0x12;
		msglen += standin_varint(msg + msglen, len);
		for (i = 0; i < len; i++)
			msg[msglen++] = standin_stream_byte(pos + i);
	}

	/* The client takes the header in little endian, as the server sends */
	sc.status_code = PROTOBUF_C_RPC_STATUS_CODE_SUCCESS;
	sc.method_index = cs.method_index;
	sc.message_length = (uint32_t)msglen;
	sc.request_id = cs.request_id;
	memcpy(resp, &sc, sizeof(sc));

	return send(fd, resp, sizeof(sc) + msglen, MSG_NOSIGNAL) ==
	       (ssize_t)(sizeof(sc) + msglen);
}

static void *standin_main(void *unused)
{
	struct pollfd pfd[1 + STANDIN_MAX_CONNS];
	nfds_t nfds = 1, i;

	(void)unused;

	pfd[0].fd = standin_fd;
	pfd[0].events = POLLIN;

	while (!atomic_load(&standin_stopping)) {
		if (poll(pfd, nfds, 50) <= 0)
			continue;

		for (i = 1; i < nfds; i++) {
			if (!pfd[i].revents)
				continue;
			if ((pfd[i].revents & POLLIN) &&
			    standin_serve(pfd[i].fd))
				continue;

			close(pfd[i].fd);
			pfd[i--] = pfd[--nfds];
		}

		if ((pfd[0].revents & POLLIN) &&
		    nfds < 1 + STANDIN_MAX_CONNS) {
			int fd = accept4(standin_fd, NULL, NULL, SOCK_CLOEXEC);

			if (fd >= 0) {
				pfd[nfds].fd = fd;
				pfd[nfds].events = POLLIN;
				pfd[nfds].revents = 0;
				nfds++;
			}
		}
	}

	for (i = 1; i < nfds; i++)
		close(pfd[i].fd);

	return NULL;
}

int standin_start(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("Something listens on %s already\n", addr.sun_path);
		close(fd);
		return -EADDRINUSE;
	}
	close(fd);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/*
	 * Open to everybody, as the unprivileged RPC socket of the esdm-server
	 * is: run as root, the daemon drops its privileges to nobody before it
	 * connects. The umask would leave the socket without write access for
	 * it.
	 */
	unlink(addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    chmod(addr.sun_path, 0666) || listen(fd, 16)) {
		int errsv = errno;

		printf("Cannot listen on %s: %s\n", addr.sun_path,
		       strerror(errsv));
		close(fd);
		return -errsv;
	}

	standin_fd = fd;
	atomic_store(&standin_stopping, false);
	if (pthread_create(&standin_thread, NULL, standin_main, NULL)) {
		close(fd);
		unlink(addr.sun_path);
		standin_fd = -1;
		return -EAGAIN;
	}

	return 0;
}

int standin_stop_refusing(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd, ret = 0;

	standin_stop();

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	/* Bound, never listening, and closed: the file stays, refusing */
	unlink(addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    chmod(addr.sun_path, 0666))
		ret = -errno;
	close(fd);

	return ret;
}

void standin_stop(void)
{
	if (standin_fd < 0)
		return;

	atomic_store(&standin_stopping, true);
	pthread_join(standin_thread, NULL);
	close(standin_fd);
	standin_fd = -1;
	unlink(ESDM_RPC_UNPRIV_SOCKET);
}
