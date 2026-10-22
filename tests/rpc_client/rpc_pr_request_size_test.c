/*
 * Test: a prediction resistance request beyond ESDM_RPC_MAX_PR_REQUEST_SIZE is
 * served in part
 *
 * The client library splits its prediction resistance requests into parts of
 * ESDM_RPC_MAX_PR_REQUEST_SIZE, but clients from before that limit ask for up
 * to ESDM_RPC_MAX_DATA at once. The server must serve them a part rather than
 * refuse the request with the negated limit: that value is an errno to every
 * client - -EPIPE for a limit of 32 - and not the size hint the clients only
 * take a return code below -255 for.
 *
 * The request is sent the way such a client sends it, on a connection of its
 * own, as today's client library cannot be made to ask for more.
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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_service.h"

/*
 * Method index of RpcGetRandomBytesPr - the order of service UnprivAccess in
 * unpriv_access.proto.
 */
#define TEST_METHOD_GET_RANDOM_BYTES_PR 4

/* Twice the limit, as a client from before it may ask for */
#define TEST_REQUEST_LEN (2 * ESDM_RPC_MAX_PR_REQUEST_SIZE)

/* How often a busy prediction resistance DRNG is asked again, once a second */
#define TEST_ATTEMPTS 60

static int test_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		close(fd);
		return -errsv;
	}

	return fd;
}

static size_t test_put_varint(uint8_t *buf, uint64_t val)
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

static bool test_get_varint(const uint8_t *buf, size_t len, size_t *pos,
			    uint64_t *val)
{
	unsigned int shift = 0;

	*val = 0;
	while (*pos < len && shift < 64) {
		uint8_t b = buf[(*pos)++];

		*val |= (uint64_t)(b & 0x7f) << shift;
		if (!(b & 0x80))
			return true;
		shift += 7;
	}

	return false;
}

/*
 * Ask for TEST_REQUEST_LEN prediction resistant bytes on @fd. Returns the
 * return code of the answer, with the length of its payload in @payload_len.
 */
static int test_request(int fd, int64_t *ret, uint64_t *payload_len)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE];
	struct esdm_rpc_proto_cs_header cs = {
		.method_index = TEST_METHOD_GET_RANDOM_BYTES_PR,
		.request_id = 0,
	};
	struct esdm_rpc_proto_sc_header sc;
	uint8_t *msg = buf + sizeof(cs);
	size_t msglen = 0, pos;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	uint64_t val;
	ssize_t rc;

	/* GetRandomBytesRequest: len (field 1, varint) */
	msg[msglen++] = 0x08;
	msglen += test_put_varint(msg + msglen, TEST_REQUEST_LEN);

	/* The server takes the header in little endian */
	cs.message_length = (uint32_t)msglen;
	memcpy(buf, &cs, sizeof(cs));

	if (send(fd, buf, sizeof(cs) + msglen, MSG_NOSIGNAL) !=
	    (ssize_t)(sizeof(cs) + msglen))
		return -errno;

	if (poll(&pfd, 1, 10000) <= 0)
		return -ETIMEDOUT;
	rc = recv(fd, buf, sizeof(buf), 0);
	if (rc < (ssize_t)sizeof(sc))
		return -EPROTO;

	memcpy(&sc, buf, sizeof(sc));
	if (sc.status_code != PROTOBUF_C_RPC_STATUS_CODE_SUCCESS ||
	    sc.message_length > (size_t)rc - sizeof(sc))
		return -EPROTO;

	/* RandValResponse: ret (field 1, int64), randval (field 2, bytes) */
	msg = buf + sizeof(sc);
	msglen = sc.message_length;
	pos = 0;
	*ret = 0;
	*payload_len = 0;
	while (pos < msglen) {
		uint8_t key = msg[pos++];

		if (key == 0x08) {
			if (!test_get_varint(msg, msglen, &pos, &val))
				return -EPROTO;
			*ret = (int64_t)val;
		} else if (key == 0x12) {
			if (!test_get_varint(msg, msglen, &pos, &val) ||
			    val > msglen - pos)
				return -EPROTO;
			*payload_len = val;
			pos += val;
		} else {
			return -EPROTO;
		}
	}

	return 0;
}

int main(void)
{
	struct timespec poll_ts = { .tv_sec = 1, .tv_nsec = 0 };
	uint64_t payload_len = 0;
	unsigned int i;
	int64_t answer = 0;
	int fd, ret;

	ret = env_init();
	if (ret)
		return ret;

	fd = test_connect();
	if (fd < 0) {
		printf("FAIL: cannot connect: %s\n", strerror(-fd));
		ret = 1;
		goto out;
	}

	for (i = 0; i < TEST_ATTEMPTS; i++) {
		ret = test_request(fd, &answer, &payload_len);
		if (ret) {
			printf("FAIL: request failed: %s\n", strerror(-ret));
			ret = 1;
			goto out_close;
		}
		if (answer != -EAGAIN)
			break;
		nanosleep(&poll_ts, NULL);
	}

	printf("Request for %d bytes answered with %lld and %llu bytes\n",
	       TEST_REQUEST_LEN, (long long)answer,
	       (unsigned long long)payload_len);

	if (answer <= 0 || answer > ESDM_RPC_MAX_PR_REQUEST_SIZE) {
		printf("FAIL: expected a part of at most %d bytes\n",
		       ESDM_RPC_MAX_PR_REQUEST_SIZE);
		ret = 1;
	} else if ((uint64_t)answer != payload_len) {
		printf("FAIL: the payload does not match the return code\n");
		ret = 1;
	}

out_close:
	close(fd);
out:
	env_fini();

	if (!ret)
		printf("PASS\n");

	return ret;
}
