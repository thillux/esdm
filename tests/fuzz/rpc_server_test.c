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
 * The answers the RPC server gives where it cannot give the one asked for.
 *
 * Driven through the request hook of the fuzz harnesses, which hands a buffer to
 * the server as if it had been read off a client connection and lets the server
 * answer on a socket of the test's. Hence no daemon and no privileges:
 *
 *   - the self test call is refused to a client that is not root,
 *   - a response the server cannot pack is answered with a failure status
 *     rather than with silence the client has to time out on,
 *   - a client that does not read its answers is dropped instead of being
 *     waited for on every request.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common_test.h"
#include "conv_be_le.h"
#include "esdm.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "priv_access.pb-c.h"
#include "unpriv_access.pb-c.h"

/* The server's end and the client's end of the connection */
static int server_fd = -1;
static int client_fd = -1;

#define TEST_REQUEST_ID 0x1234

/* A request for @method of @desc carrying an empty message */
static int test_request(ProtobufCService *service, bool privileged,
			const char *method)
{
	const ProtobufCMethodDescriptor *m =
		protobuf_c_service_descriptor_get_method_by_name(
			service->descriptor, method);
	struct esdm_rpc_proto_cs_header header;

	if (!m) {
		CHECK(0, "no method %s", method);
		return -EINVAL;
	}

	header.method_index =
		le_bswap32((uint32_t)(m - service->descriptor->methods));
	header.message_length = 0;
	header.request_id = le_bswap32(TEST_REQUEST_ID);

	return esdm_rpcs_fuzz_request(service, privileged, (uint8_t *)&header,
				      sizeof(header), server_fd);
}

/* Take the answer off the client's end, < 0 if there is none */
static ssize_t test_answer(uint8_t *buf, size_t len)
{
	return recv(client_fd, buf, len, MSG_DONTWAIT);
}

static void test_drain(void)
{
	static uint8_t sink[ESDM_RPC_MAX_MSG_SIZE];

	while (recv(client_fd, sink, sizeof(sink), MSG_DONTWAIT) > 0)
		;
}

/******************************************************************************
 * The self test is a privileged call
 ******************************************************************************/

static void test_selftest_refused(void)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE];
	struct esdm_rpc_proto_sc_header *reply =
		(struct esdm_rpc_proto_sc_header *)buf;
	SelftestResponse *response;
	ssize_t received;

	/* Root is who the call is meant for */
	if (!geteuid()) {
		printf("running as root - skipping the refused self test\n");
		return;
	}

	test_drain();
	CHECK_EQ(test_request((ProtobufCService *)&priv_access_service, true,
			      "RpcSelftest"),
		 0);

	received = test_answer(buf, sizeof(buf));
	CHECK(received >= (ssize_t)sizeof(*reply),
	      "the self test request was not answered");
	if (received < (ssize_t)sizeof(*reply))
		return;

	CHECK_EQ(le_bswap32(reply->status_code),
		 PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);

	response = selftest_response__unpack(
		NULL, le_bswap32(reply->message_length), buf + sizeof(*reply));
	CHECK(response != NULL, "the self test answer does not unpack");
	if (!response)
		return;

	CHECK_EQ(response->ret, -EPERM);

	selftest_response__free_unpacked(response, NULL);
}

/******************************************************************************
 * A service whose answer is chosen by the test
 ******************************************************************************/

static char *test_status_buffer;

/* Answers every call with a StatusResponse carrying test_status_buffer */
static void test_service_invoke(ProtobufCService *service,
				unsigned int method_index,
				const ProtobufCMessage *input,
				ProtobufCClosure closure, void *closure_data)
{
	StatusResponse response = STATUS_RESPONSE__INIT;

	(void)service;
	(void)method_index;
	(void)input;

	response.ret = 0;
	response.buffer = test_status_buffer;

	closure((const ProtobufCMessage *)&response, closure_data);
}

static ProtobufCService test_service = {
	.descriptor = &unpriv_access__descriptor,
	.invoke = test_service_invoke,
	.destroy = NULL,
};

/* An answer larger than a message may be is answered with a failure */
static void test_unpackable_answer(void)
{
	struct esdm_rpc_proto_sc_header reply;
	ssize_t received;

	test_status_buffer = malloc(ESDM_RPC_MAX_MSG_SIZE + 1);
	CHECK(test_status_buffer != NULL, "out of memory");
	if (!test_status_buffer)
		return;
	memset(test_status_buffer, 'a', ESDM_RPC_MAX_MSG_SIZE);
	test_status_buffer[ESDM_RPC_MAX_MSG_SIZE] = '\0';

	test_drain();
	test_request(&test_service, false, "RpcStatus");

	received = test_answer((uint8_t *)&reply, sizeof(reply));
	CHECK_EQ(received, (ssize_t)sizeof(reply));
	if (received == (ssize_t)sizeof(reply)) {
		CHECK_EQ(le_bswap32(reply.status_code),
			 PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED);
		CHECK_EQ(le_bswap32(reply.request_id), TEST_REQUEST_ID);
		CHECK_EQ(le_bswap32(reply.message_length), 0);
	}

	free(test_status_buffer);
	test_status_buffer = NULL;
}

/* A client whose answers pile up unread is dropped */
static void test_unread_answers(void)
{
	static uint8_t filler[1024];
	struct esdm_rpc_proto_sc_header reply;
	unsigned int queued = 0;
	int ret;

	test_status_buffer = (char *)"answer";

	/* Fill the client's end until the server can no longer write */
	test_drain();
	while (send(server_fd, filler, sizeof(filler), MSG_DONTWAIT) > 0)
		queued++;
	CHECK(queued > 0 && (errno == EAGAIN || errno == EWOULDBLOCK),
	      "cannot fill the connection: %s", strerror(errno));

	ret = test_request(&test_service, false, "RpcStatus");
	CHECK_EQ(ret, -EPIPE);

	/* Nothing but the filler arrived - and the test's descriptor lives */
	while (test_answer((uint8_t *)filler, sizeof(filler)) > 0)
		queued--;
	CHECK_EQ(queued, 0);

	/* Once the client reads again, it is answered again */
	CHECK_EQ(test_request(&test_service, false, "RpcStatus"), 0);
	CHECK_EQ(test_answer((uint8_t *)&reply, sizeof(reply)) > 0, 1);

	test_status_buffer = NULL;
}

int main(void)
{
	int sockets[2];

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/* The type of a client connection - see esdm_rpcs_start() */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) < 0) {
		printf("cannot create the connection: %s\n", strerror(errno));
		return 1;
	}
	server_fd = sockets[0];
	client_fd = sockets[1];

	/* Non-blocking like an accepted connection */
	if (set_fd_nonblocking(server_fd) || set_fd_nonblocking(client_fd)) {
		printf("cannot set the connection non-blocking\n");
		return 1;
	}

	if (esdm_init()) {
		printf("cannot initialize the ESDM\n");
		return 1;
	}

	test_selftest_refused();
	test_unpackable_answer();
	test_unread_answers();

	esdm_fini();

	close(server_fd);
	close(client_fd);

	return common_test_result("rpc_server");
}
