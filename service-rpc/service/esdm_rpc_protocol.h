/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_RPC_PROTOCOL_H
#define ESDM_RPC_PROTOCOL_H

#include <protobuf-c/protobuf-c.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default RPC Protocol implementation that is consistent with protobuf-c-rpc
 *	client issues request with header:
 *      	method_index	32-bit little-endian
 *		message_length	32-bit little-endian
 *		request_id	32-bit any-endian
 *	server responds with header:
 *		status_code	32-bit little-endian
 *		method_index	32-bit little-endian
 *		message_length	32-bit little-endian
 *		request_id	32-bit any-endian
 */
struct esdm_rpc_proto_cs_header {
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));

struct esdm_rpc_proto_sc_header {
	uint32_t status_code;
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));

/* Data buffer client to server */
struct esdm_rpc_proto_cs {
	struct esdm_rpc_proto_cs_header header;
	uint8_t data[];
} __attribute__((packed));

/* Data buffer client to server */
struct esdm_rpc_proto_sc {
	struct esdm_rpc_proto_sc_header header;
	uint8_t data[];
} __attribute__((packed));

/* Use same error codes as protobuf-c-rpc */
typedef enum {
	PROTOBUF_C_RPC_STATUS_CODE_SUCCESS,
	PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED,
	PROTOBUF_C_RPC_STATUS_CODE_TOO_MANY_PENDING
} ProtobufC_RPC_Status_Code;

/*
 * STARTDTLS: switching a connection to DTLS, opportunistically - see
 * common/esdm_dtls.h on the DTLS itself.
 *
 * Request: a client built with DTLS sends, as the first message of a new
 * connection and in the clear, a request header alone: method_index
 * ESDM_RPC_PROTO_STARTDTLS - the bytes "DTLS" on the wire, far outside of the
 * methods of either service -, message_length 0, and a request_id the server
 * echoes.
 *
 * Answer, in the clear, with method_index and request_id echoed:
 *	status_code SUCCESS, message_length 4, the message the 4 bytes "DTLS" -
 *	    the server switches to DTLS. A server answering each request with
 *	    its header echoed, as test stand-ins do, cannot agree by accident.
 *	status_code SERVICE_FAILED, message_length 0 - it does not: no DTLS in
 *	    this build, switched off, or none it can set up. So does any other
 *	    answer, and the connection goes on in the clear.
 *
 * The probe: right after the STARTDTLS request, without waiting for its
 * answer, the client sends a request that changes nothing and costs nothing,
 * with an empty message - ESDM_RPC_PROTO_STARTDTLS_PROBE on the unprivileged
 * interface, which returns the pool size, and
 * ESDM_RPC_PROTO_STARTDTLS_PROBE_PRIV on the privileged one, which refuses to
 * add entropy without data. The server answers it in the clear as any other
 * request, after the answer to STARTDTLS.
 *
 * The switch takes place after the answer to the probe. The handshake follows,
 * the client being the DTLS client, and from then on every message of either
 * side is a sequence of DTLS records - one record per SOCK_SEQPACKET message -
 * carrying the request or answer as above. STARTDTLS is valid only while a
 * connection is in the clear, and any other request of it a protocol violation
 * that closes the connection.
 *
 * Compatibility: a client not knowing STARTDTLS never sends it, and is served
 * in the clear. A server not knowing it - ESDM 1.2.3 and before - takes the
 * method index as invalid and closes the connection without an answer; the
 * client then goes on in the clear on a new connection. Mostly, however, it
 * keeps the connection open and leaves the request unanswered, until it closes
 * the connection as idle: its workers decide on closing by an errno value left
 * over from earlier calls, which is EAGAIN in a worker once a call failed so -
 * in a worker of the unprivileged interface, an accept() lost to another
 * worker. This is what the probe is for: the old server answers it, and its
 * answer coming first tells the client that the STARTDTLS request went
 * unanswered - the connection goes on in the clear, in step and without
 * waiting for anything. A server answering neither is given up on after
 * ESDM_RPCC_DTLS_TIMEOUT_MS of the client, which then goes on in the clear on
 * a new connection.
 */
#define ESDM_RPC_PROTO_STARTDTLS 0x534c5444

/* Names of the probe methods of the two interfaces, see above */
#define ESDM_RPC_PROTO_STARTDTLS_PROBE "RpcGetPoolsize"
#define ESDM_RPC_PROTO_STARTDTLS_PROBE_PRIV "RpcRndAddEntropy"

int set_fd_nonblocking(int fd);

int esdm_rpc_proto_get_descriptor(const ProtobufCService *service,
				  const struct esdm_rpc_proto_cs *received_data,
				  const ProtobufCMessageDescriptor **desc);

/* Helpers used for protobuf-c allocator */
void *esdm_rpc_alloc(void *allocator_data, size_t size);
void esdm_rpc_free(void *allocator_data, void *data);

/*
 * Decode an int64 "ret" (field 1) + bytes "randval" (field 2) response in
 * place. On success *payload points into data (no copy/allocation).
 */
int esdm_rpc_decode_bytes_response(const uint8_t *data, size_t data_len,
				   int64_t *ret_val, const uint8_t **payload,
				   size_t *payload_len);

/*
 * Encode an int64 "ret" (field 1) + bytes "randval" (field 2) response into
 * dst. On success *out_len holds the number of bytes written.
 */
int esdm_rpc_encode_bytes_response(uint8_t *dst, size_t dst_len,
				   int64_t ret_val, const uint8_t *payload,
				   size_t payload_len, size_t *out_len);

/*
 * Does this message descriptor qualify for the hand-rolled bytes-response
 * encode/decode fast paths (exactly { int64 ret = 1; bytes randval = 2; })?
 */
bool esdm_rpc_is_fast_bytes_response(
	const ProtobufCMessageDescriptor *message_desc);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_PROTOCOL_H */
