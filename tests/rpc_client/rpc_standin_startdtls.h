/*
 * STARTDTLS for the stand-in servers of the tests
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

#ifndef RPC_STANDIN_STARTDTLS_H
#define RPC_STANDIN_STARTDTLS_H

#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "esdm_rpc_protocol.h"

/*
 * A client built with DTLS asks for it first on every new connection - see
 * ESDM_RPC_PROTO_STARTDTLS. A stand-in server of a test that counts or
 * delays the requests it serves refuses it as a server without DTLS does,
 * answering the probe the client sends behind it as well: neither is a
 * request of the test.
 *
 * @param [in] fd The connection, blocking, the request @cs was read from
 * @param [in] cs The header of the request, as received
 *
 * @return true if @cs was the STARTDTLS request, which is answered then
 */
static inline bool
test_standin_startdtls(int fd, const struct esdm_rpc_proto_cs_header *cs)
{
	struct esdm_rpc_proto_sc_header sc = {
		.status_code = PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED,
		.method_index = cs->method_index,
		.message_length = 0,
		.request_id = cs->request_id,
	};
	struct esdm_rpc_proto_cs_header probe;

	if (cs->method_index != ESDM_RPC_PROTO_STARTDTLS)
		return false;

	if (send(fd, &sc, sizeof(sc), MSG_NOSIGNAL) != (ssize_t)sizeof(sc))
		return true;

	/* The probe is right behind it: ret 0 of an empty answer will do */
	if (recv(fd, &probe, sizeof(probe), 0) < (ssize_t)sizeof(probe))
		return true;

	sc.status_code = PROTOBUF_C_RPC_STATUS_CODE_SUCCESS;
	sc.method_index = probe.method_index;
	sc.request_id = probe.request_id;
	(void)send(fd, &sc, sizeof(sc), MSG_NOSIGNAL);

	return true;
}

#endif /* RPC_STANDIN_STARTDTLS_H */
