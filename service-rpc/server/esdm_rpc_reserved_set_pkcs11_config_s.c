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

#include <errno.h>

#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"

/*
 * The slot of the call that configured the PKCS#11 entropy source, which
 * esdm-es-pkcs11(8) serves now - see priv_access.proto. Kept so that the calls
 * after it keep their index on the wire.
 *
 * A client that still knows the call sends the token label and the PIN in
 * fields this request does not have, which protobuf-c keeps as unknown fields
 * of the decoded request - in the scratch buffer of the server, which is wiped
 * once the request is served.
 */
void esdm_rpc_reserved_set_pkcs11_config(PrivAccess_Service *service,
					 const EmptyRequest *request,
					 RetResponse_Closure closure,
					 void *closure_data)
{
	RetResponse response = RET_RESPONSE__INIT;

	(void)service;
	(void)request;

	response.ret = -EOPNOTSUPP;
	closure(&response, closure_data);
}
