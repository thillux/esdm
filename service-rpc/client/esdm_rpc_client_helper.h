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

#ifndef ESDM_RPC_CLIENT_HELPER_H
#define ESDM_RPC_CLIENT_HELPER_H

#include <errno.h>
#include <stdint.h>
#include <sys/types.h>

#include "esdm_rpc_service.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The 64-bit return code of a RandValResponse as ssize_t. The server never
 * sends one of a magnitude beyond ESDM_RPC_MAX_DATA - neither an errno, nor its
 * negated maximum request size, nor a byte count. A larger one is refused
 * rather than cut to 32 bits, which may turn an error into a byte count.
 */
static inline ssize_t esdm_rpcc_randval_ret(int64_t ret)
{
	if (ret < -(int64_t)ESDM_RPC_MAX_DATA ||
	    ret > (int64_t)ESDM_RPC_MAX_DATA)
		return -EPROTO;
	return (ssize_t)ret;
}

#define esdm_rpcc_error_check(response, buffer)                                \
	if (!response) {                                                       \
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC, "missing data\n");     \
		buffer->ret = -EFAULT;                                         \
		return;                                                        \
	} else if (IS_ERR(response)) {                                         \
		esdm_logger(LOGGER_DEBUG, LOGGER_C_RPC,                        \
			    "missing data - connection interrupted\n");        \
		buffer->ret = (int)PTR_ERR(response);                          \
		return;                                                        \
	}

#ifdef __cplusplus
}
#endif

#endif /* ESDM_RPC_CLIENT_HELPER_H */
