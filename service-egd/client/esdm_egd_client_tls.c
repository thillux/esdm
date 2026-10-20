/*
 * The TLS module of libesdm_egd_client - see esdm_egd_client_tls.h
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

#include "esdm_egd_client_tls.h"
#include "visibility.h"

static const struct esdm_egd_tls_module esdm_egd_tls_module_ops = {
	.version = ESDM_EGD_TLS_MODULE_VERSION,
	.ctx_alloc = esdm_tls_ctx_alloc,
	.ctx_get = esdm_tls_ctx_get,
	.ctx_put = esdm_tls_ctx_put,
	.ctx_crl_report = esdm_tls_ctx_crl_report,
	.alloc = esdm_tls_alloc,
	.free = esdm_tls_free,
	.handshake = esdm_tls_handshake,
	.send = esdm_tls_send,
	.flush = esdm_tls_flush,
	.recv = esdm_tls_recv,
	.close_notify = esdm_tls_close_notify,
	.peer_subject = esdm_tls_peer_subject,
	.cipher = esdm_tls_cipher,
	.group = esdm_tls_group,
	.error = esdm_tls_error,
	.wait = esdm_tls_wait,
	.stamp = esdm_tls_stamp,
};

DSO_PUBLIC
const struct esdm_egd_tls_module *esdm_egd_tls_module(void)
{
	return &esdm_egd_tls_module_ops;
}
