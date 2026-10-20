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
 * The TLS module of libesdm_egd_client - not API.
 *
 * libesdm_egd_client serves sandboxed processes, OpenSSH's pre-authentication
 * child among them, whose seccomp filter kills for any syscall it does not
 * expect - those a TLS stack makes when it is loaded and unloaded included:
 * Botan unlocks its locked memory pool when the process exits, which the
 * filter of OpenSSH answers with SIGSYS. So the library does not depend on a
 * TLS stack. The TLS layer of esdm_tls.h, and with it the TLS stack, is a
 * module of its own - esdm-egd-tls.so in the ESDM directory of the libraries
 * -, which the library loads with dlopen(3) when the first client in TLS mode
 * is allocated, and never otherwise. The daemons link the TLS layer directly.
 *
 * The module hands out the functions of esdm_tls.h the client uses, for the
 * library built along with it only: the version has to match exactly.
 */

#ifndef ESDM_EGD_CLIENT_TLS_H
#define ESDM_EGD_CLIENT_TLS_H

#include "esdm_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESDM_EGD_TLS_MODULE_VERSION 3

/* What the library looks up in the module */
#define ESDM_EGD_TLS_MODULE_SYMBOL "esdm_egd_tls_module"

/* Environment variable naming another module, for the test suite */
#define ESDM_EGD_TLS_MODULE_ENV "ESDM_EGD_TLS_MODULE"

/* The functions of esdm_tls.h, each named as there without esdm_tls_ */
struct esdm_egd_tls_module {
	unsigned int version;
	int (*ctx_alloc)(bool server, const struct esdm_tls_config *cfg,
			 struct esdm_tls_ctx **ctx);
	void (*ctx_get)(struct esdm_tls_ctx *ctx);
	void (*ctx_put)(struct esdm_tls_ctx *ctx);
	void (*ctx_crl_report)(struct esdm_tls_ctx *ctx, bool all);
	int (*alloc)(struct esdm_tls_ctx *ctx, int fd, const char *server_name,
		     struct esdm_tls **tls);
	void (*free)(struct esdm_tls *tls);
	int (*handshake)(struct esdm_tls *tls);
	ssize_t (*send)(struct esdm_tls *tls, const void *buf, size_t len);
	int (*flush)(struct esdm_tls *tls);
	ssize_t (*recv)(struct esdm_tls *tls, void *buf, size_t len);
	void (*close_notify)(struct esdm_tls *tls);
	const char *(*peer_subject)(struct esdm_tls *tls);
	const char *(*cipher)(struct esdm_tls *tls);
	const char *(*group)(struct esdm_tls *tls);
	const char *(*error)(struct esdm_tls *tls);
	bool (*confirmed)(struct esdm_tls *tls);
	int (*wait)(struct esdm_tls *tls, int timeout_ms);
	void (*stamp)(const struct esdm_tls_config *cfg,
		      uint8_t stamp[ESDM_TLS_STAMP_LEN]);
};

/* The entry point of the module */
const struct esdm_egd_tls_module *esdm_egd_tls_module(void);

struct esdm_egd_client;

/**
 * @brief Check the TLS connection of a client as a server checks its clients
 *
 * For the esdm-egd-net-relay, which links the client with the TLS layer - the
 * library and its module have no such function: the connection is closed if
 * the server's chain is revoked by a CRL of @ctx - NULL for none -, or if its
 * certificate expired. The next request makes a new connection, whose
 * handshake the server has to pass with the files as they are then.
 *
 * A client in a request is not waited for: its connection is checked before
 * its next request, against @ctx.
 *
 * @return 1 if the connection was closed, 0 if it is in order or there is
 *	   none, -EBUSY if the check waits for the next request
 */
int esdm_egd_client_net_check(struct esdm_egd_client *client,
			      struct esdm_tls_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_EGD_CLIENT_TLS_H */
