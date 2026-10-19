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
 * What the esdm-egd-net-server and the esdm-egd-net-relay share beyond the
 * network helpers of esdm_net.h: their plain TCP mode.
 */

#ifndef EGD_NET_COMMON_H
#define EGD_NET_COMMON_H

#include <stdbool.h>

#include "esdm_net.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Resolve and check the TLS options of a daemon
 *
 * Plain TCP is never a default: with @plain, every TLS option is an error;
 * without it, the certificate, its key and the trust anchors are required -
 * see esdm_net_tls_files_resolve(). A build without a TLS stack refuses all
 * of it.
 *
 * @return 0, or -EINVAL after telling what is wrong on stderr
 */
int egd_net_tls_files_resolve(struct esdm_net_tls_files *files, bool plain,
			      bool tls_option_given);

/**
 * @brief Log that the traffic is in the clear - at the start of plain mode
 */
void egd_net_plain_warning(const char *daemon);

#ifdef __cplusplus
}
#endif

#endif /* EGD_NET_COMMON_H */
