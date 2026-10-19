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
#include <stdio.h>

#include "config.h"
#include "egd_net_common.h"
#include "esdm_logger.h"

int egd_net_tls_files_resolve(struct esdm_net_tls_files *files, bool plain,
			      bool tls_option_given)
{
	if (plain) {
		if (tls_option_given) {
			fprintf(stderr,
				"--plain cannot be combined with TLS options\n");
			return -EINVAL;
		}
		return 0;
	}

#ifndef ESDM_EGD_NET_TLS
	(void)files;
	fprintf(stderr,
		"This ESDM is built without TLS - the crypto backend has no TLS stack (meson option egd-net-tls).\n"
		"Only --plain is available, on networks protected underneath.\n");
	return -EINVAL;
#else
	return esdm_net_tls_files_resolve(
		files, "--plain on a network protected underneath");
#endif
}

void egd_net_plain_warning(const char *daemon)
{
	esdm_logger(
		LOGGER_WARN, LOGGER_C_ANY,
		"%s: plain TCP - the traffic is neither encrypted nor authenticated. The network has to provide both, by IPsec or WireGuard, say: the random numbers can be read and altered by anybody on the path otherwise.\n",
		daemon);
}
