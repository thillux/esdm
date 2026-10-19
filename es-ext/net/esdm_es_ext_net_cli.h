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
 * The network mode on the command line of the daemons serving a provider
 * with libesdm_es_ext - esdm-es-ext-serve and esdm-es-pkcs11: the options of
 * esdm_es_ext_server_alloc_net(), named as those of the esdm-egd-net-server
 * where they mean the same, the sockets of socket activation, and the drop of
 * the privileges. Compiled into each of them - no API of the library: a
 * provider of its own fills struct esdm_es_ext_server_net_config itself.
 */

#ifndef ESDM_ES_EXT_NET_CLI_H
#define ESDM_ES_EXT_NET_CLI_H

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>

#include "config.h"
#include "esdm_es_ext.h"

#ifdef ESDM_ES_EXT_NET
#include "esdm_net.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* The option codes, out of the way of those of a daemon */
enum {
	ES_EXT_NET_OPT_LISTEN = 0x1000,
	ES_EXT_NET_OPT_CERT,
	ES_EXT_NET_OPT_KEY,
	ES_EXT_NET_OPT_CA,
	ES_EXT_NET_OPT_CRL,
	ES_EXT_NET_OPT_CRL_CHECK_ALL,
	ES_EXT_NET_OPT_CRL_ALLOW_EXPIRED,
	ES_EXT_NET_OPT_RELOAD_INTERVAL,
	ES_EXT_NET_OPT_ALLOW,
	ES_EXT_NET_OPT_MAX_CONNECTIONS,
	ES_EXT_NET_OPT_MAX_HANDSHAKES,
	ES_EXT_NET_OPT_MAX_HANDSHAKES_PER_SOURCE,
	ES_EXT_NET_OPT_MAX_PER_CLIENT,
	ES_EXT_NET_OPT_HANDSHAKE_TIMEOUT,
	ES_EXT_NET_OPT_IDLE_TIMEOUT,
	ES_EXT_NET_OPT_USERNAME,
	ES_EXT_NET_OPT_GROUPNAME,
};

/* The entries of the options, for the struct option array of a daemon */
#define ES_EXT_NET_CLI_OPTIONS                                                 \
	{ "listen", required_argument, NULL, ES_EXT_NET_OPT_LISTEN },          \
		{ "cert", required_argument, NULL, ES_EXT_NET_OPT_CERT },      \
		{ "key", required_argument, NULL, ES_EXT_NET_OPT_KEY },        \
		{ "ca", required_argument, NULL, ES_EXT_NET_OPT_CA },          \
		{ "crl", required_argument, NULL, ES_EXT_NET_OPT_CRL },        \
		{ "crl_check_all", no_argument, NULL,                          \
		  ES_EXT_NET_OPT_CRL_CHECK_ALL },                              \
		{ "crl_allow_expired", no_argument, NULL,                      \
		  ES_EXT_NET_OPT_CRL_ALLOW_EXPIRED },                          \
		{ "reload_interval", required_argument, NULL,                  \
		  ES_EXT_NET_OPT_RELOAD_INTERVAL },                            \
		{ "allow", required_argument, NULL, ES_EXT_NET_OPT_ALLOW },    \
		{ "max_connections", required_argument, NULL,                  \
		  ES_EXT_NET_OPT_MAX_CONNECTIONS },                            \
		{ "max_handshakes", required_argument, NULL,                   \
		  ES_EXT_NET_OPT_MAX_HANDSHAKES },                             \
		{ "max_handshakes_per_source", required_argument, NULL,        \
		  ES_EXT_NET_OPT_MAX_HANDSHAKES_PER_SOURCE },                  \
		{ "max_per_client", required_argument, NULL,                   \
		  ES_EXT_NET_OPT_MAX_PER_CLIENT },                             \
		{ "handshake_timeout", required_argument, NULL,                \
		  ES_EXT_NET_OPT_HANDSHAKE_TIMEOUT },                          \
		{ "idle_timeout", required_argument, NULL,                     \
		  ES_EXT_NET_OPT_IDLE_TIMEOUT },                               \
		{ "username", required_argument, NULL,                         \
		  ES_EXT_NET_OPT_USERNAME },                                   \
	{                                                                      \
		"groupname", required_argument, NULL, ES_EXT_NET_OPT_GROUPNAME \
	}

/* What the options gathered */
struct es_ext_net_cli {
	struct esdm_es_ext_server_net_config cfg;
	const char *listen[ESDM_ES_EXT_NET_MAX_LISTEN + 1];
	unsigned int listen_num;
	const char *allow[ESDM_ES_EXT_NET_MAX_ALLOW + 1];
	unsigned int allow_num;
	const char *crl[ESDM_ES_EXT_NET_MAX_CRL + 1];
#ifdef ESDM_ES_EXT_NET
	struct esdm_net_tls_files files;
	int fds[ESDM_NET_MAX_LISTEN];
#endif
	int fds_num;
	const char *username;
	const char *groupname;
	/* A network option was given, or one of the TLS files */
	bool option;
};

void es_ext_net_cli_init(struct es_ext_net_cli *cli);
void es_ext_net_cli_free(struct es_ext_net_cli *cli);

/*
 * Take up the option @opt with @arg.
 *
 * @return 1 if it is one of the network mode and was taken, 0 if it is none,
 *	   -1 after telling on stderr what is wrong
 */
int es_ext_net_cli_option(struct es_ext_net_cli *cli, int opt,
			  const char *arg);

/* The usage of the options */
void es_ext_net_cli_usage(FILE *out);

/*
 * Does the daemon serve on the network? It does with --listen, and when it
 * was handed listening sockets by socket activation - which are taken over
 * here.
 */
bool es_ext_net_cli_wanted(struct es_ext_net_cli *cli);

/*
 * Set the verbosity of the daemon once its mode is known: @count times -v
 * above the default of the mode. On the network, warnings and errors are
 * logged without -v, as by the other daemons on the network - a rotation that
 * does not load, a client beyond a bound -; on a Unix domain socket, the
 * default of the logger stays as it was.
 */
void es_ext_net_cli_verbosity(bool net, unsigned int count);

/*
 * Serve @plugin on the network: the files resolved - a name without a slash a
 * credential of the service, the credentials "cert", "key" and "ca" without
 * the options -, the server allocated, see esdm_es_ext_server_alloc_net().
 *
 * @return 0, or -1 after telling on stderr what is wrong
 */
int es_ext_net_cli_server(struct es_ext_net_cli *cli,
			  const struct esdm_es_ext_plugin *plugin,
			  struct esdm_es_ext_server **server);

/*
 * Started as root, become the user of --username (default nobody) for good -
 * once the server holds its sockets and files and its plugin is set up, as
 * the esdm-egd-net-server does.
 *
 * @return 0, or -1 after telling on stderr
 */
int es_ext_net_cli_drop_privileges(struct es_ext_net_cli *cli);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_ES_EXT_NET_CLI_H */
