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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esdm_es_ext_net_cli.h"
#include "esdm_logger.h"

#ifdef ESDM_ES_EXT_NET
#include "privileges.h"
#endif

void es_ext_net_cli_init(struct es_ext_net_cli *cli)
{
	memset(cli, 0, sizeof(*cli));
	esdm_es_ext_server_net_config_init(&cli->cfg);
	cli->username = "nobody";
}

void es_ext_net_cli_free(struct es_ext_net_cli *cli)
{
#ifdef ESDM_ES_EXT_NET
	esdm_net_tls_files_free(&cli->files);
#endif
	memset(cli, 0, sizeof(*cli));
}

#ifdef ESDM_ES_EXT_NET

/* A number of an option, from 0 to @max */
static int es_ext_net_cli_uint(const char *opt, const char *arg,
			       unsigned long max, unsigned int *val)
{
	return esdm_net_parse_uint(opt, arg, max, val) ? -1 : 1;
}

int es_ext_net_cli_option(struct es_ext_net_cli *cli, int opt,
			  const char *arg)
{
	struct esdm_es_ext_server_net_config *cfg = &cli->cfg;
	int ret;

	switch (opt) {
	case ES_EXT_NET_OPT_LISTEN:
		if (cli->listen_num >= ESDM_ES_EXT_NET_MAX_LISTEN) {
			fprintf(stderr,
				"--listen may be given %u times at most\n",
				ESDM_ES_EXT_NET_MAX_LISTEN);
			return -1;
		}
		cli->listen[cli->listen_num++] = arg;
		cli->option = true;
		return 1;
	case ES_EXT_NET_OPT_CERT:
	case ES_EXT_NET_OPT_KEY:
	case ES_EXT_NET_OPT_CA:
	case ES_EXT_NET_OPT_CRL:
	case ES_EXT_NET_OPT_CRL_CHECK_ALL:
	case ES_EXT_NET_OPT_CRL_ALLOW_EXPIRED: {
		static const char *const names[] = {
			"cert", "key", "ca", "crl", "crl_check_all",
			"crl_allow_expired"
		};

		cli->option = true;
		ret = esdm_net_tls_option(&cli->files,
					  names[opt - ES_EXT_NET_OPT_CERT],
					  arg);
		return ret == 1 ? 1 : -1;
	}
	case ES_EXT_NET_OPT_RELOAD_INTERVAL:
		cli->option = true;
		return es_ext_net_cli_uint("reload_interval", arg, 86400 * 365,
					   &cfg->reload_interval);
	case ES_EXT_NET_OPT_ALLOW:
		if (cli->allow_num >= ESDM_ES_EXT_NET_MAX_ALLOW) {
			fprintf(stderr,
				"--allow may be given %u times at most\n",
				ESDM_ES_EXT_NET_MAX_ALLOW);
			return -1;
		}
		{
			struct esdm_net_cidr cidr;

			if (esdm_net_cidr_parse(arg, &cidr)) {
				fprintf(stderr,
					"--allow takes a network such as 192.0.2.0/24 or 2001:db8::/32, not \"%s\"\n",
					arg);
				return -1;
			}
		}
		cli->allow[cli->allow_num++] = arg;
		cli->option = true;
		return 1;
	case ES_EXT_NET_OPT_MAX_CONNECTIONS:
		cli->option = true;
		return es_ext_net_cli_uint("max_connections", arg, 100000,
					   &cfg->max_connections);
	case ES_EXT_NET_OPT_MAX_HANDSHAKES:
		cli->option = true;
		return es_ext_net_cli_uint("max_handshakes", arg, 100000,
					   &cfg->max_handshakes);
	case ES_EXT_NET_OPT_MAX_HANDSHAKES_PER_SOURCE:
		cli->option = true;
		return es_ext_net_cli_uint("max_handshakes_per_source", arg,
					   100000,
					   &cfg->max_handshakes_per_source);
	case ES_EXT_NET_OPT_MAX_PER_CLIENT:
		cli->option = true;
		return es_ext_net_cli_uint("max_per_client", arg, 100000,
					   &cfg->max_per_client);
	case ES_EXT_NET_OPT_HANDSHAKE_TIMEOUT:
		cli->option = true;
		return es_ext_net_cli_uint("handshake_timeout", arg, 3600,
					   &cfg->handshake_timeout);
	case ES_EXT_NET_OPT_IDLE_TIMEOUT:
		cli->option = true;
		return es_ext_net_cli_uint("idle_timeout", arg, 86400 * 7,
					   &cfg->idle_timeout);
	case ES_EXT_NET_OPT_USERNAME:
		cli->username = arg;
		cli->option = true;
		return 1;
	case ES_EXT_NET_OPT_GROUPNAME:
		cli->groupname = arg;
		cli->option = true;
		return 1;
	default:
		return 0;
	}
}

bool es_ext_net_cli_wanted(struct es_ext_net_cli *cli)
{
	/* Sockets handed over are taken whenever they are there */
	cli->fds_num = esdm_net_listen_fds(cli->fds, ESDM_NET_MAX_LISTEN);

	return cli->listen_num || cli->fds_num;
}

int es_ext_net_cli_server(struct es_ext_net_cli *cli,
			  const struct esdm_es_ext_plugin *plugin,
			  struct esdm_es_ext_server **server)
{
	struct esdm_es_ext_server_net_config *cfg = &cli->cfg;
	unsigned int i;
	int ret;

	if (!cfg->max_connections || !cfg->max_handshakes ||
	    !cfg->max_handshakes_per_source || !cfg->max_per_client ||
	    !cfg->handshake_timeout) {
		fprintf(stderr,
			"The bounds of the connections and the handshake timeout must not be 0\n");
		return -1;
	}

	if (esdm_net_tls_files_resolve(&cli->files, NULL))
		return -1;

	cfg->listen = cli->listen_num ? cli->listen : NULL;
	cfg->listen_fds = cli->fds;
	cfg->listen_fds_num = (unsigned int)cli->fds_num;
	cfg->cert_file = cli->files.cert;
	cfg->key_file = cli->files.key;
	cfg->ca_file = cli->files.ca;
	for (i = 0; i < cli->files.crl_num; i++)
		cli->crl[i] = cli->files.crl[i];
	cli->crl[i] = NULL;
	cfg->crl_files = cli->files.crl_num ? cli->crl : NULL;
	cfg->crl_flags =
		(cli->files.crl_check_all ? ESDM_ES_EXT_NET_CRL_CHECK_ALL : 0) |
		(cli->files.crl_allow_expired ?
			 ESDM_ES_EXT_NET_CRL_ALLOW_EXPIRED :
			 0);
	cfg->allow = cli->allow_num ? cli->allow : NULL;

	ret = esdm_es_ext_server_alloc_net(plugin, cfg, server);
	if (ret) {
		fprintf(stderr, "Cannot serve on the network: %s\n",
			strerror(-ret));
		return -1;
	}

	return 0;
}

int es_ext_net_cli_drop_privileges(struct es_ext_net_cli *cli)
{
	if (getuid())
		return 0;

	if (drop_privileges_permanent(cli->username, cli->groupname)) {
		fprintf(stderr, "Cannot drop the privileges to %s\n",
			cli->username);
		return -1;
	}

	return 0;
}

void es_ext_net_cli_usage(FILE *out)
{
	fprintf(out,
		"\nOn the network - TCP, TLS 1.3 with certificates:\n"
		"\t   --listen <[HOST]:PORT>\tServe on HOST, any address without,\n"
		"\t\t\t\tPORT (relays connect to %u by default); may be\n"
		"\t\t\t\trepeated\n"
		"\t\t\t\t(default: the sockets of socket activation)\n"
		"\t   --cert <FILE>\tCertificate of the provider, PEM\n"
		"\t   --key <FILE>\t\tIts private key, PEM, PKCS#8\n"
		"\t   --ca <FILE>\t\tTrust anchors the client certificates must\n"
		"\t\t\t\tchain to, PEM\n"
		"\t   --crl <FILE>\t\tCRLs, PEM; may be repeated\n"
		"\t   --crl_check_all\tRequire CRLs of the CA certificates as well\n"
		"\t   --crl_allow_expired\tOnly warn of a CRL past its nextUpdate\n"
		"\t   --reload_interval <SEC>\tCheck the TLS files for a change\n"
		"\t\t\t\tthis often, 0 for never (default 60); SIGHUP\n"
		"\t\t\t\treloads them at once\n"
		"\t   --allow <CIDR>\tServe only clients of the network CIDR;\n"
		"\t\t\t\tmay be repeated (default: any)\n"
		"\t   --max_connections <N>\tConnections in all (default 64)\n"
		"\t   --max_handshakes <N>\tConnections in their handshake\n"
		"\t\t\t\t(default 16)\n"
		"\t   --max_handshakes_per_source <N>\tThe same per source\n"
		"\t\t\t\taddress, per /64 for IPv6 (default 4)\n"
		"\t   --max_per_client <N>\tConnections per client certificate\n"
		"\t\t\t\t(default 4)\n"
		"\t   --handshake_timeout <SEC>\tLength of the handshake (default 10)\n"
		"\t   --idle_timeout <SEC>\tSilence after which a connection is\n"
		"\t\t\t\tclosed, 0 for never (default 600)\n"
		"\t   --username <USER>\tUser to switch to when started as root\n"
		"\t\t\t\t(default: nobody)\n"
		"\t   --groupname <GROUP>\tGroup to switch to (default: none)\n"
		"\tA file without a slash in its name is a credential of the service,\n"
		"\ttaken from $CREDENTIALS_DIRECTORY (systemd LoadCredential=); without\n"
		"\t--cert, --key and --ca, the credentials cert, key and ca are used.\n",
		ESDM_ES_EXT_NET_PORT);
}

#else /* ESDM_ES_EXT_NET */

int es_ext_net_cli_option(struct es_ext_net_cli *cli, int opt,
			  const char *arg)
{
	(void)arg;

	if (opt < ES_EXT_NET_OPT_LISTEN || opt > ES_EXT_NET_OPT_GROUPNAME)
		return 0;
	cli->option = true;
	return 1;
}

bool es_ext_net_cli_wanted(struct es_ext_net_cli *cli)
{
	return cli->option;
}

int es_ext_net_cli_server(struct es_ext_net_cli *cli,
			  const struct esdm_es_ext_plugin *plugin,
			  struct esdm_es_ext_server **server)
{
	(void)cli;
	(void)plugin;
	*server = NULL;
	fprintf(stderr,
		"This ESDM is built without serving external entropy sources on the network (meson option es-ext-net)\n");
	return -1;
}

int es_ext_net_cli_drop_privileges(struct es_ext_net_cli *cli)
{
	(void)cli;
	return 0;
}

void es_ext_net_cli_usage(FILE *out)
{
	(void)out;
}

#endif /* ESDM_ES_EXT_NET */

void es_ext_net_cli_verbosity(bool net, unsigned int count)
{
	unsigned int level = net ? LOGGER_WARN :
				   esdm_logger_get_verbosity(LOGGER_C_ANY);

	level += count;
	if (level >= LOGGER_MAX_LEVEL)
		level = LOGGER_MAX_LEVEL - 1;
	esdm_logger_set_verbosity((enum esdm_logger_verbosity)level);
}
