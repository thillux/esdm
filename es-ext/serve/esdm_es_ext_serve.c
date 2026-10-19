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
 * esdm-es-ext-serve: serve an external entropy source plugin library on a Unix
 * domain socket the ESDM connects to - see esdm-es-ext-serve(8). The same
 * plugin that esdm-server --es_ext_lib loads into the daemon runs in a process
 * of its own this way.
 */

#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"

/* Set by the build, see es-ext/meson.build */
#ifndef ESDM_ES_EXT_SERVE_VERSION
#define ESDM_ES_EXT_SERVE_VERSION "unknown"
#endif

static struct esdm_es_ext_server *serve_server;

static void serve_stop(int sig)
{
	(void)sig;
	esdm_es_ext_server_stop(serve_server);
}

/* Clients to be served next to root */
#define SERVE_MAX_CLIENT_UIDS 8

/* A uid, or the uid of a user name; (uid_t)-1 if it is neither */
static uid_t serve_parse_uid(const char *arg)
{
	struct passwd *pw;
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (arg[0] != '\0' && arg[0] != '-' && *end == '\0' && !errno &&
	    val < (unsigned long)(uid_t)-1)
		return (uid_t)val;

	pw = getpwnam(arg);
	return pw ? pw->pw_uid : (uid_t)-1;
}

static void usage(void)
{
	fprintf(stderr, "\nESDM external entropy source provider\n\n");
	fprintf(stderr, "esdm-es-ext-serve %s\n\n", ESDM_ES_EXT_SERVE_VERSION);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"\t-l --plugin <PATH>\tPlugin library of the entropy source\n");
	fprintf(stderr,
		"\t-s --socket <PATH>\tUnix domain socket to serve it on\n");
	fprintf(stderr,
		"\t-m --mode <MODE>\tAccess mode of the socket, octal (default 0666)\n");
	fprintf(stderr,
		"\t-u --client_uid <USER>\tServe clients running as USER (uid or name)\n");
	fprintf(stderr,
		"\t\t\tnext to root; may be repeated (default: nobody)\n");
	fprintf(stderr, "\t   --no_dtls\tDo not offer DTLS to the clients\n");
	fprintf(stderr,
		"\t   --name <NAME>\tDeclare NAME as the name of the source in place\n");
	fprintf(stderr,
		"\t\t\tof the one of the plugin: 1 to %u bytes of UTF-8 without\n",
		ESDM_ES_EXT_NAME_MAX);
	fprintf(stderr, "\t\t\tcontrol characters\n");
	fprintf(stderr,
		"\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tThis help information\n");
	fprintf(stderr, "\t   --version\tPrint version\n");
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "plugin", required_argument, NULL, 'l' },
		{ "socket", required_argument, NULL, 's' },
		{ "mode", required_argument, NULL, 'm' },
		{ "client_uid", required_argument, NULL, 'u' },
		{ "no_dtls", no_argument, NULL, 'D' },
		{ "name", required_argument, NULL, 'N' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	struct esdm_es_ext_plugin_handle *handle = NULL;
	const struct esdm_es_ext_plugin *plugin;
	const char *plugin_path = NULL, *socket_path = NULL, *name = NULL;
	struct sigaction sa;
	uid_t client_uids[SERVE_MAX_CLIENT_UIDS];
	unsigned int client_uids_num = 0, i;
	mode_t mode = 0666;
	bool dtls = true;
	int c, ret;

	while ((c = getopt_long(argc, argv, "l:s:m:u:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			plugin_path = optarg;
			break;
		case 's':
			socket_path = optarg;
			break;
		case 'm': {
			unsigned long val;
			char *end;

			errno = 0;
			val = strtoul(optarg, &end, 8);
			if (errno || end == optarg || *end != '\0' ||
			    val > 0777) {
				fprintf(stderr,
					"--mode takes an octal access mode, not \"%s\"\n",
					optarg);
				return 1;
			}
			mode = (mode_t)val;
			break;
		}
		case 'u': {
			uid_t uid = serve_parse_uid(optarg);

			if (uid == (uid_t)-1) {
				fprintf(stderr,
					"--client_uid takes a uid or a user name, not \"%s\"\n",
					optarg);
				return 1;
			}
			if (client_uids_num >= SERVE_MAX_CLIENT_UIDS) {
				fprintf(stderr,
					"--client_uid may be given %u times at most\n",
					SERVE_MAX_CLIENT_UIDS);
				return 1;
			}
			client_uids[client_uids_num++] = uid;
			break;
		}
		case 'D':
			dtls = false;
			break;
		case 'N':
			if (!esdm_es_ext_name_valid(optarg, strlen(optarg))) {
				fprintf(stderr,
					"--name takes 1 to %u bytes of UTF-8 without control characters\n",
					ESDM_ES_EXT_NAME_MAX);
				return 1;
			}
			name = optarg;
			break;
		case 'v':
			esdm_logger_inc_verbosity();
			break;
		case 'V':
			printf("esdm-es-ext-serve %s\n",
			       ESDM_ES_EXT_SERVE_VERSION);
			return 0;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	if (optind != argc || !plugin_path || !socket_path) {
		fprintf(stderr, "--plugin and --socket are required\n");
		usage();
		return 1;
	}

	ret = esdm_es_ext_plugin_load(plugin_path, &handle, &plugin);
	if (ret) {
		fprintf(stderr, "Cannot use the plugin library %s: %s\n",
			plugin_path, strerror(-ret));
		return 1;
	}

	ret = esdm_es_ext_server_alloc(plugin, socket_path, mode,
				       &serve_server);
	if (ret) {
		fprintf(stderr, "Cannot serve %s on %s: %s\n", plugin_path,
			socket_path, strerror(-ret));
		esdm_es_ext_plugin_unload(handle);
		return 1;
	}

	/*
	 * The ESDM runs as nobody unless told otherwise - see esdm-server
	 * --username. Without a user of that name, root alone is served.
	 */
	if (!client_uids_num) {
		uid_t nobody = serve_parse_uid("nobody");

		if (nobody != (uid_t)-1)
			client_uids[client_uids_num++] = nobody;
		else
			client_uids[client_uids_num++] = 0;
	}
	for (i = 0; i < client_uids_num; i++) {
		ret = esdm_es_ext_server_allow_uid(serve_server,
						   client_uids[i]);
		if (ret) {
			fprintf(stderr, "Cannot serve uid %u: %s\n",
				(unsigned int)client_uids[i], strerror(-ret));
			esdm_es_ext_server_free(serve_server);
			esdm_es_ext_plugin_unload(handle);
			return 1;
		}
	}

	/* Offered by a library that has it, unless told otherwise */
	if (!dtls)
		esdm_es_ext_server_set_dtls(serve_server, 0);

	/* Checked above already */
	if (name)
		(void)esdm_es_ext_server_set_name(serve_server, name);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = serve_stop;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	if (!name)
		name = esdm_es_ext_name_or_null(plugin->name);
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "Serving external entropy source %s on %s\n",
		    name ? name : plugin_path, socket_path);

	ret = esdm_es_ext_server_run(serve_server);
	if (ret)
		fprintf(stderr, "Serving %s failed: %s\n", socket_path,
			strerror(-ret));

	esdm_es_ext_server_free(serve_server);
	esdm_es_ext_plugin_unload(handle);

	return ret ? 1 : 0;
}
