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
 * of its own this way. With --listen, or sockets of socket activation, it
 * serves the plugin on the network instead, to the esdm-es-ext-relay of the
 * host of an ESDM - see esdm_es_ext_net_cli.h.
 */

#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_net_cli.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "systemd_support.h"

/* Set by the build, see es-ext/meson.build */
#ifndef ESDM_ES_EXT_SERVE_VERSION
#define ESDM_ES_EXT_SERVE_VERSION "unknown"
#endif

static struct esdm_es_ext_server *serve_server;

/* Serving on the network, where SIGHUP takes the TLS files up again */
static bool serve_net;

/*
 * The signals ending the provider. They are blocked in every thread from the
 * start - those a plugin may start in its init included - and taken by a
 * thread of its own with sigwait(2) rather than by a handler: a handler is
 * run whenever the signal arrives only as long as nothing defers it. A thread
 * sanitizer does - until the thread enters a function it intercepts - and the
 * poll(2) of the server, built with _FORTIFY_SOURCE, is __poll_chk(), which it
 * does not intercept: the signal arrived while the server polled, the server
 * went on polling, the handler never ran, and the provider ignored SIGTERM.
 */
static sigset_t serve_signal_set;

static void *serve_signals(void *arg)
{
	int sig;

	(void)arg;
	while (!sigwait(&serve_signal_set, &sig)) {
		if (sig == SIGHUP && serve_net) {
			esdm_es_ext_server_reload(serve_server);
			continue;
		}
		esdm_es_ext_server_stop(serve_server);
		break;
	}
	return NULL;
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
		"\t   --entropy_rate <BITS>\tDeclare BITS of entropy per 256 bits of\n");
	fprintf(stderr,
		"\t\t\tdata, 0 to 256, as the rate of the source in place of the one\n");
	fprintf(stderr, "\t\t\tof the plugin\n");
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
	es_ext_net_cli_usage(stderr);
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
		{ "entropy_rate", required_argument, NULL, 'R' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		ES_EXT_NET_CLI_OPTIONS,
		{ NULL, 0, NULL, 0 }
	};
	struct esdm_es_ext_plugin_handle *handle = NULL;
	struct es_ext_net_cli net;
	bool unix_option = false;
	const struct esdm_es_ext_plugin *plugin;
	const char *plugin_path = NULL, *socket_path = NULL, *name = NULL;
	pthread_t signal_thread;
	uid_t client_uids[SERVE_MAX_CLIENT_UIDS];
	unsigned int client_uids_num = 0, i, verbose = 0;
	uint32_t rate = ESDM_ES_EXT_PROTO_RATE_NONE;
	mode_t mode = 0666;
	bool dtls = true;
	int c, ret;

	sigemptyset(&serve_signal_set);
	sigaddset(&serve_signal_set, SIGTERM);
	sigaddset(&serve_signal_set, SIGINT);
	sigaddset(&serve_signal_set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &serve_signal_set, NULL);

	es_ext_net_cli_init(&net);

	while ((c = getopt_long(argc, argv, "l:s:m:u:vh", opts, NULL)) != -1) {
		switch (c) {
		case 'l':
			plugin_path = optarg;
			break;
		case 's':
			socket_path = optarg;
			break;
		case 'm': {
			unix_option = true;
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

			unix_option = true;
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
			unix_option = true;
			dtls = false;
			break;
		case 'R': {
			unsigned long val;
			char *end;

			errno = 0;
			val = strtoul(optarg, &end, 10);
			if (errno || end == optarg || *end != '\0' ||
			    optarg[0] == '-' ||
			    val > ESDM_ES_EXT_ENTROPY_RATE_MAX) {
				fprintf(stderr,
					"--entropy_rate takes an entropy rate from 0 to %u, not \"%s\"\n",
					ESDM_ES_EXT_ENTROPY_RATE_MAX, optarg);
				return 1;
			}
			rate = (uint32_t)val;
			break;
		}
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
			verbose++;
			break;
		case 'V':
			printf("esdm-es-ext-serve %s\n",
			       ESDM_ES_EXT_SERVE_VERSION);
			return 0;
		case 'h':
			usage();
			return 0;
		default:
			ret = es_ext_net_cli_option(&net, c, optarg);
			if (ret > 0)
				break;
			if (!ret)
				usage();
			es_ext_net_cli_free(&net);
			return 1;
		}
	}

	serve_net = es_ext_net_cli_wanted(&net);
	es_ext_net_cli_verbosity(serve_net, verbose);
	if (optind != argc || !plugin_path || (!socket_path && !serve_net)) {
		fprintf(stderr,
			"--plugin is required, and --socket or --listen\n");
		usage();
		es_ext_net_cli_free(&net);
		return 1;
	}
	if (serve_net && (socket_path || unix_option)) {
		fprintf(stderr,
			"--socket, --mode, --client_uid and --no_dtls are for a Unix domain socket - not for --listen\n");
		es_ext_net_cli_free(&net);
		return 1;
	}
	if (!serve_net && net.option) {
		fprintf(stderr,
			"The options of the network take --listen, or sockets of socket activation\n");
		es_ext_net_cli_free(&net);
		return 1;
	}

	ret = esdm_es_ext_plugin_load(plugin_path, &handle, &plugin);
	if (ret) {
		fprintf(stderr, "Cannot use the plugin library %s: %s\n",
			plugin_path, strerror(-ret));
		es_ext_net_cli_free(&net);
		return 1;
	}

	if (serve_net) {
		/*
		 * The init of the plugin runs with the privileges the daemon
		 * was started with, as it does in the ESDM - the rest without
		 */
		if (es_ext_net_cli_server(&net, plugin, &serve_server)) {
			esdm_es_ext_plugin_unload(handle);
			es_ext_net_cli_free(&net);
			return 1;
		}
		if (es_ext_net_cli_drop_privileges(&net)) {
			esdm_es_ext_server_free(serve_server);
			esdm_es_ext_plugin_unload(handle);
			es_ext_net_cli_free(&net);
			return 1;
		}
		goto served;
	}

	ret = esdm_es_ext_server_alloc(plugin, socket_path, mode,
				       &serve_server);
	if (ret) {
		fprintf(stderr, "Cannot serve %s on %s: %s\n", plugin_path,
			socket_path, strerror(-ret));
		esdm_es_ext_plugin_unload(handle);
		es_ext_net_cli_free(&net);
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

served:
	/* Checked above already */
	if (name)
		(void)esdm_es_ext_server_set_name(serve_server, name);
	if (rate != ESDM_ES_EXT_PROTO_RATE_NONE)
		(void)esdm_es_ext_server_set_entropy_rate(serve_server, rate);

	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	ret = -pthread_create(&signal_thread, NULL, serve_signals, NULL);
	if (ret) {
		fprintf(stderr, "Cannot wait for signals: %s\n", strerror(-ret));
		esdm_es_ext_server_free(serve_server);
		esdm_es_ext_plugin_unload(handle);
		return 1;
	}

	if (!name)
		name = esdm_es_ext_name_or_null(plugin->name);
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "Serving external entropy source %s on %s\n",
		    name ? name : plugin_path,
		    serve_net ? "the network" : socket_path);

	/* The socket accepts connections: ready, where systemd asks */
	(void)systemd_notify_ready();

	ret = esdm_es_ext_server_run(serve_server);
	if (ret)
		fprintf(stderr, "Serving %s failed: %s\n",
			serve_net ? "the network" : socket_path,
			strerror(-ret));

	(void)systemd_notify_stopping();

	/* The signal thread ended with the signal, or waits for one still */
	pthread_kill(signal_thread, SIGTERM);
	pthread_join(signal_thread, NULL);

	esdm_es_ext_server_free(serve_server);
	esdm_es_ext_plugin_unload(handle);
	es_ext_net_cli_free(&net);

	return ret ? 1 : 0;
}
