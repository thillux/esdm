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
 * A provider program: its command line, and the serving of its source by the
 * provider server of this library on a Unix domain socket the ESDM connects
 * to - or, with --listen or sockets of socket activation, on the network, to
 * the esdm-es-ext-relay of the host of an ESDM, see esdm_es_ext_net_cli.h.
 * What esdm_es_ext_provider_main() runs, and esdm-es-pkcs11 with options of
 * its own - see esdm_es_ext_provider.h and libesdm_es_ext(3).
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
#include "esdm_es_ext_provider.h"
#include "esdm_logger.h"
#include "systemd_support.h"
#include "visibility.h"

/* The server of the process: one provider program serves one source */
static struct esdm_es_ext_server *provider_server;

/* Serving on the network, where SIGHUP takes the TLS files up again */
static bool provider_net;

/*
 * The signals ending the provider. They are blocked in every thread from the
 * start - those the init of a source may start included - and taken by a
 * thread of its own with sigwait(2) rather than by a handler: a handler is
 * run whenever the signal arrives only as long as nothing defers it. A thread
 * sanitizer does - until the thread enters a function it intercepts - and the
 * poll(2) of the server, built with _FORTIFY_SOURCE, is __poll_chk(), which it
 * does not intercept: the signal arrived while the server polled, the server
 * went on polling, the handler never ran, and the provider ignored SIGTERM.
 */
static sigset_t provider_signal_set;

static void *provider_signals(void *arg)
{
	int sig;

	(void)arg;
	while (!sigwait(&provider_signal_set, &sig)) {
		if (sig == SIGHUP && provider_net) {
			esdm_es_ext_server_reload(provider_server);
			continue;
		}
		esdm_es_ext_server_stop(provider_server);
		break;
	}
	return NULL;
}

/* Clients to be served next to root */
#define PROVIDER_MAX_CLIENT_UIDS 8

/* The codes of the common options without a short one */
enum {
	PROVIDER_OPT_NO_DTLS = 0x2000,
	PROVIDER_OPT_NAME,
	PROVIDER_OPT_ENTROPY_RATE,
	PROVIDER_OPT_VERSION,
};

/* The short options next to those of the program */
#define PROVIDER_SHORT_OPTIONS "s:m:u:vh"

static const struct option provider_options[] = {
	{ "socket", required_argument, NULL, 's' },
	{ "mode", required_argument, NULL, 'm' },
	{ "client_uid", required_argument, NULL, 'u' },
	{ "no_dtls", no_argument, NULL, PROVIDER_OPT_NO_DTLS },
	{ "name", required_argument, NULL, PROVIDER_OPT_NAME },
	{ "entropy_rate", required_argument, NULL, PROVIDER_OPT_ENTROPY_RATE },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, PROVIDER_OPT_VERSION },
	ES_EXT_NET_CLI_OPTIONS,
};

#define PROVIDER_OPTIONS_NUM                                                   \
	(sizeof(provider_options) / sizeof(provider_options[0]))

/* A uid, or the uid of a user name; (uid_t)-1 if it is neither */
static uid_t provider_parse_uid(const char *arg)
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

/* The name of the program: its own, or the one it was started under */
static const char *provider_name(const struct esdm_es_ext_provider_cli *cli,
				 int argc, char *argv[])
{
	const char *slash;

	if (cli->name)
		return cli->name;
	if (argc < 1 || !argv[0] || !argv[0][0])
		return "esdm-es-ext-provider";
	slash = strrchr(argv[0], '/');
	return slash && slash[1] ? slash + 1 : argv[0];
}

static void provider_usage(const struct esdm_es_ext_provider_cli *cli,
			   const char *name)
{
	fprintf(stderr, "\n%s\n\n",
		cli->title ? cli->title :
			     "ESDM external entropy source provider");
	if (cli->version)
		fprintf(stderr, "%s %s\n\n", name, cli->version);
	else
		fprintf(stderr, "%s (libesdm_es_ext %s)\n\n", name, VERSION);
	fprintf(stderr, "Usage:\n");
	if (cli->usage)
		cli->usage(stderr);
	if (cli->socket_path) {
		fprintf(stderr,
			"\t-s --socket <PATH>\tUnix domain socket to serve on (default:\n");
		fprintf(stderr, "\t\t\t%s)\n", cli->socket_path);
	} else {
		fprintf(stderr,
			"\t-s --socket <PATH>\tUnix domain socket to serve on\n");
	}
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
	fprintf(stderr, "\t\t\tit declares itself\n");
	fprintf(stderr,
		"\t   --name <NAME>\tDeclare NAME as the name of the source in place\n");
	fprintf(stderr,
		"\t\t\tof its own: 1 to %u bytes of UTF-8 without control\n",
		ESDM_ES_EXT_NAME_MAX);
	fprintf(stderr, "\t\t\tcharacters\n");
	fprintf(stderr,
		"\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tThis help information\n");
	fprintf(stderr, "\t   --version\tPrint version\n");
	es_ext_net_cli_usage(stderr);
}

/*
 * Tell what is wrong with the command line of a program with a secret,
 * getopt_long() having returned @c for it - without repeating what was given:
 * a secret given there by mistake would go to the journal with it, with every
 * start of the daemon. getopt_long() itself is told not to print anything, as
 * it repeats an option it does not know, or one too short to tell apart, with
 * the argument attached to it - "--pin=1234".
 */
static void provider_option_error(const struct esdm_es_ext_provider_cli *cli,
				  int c, const struct option *opts)
{
	const struct option *opt;

	/* An option the program knows, but without its argument */
	if (c == ':') {
		for (opt = opts; opt->name; opt++) {
			if (opt->val == optopt) {
				fprintf(stderr, "--%s needs an argument\n",
					opt->name);
				return;
			}
		}
	}

	fprintf(stderr,
		"Unknown option, one too short to tell apart, or one with an argument it does not take - not repeated here, as it may hold %s\n",
		cli->secret);
}

/* The common options, followed by those of the program; NULL without memory */
static struct option *
provider_options_merge(const struct esdm_es_ext_provider_cli *cli,
		       char **short_options)
{
	const struct option *opt;
	struct option *opts;
	size_t n = 0, len;

	for (opt = cli->options; opt && opt->name; opt++)
		n++;

	opts = calloc(PROVIDER_OPTIONS_NUM + n + 1, sizeof(*opts));
	if (!opts)
		return NULL;
	memcpy(opts, provider_options, sizeof(provider_options));
	if (n)
		memcpy(opts + PROVIDER_OPTIONS_NUM, cli->options,
		       n * sizeof(*opts));

	/* A colon in front: no message of getopt_long(), see above */
	len = 1 + strlen(PROVIDER_SHORT_OPTIONS) +
	      (cli->short_options ? strlen(cli->short_options) : 0) + 1;
	*short_options = malloc(len);
	if (!*short_options) {
		free(opts);
		return NULL;
	}
	snprintf(*short_options, len, "%s%s%s", cli->secret ? ":" : "",
		 PROVIDER_SHORT_OPTIONS,
		 cli->short_options ? cli->short_options : "");

	return opts;
}

int esdm_es_ext_provider_cli_main(const struct esdm_es_ext_provider_cli *cli,
				  const struct esdm_es_ext_plugin *plugin,
				  int argc, char *argv[])
{
	struct esdm_es_ext_provider_settings settings = {
		.entropy_rate = ESDM_ES_EXT_PROTO_RATE_NONE,
	};
	struct es_ext_net_cli net;
	struct option *opts;
	pthread_t signal_thread;
	uid_t client_uids[PROVIDER_MAX_CLIENT_UIDS];
	const char *name = provider_name(cli, argc, argv), *source;
	const char *socket_path = cli->socket_path;
	char *short_options = NULL;
	unsigned int client_uids_num = 0, i, verbose = 0;
	mode_t mode = 0666;
	bool unix_option = false, dtls = true;
	int c, ret = 1;

	sigemptyset(&provider_signal_set);
	sigaddset(&provider_signal_set, SIGTERM);
	sigaddset(&provider_signal_set, SIGINT);
	sigaddset(&provider_signal_set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &provider_signal_set, NULL);

	es_ext_net_cli_init(&net);

	opts = provider_options_merge(cli, &short_options);
	if (!opts) {
		fprintf(stderr, "Cannot take the command line: %s\n",
			strerror(ENOMEM));
		return 1;
	}

	/* What getopt_long() would print repeats what was given, see above */
	if (cli->secret)
		opterr = 0;
	while ((c = getopt_long(argc, argv, short_options, opts, NULL)) != -1) {
		switch (c) {
		case 's':
			socket_path = optarg;
			unix_option = true;
			break;
		case 'm': {
			unsigned long val;
			char *end;

			unix_option = true;
			errno = 0;
			val = strtoul(optarg, &end, 8);
			if (errno || end == optarg || *end != '\0' ||
			    val > 0777) {
				fprintf(stderr,
					"--mode takes an octal access mode, not \"%s\"\n",
					optarg);
				goto out;
			}
			mode = (mode_t)val;
			break;
		}
		case 'u': {
			uid_t uid = provider_parse_uid(optarg);

			unix_option = true;
			if (uid == (uid_t)-1) {
				fprintf(stderr,
					"--client_uid takes a uid or a user name, not \"%s\"\n",
					optarg);
				goto out;
			}
			if (client_uids_num >= PROVIDER_MAX_CLIENT_UIDS) {
				fprintf(stderr,
					"--client_uid may be given %u times at most\n",
					PROVIDER_MAX_CLIENT_UIDS);
				goto out;
			}
			client_uids[client_uids_num++] = uid;
			break;
		}
		case PROVIDER_OPT_NO_DTLS:
			unix_option = true;
			dtls = false;
			break;
		case PROVIDER_OPT_ENTROPY_RATE: {
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
				goto out;
			}
			settings.entropy_rate = (uint32_t)val;
			break;
		}
		case PROVIDER_OPT_NAME:
			if (!esdm_es_ext_name_valid(optarg, strlen(optarg))) {
				fprintf(stderr,
					"--name takes 1 to %u bytes of UTF-8 without control characters\n",
					ESDM_ES_EXT_NAME_MAX);
				goto out;
			}
			settings.name = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case PROVIDER_OPT_VERSION:
			if (cli->version)
				printf("%s %s\n", name, cli->version);
			else
				printf("%s (libesdm_es_ext %s)\n", name,
				       VERSION);
			ret = 0;
			goto out;
		case 'h':
			provider_usage(cli, name);
			ret = 0;
			goto out;
		case '?':
		case ':':
			/* Told by getopt_long() already without a secret */
			if (cli->secret)
				provider_option_error(cli, c, opts);
			provider_usage(cli, name);
			goto out;
		default: {
			int taken = es_ext_net_cli_option(&net, c, optarg);

			if (taken > 0)
				break;
			if (taken < 0)
				goto out;

			/* Every other option is one of the program */
			if (!cli->option || cli->option(c, optarg))
				goto out;
			break;
		}
		}
	}

	provider_net = es_ext_net_cli_wanted(&net);
	es_ext_net_cli_verbosity(provider_net, verbose);

	if (optind != argc) {
		/* Not repeated either: it may well be the secret */
		if (cli->secret)
			fprintf(stderr,
				"Unexpected argument - not repeated here, as it may hold %s\n",
				cli->secret);
		else
			fprintf(stderr, "Unexpected argument \"%s\"\n",
				argv[optind]);
		provider_usage(cli, name);
		goto out;
	}
	if (provider_net && unix_option) {
		fprintf(stderr,
			"--socket, --mode, --client_uid and --no_dtls are for a Unix domain socket - not for --listen\n");
		goto out;
	}
	if (!provider_net && net.option) {
		fprintf(stderr,
			"The options of the network take --listen, or sockets of socket activation\n");
		goto out;
	}
	if (!provider_net && !socket_path) {
		fprintf(stderr, "--socket or --listen is required\n");
		provider_usage(cli, name);
		goto out;
	}

	settings.net = provider_net;
	settings.socket_path = provider_net ? NULL : socket_path;
	if (cli->setup && cli->setup(&settings))
		goto out;

	/*
	 * The init of the source runs with the privileges the program was
	 * started with, and on the network the rest without - see
	 * es_ext_net_cli_drop_privileges()
	 */
	if (provider_net) {
		if (es_ext_net_cli_server(&net, plugin, &provider_server))
			goto out;
		if (es_ext_net_cli_drop_privileges(&net))
			goto out_free;
		goto served;
	}

	ret = esdm_es_ext_server_alloc(plugin, socket_path, mode,
				       &provider_server);
	if (ret) {
		fprintf(stderr, "Cannot serve on %s: %s\n", socket_path,
			strerror(-ret));
		ret = 1;
		goto out;
	}
	ret = 1;

	/*
	 * The ESDM runs as nobody unless told otherwise - see esdm-server
	 * --username. Without a user of that name, root alone is served.
	 */
	if (!client_uids_num) {
		uid_t nobody = provider_parse_uid("nobody");

		client_uids[client_uids_num++] =
			nobody != (uid_t)-1 ? nobody : 0;
	}
	for (i = 0; i < client_uids_num; i++) {
		c = esdm_es_ext_server_allow_uid(provider_server,
						 client_uids[i]);
		if (c) {
			fprintf(stderr, "Cannot serve uid %u: %s\n",
				(unsigned int)client_uids[i], strerror(-c));
			goto out_free;
		}
	}

	/* Offered by a library that has it, unless told otherwise */
	if (!dtls)
		esdm_es_ext_server_set_dtls(provider_server, 0);

served:
	/* Checked above already */
	if (settings.name)
		(void)esdm_es_ext_server_set_name(provider_server,
						  settings.name);
	if (settings.entropy_rate != ESDM_ES_EXT_PROTO_RATE_NONE)
		(void)esdm_es_ext_server_set_entropy_rate(
			provider_server, settings.entropy_rate);

	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	c = pthread_create(&signal_thread, NULL, provider_signals, NULL);
	if (c) {
		fprintf(stderr, "Cannot wait for signals: %s\n", strerror(c));
		goto out_free;
	}

	source = settings.name ? settings.name :
				 esdm_es_ext_name_or_null(plugin->name);
	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "Serving external entropy source %s on %s\n",
		    source ? source : name,
		    provider_net ? "the network" : socket_path);

	/*
	 * The socket accepts connections, and the source is set up: a unit
	 * ordered before the ESDM has the ESDM find it at its initial seeding.
	 */
	(void)systemd_notify_ready();

	c = esdm_es_ext_server_run(provider_server);
	if (c)
		fprintf(stderr, "Serving %s failed: %s\n",
			provider_net ? "the network" : socket_path,
			strerror(-c));
	ret = c ? 1 : 0;

	(void)systemd_notify_stopping();

	/* The signal thread ended with the signal, or waits for one still */
	pthread_kill(signal_thread, SIGTERM);
	pthread_join(signal_thread, NULL);

out_free:
	/* Calls the fini of the source */
	esdm_es_ext_server_free(provider_server);
	provider_server = NULL;
out:
	es_ext_net_cli_free(&net);
	free(short_options);
	free(opts);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_provider_main(const struct esdm_es_ext_plugin *plugin,
			      int argc, char *argv[])
{
	static const struct esdm_es_ext_provider_cli cli = { 0 };

	return esdm_es_ext_provider_cli_main(&cli, plugin, argc, argv);
}
