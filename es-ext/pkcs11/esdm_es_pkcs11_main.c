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
 * esdm-es-pkcs11: serve the random number generator of a PKCS#11 token as an
 * external entropy source on a Unix domain socket the ESDM connects to - see
 * esdm-es-pkcs11(8). The source is esdm_es_pkcs11.c, served by the provider
 * server of libesdm_es_ext as esdm-es-ext-serve serves a plugin library.
 *
 * The PIN is configuration of this daemon, read from a file or a systemd
 * credential: never from the command line, where every user of the machine
 * reads it in /proc, and never from the build.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"
#include "memset_secure.h"
#include "systemd_support.h"

/* Set by the build, see es-ext/meson.build */
#ifndef ESDM_ES_PKCS11_VERSION
#define ESDM_ES_PKCS11_VERSION "unknown"
#endif

/* Where the daemon serves unless told otherwise - see its systemd unit */
#define ESDM_ES_PKCS11_SOCKET "/run/esdm-es-pkcs11/esdm-es-pkcs11.socket"

/*
 * The systemd credential the PIN is read from, in $CREDENTIALS_DIRECTORY -
 * LoadCredential=pkcs11-pin:/etc/esdm/pkcs11-pin in the unit
 */
#define ESDM_ES_PKCS11_PIN_CREDENTIAL "pkcs11-pin"

/*
 * The PIN of a PKCS#11 token is a few bytes, at most a passphrase - a file
 * beyond this size holds something else
 */
#define ESDM_ES_PKCS11_PIN_MAX 256

/* Clients to be served next to root */
#define ESDM_ES_PKCS11_MAX_CLIENT_UIDS 8

static struct esdm_es_ext_server *pkcs11_server;

/*
 * The signals ending the daemon, taken by a thread of its own with sigwait(2)
 * rather than by a handler - see esdm-es-ext-serve on why.
 */
static sigset_t pkcs11_signal_set;

static void *pkcs11_signals(void *arg)
{
	int sig;

	(void)arg;
	if (!sigwait(&pkcs11_signal_set, &sig))
		esdm_es_ext_server_stop(pkcs11_server);
	return NULL;
}

/* A uid, or the uid of a user name; (uid_t)-1 if it is neither */
static uid_t pkcs11_parse_uid(const char *arg)
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

/*
 * Read the PIN from the file @path: its first line, without the line break,
 * a NUL-terminated copy on the heap, which the caller wipes. The file is the
 * secret, so it has to be a regular file, and one that every user can read is
 * worth a warning - one of a group is not: a file of root that the group of
 * the daemon reads, and a systemd credential (0440 behind a directory only
 * the service reaches), are as they should be.
 *
 * @return the PIN, NULL with the reason printed otherwise
 */
static char *pkcs11_read_pin(const char *path)
{
	char raw[ESDM_ES_PKCS11_PIN_MAX + 2], *pin = NULL;
	size_t len = 0;
	struct stat sb;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (fd < 0) {
		fprintf(stderr, "Cannot open the PIN file %s: %s\n", path,
			strerror(errno));
		return NULL;
	}

	if (fstat(fd, &sb) || !S_ISREG(sb.st_mode)) {
		fprintf(stderr, "The PIN file %s is no regular file\n", path);
		goto out;
	}
	if (sb.st_mode & S_IRWXO)
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "The PIN file %s is open to every user\n", path);

	/* One byte more than a PIN may have, to tell a longer file */
	while (len < sizeof(raw) - 1) {
		ssize_t n = read(fd, raw + len, sizeof(raw) - 1 - len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			fprintf(stderr, "Cannot read the PIN file %s: %s\n",
				path, strerror(errno));
			goto out;
		}
		if (!n)
			break;
		len += (size_t)n;
	}
	raw[len] = '\0';

	/* One line, "\n" or "\r\n" terminated or not */
	if (len && raw[len - 1] == '\n')
		raw[--len] = '\0';
	if (len && raw[len - 1] == '\r')
		raw[--len] = '\0';

	if (len > ESDM_ES_PKCS11_PIN_MAX || memchr(raw, '\n', len) ||
	    memchr(raw, '\0', len)) {
		fprintf(stderr,
			"The PIN file %s holds more than one line of up to %u bytes\n",
			path, ESDM_ES_PKCS11_PIN_MAX);
		goto out;
	}
	if (!len) {
		fprintf(stderr, "The PIN file %s is empty\n", path);
		goto out;
	}

	pin = strdup(raw);
	if (!pin)
		fprintf(stderr, "Cannot hold the PIN: %s\n", strerror(ENOMEM));

out:
	memset_secure(raw, 0, sizeof(raw));
	close(fd);
	return pin;
}

/*
 * The PIN: from @pin_file if given, else from the systemd credential
 * @credential if the daemon has credentials. A credential asked for by name
 * (@credential_given) has to be there; the default one is optional.
 *
 * @return 0 with *@pin set - NULL for none - or 1 with the reason printed
 */
static int pkcs11_pin(const char *pin_file, const char *credential,
		      bool credential_given, char **pin)
{
	const char *dir = getenv("CREDENTIALS_DIRECTORY");
	char path[4096];
	struct stat sb;

	*pin = NULL;

	if (pin_file) {
		*pin = pkcs11_read_pin(pin_file);
		return *pin ? 0 : 1;
	}

	if (!dir || !dir[0]) {
		if (!credential_given)
			return 0;
		fprintf(stderr,
			"--pin_credential %s: the daemon has no credentials ($CREDENTIALS_DIRECTORY is not set)\n",
			credential);
		return 1;
	}

	if (!credential[0] || strchr(credential, '/')) {
		fprintf(stderr,
			"--pin_credential takes the name of a credential, not \"%s\"\n",
			credential);
		return 1;
	}

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, credential) >=
	    sizeof(path)) {
		fprintf(stderr, "The credential path is too long\n");
		return 1;
	}

	if (lstat(path, &sb) && errno == ENOENT && !credential_given)
		return 0;

	*pin = pkcs11_read_pin(path);
	return *pin ? 0 : 1;
}

static void usage(void)
{
	fprintf(stderr, "\nESDM PKCS#11 entropy source\n\n");
	fprintf(stderr, "esdm-es-pkcs11 %s\n\n", ESDM_ES_PKCS11_VERSION);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"\t-M --module <PATH>\tPKCS#11 module to load (default: %s)\n",
		ESDM_PKCS11_MODULE_PATH[0] ? ESDM_PKCS11_MODULE_PATH :
					     "none, required");
	fprintf(stderr,
		"\t-t --token_label <LABEL>\tUse the token of LABEL (default: %s)\n",
		ESDM_PKCS11_TOKEN_LABEL[0] ?
			ESDM_PKCS11_TOKEN_LABEL :
			"the first one with a random number generator");
	fprintf(stderr,
		"\t-p --pin_file <PATH>\tRead the user PIN from the first line of PATH\n");
	fprintf(stderr,
		"\t   --pin_credential <NAME>\tRead the user PIN from the systemd\n");
	fprintf(stderr,
		"\t\t\tcredential NAME (default: %s, if the daemon has it)\n",
		ESDM_ES_PKCS11_PIN_CREDENTIAL);
	fprintf(stderr,
		"\t-s --socket <PATH>\tUnix domain socket to serve on (default:\n");
	fprintf(stderr, "\t\t\t%s)\n", ESDM_ES_PKCS11_SOCKET);
	fprintf(stderr,
		"\t-m --mode <MODE>\tAccess mode of the socket, octal (default 0666)\n");
	fprintf(stderr,
		"\t-u --client_uid <USER>\tServe clients running as USER (uid or name)\n");
	fprintf(stderr,
		"\t\t\tnext to root; may be repeated (default: nobody)\n");
	fprintf(stderr, "\t   --no_dtls\tDo not offer DTLS to the clients\n");
	fprintf(stderr,
		"\t   --entropy_rate <BITS>\tDeclare BITS of entropy per 256 bits of\n");
	fprintf(stderr, "\t\t\tdata, 0 to 256 (default: %u)\n",
		ESDM_PKCS11_ENTROPY_RATE);
	fprintf(stderr,
		"\t   --name <NAME>\tDeclare NAME as the name of the source: 1 to %u\n",
		ESDM_ES_EXT_NAME_MAX);
	fprintf(stderr,
		"\t\t\tbytes of UTF-8 without control characters (default:\n");
	fprintf(stderr, "\t\t\t\"%s\", followed by the token label if given)\n",
		ESDM_PKCS11_NAME);
	fprintf(stderr,
		"\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tThis help information\n");
	fprintf(stderr, "\t   --version\tPrint version\n");
}

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "module", required_argument, NULL, 'M' },
		{ "token_label", required_argument, NULL, 't' },
		{ "pin_file", required_argument, NULL, 'p' },
		{ "pin_credential", required_argument, NULL, 'C' },
		{ "socket", required_argument, NULL, 's' },
		{ "mode", required_argument, NULL, 'm' },
		{ "client_uid", required_argument, NULL, 'u' },
		{ "no_dtls", no_argument, NULL, 'D' },
		{ "name", required_argument, NULL, 'N' },
		{ "entropy_rate", required_argument, NULL, 'R' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 }
	};
	struct esdm_es_pkcs11_config config = {
		.module_path = ESDM_PKCS11_MODULE_PATH,
		.token_label = ESDM_PKCS11_TOKEN_LABEL,
		.pin = NULL,
		.entropy_rate = ESDM_PKCS11_ENTROPY_RATE,
	};
	const char *socket_path = ESDM_ES_PKCS11_SOCKET, *name = NULL;
	const char *pin_file = NULL;
	const char *credential = ESDM_ES_PKCS11_PIN_CREDENTIAL;
	bool credential_given = false;
	pthread_t signal_thread;
	uid_t client_uids[ESDM_ES_PKCS11_MAX_CLIENT_UIDS];
	unsigned int client_uids_num = 0, i;
	mode_t mode = 0666;
	bool dtls = true;
	int c, ret;

	sigemptyset(&pkcs11_signal_set);
	sigaddset(&pkcs11_signal_set, SIGTERM);
	sigaddset(&pkcs11_signal_set, SIGINT);
	sigaddset(&pkcs11_signal_set, SIGHUP);
	pthread_sigmask(SIG_BLOCK, &pkcs11_signal_set, NULL);

	while ((c = getopt_long(argc, argv, "M:t:p:s:m:u:vh", opts, NULL)) !=
	       -1) {
		switch (c) {
		case 'M':
			config.module_path = optarg;
			break;
		case 't':
			config.token_label = optarg;
			break;
		case 'p':
			pin_file = optarg;
			break;
		case 'C':
			credential = optarg;
			credential_given = true;
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
			uid_t uid = pkcs11_parse_uid(optarg);

			if (uid == (uid_t)-1) {
				fprintf(stderr,
					"--client_uid takes a uid or a user name, not \"%s\"\n",
					optarg);
				return 1;
			}
			if (client_uids_num >= ESDM_ES_PKCS11_MAX_CLIENT_UIDS) {
				fprintf(stderr,
					"--client_uid may be given %u times at most\n",
					ESDM_ES_PKCS11_MAX_CLIENT_UIDS);
				return 1;
			}
			client_uids[client_uids_num++] = uid;
			break;
		}
		case 'D':
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
			config.entropy_rate = (uint32_t)val;
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
			esdm_logger_inc_verbosity();
			break;
		case 'V':
			printf("esdm-es-pkcs11 %s\n", ESDM_ES_PKCS11_VERSION);
			return 0;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			return 1;
		}
	}

	if (optind != argc) {
		fprintf(stderr,
			"Unexpected argument \"%s\" - the PIN is read from a file or a credential, see --pin_file\n",
			argv[optind]);
		usage();
		return 1;
	}

	if (!config.module_path || !config.module_path[0]) {
		fprintf(stderr,
			"No PKCS#11 module: give one with --module, or build with es_pkcs11_module_path\n");
		usage();
		return 1;
	}

	if (pkcs11_pin(pin_file, credential, credential_given, &config.pin))
		return 1;

	/*
	 * Nothing of this process goes into a core dump, nor can another
	 * process of its user read its memory with ptrace(2): it holds the
	 * PIN, and the module may hold the session of the user logged in.
	 */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "Cannot keep the daemon out of core dumps: %s\n",
			    strerror(errno));

	/* The source takes the PIN over */
	esdm_es_pkcs11_configure(&config);

	ret = esdm_es_ext_server_alloc(&esdm_es_pkcs11_plugin, socket_path,
				       mode, &pkcs11_server);
	if (ret) {
		fprintf(stderr, "Cannot serve the PKCS#11 source on %s: %s\n",
			socket_path, strerror(-ret));
		return 1;
	}

	/*
	 * The ESDM runs as nobody unless told otherwise - see esdm-server
	 * --username. Without a user of that name, root alone is served.
	 */
	if (!client_uids_num) {
		uid_t nobody = pkcs11_parse_uid("nobody");

		client_uids[client_uids_num++] =
			nobody != (uid_t)-1 ? nobody : 0;
	}
	for (i = 0; i < client_uids_num; i++) {
		ret = esdm_es_ext_server_allow_uid(pkcs11_server,
						   client_uids[i]);
		if (ret) {
			fprintf(stderr, "Cannot serve uid %u: %s\n",
				(unsigned int)client_uids[i], strerror(-ret));
			esdm_es_ext_server_free(pkcs11_server);
			return 1;
		}
	}

	/* Offered by a library that has it, unless told otherwise */
	if (!dtls)
		esdm_es_ext_server_set_dtls(pkcs11_server, 0);

	/* Checked above already */
	if (name)
		(void)esdm_es_ext_server_set_name(pkcs11_server, name);

	/* A client gone mid-answer is no reason to terminate */
	signal(SIGPIPE, SIG_IGN);

	ret = -pthread_create(&signal_thread, NULL, pkcs11_signals, NULL);
	if (ret) {
		fprintf(stderr, "Cannot wait for signals: %s\n",
			strerror(-ret));
		esdm_es_ext_server_free(pkcs11_server);
		return 1;
	}

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY,
		    "Serving %s, PKCS#11 module %s, on %s\n",
		    name ? name : esdm_es_pkcs11_plugin.name,
		    config.module_path, socket_path);

	/*
	 * The socket accepts connections, and the token was looked for: a
	 * unit ordered before the ESDM has the ESDM find the token at its
	 * initial seeding.
	 */
	(void)systemd_notify_ready();

	ret = esdm_es_ext_server_run(pkcs11_server);
	if (ret)
		fprintf(stderr, "Serving %s failed: %s\n", socket_path,
			strerror(-ret));

	(void)systemd_notify_stopping();

	/* The signal thread ended with the signal, or waits for one still */
	pthread_kill(signal_thread, SIGTERM);
	pthread_join(signal_thread, NULL);

	/* Logs out of the token and wipes the PIN */
	esdm_es_ext_server_free(pkcs11_server);

	return ret ? 1 : 0;
}
