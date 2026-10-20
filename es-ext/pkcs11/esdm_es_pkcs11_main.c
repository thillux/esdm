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
 * program of libesdm_es_ext - its command line, and with --listen, or sockets
 * of socket activation, the network, see esdm_es_ext_provider.h - with the
 * options of the token next to the common ones.
 *
 * The PIN is configuration of this daemon, read from a file or a systemd
 * credential: never from the command line, where every user of the machine
 * reads it in /proc, and never from the build.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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
#include "esdm_es_ext_provider.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"
#include "memset_secure.h"

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

/* What the options of the token configure, the source taking it over */
static struct esdm_es_pkcs11_config pkcs11_config = {
	.module_path = ESDM_PKCS11_MODULE_PATH,
	.token_label = ESDM_PKCS11_TOKEN_LABEL,
	.pin = NULL,
	.entropy_rate = ESDM_PKCS11_ENTROPY_RATE,
};
static const char *pkcs11_pin_file;
static const char *pkcs11_credential = ESDM_ES_PKCS11_PIN_CREDENTIAL;
static bool pkcs11_credential_given;

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

/* The options of the token, next to the common ones of a provider */
enum {
	PKCS11_OPT_PIN_CREDENTIAL = 0x100,
};

static const struct option pkcs11_options[] = {
	{ "module", required_argument, NULL, 'M' },
	{ "token_label", required_argument, NULL, 't' },
	{ "pin_file", required_argument, NULL, 'p' },
	{ "pin_credential", required_argument, NULL,
	  PKCS11_OPT_PIN_CREDENTIAL },
	{ NULL, 0, NULL, 0 }
};

static int pkcs11_option(int opt, const char *arg)
{
	switch (opt) {
	case 'M':
		pkcs11_config.module_path = arg;
		return 0;
	case 't':
		pkcs11_config.token_label = arg;
		return 0;
	case 'p':
		pkcs11_pin_file = arg;
		return 0;
	case PKCS11_OPT_PIN_CREDENTIAL:
		pkcs11_credential = arg;
		pkcs11_credential_given = true;
		return 0;
	default:
		return -1;
	}
}

static void pkcs11_usage(FILE *out)
{
	fprintf(out,
		"\t-M --module <PATH>\tPKCS#11 module to load (default: %s)\n",
		ESDM_PKCS11_MODULE_PATH[0] ? ESDM_PKCS11_MODULE_PATH :
					     "none, required");
	fprintf(out,
		"\t-t --token_label <LABEL>\tUse the token of LABEL (default: %s)\n",
		ESDM_PKCS11_TOKEN_LABEL[0] ?
			ESDM_PKCS11_TOKEN_LABEL :
			"the first one with a random number generator");
	fprintf(out,
		"\t-p --pin_file <PATH>\tRead the user PIN from the first line of PATH\n");
	fprintf(out,
		"\t   --pin_credential <NAME>\tRead the user PIN from the systemd\n");
	fprintf(out,
		"\t\t\tcredential NAME (default: %s, if the daemon has it)\n",
		ESDM_ES_PKCS11_PIN_CREDENTIAL);
	fprintf(out,
		"\tThe source declares the name \"%s\", followed by the token label\n",
		ESDM_PKCS11_NAME);
	fprintf(out,
		"\tif given, and the entropy rate %u - unless --name and\n",
		ESDM_PKCS11_ENTROPY_RATE);
	fprintf(out, "\t--entropy_rate below say otherwise.\n");
}

/*
 * Once the command line is taken, before the source is set up: the module,
 * the PIN, and the source configured with them
 */
static int pkcs11_setup(const struct esdm_es_ext_provider_settings *settings)
{
	if (!pkcs11_config.module_path || !pkcs11_config.module_path[0]) {
		fprintf(stderr,
			"No PKCS#11 module: give one with --module, or build with es_pkcs11_module_path\n");
		return -1;
	}

	/* The source claims what the rate declared allows */
	if (settings->entropy_rate != ESDM_ES_EXT_PROTO_RATE_NONE)
		pkcs11_config.entropy_rate = settings->entropy_rate;

	if (pkcs11_pin(pkcs11_pin_file, pkcs11_credential,
		       pkcs11_credential_given, &pkcs11_config.pin))
		return -1;

	/*
	 * Nothing of this process goes into a core dump, nor can another
	 * process of its user read its memory with ptrace(2): it holds the
	 * PIN, and the module may hold the session of the user logged in.
	 */
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0))
		esdm_logger(LOGGER_WARN, LOGGER_C_ANY,
			    "Cannot keep the daemon out of core dumps: %s\n",
			    strerror(errno));

	/*
	 * The source takes the PIN over; it looks for the token in its init,
	 * with the privileges the daemon was started with - and logs out of
	 * it and wipes the PIN in its fini
	 */
	esdm_es_pkcs11_configure(&pkcs11_config);

	esdm_logger(LOGGER_STATUS, LOGGER_C_ANY, "PKCS#11 module %s\n",
		    pkcs11_config.module_path);

	return 0;
}

static const struct esdm_es_ext_provider_cli pkcs11_cli = {
	.name = "esdm-es-pkcs11",
	.version = ESDM_ES_PKCS11_VERSION,
	.title = "ESDM PKCS#11 entropy source",
	.socket_path = ESDM_ES_PKCS11_SOCKET,
	.short_options = "M:t:p:",
	.options = pkcs11_options,
	.option = pkcs11_option,
	.usage = pkcs11_usage,
	.setup = pkcs11_setup,
	/*
	 * A PIN given on the command line by mistake is not repeated, with
	 * every start of the daemon, in its journal
	 */
	.secret =
		"the PIN, which is read from a file or a credential, see --pin_file",
};

int main(int argc, char *argv[])
{
	return esdm_es_ext_provider_cli_main(&pkcs11_cli, &esdm_es_pkcs11_plugin,
					     argc, argv);
}
