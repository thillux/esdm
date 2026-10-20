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
 * The command line of a provider program, and the serving of its source -
 * what esdm_es_ext_provider_main() of esdm_es_ext.h runs, with room for the
 * options of a program of its own next to the common ones: esdm-es-pkcs11
 * takes its PKCS#11 module, its token and its PIN this way, and shares the
 * rest with every other provider program.
 *
 * No API of the library: it is not installed, and its function is not
 * exported by libesdm_es_ext.so - see version.lds. The programs of the ESDM
 * using it link the static library, where they reach it.
 */

#ifndef _ESDM_ES_EXT_PROVIDER_H
#define _ESDM_ES_EXT_PROVIDER_H

#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "esdm_es_ext.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * What the common options asked for, handed to the setup of the program
 *
 * @name: --name, NULL for none
 * @entropy_rate: --entropy_rate, ESDM_ES_EXT_PROTO_RATE_NONE for none
 * @net: Serving on the network
 * @socket_path: The Unix domain socket served on, NULL on the network
 */
struct esdm_es_ext_provider_settings {
	const char *name;
	uint32_t entropy_rate;
	bool net;
	const char *socket_path;
};

/*
 * A provider program
 *
 * @name: The name of the program, for --version and the usage; NULL for the
 *	  name it was started under
 * @version: Its version, for --version; NULL for the one of the library
 * @title: What it serves, the first line of the usage; NULL for a provider
 *	   of an external entropy source
 * @socket_path: The Unix domain socket served without --socket; NULL for
 *		 none, which makes --socket or the network a requirement
 * @short_options: The short options of the program, as getopt(3) takes
 *		   them, without a colon in front; NULL for none. The common
 *		   ones are s, m, u, v and h.
 * @options: The long options of the program, terminated by an entry of
 *	     zeros; NULL for none. Their codes must be none of the short
 *	     options above, nor 0x1000 or above, where those of the library
 *	     are.
 * @option: Take the option @opt of the program with @arg: 0, or -1 after
 *	    telling on stderr what is wrong
 * @usage: Print the usage of the options of the program to @out, ahead of
 *	   the common ones; NULL for none
 * @setup: Called once the command line is taken, and before the source is
 *	   set up - its init called - and served: 0, or -1 after telling on
 *	   stderr what is wrong. NULL for nothing to set up.
 * @secret: A secret the command line may hold by mistake - its text
 *	    completing "as it may hold ...". A command line that is wrong is
 *	    told without repeating any of it then: its output goes to the
 *	    journal of the service. NULL for none, which leaves the messages
 *	    to getopt_long(3).
 */
struct esdm_es_ext_provider_cli {
	const char *name;
	const char *version;
	const char *title;
	const char *socket_path;
	const char *short_options;
	const struct option *options;
	int (*option)(int opt, const char *arg);
	void (*usage)(FILE *out);
	int (*setup)(const struct esdm_es_ext_provider_settings *settings);
	const char *secret;
};

/*
 * Run the provider program @cli serving @plugin with the command line of
 * @argc and @argv - see esdm_es_ext_provider_main(), which runs it for a
 * program without options of its own.
 *
 * @return the exit status of the program
 */
int esdm_es_ext_provider_cli_main(const struct esdm_es_ext_provider_cli *cli,
				  const struct esdm_es_ext_plugin *plugin,
				  int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* _ESDM_ES_EXT_PROVIDER_H */
