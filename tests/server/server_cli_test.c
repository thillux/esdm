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
 * Tests for the esdm-server command line.
 *
 * The suite starts the daemon in several places, but always with no options or
 * the one or two a particular test needs, so everything else the command line
 * accepts - and everything it says when given something it does not - was never
 * executed. None of that needs the daemon to come up: the options are parsed
 * before the check refusing to run as anything but root, so an unprivileged run
 * reaches all of the parsing and stops right afterwards. --help and --version
 * are their own answer, exiting before anything else happens.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"

#include "../test_run.h"

/* What an unprivileged run gets to say before it stops */
#define TEST_NOT_ROOT "must start as root"

static void test_usage(void)
{
	const char *const help[] = { "-h", NULL };
	const char *const help_long[] = { "--help", NULL };
	struct test_run r;
	int rc = test_run(&r, help, NULL);

	/*
	 * The usage is what someone gets who does not know the options yet, so
	 * having asked for it is not success - there is no daemon afterwards.
	 */
	CHECK_EQ(rc, 1);
	CHECK(strstr(r.err, "ESDM RPC server") != NULL,
	      "the usage does not name the program (output: %.200s)", r.err);

	/*
	 * Spot-check the options that a user has to be told about: the two that
	 * decide who the daemon runs as, the one that keeps it in the
	 * foreground, and the one that hands it a socket to serve.
	 */
	CHECK(strstr(r.err, "--username") != NULL,
	      "the usage does not mention --username");
	CHECK(strstr(r.err, "--groupname") != NULL,
	      "the usage does not mention --groupname");
	CHECK(strstr(r.err, "--foreground") != NULL,
	      "the usage does not mention --foreground");
	CHECK(strstr(r.err, "--egd_socket") != NULL,
	      "the usage does not mention --egd_socket");

	/* The long form is the same answer */
	CHECK_EQ(test_run(&r, help_long, NULL), 1);
	CHECK(strstr(r.err, "ESDM RPC server") != NULL,
	      "--help does not print the usage (output: %.200s)", r.err);
}

static void test_version(void)
{
	const char *const opts[] = { "--version", NULL };
	struct test_run r;
	int rc = test_run(&r, opts, NULL);

	/* Asking what this is has an answer, so it is not a failure */
	CHECK_EQ(rc, 0);
	/*
	 * esdm-server(8) promises the version of the ESDM library the daemon
	 * was built against, and that is what esdm_version() reports. Only a
	 * test mode build prefixes it with a banner naming the ESDM, so the
	 * name of the project is not something to look for here.
	 */
	CHECK(strstr(r.err, "library version") != NULL,
	      "the version is not the library version (output: %.200s)",
	      r.err);
	CHECK(strstr(r.err, VERSION) != NULL,
	      "the version does not report " VERSION " (output: %.200s)",
	      r.err);
}

static void test_unknown_option(void)
{
	const char *const unknown[] = { "--no-such-option", NULL };
	const char *const unknown_short[] = { "-Z", NULL };
	/*
	 * The second EGD socket for prediction resistance is gone - the ESDM
	 * serves that with a command on the one socket. A setup still asking
	 * for it has to learn so rather than run without what it asked for.
	 */
	const char *const egd_pr[] = { "--egd_socket_pr",
				       "/nonexistent/esdm-egd-pr.socket", NULL };
	const char *const egd_pr_short[] = {
		"-E", "/nonexistent/esdm-egd-pr.socket", NULL
	};
	struct test_run r;

	/*
	 * An option the daemon does not know is answered with the usage rather
	 * than ignored - starting a daemon that quietly did something other
	 * than what was asked is the outcome to avoid.
	 */
	CHECK_EQ(test_run(&r, unknown, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "an unknown option was rejected without the usage (output: %.200s)",
	      r.err);

	CHECK_EQ(test_run(&r, unknown_short, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "an unknown short option was rejected without the usage (output: %.200s)",
	      r.err);

	CHECK_EQ(test_run(&r, egd_pr, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "--egd_socket_pr was not rejected with the usage (output: %.200s)",
	      r.err);

	CHECK_EQ(test_run(&r, egd_pr_short, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "-E was not rejected with the usage (output: %.200s)", r.err);
}

/*
 * The options that only set something up for later. All of them are accepted
 * in one go: what each records is not observable from outside, but that the
 * parser takes them - and takes them in either spelling - is.
 */
static void test_options_accepted(void)
{
	static const char *const long_form[] = {
		"--verbose",     "--foreground",  "--force_irqes",
		"--force_schedes", "--memlock",   "--small_memory",
		"--keep_ipc",    "--jent_block_disable",
		"--raise_sched_priority",
		"--username",    "nobody",        "--groupname",
		"nogroup",       NULL
	};
	/* The switches of the RPC server, taken whatever the build */
	static const char *const rpc_switches[] = {
		"--no_dtls", "--no_io_uring", "--no_fixed_drng_mapping",
		"--no_io_uring_multishot", NULL
	};
	static const char *const short_form[] = { "-v", "-f",       "-i", "-s",
						  "-m", "-M",       "-P", "-u",
						  "nobody", "-g",   "nogroup",
						  NULL };
	static const char *const sockets[] = { "-e",
					       "/nonexistent/esdm-egd.socket",
					       NULL };
	static const char *const sockets_long[] = {
		"--egd_socket", "/nonexistent/esdm-egd.socket", NULL
	};
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the parse-only checks\n");
		return;
	}

	/*
	 * Each of these gets as far as the privilege check and no further,
	 * which is what says the parser accepted everything before it. A
	 * rejected option would have exited with the usage instead.
	 */
	CHECK_EQ(test_run(&r, long_form, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the long options were not all accepted (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, rpc_switches, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the RPC server switches were not all accepted (output: %.300s)",
	      r.err);

	CHECK_EQ(test_run(&r, short_form, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the short options were not all accepted (output: %.300s)", r.err);

	/*
	 * The EGD socket is only recorded here - it is bound once the daemon
	 * is up, so a path that cannot exist is accepted at this point.
	 */
	CHECK_EQ(test_run(&r, sockets, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the EGD socket options were not accepted (output: %.300s)",
	      r.err);

	CHECK_EQ(test_run(&r, sockets_long, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "the long EGD socket options were not accepted (output: %.300s)",
	      r.err);
}

/*
 * --syslog sends everything the daemon has to say to the system log. The
 * refusal that follows therefore has to be looked for in the exit status: it is
 * no longer on stderr, and that is the point of the option.
 */
static void test_syslog(void)
{
	const char *const opts[] = { "--syslog", NULL };
	const char *const opts_short[] = { "-S", NULL };
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the syslog checks\n");
		return;
	}

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) == NULL,
	      "--syslog left the log on stderr (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, opts_short, NULL), 1);
}

/*
 * The PID file path is taken while parsing and the file is only created once
 * the daemon starts, so an unprivileged run says nothing about the path - what
 * it does say is that the option was understood.
 */
static void test_pid_file_option(void)
{
	const char *const opts[] = { "--pid", "/nonexistent/esdm.pid", NULL };
	const char *const opts_short[] = { "-p", "/nonexistent/esdm.pid",
					   NULL };
	struct test_run r;

	if (!geteuid()) {
		printf("running as root - skipping the PID file checks\n");
		return;
	}

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "--pid was not accepted (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, opts_short, NULL), 1);
	CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
	      "-p was not accepted (output: %.300s)", r.err);
}

/*
 * The daemon reports what makes it fail without being asked to be verbose: no
 * -v used to be the level of no output at all, and the daemon then ended with
 * nothing but its exit status. A PID file that cannot be created is the first
 * failure past the privilege check, so this needs root, and the daemon ends
 * there, before it set up anything.
 */
static void test_errors_without_verbose(void)
{
	const char *const opts[] = { "-f", "--pid", "/nonexistent/esdm.pid",
				     NULL };
	struct test_run r;

	if (geteuid()) {
		printf("not running as root - skipping the error report check\n");
		return;
	}

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, "Cannot open pid file") != NULL,
	      "the failure was not reported without -v (output: %.300s)",
	      r.err);
}

/*
 * The PKCS#11 entropy source is esdm-es-pkcs11, which the ESDM reads as an
 * external one, and which takes its module on its own command line. The
 * option of the server that named the module is gone: a setup still giving it
 * has to learn so - with the usage, as for any unknown option - rather than
 * run without the token it asked for. Nor does the usage offer it.
 */
static void test_pkcs11_module_gone(void)
{
	const char *const opts[] = { "--pkcs11_module",
				     "/nonexistent/libpkcs11-test.so", NULL };
	struct test_run r;

	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, "Usage") != NULL,
	      "--pkcs11_module was not rejected with the usage (output: %.300s)",
	      r.err);
	CHECK(strstr(r.err, TEST_NOT_ROOT) == NULL,
	      "--pkcs11_module was refused only after the parsing (output: %.300s)",
	      r.err);

	CHECK_EQ(test_run(&r, (const char *const[]){ "-h", NULL }, NULL), 1);
	CHECK(strstr(r.err, "pkcs11") == NULL,
	      "the usage still offers a PKCS#11 option");
}

/*
 * External entropy sources are no longer loaded into the daemon as plugin
 * libraries - a source is served by a provider of its own, read with
 * --es_ext_socket. A setup still naming a plugin library has to learn so, with
 * the usage as for any unknown option, rather than run without the source it
 * asked for. Nor does the usage offer the options any longer.
 */
static void test_es_ext_lib_gone(void)
{
	static const char *const gone[][3] = {
		{ "--es_ext_lib", "/nonexistent/libesdm-es-ext-test.so", NULL },
		{ "--es_ext_lib_entropy_rate", "128", NULL },
	};
	struct test_run r;
	unsigned int i;

	for (i = 0; i < sizeof(gone) / sizeof(gone[0]); i++) {
		CHECK_EQ(test_run(&r, gone[i], NULL), 1);
		CHECK(strstr(r.err, "Usage") != NULL,
		      "%s was not rejected with the usage (output: %.300s)",
		      gone[i][0], r.err);
		CHECK(strstr(r.err, TEST_NOT_ROOT) == NULL,
		      "%s was refused only after the parsing (output: %.300s)",
		      gone[i][0], r.err);
	}

	CHECK_EQ(test_run(&r, (const char *const[]){ "-h", NULL }, NULL), 1);
	CHECK(strstr(r.err, "--es_ext_lib") == NULL &&
		      strstr(r.err, "plugin") == NULL,
	      "the usage still offers a plugin library");
}

/*
 * The socket of the external entropy source provider, the cap of its credit
 * and the user it may run as. The socket is only connected to by esdm_init(),
 * so an unprivileged run accepts any path.
 */
static void test_es_ext_socket_options(void)
{
	const char *const opts[] = { "--es_ext_socket",
				     "/nonexistent/esdm-es-ext.socket",
				     "--es_ext_socket_entropy_rate", "auto",
				     "--es_ext_socket_uid", "1234", NULL };
	const char *const by_name[] = { "--es_ext_socket_uid", "root", NULL };
	const char *const empty[] = { "--es_ext_socket", "", NULL };
	const char *const no_user[] = { "--es_ext_socket_uid",
					"no-such-user-esdm-test", NULL };
	const char *const bad_rate[] = { "--es_ext_socket_entropy_rate", "300",
					 NULL };
	struct test_run r;

#ifdef ESDM_ES_EXT
	/* Accepted, as root the daemon would start */
	if (geteuid()) {
		CHECK_EQ(test_run(&r, opts, NULL), 1);
		CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
		      "the --es_ext_socket options were not accepted (output: %.300s)",
		      r.err);

		CHECK_EQ(test_run(&r, by_name, NULL), 1);
		CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
		      "a user name for --es_ext_socket_uid was not accepted (output: %.300s)",
		      r.err);
	}
#else
	(void)by_name;
	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, "not part of this build") != NULL,
	      "--es_ext_socket was not refused without external ES (output: %.300s)",
	      r.err);
#endif

	CHECK_EQ(test_run(&r, empty, NULL), 1);
	CHECK(strstr(r.err, "must not be empty") != NULL,
	      "an empty --es_ext_socket was not refused (output: %.300s)",
	      r.err);

	CHECK_EQ(test_run(&r, no_user, NULL), 1);
	CHECK(strstr(r.err, "uid or a user name") != NULL,
	      "an unknown user was not refused (output: %.300s)", r.err);

	CHECK_EQ(test_run(&r, bad_rate, NULL), 1);
	CHECK(strstr(r.err, "entropy rate from 0 to 256") != NULL,
	      "--es_ext_socket_entropy_rate 300 was not refused (output: %.300s)",
	      r.err);
}

/*
 * The options of the external sources may be given once per source, the n-th
 * occurrence of an option configuring the n-th source: as often as the build
 * has sources is accepted, once more is refused - before the parsing is done,
 * with a message that says why.
 */
static void test_es_ext_repeated_options(void)
{
#ifdef ESDM_ES_EXT
	static const struct {
		const char *opt;
		const char *arg;
	} opts[] = {
		{ "--es_ext_socket", "/nonexistent/esdm-es-ext.socket" },
		{ "--es_ext_socket_entropy_rate", "64" },
		{ "--es_ext_socket_uid", "1234" },
	};
	/* Up to 16 sources, and one occurrence more */
	const char *argv[2 * 17 + 1];
	struct test_run r;
	unsigned int i, n;

	for (i = 0; i < sizeof(opts) / sizeof(opts[0]); i++) {
		for (n = 0; n <= ESDM_EXT_SOCKET_NUM; n++) {
			argv[2 * n] = opts[i].opt;
			argv[2 * n + 1] = opts[i].arg;
		}

		/* Once per source */
		argv[2 * ESDM_EXT_SOCKET_NUM] = NULL;
		if (geteuid()) {
			CHECK_EQ(test_run(&r, argv, NULL), 1);
			CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
			      "%s given %u times was not accepted (output: %.300s)",
			      opts[i].opt, ESDM_EXT_SOCKET_NUM, r.err);
		}

		/* And once more */
		argv[2 * ESDM_EXT_SOCKET_NUM] = opts[i].opt;
		argv[2 * ESDM_EXT_SOCKET_NUM + 2] = NULL;
		CHECK_EQ(test_run(&r, argv, NULL), 1);
		CHECK(strstr(r.err, "is given more often than this build has") !=
			      NULL,
		      "%s given %u times was not refused (output: %.300s)",
		      opts[i].opt, ESDM_EXT_SOCKET_NUM + 1, r.err);
		CHECK(strstr(r.err, TEST_NOT_ROOT) == NULL,
		      "%s given too often was refused only after the parsing (output: %.300s)",
		      opts[i].opt, r.err);
	}

	/* The usage tells how many sources the options configure */
	CHECK_EQ(test_run(&r, (const char *const[]){ "-h", NULL }, NULL), 1);
	CHECK(strstr(r.err, "n-th occurrence") != NULL,
	      "the usage does not say the options configure one source each");
#endif
}

/* The kernel crypto API RNG of the kernel Jitter RNG source */
static void test_es_jent_kernel_name_option(void)
{
	const char *const opts[] = { "--es_jent_kernel_name",
				     "jitterentropy_rng_test", NULL };
	const char *const empty[] = { "--es_jent_kernel_name", "", NULL };
	struct test_run r;

#ifdef ESDM_ES_JENT_KERNEL
	/* Accepted, as root the daemon would start */
	if (geteuid()) {
		CHECK_EQ(test_run(&r, opts, NULL), 1);
		CHECK(strstr(r.err, TEST_NOT_ROOT) != NULL,
		      "--es_jent_kernel_name was not accepted (output: %.300s)",
		      r.err);
	}
#else
	CHECK_EQ(test_run(&r, opts, NULL), 1);
	CHECK(strstr(r.err, "not part of this build") != NULL,
	      "--es_jent_kernel_name was not refused without the source (output: %.300s)",
	      r.err);
#endif

	CHECK_EQ(test_run(&r, empty, NULL), 1);
	CHECK(strstr(r.err, "must not be empty") != NULL,
	      "an empty --es_jent_kernel_name was not refused (output: %.300s)",
	      r.err);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("usage: %s <path to esdm-server>\n", argv[0]);
		return 1;
	}

	if (test_run_init(argv[1]))
		return 1;

	test_usage();
	test_version();
	test_unknown_option();
	test_options_accepted();
	test_syslog();
	test_pid_file_option();
	test_errors_without_verbose();
	test_pkcs11_module_gone();
	test_es_ext_lib_gone();
	test_es_ext_socket_options();
	test_es_ext_repeated_options();
	test_es_jent_kernel_name_option();

	test_run_fini();

	return common_test_result("server_cli");
}
