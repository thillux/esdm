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
 * What the tests of esdm-es-pkcs11 share: a directory of their own holding a
 * SoftHSM configuration, its tokens, the PIN files and the socket, SoftHSM
 * found next to the softhsm2-util on the path, and the daemon started in
 * front of it - through es_pkcs11_shim.c, which counts the logins into
 * pk.login_log, fails C_GenerateRandom while pk.fail exists and repeats its
 * output while pk.repeat does.
 */

#ifndef _ES_PKCS11_TEST_UTIL_H
#define _ES_PKCS11_TEST_UTIL_H

#define _GNU_SOURCE
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "es_ext_test_util.h"

/* As the daemon has it - see es-ext/pkcs11/esdm_es_pkcs11.h */
#define PK_RETRY_INTERVAL_SEC 5

#define PK_TOKEN_LABEL "esdm-test-token"
#define PK_TOKEN_PIN "648219"
#define PK_TOKEN_SO_PIN "1234567890"

#define PK_DIR_TEMPLATE "/tmp/esdm-es-pkcs11-test-XXXXXX"
#define PK_PATH_SIZE (sizeof(PK_DIR_TEMPLATE) + 32)

static struct {
	/* The daemon and the module of the test in front of SoftHSM */
	const char *daemon;
	const char *shim;
	char softhsm[PATH_MAX];

	char dir[sizeof(PK_DIR_TEMPLATE)];
	char socket[PK_PATH_SIZE];
	char conf[PK_PATH_SIZE];
	char login_log[PK_PATH_SIZE];
	char fail[PK_PATH_SIZE];
	char repeat[PK_PATH_SIZE];
	char daemon_log[PK_PATH_SIZE];
	char pin_good[PK_PATH_SIZE];
	char pin_wrong[PK_PATH_SIZE];
	char cred_dir[PK_PATH_SIZE];

	pid_t pid;
} pk;

static inline int pk_write_file(const char *path, const char *content,
				mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	size_t len = strlen(content);
	int ret = 0;

	if (fd < 0)
		return -1;
	if (write(fd, content, len) != (ssize_t)len)
		ret = -1;
	close(fd);
	return ret;
}

/* Lines of the file @path containing @what, 0 for a file that is not there */
static inline unsigned int pk_count_lines(const char *path, const char *what)
{
	unsigned int count = 0;
	char line[1024];
	FILE *f = fopen(path, "re");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, what))
			count++;
	}
	fclose(f);
	return count;
}

/* The directory of the test with the paths in it, and the PIN files */
static inline int pk_setup(const char *daemon, const char *shim)
{
	pk.daemon = daemon;
	pk.shim = shim;

	snprintf(pk.dir, sizeof(pk.dir), "%s", PK_DIR_TEMPLATE);
	if (!mkdtemp(pk.dir))
		return 1;

	snprintf(pk.socket, sizeof(pk.socket), "%s/pkcs11.socket", pk.dir);
	snprintf(pk.conf, sizeof(pk.conf), "%s/softhsm2.conf", pk.dir);
	snprintf(pk.login_log, sizeof(pk.login_log), "%s/login.log", pk.dir);
	snprintf(pk.fail, sizeof(pk.fail), "%s/fail", pk.dir);
	snprintf(pk.repeat, sizeof(pk.repeat), "%s/repeat", pk.dir);
	snprintf(pk.daemon_log, sizeof(pk.daemon_log), "%s/daemon.log", pk.dir);
	snprintf(pk.pin_good, sizeof(pk.pin_good), "%s/pin", pk.dir);
	snprintf(pk.pin_wrong, sizeof(pk.pin_wrong), "%s/wrong-pin", pk.dir);
	snprintf(pk.cred_dir, sizeof(pk.cred_dir), "%s/credentials", pk.dir);

	if (pk_write_file(pk.pin_good, PK_TOKEN_PIN "\n", 0600) ||
	    pk_write_file(pk.pin_wrong, "000000\n", 0600) ||
	    mkdir(pk.cred_dir, 0700))
		return 1;

	return 0;
}

static inline int pk_rm(const char *path, const struct stat *sb, int flag,
			struct FTW *ftw)
{
	(void)sb;
	(void)flag;
	(void)ftw;
	return remove(path);
}

/* Stop a daemon left running and remove the directory of the test */
static inline void pk_cleanup(void)
{
	es_ext_test_terminate(pk.pid);
	pk.pid = 0;
	if (pk.dir[0] && strcmp(pk.dir, PK_DIR_TEMPLATE))
		nftw(pk.dir, pk_rm, 16, FTW_DEPTH | FTW_PHYS);
}

/*
 * Run softhsm2-util with @argv on the configuration of the test. Returns its
 * exit status, or -1 if it could not be run at all.
 */
static inline int pk_softhsm_util(char *const argv[])
{
	char conf[PK_PATH_SIZE + 16];
	char *envp[] = { conf, NULL };
	posix_spawn_file_actions_t fa;
	pid_t pid;
	int ret;

	snprintf(conf, sizeof(conf), "SOFTHSM2_CONF=%s", pk.conf);

	/* Keep the log readable; failures are reported by the caller */
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null",
					 O_WRONLY, 0);
	posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null",
					 O_WRONLY, 0);
	ret = posix_spawnp(&pid, "softhsm2-util", &fa, NULL, argv, envp);
	posix_spawn_file_actions_destroy(&fa);
	if (ret)
		return -1;

	ret = es_ext_test_wait(pid);
	return ret == 127 ? -1 : ret;
}

/* Create a token of the label @label with the PIN of the test */
static inline int pk_init_token(const char *label)
{
	char *argv[] = { "softhsm2-util", "--init-token",
			 "--free",	  "--label",
			 (char *)label,	  "--so-pin",
			 PK_TOKEN_SO_PIN, "--pin",
			 PK_TOKEN_PIN,	  NULL };

	return pk_softhsm_util(argv);
}

/*
 * The SoftHSM module next to the softhsm2-util on the path - the one that
 * creates the tokens has to be the one reading them - or the module of the
 * build if that is a SoftHSM.
 */
static inline bool pk_find_softhsm(void)
{
	const char *path = getenv("PATH");
	char *paths, *dir, *save = NULL;
	bool found = false;

	if (path && (paths = strdup(path))) {
		for (dir = strtok_r(paths, ":", &save); dir && !found;
		     dir = strtok_r(NULL, ":", &save)) {
			char util[PATH_MAX], real[PATH_MAX];

			snprintf(util, sizeof(util), "%s/softhsm2-util", dir);
			if (access(util, X_OK) || !realpath(util, real))
				continue;
			snprintf(pk.softhsm, sizeof(pk.softhsm),
				 "%s/../lib/softhsm/libsofthsm2.so",
				 dirname(real));
			found = !access(pk.softhsm, R_OK);
		}
		free(paths);
	}

	if (!found && strstr(ESDM_PKCS11_MODULE_PATH, "softhsm") &&
	    !access(ESDM_PKCS11_MODULE_PATH, R_OK)) {
		snprintf(pk.softhsm, sizeof(pk.softhsm), "%s",
			 ESDM_PKCS11_MODULE_PATH);
		found = true;
	}

	return found;
}

/* A configuration of SoftHSM of the test's own, and the token of the test */
static inline int pk_softhsm_setup(void)
{
	char tokens[PK_PATH_SIZE + 16], conf[PK_PATH_SIZE * 2 + 128];

	snprintf(tokens, sizeof(tokens), "%s/tokens", pk.dir);
	if (mkdir(tokens, 0700))
		return 1;
	snprintf(conf, sizeof(conf),
		 "directories.tokendir = %s\n"
		 "objectstore.backend = file\n"
		 "log.level = ERROR\n",
		 tokens);
	if (pk_write_file(pk.conf, conf, 0600))
		return 1;

	return pk_init_token(PK_TOKEN_LABEL) ? 1 : 0;
}

/*
 * Start the daemon with the arguments @args, NULL terminated, after those for
 * the socket and the client of the test, and the variables @env in its
 * environment next to those of SoftHSM and the shim. Its output goes to
 * pk.daemon_log.
 */
static inline pid_t pk_spawn(const char *const *args, const char *const *env)
{
	char uid[16], conf[PK_PATH_SIZE + 32], module[PATH_MAX + 32];
	char login[PK_PATH_SIZE + 32], fail[PK_PATH_SIZE + 32];
	char repeat[PK_PATH_SIZE + 32];
	char *argv[40], *envp[16];
	posix_spawn_file_actions_t fa;
	unsigned int n = 0, e = 0;
	pid_t pid;
	int ret;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	argv[n++] = (char *)pk.daemon;
	argv[n++] = "--socket";
	argv[n++] = pk.socket;
	argv[n++] = "--client_uid";
	argv[n++] = uid;
	argv[n++] = "-vvvv";
	while (args && *args && n < sizeof(argv) / sizeof(argv[0]) - 1)
		argv[n++] = (char *)*args++;
	argv[n] = NULL;

	snprintf(conf, sizeof(conf), "SOFTHSM2_CONF=%s", pk.conf);
	snprintf(module, sizeof(module), "ESDM_PKCS11_SHIM_MODULE=%s",
		 pk.softhsm);
	snprintf(login, sizeof(login), "ESDM_PKCS11_SHIM_LOG=%s", pk.login_log);
	snprintf(fail, sizeof(fail), "ESDM_PKCS11_SHIM_FAIL=%s", pk.fail);
	snprintf(repeat, sizeof(repeat), "ESDM_PKCS11_SHIM_REPEAT=%s",
		 pk.repeat);
	envp[e++] = conf;
	envp[e++] = module;
	envp[e++] = login;
	envp[e++] = fail;
	envp[e++] = repeat;
	while (env && *env && e < sizeof(envp) / sizeof(envp[0]) - 1)
		envp[e++] = (char *)*env++;
	envp[e] = NULL;

	unlink(pk.socket);
	unlink(pk.login_log);
	posix_spawn_file_actions_init(&fa);
	posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, pk.daemon_log,
					 O_WRONLY | O_CREAT | O_TRUNC, 0600);
	posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
	ret = posix_spawn(&pid, pk.daemon, &fa, NULL, argv, envp);
	posix_spawn_file_actions_destroy(&fa);

	return ret ? -1 : pid;
}

/* Start the daemon and wait for it to serve - see pk_spawn() */
static inline bool pk_start(const char *const *args, const char *const *env)
{
	char line[512];
	FILE *log;

	pk.pid = pk_spawn(args, env);
	if (pk.pid > 0 && es_ext_test_wait_socket(pk.socket))
		return true;

	printf("esdm-es-pkcs11 did not come up, its log:\n");
	log = fopen(pk.daemon_log, "re");
	while (log && fgets(line, sizeof(line), log))
		fputs(line, stdout);
	if (log)
		fclose(log);

	es_ext_test_terminate(pk.pid);
	pk.pid = 0;
	return false;
}

/*
 * Stop the daemon. Returns whether it ended cleanly on SIGTERM and removed its
 * socket.
 */
static inline bool pk_stop(void)
{
	int status;
	bool ret;

	if (pk.pid <= 0)
		return true;
	kill(pk.pid, SIGTERM);
	ret = waitpid(pk.pid, &status, 0) == pk.pid && WIFEXITED(status) &&
	      !WEXITSTATUS(status);
	pk.pid = 0;
	return ret && access(pk.socket, F_OK);
}

#endif /* _ES_PKCS11_TEST_UTIL_H */
