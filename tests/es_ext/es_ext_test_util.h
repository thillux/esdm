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
 * What the tests of the external entropy sources share: starting providers -
 * provider programs of the test - and waiting for them, and finding a source
 * in the JSON status of the ESDM.
 */

#ifndef _ES_EXT_TEST_UTIL_H
#define _ES_EXT_TEST_UTIL_H

#include <json-c/json.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static inline void es_ext_test_sleep_ms(long ms)
{
	const struct timespec ts = { .tv_sec = ms / 1000,
				     .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/*
 * Start @argv with the environment @envp - an empty one for NULL, as the test
 * suite runs its daemons
 */
static inline pid_t es_ext_test_spawn(char *const argv[], char *const envp[])
{
	char *const empty[] = { NULL };
	pid_t pid;

	if (posix_spawn(&pid, argv[0], NULL, NULL, argv, envp ? envp : empty))
		return -1;
	return pid;
}

/* The exit status of @pid, 128 if it did not exit, -1 if it is no child */
static inline int es_ext_test_wait(pid_t pid)
{
	int status;

	if (waitpid(pid, &status, 0) != pid)
		return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

/* Terminate @pid and reap it - killed if it does not end within 10 seconds */
static inline void es_ext_test_terminate(pid_t pid)
{
	unsigned int i;
	int status;

	if (pid <= 0)
		return;
	kill(pid, SIGTERM);
	for (i = 0; i < 1000; i++) {
		if (waitpid(pid, &status, WNOHANG) == pid)
			return;
		es_ext_test_sleep_ms(10);
	}
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
}

/*
 * Does a socket accept connections on @path?
 *
 * The file of a socket appears with its bind(2), before the listen(2), and a
 * connect(2) in between is refused - on a loaded machine often enough to fail
 * a test that took the file for the provider being up. /proc/net/unix tells a
 * listening socket by its flags (__SO_ACCEPTCON). Without it, the file is all
 * there is to go by.
 */
static inline bool es_ext_test_socket_ready(const char *path)
{
	char line[512], sock_path[256];
	unsigned int flags;
	struct stat sb;
	bool ready = false;
	FILE *f;

	if (lstat(path, &sb) || !S_ISSOCK(sb.st_mode))
		return false;

	f = fopen("/proc/net/unix", "re");
	if (!f)
		return true;

	while (!ready && fgets(line, sizeof(line), f)) {
		/* Num RefCount Protocol Flags Type St Inode Path */
		if (sscanf(line, "%*s %*x %*x %x %*x %*x %*u %255s", &flags,
			   sock_path) != 2)
			continue;
		ready = (flags & 0x10000) && !strcmp(sock_path, path);
	}

	fclose(f);
	return ready;
}

/* Wait up to 10 seconds for a socket to accept connections on @path */
static inline bool es_ext_test_wait_socket(const char *path)
{
	unsigned int i;

	for (i = 0; i < 500; i++) {
		if (es_ext_test_socket_ready(path))
			return true;
		es_ext_test_sleep_ms(20);
	}

	return false;
}

/*
 * Start the provider program @provider - one of the test source, see
 * es_ext_test_plugin.c - on @socket for clients of the user of the test - or,
 * run as root, for the esdm-server, root and nobody - with the arguments
 * @extra in addition (NULL terminated, NULL for none) and the settings
 * @settings of the test source (see ES_EXT_TEST_PLUGIN_ENV, NULL for none).
 * Returns once the socket is there.
 *
 * @return the pid of the provider, -1 if it does not come up
 */
static inline pid_t es_ext_test_serve(const char *provider, const char *socket,
				      const char *const *extra,
				      const char *settings)
{
	char *argv[32], uid[16], env[1100];
	char *envp[2] = { NULL, NULL };
	unsigned int n = 0;
	pid_t pid;

	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	argv[n++] = (char *)provider;
	argv[n++] = "--socket";
	argv[n++] = (char *)socket;
	if (getuid()) {
		argv[n++] = "--client_uid";
		argv[n++] = uid;
	}
	while (extra && *extra && n < sizeof(argv) / sizeof(argv[0]) - 1)
		argv[n++] = (char *)*extra++;
	argv[n] = NULL;

	if (settings) {
		snprintf(env, sizeof(env), "ESDM_ES_EXT_TEST_PLUGIN=%s",
			 settings);
		envp[0] = env;
	}

	unlink(socket);
	pid = es_ext_test_spawn(argv, envp);
	if (pid <= 0)
		return -1;
	if (!es_ext_test_wait_socket(socket)) {
		es_ext_test_terminate(pid);
		return -1;
	}

	return pid;
}

/*
 * The object of the entropy source whose member @key is @val in the
 * "entropy_sources" of the JSON status @root, NULL if there is none
 */
static inline struct json_object *
es_ext_test_status_find(struct json_object *root, const char *key,
			const char *val)
{
	struct json_object *sources, *es, *member;
	size_t i;

	if (!json_object_object_get_ex(root, "entropy_sources", &sources))
		return NULL;

	for (i = 0; i < json_object_array_length(sources); i++) {
		es = json_object_array_get_idx(sources, i);
		if (json_object_object_get_ex(es, key, &member) &&
		    json_object_is_type(member, json_type_string) &&
		    !strcmp(json_object_get_string(member), val))
			return es;
	}

	return NULL;
}

/* The external entropy source of the instance name @instance */
static inline struct json_object *es_ext_test_status_es(struct json_object *root,
							const char *instance)
{
	return es_ext_test_status_find(root, "instance", instance);
}

#endif /* _ES_EXT_TEST_UTIL_H */
