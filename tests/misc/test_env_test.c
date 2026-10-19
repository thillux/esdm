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
 * The helpers the tests start their daemons with, see tests/test_wait.h and
 * tests/test_env.h:
 *
 * - a daemon is ready once it accepts connections: a socket bound but not
 *   listening yet is there as a file, and refuses them - which a test
 *   connecting on seeing the file ran into on a loaded machine;
 * - the options of the sanitizers reach the daemon, what the test has for
 *   itself alone does not;
 * - a daemon that aborts - a finding of ASan or UBSan -, exits with the exit
 *   code of TSan, or crashes fails the test, one ending for SIGTERM does not.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "../test_env.h"
#include "../test_wait.h"

/* How long the socket below stays bound before it listens */
#define TEST_LISTEN_DELAY_MS 200

static void *test_listen_later(void *arg)
{
	struct timespec delay = { .tv_sec = 0,
				  .tv_nsec = TEST_LISTEN_DELAY_MS * 1000000L };
	int fd = *(int *)arg;

	nanosleep(&delay, NULL);
	CHECK(!listen(fd, 4), "cannot listen: %s", strerror(errno));

	return NULL;
}

static void test_listener(void)
{
	char dir[] = "/tmp/esdm-test-env-XXXXXX";
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	pthread_t thread;
	int fd;

	if (!mkdtemp(dir)) {
		CHECK(0, "cannot create a directory: %s", strerror(errno));
		return;
	}
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/socket", dir);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	CHECK(fd >= 0, "cannot create a socket: %s", strerror(errno));
	if (fd < 0)
		goto out;
	CHECK(!bind(fd, (struct sockaddr *)&addr, sizeof(addr)),
	      "cannot bind: %s", strerror(errno));

	/* Bound: the file is there, but nothing accepts yet */
	CHECK(test_wait_for_type(addr.sun_path, S_IFSOCK, 0),
	      "the bound socket is no socket file");
	CHECK(!test_wait_for_listener(addr.sun_path, SOCK_SEQPACKET, 20),
	      "a socket that does not listen was taken for a ready daemon");

	/* Listening a moment later, which the wait waits for */
	if (pthread_create(&thread, NULL, test_listen_later, &fd)) {
		CHECK(0, "cannot start a thread");
		goto out;
	}
	CHECK(test_wait_for_listener(addr.sun_path, SOCK_SEQPACKET,
				     TEST_WAIT_TIMEOUT_MS),
	      "the socket listening was not taken for a ready daemon");
	pthread_join(thread, NULL);

	/* A socket of another type is no daemon of the one waited for */
	CHECK(!test_wait_for_listener(addr.sun_path, SOCK_STREAM, 0),
	      "a SOCK_SEQPACKET socket accepted a SOCK_STREAM connection");

out:
	if (fd >= 0)
		close(fd);
	unlink(addr.sun_path);
	rmdir(dir);
}

/* Is @var among the variables of @envp? */
static bool test_envp_has(char *const *envp, const char *var)
{
	for (; *envp; envp++) {
		if (!strcmp(*envp, var))
			return true;
	}
	return false;
}

static void test_daemon_env(void)
{
	char *envp[TEST_ENV_MAX_VARS + 1];

	setenv("ASAN_OPTIONS", "abort_on_error=1", 1);
	setenv("UBSAN_OPTIONS", "halt_on_error=1", 1);
	setenv("TSAN_OPTIONS", "halt_on_error=0", 1);
	setenv("LD_PRELOAD", "libtest-only.so", 1);

	test_env_daemon_envp(envp, TEST_ENV_MAX_VARS + 1);

	CHECK(test_envp_has(envp, "ASAN_OPTIONS=abort_on_error=1"),
	      "ASAN_OPTIONS does not reach the daemon");
	CHECK(test_envp_has(envp, "UBSAN_OPTIONS=halt_on_error=1"),
	      "UBSAN_OPTIONS does not reach the daemon");
	CHECK(test_envp_has(envp, "TSAN_OPTIONS=halt_on_error=0"),
	      "TSAN_OPTIONS does not reach the daemon");
	CHECK(!test_envp_has(envp, "LD_PRELOAD=libtest-only.so"),
	      "LD_PRELOAD of the test reaches the daemon");
}

/* A daemon that ends with @how: an exit code >= 0, or a negative signal */
static pid_t test_daemon(int how)
{
	pid_t pid = fork();

	if (pid)
		return pid;

	if (how >= 0)
		_exit(how);

	/* As the sanitizers abort, and as a crash ends a process */
	signal(-how, SIG_DFL);
	raise(-how);
	_exit(0);
}

/* What test_env_reap_daemon() says about a daemon ending with @how */
static int test_reap(int how)
{
	pid_t pid = test_daemon(how);

	if (pid < 0) {
		CHECK(0, "cannot fork: %s", strerror(errno));
		return -1;
	}

	return test_env_reap_daemon(pid, "test daemon");
}

static void test_daemon_exit(void)
{
	CHECK_EQ(test_reap(0), 0);
	CHECK_EQ(test_reap(1), 0);
	CHECK_EQ(test_reap(-SIGTERM), 0);
	CHECK_EQ(test_reap(-SIGKILL), 0);

	CHECK_EQ(test_reap(-SIGABRT), 1);
	CHECK_EQ(test_reap(TEST_ENV_SANITIZER_EXIT), 1);
	CHECK_EQ(test_reap(-SIGSEGV), 1);
	CHECK_EQ(test_reap(-SIGBUS), 1);
}

int main(void)
{
	test_listener();
	test_daemon_env();
	test_daemon_exit();

	return common_test_result("test environment");
}
