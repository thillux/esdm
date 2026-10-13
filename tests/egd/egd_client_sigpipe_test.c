/*
 * SIGPIPE discipline of the EGD client library
 *
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
 * A peer closing between the client's poll for writability and its write.
 *
 * The client cannot send with MSG_NOSIGNAL, see the syscall discipline in its
 * header, so that write raises SIGPIPE - which must neither kill the process
 * nor be left for the caller to find. The window is hit on purpose: the build
 * wraps the client's write(2), which closes the peer right before writing, and
 * its sigtimedwait(2), which is counted - OpenSSH's sandbox kills for it, so it
 * may only be called where SIGPIPE is not ignored. Run with the default
 * disposition, a client that gets this wrong kills the test.
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
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_egd_client.h"

#define TEST_TIMEOUT_MS 1000

static char tmpdir[] = "/tmp/esdm-egd-sigpipe-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];

static int ret = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

/* Peer end to close on the client's next write, -1 for none. */
static int hook_close_fd = -1;
static unsigned int hook_epipe, hook_sigtimedwait;

ssize_t __real_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count);
ssize_t __wrap_write(int fd, const void *buf, size_t count)
{
	ssize_t rc;

	if (hook_close_fd >= 0) {
		close(hook_close_fd);
		hook_close_fd = -1;
	}

	rc = __real_write(fd, buf, count);
	if (rc < 0 && errno == EPIPE)
		hook_epipe++;

	return rc;
}

int __real_sigtimedwait(const sigset_t *set, siginfo_t *info,
			const struct timespec *timeout);
int __wrap_sigtimedwait(const sigset_t *set, siginfo_t *info,
			const struct timespec *timeout);
int __wrap_sigtimedwait(const sigset_t *set, siginfo_t *info,
			const struct timespec *timeout)
{
	hook_sigtimedwait++;

	return __real_sigtimedwait(set, info, timeout);
}

static int test_listen(void)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    listen(fd, 4) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * @caller_blocks: SIGPIPE is blocked by the caller
 * @ignored: SIGPIPE is ignored when the client connects
 * @takes: whether the client is to take the SIGPIPE off itself
 */
static void test_vanish(const char *name, bool caller_blocks, bool ignored,
			bool takes)
{
	const struct timespec nowait = { 0, 0 };
	struct esdm_egd_client *client = NULL;
	sigset_t sigpipe, pending;
	pid_t pid = 0;
	int lfd, peer, rc;

	printf("EGD client SIGPIPE: %s\n", name);

	sigemptyset(&sigpipe);
	sigaddset(&sigpipe, SIGPIPE);

	lfd = test_listen();
	if (lfd < 0) {
		CHECK(0, "cannot listen on %s: %s", sockpath, strerror(errno));
		return;
	}

	if (ignored)
		signal(SIGPIPE, SIG_IGN);

	rc = esdm_egd_client_alloc(&client, sockpath, TEST_TIMEOUT_MS);
	peer = accept(lfd, NULL, NULL);

	/* Nobody to reconnect to, so the retry fails at once. */
	close(lfd);
	unlink(sockpath);

	if (rc || peer < 0) {
		CHECK(0, "the client did not connect: %d", rc);
		if (peer >= 0)
			close(peer);
		esdm_egd_client_free(client);
		signal(SIGPIPE, SIG_DFL);
		return;
	}

	if (caller_blocks)
		pthread_sigmask(SIG_BLOCK, &sigpipe, NULL);

	hook_epipe = 0;
	hook_sigtimedwait = 0;
	hook_close_fd = peer;

	rc = esdm_egd_client_get_pid(client, &pid);

	CHECK(rc < 0, "a request to a vanished peer succeeded");
	CHECK(hook_epipe == 1, "the peer did not vanish under the write");
	CHECK(hook_sigtimedwait == (takes ? 1 : 0),
	      "the client called sigtimedwait %u times, expected %u",
	      hook_sigtimedwait, takes ? 1 : 0);

	if (caller_blocks) {
		/* The caller's to collect, mixed up with any of its own. */
		sigpending(&pending);
		CHECK(sigismember(&pending, SIGPIPE),
		      "the client took a SIGPIPE the caller blocked");
		__real_sigtimedwait(&sigpipe, NULL, &nowait);
		pthread_sigmask(SIG_UNBLOCK, &sigpipe, NULL);
	}

	/* An ignored one is discarded once it is unblocked. */
	if (ignored)
		signal(SIGPIPE, SIG_DFL);

	esdm_egd_client_free(client);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	setvbuf(stdout, NULL, _IONBF, 0);
	alarm(60);

	/* The default disposition - a SIGPIPE let through ends the test. */
	signal(SIGPIPE, SIG_DFL);

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	test_vanish("default disposition", false, false, true);
	test_vanish("blocked by the caller", true, false, false);
	test_vanish("ignored, as in OpenSSH", false, true, false);

	rmdir(tmpdir);

	printf("EGD client SIGPIPE: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
