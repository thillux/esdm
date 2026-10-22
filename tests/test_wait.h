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

#ifndef TEST_WAIT_H
#define TEST_WAIT_H

#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/*
 * Wait for a daemon the test just forked to be ready, by watching for the path
 * it creates once it is - and for that path to be of the right kind.
 *
 * The type check is the point: a CUSE frontend creates its bind mount target as
 * an ordinary file and only then mounts the device over it, so a test waiting
 * for mere existence opens the placeholder and every ioctl fails with ENOTTY.
 *
 * This replaces a fixed one second sleep per daemon, which was both slower than
 * needed - most of a minute across the suite - and less reliable, as a loaded
 * machine can take longer and the test would then race the daemon.
 *
 * Returns 1 once the path exists, 0 if it did not appear within the timeout.
 * The caller carries on either way: the operation that follows gives a far
 * better diagnostic than a bare timeout here would.
 */
static inline int test_wait_for_type(const char *path, mode_t type,
				    unsigned int timeout_ms)
{
	/*
	 * Short enough that startup is not rounded up noticeably, long enough
	 * not to spin on a machine where the daemon needs a moment.
	 */
	static const unsigned int poll_ms = 5;
	struct timespec pause = { .tv_sec = 0,
				  .tv_nsec = poll_ms * 1000L * 1000L };
	unsigned int waited;
	struct stat sb;

	for (waited = 0; waited < timeout_ms; waited += poll_ms) {
		if (!stat(path, &sb) && (sb.st_mode & S_IFMT) == type)
			return 1;
		nanosleep(&pause, NULL);
	}

	/* One last look, so a timeout of zero still checks once */
	if (!stat(path, &sb) && (sb.st_mode & S_IFMT) == type)
		return 1;

	fprintf(stderr,
		"Test environment: %s did not become ready within %u ms\n",
		path, timeout_ms);

	return 0;
}

/* Generous: it only matters when something is wrong */
#define TEST_WAIT_TIMEOUT_MS 30000

/*
 * Wait for a daemon the test just forked to accept connections on the Unix
 * domain socket @path of @sock_type - SOCK_SEQPACKET for the RPC interfaces,
 * SOCK_STREAM for EGD.
 *
 * The socket file exists from the bind(2) on, but a connect(2) is refused
 * until the daemon listens. A test connecting at once on seeing the file -
 * with a client of its own, or one that does not retry - therefore failed now
 * and then on a loaded machine. Ready is a connection that succeeded; it is
 * closed again at once, which the daemon sees as a client that went away.
 *
 * Returns 1 once a connection succeeded, 0 if none did within the timeout.
 */
static inline int test_wait_for_listener(const char *path, int sock_type,
					 unsigned int timeout_ms)
{
	static const unsigned int poll_ms = 5;
	struct timespec pause = { .tv_sec = 0,
				  .tv_nsec = poll_ms * 1000L * 1000L };
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	unsigned int waited = 0;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	for (;;) {
		int fd = socket(AF_UNIX, sock_type | SOCK_CLOEXEC, 0);

		if (fd >= 0) {
			int ret = connect(fd, (struct sockaddr *)&addr,
					  sizeof(addr));

			close(fd);
			if (!ret)
				return 1;
		}

		if (waited >= timeout_ms)
			break;
		nanosleep(&pause, NULL);
		waited += poll_ms;
	}

	fprintf(stderr,
		"Test environment: nothing accepted connections on %s within %u ms\n",
		path, timeout_ms);

	return 0;
}

#endif /* TEST_WAIT_H */
