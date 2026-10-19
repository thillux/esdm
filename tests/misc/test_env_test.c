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
 * The helpers the tests start their daemons with, see tests/test_wait.h:
 *
 * - a daemon is ready once it accepts connections: a socket bound but not
 *   listening yet is there as a file, and refuses them - which a test
 *   connecting on seeing the file ran into on a loaded machine.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
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

int main(void)
{
	test_listener();

	return common_test_result("test environment");
}
