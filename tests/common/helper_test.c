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
 * Tests for common/helper.c and the macros of common/helper.h.
 *
 * The interesting part is esdm_safe_read()/esdm_safe_write(), the short
 * read/write loops every pipe and socket consumer in the tree relies on. Both
 * have to tell three easily confused outcomes apart: a partial transfer to be
 * resumed, an end of file, and a genuine error reported as a negative errno.
 * EINTR belongs to the first group and is provoked here with a real signal.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common_test.h"
#include "config.h"
#include "helper.h"

static volatile sig_atomic_t signals_seen;

static void sigusr1_handler(int sig)
{
	(void)sig;
	signals_seen++;
}

static void test_online_nodes(void)
{
	uint32_t nodes = esdm_online_nodes();
	unsigned int i;

	CHECK(nodes >= 1, "esdm_online_nodes returned %u", nodes);
	CHECK(nodes <= THREADING_MAX_WORKER_THREADS,
	      "esdm_online_nodes returned %u, more than the %u worker threads",
	      nodes, (unsigned int)THREADING_MAX_WORKER_THREADS);

	/* The value is cached, so it must not change between calls */
	CHECK_EQ(esdm_online_nodes(), nodes);

	/* The node a caller is steered to always has to be a valid index */
	for (i = 0; i < 10000; i++) {
		uint32_t node = esdm_curr_node();

		if (node >= nodes) {
			CHECK(0, "esdm_curr_node returned %u for %u nodes",
			      node, nodes);
			break;
		}
	}
}

/* Whole seconds of @clk, -1 if it cannot be read */
static long long clock_sec(clockid_t clk)
{
	struct timespec ts;

	if (clock_gettime(clk, &ts))
		return -1;
	return (long long)ts.tv_sec;
}

static int write_file(const char *path, const char *text)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t len = (ssize_t)strlen(text);
	int ret = 0;

	if (fd < 0)
		return -errno;
	if (write(fd, text, (size_t)len) != len)
		ret = -errno;
	close(fd);
	return ret;
}

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

/* The suspend played in a time namespace, in seconds */
#define TEST_SUSPENDED_SEC 100000

/*
 * In a time namespace whose CLOCK_BOOTTIME runs TEST_SUSPENDED_SEC ahead of its
 * CLOCK_MONOTONIC - which is what a suspend of that long looks like - does
 * esdm_monotonic_now() count the suspended time? It reads the time spent
 * suspended once per second, so the answer may take that long.
 *
 * @return 0 if it does, 1 if not, 77 if no time namespace can be had here
 */
static int monotonic_now_suspended(void)
{
	char map[64];
	uid_t uid = geteuid();
	gid_t gid = getegid();
	int status, i;
	pid_t pid;

	/* A time namespace is owned by a user namespace, created along */
	if (unshare(CLONE_NEWUSER | CLONE_NEWTIME))
		return 77;

	snprintf(map, sizeof(map), "0 %u 1", (unsigned int)uid);
	if (write_file("/proc/self/setgroups", "deny") ||
	    write_file("/proc/self/uid_map", map))
		return 77;
	snprintf(map, sizeof(map), "0 %u 1", (unsigned int)gid);
	if (write_file("/proc/self/gid_map", map))
		return 77;

	/* Only before the first process enters the namespace */
	snprintf(map, sizeof(map), "boottime %d 0", TEST_SUSPENDED_SEC);
	if (write_file("/proc/self/timens_offsets", map))
		return 77;

	/* The caller stays outside, its children enter */
	pid = fork();
	if (pid < 0)
		return 77;
	if (!pid) {
		for (i = 0; i < 30; i++) {
			struct timespec pause = { .tv_sec = 0,
						  .tv_nsec =
							  100 * 1000 * 1000 };
			long long mono = clock_sec(CLOCK_MONOTONIC);

			if (esdm_monotonic_now() - mono >=
			    TEST_SUSPENDED_SEC - 1)
				_exit(0);
			nanosleep(&pause, NULL);
		}
		_exit(1);
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

/*
 * esdm_monotonic_now() keeps the time on CLOCK_BOOTTIME: the reseed interval
 * of the DRNGs is timed with it, and a seed taken before a suspend must not
 * serve on for a full interval after the resume.
 */
static void test_monotonic_now(void)
{
	long long boot, now, later;
	int status;
	pid_t pid;

	boot = clock_sec(CLOCK_BOOTTIME);
	now = esdm_monotonic_now();
	later = esdm_monotonic_now();

	/* The coarse clock it is read from lags by less than a tick */
	CHECK(now >= boot - 1 && now <= boot + 1,
	      "esdm_monotonic_now() returned %lld, CLOCK_BOOTTIME is at %lld",
	      now, boot);
	CHECK(later >= now, "esdm_monotonic_now() went back from %lld to %lld",
	      now, later);

	/* Namespaces of a process of their own, which they are kept to */
	pid = fork();
	if (pid < 0) {
		CHECK(0, "cannot fork: %s", strerror(errno));
		return;
	}
	if (!pid)
		_exit(monotonic_now_suspended());

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
		CHECK(0, "the suspend check did not complete");
		return;
	}

	if (WEXITSTATUS(status) == 77) {
		printf("esdm_monotonic_now: suspend not covered, no time namespace to be had\n");
		return;
	}

	CHECK(!WEXITSTATUS(status),
	      "esdm_monotonic_now() does not count %d seconds spent suspended",
	      TEST_SUSPENDED_SEC);
}

static void test_helper_macros(void)
{
	static const int array[7] = { 0 };
	uint8_t buf[16] __aligned(8);

	CHECK_EQ(ARRAY_SIZE(array), 7);

	CHECK_EQ(aligned(buf, 7), 1);
	CHECK_EQ(aligned(buf + 1, 7), 0);
	CHECK_EQ(aligned(buf + 4, 3), 1);
	CHECK_EQ(aligned(buf + 4, 7), 0);
}

static void test_safe_read_write_roundtrip(void)
{
	uint8_t out[512], in[512];
	int fds[2];
	unsigned int i;

	for (i = 0; i < sizeof(out); i++)
		out[i] = (uint8_t)(i * 11 + 5);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	CHECK_EQ(esdm_safe_write(fds[1], out, sizeof(out)),
		 (ssize_t)sizeof(out));
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));

	/* A zero-length transfer is a no-op rather than an error */
	CHECK_EQ(esdm_safe_write(fds[1], out, 0), 0);
	CHECK_EQ(esdm_safe_read(fds[0], in, 0), 0);

	close(fds[0]);
	close(fds[1]);
}

struct chunked_writer {
	int fd;
	const uint8_t *data;
	size_t len;
	size_t chunk;
};

static void *chunked_writer(void *arg)
{
	struct chunked_writer *w = arg;
	size_t off;

	for (off = 0; off < w->len; off += w->chunk) {
		size_t this = w->len - off < w->chunk ? w->len - off : w->chunk;

		if (write(w->fd, w->data + off, this) < 0)
			break;
		usleep(1000);
	}

	close(w->fd);
	return NULL;
}

static void test_safe_read_partial(void)
{
	uint8_t out[4096], in[4096];
	struct chunked_writer w;
	pthread_t tid;
	int fds[2];
	unsigned int i;

	for (i = 0; i < sizeof(out); i++)
		out[i] = (uint8_t)(i * 7 + 1);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	w.fd = fds[1];
	w.data = out;
	w.len = sizeof(out);
	w.chunk = 137;

	CHECK_EQ(pthread_create(&tid, NULL, chunked_writer, &w), 0);

	/* The data arrives in many small chunks - all of it has to be assembled */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));

	pthread_join(tid, NULL);
	close(fds[0]);
}

static void test_safe_read_eof(void)
{
	uint8_t out[16], in[128];
	int fds[2];

	memset(out, 0x5a, sizeof(out));

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	CHECK_EQ(write(fds[1], out, sizeof(out)), (ssize_t)sizeof(out));
	close(fds[1]);

	/* Asking for more than the peer sent returns what arrived before EOF */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(out));
	CHECK_MEM_EQ(in, out, sizeof(out));

	/* Reading past the end of file yields zero, not an error */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), 0);

	close(fds[0]);
}

struct drainer {
	int fd;
	size_t len;
};

static void *drainer(void *arg)
{
	struct drainer *d = arg;
	uint8_t buf[1024];
	size_t done = 0;

	while (done < d->len) {
		ssize_t r = read(d->fd, buf, sizeof(buf));

		if (r <= 0)
			break;
		done += (size_t)r;
	}

	close(d->fd);
	return NULL;
}

static void test_safe_write_partial(void)
{
	/* Larger than the default pipe capacity, so write() must go short */
	static uint8_t out[512 * 1024];
	struct drainer d;
	pthread_t tid;
	int fds[2];

	memset(out, 0x3c, sizeof(out));

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	d.fd = fds[0];
	d.len = sizeof(out);

	CHECK_EQ(pthread_create(&tid, NULL, drainer, &d), 0);

	CHECK_EQ(esdm_safe_write(fds[1], out, sizeof(out)),
		 (ssize_t)sizeof(out));

	close(fds[1]);
	pthread_join(tid, NULL);
}

struct interrupter {
	pthread_t target;
	int fd;
	const uint8_t *data;
	size_t len;
};

static void *interrupter(void *arg)
{
	struct interrupter *in = arg;
	unsigned int i;
	sigset_t block;

	/* Keep the signals aimed at the reader from landing here */
	sigemptyset(&block);
	sigaddset(&block, SIGUSR1);
	pthread_sigmask(SIG_BLOCK, &block, NULL);

	for (i = 0; i < 5; i++) {
		usleep(20000);
		pthread_kill(in->target, SIGUSR1);
	}

	usleep(20000);
	if (write(in->fd, in->data, in->len) < 0) {
		/* reported by the reader's short result */
	}
	close(in->fd);
	return NULL;
}

static void test_safe_read_eintr(void)
{
	uint8_t out[64], in[64];
	struct interrupter arg;
	struct sigaction sa, old;
	pthread_t tid;
	int fds[2];

	memset(out, 0xa7, sizeof(out));

	/* No SA_RESTART: the blocked read() has to come back with EINTR */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	CHECK_EQ(sigaction(SIGUSR1, &sa, &old), 0);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		sigaction(SIGUSR1, &old, NULL);
		return;
	}

	arg.target = pthread_self();
	arg.fd = fds[1];
	arg.data = out;
	arg.len = sizeof(out);
	signals_seen = 0;

	CHECK_EQ(pthread_create(&tid, NULL, interrupter, &arg), 0);

	/*
	 * The read blocks while the signals arrive. Every one of them makes
	 * read() fail with EINTR, which esdm_safe_read has to retry instead of
	 * reporting - otherwise this returns -EINTR and loses the data.
	 */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), (ssize_t)sizeof(in));
	CHECK_MEM_EQ(in, out, sizeof(out));
	CHECK(signals_seen > 0, "no signal was delivered to the reader");

	pthread_join(tid, NULL);
	close(fds[0]);
	sigaction(SIGUSR1, &old, NULL);
}

static void test_safe_read_write_errors(void)
{
	uint8_t buf[16];
	int fds[2];

	memset(buf, 0, sizeof(buf));

	/* A bad descriptor is reported as a negative errno */
	CHECK_EQ(esdm_safe_read(-1, buf, sizeof(buf)), -EBADF);
	CHECK_EQ(esdm_safe_write(-1, buf, sizeof(buf)), -EBADF);

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	/* Writing into a pipe whose reader is gone reports EPIPE */
	signal(SIGPIPE, SIG_IGN);
	close(fds[0]);
	CHECK_EQ(esdm_safe_write(fds[1], buf, sizeof(buf)), -EPIPE);
	close(fds[1]);
	signal(SIGPIPE, SIG_DFL);
}

/*
 * An error after part of the buffer was transferred must not swallow what was
 * transferred - the data is gone from the descriptor (or sent) either way.
 * Like read(2) and write(2), the partial count is reported and the error is
 * left for the next call. A non-blocking pipe produces exactly that sequence:
 * a short transfer followed by EAGAIN.
 */
static void test_safe_read_write_partial_error(void)
{
	uint8_t out[2 * 4096], in[2 * 4096];
	ssize_t capacity, ret;
	int fds[2];

	memset(out, 0x5a, sizeof(out));

	if (pipe(fds) < 0) {
		CHECK(0, "pipe() failed: %s", strerror(errno));
		return;
	}

	/* Shrink the pipe below the buffer size (a page at the least) */
	capacity = fcntl(fds[1], F_SETPIPE_SZ, 4096);
	if (capacity < 0)
		capacity = fcntl(fds[1], F_GETPIPE_SZ);
	if (capacity <= 0 || (size_t)capacity >= sizeof(out)) {
		CHECK(0, "cannot size the pipe below %zu bytes", sizeof(out));
		goto out;
	}

	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0) {
		CHECK(0, "cannot make the pipe non-blocking: %s",
		      strerror(errno));
		goto out;
	}

	/* The pipe takes what fits, then the next write fails with EAGAIN */
	ret = esdm_safe_write(fds[1], out, sizeof(out));
	CHECK_EQ(ret, capacity);

	/* The pipe hands out what it holds, then the next read fails */
	ret = esdm_safe_read(fds[0], in, sizeof(in));
	CHECK_EQ(ret, capacity);
	if (ret > 0)
		CHECK_MEM_EQ(in, out, (size_t)ret);

	/* With nothing transferred, the error itself is reported */
	CHECK_EQ(esdm_safe_read(fds[0], in, sizeof(in)), -EAGAIN);

out:
	close(fds[0]);
	close(fds[1]);
}

/*
 * Whether a descriptor still is the file at its path: the esdm-server takes the
 * lock of its PID file only for good when the path still names the file it
 * opened. One its previous holder removed meanwhile, or replaced, is not.
 */
static void test_fd_at_path(void)
{
	char dir[] = "/tmp/esdm-helper-test-XXXXXX";
	char path[64], other_path[64];
	int fd, other_fd;

	CHECK_EQ(esdm_fd_at_path(-1, "/"), -EBADF);

	if (!mkdtemp(dir)) {
		CHECK(0, "mkdtemp failed: %s", strerror(errno));
		return;
	}
	snprintf(path, sizeof(path), "%s/file", dir);
	snprintf(other_path, sizeof(other_path), "%s/other", dir);

	fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0) {
		CHECK(0, "cannot create %s: %s", path, strerror(errno));
		rmdir(dir);
		return;
	}
	CHECK_EQ(esdm_fd_at_path(fd, NULL), -EINVAL);

	/* The file it was opened at */
	CHECK_EQ(esdm_fd_at_path(fd, path), 1);

	/* Another file is not */
	other_fd = open(other_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	CHECK(other_fd >= 0, "cannot create %s: %s", other_path,
	      strerror(errno));
	CHECK_EQ(esdm_fd_at_path(fd, other_path), 0);

	/* A symbolic link at the path is not the file it points to */
	unlink(other_path);
	CHECK_EQ(symlink(path, other_path), 0);
	CHECK_EQ(esdm_fd_at_path(fd, other_path), 0);
	unlink(other_path);

	/* Removed after it was opened, the file is at no path */
	CHECK_EQ(unlink(path), 0);
	CHECK_EQ(esdm_fd_at_path(fd, path), 0);

	/* Nor once another file was created in its place */
	if (other_fd >= 0)
		close(other_fd);
	other_fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(other_fd >= 0, "cannot create %s again: %s", path,
	      strerror(errno));
	CHECK_EQ(esdm_fd_at_path(fd, path), 0);
	if (other_fd >= 0) {
		CHECK_EQ(esdm_fd_at_path(other_fd, path), 1);
		close(other_fd);
	}

	/* A path below a file names nothing */
	snprintf(other_path, sizeof(other_path), "%s/file/below", dir);
	CHECK_EQ(esdm_fd_at_path(fd, other_path), 0);

	close(fd);
	unlink(path);
	rmdir(dir);
}

/* A segment status as IPC_STAT reports it, with only the uids of interest */
static struct shmid_ds shm_with(uid_t cuid, uid_t uid)
{
	struct shmid_ds buf;

	memset(&buf, 0, sizeof(buf));
	buf.shm_perm.cuid = cuid;
	buf.shm_perm.uid = uid;

	return buf;
}

/* Bind a Unix socket at @path, returning its descriptor or -1 */
static int bind_socket(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * A caller whose real uid is not its effective one runs with privileges its
 * user does not have, like a set-uid program: the user could have created the
 * segment, which is not taken for the server's. Only root can switch the real
 * uid alone, and does so in a child, as there is no way back.
 */
static void test_shm_created_by_server_privileged(uid_t other)
{
	struct shmid_ds buf;
	pid_t pid;
	int status;

	if (geteuid()) {
		printf("esdm_shm_created_by_server: privileged caller not covered, needs root\n");
		return;
	}

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork failed: %s", strerror(errno));
		return;
	}

	if (pid == 0) {
		int failed = 0;

		if (setresuid(other, 0, 0) || getuid() != other)
			_exit(2);

		/* The invoking user's segment is not the server's */
		buf = shm_with(other, other);
		if (esdm_shm_created_by_server(&buf, NULL))
			failed |= 4;

		/* Root's still is */
		buf = shm_with(0, 0);
		if (!esdm_shm_created_by_server(&buf, NULL))
			failed |= 8;

		_exit(failed);
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status)) {
		CHECK(0, "the privileged caller did not terminate normally");
		return;
	}

	switch (WEXITSTATUS(status)) {
	case 0:
		break;
	case 2:
		printf("esdm_shm_created_by_server: privileged caller not covered, cannot switch the real uid to %u\n",
		       (unsigned int)other);
		break;
	default:
		CHECK(!(WEXITSTATUS(status) & 4),
		      "a caller of real uid %u and effective uid 0 accepts the segment of uid %u",
		      (unsigned int)other, (unsigned int)other);
		CHECK(!(WEXITSTATUS(status) & 8),
		      "a caller of real uid %u and effective uid 0 rejects the segment of root",
		      (unsigned int)other);
	}
}

/*
 * Which status segments a client takes for the server's: those of root, of the
 * owner of the server's socket and of its own uid - not one another user
 * created while no server ran, whatever it was handed over to afterwards.
 */
static void test_shm_created_by_server(void)
{
	uid_t self = getuid();
	/* A uid that is neither root nor the caller */
	uid_t other = (self == 4242) ? 4243 : 4242;
	char dir[] = "/tmp/esdm-helper-test-XXXXXX";
	char sock_path[64], file_path[64];
	struct shmid_ds buf;
	int fd;

	CHECK(!esdm_shm_created_by_server(NULL, NULL),
	      "no segment status is accepted");

	buf = shm_with(0, 0);
	CHECK(esdm_shm_created_by_server(&buf, NULL),
	      "the segment of root is not accepted");

	buf = shm_with(self, self);
	CHECK(esdm_shm_created_by_server(&buf, NULL),
	      "the segment of the caller's own uid is not accepted");

	buf = shm_with(other, other);
	CHECK(!esdm_shm_created_by_server(&buf, NULL),
	      "the segment of uid %u is accepted", (unsigned int)other);

	/* Handing it to root afterwards does not make it the server's */
	buf = shm_with(other, 0);
	CHECK(!esdm_shm_created_by_server(&buf, NULL),
	      "the segment uid %u created and handed to root is accepted",
	      (unsigned int)other);

	/* Nor does a segment of root handed to somebody else stay trusted */
	buf = shm_with(0, other);
	CHECK(!esdm_shm_created_by_server(&buf, NULL),
	      "the segment of root handed to uid %u is accepted",
	      (unsigned int)other);

	if (!mkdtemp(dir)) {
		CHECK(0, "mkdtemp failed: %s", strerror(errno));
		return;
	}
	snprintf(sock_path, sizeof(sock_path), "%s/socket", dir);
	snprintf(file_path, sizeof(file_path), "%s/file", dir);

	/* A socket that is not there names nobody */
	buf = shm_with(other, other);
	CHECK(!esdm_shm_created_by_server(&buf, sock_path),
	      "a missing socket names uid %u", (unsigned int)other);

	fd = bind_socket(sock_path);
	CHECK(fd >= 0, "cannot bind %s: %s", sock_path, strerror(errno));

	/* The socket's owner is the server, which is the caller here */
	CHECK(!esdm_shm_created_by_server(&buf, sock_path),
	      "the socket of uid %u names uid %u", (unsigned int)self,
	      (unsigned int)other);

	/* Only root can hand the socket to another uid, which then counts */
	if (fd >= 0 && !geteuid() && !chown(sock_path, other, other)) {
		CHECK(esdm_shm_created_by_server(&buf, sock_path),
		      "the segment of the socket's owner %u is not accepted",
		      (unsigned int)other);

		/* A file in its place is no server's socket */
		close(open(file_path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600));
		CHECK_EQ(chown(file_path, other, other), 0);
		CHECK(!esdm_shm_created_by_server(&buf, file_path),
		      "a plain file names uid %u", (unsigned int)other);
		unlink(file_path);
	} else {
		printf("esdm_shm_created_by_server: socket owner of another uid not covered, needs root\n");
	}

	if (fd >= 0)
		close(fd);
	unlink(sock_path);
	rmdir(dir);

	test_shm_created_by_server_privileged(other);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/* No-op unless the tree was configured with memory-debug */
	may_enable_memory_debugging();

	test_online_nodes();
	test_monotonic_now();
	test_helper_macros();
	test_safe_read_write_roundtrip();
	test_safe_read_partial();
	test_safe_read_eof();
	test_safe_write_partial();
	test_safe_read_eintr();
	test_safe_read_write_errors();
	test_safe_read_write_partial_error();
	test_fd_at_path();
	test_shm_created_by_server();

	return common_test_result("helper");
}
