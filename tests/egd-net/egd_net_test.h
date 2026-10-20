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
 * What the tests of the EGD network daemons share: starting a daemon with the
 * sockets it serves handed over by socket activation - bound here to a port
 * the kernel picked, so no two tests race for a port -, and speaking to it in
 * raw protocol bytes over TCP or TLS.
 */

#ifndef EGD_NET_TEST_H
#define EGD_NET_TEST_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "config.h"
#include "esdm_egd_protocol.h"
#include "esdm_tls.h"

#include "../test_env.h"

#ifndef ESDM_TEST_PKI
#error "ESDM_TEST_PKI must name the directory of the test PKI"
#endif

#define PKI(name) ESDM_TEST_PKI "/" name

/* Bound of a wait for an answer of a daemon */
#define TEST_IO_MS 10000

static int failures = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL (line %d): ", __LINE__);                \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			failures++;                                            \
		}                                                              \
	} while (0)

static inline void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = (time_t)(ms / 1000),
			       .tv_nsec = (long)(ms % 1000) * 1000000L };

	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

static inline uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * A listening TCP socket on @addr, port picked by the kernel; @port receives
 * it. -1 if the address cannot be bound - no IPv6 on the host, say.
 */
static inline int test_listener(const char *addr, uint16_t *port)
{
	struct sockaddr_storage ss;
	socklen_t len;
	int fd, one = 1;

	memset(&ss, 0, sizeof(ss));
	if (strchr(addr, ':')) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

		in6->sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, addr, &in6->sin6_addr) != 1)
			return -1;
		len = sizeof(*in6);
	} else {
		struct sockaddr_in *in4 = (struct sockaddr_in *)&ss;

		in4->sin_family = AF_INET;
		if (inet_pton(AF_INET, addr, &in4->sin_addr) != 1)
			return -1;
		len = sizeof(*in4);
	}

	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ss.ss_family == AF_INET6)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	if (bind(fd, (struct sockaddr *)&ss, len) < 0 || listen(fd, 64) < 0) {
		close(fd);
		return -1;
	}

	len = sizeof(ss);
	getsockname(fd, (struct sockaddr *)&ss, &len);
	*port = ntohs(ss.ss_family == AF_INET ?
			      ((struct sockaddr_in *)&ss)->sin_port :
			      ((struct sockaddr_in6 *)&ss)->sin6_port);
	return fd;
}

/*
 * Start @path with @argv, the @nfds descriptors of @fds handed over by socket
 * activation, its output going where the test's goes.
 */
static inline pid_t test_daemon_start(const char *path, char *const argv[],
				      const int *fds, int nfds)
{
	char *envp[TEST_ENV_MAX_VARS + 4];
	char listen_fds[32], listen_pid[32];
	size_t n;
	pid_t pid;
	int i;

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(envp, TEST_ENV_MAX_VARS + 1);
	for (n = 0; envp[n]; n++)
		;

	fflush(stdout);
	pid = fork();
	if (pid)
		return pid;

	/*
	 * The descriptors from 3 on, in order - out of the way first, as one
	 * of them may sit where another one goes.
	 */
	{
		int tmp[16];

		if (nfds > 16)
			_exit(126);
		for (i = 0; i < nfds; i++) {
			tmp[i] = fcntl(fds[i], F_DUPFD_CLOEXEC, 100);
			if (tmp[i] < 0)
				_exit(126);
		}
		for (i = 0; i < nfds; i++) {
			if (dup2(tmp[i], 3 + i) < 0)
				_exit(126);
			close(tmp[i]);
		}
	}

	if (nfds) {
		snprintf(listen_fds, sizeof(listen_fds), "LISTEN_FDS=%d", nfds);
		snprintf(listen_pid, sizeof(listen_pid), "LISTEN_PID=%d",
			 (int)getpid());
		envp[n++] = listen_fds;
		envp[n++] = listen_pid;
	}
	envp[n] = NULL;

	execve(path, argv, envp);
	_exit(127);
}

/*
 * Wait for @pid to exit, for at most @ms.
 *
 * @return its exit status, -1 if it did not exit in time - it is killed then
 */
static inline int test_daemon_wait(pid_t pid, unsigned int ms)
{
	uint64_t end = test_now_ms() + ms;
	int status;

	while (test_now_ms() < end) {
		pid_t r = waitpid(pid, &status, WNOHANG);

		if (r == pid)
			return WIFEXITED(status) ? WEXITSTATUS(status) :
						   128 + WTERMSIG(status);
		test_sleep_ms(20);
	}

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return -1;
}

static inline int test_daemon_stop(pid_t pid)
{
	if (pid <= 0)
		return -1;
	kill(pid, SIGTERM);
	return test_daemon_wait(pid, 15000);
}

/*
 * A non-blocking TCP connection to @addr:@port, from @src if given. -1 if it
 * cannot be made - not even to be refused.
 */
static inline int test_connect(const char *addr, uint16_t port,
			       const char *src)
{
	struct sockaddr_storage ss, sss;
	struct pollfd pfd;
	socklen_t len, slen = 0;
	int fd, one = 1, err = 0;

	memset(&ss, 0, sizeof(ss));
	memset(&sss, 0, sizeof(sss));
	if (strchr(addr, ':')) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		inet_pton(AF_INET6, addr, &in6->sin6_addr);
		len = sizeof(*in6);
		if (src) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&sss;

			s6->sin6_family = AF_INET6;
			inet_pton(AF_INET6, src, &s6->sin6_addr);
			slen = sizeof(*s6);
		}
	} else {
		struct sockaddr_in *in4 = (struct sockaddr_in *)&ss;

		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		inet_pton(AF_INET, addr, &in4->sin_addr);
		len = sizeof(*in4);
		if (src) {
			struct sockaddr_in *s4 = (struct sockaddr_in *)&sss;

			s4->sin_family = AF_INET;
			inet_pton(AF_INET, src, &s4->sin_addr);
			slen = sizeof(*s4);
		}
	}

	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    0);
	if (fd < 0)
		return -1;
	if (src && bind(fd, (struct sockaddr *)&sss, slen) < 0) {
		close(fd);
		return -1;
	}
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	if (connect(fd, (struct sockaddr *)&ss, len) < 0 &&
	    errno != EINPROGRESS) {
		close(fd);
		return -1;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;
	if (poll(&pfd, 1, TEST_IO_MS) != 1) {
		close(fd);
		return -1;
	}
	len = sizeof(err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (err) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * Does the peer close the plain connection within @ms? Data it still sends is
 * read and dropped.
 */
static inline bool test_fd_closed(int fd, unsigned int ms)
{
	uint64_t end = test_now_ms() + ms;
	uint8_t buf[256];

	while (test_now_ms() < end) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;

		if (poll(&pfd, 1, 50) <= 0)
			continue;
		n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
		if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR))
			return true;
	}
	return false;
}

/* Send all of @buf in plain */
static inline int test_send(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t done = 0;

	while (done < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLOUT };
		ssize_t n = send(fd, p + done, len - done,
				 MSG_NOSIGNAL | MSG_DONTWAIT);

		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (n < 0 && errno != EAGAIN)
			return -1;
		if (poll(&pfd, 1, TEST_IO_MS) != 1)
			return -1;
	}
	return 0;
}

/* Receive exactly @len bytes in plain */
static inline int test_recv(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;

		if (poll(&pfd, 1, TEST_IO_MS) != 1)
			return -1;
		n = recv(fd, p + got, len - got, MSG_DONTWAIT);
		if (n == 0)
			return -1;
		if (n < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			return -1;
		}
		got += (size_t)n;
	}
	return 0;
}

/* The PID command in plain: the PID, or -1 */
static inline long test_plain_pid(int fd)
{
	const uint8_t cmd = ESDM_EGD_CMD_GET_PID;
	char digits[32];
	uint8_t len;

	if (test_send(fd, &cmd, 1) || test_recv(fd, &len, 1) || !len ||
	    len >= sizeof(digits) || test_recv(fd, digits, len))
		return -1;
	digits[len] = '\0';
	return strtol(digits, NULL, 10);
}

#ifdef ESDM_EGD_NET_TLS

/* A TLS connection of the test, and its socket */
struct test_tls {
	int fd;
	struct esdm_tls *tls;
	struct esdm_tls_ctx *ctx;
};

static inline void test_tls_close(struct test_tls *t)
{
	esdm_tls_free(t->tls);
	esdm_tls_ctx_put(t->ctx);
	if (t->fd >= 0)
		close(t->fd);
	t->tls = NULL;
	t->ctx = NULL;
	t->fd = -1;
}

/*
 * The handshake on the connection t->fd, with the certificate @cert of the PKI
 * - NULL for none - expecting the server to be issued for @server_name, and
 * trusting the CA of the PKI and @extra_ca, NULL for none.
 *
 * @return the result of the handshake: 0, or a negative errno - @t is to be
 *	   closed either way
 */
static inline int test_tls_shake_ca(struct test_tls *t, const char *cert,
				    const char *key, const char *server_name,
				    const char *extra_ca)
{
	struct esdm_tls_config cfg;
	uint64_t end;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_files[cfg.ca_files_num++] = PKI("ca.crt");
	if (extra_ca)
		cfg.ca_files[cfg.ca_files_num++] = extra_ca;
	ret = esdm_tls_ctx_alloc(false, &cfg, &t->ctx);
	if (ret)
		return ret;
	ret = esdm_tls_alloc(t->ctx, t->fd, server_name, &t->tls);
	if (ret)
		return ret;

	end = test_now_ms() + TEST_IO_MS;
	while ((ret = esdm_tls_handshake(t->tls)) == -EAGAIN) {
		if (test_now_ms() >= end)
			return -ETIMEDOUT;
		esdm_tls_wait(t->tls, 100);
	}

	return ret;
}

/* The handshake, trusting the CA of the PKI - see test_tls_shake_ca() */
static inline int test_tls_shake(struct test_tls *t, const char *cert,
				 const char *key, const char *server_name)
{
	return test_tls_shake_ca(t, cert, key, server_name, NULL);
}

/* Connect to @port of 127.0.0.1, and shake hands - see test_tls_shake() */
static inline int test_tls_open(struct test_tls *t, uint16_t port,
				const char *cert, const char *key,
				const char *server_name)
{
	memset(t, 0, sizeof(*t));
	t->fd = test_connect("127.0.0.1", port, NULL);
	if (t->fd < 0)
		return -ECONNREFUSED;

	return test_tls_shake(t, cert, key, server_name);
}

static inline int test_tls_send(struct test_tls *t, const void *buf,
				size_t len)
{
	const uint8_t *p = buf;
	uint64_t end = test_now_ms() + TEST_IO_MS;
	size_t done = 0;
	int ret;

	while (done < len) {
		ssize_t n = esdm_tls_send(t->tls, p + done, len - done);

		if (n > 0) {
			done += (size_t)n;
			continue;
		}
		if (n != -EAGAIN || test_now_ms() >= end)
			return n ? (int)n : -EIO;
		esdm_tls_wait(t->tls, 100);
	}
	while ((ret = esdm_tls_flush(t->tls)) == -EAGAIN) {
		if (test_now_ms() >= end)
			return -ETIMEDOUT;
		esdm_tls_wait(t->tls, 100);
	}
	return ret;
}

/* @return 0 when all of @len came, -EPIPE at the end, a negative errno */
static inline int test_tls_recv(struct test_tls *t, void *buf, size_t len,
				unsigned int ms)
{
	uint8_t *p = buf;
	uint64_t end = test_now_ms() + ms;
	size_t got = 0;

	while (got < len) {
		ssize_t n = esdm_tls_recv(t->tls, p + got, len - got);

		if (n > 0) {
			got += (size_t)n;
			continue;
		}
		if (n == 0)
			return -EPIPE;
		if (n != -EAGAIN)
			return (int)n;
		if (test_now_ms() >= end)
			return -ETIMEDOUT;
		esdm_tls_wait(t->tls, 50);
	}
	return 0;
}

/* The PID command over TLS: the PID, or a negative errno */
static inline long test_tls_pid(struct test_tls *t)
{
	const uint8_t cmd = ESDM_EGD_CMD_GET_PID;
	char digits[32];
	uint8_t len;
	int ret;

	ret = test_tls_send(t, &cmd, 1);
	if (!ret)
		ret = test_tls_recv(t, &len, 1, TEST_IO_MS);
	if (!ret && (!len || len >= sizeof(digits)))
		ret = -EPROTO;
	if (!ret)
		ret = test_tls_recv(t, digits, len, TEST_IO_MS);
	if (ret)
		return ret;
	digits[len] = '\0';
	return strtol(digits, NULL, 10);
}

/* Does the server end the TLS connection within @ms? */
static inline bool test_tls_closed(struct test_tls *t, unsigned int ms)
{
	uint8_t byte;
	int ret = test_tls_recv(t, &byte, 1, ms);

	return ret && ret != -ETIMEDOUT;
}

#endif /* ESDM_EGD_NET_TLS */

/* Write @src to @dst, replacing it by a rename - as a rotation does */
static inline int test_install(const char *src, const char *dst)
{
	char tmp[4096], buf[8192];
	int in, out;
	ssize_t n;

	snprintf(tmp, sizeof(tmp), "%s.new", dst);
	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -1;
	out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, (size_t)n) != n) {
			n = -1;
			break;
		}
	}
	close(in);
	close(out);
	if (n < 0)
		return -1;
	return rename(tmp, dst);
}

#endif /* EGD_NET_TEST_H */
