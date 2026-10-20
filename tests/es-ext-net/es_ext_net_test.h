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
 * What the tests of the external entropy sources on the network share: TCP
 * sockets on loopback, bound to a port the kernel picked - so that no two
 * tests race for a port -, the daemons under test, and a client of them.
 *
 * The test PKI is the one of the EGD network tests, tests/egd-net/pki.
 */

#ifndef ES_EXT_NET_TEST_H
#define ES_EXT_NET_TEST_H

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_dtls.h"
#include "esdm_es_ext_proto.h"
#include "esdm_tls.h"

#include "../test_env.h"

/* Bound of a wait for an answer of a daemon */
#define TEST_IO_MS 10000

#ifndef ESDM_TEST_PKI
#error "ESDM_TEST_PKI must name the directory of the test PKI"
#endif

#define PKI(name) ESDM_TEST_PKI "/" name

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

/* @addr with port @port into @ss; the size of the address */
static inline socklen_t test_sockaddr(const char *addr, uint16_t port,
				      struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	if (strchr(addr, ':')) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;

		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, addr, &in6->sin6_addr) != 1)
			return 0;
		return sizeof(*in6);
	} else {
		struct sockaddr_in *in4 = (struct sockaddr_in *)ss;

		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		if (inet_pton(AF_INET, addr, &in4->sin_addr) != 1)
			return 0;
		return sizeof(*in4);
	}
}

/*
 * A listening TCP socket on @addr, port picked by the kernel - @port receives
 * it. -1 if the address cannot be bound - no IPv6 on the host, say.
 */
static inline int test_tcp_listener(const char *addr, uint16_t *port)
{
	struct sockaddr_storage ss;
	socklen_t len = test_sockaddr(addr, 0, &ss);
	int fd, one = 1;

	if (!len)
		return -1;
	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
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
 * A TCP socket of @src - any address if NULL - connected to @addr:@port,
 * blocking until the connection is up and non-blocking afterwards; -1 if it
 * cannot connect.
 */
static inline int test_tcp_connect_from(const char *addr, uint16_t port,
					const char *src)
{
	struct sockaddr_storage ss, sss;
	socklen_t len = test_sockaddr(addr, port, &ss), slen = 0;
	struct timeval tv = { .tv_sec = TEST_IO_MS / 1000 };
	int fd, flags, one = 1;

	if (!len)
		return -1;
	if (src) {
		slen = test_sockaddr(src, 0, &sss);
		if (!slen)
			return -1;
	}
	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0)
		return -1;
	/* A server that does not take the connection: no waiting forever */
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	if ((src && bind(fd, (struct sockaddr *)&sss, slen) < 0) ||
	    connect(fd, (struct sockaddr *)&ss, len) < 0) {
		close(fd);
		return -1;
	}

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	return fd;
}

/*
 * Start @path with @argv, the @nfds descriptors of @fds handed over by socket
 * activation and @env - "NAME=value", NULL for none - in its environment, its
 * output going where the test's goes.
 */
static inline pid_t test_daemon_start(const char *path, char *const argv[],
				      const int *fds, int nfds, const char *env)
{
	char *envp[TEST_ENV_MAX_VARS + 5];
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
	if (env)
		envp[n++] = (char *)env;
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

/* A client of the network: a connection and the TLS of it */
struct test_conn {
	int fd;
	struct esdm_dtls *dtls;
	int ret;
};

static inline void test_conn_close(struct test_conn *c)
{
	esdm_dtls_free(c->dtls);
	if (c->fd >= 0)
		close(c->fd);
	c->dtls = NULL;
	c->fd = -1;
}

/*
 * Connect to @addr:@port from @src - NULL for any address - and do the
 * handshake as a client of @ctx, expecting the server to be @name.
 *
 * @return 0 when the handshake completed, a negative errno otherwise - in
 *	   c->ret as well; c->fd stays open for a look at what became of it
 */
static inline int test_conn_open(struct test_conn *c, const char *addr,
				 uint16_t port, const char *src,
				 struct esdm_tls_ctx *ctx, const char *name)
{
	uint64_t end = test_now_ms() + TEST_IO_MS;

	c->dtls = NULL;
	c->ret = -ECONNREFUSED;
	c->fd = test_tcp_connect_from(addr, port, src);
	if (c->fd < 0)
		return c->ret;

	c->ret = esdm_dtls_alloc_tls(ctx, c->fd,
				     ESDM_ES_EXT_PROTO_RSP_LEN +
					     ESDM_ES_EXT_PROTO_MAX_RSP_DATA,
				     name, &c->dtls);
	if (c->ret)
		return c->ret;

	while ((c->ret = esdm_dtls_handshake(c->dtls)) == -EAGAIN) {
		struct pollfd pfd = { .fd = c->fd,
				      .events = esdm_dtls_want(c->dtls) };

		if (test_now_ms() >= end)
			return c->ret = -ETIMEDOUT;
		poll(&pfd, 1, 50);
	}

	return c->ret;
}

/*
 * One request of @type for @length bytes, and its answer into @rsp of
 * ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA bytes.
 *
 * @return the size of the answer, or a negative errno - -ECONNRESET for a
 *	   connection the server closed
 */
static inline ssize_t test_conn_request(struct test_conn *c, uint16_t type,
					uint32_t length, uint8_t *rsp)
{
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	uint64_t end = test_now_ms() + TEST_IO_MS;
	ssize_t n;
	int ret;

	esdm_es_ext_proto_req_pack(req, type, length);
	ret = esdm_dtls_send(c->dtls, req, sizeof(req));
	if (ret)
		return ret;

	for (;;) {
		struct pollfd pfd = { .fd = c->fd, .events = POLLIN };

		n = esdm_dtls_recv(c->dtls, rsp,
				   ESDM_ES_EXT_PROTO_RSP_LEN +
					   ESDM_ES_EXT_PROTO_MAX_RSP_DATA);
		if (n != -EAGAIN)
			return n;
		if (test_now_ms() >= end)
			return -ETIMEDOUT;
		poll(&pfd, 1, 50);
	}
}

/*
 * Does the server close the connection within @ms? Whatever it still sends is
 * read and dropped.
 */
static inline bool test_fd_closed(int fd, unsigned int ms)
{
	uint64_t end = test_now_ms() + ms;
	uint8_t buf[20000];

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

#endif /* ES_EXT_NET_TEST_H */
