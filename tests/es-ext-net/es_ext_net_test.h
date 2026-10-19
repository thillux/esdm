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
 * What the tests of the external entropy sources on the network share: SCTP
 * sockets on loopback, bound to a port the kernel picked - so that no two
 * tests race for a port -, with or without the SCTP-AUTH of
 * esdm_tls_sctp_prepare(), and the skip of a test on a host whose kernel has
 * no SCTP.
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
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <linux/sctp.h>

#include "esdm_tls.h"

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

/*
 * Does the kernel have SCTP? A test without it is skipped (77): the kernel
 * module sctp is not loaded, and cannot be by the test.
 */
static inline bool test_sctp_available(void)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);

	if (fd < 0) {
		if (errno == EPROTONOSUPPORT || errno == ESOCKTNOSUPPORT ||
		    errno == EAFNOSUPPORT) {
			printf("No SCTP in this kernel (%s) - the module sctp is not loaded\n",
			       strerror(errno));
			return false;
		}
		return true;
	}
	close(fd);
	return true;
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
 * A listening SCTP socket of the one-to-one style on @addr, port picked by the
 * kernel - @port receives it -, set up for SCTP-AUTH if @auth. -1 if the
 * address cannot be bound - no IPv6 on the host, say.
 */
static inline int test_sctp_listener(const char *addr, bool auth,
				     uint16_t *port)
{
	struct sockaddr_storage ss;
	socklen_t len = test_sockaddr(addr, 0, &ss);
	int fd, one = 1;

	if (!len)
		return -1;
	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (fd < 0)
		return -1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (ss.ss_family == AF_INET6)
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
	if ((auth && esdm_tls_sctp_prepare(fd)) ||
	    bind(fd, (struct sockaddr *)&ss, len) < 0 || listen(fd, 64) < 0) {
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
 * An SCTP socket connected to @addr:@port, set up for SCTP-AUTH if @auth,
 * blocking until the association is up and non-blocking afterwards; -1 if
 * it cannot connect.
 */
static inline int test_sctp_connect(const char *addr, uint16_t port, bool auth)
{
	struct sockaddr_storage ss;
	socklen_t len = test_sockaddr(addr, port, &ss);
	int fd, flags;

	if (!len)
		return -1;
	fd = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_SCTP);
	if (fd < 0)
		return -1;
	if ((auth && esdm_tls_sctp_prepare(fd)) ||
	    connect(fd, (struct sockaddr *)&ss, len) < 0) {
		close(fd);
		return -1;
	}

	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	return fd;
}

/* The active key of SCTP-AUTH of the association on @fd, or a negative errno */
static inline int test_sctp_active_key(int fd)
{
	struct sctp_authkeyid id = { 0 };
	socklen_t len = sizeof(id);

	if (getsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &id, &len) < 0)
		return -errno;
	return id.scact_keynumber;
}

/* Does the association have the key @key? Making it active tells. */
static inline bool test_sctp_has_key(int fd, uint16_t key)
{
	int active = test_sctp_active_key(fd);
	struct sctp_authkeyid id = { .scact_keynumber = key };
	bool ret;

	if (active < 0)
		return false;
	ret = !setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &id,
			  sizeof(id));
	id.scact_keynumber = (uint16_t)active;
	setsockopt(fd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &id, sizeof(id));
	return ret;
}

/*
 * Does the list of chunks @opt of @fd - SCTP_LOCAL_AUTH_CHUNKS or
 * SCTP_PEER_AUTH_CHUNKS - hold DATA and FORWARD-TSN?
 */
static inline bool test_sctp_auth_chunks(int fd, int opt)
{
	union {
		struct sctp_authchunks chunks;
		uint8_t buf[sizeof(struct sctp_authchunks) + 256];
	} u;
	socklen_t len = sizeof(u);
	bool data = false, fwd = false;
	unsigned int i;

	memset(&u, 0, sizeof(u));
	if (getsockopt(fd, IPPROTO_SCTP, opt, &u, &len) < 0)
		return false;
	for (i = 0; i < u.chunks.gauth_number_of_chunks && i < 256; i++) {
		if (u.chunks.gauth_chunks[i] == 0)
			data = true;
		if (u.chunks.gauth_chunks[i] == 192)
			fwd = true;
	}
	return data && fwd;
}

#endif /* ES_EXT_NET_TEST_H */
