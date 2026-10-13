/*
 * Test: a call that cannot connect ends at its deadline or its interruption
 *
 * A socket file that nobody listens on - left behind by a server that died, or
 * one that is being restarted - refuses every connection. The client tries a
 * number of times with a pause in between, which adds up to seconds. Neither
 * the timeout of esdm_rpcc_get_random_bytes_full_timeout() nor the registered
 * interrupt function may be ignored for that long.
 *
 * A timeout that is no valid relative time is refused instead.
 *
 * The test binds the unprivileged socket without listening on it.
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

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"

#define TEST_LEN 32

/*
 * The connection attempts alone take more than two seconds by default, one
 * pause between them some 270 ms. Whatever ends in less than this did not go
 * through all of them.
 */
#define TEST_MAX_MS 1000

static atomic_bool test_interrupt_now;

static int test_interrupt(void *data)
{
	(void)data;

	return atomic_load(&test_interrupt_now);
}

static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Bind the unprivileged socket without listening - unless an ESDM uses it */
static int test_bind(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	if (!connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		printf("Something listens on %s already\n", addr.sun_path);
		close(fd);
		return -EADDRINUSE;
	}
	close(fd);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	unlink(addr.sun_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		printf("Cannot bind %s: %s\n", addr.sun_path, strerror(errsv));
		close(fd);
		return -errsv;
	}

	return fd;
}

static int test_timed_call(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 200 * 1000000 };
	uint8_t buf[TEST_LEN];
	uint64_t start, took;
	ssize_t ret;

	printf("A timed call ends at its timeout while the connection is refused\n");

	start = test_now_ms();
	ret = esdm_rpcc_get_random_bytes_full_timeout(buf, sizeof(buf), &ts);
	took = test_now_ms() - start;

	if (ret >= 0) {
		printf("FAIL: the call returned %zd\n", ret);
		return 1;
	}
	if (took > TEST_MAX_MS) {
		printf("FAIL: the call took %llu ms for 200 ms (%zd)\n",
		       (unsigned long long)took, ret);
		return 1;
	}

	printf("  the call ended after %llu ms with %zd\n",
	       (unsigned long long)took, ret);

	return 0;
}

/*
 * A timeout that is no valid relative time is refused before it becomes a
 * deadline. The only connection is held meanwhile, so the call has to wait for
 * it until that deadline - which pthread_mutex_clocklock() refuses with EINVAL
 * for a negative tv_nsec, aborting the process.
 */
static int test_invalid_timeout(void)
{
	static const struct timespec invalid[] = {
		{ .tv_sec = 0, .tv_nsec = -999999999 },
		{ .tv_sec = 0, .tv_nsec = 1000000000 },
		{ .tv_sec = -1, .tv_nsec = 0 },
	};
	esdm_rpc_client_connection_t *held = NULL;
	uint8_t buf[TEST_LEN];
	unsigned int i;
	int fail = 0;

	printf("A timed call refuses an invalid timeout\n");

	if (esdm_rpcc_get_unpriv_service(&held, NULL)) {
		printf("FAIL: cannot take the connection\n");
		return 1;
	}

	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		struct timespec ts = invalid[i];
		ssize_t ret = esdm_rpcc_get_random_bytes_full_timeout(
			buf, sizeof(buf), &ts);

		if (ret != -EINVAL) {
			printf("FAIL: { %lld, %ld } gave %zd, not -EINVAL\n",
			       (long long)invalid[i].tv_sec,
			       invalid[i].tv_nsec, ret);
			fail = 1;
		}
	}

	esdm_rpcc_put_unpriv_service(held);

	return fail;
}

static int test_interrupted_call(void)
{
	uint8_t buf[TEST_LEN];
	uint64_t start, took;
	ssize_t ret;

	printf("An interrupted call ends while the connection is refused\n");

	atomic_store(&test_interrupt_now, true);
	start = test_now_ms();
	ret = esdm_rpcc_get_random_bytes(buf, sizeof(buf));
	took = test_now_ms() - start;
	atomic_store(&test_interrupt_now, false);

	if (ret >= 0) {
		printf("FAIL: the call returned %zd\n", ret);
		return 1;
	}
	if (took > TEST_MAX_MS) {
		printf("FAIL: the interrupted call took %llu ms (%zd)\n",
		       (unsigned long long)took, ret);
		return 1;
	}

	printf("  the call ended after %llu ms with %zd\n",
	       (unsigned long long)took, ret);

	return 0;
}

int main(void)
{
	int fd, ret;

	fd = test_bind();
	if (fd < 0)
		return 77;

	/* One connection, which test_invalid_timeout() holds */
	esdm_rpcc_set_max_online_nodes(1);

	ret = esdm_rpcc_init_unpriv_service(test_interrupt);
	if (ret) {
		printf("Cannot initialize the RPC client: %d\n", ret);
		ret = 1;
		goto out;
	}

	ret = test_timed_call();
	ret |= test_invalid_timeout();
	ret |= test_interrupted_call();

	esdm_rpcc_fini_unpriv_service();

out:
	close(fd);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	if (!ret)
		printf("PASS\n");

	return ret;
}
