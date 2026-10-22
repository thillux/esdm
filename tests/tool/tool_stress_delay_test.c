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
 * Tests for frontends/tool/stress_delay.c - the worker of the stress modes.
 *
 * The collector, handle_messages(), waits until every worker sent its exit
 * message. A worker that leaves without one holds the tool forever, so each
 * way out of the worker has to send it - including the one taken when its
 * request buffer cannot be allocated, which the malloc() replaced below makes
 * fail.
 *
 * The translation unit is compiled into the test, and the ESDM is replaced by
 * the RPC call it makes, so no request leaves this process.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common_test.h"

/* Whether the request buffer of the worker is to be allocated */
static bool test_malloc_fails;

static void *test_malloc(size_t size)
{
	return test_malloc_fails ? NULL : malloc(size);
}

#define malloc(size) test_malloc(size)
#define esdm_rpcc_get_random_bytes_full test_get_random_bytes_full

static ssize_t test_get_random_bytes_full(uint8_t *buf, size_t buflen)
{
	memset(buf, 0, buflen);
	return (ssize_t)buflen;
}

/* The unit under test */
#include "stress_delay.c"

#undef malloc

/* Long enough for a few requests, and still short for a test */
#define TEST_STRESS_SEC 0.1

/*
 * Run the worker on one end of a socket pair and check what it sends on the
 * other: its exit message, which is the last one, after which it closed the
 * socket. It runs in a process of its own, as a worker of the process stress
 * mode does, so that the messages are read while it sends them.
 */
static void run_worker(bool alloc_fails)
{
	struct test_msg m, last;
	unsigned int exits = 0;
	int socks[2], status;
	ssize_t got;
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, socks) < 0) {
		CHECK(0, "socketpair() failed: %s", strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork() failed: %s", strerror(errno));
		close(socks[0]);
		close(socks[1]);
		return;
	}

	if (pid == 0) {
		close(socks[0]);
		test_malloc_fails = alloc_fails;
		handle_stress_delay_one_core(TEST_STRESS_SEC, 7, socks[1], 32);
		_exit(0);
	}

	close(socks[1]);

	memset(&last, 0, sizeof(last));
	while ((got = read(socks[0], &m, sizeof(m))) == (ssize_t)sizeof(m)) {
		if (m.is_exit)
			exits++;
		last = m;
	}

	/* The worker closed its end once it was done */
	CHECK_EQ(got, 0);
	CHECK_EQ(exits, 1);
	CHECK_EQ(last.is_exit, 1);
	CHECK_EQ(last.id, 7);
	CHECK_EQ(last.request_size, 32);

	if (alloc_fails) {
		/* Nothing requested, and no rate made up out of 0/0 */
		CHECK_EQ(last.requests, 0);
		CHECK_EQ(last.bytes, 0);
		CHECK(last.req_per_sec == 0.0 && last.bytes_per_sec == 0.0,
		      "a worker that requested nothing reports %f requests and %f bytes per second",
		      last.req_per_sec, last.bytes_per_sec);
	} else {
		CHECK(last.requests > 0, "the worker requested nothing");
	}

	close(socks[0]);

	CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
		      !WEXITSTATUS(status),
	      "the worker did not finish cleanly");
}

int main(void)
{
	/* A worker that never reports holds the test - fail it instead */
	alarm(30);

	run_worker(false);
	run_worker(true);

	return common_test_result("esdm-tool stress worker");
}
