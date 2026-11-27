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
 * A process forked from one that initialized the ESDM holds a copy of every
 * DRNG state: served from it, parent and child would hand out the same bits.
 * The child must get no output from any call, and the parent must go on
 * unaffected.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "esdm.h"

#define CHECK(cond, msg)                                                      \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failed = 1;                                            \
		}                                                              \
	} while (0)

/* Every output call of the library, as the child of a fork sees it */
static int child(void)
{
	uint64_t seed[128];
	uint8_t buf[32], zero[32] = { 0 };
	int failed = 0;

	memset(buf, 0, sizeof(buf));
	CHECK(esdm_get_random_bytes_full(buf, sizeof(buf)) == -EOPNOTSUPP,
	      "full call served a forked process");
	CHECK(esdm_get_random_bytes(buf, sizeof(buf)) == -EOPNOTSUPP,
	      "non-blocking call served a forked process");
	CHECK(esdm_get_random_bytes_pr(buf, sizeof(buf)) == -EOPNOTSUPP,
	      "prediction resistance call served a forked process");
	CHECK(esdm_get_random_bytes_pr_noblock(buf, sizeof(buf)) ==
		      -EOPNOTSUPP,
	      "non-blocking PR call served a forked process");
	CHECK(esdm_get_random_bytes_full_noblock(buf, sizeof(buf)) ==
		      -EOPNOTSUPP,
	      "non-blocking full call served a forked process");
	CHECK(esdm_get_seed(seed, sizeof(seed), 0) == -EOPNOTSUPP,
	      "seed call served a forked process");
	CHECK(!memcmp(buf, zero, sizeof(buf)), "the buffer was written");

	/* Returns at once: the threads it would join do not exist here */
	esdm_fini();
	return failed;
}

int main(int argc, char *argv[])
{
	uint8_t before[32], after[32];
	int status = 0, failed = 0;
	pid_t pid;

	(void)argc;
	(void)argv;

#ifndef ESDM_TESTMODE
	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#endif

	if (esdm_init())
		return 1;

	/* Waits until the DRNGs are seeded: the child inherits them so */
	CHECK(esdm_get_random_bytes_full(before, sizeof(before)) ==
		      (ssize_t)sizeof(before),
	      "no output before the fork");

	pid = fork();
	if (pid < 0) {
		esdm_fini();
		return 1;
	}
	if (!pid)
		_exit(child());

	CHECK(waitpid(pid, &status, 0) == pid, "waitpid");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status),
	      "the forked process got output or did not return");

	CHECK(esdm_get_random_bytes_full(after, sizeof(after)) ==
		      (ssize_t)sizeof(after),
	      "the parent got no output after the fork");
	CHECK(memcmp(before, after, sizeof(before)),
	      "the parent repeats itself");

	esdm_fini();
	return failed;
}
