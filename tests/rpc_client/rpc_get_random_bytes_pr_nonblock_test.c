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
 * The non-blocking prediction resistant request against a running server.
 *
 * Whether the server answers a request with -EAGAIN - the ESDM is not
 * operational yet, or another prediction resistant request is in flight -
 * cannot be steered from here. So each call may return -EAGAIN, but when it
 * returns data, the data has to be there and nothing beyond what it reports,
 * and the server has to come up with data within a bounded time.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "env.h"
#include "esdm_rpc_client.h"

/* Requests that have to succeed - of one PR block and of several of them. */
#define TEST_SUCCESSES 10
#define TEST_SMALL_LEN 32
#define TEST_LARGE_LEN 100

/* How long the server may keep answering -EAGAIN altogether. */
#define TEST_AGAIN_LIMIT_MS 30000
#define TEST_AGAIN_POLL_MS 10

#define TEST_CANARY 0xa5

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000 * 1000 };

	nanosleep(&ts, NULL);
}

/* Are the @len bytes of @buf all @val? */
static int test_all(const uint8_t *buf, size_t len, uint8_t val)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != val)
			return 0;
	}

	return 1;
}

/*
 * @return 0 when TEST_SUCCESSES requests of @len bytes returned data
 */
static int test_nonblock(size_t len)
{
	uint8_t buf[TEST_LARGE_LEN + 16];
	unsigned int successes = 0, again = 0;

	printf("Non-blocking PR requests of %zu bytes\n", len);

	while (successes < TEST_SUCCESSES) {
		ssize_t rc;

		memset(buf, TEST_CANARY, sizeof(buf));

		rc = esdm_rpcc_get_random_bytes_pr_nonblock(buf, len);
		if (rc == -EAGAIN) {
			/* Nothing may have been written. */
			if (!test_all(buf, sizeof(buf), TEST_CANARY)) {
				printf("-EAGAIN, but the buffer was written\n");
				return 1;
			}
			if (++again * TEST_AGAIN_POLL_MS >=
			    TEST_AGAIN_LIMIT_MS) {
				printf("the server never answered with data\n");
				return 1;
			}
			test_sleep_ms(TEST_AGAIN_POLL_MS);
			continue;
		}
		if (rc < 0) {
			printf("request failed: %zd\n", rc);
			return 1;
		}
		if (rc == 0 || (size_t)rc > len) {
			printf("%zd bytes returned for a request of %zu\n", rc,
			       len);
			return 1;
		}

		/*
		 * Random data that happens to equal the canary throughout is
		 * as unlikely as all zeroes.
		 */
		if (test_all(buf, (size_t)rc, TEST_CANARY) ||
		    test_all(buf, (size_t)rc, 0)) {
			printf("%zd bytes reported, but not delivered\n", rc);
			return 1;
		}
		if (!test_all(buf + rc, sizeof(buf) - (size_t)rc,
			      TEST_CANARY)) {
			printf("more than the reported %zd bytes were written\n",
			       rc);
			return 1;
		}

		successes++;
	}

	printf("  %u requests served, %u answered with -EAGAIN\n", successes,
	       again);

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = env_init();
	if (ret)
		return ret;

	ret = esdm_rpcc_init_unpriv_service(NULL);
	if (ret) {
		ret = 1;
		goto out;
	}

	ret = test_nonblock(TEST_SMALL_LEN);
	if (!ret)
		ret = test_nonblock(TEST_LARGE_LEN);

out:
	esdm_rpcc_fini_unpriv_service();
	env_fini();
	return ret;
}
