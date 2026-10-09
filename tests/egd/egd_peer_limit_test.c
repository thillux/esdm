/*
 * Tests of the per-UID connection accounting of the server sockets
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

/*
 * The accounting is included rather than linked: the test inspects its table,
 * whose entries are private to it, and replaces the logger to count the
 * warnings it gives.
 */

#include <stdio.h>

#include "esdm_peer_limit.c"

/* A UID ESDM_PEER_LIMIT_BUCKETS apart shares the bucket of TEST_UID. */
#define TEST_UID 1000
#define TEST_UID_SAME_BUCKET (TEST_UID + ESDM_PEER_LIMIT_BUCKETS)
#define TEST_MAX 3

#define TEST_THREADS 8
#define TEST_THREAD_ROUNDS 10000

static unsigned int test_warnings;
static int ret = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

void _esdm_logger(const enum esdm_logger_verbosity severity,
		  const enum esdm_logger_class class_, const char *file,
		  const char *func, const uint32_t line, const char *fmt, ...)
{
	(void)class_;
	(void)file;
	(void)func;
	(void)line;
	(void)fmt;

	/* Under the lock of the accounting, which is all that calls this. */
	if (severity == LOGGER_WARN)
		test_warnings++;
}

/* Connections accounted for @uid, 0 when it has no entry. */
static unsigned int test_count(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry *entry = *esdm_peer_limit_slot(limit, uid);

	return entry ? entry->count : 0;
}

/* Is the table empty - is every entry released with its last connection? */
static bool test_empty(struct esdm_peer_limit *limit)
{
	unsigned int i;

	for (i = 0; i < ESDM_PEER_LIMIT_BUCKETS; i++) {
		if (limit->buckets[i])
			return false;
	}

	return true;
}

/* Root is never limited, and never even accounted. */
static void test_root_exempt(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	unsigned int i;

	printf("peer limit: root is exempt\n");

	for (i = 0; i < 10 * TEST_MAX; i++)
		CHECK(esdm_peer_limit_get(&limit, 0),
		      "root was refused its connection %u", i + 1);
	CHECK(test_empty(&limit), "root was accounted");

	for (i = 0; i < 10 * TEST_MAX; i++)
		esdm_peer_limit_put(&limit, 0);
	CHECK(test_empty(&limit), "releasing root's connections left entries");
	CHECK(!test_warnings, "root was reported at a limit");
}

/* The limit applies per UID, and releasing a connection makes room again. */
static void test_limit(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	unsigned int i;

	printf("peer limit: bound per UID\n");
	test_warnings = 0;

	for (i = 0; i < TEST_MAX; i++)
		CHECK(esdm_peer_limit_get(&limit, TEST_UID),
		      "connection %u below the limit was refused", i + 1);
	CHECK(!esdm_peer_limit_get(&limit, TEST_UID),
	      "a connection beyond the limit was admitted");
	CHECK(test_count(&limit, TEST_UID) == TEST_MAX,
	      "a refused connection was accounted: %u",
	      test_count(&limit, TEST_UID));

	/* Another UID - even one sharing the bucket - is not affected. */
	CHECK(esdm_peer_limit_get(&limit, TEST_UID_SAME_BUCKET),
	      "a UID was refused for the connections of another one");
	CHECK(test_count(&limit, TEST_UID_SAME_BUCKET) == 1,
	      "the other UID holds %u connections, not 1",
	      test_count(&limit, TEST_UID_SAME_BUCKET));
	esdm_peer_limit_put(&limit, TEST_UID_SAME_BUCKET);

	/* One released, one more admitted - and no more. */
	esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(esdm_peer_limit_get(&limit, TEST_UID),
	      "a released connection did not make room for a new one");
	CHECK(!esdm_peer_limit_get(&limit, TEST_UID),
	      "releasing one connection made room for two");

	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_empty(&limit),
	      "entries remain after all connections were released");
}

/*
 * Connections are neither leaked by refusals nor created by releases that were
 * never admitted - the count does not wrap.
 */
static void test_no_leak(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	unsigned int i;

	printf("peer limit: no leaked or underflowing count\n");

	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_get(&limit, TEST_UID);
	for (i = 0; i < 100; i++)
		CHECK(!esdm_peer_limit_get(&limit, TEST_UID),
		      "refused attempt %u was admitted", i + 1);
	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_empty(&limit), "refused connections were accounted");

	/* Unbalanced releases must not turn into credit. */
	for (i = 0; i < 5; i++)
		esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_empty(&limit), "a release without a connection left an entry");

	for (i = 0; i < TEST_MAX; i++)
		CHECK(esdm_peer_limit_get(&limit, TEST_UID),
		      "connection %u was refused", i + 1);
	CHECK(!esdm_peer_limit_get(&limit, TEST_UID),
	      "unbalanced releases raised the limit");
	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_empty(&limit), "entries remain after all were released");
}

/* One warning per episode at the limit, another for the next episode. */
static void test_warning(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	unsigned int i;

	printf("peer limit: one warning per episode\n");
	test_warnings = 0;

	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_get(&limit, TEST_UID);
	for (i = 0; i < 10; i++)
		esdm_peer_limit_get(&limit, TEST_UID);
	CHECK(test_warnings == 1, "%u warnings for one episode, not 1",
	      test_warnings);

	/*
	 * Dropping below the limit ends the episode, also while the UID still
	 * holds connections.
	 */
	esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_count(&limit, TEST_UID) == TEST_MAX - 1,
	      "%u connections accounted, not %u", test_count(&limit, TEST_UID),
	      TEST_MAX - 1);
	CHECK(esdm_peer_limit_get(&limit, TEST_UID),
	      "a connection below the limit was refused");
	for (i = 0; i < 10; i++)
		esdm_peer_limit_get(&limit, TEST_UID);
	CHECK(test_warnings == 2, "%u warnings for two episodes, not 2",
	      test_warnings);

	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(test_empty(&limit), "entries remain after all were released");
}

static struct esdm_peer_limit test_shared =
	ESDM_PEER_LIMIT_INIT("test", TEST_THREADS * TEST_MAX);

static void *test_thread(void *arg)
{
	uid_t uid = TEST_UID + (uid_t)(uintptr_t)arg % 2;
	unsigned int i, admitted = 0;

	for (i = 0; i < TEST_THREAD_ROUNDS; i++) {
		if (esdm_peer_limit_get(&test_shared, uid))
			admitted++;
		if (admitted && (i % 3) == 2) {
			esdm_peer_limit_put(&test_shared, uid);
			admitted--;
		}
	}

	while (admitted--)
		esdm_peer_limit_put(&test_shared, uid);

	return NULL;
}

/* One accounting instance shared by several threads, as the RPC workers do. */
static void test_threads(void)
{
	pthread_t threads[TEST_THREADS];
	unsigned int i, started;

	printf("peer limit: concurrent use\n");

	for (started = 0; started < TEST_THREADS; started++) {
		if (pthread_create(&threads[started], NULL, test_thread,
				   (void *)(uintptr_t)started)) {
			CHECK(0, "cannot start thread %u", started);
			break;
		}
	}
	for (i = 0; i < started; i++)
		pthread_join(threads[i], NULL);

	CHECK(test_empty(&test_shared),
	      "entries remain after all threads released their connections");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	setvbuf(stdout, NULL, _IONBF, 0);

	test_root_exempt();
	test_limit();
	test_no_leak();
	test_warning();
	test_threads();

	printf("peer limit: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
