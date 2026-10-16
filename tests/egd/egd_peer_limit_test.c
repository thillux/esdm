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
 * warnings it gives. The same goes for the accounts the peers are accounted
 * to, whose subordinate UID ranges are read from a file of the test's.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static char test_subuid[] = "/tmp/esdm-peer-limit-test-XXXXXX";
#define ESDM_PEER_ACCOUNT_SUBUID test_subuid

#include "esdm_peer_account.c"
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

/*
 * What a UID holds, and what the UID holding the most holds - the latter is
 * what picks the connections to close first. Root holds none by that count.
 */
static void test_counts(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	unsigned int i;

	printf("peer limit: connections held per UID and at most\n");

	CHECK(esdm_peer_limit_max_count(&limit) == 0,
	      "an empty table reports a UID holding %u",
	      esdm_peer_limit_max_count(&limit));

	for (i = 0; i < 5; i++)
		esdm_peer_limit_get(&limit, 0);
	CHECK(esdm_peer_limit_count(&limit, 0) == 0,
	      "root is reported holding %u", esdm_peer_limit_count(&limit, 0));
	CHECK(esdm_peer_limit_max_count(&limit) == 0,
	      "root's connections count towards the most held: %u",
	      esdm_peer_limit_max_count(&limit));

	/* Two UIDs in the same bucket must not be mixed up. */
	esdm_peer_limit_get(&limit, TEST_UID);
	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_get(&limit, TEST_UID_SAME_BUCKET);
	CHECK(esdm_peer_limit_count(&limit, TEST_UID) == 1,
	      "UID holds %u, not 1", esdm_peer_limit_count(&limit, TEST_UID));
	CHECK(esdm_peer_limit_count(&limit, TEST_UID_SAME_BUCKET) == TEST_MAX,
	      "UID holds %u, not %u",
	      esdm_peer_limit_count(&limit, TEST_UID_SAME_BUCKET), TEST_MAX);
	CHECK(esdm_peer_limit_count(&limit, TEST_UID + 1) == 0,
	      "a UID without connections holds %u",
	      esdm_peer_limit_count(&limit, TEST_UID + 1));
	CHECK(esdm_peer_limit_max_count(&limit) == TEST_MAX,
	      "the most held is %u, not %u", esdm_peer_limit_max_count(&limit),
	      TEST_MAX);

	/* A refusal is not held. */
	CHECK(!esdm_peer_limit_get(&limit, TEST_UID_SAME_BUCKET),
	      "a connection beyond the limit was admitted");
	CHECK(esdm_peer_limit_max_count(&limit) == TEST_MAX,
	      "a refused connection counts towards the most held: %u",
	      esdm_peer_limit_max_count(&limit));

	/* The most held follows the releases. */
	for (i = 0; i < TEST_MAX; i++)
		esdm_peer_limit_put(&limit, TEST_UID_SAME_BUCKET);
	CHECK(esdm_peer_limit_max_count(&limit) == 1,
	      "the most held is %u after the releases, not 1",
	      esdm_peer_limit_max_count(&limit));

	esdm_peer_limit_put(&limit, TEST_UID);
	CHECK(esdm_peer_limit_max_count(&limit) == 0,
	      "the most held is %u with nothing held",
	      esdm_peer_limit_max_count(&limit));
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

/****************************
 * Accounts
 ****************************/

/* A user with a subordinate range, and the range */
#define TEST_OWNER 60001
#define TEST_SUB_BASE 61000
#define TEST_SUB_COUNT 8
/* The range root shares out to a container, see test_account_container() */
#define TEST_CT_BASE 62000
#define TEST_CT_COUNT 4

/* Ask for the subordinate UID ranges again at the next account. */
static void test_subuid_recheck(void)
{
	pthread_mutex_lock(&esdm_peer_account_subuid_table.lock);
	esdm_peer_account_subuid_table.checked = 0;
	pthread_mutex_unlock(&esdm_peer_account_subuid_table.lock);
}

static int test_subuid_write(const char *content)
{
	FILE *f = fopen(test_subuid, "w");

	if (!f)
		return -1;
	fputs(content, f);
	fclose(f);
	test_subuid_recheck();

	return 0;
}

/*
 * The subordinate UID ranges, which are what the daemon goes by once it
 * dropped its privileges: a UID in the range of a user is accounted to that
 * user. Ranges of root's, or of nobody that resolves, are not, and neither is
 * a line that is no range - and a change of the file is picked up.
 */
static void test_account_subuid(void)
{
	printf("peer account: subordinate UID ranges\n");

	if (test_subuid_write("# subordinate UIDs\n"
			      "60001:200000:65536\n"
			      "root:300000:65536\n"
			      "0:400000:100\n"
			      "esdm-no-such-user-for-sure:500000:100\n"
			      "\n"
			      "garbage\n"
			      "60003:x:10\n"
			      "60003:700000:0\n"
			      "60003:4294967200:1000\n"
			      "60002:600000:10")) {
		CHECK(0, "cannot write %s: %s", test_subuid, strerror(errno));
		return;
	}

	CHECK(esdm_peer_account_subuid(200000) == 60001 &&
		      esdm_peer_account_subuid(265535) == 60001,
	      "a UID of a range was not accounted to its owner");
	CHECK(esdm_peer_account_subuid(199999) == 199999 &&
		      esdm_peer_account_subuid(265536) == 265536,
	      "a UID next to a range was accounted to its owner");
	CHECK(esdm_peer_account_subuid(60001) == 60001,
	      "the owner of a range is not accounted to itself");
	CHECK(esdm_peer_account_subuid(300000) == 300000 &&
		      esdm_peer_account_subuid(400000) == 400000,
	      "a UID of a range of root's was accounted to root");
	CHECK(esdm_peer_account_subuid(500000) == 500000,
	      "a UID of a range of an unknown owner was accounted to it");
	CHECK(esdm_peer_account_subuid(700000) == 700000 &&
		      esdm_peer_account_subuid(4294967200U) == 4294967200U,
	      "an empty or overflowing range was taken");
	CHECK(esdm_peer_account_subuid(600009) == 60002 &&
		      esdm_peer_account_subuid(600010) == 600010,
	      "the last line, without a newline, was not taken as it is");

	/* A new user gets a range - without a restart. */
	if (test_subuid_write("60001:200000:65536\n60004:800000:5\n")) {
		CHECK(0, "cannot rewrite %s", test_subuid);
		return;
	}
	CHECK(esdm_peer_account_subuid(800004) == 60004,
	      "a range added to the file was not picked up");
	CHECK(esdm_peer_account_subuid(600000) == 600000,
	      "a range removed from the file is still taken");

	/* No file, no ranges. */
	unlink(test_subuid);
	test_subuid_recheck();
	CHECK(esdm_peer_account_subuid(200000) == 200000,
	      "the ranges of a removed file are still taken");
}

/*
 * Root is root without any lookup, and nothing that fails along the way makes
 * anybody else root - a socket that tells nothing about its peer least of all.
 */
static void test_account_root(void)
{
	struct ucred cred = { .pid = 0, .uid = 0, .gid = 0 };

	printf("peer account: root, and nobody else, is 0\n");

	CHECK(esdm_peer_account(-1, &cred) == 0, "root is not accounted as 0");

	cred.uid = TEST_SUB_BASE;
	cred.pid = getpid();
	CHECK(esdm_peer_account(-1, &cred) == TEST_SUB_BASE,
	      "a peer whose namespace is unknown is accounted as %u",
	      (unsigned int)esdm_peer_account(-1, &cred));
}

/* A socket to connect to, by an abstract name - no file to clean up */
static int test_listen(struct sockaddr_un *addr)
{
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1,
		 "esdm-peer-limit-test-%d", (int)getpid());

	if (bind(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0 ||
	    listen(fd, 16) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* Connect and wait for the test to close the connection - the peer lives on. */
static void test_peer(const struct sockaddr_un *addr)
{
	char b;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0 || connect(fd, (const struct sockaddr *)addr, sizeof(*addr)))
		_exit(1);
	while (read(fd, &b, 1) < 0 && errno == EINTR)
		;
	_exit(0);
}

/*
 * A process in a user namespace of its own, as @owner (root to keep root),
 * mapped by the test - as newuidmap(1) would - to its owner and @count UIDs
 * from @base on. It connects @conns times, as UIDs 1 up of its namespace, each
 * from a process of its own that lives until the test closes the connection.
 *
 * @return the PID of the process, < 0 on error
 */
static pid_t test_userns_peers(const struct sockaddr_un *addr, uid_t owner,
			       uid_t base, unsigned int count,
			       unsigned int conns)
{
	char map[128], path[64], b = 0;
	int sv[2], fd;
	unsigned int i;
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(sv[0]);
		close(sv[1]);
		return -1;
	}

	if (!pid) {
		close(sv[0]);
		if (owner && (setgroups(0, NULL) ||
			      setresgid((gid_t)owner, (gid_t)owner,
					(gid_t)owner) ||
			      setresuid(owner, owner, owner)))
			_exit(2);
		if (unshare(CLONE_NEWUSER))
			_exit(3);
		if (write(sv[1], &b, 1) != 1 || read(sv[1], &b, 1) != 1 || b)
			_exit(4);

		for (i = 1; i <= conns; i++) {
			pid_t peer = fork();

			if (peer < 0)
				_exit(5);
			if (!peer) {
				if (setresuid(i, i, i))
					_exit(6);
				test_peer(addr);
			}
		}
		while (wait(NULL) > 0 || errno == EINTR)
			;
		_exit(0);
	}

	close(sv[1]);

	/* The map of the owner and its range - only root may write it. */
	if (owner)
		snprintf(map, sizeof(map), "0 %u 1\n1 %u %u\n",
			 (unsigned int)owner, (unsigned int)base, count);
	else
		snprintf(map, sizeof(map), "0 %u %u\n", (unsigned int)base,
			 count);
	snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)pid);

	b = 1;
	if (read(sv[0], &b, 1) == 1) {
		fd = open(path, O_WRONLY | O_CLOEXEC);
		if (fd >= 0) {
			if (write(fd, map, strlen(map)) == (ssize_t)strlen(map))
				b = 0;
			close(fd);
		}
	}
	if (write(sv[0], &b, 1) != 1)
		b = 1;
	close(sv[0]);

	if (b) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}

	return pid;
}

/* Accept a connection, within a few seconds. */
static int test_accept(int lfd, struct ucred *cred)
{
	struct pollfd pfd = { .fd = lfd, .events = POLLIN };
	socklen_t len = sizeof(*cred);
	int fd;

	if (poll(&pfd, 1, 10000) != 1)
		return -1;

	fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
	if (fd < 0)
		return -1;

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, cred, &len) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/*
 * A user connecting as the UIDs of its subordinate range from a user namespace
 * of its own is one account, that of the user - and bounded as one. The test's
 * subordinate UID ranges hold none, so only the namespace can tell. Needs root
 * to map the range, as newuidmap(1) does.
 */
static void test_account_userns(void)
{
	struct esdm_peer_limit limit = ESDM_PEER_LIMIT_INIT("test", TEST_MAX);
	int lfd, fds[TEST_MAX + 1];
	struct sockaddr_un addr;
	unsigned int i, n = 0, admitted = 0;
	pid_t pid;

	printf("peer account: the UIDs of a subordinate range are their user's\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: mapping a subordinate range needs root\n");
		return;
	}

	lfd = test_listen(&addr);
	if (lfd < 0) {
		CHECK(0, "cannot listen: %s", strerror(errno));
		return;
	}

	pid = test_userns_peers(&addr, TEST_OWNER, TEST_SUB_BASE,
				TEST_SUB_COUNT, TEST_MAX + 1);
	if (pid < 0) {
		CHECK(0, "cannot start the peers in a user namespace");
		close(lfd);
		return;
	}

	for (i = 0; i < TEST_MAX + 1; i++) {
		struct ucred cred;
		uid_t account;

		fds[n] = test_accept(lfd, &cred);
		if (fds[n] < 0) {
			CHECK(0, "peer %u did not connect", i + 1);
			break;
		}
		n++;

		CHECK(cred.uid >= TEST_SUB_BASE &&
			      cred.uid < TEST_SUB_BASE + TEST_SUB_COUNT,
		      "a peer connected as UID %u, not one of the range",
		      (unsigned int)cred.uid);

		account = esdm_peer_account(fds[n - 1], &cred);
		CHECK(account == TEST_OWNER,
		      "UID %u of the range was accounted to %u, not to its user %u",
		      (unsigned int)cred.uid, (unsigned int)account,
		      TEST_OWNER);

		if (esdm_peer_limit_get(&limit, account))
			admitted++;
	}

	CHECK(admitted == TEST_MAX,
	      "%u connections of %u UIDs of one user were admitted, not its bound of %u",
	      admitted, n, TEST_MAX);

	while (admitted--)
		esdm_peer_limit_put(&limit, TEST_OWNER);
	CHECK(test_empty(&limit), "entries remain after all were released");

	for (i = 0; i < n; i++)
		close(fds[i]);
	waitpid(pid, NULL, 0);
	close(lfd);
}

/*
 * The same with the privileges dropped, as the daemon serves its clients: the
 * kernel no longer shows the namespace of another user's process, and the
 * subordinate UID ranges tell the user instead. Without a range, the UID is
 * its own account - and never root's. Needs root as above.
 */
static void test_account_unprivileged(void)
{
	int lfd, fd = -1, status = 0;
	struct sockaddr_un addr;
	struct ucred cred;
	pid_t pid, server;
	char ranges[64];

	printf("peer account: once unprivileged, the subordinate UID ranges tell\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: mapping a subordinate range needs root\n");
		return;
	}

	snprintf(ranges, sizeof(ranges), "%u:%u:%u\n", TEST_OWNER,
		 TEST_SUB_BASE, TEST_SUB_COUNT);
	if (test_subuid_write(ranges) || chmod(test_subuid, 0644)) {
		CHECK(0, "cannot write %s", test_subuid);
		return;
	}

	lfd = test_listen(&addr);
	if (lfd < 0) {
		CHECK(0, "cannot listen: %s", strerror(errno));
		return;
	}

	pid = test_userns_peers(&addr, TEST_OWNER, TEST_SUB_BASE,
				TEST_SUB_COUNT, 1);
	if (pid < 0) {
		CHECK(0, "cannot start a peer in a user namespace");
		goto out;
	}

	fd = test_accept(lfd, &cred);
	CHECK(fd >= 0, "the peer did not connect");
	if (fd < 0)
		goto out_peer;

	/*
	 * 0: accounted to the user by its range, 1: by the namespace although
	 * the kernel should not have shown it, 2: otherwise, 3: no ranges, and
	 * accounted to anything but its UID.
	 */
	server = fork();
	if (!server) {
		const uid_t uid = TEST_OWNER + 1;

		if (setgroups(0, NULL) || setresgid(uid, uid, uid) ||
		    setresuid(uid, uid, uid))
			_exit(4);
		if (esdm_peer_account_open_userns(fd, &cred) >= 0)
			_exit(1);
		if (esdm_peer_account(fd, &cred) != TEST_OWNER)
			_exit(2);
		/* The file is the parent's to remove, see below. */
		test_subuid_recheck();
		while (!access(test_subuid, F_OK))
			usleep(1000);
		_exit(esdm_peer_account(fd, &cred) == cred.uid ? 0 : 3);
	}
	if (server > 0) {
		usleep(100000);
		unlink(test_subuid);
	}
	CHECK(server > 0 && waitpid(server, &status, 0) == server &&
		      WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "an unprivileged server did not account a peer by the subordinate UID ranges: %d",
	      server > 0 && WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	close(fd);
out_peer:
	waitpid(pid, NULL, 0);
out:
	unlink(test_subuid);
	test_subuid_recheck();
	close(lfd);
}

/*
 * A user namespace only root created and filled - a container's - is root's to
 * share out: its UIDs are accounted by themselves, and none of them as root,
 * its owner. Needs root to create such a namespace.
 */
static void test_account_container(void)
{
	int lfd, fd = -1;
	struct sockaddr_un addr;
	struct ucred cred;
	uid_t account;
	pid_t pid;

	printf("peer account: the UIDs of a container of root's are their own\n");

	if (geteuid() != 0) {
		printf("  SKIPPED: a container of root's needs root\n");
		return;
	}

	lfd = test_listen(&addr);
	if (lfd < 0) {
		CHECK(0, "cannot listen: %s", strerror(errno));
		return;
	}

	pid = test_userns_peers(&addr, 0, TEST_CT_BASE, TEST_CT_COUNT, 1);
	if (pid < 0) {
		CHECK(0, "cannot start a peer in a user namespace");
		close(lfd);
		return;
	}

	fd = test_accept(lfd, &cred);
	CHECK(fd >= 0, "the peer did not connect");
	if (fd >= 0) {
		account = esdm_peer_account(fd, &cred);
		CHECK(cred.uid == TEST_CT_BASE + 1,
		      "the peer connected as UID %u, not %u",
		      (unsigned int)cred.uid, TEST_CT_BASE + 1);
		CHECK(account == cred.uid,
		      "UID %u of a container was accounted to %u",
		      (unsigned int)cred.uid, (unsigned int)account);
		close(fd);
	}

	waitpid(pid, NULL, 0);
	close(lfd);
}

/*
 * A peer that is gone by the time it is accounted cannot be asked for its
 * namespace - and is not accounted by whatever process has its PID now, nor as
 * root, but by its UID.
 */
static void test_account_gone(void)
{
	int lfd, fd;
	struct sockaddr_un addr;
	struct ucred cred;
	pid_t pid;

	printf("peer account: a peer that is gone is its UID\n");

	lfd = test_listen(&addr);
	if (lfd < 0) {
		CHECK(0, "cannot listen: %s", strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		CHECK(0, "cannot fork");
		close(lfd);
		return;
	}
	if (!pid) {
		int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

		if (geteuid() == 0 && setresuid(TEST_SUB_BASE, TEST_SUB_BASE,
						TEST_SUB_BASE))
			_exit(1);
		_exit(s < 0 || connect(s, (struct sockaddr *)&addr,
				       sizeof(addr)));
	}
	waitpid(pid, NULL, 0);

	fd = test_accept(lfd, &cred);
	CHECK(fd >= 0, "the peer did not connect");
	if (fd >= 0) {
		uid_t account = esdm_peer_account(fd, &cred);

		CHECK(account == cred.uid && account != 0,
		      "a peer of UID %u that is gone was accounted to %u",
		      (unsigned int)cred.uid, (unsigned int)account);
		close(fd);
	}

	close(lfd);
}

int main(int argc, char *argv[])
{
	int fd;

	(void)argc;
	(void)argv;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* The file of the subordinate UID ranges, empty to begin with. */
	fd = mkstemp(test_subuid);
	if (fd < 0) {
		printf("Cannot create %s: %s\n", test_subuid, strerror(errno));
		return 1;
	}
	close(fd);

	test_root_exempt();
	test_limit();
	test_no_leak();
	test_warning();
	test_counts();
	test_threads();

	test_account_subuid();
	test_account_root();
	test_account_userns();
	test_account_unprivileged();
	test_account_container();
	test_account_gone();

	unlink(test_subuid);

	printf("peer limit: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
