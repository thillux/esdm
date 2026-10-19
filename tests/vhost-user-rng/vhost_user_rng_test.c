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
 * esdm-vhost-user-rng driven by a front-end of the test: the vhost-user
 * protocol, the serving of the ring, a guest doing what it must not, and a
 * front-end doing what it must not. The random bytes come from a stand-in
 * ESDM, see vu_standin.h, whose stream the test predicts.
 *
 * Every check of a request also checks that the daemon wrote nothing into
 * guest memory but the bytes of the request and the used ring: guest memory
 * starts out filled with FE_CANARY, which the stand-in never serves.
 *
 * The test cases are grouped, one group per argument, as each group runs a
 * daemon - or several - of its own:
 *
 *	protocol	negotiation, malformed and unsupported messages
 *	ring		serving requests, chains, indirect tables, notifications
 *	hostile		requests and rings a hostile guest writes
 *	lifecycle	stopping, disabling, resetting, reconnecting, memory
 *			changing under a request, waiting for the seeding
 *	options		--max_bytes/--period_ms, --pr, and --user/--group
 *			when run as root
 *	esdm		the real thing: an esdm-server instead of the stand-in,
 *			which takes root, as the server does
 */

#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../rpc_client/env.h"
#include "../test_env.h"
#include "../test_plan.h"
#include "../test_wait.h"
#include "vu_frontend.h"
#include "vu_standin.h"

/* Guest memory: above 4 GiB, so that addresses need all 64 bits */
#define TEST_GPA 0x100000000ULL
#define TEST_MEM_SIZE (1U << 20)
#define TEST_NUM 8

/* What the daemon serves one request with at most */
#define TEST_REQ_MAX 4096

#define TEST_WAIT_MS 5000
/* How long nothing has to happen to count as not happening */
#define TEST_QUIET_MS 400

#define TEST_PFEATURES                                                         \
	(VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_MQ) |                            \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK) |                     \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_RESET_DEVICE) |                  \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS))

#define TEST_INDIRECT VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC)
#define TEST_EVENT_IDX VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX)

static const char *test_daemon;
static char test_dir[64];
static char test_sock[96];
static unsigned int test_failures;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!TEST_CHECK(cond, __VA_ARGS__))                            \
			test_failures++;                                       \
	} while (0)

/******************************************************************************
 * Helpers
 ******************************************************************************/

/* Start the daemon, logging into @log_fd, with -vvvvv if @verbose */
static pid_t test_start_log(const char *const *extra, int log_fd,
			    bool verbose)
{
	pid_t pid;

	unlink(test_sock);
	pid = fe_spawn_log(test_daemon, test_sock, extra, log_fd, verbose);
	if (pid < 0)
		return pid;

	if (!test_wait_for_type(test_sock, S_IFSOCK, TEST_WAIT_TIMEOUT_MS)) {
		fe_stop(pid, 1000);
		return -ETIMEDOUT;
	}

	return pid;
}

static pid_t test_start(const char *const *extra)
{
	return test_start_log(extra, -1, true);
}

/* A file in the test directory for the log of a daemon, -1 on error */
static int test_log_open(void)
{
	char path[128];

	snprintf(path, sizeof(path), "%s/daemon.log", test_dir);
	return open(path, O_RDWR | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC,
		    0600);
}

static void test_log_close(int fd)
{
	char path[128];

	snprintf(path, sizeof(path), "%s/daemon.log", test_dir);
	close(fd);
	unlink(path);
}

/*
 * The log of a daemon so far, at most 1 MiB of it, NUL terminated - NULL if it
 * cannot be read
 */
static char *test_log_read(int fd, size_t *len)
{
	static const size_t max = 1U << 20;
	char *buf = malloc(max + 1);
	size_t got = 0;

	if (!buf)
		return NULL;

	while (got < max) {
		ssize_t n = pread(fd, buf + got, max - got, (off_t)got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		got += (size_t)n;
	}
	buf[got] = 0;
	if (len)
		*len = got;

	return buf;
}

/* How often the log of a daemon holds @what */
static unsigned int test_log_count(int fd, const char *what)
{
	char *buf = test_log_read(fd, NULL);
	const char *p;
	unsigned int n = 0;

	if (!buf)
		return 0;
	for (p = buf; (p = strstr(p, what)); p += strlen(what))
		n++;
	free(buf);

	return n;
}

/* Wait until a line of the log holds @what */
static bool test_log_wait(int fd, const char *what, int timeout_ms)
{
	uint64_t end = fe_now_ms() + (uint64_t)timeout_ms;

	do {
		if (test_log_count(fd, what))
			return true;
		fe_sleep_ms(20);
	} while (fe_now_ms() < end);

	return false;
}

/* Print the log of a daemon from offset @from on into the output of the test */
static void test_log_print(int fd, size_t from)
{
	size_t len = 0;
	char *buf = test_log_read(fd, &len);

	if (!buf)
		return;
	if (from < len)
		printf("  log of the daemon:\n%s\n", buf + from);
	free(buf);
}

static void test_end(pid_t pid)
{
	int status;

	CHECK(fe_alive(pid), "daemon %d alive at the end", (int)pid);
	status = fe_stop(pid, 5000);
	CHECK(status == 0, "daemon exit status %d after SIGTERM", status);
}

/* Copy of guest memory to compare against */
static uint8_t *test_snapshot(const struct fe_mem *m)
{
	uint8_t *s = malloc(m->size);

	if (s)
		memcpy(s, m->ptr, m->size);
	return s;
}

struct test_range {
	size_t off;
	size_t len;
};

/*
 * Bytes of @m changed against @snap outside the rings and @n ranges of
 * offsets
 */
static size_t test_changed_outside(const struct fe *fe, const struct fe_mem *m,
				   const uint8_t *snap,
				   const struct test_range *allowed,
				   unsigned int n)
{
	size_t i, changed = 0, used_end, avail_end;
	unsigned int r;

	used_end = FE_USED_OFF + 4 + 8 * (size_t)fe->num + 2;
	avail_end = FE_AVAIL_OFF + 4 + 2 * (size_t)fe->num + 2;

	for (i = 0; i < m->size; i++) {
		bool ok = false;

		if (m->ptr[i] == snap[i])
			continue;
		/* The used ring is the device's, the available the driver's */
		if (m == fe->mem && i >= FE_USED_OFF && i < used_end)
			continue;
		if (m == fe->mem && i >= FE_AVAIL_OFF && i < avail_end)
			continue;
		for (r = 0; r < n; r++) {
			if (i >= allowed[r].off &&
			    i < allowed[r].off + allowed[r].len)
				ok = true;
		}
		if (!ok) {
			if (!changed)
				printf("  first stray write at offset 0x%zx\n",
				       i);
			changed++;
		}
	}

	return changed;
}

/* Whether @len bytes at @p are the stream from @pos on */
static bool test_is_stream(const uint8_t *p, size_t len, uint64_t pos)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] != standin_stream_byte(pos + i)) {
			printf("  byte %zu is 0x%02x, the stream has 0x%02x\n",
			       i, p[i], standin_stream_byte(pos + i));
			return false;
		}
	}

	return true;
}

/* Whether none of @len bytes at @p is the canary any more */
static bool test_all_written(const uint8_t *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] == FE_CANARY)
			return false;
	}
	return true;
}

/*
 * Make @head available, wait for it to be used, and check the used element:
 * the head as ID and @expect_len as length. Returns whether all held.
 */
static bool test_serve(struct fe *fe, uint16_t head, uint32_t expect_len)
{
	uint16_t target = (uint16_t)(drv_used_idx(fe) + 1);
	uint32_t id = 0, len = 0;
	bool ok;

	drv_avail(fe, head);
	ok = drv_wait_used(fe, target, TEST_WAIT_MS);
	CHECK(ok, "request %u completed", head);
	if (!ok)
		return false;

	drv_used_elem(fe, (uint16_t)(target - 1), &id, &len);
	CHECK(id == head, "used ID %u for request %u", id, head);
	CHECK(len == expect_len, "used length %u, expected %u", len,
	      expect_len);

	return id == head && len == expect_len;
}

/* A request the guest got wrong: completed with 0, nothing else written */
static void test_bad(struct fe *fe, uint16_t head, const char *what)
{
	uint8_t *snap = test_snapshot(fe->mem);

	TEST_STEP("hostile request: %s", what);
	if (!snap) {
		test_failures++;
		return;
	}

	test_serve(fe, head, 0);
	CHECK(!test_changed_outside(fe, fe->mem, snap, NULL, 0),
	      "%s: nothing written but the used ring", what);
	free(snap);
}

/* Whether no request is completed within TEST_QUIET_MS */
static bool test_quiet(struct fe *fe)
{
	uint16_t idx = drv_used_idx(fe);

	fe_sleep_ms(TEST_QUIET_MS);
	return drv_used_idx(fe) == idx;
}

/* CPU time process @pid spent so far in milliseconds, -1 if unknown */
static long test_cpu_ms(pid_t pid)
{
	unsigned long utime, stime;
	char path[64], buf[1024];
	const char *p;
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;

	/* Fields 14 and 15, behind the name in parentheses, see proc(5) */
	p = strrchr(buf, ')');
	if (!p || sscanf(p + 1,
			 " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
			 &utime, &stime) != 2)
		return -1;

	return (long)((utime + stime) * 1000 /
		      (unsigned long)sysconf(_SC_CLK_TCK));
}

/* A fresh connection to the daemon answers GET_FEATURES */
static bool test_responsive(void)
{
	struct fe fe;
	uint64_t features = 0;
	int ret = fe_connect(&fe, test_sock);

	if (!ret)
		ret = fe_get_u64(&fe, VHOST_USER_GET_FEATURES, &features);
	fe_close(&fe);

	return !ret && features;
}

/******************************************************************************
 * protocol
 ******************************************************************************/

static void test_negotiation(void)
{
	uint64_t v = 0;
	struct fe fe;
	int ret;

	TEST_STEP("negotiation of features and protocol features");

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		return;

	CHECK(!fe_get_u64(&fe, VHOST_USER_GET_FEATURES, &v), "GET_FEATURES");
	CHECK((v & VHOST_USER_BIT(VIRTIO_F_VERSION_1)) &&
		      (v & TEST_INDIRECT) && (v & TEST_EVENT_IDX) &&
		      (v & VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES)),
	      "features 0x%llx offer VERSION_1, INDIRECT_DESC, EVENT_IDX, PROTOCOL_FEATURES",
	      (unsigned long long)v);
	CHECK(!(v & (VHOST_USER_BIT(VIRTIO_F_RING_PACKED) |
		     VHOST_USER_BIT(VHOST_F_LOG_ALL) |
		     VHOST_USER_BIT(VIRTIO_F_ACCESS_PLATFORM))),
	      "features 0x%llx offer no packed ring, dirty log or IOMMU",
	      (unsigned long long)v);

	CHECK(!fe_get_u64(&fe, VHOST_USER_GET_PROTOCOL_FEATURES, &v),
	      "GET_PROTOCOL_FEATURES");
	CHECK((v & TEST_PFEATURES) == TEST_PFEATURES,
	      "protocol features 0x%llx offer MQ, REPLY_ACK, RESET_DEVICE, CONFIGURE_MEM_SLOTS",
	      (unsigned long long)v);
	CHECK(!(v & (VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_CONFIG) |
		     VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_LOG_SHMFD) |
		     VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD))),
	      "protocol features 0x%llx offer no config space, log or inflight",
	      (unsigned long long)v);

	/* The acknowledgement of this one is switched on by itself */
	ret = fe_send(&fe, VHOST_USER_SET_PROTOCOL_FEATURES,
		      VHOST_USER_NEED_REPLY_MASK, &(uint64_t){ TEST_PFEATURES },
		      8, NULL, 0);
	fe.reply_ack = true;
	CHECK(!ret, "SET_PROTOCOL_FEATURES sent");
	{
		struct vhost_user_hdr hdr;
		uint64_t ack = 1;

		ret = fe_recv(&fe, &hdr, &ack, sizeof(ack), TEST_WAIT_MS);
		CHECK(!ret && hdr.request == VHOST_USER_SET_PROTOCOL_FEATURES &&
			      hdr.size == 8 && !ack,
		      "SET_PROTOCOL_FEATURES acknowledged: %d, ack %llu", ret,
		      (unsigned long long)ack);
	}

	ret = fe_get_u64(&fe, VHOST_USER_GET_QUEUE_NUM, &v);
	CHECK(!ret && v == 1, "GET_QUEUE_NUM %llu", (unsigned long long)v);
	ret = fe_get_u64(&fe, VHOST_USER_GET_MAX_MEM_SLOTS, &v);
	CHECK(!ret && v == 509, "GET_MAX_MEM_SLOTS %llu",
	      (unsigned long long)v);
	CHECK(!fe_request(&fe, VHOST_USER_SET_OWNER, NULL, 0, NULL, 0),
	      "SET_OWNER");

	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_FEATURES,
			  VHOST_USER_BIT(VIRTIO_F_VERSION_1) | TEST_EVENT_IDX |
				  VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES)),
	      "SET_FEATURES accepted");
	CHECK(fe_set_u64(&fe, VHOST_USER_SET_FEATURES,
			 VHOST_USER_BIT(VIRTIO_F_VERSION_1) |
				 VHOST_USER_BIT(VIRTIO_F_RING_PACKED)) > 0,
	      "SET_FEATURES with the packed ring refused");
	CHECK(fe_set_u64(&fe, VHOST_USER_SET_FEATURES,
			 VHOST_USER_BIT(VHOST_F_LOG_ALL)) > 0,
	      "SET_FEATURES with the dirty log refused");
	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_FEATURES,
			  VHOST_USER_BIT(VIRTIO_F_VERSION_1) |
				  VHOST_USER_BIT(VIRTIO_F_IN_ORDER)),
	      "SET_FEATURES with IN_ORDER, not offered, ignored");
	CHECK(fe_set_u64(&fe, VHOST_USER_SET_PROTOCOL_FEATURES,
			 TEST_PFEATURES |
				 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_CONFIG)) > 0,
	      "SET_PROTOCOL_FEATURES with CONFIG refused");
	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_PROTOCOL_FEATURES,
			  TEST_PFEATURES),
	      "SET_PROTOCOL_FEATURES again");

	fe_close(&fe);
}

/*
 * One malformed message on a connection of its own: the daemon closes it, or
 * - @closes false - answers and goes on. Either way it serves the next one.
 */
static void test_malformed_one(const char *what, uint32_t request,
			       uint32_t flags, const void *payload,
			       uint32_t size, const int *fds,
			       unsigned int nfds, bool closes)
{
	struct fe fe;
	int ret;

	TEST_STEP("malformed message: %s", what);

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		return;

	ret = fe_send(&fe, request, flags, payload, size, fds, nfds);
	CHECK(!ret, "%s sent: %d", what, ret);

	if (closes) {
		CHECK(fe_closed(&fe, TEST_WAIT_MS), "%s closes the connection",
		      what);
	} else {
		uint64_t v = 0;

		CHECK(!fe_get_u64(&fe, VHOST_USER_GET_FEATURES, &v) && v,
		      "%s leaves the connection usable", what);
	}

	fe_close(&fe);
	CHECK(test_responsive(), "daemon serves after %s", what);
}

/* Raw bytes on a connection of their own, then the connection closed */
static void test_raw_one(const char *what, const void *buf, size_t len)
{
	struct fe fe;
	int ret;

	TEST_STEP("truncated message: %s", what);

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		return;
	CHECK(write(fe.sock, buf, len) == (ssize_t)len, "%s written", what);
	fe_close(&fe);

	CHECK(test_responsive(), "daemon serves after %s", what);
}

static void test_malformed(pid_t pid)
{
	struct vhost_user_hdr hdr = { .request = VHOST_USER_SET_FEATURES,
				      .flags = VHOST_USER_VERSION,
				      .size = 8 };
	uint8_t raw[sizeof(hdr) + 4] = { 0 };
	uint64_t u64 = 0;
	struct vhost_user_vring_state state = { 0 };
	uint8_t table[8 + 33 * 32] = { 0 };
	int fds[40];
	unsigned int i;
	int efd = eventfd(0, EFD_CLOEXEC);

	for (i = 0; i < 40; i++)
		fds[i] = efd;

	test_raw_one("header cut short", &hdr, 6);
	memcpy(raw, &hdr, sizeof(hdr));
	test_raw_one("payload cut short", raw, sizeof(raw));

	{
		/* The size field says 1 MiB, the send carries only the header */
		struct fe fe;

		TEST_STEP("malformed message: payload of 1 MiB announced");
		if (!fe_connect(&fe, test_sock)) {
			struct vhost_user_hdr big = {
				.request = VHOST_USER_SET_FEATURES,
				.flags = VHOST_USER_VERSION,
				.size = 1U << 20
			};

			CHECK(write(fe.sock, &big, sizeof(big)) ==
				      (ssize_t)sizeof(big),
			      "header written");
			CHECK(fe_closed(&fe, TEST_WAIT_MS),
			      "a 1 MiB payload closes the connection");
			fe_close(&fe);
		}
	}

	/* fe_send() adds version 1 to the flags: 1 | 2 is version 3 */
	test_malformed_one("version 3", VHOST_USER_GET_FEATURES, 0x2, NULL, 0,
			   NULL, 0, true);
	test_malformed_one("reply flag on a request", VHOST_USER_GET_FEATURES,
			   VHOST_USER_REPLY_MASK, NULL, 0, NULL, 0, true);
	test_malformed_one("unknown flag", VHOST_USER_GET_FEATURES, 0x100,
			   NULL, 0, NULL, 0, true);
	test_malformed_one("SET_VRING_NUM with 4 bytes",
			   VHOST_USER_SET_VRING_NUM, 0, &state, 4, NULL, 0,
			   true);
	test_malformed_one("GET_FEATURES with payload",
			   VHOST_USER_GET_FEATURES, 0, &u64, 8, NULL, 0, true);
	test_malformed_one("GET_FEATURES with a descriptor",
			   VHOST_USER_GET_FEATURES, 0, NULL, 0, fds, 1, true);
	test_malformed_one("SET_VRING_KICK without descriptor",
			   VHOST_USER_SET_VRING_KICK, 0, &u64, 8, NULL, 0,
			   true);
	u64 = VHOST_USER_VRING_NOFD_MASK;
	test_malformed_one("SET_VRING_KICK without-descriptor flag and one",
			   VHOST_USER_SET_VRING_KICK, 0, &u64, 8, fds, 1,
			   true);
	u64 = 0;
	test_malformed_one("SET_VRING_CALL with two descriptors",
			   VHOST_USER_SET_VRING_CALL, 0, &u64, 8, fds, 2,
			   true);
	table[0] = 2;
	test_malformed_one("SET_MEM_TABLE of 2 regions with 1 descriptor",
			   VHOST_USER_SET_MEM_TABLE, 0, table, 8 + 2 * 32, fds,
			   1, true);
	test_malformed_one("SET_MEM_TABLE of 2 regions with 3 descriptors",
			   VHOST_USER_SET_MEM_TABLE, 0, table, 8 + 2 * 32, fds,
			   3, true);
	test_malformed_one("SET_MEM_TABLE of 2 regions in 3",
			   VHOST_USER_SET_MEM_TABLE, 0, table, 8 + 3 * 32, fds,
			   2, true);
	table[0] = 33;
	test_malformed_one("SET_MEM_TABLE of 33 regions",
			   VHOST_USER_SET_MEM_TABLE, 0, table, 8 + 33 * 32,
			   fds, 0, true);
	test_malformed_one("40 descriptors", VHOST_USER_GET_FEATURES, 0, NULL,
			   0, fds, 40, true);
	test_malformed_one("ADD_MEM_REG without descriptor",
			   VHOST_USER_ADD_MEM_REG, 0, table, 40, NULL, 0, true);
	test_malformed_one("GET_INFLIGHT_FD, not offered",
			   VHOST_USER_GET_INFLIGHT_FD, 0, table, 24, NULL, 0,
			   true);
	/* Its reply is the state of the ring, which vring 1 has none of */
	state.index = 1;
	test_malformed_one("GET_VRING_BASE of vring 1",
			   VHOST_USER_GET_VRING_BASE, 0, &state, sizeof(state),
			   NULL, 0, true);
	test_malformed_one("GET_VRING_BASE of vring 1, a reply asked for",
			   VHOST_USER_GET_VRING_BASE,
			   VHOST_USER_NEED_REPLY_MASK, &state, sizeof(state),
			   NULL, 0, true);
	state.index = 0;
	test_malformed_one("unknown request 99", 99, 0, NULL, 0, NULL, 0,
			   false);
	test_malformed_one("unknown request 0 with a descriptor", 0, 0, NULL,
			   0, fds, 1, false);

	close(efd);
	CHECK(fe_alive(pid), "daemon alive after the malformed messages");
}

/* Requests that make sense as messages, but fail - or are not supported */
static void test_refused(pid_t pid)
{
	struct vhost_user_vring_addr addr = { 0 };
	struct vhost_user_hdr hdr;
	struct fe_mem mem, mem2;
	struct fe fe;
	uint8_t buf[4096];
	uint32_t num = 1;
	uint64_t v;
	int ret, efd;

	TEST_STEP("requests that fail");

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		return;
	CHECK(!fe_negotiate(&fe, 0, TEST_PFEATURES), "negotiation");

	/* The ring before there is memory: deferred, not refused */
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 8),
	      "SET_VRING_NUM before SET_MEM_TABLE");
	addr.desc_user_addr = 0x10000;
	addr.avail_user_addr = 0x20000;
	addr.used_user_addr = 0x30000;
	CHECK(!fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			  NULL, 0),
	      "SET_VRING_ADDR before SET_MEM_TABLE");
	addr.flags = 1U << VHOST_VRING_F_LOG;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "SET_VRING_ADDR with logging refused");
	addr.flags = 0;
	addr.index = 1;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "SET_VRING_ADDR of vring 1 refused");

	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 0) > 0,
	      "queue size 0 refused");
	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 3) > 0,
	      "queue size 3 refused");
	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 65536) > 0,
	      "queue size 65536 refused");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 32768),
	      "queue size 32768 accepted");
	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 3, 8) > 0,
	      "SET_VRING_NUM of vring 3 refused");
	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_BASE, 0, 0x10000) > 0,
	      "ring base beyond 16 bits refused");
	CHECK(fe_set_state(&fe, VHOST_USER_SET_VRING_ENABLE, 0, 2) > 0,
	      "SET_VRING_ENABLE 2 refused");

	efd = eventfd(0, EFD_CLOEXEC);
	v = 7;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_KICK, &v, 8, &efd, 1) > 0,
	      "SET_VRING_KICK of vring 7 refused");
	v = 0x200;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_CALL, &v, 8, &efd, 1) > 0,
	      "SET_VRING_CALL with a reserved bit refused");
	close(efd);

	ret = fe_get_vring_base(&fe, 0, &num);
	CHECK(!ret && num == 0, "GET_VRING_BASE of a ring never started: %u",
	      num);

	/* Memory regions the daemon cannot take */
	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_mem_create(&mem2, TEST_MEM_SIZE, TEST_GPA), "memfd");

	mem.size = 0;
	CHECK(fe_set_mem_table(&fe, &mem, 1) > 0, "region of size 0 refused");
	mem.size = 2 * TEST_MEM_SIZE;
	CHECK(fe_set_mem_table(&fe, &mem, 1) > 0,
	      "region beyond the end of its file refused");
	mem.size = TEST_MEM_SIZE;
	mem.gpa = ~0ULL - 0x1000;
	CHECK(fe_set_mem_table(&fe, &mem, 1) > 0,
	      "region wrapping around the guest address space refused");
	mem.gpa = TEST_GPA;
	{
		struct fe_mem two[2] = { mem, mem2 };

		CHECK(fe_set_mem_table(&fe, two, 2) > 0,
		      "overlapping regions refused");
	}
	CHECK(!fe_set_mem_table(&fe, &mem, 1), "a proper region taken");
	CHECK(fe_add_mem_reg(&fe, &mem2) > 0,
	      "ADD_MEM_REG of an overlapping region refused");
	mem2.gpa = TEST_GPA + 2 * TEST_MEM_SIZE;
	mem2.uaddr += 7;
	CHECK(fe_rem_mem_reg(&fe, &mem2) > 0,
	      "REM_MEM_REG of an unknown region refused");

	/* Unsupported, with a reply the specification defines */
	CHECK(!fe_send(&fe, VHOST_USER_GET_CONFIG, 0, buf, 12, NULL, 0),
	      "GET_CONFIG sent");
	ret = fe_recv(&fe, &hdr, buf, sizeof(buf), TEST_WAIT_MS);
	CHECK(!ret && hdr.request == VHOST_USER_GET_CONFIG && !hdr.size,
	      "GET_CONFIG answered without payload: %d, size %u", ret,
	      hdr.size);
	memset(buf, 0, 32);
	CHECK(!fe_send(&fe, VHOST_USER_IOTLB_MSG, 0, buf, 32, NULL, 0),
	      "IOTLB_MSG sent");
	ret = fe_recv(&fe, &hdr, &v, sizeof(v), TEST_WAIT_MS);
	CHECK(!ret && hdr.request == VHOST_USER_IOTLB_MSG && hdr.size == 8 && v,
	      "IOTLB_MSG answered with a failure");
	CHECK(fe_request(&fe, VHOST_USER_SET_LOG_BASE, buf, 8, NULL, 0) > 0,
	      "SET_LOG_BASE refused");
	CHECK(fe_request(&fe, 99, NULL, 0, NULL, 0) > 0,
	      "unknown request refused with REPLY_ACK");

	fe_close(&fe);
	fe_mem_destroy(&mem);
	fe_mem_destroy(&mem2);

	/*
	 * With REPLY_ACK, a failure of GET_VRING_BASE would be acknowledged
	 * where the front-end reads the state of the ring: the connection is
	 * closed instead
	 */
	{
		struct vhost_user_vring_state state = { .index = 1 };

		CHECK(!fe_connect(&fe, test_sock), "connect");
		CHECK(!fe_negotiate(&fe, 0, TEST_PFEATURES), "negotiation");
		CHECK(!fe_send(&fe, VHOST_USER_GET_VRING_BASE,
			       VHOST_USER_NEED_REPLY_MASK, &state,
			       sizeof(state), NULL, 0),
		      "GET_VRING_BASE of vring 1 sent");
		CHECK(fe_closed(&fe, TEST_WAIT_MS),
		      "GET_VRING_BASE of vring 1 closes the connection, REPLY_ACK negotiated");
		fe_close(&fe);
	}

	CHECK(fe_alive(pid), "daemon alive after the refused requests");
}

static int test_group_protocol(void)
{
	pid_t pid = test_start(NULL);

	if (pid < 0)
		return 1;

	test_negotiation();
	test_malformed(pid);
	test_refused(pid);

	test_end(pid);
	return 0;
}

/******************************************************************************
 * ring
 ******************************************************************************/

/* One request of a single buffer of @len bytes at @off, all of it served */
static void test_simple(struct fe *fe, size_t off, uint32_t len,
			uint32_t expect)
{
	struct test_range r = { FE_DATA_OFF + off, expect };
	uint64_t pos = standin_pos();
	uint8_t *snap;

	drv_desc(fe, 0, fe_data_gpa(fe, off), len, VIRTQ_DESC_F_WRITE, 0);
	snap = test_snapshot(fe->mem);
	if (!snap) {
		test_failures++;
		return;
	}
	if (test_serve(fe, 0, expect)) {
		CHECK(test_is_stream(fe_data_ptr(fe, off), expect, pos),
		      "the %u bytes served are those of the ESDM", expect);
		CHECK(!test_changed_outside(fe, fe->mem, snap, &r, 1),
		      "nothing written beyond the %u bytes", expect);
	}
	free(snap);
}

static void test_ring_basic(void)
{
	struct fe_mem mem;
	struct fe fe;
	uint8_t *snap;
	uint64_t pos;
	struct test_range r[2];
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, TEST_INDIRECT, TEST_PFEATURES,
		       TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	TEST_STEP("one buffer");
	test_simple(&fe, 0, 64, 64);
	CHECK(fe_signalled(fe.call, TEST_WAIT_MS), "guest notified");

	TEST_STEP("one buffer of 1 byte");
	test_simple(&fe, 0x100, 1, 1);

	TEST_STEP("a buffer larger than a request is served with");
	test_simple(&fe, 0x1000, 65536, TEST_REQ_MAX);

	TEST_STEP("a chain of three buffers");
	pos = standin_pos();
	drv_desc(&fe, 1, fe_data_gpa(&fe, 0x20000), 16,
		 VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 4);
	drv_desc(&fe, 4, fe_data_gpa(&fe, 0x21000), 0,
		 VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 2);
	drv_desc(&fe, 2, fe_data_gpa(&fe, 0x22000), 48, VIRTQ_DESC_F_WRITE,
		 0);
	snap = test_snapshot(&mem);
	if (test_serve(&fe, 1, 64)) {
		r[0] = (struct test_range){ FE_DATA_OFF + 0x20000, 16 };
		r[1] = (struct test_range){ FE_DATA_OFF + 0x22000, 48 };
		CHECK(test_is_stream(fe_data_ptr(&fe, 0x20000), 16, pos) &&
			      test_is_stream(fe_data_ptr(&fe, 0x22000), 48,
					     pos + 16),
		      "the chain holds the bytes in order");
		CHECK(!test_changed_outside(&fe, &mem, snap, r, 2),
		      "nothing written beyond the chain");
	}
	free(snap);

	TEST_STEP("a chain of zero-length buffers");
	drv_desc(&fe, 3, fe_data_gpa(&fe, 0x23000), 0,
		 VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 5);
	drv_desc(&fe, 5, fe_data_gpa(&fe, 0x23000), 0, VIRTQ_DESC_F_WRITE, 0);
	test_bad(&fe, 3, "only zero-length buffers");

	TEST_STEP("no interrupt while the driver suppresses it");
	(void)fe_signalled(fe.call, 0);
	drv_set_avail_flags(&fe, VIRTQ_AVAIL_F_NO_INTERRUPT);
	test_simple(&fe, 0, 32, 32);
	CHECK(!fe_signalled(fe.call, TEST_QUIET_MS),
	      "no notification with VIRTQ_AVAIL_F_NO_INTERRUPT");
	drv_set_avail_flags(&fe, 0);
	test_simple(&fe, 0, 32, 32);
	CHECK(fe_signalled(fe.call, TEST_WAIT_MS),
	      "notification without VIRTQ_AVAIL_F_NO_INTERRUPT");

	TEST_STEP("many requests, the ring wrapping around");
	{
		unsigned int i;
		uint16_t start = drv_used_idx(&fe);

		for (i = 0; i < 3 * TEST_NUM; i++) {
			drv_desc(&fe, 6, fe_data_gpa(&fe, 0x30000 + 64 * i), 64,
				 VIRTQ_DESC_F_WRITE, 0);
			if (!test_serve(&fe, 6, 64))
				break;
		}
		CHECK(drv_used_idx(&fe) == (uint16_t)(start + 3 * TEST_NUM),
		      "used index %u after %u requests", drv_used_idx(&fe),
		      3 * TEST_NUM);
	}

	TEST_STEP("several requests made available at once");
	{
		uint16_t start = drv_used_idx(&fe), i;
		uint64_t base = fe.avail_idx;
		uint16_t *ring = (uint16_t *)(void *)(mem.ptr + FE_AVAIL_OFF + 4);

		for (i = 0; i < TEST_NUM; i++) {
			drv_desc(&fe, i, fe_data_gpa(&fe, 0x40000 + 256 * (size_t)i),
				 256, VIRTQ_DESC_F_WRITE, 0);
			ring[(base + i) & (TEST_NUM - 1)] = htole16(i);
		}
		drv_avail_raw(&fe, (uint16_t)(base + TEST_NUM));
		drv_kick(&fe);
		CHECK(drv_wait_used(&fe, (uint16_t)(start + TEST_NUM),
				    TEST_WAIT_MS),
		      "%u requests completed", TEST_NUM);
		for (i = 0; i < TEST_NUM; i++) {
			uint32_t id, len;

			drv_used_elem(&fe, (uint16_t)(start + i), &id, &len);
			CHECK(id == i && len == 256,
			      "request %u in order: ID %u, length %u", i, id,
			      len);
			CHECK(test_all_written(fe_data_ptr(&fe, 0x40000 + 256 * (size_t)i),
					       256),
			      "request %u filled", i);
		}
	}

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
}

static void test_ring_indirect(void)
{
	struct fe_mem mem;
	struct fe fe;
	uint8_t *snap;
	uint64_t pos;
	struct test_range r[2];
	uint8_t *table;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, TEST_INDIRECT, TEST_PFEATURES,
		       TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	TEST_STEP("an indirect table of two buffers");
	pos = standin_pos();
	/* The table, written as the driver does, at an odd address */
	table = fe_data_ptr(&fe, 0x8008);
	{
		struct fe tmp = fe;
		struct fe_mem tm = mem;

		/* drv_desc() writes at FE_DESC_OFF of the memory it is given */
		tm.ptr = table - FE_DESC_OFF;
		tmp.mem = &tm;
		drv_desc(&tmp, 0, fe_data_gpa(&fe, 0x9000), 32,
			 VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 1);
		drv_desc(&tmp, 1, fe_data_gpa(&fe, 0xa000), 32,
			 VIRTQ_DESC_F_WRITE, 0);
	}
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0x8008), 32, VIRTQ_DESC_F_INDIRECT,
		 0);
	snap = test_snapshot(&mem);
	if (test_serve(&fe, 0, 64)) {
		r[0] = (struct test_range){ FE_DATA_OFF + 0x9000, 32 };
		r[1] = (struct test_range){ FE_DATA_OFF + 0xa000, 32 };
		CHECK(test_is_stream(fe_data_ptr(&fe, 0x9000), 32, pos) &&
			      test_is_stream(fe_data_ptr(&fe, 0xa000), 32,
					     pos + 32),
		      "the indirect buffers hold the bytes");
		CHECK(!test_changed_outside(&fe, &mem, snap, r, 2),
		      "nothing written beyond the indirect buffers");
	}
	free(snap);

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
}

static void test_ring_event_idx(void)
{
	struct fe_mem mem;
	struct fe fe;
	uint16_t used;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, TEST_EVENT_IDX, TEST_PFEATURES,
		       TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	TEST_STEP("event index: the device asks for the next kick");
	/* Notify at every completion, as a driver does that waits for one */
	drv_set_used_event(&fe, 0);
	test_simple(&fe, 0, 32, 32);
	CHECK(fe_signalled(fe.call, TEST_WAIT_MS), "notified at used event 0");
	used = drv_used_idx(&fe);
	fe_sleep_ms(100);
	{
		uint16_t ev = drv_avail_event(&fe);

		CHECK(ev == used, "avail event %u is the next request %u", ev,
		      used);
	}

	TEST_STEP("event index: a notification only past the used event");
	(void)fe_signalled(fe.call, 0);
	drv_set_used_event(&fe, (uint16_t)(used + 1));
	test_simple(&fe, 0, 32, 32);
	CHECK(!fe_signalled(fe.call, TEST_QUIET_MS),
	      "no notification before the used event");
	test_simple(&fe, 0, 32, 32);
	CHECK(fe_signalled(fe.call, TEST_WAIT_MS),
	      "notification past the used event");

	TEST_STEP("event index: indirect descriptors not negotiated");
	drv_desc(&fe, 1, fe_data_gpa(&fe, 0x8000), 16, VIRTQ_DESC_F_INDIRECT,
		 0);
	test_bad(&fe, 1, "indirect table without INDIRECT_DESC");

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
}

/* Buffers spanning two adjacent regions, and a region with a gap behind */
static void test_ring_regions(void)
{
	struct fe_mem mem[3];
	struct fe fe;
	uint64_t pos;
	uint8_t *snap0, *snap1;
	struct test_range r0, r1;
	int ret;

	CHECK(!fe_mem_create(&mem[0], TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_mem_create(&mem[1], TEST_MEM_SIZE, TEST_GPA + TEST_MEM_SIZE),
	      "memfd");
	/* A gap of a page between the second region and the third */
	CHECK(!fe_mem_create(&mem[2], TEST_MEM_SIZE,
			     TEST_GPA + 2 * TEST_MEM_SIZE + 4096),
	      "memfd");

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		goto out;
	fe.mem = &mem[0];
	CHECK(!fe_negotiate(&fe, TEST_INDIRECT, TEST_PFEATURES),
	      "negotiation");
	CHECK(!fe_set_mem_table(&fe, mem, 3), "three regions");
	CHECK(!fe_ring_setup(&fe, TEST_NUM), "ring");

	TEST_STEP("a buffer spanning two adjacent regions");
	pos = standin_pos();
	drv_desc(&fe, 0, TEST_GPA + TEST_MEM_SIZE - 16, 48, VIRTQ_DESC_F_WRITE,
		 0);
	snap0 = test_snapshot(&mem[0]);
	snap1 = test_snapshot(&mem[1]);
	if (test_serve(&fe, 0, 48)) {
		r0 = (struct test_range){ TEST_MEM_SIZE - 16, 16 };
		r1 = (struct test_range){ 0, 32 };
		CHECK(test_is_stream(mem[0].ptr + TEST_MEM_SIZE - 16, 16, pos) &&
			      test_is_stream(mem[1].ptr, 32, pos + 16),
		      "the bytes continue in the second region");
		CHECK(!test_changed_outside(&fe, &mem[0], snap0, &r0, 1) &&
			      !test_changed_outside(&fe, &mem[1], snap1, &r1,
						    1),
		      "nothing written beyond the buffer");
	}
	free(snap0);
	free(snap1);

	TEST_STEP("a buffer running into the gap behind a region");
	drv_desc(&fe, 0, TEST_GPA + 2 * TEST_MEM_SIZE - 16, 48,
		 VIRTQ_DESC_F_WRITE, 0);
	snap1 = test_snapshot(&mem[1]);
	test_bad(&fe, 0, "buffer into a gap between regions");
	CHECK(!test_changed_outside(&fe, &mem[1], snap1, NULL, 0),
	      "the region before the gap untouched");
	free(snap1);

	TEST_STEP("a buffer in the third region");
	pos = standin_pos();
	drv_desc(&fe, 0, mem[2].gpa + 4096, 64, VIRTQ_DESC_F_WRITE, 0);
	if (test_serve(&fe, 0, 64))
		CHECK(test_is_stream(mem[2].ptr + 4096, 64, pos),
		      "the third region holds the bytes");

	fe_close(&fe);
out:
	fe_mem_destroy(&mem[0]);
	fe_mem_destroy(&mem[1]);
	fe_mem_destroy(&mem[2]);
}

/*
 * What QEMU's vhost-user-rng on the legacy virtio-mmio transport of its microvm
 * machine negotiates: a queue of 4 and the features of the lower 32 bits a
 * legacy driver sees - no VIRTIO_F_VERSION_1, the ring served little endian.
 */
static void test_ring_legacy(void)
{
	struct fe_mem mem;
	struct fe fe;
	unsigned int i;
	int ret;

	TEST_STEP("a legacy driver: no VIRTIO_F_VERSION_1, a queue of 4");
	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		goto out;
	fe.mem = &mem;
	CHECK(!fe_negotiate(&fe, 0, TEST_PFEATURES), "negotiation");
	fe.features = VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES) |
		      TEST_EVENT_IDX | TEST_INDIRECT;
	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_FEATURES, fe.features),
	      "SET_FEATURES without VIRTIO_F_VERSION_1");
	CHECK(!fe_set_mem_table(&fe, &mem, 1), "memory");
	CHECK(!fe_ring_setup(&fe, 4), "ring of 4");

	drv_set_used_event(&fe, 0);
	for (i = 0; i < 9; i++) {
		uint16_t used = drv_used_idx(&fe);

		drv_set_used_event(&fe, used);
		test_simple(&fe, 64 * i, 64, 64);
		CHECK(fe_signalled(fe.call, TEST_WAIT_MS),
		      "request %u notified", i);
	}

	fe_close(&fe);
out:
	fe_mem_destroy(&mem);
}

static int test_group_ring(void)
{
	pid_t pid = test_start(NULL);

	if (pid < 0)
		return 1;

	test_ring_basic();
	test_ring_indirect();
	test_ring_event_idx();
	test_ring_regions();
	test_ring_legacy();

	test_end(pid);
	return 0;
}

/******************************************************************************
 * hostile
 ******************************************************************************/

/* Write descriptor @i of an indirect table at data offset @off */
static void test_table_desc(struct fe *fe, size_t off, uint16_t i,
			    uint64_t addr, uint32_t len, uint16_t flags,
			    uint16_t next)
{
	struct fe_mem tm = *fe->mem;
	struct fe tmp = *fe;

	tm.ptr = fe_data_ptr(fe, off) - FE_DESC_OFF;
	tmp.mem = &tm;
	drv_desc(&tmp, i, addr, len, flags, next);
}

/*
 * Stop and restart a broken ring at where it stopped, with a usable request
 * where the broken one was. Like QEMU, the front-end hands over new kick and
 * call notifiers, but not the err notifier: QEMU sets that once, when it sets
 * the device up, and the next broken ring is signalled on it all the same.
 */
static void test_restart(struct fe *fe)
{
	uint32_t base = 0xffff;
	uint16_t used = drv_used_idx(fe);
	uint16_t *ring = (uint16_t *)(void *)(fe->mem->ptr + FE_AVAIL_OFF + 4);

	int ret = fe_get_vring_base(fe, 0, &base);

	CHECK(!ret && base == used, "GET_VRING_BASE %u, used index %u", base,
	      used);

	/* The driver resets its view of the ring to what was used */
	ring[used & (fe->num - 1)] = 0;
	drv_desc(fe, 0, fe_data_gpa(fe, 0), 16, VIRTQ_DESC_F_WRITE, 0);
	drv_avail_raw(fe, used);

	CHECK(!fe_set_state(fe, VHOST_USER_SET_VRING_BASE, 0, used),
	      "SET_VRING_BASE");
	CHECK(!fe_set_vring_fd(fe, VHOST_USER_SET_VRING_KICK),
	      "SET_VRING_KICK");
	CHECK(!fe_set_vring_fd(fe, VHOST_USER_SET_VRING_CALL),
	      "SET_VRING_CALL");

	test_serve(fe, 0, 16);
}

static void test_hostile_requests(struct fe *fe)
{
	const uint16_t W = VIRTQ_DESC_F_WRITE, N = VIRTQ_DESC_F_NEXT,
		       I = VIRTQ_DESC_F_INDIRECT;
	uint64_t end = TEST_GPA + TEST_MEM_SIZE;

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, 0, 0);
	test_bad(fe, 0, "read-only buffer");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W | N, 1);
	drv_desc(fe, 1, fe_data_gpa(fe, 0x100), 64, 0, 0);
	test_bad(fe, 0, "writable buffer chained to a read-only one");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W | N, TEST_NUM);
	test_bad(fe, 0, "next index beyond the queue");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W | N, 0xffff);
	test_bad(fe, 0, "next index 0xffff");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W | N, 1);
	drv_desc(fe, 1, fe_data_gpa(fe, 0x100), 64, W | N, 0);
	test_bad(fe, 0, "chain looping over two descriptors");

	drv_desc(fe, 2, fe_data_gpa(fe, 0), 64, W | N, 2);
	test_bad(fe, 2, "descriptor chained to itself");

	drv_desc(fe, 0, end - 16, 32, W, 0);
	test_bad(fe, 0, "buffer beyond the end of guest memory");

	drv_desc(fe, 0, TEST_GPA - 16, 32, W, 0);
	test_bad(fe, 0, "buffer starting before guest memory");

	drv_desc(fe, 0, 0x1000, 32, W, 0);
	test_bad(fe, 0, "buffer outside of guest memory");

	drv_desc(fe, 0, 0xfffffffffffffff0ULL, 0x20, W, 0);
	test_bad(fe, 0, "buffer wrapping around the address space");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 0xffffffff, W, 0);
	test_bad(fe, 0, "buffer of 4 GiB");

	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W | N, 1);
	drv_desc(fe, 1, end - 8, 16, W, 0);
	test_bad(fe, 0, "chain ending beyond guest memory");

	/* Indirect tables */
	test_table_desc(fe, 0x8000, 0, fe_data_gpa(fe, 0x9000), 32, W, 0);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 24, I, 0);
	test_bad(fe, 0, "indirect table of 24 bytes");

	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 0, I, 0);
	test_bad(fe, 0, "indirect table of 0 bytes");

	drv_desc(fe, 0, end - 16, 32, I, 0);
	test_bad(fe, 0, "indirect table beyond guest memory");

	drv_desc(fe, 0, 0xfffffffffffffff0ULL, 32, I, 0);
	test_bad(fe, 0, "indirect table wrapping around");

	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 16 * (TEST_NUM + 1), I, 0);
	test_bad(fe, 0, "indirect table longer than the queue");

	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 16, I | N, 1);
	drv_desc(fe, 1, fe_data_gpa(fe, 0x100), 16, W, 0);
	test_bad(fe, 0, "indirect table with NEXT");

	drv_desc(fe, 0, fe_data_gpa(fe, 0x100), 16, W | N, 1);
	drv_desc(fe, 1, fe_data_gpa(fe, 0x8000), 16, I, 0);
	test_bad(fe, 0, "indirect table in the middle of a chain");

	test_table_desc(fe, 0x8000, 0, fe_data_gpa(fe, 0x8100), 16, I, 0);
	test_table_desc(fe, 0x8100, 0, fe_data_gpa(fe, 0x9000), 32, W, 0);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 16, I, 0);
	test_bad(fe, 0, "nested indirect table");

	test_table_desc(fe, 0x8000, 0, fe_data_gpa(fe, 0x9000), 32, W | N, 1);
	test_table_desc(fe, 0x8000, 1, fe_data_gpa(fe, 0x9100), 32, W | N, 0);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 32, I, 0);
	test_bad(fe, 0, "indirect table looping");

	test_table_desc(fe, 0x8000, 0, fe_data_gpa(fe, 0x9000), 32, W | N, 2);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 32, I, 0);
	test_bad(fe, 0, "next index beyond the indirect table");

	test_table_desc(fe, 0x8000, 0, fe_data_gpa(fe, 0x9000), 32, 0, 0);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 16, I, 0);
	test_bad(fe, 0, "read-only buffer in an indirect table");

	test_table_desc(fe, 0x8000, 0, end - 8, 32, W, 0);
	drv_desc(fe, 0, fe_data_gpa(fe, 0x8000), 16, I, 0);
	test_bad(fe, 0, "indirect buffer beyond guest memory");

	/* The ring still serves after all of it */
	TEST_STEP("a proper request after the hostile ones");
	drv_desc(fe, 0, fe_data_gpa(fe, 0), 64, W, 0);
	test_serve(fe, 0, 64);
}

static void test_hostile_ring(struct fe *fe)
{
	uint16_t *ring = (uint16_t *)(void *)(fe->mem->ptr + FE_AVAIL_OFF + 4);
	uint16_t used;

	TEST_STEP("hostile ring: a head beyond the queue");
	(void)fe_signalled(fe->err, 0);
	used = drv_used_idx(fe);
	ring[fe->avail_idx & (fe->num - 1)] = 100;
	drv_avail_raw(fe, (uint16_t)(fe->avail_idx + 1));
	drv_kick(fe);
	CHECK(fe_signalled(fe->err, TEST_WAIT_MS), "error signalled");
	CHECK(drv_used_idx(fe) == used, "nothing completed");
	/* A broken ring stays so, also for a proper request behind */
	drv_desc(fe, 0, fe_data_gpa(fe, 0), 16, VIRTQ_DESC_F_WRITE, 0);
	drv_avail(fe, 0);
	CHECK(test_quiet(fe), "the broken ring is not processed");
	CHECK(!fe_signalled(fe->err, TEST_QUIET_MS), "error signalled once");
	test_restart(fe);

	TEST_STEP("hostile ring: the available index jumping beyond the queue");
	used = drv_used_idx(fe);
	drv_avail_raw(fe, (uint16_t)(fe->avail_idx + fe->num + 1));
	drv_kick(fe);
	CHECK(fe_signalled(fe->err, TEST_WAIT_MS),
	      "error signalled after a restart, on the err notifier of the set-up");
	CHECK(drv_used_idx(fe) == used, "nothing completed");
	test_restart(fe);

	TEST_STEP("hostile ring: the available index going backwards");
	used = drv_used_idx(fe);
	drv_avail_raw(fe, (uint16_t)(fe->avail_idx - 1));
	drv_kick(fe);
	CHECK(fe_signalled(fe->err, TEST_WAIT_MS),
	      "error signalled after another restart");
	CHECK(drv_used_idx(fe) == used, "nothing completed");
	test_restart(fe);

	TEST_STEP("hostile ring: the used index scribbled over");
	/* The device keeps its own index and goes on */
	used = drv_used_idx(fe);
	*(uint16_t *)(void *)(fe->mem->ptr + FE_USED_OFF + 2) = 0x5555;
	drv_desc(fe, 0, fe_data_gpa(fe, 0), 16, VIRTQ_DESC_F_WRITE, 0);
	drv_avail(fe, 0);
	CHECK(drv_wait_used(fe, (uint16_t)(used + 1), TEST_WAIT_MS),
	      "the device publishes its own used index %u",
	      drv_used_idx(fe));
}

/* A ring at the very end of a region, with all of its fields */
static void test_hostile_layout(void)
{
	struct vhost_user_vring_addr addr = { 0 };
	struct fe_mem mem;
	struct fe fe;
	int ret;

	TEST_STEP("rings not where guest memory is");
	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		goto out;
	fe.mem = &mem;
	CHECK(!fe_negotiate(&fe, TEST_EVENT_IDX, TEST_PFEATURES),
	      "negotiation");
	CHECK(!fe_set_mem_table(&fe, &mem, 1), "memory");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, 256), "size");

	addr.desc_user_addr = mem.uaddr;
	addr.avail_user_addr = mem.uaddr + 0x2000;
	/* The used ring of 256 entries and its event index is 2054 bytes */
	addr.used_user_addr = mem.uaddr + TEST_MEM_SIZE - 2052;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "used ring 2 bytes beyond the region refused");
	addr.used_user_addr = mem.uaddr + 0x3002;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "misaligned used ring refused");
	addr.used_user_addr = mem.uaddr + 0x3000;
	addr.desc_user_addr = mem.uaddr + 8;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "misaligned descriptor table refused");
	addr.desc_user_addr = ~0ULL - 64;
	CHECK(fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0) > 0,
	      "descriptor table wrapping around refused");
	addr.desc_user_addr = mem.uaddr;
	addr.used_user_addr = mem.uaddr + TEST_MEM_SIZE - 2056;
	CHECK(!fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			  NULL, 0),
	      "used ring 2 bytes before the end of the region accepted");

	fe_close(&fe);
out:
	fe_mem_destroy(&mem);
}

static int test_group_hostile(void)
{
	struct fe_mem mem;
	struct fe fe;
	pid_t pid = test_start(NULL);
	int ret;

	if (pid < 0)
		return 1;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, TEST_INDIRECT, TEST_PFEATURES,
		       TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (!ret) {
		test_hostile_requests(&fe);
		test_hostile_ring(&fe);
	}
	fe_close(&fe);
	fe_mem_destroy(&mem);

	test_hostile_layout();

	test_end(pid);
	return 0;
}

/******************************************************************************
 * lifecycle
 ******************************************************************************/

static void test_lifecycle_rings(void)
{
	struct fe_mem mem;
	struct fe fe;
	uint32_t base = 0;
	uint16_t used;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);
	test_serve(&fe, 0, 64);
	test_serve(&fe, 0, 64);

	TEST_STEP("GET_VRING_BASE stops the ring");
	ret = fe_get_vring_base(&fe, 0, &base);
	CHECK(!ret && base == 3, "GET_VRING_BASE %u after 3 requests", base);
	drv_avail(&fe, 0);
	CHECK(test_quiet(&fe), "a stopped ring is not processed");

	TEST_STEP("the ring restarted at its base");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_BASE, 0, base),
	      "SET_VRING_BASE");
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK),
	      "SET_VRING_KICK");
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_CALL),
	      "SET_VRING_CALL");
	CHECK(drv_wait_used(&fe, 4, TEST_WAIT_MS),
	      "the request made while stopped is served");

	TEST_STEP("a disabled ring");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_ENABLE, 0, 0),
	      "SET_VRING_ENABLE 0");
	drv_avail(&fe, 0);
	CHECK(test_quiet(&fe), "a disabled ring is not processed");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_ENABLE, 0, 1),
	      "SET_VRING_ENABLE 1");
	CHECK(drv_wait_used(&fe, 5, TEST_WAIT_MS),
	      "the request is served once enabled");

	TEST_STEP("a ring without kick descriptor is polled");
	{
		uint64_t v = VHOST_USER_VRING_NOFD_MASK;

		CHECK(!fe_request(&fe, VHOST_USER_SET_VRING_KICK, &v, 8, NULL,
				  0),
		      "SET_VRING_KICK without descriptor");
		used = drv_used_idx(&fe);
		drv_avail(&fe, 0);
		CHECK(drv_wait_used(&fe, (uint16_t)(used + 1), TEST_WAIT_MS),
		      "served without a kick");
		CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK),
		      "kick descriptor again");
	}

	TEST_STEP("the ring base of the front-end behind the used index");
	/* A restart at a base the guest is past, as Cloud Hypervisor does */
	CHECK(!fe_get_vring_base(&fe, 0, &base), "GET_VRING_BASE");
	used = drv_used_idx(&fe);
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_BASE, 0,
			    (uint16_t)(used + 2)),
	      "SET_VRING_BASE ahead of the used index");
	/* Two requests the guest made that a lost back-end took */
	drv_avail_raw(&fe, (uint16_t)(used + 2));
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK),
	      "SET_VRING_KICK");
	CHECK(drv_wait_used(&fe, (uint16_t)(used + 2), TEST_WAIT_MS),
	      "both requests served from the used index on");

	TEST_STEP("RESET_OWNER resets the ring");
	CHECK(!fe_request(&fe, VHOST_USER_RESET_OWNER, NULL, 0, NULL, 0),
	      "RESET_OWNER");
	used = drv_used_idx(&fe);
	drv_avail(&fe, 0);
	CHECK(test_quiet(&fe), "a reset ring is not processed");
	CHECK(!fe_ring_setup(&fe, TEST_NUM), "ring set up again");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);

	TEST_STEP("RESET_DEVICE resets the device");
	CHECK(!fe_request(&fe, VHOST_USER_RESET_DEVICE, NULL, 0, NULL, 0),
	      "RESET_DEVICE");
	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_FEATURES, fe.features),
	      "SET_FEATURES again");
	CHECK(!fe_ring_setup(&fe, TEST_NUM), "ring set up again");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);

	TEST_STEP("without the protocol features, rings start enabled");
	fe_close(&fe);
	CHECK(!fe_connect(&fe, test_sock), "connect");
	fe.mem = &mem;
	CHECK(!fe_set_u64(&fe, VHOST_USER_SET_FEATURES,
			  VHOST_USER_BIT(VIRTIO_F_VERSION_1)),
	      "SET_FEATURES without protocol features");
	CHECK(!fe_set_mem_table(&fe, &mem, 1), "memory");
	fe.num = TEST_NUM;
	memset(mem.ptr + FE_DESC_OFF, 0, FE_DATA_OFF - FE_DESC_OFF);
	fe.avail_idx = 0;
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_NUM, 0, TEST_NUM), "num");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_BASE, 0, 0), "base");
	{
		struct vhost_user_vring_addr addr = {
			.desc_user_addr = mem.uaddr + FE_DESC_OFF,
			.avail_user_addr = mem.uaddr + FE_AVAIL_OFF,
			.used_user_addr = mem.uaddr + FE_USED_OFF,
		};

		CHECK(!fe_request(&fe, VHOST_USER_SET_VRING_ADDR, &addr,
				  sizeof(addr), NULL, 0),
		      "addr");
	}
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK), "kick");
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_CALL), "call");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
}

/*
 * A kick descriptor that is no eventfd but readable for good is ignored rather
 * than waking the worker without end, until the front-end hands over another
 */
static void test_lifecycle_bad_kick(pid_t pid)
{
	static const char *const devs[] = { "/dev/zero", "/dev/null",
					    "/dev/urandom" };
	struct fe_mem mem, file;
	struct fe fe;
	unsigned int i;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	/* A file of 64 KiB, every byte FE_CANARY */
	CHECK(!fe_mem_create(&file, 65536, 0), "memfd of the file");
	ret = fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	for (i = 0; i <= 3; i++) {
		const char *what = i < 3 ? devs[i] : "a file of 64 KiB";
		uint64_t idx = 0;
		long before, after;
		int fd;

		TEST_STEP("a kick descriptor of %s", what);
		fd = i < 3 ? open(devs[i], O_RDONLY | O_CLOEXEC) :
			     fcntl(file.fd, F_DUPFD_CLOEXEC, 0);
		CHECK(fd >= 0, "%s opened", what);
		if (fd < 0)
			continue;
		CHECK(!fe_request(&fe, VHOST_USER_SET_VRING_KICK, &idx,
				  sizeof(idx), &fd, 1),
		      "SET_VRING_KICK with %s", what);
		close(fd);

		fe_sleep_ms(200);
		before = test_cpu_ms(pid);
		fe_sleep_ms(1000);
		after = test_cpu_ms(pid);
		CHECK(before >= 0 && after >= 0 && after - before < 300,
		      "the daemon spent %ld ms of CPU time in a second",
		      after - before);

		CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK),
		      "an eventfd again");
		drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE,
			 0);
		test_serve(&fe, 0, 64);
	}

out:
	fe_close(&fe);
	fe_mem_destroy(&file);
	fe_mem_destroy(&mem);
}

/*
 * The ESDM refusing every connection - its socket left behind - is logged once
 * by the daemon, and the RPC client with its lines about every attempt does not
 * fill the log meanwhile: a daemon of its own without -v, logging into a file
 */
static void test_lifecycle_esdm_refusing(void)
{
	struct fe_mem mem;
	struct fe fe;
	size_t before = 0, after = 0;
	int log_fd, ret;
	pid_t pid;

	TEST_STEP("the ESDM refusing every connection does not flood the log");
	log_fd = test_log_open();
	CHECK(log_fd >= 0, "log file");
	if (log_fd < 0)
		return;
	pid = test_start_log(NULL, log_fd, false);
	CHECK(pid > 0, "daemon started: %d", (int)pid);
	if (pid <= 0)
		goto out_log;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);

	ret = standin_stop_refusing();
	CHECK(!ret, "the stand-in refusing: %d", ret);
	drv_avail(&fe, 0);
	/* The first request fails once every connection attempt has */
	CHECK(test_log_wait(log_fd, "Cannot obtain random bytes",
			    3 * TEST_WAIT_MS),
	      "the daemon logs that the ESDM fails");

	free(test_log_read(log_fd, &before));
	/* Two more requests, each of 10 attempts that are refused */
	fe_sleep_ms(6000);
	free(test_log_read(log_fd, &after));
	CHECK(after == before,
	      "%zu bytes logged while the ESDM went on refusing",
	      after - before);
	if (after != before)
		test_log_print(log_fd, before);

	ret = standin_start();
	CHECK(!ret, "the stand-in back: %d", ret);
	CHECK(drv_wait_used(&fe, 2, 3 * TEST_WAIT_MS),
	      "served once the ESDM is back");
	CHECK(test_log_wait(log_fd, "The ESDM serves again", TEST_WAIT_MS),
	      "the daemon logs that the ESDM serves again");

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);
out_log:
	test_log_close(log_fd);
}

/*
 * The ESDM gone, and its socket with it: the daemon asks again after 100 ms,
 * doubling the wait up to 5 seconds - what the RPC client logs about every
 * attempt in debug messages shows when it does. A daemon of its own, logging
 * into a file.
 */
static void test_lifecycle_esdm_backoff(void)
{
	uint64_t start, last = 0, gap, gap_max = 0;
	unsigned int seen = 0, n;
	struct fe_mem mem;
	struct fe fe;
	int log_fd, ret;
	pid_t pid;

	TEST_STEP("the ESDM gone: asked again at most every 5 seconds");
	log_fd = test_log_open();
	CHECK(log_fd >= 0, "log file");
	if (log_fd < 0)
		return;
	pid = test_start_log(NULL, log_fd, true);
	CHECK(pid > 0, "daemon started: %d", (int)pid);
	if (pid <= 0)
		goto out_log;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);

	standin_stop();
	drv_avail(&fe, 0);

	/*
	 * Attempts after 0.1, 0.3, 0.7, 1.5, 3.1, 6.3 and 11.3 s: the wait
	 * before the last one is the first of 5 seconds
	 */
	start = fe_now_ms();
	while (fe_now_ms() - start < 16000 && gap_max < 4500) {
		n = test_log_count(log_fd, "not available");
		if (n != seen) {
			uint64_t now = fe_now_ms();

			gap = now - last;
			if (seen && gap > gap_max)
				gap_max = gap;
			seen = n;
			last = now;
		}
		fe_sleep_ms(20);
	}
	CHECK(gap_max >= 4500 && gap_max < 6000,
	      "%u attempts, the longest wait between two %llu ms", seen,
	      (unsigned long long)gap_max);

	ret = standin_start();
	CHECK(!ret, "the stand-in back: %d", ret);
	CHECK(drv_wait_used(&fe, 2, 3 * TEST_WAIT_MS),
	      "served once the ESDM is back");

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);
out_log:
	test_log_close(log_fd);
}

/*
 * A request waits for the ESDM to be seeded, and what the front-end does
 * meanwhile is never held up by it
 */
static void test_lifecycle_seeding(void)
{
	struct fe_mem mem, mem2;
	struct fe fe;
	uint32_t base = 0;
	uint64_t start, pos, took;
	uint8_t *snap;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_mem_create(&mem2, TEST_MEM_SIZE, TEST_GPA), "memfd");
	ret = fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM);
	CHECK(!ret, "set-up: %d", ret);
	if (ret)
		goto out;

	TEST_STEP("nothing is served before the ESDM is seeded");
	standin_set_seeded(false);
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	drv_avail(&fe, 0);
	fe_sleep_ms(1500);
	CHECK(drv_used_idx(&fe) == 0, "not served while unseeded");
	CHECK(fe_data_ptr(&fe, 0)[0] == FE_CANARY, "nothing written");
	standin_set_seeded(true);
	CHECK(drv_wait_used(&fe, 1, TEST_WAIT_MS), "served once seeded");
	CHECK(test_all_written(fe_data_ptr(&fe, 0), 64), "the buffer filled");

	TEST_STEP("GET_VRING_BASE does not wait for the ESDM");
	standin_set_seeded(false);
	drv_avail(&fe, 0);
	fe_sleep_ms(300);
	start = fe_now_ms();
	ret = fe_get_vring_base(&fe, 0, &base);
	took = fe_now_ms() - start;
	CHECK(!ret, "GET_VRING_BASE");
	CHECK(took < 1000, "GET_VRING_BASE took %llu ms",
	      (unsigned long long)took);
	CHECK(base == 1, "the request waiting is not counted: base %u", base);
	standin_set_seeded(true);
	CHECK(test_quiet(&fe), "the stopped ring completes nothing");
	CHECK(!fe_set_state(&fe, VHOST_USER_SET_VRING_BASE, 0, base),
	      "SET_VRING_BASE");
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_KICK), "kick");
	CHECK(!fe_set_vring_fd(&fe, VHOST_USER_SET_VRING_CALL), "call");
	CHECK(drv_wait_used(&fe, 2, TEST_WAIT_MS),
	      "the request is served after the restart");

	TEST_STEP("SET_MEM_TABLE replacing the memory under a waiting request");
	standin_set_seeded(false);
	memset(fe_data_ptr(&fe, 0x100), FE_CANARY, 64);
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0x100), 64, VIRTQ_DESC_F_WRITE, 0);
	drv_avail(&fe, 0);
	fe_sleep_ms(300);
	/* Same addresses, other memory: what QEMU does on a remap */
	memcpy(mem2.ptr, mem.ptr, TEST_MEM_SIZE);
	mem2.uaddr = mem.uaddr;
	snap = test_snapshot(&mem);
	CHECK(!fe_set_mem_table(&fe, &mem2, 1), "SET_MEM_TABLE");
	pos = standin_pos();
	standin_set_seeded(true);
	{
		struct fe on2 = fe;

		on2.mem = &mem2;
		CHECK(drv_wait_used(&on2, 3, TEST_WAIT_MS),
		      "served in the new memory");
		CHECK(test_is_stream(mem2.ptr + FE_DATA_OFF + 0x100, 64, pos),
		      "the new memory holds the bytes");
	}
	CHECK(!memcmp(snap, mem.ptr, TEST_MEM_SIZE),
	      "the old memory untouched");
	free(snap);

	TEST_STEP("the front-end going away under a waiting request");
	{
		struct fe on2 = fe;

		on2.mem = &mem2;
		standin_set_seeded(false);
		drv_desc(&on2, 0, mem2.gpa + FE_DATA_OFF + 0x200, 64,
			 VIRTQ_DESC_F_WRITE, 0);
		drv_avail(&on2, 0);
		fe_sleep_ms(300);
		snap = test_snapshot(&mem2);
		fe_close(&fe);
		bool served;

		start = fe_now_ms();
		served = test_responsive();
		took = fe_now_ms() - start;
		CHECK(served, "the next front-end is served");
		CHECK(took < 2000, "the next connection was taken after %llu ms",
		      (unsigned long long)took);
		standin_set_seeded(true);
		fe_sleep_ms(1500);
		CHECK(!memcmp(snap, mem2.ptr, TEST_MEM_SIZE),
		      "nothing written after the disconnect");
		free(snap);
	}

out:
	fe_close(&fe);
	fe_mem_destroy(&mem);
	fe_mem_destroy(&mem2);
}

/* Memory handed over region by region, as QEMU does with CONFIGURE_MEM_SLOTS */
static void test_lifecycle_mem_slots(void)
{
	struct fe_mem mem, data;
	struct fe fe;
	uint64_t pos;
	int ret;

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_mem_create(&data, TEST_MEM_SIZE, 2 * TEST_GPA), "memfd");

	ret = fe_connect(&fe, test_sock);
	CHECK(!ret, "connect: %d", ret);
	if (ret)
		goto out;
	fe.mem = &mem;
	CHECK(!fe_negotiate(&fe, 0, TEST_PFEATURES), "negotiation");

	TEST_STEP("ADD_MEM_REG");
	CHECK(!fe_add_mem_reg(&fe, &mem), "ADD_MEM_REG of the ring region");
	CHECK(!fe_add_mem_reg(&fe, &data), "ADD_MEM_REG of the data region");
	CHECK(!fe_ring_setup(&fe, TEST_NUM), "ring");
	pos = standin_pos();
	drv_desc(&fe, 0, data.gpa + 0x100, 64, VIRTQ_DESC_F_WRITE, 0);
	if (test_serve(&fe, 0, 64))
		CHECK(test_is_stream(data.ptr + 0x100, 64, pos),
		      "the data region holds the bytes");

	TEST_STEP("REM_MEM_REG of the data region");
	CHECK(!fe_rem_mem_reg(&fe, &data), "REM_MEM_REG");
	memset(data.ptr, FE_CANARY, 4096);
	drv_desc(&fe, 0, data.gpa + 0x100, 64, VIRTQ_DESC_F_WRITE, 0);
	test_bad(&fe, 0, "buffer in a removed region");
	CHECK(data.ptr[0x100] == FE_CANARY, "the removed region untouched");
	CHECK(!fe_add_mem_reg(&fe, &data), "ADD_MEM_REG again");
	test_serve(&fe, 0, 64);

	TEST_STEP("REM_MEM_REG of the region holding the ring");
	CHECK(!fe_rem_mem_reg(&fe, &mem), "REM_MEM_REG");
	{
		uint16_t used = drv_used_idx(&fe);

		drv_avail(&fe, 0);
		CHECK(test_quiet(&fe),
		      "a ring without memory is not processed");
		CHECK(!fe_add_mem_reg(&fe, &mem), "ADD_MEM_REG again");
		CHECK(drv_wait_used(&fe, (uint16_t)(used + 1), TEST_WAIT_MS),
		      "the ring is processed once its memory is back");
	}

	fe_close(&fe);
out:
	fe_mem_destroy(&mem);
	fe_mem_destroy(&data);
}

static int test_group_lifecycle(void)
{
	pid_t pid = test_start(NULL);
	struct fe_mem mem;
	struct fe fe;
	uint64_t start, took;
	int status;

	if (pid < 0)
		return 1;

	test_lifecycle_rings();
	test_lifecycle_bad_kick(pid);
	test_lifecycle_seeding();
	test_lifecycle_mem_slots();

	TEST_STEP("the daemon ends while a request waits for the ESDM");
	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM),
	      "set-up");
	standin_set_seeded(false);
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	drv_avail(&fe, 0);
	fe_sleep_ms(300);
	start = fe_now_ms();
	kill(pid, SIGTERM);
	CHECK(fe_closed(&fe, 5000), "the front-end is let go");
	/*
	 * By then nobody listens any more: a front-end reconnecting at once is
	 * refused rather than taken into a backlog about to go away
	 */
	{
		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

		snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
			 test_sock);
		CHECK(fd >= 0 &&
			      connect(fd, (struct sockaddr *)&addr,
				      sizeof(addr)) < 0,
		      "a reconnecting front-end is refused");
		if (fd >= 0)
			close(fd);
	}
	status = fe_stop(pid, 5000);
	took = fe_now_ms() - start;
	CHECK(status == 0, "exit status %d", status);
	CHECK(took < 3000, "ended after %llu ms", (unsigned long long)took);
	standin_set_seeded(true);
	fe_close(&fe);
	fe_mem_destroy(&mem);

	/* Daemons of their own, after the one of the group ended */
	test_lifecycle_esdm_refusing();
	test_lifecycle_esdm_backoff();

	return 0;
}

/******************************************************************************
 * options
 ******************************************************************************/

static void test_options_ratelimit(void)
{
	static const char *const args[] = { "--max_bytes", "512",
					    "--period_ms", "1000", NULL };
	struct fe_mem mem;
	struct fe fe;
	uint64_t start, took;
	unsigned int i;
	pid_t pid;

	TEST_STEP("--max_bytes 512 --period_ms 1000");
	pid = test_start(args);
	if (pid < 0) {
		test_failures++;
		return;
	}

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM),
	      "set-up");

	/* 512 at once from the full bucket, 1024 more over two seconds */
	start = fe_now_ms();
	for (i = 0; i < 6; i++) {
		drv_desc(&fe, 0, fe_data_gpa(&fe, 256 * i), 256,
			 VIRTQ_DESC_F_WRITE, 0);
		if (!test_serve(&fe, 0, 256))
			break;
	}
	took = fe_now_ms() - start;
	CHECK(took >= 1800 && took < 4000,
	      "1536 bytes at 512 per second took %llu ms",
	      (unsigned long long)took);

	/* A request larger than the bucket gets what the bucket holds */
	fe_sleep_ms(1100);
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0x10000), 2048, VIRTQ_DESC_F_WRITE,
		 0);
	test_serve(&fe, 0, 512);

	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);
}

static void test_options_pr(void)
{
	static const char *const args[] = { "--pr", NULL };
	static const char *const unlimited[] = { "--pr", "--max_bytes", "0",
						 NULL };
	unsigned int full, pr;
	struct fe_mem mem;
	struct fe fe;
	pid_t pid;

	TEST_STEP("--pr serves from the prediction resistant DRNG");
	pid = test_start(args);
	if (pid < 0) {
		test_failures++;
		return;
	}

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM),
	      "set-up");

	full = standin_full_requests();
	pr = standin_pr_requests();
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 512, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 512);
	CHECK(standin_pr_requests() > pr, "%u prediction resistant requests",
	      standin_pr_requests() - pr);
	CHECK(standin_full_requests() == full,
	      "%u requests of the fully seeded DRNG",
	      standin_full_requests() - full);

	/*
	 * Every 32 bytes are a reseed of the ESDM: --pr comes with a bucket of
	 * 1024 bytes a second, and a larger request gets what it holds
	 */
	TEST_STEP("--pr limits the guest to 1024 bytes a second by default");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0x1000), TEST_REQ_MAX,
		 VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 1024);

	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);

	TEST_STEP("--pr --max_bytes 0 serves without a limit");
	pid = test_start(unlimited);
	if (pid < 0) {
		test_failures++;
		return;
	}
	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM),
	      "set-up");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), TEST_REQ_MAX, VIRTQ_DESC_F_WRITE,
		 0);
	test_serve(&fe, 0, TEST_REQ_MAX);

	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);
}

/* Line @key of the status of process @pid, without the key */
static bool test_proc_status(pid_t pid, const char *key, char *line,
			     size_t len)
{
	char path[64], buf[8192];
	const char *p;
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = 0;

	for (p = buf; p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
		size_t klen = strlen(key), i = 0;

		if (strncmp(p, key, klen) || p[klen] != ':')
			continue;
		for (p += klen + 1; *p == '\t' || *p == ' '; p++)
			;
		while (p[i] && p[i] != '\n' && i + 1 < len) {
			line[i] = p[i];
			i++;
		}
		line[i] = 0;
		return true;
	}

	return false;
}

/* Whether the four IDs of a Uid: or Gid: line of the status are all @id */
static bool test_ids_are(const char *line, unsigned int id)
{
	unsigned int ids[4];

	return sscanf(line, "%u %u %u %u", &ids[0], &ids[1], &ids[2],
		      &ids[3]) == 4 &&
	       ids[0] == id && ids[1] == id && ids[2] == id && ids[3] == id;
}

/*
 * Start the daemon with @args as root and check the user, group and
 * supplementary groups it dropped to, then that it serves
 */
static void test_options_ids(const char *const *args, uid_t uid, gid_t gid,
			     const gid_t *groups, unsigned int ngroups)
{
	char line[512] = "";
	unsigned int n = 0, i;
	bool dropped = false;
	struct fe_mem mem;
	struct fe fe;
	uint64_t end;
	const char *p;
	pid_t pid;

	pid = test_start(args);
	if (pid < 0) {
		test_failures++;
		return;
	}

	/* Dropped right after the socket is there */
	end = fe_now_ms() + TEST_WAIT_MS;
	do {
		dropped = test_proc_status(pid, "Uid", line, sizeof(line)) &&
			  test_ids_are(line, (unsigned int)uid);
		if (!dropped)
			fe_sleep_ms(20);
	} while (!dropped && fe_now_ms() < end);
	CHECK(dropped, "UIDs %s, expected %u", line, (unsigned int)uid);

	CHECK(test_proc_status(pid, "Gid", line, sizeof(line)) &&
		      test_ids_are(line, (unsigned int)gid),
	      "GIDs %s, expected %u", line, (unsigned int)gid);

	line[0] = 0;
	CHECK(test_proc_status(pid, "Groups", line, sizeof(line)),
	      "supplementary groups listed");
	for (p = line; *p;) {
		char *e;
		unsigned long g = strtoul(p, &e, 10);
		bool known = false;

		if (e == p)
			break;
		for (i = 0; i < ngroups; i++)
			known |= g == (unsigned long)groups[i];
		CHECK(known, "supplementary group %lu expected", g);
		n++;
		p = e;
		while (*p == ' ')
			p++;
	}
	CHECK(n == ngroups, "%u supplementary groups (%s), expected %u", n,
	      line, ngroups);

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, 0, TEST_PFEATURES, TEST_NUM),
	      "set-up");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), 64, VIRTQ_DESC_F_WRITE, 0);
	test_serve(&fe, 0, 64);
	fe_close(&fe);
	fe_mem_destroy(&mem);

	test_end(pid);
}

/*
 * Started as root, the daemon drops to --user and --group: the group of the
 * process is the one of --group, which is a supplementary group as is the
 * group of the user - and without --group, the group of the user alone
 */
static void test_options_privileges(void)
{
	static const char *const user[] = { "--user", "nobody", NULL };
	const char *group[] = { "--user", "nobody", "--group", NULL, NULL };
	char name[64] = "";
	const struct passwd *pw;
	const struct group *gr;
	gid_t groups[2], gid = 0;
	uid_t nobody;

	if (geteuid()) {
		printf("Not root - skipping --user and --group\n");
		return;
	}

	pw = getpwnam("nobody");
	CHECK(pw, "user nobody known");
	if (!pw)
		return;
	nobody = pw->pw_uid;
	groups[1] = pw->pw_gid;

	/* A group neither root's nor nobody's, mapped in a user namespace */
	setgrent();
	while ((gr = getgrent())) {
		if (gr->gr_gid && gr->gr_gid != groups[1] &&
		    gr->gr_gid < 65536 && strlen(gr->gr_name) < sizeof(name)) {
			snprintf(name, sizeof(name), "%s", gr->gr_name);
			gid = gr->gr_gid;
			break;
		}
	}
	endgrent();

	TEST_STEP("--user nobody: the group of nobody, no supplementary ones");
	test_options_ids(user, nobody, groups[1], NULL, 0);

	if (!gid) {
		printf("No group but root's and nobody's - skipping --group\n");
		return;
	}
	TEST_STEP("--user nobody --group %s: group %s, nobody's supplementary",
		  name, name);
	group[3] = name;
	groups[0] = gid;
	test_options_ids(group, nobody, gid, groups, 2);
}

static int test_group_options(void)
{
	test_options_ratelimit();
	test_options_pr();
	test_options_privileges();
	return 0;
}

/******************************************************************************
 * esdm
 ******************************************************************************/

/* A request of 4096 bytes served from the ESDM, not from the stand-in */
static void test_esdm_one(const char *const *extra, const char *what)
{
	struct fe_mem mem;
	struct fe fe;
	unsigned int distinct = 0, i;
	bool seen[256] = { false };
	uint8_t *p;
	pid_t pid;

	TEST_STEP("%s", what);
	pid = test_start(extra);
	if (pid < 0) {
		test_failures++;
		return;
	}

	CHECK(!fe_mem_create(&mem, TEST_MEM_SIZE, TEST_GPA), "memfd");
	CHECK(!fe_setup(&fe, test_sock, &mem, TEST_EVENT_IDX, TEST_PFEATURES,
			TEST_NUM),
	      "set-up");
	drv_desc(&fe, 0, fe_data_gpa(&fe, 0), TEST_REQ_MAX, VIRTQ_DESC_F_WRITE,
		 0);
	/* The ESDM may still be seeding: give it the time it takes */
	drv_avail(&fe, 0);
	CHECK(drv_wait_used(&fe, 1, 60000), "served");

	p = fe_data_ptr(&fe, 0);
	for (i = 0; i < TEST_REQ_MAX; i++) {
		if (!seen[p[i]])
			distinct++;
		seen[p[i]] = true;
	}
	CHECK(distinct > 200, "%u distinct byte values in %u bytes", distinct,
	      TEST_REQ_MAX);
	CHECK(fe_data_ptr(&fe, TEST_REQ_MAX)[0] == FE_CANARY,
	      "nothing written behind the buffer");

	fe_close(&fe);
	fe_mem_destroy(&mem);
	test_end(pid);
}

static int test_group_esdm(void)
{
	static const char *const pr[] = { "--pr", NULL };

	test_esdm_one(NULL, "served from the fully seeded DRNG of the ESDM");
	test_esdm_one(pr, "served from the prediction resistant DRNG");

	return 0;
}

/******************************************************************************
 * main
 ******************************************************************************/

static const struct {
	const char *name;
	int (*run)(void);
} test_groups[] = {
	{ "protocol", test_group_protocol },
	{ "ring", test_group_ring },
	{ "hostile", test_group_hostile },
	{ "lifecycle", test_group_lifecycle },
	{ "options", test_group_options },
	{ "esdm", test_group_esdm },
};

int main(int argc, char *argv[])
{
	int (*run)(void) = NULL;
	unsigned int i;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <group>\n", argv[0]);
		return 1;
	}
	for (i = 0; i < sizeof(test_groups) / sizeof(test_groups[0]); i++) {
		if (!strcmp(argv[1], test_groups[i].name))
			run = test_groups[i].run;
	}
	if (!run) {
		fprintf(stderr, "Unknown group %s\n", argv[1]);
		return 1;
	}

	test_daemon = getenv("ESDM_VHOST_USER_RNG");
	if (test_env_check_file(test_daemon))
		return 1;

	if (run == test_group_esdm) {
		/* An esdm-server of its own, in namespaces of its own */
		ret = env_init();
		if (ret) {
			env_fini();
			return ret == 77 ? 77 : 1;
		}
	} else {
		/* The stand-in takes the socket a test mode build connects to */
		ret = standin_start();
		if (ret) {
			printf("No stand-in ESDM: %s - skipping\n",
			       strerror(-ret));
			return 77;
		}
	}

	snprintf(test_dir, sizeof(test_dir), "/tmp/esdm-vu-test-XXXXXX");
	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		if (run == test_group_esdm)
			env_fini();
		else
			standin_stop();
		return 1;
	}
	snprintf(test_sock, sizeof(test_sock), "%s/vm.sock", test_dir);

	TEST_STEP("group %s", argv[1]);
	ret = run();

	unlink(test_sock);
	rmdir(test_dir);
	if (run == test_group_esdm)
		env_fini();
	else
		standin_stop();

	if (ret || test_failures) {
		printf("FAIL: %u checks failed\n", test_failures);
		return 1;
	}

	printf("PASS\n");
	return 0;
}
