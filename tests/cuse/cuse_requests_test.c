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
 * Tests of how the CUSE device answers its requests: each one exactly once,
 * and none of them held up by another one.
 *
 * As in cuse_device_test.c, the translation unit is compiled into the test and
 * the libfuse reply functions are provided here. Unlike there, every request is
 * a struct of its own that records the replies it got, so that requests served
 * concurrently on several threads can be told apart, and a second reply to one
 * request shows up as such - in libfuse, it is a use of the request after it
 * was freed.
 *
 * The ESDM is replaced by the get functions the read handler is given, so no
 * RPC leaves this process for the reads.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/random.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common_test.h"

/* The unit under test */
#include "cuse_device.c"

enum reply_kind {
	REPLY_NONE,
	REPLY_ERR,
	REPLY_IOCTL,
	REPLY_IOCTL_RETRY,
	REPLY_BUF,
	REPLY_WRITE,
	REPLY_OPEN,
	REPLY_POLL,
};

/* What a fuse_req_t points to in this test */
struct test_req {
	/* The number of replies sent, and the last one */
	atomic_uint replies;
	enum reply_kind kind;
	int err;
	size_t size;
	unsigned int revents;

	/* Whether sending the reply fails, as for a request the kernel dropped */
	bool send_fails;
	/* Whether the caller was interrupted */
	atomic_bool interrupted;
};

static int test_reply(fuse_req_t req, enum reply_kind kind, int err,
		      size_t size)
{
	struct test_req *r = (struct test_req *)req;

	atomic_fetch_add(&r->replies, 1);
	r->kind = kind;
	r->err = err;
	r->size = size;

	/* libfuse frees the request here, also when sending fails */
	return r->send_fails ? -ENOENT : 0;
}

static void test_req_init(struct test_req *r)
{
	memset(r, 0, sizeof(*r));
}

/* The caller every handler below sees */
static struct fuse_ctx test_ctx;

/******************************************************************************
 * The libfuse side, replaced so a handler can be called without a session
 ******************************************************************************/

int fuse_reply_err(fuse_req_t req, int err)
{
	return test_reply(req, REPLY_ERR, err, 0);
}

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size)
{
	(void)buf;
	return test_reply(req, REPLY_IOCTL, result, size);
}

int fuse_reply_ioctl_retry(fuse_req_t req, const struct iovec *in_iov,
			   size_t in_count, const struct iovec *out_iov,
			   size_t out_count)
{
	(void)in_iov;
	(void)out_iov;
	return test_reply(req, REPLY_IOCTL_RETRY, 0, in_count + out_count);
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
	(void)buf;
	return test_reply(req, REPLY_BUF, 0, size);
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
	return test_reply(req, REPLY_WRITE, 0, count);
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi)
{
	(void)fi;
	return test_reply(req, REPLY_OPEN, 0, 0);
}

int fuse_reply_poll(fuse_req_t req, unsigned revents)
{
	struct test_req *r = (struct test_req *)req;

	r->revents = revents;
	return test_reply(req, REPLY_POLL, 0, 0);
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
	(void)req;

	return &test_ctx;
}

int fuse_req_interrupted(fuse_req_t req)
{
	struct test_req *r = (struct test_req *)req;

	return atomic_load(&r->interrupted);
}

int fuse_notify_poll(struct fuse_pollhandle *ph)
{
	(void)ph;

	return 0;
}

void fuse_pollhandle_destroy(struct fuse_pollhandle *ph)
{
	(void)ph;
}

void fuse_session_exit(struct fuse_session *se)
{
	(void)se;
}

/******************************************************************************
 * The privilege helpers, replaced as in cuse_device_test.c
 ******************************************************************************/

int raise_privilege_transient(uid_t uid, gid_t gid)
{
	(void)uid;
	(void)gid;

	return 0;
}

int drop_privileges_transient(const char *user)
{
	(void)user;

	return 0;
}

int drop_supplemental_groups(void)
{
	return 0;
}

/* Every caller of this test holds CAP_SYS_ADMIN */
int caller_cap_sys_admin(pid_t pid, uid_t fsuid)
{
	(void)pid;
	(void)fsuid;

	return 1;
}

int caller_cap_sys_admin_fsroot(pid_t pid, uid_t fsuid)
{
	(void)pid;
	(void)fsuid;

	return 1;
}

/******************************************************************************
 * The device helpers of cuse_helper.c, see cuse_device_test.c
 ******************************************************************************/

int esdm_cuse_file_name(char *outfile, size_t outfilelen, const char *name)
{
	snprintf(outfile, outfilelen, "tst-%s", name);

	return 0;
}

int esdm_cuse_bind_mount(const char *src, const char *dst)
{
	(void)src;
	(void)dst;

	return 0;
}

int esdm_cuse_bind_unmount(char **src, char **dst)
{
	(void)src;
	(void)dst;

	return 0;
}

/******************************************************************************
 * The ESDM, as the read handler asks it
 ******************************************************************************/

#define TEST_BYTE 0x5a

/* An ESDM that answers every request at once */
static ssize_t test_get_served(uint8_t *buf, size_t buflen, void *int_data)
{
	(void)int_data;

	memset(buf, TEST_BYTE, buflen);

	return (ssize_t)buflen;
}

static void read_call(struct test_req *r, int flags, size_t size,
		      get_func_t get)
{
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = flags;
	esdm_cuse_read_internal((fuse_req_t)r, size, 0, &fi, get, -1);
}

/*
 * A read whose reply cannot be sent. libfuse has freed the request by then,
 * so it must not be answered once more with the error the send returned.
 */
static void test_read_reply_once(void)
{
	struct test_req r;

	test_req_init(&r);
	r.send_fails = true;
	read_call(&r, 0, 32, test_get_served);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.kind, REPLY_BUF);
	CHECK_EQ(r.size, 32);

	/* The same for a read beyond the buffer on the stack */
	test_req_init(&r);
	r.send_fails = true;
	read_call(&r, 0, 4096, test_get_served);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.kind, REPLY_BUF);
	CHECK_EQ(r.size, 4096);
}

/*
 * An ESDM that is not seeded until the test says so. It is asked again and
 * again meanwhile, and in between, it asks esdm_cuse_interrupt() whether to
 * give up, as the RPC client does before every request it sends.
 */
static atomic_bool test_seeded;
static atomic_uint test_get_calls;

static ssize_t test_get_unseeded(uint8_t *buf, size_t buflen, void *int_data)
{
	static const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };

	atomic_fetch_add(&test_get_calls, 1);

	while (!atomic_load(&test_seeded)) {
		if (esdm_cuse_interrupt(int_data))
			return -EINTR;
		nanosleep(&ts, NULL);
	}

	memset(buf, TEST_BYTE, buflen);

	return (ssize_t)buflen;
}

struct test_thread {
	pthread_t thread;
	struct test_req r;
	atomic_bool done;
};

/* A blocking read of /dev/random */
static void *test_read_thread(void *arg)
{
	struct test_thread *t = arg;

	read_call(&t->r, 0, 32, test_get_unseeded);
	atomic_store(&t->done, true);

	return NULL;
}

/* A privileged ioctl: the reseed of the kernel's CRNG, which needs no ESDM */
static void *test_ioctl_thread(void *arg)
{
	struct test_thread *t = arg;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	esdm_cuse_ioctl(-1, (fuse_req_t)&t->r, 44, NULL, &fi, 0, NULL, 0, 0);
	atomic_store(&t->done, true);

	return NULL;
}

/* Wait for up to 5 seconds for the flag to be set */
static bool test_wait_for(atomic_bool *flag)
{
	static const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	unsigned int i;

	for (i = 0; i < 5000 && !atomic_load(flag); i++)
		nanosleep(&ts, NULL);

	return atomic_load(flag);
}

/*
 * A read of /dev/random waits for the seeding of the ESDM, holding the reader
 * lock. A privileged ioctl must not wait for it: the ESDM may wait for exactly
 * that request, e.g. for rngd to credit entropy. With the writer-preferring
 * lock, every read and write after it would wait as well.
 */
static void test_read_gives_way(void)
{
	static const struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
	struct test_thread reader, priv;
	unsigned int i;

	memset(&reader, 0, sizeof(reader));
	memset(&priv, 0, sizeof(priv));
	atomic_store(&test_seeded, false);
	atomic_store(&test_get_calls, 0);

	if (pthread_create(&reader.thread, NULL, test_read_thread, &reader)) {
		CHECK(0, "cannot start the reader");
		return;
	}

	/* The read waits in the ESDM, holding the reader lock */
	for (i = 0; i < 5000 && !atomic_load(&test_get_calls); i++)
		nanosleep(&ts, NULL);
	CHECK(atomic_load(&test_get_calls), "the read never asked the ESDM");

	if (pthread_create(&priv.thread, NULL, test_ioctl_thread, &priv)) {
		CHECK(0, "cannot start the privileged ioctl");
		atomic_store(&test_seeded, true);
		pthread_join(reader.thread, NULL);
		return;
	}

	CHECK(test_wait_for(&priv.done),
	      "the privileged ioctl waited for a read that waits for the seeding");
	CHECK(!atomic_load(&reader.done),
	      "the read was answered before the ESDM was seeded");

	/* Let everything finish, which it does in either case */
	atomic_store(&test_seeded, true);
	pthread_join(priv.thread, NULL);
	pthread_join(reader.thread, NULL);

	CHECK_EQ(atomic_load(&priv.r.replies), 1);
	CHECK_EQ(priv.r.kind, REPLY_IOCTL);
	CHECK_EQ(priv.r.err, 0);

	/* The read went on once the ioctl was through, and was served */
	CHECK_EQ(atomic_load(&reader.r.replies), 1);
	CHECK_EQ(reader.r.kind, REPLY_BUF);
	CHECK_EQ(reader.r.size, 32);
	CHECK(atomic_load(&test_get_calls) >= 2,
	      "the read did not ask the ESDM again after giving way");

	/* Nothing waits for the write lock any more */
	CHECK_EQ(atomic_load(&esdm_cuse_priv_waiting), 0);
}

/*
 * A reader interrupted while it gave way is answered with EINTR, rather than
 * waiting for the ESDM it no longer waits for.
 */
static void test_read_interrupted_giving_way(void)
{
	struct test_req r;

	test_req_init(&r);
	atomic_store(&r.interrupted, true);

	/* As if a privileged request waited all along */
	atomic_store(&esdm_cuse_priv_waiting, 1);
	atomic_store(&test_seeded, false);
	read_call(&r, 0, 32, test_get_unseeded);
	atomic_store(&esdm_cuse_priv_waiting, 0);

	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.kind, REPLY_ERR);
	CHECK_EQ(r.err, EINTR);
}

/*
 * /dev/urandom is always readable and writable, as the kernel's is, which has
 * no poll handler. Without a status segment, nothing tells that the ESDM is
 * seeded - which /dev/random waits for, but /dev/urandom does not.
 */
static void test_poll_urandom(void)
{
	static const unsigned int all =
		POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM;
	struct fuse_file_info fi;
	struct test_req r;

	CHECK(esdm_cuse_shm_status == NULL,
	      "the status segment is attached, which this test does not expect");

	memset(&fi, 0, sizeof(fi));
	fi.poll_events = POLLIN;
	test_req_init(&r);
	esdm_cuse_poll_urandom((fuse_req_t)&r, &fi, NULL);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.kind, REPLY_POLL);
	CHECK_EQ(r.revents, all);

	fi.poll_events = POLLOUT;
	test_req_init(&r);
	esdm_cuse_poll_urandom((fuse_req_t)&r, &fi, NULL);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.revents, all);

	/* /dev/random has nothing to report then */
	fi.fh = 1;
	fi.poll_events = POLLIN;
	test_req_init(&r);
	esdm_cuse_poll((fuse_req_t)&r, &fi, NULL);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.revents, 0);

	/*
	 * A poll that does not wait passes no handle. It must leave nothing
	 * registered: a node without handle marks a suspend wake-up, which
	 * the next poll would report as an event.
	 */
	CHECK(esdm_cuse_poll_list == NULL,
	      "a poll without handle was registered");
	test_req_init(&r);
	esdm_cuse_poll((fuse_req_t)&r, &fi, NULL);
	CHECK_EQ(atomic_load(&r.replies), 1);
	CHECK_EQ(r.revents, 0);
	esdm_cuse_poll_remove_fh(1, false);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	memset(&test_ctx, 0, sizeof(test_ctx));
	test_ctx.pid = getpid();

	/* What the daemon is once the device is up: dropped to "nobody" */
	esdm_cuse_dropped = true;
	atomic_store(&esdm_cuse_ready, true);

	test_read_reply_once();
	test_read_gives_way();
	test_read_interrupted_giving_way();
	test_poll_urandom();

	return common_test_result("cuse_requests");
}
