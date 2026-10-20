// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend - EGD client
 *
 * The module reaches the ESDM over its EGD socket, a Unix domain stream socket
 * of the esdm-server in user space, with the standard EGD commands and the
 * ESDM's extensions of them. No protobuf, no RPC: every request is a command
 * byte with fixed size arguments, every answer has a size known from the
 * request or announced by a length prefix.
 *
 * Connecting
 * ----------
 * The path of a Unix domain socket is looked up in the file system context of
 * the task calling connect(): its root, its mount namespace. Connecting in the
 * context of the process reading a device would let a process in a container
 * have the module talk to whatever the container has at that path - with the
 * module's privileges towards it, see below. So connections are made on the
 * module's workqueue only. Its workers are kernel threads, forked by kthreadd
 * with CLONE_FS: they share the fs_struct of init, i.e. its root and working
 * directory in the initial mount namespace, also after the initramfs handed
 * over to the real root, and they run with the initial credentials. Since
 * Linux 7.3 kernel threads no longer share init's fs_struct: theirs has an
 * empty root (nullfs), where every lookup fails with -ENOENT, and a kernel
 * thread takes the one of init for a lookup with scoped_with_init_fs(),
 * which the work below does around everything it runs.
 *
 * That makes the module's connections root's: the ESDM takes the peer
 * credentials at connect time, and honours the entropy claims and the
 * privileged commands of a root peer. The module therefore checks its own
 * callers before it sends any of those, see esdm_cdev_main.c.
 *
 * Once connected, the requests are carried out in the context of the caller:
 * sending and receiving on a connected socket involves no path lookup, and the
 * caller's signals interrupt the waits - except the one for the answer of a
 * command that changes something in the ESDM, see esdm_cdev_recv_committed().
 *
 * Connections
 * -----------
 * A small pool of connections, each serving one request at a time - EGD has
 * no request identifiers, so answers are matched to requests by their order.
 * A request takes a connection that is free, or waits for one, as long as a
 * transfer at most. A request holds its connection for the ESDM's answers
 * only: it brings what it sends along, rather than reading user memory then.
 * A connection that failed in any way is closed, as the position of the
 * stream is unknown then, and made anew by the next request on it. One that
 * cannot be made, or that failed by the ESDM's fault, is not made again for a
 * while, growing up to ESDM_CDEV_BACKOFF_MAX_MS until a request on it
 * succeeds, so that a missing or frozen ESDM costs a failed connect or a
 * timeout now and then rather than one per read.
 *
 * Every answer is untrusted input: its lengths are checked against what was
 * asked for and against the protocol's bounds before anything is read, and a
 * connection with an answer that does not fit is closed.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/jiffies.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/sock.h>

#include "esdm_cdev.h"

static char *egd_socket = "/run/esdm-egd.socket";
module_param(egd_socket, charp, 0444);
MODULE_PARM_DESC(egd_socket,
		 "Path of the ESDM's EGD socket (default: /run/esdm-egd.socket)");

static unsigned int connections = 4;
module_param(connections, uint, 0444);
MODULE_PARM_DESC(connections,
		 "Number of connections to the ESDM (1 to 64, default: 4)");

static unsigned int timeout_ms = 5000;
module_param(timeout_ms, uint, 0644);
MODULE_PARM_DESC(timeout_ms,
		 "Bound in milliseconds on connecting and on each transfer (100 to 60000, default: 5000)");

#define ESDM_CDEV_MAX_CONNECTIONS 64
#define ESDM_CDEV_BACKOFF_MIN_MS 50
#define ESDM_CDEV_BACKOFF_MAX_MS 2000

struct esdm_cdev_conn {
	/* Serializes the requests, and guards everything below */
	struct mutex lock;
	/* NULL while not connected */
	struct socket *sock;
	/* No connect before this point in time while backoff_ms is set */
	unsigned long retry_at;
	unsigned int backoff_ms;
};

static struct esdm_cdev_conn *esdm_cdev_conns;
static unsigned int esdm_cdev_nconns;
static atomic_t esdm_cdev_conn_next = ATOMIC_INIT(0);
/* Requests waiting for a connection to be freed */
static DECLARE_WAIT_QUEUE_HEAD(esdm_cdev_conn_wait);
static struct workqueue_struct *esdm_cdev_wq;

/* Whether the last connect succeeded, -1 before the first: for the log only */
static atomic_t esdm_cdev_reachable = ATOMIC_INIT(-1);

static unsigned int esdm_cdev_timeout_ms(void)
{
	return clamp_t(unsigned int, READ_ONCE(timeout_ms), 100, 60000);
}

static u32 esdm_cdev_be32(const u8 *p)
{
	return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | (u32)p[3];
}

static void esdm_cdev_put_be32(u8 *p, u32 val)
{
	p[0] = (u8)(val >> 24);
	p[1] = (u8)(val >> 16);
	p[2] = (u8)(val >> 8);
	p[3] = (u8)val;
}

/****************************** Running as init ******************************/

struct esdm_cdev_initcall {
	struct work_struct work;
	struct completion done;
	/* The waiter's and the work's */
	refcount_t ref;
	int (*fn)(void *out);
	void (*discard)(void *out);
	/* The waiter copied the result, which is no longer the work's */
	bool taken;
	int ret;
	size_t outlen;
	u8 out[];
};

static void esdm_cdev_initcall_put(struct esdm_cdev_initcall *ic)
{
	if (!refcount_dec_and_test(&ic->ref))
		return;

	if (!ic->taken && !ic->ret && ic->discard)
		ic->discard(ic->out);
	kfree_sensitive(ic);
}

static void esdm_cdev_initcall_work(struct work_struct *work)
{
	struct esdm_cdev_initcall *ic =
		container_of(work, struct esdm_cdev_initcall, work);

	/* The file system context of init, see "Connecting" above */
#ifdef scoped_with_init_fs
	scoped_with_init_fs()
		ic->ret = ic->fn(ic->out);
#else
	ic->ret = ic->fn(ic->out);
#endif
	complete(&ic->done);
	esdm_cdev_initcall_put(ic);
}

int esdm_cdev_run_in_init(int (*fn)(void *out), void (*discard)(void *out),
			  void *res, size_t reslen, unsigned int tmo_ms)
{
	struct esdm_cdev_initcall *ic;
	long left, tmo;
	int ret;

	ic = kzalloc(struct_size(ic, out, reslen), GFP_KERNEL);
	if (!ic)
		return -ENOMEM;

	INIT_WORK(&ic->work, esdm_cdev_initcall_work);
	init_completion(&ic->done);
	refcount_set(&ic->ref, 2);
	ic->fn = fn;
	ic->discard = discard;
	ic->outlen = reslen;

	queue_work(esdm_cdev_wq, &ic->work);

	tmo = msecs_to_jiffies(tmo_ms);
	left = wait_for_completion_interruptible_timeout(&ic->done, tmo);
	if (left > 0) {
		ret = ic->ret;
		if (!ret) {
			memcpy(res, ic->out, reslen);
			ic->taken = true;
		}
	} else {
		ret = left ? (int)left : -ETIMEDOUT;
	}

	esdm_cdev_initcall_put(ic);

	return ret;
}

/******************************** Connections ********************************/

/* Runs on the workqueue, see above */
static int esdm_cdev_connect_fn(void *out)
{
	/*
	 * In a struct sockaddr_storage, as the system calls pass addresses:
	 * unix_mkname_bsd() terminates the path at sun_path[108], past the
	 * end of a struct sockaddr_un. Kernels without "net: avoid address
	 * overwrite in kernel_connect", such as early 6.1 ones, do that on the
	 * caller's address.
	 */
	struct sockaddr_storage addr = { .ss_family = AF_UNIX };
	struct sockaddr_un *sun = (struct sockaddr_un *)&addr;
	struct socket **res = out, *sock;
	int ret;

	strscpy(sun->sun_path, egd_socket, sizeof(sun->sun_path));

	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sock);
	if (ret)
		return ret;

	/*
	 * Non-blocking: a full listen backlog of the ESDM is a failure to
	 * connect rather than a wait. The address type of kernel_connect()
	 * differs between kernel versions, the void pointer fits both.
	 */
	ret = kernel_connect(sock, (void *)&addr, sizeof(*sun), O_NONBLOCK);
	if (ret) {
		sock_release(sock);
		return ret;
	}

	*res = sock;

	return 0;
}

static void esdm_cdev_connect_discard(void *out)
{
	struct socket **sock = out;

	sock_release(*sock);
}

/* Caller holds conn->lock */
static int esdm_cdev_conn_connect(struct esdm_cdev_conn *conn)
{
	struct socket *sock = NULL;
	int ret;

	if (conn->sock)
		return 0;

	if (conn->backoff_ms && time_before(jiffies, conn->retry_at))
		return -ENOTCONN;

	ret = esdm_cdev_run_in_init(esdm_cdev_connect_fn,
				    esdm_cdev_connect_discard, &sock,
				    sizeof(sock), esdm_cdev_timeout_ms());
	if (ret == -ERESTARTSYS)
		return ret;
	if (ret) {
		conn->backoff_ms = clamp(conn->backoff_ms * 2,
					 ESDM_CDEV_BACKOFF_MIN_MS,
					 ESDM_CDEV_BACKOFF_MAX_MS);
		conn->retry_at = jiffies + msecs_to_jiffies(conn->backoff_ms);
		if (atomic_xchg(&esdm_cdev_reachable, 0) != 0)
			pr_warn("cannot connect to the ESDM at %s: %d\n",
				egd_socket, ret);
		return -ENOTCONN;
	}

	/*
	 * The backoff stays until a request succeeded: an ESDM that accepts
	 * connections but does not answer would otherwise be waited for the
	 * full timeout on every request.
	 */
	conn->sock = sock;
	if (atomic_xchg(&esdm_cdev_reachable, 1) != 1)
		pr_info("connected to the ESDM at %s\n", egd_socket);

	return 0;
}

/*
 * Close the connection of a failed request. @backoff: the failure was the
 * ESDM's - an answer that does not fit, a timeout, a closed connection - so
 * the next connect waits a moment. A caller that was interrupted is no reason
 * to make anybody else wait.
 */
static void esdm_cdev_conn_drop(struct esdm_cdev_conn *conn, bool backoff)
{
	sock_release(conn->sock);
	conn->sock = NULL;

	if (backoff) {
		conn->backoff_ms = clamp(conn->backoff_ms * 2,
					 ESDM_CDEV_BACKOFF_MIN_MS,
					 ESDM_CDEV_BACKOFF_MAX_MS);
		conn->retry_at = jiffies + msecs_to_jiffies(conn->backoff_ms);
	}
}

/* A free connection, locked, looking from the one at @start on */
static struct esdm_cdev_conn *esdm_cdev_conn_try(unsigned int start)
{
	unsigned int i;

	for (i = 0; i < esdm_cdev_nconns; i++) {
		struct esdm_cdev_conn *conn =
			&esdm_cdev_conns[(start + i) % esdm_cdev_nconns];

		if (mutex_trylock(&conn->lock))
			return conn;
	}

	return NULL;
}

/*
 * A free connection, or the first one freed within the timeout. A request
 * that gets none fails as one the ESDM did not answer: the connections are
 * all busy with requests the ESDM takes its time for.
 */
static struct esdm_cdev_conn *esdm_cdev_conn_get(void)
{
	struct esdm_cdev_conn *conn = NULL;
	unsigned int start;
	long left;

	start = (unsigned int)atomic_inc_return(&esdm_cdev_conn_next);
	left = wait_event_interruptible_timeout(
		esdm_cdev_conn_wait, (conn = esdm_cdev_conn_try(start)) != NULL,
		msecs_to_jiffies(esdm_cdev_timeout_ms()));
	if (left < 0)
		return ERR_PTR(-ERESTARTSYS);
	if (!conn)
		return ERR_PTR(-ETIMEDOUT);

	return conn;
}

static void esdm_cdev_conn_put(struct esdm_cdev_conn *conn)
{
	mutex_unlock(&conn->lock);
	wake_up(&esdm_cdev_conn_wait);
}

/********************************* Transfers *********************************/

/* Send all of @buf; *@sent tells whether any of it went out */
static int esdm_cdev_send(struct socket *sock, const void *buf, size_t len,
			  bool *sent)
{
	while (len) {
		struct kvec iov = { .iov_base = (void *)buf, .iov_len = len };
		/* A peer that went away is an error, not a SIGPIPE */
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		int ret = kernel_sendmsg(sock, &msg, &iov, 1, len);

		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if (!ret || (size_t)ret > len)
			return -EIO;

		*sent = true;
		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

/* Receive exactly @len bytes */
static int esdm_cdev_recv(struct socket *sock, void *buf, size_t len)
{
	while (len) {
		struct kvec iov = { .iov_base = buf, .iov_len = len };
		struct msghdr msg = { .msg_flags = 0 };
		int ret = kernel_recvmsg(sock, &msg, &iov, 1, len, MSG_WAITALL);

		/* The ESDM closed the connection */
		if (!ret)
			return -ECONNRESET;
		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if ((size_t)ret > len)
			return -EIO;

		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

/*
 * Receive what is there, up to @len bytes, waiting for the first of them.
 * Returns the number of bytes received, or a negative errno.
 */
static int esdm_cdev_recv_some(struct socket *sock, void *buf, size_t len)
{
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr msg = { .msg_flags = 0 };
	int ret = kernel_recvmsg(sock, &msg, &iov, 1, len, 0);

	/* The ESDM closed the connection */
	if (!ret)
		return -ECONNRESET;
	if (ret == -EAGAIN)
		return -ETIMEDOUT;
	if (ret > 0 && (size_t)ret > len)
		return -EIO;

	return ret;
}

static bool esdm_cdev_interrupted(int ret)
{
	return ret == -ERESTARTSYS || ret == -EINTR || ret == -ERESTARTNOINTR ||
	       ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK;
}

/*
 * Receive exactly @len bytes of the answer to a command the ESDM carries out
 * once it has it, also when nobody waits for the answer any more - the
 * commands changing its entropy accounting or its DRNGs. A caller interrupted
 * now would have the command restarted, and carried out twice. So the answer
 * is waited for despite signals, bounded by the timeout as every wait; only a
 * fatal signal ends the wait, after which nothing is restarted. The socket's
 * waits end at any signal, so with one pending, the answer is polled for.
 */
static int esdm_cdev_recv_committed(struct socket *sock, void *buf, size_t len)
{
	unsigned long end = jiffies + READ_ONCE(sock->sk->sk_rcvtimeo);

	while (len) {
		struct kvec iov = { .iov_base = buf, .iov_len = len };
		struct msghdr msg = { .msg_flags = 0 };
		bool polling = signal_pending(current);
		int ret;

		if (fatal_signal_pending(current))
			return -EINTR;

		ret = kernel_recvmsg(sock, &msg, &iov, 1, len,
				     polling ? MSG_DONTWAIT : MSG_WAITALL);

		if (!ret)
			return -ECONNRESET;
		if (polling && ret == -EAGAIN) {
			if (time_after(jiffies, end))
				return -ETIMEDOUT;
			schedule_timeout_uninterruptible(1);
			continue;
		}
		/* A signal came while waiting */
		if (esdm_cdev_interrupted(ret))
			continue;
		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if ((size_t)ret > len)
			return -EIO;

		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

/*
 * Carry out one request with @op on a connection: connected, with the
 * timeouts set, and locked. A request that failed before anything of it went
 * out - a connection the ESDM closed while it was idle, as on its restart - is
 * tried once more on a fresh connection.
 *
 * @changes: the request changes something in the ESDM, which carries it out
 * once it has it. One that went out is therefore not restarted, nor tried
 * again, whatever happens to its answer.
 *
 * Returns 0, -ERESTARTSYS when the caller was interrupted, -ENOTCONN when the
 * ESDM cannot be reached, -ETIMEDOUT when no connection was free in time, or
 * the error of @op.
 */
static int esdm_cdev_invoke(int (*op)(struct socket *sock, void *arg,
				      bool *sent),
			    void *arg, bool changes)
{
	struct esdm_cdev_conn *conn = esdm_cdev_conn_get();
	unsigned int attempt;
	int ret = -ENOTCONN;

	if (IS_ERR(conn))
		return PTR_ERR(conn);

	for (attempt = 0; attempt < 2; attempt++) {
		long tmo = msecs_to_jiffies(esdm_cdev_timeout_ms());
		bool sent = false;

		ret = esdm_cdev_conn_connect(conn);
		if (ret)
			break;

		WRITE_ONCE(conn->sock->sk->sk_rcvtimeo, tmo);
		WRITE_ONCE(conn->sock->sk->sk_sndtimeo, tmo);

		ret = op(conn->sock, arg, &sent);
		if (!ret) {
			conn->backoff_ms = 0;
			break;
		}

		/* Gone out: its error, or -EINTR for a fatal signal */
		if (changes && sent) {
			bool intr = esdm_cdev_interrupted(ret);

			esdm_cdev_conn_drop(conn, !intr);
			if (intr)
				ret = -EINTR;
			break;
		}

		/* Interrupted, or the ESDM went wrong: the stream is lost */
		if (esdm_cdev_interrupted(ret) || signal_pending(current)) {
			esdm_cdev_conn_drop(conn, false);
			ret = -ERESTARTSYS;
			break;
		}

		esdm_cdev_conn_drop(conn, sent);
		if (sent)
			break;
	}

	esdm_cdev_conn_put(conn);

	return ret;
}

/*********************************** Reads ***********************************/

struct esdm_cdev_read_op {
	u8 cmd;
	size_t len;
	u8 *buf;
	size_t got;
};

/*
 * The read commands of one request go out together, and their answers are
 * collected after: one round trip for up to ESDM_CDEV_READ_MAX bytes rather
 * than one per 255 bytes. The ESDM serves the commands of a connection in
 * order, so the answers come in the order of the commands - as one response,
 * where they are served in full, see esdm_egd_read_run(). They are received
 * as they come, as much at a time as there is, rather than with two receives
 * per answer, and their bytes are moved to the front of the buffer behind
 * each other.
 */
static int esdm_cdev_read_op(struct socket *sock, void *arg, bool *sent)
{
	struct esdm_cdev_read_op *op = arg;
	u8 req[2 * ESDM_CDEV_READ_CMDS];
	size_t num = DIV_ROUND_UP(op->len, ESDM_EGD_MAX_TRANSFER);
	/* The answers in full, with their length bytes */
	size_t room = ESDM_CDEV_READ_ROOM(op->len);
	size_t i, have = 0, pos = 0;
	int ret;

	for (i = 0; i < num; i++) {
		size_t chunk = min_t(size_t, op->len - i * ESDM_EGD_MAX_TRANSFER,
				     ESDM_EGD_MAX_TRANSFER);

		req[2 * i] = op->cmd;
		req[2 * i + 1] = (u8)chunk;
	}

	ret = esdm_cdev_send(sock, req, 2 * num, sent);
	if (ret)
		return ret;

	op->got = 0;
	i = 0;
	while (i < num) {
		/* The answers complete so far */
		while (i < num && pos < have) {
			u8 got = op->buf[pos];

			/* More than asked for is not the protocol */
			if (got > req[2 * i + 1]) {
				ret = -EPROTO;
				goto err;
			}
			if (pos + 1 + got > have)
				break;

			/*
			 * A short answer leaves no gap: what came is
			 * contiguous. Ahead of the answer by its length byte
			 * at least, so nothing not taken yet is overwritten.
			 */
			memmove(op->buf + op->got, op->buf + pos + 1, got);
			op->got += got;
			pos += 1 + (size_t)got;
			i++;
		}
		if (i == num)
			break;

		/*
		 * No more than the answers can hold, so nothing is taken from
		 * the stream that does not belong to them
		 */
		ret = esdm_cdev_recv_some(sock, op->buf + have, room - have);
		if (ret < 0)
			goto err;
		have += (size_t)ret;
	}

	/* Bytes behind the last answer, which nothing asked for */
	if (pos != have) {
		ret = -EPROTO;
		goto err;
	}

	/* What is left behind the bytes moved to the front */
	memzero_explicit(op->buf + op->got, room - op->got);

	return 0;

err:
	memzero_explicit(op->buf, room);
	op->got = 0;
	return ret;
}

int esdm_cdev_egd_read(u8 cmd, u8 *buf, size_t len)
{
	struct esdm_cdev_read_op op = {
		.cmd = cmd,
		.len = min_t(size_t, len, ESDM_CDEV_READ_MAX),
		.buf = buf,
	};
	int ret;

	if (!len)
		return 0;

	ret = esdm_cdev_invoke(esdm_cdev_read_op, &op, false);

	return ret ? ret : (int)op.got;
}

/********************************** Writes ***********************************/

/* Insertions sent together, and the bytes they carry at most */
#define ESDM_CDEV_INSERT_CMDS 16
#define ESDM_CDEV_INSERT_MAX (ESDM_CDEV_INSERT_CMDS * ESDM_EGD_MAX_TRANSFER)

struct esdm_cdev_insert_op {
	/*
	 * The insertions - command, entropy, length and data - and the entropy
	 * count behind them, @len bytes
	 */
	u8 *cmd;
	size_t len;
};

/*
 * The insertions have no answer. The one of the entropy count behind them
 * tells that the ESDM took them, as it serves the commands of a connection in
 * order.
 */
static int esdm_cdev_insert_op(struct socket *sock, void *arg, bool *sent)
{
	struct esdm_cdev_insert_op *op = arg;
	u8 count[4];
	int ret;

	ret = esdm_cdev_send(sock, op->cmd, op->len, sent);
	if (!ret)
		ret = esdm_cdev_recv(sock, count, sizeof(count));

	return ret;
}

/*
 * Copy up to ESDM_CDEV_INSERT_MAX bytes of user memory at @ubuf into the
 * insertions of @op, without entropy. Returns the number of bytes copied,
 * fewer than @len when user memory was not readable.
 */
static size_t esdm_cdev_insert_fill(struct esdm_cdev_insert_op *op,
				    const char __user *ubuf, size_t len)
{
	size_t done = 0;
	u8 *p = op->cmd;

	while (done < len) {
		size_t chunk = min_t(size_t, len - done, ESDM_EGD_MAX_TRANSFER);
		size_t left = copy_from_user(p + 4, ubuf + done, chunk);

		chunk -= left;
		if (chunk) {
			p[0] = ESDM_EGD_CMD_WRITE_ENTROPY;
			p[1] = 0;
			p[2] = 0;
			p[3] = (u8)chunk;
			p += 4 + chunk;
			done += chunk;
		}
		if (left)
			break;
	}

	if (done)
		*p++ = ESDM_EGD_CMD_ENTROPY_COUNT;
	op->len = (size_t)(p - op->cmd);

	return done;
}

ssize_t esdm_cdev_egd_insert_user(const char __user *ubuf, size_t len)
{
	struct esdm_cdev_insert_op op;
	size_t done = 0;
	int ret = 0;

	if (!len)
		return 0;

	op.cmd = kmalloc(ESDM_CDEV_INSERT_CMDS * ESDM_EGD_MAX_CMD_SIZE + 1,
			 GFP_KERNEL);
	if (!op.cmd)
		return -ENOMEM;

	while (done < len) {
		size_t want = min_t(size_t, len - done, ESDM_CDEV_INSERT_MAX);
		size_t got;

		/*
		 * User memory is copied before a connection is taken: reading
		 * it may take as long as somebody else wants - a page of a
		 * file of a FUSE daemon that does not answer - and the
		 * connection would be held for that long, with every request
		 * of every other caller waiting for it.
		 */
		got = esdm_cdev_insert_fill(&op, ubuf + done, want);
		if (!got) {
			ret = -EFAULT;
			break;
		}

		ret = esdm_cdev_invoke(esdm_cdev_insert_op, &op, false);
		memzero_explicit(op.cmd, op.len);
		if (ret)
			break;
		done += got;

		if (got < want) {
			ret = -EFAULT;
			break;
		}

		/* As the kernel's devices: a signal ends the write */
		if (signal_pending(current))
			break;
		cond_resched();
	}

	kfree_sensitive(op.cmd);

	/* What was written is returned, an error only without any */
	return done ? (ssize_t)done : ret;
}

/******************************** Queries ************************************/

static int esdm_cdev_state_op(struct socket *sock, void *arg, bool *sent)
{
	struct esdm_cdev_state *state = arg;
	u32 fields[ESDM_EGD_STATE_NUM_FIELDS];
	u8 req = ESDM_EGD_CMD_ESDM_GET_STATE, num, val[4];
	unsigned int i;
	int ret;

	ret = esdm_cdev_send(sock, &req, sizeof(req), sent);
	if (ret)
		return ret;

	ret = esdm_cdev_recv(sock, &num, sizeof(num));
	if (ret)
		return ret;

	/* Fields are only ever appended, the ones known here are required */
	if (num < ESDM_EGD_STATE_NUM_FIELDS)
		return -EPROTO;

	for (i = 0; i < num; i++) {
		ret = esdm_cdev_recv(sock, val, sizeof(val));
		if (ret)
			return ret;
		if (i < ESDM_EGD_STATE_NUM_FIELDS)
			fields[i] = esdm_cdev_be32(val);
	}

	state->flags = fields[ESDM_EGD_STATE_FLAGS];
	state->ent_cnt = fields[ESDM_EGD_STATE_ENT_CNT];
	state->poolsize = fields[ESDM_EGD_STATE_POOLSIZE];
	state->write_wakeup = fields[ESDM_EGD_STATE_WRITE_WAKEUP];
	state->min_reseed_secs = fields[ESDM_EGD_STATE_MIN_RESEED_SECS];

	return 0;
}

int esdm_cdev_egd_get_state(struct esdm_cdev_state *state)
{
	return esdm_cdev_invoke(esdm_cdev_state_op, state, false);
}

struct esdm_cdev_status_op {
	bool json;
	char *report;
	size_t len;
};

static int esdm_cdev_status_op(struct socket *sock, void *arg, bool *sent)
{
	struct esdm_cdev_status_op *op = arg;
	u8 req = op->json ? ESDM_EGD_CMD_ESDM_STATUS_JSON :
			    ESDM_EGD_CMD_ESDM_STATUS;
	u8 val[4];
	char *report;
	u32 len;
	int ret;

	ret = esdm_cdev_send(sock, &req, sizeof(req), sent);
	if (ret)
		return ret;

	ret = esdm_cdev_recv(sock, val, sizeof(val));
	if (ret)
		return ret;

	len = esdm_cdev_be32(val);
	if (len > ESDM_EGD_MAX_STATUS)
		return -EPROTO;

	/* Held by the snapshot of a proc file, see esdm_cdev_proc.c */
	report = kvmalloc(len + 1, GFP_KERNEL_ACCOUNT);
	if (!report)
		return -ENOMEM;

	ret = esdm_cdev_recv(sock, report, len);
	if (ret) {
		kvfree(report);
		return ret;
	}
	report[len] = '\0';

	op->report = report;
	op->len = len;

	return 0;
}

int esdm_cdev_egd_status(bool json, char **report, size_t *len)
{
	struct esdm_cdev_status_op op = { .json = json };
	int ret;

	ret = esdm_cdev_invoke(esdm_cdev_status_op, &op, false);
	if (ret)
		return ret;

	*report = op.report;
	*len = op.len;

	return 0;
}

struct esdm_cdev_priv_op {
	u8 cmd;
	bool has_arg;
	u32 arg;
	int status;
};

static int esdm_cdev_priv_op(struct socket *sock, void *arg, bool *sent)
{
	struct esdm_cdev_priv_op *op = arg;
	u8 req[5] = { op->cmd }, val[4];
	s32 status;
	int ret;

	esdm_cdev_put_be32(req + 1, op->arg);

	ret = esdm_cdev_send(sock, req, op->has_arg ? 5 : 1, sent);
	if (ret)
		return ret;

	ret = esdm_cdev_recv_committed(sock, val, sizeof(val));
	if (ret)
		return ret;

	/* Success, or a negative errno - nothing else */
	status = (s32)esdm_cdev_be32(val);
	if (status > 0 || status < -MAX_ERRNO)
		return -EPROTO;

	op->status = status;

	return 0;
}

int esdm_cdev_egd_priv(u8 cmd, bool has_arg, u32 arg)
{
	struct esdm_cdev_priv_op op = {
		.cmd = cmd,
		.has_arg = has_arg,
		.arg = arg,
	};
	int ret;

	ret = esdm_cdev_invoke(esdm_cdev_priv_op, &op, true);

	return ret ? ret : op.status;
}

/****************************** Initialization *******************************/

int esdm_cdev_egd_init(void)
{
	unsigned int i;

	if (!egd_socket || !*egd_socket ||
	    strlen(egd_socket) >= sizeof_field(struct sockaddr_un, sun_path)) {
		pr_err("invalid EGD socket path\n");
		return -EINVAL;
	}

	esdm_cdev_nconns = clamp_t(unsigned int, connections, 1,
				   ESDM_CDEV_MAX_CONNECTIONS);
	esdm_cdev_conns = kcalloc(esdm_cdev_nconns, sizeof(*esdm_cdev_conns),
				  GFP_KERNEL);
	if (!esdm_cdev_conns)
		return -ENOMEM;

	for (i = 0; i < esdm_cdev_nconns; i++)
		mutex_init(&esdm_cdev_conns[i].lock);

	esdm_cdev_wq = alloc_workqueue("esdm_cdev", WQ_UNBOUND, 0);
	if (!esdm_cdev_wq) {
		kfree(esdm_cdev_conns);
		esdm_cdev_conns = NULL;
		return -ENOMEM;
	}

	return 0;
}

/*
 * Only once nobody uses the module any more: the devices and proc files are
 * gone, and with them every caller of the functions above.
 */
void esdm_cdev_egd_fini(void)
{
	unsigned int i;

	/* Waits for the work still running, whose waiters gave up */
	destroy_workqueue(esdm_cdev_wq);

	for (i = 0; i < esdm_cdev_nconns; i++) {
		struct esdm_cdev_conn *conn = &esdm_cdev_conns[i];

		if (conn->sock)
			sock_release(conn->sock);
		mutex_destroy(&conn->lock);
	}

	kfree(esdm_cdev_conns);
	esdm_cdev_conns = NULL;
}
