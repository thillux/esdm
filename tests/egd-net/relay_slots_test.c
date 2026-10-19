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
 * The esdm-egd-net-relay with all of its local connection slots taken: a new
 * connection is served, and one of the user holding the most closed for it -
 * the one its consumer used least recently:
 *
 *  - a user holding all slots pays for a new connection of its own with one
 *    of its own,
 *  - with several users (root only), a user holding fewer than the most -
 *    even one whose connection was used least recently of all - keeps its
 *    connections, and a new one of another user takes a slot of the user
 *    holding the most.
 *
 * Needs neither an ESDM nor a server: the relay answers the get PID command
 * itself, and its server is a port nobody listens on, in plain TCP. The
 * connections of other users are made by child processes under their UIDs
 * when the test runs as root; otherwise that part is skipped.
 */

#include "egd_net_test.h"

#include <grp.h>
#include <sys/un.h>

static const char *relay_bin;
static char tmpdir[] = "/tmp/esdm-egd-net-slots-test-XXXXXX";
static char sock[sizeof(tmpdir) + 16];

/* A relay with @max_connections slots, its server unreachable */
static pid_t relay_start(const char *max_connections)
{
	char connect[64], *argv[32];
	unsigned int n = 0;
	uint16_t port = 0;
	struct stat sb;
	uint64_t end;
	pid_t pid;
	int lfd;

	/* A port nobody listens on */
	lfd = test_listener("127.0.0.1", &port);
	if (lfd < 0)
		return -1;
	close(lfd);
	snprintf(connect, sizeof(connect), "127.0.0.1:%u", port);

	argv[n++] = (char *)relay_bin;
	argv[n++] = (char *)"-vvvv";
	if (!getuid()) {
		argv[n++] = (char *)"--username";
		argv[n++] = (char *)"root";
	}
	argv[n++] = (char *)"--plain";
	argv[n++] = (char *)"--connect";
	argv[n++] = connect;
	argv[n++] = (char *)"--timeout";
	argv[n++] = (char *)"2";
	argv[n++] = (char *)"--socket";
	argv[n++] = sock;
	argv[n++] = (char *)"--max_connections";
	argv[n++] = (char *)max_connections;
	argv[n++] = (char *)"--max_per_uid";
	argv[n++] = (char *)"8";
	argv[n] = NULL;

	unlink(sock);
	pid = test_daemon_start(relay_bin, argv, NULL, 0);
	if (pid < 0)
		return -1;

	end = test_now_ms() + 15000;
	while (test_now_ms() < end) {
		if (!stat(sock, &sb) && S_ISSOCK(sb.st_mode))
			return pid;
		test_sleep_ms(50);
	}
	test_daemon_stop(pid);
	return -1;
}

/* A connection to the relay that the relay served: it answered the PID */
static int relay_connect(pid_t relay)
{
	struct sockaddr_un addr;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
	    test_plain_pid(fd) != relay) {
		close(fd);
		return -1;
	}

	/* Apart in time from the next one, to the relay's clock */
	test_sleep_ms(20);
	return fd;
}

/*
 * relay_connect() as @uid: from a process of its own, which hands the
 * connection over once it was served, and is gone
 */
static int relay_connect_as(pid_t relay, uid_t uid)
{
	char data = 0, cbuf[CMSG_SPACE(sizeof(int))];
	struct iovec iov = { .iov_base = &data, .iov_len = 1 };
	struct msghdr msg = { .msg_iov = &iov,
			      .msg_iovlen = 1,
			      .msg_control = cbuf,
			      .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cmsg;
	int sv[2], fd = -1;
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
		/* May be denied in a user namespace, and is no matter then */
		(void)setgroups(0, NULL);
		if (setresgid((gid_t)uid, (gid_t)uid, (gid_t)uid) ||
		    setresuid(uid, uid, uid))
			_exit(1);
		fd = relay_connect(relay);
		if (fd < 0)
			_exit(2);

		memset(cbuf, 0, sizeof(cbuf));
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
		_exit(sendmsg(sv[1], &msg, 0) == 1 ? 0 : 3);
	}

	close(sv[1]);
	if (recvmsg(sv[0], &msg, MSG_CMSG_CLOEXEC) == 1) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));
	}
	close(sv[0]);
	waitpid(pid, NULL, 0);

	return fd;
}

/*
 * A connection of an unprivileged user: the test's, or as root - whose
 * connections are never closed for others - user 1001
 */
static int user_connect(pid_t relay)
{
	return getuid() ? relay_connect(relay) : relay_connect_as(relay, 1001);
}

/* Is the connection still served? */
static bool served(int fd, pid_t relay)
{
	return fd >= 0 && test_plain_pid(fd) == relay;
}

static void close_all(int *fds, unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		if (fds[i] >= 0)
			close(fds[i]);
		fds[i] = -1;
	}
}

/* One user holding all slots: a new connection costs it its own */
static void test_one_user(void)
{
	int fds[4], i;
	pid_t relay;

	printf("Relay: all slots taken by one user\n");

	relay = relay_start("3");
	CHECK(relay > 0, "the relay did not start");
	if (relay <= 0)
		return;

	for (i = 0; i < 3; i++) {
		fds[i] = user_connect(relay);
		CHECK(fds[i] >= 0, "connection %d was not served", i);
	}

	/* The second one is the one used least recently now */
	CHECK(served(fds[0], relay), "the first connection was lost");
	test_sleep_ms(20);

	fds[3] = user_connect(relay);
	CHECK(fds[3] >= 0,
	      "a new connection was refused with all slots taken");
	CHECK(fds[1] >= 0 && test_fd_closed(fds[1], 3000),
	      "the connection used least recently was not closed for it");
	CHECK(served(fds[0], relay) && served(fds[2], relay),
	      "another connection was closed");

	close_all(fds, 4);
	CHECK(test_daemon_stop(relay) == 0, "the relay did not stop");
}

/*
 * Several users (root only): the slots go from the user holding the most,
 * not from the one whose connection was used least recently of all
 */
static void test_users(void)
{
	int u1[3], u2, u3, u1_new, i;
	pid_t relay;

	printf("Relay: all slots taken by several users\n");
	if (getuid()) {
		printf("  not root, skipped\n");
		return;
	}

	relay = relay_start("4");
	CHECK(relay > 0, "the relay did not start");
	if (relay <= 0)
		return;

	/* Used least recently of all, but by the user holding the fewest */
	u2 = relay_connect_as(relay, 1002);
	CHECK(u2 >= 0, "the connection of user 1002 was not served");
	for (i = 0; i < 3; i++) {
		u1[i] = relay_connect_as(relay, 1001);
		CHECK(u1[i] >= 0, "connection %d of user 1001 was not served",
		      i);
	}

	/* User 1001 holds the most: its connection used least recently goes */
	u3 = relay_connect_as(relay, 1003);
	CHECK(u3 >= 0, "the connection of user 1003 was refused");
	CHECK(u1[0] >= 0 && test_fd_closed(u1[0], 3000),
	      "no connection of the user holding the most was closed");
	CHECK(served(u2, relay),
	      "the connection of a user holding fewer was closed");

	/* A new connection of the user holding the most costs it its own */
	u1_new = relay_connect_as(relay, 1001);
	CHECK(u1_new >= 0, "the new connection of user 1001 was refused");
	CHECK(u1[1] >= 0 && test_fd_closed(u1[1], 3000),
	      "user 1001 did not pay for its new connection itself");
	CHECK(served(u1[2], relay) && served(u2, relay) && served(u3, relay),
	      "another connection was closed");

	close_all(u1, 3);
	if (u2 >= 0)
		close(u2);
	if (u3 >= 0)
		close(u3);
	if (u1_new >= 0)
		close(u1_new);
	CHECK(test_daemon_stop(relay) == 0, "the relay did not stop");
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(300);
	signal(SIGPIPE, SIG_IGN);

	relay_bin = getenv("ESDM_EGD_NET_RELAY");
	if (test_env_check_file(relay_bin))
		return 1;
	if (!mkdtemp(tmpdir)) {
		printf("Cannot create %s\n", tmpdir);
		return 1;
	}
	/* For the users of the connections, see relay_connect_as() */
	chmod(tmpdir, 0755);
	snprintf(sock, sizeof(sock), "%s/egd.sock", tmpdir);

	test_one_user();
	test_users();

	unlink(sock);
	rmdir(tmpdir);

	printf("EGD network relay slots: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
