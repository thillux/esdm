/*
 * Tests of the EGD interface of the esdm-server
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
 * The counterpart of egd_client_test: that one drives the client against a peer
 * of its own to reach answers a correct server never gives, this one against
 * the real esdm-server started with --egd_socket. Both sides of the protocol
 * are only covered together. The server refuses to run unprivileged, so this
 * skips (77) when not started as root.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"

#include "../test_env.h"
#include "../test_namespace.h"

/*
 * The blocking read waits for the ESDM to become operational, which right
 * after its start legitimately takes a moment.
 */
#define TEST_TIMEOUT_MS 30000

/* How long the server is given to accept on its socket. */
#define TEST_SERVER_START_SEC 30

/*
 * Backstop for a request that never comes back - a server that created its
 * socket but does not serve it, say. Below the timeout the test harness applies
 * to the whole run, so the failure is this test's rather than the harness'.
 */
#define TEST_WATCHDOG_SEC 240

static char tmpdir[] = "/tmp/esdm-egd-server-test-XXXXXX";
static char sockpath[sizeof(tmpdir) + 32];
static pid_t server_pid;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

/* Does the server accept connections on its socket yet? */
static int server_accepts(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	int ret;

	if (fd < 0)
		return 0;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
	ret = !connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	close(fd);

	return ret;
}

static int server_start(void)
{
	const char *server = getenv("ESDM_SERVER");
	struct timespec wait = { .tv_sec = 0, .tv_nsec = 200 * 1000 * 1000 };
	char *server_envp[TEST_ENV_MAX_VARS + 1];
	struct stat sb;
	unsigned int i;

	if (server == NULL || stat(server, &sb) < 0 || !S_ISREG(sb.st_mode)) {
		printf("ESDM_SERVER does not point at the esdm-server binary\n");
		return 1;
	}

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(server_envp, TEST_ENV_MAX_VARS + 1);

	server_pid = fork();
	if (server_pid < 0)
		return 1;

	if (server_pid == 0) {
		char binary[FILENAME_MAX];
		char socket_arg[sizeof(sockpath)];
		/*
		 * Verbose logging implies staying in the foreground. In its
		 * own PID namespace the daemon is PID 1 there, while the PID
		 * to report is the one started here, see the PID request.
		 */
		char *argv[] = { binary,
				 (char *)"-vvvvv",
				 (char *)"--pid_namespace",
				 (char *)"--egd_socket",
				 socket_arg,
				 NULL };

		snprintf(binary, sizeof(binary), "%s", server);
		snprintf(socket_arg, sizeof(socket_arg), "%s", sockpath);
		execve(server, argv, server_envp);

		/* NOTREACHED */
		_exit(1);
	}

	/*
	 * The server is ready once it accepts on its socket: the file is there
	 * from the bind(2) on, but a connection is refused until the listen(2).
	 */
	for (i = 0; i < TEST_SERVER_START_SEC * 5; i++) {
		if (server_accepts())
			return 0;
		if (waitpid(server_pid, NULL, WNOHANG) == server_pid) {
			printf("The esdm-server terminated during its start\n");
			server_pid = 0;
			return 1;
		}
		nanosleep(&wait, NULL);
	}

	printf("The esdm-server did not accept on %s\n", sockpath);

	return 1;
}

static void server_stop(void)
{
	struct timespec wait = { .tv_sec = 1, .tv_nsec = 0 };

	if (server_pid <= 0)
		return;

	printf("Killing server PID %u\n", (unsigned int)server_pid);
	kill(server_pid, SIGTERM);
	test_env_reap_daemon_or_fail(server_pid, "esdm-server");
	server_pid = 0;

	nanosleep(&wait, NULL);
}

/*
 * The ESDM's own commands have no client library calls but the prediction
 * resistant reads: they are spoken here in raw bytes, on a connection of their
 * own.
 */
static int raw_connect(void)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sockpath);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static int raw_send(int fd, const void *buf, size_t len)
{
	return send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

static int raw_recv(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t rc;

		if (poll(&pfd, 1, TEST_TIMEOUT_MS) <= 0)
			return -1;
		rc = recv(fd, p + got, len - got, 0);
		if (rc <= 0)
			return -1;
		got += (size_t)rc;
	}

	return 0;
}

static uint32_t raw_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Command 0xe3, the first ESDM_EGD_STATE_NUM_FIELDS fields */
static int raw_state(int fd, uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS])
{
	const uint8_t cmd = ESDM_EGD_CMD_ESDM_GET_STATE;
	uint8_t count, resp[4 * 63];
	unsigned int i;

	if (raw_send(fd, &cmd, 1) || raw_recv(fd, &count, 1) || count > 63 ||
	    count < ESDM_EGD_STATE_NUM_FIELDS ||
	    raw_recv(fd, resp, 4 * (size_t)count))
		return -1;

	for (i = 0; i < ESDM_EGD_STATE_NUM_FIELDS; i++)
		fields[i] = raw_be32(resp + 4 * i);

	return 0;
}

/* Commands 0xe4 and 0xe5, the report as a string to be freed */
static char *raw_status(int fd, uint8_t cmd)
{
	uint8_t hdr[4];
	uint32_t len;
	char *report;

	if (raw_send(fd, &cmd, 1) || raw_recv(fd, hdr, sizeof(hdr)))
		return NULL;

	len = raw_be32(hdr);
	if (!len || len > ESDM_EGD_MAX_STATUS)
		return NULL;

	report = calloc(1, (size_t)len + 1);
	if (report && raw_recv(fd, report, len)) {
		free(report);
		report = NULL;
	}

	return report;
}

/* Commands 0xe6 to 0xea, the status they are answered with */
static int raw_priv(int fd, uint8_t command, uint32_t arg, int32_t *status)
{
	uint8_t cmd[5] = { command, (uint8_t)(arg >> 24), (uint8_t)(arg >> 16),
			   (uint8_t)(arg >> 8), (uint8_t)arg };
	size_t len = (command == ESDM_EGD_CMD_ESDM_CLEAR_POOL ||
		      command == ESDM_EGD_CMD_ESDM_RESEED) ?
			     1 :
			     5;
	uint8_t resp[4];

	if (raw_send(fd, cmd, len) || raw_recv(fd, resp, sizeof(resp)))
		return -1;

	*status = (int32_t)raw_be32(resp);

	return 0;
}

/* The ESDM's own commands against the daemon, as root and as somebody else */
static int test_esdm_commands(void)
{
	uint32_t orig[ESDM_EGD_STATE_NUM_FIELDS];
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS];
	char *report;
	int32_t status = 1;
	int fd, ret = 0, wstatus;
	pid_t child;

	printf("EGD server: ESDM state and status\n");
	fd = raw_connect();
	if (fd < 0) {
		CHECK(0, "cannot connect to %s", sockpath);
		return ret;
	}

	CHECK(raw_state(fd, orig) == 0, "the state was not answered");
	CHECK(orig[ESDM_EGD_STATE_FLAGS] & ESDM_EGD_STATE_FLAG_OPERATIONAL,
	      "the daemon does not report itself operational");
	CHECK(orig[ESDM_EGD_STATE_POOLSIZE] > 0, "the pool size is zero");

	report = raw_status(fd, ESDM_EGD_CMD_ESDM_STATUS);
	CHECK(report && strstr(report, "DRNG name: "),
	      "the status is no status: %.200s", report ? report : "");
	free(report);

	report = raw_status(fd, ESDM_EGD_CMD_ESDM_STATUS_JSON);
	CHECK(report && report[0] == '{' && strstr(report, "\"drngs\""),
	      "the JSON status is no status: %.200s", report ? report : "");
	free(report);

	printf("EGD server: ESDM privileged commands as root\n");
	CHECK(raw_priv(fd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
		       orig[ESDM_EGD_STATE_MIN_RESEED_SECS] == 99 ? 98 : 99,
		       &status) == 0 &&
		      status == 0,
	      "setting the reseed seconds failed: %d", status);
	CHECK(raw_state(fd, fields) == 0 &&
		      fields[ESDM_EGD_STATE_MIN_RESEED_SECS] ==
			      (orig[ESDM_EGD_STATE_MIN_RESEED_SECS] == 99 ? 98 :
									     99),
	      "the reseed seconds were not set");
	CHECK(raw_priv(fd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
		       orig[ESDM_EGD_STATE_MIN_RESEED_SECS], &status) == 0 &&
		      status == 0,
	      "restoring the reseed seconds failed: %d", status);
	CHECK(raw_priv(fd, ESDM_EGD_CMD_ESDM_RESEED, 0, &status) == 0 &&
		      status == 0,
	      "the reseed failed: %d", status);
	close(fd);

	/*
	 * The same command from somebody else, whom the daemon knows by the
	 * credentials of the socket.
	 */
	printf("EGD server: ESDM privileged commands of an unprivileged user\n");
	if (chmod(tmpdir, 0711) < 0) {
		CHECK(0, "cannot open %s to other users", tmpdir);
		return ret;
	}
	child = fork();
	if (child < 0) {
		CHECK(0, "cannot fork");
		return ret;
	}
	if (!child) {
		int cfd;

		if (setgid(65534) < 0 || setuid(65534) < 0)
			_exit(2);
		cfd = raw_connect();
		if (cfd < 0)
			_exit(3);
		if (raw_priv(cfd, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS, 7,
			     &status) ||
		    status != -EPERM)
			_exit(4);
		if (raw_state(cfd, fields) ||
		    fields[ESDM_EGD_STATE_MIN_RESEED_SECS] == 7)
			_exit(5);
		_exit(0);
	}
	CHECK(waitpid(child, &wstatus, 0) == child && WIFEXITED(wstatus) &&
		      WEXITSTATUS(wstatus) == 0,
	      "the unprivileged user was not refused (status 0x%x)", wstatus);
	chmod(tmpdir, 0700);

	return ret;
}

int main(int argc, char *argv[])
{
	struct esdm_egd_client *client = NULL;
	/* More than one protocol transfer, so the server serves two. */
	uint8_t buf[300];
	uint8_t zero[sizeof(buf)];
	uint8_t seed[32];
	size_t generated = 0;
	uint32_t bits = 0;
	unsigned int i;
	pid_t pid = 0;
	int ret = 0;

	(void)argc;
	(void)argv;

	memset(zero, 0, sizeof(zero));

	/*
	 * The server shares this output and is started with verbose logging, so
	 * keep the test's own progress in step with it - and keep it readable
	 * should the run be killed part way through.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(TEST_WATCHDOG_SEC);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}

	/*
	 * The EGD socket below is named uniquely, but the server started on it
	 * also claims the fixed RPC socket, semaphore and IPC names. Run in
	 * namespaces of our own so those cannot collide with another test using
	 * the same ones - see tests/test_namespace.h.
	 */
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}
	snprintf(sockpath, sizeof(sockpath), "%s/egd.sock", tmpdir);

	if (server_start()) {
		rmdir(tmpdir);
		return 1;
	}

	if (esdm_egd_client_alloc(&client, sockpath, TEST_TIMEOUT_MS)) {
		printf("Cannot allocate the client\n");
		server_stop();
		rmdir(tmpdir);
		return 1;
	}

	printf("EGD server: PID request\n");
	CHECK(esdm_egd_client_get_pid(client, &pid) == 0,
	      "the PID request failed");
	/*
	 * A PID the caller can act on: the process started here, which
	 * forwards signals to the daemon - not the daemon, whose own PID is 1
	 * and names init outside its namespace.
	 */
	CHECK(pid == server_pid,
	      "the server reports PID %d, it was started as %d", (int)pid,
	      (int)server_pid);

	printf("EGD server: entropy count\n");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	printf("  %u bits available\n", bits);

	printf("EGD server: blocking read\n");
	memset(buf, 0, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");
	CHECK(memcmp(buf, zero, sizeof(buf)) != 0,
	      "the blocking read delivered nothing but zeroes");

	printf("EGD server: non-blocking read\n");
	CHECK(esdm_egd_client_get_random_nonblock(client, buf,
						  ESDM_EGD_MAX_TRANSFER,
						  &generated) == 0,
	      "the non-blocking read failed");
	/* A short answer is legitimate, more than was asked for is not. */
	CHECK(generated <= ESDM_EGD_MAX_TRANSFER,
	      "%zu bytes delivered, at most %u were asked for", generated,
	      ESDM_EGD_MAX_TRANSFER);
	printf("  %zu of %u bytes delivered right away\n", generated,
	       ESDM_EGD_MAX_TRANSFER);

	printf("EGD server: entropy insertion\n");
	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;
	CHECK(esdm_egd_client_write_entropy(client, seed, sizeof(seed),
					    8 * sizeof(seed)) == 0,
	      "the entropy insertion failed");
	/*
	 * The command has no answer of its own, so a following request is what
	 * shows that the server kept the stream in sync over it.
	 */
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count after an insertion failed");

	printf("EGD server: many requests on one connection\n");
	for (i = 0; i < 16; i++) {
		if (esdm_egd_client_get_random(client, buf, 64)) {
			CHECK(0, "request %u failed", i);
			break;
		}
	}

	printf("EGD server: prediction resistant reads\n");
	memset(buf, 0, sizeof(buf));
	CHECK(esdm_egd_client_get_random_pr(client, buf, sizeof(buf)) == 0,
	      "the prediction resistant blocking read failed");
	CHECK(memcmp(buf, zero, sizeof(buf)) != 0,
	      "the prediction resistant read delivered nothing but zeroes");
	CHECK(esdm_egd_client_get_random_pr_nonblock(
		      client, buf, ESDM_EGD_MAX_TRANSFER, &generated) == 0,
	      "the prediction resistant non-blocking read failed");
	CHECK(generated <= ESDM_EGD_MAX_TRANSFER,
	      "%zu prediction resistant bytes delivered, at most %u were asked for",
	      generated, ESDM_EGD_MAX_TRANSFER);
	printf("  %zu of %u prediction resistant bytes delivered right away\n",
	       generated, ESDM_EGD_MAX_TRANSFER);

	if (test_esdm_commands())
		ret = 1;

	/*
	 * The daemon goes away underneath the client: the request must come
	 * back with an error rather than hang or take the caller down with a
	 * SIGPIPE.
	 */
	printf("EGD server: the daemon goes away\n");
	server_stop();
	CHECK(esdm_egd_client_get_random(client, buf, 16) < 0,
	      "a request against the stopped daemon succeeded");

	esdm_egd_client_free(client);
	rmdir(tmpdir);

	printf("EGD server: %s\n", ret ? "FAILED" : "passed");

	return ret;
}
