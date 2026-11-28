/*
 * Protocol level tests of the EGD client library
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
 * These run against the test peer next to this file rather than an esdm-server,
 * because they are about the client's own behaviour: its command framing, what
 * it makes of an answer no correct server would give, and how it handles a
 * connection that is gone. No privileges needed; the esdm-server side of the
 * protocol is covered by egd_server_test.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "egd_peer.h"
#include "esdm_egd_client.h"
#include "esdm_egd_protocol.h"

/*
 * Bound on every wait of a client under test. Generous enough not to be hit by
 * a loaded machine, short enough that the deliberately unanswered requests do
 * not stretch the test run.
 */
#define TEST_TIMEOUT_MS 2000

/*
 * Backstop for a client that does not come back at all. Well above what the
 * deliberately unanswered requests add up to, and below the timeout the test
 * harness applies to the whole run.
 */
#define TEST_WATCHDOG_SEC 90

static char tmpdir[] = "/tmp/esdm-egd-test-XXXXXX";

/* Socket path of one test, in the temporary directory created by main(). */
static const char *test_socket(const char *name)
{
	static char path[sizeof(((struct sockaddr_un *)0)->sun_path)];

	snprintf(path, sizeof(path), "%s/%s.sock", tmpdir, name);

	return path;
}

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL: ");                                    \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			ret = 1;                                               \
		}                                                              \
	} while (0)

/*
 * A request longer than one protocol transfer has to be split by the client,
 * and the pieces have to arrive in order. The peer answers with a counter, so
 * the reassembled result says both.
 */
static int test_blocking_read_chunking(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	/* Two transfers: a full one of 255 bytes and a remainder of 45. */
	uint8_t buf[300];
	size_t i;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("chunk"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("chunk"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");

	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0, "byte %zu is 0x%02x, expected 0x%02x", i,
			      buf[i], egd_peer_data_byte(i));
			break;
		}
	}

	CHECK(egd_peer_requests(peer) == 2, "%u transfers, expected 2",
	      egd_peer_requests(peer));
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The non-blocking read reports what it got, which may be less than asked. */
static int test_nonblocking_read(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[32];
	size_t generated = 0;
	size_t i;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("nonblock"), EGD_PEER_SHORT))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("nonblock"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == 0,
	      "the non-blocking read failed");
	CHECK(generated == sizeof(buf) / 2, "%zu bytes delivered, expected %zu",
	      generated, sizeof(buf) / 2);

	for (i = 0; i < generated; i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0, "byte %zu is 0x%02x, expected 0x%02x", i,
			      buf[i], egd_peer_data_byte(i));
			break;
		}
	}

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A peer announcing more data than was asked for is not speaking this protocol.
 * Reading it would overrun the caller's buffer and desynchronize the stream, so
 * the client has to refuse on the length byte alone.
 */
static int test_nonblocking_overlong(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	size_t generated = 1;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("overlong"), EGD_PEER_OVERLONG))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("overlong"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == -EPROTO,
	      "an overlong answer was not rejected with -EPROTO");
	CHECK(generated == 0, "%zu bytes reported after the failure", generated);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The entropy count arrives as a big endian four byte number. */
static int test_entropy_count(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("entcnt"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("entcnt"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(bits == EGD_PEER_ENTROPY_BITS, "%u bits, expected %u", bits,
	      EGD_PEER_ENTROPY_BITS);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * The state flags come first; the fields a client does not know are read and
 * skipped, so that the next answer is still in sync.
 */
static int test_get_state_flags(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t flags = 0, bits = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("state"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("state"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_state_flags(client, &flags) == 0,
	      "the state query failed");
	CHECK(flags == (ESDM_EGD_STATE_FLAG_OPERATIONAL |
			ESDM_EGD_STATE_FLAG_FULLY_SEEDED),
	      "flags 0x%x", flags);
	CHECK(esdm_egd_client_get_state_flags(client, NULL) == -EINVAL,
	      "no flags pointer was accepted");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0 &&
		      bits == EGD_PEER_ENTROPY_BITS,
	      "the answer after the state is out of sync");

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The PID arrives as a string, without a terminating NUL. */
static int test_get_pid(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	pid_t pid = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("getpid"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("getpid"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_pid(client, &pid) == 0,
	      "the PID request failed");
	CHECK(pid == EGD_PEER_PID, "PID %d, expected %d", (int)pid,
	      EGD_PEER_PID);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The write command carries its entropy claim and its length in the header. */
static int test_write_entropy(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	static const uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef,
					0x01, 0x02, 0x03, 0x04 };
	uint8_t received[sizeof(data)];
	uint32_t bits = 0;
	size_t len = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("write"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("write"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_write_entropy(client, data, sizeof(data), 64) == 0,
	      "the entropy insertion failed");

	/*
	 * The command has no answer, so the client is done before the peer has
	 * necessarily read it. One request that does get answered orders the
	 * two against each other.
	 */
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");

	CHECK(egd_peer_last_write(peer, received, sizeof(received), &len,
				  &bits) == 1,
	      "the peer did not receive exactly one write command");
	CHECK(len == sizeof(data), "%zu bytes written, expected %zu", len,
	      sizeof(data));
	CHECK(bits == 64, "%u bits claimed, expected 64", bits);
	CHECK(memcmp(received, data, sizeof(data)) == 0,
	      "the written data does not match");

	/*
	 * The claim is two bytes on the wire, so a larger one is capped rather
	 * than truncated into a small number.
	 */
	CHECK(esdm_egd_client_write_entropy(client, data, sizeof(data),
					    UINT32_MAX) == 0,
	      "the entropy insertion with a large claim failed");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(egd_peer_last_write(peer, NULL, 0, NULL, &bits) == 2,
	      "the peer did not receive the second write command");
	CHECK(bits == UINT16_MAX, "%u bits claimed, expected %u", bits,
	      UINT16_MAX);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Nothing here may reach the peer, and nothing may crash. */
static int test_arguments(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	size_t generated = 1;
	uint32_t bits;
	pid_t pid;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("args"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("args"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_alloc(NULL, test_socket("args"), 0) == -EINVAL,
	      "an allocation without a result pointer was accepted");

	CHECK(esdm_egd_client_get_random(client, NULL, 16) == -EINVAL,
	      "a blocking read without a buffer was accepted");
	CHECK(esdm_egd_client_get_random(NULL, buf, sizeof(buf)) == -EINVAL,
	      "a blocking read without a client was accepted");
	CHECK(esdm_egd_client_get_random(client, buf, 0) == 0,
	      "an empty blocking read is not a no-op");

	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  NULL) == -EINVAL,
	      "a non-blocking read without a result pointer was accepted");
	/* The protocol cannot express more than one transfer here. */
	CHECK(esdm_egd_client_get_random_nonblock(client, buf,
						  ESDM_EGD_MAX_TRANSFER + 1,
						  &generated) == -EINVAL,
	      "an oversized non-blocking read was accepted");
	CHECK(esdm_egd_client_get_random_nonblock(client, buf, 0,
						  &generated) == 0,
	      "an empty non-blocking read is not a no-op");
	CHECK(generated == 0, "%zu bytes reported for an empty read",
	      generated);

	CHECK(esdm_egd_client_entropy_count(client, NULL) == -EINVAL,
	      "an entropy count without a result pointer was accepted");
	CHECK(esdm_egd_client_entropy_count(NULL, &bits) == -EINVAL,
	      "an entropy count without a client was accepted");

	CHECK(esdm_egd_client_get_pid(client, NULL) == -EINVAL,
	      "a PID request without a result pointer was accepted");
	CHECK(esdm_egd_client_get_pid(NULL, &pid) == -EINVAL,
	      "a PID request without a client was accepted");

	CHECK(esdm_egd_client_write_entropy(client, NULL, 16, 0) == -EINVAL,
	      "an insertion without data was accepted");
	CHECK(esdm_egd_client_write_entropy(client, buf,
					    ESDM_EGD_MAX_TRANSFER + 1,
					    0) == -EINVAL,
	      "an oversized insertion was accepted");
	CHECK(esdm_egd_client_write_entropy(client, buf, 0, 0) == 0,
	      "an empty insertion is not a no-op");

	CHECK(esdm_egd_client_socket_path(NULL) == NULL,
	      "a socket path was reported for no client");
	CHECK(esdm_egd_client_socket_path(client) != NULL &&
		      !strcmp(esdm_egd_client_socket_path(client),
			      test_socket("args")),
	      "the client reports the wrong socket path");

	CHECK(egd_peer_requests(peer) == 0,
	      "%u requests reached the peer, expected none",
	      egd_peer_requests(peer));

	/* Releasing no client at all is allowed. */
	esdm_egd_client_free(NULL);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Without a path, the one from the environment is used. */
static int test_socket_path_from_env(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("env"), EGD_PEER_NORMAL))
		return 1;

	setenv("ESDM_EGD_SOCKET", test_socket("env"), 1);

	if (esdm_egd_client_alloc(&client, NULL, TEST_TIMEOUT_MS)) {
		unsetenv("ESDM_EGD_SOCKET");
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(!strcmp(esdm_egd_client_socket_path(client), test_socket("env")),
	      "the environment socket path was not taken over");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the connection from the environment path does not work");

	/* An empty path is not a path either. */
	unsetenv("ESDM_EGD_SOCKET");
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * The daemon is restarted between two requests: the first attempt fails on the
 * connection it had, and the retry on a fresh one succeeds - the caller sees
 * nothing but a successful request.
 */
static int test_reconnect(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("reconnect"), EGD_PEER_HANGUP))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("reconnect"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the request was not retried on a fresh connection");
	CHECK(egd_peer_connections(peer) == 2, "%u connections, expected 2",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A failed request must not leave anything behind that could be mistaken for
 * random data.
 */
static int test_failure_wipes_buffer(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	uint8_t zero[sizeof(buf)];
	size_t generated = 1;
	int ret = 0;

	memset(zero, 0, sizeof(zero));

	if (egd_peer_start(&peer, test_socket("silent"), EGD_PEER_SILENT))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("silent"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) ==
		      -ETIMEDOUT,
	      "an unanswered blocking read did not time out");
	CHECK(memcmp(buf, zero, sizeof(buf)) == 0,
	      "the buffer was not cleansed after the failure");

	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random_nonblock(client, buf, sizeof(buf),
						  &generated) == -ETIMEDOUT,
	      "an unanswered non-blocking read did not time out");
	CHECK(memcmp(buf, zero, sizeof(buf)) == 0,
	      "the buffer was not cleansed after the failure");
	CHECK(generated == 0, "%zu bytes reported after the failure",
	      generated);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Is @fd still the application's /dev/zero? */
static bool test_is_dev_zero(int fd)
{
	struct stat st;

	return fstat(fd, &st) == 0 && S_ISCHR(st.st_mode);
}

/*
 * An application may close descriptor ranges it did not open - OpenSSH does on
 * its way into the pre-authentication child - freeing the number for reuse.
 * Reading "random" data out of whatever took its place would be a silent and
 * serious failure, so the client has to notice, and leave the descriptor alone
 * on reconnect, fork and free. The check needs the client's descriptor, which
 * is the lowest free one at connect time; nothing else here opens one in
 * between, but that is verified rather than trusted.
 */
static int test_descriptor_identity(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	uint8_t buf[16];
	size_t i;
	pid_t child;
	int fd, zero_fd, status, ret = 0;

	if (egd_peer_start(&peer, test_socket("closefrom"), EGD_PEER_NORMAL))
		return 1;

	/* The number the client's socket is about to get. */
	fd = dup(0);
	if (fd < 0) {
		egd_peer_stop(peer);
		return 1;
	}
	close(fd);

	if (esdm_egd_client_alloc(&client, test_socket("closefrom"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	if (getpeername(fd, (struct sockaddr *)&addr, &addrlen) < 0 ||
	    strcmp(addr.sun_path, test_socket("closefrom"))) {
		printf("  SKIP: the client's descriptor could not be identified\n");
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 0;
	}

	/* Close it behind the client's back and let something else have it. */
	close(fd);
	zero_fd = open("/dev/zero", O_RDONLY);
	if (zero_fd != fd) {
		printf("  SKIP: the descriptor number was not reused\n");
		if (zero_fd >= 0)
			close(zero_fd);
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 0;
	}

	/* The fork handler gives up the client's connections in the child */
	child = fork();
	if (child == 0)
		_exit(test_is_dev_zero(zero_fd) ? 0 : 1);
	CHECK(child > 0 && waitpid(child, &status, 0) == child &&
		      WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "the fork child lost the application's descriptor");

	/*
	 * Reading from /dev/zero would succeed and deliver zeros. The client
	 * has to reconnect instead and come back with the peer's data.
	 */
	memset(buf, 0xff, sizeof(buf));
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");
	CHECK(test_is_dev_zero(zero_fd),
	      "the client closed the application's descriptor on reconnect");
	for (i = 0; i < sizeof(buf); i++) {
		if (buf[i] != egd_peer_data_byte(i)) {
			CHECK(0,
			      "byte %zu is 0x%02x, expected 0x%02x - the data does not come from the peer",
			      i, buf[i], egd_peer_data_byte(i));
			break;
		}
	}
	CHECK(egd_peer_connections(peer) == 2,
	      "%u connections, expected the client to have reconnected",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	CHECK(test_is_dev_zero(zero_fd),
	      "freeing the client closed the application's descriptor");
	close(zero_fd);
	egd_peer_stop(peer);

	return ret;
}

/*
 * The kernel reports the peer by the path the server bound, not the configured
 * one (/var/run is mostly a symlink to /run). That must not read as a foreign
 * descriptor: every operation would reconnect, which a sandbox cannot.
 */
static int test_symlinked_path(void)
{
	char link[sizeof(((struct sockaddr_un *)0)->sun_path)];
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	uint8_t buf[16];
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("target"), EGD_PEER_NORMAL))
		return 1;

	snprintf(link, sizeof(link), "%s/link.sock", tmpdir);
	if (symlink(test_socket("target"), link)) {
		egd_peer_stop(peer);
		return 1;
	}

	if (esdm_egd_client_alloc(&client, link, TEST_TIMEOUT_MS)) {
		unlink(link);
		egd_peer_stop(peer);
		return 1;
	}

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the entropy count failed");
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected the client to keep its first one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	unlink(link);
	egd_peer_stop(peer);

	return ret;
}

static volatile sig_atomic_t test_sigpipe;

static void test_sigpipe_handler(int sig)
{
	(void)sig;
	test_sigpipe = 1;
}

/*
 * A peer that stopped reading leaves the socket writable without a hangup;
 * the write then must fail the operation, not raise SIGPIPE and kill the
 * application. Caught here so that a failure is reported, not fatal.
 */
static int test_write_to_closed_peer(void)
{
	struct sigaction sa, old_sa;
	sigset_t mask, pending;
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	unsigned int i;
	int rc, ret = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = test_sigpipe_handler;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGPIPE, &sa, &old_sa))
		return 1;
	test_sigpipe = 0;

	if (egd_peer_start(&peer, test_socket("shutrd"), EGD_PEER_SHUT_RD)) {
		sigaction(SIGPIPE, &old_sa, NULL);
		return 1;
	}

	/* Short: the retry may write before the peer shut its end down */
	if (esdm_egd_client_alloc(&client, test_socket("shutrd"), 500)) {
		egd_peer_stop(peer);
		sigaction(SIGPIPE, &old_sa, NULL);
		return 1;
	}

	/* The first attempt is to find the receiving end shut down */
	for (i = 0; i < 100 && egd_peer_connections(peer) < 1; i++)
		usleep(10 * 1000);

	rc = esdm_egd_client_entropy_count(client, &bits);
	CHECK(rc == -EPIPE || rc == -ETIMEDOUT,
	      "the request to a peer that does not read returned %d", rc);
	CHECK(!test_sigpipe, "writing to the peer raised SIGPIPE");

	/* The signal mask is as it was, with nothing left pending */
	CHECK(pthread_sigmask(SIG_SETMASK, NULL, &mask) == 0 &&
		      !sigismember(&mask, SIGPIPE),
	      "SIGPIPE was left blocked");
	CHECK(sigpending(&pending) == 0 && !sigismember(&pending, SIGPIPE),
	      "a SIGPIPE was left pending");

	esdm_egd_client_free(client);
	egd_peer_stop(peer);
	sigaction(SIGPIPE, &old_sa, NULL);

	return ret;
}

/*
 * Two processes issuing commands on one connection would desynchronize the
 * stream, so a child must not inherit the parent's. It gets one of its own,
 * and the parent's keeps working.
 */
static int test_fork(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[16];
	int status = 0;
	pid_t pid;
	int ret = 0;

	if (egd_peer_start(&peer, test_socket("fork"), EGD_PEER_NORMAL))
		return 1;

	if (esdm_egd_client_alloc(&client, test_socket("fork"),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(peer);
		return 1;
	}

	/* Establish the connection that the child must not use. */
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the blocking read failed");

	pid = fork();
	if (pid < 0) {
		CHECK(0, "fork failed");
		esdm_egd_client_free(client);
		egd_peer_stop(peer);
		return 1;
	}
	if (pid == 0) {
		uint8_t child_buf[16];

		/*
		 * The peer's threads do not exist here, so the client is all
		 * this child may touch of the test - and _exit() rather than
		 * exit() keeps it from running the parent's atexit handlers.
		 */
		_exit(esdm_egd_client_get_random(client, child_buf,
						 sizeof(child_buf)) ?
			      1 :
			      0);
	}

	waitpid(pid, &status, 0);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "the child could not use the client (status %#x)", status);

	/* The parent's connection survived the child. */
	CHECK(esdm_egd_client_get_random(client, buf, sizeof(buf)) == 0,
	      "the parent's connection stopped working");
	CHECK(egd_peer_connections(peer) == 2,
	      "%u connections, expected the child to have opened its own",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A client whose peer is not there yet is handed back usable - a consumer set
 * up before the ESDM is running keeps working once it arrives.
 */
static int test_late_peer(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint32_t bits = 0;
	int ret = 0;

	CHECK(esdm_egd_client_alloc(&client, test_socket("late"),
				    TEST_TIMEOUT_MS) == 0,
	      "the allocation without a peer failed");
	if (client == NULL)
		return 1;

	if (egd_peer_start(&peer, test_socket("late"), EGD_PEER_NORMAL)) {
		esdm_egd_client_free(client);
		return 1;
	}

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0,
	      "the client did not connect once the peer arrived");
	CHECK(bits == EGD_PEER_ENTROPY_BITS, "%u bits, expected %u", bits,
	      EGD_PEER_ENTROPY_BITS);

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

struct egd_test {
	const char *name;
	int (*run)(void);
};

/* Start a peer in @mode and connect a client to it */
static int test_setup(const char *name, enum egd_peer_mode mode,
		      struct egd_peer **peer, struct esdm_egd_client **client)
{
	if (egd_peer_start(peer, test_socket(name), mode))
		return 1;

	if (esdm_egd_client_alloc(client, test_socket(name),
				  TEST_TIMEOUT_MS)) {
		egd_peer_stop(*peer);
		return 1;
	}

	return 0;
}

/* Is @buf the peer's counter sequence from @offset on? */
static bool test_is_sequence(const uint8_t *buf, size_t len, size_t offset)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i] != egd_peer_data_byte(offset + i))
			return false;
	}

	return true;
}

/*
 * The prediction resistance and the unseeded reads are the reads of EGD under
 * another command byte: split and reassembled, or short, as those.
 */
static int test_esdm_reads(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	uint8_t buf[300];
	size_t generated = 0;
	int ret = 0;

	if (test_setup("esdmread", EGD_PEER_SHORT, &peer, &client))
		return 1;

	CHECK(esdm_egd_client_get_random_pr(client, buf, sizeof(buf)) == 0,
	      "the blocking PR read failed");
	CHECK(test_is_sequence(buf, sizeof(buf), 0),
	      "the blocking PR read is not reassembled in order");
	CHECK(egd_peer_requests(peer) == 2, "%u transfers, expected 2",
	      egd_peer_requests(peer));

	CHECK(esdm_egd_client_get_random_pr_nonblock(client, buf, 100,
						     &generated) == 0 &&
		      generated == 50,
	      "the non-blocking PR read delivered %zu bytes, expected 50",
	      generated);
	CHECK(test_is_sequence(buf, generated, 300),
	      "the non-blocking PR read is out of sequence");

	CHECK(esdm_egd_client_get_random_unseeded(client, buf, 100,
						  &generated) == 0 &&
		      generated == 50,
	      "the unseeded read delivered %zu bytes, expected 50", generated);
	CHECK(test_is_sequence(buf, generated, 350),
	      "the unseeded read is out of sequence");

	CHECK(esdm_egd_client_get_random_pr(client, NULL, 1) == -EINVAL,
	      "a PR read without a buffer was accepted");
	CHECK(esdm_egd_client_get_random_pr_nonblock(
		      client, buf, ESDM_EGD_MAX_TRANSFER + 1, &generated) ==
		      -EINVAL,
	      "a non-blocking PR read beyond one transfer was accepted");
	CHECK(esdm_egd_client_get_random_unseeded(
		      client, buf, ESDM_EGD_MAX_TRANSFER + 1, &generated) ==
		      -EINVAL,
	      "an unseeded read beyond one transfer was accepted");
	CHECK(esdm_egd_client_get_random_unseeded(client, buf, 1, NULL) ==
		      -EINVAL,
	      "an unseeded read without a length was accepted");

	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The bulk read takes more than one EGD transfer in a single request. */
static int test_bulk_read(void)
{
	static const uint8_t reads[] = { ESDM_EGD_CMD_READ_NONBLOCK,
					 ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK,
					 ESDM_EGD_CMD_ESDM_READ_UNSEEDED };
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	static uint8_t buf[ESDM_EGD_MAX_BULK + 1];
	uint8_t zero[64] = { 0 };
	size_t generated = 0, offset = 0;
	unsigned int i, requests;
	int ret = 0;

	if (test_setup("bulk", EGD_PEER_NORMAL, &peer, &client))
		return 1;

	for (i = 0; i < sizeof(reads); i++) {
		CHECK(esdm_egd_client_get_random_bulk(client, reads[i], buf,
						      1000, &generated) == 0 &&
			      generated == 1000,
		      "the bulk read 0x%02x delivered %zu bytes, expected 1000",
		      reads[i], generated);
		CHECK(test_is_sequence(buf, generated, offset),
		      "the bulk read 0x%02x is out of sequence", reads[i]);
		offset += generated;
	}
	CHECK(egd_peer_requests(peer) == 3, "%u requests, expected 3",
	      egd_peer_requests(peer));

	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_READ_NONBLOCK, buf,
					      ESDM_EGD_MAX_BULK,
					      &generated) == 0 &&
		      generated == ESDM_EGD_MAX_BULK,
	      "the largest bulk read delivered %zu bytes", generated);

	/* What the ESDM would close the connection for never reaches it */
	requests = egd_peer_requests(peer);
	CHECK(esdm_egd_client_get_random_bulk(client, ESDM_EGD_CMD_READ_BLOCK,
					      buf, 16, &generated) == -EINVAL,
	      "a bulk read standing for the blocking read was accepted");
	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_READ_NONBLOCK, buf,
					      ESDM_EGD_MAX_BULK + 1,
					      &generated) == -EINVAL,
	      "a bulk read beyond the bound was accepted");
	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_READ_NONBLOCK, NULL,
					      16, &generated) == -EINVAL,
	      "a bulk read without a buffer was accepted");
	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_READ_NONBLOCK, buf,
					      0, &generated) == 0 &&
		      generated == 0,
	      "an empty bulk read failed");
	CHECK(egd_peer_requests(peer) == requests,
	      "a rejected bulk read was sent");

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	/* A short answer is reported as such */
	if (test_setup("bulkshort", EGD_PEER_SHORT, &peer, &client))
		return 1;
	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_ESDM_READ_UNSEEDED,
					      buf, 1000, &generated) == 0 &&
		      generated == 500,
	      "the short bulk read delivered %zu bytes, expected 500",
	      generated);
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	/* More than asked for is rejected on the length, the buffer wiped */
	if (test_setup("bulklong", EGD_PEER_OVERLONG, &peer, &client))
		return 1;
	memset(buf, 0xaa, sizeof(zero));
	CHECK(esdm_egd_client_get_random_bulk(client,
					      ESDM_EGD_CMD_READ_NONBLOCK, buf,
					      sizeof(zero),
					      &generated) == -EPROTO,
	      "an overlong bulk answer was accepted");
	CHECK(generated == 0 && !memcmp(buf, zero, sizeof(zero)),
	      "the buffer of a failed bulk read was not cleansed");
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* Every field of the state, and the stream in sync after the unknown one. */
static int test_get_state(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	struct esdm_egd_client_state state;
	uint32_t bits = 0;
	int ret = 0;

	if (test_setup("fullstate", EGD_PEER_NORMAL, &peer, &client))
		return 1;

	memset(&state, 0xff, sizeof(state));
	CHECK(esdm_egd_client_get_state(client, &state) == 0,
	      "the state query failed");
	CHECK(state.flags == (ESDM_EGD_STATE_FLAG_OPERATIONAL |
			      ESDM_EGD_STATE_FLAG_FULLY_SEEDED),
	      "flags 0x%x", state.flags);
	CHECK(state.entropy_count == EGD_PEER_STATE_ENT_CNT,
	      "entropy count 0x%x", state.entropy_count);
	CHECK(state.poolsize == EGD_PEER_STATE_POOLSIZE, "pool size 0x%x",
	      state.poolsize);
	CHECK(state.write_wakeup == EGD_PEER_STATE_WRITE_WAKEUP,
	      "write wakeup threshold 0x%x", state.write_wakeup);
	CHECK(state.min_reseed_secs == EGD_PEER_STATE_MIN_RESEED_SECS,
	      "reseed seconds 0x%x", state.min_reseed_secs);
	CHECK(esdm_egd_client_get_state(client, NULL) == -EINVAL,
	      "no state pointer was accepted");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0 &&
		      bits == EGD_PEER_ENTROPY_BITS,
	      "the answer after the state is out of sync");

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * The status reports arrive without a NUL and may exceed the caller's buffer:
 * the text is cut short, the JSON document refused, and either way all of the
 * report is taken off the stream.
 */
static int test_status(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	char buf[ESDM_EGD_MAX_STATUS + 1], small[8];
	uint32_t bits = 0;
	int ret = 0;

	if (test_setup("status", EGD_PEER_NORMAL, &peer, &client))
		return 1;

	memset(buf, 'x', sizeof(buf));
	CHECK(esdm_egd_client_status(client, buf, sizeof(buf)) == 0,
	      "the status request failed");
	CHECK(!strcmp(buf, EGD_PEER_STATUS), "status \"%s\"", buf);

	memset(buf, 'x', sizeof(buf));
	CHECK(esdm_egd_client_status_json(client, buf, sizeof(buf)) == 0,
	      "the JSON status request failed");
	CHECK(!strcmp(buf, EGD_PEER_STATUS_JSON), "JSON status \"%s\"", buf);

	/* A buffer of exactly the report and its NUL */
	CHECK(esdm_egd_client_status_json(client, buf,
					  strlen(EGD_PEER_STATUS_JSON) + 1) ==
		      0 &&
		      !strcmp(buf, EGD_PEER_STATUS_JSON),
	      "the JSON status does not fit a buffer of its size");
	CHECK(esdm_egd_client_status_json(client, buf,
					  strlen(EGD_PEER_STATUS_JSON)) ==
		      -EMSGSIZE &&
		      buf[0] == '\0',
	      "a JSON status one byte too long was returned");

	memset(small, 'x', sizeof(small));
	CHECK(esdm_egd_client_status(client, small, sizeof(small)) == 0,
	      "the status request into a small buffer failed");
	CHECK(strlen(small) == sizeof(small) - 1 &&
		      !strncmp(small, EGD_PEER_STATUS, sizeof(small) - 1),
	      "the status is not cut to the buffer: \"%.8s\"", small);
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0 &&
		      bits == EGD_PEER_ENTROPY_BITS,
	      "the answer after a status cut short is out of sync");

	CHECK(esdm_egd_client_status_json(client, small, sizeof(small)) ==
		      -EMSGSIZE,
	      "a JSON status that does not fit was returned");
	CHECK(small[0] == '\0', "a refused JSON status left data behind");
	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0 &&
		      bits == EGD_PEER_ENTROPY_BITS,
	      "the answer after a refused JSON status is out of sync");

	CHECK(esdm_egd_client_status(client, NULL, 16) == -EINVAL,
	      "a status request without a buffer was accepted");
	CHECK(esdm_egd_client_status_json(client, buf, 0) == -EINVAL,
	      "a status request with an empty buffer was accepted");
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	/* An ESDM that cannot produce the report sends an empty one */
	if (test_setup("nostatus", EGD_PEER_SHORT, &peer, &client))
		return 1;
	CHECK(esdm_egd_client_status(client, buf, sizeof(buf)) == -ENODATA,
	      "an empty status was not reported");
	CHECK(esdm_egd_client_status_json(client, buf, sizeof(buf)) ==
		      -ENODATA,
	      "an empty JSON status was not reported");
	CHECK(egd_peer_connections(peer) == 1,
	      "an empty status dropped the connection");
	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* One privileged command: sent with its argument, answered with a status */
static int test_priv_cmd(struct egd_peer *peer, int result, int expected,
			 uint8_t cmd, uint32_t arg, unsigned int count)
{
	uint8_t seen_cmd = 0;
	uint32_t seen_arg = ~arg;
	int ret = 0;

	CHECK(result == expected, "command 0x%02x returned %d, expected %d",
	      cmd, result, expected);
	CHECK(egd_peer_last_priv(peer, &seen_cmd, &seen_arg) == count,
	      "command 0x%02x did not arrive", cmd);
	CHECK(seen_cmd == cmd && seen_arg == arg,
	      "command 0x%02x with argument %u arrived as 0x%02x with %u", cmd,
	      arg, seen_cmd, seen_arg);

	return ret;
}

static int test_priv_cmds(struct egd_peer *peer,
			  struct esdm_egd_client *client, int expected)
{
	int ret = 0;

	ret |= test_priv_cmd(peer,
			     esdm_egd_client_add_to_entropy_count(client, 384),
			     expected, ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT, 384,
			     1);
	ret |= test_priv_cmd(peer, esdm_egd_client_clear_pool(client),
			     expected, ESDM_EGD_CMD_ESDM_CLEAR_POOL, 0, 2);
	ret |= test_priv_cmd(peer, esdm_egd_client_reseed(client), expected,
			     ESDM_EGD_CMD_ESDM_RESEED, 0, 3);
	ret |= test_priv_cmd(peer,
			     esdm_egd_client_set_write_wakeup(client,
							      0x01020304),
			     expected, ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP,
			     0x01020304, 4);
	ret |= test_priv_cmd(peer,
			     esdm_egd_client_set_min_reseed_secs(client, 600),
			     expected, ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS,
			     600, 5);

	return ret;
}

/*
 * The privileged commands are answered with a status. A refusal is such an
 * answer: it is handed to the caller and neither repeated nor paid for with the
 * connection.
 */
static int test_privileged(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	struct esdm_egd_client_state state;
	int ret = 0;

	if (test_setup("priv", EGD_PEER_NORMAL, &peer, &client))
		return 1;

	ret |= test_priv_cmds(peer, client, 0);
	CHECK(esdm_egd_client_get_state(client, &state) == 0 &&
		      state.write_wakeup == 0x01020304 &&
		      state.min_reseed_secs == 600,
	      "the state does not show what was set: %u, %u",
	      state.write_wakeup, state.min_reseed_secs);
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	if (test_setup("unpriv", EGD_PEER_UNPRIVILEGED, &peer, &client))
		return 1;

	ret |= test_priv_cmds(peer, client, -EPERM);
	CHECK(esdm_egd_client_get_state(client, &state) == 0 &&
		      state.write_wakeup == EGD_PEER_STATE_WRITE_WAKEUP &&
		      state.min_reseed_secs == EGD_PEER_STATE_MIN_RESEED_SECS,
	      "the state after refused commands: %u, %u", state.write_wakeup,
	      state.min_reseed_secs);
	CHECK(egd_peer_connections(peer) == 1,
	      "a refusal cost the connection: %u connections",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/* The bulk insert carries its length in four bytes and is confirmed. */
static int test_insert(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	static uint8_t data[ESDM_EGD_MAX_BULK + 1];
	uint32_t sum = 0, expected = 0;
	size_t len = 0, i;
	int ret = 0;

	if (test_setup("insert", EGD_PEER_NORMAL, &peer, &client))
		return 1;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7);
	for (i = 0; i < 1000; i++)
		expected += data[i];

	CHECK(esdm_egd_client_insert(client, data, 1000) == 0,
	      "the bulk insert failed");
	CHECK(egd_peer_inserted(peer, &len, &sum) == 1 && len == 1000 &&
		      sum == expected,
	      "%zu bytes with sum %u arrived, expected 1000 with sum %u", len,
	      sum, expected);

	CHECK(esdm_egd_client_insert(client, data, ESDM_EGD_MAX_BULK) == 0,
	      "the largest bulk insert failed");
	CHECK(egd_peer_inserted(peer, &len, NULL) == 2 &&
		      len == 1000 + ESDM_EGD_MAX_BULK,
	      "%zu bytes arrived in all", len);

	CHECK(esdm_egd_client_insert(client, data, 0) == 0,
	      "an empty bulk insert failed");
	CHECK(esdm_egd_client_insert(client, data, sizeof(data)) == -EINVAL,
	      "a bulk insert beyond the bound was accepted");
	CHECK(esdm_egd_client_insert(client, NULL, 16) == -EINVAL,
	      "a bulk insert without data was accepted");
	CHECK(egd_peer_inserted(peer, NULL, NULL) == 2,
	      "a rejected bulk insert was sent");
	CHECK(egd_peer_connections(peer) == 1,
	      "%u connections, expected a single one",
	      egd_peer_connections(peer));

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

/*
 * A peer that does not know the commands of the ESDM closes the connection.
 * That is an error after the one retry, and the commands of EGD work on.
 */
static int test_legacy_peer(void)
{
	struct egd_peer *peer;
	struct esdm_egd_client *client = NULL;
	struct esdm_egd_client_state state;
	uint8_t buf[16];
	uint32_t bits = 0;
	int ret = 0;

	if (test_setup("legacy", EGD_PEER_LEGACY, &peer, &client))
		return 1;

	CHECK(esdm_egd_client_get_state(client, &state) < 0,
	      "a state was read from a peer that has none");
	CHECK(egd_peer_connections(peer) == 2,
	      "%u connections, expected the first one and a retry",
	      egd_peer_connections(peer));
	/* The peer serves a handful of connections, each of these takes two */
	CHECK(esdm_egd_client_reseed(client) < 0,
	      "a reseed was confirmed by a peer that knows none");
	CHECK(esdm_egd_client_get_random_pr(client, buf, sizeof(buf)) < 0,
	      "a PR read was answered by a peer that knows none");

	CHECK(esdm_egd_client_entropy_count(client, &bits) == 0 &&
		      bits == EGD_PEER_ENTROPY_BITS,
	      "the EGD commands do not work after an unknown one");

	esdm_egd_client_free(client);
	egd_peer_stop(peer);

	return ret;
}

int main(int argc, char *argv[])
{
	static const struct egd_test tests[] = {
		{ "blocking read chunking", test_blocking_read_chunking },
		{ "non-blocking read", test_nonblocking_read },
		{ "overlong answer", test_nonblocking_overlong },
		{ "entropy count", test_entropy_count },
		{ "state flags", test_get_state_flags },
		{ "PID request", test_get_pid },
		{ "entropy insertion", test_write_entropy },
		{ "argument checks", test_arguments },
		{ "socket path from the environment",
		  test_socket_path_from_env },
		{ "reconnect after a hangup", test_reconnect },
		{ "buffer cleansing on failure", test_failure_wipes_buffer },
		{ "descriptor identity", test_descriptor_identity },
		{ "socket path through a symlink", test_symlinked_path },
		{ "write to a peer that does not read",
		  test_write_to_closed_peer },
		{ "fork", test_fork },
		{ "peer arriving late", test_late_peer },
		{ "ESDM reads", test_esdm_reads },
		{ "ESDM bulk read", test_bulk_read },
		{ "ESDM state", test_get_state },
		{ "ESDM status reports", test_status },
		{ "ESDM privileged commands", test_privileged },
		{ "ESDM bulk insert", test_insert },
		{ "peer without the ESDM commands", test_legacy_peer },
	};
	unsigned int failed = 0;
	size_t i;

	(void)argc;
	(void)argv;

	/*
	 * Line buffered: should a client ever wedge, the test is killed by the
	 * watchdog below or by the harness, and what it printed until then is
	 * the only indication of where it got stuck.
	 */
	setvbuf(stdout, NULL, _IOLBF, 0);

	/*
	 * Every wait in here is bounded, so the whole run is. Being killed here
	 * means a client did not come back at all, which has to be a failure
	 * rather than a test run that hangs until the harness gives up.
	 */
	alarm(TEST_WATCHDOG_SEC);

	if (mkdtemp(tmpdir) == NULL) {
		printf("Cannot create the temporary directory: %s\n",
		       strerror(errno));
		return 1;
	}

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int ret;

		printf("EGD client: %s\n", tests[i].name);
		ret = tests[i].run();
		if (ret)
			failed++;
	}

	rmdir(tmpdir);

	printf("EGD client: %zu tests, %u failed\n",
	       sizeof(tests) / sizeof(tests[0]), failed);

	return failed ? 1 : 0;
}
