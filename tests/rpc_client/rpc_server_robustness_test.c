/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The unprivileged RPC interface served from a thread of this process, like
 * in tests/fuzz/rpc_client_fuzz.c: a fork() while requests are in flight
 * leaves the parent's connections intact, and a request that reaches a
 * connection while the idle timer closes it is answered.
 *
 * Runs unprivileged: the namespaces of tests/test_ipc_ns.c give it a /tmp of
 * its own to bind the socket in.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test_namespace.h"
#include "conv_be_le.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/* From esdm.h, whose definitions clash with those of esdm_rpc_client.h */
int esdm_init(void);
void esdm_fini(void);

#define TEST_FORKS 50

static pthread_t test_server;
static bool test_server_started = false;
static atomic_bool test_server_returned = false;

static void test_sleep_ms(long ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static void *test_serve(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_serve_in_process(
		ESDM_RPC_UNPRIV_SOCKET,
		(ProtobufCService *)&unpriv_access_service, false);
	if (ret)
		printf("RPC server did not run: %s\n", strerror(-ret));
	atomic_store(&test_server_returned, true);

	return NULL;
}

static atomic_bool test_fork_done = false;
static atomic_uint test_fork_failures = 0;

static void *test_fork_requester(void *unused)
{
	uint8_t buf[32];

	(void)unused;

	while (!atomic_load(&test_fork_done)) {
		ssize_t ret = esdm_rpcc_get_random_bytes(buf, sizeof(buf));

		if (ret != (ssize_t)sizeof(buf)) {
			printf("fork: request failed with %zd\n", ret);
			atomic_fetch_add(&test_fork_failures, 1);
		}
	}

	return NULL;
}

/* A child inherits the connections - its exit must not end the parent's */
static int test_fork(void)
{
	pthread_t thread;
	unsigned int i;

	if (pthread_create(&thread, NULL, test_fork_requester, NULL)) {
		printf("fork: cannot start the requesting thread\n");
		return 1;
	}

	for (i = 0; i < TEST_FORKS; i++) {
		pid_t pid = fork();

		if (pid == 0)
			_exit(0);
		if (pid > 0)
			waitpid(pid, NULL, 0);
		test_sleep_ms(10);
	}

	atomic_store(&test_fork_done, true);
	pthread_join(thread, NULL);

	printf("fork: %u failed requests during %u forks\n",
	       atomic_load(&test_fork_failures), TEST_FORKS);
	return atomic_load(&test_fork_failures) != 0;
}

/*
 * The idle timer of a worker closes the connections not used for an interval.
 * A request written to such a connection before the server stops reading from
 * it must be answered: closed with the connection, it would be lost, and a
 * client does not repeat every request. The test finds the phase of the timer
 * with a connection it leaves idle, then opens connections that all fall due
 * at one pass of the timer and writes two requests to each of them, one behind
 * the other, around that pass. A write the server refuses is fine - the client
 * connects anew - but a request that was written gets its answer.
 *
 * The server closes nothing unanswered here whatever the timing; how many
 * requests meet the pass, and so whether a server that drops them is caught,
 * is up to the scheduler.
 */
#define TEST_IDLE_CONNS 300
#define TEST_IDLE_ROUNDS 3
#define TEST_IDLE_PIPELINE 2
/* The requests of a round start this long before the pass ... */
#define TEST_IDLE_LEAD 0.001
/* ... and are spread over this time */
#define TEST_IDLE_SPAN 0.005
#define TEST_IDLE_TIMEOUT ((double)ESDM_RPC_IDLE_TIMEOUT_USEC / 1e6)

static double test_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void test_sleep_until(double when)
{
	double now = test_now();

	if (when > now)
		test_sleep_ms((long)((when - now) * 1000));
}

static int test_idle_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

/* What the server sends next: > 0 a message, 0 it closed, < 0 nothing */
static ssize_t test_idle_receive(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	uint8_t buf[256];
	ssize_t ret;

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return -1;
	ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);

	/* ECONNRESET: closed with the request unread */
	return ret < 0 ? 0 : ret;
}

static int test_idle(void)
{
	const ProtobufCMethodDescriptor *method =
		protobuf_c_service_descriptor_get_method_by_name(
			&unpriv_access__descriptor, "RpcGetRandomBytes");
	struct esdm_rpc_proto_cs_header header;
	/* GetRandomBytesRequest: field 1, a varint, 32 bytes */
	static const uint8_t body[] = { 0x08, 32 };
	uint8_t req[sizeof(header) + sizeof(body)];
	static int fds[TEST_IDLE_CONNS];
	static unsigned int sent[TEST_IDLE_CONNS];
	unsigned int answered = 0, refused = 0, dropped = 0, round, n;
	double tick;
	int probe, i;

	if (!method) {
		printf("idle: no method to call\n");
		return 1;
	}
	header.method_index =
		le_bswap32((uint32_t)(method - unpriv_access__descriptor.methods));
	header.message_length = le_bswap32(sizeof(body));
	header.request_id = le_bswap32(1);
	memcpy(req, &header, sizeof(header));
	memcpy(req + sizeof(header), body, sizeof(body));

	/* The timer closes an idle connection at one of its passes */
	probe = test_idle_connect();
	if (probe < 0 ||
	    test_idle_receive(probe, (int)(3000 * TEST_IDLE_TIMEOUT)) != 0) {
		printf("idle: the server does not close an idle connection\n");
		if (probe >= 0)
			close(probe);
		return 1;
	}
	tick = test_now();
	close(probe);

	for (round = 0; round < TEST_IDLE_ROUNDS; round++) {
		double start, step = TEST_IDLE_SPAN / TEST_IDLE_CONNS;

		/*
		 * Opened shortly after a pass, the connections are not idle
		 * for an interval at the next one and fall due at the second.
		 */
		while (tick + 0.02 < test_now())
			tick += TEST_IDLE_TIMEOUT;
		test_sleep_until(tick + 0.02);
		for (i = 0; i < TEST_IDLE_CONNS; i++) {
			fds[i] = test_idle_connect();
			if (fds[i] < 0) {
				printf("idle: cannot connect\n");
				while (i--)
					close(fds[i]);
				return 1;
			}
		}

		/*
		 * A pass closes in the order the connections were accepted
		 * in: write to the last ones first, they stay open longest.
		 */
		start = tick + 2 * TEST_IDLE_TIMEOUT - TEST_IDLE_LEAD;
		test_sleep_until(start - 0.005);
		for (i = TEST_IDLE_CONNS - 1; i >= 0; i--) {
			while (test_now() <
			       start + step * (TEST_IDLE_CONNS - 1 - i))
				;
			for (n = 0; n < TEST_IDLE_PIPELINE; n++) {
				if (send(fds[i], req, sizeof(req),
					 MSG_NOSIGNAL | MSG_DONTWAIT) !=
				    (ssize_t)sizeof(req))
					break;
			}
			sent[i] = n;
		}

		for (i = 0; i < TEST_IDLE_CONNS; i++) {
			refused += TEST_IDLE_PIPELINE - sent[i];
			for (n = 0; n < sent[i]; n++) {
				if (test_idle_receive(fds[i], 5000) > 0)
					answered++;
				else
					dropped++;
			}
			close(fds[i]);
		}
	}

	printf("idle: of %u requests around the idle timer %u were answered, %u refused at the write, %u written and not answered\n",
	       TEST_IDLE_ROUNDS * TEST_IDLE_CONNS * TEST_IDLE_PIPELINE, answered,
	       refused, dropped);

	return dropped != 0;
}

static int test_start_server(void)
{
	struct stat sb;
	uint8_t buf[32];
	unsigned int i;

	if (esdm_init() || esdm_test_shm_status_init() || thread_init(1)) {
		printf("Cannot initialize the ESDM\n");
		return 1;
	}

	if (pthread_create(&test_server, NULL, test_serve, NULL)) {
		printf("Cannot start the RPC server thread\n");
		return 1;
	}
	test_server_started = true;

	for (i = 0; i < 500; i++) {
		if (atomic_load(&test_server_returned))
			return 1;
		if (!stat(ESDM_RPC_UNPRIV_SOCKET, &sb) && S_ISSOCK(sb.st_mode))
			break;
		test_sleep_ms(10);
	}

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot initialize the RPC client\n");
		return 1;
	}

	/* Until the ESDM is seeded - the test wants its data */
	if (esdm_rpcc_get_random_bytes_full(buf, sizeof(buf)) !=
	    (ssize_t)sizeof(buf)) {
		printf("The RPC server does not deliver data\n");
		return 1;
	}

	return 0;
}

int main(void)
{
	int ret;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 77;
	}

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	if (test_start_server()) {
		ret = 1;
		goto out;
	}

	ret = test_fork();
	ret |= test_idle();

	esdm_rpcc_fini_unpriv_service();

out:
	esdm_rpc_server_signal_exit();
	if (test_server_started)
		pthread_join(test_server, NULL);
	esdm_fini();

	return ret;
}
