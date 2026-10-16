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
 * Prediction resistant requests spread over many connections of one worker of
 * the RPC server.
 *
 * Each costs a reseed, and a worker serves all of its ready connections one
 * after the other: unbound, a few hundred of them hold up every other client
 * of the worker for seconds. The worker therefore spends only so much time per
 * round on them and answers the rest with -EAGAIN, which the clients retry on.
 *
 * The real unprivileged service is served on a socket of the test's own,
 * through the serve hook of the fuzz harnesses, by a single worker - with
 * several, the requests spread over them and the PR DRNG, which serves one
 * caller at a time, answers -EAGAIN to all but one anyway. No daemon and no
 * privileges are needed, but an operational ESDM is: the Jitter RNG is enough.
 *
 *   - every request is answered, with the bytes asked for or -EAGAIN,
 *   - with more of them pending at once than fit into a round, some are
 *     answered -EAGAIN,
 *   - a cheap request of another client is answered all the same.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "common.pb-c.h"
#include "common_test.h"
#include "config.h"
#include "conv_be_le.h"
#include "esdm.h"
#include "esdm_config.h"
#include "esdm_logger.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

/* Size of each request, the most the server serves at once */
#define TEST_PR_LEN 32

/* Most connections the flood is spread over */
#define TEST_MAX_CONNS 256

/*
 * The time the server spends per round on prediction resistant requests, see
 * ESDM_RPCS_PR_BUDGET_NS. The flood is sized to take several times as long.
 */
#define TEST_BUDGET_MS 25

static char test_dir[] = "/tmp/esdm-rpc-pr-budget-test.XXXXXX";
static char test_path[sizeof(test_dir) + 16];

static atomic_bool test_serve_failed;

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

static uint64_t test_now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

static void *test_serve(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(
		test_path, (ProtobufCService *)&unpriv_access_service, false);
	if (ret) {
		fprintf(stderr, "the server did not run: %s\n", strerror(-ret));
		atomic_store(&test_serve_failed, true);
	}

	return NULL;
}

static bool test_wait_for_socket(void)
{
	unsigned int i;
	struct stat sb;

	for (i = 0; i < 500; i++) {
		if (atomic_load(&test_serve_failed))
			return false;
		if (!stat(test_path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(10);
	}

	return false;
}

static int test_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_path);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		int errsv = errno;

		close(fd);
		return -errsv;
	}

	return fd;
}

static uint32_t test_method(const char *name)
{
	const ProtobufCServiceDescriptor *desc = &unpriv_access__descriptor;
	const ProtobufCMethodDescriptor *m =
		protobuf_c_service_descriptor_get_method_by_name(desc, name);

	if (!m) {
		CHECK(0, "no method %s", name);
		return 0;
	}

	return (uint32_t)(m - desc->methods);
}

/* Send a request for @method carrying @msg, NULL for an empty one */
static bool test_send(int fd, uint32_t method, const ProtobufCMessage *msg,
		      uint32_t request_id)
{
	uint8_t buf[sizeof(struct esdm_rpc_proto_cs_header) + 64];
	struct esdm_rpc_proto_cs_header header;
	size_t len = 0;

	if (msg) {
		len = protobuf_c_message_get_packed_size(msg);
		if (len > sizeof(buf) - sizeof(header))
			return false;
		protobuf_c_message_pack(msg, buf + sizeof(header));
	}

	header.method_index = le_bswap32(method);
	header.message_length = le_bswap32((uint32_t)len);
	header.request_id = le_bswap32(request_id);
	memcpy(buf, &header, sizeof(header));

	return send(fd, buf, sizeof(header) + len, MSG_NOSIGNAL) ==
	       (ssize_t)(sizeof(header) + len);
}

/*
 * Wait up to @timeout_ms for the answer to @request_id. With @randval, it is
 * the answer to a request for random bytes, and its return code goes there.
 */
static bool test_answer(int fd, uint32_t request_id, int timeout_ms,
			int64_t *randval)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE];
	struct esdm_rpc_proto_sc_header reply;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	RandValResponse *response;
	ssize_t received;
	uint32_t len;

	if (poll(&pfd, 1, timeout_ms) != 1)
		return false;

	received = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
	if (received < (ssize_t)sizeof(reply))
		return false;

	memcpy(&reply, buf, sizeof(reply));
	if (le_bswap32(reply.request_id) != request_id)
		return false;

	if (!randval)
		return true;

	len = le_bswap32(reply.message_length);
	if (len > (size_t)received - sizeof(reply))
		return false;

	response = rand_val_response__unpack(NULL, len, buf + sizeof(reply));
	if (!response)
		return false;

	*randval = response->ret;
	if (response->ret > 0 && response->randval.len != (size_t)response->ret)
		*randval = INT64_MIN;
	rand_val_response__free_unpacked(response, NULL);

	return true;
}

/* Time one prediction resistant generation takes here, in microseconds */
static uint64_t test_pr_cost_us(void)
{
	uint8_t buf[TEST_PR_LEN];
	uint64_t start, best = UINT64_MAX;
	unsigned int i;

	for (i = 0; i < 5; i++) {
		ssize_t rc;

		start = test_now_us();
		rc = esdm_get_random_bytes_pr_noblock(buf, sizeof(buf));
		if (rc != (ssize_t)sizeof(buf))
			continue;
		if (test_now_us() - start < best)
			best = test_now_us() - start;
	}

	return best;
}

static void test_flood(void)
{
	static int fds[TEST_MAX_CONNS];
	GetRandomBytesRequest msg = GET_RANDOM_BYTES_REQUEST__INIT;
	uint32_t pr = test_method("RpcGetRandomBytesPr");
	uint32_t ent = test_method("RpcGetEntLvl");
	unsigned int i, conns, served = 0, eagain = 0, other = 0, opened = 0;
	uint64_t cost, start, bystander_us;
	int bystander;

	printf("Prediction resistant requests on many connections of one worker\n");

	cost = test_pr_cost_us();
	if (cost == UINT64_MAX) {
		printf("  SKIPPED: the PR DRNG does not deliver here\n");
		return;
	}

	/*
	 * Pending at once, they take several rounds' worth of time - an order
	 * of magnitude more than fit into one.
	 */
	conns = (unsigned int)(10 * TEST_BUDGET_MS * 1000 / (cost ? cost : 1));
	if (conns < 16)
		conns = 16;
	if (conns > TEST_MAX_CONNS)
		conns = TEST_MAX_CONNS;
	printf("  %llu us per generation, %u connections\n",
	       (unsigned long long)cost, conns);

	bystander = test_connect();
	CHECK(bystander >= 0, "cannot connect: %s", strerror(-bystander));
	if (bystander < 0)
		return;

	for (opened = 0; opened < conns; opened++) {
		fds[opened] = test_connect();
		if (fds[opened] < 0) {
			CHECK(0, "cannot connect: %s", strerror(-fds[opened]));
			goto out;
		}
	}

	msg.len = TEST_PR_LEN;
	for (i = 0; i < conns; i++)
		CHECK(test_send(fds[i], pr, &msg.base, i),
		      "cannot send request %u", i);

	/* Right behind the flood */
	start = test_now_us();
	CHECK(test_send(bystander, ent, NULL, conns),
	      "cannot send the bystander's request");
	CHECK(test_answer(bystander, conns, 10000, NULL),
	      "the bystander's request was not answered");
	bystander_us = test_now_us() - start;

	for (i = 0; i < conns; i++) {
		int64_t rc = 0;

		if (!test_answer(fds[i], i, 30000, &rc)) {
			CHECK(0, "request %u was not answered", i);
			continue;
		}

		if (rc == TEST_PR_LEN)
			served++;
		else if (rc == -EAGAIN)
			eagain++;
		else
			other++;
	}

	printf("  %u served, %u -EAGAIN, bystander answered after %llu ms\n",
	       served, eagain, (unsigned long long)(bystander_us / 1000));

	CHECK(other == 0, "%u answers were neither the bytes nor -EAGAIN",
	      other);
	CHECK(served > 0, "no request was served");
	CHECK(eagain > 0,
	      "all %u requests were served in a row - the worker had no bound",
	      conns);

out:
	while (opened--)
		close(fds[opened]);
	close(bystander);
}

int main(void)
{
	pthread_t thread;
	unsigned int i;

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/* One worker, see above - the server starts one per node. */
	esdm_config_max_nodes_set(1);

	if (esdm_init()) {
		fprintf(stderr, "cannot initialize the ESDM\n");
		return 1;
	}

	for (i = 0; i < 600 && !esdm_state_operational(); i++)
		test_sleep_ms(100);
	if (!esdm_state_operational()) {
		printf("SKIPPED: the ESDM does not become operational here\n");
		esdm_fini();
		return 77;
	}

	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		esdm_fini();
		return 1;
	}
	snprintf(test_path, sizeof(test_path), "%s/unpriv", test_dir);

	if (thread_init(1)) {
		fprintf(stderr, "cannot initialize threading support\n");
		return 1;
	}

	if (pthread_create(&thread, NULL, test_serve, NULL)) {
		fprintf(stderr, "cannot start the server thread\n");
		return 1;
	}

	if (!test_wait_for_socket()) {
		fprintf(stderr, "the server did not come up\n");
		return 1;
	}

	test_flood();

	esdm_rpc_server_signal_exit();
	pthread_join(thread, NULL);

	unlink(test_path);
	rmdir(test_dir);
	esdm_fini();

	if (!common_test_failures)
		printf("PASS\n");

	return common_test_failures ? 1 : 0;
}
