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
 * The opportunistic DTLS of the RPC connections - see ESDM_RPC_PROTO_STARTDTLS
 * in esdm_rpc_protocol.h.
 *
 * The server's accept loop and workers serve stand-in services on sockets of
 * the test's own, through the serve hook of the fuzz harnesses, and the client
 * library of this process reaches them through a relay on the sockets it
 * connects to, which looks at every message passing:
 *
 *   - with DTLS, the largest answer and the largest request of either
 *     interface pass encrypted - the relay sees none of the data -, and the
 *     server sees the requests come encrypted,
 *   - a server refusing DTLS serves the client in the clear, on the same
 *     connection, and the relay sees the data then,
 *   - a forked child encrypts a connection of its own, and leaves the one of
 *     its parent alone,
 *   - a client not knowing STARTDTLS is served in the clear,
 *   - a client stalling its handshake or sending garbage instead holds up
 *     nobody, and its connection is closed,
 *   - a server not knowing STARTDTLS, as ESDM 1.2.3 and before, whether it
 *     closes the connection on it or leaves it unanswered, serves the client
 *     in the clear without the client waiting for it, on either interface.
 *
 * Without DTLS built, the client does not ask for it, and a server answers a
 * STARTDTLS request with a refusal, the connection going on in the clear.
 *
 * Started with "serve", it serves the stand-in services on the sockets the
 * client connects to until SIGTERM, answering requests for random numbers in
 * the clear with -EPERM - the server of rpc_dtls_getrandom_test.c.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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

#include "common_test.h"
#include "config.h"
#include "conv_be_le.h"
#include "esdm_dtls.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "helper.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_protocol.h"
#include "esdm_rpc_server.h"
#include "esdm_rpc_service.h"
#include "priv_access.pb-c.h"
#include "threading_support.h"
#include "unpriv_access.pb-c.h"

#define TEST_IDLE_MS (ESDM_RPC_IDLE_TIMEOUT_USEC / 1000)

/* The largest request of the privileged interface the test sends */
#define TEST_PRIV_LEN 32768

static char test_dir[] = "/tmp/esdm-rpc-dtls-test.XXXXXX";
static char test_priv_path[sizeof(test_dir) + 16];
static char test_unpriv_path[sizeof(test_dir) + 16];

static atomic_bool test_serve_failed;

/* What the stand-in services hand out and what they were handed */
static uint8_t test_pattern[ESDM_RPC_MAX_DATA];
static uint8_t test_wpattern[ESDM_RPC_MAX_DATA];
static uint8_t test_written[ESDM_RPC_MAX_DATA];
static size_t test_written_len;
static pthread_mutex_t test_written_lock = PTHREAD_MUTEX_INITIALIZER;

/* Requests of the test - not the probe - served encrypted and in the clear */
static atomic_uint test_calls_encrypted;
static atomic_uint test_calls_clear;

/* Random numbers for an encrypted connection only, see main() */
static bool test_encrypted_only;

static void test_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

#ifdef ESDM_DTLS
static uint64_t test_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
#endif

/* Bytes that do not repeat, so a part of them seen anywhere tells */
static void test_fill(uint8_t *buf, size_t len, uint64_t state)
{
	size_t i;

	for (i = 0; i < len; i++) {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		buf[i] = (uint8_t)(state >> 24);
	}
}

/******************************************************************************
 * The stand-in services
 ******************************************************************************/

static void test_count(void *closure_data)
{
	if (esdm_rpcs_fuzz_conn_encrypted(closure_data))
		atomic_fetch_add(&test_calls_encrypted, 1);
	else
		atomic_fetch_add(&test_calls_clear, 1);
}

static void test_record(const uint8_t *data, size_t len)
{
	pthread_mutex_lock(&test_written_lock);
	if (len > sizeof(test_written))
		len = sizeof(test_written);
	memcpy(test_written, data, len);
	test_written_len = len;
	pthread_mutex_unlock(&test_written_lock);
}

/* The answer of a method the test does not look at: all fields zero */
static void test_answer_empty(const ProtobufCMethodDescriptor *method,
			      ProtobufCClosure closure, void *closure_data)
{
	uint64_t msg[64];

	if (method->output->sizeof_message > sizeof(msg))
		return;
	protobuf_c_message_init(method->output, msg);
	closure((const ProtobufCMessage *)msg, closure_data);
}

static void test_unpriv_invoke(ProtobufCService *service,
			       unsigned int method_index,
			       const ProtobufCMessage *input,
			       ProtobufCClosure closure, void *closure_data)
{
	const ProtobufCMethodDescriptor *method =
		&unpriv_access__descriptor.methods[method_index];

	(void)service;

	/* The probe of STARTDTLS, in the clear whatever comes after it */
	if (!strcmp(method->name, ESDM_RPC_PROTO_STARTDTLS_PROBE)) {
		test_answer_empty(method, closure, closure_data);
		return;
	}

	test_count(closure_data);

	if (!strcmp(method->name, "RpcGetRandomBytes") ||
	    !strcmp(method->name, "RpcGetRandomBytesFull") ||
	    !strcmp(method->name, "RpcGetRandomBytesPr")) {
		const GetRandomBytesRequest *req =
			(const GetRandomBytesRequest *)input;
		RandValResponse resp = RAND_VAL_RESPONSE__INIT;
		size_t len = req->len < sizeof(test_pattern) ?
				     (size_t)req->len :
				     sizeof(test_pattern);

		if (test_encrypted_only &&
		    !esdm_rpcs_fuzz_conn_encrypted(closure_data)) {
			resp.ret = -EPERM;
			closure((const ProtobufCMessage *)&resp, closure_data);
			return;
		}

		resp.ret = (int64_t)len;
		resp.randval.data = test_pattern;
		resp.randval.len = len;
		closure((const ProtobufCMessage *)&resp, closure_data);
		return;
	}

	if (!strcmp(method->name, "RpcWriteData")) {
		const WriteDataRequest *req = (const WriteDataRequest *)input;
		RetResponse resp = RET_RESPONSE__INIT;

		test_record(req->data.data, req->data.len);
		closure((const ProtobufCMessage *)&resp, closure_data);
		return;
	}

	test_answer_empty(method, closure, closure_data);
}

static void test_priv_invoke(ProtobufCService *service,
			     unsigned int method_index,
			     const ProtobufCMessage *input,
			     ProtobufCClosure closure, void *closure_data)
{
	const ProtobufCMethodDescriptor *method =
		&priv_access__descriptor.methods[method_index];

	(void)service;

	if (!strcmp(method->name, "RpcRndAddEntropy")) {
		const RndAddEntropyRequest *req =
			(const RndAddEntropyRequest *)input;
		RetResponse resp = RET_RESPONSE__INIT;

		/* The probe of STARTDTLS, refused as the ESDM does */
		if (!req->randval.data) {
			resp.ret = -EFAULT;
			closure((const ProtobufCMessage *)&resp, closure_data);
			return;
		}

		test_record(req->randval.data, req->randval.len);
	}

	test_count(closure_data);
	test_answer_empty(method, closure, closure_data);
}

static ProtobufCService test_priv_service = {
	.descriptor = &priv_access__descriptor,
	.invoke = test_priv_invoke,
	.destroy = NULL,
};

static ProtobufCService test_unpriv_service = {
	.descriptor = &unpriv_access__descriptor,
	.invoke = test_unpriv_invoke,
	.destroy = NULL,
};

static void *test_serve_priv(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(test_priv_path, &test_priv_service, true);
	if (ret) {
		fprintf(stderr, "the privileged server did not run: %s\n",
			strerror(-ret));
		atomic_store(&test_serve_failed, true);
	}

	return NULL;
}

static void *test_serve_unpriv(void *unused)
{
	int ret;

	(void)unused;

	ret = esdm_rpcs_fuzz_serve(test_unpriv_path, &test_unpriv_service,
				   false);
	if (ret) {
		fprintf(stderr, "the unprivileged server did not run: %s\n",
			strerror(-ret));
		atomic_store(&test_serve_failed, true);
	}

	return NULL;
}

static bool test_wait_for_socket(const char *path)
{
	unsigned int i;
	struct stat sb;

	for (i = 0; i < 500; i++) {
		if (atomic_load(&test_serve_failed))
			return false;
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(10);
	}

	return false;
}

static int test_connect(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

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

/*
 * Is the peer on @fd this process, or a child of it? The sockets the client
 * connects to are fixed at build time, and a test of another build may try
 * them: its connections are not counted, nor served.
 */
static bool test_peer_ours(int fd)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	char path[64], line[256];
	bool ours = false;
	FILE *status;

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len))
		return false;
	if (cred.pid == getpid())
		return true;

	snprintf(path, sizeof(path), "/proc/%d/status", (int)cred.pid);
	status = fopen(path, "r");
	if (!status)
		return false;
	while (fgets(line, sizeof(line), status)) {
		int ppid;

		if (sscanf(line, "PPid: %d", &ppid) == 1) {
			ours = ppid == (int)getpid();
			break;
		}
	}
	fclose(status);

	return ours;
}

/* Listen on @path, one of the sockets the client connects to */
static int test_listen(const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = test_connect(path);

	if (fd >= 0) {
		close(fd);
		return -EADDRINUSE;
	}

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	unlink(path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(fd, 64)) {
		int errsv = errno;

		close(fd);
		return -errsv;
	}

	return fd;
}

/******************************************************************************
 * The relay between the client and the server, looking at every message
 ******************************************************************************/

#define TEST_RELAY_PAIRS 16

static int test_relay_listen[2] = { -1, -1 };
static const char *test_relay_target[2];
static pthread_t test_relay_thread;
static atomic_bool test_relay_stop;

static atomic_uint test_relay_conns;
static atomic_uint test_relay_startdtls;
static atomic_uint test_relay_records;
static atomic_bool test_relay_saw_plaintext;

/* Does @buf hold a piece of the data the test sends or receives? */
static bool test_has_plaintext(const uint8_t *buf, size_t len)
{
	static const size_t offsets[] = { 0, 4096, 32768, 65000 };
	size_t i;

	for (i = 0; i < ARRAY_SIZE(offsets); i++) {
		if (memmem(buf, len, test_pattern + offsets[i], 16) ||
		    memmem(buf, len, test_wpattern + offsets[i], 16))
			return true;
	}

	return false;
}

static void test_relay_inspect(const uint8_t *buf, size_t len)
{
	uint32_t method_index;

	if (len >= sizeof(method_index)) {
		memcpy(&method_index, buf, sizeof(method_index));
		if (le_bswap32(method_index) == ESDM_RPC_PROTO_STARTDTLS)
			atomic_fetch_add(&test_relay_startdtls, 1);
	}

	/* Application data of DTLS 1.2 */
	if (len >= 3 && buf[0] == 23 && buf[1] == 0xfe && buf[2] == 0xfd)
		atomic_fetch_add(&test_relay_records, 1);

	if (test_has_plaintext(buf, len))
		atomic_store(&test_relay_saw_plaintext, true);
}

static void *test_relay_run(void *unused)
{
	static uint8_t buf[ESDM_RPC_MAX_MSG_SIZE + 1024];
	struct pollfd pfd[2 + 2 * TEST_RELAY_PAIRS];
	nfds_t nfds = 2, i;

	(void)unused;

	pfd[0] =
		(struct pollfd){ .fd = test_relay_listen[0], .events = POLLIN };
	pfd[1] =
		(struct pollfd){ .fd = test_relay_listen[1], .events = POLLIN };

	while (!atomic_load(&test_relay_stop)) {
		if (poll(pfd, nfds, 50) <= 0)
			continue;

		/* The connections come in pairs: client, server */
		for (i = 2; i < nfds; i += 2) {
			bool gone = false;
			nfds_t side;

			for (side = 0; side < 2 && !gone; side++) {
				struct pollfd *from = &pfd[i + side];
				struct pollfd *to = &pfd[i + !side];
				ssize_t n;

				if (!from->revents)
					continue;
				n = recv(from->fd, buf, sizeof(buf),
					 MSG_DONTWAIT);
				if (n < 0 && errno == EAGAIN)
					continue;
				if (n <= 0) {
					gone = true;
					break;
				}
				test_relay_inspect(buf, (size_t)n);
				if (send(to->fd, buf, (size_t)n,
					 MSG_NOSIGNAL) != n)
					gone = true;
			}

			if (gone) {
				close(pfd[i].fd);
				close(pfd[i + 1].fd);
				pfd[i] = pfd[nfds - 2];
				pfd[i + 1] = pfd[nfds - 1];
				nfds -= 2;
				i -= 2;
			}
		}

		for (i = 0; i < 2; i++) {
			int client, server;

			if (!(pfd[i].revents & POLLIN) ||
			    nfds >= ARRAY_SIZE(pfd))
				continue;

			client = accept4(pfd[i].fd, NULL, NULL, SOCK_CLOEXEC);
			if (client < 0)
				continue;
			if (!test_peer_ours(client)) {
				close(client);
				continue;
			}
			server = test_connect(test_relay_target[i]);
			if (server < 0) {
				close(client);
				continue;
			}

			atomic_fetch_add(&test_relay_conns, 1);
			pfd[nfds++] = (struct pollfd){ .fd = client,
						       .events = POLLIN };
			pfd[nfds++] = (struct pollfd){ .fd = server,
						       .events = POLLIN };
		}
	}

	for (i = 2; i < nfds; i++)
		close(pfd[i].fd);

	return NULL;
}

static int test_relay_start(void)
{
	test_relay_target[0] = test_unpriv_path;
	test_relay_target[1] = test_priv_path;

	test_relay_listen[0] = test_listen(ESDM_RPC_UNPRIV_SOCKET);
	if (test_relay_listen[0] < 0)
		return test_relay_listen[0];
	test_relay_listen[1] = test_listen(ESDM_RPC_PRIV_SOCKET);
	if (test_relay_listen[1] < 0) {
		close(test_relay_listen[0]);
		unlink(ESDM_RPC_UNPRIV_SOCKET);
		return test_relay_listen[1];
	}

	atomic_store(&test_relay_stop, false);
	return -pthread_create(&test_relay_thread, NULL, test_relay_run, NULL);
}

static void test_relay_finish(void)
{
	atomic_store(&test_relay_stop, true);
	pthread_join(test_relay_thread, NULL);
	close(test_relay_listen[0]);
	close(test_relay_listen[1]);
	unlink(ESDM_RPC_UNPRIV_SOCKET);
	unlink(ESDM_RPC_PRIV_SOCKET);
}

static void test_relay_reset(void)
{
	atomic_store(&test_relay_conns, 0);
	atomic_store(&test_relay_startdtls, 0);
	atomic_store(&test_relay_records, 0);
	atomic_store(&test_relay_saw_plaintext, false);
	atomic_store(&test_calls_encrypted, 0);
	atomic_store(&test_calls_clear, 0);
}

/******************************************************************************
 * The client
 ******************************************************************************/

/* Connections the client starts afresh with, nothing remembered */
static void test_client_start(void)
{
	CHECK_EQ(esdm_rpcc_init_unpriv_service(NULL), 0);
	CHECK_EQ(esdm_rpcc_init_priv_service(NULL), 0);
}

static void test_client_stop(void)
{
	esdm_rpcc_force_fini_unpriv_service();
	esdm_rpcc_force_fini_priv_service();
}

/* Is the connection of the unprivileged (or privileged) service encrypted? */
static bool test_client_encrypted(bool privileged)
{
	esdm_rpc_client_connection_t *rpc_conn = NULL;
	bool ret;

	if (privileged ? esdm_rpcc_get_priv_service(&rpc_conn, NULL) :
			 esdm_rpcc_get_unpriv_service(&rpc_conn, NULL))
		return false;
	ret = rpc_conn->dtls != NULL;
	if (privileged)
		esdm_rpcc_put_priv_service(rpc_conn);
	else
		esdm_rpcc_put_unpriv_service(rpc_conn);

	return ret;
}

/* The largest calls of both interfaces, each checked for what it carried */
static void test_calls(void)
{
	static uint8_t buf[ESDM_RPC_MAX_DATA];
	bool written;

	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	CHECK_MEM_EQ(buf, test_pattern, sizeof(buf));

	CHECK_EQ(esdm_rpcc_write_data(test_wpattern, sizeof(test_wpattern)), 0);
	pthread_mutex_lock(&test_written_lock);
	written = test_written_len == sizeof(test_wpattern) &&
		  !memcmp(test_written, test_wpattern, sizeof(test_wpattern));
	pthread_mutex_unlock(&test_written_lock);
	CHECK(written, "the server did not get the data written");

	CHECK_EQ(esdm_rpcc_rnd_add_entropy(test_wpattern, TEST_PRIV_LEN, 0), 0);
	pthread_mutex_lock(&test_written_lock);
	written = test_written_len == TEST_PRIV_LEN &&
		  !memcmp(test_written, test_wpattern, TEST_PRIV_LEN);
	pthread_mutex_unlock(&test_written_lock);
	CHECK(written, "the server did not get the entropy added");
}

/******************************************************************************
 * The tests
 ******************************************************************************/

/*
 * Encrypted where both sides have DTLS - which they do unless it is not built -
 * and in the clear where the server refuses it: the calls work either way, and
 * the relay sees their data only in the clear.
 */
static void test_eavesdrop(bool server_dtls)
{
	bool dtls = server_dtls;

#ifndef ESDM_DTLS
	dtls = false;
#endif

	printf("Calls through an eavesdropping relay, %s\n",
	       server_dtls ? "server offering DTLS" : "server refusing DTLS");

	esdm_rpc_server_set_dtls(server_dtls);
	test_relay_reset();
	test_client_start();

	test_calls();

	CHECK_EQ(test_client_encrypted(false), dtls);
	CHECK_EQ(test_client_encrypted(true), dtls);
	/* One connection per interface: a refusal keeps the connection */
	CHECK_EQ(atomic_load(&test_relay_conns), 2);
	CHECK_EQ(atomic_load(&test_calls_encrypted), dtls ? 3 : 0);
	CHECK_EQ(atomic_load(&test_calls_clear), dtls ? 0 : 3);
#ifdef ESDM_DTLS
	CHECK_EQ(atomic_load(&test_relay_startdtls), 2);
#else
	CHECK_EQ(atomic_load(&test_relay_startdtls), 0);
#endif

	if (dtls) {
		CHECK(!atomic_load(&test_relay_saw_plaintext),
		      "the data can be read off the connection");
		/*
		 * The largest answer and the largest request take 5 records
		 * each, the privileged request 3, and every other one 1
		 */
		CHECK(atomic_load(&test_relay_records) >= 16,
		      "%u DTLS records only", atomic_load(&test_relay_records));
	} else {
		CHECK(atomic_load(&test_relay_saw_plaintext),
		      "the relay does not see the data in the clear");
		CHECK_EQ(atomic_load(&test_relay_records), 0);
	}

	test_client_stop();
	esdm_rpc_server_set_dtls(true);
}

/*
 * A forked child sets up a connection of its own, and leaves the one of its
 * parent in place: the parent goes on with it, encrypted, without a new
 * connection.
 */
static void test_fork(void)
{
	uint8_t buf[64];
	unsigned int conns;
	pid_t pid;
	int status;

	printf("A forked child and its parent\n");

	test_relay_reset();
	test_client_start();

	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	conns = atomic_load(&test_relay_conns);
	CHECK_EQ(conns, 1);

	fflush(stdout);
	fflush(stderr);
	pid = fork();
	CHECK(pid >= 0, "cannot fork: %s", strerror(errno));
	if (pid < 0)
		return;
	if (!pid) {
		bool ok = !test_client_encrypted(false);

		/* The parent's connection is gone here, a new one comes */
		ok = ok && esdm_rpcc_get_random_bytes(buf, sizeof(buf)) ==
				   (ssize_t)sizeof(buf);
		ok = ok && !memcmp(buf, test_pattern, sizeof(buf));
#ifdef ESDM_DTLS
		ok = ok && test_client_encrypted(false);
#endif
		_exit(ok ? 0 : 1);
	}

	CHECK(waitpid(pid, &status, 0) == pid, "cannot wait for the child");
	CHECK(WIFEXITED(status) && !WEXITSTATUS(status),
	      "the child could not use a connection of its own");
	CHECK_EQ(atomic_load(&test_relay_conns), conns + 1);

	/* The parent's connection is still there, and still works */
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	CHECK_MEM_EQ(buf, test_pattern, sizeof(buf));
	CHECK_EQ(atomic_load(&test_relay_conns), conns + 1);
#ifdef ESDM_DTLS
	CHECK(test_client_encrypted(false), "the parent lost its DTLS");
	CHECK(!atomic_load(&test_relay_saw_plaintext),
	      "the data can be read off the connection");
#endif

	test_client_stop();
}

/* Send a request of @method_index with the GetRandomBytesRequest of @len */
static bool test_raw_request(int fd, uint32_t method_index, uint64_t len)
{
	GetRandomBytesRequest req = GET_RANDOM_BYTES_REQUEST__INIT;
	uint8_t msg[sizeof(struct esdm_rpc_proto_cs_header) + 16];
	struct esdm_rpc_proto_cs_header cs;
	size_t packed;

	req.len = len;
	packed = get_random_bytes_request__pack(&req, msg + sizeof(cs));

	cs.method_index = le_bswap32(method_index);
	cs.message_length = le_bswap32((uint32_t)packed);
	cs.request_id = 0;
	memcpy(msg, &cs, sizeof(cs));

	return send(fd, msg, sizeof(cs) + packed, MSG_NOSIGNAL) ==
	       (ssize_t)(sizeof(cs) + packed);
}

/* Receive an answer in the clear into @buf, waiting for @timeout_ms */
static ssize_t test_raw_answer(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return -ETIMEDOUT;

	return recv(fd, buf, len, MSG_DONTWAIT);
}

static uint32_t test_method(const ProtobufCServiceDescriptor *desc,
			    const char *name)
{
	const ProtobufCMethodDescriptor *method =
		protobuf_c_service_descriptor_get_method_by_name(desc, name);

	return (uint32_t)(method - desc->methods);
}

/*
 * A client not knowing STARTDTLS is served in the clear - and so is one whose
 * STARTDTLS a server refuses, on the same connection.
 */
static void test_old_client(void)
{
	uint8_t buf[256];
	struct esdm_rpc_proto_sc_header sc;
	RandValResponse *resp;
	ssize_t n;
	int fd;

	printf("A client not asking for DTLS\n");

	test_relay_reset();
	fd = test_connect(test_unpriv_path);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;

	CHECK(test_raw_request(fd,
			       test_method(&unpriv_access__descriptor,
					   "RpcGetRandomBytes"),
			       64),
	      "cannot send the request");
	n = test_raw_answer(fd, buf, sizeof(buf), 5000);
	CHECK(n > (ssize_t)sizeof(sc), "no answer: %zd", n);
	if (n > (ssize_t)sizeof(sc)) {
		memcpy(&sc, buf, sizeof(sc));
		CHECK_EQ(le_bswap32(sc.status_code),
			 PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
		resp = rand_val_response__unpack(NULL, (size_t)n - sizeof(sc),
						 buf + sizeof(sc));
		CHECK(resp && resp->randval.len == 64 &&
			      !memcmp(resp->randval.data, test_pattern, 64),
		      "not the bytes of the server");
		if (resp)
			rand_val_response__free_unpacked(resp, NULL);
	}
	CHECK_EQ(atomic_load(&test_calls_clear), 1);

	close(fd);

#ifndef ESDM_DTLS
	/* A server without DTLS refuses STARTDTLS, and goes on in the clear */
	printf("STARTDTLS to a server without DTLS\n");
	fd = test_connect(test_priv_path);
	CHECK(fd >= 0, "cannot connect: %s", strerror(-fd));
	if (fd < 0)
		return;
	CHECK(test_raw_request(fd, ESDM_RPC_PROTO_STARTDTLS, 0),
	      "cannot send STARTDTLS");
	n = test_raw_answer(fd, buf, sizeof(buf), 5000);
	CHECK_EQ(n, sizeof(sc));
#endif
}

#ifdef ESDM_DTLS
/*
 * Ask for DTLS on a new connection to the unprivileged interface, as far as
 * the answers to STARTDTLS and its probe: the server waits for the client's
 * hello then - if it agreed, which @accepted tells.
 */
static int test_raw_startdtls_answer(bool *accepted)
{
	uint8_t buf[64];
	struct esdm_rpc_proto_sc_header sc;
	int fd = test_connect(test_unpriv_path);
	ssize_t n;

	*accepted = false;
	if (fd < 0)
		return fd;

	/* An empty GetRandomBytesRequest is a header alone, as STARTDTLS is */
	if (!test_raw_request(fd, ESDM_RPC_PROTO_STARTDTLS, 0) ||
	    !test_raw_request(fd,
			      test_method(&unpriv_access__descriptor,
					  ESDM_RPC_PROTO_STARTDTLS_PROBE),
			      0)) {
		close(fd);
		return -EIO;
	}

	n = test_raw_answer(fd, buf, sizeof(buf), 5000);
	CHECK(n >= (ssize_t)sizeof(sc), "STARTDTLS was not answered");
	if (n >= (ssize_t)sizeof(sc)) {
		memcpy(&sc, buf, sizeof(sc));
		*accepted = n == sizeof(sc) + 4 &&
			    le_bswap32(sc.status_code) ==
				    PROTOBUF_C_RPC_STATUS_CODE_SUCCESS;
	}
	n = test_raw_answer(fd, buf, sizeof(buf), 5000);
	CHECK(n >= (ssize_t)sizeof(sc), "the probe was not answered");

	return fd;
}

/* As test_raw_startdtls_answer(), the server agreeing */
static int test_raw_startdtls(void)
{
	bool accepted;
	int fd = test_raw_startdtls_answer(&accepted);

	CHECK(fd < 0 || accepted, "STARTDTLS refused");

	return fd;
}

/* A connection encrypted by the test itself, -errno if it cannot be */
static int test_raw_dtls(struct esdm_dtls_ctx *ctx, struct esdm_dtls **dtls,
			 bool *accepted)
{
	int fd = test_raw_startdtls_answer(accepted);
	int ret;

	*dtls = NULL;
	if (fd < 0 || !*accepted)
		return fd;

	ret = set_fd_nonblocking(fd);
	if (!ret)
		ret = esdm_dtls_alloc(ctx, fd, ESDM_RPC_MAX_MSG_SIZE, dtls);
	while (!ret) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		ret = esdm_dtls_handshake(*dtls);
		if (ret != -EAGAIN)
			break;
		ret = poll(&pfd, 1, 5000) > 0 ? 0 : -ETIMEDOUT;
	}
	if (ret) {
		esdm_dtls_free(*dtls);
		*dtls = NULL;
		close(fd);
		return ret;
	}

	return fd;
}
#endif

/*
 * An unprivileged user gets so many encrypted connections, and those beyond
 * are refused DTLS - served in the clear - until one of them is closed. Root
 * is exempt.
 */
static void test_dtls_bound(void)
{
#ifdef ESDM_DTLS
#define TEST_DTLS_BOUND 64
	static struct esdm_dtls *dtls[TEST_DTLS_BOUND + 1];
	static int fds[TEST_DTLS_BOUND + 1];
	struct esdm_dtls_ctx *ctx = NULL;
	uint8_t buf[64];
	bool accepted;
	unsigned int i;

	if (!getuid()) {
		printf("Encrypted connections of one user - skipped as root\n");
		return;
	}

	printf("Encrypted connections of one user\n");

	CHECK_EQ(esdm_dtls_ctx_alloc(false, &ctx), 0);
	if (!ctx)
		return;

	for (i = 0; i < TEST_DTLS_BOUND; i++) {
		fds[i] = test_raw_dtls(ctx, &dtls[i], &accepted);
		CHECK(fds[i] >= 0 && accepted && dtls[i],
		      "connection %u not encrypted: %d", i, fds[i]);
	}

	/* Beyond the bound: refused, and used in the clear */
	fds[i] = test_raw_dtls(ctx, &dtls[i], &accepted);
	CHECK(fds[i] >= 0 && !accepted, "connection %u encrypted", i);
	if (fds[i] >= 0) {
		CHECK(test_raw_request(fds[i],
				       test_method(&unpriv_access__descriptor,
						   "RpcGetRandomBytes"),
				       16),
		      "cannot send in the clear");
		CHECK(test_raw_answer(fds[i], buf, sizeof(buf), 5000) > 0,
		      "not served in the clear");
		esdm_dtls_free(dtls[i]);
		close(fds[i]);
	}

	/* One closed, the next one is encrypted again */
	esdm_dtls_free(dtls[0]);
	if (fds[0] >= 0)
		close(fds[0]);
	test_sleep_ms(100);
	fds[0] = test_raw_dtls(ctx, &dtls[0], &accepted);
	CHECK(fds[0] >= 0 && accepted && dtls[0],
	      "not encrypted after a close: %d", fds[0]);

	for (i = 0; i < TEST_DTLS_BOUND; i++) {
		esdm_dtls_free(dtls[i]);
		if (fds[i] >= 0)
			close(fds[i]);
	}
	esdm_dtls_ctx_free(ctx);
#endif
}

/*
 * A client stalling its handshake holds up nobody, and is closed as idle; one
 * sending garbage instead of a hello is closed right away.
 */
static void test_bad_handshakes(void)
{
#ifdef ESDM_DTLS
	uint8_t buf[64];
	uint64_t start;
	int stalled, garbage;
	ssize_t n;

	printf("Handshakes stalled and broken\n");

	stalled = test_raw_startdtls();
	CHECK(stalled >= 0, "cannot start a handshake: %s", strerror(-stalled));
	garbage = test_raw_startdtls();
	CHECK(garbage >= 0, "cannot start a handshake: %s", strerror(-garbage));
	if (stalled < 0 || garbage < 0)
		return;

	CHECK(send(garbage, "hello?", 6, MSG_NOSIGNAL) == 6,
	      "cannot send the garbage");
	n = test_raw_answer(garbage, buf, sizeof(buf), 5000);
	CHECK_EQ(n, 0);
	close(garbage);

	/* Served all the same, encrypted */
	test_relay_reset();
	test_client_start();
	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	CHECK(test_client_encrypted(false), "not encrypted");
	test_client_stop();

	/* Reaped as idle within two rounds of the idle timer */
	start = test_now_ms();
	n = test_raw_answer(stalled, buf, sizeof(buf), 3 * TEST_IDLE_MS);
	CHECK_EQ(n, 0);
	CHECK(test_now_ms() - start < 3 * TEST_IDLE_MS,
	      "the stalled handshake was not closed");
	close(stalled);
#endif
}

/******************************************************************************
 * A server not knowing STARTDTLS, as ESDM 1.2.3 and before
 ******************************************************************************/

enum test_old_mode {
	/* It closes the connection on a method it does not know */
	test_old_close,
	/* It leaves the request unanswered, keeping the connection */
	test_old_silent,
};

#ifdef ESDM_DTLS
static int test_old_listen[2] = { -1, -1 };
static _Atomic enum test_old_mode test_old_mode;
static atomic_bool test_old_stop;
static atomic_uint test_old_conns;
static atomic_uint test_old_startdtls;

/* Serve one message on @fd as an old server; false when it closes */
static bool test_old_serve(int fd, bool privileged)
{
	const ProtobufCServiceDescriptor *desc =
		privileged ? &priv_access__descriptor :
			     &unpriv_access__descriptor;
	uint8_t req[ESDM_RPC_MAX_MSG_SIZE];
	uint8_t resp[sizeof(struct esdm_rpc_proto_sc_header) + 128];
	struct esdm_rpc_proto_cs_header cs;
	struct esdm_rpc_proto_sc_header sc;
	size_t msglen = 0;
	ssize_t n;

	n = recv(fd, req, sizeof(req), 0);
	if (n < (ssize_t)sizeof(cs))
		return false;
	memcpy(&cs, req, sizeof(cs));
	cs.method_index = le_bswap32(cs.method_index);

	if (cs.method_index >= desc->n_methods) {
		if (cs.method_index == ESDM_RPC_PROTO_STARTDTLS)
			atomic_fetch_add(&test_old_startdtls, 1);
		return atomic_load(&test_old_mode) == test_old_silent;
	}

	if (!privileged &&
	    !strcmp(desc->methods[cs.method_index].name, "RpcGetRandomBytes")) {
		GetRandomBytesRequest *r = get_random_bytes_request__unpack(
			NULL, (size_t)n - sizeof(cs), req + sizeof(cs));
		RandValResponse rv = RAND_VAL_RESPONSE__INIT;
		size_t len = r && r->len < 64 ? (size_t)r->len : 64;

		if (r)
			get_random_bytes_request__free_unpacked(r, NULL);
		rv.ret = (int64_t)len;
		rv.randval.data = test_pattern;
		rv.randval.len = len;
		msglen = rand_val_response__pack(&rv, resp + sizeof(sc));
	}

	/* Anything else: the answer of all fields zero, an empty message */
	sc.status_code = le_bswap32(PROTOBUF_C_RPC_STATUS_CODE_SUCCESS);
	sc.method_index = le_bswap32(cs.method_index);
	sc.message_length = le_bswap32((uint32_t)msglen);
	sc.request_id = cs.request_id;
	memcpy(resp, &sc, sizeof(sc));

	return send(fd, resp, sizeof(sc) + msglen, MSG_NOSIGNAL) ==
	       (ssize_t)(sizeof(sc) + msglen);
}

static void *test_old_run(void *unused)
{
	struct pollfd pfd[2 + TEST_RELAY_PAIRS];
	bool privileged[2 + TEST_RELAY_PAIRS] = { false, true };
	nfds_t nfds = 2, i;

	(void)unused;

	pfd[0] = (struct pollfd){ .fd = test_old_listen[0], .events = POLLIN };
	pfd[1] = (struct pollfd){ .fd = test_old_listen[1], .events = POLLIN };

	while (!atomic_load(&test_old_stop)) {
		if (poll(pfd, nfds, 50) <= 0)
			continue;

		for (i = 2; i < nfds; i++) {
			if (!pfd[i].revents)
				continue;
			if ((pfd[i].revents & POLLIN) &&
			    test_old_serve(pfd[i].fd, privileged[i]))
				continue;
			close(pfd[i].fd);
			pfd[i] = pfd[nfds - 1];
			privileged[i] = privileged[nfds - 1];
			nfds--;
			i--;
		}

		for (i = 0; i < 2; i++) {
			int fd;

			if (!(pfd[i].revents & POLLIN) ||
			    nfds >= ARRAY_SIZE(pfd))
				continue;
			fd = accept4(pfd[i].fd, NULL, NULL, SOCK_CLOEXEC);
			if (fd < 0)
				continue;
			if (!test_peer_ours(fd)) {
				close(fd);
				continue;
			}
			atomic_fetch_add(&test_old_conns, 1);
			privileged[nfds] = i;
			pfd[nfds++] =
				(struct pollfd){ .fd = fd, .events = POLLIN };
		}
	}

	for (i = 2; i < nfds; i++)
		close(pfd[i].fd);

	return NULL;
}

#endif /* ESDM_DTLS */

/*
 * The client against an old server: served in the clear, at once - also by a
 * server leaving STARTDTLS unanswered, as ESDM 1.2.3 mostly does. A new
 * connection does not ask again for a while.
 */
static void test_old_server(enum test_old_mode mode)
{
#ifdef ESDM_DTLS
	static const uint8_t data[32];
	uint8_t buf[64];
	uint64_t start, took;
	pthread_t thread;

	printf("An old server %s\n",
	       mode == test_old_close ? "closing the connection on STARTDTLS" :
					"leaving STARTDTLS unanswered");

	test_old_listen[0] = test_listen(ESDM_RPC_UNPRIV_SOCKET);
	test_old_listen[1] = test_listen(ESDM_RPC_PRIV_SOCKET);
	CHECK(test_old_listen[0] >= 0 && test_old_listen[1] >= 0,
	      "cannot listen as the old server");
	if (test_old_listen[0] < 0 || test_old_listen[1] < 0)
		goto out;

	atomic_store(&test_old_mode, mode);
	atomic_store(&test_old_stop, false);
	atomic_store(&test_old_conns, 0);
	atomic_store(&test_old_startdtls, 0);
	if (pthread_create(&thread, NULL, test_old_run, NULL)) {
		CHECK(0, "cannot start the old server");
		goto out;
	}

	test_client_start();

	start = test_now_ms();
	memset(buf, 0, sizeof(buf));
	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	took = test_now_ms() - start;
	CHECK_MEM_EQ(buf, test_pattern, sizeof(buf));
	CHECK(took < 500, "the call took %llu ms", (unsigned long long)took);
	CHECK(!test_client_encrypted(false), "encrypted with an old server?");
	CHECK_EQ(atomic_load(&test_old_startdtls), 1);
	/* Closed on STARTDTLS, the client connects again */
	CHECK_EQ(atomic_load(&test_old_conns), mode == test_old_close ? 2 : 1);

	/* A new connection, once the old one is idle, does not ask again */
	test_sleep_ms(TEST_IDLE_MS / 2 + 100);
	CHECK_EQ(esdm_rpcc_get_random_bytes(buf, sizeof(buf)),
		 (ssize_t)sizeof(buf));
	CHECK_EQ(atomic_load(&test_old_startdtls), 1);
	CHECK_EQ(atomic_load(&test_old_conns), mode == test_old_close ? 3 : 2);

	/* And so the privileged interface */
	start = test_now_ms();
	CHECK_EQ(esdm_rpcc_rnd_add_entropy(data, sizeof(data), 0), 0);
	took = test_now_ms() - start;
	CHECK_EQ(atomic_load(&test_old_startdtls), 2);
	CHECK(took < 500, "the call took %llu ms", (unsigned long long)took);

	test_client_stop();

	atomic_store(&test_old_stop, true);
	pthread_join(thread, NULL);

out:
	if (test_old_listen[0] >= 0) {
		close(test_old_listen[0]);
		unlink(ESDM_RPC_UNPRIV_SOCKET);
	}
	if (test_old_listen[1] >= 0) {
		close(test_old_listen[1]);
		unlink(ESDM_RPC_PRIV_SOCKET);
	}
	test_old_listen[0] = test_old_listen[1] = -1;
#else
	(void)mode;
#endif
}

/*
 * Serve the stand-in services on the sockets the client connects to, until
 * SIGTERM.
 */
static int test_serve(void)
{
	pthread_t priv_thread, unpriv_thread;
	sigset_t set;
	int sig;

	snprintf(test_priv_path, sizeof(test_priv_path), "%s",
		 ESDM_RPC_PRIV_SOCKET);
	snprintf(test_unpriv_path, sizeof(test_unpriv_path), "%s",
		 ESDM_RPC_UNPRIV_SOCKET);
	test_encrypted_only = true;
	/* Opt-in, as with esdm-server --dtls */
	esdm_rpc_server_set_dtls(true);

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	if (thread_init(1) ||
	    pthread_create(&priv_thread, NULL, test_serve_priv, NULL) ||
	    pthread_create(&unpriv_thread, NULL, test_serve_unpriv, NULL)) {
		fprintf(stderr, "cannot start the server threads\n");
		return 1;
	}

	sigwait(&set, &sig);

	esdm_rpc_server_signal_exit();
	pthread_join(priv_thread, NULL);
	pthread_join(unpriv_thread, NULL);

	/* The sockets are those of a real server, see above */
	unlink(ESDM_RPC_PRIV_SOCKET);
	unlink(ESDM_RPC_UNPRIV_SOCKET);

	return atomic_load(&test_serve_failed) ? 1 : 0;
}

int main(int argc, char *argv[])
{
	pthread_t priv_thread, unpriv_thread;
	int ret;

	esdm_logger_set_verbosity(getenv("ESDM_TEST_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	test_fill(test_pattern, sizeof(test_pattern), 0x9e3779b97f4a7c15ULL);
	test_fill(test_wpattern, sizeof(test_wpattern), 0xc2b2ae3d27d4eb4fULL);

	if (argc > 1 && !strcmp(argv[1], "serve"))
		return test_serve();

	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(test_priv_path, sizeof(test_priv_path), "%s/priv", test_dir);
	snprintf(test_unpriv_path, sizeof(test_unpriv_path), "%s/unpriv",
		 test_dir);

	if (thread_init(1)) {
		fprintf(stderr, "cannot initialize threading support\n");
		return 1;
	}

	/* One connection per interface, which the counts above rely on */
	esdm_rpcc_set_max_online_nodes(1);

	if (pthread_create(&priv_thread, NULL, test_serve_priv, NULL) ||
	    pthread_create(&unpriv_thread, NULL, test_serve_unpriv, NULL)) {
		fprintf(stderr, "cannot start the server threads\n");
		return 1;
	}

	if (!test_wait_for_socket(test_priv_path) ||
	    !test_wait_for_socket(test_unpriv_path)) {
		fprintf(stderr, "the server did not come up\n");
		return 1;
	}

	ret = test_relay_start();
	if (ret) {
		/* The sockets the client connects to belong to somebody else */
		printf("Cannot listen on the RPC sockets: %s - skipping\n",
		       strerror(-ret));
		esdm_rpc_server_signal_exit();
		pthread_join(priv_thread, NULL);
		pthread_join(unpriv_thread, NULL);
		return 77;
	}

	test_eavesdrop(true);
	test_eavesdrop(false);
	test_fork();
	test_old_client();
	test_bad_handshakes();
	test_dtls_bound();

	test_relay_finish();

	test_old_server(test_old_close);
	test_old_server(test_old_silent);

	esdm_rpc_server_signal_exit();
	pthread_join(priv_thread, NULL);
	pthread_join(unpriv_thread, NULL);

	unlink(test_priv_path);
	unlink(test_unpriv_path);
	rmdir(test_dir);

	if (!common_test_failures)
		printf("PASS\n");

	return common_test_failures ? 1 : 0;
}
