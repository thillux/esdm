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
 * Throughput of the ways to the random numbers of the ESDM, for comparison:
 * the EGD socket of the esdm-server - by the client library and in raw
 * protocol bytes, one command at a time and pipelined -, the unprivileged RPC
 * interface, and the EGD protocol on the network - by the client library
 * directly to the esdm-egd-net-server, and through the esdm-egd-net-relay -,
 * in plain TCP and in TLS. Each in requests of the sizes a consumer asks for.
 *
 * Informational: it measures, it does not judge. Every figure is the median
 * of several runs of a fixed time, next to the slowest and the fastest one -
 * the machine it runs on may be busy with anything else.
 *
 * Like the end to end test next to it, this starts an esdm-server, which
 * takes root, and runs in namespaces of its own. Registered as a benchmark:
 * meson test --benchmark, or run it with the paths of the daemons in
 * ESDM_SERVER, ESDM_EGD_NET_SERVER and ESDM_EGD_NET_RELAY. Arguments select the
 * paths by a part of their name ("rpc", "tls", "relay", ...).
 */

#include "egd_net_test.h"
#include "esdm_egd_client.h"
#include "esdm_rpc_client.h"
#include "../test_namespace.h"

#include <sys/un.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* Runs per figure, and how long each one reads */
#define BENCH_RUNS 5
#define BENCH_RUN_MS 400

static const char *esdm_server_bin, *net_server_bin, *relay_bin;
static char tmpdir[] = "/tmp/esdm-egd-bench-XXXXXX";
static char egd_sock[sizeof(tmpdir) + 16];
static int bench_argc;
static char **bench_argv;

static uint64_t bench_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Is the path @name selected by the arguments? All are without any. */
static bool bench_selected(const char *name)
{
	int i;

	if (bench_argc <= 1)
		return true;
	for (i = 1; i < bench_argc; i++) {
		if (strstr(name, bench_argv[i]))
			return true;
	}
	return false;
}

/* One request of @len bytes into @buf: 0, or a negative errno */
typedef int (*bench_fn)(void *ctx, uint8_t *buf, size_t len);

static int bench_cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/*
 * Requests of @len bytes by @fn, for BENCH_RUN_MS each of BENCH_RUNS runs. The
 * median, the slowest and the fastest run in MB/s, and the requests per second
 * of the median.
 */
static void bench(const char *name, bench_fn fn, void *ctx, size_t len)
{
	double mbs[BENCH_RUNS];
	uint8_t *buf;
	unsigned int run;

	if (!bench_selected(name))
		return;

	buf = malloc(len);
	if (!buf) {
		failures++;
		return;
	}

	/* Warm up: the connections are made, the DRNG is there */
	if (fn(ctx, buf, len)) {
		printf("%-36s %7zu  failed\n", name, len);
		failures++;
		free(buf);
		return;
	}

	for (run = 0; run < BENCH_RUNS; run++) {
		uint64_t start = bench_now_ns(), end, total = 0;

		end = start + (uint64_t)BENCH_RUN_MS * 1000000ULL;
		do {
			int ret = fn(ctx, buf, len);

			if (ret) {
				printf("%-36s %7zu  failed: %s\n", name, len,
				       strerror(-ret));
				failures++;
				free(buf);
				return;
			}
			total += len;
		} while (bench_now_ns() < end);

		mbs[run] = (double)total / ((double)(bench_now_ns() - start) /
					    1e9) / 1e6;
	}

	qsort(mbs, BENCH_RUNS, sizeof(mbs[0]), bench_cmp);
	printf("%-36s %7zu  %9.2f MB/s  %9.0f req/s  (%.2f .. %.2f)\n", name,
	       len, mbs[BENCH_RUNS / 2], mbs[BENCH_RUNS / 2] * 1e6 / (double)len,
	       mbs[0], mbs[BENCH_RUNS - 1]);

	memset(buf, 0, len);
	free(buf);
}

static const size_t bench_sizes[] = { 32, 255, 4096, 65536 };

/******************************************************************************
 * The paths
 ******************************************************************************/

/* The client library, blocking reads */
static int bench_lib(void *ctx, uint8_t *buf, size_t len)
{
	return esdm_egd_client_get_random(ctx, buf, len);
}

/* The client library, the unseeded read of /dev/urandom - 255 at most */
static int bench_lib_unseeded(void *ctx, uint8_t *buf, size_t len)
{
	size_t done = 0;

	while (done < len) {
		size_t chunk = len - done, got = 0;
		int ret;

		if (chunk > ESDM_EGD_MAX_TRANSFER)
			chunk = ESDM_EGD_MAX_TRANSFER;
		ret = esdm_egd_client_get_random_unseeded(ctx, buf + done,
							  chunk, &got);
		if (ret)
			return ret;
		if (!got)
			return -EAGAIN;
		done += got;
	}
	return 0;
}

/*
 * Raw protocol bytes on the EGD socket: the unseeded read the esdm_cdev
 * module sends, as many commands at a time as @len takes - all of them sent
 * at once, the answers collected after, as the module does.
 */
static int bench_raw(void *ctx, uint8_t *buf, size_t len)
{
	int fd = *(int *)ctx;
	uint8_t req[2 * 256];
	size_t num = (len + ESDM_EGD_MAX_TRANSFER - 1) / ESDM_EGD_MAX_TRANSFER;
	size_t i, done = 0;

	if (num > sizeof(req) / 2)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		size_t chunk = len - i * ESDM_EGD_MAX_TRANSFER;

		req[2 * i] = ESDM_EGD_CMD_ESDM_READ_UNSEEDED;
		req[2 * i + 1] = (uint8_t)(chunk > ESDM_EGD_MAX_TRANSFER ?
						   ESDM_EGD_MAX_TRANSFER :
						   chunk);
	}
	if (test_send(fd, req, 2 * num))
		return -EIO;

	for (i = 0; i < num; i++) {
		uint8_t n;

		if (test_recv(fd, &n, 1) || n != req[2 * i + 1] ||
		    test_recv(fd, buf + done, n))
			return -EIO;
		done += n;
	}

	return 0;
}

/* The RPC interface */
static int bench_rpc(void *ctx, uint8_t *buf, size_t len)
{
	ssize_t ret = esdm_rpcc_get_random_bytes_full(buf, len);

	(void)ctx;
	if (ret < 0)
		return (int)ret;
	return (size_t)ret == len ? 0 : -EIO;
}

static int bench_raw_connect(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* All sizes by the library on the socket at @path */
static void bench_unix(const char *what, const char *path)
{
	struct esdm_egd_client *client = NULL;
	char name[128];
	unsigned int i;

	if (esdm_egd_client_alloc(&client, path, 30000)) {
		failures++;
		return;
	}

	snprintf(name, sizeof(name), "%s lib blocking", what);
	for (i = 0; i < ARRAY_SIZE(bench_sizes); i++)
		bench(name, bench_lib, client, bench_sizes[i]);

	snprintf(name, sizeof(name), "%s lib unseeded", what);
	for (i = 0; i < ARRAY_SIZE(bench_sizes); i++)
		bench(name, bench_lib_unseeded, client, bench_sizes[i]);

	esdm_egd_client_free(client);
}

/* The library to the network server on @port */
static void bench_net(const char *what, uint16_t port, bool plain)
{
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *client = NULL;
	char address[64], name[128];
	unsigned int i;

	snprintf(address, sizeof(address), "127.0.0.1:%u", port);
	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.address = address;
	cfg.timeout_ms = 30000;
	if (plain) {
		cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	} else {
		cfg.mode = ESDM_EGD_CLIENT_NET_TLS;
		cfg.cert_file = PKI("client1.crt");
		cfg.key_file = PKI("client1.key");
		cfg.ca_file = PKI("ca.crt");
		cfg.server_name = "localhost";
	}
	if (esdm_egd_client_alloc_net(&client, &cfg)) {
		failures++;
		return;
	}

	snprintf(name, sizeof(name), "%s lib blocking", what);
	for (i = 0; i < ARRAY_SIZE(bench_sizes); i++)
		bench(name, bench_lib, client, bench_sizes[i]);

	esdm_egd_client_free(client);
}

static pid_t start(const char *bin, const char *const *args, const int *fds,
		   int nfds)
{
	char *argv[64];
	unsigned int n = 0;

	argv[n++] = (char *)bin;
	while (args && *args && n < 63)
		argv[n++] = (char *)*args++;
	argv[n] = NULL;

	return test_daemon_start(bin, argv, fds, nfds);
}

static bool wait_socket(const char *path, unsigned int ms)
{
	uint64_t end = test_now_ms() + ms;
	struct stat sb;

	while (test_now_ms() < end) {
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(50);
	}
	return false;
}

static pid_t net_server_start(int lfd, bool plain)
{
	static const char *const tls[] = { "--username", "root",
					   "--cert",	 PKI("server.crt"),
					   "--key",	 PKI("server.key"),
					   "--ca",	 PKI("ca.crt"),
					   "--reload_interval", "0",
					   NULL };
	static const char *const plain_args[] = { "--username", "root",
						  "--plain", NULL };

	return start(net_server_bin, plain ? plain_args : tls, &lfd, 1);
}

static pid_t relay_start(const char *sock, uint16_t port, bool plain)
{
	char connect[64];
	const char *args[32];
	unsigned int n = 0;
	pid_t pid;

	snprintf(connect, sizeof(connect), "127.0.0.1:%u", port);
	args[n++] = "--username";
	args[n++] = "root";
	args[n++] = "--socket";
	args[n++] = sock;
	args[n++] = "--connect";
	args[n++] = connect;
	if (plain) {
		args[n++] = "--plain";
	} else {
		args[n++] = "--cert";
		args[n++] = PKI("client1.crt");
		args[n++] = "--key";
		args[n++] = PKI("client1.key");
		args[n++] = "--ca";
		args[n++] = PKI("ca.crt");
		args[n++] = "--server_name";
		args[n++] = "localhost";
	}
	args[n] = NULL;

	pid = start(relay_bin, args, NULL, 0);
	if (pid > 0 && !wait_socket(sock, 15000)) {
		test_daemon_stop(pid);
		return -1;
	}
	return pid;
}

/* The network server in @plain or TLS mode, directly and by the relay */
static void bench_network(bool plain)
{
	const char *mode = plain ? "plain" : "tls";
	char sock[sizeof(tmpdir) + 32], what[64];
	uint16_t port = 0;
	pid_t server, relay;
	int lfd;

#ifndef ESDM_EGD_NET_TLS
	if (!plain)
		return;
#endif

	snprintf(what, sizeof(what), "net %s", mode);
	if (!bench_selected(what)) {
		snprintf(what, sizeof(what), "relay %s", mode);
		if (!bench_selected(what))
			return;
	}

	snprintf(sock, sizeof(sock), "%s/relay-%s.sock", tmpdir, mode);
	lfd = test_listener("127.0.0.1", &port);
	server = net_server_start(lfd, plain);
	relay = relay_start(sock, port, plain);
	if (server <= 0 || relay <= 0) {
		printf("The %s daemons did not start\n", mode);
		failures++;
		goto out;
	}

	snprintf(what, sizeof(what), "net %s", mode);
	if (bench_selected(what))
		bench_net(what, port, plain);

	snprintf(what, sizeof(what), "relay %s", mode);
	if (bench_selected(what))
		bench_unix(what, sock);

out:
	if (relay > 0)
		test_daemon_stop(relay);
	if (server > 0)
		test_daemon_stop(server);
	close(lfd);
}

int main(int argc, char *argv[])
{
	static const char *const esdm_args[] = { "--pid_namespace",
						 "--egd_socket", egd_sock,
						 NULL };
	pid_t esdm_pid;
	unsigned int i;
	int fd, ret;

	setvbuf(stdout, NULL, _IOLBF, 0);
	bench_argc = argc;
	bench_argv = argv;

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#ifndef ESDM_TESTMODE
	printf("Needs testmode\n");
	return 77;
#endif

	esdm_server_bin = getenv("ESDM_SERVER");
	net_server_bin = getenv("ESDM_EGD_NET_SERVER");
	relay_bin = getenv("ESDM_EGD_NET_RELAY");
	if (test_env_check_file(esdm_server_bin) ||
	    test_env_check_file(net_server_bin) ||
	    test_env_check_file(relay_bin))
		return 1;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the namespaces: %s\n", strerror(-ret));
		return 1;
	}
	if (!mkdtemp(tmpdir))
		return 1;
	snprintf(egd_sock, sizeof(egd_sock), "%s/egd.sock", tmpdir);

	esdm_pid = start(esdm_server_bin, esdm_args, NULL, 0);
	if (esdm_pid <= 0 ||
	    !wait_socket("/tmp/esdm-rpc-unpriv-testmode.socket", 30000) ||
	    !wait_socket(egd_sock, 30000)) {
		printf("The esdm-server did not start\n");
		return 1;
	}

	printf("%-36s %7s  %14s  %15s  %s\n", "path", "bytes", "median",
	       "", "(slowest .. fastest MB/s)");

	bench_unix("egd", egd_sock);

	fd = bench_raw_connect(egd_sock);
	if (fd < 0) {
		failures++;
	} else {
		for (i = 0; i < ARRAY_SIZE(bench_sizes); i++) {
			if (bench_sizes[i] > 16 * ESDM_EGD_MAX_TRANSFER)
				continue;
			bench("egd raw unseeded pipelined", bench_raw, &fd,
			      bench_sizes[i]);
		}
		/* A batch of the module: 16 commands */
		bench("egd raw unseeded pipelined", bench_raw, &fd,
		      16 * ESDM_EGD_MAX_TRANSFER);
		close(fd);
	}

	if (bench_selected("rpc")) {
		if (esdm_rpcc_init_unpriv_service(NULL)) {
			failures++;
		} else {
			for (i = 0; i < ARRAY_SIZE(bench_sizes); i++)
				bench("rpc full", bench_rpc, NULL,
				      bench_sizes[i]);
			esdm_rpcc_fini_unpriv_service();
		}
	}

	bench_network(true);
	bench_network(false);

	test_daemon_stop(esdm_pid);
	unlink(egd_sock);
	rmdir(tmpdir);

	return failures ? 1 : 0;
}
