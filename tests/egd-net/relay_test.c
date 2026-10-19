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
 * The EGD protocol over the network end to end: an esdm-server, the
 * esdm-egd-net-server in front of it, the esdm-egd-net-relay in front of that,
 * and the EGD client library speaking every command of the protocol through
 * all of them - directly to the network server in its network modes, and to
 * the relay through its Unix domain socket, in TLS and in plain TCP. A restart
 * of the network server between two commands must not be seen by a consumer
 * of the relay, and the relay takes up a rotated client certificate for its
 * next connection.
 *
 * The esdm-server refuses to run unprivileged, so this skips (77) when not
 * started as root, and runs in namespaces of its own - see
 * tests/test_namespace.h.
 */

#include "egd_net_test.h"
#include "esdm_egd_client.h"
#include "../test_namespace.h"

static const char *esdm_server_bin, *net_server_bin, *relay_bin;
static char tmpdir[] = "/tmp/esdm-egd-net-relay-test-XXXXXX";
static pid_t esdm_pid;

static pid_t start(const char *bin, const char *const *args, const int *fds,
		   int nfds)
{
	char *argv[64];
	unsigned int n = 0;

	argv[n++] = (char *)bin;
	argv[n++] = (char *)"-vvvv";
	while (args && *args && n < 63)
		argv[n++] = (char *)*args++;
	argv[n] = NULL;

	return test_daemon_start(bin, argv, fds, nfds);
}

/* A network server on the listener @lfd */
static pid_t net_server_start(int lfd, bool plain)
{
	static const char *const tls[] = {
		"--username", "root", "--cert", PKI("server.crt"), "--key",
		PKI("server.key"), "--ca", PKI("ca.crt"), "--crl",
		PKI("int.crl"), "--reload_interval", "0", NULL
	};
	static const char *const plain_args[] = { "--username", "root",
						  "--plain", NULL };

	return start(net_server_bin, plain ? plain_args : tls, &lfd, 1);
}

/* Wait until the socket at @path is there, for at most @ms */
static bool wait_socket(const char *path, unsigned int ms)
{
	uint64_t end = test_now_ms() + ms;
	struct stat sb;

	while (test_now_ms() < end) {
		if (!stat(path, &sb) && S_ISSOCK(sb.st_mode))
			return true;
		test_sleep_ms(100);
	}
	return false;
}

/* A relay on @sock, to @port, with the client certificate @cert */
static pid_t relay_start(const char *sock, uint16_t port, bool plain,
			 const char *cert, const char *key)
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
	args[n++] = "--timeout";
	args[n++] = "10";
	if (plain) {
		args[n++] = "--plain";
	} else {
		args[n++] = "--cert";
		args[n++] = cert;
		args[n++] = "--key";
		args[n++] = key;
		args[n++] = "--ca";
		args[n++] = PKI("ca.crt");
		args[n++] = "--server_name";
		args[n++] = "localhost";
		args[n++] = "--crl";
		args[n++] = PKI("ca.crl");
	}
	args[n] = NULL;

	pid = start(relay_bin, args, NULL, 0);
	if (pid > 0 && !wait_socket(sock, 15000)) {
		test_daemon_stop(pid);
		return -1;
	}
	return pid;
}

static bool nonzero(const uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		if (buf[i])
			return true;
	}
	return false;
}

/*
 * Every command of the protocol through @client, whose daemon - the one
 * answering the PID - is @pid.
 */
static void all_commands(struct esdm_egd_client *client, pid_t pid,
			 const char *what)
{
	uint32_t fields[ESDM_EGD_STATE_NUM_FIELDS + 4];
	unsigned int num = ESDM_EGD_STATE_NUM_FIELDS + 4;
	uint8_t buf[300], seed[32];
	char *report = malloc(ESDM_EGD_MAX_STATUS + 1);
	size_t generated = 0;
	uint32_t bits = 0;
	pid_t got = 0;
	int ret;

	printf("%s: every command\n", what);

	ret = esdm_egd_client_get_pid(client, &got);
	CHECK(!ret && got == pid, "%s: PID %d, expected %d (%d)", what,
	      (int)got, (int)pid, ret);

	ret = esdm_egd_client_entropy_count(client, &bits);
	CHECK(!ret, "%s: entropy count: %d", what, ret);

	memset(buf, 0, sizeof(buf));
	ret = esdm_egd_client_get_random(client, buf, sizeof(buf));
	CHECK(!ret && nonzero(buf, sizeof(buf)), "%s: blocking read: %d",
	      what, ret);

	/*
	 * More blocking reads than the client sends at once, which the daemons
	 * answer together - in runs of at most ESDM_EGD_SERVE_RUN_LIMIT bytes
	 */
	{
		const size_t large = 70000;
		uint8_t *big = calloc(1, large);
		size_t i;

		CHECK(big != NULL, "%s: no memory for the large read", what);
		if (big) {
			ret = esdm_egd_client_get_random(client, big, large);
			for (i = 0; i + 64 <= large; i += 4096) {
				if (!nonzero(big + i, 64))
					break;
			}
			CHECK(!ret && i + 64 > large,
			      "%s: large blocking read: %d, zeroes at %zu",
			      what, ret, i);
			free(big);
		}
	}

	ret = esdm_egd_client_get_random_nonblock(client, buf,
						  ESDM_EGD_MAX_TRANSFER,
						  &generated);
	CHECK(!ret && generated <= ESDM_EGD_MAX_TRANSFER,
	      "%s: non-blocking read: %d", what, ret);
	printf("  %zu bytes right away\n", generated);

	memset(buf, 0, sizeof(buf));
	ret = esdm_egd_client_get_random_pr(client, buf, 64);
	CHECK(!ret && nonzero(buf, 64), "%s: prediction resistant read: %d",
	      what, ret);
	ret = esdm_egd_client_get_random_pr_nonblock(client, buf, 32,
						     &generated);
	CHECK(!ret && generated <= 32,
	      "%s: non-blocking prediction resistant read: %d", what, ret);

	/* Operational by now: the blocking read was answered */
	ret = esdm_egd_client_get_random_unseeded(client, buf, 32, &generated);
	CHECK(!ret && generated == 32 && nonzero(buf, 32),
	      "%s: read unseeded: %d, %zu bytes", what, ret, generated);

	ret = esdm_egd_client_get_state(client, fields, &num);
	CHECK(!ret && num >= ESDM_EGD_STATE_NUM_FIELDS &&
		      (fields[ESDM_EGD_STATE_FLAGS] &
		       ESDM_EGD_STATE_FLAG_OPERATIONAL) &&
		      fields[ESDM_EGD_STATE_POOLSIZE],
	      "%s: state: %d, %u fields, flags 0x%x", what, ret, num,
	      fields[ESDM_EGD_STATE_FLAGS]);

	if (report) {
		ret = esdm_egd_client_status(client, report,
					     ESDM_EGD_MAX_STATUS + 1);
		CHECK(ret > 0 && strstr(report, "DRNG name: "),
		      "%s: status: %d", what, ret);
		ret = esdm_egd_client_status_json(client, report,
						  ESDM_EGD_MAX_STATUS + 1);
		CHECK(ret > 0 && report[0] == '{' && strstr(report, "\"drngs\""),
		      "%s: JSON status: %d", what, ret);
		/* Too small a buffer: the text cut short, the JSON empty */
		ret = esdm_egd_client_status(client, report, 16);
		CHECK(ret == -EMSGSIZE && strlen(report) == 15,
		      "%s: short status: %d", what, ret);
		ret = esdm_egd_client_status_json(client, report, 16);
		CHECK(ret == -EMSGSIZE && !report[0],
		      "%s: short JSON status: %d", what, ret);
		free(report);
	}

	/* The claim is dropped by the network server; nothing breaks */
	memset(seed, 0x5a, sizeof(seed));
	ret = esdm_egd_client_write_entropy(client, seed, sizeof(seed),
					    8 * sizeof(seed));
	CHECK(!ret, "%s: insertion: %d", what, ret);
	ret = esdm_egd_client_entropy_count(client, &bits);
	CHECK(!ret, "%s: entropy count after an insertion: %d", what, ret);
}

static struct esdm_egd_client *net_client(uint16_t port, bool plain)
{
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *client = NULL;
	char address[64];

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
	CHECK(!esdm_egd_client_alloc_net(&client, &cfg),
	      "no network client of port %u", port);
	return client;
}

static struct esdm_egd_client *unix_client(const char *sock)
{
	struct esdm_egd_client *client = NULL;

	CHECK(!esdm_egd_client_alloc(&client, sock, 30000),
	      "no client of %s", sock);
	return client;
}

static int esdm_start(void)
{
	static const char *const args[] = { "--pid_namespace", NULL };

	esdm_pid = start(esdm_server_bin, args, NULL, 0);
	return esdm_pid > 0 ? 0 : -1;
}

/*
 * The TLS mode: every command directly and through the relay, a restart of
 * the network server, and the relay taking up a rotated certificate.
 */
static void test_tls(void)
{
#ifdef ESDM_EGD_NET_TLS
	char sock[sizeof(tmpdir) + 16], sock_rot[sizeof(tmpdir) + 16];
	char crt[sizeof(tmpdir) + 16], key[sizeof(tmpdir) + 16];
	struct esdm_egd_client *client, *a, *b;
	uint8_t buf[64];
	uint16_t port = 0;
	pid_t server, relay, relay_rot, pid;
	int lfd, ret;

	snprintf(sock, sizeof(sock), "%s/egd-tls.sock", tmpdir);
	snprintf(sock_rot, sizeof(sock_rot), "%s/egd-rot.sock", tmpdir);
	snprintf(crt, sizeof(crt), "%s/relay.crt", tmpdir);
	snprintf(key, sizeof(key), "%s/relay.key", tmpdir);

	lfd = test_listener("127.0.0.1", &port);
	server = net_server_start(lfd, false);
	relay = relay_start(sock, port, false, PKI("client1.crt"),
			    PKI("client1.key"));
	CHECK(server > 0 && relay > 0, "the TLS daemons did not start");

	client = net_client(port, false);
	all_commands(client, server, "Library over TLS");
	esdm_egd_client_free(client);

	/* Through the relay, as a legacy consumer sees it */
	client = unix_client(sock);
	all_commands(client, relay, "Relay over TLS");

	/* The network server restarts between two commands */
	printf("Relay over TLS: restart of the network server\n");
	CHECK(test_daemon_stop(server) == 0, "the network server did not stop");
	server = net_server_start(lfd, false);
	ret = esdm_egd_client_get_random(client, buf, sizeof(buf));
	CHECK(!ret, "the restart was seen by the consumer: %d", ret);
	ret = esdm_egd_client_get_pid(client, &pid);
	CHECK(!ret && pid == relay, "the relay changed: %d", ret);
	esdm_egd_client_free(client);

	/*
	 * A rotated client certificate is taken up by the relay for its next
	 * upstream connection: to the revoked one, which the network server
	 * refuses, and on to another good one. A connection made before keeps
	 * the certificate it was made with.
	 */
	printf("Relay: rotation of its client certificate\n");
	CHECK(!test_install(PKI("client1.crt"), crt) &&
		      !test_install(PKI("client1.key"), key),
	      "cannot install the certificate of the relay");
	relay_rot = relay_start(sock_rot, port, false, crt, key);
	CHECK(relay_rot > 0, "the rotating relay did not start");
	a = unix_client(sock_rot);
	CHECK(!esdm_egd_client_get_random(a, buf, sizeof(buf)),
	      "the first certificate was refused");

	CHECK(!test_install(PKI("client-revoked.key"), key) &&
		      !test_install(PKI("client-revoked.crt"), crt),
	      "cannot rotate to the revoked certificate");
	b = unix_client(sock_rot);
	CHECK(esdm_egd_client_get_random(b, buf, sizeof(buf)) < 0,
	      "the revoked certificate was not taken up");
	esdm_egd_client_free(b);
	CHECK(!esdm_egd_client_get_random(a, buf, sizeof(buf)),
	      "the connection made before lost its certificate");

	CHECK(!test_install(PKI("client2.key"), key) &&
		      !test_install(PKI("client2.crt"), crt),
	      "cannot rotate to client 2");
	b = unix_client(sock_rot);
	CHECK(!esdm_egd_client_get_random(b, buf, sizeof(buf)),
	      "the certificate of client 2 was not taken up");
	esdm_egd_client_free(b);
	esdm_egd_client_free(a);

	CHECK(test_daemon_stop(relay_rot) == 0, "the relay did not stop");
	CHECK(test_daemon_stop(relay) == 0, "the relay did not stop");
	CHECK(test_daemon_stop(server) == 0, "the server did not stop");
	close(lfd);
	unlink(crt);
	unlink(key);
#else
	printf("Built without egd-net-tls, the TLS mode is not tested\n");
#endif
}

/* Plain TCP: every command directly and through the relay, and a restart */
static void test_plain(void)
{
	char sock[sizeof(tmpdir) + 16];
	struct esdm_egd_client *client;
	uint8_t buf[64];
	uint16_t port = 0;
	pid_t server, relay;
	int lfd, ret;

	snprintf(sock, sizeof(sock), "%s/egd-plain.sock", tmpdir);

	lfd = test_listener("127.0.0.1", &port);
	server = net_server_start(lfd, true);
	relay = relay_start(sock, port, true, NULL, NULL);
	CHECK(server > 0 && relay > 0, "the plain daemons did not start");

	client = net_client(port, true);
	all_commands(client, server, "Library over plain TCP");
	esdm_egd_client_free(client);

	client = unix_client(sock);
	all_commands(client, relay, "Relay over plain TCP");
	printf("Relay over plain TCP: restart of the network server\n");
	CHECK(test_daemon_stop(server) == 0, "the network server did not stop");
	server = net_server_start(lfd, true);
	ret = esdm_egd_client_get_random(client, buf, sizeof(buf));
	CHECK(!ret, "the restart was seen by the consumer: %d", ret);
	esdm_egd_client_free(client);

	CHECK(test_daemon_stop(relay) == 0, "the relay did not stop");
	CHECK(test_daemon_stop(server) == 0, "the server did not stop");
	close(lfd);
}

int main(void)
{
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(600);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
#ifndef ESDM_TESTMODE
	/* The RPC socket of a test server is the one of testmode */
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
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}
	if (!mkdtemp(tmpdir))
		return 1;

	/* Up once its unprivileged RPC socket is - the one of testmode */
	if (esdm_start() ||
	    !wait_socket("/tmp/esdm-rpc-unpriv-testmode.socket", 30000)) {
		printf("The esdm-server did not start\n");
		return 1;
	}

	test_tls();
	test_plain();

	test_daemon_stop(esdm_pid);
	rmdir(tmpdir);

	printf("EGD network end to end: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
