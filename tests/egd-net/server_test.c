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
 * The esdm-egd-net-server, as the network sees it: what it refuses to start
 * with, the bounds of its connections, its TLS files taken up while it runs,
 * revocation of established connections, plain TCP and the allowlist. None of
 * this needs an ESDM - the commands spoken here are the ones the daemon
 * answers itself: the PID, and the privileged commands it refuses - so this
 * runs unprivileged; relay_test covers the commands answered by the ESDM.
 */

#include "egd_net_test.h"
#include "esdm_egd_client.h"

static const char *server_bin;
static char tmpdir[] = "/tmp/esdm-egd-net-server-test-XXXXXX";

/* The listener handed to the server, and its port */
struct server {
	pid_t pid;
	int lfd, lfd6;
	uint16_t port, port6;
};

/*
 * Start the server with @args, NULL-terminated, listening on 127.0.0.1 - and
 * ::1 with @v6, where the host has it.
 */
static int server_start(struct server *s, bool v6, const char *const *args)
{
	char *argv[64];
	int fds[2], nfds = 0;
	unsigned int n = 0;

	memset(s, 0, sizeof(*s));
	s->lfd6 = -1;
	s->lfd = test_listener("127.0.0.1", &s->port);
	if (s->lfd < 0)
		return -1;
	fds[nfds++] = s->lfd;
	if (v6) {
		s->lfd6 = test_listener("::1", &s->port6);
		if (s->lfd6 >= 0)
			fds[nfds++] = s->lfd6;
	}

	argv[n++] = (char *)server_bin;
	argv[n++] = (char *)"-vvvv";
	/* Root keeps root, so that it can read the files of the test */
	if (!getuid()) {
		argv[n++] = (char *)"--username";
		argv[n++] = (char *)"root";
	}
	while (args && *args && n < 63)
		argv[n++] = (char *)*args++;
	argv[n] = NULL;

	s->pid = test_daemon_start(server_bin, argv, fds, nfds);
	if (s->pid < 0)
		return -1;

	/* Up once it answers - the listener queues the connection meanwhile */
	{
		uint64_t end = test_now_ms() + 15000;

		while (test_now_ms() < end) {
			if (waitpid(s->pid, NULL, WNOHANG) == s->pid) {
				s->pid = 0;
				return -1;
			}
			/* The log line tells it is serving */
			test_sleep_ms(100);
			break;
		}
	}
	return 0;
}

static void server_stop(struct server *s)
{
	int status = test_daemon_stop(s->pid);

	CHECK(status == 0, "the server exited with %d", status);
	if (s->lfd >= 0)
		close(s->lfd);
	if (s->lfd6 >= 0)
		close(s->lfd6);
	memset(s, 0, sizeof(*s));
}

/* The server must refuse to start with @args, NULL-terminated */
static void expect_refusal(const char *what, const char *const *args)
{
	struct server s;
	int status;

	if (server_start(&s, false, args)) {
		/* Gone before it was looked at: what it should do */
		close(s.lfd);
		return;
	}
	status = test_daemon_wait(s.pid, 10000);
	CHECK(status > 0 && status < 128,
	      "%s: the server started (exit status %d)", what, status);
	close(s.lfd);
}

static void test_refusals(void)
{
	static const char *const none[] = { NULL };
	static const char *const plain_tls[] = { "--plain", "--cert",
						 PKI("server.crt"), NULL };
	static const char *const plain_crl[] = { "--plain", "--crl",
						 PKI("int.crl"), NULL };
	static const char *const zero[] = { "--plain", "--max_per_client", "0",
					    NULL };

	printf("Server: what it refuses to start with\n");
	expect_refusal("neither TLS files nor --plain", none);
	expect_refusal("--plain with --cert", plain_tls);
	expect_refusal("--plain with --crl", plain_crl);
	expect_refusal("a bound of 0", zero);

#ifndef ESDM_EGD_NET_TLS
	{
		static const char *const tls[] = {
			"--cert", PKI("server.crt"), "--key", PKI("server.key"),
			"--ca", PKI("ca.crt"), NULL
		};

		expect_refusal("TLS without a TLS stack", tls);
	}
#endif
}

/* The configuration checks of the library's network modes */
static void test_library_config(void)
{
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *client = NULL;

	printf("Library: network configurations\n");

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	cfg.address = "127.0.0.1:1";
	cfg.cert_file = PKI("client1.crt");
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EINVAL,
	      "plain TCP with a certificate was accepted");

	cfg.cert_file = NULL;
	cfg.address = "[::1";
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EINVAL,
	      "an address that does not parse was accepted");

	cfg.address = "127.0.0.1:1";
	cfg.mode = 0;
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EINVAL,
	      "no mode was accepted");

	cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	cfg.size = 4;
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EINVAL,
	      "a configuration too small was accepted");

	cfg.size = sizeof(cfg);
	cfg.mode = ESDM_EGD_CLIENT_NET_TLS;
#ifdef ESDM_EGD_NET_TLS
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EINVAL,
	      "TLS without a certificate was accepted");
#else
	CHECK(esdm_egd_client_alloc_net(&client, &cfg) == -EOPNOTSUPP,
	      "TLS in a build without it was not refused as such");
#endif
	CHECK(!client, "a client was handed out");
}

/* A library client of the server, in plain TCP or TLS with @cert */
static struct esdm_egd_client *lib_client(const char *address,
					  const char *cert, const char *key)
{
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *client = NULL;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.address = address;
	cfg.timeout_ms = TEST_IO_MS;
	if (cert) {
		cfg.mode = ESDM_EGD_CLIENT_NET_TLS;
		cfg.cert_file = cert;
		cfg.key_file = key;
		cfg.ca_file = PKI("ca.crt");
		cfg.server_name = "localhost";
	} else {
		cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	}

	ret = esdm_egd_client_alloc_net(&client, &cfg);
	CHECK(!ret, "library client of %s: %s", address, strerror(-ret));
	return client;
}

static void test_plain(void)
{
	static const char *const args[] = {
		"--plain", "--max_per_client", "2", "--handshake_timeout", "2",
		"--allow", "127.0.0.1/32", "--allow", "::1", NULL
	};
	struct esdm_egd_client *client;
	char address[64];
	uint8_t cmd[5] = { ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP, 0, 0, 1, 0 };
	uint8_t resp[4];
	struct server s;
	pid_t pid = 0;
	int fd1, fd2, fd3, ret;

	printf("Server: plain TCP\n");
	if (server_start(&s, true, args)) {
		CHECK(0, "the server did not start");
		return;
	}

	fd1 = test_connect("127.0.0.1", s.port, NULL);
	CHECK(test_plain_pid(fd1) == s.pid, "no PID in plain TCP");

	/* Privileged commands are refused, and the connection goes on */
	CHECK(!test_send(fd1, cmd, sizeof(cmd)) && !test_recv(fd1, resp, 4) &&
		      (int32_t)((uint32_t)resp[0] << 24 |
				(uint32_t)resp[1] << 16 |
				(uint32_t)resp[2] << 8 | resp[3]) == -EPERM,
	      "a privileged command was not refused");
	CHECK(test_plain_pid(fd1) == s.pid,
	      "the connection broke after a refused command");

	/* The bound per source address */
	fd2 = test_connect("127.0.0.1", s.port, NULL);
	CHECK(test_plain_pid(fd2) == s.pid, "no PID on the second connection");
	fd3 = test_connect("127.0.0.1", s.port, NULL);
	CHECK(fd3 >= 0 && test_fd_closed(fd3, 2000),
	      "a third connection of the source was served");
	if (fd3 >= 0)
		close(fd3);
	close(fd2);
	test_sleep_ms(300);

	/* A source the allowlist does not have */
	fd3 = test_connect("127.0.0.1", s.port, "127.0.0.2");
	if (fd3 >= 0) {
		CHECK(test_fd_closed(fd3, 2000),
		      "a source not allowed was served");
		close(fd3);
	} else {
		printf("  127.0.0.2 cannot be bound, allowlist not tested\n");
	}

	/* A silent client is closed after its probation */
	fd3 = test_connect("127.0.0.1", s.port, NULL);
	CHECK(fd3 >= 0 && test_fd_closed(fd3, 5000),
	      "a silent client was not closed");
	if (fd3 >= 0)
		close(fd3);

	/* An unknown command ends the connection */
	cmd[0] = 0x77;
	CHECK(!test_send(fd1, cmd, 1) && test_fd_closed(fd1, 2000),
	      "an unknown command did not end the connection");
	close(fd1);
	test_sleep_ms(300);

	/* The library in plain mode */
	snprintf(address, sizeof(address), "127.0.0.1:%u", s.port);
	client = lib_client(address, NULL, NULL);
	ret = esdm_egd_client_get_pid(client, &pid);
	CHECK(!ret && pid == s.pid, "the library got no PID: %d", ret);
	esdm_egd_client_free(client);

	if (s.lfd6 >= 0) {
		snprintf(address, sizeof(address), "[::1]:%u", s.port6);
		client = lib_client(address, NULL, NULL);
		ret = esdm_egd_client_get_pid(client, &pid);
		CHECK(!ret && pid == s.pid,
		      "the library got no PID over IPv6: %d", ret);
		esdm_egd_client_free(client);
	} else {
		printf("  no IPv6 on this host\n");
	}

	server_stop(&s);
}

#ifdef ESDM_EGD_NET_TLS

static void test_tls(void)
{
	static const char *const args[] = {
		"--cert", PKI("server.crt"), "--key", PKI("server.key"), "--ca",
		PKI("ca.crt"), "--max_per_client", "2", "--handshake_timeout",
		"2", "--max_handshakes_per_source", "3", "--idle_timeout", "3",
		NULL
	};
	uint8_t write_cmd[4 + 8] = { ESDM_EGD_CMD_WRITE_ENTROPY, 0x08, 0x00, 8 };
	uint8_t priv = ESDM_EGD_CMD_ESDM_RESEED, resp[4], unknown = 0x77;
	struct test_tls a, b, c, d;
	struct esdm_egd_client *client;
	char address[64];
	int silent[4], i, ret;
	pid_t pid = 0;
	struct server s;

	printf("Server: TLS\n");
	if (server_start(&s, false, args)) {
		CHECK(0, "the server did not start");
		return;
	}

	ret = test_tls_open(&a, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	CHECK(!ret, "client 1 was refused: %d", ret);
	CHECK(test_tls_pid(&a) == s.pid, "no PID over TLS");

	/* Privileged commands are refused, claims dropped, all in step */
	CHECK(!test_tls_send(&a, &priv, 1) &&
		      !test_tls_recv(&a, resp, sizeof(resp), TEST_IO_MS) &&
		      (int32_t)((uint32_t)resp[0] << 24 |
				(uint32_t)resp[1] << 16 |
				(uint32_t)resp[2] << 8 | resp[3]) == -EPERM,
	      "a privileged command was not refused");
	CHECK(!test_tls_send(&a, write_cmd, sizeof(write_cmd)),
	      "insertion with a claim");
	CHECK(test_tls_pid(&a) == s.pid,
	      "out of step after a refused command and an insertion");

	/* The bound per client certificate */
	ret = test_tls_open(&b, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	CHECK(!ret && test_tls_pid(&b) == s.pid,
	      "the second connection of client 1 failed");
	ret = test_tls_open(&c, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	CHECK(ret || test_tls_closed(&c, 3000),
	      "a third connection of client 1 was served");
	test_tls_close(&c);
	ret = test_tls_open(&c, s.port, PKI("client2.crt"), PKI("client2.key"),
			    "localhost");
	CHECK(!ret && test_tls_pid(&c) == s.pid,
	      "client 2 was refused next to client 1");
	test_tls_close(&c);
	test_tls_close(&b);
	test_sleep_ms(300);

	/* No certificate, or one of another CA */
	ret = test_tls_open(&c, s.port, NULL, NULL, "localhost");
	CHECK(ret || test_tls_closed(&c, 3000),
	      "a client without a certificate was served");
	test_tls_close(&c);
	ret = test_tls_open(&c, s.port, PKI("client-expired.crt"),
			    PKI("client-expired.key"), "localhost");
	CHECK(ret || test_tls_closed(&c, 3000),
	      "a client with an expired certificate was served");
	test_tls_close(&c);

	/* An unknown command ends the connection */
	ret = test_tls_open(&c, s.port, PKI("client2.crt"), PKI("client2.key"),
			    "localhost");
	CHECK(!ret && !test_tls_send(&c, &unknown, 1) &&
		      test_tls_closed(&c, 3000),
	      "an unknown command did not end the connection");
	test_tls_close(&c);

	/*
	 * Silent connections: three of the source may wait for their
	 * handshake, a fourth is closed at once - and so is any other of the
	 * source while they wait. All are gone after the handshake timeout.
	 */
	for (i = 0; i < 3; i++)
		silent[i] = test_connect("127.0.0.1", s.port, NULL);
	silent[3] = test_connect("127.0.0.1", s.port, NULL);
	CHECK(silent[3] >= 0 && test_fd_closed(silent[3], 1000),
	      "a fourth silent connection of the source was kept");
	ret = test_tls_open(&d, s.port, PKI("client2.crt"), PKI("client2.key"),
			    "localhost");
	CHECK(ret || test_tls_closed(&d, 1000),
	      "a client was served while its source had the handshakes taken");
	test_tls_close(&d);
	for (i = 0; i < 3; i++) {
		CHECK(silent[i] >= 0 && test_fd_closed(silent[i], 5000),
		      "silent connection %d was not closed", i);
		if (silent[i] >= 0)
			close(silent[i]);
	}
	if (silent[3] >= 0)
		close(silent[3]);
	ret = test_tls_open(&d, s.port, PKI("client2.crt"), PKI("client2.key"),
			    "localhost");
	CHECK(!ret && test_tls_pid(&d) == s.pid,
	      "client 2 was refused after the silent ones were gone");

	/* The idle timeout, and the library reconnecting across it */
	snprintf(address, sizeof(address), "127.0.0.1:%u", s.port);
	client = lib_client(address, PKI("client2.crt"), PKI("client2.key"));
	ret = esdm_egd_client_get_pid(client, &pid);
	CHECK(!ret && pid == s.pid, "the library got no PID over TLS: %d",
	      ret);
	test_sleep_ms(4500);
	CHECK(test_tls_closed(&d, 1000), "an idle connection was kept");
	CHECK(test_tls_closed(&a, 1000), "an idle connection was kept");
	ret = esdm_egd_client_get_pid(client, &pid);
	CHECK(!ret && pid == s.pid,
	      "the library did not reconnect after the idle timeout: %d",
	      ret);
	esdm_egd_client_free(client);

	test_tls_close(&a);
	test_tls_close(&d);
	server_stop(&s);
}

/* The fingerprint of the server a connection reached, or zeros */
static void server_fp(struct test_tls *t, uint8_t fp[ESDM_TLS_FINGERPRINT_LEN])
{
	if (esdm_tls_peer_fingerprint(t->tls, fp))
		memset(fp, 0, ESDM_TLS_FINGERPRINT_LEN);
}

/* Wait until a new connection reaches a server other than @old, for @ms */
static bool server_rotated(uint16_t port, const char *name,
			   const uint8_t old[ESDM_TLS_FINGERPRINT_LEN],
			   unsigned int ms)
{
	uint8_t fp[ESDM_TLS_FINGERPRINT_LEN];
	uint64_t end = test_now_ms() + ms;
	struct test_tls t;

	while (test_now_ms() < end) {
		int ret = test_tls_open(&t, port, PKI("client1.crt"),
					PKI("client1.key"), name);

		server_fp(&t, fp);
		test_tls_close(&t);
		if (!ret && memcmp(fp, old, sizeof(fp)))
			return true;
		test_sleep_ms(200);
	}
	return false;
}

/* The PKI files of a server in the temporary directory, to rotate */
static char tmp_crt[sizeof(tmpdir) + 16], tmp_key[sizeof(tmpdir) + 16];
static char tmp_ca[sizeof(tmpdir) + 16], tmp_crl[sizeof(tmpdir) + 16];

static int install_pki(const char *crl)
{
	snprintf(tmp_crt, sizeof(tmp_crt), "%s/server.crt", tmpdir);
	snprintf(tmp_key, sizeof(tmp_key), "%s/server.key", tmpdir);
	snprintf(tmp_ca, sizeof(tmp_ca), "%s/ca.crt", tmpdir);
	snprintf(tmp_crl, sizeof(tmp_crl), "%s/crl.pem", tmpdir);

	if (test_install(PKI("server.crt"), tmp_crt) ||
	    test_install(PKI("server.key"), tmp_key) ||
	    test_install(PKI("ca.crt"), tmp_ca) ||
	    test_install(crl, tmp_crl)) {
		CHECK(0, "cannot copy the PKI to %s", tmpdir);
		return -1;
	}
	return 0;
}

/* Reload by itself: the CRLs, a renewed certificate, a broken rotation */
static void test_tls_rotation(void)
{
	const char *args[] = { "--cert", tmp_crt, "--key", tmp_key,
			       "--ca", tmp_ca, "--crl", tmp_crl,
			       "--reload_interval", "1", "--idle_timeout", "0",
			       NULL };
	uint8_t fp_old[ESDM_TLS_FINGERPRINT_LEN], fp[ESDM_TLS_FINGERPRINT_LEN];
	struct test_tls one, revoked, t;
	struct server s;
	int ret;

	printf("Server: rotation and revocation, taken up by themselves\n");

	if (install_pki(PKI("int-empty.crl")))
		return;
	if (server_start(&s, false, args)) {
		CHECK(0, "the server did not start");
		return;
	}

	ret = test_tls_open(&one, s.port, PKI("client1.crt"),
			    PKI("client1.key"), "localhost");
	CHECK(!ret && test_tls_pid(&one) == s.pid, "client 1 was refused");
	server_fp(&one, fp_old);
	ret = test_tls_open(&revoked, s.port, PKI("client-revoked.crt"),
			    PKI("client-revoked.key"), "localhost");
	CHECK(!ret && test_tls_pid(&revoked) == s.pid,
	      "the client to be revoked was refused before");

	/* The CRL revoking it is taken up, and its connection closed */
	CHECK(!test_install(PKI("int.crl"), tmp_crl), "installing the CRL");
	CHECK(test_tls_closed(&revoked, 5000),
	      "the connection of a revoked client was kept");
	test_tls_close(&revoked);
	CHECK(test_tls_pid(&one) == s.pid,
	      "client 1 lost its connection to the revocation");
	ret = test_tls_open(&t, s.port, PKI("client-revoked.crt"),
			    PKI("client-revoked.key"), "localhost");
	CHECK(ret || test_tls_closed(&t, 3000),
	      "the revoked client was served again");
	test_tls_close(&t);

	/* A renewed certificate */
	CHECK(!test_install(PKI("server-renewed.key"), tmp_key) &&
		      !test_install(PKI("server-renewed.crt"), tmp_crt),
	      "installing the renewed certificate");
	CHECK(server_rotated(s.port, "localhost", fp_old, 5000),
	      "the renewed certificate was not taken up");
	CHECK(test_tls_pid(&one) == s.pid,
	      "client 1 lost its connection to the rotation");

	/*
	 * A broken rotation - a key not belonging to the certificate - keeps
	 * the renewed certificate in service.
	 */
	ret = test_tls_open(&t, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	server_fp(&t, fp_old);
	test_tls_close(&t);
	CHECK(!test_install(PKI("server.crt"), tmp_crt), "installing a broken pair");
	test_sleep_ms(2500);
	ret = test_tls_open(&t, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	server_fp(&t, fp);
	CHECK(!ret && !memcmp(fp, fp_old, sizeof(fp)) &&
		      test_tls_pid(&t) == s.pid,
	      "a broken rotation took the server down: %d", ret);
	test_tls_close(&t);

	test_tls_close(&one);
	server_stop(&s);
}

/* Reload on SIGHUP only */
static void test_tls_sighup(void)
{
	const char *args[] = { "--cert", tmp_crt, "--key", tmp_key,
			       "--ca", tmp_ca, "--reload_interval", "0", NULL };
	uint8_t fp_old[ESDM_TLS_FINGERPRINT_LEN], fp[ESDM_TLS_FINGERPRINT_LEN];
	struct test_tls t;
	struct server s;
	int ret;

	printf("Server: rotation on SIGHUP\n");

	if (install_pki(PKI("int.crl")))
		return;
	if (server_start(&s, false, args)) {
		CHECK(0, "the server did not start");
		return;
	}

	ret = test_tls_open(&t, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	CHECK(!ret, "client 1 was refused: %d", ret);
	server_fp(&t, fp_old);
	test_tls_close(&t);

	CHECK(!test_install(PKI("server-renewed.key"), tmp_key) &&
		      !test_install(PKI("server-renewed.crt"), tmp_crt),
	      "installing the renewed certificate");
	test_sleep_ms(1500);
	ret = test_tls_open(&t, s.port, PKI("client1.crt"), PKI("client1.key"),
			    "localhost");
	server_fp(&t, fp);
	CHECK(!ret && !memcmp(fp, fp_old, sizeof(fp)),
	      "the certificate changed without SIGHUP");
	test_tls_close(&t);

	kill(s.pid, SIGHUP);
	CHECK(server_rotated(s.port, "localhost", fp_old, 3000),
	      "SIGHUP did not take up the renewed certificate");

	server_stop(&s);
}

/*
 * A reload while a handshake runs: the handshake was begun with the context
 * before, whose CRL did not revoke the client - the one in place once it
 * completes does.
 */
static void test_tls_reload_race(void)
{
	const char *args[] = { "--cert", tmp_crt, "--key", tmp_key,
			       "--ca", tmp_ca, "--crl", tmp_crl,
			       "--reload_interval", "0", NULL };
	struct test_tls revoked, good;
	struct server s;
	int ret;

	printf("Server: a handshake overlapping a reload\n");

	if (install_pki(PKI("int-empty.crl")))
		return;
	if (server_start(&s, false, args)) {
		CHECK(0, "the server did not start");
		return;
	}

	/* Connected, and the server has its TLS for them */
	memset(&revoked, 0, sizeof(revoked));
	memset(&good, 0, sizeof(good));
	revoked.fd = test_connect("127.0.0.1", s.port, NULL);
	good.fd = test_connect("127.0.0.1", s.port, NULL);
	CHECK(revoked.fd >= 0 && good.fd >= 0, "cannot connect");
	test_sleep_ms(500);

	/* The CRL revoking the client, reloaded before it shakes hands */
	CHECK(!test_install(PKI("int.crl"), tmp_crl), "installing the CRL");
	kill(s.pid, SIGHUP);
	test_sleep_ms(1000);

	ret = test_tls_shake(&revoked, PKI("client-revoked.crt"),
			     PKI("client-revoked.key"), "localhost");
	CHECK(ret || test_tls_closed(&revoked, 3000),
	      "a client revoked during its handshake was served");
	ret = test_tls_shake(&good, PKI("client1.crt"), PKI("client1.key"),
			     "localhost");
	CHECK(!ret && test_tls_pid(&good) == s.pid,
	      "a client not revoked was refused after the reload: %d", ret);

	test_tls_close(&revoked);
	test_tls_close(&good);
	server_stop(&s);
}

#endif /* ESDM_EGD_NET_TLS */

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(600);

	server_bin = getenv("ESDM_EGD_NET_SERVER");
	if (test_env_check_file(server_bin))
		return 1;
	if (!mkdtemp(tmpdir)) {
		printf("Cannot create %s\n", tmpdir);
		return 1;
	}
	/* The server may run as another user, see server_start() */
	chmod(tmpdir, 0755);

	test_refusals();
	test_library_config();
	test_plain();
#ifdef ESDM_EGD_NET_TLS
	test_tls();
	test_tls_rotation();
	test_tls_sighup();
	test_tls_reload_race();
#else
	printf("Built without egd-net-tls, the TLS mode is not tested\n");
#endif

	{
		static const char *const files[] = {
			"server.crt", "server.key", "ca.crt", "crl.pem",
			"server.crt.new", "server.key.new", "crl.pem.new"
		};
		char path[sizeof(tmpdir) + 32];
		size_t i;

		for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
			snprintf(path, sizeof(path), "%s/%s", tmpdir, files[i]);
			unlink(path);
		}
		rmdir(tmpdir);
	}

	printf("EGD network server: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
