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
 * The network mode of the provider server of libesdm_es_ext, as a provider
 * program - esdm_es_ext_provider_main() - offers it, serving the test source
 * on SCTP with DTLS and certificates - its socket handed over by socket
 * activation, bound here to a port the kernel picked:
 *
 *  - the requests inside the DTLS, the fields of STATUS on the network - the
 *    transport and the peer asking -, and the refusals: STARTDTLS, a client
 *    without a certificate or of an untrusted CA, an association without
 *    SCTP-AUTH;
 *  - the allowlist, from the second loopback address;
 *  - the bounds: the connections in all, those in their handshake, in all and
 *    per source, and those per client;
 *  - the handshake timeout and the idle timeout;
 *  - the rotation of the certificate taken up by itself, one that does not
 *    load leaving the server up, and a CRL taken up on SIGHUP closing the
 *    established connection of the client it revokes;
 *  - the options it refuses to start with.
 *
 * Needs no privileges. Skips (77) in a build without es-ext-net, and on a
 * kernel without SCTP.
 *
 * Usage: es_ext_net_server_test <test provider>
 */

#define _GNU_SOURCE
#include "config.h"

#include <json-c/json.h>
#include <sys/stat.h>

#include "es_ext_net_test.h"
#include "esdm_logger.h"

#ifdef ESDM_ES_EXT_NET

static const char *serve_path;

/* A client context of the test PKI, by the base name of its files */
static struct esdm_tls_ctx *client_of(const char *name)
{
	char cert[512], key[512];
	struct esdm_tls_config cfg;
	struct esdm_tls_ctx *ctx = NULL;

	snprintf(cert, sizeof(cert), "%s/%s.crt", ESDM_TEST_PKI, name);
	snprintf(key, sizeof(key), "%s/%s.key", ESDM_TEST_PKI, name);
	memset(&cfg, 0, sizeof(cfg));
	cfg.cert_file = cert;
	cfg.key_file = key;
	cfg.ca_file = PKI("ca.crt");
	cfg.transport = ESDM_TLS_TRANSPORT_SCTP;
	CHECK(!esdm_tls_ctx_alloc(false, &cfg, &ctx), "client context %s",
	      name);
	return ctx;
}

/* The server under test, and the port it serves on */
struct server {
	pid_t pid;
	uint16_t port;
};

/*
 * Start the provider on a listener of 127.0.0.1, with the certificate
 * @cert and its key @key - the test PKI's server by default - and the options
 * @extra, NULL-terminated. Wait until it serves.
 *
 * @return 0, or -1
 */
static int server_start(struct server *s, const char *cert, const char *key,
			const char *const *extra, struct esdm_tls_ctx *probe)
{
	char *argv[48];
	unsigned int n = 0;
	int lfd;

	memset(s, 0, sizeof(*s));
	lfd = test_sctp_listener("127.0.0.1", true, &s->port);
	if (lfd < 0)
		return -1;

	argv[n++] = (char *)serve_path;
	argv[n++] = "--cert";
	argv[n++] = (char *)(cert ? cert : PKI("server.crt"));
	argv[n++] = "--key";
	argv[n++] = (char *)(key ? key : PKI("server.key"));
	argv[n++] = "--ca";
	argv[n++] = PKI("ca.crt");
	argv[n++] = "-v";
	while (extra && *extra && n < sizeof(argv) / sizeof(argv[0]) - 1)
		argv[n++] = (char *)*extra++;
	argv[n] = NULL;

	s->pid = test_daemon_start(serve_path, argv, &lfd, 1, NULL);
	close(lfd);
	if (s->pid <= 0)
		return -1;

	/* Served once a client gets through its handshake */
	if (probe) {
		uint64_t end = test_now_ms() + TEST_IO_MS;
		struct test_conn c;

		while (test_now_ms() < end) {
			int ret = test_conn_open(&c, "127.0.0.1", s->port, NULL,
						 probe, "localhost");

			test_conn_close(&c);
			if (!ret)
				return 0;
			test_sleep_ms(50);
		}
		return -1;
	}

	return 0;
}

static void server_stop(struct server *s)
{
	CHECK(test_daemon_stop(s->pid) == 0,
	      "the server did not end cleanly on SIGTERM");
	s->pid = 0;
}

/* The JSON of the answer @rsp of @n bytes to a STATUS */
static struct json_object *status_of(const uint8_t *rsp, ssize_t n)
{
	const char *text;
	size_t len;
	int32_t status;

	if (n < 0 || esdm_es_ext_proto_status_unpack(
			     rsp, (size_t)n, ESDM_ES_EXT_PROTO_STATUS_MAX,
			     &status, &text, &len) ||
	    status)
		return NULL;
	return json_tokener_parse(text);
}

static const char *json_str(struct json_object *obj, const char *a,
			    const char *b)
{
	struct json_object *v;

	if (!json_object_object_get_ex(obj, a, &v) ||
	    !json_object_object_get_ex(v, b, &v) ||
	    !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

/* A raw association without a handshake, from @src */
static int raw_assoc(uint16_t port, const char *src)
{
	return test_sctp_connect_from("127.0.0.1", port, src, true);
}

static void test_requests(void)
{
	struct esdm_tls_ctx *c1 = client_of("client1"),
			    *none = NULL, *rogue = NULL;
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	struct esdm_tls_config cfg;
	struct json_object *obj;
	const uint8_t *data;
	const char *name, *str;
	struct test_conn c;
	struct server s;
	uint32_t bits, rate;
	size_t namelen;
	int32_t status;
	ssize_t n;
	int fd;

	printf("Provider server on the network: requests and refusals\n");

	CHECK(!server_start(&s, NULL, NULL, NULL, c1), "the server is not up");

	CHECK(!test_conn_open(&c, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1: %d", c.ret);
	n = test_conn_request(&c, ESDM_ES_EXT_PROTO_INFO, 0, rsp);
	CHECK(n > 0 && !esdm_es_ext_proto_info_unpack(rsp, (size_t)n, &status,
						      &rate, &name, &namelen) &&
		      !status && namelen == strlen("es-ext-test") &&
		      !memcmp(name, "es-ext-test", namelen),
	      "INFO: %zd", n);
	n = test_conn_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY, 32, rsp);
	CHECK(n > 0 && !esdm_es_ext_proto_rsp_unpack(
			       rsp, (size_t)n, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			       32, &status, &bits, &data) &&
		      !status,
	      "GET_ENTROPY: %zd", n);
	n = test_conn_request(&c, ESDM_ES_EXT_PROTO_STATUS,
			      ESDM_ES_EXT_PROTO_STATUS_MAX, rsp);
	obj = status_of(rsp, n);
	CHECK(obj, "no STATUS: %zd", n);
	str = json_str(obj, "server", "transport");
	CHECK(str && !strcmp(str, "sctp"), "the transport is %s",
	      str ? str : "missing");
	/* The peer asking: the SHA-256 of the certificate of client 1 */
	str = json_str(obj, "server", "peer");
	CHECK(str && strlen(str) == 2 * ESDM_TLS_FINGERPRINT_LEN &&
		      strspn(str, "0123456789abcdef") == strlen(str),
	      "the peer is %s", str ? str : "missing");
	if (str)
		printf("  STATUS tells the peer %s\n", str);
	json_object_put(obj);

	/* STARTDTLS inside the DTLS: no such thing on the network */
	n = test_conn_request(&c, ESDM_ES_EXT_PROTO_STARTDTLS, 0, rsp);
	CHECK(n < 0, "STARTDTLS was answered on the network: %zd", n);
	test_conn_close(&c);

	/* No client certificate, an untrusted CA */
	memset(&cfg, 0, sizeof(cfg));
	cfg.ca_file = PKI("ca.crt");
	cfg.transport = ESDM_TLS_TRANSPORT_SCTP;
	CHECK(!esdm_tls_ctx_alloc(false, &cfg, &none), "context");
	CHECK(test_conn_open(&c, "127.0.0.1", s.port, NULL, none,
			     "localhost") ||
		      test_conn_request(&c, ESDM_ES_EXT_PROTO_INFO, 0, rsp) < 0,
	      "a client without a certificate was served");
	test_conn_close(&c);
	cfg.cert_file = PKI("rogue-client.crt");
	cfg.key_file = PKI("rogue-client.key");
	cfg.ca_file = PKI("rogue-ca.crt");
	CHECK(!esdm_tls_ctx_alloc(false, &cfg, &rogue), "context");
	CHECK(test_conn_open(&c, "127.0.0.1", s.port, NULL, rogue,
			     "localhost"),
	      "a client of an untrusted CA was served");
	test_conn_close(&c);

	/* No SCTP-AUTH: the association is closed as it is accepted */
	fd = test_sctp_connect_from("127.0.0.1", s.port, NULL, false);
	CHECK(fd >= 0 && test_fd_closed(fd, 3000),
	      "an association without SCTP-AUTH was kept");
	if (fd >= 0)
		close(fd);

	/* Still serving */
	CHECK(!test_conn_open(&c, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1 after the refusals: %d", c.ret);
	test_conn_close(&c);

	server_stop(&s);
	esdm_tls_ctx_put(c1);
	esdm_tls_ctx_put(none);
	esdm_tls_ctx_put(rogue);
}

static void test_allowlist(void)
{
	static const char *const extra[] = { "--allow", "127.0.0.2/32", NULL };
	struct esdm_tls_ctx *c1 = client_of("client1");
	struct test_conn c;
	struct server s;

	printf("Provider server on the network: allowlist\n");

	CHECK(!server_start(&s, NULL, NULL, extra, NULL), "server");
	test_sleep_ms(300);

	CHECK(test_conn_open(&c, "127.0.0.1", s.port, "127.0.0.1", c1,
			     "localhost"),
	      "a client outside the allowlist was served");
	test_conn_close(&c);
	CHECK(!test_conn_open(&c, "127.0.0.1", s.port, "127.0.0.2", c1,
			      "localhost"),
	      "a client of the allowlist was refused: %d", c.ret);
	test_conn_close(&c);

	server_stop(&s);
	esdm_tls_ctx_put(c1);
}

static void test_bounds(void)
{
	static const char *const extra[] = { "--max_connections",
					     "3",
					     "--max_handshakes",
					     "2",
					     "--max_handshakes_per_source",
					     "1",
					     "--max_per_client",
					     "1",
					     NULL };
	struct esdm_tls_ctx *c1 = client_of("client1"),
			    *c2 = client_of("client2"),
			    *crev = client_of("client-revoked");
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	struct test_conn a, b, d, e;
	struct server s;
	int r1, r2, r3;

	printf("Provider server on the network: bounds\n");

	CHECK(!server_start(&s, NULL, NULL, extra, c1), "server");

	/* In their handshake: one per source, two in all */
	r1 = raw_assoc(s.port, "127.0.0.1");
	test_sleep_ms(200);
	r2 = raw_assoc(s.port, "127.0.0.1");
	CHECK(r2 < 0 || test_fd_closed(r2, 3000),
	      "a second handshake of one source was taken");
	r3 = raw_assoc(s.port, "127.0.0.2");
	test_sleep_ms(200);
	CHECK(r3 >= 0 && !test_fd_closed(r3, 300),
	      "a handshake of another source was refused");
	CHECK(test_conn_open(&d, "127.0.0.1", s.port, "127.0.0.3", c2,
			     "localhost"),
	      "a third handshake was taken");
	test_conn_close(&d);
	if (r1 >= 0)
		close(r1);
	if (r2 >= 0)
		close(r2);
	if (r3 >= 0)
		close(r3);
	test_sleep_ms(300);

	/* One connection per client */
	CHECK(!test_conn_open(&a, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1: %d", a.ret);
	CHECK(test_conn_open(&b, "127.0.0.1", s.port, NULL, c1,
			     "localhost") ||
		      test_conn_request(&b, ESDM_ES_EXT_PROTO_INFO, 0, rsp) <
			      0,
	      "a second connection of client 1 was served");
	test_conn_close(&b);

	/* Three in all */
	CHECK(!test_conn_open(&d, "127.0.0.1", s.port, NULL, c2, "localhost"),
	      "client 2: %d", d.ret);
	CHECK(!test_conn_open(&e, "127.0.0.1", s.port, NULL, crev,
			      "localhost"),
	      "a third client: %d", e.ret);
	CHECK(test_conn_open(&b, "127.0.0.1", s.port, "127.0.0.2", c2,
			     "localhost"),
	      "a fourth connection was taken");
	test_conn_close(&b);

	CHECK(test_conn_request(&a, ESDM_ES_EXT_PROTO_INFO, 0, rsp) > 0,
	      "client 1 lost its connection");
	test_conn_close(&a);
	test_conn_close(&d);
	test_conn_close(&e);

	server_stop(&s);
	esdm_tls_ctx_put(c1);
	esdm_tls_ctx_put(c2);
	esdm_tls_ctx_put(crev);
}

static void test_timeouts(void)
{
	static const char *const extra[] = { "--handshake_timeout", "1",
					     "--idle_timeout", "1", NULL };
	struct esdm_tls_ctx *c1 = client_of("client1");
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	struct test_conn c;
	struct server s;
	uint64_t start;
	int fd;

	printf("Provider server on the network: timeouts\n");

	CHECK(!server_start(&s, NULL, NULL, extra, c1), "server");

	start = test_now_ms();
	fd = raw_assoc(s.port, NULL);
	CHECK(fd >= 0 && test_fd_closed(fd, 4000),
	      "a silent handshake was not ended");
	printf("  a silent handshake ended after %llu ms\n",
	       (unsigned long long)(test_now_ms() - start));
	if (fd >= 0)
		close(fd);

	CHECK(!test_conn_open(&c, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1: %d", c.ret);
	CHECK(test_conn_request(&c, ESDM_ES_EXT_PROTO_INFO, 0, rsp) > 0,
	      "INFO");
	start = test_now_ms();
	CHECK(test_fd_closed(c.fd, 4000), "an idle connection was not closed");
	printf("  an idle connection closed after %llu ms\n",
	       (unsigned long long)(test_now_ms() - start));
	test_conn_close(&c);

	server_stop(&s);
	esdm_tls_ctx_put(c1);
}

/* Copy @from to @to through a file renamed into place */
static int copy_file(const char *from, const char *to)
{
	char tmp[600], buf[8192];
	FILE *in = fopen(from, "rb"), *out;
	size_t n;

	snprintf(tmp, sizeof(tmp), "%s.new", to);
	out = fopen(tmp, "wb");
	if (!in || !out) {
		if (in)
			fclose(in);
		if (out)
			fclose(out);
		return -1;
	}
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
		fwrite(buf, 1, n, out);
	/* Readable by the server once it dropped its privileges, as root */
	fchmod(fileno(out), 0644);
	fclose(in);
	fclose(out);
	return rename(tmp, to);
}

static void test_rotation(void)
{
	char dir[] = "/tmp/esdm-es-ext-net-test-XXXXXX";
	char cert[600], key[600], crl[600], ca[600];
	/* Copies all, readable by the server once it dropped its privileges */
	const char *extra[] = { "--crl", crl, "--ca", ca, "--reload_interval",
				"1", NULL };
	struct esdm_tls_ctx *c1 = client_of("client1"),
			    *crev = client_of("client-revoked");
	uint8_t rsp[ESDM_ES_EXT_PROTO_RSP_LEN + ESDM_ES_EXT_PROTO_MAX_RSP_DATA];
	uint8_t fp_old[ESDM_TLS_FINGERPRINT_LEN],
		fp_new[ESDM_TLS_FINGERPRINT_LEN];
	struct test_conn a, r, n;
	struct server s;
	FILE *f;

	printf("Provider server on the network: rotation and revocation\n");

	CHECK(mkdtemp(dir) && !chmod(dir, 0755), "temporary directory");
	snprintf(cert, sizeof(cert), "%s/server.crt", dir);
	snprintf(key, sizeof(key), "%s/server.key", dir);
	snprintf(crl, sizeof(crl), "%s/int.crl", dir);
	snprintf(ca, sizeof(ca), "%s/ca.crt", dir);
	CHECK(!copy_file(PKI("server.crt"), cert) &&
		      !copy_file(PKI("server.key"), key) &&
		      !copy_file(PKI("int-empty.crl"), crl) &&
		      !copy_file(PKI("ca.crt"), ca),
	      "copies of the PKI");
	chmod(key, 0644);

	CHECK(!server_start(&s, cert, key, extra, c1), "server");

	CHECK(!test_conn_open(&a, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1: %d", a.ret);
	CHECK(!esdm_tls_peer_fingerprint(esdm_dtls_tls(a.dtls), fp_old),
	      "fingerprint");
	CHECK(!test_conn_open(&r, "127.0.0.1", s.port, NULL, crev, "localhost"),
	      "the client to be revoked: %d", r.ret);

	/* Renewed, taken up by itself */
	CHECK(!copy_file(PKI("server-renewed.key"), key) &&
		      !copy_file(PKI("server-renewed.crt"), cert),
	      "renewal");
	chmod(key, 0644);
	test_sleep_ms(2500);
	CHECK(!test_conn_open(&n, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1 after the renewal: %d", n.ret);
	CHECK(!esdm_tls_peer_fingerprint(esdm_dtls_tls(n.dtls), fp_new) &&
		      memcmp(fp_old, fp_new, sizeof(fp_old)),
	      "the renewed certificate was not taken up");
	test_conn_close(&n);
	CHECK(test_conn_request(&a, ESDM_ES_EXT_PROTO_INFO, 0, rsp) > 0,
	      "the connection of the old certificate stopped working");

	/* A rotation that does not load leaves the server up */
	f = fopen(cert, "w");
	if (f) {
		fputs("-----BEGIN CERTIFICATE-----\ngarbage\n", f);
		fclose(f);
	}
	test_sleep_ms(2500);
	CHECK(!test_conn_open(&n, "127.0.0.1", s.port, NULL, c1, "localhost"),
	      "client 1 after a broken rotation: %d", n.ret);
	test_conn_close(&n);
	CHECK(!copy_file(PKI("server-renewed.crt"), cert), "repair");

	/* A CRL taken up on SIGHUP closes the connection it revokes */
	CHECK(!copy_file(PKI("int.crl"), crl), "the new CRL");
	kill(s.pid, SIGHUP);
	CHECK(test_fd_closed(r.fd, 4000),
	      "the connection of the revoked client was not closed");
	test_conn_close(&r);
	CHECK(test_conn_request(&a, ESDM_ES_EXT_PROTO_INFO, 0, rsp) > 0,
	      "the connection of client 1 was closed with the revoked one");
	CHECK(test_conn_open(&r, "127.0.0.1", s.port, NULL, crev, "localhost") ||
		      test_conn_request(&r, ESDM_ES_EXT_PROTO_INFO, 0, rsp) <
			      0,
	      "the revoked client was served again");
	test_conn_close(&r);
	test_conn_close(&a);

	server_stop(&s);
	unlink(cert);
	unlink(key);
	unlink(crl);
	unlink(ca);
	rmdir(dir);
	esdm_tls_ctx_put(c1);
	esdm_tls_ctx_put(crev);
}

static void test_options(void)
{
	char *const no_files[] = { (char *)serve_path, "--listen",
				   "127.0.0.1:0", NULL };
	char *const mixed[] = { (char *)serve_path, "--socket", "/tmp/x.sock",
				"--listen", "127.0.0.1:0", NULL };
	char *const net_without_listen[] = { (char *)serve_path, "--socket",
					     "/tmp/x.sock", "--allow",
					     "127.0.0.1", NULL };
	pid_t pid;

	printf("Provider server on the network: options refused\n");

	pid = test_daemon_start(serve_path, no_files, NULL, 0, NULL);
	CHECK(test_daemon_wait(pid, 10000) == 1,
	      "started without the TLS files");
	pid = test_daemon_start(serve_path, mixed, NULL, 0, NULL);
	CHECK(test_daemon_wait(pid, 10000) == 1,
	      "started with --socket and --listen");
	pid = test_daemon_start(serve_path, net_without_listen, NULL, 0, NULL);
	CHECK(test_daemon_wait(pid, 10000) == 1,
	      "started with an option of the network on a Unix domain socket");
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);

	if (argc != 2) {
		printf("Usage: %s <test provider>\n", argv[0]);
		return 1;
	}
	serve_path = argv[1];
	signal(SIGPIPE, SIG_IGN);

	if (!test_sctp_available())
		return 77;

	test_requests();
	test_allowlist();
	test_bounds();
	test_timeouts();
	test_rotation();
	test_options();

	printf("Provider server on the network: %s\n",
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else /* ESDM_ES_EXT_NET */

int main(void)
{
	printf("Built without es-ext-net\n");
	return 77;
}

#endif /* ESDM_ES_EXT_NET */
