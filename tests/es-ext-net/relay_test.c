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
 * The esdm-es-ext-relay between a client of its local provider socket -
 * speaking the protocol as the ESDM does - and the provider program of the
 * rated test source on the network:
 *
 *  - every request forwarded one to one, in the clear and inside the local
 *    DTLS: INFO with the name and the rate of the remote provider, SELFTEST,
 *    GET_ENTROPY, STATUS of the remote server - its transport, and the relay
 *    as the peer asking;
 *  - INFO first: a client asking anything else first is closed;
 *  - the remote provider restarted between two requests, declaring another
 *    name: the local connection is closed, and a new one gets the new name;
 *  - the remote provider gone: INFO answered with an errno at once, and the
 *    connection closed;
 *  - a remote provider too slow for the timeout of the relay: the request
 *    answered with an errno in time;
 *  - a provider of another name than the relay expects: refused.
 *
 * Needs no privileges. Skips (77) in a build without es-ext-net.
 *
 * Usage: es_ext_net_relay_test <esdm-es-ext-relay> <rated test provider>
 */

#define _GNU_SOURCE
#include "config.h"

#include <json-c/json.h>
#include <sys/stat.h>

#include "es_ext_net_test.h"
#include "esdm_logger.h"

#include "../es_ext/es_ext_test_client.h"
#include "../es_ext/es_ext_test_plugin.h"
#include "../es_ext/es_ext_test_util.h"

#ifdef ESDM_ES_EXT_NET

static const char *relay_path;
static const char *serve_path;

static char test_dir[] = "/tmp/esdm-es-ext-relay-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

/*
 * Start the provider on 127.0.0.1:@port - 0 for a port picked by the kernel,
 * *@port receives it - with the settings @settings of the test source and the
 * options @extra, NULL-terminated.
 */
static pid_t serve_start(uint16_t *port, const char *settings,
			 const char *const *extra)
{
	char *argv[32], env[256];
	struct sockaddr_storage ss;
	unsigned int n = 0;
	int lfd, one = 1;
	pid_t pid;

	if (!*port) {
		lfd = test_tcp_listener("127.0.0.1", port);
	} else {
		/* The same port again, for a restarted provider */
		socklen_t len = test_sockaddr("127.0.0.1", *port, &ss);

		lfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC,
			     IPPROTO_TCP);
		if (lfd >= 0) {
			setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one,
				   sizeof(one));
			if (bind(lfd, (struct sockaddr *)&ss, len) < 0 ||
			    listen(lfd, 16) < 0) {
				close(lfd);
				lfd = -1;
			}
		}
	}
	if (lfd < 0)
		return -1;

	argv[n++] = (char *)serve_path;
	argv[n++] = "--cert";
	argv[n++] = PKI("server.crt");
	argv[n++] = "--key";
	argv[n++] = PKI("server.key");
	argv[n++] = "--ca";
	argv[n++] = PKI("ca.crt");
	while (extra && *extra && n < sizeof(argv) / sizeof(argv[0]) - 1)
		argv[n++] = (char *)*extra++;
	argv[n] = NULL;

	snprintf(env, sizeof(env), "%s=%s", ES_EXT_TEST_PLUGIN_ENV,
		 settings ? settings : "");
	pid = test_daemon_start(serve_path, argv, &lfd, 1,
				settings ? env : NULL);
	close(lfd);
	/* Serving once it set itself up: a moment */
	test_sleep_ms(300);
	return pid;
}

/* Start the relay to 127.0.0.1:@port, expecting the server @name */
static pid_t relay_start(uint16_t port, const char *name,
			 const char *const *extra)
{
	char *argv[40], connect[64], uid[16];
	unsigned int n = 0;
	pid_t pid;

	snprintf(connect, sizeof(connect), "127.0.0.1:%u", port);
	snprintf(uid, sizeof(uid), "%u", (unsigned int)getuid());
	argv[n++] = (char *)relay_path;
	argv[n++] = "--connect";
	argv[n++] = connect;
	argv[n++] = "--server_name";
	argv[n++] = (char *)name;
	argv[n++] = "--socket";
	argv[n++] = test_socket;
	argv[n++] = "--client_uid";
	argv[n++] = uid;
	argv[n++] = "--cert";
	argv[n++] = PKI("client1.crt");
	argv[n++] = "--key";
	argv[n++] = PKI("client1.key");
	argv[n++] = "--ca";
	argv[n++] = PKI("ca.crt");
	argv[n++] = "-vv";
	while (extra && *extra && n < sizeof(argv) / sizeof(argv[0]) - 1)
		argv[n++] = (char *)*extra++;
	argv[n] = NULL;

	unlink(test_socket);
	pid = test_daemon_start(relay_path, argv, NULL, 0, NULL);
	if (pid > 0 && !es_ext_test_wait_socket(test_socket)) {
		test_daemon_stop(pid);
		return -1;
	}
	return pid;
}

/* INFO through the relay: its status, and the name declared */
static int relay_info(struct es_ext_test_client *c, char *name, size_t len,
		      uint32_t *rate)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	const char *n;
	size_t nlen;
	int32_t status;
	ssize_t got;

	name[0] = '\0';
	got = es_ext_test_client_request(c, ESDM_ES_EXT_PROTO_INFO, 0, rsp,
					 sizeof(rsp));
	if (got <= 0)
		return got ? (int)got : -ECONNRESET;
	if (esdm_es_ext_proto_info_unpack(rsp, (size_t)got, &status, rate, &n,
					  &nlen))
		return -EPROTO;
	if (status)
		return status;
	snprintf(name, len, "%.*s", (int)nlen, n);
	return 0;
}

/* Is the local connection closed by the relay within @ms? */
static bool local_closed(struct es_ext_test_client *c, unsigned int ms)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	uint64_t end = test_now_ms() + ms;

	while (test_now_ms() < end) {
		struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
		ssize_t n;

		if (poll(&pfd, 1, 50) <= 0)
			continue;
		n = recv(c->fd, rsp, sizeof(rsp), MSG_DONTWAIT);
		if (n == 0 || (n < 0 && errno != EAGAIN))
			return true;
	}
	return false;
}

static void test_forwarding(uint16_t port, bool dtls)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	struct es_ext_test_client c;
	struct json_object *obj, *v;
	const uint8_t *data;
	const char *text;
	char name[64];
	size_t textlen;
	uint32_t rate = 0, bits;
	int32_t status;
	ssize_t n;

	printf("Relay: forwarding, %s\n", dtls ? "local DTLS" : "in the clear");

	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	CHECK(!relay_info(&c, name, sizeof(name), &rate) &&
		      !strcmp(name, ES_EXT_TEST_RATED_NAME) &&
		      rate == ES_EXT_TEST_RATED_RATE,
	      "INFO: %s, %u", name, rate);

	n = es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_SELFTEST, 0, rsp,
				       sizeof(rsp));
	CHECK(n > 0 && !esdm_es_ext_proto_rsp_unpack(
			       rsp, (size_t)n, ESDM_ES_EXT_PROTO_SELFTEST, 0,
			       &status, &bits, &data) &&
		      !status,
	      "SELFTEST: %zd", n);

	n = es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY, 48,
				       rsp, sizeof(rsp));
	CHECK(n > 0 && !esdm_es_ext_proto_rsp_unpack(
			       rsp, (size_t)n, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			       48, &status, &bits, &data) &&
		      !status && bits <= 48 * 8,
	      "GET_ENTROPY: %zd", n);

	n = es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_STATUS,
				       ESDM_ES_EXT_PROTO_STATUS_MAX, rsp,
				       sizeof(rsp));
	obj = NULL;
	text = NULL;
	textlen = 0;
	if (n > 0 && !esdm_es_ext_proto_status_unpack(
			     rsp, (size_t)n, ESDM_ES_EXT_PROTO_STATUS_MAX,
			     &status, &text, &textlen) &&
	    !status) {
		char json[ESDM_ES_EXT_PROTO_STATUS_MAX + 1];

		/* Not terminated in the answer */
		snprintf(json, sizeof(json), "%.*s", (int)textlen, text);
		obj = json_tokener_parse(json);
	}
	CHECK(obj && json_object_object_get_ex(obj, "server", &v) &&
		      json_object_object_get_ex(v, "transport", &v) &&
		      !strcmp(json_object_get_string(v), "tcp"),
	      "STATUS of the remote server: %.*s", (int)textlen,
	      text ? text : "");
	CHECK(obj && json_object_object_get_ex(obj, "server", &v) &&
		      json_object_object_get_ex(v, "peer", &v) &&
		      strlen(json_object_get_string(v)) == 64,
	      "STATUS tells no peer");
	CHECK(obj && json_object_object_get_ex(obj, "plugin", &v) &&
		      json_object_is_type(v, json_type_object),
	      "STATUS of the remote source is missing");
	json_object_put(obj);

	es_ext_test_client_close(&c);

	/* Something but INFO first: closed */
	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	n = es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY, 32,
				       rsp, sizeof(rsp));
	CHECK(n <= 0, "a request before INFO was answered");
	es_ext_test_client_close(&c);
	(void)port;
}

static void test_restart(pid_t *serve, uint16_t port, bool dtls)
{
	static const char *const renamed[] = { "--name", "es-ext-renamed",
					       NULL };
	struct es_ext_test_client c;
	char name[64];
	uint32_t rate;
	uint64_t start;
	int ret;

	printf("Relay: the provider restarted and gone, %s\n",
	       dtls ? "local DTLS" : "in the clear");

	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	CHECK(!relay_info(&c, name, sizeof(name), &rate), "INFO");

	/* Restarted between two requests, with another name */
	test_daemon_stop(*serve);
	CHECK(local_closed(&c, 5000),
	      "the local connection outlived the upstream one");
	es_ext_test_client_close(&c);
	*serve = serve_start(&port, NULL, renamed);
	CHECK(*serve > 0, "restart");
	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	CHECK(!relay_info(&c, name, sizeof(name), &rate) &&
		      !strcmp(name, "es-ext-renamed"),
	      "INFO after the restart: %s", name);
	es_ext_test_client_close(&c);

	/* Gone: INFO answered with an errno at once, then closed */
	test_daemon_stop(*serve);
	*serve = 0;
	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	start = test_now_ms();
	ret = relay_info(&c, name, sizeof(name), &rate);
	CHECK(ret < 0 && ret != -ECONNRESET && ret != -ETIMEDOUT,
	      "INFO with the provider gone: %d", ret);
	CHECK(test_now_ms() - start < 2000,
	      "the answer took %llu ms, longer than the ESDM waits",
	      (unsigned long long)(test_now_ms() - start));
	printf("  with the provider gone, INFO is answered with %s\n",
	       strerror(-ret));
	CHECK(local_closed(&c, 3000), "the local connection stayed");
	es_ext_test_client_close(&c);

	*serve = serve_start(&port, NULL, NULL);
	CHECK(*serve > 0, "restart");
	CHECK(!es_ext_test_client_open(&c, test_socket, dtls),
	      "no local connection");
	CHECK(!relay_info(&c, name, sizeof(name), &rate) &&
		      !strcmp(name, ES_EXT_TEST_RATED_NAME),
	      "INFO with the provider back: %s", name);
	es_ext_test_client_close(&c);
}

static void test_slow_and_wrong(void)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	struct es_ext_test_client c;
	const uint8_t *data;
	uint16_t port = 0;
	char name[64];
	uint32_t rate, bits;
	int32_t status = 0;
	uint64_t start;
	pid_t serve, relay;
	ssize_t n;

	printf("Relay: a slow provider, and one of another name\n");

	/* Slower than the timeout of the relay */
	serve = serve_start(&port, "get_delay_ms=4000", NULL);
	relay = relay_start(port, "localhost", NULL);
	CHECK(serve > 0 && relay > 0, "daemons");
	CHECK(!es_ext_test_client_open(&c, test_socket, false),
	      "no local connection");
	CHECK(!relay_info(&c, name, sizeof(name), &rate), "INFO");
	start = test_now_ms();
	n = es_ext_test_client_request(&c, ESDM_ES_EXT_PROTO_GET_ENTROPY, 32,
				       rsp, sizeof(rsp));
	CHECK(n > 0 && !esdm_es_ext_proto_rsp_unpack(
			       rsp, (size_t)n, ESDM_ES_EXT_PROTO_GET_ENTROPY,
			       32, &status, &bits, &data) &&
		      status == -ETIMEDOUT,
	      "a slow request: %zd, %d", n, status);
	CHECK(test_now_ms() - start < 2000, "the answer took %llu ms",
	      (unsigned long long)(test_now_ms() - start));
	es_ext_test_client_close(&c);
	test_daemon_stop(relay);
	/* Still in the source, which holds up its server */
	test_daemon_stop(serve);

	/* The relay expects another name than the provider's certificate's */
	serve = serve_start(&port, NULL, NULL);
	relay = relay_start(port, "wrong.example", NULL);
	CHECK(relay > 0, "relay");
	CHECK(!es_ext_test_client_open(&c, test_socket, false),
	      "no local connection");
	CHECK(relay_info(&c, name, sizeof(name), &rate) < 0,
	      "a provider of another name was taken");
	es_ext_test_client_close(&c);
	test_daemon_stop(relay);
	test_daemon_stop(serve);
}

/* Copy @src to @dst, by renaming a copy into its place */
static int install_file(const char *src, const char *dst)
{
	char tmp[256], buf[8192];
	int in, out;
	ssize_t n;

	snprintf(tmp, sizeof(tmp), "%s.new", dst);
	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -1;
	out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, (size_t)n) != n) {
			n = -1;
			break;
		}
	}
	close(in);
	close(out);
	if (n < 0)
		return -1;
	return rename(tmp, dst);
}

/*
 * The CRLs taken up while the handshake with the provider runs: the handshake
 * was begun with the context before, whose CRL did not revoke the provider -
 * the one in place once it completes does. The provider is held up by
 * SIGSTOP: its kernel takes the association, and the handshake waits for it.
 * Then an established upstream connection, closed by a reload revoking it.
 */
static void test_revocation(void)
{
	uint8_t rsp[ES_EXT_TEST_CLIENT_RSP_MAX];
	char crl[sizeof(test_dir) + 16];
	/*
	 * Root keeps root, so that the relay reads the files of the test
	 * again on a reload - nobody may not
	 */
	const char *const extra[] = { "--crl",
				      crl,
				      "--reload_interval",
				      "0",
				      "--timeout_ms",
				      "8000",
				      getuid() ? NULL : "--username",
				      "root",
				      NULL };
	uint8_t req[ESDM_ES_EXT_PROTO_REQ_LEN];
	struct es_ext_test_client c;
	const char *name;
	char info[64];
	uint16_t port = 0;
	size_t namelen;
	uint32_t rate;
	int32_t status = 0;
	pid_t serve, relay;
	ssize_t n;

	printf("Relay: revocation of the provider, during its handshake and after\n");

	snprintf(crl, sizeof(crl), "%s/crl.pem", test_dir);
	CHECK(!install_file(PKI("ca.crl"), crl), "installing the CRL");
	serve = serve_start(&port, NULL, NULL);
	relay = relay_start(port, "localhost", extra);
	CHECK(serve > 0 && relay > 0, "daemons");

	/* INFO waits for the handshake, while the CRL revoking it is loaded */
	kill(serve, SIGSTOP);
	CHECK(!es_ext_test_client_open(&c, test_socket, false),
	      "no local connection");
	esdm_es_ext_proto_req_pack(req, ESDM_ES_EXT_PROTO_INFO, 0);
	CHECK(!es_ext_test_client_send(&c, req, sizeof(req)), "sending INFO");
	test_sleep_ms(500);
	CHECK(!install_file(PKI("ca-revoked-server.crl"), crl),
	      "installing the CRL revoking the provider");
	kill(relay, SIGHUP);
	test_sleep_ms(1000);
	kill(serve, SIGCONT);

	n = es_ext_test_client_recv(&c, rsp, sizeof(rsp));
	CHECK(n > 0 && !esdm_es_ext_proto_info_unpack(rsp, (size_t)n, &status,
						      &rate, &name, &namelen) &&
		      status < 0,
	      "a provider revoked during its handshake was taken: %zd, %d",
	      n, status);
	CHECK(local_closed(&c, 3000), "the local connection stayed");
	es_ext_test_client_close(&c);

	/* Established, and revoked by the next reload */
	CHECK(!install_file(PKI("ca.crl"), crl), "installing the CRL");
	kill(relay, SIGHUP);
	test_sleep_ms(1000);
	CHECK(!es_ext_test_client_open(&c, test_socket, false),
	      "no local connection");
	CHECK(!relay_info(&c, info, sizeof(info), &rate),
	      "INFO with the provider no longer revoked");
	CHECK(!install_file(PKI("ca-revoked-server.crl"), crl),
	      "installing the CRL revoking the provider");
	kill(relay, SIGHUP);
	CHECK(local_closed(&c, 5000),
	      "the connection to a revoked provider was kept");
	es_ext_test_client_close(&c);

	test_daemon_stop(relay);
	test_daemon_stop(serve);
	unlink(crl);
}

int main(int argc, char *argv[])
{
	uint16_t port = 0;
	pid_t serve, relay;
	unsigned int dtls;

	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);

	if (argc != 3) {
		printf("Usage: %s <esdm-es-ext-relay> <rated test provider>\n",
		       argv[0]);
		return 1;
	}
	relay_path = argv[1];
	serve_path = argv[2];
	signal(SIGPIPE, SIG_IGN);

	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("Cannot create the directory: %s\n", strerror(errno));
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/relay.socket",
		 test_dir);

	serve = serve_start(&port, NULL, NULL);
	relay = relay_start(port, "localhost", NULL);
	CHECK(serve > 0 && relay > 0, "the daemons are not up");

	for (dtls = 0; dtls < 2; dtls++) {
#ifndef ESDM_DTLS
		if (dtls)
			continue;
#endif
		test_forwarding(port, dtls);
		test_restart(&serve, port, dtls);
	}

	CHECK(test_daemon_stop(relay) == 0,
	      "the relay did not end cleanly on SIGTERM");
	test_daemon_stop(serve);

	test_slow_and_wrong();
	test_revocation();

	unlink(test_socket);
	rmdir(test_dir);

	printf("Relay: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else /* ESDM_ES_EXT_NET */

int main(void)
{
	printf("Built without es-ext-net\n");
	return 77;
}

#endif /* ESDM_ES_EXT_NET */
