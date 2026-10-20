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
 * An external entropy source on the network, end to end: the esdm-server
 * reads its ExternalSocket source from the provider socket of the
 * esdm-es-ext-relay, which forwards over TCP with TLS and certificates to
 * the provider program of the rated test source.
 *
 *  - the source is connected, shown under the name the remote provider
 *    declares and credited at the rate it declares;
 *  - its status in the ESDM is the one of the remote server - transport
 *    "tcp" - and of the remote source, passed through;
 *  - it delivers - with the ESDM's privileges dropped, as the relay serves
 *    the user nobody next to root;
 *  - the remote provider restarted between two seedings: the next one is
 *    served by it again, the relay connecting anew.
 *
 * Skipped (77) unless run as root, as the esdm-server refuses to start
 * otherwise, and in a build without es-ext-net.
 * The daemon claims the fixed socket, semaphore and IPC names, so the test
 * puts itself in namespaces of its own.
 *
 * Usage: es_ext_net_esdm_test <esdm-server> <esdm-es-ext-relay>
 *			       <rated test provider>
 */

#define _GNU_SOURCE
#include "config.h"

#include <json-c/json.h>
#include <sys/stat.h>

#include "es_ext_net_test.h"
#include "esdm_logger.h"
#include "esdm_rpc_client.h"

#include "../es_ext/es_ext_test_plugin.h"
#include "../es_ext/es_ext_test_util.h"
#include "../test_namespace.h"

#if defined(ESDM_ES_EXT_NET) && ESDM_EXT_SOCKET_NUM > 0

#if ESDM_EXT_SOCKET_NUM > 1
#define TEST_EXTSOCK "ExternalSocket0"
#else
#define TEST_EXTSOCK "ExternalSocket"
#endif

/* How long the daemons are given to come up */
#define TEST_START_SEC 30

static char test_dir[] = "/tmp/esdm-es-ext-net-esdm-test-XXXXXX";
static char test_socket[sizeof(test_dir) + 32];

static const char *server_path, *relay_path, *serve_path;

/* The provider on 127.0.0.1:*@port, picked by the kernel if 0 */
static pid_t serve_start(uint16_t *port)
{
	char *argv[] = { (char *)serve_path, "--cert", PKI("server.crt"),
			 "--key", PKI("server.key"), "--ca", PKI("ca.crt"),
			 NULL };
	struct sockaddr_storage ss;
	int lfd, one = 1;
	pid_t pid;

	if (!*port) {
		lfd = test_tcp_listener("127.0.0.1", port);
	} else {
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

	pid = test_daemon_start(serve_path, argv, &lfd, 1, NULL);
	close(lfd);
	test_sleep_ms(300);
	return pid;
}

/* The JSON status of the ESDM, once it answers */
static struct json_object *esdm_status(void)
{
	static char status[65536];
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 10; i++) {
		memset(status, 0, sizeof(status));
		if (!esdm_rpcc_status_json(status, sizeof(status)))
			return json_tokener_parse(status);
		test_sleep_ms(100);
	}

	return NULL;
}

static const char *json_str(struct json_object *obj, const char *key)
{
	struct json_object *v;

	if (!obj || !json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

static int64_t json_int(struct json_object *obj, const char *key)
{
	struct json_object *v;

	if (!obj || !json_object_object_get_ex(obj, key, &v) ||
	    !json_object_is_type(v, json_type_int))
		return -1;
	return json_object_get_int64(v);
}

/* The source as the ESDM shows it, once it is connected */
static struct json_object *source_connected(struct json_object **root)
{
	struct json_object *es = NULL;
	unsigned int i;

	for (i = 0; i < TEST_START_SEC * 2; i++) {
		const char *status;

		json_object_put(*root);
		*root = esdm_status();
		es = es_ext_test_status_es(*root, TEST_EXTSOCK);
		status = json_str(es, "status");
		if (status && strstr(status, "connected") &&
		    !strstr(status, "not connected"))
			return es;
		test_sleep_ms(500);
	}

	return es;
}

static void test_esdm(void)
{
	char connect[64];
	char *relay_argv[] = {
		(char *)relay_path, "--connect", connect, "--server_name",
		"localhost", "--socket", test_socket, "--cert",
		PKI("client1.crt"), "--key", PKI("client1.key"), "--ca",
		PKI("ca.crt"), "-vv", NULL
	};
	char *server_argv[] = { (char *)server_path, "-f", "--es_ext_socket",
				test_socket, NULL };
	struct json_object *root = NULL, *es, *provider, *server;
	static uint8_t seed[8192];
	uint16_t port = 0;
	pid_t serve, relay, esdm;

	printf("The ESDM reading a provider on the network\n");

	serve = serve_start(&port);
	snprintf(connect, sizeof(connect), "127.0.0.1:%u", port);
	relay = test_daemon_start(relay_path, relay_argv, NULL, 0, NULL);
	CHECK(serve > 0 && relay > 0 && es_ext_test_wait_socket(test_socket),
	      "the provider and the relay did not come up");

	esdm = test_daemon_start(server_path, server_argv, NULL, 0, NULL);
	CHECK(esdm > 0, "cannot start %s", server_path);

	es = source_connected(&root);
	CHECK(es, "the status lists no " TEST_EXTSOCK " source");
	printf("  %s\n", json_object_to_json_string(es));
	CHECK(json_str(es, "name") &&
		      !strcmp(json_str(es, "name"), ES_EXT_TEST_RATED_NAME),
	      "the source is not shown under the name of the remote provider");
	CHECK(json_int(es, "entropy_rate") == ES_EXT_TEST_RATED_RATE &&
		      json_str(es, "entropy_rate_source") &&
		      !strcmp(json_str(es, "entropy_rate_source"),
			      "provider"),
	      "the source is not credited at the rate the remote provider declares");
	CHECK(json_object_object_get_ex(es, "provider", &provider) &&
		      json_object_object_get_ex(provider, "server", &server) &&
		      json_str(server, "transport") &&
		      !strcmp(json_str(server, "transport"), "tcp") &&
		      json_object_object_get_ex(provider, "plugin", &server) &&
		      json_object_is_type(server, json_type_object),
	      "the status of the remote provider is not passed through");

	/* With its privileges dropped */
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the remote provider");

	/* The remote provider restarted between two seedings */
	test_daemon_stop(serve);
	test_sleep_ms(500);
	serve = serve_start(&port);
	CHECK(serve > 0, "restart");
	/* After the retry interval of the source, if the connection failed */
	test_sleep_ms(6000);
	CHECK(esdm_rpcc_get_seed(seed, sizeof(seed), 0) > 0,
	      "no seed with the remote provider back");
	es = source_connected(&root);
	CHECK(es && json_str(es, "name") &&
		      !strcmp(json_str(es, "name"), ES_EXT_TEST_RATED_NAME),
	      "the remote provider back is not connected again");

	json_object_put(root);
	test_daemon_stop(esdm);
	test_daemon_stop(relay);
	test_daemon_stop(serve);
}

int main(int argc, char *argv[])
{
	int ret;

	setvbuf(stdout, NULL, _IOLBF, 0);
	esdm_logger_set_verbosity(LOGGER_WARN);

	if (argc != 4) {
		printf("Usage: %s <esdm-server> <esdm-es-ext-relay> <rated test provider>\n",
		       argv[0]);
		return 1;
	}
	server_path = argv[1];
	relay_path = argv[2];
	serve_path = argv[3];
	signal(SIGPIPE, SIG_IGN);

	if (getuid()) {
		printf("Program must be started as root\n");
		return 77;
	}
	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return 1;
	}

	/* Traversable for the daemons once they dropped their privileges */
	if (!mkdtemp(test_dir) || chmod(test_dir, 0755)) {
		printf("Cannot create the directory: %s\n", strerror(errno));
		return 1;
	}
	snprintf(test_socket, sizeof(test_socket), "%s/relay.socket",
		 test_dir);

	if (esdm_rpcc_init_unpriv_service(NULL)) {
		printf("Cannot set up the RPC client\n");
		return 1;
	}

	test_esdm();

	esdm_rpcc_fini_unpriv_service();
	unlink(test_socket);
	rmdir(test_dir);

	printf("The ESDM reading a provider on the network: %s\n",
	       failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}

#else

int main(void)
{
	printf("Built without es-ext-net, or without an ExternalSocket source\n");
	return 77;
}

#endif
