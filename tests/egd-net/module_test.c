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
 * libesdm_egd_client.so and its TLS module: a process using the library on the
 * Unix domain socket or in plain TCP has no TLS stack loaded - a sandboxed one
 * would be killed for what a TLS stack does when it is loaded and unloaded,
 * see esdm_egd_client_tls.h -, and one allocating a client in TLS mode loads
 * the module, through which the client then works. Against an
 * esdm-egd-net-server, which needs no ESDM for the PID. Skips (77) in a build
 * without egd-net-tls.
 */

#include "egd_net_test.h"
#include "esdm_egd_client.h"

/* Is a mapping of a file whose name holds @needle in this process? */
static bool mapped(const char *needle)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	char line[4096];
	bool found = false;

	if (!maps)
		return false;
	while (!found && fgets(line, sizeof(line), maps)) {
		const char *path = strchr(line, '/');

		found = path && strstr(path, needle);
	}
	fclose(maps);
	return found;
}

static bool tls_stack_mapped(void)
{
	static const char *const stacks[] = { "libssl", "libcrypto",
					      "libgnutls", "libbotan",
					      "esdm-egd-tls" };
	unsigned int i;

	for (i = 0; i < sizeof(stacks) / sizeof(stacks[0]); i++) {
		if (mapped(stacks[i])) {
			printf("  %s is loaded\n", stacks[i]);
			return true;
		}
	}
	return false;
}

int main(void)
{
#ifdef ESDM_EGD_NET_TLS
	static const char *const args[] = { "--cert", PKI("server.crt"),
					    "--key", PKI("server.key"), "--ca",
					    PKI("ca.crt"), NULL };
	static const char *const plain_args[] = { "--plain", NULL };
	const char *server = getenv("ESDM_EGD_NET_SERVER");
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *unix_client = NULL, *plain = NULL, *tls = NULL;
	char *argv[16], address[64];
	uint16_t port = 0, plain_port = 0;
	int lfd, plain_lfd, ret;
	unsigned int n = 0;
	pid_t pid = 0, server_pid, plain_pid;

	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(120);

	if (test_env_check_file(server))
		return 1;

	lfd = test_listener("127.0.0.1", &port);
	plain_lfd = test_listener("127.0.0.1", &plain_port);
	if (lfd < 0 || plain_lfd < 0)
		return 1;

	argv[n++] = (char *)server;
	if (!getuid()) {
		argv[n++] = (char *)"--username";
		argv[n++] = (char *)"root";
	}
	for (ret = 0; args[ret]; ret++)
		argv[n++] = (char *)args[ret];
	argv[n] = NULL;
	server_pid = test_daemon_start(server, argv, &lfd, 1);
	n = 1 + (getuid() ? 0 : 2);
	argv[n++] = (char *)plain_args[0];
	argv[n] = NULL;
	plain_pid = test_daemon_start(server, argv, &plain_lfd, 1);

	printf("Library: no TLS stack without a TLS client\n");
	CHECK(!tls_stack_mapped(), "a TLS stack is loaded at the start");
	CHECK(!esdm_egd_client_alloc(&unix_client, "/nonexistent/egd.sock",
				     1000),
	      "no client of the Unix domain socket");
	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.mode = ESDM_EGD_CLIENT_NET_PLAIN;
	snprintf(address, sizeof(address), "127.0.0.1:%u", plain_port);
	cfg.address = address;
	CHECK(!esdm_egd_client_alloc_net(&plain, &cfg), "no plain client");
	CHECK(!esdm_egd_client_get_pid(plain, &pid) && pid == plain_pid,
	      "no PID in plain TCP");
	CHECK(!tls_stack_mapped(),
	      "a TLS stack is loaded for the Unix domain socket and plain TCP");

	printf("Library: the TLS module for a TLS client\n");
	cfg.mode = ESDM_EGD_CLIENT_NET_TLS;
	snprintf(address, sizeof(address), "127.0.0.1:%u", port);
	cfg.cert_file = PKI("client1.crt");
	cfg.key_file = PKI("client1.key");
	cfg.ca_file = PKI("ca.crt");
	cfg.server_name = "localhost";
	ret = esdm_egd_client_alloc_net(&tls, &cfg);
	CHECK(!ret, "no TLS client: %d", ret);
	CHECK(mapped("esdm-egd-tls"), "the TLS module is not loaded");
	ret = esdm_egd_client_get_pid(tls, &pid);
	CHECK(!ret && pid == server_pid, "no PID over TLS: %d", ret);

	esdm_egd_client_free(tls);
	esdm_egd_client_free(plain);
	esdm_egd_client_free(unix_client);
	CHECK(test_daemon_stop(server_pid) == 0, "the server did not stop");
	CHECK(test_daemon_stop(plain_pid) == 0, "the server did not stop");
	close(lfd);
	close(plain_lfd);

	printf("EGD client TLS module: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
#else
	(void)failures;
	printf("Built without egd-net-tls\n");
	return 77;
#endif
}
