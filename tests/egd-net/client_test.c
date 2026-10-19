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
 * The network modes of libesdm_egd_client against a server the test plays: a
 * connection the server closed - as it closes one that was idle for long - is
 * replaced rather than used for the next request. An insertion is not
 * answered, and one written into the closed connection would be lost without
 * anybody noticing.
 *
 * The server played here ends its side of the connection only, and keeps the
 * socket: what the client still writes into it is taken by the kernel and
 * never read, as with a server that closed for good the data written before
 * its reset arrives - which on the loopback arrives before the second write
 * of the client already, and on a network does not.
 */

#include "egd_net_test.h"
#include "esdm_egd_client.h"

#include <pthread.h>

#ifndef ESDM_EGD_NET_TLS
/* What the server side needs of struct test_tls, without the TLS */
struct test_tls {
	int fd;
};

static inline void test_tls_close(struct test_tls *t)
{
	if (t->fd >= 0)
		close(t->fd);
	t->fd = -1;
}
#endif

/* An insertion of 16 bytes: the command, the entropy claim, the length */
#define REQUEST_LEN (4 + 16)

/* The server played here */
struct fake {
	int lfd;
	uint16_t port;
	bool tls;
	struct esdm_tls_ctx *ctx;

	/* Connections it accepted, and the requests of its second one */
	unsigned int accepted;
	uint8_t got[2][REQUEST_LEN];
	int result;
};

/* The next connection within @ms, -1 if none comes */
static int fake_accept(struct fake *f, unsigned int ms)
{
	struct pollfd pfd = { .fd = f->lfd, .events = POLLIN };
	int fd;

	if (poll(&pfd, 1, (int)ms) != 1)
		return -1;
	fd = accept4(f->lfd, NULL, NULL, SOCK_CLOEXEC);
	if (fd >= 0)
		f->accepted++;
	return fd;
}

/* Accept a connection, and in TLS shake hands on it */
static int fake_open(struct fake *f, struct test_tls *t)
{
	memset(t, 0, sizeof(*t));
	t->fd = fake_accept(f, TEST_IO_MS);
	if (t->fd < 0)
		return -ETIMEDOUT;

#ifdef ESDM_EGD_NET_TLS
	if (f->tls) {
		uint64_t end = test_now_ms() + TEST_IO_MS;
		int ret;

		if (esdm_tls_alloc(f->ctx, t->fd, NULL, &t->tls))
			return -ENOMEM;
		while ((ret = esdm_tls_handshake(t->tls)) == -EAGAIN) {
			if (test_now_ms() >= end)
				return -ETIMEDOUT;
			esdm_tls_wait(t->tls, 100);
		}
		return ret;
	}
#endif

	return 0;
}

static int fake_read(struct fake *f, struct test_tls *t, uint8_t *buf,
		     size_t len)
{
#ifdef ESDM_EGD_NET_TLS
	if (f->tls)
		return test_tls_recv(t, buf, len, TEST_IO_MS);
#else
	(void)f;
#endif
	return test_recv(t->fd, buf, len) ? -EIO : 0;
}

static void *fake_server(void *arg)
{
	struct fake *f = arg;
	struct test_tls idle, t;
	int ret;

	/* The first connection, ended as one that was idle for long is */
	ret = fake_open(f, &idle);
#ifdef ESDM_EGD_NET_TLS
	if (!ret && f->tls)
		esdm_tls_close_notify(idle.tls);
#endif
	if (!ret)
		shutdown(idle.fd, SHUT_WR);
	if (ret) {
		f->result = ret;
		test_tls_close(&idle);
		return NULL;
	}

	/* The second one, which both insertions have to arrive on */
	ret = fake_open(f, &t);
	if (!ret)
		ret = fake_read(f, &t, f->got[0], sizeof(f->got[0]));
	if (!ret)
		ret = fake_read(f, &t, f->got[1], sizeof(f->got[1]));
	f->result = ret;
	test_tls_close(&t);
	test_tls_close(&idle);

	return NULL;
}

static void test_reconnect(bool tls)
{
	struct esdm_egd_client_net_config cfg;
	struct esdm_egd_client *client = NULL;
	struct pollfd pfd;
	struct fake f;
	pthread_t thread;
	uint8_t data[16];
	char address[64];
	unsigned int i;
	int ret;

	printf("Client (%s): a connection the server closed is replaced\n",
	       tls ? "TLS" : "plain TCP");

	memset(&f, 0, sizeof(f));
	f.tls = tls;
	f.lfd = test_listener("127.0.0.1", &f.port);
	if (f.lfd < 0) {
		CHECK(0, "no listener");
		return;
	}

#ifdef ESDM_EGD_NET_TLS
	if (tls) {
		struct esdm_tls_config scfg;

		memset(&scfg, 0, sizeof(scfg));
		scfg.cert_file = PKI("server.crt");
		scfg.key_file = PKI("server.key");
		scfg.ca_file = PKI("ca.crt");
		ret = esdm_tls_ctx_alloc(true, &scfg, &f.ctx);
		CHECK(!ret, "no server context: %d", ret);
		if (ret) {
			close(f.lfd);
			return;
		}
	}
#endif

	if (pthread_create(&thread, NULL, fake_server, &f)) {
		CHECK(0, "no thread");
		close(f.lfd);
		return;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sizeof(cfg);
	cfg.mode = tls ? ESDM_EGD_CLIENT_NET_TLS : ESDM_EGD_CLIENT_NET_PLAIN;
	snprintf(address, sizeof(address), "127.0.0.1:%u", f.port);
	cfg.address = address;
	cfg.timeout_ms = 5000;
	if (tls) {
		cfg.cert_file = PKI("client1.crt");
		cfg.key_file = PKI("client1.key");
		cfg.ca_file = PKI("ca.crt");
		cfg.server_name = "localhost";
	}
	ret = esdm_egd_client_alloc_net(&client, &cfg);
	CHECK(!ret, "no client: %d", ret);

	/* The server closed the connection meanwhile */
	test_sleep_ms(300);

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)i;
	ret = esdm_egd_client_write_entropy(client, data, sizeof(data), 8);
	CHECK(!ret, "the first insertion failed: %d", ret);
	data[0] = 0xff;
	ret = esdm_egd_client_write_entropy(client, data, sizeof(data), 8);
	CHECK(!ret, "the second insertion failed: %d", ret);

	pthread_join(thread, NULL);
	CHECK(!f.result, "the insertions did not arrive: %d", f.result);
	CHECK(f.got[0][0] == ESDM_EGD_CMD_WRITE_ENTROPY && f.got[0][2] == 8 &&
		      f.got[0][3] == 16 && f.got[0][4] == 0 &&
		      f.got[1][0] == ESDM_EGD_CMD_WRITE_ENTROPY &&
		      f.got[1][4] == 0xff,
	      "the insertions arrived garbled");
	CHECK(f.accepted == 2,
	      "the client connected %u times rather than twice", f.accepted);

	/* Nor does it connect again: the second connection was reused */
	pfd.fd = f.lfd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	CHECK(poll(&pfd, 1, 200) == 0, "the client connected a third time");

	esdm_egd_client_free(client);
#ifdef ESDM_EGD_NET_TLS
	esdm_tls_ctx_put(f.ctx);
#endif
	close(f.lfd);
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(120);

	test_reconnect(false);
#ifdef ESDM_EGD_NET_TLS
	test_reconnect(true);
#else
	printf("Built without egd-net-tls, the TLS mode is not tested\n");
#endif

	printf("EGD network client: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
