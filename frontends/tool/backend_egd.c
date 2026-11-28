/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The backend of esdm-tool for the EGD interface, see backend.h: the one of a
 * build without the RPC interface (meson option esdm-server-rpc). It carries
 * out what the EGD protocol with the extensions of the ESDM can express, see
 * esdm_egd_protocol.h, through libesdm_egd_client. The commands of the tool it
 * cannot express are refused by main() with what tool_be_missing() says.
 *
 * There is one socket for all commands. The ESDM carries out the privileged
 * ones for a peer connected as root, which is what the tool insists on for
 * them in any case.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <esdm_egd_client.h>
#include <esdm_egd_protocol.h>

#include "backend.h"
#include "config.h"
#include "memset_secure.h"
#include "tool.h"

/* Environment variable naming the socket, as libesdm_egd_client reads it */
#define TOOL_BE_SOCKET_ENV "ESDM_EGD_SOCKET"

/* Pause between two reads that do not wait, see the read with a timeout */
#define TOOL_BE_POLL_NS 20000000

/* The largest status report and its NUL; a read is one bulk read at most */
const size_t tool_be_max_data = ESDM_EGD_MAX_STATUS + 1;

const char *tool_be_missing(void)
{
	return "the RPC interface, which is not part of this build (meson option esdm-server-rpc)";
}

/*
 * The socket of the server: the one the environment names, else the one a
 * server of this build serves when it is given none.
 */
static const char *tool_be_socket(void)
{
	const char *path = secure_getenv(TOOL_BE_SOCKET_ENV);

	return (path && *path) ? path : ESDM_EGD_DEFAULT_SOCKET;
}

void tool_be_usage(void)
{
	fprintf(stderr,
		"\nThis esdm-tool is built without the RPC interface and works over the EGD\n");
	fprintf(stderr,
		"interface of the ESDM server, on the socket the environment variable\n");
	fprintf(stderr, "%s names (default: %s).\n", TOOL_BE_SOCKET_ENV,
		ESDM_EGD_DEFAULT_SOCKET);
	fprintf(stderr,
		"Not available over this interface: --drng-status, --drng-status-json,\n");
	fprintf(stderr,
		"--jent-status, --get-seed, --selftest, --set-es-rate, --stress-init-fini.\n");
}

const char *const *tool_be_sockets(void)
{
	static const char *sockets[2];

	sockets[0] = tool_be_socket();
	sockets[1] = NULL;

	return sockets;
}

/*
 * A client is one connection and serializes its requests. Each thread has one
 * of its own, so that the threads of the stress modes load the server side by
 * side instead of taking turns on one connection.
 */
static pthread_key_t tool_be_key;
static pthread_once_t tool_be_key_once = PTHREAD_ONCE_INIT;
static int tool_be_key_ret = -EFAULT;

static void tool_be_client_free(void *client)
{
	esdm_egd_client_free(client);
}

static void tool_be_key_init(void)
{
	tool_be_key_ret = -pthread_key_create(&tool_be_key, tool_be_client_free);
}

static struct esdm_egd_client *tool_be_client(void)
{
	struct esdm_egd_client *client;

	pthread_once(&tool_be_key_once, tool_be_key_init);
	if (tool_be_key_ret)
		return NULL;

	client = pthread_getspecific(tool_be_key);
	if (client)
		return client;

	/* NULL where it fails: every request is then answered with -EINVAL */
	if (esdm_egd_client_alloc(&client, tool_be_socket(), 0))
		return NULL;
	if (pthread_setspecific(tool_be_key, client)) {
		esdm_egd_client_free(client);
		return NULL;
	}

	return client;
}

/*
 * Nothing to set up: a thread connects with its first request, so that a
 * command that asks the server for nothing does not connect at all.
 */
int tool_be_init(void)
{
	return 0;
}

void tool_be_fini(void)
{
	/* The client of the calling thread; a thread that ends frees its own */
	if (tool_be_key_ret)
		return;

	esdm_egd_client_free(pthread_getspecific(tool_be_key));
	pthread_setspecific(tool_be_key, NULL);
}

int tool_be_init_priv(void)
{
	return 0;
}

void tool_be_fini_priv(void)
{
}

int tool_be_status(char *buf, size_t buflen)
{
	return esdm_egd_client_status(tool_be_client(), buf, buflen);
}

int tool_be_status_json(char *buf, size_t buflen)
{
	return esdm_egd_client_status_json(tool_be_client(), buf, buflen);
}

int tool_be_is_fully_seeded(bool *fully_seeded)
{
	uint32_t flags = 0;
	int ret = esdm_egd_client_get_state_flags(tool_be_client(), &flags);

	if (!ret)
		*fully_seeded = !!(flags & ESDM_EGD_STATE_FLAG_FULLY_SEEDED);

	return ret;
}

/* The entropy of all entropy sources: what the entropy count of EGD reports */
int tool_be_get_ent_lvl(unsigned int *entlvl)
{
	uint32_t bits = 0;
	int ret = esdm_egd_client_entropy_count(tool_be_client(), &bits);

	if (!ret)
		*entlvl = bits;

	return ret;
}

/* The entropy of the auxiliary pool: a field of the state */
int tool_be_rnd_get_ent_cnt(unsigned int *entcnt)
{
	struct esdm_egd_client_state state;
	int ret = esdm_egd_client_get_state(tool_be_client(), &state);

	if (!ret)
		*entcnt = state.entropy_count;

	return ret;
}

int tool_be_get_min_reseed_secs(unsigned int *seconds)
{
	struct esdm_egd_client_state state;
	int ret = esdm_egd_client_get_state(tool_be_client(), &state);

	if (!ret)
		*seconds = state.min_reseed_secs;

	return ret;
}

/*
 * One bulk read standing for the read @read_cmd that does not wait.
 *
 * @return the number of bytes delivered, which may be none, < 0 on error
 */
static ssize_t tool_be_read_bulk(uint8_t read_cmd, uint8_t *buf, size_t buflen)
{
	size_t generated = 0;
	int ret;

	if (buflen > ESDM_EGD_MAX_BULK)
		buflen = ESDM_EGD_MAX_BULK;

	ret = esdm_egd_client_get_random_bulk(tool_be_client(), read_cmd, buf,
					      buflen, &generated);

	return ret ? ret : (ssize_t)generated;
}

/*
 * As esdm_rpcc_get_random_bytes(): without waiting for the DRNGs to be fully
 * seeded, short or -EAGAIN from an operational ESDM whose DRNGs await their
 * reseed, nothing from one that is not operational.
 */
ssize_t tool_be_get_random_bytes(uint8_t *buf, size_t buflen)
{
	ssize_t ret = tool_be_read_bulk(ESDM_EGD_CMD_ESDM_READ_UNSEEDED, buf,
					buflen);
	uint32_t flags = 0;

	if (ret || !buflen)
		return ret;

	if (!esdm_egd_client_get_state_flags(tool_be_client(), &flags) &&
	    (flags & ESDM_EGD_STATE_FLAG_OPERATIONAL))
		return -EAGAIN;

	return 0;
}

/*
 * A read that waits until all of @buflen is there. The blocking reads of the
 * protocol transfer 255 bytes each, so that a larger request first takes what
 * a bulk read delivers at once and waits for the remainder only.
 */
static ssize_t tool_be_read_wait(bool pr, uint8_t *buf, size_t buflen)
{
	size_t done = 0;
	int ret;

	if (buflen > ESDM_EGD_MAX_TRANSFER) {
		ssize_t got = tool_be_read_bulk(
			pr ? ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK :
			     ESDM_EGD_CMD_READ_NONBLOCK,
			buf, buflen);

		if (got < 0)
			return got;
		done = (size_t)got;
	}

	if (done < buflen) {
		if (pr)
			ret = esdm_egd_client_get_random_pr(tool_be_client(),
							    buf + done,
							    buflen - done);
		else
			ret = esdm_egd_client_get_random(tool_be_client(),
							 buf + done,
							 buflen - done);
		if (ret) {
			/* Nothing of a failed request is left with the caller */
			memset_secure(buf, 0, done);
			return ret;
		}
	}

	return (ssize_t)buflen;
}

ssize_t tool_be_get_random_bytes_full(uint8_t *buf, size_t buflen)
{
	return tool_be_read_wait(false, buf, buflen);
}

ssize_t tool_be_get_random_bytes_pr(uint8_t *buf, size_t buflen)
{
	return tool_be_read_wait(true, buf, buflen);
}

/*
 * The protocol has no read with a timeout. The read that does not wait is
 * repeated until it delivered everything or the time is up. The ESDM holds
 * such a read back for up to a second while its DRNGs await a reseed, so that
 * the timeout may be exceeded by that much.
 */
ssize_t tool_be_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
					      struct timespec *ts)
{
	const struct timespec pause = { .tv_sec = 0,
					.tv_nsec = TOOL_BE_POLL_NS };
	struct timespec start, now;
	size_t done = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);

	while (1) {
		ssize_t got = tool_be_read_bulk(ESDM_EGD_CMD_READ_NONBLOCK,
						buf + done, buflen - done);

		if (got < 0) {
			memset_secure(buf, 0, done);
			return got;
		}
		done += (size_t)got;
		if (done >= buflen)
			return (ssize_t)buflen;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (timespec_diff(&start, &now) >=
		    (double)ts->tv_sec + (double)ts->tv_nsec / 1E9) {
			memset_secure(buf, 0, done);
			return -ETIMEDOUT;
		}

		nanosleep(&pause, NULL);
	}
}

/*
 * Data with an entropy claim: the data first, with the insertion of the ESDM
 * extensions, which the ESDM confirms, and the claim after it. The pool thus
 * never holds a credit for data that is not in it yet, and a failed insertion
 * is reported, neither of which the write entropy command of EGD offers: it
 * credits with each of its 255 byte transfers and has no answer. The claim is
 * honored for a peer connected as root only, so that it is preceded by a
 * privileged command that changes nothing but is refused for any other peer,
 * before any data is inserted.
 */
int tool_be_rnd_add_entropy(const uint8_t *entropy_buf, size_t entropy_buf_len,
			    uint32_t entropy_cnt)
{
	struct esdm_egd_client *client = tool_be_client();
	int ret;

	/* As the RPC interface: the data cannot hold more than it has bits */
	if (entropy_cnt > entropy_buf_len * 8)
		return -EINVAL;

	if (entropy_cnt) {
		ret = esdm_egd_client_add_to_entropy_count(client, 0);
		if (ret)
			return ret;
	}

	while (entropy_buf_len) {
		size_t chunk = (entropy_buf_len > ESDM_EGD_MAX_BULK) ?
				       ESDM_EGD_MAX_BULK :
				       entropy_buf_len;

		ret = esdm_egd_client_insert(client, entropy_buf, chunk);
		if (ret)
			return ret;

		entropy_buf += chunk;
		entropy_buf_len -= chunk;
	}

	if (!entropy_cnt)
		return 0;

	return esdm_egd_client_add_to_entropy_count(client, entropy_cnt);
}

int tool_be_rnd_clear_pool(void)
{
	return esdm_egd_client_clear_pool(tool_be_client());
}

int tool_be_rnd_reseed_crng(void)
{
	return esdm_egd_client_reseed(tool_be_client());
}

int tool_be_set_min_reseed_secs(unsigned int seconds)
{
	return esdm_egd_client_set_min_reseed_secs(tool_be_client(), seconds);
}

/*
 * What the protocol cannot express, see tool_be_missing(): main() refuses the
 * commands that need these before it calls them.
 */
ssize_t tool_be_get_seed(uint8_t *buf, size_t buflen, bool fully_seeded)
{
	(void)buf;
	(void)buflen;
	(void)fully_seeded;
	return -EOPNOTSUPP;
}

int tool_be_drng_status_json(uint32_t node, char *buf, size_t buflen)
{
	(void)node;
	(void)buf;
	(void)buflen;
	return -EOPNOTSUPP;
}

int tool_be_drng_status_pr_json(char *buf, size_t buflen)
{
	(void)buf;
	(void)buflen;
	return -EOPNOTSUPP;
}

int tool_be_jent_status(char *buf, size_t buflen)
{
	(void)buf;
	(void)buflen;
	return -EOPNOTSUPP;
}

int tool_be_set_es_rate(const char *es, uint32_t rate)
{
	(void)es;
	(void)rate;
	return -EOPNOTSUPP;
}

int tool_be_selftest(struct tool_be_selftest_result *result)
{
	memset(result, 0, sizeof(*result));
	return -EOPNOTSUPP;
}

/* The stress mode of the reference counting of the RPC client library */
int handle_stress_init_fini(double timeout_sec, int num_threads)
{
	(void)timeout_sec;
	(void)num_threads;
	return EXIT_FAILURE;
}
