/*
 * The EGD protocol served on one connection by a thread of its own
 *
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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bitshift_be.h"
#include "esdm_egd_protocol.h"
#include "esdm_egd_serve.h"
#include "esdm_logger.h"
#include "memset_secure.h"

/*
 * Room for one maximum sized command plus the beginning of the next one, so a
 * client pipelining its requests does not have to be read byte-wise.
 */
#define ESDM_EGD_SERVE_BUFSIZE (2 * ESDM_EGD_MAX_CMD_SIZE)

/*
 * Bytes of the blocking reads in a row answered by one read of the backend, see
 * esdm_egd_serve_read_run().
 */
#define ESDM_EGD_SERVE_RUN_MAX ESDM_EGD_SERVE_RUN_LIMIT

/*
 * Stack of a connection thread: the TLS stacks need some of it for a handshake,
 * the RPC client for a request, the serving loop itself little - its buffers
 * of any size are on the heap.
 */
#define ESDM_EGD_SERVE_STACK (512 * 1024)

/*
 * The size of the command at the head of @in: 0 if more of it has to arrive
 * to tell, -EPROTO for a command that does not exist.
 */
static ssize_t esdm_egd_serve_cmd_len(const uint8_t *in, size_t in_len)
{
	if (!in_len)
		return 0;

	switch (in[0]) {
	case ESDM_EGD_CMD_ENTROPY_COUNT:
	case ESDM_EGD_CMD_GET_PID:
	case ESDM_EGD_CMD_ESDM_GET_STATE:
	case ESDM_EGD_CMD_ESDM_STATUS:
	case ESDM_EGD_CMD_ESDM_STATUS_JSON:
	case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
	case ESDM_EGD_CMD_ESDM_RESEED:
		return 1;
	case ESDM_EGD_CMD_READ_NONBLOCK:
	case ESDM_EGD_CMD_READ_BLOCK:
	case ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK:
	case ESDM_EGD_CMD_ESDM_PR_READ_BLOCK:
	case ESDM_EGD_CMD_ESDM_READ_UNSEEDED:
		return 2;
	case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
	case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
	case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
		return 5;
	case ESDM_EGD_CMD_WRITE_ENTROPY:
		return in_len < 4 ? 0 : 4 + (ssize_t)in[3];
	default:
		return -EPROTO;
	}
}

/* Milliseconds on the monotonic clock */
static uint64_t esdm_egd_serve_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * What is left of @timeout_ms after @start, for a read: 0 once it passed,
 * which reads what is there already and waits for nothing
 */
static int esdm_egd_serve_left_ms(uint64_t start, unsigned int timeout_ms)
{
	uint64_t now = esdm_egd_serve_now_ms();

	if (now - start >= timeout_ms)
		return 0;
	return (int)(timeout_ms - (now - start));
}

/* Does the error of a backend end the connection? See the ops. */
static bool esdm_egd_serve_fatal(int ret)
{
	return ret == -EINTR || ret == -ESHUTDOWN;
}

static int esdm_egd_serve_write(const struct esdm_egd_serve_conn *c,
				const uint8_t *buf, size_t len)
{
	return c->io->write(c->io_ctx, buf, len, (int)c->io_timeout_ms);
}

/* Commands 0x01, 0xe0 and 0xe2: what is there, prefixed with its size */
static int esdm_egd_serve_read_nonblock(const struct esdm_egd_serve_conn *c,
					enum esdm_egd_serve_read kind,
					uint8_t requested)
{
	uint8_t resp[1 + ESDM_EGD_MAX_TRANSFER];
	size_t generated = 0;
	int ret;

	resp[0] = 0;
	if (requested) {
		ret = c->ops->get_random(c->be, kind, resp + 1, requested,
					 &generated);
		if (esdm_egd_serve_fatal(ret))
			return ret;
		if (ret) {
			/* The protocol has nothing but an empty answer */
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SERVER,
				    "EGD: read of %u bytes for %s failed: %s\n",
				    requested, c->peer, strerror(-ret));
			generated = 0;
		}
		if (generated > requested)
			generated = requested;
		resp[0] = (uint8_t)generated;
	}

	ret = esdm_egd_serve_write(c, resp, 1 + (size_t)resp[0]);
	memset_secure(resp, 0, sizeof(resp));

	return ret;
}

/*
 * Commands 0x02 and 0xe1: exactly what was asked for. A read that fails has
 * no answer, and the client would wait for one: the connection ends.
 */
static int esdm_egd_serve_read_block(const struct esdm_egd_serve_conn *c,
				     enum esdm_egd_serve_read kind,
				     uint8_t requested)
{
	uint8_t resp[ESDM_EGD_MAX_TRANSFER];
	size_t generated = 0;
	int ret;

	if (!requested)
		return 0;

	ret = c->ops->get_random(c->be, kind, resp, requested, &generated);
	if (!ret && generated != requested)
		ret = -EIO;
	if (ret) {
		if (!esdm_egd_serve_fatal(ret))
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD: blocking read of %u bytes for %s failed, closing the connection: %s\n",
				requested, c->peer, strerror(-ret));
		goto out;
	}

	ret = esdm_egd_serve_write(c, resp, requested);

out:
	memset_secure(resp, 0, sizeof(resp));
	return ret;
}

/*
 * The blocking reads in a row at the head of @in, as a client pipelining a
 * read beyond the 255 bytes of one transfer sends them, libesdm_egd_client
 * among them: their number, and the bytes they ask for in @len - no more than
 * ESDM_EGD_SERVE_RUN_MAX of them.
 */
static size_t esdm_egd_serve_run(const uint8_t *in, size_t in_len, size_t *len)
{
	size_t num = 0;

	*len = 0;
	while (2 * (num + 1) <= in_len &&
	       in[2 * num] == ESDM_EGD_CMD_READ_BLOCK &&
	       *len + in[2 * num + 1] <= ESDM_EGD_SERVE_RUN_MAX) {
		*len += in[2 * num + 1];
		num++;
	}

	return num;
}

/*
 * A run of blocking reads, see esdm_egd_serve_run(): one read of the backend
 * of @len bytes for all of them, and one write. The answer of a blocking read
 * is the bytes asked for and nothing else, so the bytes of the one read are
 * the answers of the commands in order. Each read of the backend is an RPC
 * request or a request to another host, whose round trip was the time of a
 * pipelined read; the bytes were not. A read that fails ends the connection,
 * as one of the commands would have.
 */
static int esdm_egd_serve_read_run(const struct esdm_egd_serve_conn *c,
				   size_t len)
{
	uint8_t *resp = malloc(len);
	size_t generated = 0;
	int ret;

	if (!resp)
		return -ENOMEM;

	ret = c->ops->get_random(c->be, ESDM_EGD_SERVE_FULL, resp, len,
				 &generated);
	if (!ret && generated != len)
		ret = -EIO;
	if (ret) {
		if (!esdm_egd_serve_fatal(ret))
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD: blocking reads of %zu bytes for %s failed, closing the connection: %s\n",
				len, c->peer, strerror(-ret));
		goto out;
	}

	ret = esdm_egd_serve_write(c, resp, len);

out:
	memset_secure(resp, 0, len);
	free(resp);
	return ret;
}

/* Command 0x00 */
static int esdm_egd_serve_entropy_count(const struct esdm_egd_serve_conn *c)
{
	uint8_t resp[4];
	uint32_t bits = 0;
	int ret = c->ops->entropy_count(c->be, &bits);

	if (ret) {
		/* No answer but a number, and none is known */
		if (!esdm_egd_serve_fatal(ret))
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD: entropy count for %s failed, closing the connection: %s\n",
				c->peer, strerror(-ret));
		return ret;
	}

	be32_to_ptr(resp, bits);
	return esdm_egd_serve_write(c, resp, sizeof(resp));
}

/* Command 0x03: the claim is dropped, the data inserted - no answer */
static int esdm_egd_serve_write_data(const struct esdm_egd_serve_conn *c,
				     uint32_t entropy_bits, const uint8_t *data,
				     uint8_t len)
{
	int ret;

	if (entropy_bits) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "EGD: ignoring entropy claim of %u bits from %s\n",
			    entropy_bits, c->peer);
	}

	if (!len)
		return 0;

	ret = c->ops->write_data(c->be, data, len);
	if (esdm_egd_serve_fatal(ret))
		return ret;
	if (ret) {
		/* No answer to report it in, and the stream is in step */
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
			    "EGD: insertion of %u bytes from %s failed: %s\n",
			    len, c->peer, strerror(-ret));
	}

	return 0;
}

/* Command 0x04: the PID of this daemon */
static int esdm_egd_serve_get_pid(const struct esdm_egd_serve_conn *c)
{
	uint8_t resp[1 + 20];
	int len;

	len = snprintf((char *)resp + 1, sizeof(resp) - 1, "%d", (int)getpid());
	if (len < 0 || (size_t)len >= sizeof(resp) - 1)
		return -EFAULT;
	resp[0] = (uint8_t)len;

	return esdm_egd_serve_write(c, resp, 1 + (size_t)len);
}

/* Command 0xe3 */
static int esdm_egd_serve_get_state(const struct esdm_egd_serve_conn *c)
{
	uint32_t fields[ESDM_EGD_SERVE_MAX_STATE_FIELDS];
	uint8_t resp[1 + 4 * ESDM_EGD_SERVE_MAX_STATE_FIELDS];
	unsigned int num = 0, i;
	int ret;

	ret = c->ops->get_state(c->be, fields, ESDM_EGD_SERVE_MAX_STATE_FIELDS,
				&num);
	if (ret) {
		/* The answer has to have the fields of the protocol */
		if (!esdm_egd_serve_fatal(ret))
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_SERVER,
				"EGD: state for %s failed, closing the connection: %s\n",
				c->peer, strerror(-ret));
		return ret;
	}
	if (num > ESDM_EGD_SERVE_MAX_STATE_FIELDS)
		num = ESDM_EGD_SERVE_MAX_STATE_FIELDS;

	resp[0] = (uint8_t)num;
	for (i = 0; i < num; i++)
		be32_to_ptr(resp + 1 + 4 * i, fields[i]);

	return esdm_egd_serve_write(c, resp, 1 + 4 * (size_t)num);
}

/*
 * Commands 0xe4 and 0xe5 (@json): the report preceded by its length, an empty
 * one if it cannot be had.
 */
static int esdm_egd_serve_status(const struct esdm_egd_serve_conn *c, bool json)
{
	size_t alloc = 4 + ESDM_EGD_MAX_STATUS + 1, len = 0;
	uint8_t *buf = calloc(1, alloc);
	int ret;

	if (!buf) {
		uint8_t empty[4] = { 0 };

		return esdm_egd_serve_write(c, empty, sizeof(empty));
	}

	ret = c->ops->status(c->be, json, (char *)buf + 4, alloc - 4, &len);
	if (esdm_egd_serve_fatal(ret)) {
		free(buf);
		return ret;
	}
	if (ret || len > ESDM_EGD_MAX_STATUS)
		len = 0;

	be32_to_ptr(buf, (uint32_t)len);
	ret = esdm_egd_serve_write(c, buf, 4 + len);
	free(buf);

	return ret;
}

/* Commands 0xe6 to 0xea: refused - nobody served here is privileged */
static int esdm_egd_serve_priv(const struct esdm_egd_serve_conn *c, uint8_t cmd)
{
	uint8_t resp[4];

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
		    "EGD: refusing command 0x%02x of %s\n", cmd, c->peer);

	be32_to_ptr(resp, (uint32_t)(int32_t)-EPERM);
	return esdm_egd_serve_write(c, resp, sizeof(resp));
}

static int esdm_egd_serve_cmd(const struct esdm_egd_serve_conn *c,
			      const uint8_t *in)
{
	switch (in[0]) {
	case ESDM_EGD_CMD_ENTROPY_COUNT:
		return esdm_egd_serve_entropy_count(c);
	case ESDM_EGD_CMD_READ_NONBLOCK:
		return esdm_egd_serve_read_nonblock(
			c, ESDM_EGD_SERVE_FULL_NONBLOCK, in[1]);
	case ESDM_EGD_CMD_READ_BLOCK:
		return esdm_egd_serve_read_block(c, ESDM_EGD_SERVE_FULL, in[1]);
	case ESDM_EGD_CMD_WRITE_ENTROPY:
		/* Big endian entropy claim, see the protocol header. */
		return esdm_egd_serve_write_data(c, ptr_to_be16(in + 1), in + 4,
						 in[3]);
	case ESDM_EGD_CMD_GET_PID:
		return esdm_egd_serve_get_pid(c);
	case ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK:
		return esdm_egd_serve_read_nonblock(
			c, ESDM_EGD_SERVE_PR_NONBLOCK, in[1]);
	case ESDM_EGD_CMD_ESDM_PR_READ_BLOCK:
		return esdm_egd_serve_read_block(c, ESDM_EGD_SERVE_PR, in[1]);
	case ESDM_EGD_CMD_ESDM_READ_UNSEEDED:
		return esdm_egd_serve_read_nonblock(c, ESDM_EGD_SERVE_UNSEEDED,
						    in[1]);
	case ESDM_EGD_CMD_ESDM_GET_STATE:
		return esdm_egd_serve_get_state(c);
	case ESDM_EGD_CMD_ESDM_STATUS:
		return esdm_egd_serve_status(c, false);
	case ESDM_EGD_CMD_ESDM_STATUS_JSON:
		return esdm_egd_serve_status(c, true);
	case ESDM_EGD_CMD_ESDM_ADD_TO_ENT_CNT:
	case ESDM_EGD_CMD_ESDM_CLEAR_POOL:
	case ESDM_EGD_CMD_ESDM_RESEED:
	case ESDM_EGD_CMD_ESDM_SET_WRITE_WAKEUP:
	case ESDM_EGD_CMD_ESDM_SET_MIN_RESEED_SECS:
		return esdm_egd_serve_priv(c, in[0]);
	default:
		/* Cannot happen - esdm_egd_serve_cmd_len() filtered it out */
		return -EPROTO;
	}
}

int esdm_egd_serve(const struct esdm_egd_serve_conn *c)
{
	uint8_t in[ESDM_EGD_SERVE_BUFSIZE];
	/* The start of the serving, and of the command at the head of @in */
	uint64_t start = esdm_egd_serve_now_ms(), cmd_start = start;
	size_t in_len = 0;
	bool first = true;
	int ret = 0;

	for (;;) {
		ssize_t cmd_len, n;
		size_t run, run_len;
		int timeout;

		if (c->stop && atomic_load(c->stop)) {
			ret = -ESHUTDOWN;
			break;
		}

		cmd_len = esdm_egd_serve_cmd_len(in, in_len);
		if (cmd_len < 0) {
			/*
			 * The protocol offers no way to report an error, and
			 * an unknown command byte means the stream is out of
			 * step - the only sane reaction is to drop the client.
			 */
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_SERVER,
				    "EGD: unknown command 0x%02x from %s\n",
				    in[0], c->peer);
			ret = -EPROTO;
			break;
		}

		if (!cmd_len || in_len < (size_t)cmd_len) {
			/*
			 * Between two commands, the client may be silent for
			 * the idle timeout. Once a command started, all of its
			 * rest has to come within the timeout of a transfer
			 * from its first byte - not each part of it: a client
			 * sending a byte at a time would hold the connection
			 * for that long per byte. The first command of a
			 * client on probation has to be complete within the
			 * probation from the start, however it arrives.
			 */
			if (first && c->first_timeout_ms)
				timeout = esdm_egd_serve_left_ms(
					start, c->first_timeout_ms);
			else if (in_len)
				timeout = esdm_egd_serve_left_ms(
					cmd_start, c->io_timeout_ms);
			else
				timeout = c->idle_timeout_ms ?
						  (int)c->idle_timeout_ms :
						  -1;

			n = c->io->read(c->io_ctx, in + in_len,
					sizeof(in) - in_len, timeout);
			if (n == 0) {
				/* The client is done, a command cut short too */
				ret = 0;
				break;
			}
			if (n < 0) {
				ret = (int)n;
				if (ret == -ETIMEDOUT)
					esdm_logger(
						LOGGER_DEBUG, LOGGER_C_SERVER,
						"EGD: %s %s\n", c->peer,
						in_len ?
							"did not complete its command in time" :
							"was silent for too long");
				break;
			}
			/* The first byte of a command: its time starts */
			if (!in_len)
				cmd_start = esdm_egd_serve_now_ms();
			in_len += (size_t)n;
			continue;
		}

		if (first) {
			first = false;
			if (c->first_command)
				c->first_command(c->be);
		}

		/* Blocking reads in a row are answered together */
		run = esdm_egd_serve_run(in, in_len, &run_len);
		if (run > 1 && run_len) {
			cmd_len = 2 * (ssize_t)run;
			ret = esdm_egd_serve_read_run(c, run_len);
		} else {
			ret = esdm_egd_serve_cmd(c, in);
		}

		/*
		 * Consumed, and wiped behind what is left: client supplied
		 * entropy data must not linger in the buffer.
		 */
		in_len -= (size_t)cmd_len;
		if (in_len)
			memmove(in, in + cmd_len, in_len);
		memset_secure(in + in_len, 0, (size_t)cmd_len);

		/*
		 * The next command, pipelined behind this one, starts its time
		 * now: the client is not to be held to the time the answer took
		 */
		cmd_start = esdm_egd_serve_now_ms();

		if (ret)
			break;
	}

	memset_secure(in, 0, sizeof(in));
	return ret;
}

int esdm_egd_serve_pool_spawn(struct esdm_egd_serve_pool *pool,
			      void *(*fn)(void *), void *arg)
{
	pthread_attr_t attr;
	pthread_t thread;
	int ret;

	ret = pthread_attr_init(&attr);
	if (ret)
		return -ret;
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_attr_setstacksize(&attr, ESDM_EGD_SERVE_STACK);

	pthread_mutex_lock(&pool->lock);
	pool->threads++;
	pthread_mutex_unlock(&pool->lock);

	ret = pthread_create(&thread, &attr, fn, arg);
	pthread_attr_destroy(&attr);
	if (ret) {
		esdm_egd_serve_pool_done(pool);
		return -ret;
	}

	return 0;
}

void esdm_egd_serve_pool_done(struct esdm_egd_serve_pool *pool)
{
	pthread_mutex_lock(&pool->lock);
	pool->threads--;
	pthread_cond_broadcast(&pool->cond);
	pthread_mutex_unlock(&pool->lock);
}

unsigned int esdm_egd_serve_pool_stop(struct esdm_egd_serve_pool *pool,
				      unsigned int wait_ms)
{
	struct timespec deadline;
	unsigned int left;

	atomic_store(&pool->stop, true);

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += (time_t)(wait_ms / 1000);
	deadline.tv_nsec += (long)(wait_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	pthread_mutex_lock(&pool->lock);
	while (pool->threads) {
		if (pthread_cond_timedwait(&pool->cond, &pool->lock,
					   &deadline) == ETIMEDOUT)
			break;
	}
	left = pool->threads;
	pthread_mutex_unlock(&pool->lock);

	return left;
}
