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
 * The EGD protocol served on one connection by a thread of its own - the
 * serving loop of the daemons that serve the EGD protocol outside the
 * esdm-server: the esdm-egd-net-server, which serves it to the network and
 * answers through the RPC interface of the ESDM, and the esdm-egd-net-relay,
 * which serves the EGD socket of a host and answers through a server of the
 * network.
 *
 * Unlike the EGD interface of the esdm-server - an event loop serving many
 * connections per thread, see esdm_egd_server.c - this one blocks: a thread
 * per connection waits for the next command, hands it to the backend and
 * waits for the answer, however long that takes. The daemons serve far fewer
 * clients than the esdm-server, and their backends block anyway - an RPC
 * call, or a request to another host.
 *
 * Every command of esdm_egd_protocol.h is answered as the esdm-server answers
 * it to an unprivileged peer - which every peer of these daemons is: their
 * clients are other hosts, and their own access to the ESDM is the
 * unprivileged one:
 *
 *  - an entropy claim of an insertion (0x03) is dropped, the data inserted
 *    without credit,
 *  - the commands changing the entropy accounting or the DRNGs (0xe6 - 0xea)
 *    are answered -EPERM, and the connection stays usable,
 *  - the get PID command (0x04) answers the PID of the daemon itself,
 *  - an unknown command ends the connection, as the stream is out of step.
 *
 * The protocol cannot report an error. A blocking read that fails ends the
 * connection, a non-blocking read answers what it got - nothing -, a status
 * report that cannot be produced is answered empty.
 */

#ifndef ESDM_EGD_SERVE_H
#define ESDM_EGD_SERVE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Most fields of the state, by the length byte of the answer */
#define ESDM_EGD_SERVE_MAX_STATE_FIELDS 63

/**
 * @brief The connection, as the serving loop reads and writes it
 */
struct esdm_egd_serve_io {
	/**
	 * Read what is there, up to @len bytes, waiting at most @timeout_ms
	 * - less than zero for no bound - for the first one.
	 *
	 * @return the number of bytes read, 0 at the end of the stream,
	 *	   -ETIMEDOUT if nothing came, another negative errno
	 */
	ssize_t (*read)(void *io, uint8_t *buf, size_t len, int timeout_ms);
	/**
	 * Write all of @buf, within @timeout_ms.
	 *
	 * @return 0, or a negative errno
	 */
	int (*write)(void *io, const uint8_t *buf, size_t len, int timeout_ms);
};

/**
 * @brief The reads of the protocol
 */
enum esdm_egd_serve_read {
	/* 0x02: all bytes, waiting for the ESDM to become operational */
	ESDM_EGD_SERVE_FULL,
	/* 0x01: what is there right away */
	ESDM_EGD_SERVE_FULL_NONBLOCK,
	/* 0xe1: all bytes from the prediction resistance DRNG */
	ESDM_EGD_SERVE_PR,
	/* 0xe0: what the prediction resistance DRNG has right away */
	ESDM_EGD_SERVE_PR_NONBLOCK,
	/* 0xe2: what the DRNG has without all of them being fully seeded */
	ESDM_EGD_SERVE_UNSEEDED,
};

/**
 * @brief What answers the commands
 *
 * Every function returns 0 or a negative errno. -EINTR and -ESHUTDOWN end the
 * connection whatever the command: the backend was interrupted - the daemon
 * shuts down, or the client hung up. Any other error is answered as the
 * protocol allows, see the file header.
 */
struct esdm_egd_serve_ops {
	/* 0x00: the entropy the ESDM holds, in bits */
	int (*entropy_count)(void *be, uint32_t *bits);
	/*
	 * A read of @kind into @buf of @len bytes, at most
	 * ESDM_EGD_MAX_TRANSFER, which delivers *@generated of them. A
	 * blocking one delivers all of them or fails.
	 */
	int (*get_random)(void *be, enum esdm_egd_serve_read kind, uint8_t *buf,
			  size_t len, size_t *generated);
	/* 0xe3: up to @room fields of the state, *@num of them delivered */
	int (*get_state)(void *be, uint32_t *fields, unsigned int room,
			 unsigned int *num);
	/*
	 * 0xe4 and 0xe5 (@json): the status report into @buf of @buflen bytes,
	 * *@len of them - 0 if there is none to send, see the protocol.
	 */
	int (*status)(void *be, bool json, char *buf, size_t buflen,
		      size_t *len);
	/* 0x03: insert @len bytes, without credit */
	int (*write_data)(void *be, const uint8_t *buf, size_t len);
};

/**
 * @brief One connection to serve
 */
struct esdm_egd_serve_conn {
	const struct esdm_egd_serve_io *io;
	void *io_ctx;
	const struct esdm_egd_serve_ops *ops;
	void *be;
	/* Who the client is, for the log */
	const char *peer;
	/*
	 * How long the client may stay silent between two commands before it
	 * is closed; 0 for no bound
	 */
	unsigned int idle_timeout_ms;
	/*
	 * How long the client may take for its first command - the probation
	 * of a client that is not authenticated otherwise; 0 for the idle
	 * timeout
	 */
	unsigned int first_timeout_ms;
	/*
	 * How long the rest of a command started may take to arrive, and an
	 * answer to be taken by the client
	 */
	unsigned int io_timeout_ms;
	/* Set when the daemon shuts down; the loop starts nothing new then */
	const atomic_bool *stop;
	/*
	 * Called once the first complete command arrived, before it is
	 * served - the end of a connection's probation; may be NULL
	 */
	void (*first_command)(void *be);
};

/**
 * @brief Serve the EGD protocol on the connection until it ends
 *
 * @return 0 when the client ended the connection, otherwise a negative errno
 *	   telling why it was ended: -ETIMEDOUT when the client stayed silent
 *	   for too long or did not take an answer, -EPROTO for an unknown
 *	   command, -ESHUTDOWN when the daemon shuts down, the error of the
 *	   connection or the backend otherwise
 */
int esdm_egd_serve(const struct esdm_egd_serve_conn *conn);

/**
 * @brief The threads of the connections of a daemon
 */
struct esdm_egd_serve_pool {
	pthread_mutex_t lock;
	pthread_cond_t cond;
	unsigned int threads;
	/* Set by esdm_egd_serve_pool_stop(), for the loops of the threads */
	atomic_bool stop;
};

#define ESDM_EGD_SERVE_POOL_INIT                                               \
	{ .lock = PTHREAD_MUTEX_INITIALIZER,                                   \
	  .cond = PTHREAD_COND_INITIALIZER,                                    \
	  .threads = 0,                                                        \
	  .stop = false }

/**
 * @brief Start a thread serving a connection
 *
 * The thread is detached; @fn calls esdm_egd_serve_pool_done() as the last
 * thing it does with the pool.
 *
 * @return 0, or a negative errno - the connection is the caller's then
 */
int esdm_egd_serve_pool_spawn(struct esdm_egd_serve_pool *pool,
			      void *(*fn)(void *), void *arg);

/**
 * @brief A thread of the pool is done
 */
void esdm_egd_serve_pool_done(struct esdm_egd_serve_pool *pool);

/**
 * @brief Stop the pool: tell the threads, and wait for them
 *
 * Their connections are to be shut down by the caller before, so that the
 * threads waiting for their clients wake up.
 *
 * @param [in] wait_ms Bound of the wait
 *
 * @return the number of threads still running after the wait
 */
unsigned int esdm_egd_serve_pool_stop(struct esdm_egd_serve_pool *pool,
				      unsigned int wait_ms);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_EGD_SERVE_H */
