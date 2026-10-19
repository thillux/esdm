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
 * The vhost-user back-end of a virtio entropy device: the control messages of
 * the front-end, and the serving of the requests of the guest.
 *
 * Two threads share a device. The control thread reads the messages off the
 * connection and applies them; the worker takes the requests off the ring,
 * obtains the random bytes for them and completes them. Both work under the
 * device lock, which the worker holds only while it reads the ring or writes
 * into guest memory - never while it waits for random bytes, which may take
 * until the ESDM is seeded. So a control message is never held up by the
 * ESDM, however long it takes.
 *
 * The worker serves a request in three steps: it takes the request off the
 * ring and translates its buffers, under the lock; it obtains the random
 * bytes, without; it writes them and completes the request, under the lock
 * again. Every change the control thread makes that invalidates what the
 * first step found - other memory, another ring layout or position, a stopped
 * or disabled ring, a reset, the end of the connection - increments the
 * generation of the device, and the third step only goes ahead in the
 * generation the first one ran in. A request whose generation passed is
 * dropped, its random bytes wiped, and nothing of it reaches guest memory: the
 * request is still on the ring, as it was not consumed. The generation also
 * interrupts the wait for random bytes, see vu_source.
 *
 * That is what makes GET_VRING_BASE synchronous with the worker without
 * waiting for it: once the control thread holds the lock, the worker is in
 * none of the steps touching guest memory, and the generation it then changes
 * keeps the worker from touching it again. The index it returns counts the
 * requests completed - one the worker is still busy with is not, and is served
 * again once the ring restarts.
 */

#ifndef VHOST_USER_DEV_H
#define VHOST_USER_DEV_H

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "vhost_user.h"
#include "vhost_user_mem.h"
#include "vhost_user_vring.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The entropy device has one virtqueue, its request queue */
#define VU_NUM_QUEUES 1

/*
 * File descriptors one message carries at most: the regions of SET_MEM_TABLE.
 * QEMU sends 8 at most, the rust-vmm front-end of Cloud Hypervisor 32.
 */
#define VU_MAX_FDS 32
#define VU_MAX_TABLE_REGIONS VU_MAX_FDS

/*
 * Largest payload a message may have: above everything defined, the 1032
 * bytes of a memory table of 32 regions and the 2056 bytes of the reply to
 * GET_SHMEM_CONFIG included. A message announcing more is not read.
 */
#define VU_MAX_PAYLOAD 4096

/* Bytes one request is served with at most */
#define VU_REQ_MAX_BYTES 4096

/*
 * Bytes served before the worker looks at its file descriptors again - the
 * next round goes on right away. The bound keeps a guest asking without end
 * from making the worker deaf to the changes of the control thread; it limits
 * neither what the guest gets nor the load on the ESDM, which only the rate
 * limit does, see vu_dev_set_ratelimit().
 */
#define VU_ROUND_MAX_BYTES 65536

/* Milliseconds a message may take to arrive in full once it began */
#define VU_MSG_TIMEOUT_MS 5000

/* What vu_dev_handle() tells its caller beyond success and failure */
#define VU_DISCONNECT 1

struct vu_msg {
	struct vhost_user_hdr hdr;
	uint8_t payload[VU_MAX_PAYLOAD] __attribute__((aligned(8)));
	/* Received with the message; vu_dev_handle() consumes them all */
	int fds[VU_MAX_FDS];
	unsigned int nfds;
};

struct vu_reply {
	/* Whether there is a reply to send */
	bool send;
	struct vhost_user_hdr hdr;
	uint8_t payload[VU_MAX_PAYLOAD] __attribute__((aligned(8)));
};

/*
 * The random bytes: @fill obtains @len of them into @buf. It may wait as long
 * as it takes - for the ESDM to be seeded, or to come back - but has to give
 * up with -EINTR once vu_dev_interrupted() says so for @gen.
 *
 * @return 0 with @len bytes in @buf, -EINTR when interrupted
 */
struct vu_source {
	int (*fill)(void *ctx, uint8_t *buf, size_t len, unsigned int gen);
	void *ctx;
};

/* Optional limit of the bytes served per period, see vu_dev_set_ratelimit() */
struct vu_ratelimit {
	uint64_t max_bytes;
	uint64_t period_ms;
	/* Bytes that may be served now, up to max_bytes */
	double tokens;
	struct timespec last;
};

struct vu_dev {
	pthread_mutex_t lock;
	/* See above - changes under the lock, read without by the worker */
	atomic_uint gen;
	/* The process is going down, see vu_dev_shutdown() */
	atomic_bool shutdown;
	/*
	 * eventfd the control thread writes on every change the worker has
	 * to look at, and vu_dev_shutdown() at the end
	 */
	int wake_fd;
	/* Changes whenever the kick descriptor does, see vu_dev_worker_view */
	unsigned int kick_gen;

	/* What this back-end offers */
	uint64_t offered_features;
	uint64_t offered_protocol_features;

	/* What the front-end acknowledged */
	uint64_t features;
	uint64_t protocol_features;
	bool owner;

	struct vu_mem *mem;
	struct vu_vring vring[VU_NUM_QUEUES];

	/* The worker's alone */
	struct vu_ratelimit rl;
};

/**
 * @brief Set up a device
 *
 * @return 0 on success, < 0 on error
 */
int vu_dev_init(struct vu_dev *dev);

/** @brief Release a device; the worker has to be gone */
void vu_dev_fini(struct vu_dev *dev);

/**
 * @brief Limit the bytes served to @max_bytes per @period_ms
 *
 * A token bucket holding up to @max_bytes, refilled at @max_bytes per
 * @period_ms: a guest gets bursts of up to @max_bytes and that many per period
 * in the long run. 0 for either means no limit. To be called before the worker
 * runs.
 */
void vu_dev_set_ratelimit(struct vu_dev *dev, uint64_t max_bytes,
			  uint64_t period_ms);

/**
 * @brief The connection to the front-end ended: forget everything about it
 *
 * Every ring is stopped and its notifiers closed, the memory is unmapped and
 * the features are forgotten - the next front-end starts from scratch.
 */
void vu_dev_disconnect(struct vu_dev *dev);

/** @brief Tell the worker to end, see vu_dev_serve() */
void vu_dev_shutdown(struct vu_dev *dev);

/**
 * @brief Apply a control message
 *
 * The message header was checked for version and size by the receiving side,
 * everything else is checked here. Every file descriptor of the message is
 * consumed: taken over by the device or closed.
 *
 * @param [in] msg The message
 * @param [out] reply What to send back, if reply->send
 *
 * @return 0 to go on with the connection, VU_DISCONNECT if the front-end broke
 *	   the protocol in a way no reply can tell it
 */
int vu_dev_handle(struct vu_dev *dev, struct vu_msg *msg,
		  struct vu_reply *reply);

/**
 * @brief Receive one message from the connection
 *
 * Waits for a message to begin as long as it takes, and for the rest of it
 * VU_MSG_TIMEOUT_MS. Gives up when @stop_fd becomes readable.
 *
 * @return 0 with a message, -ECONNRESET when the front-end closed the
 *	   connection, -EINTR when stopped, < 0 for a message that cannot be
 *	   read or makes no sense as a whole
 */
int vu_conn_recv(int fd, int stop_fd, struct vu_msg *msg);

/** @brief Send a reply, 0 on success */
int vu_conn_send(int fd, const struct vu_reply *reply);

/**
 * @brief Receive one message, apply it and reply to it
 *
 * @return 0 to go on, < 0 when the connection is to be closed
 */
int vu_conn_serve(struct vu_dev *dev, int fd, int stop_fd);

/* The state of the device the worker waits on */
struct vu_worker_view {
	/* A duplicate of the kick descriptor of the ring, -1 if none */
	int kick_fd;
	unsigned int kick_gen;
	/* The ring is to be polled */
	bool poll;
};

/** @brief Bring the worker's view up to date */
void vu_dev_worker_view(struct vu_dev *dev, struct vu_worker_view *view);

/**
 * @brief Whether a wait for random bytes in generation @gen is to end
 */
bool vu_dev_interrupted(struct vu_dev *dev, unsigned int gen);

/**
 * @brief Serve requests of the guest
 *
 * @param [in] src The random bytes
 * @param [in] buf Buffer of VU_REQ_MAX_BYTES for them, wiped after use
 *
 * @return 0 to be called again at once - VU_ROUND_MAX_BYTES were served, or
 *	   the state changed under it -, a time in milliseconds to wait before
 *	   the next call - the rate limit -, or -1 if there is nothing to do
 *	   until the next kick or change
 */
int vu_dev_serve(struct vu_dev *dev, const struct vu_source *src,
		 uint8_t *buf);

#ifdef __cplusplus
}
#endif

#endif /* VHOST_USER_DEV_H */
