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
 * The request virtqueue of the entropy device - a split virtqueue in guest
 * memory, written by a driver that is assumed to be hostile.
 *
 * The guest shares the memory the rings live in and may change any byte of it
 * at any time, also while the back-end reads it. So every field of the rings
 * and of a descriptor is read exactly once, into a variable of the back-end,
 * and only that copy is looked at afterwards: the guest cannot get a value
 * past a check and another one used. The index the driver publishes its
 * requests with is read with acquire semantics, so the ring entries and
 * descriptors behind it are read after it, and the used index is published
 * with release semantics after the entry it covers was written.
 *
 * What a driver can get wrong, and how it is answered:
 *
 *	- An available index more than the queue size ahead of the last one
 *	  processed, or a head index beyond the queue: the ring as a whole is
 *	  broken, and no completion could name the request. The ring stops
 *	  being processed until the front-end restarts it, and the error is
 *	  signalled on the err file descriptor.
 *	- A request that cannot be served: a next index beyond the table, a
 *	  chain longer than the queue (which a loop in it always is), an
 *	  indirect table that is not where guest memory is, not a multiple of a
 *	  descriptor in length, nested, not at the head of the chain or larger
 *	  than the queue, a buffer that is not in guest memory or whose range
 *	  wraps around, or a buffer the device may only read - an entropy
 *	  request consists of buffers for the device to write. It is completed
 *	  with nothing written, a used length of 0, and processing goes on.
 */

#ifndef VHOST_USER_VRING_H
#define VHOST_USER_VRING_H

#include <stdbool.h>
#include <stdint.h>

#include "vhost_user.h"
#include "vhost_user_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pieces of guest memory one request is served into at most. A chain with more
 * pieces is served into the first ones only, which the used length tells the
 * driver about.
 */
#define VU_REQ_MAX_SEGS 64

struct vu_seg {
	uint8_t *host;
	uint32_t len;
};

struct vu_req {
	/* Index of the head descriptor, the ID of the request */
	uint16_t head;
	/* The driver made a mistake in it: completed with 0 bytes */
	bool bad;
	/* Bytes the request is served with, the sum of the segments */
	uint32_t len;
	unsigned int nsegs;
	struct vu_seg seg[VU_REQ_MAX_SEGS];
};

struct vu_vring {
	/* Queue size, a power of two; 0 until the front-end set it */
	uint16_t num;
	/* The ring addresses in front-end virtual addresses, once set */
	bool addr_set;
	uint64_t desc_uaddr;
	uint64_t avail_uaddr;
	uint64_t used_uaddr;

	/* Notifiers, -1 if none */
	int kick_fd;
	int call_fd;
	int err_fd;
	/* SET_VRING_KICK came without a descriptor: the ring is polled */
	bool kick_poll;

	/* Ring state of the vhost-user specification */
	bool started;
	bool enabled;

	/* From the negotiated features */
	bool event_idx;
	bool indirect;

	/*
	 * Where the rings are mapped - all three set, or none while they
	 * cannot be translated
	 */
	uint8_t *desc;
	uint8_t *avail;
	uint8_t *used;

	/* Take the used index from guest memory when next mapped */
	bool need_sync;
	/* The driver corrupted the ring, see above */
	bool broken;
	/* The ring is restarted only by the front-end; one report per start */
	bool reported;
	/* Requests of the current start completed with 0 for being malformed */
	uint64_t bad_requests;

	/*
	 * Next entry of the available ring to process, and next entry of the
	 * used ring to fill - equal whenever the ring is not processed: a
	 * request is completed before the next one is taken.
	 */
	uint16_t last_avail;
	uint16_t used_idx;
};

enum vu_pop {
	/* No request is waiting */
	VU_POP_EMPTY,
	/* A request was taken, see struct vu_req */
	VU_POP_REQ,
	/* The available ring is corrupt */
	VU_POP_BROKEN,
};

/** @brief Initialize a ring: stopped, disabled, unconfigured, no notifiers */
void vu_vring_init(struct vu_vring *vr);

/**
 * @brief Stop a ring, closing its kick and call notifiers
 *
 * The front-end hands those over again when it starts the ring. The err
 * notifier stays: QEMU hands it over once, when it sets the device up, and not
 * with every start of the ring.
 */
void vu_vring_stop(struct vu_vring *vr);

/** @brief Close all notifiers of a ring, the err notifier as well */
void vu_vring_close_fds(struct vu_vring *vr);

/**
 * @brief Translate the ring addresses through the memory table
 *
 * The rings have to lie within one region each, the descriptor table aligned
 * to 16, the used ring to 4 and the available ring to 2 bytes. With
 * VIRTIO_RING_F_EVENT_IDX, both rings include the event index behind them.
 * A ring whose size or addresses are not set yet is left unmapped.
 *
 * @return 0 if mapped or not configured yet, -EFAULT if the addresses are not
 *	   in the memory table, -EINVAL if they are misaligned
 */
int vu_vring_map(struct vu_vring *vr, struct vu_mem *mem);

/**
 * @brief Take the used index from guest memory, see vhost_user_vring.c
 */
void vu_vring_sync(struct vu_vring *vr);

/** @brief Whether the ring is to be processed */
bool vu_vring_runnable(const struct vu_vring *vr);

/**
 * @brief Take the next request off the available ring
 *
 * The request is not consumed: it is the next one again until vu_vring_push()
 * completes it. Its buffers are translated in their entirety, of which the
 * first @max_len bytes make up the segments.
 *
 * @param [in] max_len Bytes to serve the request with at most
 * @param [out] req The request
 */
enum vu_pop vu_vring_pop(struct vu_vring *vr, struct vu_mem *mem,
			 uint32_t max_len, struct vu_req *req);

/**
 * @brief Write the bytes a request is served with into its buffers
 *
 * @param [in] len Bytes in @buf, not more than req->len
 */
void vu_req_fill(const struct vu_req *req, const uint8_t *buf, uint32_t len);

/**
 * @brief Complete the request vu_vring_pop() took, and notify the driver if
 *	  it asks for it
 *
 * @param [in] len The used length: the bytes written into its buffers
 */
void vu_vring_push(struct vu_vring *vr, uint16_t head, uint32_t len);

/**
 * @brief Ask the driver for a kick at the next request
 *
 * With VIRTIO_RING_F_EVENT_IDX the driver only kicks once its available index
 * passes the event index the device publishes, so the device has to publish
 * it before it waits for a kick, and look again afterwards: a request the
 * driver made available meanwhile came without a kick.
 *
 * @return true if a request is waiting after all
 */
bool vu_vring_arm(struct vu_vring *vr);

/**
 * @brief Stop processing a corrupt ring and tell the front-end
 *
 * The err file descriptor is signalled once per start of the ring, as QEMU
 * logs every signal - a guest could otherwise fill the log of the host.
 */
void vu_vring_fail(struct vu_vring *vr);

#ifdef __cplusplus
}
#endif

#endif /* VHOST_USER_VRING_H */
