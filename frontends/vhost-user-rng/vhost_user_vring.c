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

#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "vhost_user_vring.h"

/*
 * Accesses of the rings in guest memory. The fields are naturally aligned -
 * vu_vring_map() checks the ring addresses, and every field sits at an offset
 * that is a multiple of its size - so each is a single atomic access, which
 * the compiler neither splits nor repeats. The casts go through void * as the
 * alignment is established at run time.
 */
static inline uint16_t vu_ld16(const uint8_t *p)
{
	return le16toh(__atomic_load_n((const uint16_t *)(const void *)p,
				       __ATOMIC_RELAXED));
}

static inline uint16_t vu_ld16_acquire(const uint8_t *p)
{
	return le16toh(__atomic_load_n((const uint16_t *)(const void *)p,
				       __ATOMIC_ACQUIRE));
}

static inline void vu_st16(uint8_t *p, uint16_t v)
{
	__atomic_store_n((uint16_t *)(void *)p, htole16(v), __ATOMIC_RELAXED);
}

static inline void vu_st16_release(uint8_t *p, uint16_t v)
{
	__atomic_store_n((uint16_t *)(void *)p, htole16(v), __ATOMIC_RELEASE);
}

static inline void vu_st32(uint8_t *p, uint32_t v)
{
	__atomic_store_n((uint32_t *)(void *)p, htole32(v), __ATOMIC_RELAXED);
}

/* A descriptor as copied out of guest memory */
struct vu_desc {
	uint64_t addr;
	uint32_t len;
	uint16_t flags;
	uint16_t next;
};

static void vu_desc_decode(const uint8_t raw[VIRTQ_DESC_SIZE],
			   struct vu_desc *d)
{
	uint64_t addr;
	uint32_t len;
	uint16_t flags, next;

	memcpy(&addr, raw, sizeof(addr));
	memcpy(&len, raw + 8, sizeof(len));
	memcpy(&flags, raw + 12, sizeof(flags));
	memcpy(&next, raw + 14, sizeof(next));

	d->addr = le64toh(addr);
	d->len = le32toh(len);
	d->flags = le16toh(flags);
	d->next = le16toh(next);
}

/*
 * Copy a descriptor of the table out of guest memory - byte by byte with
 * volatile reads, so each byte is read once and the decoded copy is what the
 * chain is checked and served by.
 */
static void vu_desc_fetch(const uint8_t *src, struct vu_desc *d)
{
	const volatile uint8_t *s = src;
	uint8_t raw[VIRTQ_DESC_SIZE];
	unsigned int i;

	for (i = 0; i < VIRTQ_DESC_SIZE; i++)
		raw[i] = s[i];

	vu_desc_decode(raw, d);
}

void vu_vring_init(struct vu_vring *vr)
{
	memset(vr, 0, sizeof(*vr));
	vr->kick_fd = -1;
	vr->call_fd = -1;
	vr->err_fd = -1;
}

void vu_vring_close_fds(struct vu_vring *vr)
{
	if (vr->kick_fd >= 0)
		close(vr->kick_fd);
	if (vr->call_fd >= 0)
		close(vr->call_fd);
	if (vr->err_fd >= 0)
		close(vr->err_fd);
	vr->kick_fd = -1;
	vr->call_fd = -1;
	vr->err_fd = -1;
	vr->kick_poll = false;
}

int vu_vring_map(struct vu_vring *vr, struct vu_mem *mem)
{
	uint64_t n = vr->num, ev = vr->event_idx ? 2 : 0;
	uint8_t *desc, *avail, *used;

	vr->desc = NULL;
	vr->avail = NULL;
	vr->used = NULL;

	if (!vr->num || !vr->addr_set)
		return 0;

	desc = vu_mem_uva(mem, vr->desc_uaddr, VIRTQ_DESC_SIZE * n);
	avail = vu_mem_uva(mem, vr->avail_uaddr, VIRTQ_AVAIL_RING_OFF + 2 * n + ev);
	used = vu_mem_uva(mem, vr->used_uaddr,
			  VIRTQ_USED_RING_OFF + VIRTQ_USED_ELEM_SIZE * n + ev);
	if (!desc || !avail || !used)
		return -EFAULT;

	/*
	 * The alignment the virtio specification demands, checked on the
	 * mapped addresses: those are what the atomic accesses use. A mapping
	 * starts at an offset into its file with the alignment of a page, and
	 * the front-end's address of the same byte has the same alignment.
	 */
	if (((uintptr_t)desc & (VIRTQ_DESC_ALIGN - 1)) ||
	    ((uintptr_t)avail & (VIRTQ_AVAIL_ALIGN - 1)) ||
	    ((uintptr_t)used & (VIRTQ_USED_ALIGN - 1)))
		return -EINVAL;

	vr->desc = desc;
	vr->avail = avail;
	vr->used = used;

	return 0;
}

/*
 * The used index is the driver's to read and the device's to write, and the
 * device takes it from guest memory when a ring starts: SET_VRING_BASE only
 * tells the next available entry. The two are equal for a device completing
 * its requests in order before it takes the next one, as this one does - but
 * not where the front-end lost track. A back-end that went away leaves
 * requests it took but did not complete behind, and Cloud Hypervisor hands a
 * reconnected back-end the available index of the guest as the base, which
 * passes over the requests made before. Starting at the used index serves
 * those requests again, which is harmless for an entropy device - a driver
 * gets random bytes it is waiting for - while skipping them leaves the driver
 * waiting for good.
 *
 * Indices further apart than the queue size describe no ring: one of them is
 * garbage, and the ring is not processed.
 */
void vu_vring_sync(struct vu_vring *vr)
{
	uint16_t used = vu_ld16(vr->used + VIRTQ_USED_IDX_OFF);
	uint16_t ahead = (uint16_t)(vr->last_avail - used);
	uint16_t behind = (uint16_t)(used - vr->last_avail);

	vr->need_sync = false;

	if (used != vr->last_avail) {
		if (ahead > vr->num && behind > vr->num) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_VHOST,
				"Ring base %u and used index %u of the guest are further apart than the queue size %u - not processing the ring\n",
				vr->last_avail, used, vr->num);
			vr->broken = true;
			return;
		}

		esdm_logger(
			LOGGER_VERBOSE, LOGGER_C_VHOST,
			"Ring base %u differs from the used index %u of the guest, resuming at the used index\n",
			vr->last_avail, used);
		vr->last_avail = used;
	}

	vr->used_idx = vr->last_avail;
}

bool vu_vring_runnable(const struct vu_vring *vr)
{
	return vr->started && vr->enabled && !vr->broken && !vr->need_sync &&
	       vr->desc && vr->avail && vr->used;
}

/*
 * Add the guest buffer [gpa, gpa + len) to a request: translated in full,
 * across adjacent regions if it spans them, but only the part up to @max_len
 * bytes of the request is kept as segments.
 */
static int vu_req_add(struct vu_req *req, struct vu_mem *mem, uint64_t gpa,
		      uint32_t len, uint32_t max_len)
{
	uint64_t left = len;

	/* The last byte has to be addressable without the range wrapping */
	if (len - 1 > UINT64_MAX - gpa)
		return -EFAULT;

	while (left) {
		uint64_t avail, chunk;
		uint8_t *p = vu_mem_gpa(mem, gpa, &avail);

		if (!p)
			return -EFAULT;

		chunk = avail < left ? avail : left;

		if (req->len < max_len && req->nsegs < VU_REQ_MAX_SEGS) {
			uint32_t take = max_len - req->len;

			if ((uint64_t)take > chunk)
				take = (uint32_t)chunk;

			req->seg[req->nsegs].host = p;
			req->seg[req->nsegs].len = take;
			req->nsegs++;
			req->len += take;
		}

		left -= chunk;
		/* Wraps only once nothing is left - see the check above */
		gpa += chunk;
	}

	return 0;
}

/*
 * Walk the descriptor chain of the request with head @head. Every descriptor
 * is copied out once; the walk is bounded by the size of the table it is in -
 * the queue size, or that of the indirect table - so a loop ends it as a chain
 * too long.
 */
static int vu_req_parse(struct vu_vring *vr, struct vu_mem *mem,
			uint16_t head, uint32_t max_len, struct vu_req *req)
{
	uint8_t raw[VIRTQ_DESC_SIZE];
	uint64_t table = 0;
	uint32_t idx = head, count = 0, limit = vr->num;
	bool indirect = false;
	struct vu_desc d;
	int ret;

	for (;;) {
		if (++count > limit)
			return -ELOOP;

		if (indirect) {
			/* idx < limit, and the table does not wrap */
			ret = vu_mem_read_gpa(mem, table + VIRTQ_DESC_SIZE * idx,
					      raw, sizeof(raw));
			if (ret)
				return ret;
			vu_desc_decode(raw, &d);
		} else {
			vu_desc_fetch(vr->desc + VIRTQ_DESC_SIZE * (size_t)idx,
				      &d);
		}

		if (d.flags & VIRTQ_DESC_F_INDIRECT) {
			/*
			 * One table, as the whole of the request: the
			 * specification forbids an indirect descriptor in a
			 * table and one with NEXT, and the drivers place it at
			 * the head.
			 */
			if (!vr->indirect || indirect || count != 1 ||
			    (d.flags & VIRTQ_DESC_F_NEXT))
				return -EINVAL;
			if (!d.len || d.len % VIRTQ_DESC_SIZE)
				return -EINVAL;
			/* No chain is longer than the queue */
			if (d.len / VIRTQ_DESC_SIZE > vr->num)
				return -E2BIG;
			/* All of the table is guest memory, not just a part */
			if (!vu_mem_covers_gpa(mem, d.addr, d.len))
				return -EFAULT;

			table = d.addr;
			limit = d.len / VIRTQ_DESC_SIZE;
			indirect = true;
			count = 0;
			idx = 0;
			continue;
		}

		/* Nothing of an entropy request is for the device to read */
		if (!(d.flags & VIRTQ_DESC_F_WRITE))
			return -EPERM;

		if (d.len) {
			ret = vu_req_add(req, mem, d.addr, d.len, max_len);
			if (ret)
				return ret;
		}

		if (!(d.flags & VIRTQ_DESC_F_NEXT))
			return 0;

		if (d.next >= limit)
			return -ERANGE;
		idx = d.next;
	}
}

enum vu_pop vu_vring_pop(struct vu_vring *vr, struct vu_mem *mem,
			 uint32_t max_len, struct vu_req *req)
{
	uint16_t avail_idx, pending, head;
	size_t slot;
	int ret;

	req->head = 0;
	req->bad = false;
	req->len = 0;
	req->nsegs = 0;

	if (!vu_vring_runnable(vr))
		return VU_POP_EMPTY;

	/* Acquire: the entries the index covers are read after it */
	avail_idx = vu_ld16_acquire(vr->avail + VIRTQ_AVAIL_IDX_OFF);
	pending = (uint16_t)(avail_idx - vr->last_avail);
	if (!pending)
		return VU_POP_EMPTY;

	if (pending > vr->num) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_VHOST,
			"The guest moved the available index from %u to %u, beyond the queue size %u\n",
			vr->last_avail, avail_idx, vr->num);
		return VU_POP_BROKEN;
	}

	/* num is a power of two */
	slot = (size_t)(vr->last_avail & (vr->num - 1));
	head = vu_ld16(vr->avail + VIRTQ_AVAIL_RING_OFF + 2 * slot);
	if (head >= vr->num) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_VHOST,
			"The guest made descriptor %u available, beyond the queue size %u\n",
			head, vr->num);
		return VU_POP_BROKEN;
	}

	req->head = head;
	ret = vu_req_parse(vr, mem, head, max_len, req);
	if (ret) {
		/*
		 * Reported once per start of the ring: a guest sending nothing
		 * but malformed requests must not flood the log.
		 */
		esdm_logger(vr->bad_requests ? LOGGER_DEBUG : LOGGER_WARN,
			    LOGGER_C_VHOST,
			    "Malformed request %u of the guest (%s), completed without data\n",
			    head, strerror(-ret));
		vr->bad_requests++;
		req->bad = true;
		req->len = 0;
		req->nsegs = 0;
	}

	return VU_POP_REQ;
}

void vu_req_fill(const struct vu_req *req, const uint8_t *buf, uint32_t len)
{
	unsigned int i;

	for (i = 0; i < req->nsegs && len; i++) {
		uint32_t n = req->seg[i].len < len ? req->seg[i].len : len;

		memcpy(req->seg[i].host, buf, n);
		buf += n;
		len -= n;
	}
}

/* Signal an eventfd, which the front-end may have handed over as anything */
static void vu_signal(int fd)
{
	uint64_t one = 1;
	ssize_t ret;

	if (fd < 0)
		return;

	do {
		ret = write(fd, &one, sizeof(one));
	} while (ret < 0 && errno == EINTR);
}

void vu_vring_push(struct vu_vring *vr, uint16_t head, uint32_t len)
{
	uint16_t old = vr->used_idx;
	uint8_t *elem = vr->used + VIRTQ_USED_RING_OFF +
			VIRTQ_USED_ELEM_SIZE * (size_t)(old & (vr->num - 1));
	bool notify;

	vu_st32(elem, head);
	vu_st32(elem + 4, len);

	vr->used_idx++;
	vr->last_avail++;

	/* Release: the element is visible before the index covering it */
	vu_st16_release(vr->used + VIRTQ_USED_IDX_OFF, vr->used_idx);

	/*
	 * The driver changes its wish for an interrupt after it looked at the
	 * used index, so the wish is read after the index was published: a
	 * full barrier, as a store has to precede a load.
	 */
	atomic_thread_fence(memory_order_seq_cst);

	if (vr->event_idx) {
		uint16_t used_event = vu_ld16(vr->avail + VIRTQ_AVAIL_RING_OFF +
					      2 * (size_t)vr->num);

		notify = virtq_need_event(used_event, vr->used_idx, old);
	} else {
		notify = !(vu_ld16(vr->avail + VIRTQ_AVAIL_FLAGS_OFF) &
			   VIRTQ_AVAIL_F_NO_INTERRUPT);
	}

	if (notify)
		vu_signal(vr->call_fd);
}

bool vu_vring_arm(struct vu_vring *vr)
{
	/* Without event index the driver kicks for every request it makes */
	if (!vr->event_idx)
		return false;

	vu_st16(vr->used + VIRTQ_USED_RING_OFF +
			VIRTQ_USED_ELEM_SIZE * (size_t)vr->num,
		vr->last_avail);

	/* As in vu_vring_push(): the store precedes the load */
	atomic_thread_fence(memory_order_seq_cst);

	return vu_ld16_acquire(vr->avail + VIRTQ_AVAIL_IDX_OFF) !=
	       vr->last_avail;
}

void vu_vring_fail(struct vu_vring *vr)
{
	vr->broken = true;

	if (vr->reported)
		return;
	vr->reported = true;

	esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
		    "Not processing the request ring any more until the front-end restarts it\n");
	vu_signal(vr->err_fd);
}
