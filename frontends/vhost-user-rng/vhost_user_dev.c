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
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "memset_secure.h"
#include "vhost_user_dev.h"

/*
 * What the device offers. The split ring with indirect descriptors and the
 * event index, as a virtio 1.0 device; the packed ring is not offered.
 *
 * VHOST_F_LOG_ALL is not offered either, and with it no live migration: the
 * dirty log would have to cover every byte written into guest memory, and the
 * QEMU device it would serve, vhost-user-rng, declares itself unmigratable
 * regardless, as do the generic vhost-user devices of Cloud Hypervisor in
 * effect. QEMU blocks the migration of a VM with such a device.
 */
#define VU_OFFERED_FEATURES                                                    \
	(VHOST_USER_BIT(VIRTIO_F_VERSION_1) |                                  \
	 VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC) |                         \
	 VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX) |                             \
	 VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES))

/*
 * Without VHOST_USER_PROTOCOL_F_CONFIG, as an entropy device has no
 * configuration space, nor INFLIGHT_SHMFD: a request taken off the ring and
 * not completed is still on it, see vhost_user_dev.h.
 */
#define VU_OFFERED_PROTOCOL_FEATURES                                           \
	(VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_MQ) |                            \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK) |                     \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_RESET_DEVICE) |                  \
	 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS))

/*
 * Features a front-end may set that change what the rings are or where their
 * addresses point - another ring layout, addresses through an IOMMU, a dirty
 * log to keep. Serving the device without them would be serving something
 * else, so SET_FEATURES with any of them fails. Other bits the device did not
 * offer are ignored: Cloud Hypervisor hands the guest a fixed set of transport
 * features rather than the back-end's, and passes on what the guest
 * acknowledged of it, such as VIRTIO_F_IN_ORDER - which this device, using
 * every request in order, complies with as it is.
 */
#define VU_REFUSED_FEATURES                                                    \
	(VHOST_USER_BIT(VIRTIO_F_RING_PACKED) |                                \
	 VHOST_USER_BIT(VIRTIO_F_ACCESS_PLATFORM) |                            \
	 VHOST_USER_BIT(VHOST_F_LOG_ALL))

/* Bound of a round of vu_dev_serve() in requests, served or not */
#define VU_ROUND_MAX_REQS 256

/******************************************************************************
 * Helpers
 ******************************************************************************/

static void vu_lock(struct vu_dev *dev)
{
	pthread_mutex_lock(&dev->lock);
}

static void vu_unlock(struct vu_dev *dev)
{
	pthread_mutex_unlock(&dev->lock);
}

/* Have the worker look at the device again */
static void vu_wake(struct vu_dev *dev)
{
	uint64_t one = 1;
	ssize_t ret;

	do {
		ret = write(dev->wake_fd, &one, sizeof(one));
	} while (ret < 0 && errno == EINTR);
}

/* Invalidate whatever the worker is serving, see vhost_user_dev.h */
static void vu_bump(struct vu_dev *dev)
{
	atomic_fetch_add(&dev->gen, 1);
}

static uint64_t vu_msg_u64(const struct vu_msg *msg)
{
	uint64_t v;

	memcpy(&v, msg->payload, sizeof(v));
	return v;
}

static void vu_reply_init(struct vu_reply *reply, const struct vu_msg *msg,
			  uint32_t size)
{
	reply->send = true;
	reply->hdr.request = msg->hdr.request;
	reply->hdr.flags = VHOST_USER_VERSION | VHOST_USER_REPLY_MASK;
	reply->hdr.size = size;
}

static void vu_reply_u64(struct vu_reply *reply, const struct vu_msg *msg,
			 uint64_t v)
{
	vu_reply_init(reply, msg, sizeof(v));
	memcpy(reply->payload, &v, sizeof(v));
}

/* Take file descriptor @i of the message over */
static int vu_msg_take_fd(struct vu_msg *msg, unsigned int i)
{
	int fd;

	if (i >= msg->nfds)
		return -1;

	fd = msg->fds[i];
	msg->fds[i] = -1;
	return fd;
}

static void vu_msg_close_fds(struct vu_msg *msg)
{
	unsigned int i;

	for (i = 0; i < msg->nfds; i++) {
		if (msg->fds[i] >= 0)
			close(msg->fds[i]);
		msg->fds[i] = -1;
	}
	msg->nfds = 0;
}

static struct vu_vring *vu_ring(struct vu_dev *dev, uint64_t index)
{
	if (index >= VU_NUM_QUEUES) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end names vring %llu, the device has %u\n",
			    (unsigned long long)index, VU_NUM_QUEUES);
		return NULL;
	}

	return &dev->vring[index];
}

/*
 * The notifiers come from the front-end and are written and read by the worker
 * while it holds the device lock. One that blocks - a pipe handed over as an
 * eventfd, filling up - would hold up the control thread as well, so they are
 * made non-blocking. The eventfds QEMU and Cloud Hypervisor hand over are
 * non-blocking already; for them nothing changes.
 */
static void vu_fd_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags >= 0 && !(flags & O_NONBLOCK))
		(void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Map a ring anew, and take its used index if it just started */
static void vu_refresh(struct vu_dev *dev, struct vu_vring *vr)
{
	(void)vu_vring_map(vr, dev->mem);

	if (vr->started && vr->need_sync && vr->used)
		vu_vring_sync(vr);
}

static void vu_refresh_all(struct vu_dev *dev)
{
	unsigned int i;

	for (i = 0; i < VU_NUM_QUEUES; i++)
		vu_refresh(dev, &dev->vring[i]);
}

/* Back to a ring the front-end has not touched, keeping the features */
static void vu_ring_reset(struct vu_dev *dev, struct vu_vring *vr)
{
	vu_vring_close_fds(vr);
	vu_vring_init(vr);
	vr->event_idx =
		!!(dev->features & VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX));
	vr->indirect =
		!!(dev->features & VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC));
}

/******************************************************************************
 * Request handlers - called with the device unlocked
 ******************************************************************************/

static int vu_get_features(struct vu_dev *dev, struct vu_msg *msg,
			   struct vu_reply *reply)
{
	vu_reply_u64(reply, msg, dev->offered_features);
	return 0;
}

static int vu_set_features(struct vu_dev *dev, struct vu_msg *msg,
			   struct vu_reply *reply)
{
	uint64_t features = vu_msg_u64(msg);
	unsigned int i;

	(void)reply;

	if (features & VU_REFUSED_FEATURES) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sets features 0x%llx the device cannot serve with\n",
			    (unsigned long long)(features & VU_REFUSED_FEATURES));
		return -EINVAL;
	}

	if (features & ~dev->offered_features)
		esdm_logger(LOGGER_DEBUG, LOGGER_C_VHOST,
			    "Ignoring features 0x%llx the device did not offer\n",
			    (unsigned long long)(features &
						 ~dev->offered_features));

	vu_lock(dev);
	dev->features = features & dev->offered_features;
	for (i = 0; i < VU_NUM_QUEUES; i++) {
		struct vu_vring *vr = &dev->vring[i];

		vr->event_idx = !!(dev->features &
				   VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX));
		vr->indirect = !!(dev->features &
				  VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC));

		/*
		 * Without the protocol features, rings are enabled from the
		 * start, there being no message to enable them with.
		 */
		if (!(dev->features &
		      VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES)))
			vr->enabled = true;
	}
	/* The event index changes the size of the rings */
	vu_refresh_all(dev);
	vu_bump(dev);
	vu_unlock(dev);

	return 0;
}

static int vu_get_protocol_features(struct vu_dev *dev, struct vu_msg *msg,
				    struct vu_reply *reply)
{
	vu_reply_u64(reply, msg, dev->offered_protocol_features);
	return 0;
}

static int vu_set_protocol_features(struct vu_dev *dev, struct vu_msg *msg,
				    struct vu_reply *reply)
{
	uint64_t features = vu_msg_u64(msg);

	(void)reply;

	vu_lock(dev);
	dev->protocol_features = features & dev->offered_protocol_features;
	vu_unlock(dev);

	if (features & ~dev->offered_protocol_features) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sets protocol features 0x%llx the device did not offer\n",
			    (unsigned long long)(features &
						 ~dev->offered_protocol_features));
		return -EINVAL;
	}

	return 0;
}

static int vu_set_owner(struct vu_dev *dev, struct vu_msg *msg,
			struct vu_reply *reply)
{
	(void)msg;
	(void)reply;

	vu_lock(dev);
	dev->owner = true;
	vu_unlock(dev);

	return 0;
}

/*
 * RESET_OWNER is deprecated, with the recommendation to take it as disabling
 * all rings: the rings are reset, the features stay. RESET_DEVICE resets the
 * device to the state before the features were negotiated. Both keep the
 * memory table, which belongs to the connection rather than the device.
 */
static int vu_reset(struct vu_dev *dev, struct vu_msg *msg,
		    struct vu_reply *reply)
{
	unsigned int i;

	(void)reply;

	vu_lock(dev);
	if (msg->hdr.request == VHOST_USER_RESET_DEVICE)
		dev->features = 0;
	for (i = 0; i < VU_NUM_QUEUES; i++)
		vu_ring_reset(dev, &dev->vring[i]);
	dev->kick_gen++;
	vu_bump(dev);
	vu_unlock(dev);

	return 0;
}

/*
 * Map every region of the table before anything changes: a table that cannot
 * be mapped in full leaves the one in place.
 */
static int vu_set_mem_table(struct vu_dev *dev, struct vu_msg *msg,
			    struct vu_reply *reply)
{
	struct vhost_user_mem_table table;
	struct vu_mem *mem, *old;
	unsigned int i;
	int ret = 0;

	(void)reply;

	memcpy(&table, msg->payload, sizeof(table));

	mem = calloc(1, sizeof(*mem));
	if (!mem)
		return -ENOMEM;

	for (i = 0; i < table.nregions; i++) {
		struct vhost_user_mem_region desc;
		struct vu_mem_region r;

		memcpy(&desc, msg->payload + sizeof(table) + i * sizeof(desc),
		       sizeof(desc));

		ret = vu_mem_region_map(&desc, msg->fds[i], &r);
		if (ret) {
			esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
				    "Cannot map memory region %u: %s\n", i,
				    strerror(-ret));
			goto err;
		}

		ret = vu_mem_add(mem, &r);
		if (ret) {
			esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
				    "Memory region %u overlaps another one\n",
				    i);
			vu_mem_region_unmap(&r);
			goto err;
		}

		esdm_logger(LOGGER_VERBOSE, LOGGER_C_VHOST,
			    "Memory region %u: guest 0x%llx, size 0x%llx\n", i,
			    (unsigned long long)r.gpa,
			    (unsigned long long)r.size);
	}

	vu_lock(dev);
	old = dev->mem;
	dev->mem = mem;
	vu_refresh_all(dev);
	vu_bump(dev);
	vu_unlock(dev);

	/* Nothing refers to the old table any more, see vhost_user_dev.h */
	vu_mem_clear(old);
	free(old);

	return 0;

err:
	vu_mem_clear(mem);
	free(mem);
	return ret;
}

static int vu_add_mem_reg(struct vu_dev *dev, struct vu_msg *msg,
			  struct vu_reply *reply)
{
	struct vhost_user_mem_reg reg;
	struct vu_mem_region r;
	int ret;

	(void)reply;

	memcpy(&reg, msg->payload, sizeof(reg));

	ret = vu_mem_region_map(&reg.region, msg->fds[0], &r);
	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Cannot map the memory region to add: %s\n",
			    strerror(-ret));
		return ret;
	}

	/*
	 * A new region changes no translation that succeeded before - regions
	 * do not overlap - so nothing the worker serves is invalidated. A ring
	 * that did not translate before may now.
	 */
	vu_lock(dev);
	ret = vu_mem_add(dev->mem, &r);
	if (!ret)
		vu_refresh_all(dev);
	vu_unlock(dev);

	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Cannot add the memory region: %s\n",
			    strerror(-ret));
		vu_mem_region_unmap(&r);
	}

	return ret;
}

static int vu_rem_mem_reg(struct vu_dev *dev, struct vu_msg *msg,
			  struct vu_reply *reply)
{
	struct vhost_user_mem_reg reg;
	struct vu_mem_region removed;
	int ret;

	(void)reply;

	memcpy(&reg, msg->payload, sizeof(reg));

	vu_lock(dev);
	ret = vu_mem_remove(dev->mem, reg.region.guest_phys_addr,
			    reg.region.userspace_addr, reg.region.memory_size,
			    &removed);
	if (!ret) {
		vu_refresh_all(dev);
		vu_bump(dev);
	}
	vu_unlock(dev);

	if (ret) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end removes a memory region the device does not have\n");
		return ret;
	}

	vu_mem_region_unmap(&removed);
	return 0;
}

static int vu_set_vring_num(struct vu_dev *dev, struct vu_msg *msg,
			    struct vu_reply *reply)
{
	struct vhost_user_vring_state state;
	struct vu_vring *vr;

	(void)reply;

	memcpy(&state, msg->payload, sizeof(state));
	vr = vu_ring(dev, state.index);
	if (!vr)
		return -EINVAL;

	/* A split virtqueue has a size that is a power of two */
	if (!state.num || state.num > VIRTQ_MAX_SIZE ||
	    (state.num & (state.num - 1))) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sets a queue size of %u\n", state.num);
		return -EINVAL;
	}

	vu_lock(dev);
	vr->num = (uint16_t)state.num;
	vu_refresh(dev, vr);
	vu_bump(dev);
	vu_unlock(dev);

	return 0;
}

static int vu_set_vring_addr(struct vu_dev *dev, struct vu_msg *msg,
			     struct vu_reply *reply)
{
	struct vhost_user_vring_addr addr;
	struct vu_vring *vr;
	int ret;

	(void)reply;

	memcpy(&addr, msg->payload, sizeof(addr));
	vr = vu_ring(dev, addr.index);
	if (!vr)
		return -EINVAL;

	/* Logging the used ring is part of the dirty log, see above */
	if (addr.flags) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sets vring flags 0x%x\n", addr.flags);
		return (addr.flags == (1U << VHOST_VRING_F_LOG)) ? -EOPNOTSUPP :
								  -EINVAL;
	}

	vu_lock(dev);
	vr->desc_uaddr = addr.desc_user_addr;
	vr->avail_uaddr = addr.avail_user_addr;
	vr->used_uaddr = addr.used_user_addr;
	vr->addr_set = true;
	ret = vu_vring_map(vr, dev->mem);
	if (!ret && vr->started && vr->need_sync && vr->used)
		vu_vring_sync(vr);
	vu_bump(dev);

	/*
	 * Without a memory table nothing translates yet, which the table
	 * arriving later mends. With one, the addresses are wrong.
	 */
	if (ret && !dev->mem->nregions)
		ret = 0;
	vu_unlock(dev);

	if (ret)
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "The vring addresses are %s\n",
			    ret == -EINVAL ? "misaligned" :
					     "not in the memory table");

	return ret;
}

static int vu_set_vring_base(struct vu_dev *dev, struct vu_msg *msg,
			     struct vu_reply *reply)
{
	struct vhost_user_vring_state state;
	struct vu_vring *vr;

	(void)reply;

	memcpy(&state, msg->payload, sizeof(state));
	vr = vu_ring(dev, state.index);
	if (!vr)
		return -EINVAL;

	/* The upper half is for packed virtqueues, see the specification */
	if (state.num > UINT16_MAX)
		return -EINVAL;

	vu_lock(dev);
	vr->last_avail = (uint16_t)state.num;
	vr->used_idx = (uint16_t)state.num;
	vr->need_sync = true;
	vu_refresh(dev, vr);
	vu_bump(dev);
	vu_unlock(dev);

	return 0;
}

/*
 * Stop the ring and tell where it stopped. Once the lock is held, the worker
 * writes nothing into guest memory, and the generation keeps it from going on
 * with what it is serving - see vhost_user_dev.h. Its notifiers are closed:
 * a stopped ring signals nothing, and the front-end hands new ones over when it
 * starts the ring again.
 */
static int vu_get_vring_base(struct vu_dev *dev, struct vu_msg *msg,
			     struct vu_reply *reply)
{
	struct vhost_user_vring_state state;
	struct vu_vring *vr;

	memcpy(&state, msg->payload, sizeof(state));
	vr = vu_ring(dev, state.index);
	if (!vr)
		return -EINVAL;

	vu_lock(dev);
	vr->started = false;
	vu_vring_close_fds(vr);
	dev->kick_gen++;
	vu_bump(dev);
	state.num = vr->last_avail;
	vu_unlock(dev);

	vu_reply_init(reply, msg, sizeof(state));
	memcpy(reply->payload, &state, sizeof(state));

	return 0;
}

/* SET_VRING_KICK, SET_VRING_CALL and SET_VRING_ERR */
static int vu_set_vring_fd(struct vu_dev *dev, struct vu_msg *msg,
			   struct vu_reply *reply)
{
	uint64_t v = vu_msg_u64(msg);
	bool nofd = !!(v & VHOST_USER_VRING_NOFD_MASK);
	struct vu_vring *vr;
	int fd;

	(void)reply;

	if (v & ~(VHOST_USER_VRING_IDX_MASK | VHOST_USER_VRING_NOFD_MASK))
		return -EINVAL;

	vr = vu_ring(dev, v & VHOST_USER_VRING_IDX_MASK);
	if (!vr)
		return -EINVAL;

	fd = nofd ? -1 : vu_msg_take_fd(msg, 0);
	if (fd >= 0)
		vu_fd_nonblock(fd);

	vu_lock(dev);
	switch (msg->hdr.request) {
	case VHOST_USER_SET_VRING_KICK:
		if (vr->kick_fd >= 0)
			close(vr->kick_fd);
		vr->kick_fd = fd;
		vr->kick_poll = nofd;
		dev->kick_gen++;

		/*
		 * The kick descriptor starts the ring. A stopped ring has no
		 * request in flight, so there is nothing to invalidate.
		 */
		if (!vr->started) {
			vr->started = true;
			vr->broken = false;
			vr->reported = false;
			vr->bad_requests = 0;
			vr->need_sync = true;
			vu_refresh(dev, vr);
		}
		break;
	case VHOST_USER_SET_VRING_CALL:
		if (vr->call_fd >= 0)
			close(vr->call_fd);
		vr->call_fd = fd;
		break;
	default:
		if (vr->err_fd >= 0)
			close(vr->err_fd);
		vr->err_fd = fd;
		break;
	}
	vu_unlock(dev);

	return 0;
}

static int vu_set_vring_enable(struct vu_dev *dev, struct vu_msg *msg,
			       struct vu_reply *reply)
{
	struct vhost_user_vring_state state;
	struct vu_vring *vr;

	(void)reply;

	memcpy(&state, msg->payload, sizeof(state));
	vr = vu_ring(dev, state.index);
	if (!vr)
		return -EINVAL;

	if (state.num > 1)
		return -EINVAL;

	vu_lock(dev);
	vr->enabled = !!state.num;
	/* A disabled ring is served no more data, not even what is under way */
	if (!state.num)
		vu_bump(dev);
	vu_unlock(dev);

	return 0;
}

static int vu_get_queue_num(struct vu_dev *dev, struct vu_msg *msg,
			    struct vu_reply *reply)
{
	(void)dev;

	vu_reply_u64(reply, msg, VU_NUM_QUEUES);
	return 0;
}

static int vu_get_max_mem_slots(struct vu_dev *dev, struct vu_msg *msg,
				struct vu_reply *reply)
{
	(void)dev;

	vu_reply_u64(reply, msg, VU_MEM_MAX_REGIONS);
	return 0;
}

/******************************************************************************
 * Request table
 ******************************************************************************/

/* Payload sizes beyond an exact one */
#define VU_SIZE_ANY (-1)
#define VU_SIZE_TABLE (-2)

/* File descriptors a request carries */
enum vu_fds {
	VU_FDS_NONE,
	VU_FDS_ONE,
	/* None or one, which is closed - see REM_MEM_REG */
	VU_FDS_OPTIONAL,
	/* One unless the payload carries VHOST_USER_VRING_NOFD_MASK */
	VU_FDS_VRING,
	/* One per region of SET_MEM_TABLE */
	VU_FDS_TABLE,
	/* Whatever came, all closed */
	VU_FDS_ANY,
};

/*
 * How a request the device does not support is answered. It is only sent
 * with a protocol feature the device does not offer, so a front-end sending
 * it is broken - but one waiting for a reply would wait for good. So a request
 * with a reply gets the one the specification has for a failure where it has
 * one, and the connection is closed where it has none: the front-end then
 * fails at once.
 */
enum vu_unsupported {
	/* No reply by itself: a failure with REPLY_ACK, nothing otherwise */
	VU_UNSUP_ACK,
	/* A u64 reply, non-zero for a failure */
	VU_UNSUP_U64_ERR,
	/* GET_STATUS: a status of 0 */
	VU_UNSUP_U64_ZERO,
	/* GET_CONFIG: a reply without payload is a failure */
	VU_UNSUP_EMPTY,
	/* SET_DEVICE_STATE_FD: a failure without a descriptor */
	VU_UNSUP_DEVSTATE,
	/* GET_SHMEM_CONFIG: no shared memory regions - the truth */
	VU_UNSUP_SHMEM,
	/* The reply needs what the device does not have */
	VU_UNSUP_DISCONNECT,
};

struct vu_request_info {
	const char *name;
	int (*handler)(struct vu_dev *dev, struct vu_msg *msg,
		       struct vu_reply *reply);
	int size;
	enum vu_fds fds;
	enum vu_unsupported unsupported;
};

#define VU_REQ(_req, _handler, _size, _fds)                                    \
	[_req] = { .name = #_req,                                              \
		   .handler = _handler,                                        \
		   .size = _size,                                              \
		   .fds = _fds }

#define VU_UNSUP(_req, _how)                                                   \
	[_req] = { .name = #_req,                                              \
		   .size = VU_SIZE_ANY,                                        \
		   .fds = VU_FDS_ANY,                                          \
		   .unsupported = _how }

static const struct vu_request_info vu_requests[VHOST_USER_MAX] = {
	VU_REQ(VHOST_USER_GET_FEATURES, vu_get_features, 0, VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_FEATURES, vu_set_features, 8, VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_OWNER, vu_set_owner, 0, VU_FDS_NONE),
	VU_REQ(VHOST_USER_RESET_OWNER, vu_reset, 0, VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_MEM_TABLE, vu_set_mem_table, VU_SIZE_TABLE,
	       VU_FDS_TABLE),
	VU_UNSUP(VHOST_USER_SET_LOG_BASE, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_SET_LOG_FD, VU_UNSUP_ACK),
	VU_REQ(VHOST_USER_SET_VRING_NUM, vu_set_vring_num,
	       sizeof(struct vhost_user_vring_state), VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_VRING_ADDR, vu_set_vring_addr,
	       sizeof(struct vhost_user_vring_addr), VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_VRING_BASE, vu_set_vring_base,
	       sizeof(struct vhost_user_vring_state), VU_FDS_NONE),
	VU_REQ(VHOST_USER_GET_VRING_BASE, vu_get_vring_base,
	       sizeof(struct vhost_user_vring_state), VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_VRING_KICK, vu_set_vring_fd, 8, VU_FDS_VRING),
	VU_REQ(VHOST_USER_SET_VRING_CALL, vu_set_vring_fd, 8, VU_FDS_VRING),
	VU_REQ(VHOST_USER_SET_VRING_ERR, vu_set_vring_fd, 8, VU_FDS_VRING),
	VU_REQ(VHOST_USER_GET_PROTOCOL_FEATURES, vu_get_protocol_features, 0,
	       VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_PROTOCOL_FEATURES, vu_set_protocol_features, 8,
	       VU_FDS_NONE),
	VU_REQ(VHOST_USER_GET_QUEUE_NUM, vu_get_queue_num, 0, VU_FDS_NONE),
	VU_REQ(VHOST_USER_SET_VRING_ENABLE, vu_set_vring_enable,
	       sizeof(struct vhost_user_vring_state), VU_FDS_NONE),
	VU_UNSUP(VHOST_USER_SEND_RARP, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_NET_SET_MTU, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_SET_BACKEND_REQ_FD, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_IOTLB_MSG, VU_UNSUP_U64_ERR),
	VU_UNSUP(VHOST_USER_SET_VRING_ENDIAN, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_GET_CONFIG, VU_UNSUP_EMPTY),
	VU_UNSUP(VHOST_USER_SET_CONFIG, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_CREATE_CRYPTO_SESSION, VU_UNSUP_DISCONNECT),
	VU_UNSUP(VHOST_USER_CLOSE_CRYPTO_SESSION, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_POSTCOPY_ADVISE, VU_UNSUP_DISCONNECT),
	VU_UNSUP(VHOST_USER_POSTCOPY_LISTEN, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_POSTCOPY_END, VU_UNSUP_U64_ERR),
	VU_UNSUP(VHOST_USER_GET_INFLIGHT_FD, VU_UNSUP_DISCONNECT),
	VU_UNSUP(VHOST_USER_SET_INFLIGHT_FD, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_GPU_SET_SOCKET, VU_UNSUP_ACK),
	VU_REQ(VHOST_USER_RESET_DEVICE, vu_reset, 0, VU_FDS_NONE),
	VU_UNSUP(VHOST_USER_VRING_KICK, VU_UNSUP_ACK),
	VU_REQ(VHOST_USER_GET_MAX_MEM_SLOTS, vu_get_max_mem_slots, 0,
	       VU_FDS_NONE),
	VU_REQ(VHOST_USER_ADD_MEM_REG, vu_add_mem_reg,
	       sizeof(struct vhost_user_mem_reg), VU_FDS_ONE),
	VU_REQ(VHOST_USER_REM_MEM_REG, vu_rem_mem_reg,
	       sizeof(struct vhost_user_mem_reg), VU_FDS_OPTIONAL),
	VU_UNSUP(VHOST_USER_SET_STATUS, VU_UNSUP_ACK),
	VU_UNSUP(VHOST_USER_GET_STATUS, VU_UNSUP_U64_ZERO),
	VU_UNSUP(VHOST_USER_GET_SHARED_OBJECT, VU_UNSUP_DISCONNECT),
	VU_UNSUP(VHOST_USER_SET_DEVICE_STATE_FD, VU_UNSUP_DEVSTATE),
	VU_UNSUP(VHOST_USER_CHECK_DEVICE_STATE, VU_UNSUP_U64_ERR),
	VU_UNSUP(VHOST_USER_GET_SHMEM_CONFIG, VU_UNSUP_SHMEM),
};

/*
 * Whether the payload and the file descriptors are what the request has to
 * carry. Anything else is a front-end that does not speak the protocol, not
 * a request that failed.
 */
static bool vu_msg_valid(const struct vu_request_info *ri,
			 const struct vu_msg *msg)
{
	uint32_t nregions = 0;

	switch (ri->size) {
	case VU_SIZE_ANY:
		break;
	case VU_SIZE_TABLE: {
		struct vhost_user_mem_table table;

		if (msg->hdr.size < sizeof(table))
			return false;
		memcpy(&table, msg->payload, sizeof(table));
		nregions = table.nregions;
		if (nregions > VU_MAX_TABLE_REGIONS ||
		    msg->hdr.size != sizeof(table) +
					     nregions * sizeof(struct vhost_user_mem_region))
			return false;
		break;
	}
	default:
		if (msg->hdr.size != (uint32_t)ri->size)
			return false;
		break;
	}

	switch (ri->fds) {
	case VU_FDS_NONE:
		return msg->nfds == 0;
	case VU_FDS_ONE:
		return msg->nfds == 1;
	case VU_FDS_OPTIONAL:
		return msg->nfds <= 1;
	case VU_FDS_VRING:
		if (vu_msg_u64(msg) & VHOST_USER_VRING_NOFD_MASK)
			return msg->nfds == 0;
		return msg->nfds == 1;
	case VU_FDS_TABLE:
		return msg->nfds == nregions;
	case VU_FDS_ANY:
		return true;
	}

	return false;
}

/* Answer a request the device does not support */
static int vu_unsupported(struct vu_dev *dev, const struct vu_request_info *ri,
			  struct vu_msg *msg, struct vu_reply *reply)
{
	(void)dev;

	esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
		    "Front-end sends %s, which the device does not support\n",
		    ri->name);

	switch (ri->unsupported) {
	case VU_UNSUP_ACK:
		return -EOPNOTSUPP;
	case VU_UNSUP_U64_ERR:
		vu_reply_u64(reply, msg, 1);
		return 0;
	case VU_UNSUP_U64_ZERO:
		vu_reply_u64(reply, msg, 0);
		return 0;
	case VU_UNSUP_EMPTY:
		vu_reply_init(reply, msg, 0);
		return 0;
	case VU_UNSUP_DEVSTATE:
		vu_reply_u64(reply, msg, 1 | VHOST_USER_VRING_NOFD_MASK);
		return 0;
	case VU_UNSUP_SHMEM:
		/* u32 nregions, u32 padding, u64 sizes[256] - all 0 */
		vu_reply_init(reply, msg, 8 + 256 * 8);
		memset(reply->payload, 0, 8 + 256 * 8);
		return 0;
	case VU_UNSUP_DISCONNECT:
		return VU_DISCONNECT;
	}

	return VU_DISCONNECT;
}

int vu_dev_handle(struct vu_dev *dev, struct vu_msg *msg,
		  struct vu_reply *reply)
{
	const struct vu_request_info *ri = NULL;
	uint32_t request = msg->hdr.request;
	bool need_reply = !!(msg->hdr.flags & VHOST_USER_NEED_REPLY_MASK);
	int ret;

	reply->send = false;

	if (request < VHOST_USER_MAX && vu_requests[request].name)
		ri = &vu_requests[request];

	if (!ri) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sends unknown request %u\n", request);
		ret = -EOPNOTSUPP;
		goto ack;
	}

	esdm_logger(LOGGER_DEBUG, LOGGER_C_VHOST,
		    "%s, %u bytes, %u file descriptors%s\n", ri->name,
		    msg->hdr.size, msg->nfds, need_reply ? ", reply" : "");

	if (!vu_msg_valid(ri, msg)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sends %s with %u bytes and %u file descriptors, closing the connection\n",
			    ri->name, msg->hdr.size, msg->nfds);
		ret = VU_DISCONNECT;
		goto out;
	}

	if (ri->handler)
		ret = ri->handler(dev, msg, reply);
	else
		ret = vu_unsupported(dev, ri, msg, reply);

	if (ret == VU_DISCONNECT)
		goto out;

	if (ret)
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST, "%s failed: %s\n",
			    ri->name, strerror(-ret));

ack:
	/*
	 * A request without a reply of its own is acknowledged when asked
	 * for - as negotiated by now, so that SET_PROTOCOL_FEATURES itself is
	 * acknowledged once it switches the acknowledgements on.
	 */
	if (!reply->send && need_reply &&
	    (dev->protocol_features &
	     VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK)))
		vu_reply_u64(reply, msg, ret ? (uint64_t)-ret : 0);
	ret = 0;

out:
	vu_msg_close_fds(msg);
	if (ret != VU_DISCONNECT)
		vu_wake(dev);
	return ret;
}

/******************************************************************************
 * The connection
 ******************************************************************************/

/*
 * Wait for @fd to become readable, at most @timeout_ms (-1: forever). Returns
 * 0, -ETIMEDOUT, or -EINTR when @stop_fd became readable first.
 */
static int vu_conn_wait(int fd, int stop_fd, int timeout_ms)
{
	struct pollfd pfd[2] = {
		{ .fd = fd, .events = POLLIN },
		{ .fd = stop_fd, .events = POLLIN },
	};
	int ret;

	do {
		ret = poll(pfd, stop_fd >= 0 ? 2 : 1, timeout_ms);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		return -errno;
	if (!ret)
		return -ETIMEDOUT;
	if (stop_fd >= 0 && pfd[1].revents)
		return -EINTR;

	return 0;
}

/* Read the rest of a message, @len bytes */
static int vu_conn_read(int fd, int stop_fd, uint8_t *buf, size_t len)
{
	while (len) {
		ssize_t n;
		int ret = vu_conn_wait(fd, stop_fd, VU_MSG_TIMEOUT_MS);

		if (ret)
			return ret;

		/* File descriptors only come with the start of a message */
		n = recv(fd, buf, len, MSG_DONTWAIT);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (!n)
			return -ECONNRESET;

		buf += n;
		len -= (size_t)n;
	}

	return 0;
}

/* Collect the descriptors of SCM_RIGHTS, closing those beyond VU_MAX_FDS */
static bool vu_conn_collect_fds(struct msghdr *mh, struct vu_msg *msg)
{
	struct cmsghdr *cmsg;
	bool fit = true;

	for (cmsg = CMSG_FIRSTHDR(mh); cmsg; cmsg = CMSG_NXTHDR(mh, cmsg)) {
		size_t i, n;

		if (cmsg->cmsg_level != SOL_SOCKET ||
		    cmsg->cmsg_type != SCM_RIGHTS ||
		    cmsg->cmsg_len < CMSG_LEN(0))
			continue;

		n = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		for (i = 0; i < n; i++) {
			int fd;

			memcpy(&fd, CMSG_DATA(cmsg) + i * sizeof(int),
			       sizeof(fd));
			if (msg->nfds < VU_MAX_FDS) {
				msg->fds[msg->nfds++] = fd;
			} else {
				close(fd);
				fit = false;
			}
		}
	}

	return fit;
}

int vu_conn_recv(int fd, int stop_fd, struct vu_msg *msg)
{
	union {
		char buf[CMSG_SPACE(sizeof(int) * VU_MAX_FDS)];
		struct cmsghdr align;
	} ctl;
	struct iovec iov = { .iov_base = &msg->hdr,
			     .iov_len = sizeof(msg->hdr) };
	struct msghdr mh = { .msg_iov = &iov,
			     .msg_iovlen = 1,
			     .msg_control = ctl.buf,
			     .msg_controllen = sizeof(ctl.buf) };
	uint32_t flags;
	ssize_t n;
	int ret;

	msg->nfds = 0;

	ret = vu_conn_wait(fd, stop_fd, -1);
	if (ret)
		return ret;

	do {
		n = recvmsg(fd, &mh, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return errno == EAGAIN ? -EAGAIN : -errno;
	if (!n)
		return -ECONNRESET;

	if (!vu_conn_collect_fds(&mh, msg) || (mh.msg_flags & MSG_CTRUNC)) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sends more than %u file descriptors with a message\n",
			    VU_MAX_FDS);
		ret = -EMSGSIZE;
		goto err;
	}

	ret = vu_conn_read(fd, stop_fd, (uint8_t *)&msg->hdr + n,
			   sizeof(msg->hdr) - (size_t)n);
	if (ret)
		goto err;

	flags = msg->hdr.flags;
	if ((flags & VHOST_USER_VERSION_MASK) != VHOST_USER_VERSION ||
	    (flags & ~(VHOST_USER_VERSION_MASK | VHOST_USER_NEED_REPLY_MASK))) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sends a message with flags 0x%x\n",
			    flags);
		ret = -EPROTO;
		goto err;
	}

	if (msg->hdr.size > VU_MAX_PAYLOAD) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Front-end sends a message of %u bytes\n",
			    msg->hdr.size);
		ret = -EMSGSIZE;
		goto err;
	}

	ret = vu_conn_read(fd, stop_fd, msg->payload, msg->hdr.size);
	if (ret)
		goto err;

	return 0;

err:
	vu_msg_close_fds(msg);
	return ret;
}

int vu_conn_send(int fd, const struct vu_reply *reply)
{
	uint8_t buf[sizeof(reply->hdr) + sizeof(reply->payload)];
	size_t len = sizeof(reply->hdr) + reply->hdr.size, off = 0;

	if (reply->hdr.size > sizeof(reply->payload))
		return -EINVAL;

	memcpy(buf, &reply->hdr, sizeof(reply->hdr));
	memcpy(buf + sizeof(reply->hdr), reply->payload, reply->hdr.size);

	while (off < len) {
		ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		off += (size_t)n;
	}

	return 0;
}

int vu_conn_serve(struct vu_dev *dev, int fd, int stop_fd)
{
	struct vu_msg msg;
	struct vu_reply reply;
	int ret;

	ret = vu_conn_recv(fd, stop_fd, &msg);
	if (ret == -EAGAIN)
		return 0;
	if (ret)
		return ret;

	if (vu_dev_handle(dev, &msg, &reply) == VU_DISCONNECT)
		return -EPROTO;

	if (reply.send)
		return vu_conn_send(fd, &reply);

	return 0;
}

/******************************************************************************
 * The device
 ******************************************************************************/

int vu_dev_init(struct vu_dev *dev)
{
	unsigned int i;
	int ret;

	memset(dev, 0, sizeof(*dev));
	dev->wake_fd = -1;
	atomic_init(&dev->gen, 0);
	atomic_init(&dev->shutdown, false);

	dev->offered_features = VU_OFFERED_FEATURES;
	dev->offered_protocol_features = VU_OFFERED_PROTOCOL_FEATURES;

	for (i = 0; i < VU_NUM_QUEUES; i++)
		vu_vring_init(&dev->vring[i]);

	dev->mem = calloc(1, sizeof(*dev->mem));
	if (!dev->mem)
		return -ENOMEM;

	dev->wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (dev->wake_fd < 0) {
		ret = -errno;
		goto err;
	}

	ret = -pthread_mutex_init(&dev->lock, NULL);
	if (ret)
		goto err;

	return 0;

err:
	if (dev->wake_fd >= 0)
		close(dev->wake_fd);
	dev->wake_fd = -1;
	free(dev->mem);
	dev->mem = NULL;
	return ret;
}

void vu_dev_fini(struct vu_dev *dev)
{
	unsigned int i;

	if (!dev->mem)
		return;

	for (i = 0; i < VU_NUM_QUEUES; i++)
		vu_vring_close_fds(&dev->vring[i]);
	vu_mem_clear(dev->mem);
	free(dev->mem);
	dev->mem = NULL;

	if (dev->wake_fd >= 0)
		close(dev->wake_fd);
	dev->wake_fd = -1;

	pthread_mutex_destroy(&dev->lock);
}

void vu_dev_set_ratelimit(struct vu_dev *dev, uint64_t max_bytes,
			  uint64_t period_ms)
{
	struct vu_ratelimit *rl = &dev->rl;

	if (!max_bytes || !period_ms) {
		memset(rl, 0, sizeof(*rl));
		return;
	}

	rl->max_bytes = max_bytes;
	rl->period_ms = period_ms;
	rl->tokens = (double)max_bytes;
	clock_gettime(CLOCK_MONOTONIC, &rl->last);
}

void vu_dev_disconnect(struct vu_dev *dev)
{
	unsigned int i;

	vu_lock(dev);
	dev->features = 0;
	dev->protocol_features = 0;
	dev->owner = false;
	for (i = 0; i < VU_NUM_QUEUES; i++)
		vu_ring_reset(dev, &dev->vring[i]);
	dev->kick_gen++;
	vu_bump(dev);
	/* The worker holds no pointer into it beyond the generation */
	vu_mem_clear(dev->mem);
	vu_unlock(dev);

	vu_wake(dev);
}

void vu_dev_shutdown(struct vu_dev *dev)
{
	atomic_store(&dev->shutdown, true);

	vu_lock(dev);
	vu_bump(dev);
	vu_unlock(dev);

	vu_wake(dev);
}

void vu_dev_worker_view(struct vu_dev *dev, struct vu_worker_view *view)
{
	struct vu_vring *vr = &dev->vring[0];

	vu_lock(dev);

	/*
	 * The worker waits on a duplicate of the kick descriptor, which only it
	 * closes: the control thread closes and replaces the descriptor of the
	 * ring whenever the front-end says so, and a number the worker passed
	 * to poll(2) must not become another file meanwhile.
	 */
	if (view->kick_gen != dev->kick_gen) {
		if (view->kick_fd >= 0)
			close(view->kick_fd);
		view->kick_fd = -1;
		if (vr->kick_fd >= 0)
			view->kick_fd = fcntl(vr->kick_fd, F_DUPFD_CLOEXEC, 0);
		view->kick_gen = dev->kick_gen;
	}

	view->poll = vr->kick_poll && vu_vring_runnable(vr);

	vu_unlock(dev);
}

bool vu_dev_interrupted(struct vu_dev *dev, unsigned int gen)
{
	return atomic_load(&dev->shutdown) || atomic_load(&dev->gen) != gen;
}

/******************************************************************************
 * Serving the guest
 ******************************************************************************/

/*
 * Take what the rate limit allows of the @len bytes a request wants. A request
 * waits until the bucket holds all of it - or, for one larger than the bucket,
 * as much as the bucket holds - rather than being served in slivers.
 *
 * @return 0 with *len set to the bytes to serve, or the milliseconds to wait
 */
static int vu_rl_take(struct vu_ratelimit *rl, uint32_t *len)
{
	struct timespec now;
	double elapsed_ms, need, wait_ms;

	if (!rl->max_bytes)
		return 0;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ms = (double)(now.tv_sec - rl->last.tv_sec) * 1e3 +
		     (double)(now.tv_nsec - rl->last.tv_nsec) / 1e6;
	rl->last = now;

	if (elapsed_ms > 0)
		rl->tokens += elapsed_ms * (double)rl->max_bytes /
			      (double)rl->period_ms;
	if (rl->tokens > (double)rl->max_bytes)
		rl->tokens = (double)rl->max_bytes;

	need = (double)*len < (double)rl->max_bytes ? (double)*len :
						      (double)rl->max_bytes;
	if (rl->tokens < need) {
		wait_ms = (need - rl->tokens) * (double)rl->period_ms /
			  (double)rl->max_bytes;
		if (wait_ms >= (double)INT_MAX)
			return INT_MAX;
		return (int)wait_ms + 1;
	}

	if ((double)*len > rl->tokens)
		*len = (uint32_t)rl->tokens;
	rl->tokens -= (double)*len;

	return 0;
}

static void vu_rl_refund(struct vu_ratelimit *rl, uint32_t len)
{
	if (!rl->max_bytes)
		return;

	rl->tokens += (double)len;
	if (rl->tokens > (double)rl->max_bytes)
		rl->tokens = (double)rl->max_bytes;
}

int vu_dev_serve(struct vu_dev *dev, const struct vu_source *src,
		 uint8_t *buf)
{
	struct vu_vring *vr = &dev->vring[0];
	uint32_t served = 0, rounds = 0;
	struct vu_req req;

	for (;;) {
		enum vu_pop pop;
		unsigned int gen;
		uint32_t len;
		int ret;

		/* Step 1: take a request off the ring */
		vu_lock(dev);
		if (atomic_load(&dev->shutdown) || !vu_vring_runnable(vr)) {
			vu_unlock(dev);
			return -1;
		}
		if (served >= VU_ROUND_MAX_BYTES ||
		    rounds++ >= VU_ROUND_MAX_REQS) {
			vu_unlock(dev);
			return 0;
		}

		gen = atomic_load(&dev->gen);
		pop = vu_vring_pop(vr, dev->mem, VU_REQ_MAX_BYTES, &req);
		switch (pop) {
		case VU_POP_EMPTY:
			if (vu_vring_arm(vr)) {
				vu_unlock(dev);
				continue;
			}
			vu_unlock(dev);
			return -1;
		case VU_POP_BROKEN:
			vu_vring_fail(vr);
			vu_unlock(dev);
			return -1;
		case VU_POP_REQ:
			break;
		}

		/* A malformed request or one without room is done at once */
		if (req.bad || !req.len) {
			vu_vring_push(vr, req.head, 0);
			vu_unlock(dev);
			continue;
		}
		vu_unlock(dev);

		/* Step 2: the random bytes, without the lock */
		len = req.len;
		ret = vu_rl_take(&dev->rl, &len);
		if (ret)
			return ret;

		if (src->fill(src->ctx, buf, len, gen)) {
			memset_secure(buf, 0, len);
			vu_rl_refund(&dev->rl, len);
			return 0;
		}

		/* Step 3: serve them, unless the request went stale */
		vu_lock(dev);
		if (atomic_load(&dev->gen) != gen) {
			vu_unlock(dev);
			memset_secure(buf, 0, len);
			vu_rl_refund(&dev->rl, len);
			continue;
		}
		vu_req_fill(&req, buf, len);
		vu_vring_push(vr, req.head, len);
		vu_unlock(dev);

		memset_secure(buf, 0, len);
		served += len;
	}
}
