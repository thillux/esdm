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
 * The vhost-user protocol as far as a back-end of a virtio entropy device
 * needs it, after docs/interop/vhost-user.rst of QEMU, and the split virtqueue
 * of the virtio specification (1.2, section 2.7).
 *
 * Two byte orders meet here. The vhost-user messages travel between two
 * processes of the same host and are in its byte order. The virtqueue lives in
 * guest memory and is little endian - always for a virtio 1.0 device, and on
 * the little endian guests this back-end serves for a legacy one too, see
 * vhost_user_dev.c on VIRTIO_F_VERSION_1.
 *
 * Nothing here is part of an API of the ESDM: the file is shared by the
 * daemon, its tests and its fuzz harness only.
 */

#ifndef VHOST_USER_H
#define VHOST_USER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Message header
 ******************************************************************************/

struct vhost_user_hdr {
	uint32_t request;
	uint32_t flags;
	/* Size of the payload following the header */
	uint32_t size;
};

#define VHOST_USER_HDR_SIZE ((uint32_t)sizeof(struct vhost_user_hdr))

/* Lower 2 bits of the flags: the protocol version, always 1 */
#define VHOST_USER_VERSION_MASK 0x3U
#define VHOST_USER_VERSION 0x1U
/* Set on every message the back-end sends in reply */
#define VHOST_USER_REPLY_MASK (1U << 2)
/* The front-end wants an acknowledgement, see VHOST_USER_PROTOCOL_F_REPLY_ACK */
#define VHOST_USER_NEED_REPLY_MASK (1U << 3)

/******************************************************************************
 * Requests of the front-end
 ******************************************************************************/

enum vhost_user_request {
	VHOST_USER_NONE = 0,
	VHOST_USER_GET_FEATURES = 1,
	VHOST_USER_SET_FEATURES = 2,
	VHOST_USER_SET_OWNER = 3,
	VHOST_USER_RESET_OWNER = 4,
	VHOST_USER_SET_MEM_TABLE = 5,
	VHOST_USER_SET_LOG_BASE = 6,
	VHOST_USER_SET_LOG_FD = 7,
	VHOST_USER_SET_VRING_NUM = 8,
	VHOST_USER_SET_VRING_ADDR = 9,
	VHOST_USER_SET_VRING_BASE = 10,
	VHOST_USER_GET_VRING_BASE = 11,
	VHOST_USER_SET_VRING_KICK = 12,
	VHOST_USER_SET_VRING_CALL = 13,
	VHOST_USER_SET_VRING_ERR = 14,
	VHOST_USER_GET_PROTOCOL_FEATURES = 15,
	VHOST_USER_SET_PROTOCOL_FEATURES = 16,
	VHOST_USER_GET_QUEUE_NUM = 17,
	VHOST_USER_SET_VRING_ENABLE = 18,
	VHOST_USER_SEND_RARP = 19,
	VHOST_USER_NET_SET_MTU = 20,
	VHOST_USER_SET_BACKEND_REQ_FD = 21,
	VHOST_USER_IOTLB_MSG = 22,
	VHOST_USER_SET_VRING_ENDIAN = 23,
	VHOST_USER_GET_CONFIG = 24,
	VHOST_USER_SET_CONFIG = 25,
	VHOST_USER_CREATE_CRYPTO_SESSION = 26,
	VHOST_USER_CLOSE_CRYPTO_SESSION = 27,
	VHOST_USER_POSTCOPY_ADVISE = 28,
	VHOST_USER_POSTCOPY_LISTEN = 29,
	VHOST_USER_POSTCOPY_END = 30,
	VHOST_USER_GET_INFLIGHT_FD = 31,
	VHOST_USER_SET_INFLIGHT_FD = 32,
	VHOST_USER_GPU_SET_SOCKET = 33,
	VHOST_USER_RESET_DEVICE = 34,
	VHOST_USER_VRING_KICK = 35,
	VHOST_USER_GET_MAX_MEM_SLOTS = 36,
	VHOST_USER_ADD_MEM_REG = 37,
	VHOST_USER_REM_MEM_REG = 38,
	VHOST_USER_SET_STATUS = 39,
	VHOST_USER_GET_STATUS = 40,
	VHOST_USER_GET_SHARED_OBJECT = 41,
	VHOST_USER_SET_DEVICE_STATE_FD = 42,
	VHOST_USER_CHECK_DEVICE_STATE = 43,
	VHOST_USER_GET_SHMEM_CONFIG = 44,
	VHOST_USER_MAX
};

/*
 * The u64 payload of SET_VRING_KICK, SET_VRING_CALL and SET_VRING_ERR: the
 * vring index, and a flag telling that no file descriptor came along.
 */
#define VHOST_USER_VRING_IDX_MASK 0xffULL
#define VHOST_USER_VRING_NOFD_MASK (1ULL << 8)

/******************************************************************************
 * Payloads
 ******************************************************************************/

struct vhost_user_vring_state {
	uint32_t index;
	uint32_t num;
};

/* Flag of vhost_user_vring_addr.flags: log the writes to the used ring */
#define VHOST_VRING_F_LOG 0

struct vhost_user_vring_addr {
	uint32_t index;
	uint32_t flags;
	/* Addresses in the front-end's own address space */
	uint64_t desc_user_addr;
	uint64_t used_user_addr;
	uint64_t avail_user_addr;
	/* Guest physical address of the used ring, for the dirty log */
	uint64_t log_guest_addr;
};

struct vhost_user_mem_region {
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;
	uint64_t mmap_offset;
};

/* Payload of SET_MEM_TABLE: this, followed by nregions regions */
struct vhost_user_mem_table {
	uint32_t nregions;
	uint32_t padding;
};

/* Payload of ADD_MEM_REG and REM_MEM_REG */
struct vhost_user_mem_reg {
	uint64_t padding;
	struct vhost_user_mem_region region;
};

_Static_assert(sizeof(struct vhost_user_hdr) == 12, "vhost-user header");
_Static_assert(sizeof(struct vhost_user_vring_state) == 8, "vring state");
_Static_assert(sizeof(struct vhost_user_vring_addr) == 40, "vring address");
_Static_assert(sizeof(struct vhost_user_mem_region) == 32, "memory region");
_Static_assert(sizeof(struct vhost_user_mem_table) == 8, "memory table");
_Static_assert(sizeof(struct vhost_user_mem_reg) == 40, "single region");

/******************************************************************************
 * Feature bits
 ******************************************************************************/

/* Transport features of the virtio specification */
#define VIRTIO_F_NOTIFY_ON_EMPTY 24
#define VIRTIO_F_ANY_LAYOUT 27
#define VIRTIO_RING_F_INDIRECT_DESC 28
#define VIRTIO_RING_F_EVENT_IDX 29
#define VIRTIO_F_VERSION_1 32
#define VIRTIO_F_ACCESS_PLATFORM 33
#define VIRTIO_F_RING_PACKED 34
#define VIRTIO_F_IN_ORDER 35
#define VIRTIO_F_ORDER_PLATFORM 36
#define VIRTIO_F_NOTIFICATION_DATA 38
#define VIRTIO_F_RING_RESET 40

/* vhost features sharing the feature word */
#define VHOST_F_LOG_ALL 26
#define VHOST_USER_F_PROTOCOL_FEATURES 30

/* Protocol features of vhost-user */
#define VHOST_USER_PROTOCOL_F_MQ 0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD 1
#define VHOST_USER_PROTOCOL_F_RARP 2
#define VHOST_USER_PROTOCOL_F_REPLY_ACK 3
#define VHOST_USER_PROTOCOL_F_MTU 4
#define VHOST_USER_PROTOCOL_F_BACKEND_REQ 5
#define VHOST_USER_PROTOCOL_F_CROSS_ENDIAN 6
#define VHOST_USER_PROTOCOL_F_CRYPTO_SESSION 7
#define VHOST_USER_PROTOCOL_F_PAGEFAULT 8
#define VHOST_USER_PROTOCOL_F_CONFIG 9
#define VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD 10
#define VHOST_USER_PROTOCOL_F_HOST_NOTIFIER 11
#define VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD 12
#define VHOST_USER_PROTOCOL_F_RESET_DEVICE 13
#define VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS 14
#define VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS 15
#define VHOST_USER_PROTOCOL_F_STATUS 16

#define VHOST_USER_BIT(nr) (1ULL << (nr))

/******************************************************************************
 * The split virtqueue in guest memory - all fields little endian
 ******************************************************************************/

/* The virtio device ID of an entropy device */
#define VIRTIO_ID_RNG 4

/* Largest queue size of a split virtqueue */
#define VIRTQ_MAX_SIZE 32768

/* struct virtq_desc: le64 addr, le32 len, le16 flags, le16 next */
#define VIRTQ_DESC_SIZE 16
#define VIRTQ_DESC_ALIGN 16
#define VIRTQ_DESC_F_NEXT 1
#define VIRTQ_DESC_F_WRITE 2
#define VIRTQ_DESC_F_INDIRECT 4

/*
 * struct virtq_avail: le16 flags, le16 idx, le16 ring[num], and with
 * VIRTIO_RING_F_EVENT_IDX le16 used_event behind the ring
 */
#define VIRTQ_AVAIL_ALIGN 2
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
#define VIRTQ_AVAIL_FLAGS_OFF 0
#define VIRTQ_AVAIL_IDX_OFF 2
#define VIRTQ_AVAIL_RING_OFF 4

/*
 * struct virtq_used: le16 flags, le16 idx, struct { le32 id; le32 len; }
 * ring[num], and with VIRTIO_RING_F_EVENT_IDX le16 avail_event behind the ring
 */
#define VIRTQ_USED_ALIGN 4
#define VIRTQ_USED_FLAGS_OFF 0
#define VIRTQ_USED_IDX_OFF 2
#define VIRTQ_USED_RING_OFF 4
#define VIRTQ_USED_ELEM_SIZE 8

/*
 * Whether a notification is due for the move of an index from @old_idx to
 * @new_idx past @event_idx - vring_need_event() of the virtio specification.
 */
static inline int virtq_need_event(uint16_t event_idx, uint16_t new_idx,
				   uint16_t old_idx)
{
	return (uint16_t)(new_idx - event_idx - 1) <
	       (uint16_t)(new_idx - old_idx);
}

#ifdef __cplusplus
}
#endif

#endif /* VHOST_USER_H */
