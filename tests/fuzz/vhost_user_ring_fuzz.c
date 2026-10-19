/*
 * Fuzz harness: the request ring of esdm-vhost-user-rng
 *
 * The memory of the guest, which the guest writes while the back-end parses
 * it: the descriptor table, the available ring, indirect tables, the
 * addresses and lengths of the buffers - and the used ring, which belongs to
 * the device but which the guest can scribble over as well. This is the most
 * hostile input the ESDM meets anywhere.
 *
 * An input is a few bytes of configuration - the features, the queue size,
 * the ring base the front-end gives, where the rings lie, and whether a
 * control message comes in while a request waits for its random bytes - and
 * then the image of guest memory: three regions, the first two adjacent, the
 * third behind a gap. The rings are set up through the control messages, as a
 * front-end does, and the back-end serves them from a source of the harness
 * until it has nothing left to do.
 *
 * Beyond crashes the harness holds the back-end to writing nothing but the
 * used ring and the bytes of the source, and those only into buffers the
 * guest made writable: every byte of guest memory that changed has to lie in
 * the used ring or in a buffer of a descriptor with VIRTQ_DESC_F_WRITE - of the
 * table, or of an indirect table it names -, and has to be a byte of the
 * source there. A used element has to name a descriptor of the queue and a
 * length the back-end serves at most. The control message coming in while a
 * request waits - a stop, a disable, a region removed or replaced, a reset -
 * is the case of the generation: the request goes stale and none of its bytes
 * may arrive.
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
#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "fuzz.h"
#include "vhost_user_dev.h"

/* The regions: the second adjacent to the first, the third behind a gap */
#define FUZZ_NREGIONS 3
static const struct {
	uint64_t gpa;
	uint64_t uaddr;
	size_t size;
} fuzz_layout[FUZZ_NREGIONS] = {
	{ 0x100000, 0x7f0000000000ULL, 0x10000 },
	{ 0x110000, 0x7e0000000000ULL, 0x4000 },
	{ 0x200000, 0x7d0000000000ULL, 0x1000 },
};

struct fuzz_region {
	int fd;
	/* The harness' own view of the memory */
	uint8_t *ptr;
	/* What it held before the back-end served */
	uint8_t *snap;
	/* The bytes the back-end may write */
	uint8_t *allowed;
};

static struct fuzz_region fuzz_mem[FUZZ_NREGIONS];
static uint8_t *fuzz_buf;

/* Byte the source serves */
#define FUZZ_FILL 0x5a

/* Configuration bytes at the start of an input */
#define FUZZ_CFG_LEN 6
#define FUZZ_F_EVENT_IDX 0x01
#define FUZZ_F_INDIRECT 0x02
#define FUZZ_F_INJECT 0x04
/* Without the protocol features, rings start enabled */
#define FUZZ_F_NO_PROTOCOL 0x08

/* Rounds of serving per input */
#define FUZZ_MAX_ROUNDS 16

/* The injection: which message, and at which call of the source */
static struct {
	struct vu_dev *dev;
	unsigned int at;
	unsigned int which;
	unsigned int calls;
	bool done;
} fuzz_inject;

static unsigned int fuzz_open_fds(void)
{
	DIR *d = opendir("/proc/self/fd");
	unsigned int n = 0;

	if (!d)
		return 0;
	while (readdir(d))
		n++;
	closedir(d);

	return n;
}

/******************************************************************************
 * Control messages
 ******************************************************************************/

static void fuzz_msg(struct vu_dev *dev, uint32_t request, const void *payload,
		     uint32_t size, const int *fds, unsigned int nfds)
{
	struct vu_msg msg;
	struct vu_reply reply;
	unsigned int i;

	msg.hdr.request = request;
	msg.hdr.flags = VHOST_USER_VERSION;
	msg.hdr.size = size;
	if (size)
		memcpy(msg.payload, payload, size);
	for (i = 0; i < nfds; i++)
		msg.fds[i] = fds[i];
	msg.nfds = nfds;

	(void)vu_dev_handle(dev, &msg, &reply);
}

static void fuzz_u64(struct vu_dev *dev, uint32_t request, uint64_t v)
{
	fuzz_msg(dev, request, &v, sizeof(v), NULL, 0);
}

static void fuzz_state(struct vu_dev *dev, uint32_t request, uint32_t index,
		       uint32_t num)
{
	struct vhost_user_vring_state s = { .index = index, .num = num };

	fuzz_msg(dev, request, &s, sizeof(s), NULL, 0);
}

static void fuzz_fd_msg(struct vu_dev *dev, uint32_t request)
{
	uint64_t idx = 0;
	int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

	if (fd < 0)
		abort();
	fuzz_msg(dev, request, &idx, sizeof(idx), &fd, 1);
}

static void fuzz_region_desc(unsigned int i, struct vhost_user_mem_region *r)
{
	r->guest_phys_addr = fuzz_layout[i].gpa;
	r->memory_size = fuzz_layout[i].size;
	r->userspace_addr = fuzz_layout[i].uaddr;
	r->mmap_offset = 0;
}

static void fuzz_mem_table(struct vu_dev *dev)
{
	uint8_t buf[8 + FUZZ_NREGIONS * 32] = { FUZZ_NREGIONS };
	int fds[FUZZ_NREGIONS];
	unsigned int i;

	for (i = 0; i < FUZZ_NREGIONS; i++) {
		struct vhost_user_mem_region r;

		fuzz_region_desc(i, &r);
		memcpy(buf + 8 + i * sizeof(r), &r, sizeof(r));
		fds[i] = fcntl(fuzz_mem[i].fd, F_DUPFD_CLOEXEC, 0);
		if (fds[i] < 0)
			abort();
	}
	fuzz_msg(dev, VHOST_USER_SET_MEM_TABLE, buf, sizeof(buf), fds,
		 FUZZ_NREGIONS);
}

/*
 * A control message arriving while a request waits for its random bytes. The
 * source is called without the device lock, as a front-end's message arrives
 * on the other thread at any time.
 */
static void fuzz_inject_msg(struct vu_dev *dev, unsigned int which)
{
	struct vhost_user_mem_reg reg = { 0 };

	switch (which) {
	case 0:
		fuzz_state(dev, VHOST_USER_GET_VRING_BASE, 0, 0);
		break;
	case 1:
		fuzz_state(dev, VHOST_USER_SET_VRING_ENABLE, 0, 0);
		break;
	case 2:
		fuzz_region_desc(1, &reg.region);
		fuzz_msg(dev, VHOST_USER_REM_MEM_REG, &reg, sizeof(reg), NULL,
			 0);
		break;
	case 3:
		fuzz_mem_table(dev);
		break;
	case 4:
		fuzz_msg(dev, VHOST_USER_RESET_DEVICE, NULL, 0, NULL, 0);
		break;
	case 5:
		fuzz_state(dev, VHOST_USER_SET_VRING_BASE, 0, 0);
		break;
	case 6:
		fuzz_u64(dev, VHOST_USER_SET_FEATURES,
			 VHOST_USER_BIT(VIRTIO_F_VERSION_1));
		break;
	default:
		/* A message that changes nothing the request depends on */
		fuzz_fd_msg(dev, VHOST_USER_SET_VRING_CALL);
		break;
	}
}

static int fuzz_fill(void *ctx, uint8_t *buf, size_t len, unsigned int gen)
{
	(void)ctx;
	(void)gen;

	if (fuzz_inject.dev && !fuzz_inject.done &&
	    fuzz_inject.calls++ == fuzz_inject.at) {
		fuzz_inject.done = true;
		fuzz_inject_msg(fuzz_inject.dev, fuzz_inject.which);
	}

	memset(buf, FUZZ_FILL, len);
	return 0;
}

/******************************************************************************
 * What the back-end may write
 ******************************************************************************/

/* The region and offset of a guest address, -1 if there is none */
static int fuzz_where(uint64_t gpa, size_t *off)
{
	unsigned int i;

	for (i = 0; i < FUZZ_NREGIONS; i++) {
		if (gpa - fuzz_layout[i].gpa < fuzz_layout[i].size) {
			*off = (size_t)(gpa - fuzz_layout[i].gpa);
			return (int)i;
		}
	}
	return -1;
}

/* Allow the guest range [gpa, gpa + len), as far as it is guest memory */
static void fuzz_allow(uint64_t gpa, uint64_t len)
{
	uint64_t end = len > UINT64_MAX - gpa ? UINT64_MAX : gpa + len;
	unsigned int i;

	for (i = 0; i < FUZZ_NREGIONS; i++) {
		uint64_t rs = fuzz_layout[i].gpa;
		uint64_t re = rs + fuzz_layout[i].size;
		uint64_t lo = gpa > rs ? gpa : rs;
		uint64_t hi = end < re ? end : re;

		if (lo < hi)
			memset(fuzz_mem[i].allowed + (lo - rs), 1,
			       (size_t)(hi - lo));
	}
}

/* Copy a descriptor out of the snapshot, false if it is not guest memory */
static bool fuzz_snap_desc(uint64_t gpa, uint64_t *addr, uint32_t *len,
			   uint16_t *flags)
{
	uint8_t raw[16];
	unsigned int i;

	for (i = 0; i < 16; i++) {
		size_t off;
		int r = fuzz_where(gpa + i, &off);

		if (r < 0)
			return false;
		raw[i] = fuzz_mem[r].snap[off];
	}

	memcpy(addr, raw, 8);
	memcpy(len, raw + 8, 4);
	memcpy(flags, raw + 12, 2);
	*addr = le64toh(*addr);
	*len = le32toh(*len);
	*flags = le16toh(*flags);

	return true;
}

/*
 * Everything a correct back-end may write into: the writable buffers of every
 * descriptor of the table and of every indirect table one of them names. More
 * than any one request is served into, but nothing a request can not be.
 */
static void fuzz_allowed(uint64_t desc_gpa, unsigned int num)
{
	unsigned int i, j;

	for (i = 0; i < num; i++) {
		uint64_t addr;
		uint32_t len;
		uint16_t flags;

		if (!fuzz_snap_desc(desc_gpa + 16 * (uint64_t)i, &addr, &len,
				    &flags))
			continue;

		if (flags & VIRTQ_DESC_F_WRITE)
			fuzz_allow(addr, len);

		if (!(flags & VIRTQ_DESC_F_INDIRECT))
			continue;

		for (j = 0; j < len / 16 && j < num; j++) {
			uint64_t iaddr;
			uint32_t ilen;
			uint16_t iflags;

			if (fuzz_snap_desc(addr + 16 * (uint64_t)j, &iaddr,
					   &ilen, &iflags) &&
			    (iflags & VIRTQ_DESC_F_WRITE))
				fuzz_allow(iaddr, ilen);
		}
	}
}

static void fuzz_check(uint64_t used_gpa, unsigned int num, bool event_idx)
{
	size_t used_len = 4 + 8 * (size_t)num + (event_idx ? 2 : 0), off, i;
	unsigned int r;
	int ur = fuzz_where(used_gpa, &off);

	/* The used ring is the device's to write, all of it */
	if (ur >= 0) {
		for (i = 0; i < used_len && off + i < fuzz_layout[ur].size;
		     i++)
			fuzz_mem[ur].allowed[off + i] = 2;
	}

	for (r = 0; r < FUZZ_NREGIONS; r++) {
		for (i = 0; i < fuzz_layout[r].size; i++) {
			if (fuzz_mem[r].ptr[i] == fuzz_mem[r].snap[i])
				continue;

			if (!fuzz_mem[r].allowed[i] ||
			    (fuzz_mem[r].allowed[i] == 1 &&
			     fuzz_mem[r].ptr[i] != FUZZ_FILL)) {
				fprintf(stderr,
					"byte 0x%zx of region %u changed from 0x%02x to 0x%02x, which the back-end may not write\n",
					i, r, fuzz_mem[r].snap[i],
					fuzz_mem[r].ptr[i]);
				abort();
			}
		}
	}

	/* Used elements written name a descriptor and a length served */
	if (ur >= 0 && off + 4 + 8 * (size_t)num <= fuzz_layout[ur].size) {
		const uint8_t *now = fuzz_mem[ur].ptr + off + 4;
		const uint8_t *was = fuzz_mem[ur].snap + off + 4;

		for (i = 0; i < num; i++) {
			uint32_t id, len;

			if (!memcmp(now + 8 * i, was + 8 * i, 8))
				continue;
			memcpy(&id, now + 8 * i, 4);
			memcpy(&len, now + 8 * i + 4, 4);
			id = le32toh(id);
			len = le32toh(len);
			if (id >= num || len > VU_REQ_MAX_BYTES) {
				fprintf(stderr,
					"used element %zu: ID %u, length %u\n",
					i, id, len);
				abort();
			}
		}
	}
}

/******************************************************************************
 * The harness
 ******************************************************************************/

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct vu_source src = { .fill = fuzz_fill, .ctx = NULL };
	struct vhost_user_vring_addr addr = { 0 };
	uint64_t features, base_gpa = fuzz_layout[0].gpa;
	uint64_t desc_off, avail_off, used_off;
	unsigned int num, i, fds_before;
	struct vu_dev dev;
	uint8_t flags;
	size_t pos;

	if (size < FUZZ_CFG_LEN)
		return 0;

	flags = data[0];
	num = 1U << (data[1] % 9);

	fds_before = fuzz_open_fds();

	/* The image of guest memory, the regions one after the other */
	pos = FUZZ_CFG_LEN;
	for (i = 0; i < FUZZ_NREGIONS; i++) {
		size_t n = size - pos < fuzz_layout[i].size ?
				   size - pos :
				   fuzz_layout[i].size;

		memset(fuzz_mem[i].ptr, 0, fuzz_layout[i].size);
		memset(fuzz_mem[i].allowed, 0, fuzz_layout[i].size);
		memcpy(fuzz_mem[i].ptr, data + pos, n);
		pos += n;
	}

	/* Where the rings lie in the first region */
	switch (data[4] % 4) {
	case 0:
		desc_off = 0;
		avail_off = 0x1000;
		used_off = 0x2000;
		break;
	case 1:
		/* Packed together, as small as the alignment allows */
		desc_off = 0x8000;
		avail_off = desc_off + 16 * (uint64_t)num;
		used_off = (avail_off + 6 + 2 * (uint64_t)num + 3) & ~3ULL;
		break;
	case 2:
		/* The used ring at the very end of the region */
		desc_off = 0;
		avail_off = 0x1000;
		used_off = (fuzz_layout[0].size - 6 - 8 * (uint64_t)num) &
			   ~3ULL;
		break;
	default:
		/* Overlapping: the guest's business, not the back-end's */
		desc_off = 0x4000;
		avail_off = 0x4000;
		used_off = 0x4000;
		break;
	}

	if (vu_dev_init(&dev))
		return 0;

	features = VHOST_USER_BIT(VIRTIO_F_VERSION_1);
	if (flags & FUZZ_F_EVENT_IDX)
		features |= VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX);
	if (flags & FUZZ_F_INDIRECT)
		features |= VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC);
	if (!(flags & FUZZ_F_NO_PROTOCOL))
		features |= VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES);

	fuzz_u64(&dev, VHOST_USER_SET_PROTOCOL_FEATURES,
		 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK) |
			 VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS));
	fuzz_msg(&dev, VHOST_USER_SET_OWNER, NULL, 0, NULL, 0);
	fuzz_u64(&dev, VHOST_USER_SET_FEATURES, features);
	fuzz_mem_table(&dev);
	fuzz_state(&dev, VHOST_USER_SET_VRING_NUM, 0, num);
	fuzz_state(&dev, VHOST_USER_SET_VRING_BASE, 0,
		   (uint32_t)data[2] | (uint32_t)data[3] << 8);
	addr.desc_user_addr = fuzz_layout[0].uaddr + desc_off;
	addr.avail_user_addr = fuzz_layout[0].uaddr + avail_off;
	addr.used_user_addr = fuzz_layout[0].uaddr + used_off;
	fuzz_msg(&dev, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr), NULL,
		 0);
	fuzz_fd_msg(&dev, VHOST_USER_SET_VRING_KICK);
	fuzz_fd_msg(&dev, VHOST_USER_SET_VRING_CALL);
	fuzz_fd_msg(&dev, VHOST_USER_SET_VRING_ERR);
	fuzz_state(&dev, VHOST_USER_SET_VRING_ENABLE, 0, 1);

	/* What the guest wrote, before the back-end serves */
	for (i = 0; i < FUZZ_NREGIONS; i++)
		memcpy(fuzz_mem[i].snap, fuzz_mem[i].ptr, fuzz_layout[i].size);
	fuzz_allowed(base_gpa + desc_off, num);

	memset(&fuzz_inject, 0, sizeof(fuzz_inject));
	if (flags & FUZZ_F_INJECT) {
		fuzz_inject.dev = &dev;
		fuzz_inject.which = data[5] & 7;
		fuzz_inject.at = data[5] >> 3;
	}

	for (i = 0; i < FUZZ_MAX_ROUNDS; i++) {
		if (vu_dev_serve(&dev, &src, fuzz_buf) < 0)
			break;
	}

	fuzz_check(base_gpa + used_off, num,
		   !!(flags & FUZZ_F_EVENT_IDX));

	vu_dev_disconnect(&dev);
	vu_dev_fini(&dev);

	if (fuzz_open_fds() != fds_before) {
		fprintf(stderr, "%u descriptors open before, %u after\n",
			fds_before, fuzz_open_fds());
		abort();
	}

	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	unsigned int i;

	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	for (i = 0; i < FUZZ_NREGIONS; i++) {
		struct fuzz_region *m = &fuzz_mem[i];

		m->fd = memfd_create("esdm-vu-ring-fuzz", MFD_CLOEXEC);
		if (m->fd < 0 || ftruncate(m->fd, (off_t)fuzz_layout[i].size))
			exit(1);
		m->ptr = mmap(NULL, fuzz_layout[i].size,
			      PROT_READ | PROT_WRITE, MAP_SHARED, m->fd, 0);
		m->snap = malloc(fuzz_layout[i].size);
		m->allowed = malloc(fuzz_layout[i].size);
		if (m->ptr == MAP_FAILED || !m->snap || !m->allowed)
			exit(1);
	}

	fuzz_buf = malloc(VU_REQ_MAX_BYTES);
	if (!fuzz_buf)
		exit(1);

	return 0;
}

/******************************************************************************
 * Seeds
 ******************************************************************************/

/*
 * Rings a driver writes, well formed and not: the seeds start the fuzzer
 * where the parser takes decisions, not at its first check. Each is an image
 * of the first region up to its data area at 0x4000.
 */
#define FUZZ_MAX_SEEDS 16
#define FUZZ_SEED_LEN (FUZZ_CFG_LEN + 0x4200)
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][FUZZ_SEED_LEN];
static size_t fuzz_num_seeds;

/* The seed being built, in the layout 0 of the rings */
static uint8_t *fuzz_seed_new(uint8_t flags, unsigned int log2num,
			      uint16_t base, uint8_t inject)
{
	uint8_t *s = fuzz_seed_data[fuzz_num_seeds];

	memset(s, 0, FUZZ_SEED_LEN);
	s[0] = flags;
	s[1] = (uint8_t)log2num;
	s[2] = (uint8_t)base;
	s[3] = (uint8_t)(base >> 8);
	s[4] = 0;
	s[5] = inject;

	return s + FUZZ_CFG_LEN;
}

static void fuzz_seed_desc(uint8_t *img, unsigned int i, uint64_t addr,
			   uint32_t len, uint16_t flags, uint16_t next)
{
	uint8_t *d = img + 16 * i;

	addr = htole64(addr);
	len = htole32(len);
	flags = htole16(flags);
	next = htole16(next);
	memcpy(d, &addr, 8);
	memcpy(d + 8, &len, 4);
	memcpy(d + 12, &flags, 2);
	memcpy(d + 14, &next, 2);
}

/* Make @n requests available, heads 0 to n - 1, from @first on */
static void fuzz_seed_avail(uint8_t *img, unsigned int num, uint16_t first,
			    uint16_t n)
{
	uint16_t i, idx = htole16((uint16_t)(first + n));

	for (i = 0; i < n; i++) {
		uint16_t head = htole16(i);

		memcpy(img + 0x1000 + 4 + 2 * ((first + i) & (num - 1)), &head,
		       2);
	}
	memcpy(img + 0x1002, &idx, 2);
}

static void fuzz_seed_done(const char *name)
{
	fuzz_seeds[fuzz_num_seeds].name = name;
	fuzz_seeds[fuzz_num_seeds].data = fuzz_seed_data[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].len = FUZZ_SEED_LEN;
	fuzz_num_seeds++;
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	const uint64_t A = fuzz_layout[0].gpa;
	const uint16_t W = VIRTQ_DESC_F_WRITE, N = VIRTQ_DESC_F_NEXT,
		       I = VIRTQ_DESC_F_INDIRECT;
	uint8_t *img;

	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	img = fuzz_seed_new(0, 3, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 64, W, 0);
	fuzz_seed_avail(img, 8, 0, 1);
	fuzz_seed_done("one-request");

	img = fuzz_seed_new(FUZZ_F_EVENT_IDX, 3, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 16, W | N, 1);
	fuzz_seed_desc(img, 1, A + 0x4100, 0, W | N, 2);
	fuzz_seed_desc(img, 2, A + 0x4200, 48, W, 0);
	fuzz_seed_desc(img, 3, A + 0x4300, 8000, W, 0);
	fuzz_seed_avail(img, 8, 0, 4);
	fuzz_seed_done("chains-event-idx");

	img = fuzz_seed_new(FUZZ_F_INDIRECT, 3, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x3000, 32, I, 0);
	fuzz_seed_desc(img + 0x3000, 0, A + 0x4000, 32, W | N, 1);
	fuzz_seed_desc(img + 0x3000, 1, A + 0x4100, 32, W, 0);
	fuzz_seed_avail(img, 8, 0, 1);
	fuzz_seed_done("indirect");

	/* Across the first two regions, and into the gap behind them */
	img = fuzz_seed_new(0, 2, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x10000 - 16, 48, W, 0);
	fuzz_seed_desc(img, 1, A + 0x14000 - 16, 48, W, 0);
	fuzz_seed_avail(img, 4, 0, 2);
	fuzz_seed_done("spanning-regions");

	img = fuzz_seed_new(FUZZ_F_INDIRECT, 3, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 16, W | N, 1);
	fuzz_seed_desc(img, 1, A + 0x4100, 16, W | N, 0);
	fuzz_seed_desc(img, 2, A + 0x3000, 48, I, 0);
	fuzz_seed_desc(img + 0x3000, 0, A + 0x3000, 48, I, 0);
	fuzz_seed_desc(img, 3, A + 0x4000, 16, 0, 0);
	fuzz_seed_desc(img, 4, 0xfffffffffffffff0ULL, 0x20, W, 0);
	fuzz_seed_desc(img, 5, A + 0x4000, 16, W | N, 99);
	fuzz_seed_avail(img, 8, 0, 6);
	fuzz_seed_done("malformed-requests");

	img = fuzz_seed_new(0, 3, 0, 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 16, W, 0);
	fuzz_seed_avail(img, 8, 0, 1);
	/* A head beyond the queue */
	img[0x1000 + 4] = 9;
	fuzz_seed_done("head-beyond-queue");

	img = fuzz_seed_new(0, 3, 0, 0);
	fuzz_seed_avail(img, 8, 0, 1);
	img[0x1002] = 100;
	fuzz_seed_done("avail-index-jump");

	/* A base ahead of the used index, as Cloud Hypervisor gives it */
	img = fuzz_seed_new(0, 3, 2, 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 16, W, 0);
	fuzz_seed_desc(img, 1, A + 0x4100, 16, W, 0);
	fuzz_seed_avail(img, 8, 0, 2);
	fuzz_seed_done("base-ahead-of-used");

	/* A control message while the first request waits, one of each */
	img = fuzz_seed_new(FUZZ_F_INJECT, 3, 0, 0 << 3 | 0);
	fuzz_seed_desc(img, 0, A + 0x4000, 64, W, 0);
	fuzz_seed_desc(img, 1, A + 0x10000 + 0x100, 64, W, 0);
	fuzz_seed_avail(img, 8, 0, 2);
	fuzz_seed_done("inject-get-vring-base");
	memcpy(fuzz_seed_data[fuzz_num_seeds], fuzz_seed_data[fuzz_num_seeds - 1],
	       FUZZ_SEED_LEN);
	fuzz_seed_data[fuzz_num_seeds][5] = 0 << 3 | 2;
	fuzz_seed_done("inject-rem-mem-reg");
	memcpy(fuzz_seed_data[fuzz_num_seeds], fuzz_seed_data[fuzz_num_seeds - 1],
	       FUZZ_SEED_LEN);
	fuzz_seed_data[fuzz_num_seeds][5] = 1 << 3 | 3;
	fuzz_seed_done("inject-set-mem-table");
	memcpy(fuzz_seed_data[fuzz_num_seeds], fuzz_seed_data[fuzz_num_seeds - 1],
	       FUZZ_SEED_LEN);
	fuzz_seed_data[fuzz_num_seeds][5] = 0 << 3 | 4;
	fuzz_seed_done("inject-reset-device");
	memcpy(fuzz_seed_data[fuzz_num_seeds], fuzz_seed_data[fuzz_num_seeds - 1],
	       FUZZ_SEED_LEN);
	fuzz_seed_data[fuzz_num_seeds][5] = 0 << 3 | 7;
	fuzz_seed_done("inject-set-vring-call");

	*num = fuzz_num_seeds;
	return fuzz_seeds;
}
