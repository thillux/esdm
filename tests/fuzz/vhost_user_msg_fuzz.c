/*
 * Fuzz harness: the vhost-user control messages of esdm-vhost-user-rng
 *
 * What a front-end sends the back-end of a virtio entropy device: a byte
 * stream on a Unix domain socket, with file descriptors attached to it. The
 * front-end is the VMM, less hostile than the guest, but the parser is the
 * first thing to meet whatever connects to the socket, and it is where the
 * guest memory gets mapped - so it gets the same treatment.
 *
 * An input is a sequence of records, each one write of the front-end: a byte
 * telling how many file descriptors come with it and of which kind - memfds
 * of guest memory or eventfds -, two bytes of length, and that many bytes of
 * the stream. The records are written to a socket pair up front, and the back-
 * end serves the other end until the stream ends or it closes the connection
 * - so a message may span records, and descriptors may arrive anywhere, not
 * just at the start of a message. The ring the messages set up is served once
 * at the end, from a source of random bytes of the harness.
 *
 * Beyond crashes the harness holds the back-end to the frame of its replies -
 * the reply flag, the request they answer, a size from the protocol - and to
 * the descriptors: whatever it was handed, it has closed or still holds when
 * the device is released, and then none of them is left.
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
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "fuzz.h"
#include "vhost_user_dev.h"

/* Size of a memfd handed over as guest memory */
#define FUZZ_MEM_SIZE (64 * 1024)

/* Records of an input, and descriptors of a record, at most */
#define FUZZ_MAX_RECORDS 64
#define FUZZ_MAX_FDS 40

/* Bit of the descriptor byte: memfds rather than eventfds */
#define FUZZ_FDS_MEMFD 0x80

/* The memory every memfd handed over is a duplicate of */
static int fuzz_memfd = -1;

static uint8_t *fuzz_buf;

/* Descriptors open in this process */
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

static int fuzz_fill(void *ctx, uint8_t *buf, size_t len, unsigned int gen)
{
	(void)ctx;
	(void)gen;

	memset(buf, 0xa5, len);
	return 0;
}

/* Write one record to @fd, with its descriptors */
static void fuzz_write_record(int fd, const uint8_t *data, size_t len,
			      uint8_t fdspec)
{
	union {
		char buf[CMSG_SPACE(sizeof(int) * FUZZ_MAX_FDS)];
		struct cmsghdr align;
	} ctl;
	struct iovec iov = { .iov_base = (void *)data, .iov_len = len };
	struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
	unsigned int nfds = fdspec & 0x3f, i;
	int fds[FUZZ_MAX_FDS];

	if (nfds > FUZZ_MAX_FDS)
		nfds = FUZZ_MAX_FDS;
	/* Descriptors need a byte to travel with */
	if (!len)
		nfds = 0;

	for (i = 0; i < nfds; i++) {
		fds[i] = (fdspec & FUZZ_FDS_MEMFD) ?
				 fcntl(fuzz_memfd, F_DUPFD_CLOEXEC, 0) :
				 eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (fds[i] < 0)
			abort();
	}

	if (nfds) {
		struct cmsghdr *cmsg;

		memset(&ctl, 0, sizeof(ctl));
		mh.msg_control = ctl.buf;
		mh.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
		cmsg = CMSG_FIRSTHDR(&mh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * nfds);
	}

	/* A full socket buffer only cuts the input short */
	(void)sendmsg(fd, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);

	/* The receiving end has its own copies now, or none */
	for (i = 0; i < nfds; i++)
		close(fds[i]);
}

/* Read the replies waiting, and hold them to their frame */
static void fuzz_check_replies(int fd)
{
	uint8_t buf[sizeof(struct vhost_user_hdr) + VU_MAX_PAYLOAD];

	for (;;) {
		struct vhost_user_hdr hdr;
		ssize_t n = recv(fd, &hdr, sizeof(hdr), MSG_DONTWAIT);

		if (n <= 0)
			return;
		if ((size_t)n != sizeof(hdr)) {
			fprintf(stderr, "reply header of %zd bytes\n", n);
			abort();
		}

		if (hdr.flags != (VHOST_USER_VERSION | VHOST_USER_REPLY_MASK)) {
			fprintf(stderr, "reply with flags 0x%x\n", hdr.flags);
			abort();
		}
		if (hdr.request == VHOST_USER_GET_VRING_BASE ?
			    hdr.size != sizeof(struct vhost_user_vring_state) :
		    hdr.request == VHOST_USER_GET_CONFIG ?
			    hdr.size != 0 :
		    hdr.request == VHOST_USER_GET_SHMEM_CONFIG ?
			    hdr.size != 8 + 256 * 8 :
			    hdr.size != sizeof(uint64_t)) {
			fprintf(stderr, "reply to request %u of %u bytes\n",
				hdr.request, hdr.size);
			abort();
		}

		if (hdr.size &&
		    recv(fd, buf, hdr.size, MSG_DONTWAIT) != (ssize_t)hdr.size) {
			fprintf(stderr, "reply payload cut short\n");
			abort();
		}
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const struct vu_source src = { .fill = fuzz_fill, .ctx = NULL };
	struct vu_dev dev;
	unsigned int records = 0, fds_before;
	size_t pos = 0;
	int sv[2];

	fds_before = fuzz_open_fds();

	if (vu_dev_init(&dev))
		return 0;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		vu_dev_fini(&dev);
		return 0;
	}

	/* The whole stream up front, then the end of it */
	while (pos + 3 <= size && records++ < FUZZ_MAX_RECORDS) {
		uint8_t fdspec = data[pos];
		size_t len = ((size_t)data[pos + 1] << 8) | data[pos + 2];

		pos += 3;
		if (len > size - pos)
			len = size - pos;

		fuzz_write_record(sv[0], data + pos, len, fdspec);
		pos += len;
	}
	shutdown(sv[0], SHUT_WR);

	/* Served until the stream ends or the back-end closes it */
	while (!vu_conn_serve(&dev, sv[1], -1))
		fuzz_check_replies(sv[0]);
	fuzz_check_replies(sv[0]);

	/* Whatever ring the messages set up, served once */
	(void)vu_dev_serve(&dev, &src, fuzz_buf);

	vu_dev_disconnect(&dev);
	vu_dev_fini(&dev);
	close(sv[0]);
	close(sv[1]);

	if (fuzz_open_fds() != fds_before) {
		fprintf(stderr, "%u descriptors open before, %u after\n",
			fds_before, fuzz_open_fds());
		abort();
	}

	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	esdm_logger_set_verbosity(getenv("ESDM_FUZZ_VERBOSE") ? LOGGER_DEBUG :
								LOGGER_NONE);

	/* A reply to a closed connection must not end the harness */
	signal(SIGPIPE, SIG_IGN);

	fuzz_memfd = memfd_create("esdm-vu-fuzz", MFD_CLOEXEC);
	if (fuzz_memfd < 0 || ftruncate(fuzz_memfd, FUZZ_MEM_SIZE)) {
		fprintf(stderr, "cannot create the guest memory\n");
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

#define FUZZ_MAX_SEEDS 16
#define FUZZ_SEED_MAX 2048
static struct fuzz_seed fuzz_seeds[FUZZ_MAX_SEEDS];
static uint8_t fuzz_seed_data[FUZZ_MAX_SEEDS][FUZZ_SEED_MAX];
static size_t fuzz_seed_len[FUZZ_MAX_SEEDS];
static size_t fuzz_num_seeds;

/* Append a message as one record to the seed being built */
static void fuzz_seed_msg(uint32_t request, uint32_t flags,
			  const void *payload, uint32_t size, uint8_t fdspec)
{
	struct vhost_user_hdr hdr = { .request = request,
				      .flags = VHOST_USER_VERSION | flags,
				      .size = size };
	uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];
	size_t *len = &fuzz_seed_len[fuzz_num_seeds];
	size_t rec;

	if (size > FUZZ_SEED_MAX ||
	    *len > FUZZ_SEED_MAX - 3 - sizeof(hdr) - size)
		return;
	rec = sizeof(hdr) + size;

	seed[(*len)++] = fdspec;
	seed[(*len)++] = (uint8_t)(rec >> 8);
	seed[(*len)++] = (uint8_t)rec;
	memcpy(seed + *len, &hdr, sizeof(hdr));
	if (size)
		memcpy(seed + *len + sizeof(hdr), payload, size);
	*len += rec;
}

static void fuzz_seed_u64(uint32_t request, uint64_t v, uint8_t fdspec)
{
	fuzz_seed_msg(request, VHOST_USER_NEED_REPLY_MASK, &v, sizeof(v),
		      fdspec);
}

static void fuzz_seed_state(uint32_t request, uint32_t index, uint32_t num)
{
	struct vhost_user_vring_state s = { .index = index, .num = num };

	fuzz_seed_msg(request, VHOST_USER_NEED_REPLY_MASK, &s, sizeof(s), 0);
}

static void fuzz_seed_done(const char *name)
{
	fuzz_seeds[fuzz_num_seeds].name = name;
	fuzz_seeds[fuzz_num_seeds].data = fuzz_seed_data[fuzz_num_seeds];
	fuzz_seeds[fuzz_num_seeds].len = fuzz_seed_len[fuzz_num_seeds];
	fuzz_num_seeds++;
}

/* The negotiation QEMU makes, REPLY_ACK included */
static void fuzz_seed_negotiate(uint64_t features)
{
	fuzz_seed_msg(VHOST_USER_GET_FEATURES, 0, NULL, 0, 0);
	fuzz_seed_msg(VHOST_USER_GET_PROTOCOL_FEATURES, 0, NULL, 0, 0);
	fuzz_seed_u64(VHOST_USER_SET_PROTOCOL_FEATURES,
		      VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_MQ) |
			      VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK) |
			      VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_RESET_DEVICE) |
			      VHOST_USER_BIT(
				      VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS),
		      0);
	fuzz_seed_msg(VHOST_USER_GET_QUEUE_NUM, VHOST_USER_NEED_REPLY_MASK,
		      NULL, 0, 0);
	fuzz_seed_msg(VHOST_USER_GET_MAX_MEM_SLOTS, VHOST_USER_NEED_REPLY_MASK,
		      NULL, 0, 0);
	fuzz_seed_msg(VHOST_USER_SET_OWNER, VHOST_USER_NEED_REPLY_MASK, NULL,
		      0, 0);
	fuzz_seed_u64(VHOST_USER_SET_FEATURES,
		      features | VHOST_USER_BIT(VIRTIO_F_VERSION_1) |
			      VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES),
		      0);
}

static void fuzz_seed_region(uint32_t request, uint64_t gpa, uint64_t uaddr)
{
	struct vhost_user_mem_reg reg = { 0 };

	reg.region.guest_phys_addr = gpa;
	reg.region.memory_size = FUZZ_MEM_SIZE;
	reg.region.userspace_addr = uaddr;
	fuzz_seed_msg(request, VHOST_USER_NEED_REPLY_MASK, &reg, sizeof(reg),
		      request == VHOST_USER_ADD_MEM_REG ? FUZZ_FDS_MEMFD | 1 : 0);
}

static void fuzz_seed_table(unsigned int n)
{
	uint8_t buf[8 + 4 * 32] = { 0 };
	unsigned int i;

	buf[0] = (uint8_t)n;
	for (i = 0; i < n && i < 4; i++) {
		struct vhost_user_mem_region r = {
			.guest_phys_addr = 0x100000 + i * FUZZ_MEM_SIZE,
			.memory_size = FUZZ_MEM_SIZE,
			.userspace_addr = 0x7f0000000000ULL + i * 0x100000,
		};

		memcpy(buf + 8 + i * sizeof(r), &r, sizeof(r));
	}
	fuzz_seed_msg(VHOST_USER_SET_MEM_TABLE, VHOST_USER_NEED_REPLY_MASK, buf,
		      8 + n * 32, (uint8_t)(FUZZ_FDS_MEMFD | n));
}

/* The ring set up in the first region, as QEMU orders it */
static void fuzz_seed_ring(uint32_t num)
{
	struct vhost_user_vring_addr addr = {
		.desc_user_addr = 0x7f0000000000ULL,
		.avail_user_addr = 0x7f0000001000ULL,
		.used_user_addr = 0x7f0000002000ULL,
	};

	fuzz_seed_state(VHOST_USER_SET_VRING_NUM, 0, num);
	fuzz_seed_state(VHOST_USER_SET_VRING_BASE, 0, 0);
	fuzz_seed_msg(VHOST_USER_SET_VRING_ADDR, VHOST_USER_NEED_REPLY_MASK,
		      &addr, sizeof(addr), 0);
	fuzz_seed_u64(VHOST_USER_SET_VRING_KICK, 0, 1);
	fuzz_seed_u64(VHOST_USER_SET_VRING_CALL, 0, 1);
	fuzz_seed_u64(VHOST_USER_SET_VRING_ERR, 0, 1);
	fuzz_seed_state(VHOST_USER_SET_VRING_ENABLE, 0, 1);
}

const struct fuzz_seed *fuzz_seed_corpus(size_t *num)
{
	if (fuzz_num_seeds) {
		*num = fuzz_num_seeds;
		return fuzz_seeds;
	}

	/* What QEMU does, start to stop */
	fuzz_seed_negotiate(VHOST_USER_BIT(VIRTIO_RING_F_EVENT_IDX));
	fuzz_seed_table(1);
	fuzz_seed_ring(8);
	fuzz_seed_state(VHOST_USER_GET_VRING_BASE, 0, 0);
	fuzz_seed_done("qemu-start-stop");

	/* Memory by slots, as with CONFIGURE_MEM_SLOTS */
	fuzz_seed_negotiate(VHOST_USER_BIT(VIRTIO_RING_F_INDIRECT_DESC));
	fuzz_seed_region(VHOST_USER_ADD_MEM_REG, 0x100000, 0x7f0000000000ULL);
	fuzz_seed_region(VHOST_USER_ADD_MEM_REG, 0x200000, 0x7e0000000000ULL);
	fuzz_seed_ring(4);
	fuzz_seed_region(VHOST_USER_REM_MEM_REG, 0x200000, 0x7e0000000000ULL);
	fuzz_seed_region(VHOST_USER_REM_MEM_REG, 0x100000, 0x7f0000000000ULL);
	fuzz_seed_done("mem-slots");

	/* A table replaced while the ring is set up, and resets */
	fuzz_seed_negotiate(0);
	fuzz_seed_table(1);
	fuzz_seed_ring(256);
	fuzz_seed_table(3);
	fuzz_seed_msg(VHOST_USER_RESET_OWNER, VHOST_USER_NEED_REPLY_MASK, NULL,
		      0, 0);
	fuzz_seed_ring(2);
	fuzz_seed_msg(VHOST_USER_RESET_DEVICE, VHOST_USER_NEED_REPLY_MASK, NULL,
		      0, 0);
	fuzz_seed_done("table-replaced-reset");

	/* The rings before the memory, and a kick without descriptor */
	fuzz_seed_negotiate(0);
	fuzz_seed_ring(16);
	fuzz_seed_u64(VHOST_USER_SET_VRING_KICK, VHOST_USER_VRING_NOFD_MASK, 0);
	fuzz_seed_table(1);
	fuzz_seed_done("ring-before-memory");

	/* Requests the device does not support, with replies of their own */
	fuzz_seed_negotiate(0);
	{
		uint8_t cfg[12 + 8] = { 0 };

		cfg[4] = 8;
		fuzz_seed_msg(VHOST_USER_GET_CONFIG, 0, cfg, sizeof(cfg), 0);
	}
	fuzz_seed_msg(VHOST_USER_GET_STATUS, 0, NULL, 0, 0);
	fuzz_seed_msg(VHOST_USER_GET_SHMEM_CONFIG, 0, NULL, 0, 0);
	fuzz_seed_u64(VHOST_USER_SET_LOG_BASE, 0, 0);
	fuzz_seed_msg(99, VHOST_USER_NEED_REPLY_MASK, NULL, 0, 0);
	fuzz_seed_done("unsupported");

	/* Messages that end the connection */
	fuzz_seed_negotiate(0);
	fuzz_seed_msg(VHOST_USER_GET_FEATURES, 0, NULL, 0, 3);
	fuzz_seed_done("descriptors-where-none-belong");

	fuzz_seed_negotiate(0);
	{
		/* The descriptor byte of the record of the table to come */
		size_t at = fuzz_seed_len[fuzz_num_seeds];

		fuzz_seed_table(2);
		fuzz_seed_data[fuzz_num_seeds][at] = FUZZ_FDS_MEMFD | 1;
	}
	fuzz_seed_done("table-short-of-descriptors");

	{
		struct vhost_user_hdr hdr = { .request = VHOST_USER_SET_FEATURES,
					      .flags = VHOST_USER_VERSION,
					      .size = 8 };
		uint8_t *seed = fuzz_seed_data[fuzz_num_seeds];

		/* A message cut into three writes, the last one short */
		seed[0] = 0;
		seed[1] = 0;
		seed[2] = 5;
		memcpy(seed + 3, &hdr, 5);
		seed[8] = 0;
		seed[9] = 0;
		seed[10] = 7;
		memcpy(seed + 11, (uint8_t *)&hdr + 5, 7);
		seed[18] = 0;
		seed[19] = 0;
		seed[20] = 4;
		memset(seed + 21, 0, 4);
		fuzz_seed_len[fuzz_num_seeds] = 25;
		fuzz_seed_done("message-in-pieces");
	}

	*num = fuzz_num_seeds;
	return fuzz_seeds;
}
