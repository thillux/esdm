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
 * A vhost-user front-end and virtio driver for the tests of
 * esdm-vhost-user-rng: what QEMU and the guest do, with the guest memory a
 * memfd of the test and the messages written by hand, so that a test can send
 * any of them - also those no front-end would.
 */

#ifndef VU_FRONTEND_H
#define VU_FRONTEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "vhost_user.h"

/* A region of guest memory: a memfd mapped into the test */
struct fe_mem {
	int fd;
	uint8_t *ptr;
	size_t size;
	uint64_t gpa;
	/* What the test tells the back-end as its virtual address */
	uint64_t uaddr;
};

/* Fill byte of guest memory the back-end must not write */
#define FE_CANARY 0xcc

/*
 * Layout of the rings in the first region: the descriptor table, the
 * available and the used ring, each on a page of its own, and the data area
 * behind them.
 */
#define FE_DESC_OFF 0x0000
#define FE_AVAIL_OFF 0x2000
#define FE_USED_OFF 0x3000
#define FE_DATA_OFF 0x10000

struct fe {
	int sock;
	/* Whether REPLY_ACK was negotiated: every request is acknowledged */
	bool reply_ack;
	uint64_t features;

	struct fe_mem *mem;

	/* The ring */
	uint16_t num;
	int kick;
	int call;
	int err;
	/* Next available index the driver publishes */
	uint16_t avail_idx;
};

/******************************************************************************
 * Guest memory
 ******************************************************************************/

int fe_mem_create(struct fe_mem *m, size_t size, uint64_t gpa);
void fe_mem_destroy(struct fe_mem *m);

/* The mapped address of a guest physical address in @m */
uint8_t *fe_gpa_ptr(const struct fe_mem *m, uint64_t gpa);

/******************************************************************************
 * Messages
 ******************************************************************************/

int fe_connect(struct fe *fe, const char *path);
void fe_close(struct fe *fe);

/* Send a message with @flags in addition to the version, raw */
int fe_send(struct fe *fe, uint32_t request, uint32_t flags,
	    const void *payload, uint32_t size, const int *fds,
	    unsigned int nfds);

/* Receive a reply - 0, -ETIMEDOUT, or -ECONNRESET when the back-end closed */
int fe_recv(struct fe *fe, struct vhost_user_hdr *hdr, void *payload,
	    size_t max, int timeout_ms);

/*
 * A request without a reply of its own: acknowledged with REPLY_ACK. Returns
 * 0 if acknowledged with 0 or not acknowledged, the acknowledgement otherwise,
 * or a negative errno if the connection failed.
 */
int fe_request(struct fe *fe, uint32_t request, const void *payload,
	       uint32_t size, const int *fds, unsigned int nfds);

/* A request with a u64 reply */
int fe_get_u64(struct fe *fe, uint32_t request, uint64_t *val);

/* SET_* with a u64 or vring state payload */
int fe_set_u64(struct fe *fe, uint32_t request, uint64_t val);
int fe_set_state(struct fe *fe, uint32_t request, uint32_t index,
		 uint32_t num);

/* GET_VRING_BASE */
int fe_get_vring_base(struct fe *fe, uint32_t index, uint32_t *num);

/* Whether the back-end closed the connection, waiting up to @timeout_ms */
bool fe_closed(struct fe *fe, int timeout_ms);

/******************************************************************************
 * Set-up as QEMU does it
 ******************************************************************************/

/*
 * GET_FEATURES, GET/SET_PROTOCOL_FEATURES, SET_OWNER, SET_FEATURES with
 * @features (VERSION_1 and PROTOCOL_FEATURES added) and @pfeatures
 */
int fe_negotiate(struct fe *fe, uint64_t features, uint64_t pfeatures);

int fe_set_mem_table(struct fe *fe, struct fe_mem *regions, unsigned int n);
int fe_add_mem_reg(struct fe *fe, const struct fe_mem *m);
int fe_rem_mem_reg(struct fe *fe, const struct fe_mem *m);

/* Clear the rings in @fe->mem, then NUM, BASE, ADDR, KICK, CALL, ERR, ENABLE */
int fe_ring_setup(struct fe *fe, uint16_t num);

/* SET_VRING_KICK, CALL or ERR with a new eventfd, stored in @fe */
int fe_set_vring_fd(struct fe *fe, uint32_t request);

/* The whole set-up: negotiate, one region of @mem, the ring */
int fe_setup(struct fe *fe, const char *path, struct fe_mem *mem,
	     uint64_t features, uint64_t pfeatures, uint16_t num);

/******************************************************************************
 * The driver
 ******************************************************************************/

uint64_t fe_data_gpa(const struct fe *fe, size_t off);
uint8_t *fe_data_ptr(const struct fe *fe, size_t off);

void drv_desc(struct fe *fe, uint16_t i, uint64_t addr, uint32_t len,
	      uint16_t flags, uint16_t next);
/* Make @head available and kick */
void drv_avail(struct fe *fe, uint16_t head);
/* Make @n entries available at once, without writing the ring entries */
void drv_avail_raw(struct fe *fe, uint16_t idx);
void drv_kick(struct fe *fe);

uint16_t drv_used_idx(const struct fe *fe);
void drv_used_elem(const struct fe *fe, uint16_t idx, uint32_t *id,
		   uint32_t *len);
uint16_t drv_avail_event(const struct fe *fe);
void drv_set_used_event(struct fe *fe, uint16_t v);
void drv_set_avail_flags(struct fe *fe, uint16_t flags);

/* Wait until the used index reaches @idx; false on timeout */
bool drv_wait_used(const struct fe *fe, uint16_t idx, int timeout_ms);

/* Whether eventfd @fd was signalled, consuming the signal */
bool fe_signalled(int fd, int timeout_ms);

/******************************************************************************
 * The daemon
 ******************************************************************************/

/* Start the daemon on @sock with the extra arguments @extra, NULL ended */
pid_t fe_spawn(const char *daemon, const char *sock, const char *const *extra);

/* Whether the daemon still runs */
bool fe_alive(pid_t pid);

/* SIGTERM, and its exit status - -1 if it had to be killed or crashed */
int fe_stop(pid_t pid, int timeout_ms);

uint64_t fe_now_ms(void);
void fe_sleep_ms(unsigned int ms);

#endif /* VU_FRONTEND_H */
