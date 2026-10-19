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
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../test_env.h"
#include "vu_frontend.h"

uint64_t fe_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

void fe_sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000 };

	nanosleep(&ts, NULL);
}

/******************************************************************************
 * Guest memory
 ******************************************************************************/

int fe_mem_create(struct fe_mem *m, size_t size, uint64_t gpa)
{
	memset(m, 0, sizeof(*m));
	m->fd = memfd_create("esdm-vu-test-guest", MFD_CLOEXEC);
	if (m->fd < 0)
		return -errno;

	if (ftruncate(m->fd, (off_t)size) < 0) {
		int ret = -errno;

		close(m->fd);
		return ret;
	}

	m->ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, m->fd,
		      0);
	if (m->ptr == MAP_FAILED) {
		int ret = -errno;

		close(m->fd);
		m->ptr = NULL;
		return ret;
	}

	memset(m->ptr, FE_CANARY, size);
	m->size = size;
	m->gpa = gpa;
	m->uaddr = (uint64_t)(uintptr_t)m->ptr;

	return 0;
}

void fe_mem_destroy(struct fe_mem *m)
{
	if (m->ptr)
		munmap(m->ptr, m->size);
	if (m->fd >= 0)
		close(m->fd);
	memset(m, 0, sizeof(*m));
	m->fd = -1;
}

uint8_t *fe_gpa_ptr(const struct fe_mem *m, uint64_t gpa)
{
	return m->ptr + (gpa - m->gpa);
}

/******************************************************************************
 * Messages
 ******************************************************************************/

int fe_connect(struct fe *fe, const char *path)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	unsigned int i;

	memset(fe, 0, sizeof(*fe));
	fe->kick = fe->call = fe->err = -1;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	fe->sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fe->sock < 0)
		return -errno;

	/* The daemon may still be finishing with the connection before */
	for (i = 0; i < 100; i++) {
		if (!connect(fe->sock, (struct sockaddr *)&addr, sizeof(addr)))
			return 0;
		fe_sleep_ms(50);
	}

	close(fe->sock);
	fe->sock = -1;
	return -ECONNREFUSED;
}

void fe_close(struct fe *fe)
{
	if (fe->sock >= 0)
		close(fe->sock);
	if (fe->kick >= 0)
		close(fe->kick);
	if (fe->call >= 0)
		close(fe->call);
	if (fe->err >= 0)
		close(fe->err);
	fe->sock = fe->kick = fe->call = fe->err = -1;
}

int fe_send(struct fe *fe, uint32_t request, uint32_t flags,
	    const void *payload, uint32_t size, const int *fds,
	    unsigned int nfds)
{
	union {
		char buf[CMSG_SPACE(sizeof(int) * 64)];
		struct cmsghdr align;
	} ctl;
	struct vhost_user_hdr hdr = { .request = request,
				      .flags = VHOST_USER_VERSION | flags,
				      .size = size };
	uint8_t buf[sizeof(hdr) + 8192];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(hdr) + size };
	struct msghdr mh = { .msg_iov = &iov, .msg_iovlen = 1 };
	ssize_t n;

	if (size > sizeof(buf) - sizeof(hdr) || nfds > 64)
		return -EINVAL;

	memcpy(buf, &hdr, sizeof(hdr));
	if (size)
		memcpy(buf + sizeof(hdr), payload, size);

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

	n = sendmsg(fe->sock, &mh, MSG_NOSIGNAL);
	if (n < 0)
		return -errno;
	if ((size_t)n != iov.iov_len)
		return -EIO;

	return 0;
}

static int fe_read(int fd, void *buf, size_t len, int timeout_ms)
{
	uint8_t *p = buf;

	while (len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;
		int ret = poll(&pfd, 1, timeout_ms);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!ret)
			return -ETIMEDOUT;

		n = read(fd, p, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (!n)
			return -ECONNRESET;
		p += n;
		len -= (size_t)n;
	}

	return 0;
}

int fe_recv(struct fe *fe, struct vhost_user_hdr *hdr, void *payload,
	    size_t max, int timeout_ms)
{
	int ret = fe_read(fe->sock, hdr, sizeof(*hdr), timeout_ms);

	if (ret)
		return ret;
	if (hdr->size > max)
		return -EMSGSIZE;

	return fe_read(fe->sock, payload, hdr->size, timeout_ms);
}

/* Receive the reply to @request and check its frame */
static int fe_reply(struct fe *fe, uint32_t request, void *payload,
		    uint32_t size)
{
	struct vhost_user_hdr hdr;
	uint8_t buf[4096];
	int ret = fe_recv(fe, &hdr, buf, sizeof(buf), 5000);

	if (ret)
		return ret;

	if (hdr.request != request ||
	    hdr.flags != (VHOST_USER_VERSION | VHOST_USER_REPLY_MASK) ||
	    hdr.size != size) {
		printf("  unexpected reply: request %u flags 0x%x size %u to request %u\n",
		       hdr.request, hdr.flags, hdr.size, request);
		return -EPROTO;
	}

	memcpy(payload, buf, size);
	return 0;
}

int fe_request(struct fe *fe, uint32_t request, const void *payload,
	       uint32_t size, const int *fds, unsigned int nfds)
{
	uint64_t ack;
	int ret;

	ret = fe_send(fe, request,
		      fe->reply_ack ? VHOST_USER_NEED_REPLY_MASK : 0, payload,
		      size, fds, nfds);
	if (ret || !fe->reply_ack)
		return ret;

	ret = fe_reply(fe, request, &ack, sizeof(ack));
	if (ret)
		return ret;

	return ack ? (ack > 0xffff ? 0xffff : (int)ack) : 0;
}

int fe_get_u64(struct fe *fe, uint32_t request, uint64_t *val)
{
	int ret;

	/*
	 * Like Cloud Hypervisor, which sets NEED_REPLY on every request once
	 * REPLY_ACK is negotiated: the explicit reply is the only one.
	 */
	ret = fe_send(fe, request,
		      fe->reply_ack ? VHOST_USER_NEED_REPLY_MASK : 0, NULL, 0,
		      NULL, 0);
	if (ret)
		return ret;

	return fe_reply(fe, request, val, sizeof(*val));
}

int fe_set_u64(struct fe *fe, uint32_t request, uint64_t val)
{
	return fe_request(fe, request, &val, sizeof(val), NULL, 0);
}

int fe_set_state(struct fe *fe, uint32_t request, uint32_t index,
		 uint32_t num)
{
	struct vhost_user_vring_state state = { .index = index, .num = num };

	return fe_request(fe, request, &state, sizeof(state), NULL, 0);
}

int fe_get_vring_base(struct fe *fe, uint32_t index, uint32_t *num)
{
	struct vhost_user_vring_state state = { .index = index, .num = 0 };
	int ret;

	ret = fe_send(fe, VHOST_USER_GET_VRING_BASE,
		      fe->reply_ack ? VHOST_USER_NEED_REPLY_MASK : 0, &state,
		      sizeof(state), NULL, 0);
	if (ret)
		return ret;

	ret = fe_reply(fe, VHOST_USER_GET_VRING_BASE, &state, sizeof(state));
	if (ret)
		return ret;
	if (state.index != index)
		return -EPROTO;

	*num = state.num;
	return 0;
}

bool fe_closed(struct fe *fe, int timeout_ms)
{
	struct pollfd pfd = { .fd = fe->sock, .events = POLLIN };
	uint8_t c;

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return false;

	return recv(fe->sock, &c, 1, MSG_DONTWAIT) == 0;
}

/******************************************************************************
 * Set-up
 ******************************************************************************/

int fe_negotiate(struct fe *fe, uint64_t features, uint64_t pfeatures)
{
	uint64_t offered;
	int ret;

	ret = fe_get_u64(fe, VHOST_USER_GET_FEATURES, &offered);
	if (ret)
		return ret;

	ret = fe_get_u64(fe, VHOST_USER_GET_PROTOCOL_FEATURES, &offered);
	if (ret)
		return ret;

	ret = fe_set_u64(fe, VHOST_USER_SET_PROTOCOL_FEATURES, pfeatures);
	if (ret)
		return ret;
	fe->reply_ack = !!(pfeatures &
			   VHOST_USER_BIT(VHOST_USER_PROTOCOL_F_REPLY_ACK));

	ret = fe_request(fe, VHOST_USER_SET_OWNER, NULL, 0, NULL, 0);
	if (ret)
		return ret;

	fe->features = features | VHOST_USER_BIT(VIRTIO_F_VERSION_1) |
		       VHOST_USER_BIT(VHOST_USER_F_PROTOCOL_FEATURES);
	return fe_set_u64(fe, VHOST_USER_SET_FEATURES, fe->features);
}

static void fe_region(const struct fe_mem *m, struct vhost_user_mem_region *r)
{
	r->guest_phys_addr = m->gpa;
	r->memory_size = m->size;
	r->userspace_addr = m->uaddr;
	r->mmap_offset = 0;
}

int fe_set_mem_table(struct fe *fe, struct fe_mem *regions, unsigned int n)
{
	uint8_t buf[sizeof(struct vhost_user_mem_table) +
		    32 * sizeof(struct vhost_user_mem_region)];
	struct vhost_user_mem_table table = { .nregions = n };
	int fds[32];
	unsigned int i;

	if (n > 32)
		return -EINVAL;

	memcpy(buf, &table, sizeof(table));
	for (i = 0; i < n; i++) {
		struct vhost_user_mem_region r;

		fe_region(&regions[i], &r);
		memcpy(buf + sizeof(table) + i * sizeof(r), &r, sizeof(r));
		fds[i] = regions[i].fd;
	}

	return fe_request(fe, VHOST_USER_SET_MEM_TABLE, buf,
			  (uint32_t)(sizeof(table) + n * sizeof(struct vhost_user_mem_region)),
			  fds, n);
}

int fe_add_mem_reg(struct fe *fe, const struct fe_mem *m)
{
	struct vhost_user_mem_reg reg = { 0 };

	fe_region(m, &reg.region);
	return fe_request(fe, VHOST_USER_ADD_MEM_REG, &reg, sizeof(reg),
			  &m->fd, 1);
}

int fe_rem_mem_reg(struct fe *fe, const struct fe_mem *m)
{
	struct vhost_user_mem_reg reg = { 0 };

	fe_region(m, &reg.region);
	return fe_request(fe, VHOST_USER_REM_MEM_REG, &reg, sizeof(reg), NULL,
			  0);
}

int fe_set_vring_fd(struct fe *fe, uint32_t request)
{
	int *slot = request == VHOST_USER_SET_VRING_KICK ? &fe->kick :
		    request == VHOST_USER_SET_VRING_CALL ? &fe->call :
							   &fe->err;
	uint64_t idx = 0;
	int fd, ret;

	fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (fd < 0)
		return -errno;

	ret = fe_request(fe, request, &idx, sizeof(idx), &fd, 1);
	if (*slot >= 0)
		close(*slot);
	*slot = fd;

	return ret;
}

int fe_ring_setup(struct fe *fe, uint16_t num)
{
	struct vhost_user_vring_addr addr = { 0 };
	int ret;

	fe->num = num;
	fe->avail_idx = 0;

	/* A driver hands over zeroed rings */
	memset(fe->mem->ptr + FE_DESC_OFF, 0, FE_DATA_OFF - FE_DESC_OFF);

	ret = fe_set_state(fe, VHOST_USER_SET_VRING_NUM, 0, num);
	if (ret)
		return ret;
	ret = fe_set_state(fe, VHOST_USER_SET_VRING_BASE, 0, 0);
	if (ret)
		return ret;

	addr.index = 0;
	addr.desc_user_addr = fe->mem->uaddr + FE_DESC_OFF;
	addr.avail_user_addr = fe->mem->uaddr + FE_AVAIL_OFF;
	addr.used_user_addr = fe->mem->uaddr + FE_USED_OFF;
	ret = fe_request(fe, VHOST_USER_SET_VRING_ADDR, &addr, sizeof(addr),
			 NULL, 0);
	if (ret)
		return ret;

	ret = fe_set_vring_fd(fe, VHOST_USER_SET_VRING_KICK);
	if (ret)
		return ret;
	ret = fe_set_vring_fd(fe, VHOST_USER_SET_VRING_CALL);
	if (ret)
		return ret;
	ret = fe_set_vring_fd(fe, VHOST_USER_SET_VRING_ERR);
	if (ret)
		return ret;

	return fe_set_state(fe, VHOST_USER_SET_VRING_ENABLE, 0, 1);
}

int fe_setup(struct fe *fe, const char *path, struct fe_mem *mem,
	     uint64_t features, uint64_t pfeatures, uint16_t num)
{
	int ret = fe_connect(fe, path);

	if (ret)
		return ret;

	fe->mem = mem;

	ret = fe_negotiate(fe, features, pfeatures);
	if (ret)
		return ret;

	ret = fe_set_mem_table(fe, mem, 1);
	if (ret)
		return ret;

	return fe_ring_setup(fe, num);
}

/******************************************************************************
 * The driver
 ******************************************************************************/

uint64_t fe_data_gpa(const struct fe *fe, size_t off)
{
	return fe->mem->gpa + FE_DATA_OFF + off;
}

uint8_t *fe_data_ptr(const struct fe *fe, size_t off)
{
	return fe->mem->ptr + FE_DATA_OFF + off;
}

void drv_desc(struct fe *fe, uint16_t i, uint64_t addr, uint32_t len,
	      uint16_t flags, uint16_t next)
{
	uint8_t *d = fe->mem->ptr + FE_DESC_OFF + 16 * (size_t)i;
	uint64_t a = htole64(addr);
	uint32_t l = htole32(len);
	uint16_t f = htole16(flags), n = htole16(next);

	memcpy(d, &a, 8);
	memcpy(d + 8, &l, 4);
	memcpy(d + 12, &f, 2);
	memcpy(d + 14, &n, 2);
}

static uint16_t *drv_u16(const struct fe *fe, size_t off)
{
	return (uint16_t *)(void *)(fe->mem->ptr + off);
}

void drv_avail_raw(struct fe *fe, uint16_t idx)
{
	fe->avail_idx = idx;
	__atomic_store_n(drv_u16(fe, FE_AVAIL_OFF + 2), htole16(idx),
			 __ATOMIC_RELEASE);
}

void drv_kick(struct fe *fe)
{
	uint64_t one = 1;
	ssize_t ret = write(fe->kick, &one, sizeof(one));

	(void)ret;
}

void drv_avail(struct fe *fe, uint16_t head)
{
	size_t slot = (size_t)(fe->avail_idx & (fe->num - 1));

	__atomic_store_n(drv_u16(fe, FE_AVAIL_OFF + 4 + 2 * slot),
			 htole16(head), __ATOMIC_RELAXED);
	drv_avail_raw(fe, (uint16_t)(fe->avail_idx + 1));
	drv_kick(fe);
}

uint16_t drv_used_idx(const struct fe *fe)
{
	return le16toh(__atomic_load_n(drv_u16(fe, FE_USED_OFF + 2),
				       __ATOMIC_ACQUIRE));
}

void drv_used_elem(const struct fe *fe, uint16_t idx, uint32_t *id,
		   uint32_t *len)
{
	const uint8_t *e = fe->mem->ptr + FE_USED_OFF + 4 +
			   8 * (size_t)(idx & (fe->num - 1));
	uint32_t v;

	memcpy(&v, e, 4);
	*id = le32toh(v);
	memcpy(&v, e + 4, 4);
	*len = le32toh(v);
}

uint16_t drv_avail_event(const struct fe *fe)
{
	return le16toh(__atomic_load_n(
		drv_u16(fe, FE_USED_OFF + 4 + 8 * (size_t)fe->num),
		__ATOMIC_ACQUIRE));
}

void drv_set_used_event(struct fe *fe, uint16_t v)
{
	__atomic_store_n(drv_u16(fe, FE_AVAIL_OFF + 4 + 2 * (size_t)fe->num),
			 htole16(v), __ATOMIC_SEQ_CST);
}

void drv_set_avail_flags(struct fe *fe, uint16_t flags)
{
	__atomic_store_n(drv_u16(fe, FE_AVAIL_OFF), htole16(flags),
			 __ATOMIC_SEQ_CST);
}

bool drv_wait_used(const struct fe *fe, uint16_t idx, int timeout_ms)
{
	uint64_t end = fe_now_ms() + (uint64_t)timeout_ms;

	do {
		if (drv_used_idx(fe) == idx)
			return true;
		fe_sleep_ms(2);
	} while (fe_now_ms() < end);

	return drv_used_idx(fe) == idx;
}

bool fe_signalled(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	uint64_t v;

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return false;

	return read(fd, &v, sizeof(v)) == sizeof(v) && v;
}

/******************************************************************************
 * The daemon
 ******************************************************************************/

/*
 * The variables of the sanitizers, next to those test_env.h passes: a finding
 * in the daemon is to end it, and with it the test.
 */
static const char *const fe_env_sanitizer[] = {
	"ASAN_OPTIONS=",
	"UBSAN_OPTIONS=",
	"LSAN_OPTIONS=",
	"TSAN_OPTIONS=",
};

pid_t fe_spawn(const char *daemon, const char *sock, const char *const *extra)
{
	return fe_spawn_log(daemon, sock, extra, -1, true);
}

pid_t fe_spawn_log(const char *daemon, const char *sock,
		   const char *const *extra, int log_fd, bool verbose)
{
	char *envp[TEST_ENV_MAX_VARS + 1 + 4];
	char *argv[32];
	unsigned int argc = 0, envc, i, j;
	pid_t pid;

	argv[argc++] = (char *)daemon;
	argv[argc++] = "--socket";
	argv[argc++] = (char *)sock;
	if (verbose)
		argv[argc++] = "-vvvvv";
	for (i = 0; extra && extra[i] && argc < 31; i++)
		argv[argc++] = (char *)extra[i];
	argv[argc] = NULL;

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(envp, TEST_ENV_MAX_VARS + 1);
	for (envc = 0; envp[envc]; envc++)
		;
	for (i = 0; environ && environ[i]; i++) {
		for (j = 0; j < 4; j++) {
			if (!strncmp(environ[i], fe_env_sanitizer[j],
				     strlen(fe_env_sanitizer[j])))
				envp[envc++] = environ[i];
		}
	}
	envp[envc] = NULL;

	fflush(stdout);
	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		if (log_fd >= 0 && dup2(log_fd, STDERR_FILENO) < 0)
			_exit(127);
		execve(daemon, argv, envp);
		_exit(127);
	}

	return pid;
}

bool fe_alive(pid_t pid)
{
	int status;

	return waitpid(pid, &status, WNOHANG) == 0;
}

int fe_stop(pid_t pid, int timeout_ms)
{
	uint64_t end = fe_now_ms() + (uint64_t)timeout_ms;
	int status;

	kill(pid, SIGTERM);

	do {
		pid_t ret = waitpid(pid, &status, WNOHANG);

		if (ret == pid) {
			if (WIFEXITED(status))
				return WEXITSTATUS(status);
			printf("  daemon ended by signal %d\n",
			       WIFSIGNALED(status) ? WTERMSIG(status) : -1);
			return -1;
		}
		if (ret < 0)
			return -1;
		fe_sleep_ms(10);
	} while (fe_now_ms() < end);

	printf("  daemon did not stop within %d ms\n", timeout_ms);
	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);

	return -1;
}
