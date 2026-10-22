/*
 * Creation of the Unix domain sockets of the esdm-server
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
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/stat.h>

#include "esdm_logger.h"
#include "esdm_server_socket.h"

struct esdm_server_bind {
	int fd;
	const struct sockaddr_un *addr;
	/* The bind(2) result, 0 or a negative errno */
	int ret;
	/* The thread could not get a umask of its own */
	int unshare_errno;
};

/*
 * The thread making the bind(2), see esdm_server_bind_unix(). It does nothing
 * else: what it unshared goes away with it.
 */
static void *esdm_server_bind_thread(void *arg)
{
	struct esdm_server_bind *b = arg;

	/*
	 * CLONE_FS unshares the root and working directories along with the
	 * umask - they are copies of the process' ones, so the path resolves
	 * exactly as it would for the caller.
	 */
	if (unshare(CLONE_FS) == 0)
		umask(0);
	else
		b->unshare_errno = errno;

	b->ret = 0;
	if (bind(b->fd, (const struct sockaddr *)b->addr, sizeof(*b->addr)) < 0)
		b->ret = -errno;

	return NULL;
}

int esdm_server_bind_unix(int fd, const struct sockaddr_un *addr, mode_t mode)
{
	struct esdm_server_bind b = { .fd = fd, .addr = addr, .ret = -EFAULT };
	pthread_t thread;
	int ret;

	if (!addr || addr->sun_family != AF_UNIX)
		return -EINVAL;

	/*
	 * The mode the socket file is created with - masked with the umask of
	 * the binding thread, which never adds a permission. From here on the
	 * file is never more accessible than @mode, whatever happens below.
	 */
	if (fchmod(fd, mode & 0777) < 0)
		return -errno;

	ret = -pthread_create(&thread, NULL, esdm_server_bind_thread, &b);
	if (ret)
		return ret;
	pthread_join(thread, NULL);

	if (b.unshare_errno) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_SERVER,
			"Cannot clear the umask for creating socket %s (%s) - its access mode may be narrower than %04o\n",
			addr->sun_path, strerror(b.unshare_errno),
			(unsigned int)(mode & 0777));
	}

	return b.ret;
}
