/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "config.h"

#include "arch.h"

#ifdef ESDM_MEMORY_DEBUG
#include <malloc.h>
#include <mcheck.h>
#endif

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <unistd.h>

#include "helper.h"
#include "math_helper.h"

uint32_t esdm_online_nodes(void)
{
	/*
	 * Atomic as the lazy caching is otherwise a data race: concurrent
	 * first-time callers (e.g. the privileged and the unprivileged RPC
	 * client init running in different threads) both evaluate and store it.
	 * Doing so is harmless - the value is the same for everybody - but it
	 * has to be a defined operation.
	 */
	static _Atomic uint32_t cpus = UINT32_MAX;

	/* We do not need more DRNGs than we have CPUs */
	if (cpus == UINT32_MAX) {
#ifdef _GNU_SOURCE
		long ncpus = sysconf(_SC_NPROCESSORS_ONLN);

		if (ncpus > 0) {
			/*
			 * We do not need more DRNGs than we have threads
			 * available - its counterpart is in function
			 * esdm_curr_node().
			 */
			cpus = min_uint32((uint32_t)ncpus,
					  THREADING_MAX_WORKER_THREADS);
		} else {
			cpus = 1;
		}
#else
		cpus = 1;
#endif
	}

	return cpus;
}

uint32_t esdm_curr_node(void)
{
	uint32_t cpu = esdm_arch_curr_node();

	/*
	 * Limit the CPU selection by number of available threads - this is the
	 * counterpart to esdm_config_online_nodes.
	 */
	return (cpu % esdm_online_nodes());
}

ssize_t esdm_safe_read(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t readlen;
	ssize_t bytes_read = 0;

	do {
		readlen = read(fd, buf, buflen);
		if (readlen > 0) {
			buflen -= (size_t)readlen;
			buf += (size_t)readlen;
			bytes_read += readlen;
		} else if (readlen == 0) {
			goto out;
		} else if (errno != EINTR) {
			/*
			 * Like read(2)/write(2): what was transferred before
			 * the error is reported, the error is left for the
			 * next call - the data cannot be put back.
			 */
			if (!bytes_read)
				bytes_read = -errno;
			goto out;
		}
	} while (buflen);

out:
	return bytes_read;
}

ssize_t esdm_safe_write(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t writelen;
	ssize_t bytes_written = 0;

	do {
		writelen = write(fd, buf, buflen);
		if (writelen > 0) {
			buflen -= (size_t)writelen;
			buf += (size_t)writelen;
			bytes_written += writelen;
		} else if (writelen == 0) {
			goto out;
		} else if (errno != EINTR) {
			/*
			 * Like read(2)/write(2): what was transferred before
			 * the error is reported, the error is left for the
			 * next call - the data cannot be put back.
			 */
			if (!bytes_written)
				bytes_written = -errno;
			goto out;
		}
	} while (buflen);

out:
	return bytes_written;
}

/*
 * Root, the server's uid, or the real uid of the caller: a segment the latter
 * created can only be planted by somebody who controls the caller anyway. The
 * real one, as the CUSE daemon checks with its effective uid dropped to an
 * unprivileged user, whose segments are not the server's.
 */
static bool esdm_shm_uid_trusted(uid_t uid, uid_t server_uid)
{
	return uid == 0 || uid == server_uid || uid == getuid();
}

bool esdm_shm_created_by_server(const struct shmid_ds *buf,
				const char *server_socket)
{
	struct stat sb;
	/* root, unless the socket names somebody else */
	uid_t server_uid = 0;

	if (!buf)
		return false;

	/*
	 * Only a socket counts: a plain file at the path tells nothing about
	 * who runs the server. Without one, no server runs that is not root.
	 */
	if (server_socket && !stat(server_socket, &sb) && S_ISSOCK(sb.st_mode))
		server_uid = sb.st_uid;

	/*
	 * The creator is what matters: the owner of a segment can hand it to
	 * any uid with IPC_SET, the creator stays. The owner is checked as
	 * well, as the server never hands its segment to somebody else, which
	 * could then change its permissions.
	 */
	return esdm_shm_uid_trusted(buf->shm_perm.cuid, server_uid) &&
	       esdm_shm_uid_trusted(buf->shm_perm.uid, server_uid);
}

void may_enable_memory_debugging()
{
#ifdef ESDM_MEMORY_DEBUG
	/* perform consistency checks */
	mcheck_pedantic(NULL);

	/* release memory fast, in order to
	 * check total consumption externally */
	mallopt(M_TRIM_THRESHOLD, 0);
	mallopt(M_MMAP_THRESHOLD, 0);
	mallopt(M_MMAP_MAX, -1);

	/* set newly allocated and freed memory
	 * to this value */
	mallopt(M_PERTURB, 0xff);

	/* memory options should be called very early,
	 * logger is typically not set up*/
	fprintf(stderr,
		"WARNING: Memory debugging enabled. Don't use in production.\n");
#endif
}
