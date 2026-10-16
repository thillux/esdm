/*
 * Remove the PID file between its open and its lock
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

/*
 * Preloaded into the esdm-server by server_pidfile_test: the first lockf()
 * removes the file it is about to lock, as an instance shutting down does when
 * it removes its PID file just after another one opened it. The lock is then
 * taken on a file at no path. The server has to notice and open the path
 * again, otherwise the PID file it writes is visible to nobody.
 */

/* lockf() and lockf64() are two functions, both are interposed */
#undef _FILE_OFFSET_BITS
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

/* The tree is built with hidden symbols, these must be seen to interpose */
#define PRELOAD_EXPORT __attribute__((visibility("default")))

static int unlinked;

static void unlink_once(int fd)
{
	char link[64], path[4096];
	ssize_t len;

	if (unlinked)
		return;
	unlinked = 1;

	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	len = readlink(link, path, sizeof(path) - 1);
	if (len <= 0)
		return;
	path[len] = '\0';

	unlink(path);
}

PRELOAD_EXPORT int lockf(int fd, int cmd, off_t len)
{
	int (*real)(int, int, off_t);

	/* The POSIX way around ISO C's ban of object to function pointers */
	*(void **)&real = dlsym(RTLD_NEXT, "lockf");

	unlink_once(fd);

	return real ? real(fd, cmd, len) : -1;
}

PRELOAD_EXPORT int lockf64(int fd, int cmd, off64_t len)
{
	int (*real)(int, int, off64_t);

	/* The POSIX way around ISO C's ban of object to function pointers */
	*(void **)&real = dlsym(RTLD_NEXT, "lockf64");

	unlink_once(fd);

	return real ? real(fd, cmd, len) : -1;
}
