/*
 * Copyright (C) 2018 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef HELPER_H
#define HELPER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __aligned(x) __attribute__((aligned(x)))
#define __unused __attribute__((__unused__))
#define __maybe_unused __attribute__((__unused__))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define member_to_struct(member, data_type, member_var)                        \
	(data_type *)((char *)(member) - (char *)&((data_type *)0)->member_var)

/* Whole seconds on CLOCK_MONOTONIC, 0 if the clock cannot be read */
static inline long long esdm_monotonic_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return 0;

	return (long long)now.tv_sec;
}

/* Seconds elapsed since timeout_sec (CLOCK_MONOTONIC), 0 if not yet reached */
static inline time_t esdm_time_after_now(time_t timeout_sec)
{
	time_t curr = (time_t)esdm_monotonic_now();

	return (curr > timeout_sec) ? (curr - timeout_sec) : 0;
}

static inline int aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

uint32_t esdm_online_nodes(void);
uint32_t esdm_curr_node(void);
ssize_t esdm_safe_read(int fd, uint8_t *buf, size_t buflen);
ssize_t esdm_safe_write(int fd, uint8_t *buf, size_t buflen);
void may_enable_memory_debugging(void);

/**
 * @brief Whether the file open at a descriptor still is the one at its path
 *
 * A file that was removed or replaced after it was opened is no longer the one
 * its path names, e.g. a lock file that its holder unlinked while another
 * process opened it. The path is not followed: a symbolic link at @path names
 * no file that was opened with O_NOFOLLOW.
 *
 * @param [in] fd Open descriptor of the file
 * @param [in] path Path the file was opened at
 *
 * @return 1 if @path names the file open at @fd, 0 if it names another file or
 *	   none, a negative errno if that cannot be told
 */
int esdm_fd_at_path(int fd, const char *path);

struct shmid_ds;

/**
 * @brief Whether a shared memory segment is one the ESDM server created
 *
 * The status segment uses a well-known key. Any local user can create it while
 * there is none, and would control the state it reports. The server removes
 * such a segment when it starts, but until then - and as long as no server
 * runs - a client must not take it for the server's.
 *
 * The server creates the segment with its effective uid before it drops its
 * privileges: root in the stock deployment, the uid it is started with
 * otherwise. Which one it is the clients cannot tell from a configuration, so
 * the segment is accepted when created by and owned by root or by the owner of
 * the server's RPC socket @server_socket. The socket is created likewise
 * before the privileges are dropped, or by systemd as root, in a directory
 * other users cannot write to. Whoever owns it is the one a client receives
 * its random numbers from, so a segment of that uid is no less trustworthy.
 * So is one of the caller's own uid, whose creator controls the caller anyway -
 * e.g. a server and a client run by the same unprivileged user. Not so for a
 * caller running with privileges its user does not have - a set-uid or set-gid
 * program, or one whose real and effective uids differ: the user that invoked
 * it could plant the segment, so only root and the socket owner count there.
 *
 * @param [in] buf Status of the segment as obtained with IPC_STAT
 * @param [in] server_socket Path of the server's RPC socket, may be NULL to
 *			     accept root only
 *
 * @return true if the segment is the server's, false otherwise
 */
bool esdm_shm_created_by_server(const struct shmid_ds *buf,
				const char *server_socket);

#ifdef __cplusplus
}
#endif

#endif /* HELPER_H */
