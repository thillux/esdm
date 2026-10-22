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
 * Creation of the Unix domain sockets the esdm-server listens on, shared by
 * the RPC and EGD interfaces.
 */

#ifndef ESDM_SERVER_SOCKET_H
#define ESDM_SERVER_SOCKET_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Bind a Unix domain socket to a file system path with a given mode
 *
 * The socket file is created with exactly @mode, rather than with whatever the
 * umask leaves and fixed up by a chmod(2) of the path afterwards. The latter
 * follows a symlink an attacker with write access to the directory swapped in
 * between the two calls, and it runs as root - it would hand the attacker a
 * world writable file of its choice. No path based operation follows the
 * bind(2) here.
 *
 * Linux takes the mode of a new socket file from the socket's own inode, as
 * set with fchmod(2) on the socket, masked with the umask of the binding
 * thread. The umask is a process wide attribute, though, and other threads may
 * create files at the same time - lowering it around the bind(2) would expose
 * their files. The bind(2) is therefore made by a short-lived thread of its own
 * that unshares its file system attributes, the umask among them, first: its
 * umask can be cleared without any effect on the rest of the process.
 *
 * Should the unsharing fail, the socket is bound with the umask of the process.
 * The file is then never more accessible than @mode, but possibly less - a
 * warning tells.
 *
 * @param [in] fd Socket to bind, of the AF_UNIX family
 * @param [in] addr Address to bind @fd to
 * @param [in] mode Access mode of the socket file
 *
 * @return 0 on success, < 0 on error - errno is not set
 */
int esdm_server_bind_unix(int fd, const struct sockaddr_un *addr, mode_t mode);

/**
 * @brief Bind a Unix domain socket with a given mode and group
 *
 * As esdm_server_bind_unix(), with the socket file created with the group
 * @gid rather than with the one of the process - by the binding thread
 * switching its file system gid, which no other thread of the process sees.
 * So the file belongs to the group from its creation on, without a chown(2) of
 * the path following the bind(2), for the reason given there.
 *
 * Switching to @gid takes CAP_SETGID, or @gid being the real, effective or
 * saved gid of the process - a supplementary group does not do. A directory
 * with the set-group-ID bit hands its own group to the file regardless.
 *
 * @param [in] fd Socket to bind, of the AF_UNIX family
 * @param [in] addr Address to bind @fd to
 * @param [in] mode Access mode of the socket file
 * @param [in] gid Group of the socket file, (gid_t)-1 for the one of the
 *		   process
 *
 * @return 0 on success, -EPERM if the group cannot be taken on, < 0 on other
 *	   errors - errno is not set
 */
int esdm_server_bind_unix_group(int fd, const struct sockaddr_un *addr,
				mode_t mode, gid_t gid);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_SERVER_SOCKET_H */
