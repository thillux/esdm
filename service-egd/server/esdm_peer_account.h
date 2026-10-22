/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The user a peer of the server sockets is accounted to.
 *
 * The connections of the server sockets are bounded per peer, see
 * esdm_peer_limit.h, and when connections have to be closed, those of the peer
 * holding the most go first. Taking the peer to be its UID, as SO_PEERCRED
 * tells it, does not bound a user, though: an unprivileged user may map the
 * UIDs of its subordinate range (/etc/subuid, typically 65536 of them) in a
 * user namespace and connect as each of them. Each such UID then holds a
 * connection or two, which makes every consumer of anybody else holding a few
 * - sshd, whose pre-authentication children each connect - the biggest holder
 * by comparison, the first to be closed and the one bounded first.
 *
 * The bound is therefore applied to an account rather than to a UID: the UID
 * of the user the peer acts for. That is
 *
 *   - the peer's UID if the peer runs in the user namespace of the server,
 *   - else the owner of the outermost user namespace between the server's and
 *     the peer's that is not owned by root, as seen from the server - the user
 *     who was delegated the UIDs the peer runs under. A user namespace only
 *     root created and filled, a container's, is root's decision to share out,
 *     so a peer in one is accounted by its own UID, as before,
 *   - else, when the user namespace of the peer cannot be told, the owner of
 *     the /etc/subuid range the peer's UID falls into: these ranges are what
 *     newuidmap(1) lets an unprivileged user map. This is what the daemon goes
 *     by in production - once it dropped its privileges, the kernel only shows
 *     it the user namespace of a process it may ptrace(2), which no other
 *     user's is,
 *   - else the peer's UID.
 *
 * Nothing that fails along the way makes a peer root, who is exempt: the
 * account of an unprivileged peer is never 0.
 */

#ifndef ESDM_PEER_ACCOUNT_H
#define ESDM_PEER_ACCOUNT_H

#include <sys/socket.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prepare the accounting of peers
 *
 * Latches the user namespace of the server and loads /etc/subuid. Called from
 * every interface before its first connection, while the privileges are still
 * held; repeated calls do nothing. esdm_peer_account() calls it as well, so it
 * is never used unprepared.
 */
void esdm_peer_account_init(void);

/**
 * @brief The account of the peer of a connected Unix domain socket
 *
 * @param [in] fd Socket connected to the peer
 * @param [in] cred Credentials of the peer, as SO_PEERCRED tells them
 *
 * @return the UID the peer is accounted to, 0 only for a peer of UID 0
 */
uid_t esdm_peer_account(int fd, const struct ucred *cred);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_PEER_ACCOUNT_H */
