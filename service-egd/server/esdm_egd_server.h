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

#ifndef ESDM_EGD_SERVER_H
#define ESDM_EGD_SERVER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enable the EGD (Entropy Gathering Daemon) compatibility interface
 *
 * Serving the protocol of egd.pl / prngd on an additional Unix domain stream
 * socket lets legacy clients - libgcrypt's rndegd backend, OpenSSL's
 * RAND_egd() - draw from the ESDM unmodified.
 *
 * Opt-in: disabled unless this call is made or systemd hands over a socket
 * named ESDM_EGD_SOCKET (see esdm_egd_server_socket_init()). Next to the
 * standard EGD commands, the socket serves the ESDM's own, see
 * esdm_egd_protocol.h - prediction resistant reads among them.
 *
 * Only records the request, and must be invoked before esdm_rpc_server_init(),
 * i.e. while the server is still single-threaded and privileged.
 *
 * @param [in] socket_path Path of the Unix domain socket to create
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_server_enable(const char *socket_path);

/**
 * @brief Set the PID the EGD get PID command reports
 *
 * The PID to report is the one external parties signal the daemon by. In a PID
 * namespace (linux_isolate_namespace_prefork()) that is the supervisor, while
 * the daemon itself is PID 1 of its namespace - so record it before that fork.
 * Without this call the daemon's own PID is reported.
 *
 * @param [in] pid PID to report
 */
void esdm_egd_server_set_pid(pid_t pid);

/**
 * @brief Was a socket path requested on the command line?
 *
 * Note that this is not the same as the interface being active: systemd socket
 * activation enables it without any path being known here.
 *
 * @return boolean whether esdm_egd_server_enable() was called
 */
bool esdm_egd_server_enabled(void);

/**
 * @brief Obtain the EGD listening socket
 *
 * A socket handed over by systemd under the name ESDM_EGD_SOCKET is preferred
 * and enables the interface on its own - starting the .socket unit is the
 * request to serve EGD, and the unit carries path and access mode. Otherwise
 * the path from esdm_egd_server_enable() is bound and opened to all users,
 * which needs the privileges the server only holds while initializing. This
 * must therefore run before the permanent privilege drop, while the worker
 * serving the socket is started afterwards (esdm_egd_server_start()).
 * A no-op when neither of the two enables the interface.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_server_socket_init(void);

/**
 * @brief Start the worker thread serving the EGD socket
 *
 * Must be called after the permanent privilege drop so that the worker - and
 * with it all handling of client-supplied data - runs unprivileged.
 *
 * It is a no-op when esdm_egd_server_socket_init() did not obtain a socket.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_server_start(void);

/**
 * @brief Map each EGD worker to a node DRNG of its own, or not
 *
 * By default, each worker thread serves the reads of its clients - all but the
 * prediction resistant ones - from a node DRNG it is mapped to, see
 * esdm_drng_node_bind(). Switched off, they are served by the first free node
 * DRNG they find, as every other caller is. To be called before
 * esdm_egd_server_start().
 *
 * @param [in] enable Each worker its node DRNG (true), or not (false)
 */
void esdm_egd_server_set_drng_mapping(bool enable);

/**
 * @brief Async-signal-safe shutdown trigger for the EGD worker
 *
 * Only performs an atomic store; the worker observes it within the bounded
 * poll interval of its event loop.
 */
void esdm_egd_server_signal_exit_safe(void);

/**
 * @brief Terminate the EGD worker and release the listening socket
 *
 * Waits (bounded) for the worker to leave its event loop so that no client
 * request is still being served when the ESDM is finalized.
 */
void esdm_egd_server_fini(void);

/**
 * @brief Remove the EGD socket from the file system
 *
 * A socket the server bound itself is also the server's to remove; one handed
 * over by systemd socket activation is left to systemd. As with the RPC
 * sockets, the removal needs the privileges the daemon dropped, hence this is
 * invoked from the privileged context performing the IPC cleanup.
 */
void esdm_egd_server_cleanup(void);

#ifdef ESDM_FUZZING
/**
 * @brief Hand one stream of client bytes to the EGD connection state machine
 * @param [in] out_fd Descriptor the responses are written to
 * @param [in] data The records, see above
 * @param [in] len Number of bytes in @p data
 * @return 0 when the connection remained usable, < 0 when it would have been
 * 	closed - which for a malformed stream is the expected outcome
 */
int esdm_egd_fuzz_stream(int out_fd, const uint8_t *data, size_t len);

#endif /* ESDM_FUZZING */

#ifdef __cplusplus
}
#endif

#endif /* ESDM_EGD_SERVER_H */
