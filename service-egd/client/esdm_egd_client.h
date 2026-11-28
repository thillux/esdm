/*
 * Client for the EGD (Entropy Gathering Daemon) interface of the ESDM
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

#ifndef ESDM_EGD_CLIENT_H
#define ESDM_EGD_CLIENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Client of the ESDM's EGD interface
 *
 * A client owns exactly one connection to the EGD socket. The protocol carries
 * no request identifiers - responses are matched to requests by their order on
 * the stream alone - so all operations of one client are serialized and one
 * request is in flight at a time; a caller wanting concurrency uses several
 * clients. The lock behind that is robust, so a thread killed mid operation
 * hands the client on rather than wedging it for the process' lifetime.
 *
 * All operations are thread safe and reconnect on their own:
 *
 *  - The connection is established by esdm_egd_client_alloc() and released by
 *    esdm_egd_client_free(). A client whose initial connect failed stays usable
 *    and connects on first use.
 *
 *  - A transfer failing halfway leaves the peer's parser at an unknown offset,
 *    so the connection is dropped and the operation retried once on a fresh
 *    one. A daemon restart between two requests is thus invisible.
 *
 *  - A descriptor inherited across fork() refers to the parent's connection,
 *    which two processes interleaving commands would desynchronize. A fork
 *    handler closes every inherited connection in the child; should the fork
 *    bypass it - a direct clone(2) - the client notices at its next use.
 *
 * Compared to the RPC client this needs nothing but a single Unix domain stream
 * socket, which makes it reachable from places the RPC interface is not, such
 * as a chroot. The price is a legacy protocol that can express neither
 * prediction resistance nor transfers above 255 bytes (split transparently);
 * the ESDM's extensions of the protocol add both, see
 * esdm_egd_client_get_state().
 *
 * Syscall discipline
 * ------------------
 * Once connected, the operations stay within read(2), write(2), ppoll(2),
 * close(2), getpid(2), getpeername(2), rt_sigprocmask(2), clock_gettime(2) and
 * nanosleep(2) - the set a seccomp confined process is typically still allowed,
 * OpenSSH's pre-auth sandbox being the reference case. send(2)/recv(2) are
 * avoided as they are sendto(2)/recvfrom(2), which that filter answers with
 * SECCOMP_RET_KILL, so MSG_NOSIGNAL is unavailable: a write blocks SIGPIPE for
 * its thread instead, and only once the peer is gone takes the signal off with
 * rt_sigtimedwait(2) - where a reconnect would follow anyway.
 *
 * Connecting needs socket(2) and connect(2), which such a sandbox kills the
 * process for. A client serving a sandboxed process must therefore be connected
 * before the sandbox is entered - and a process that forks into one cannot be
 * served at all, since the fork forces a reconnect.
 */
struct esdm_egd_client;

/**
 * @brief Allocate a client and connect it
 *
 * The connection is established here, which is what a caller serving a
 * sandboxed process needs - connecting is exactly what such a process may no
 * longer do, see the syscall discipline above. Failing to connect is not an
 * allocation failure: the client is handed back usable and every operation
 * retries, so a consumer initialized before the ESDM is up keeps working once
 * the daemon arrives.
 *
 * @param [out] client Allocated client, to be released with
 *		       esdm_egd_client_free()
 * @param [in] socket_path Path of the EGD socket. NULL or the empty string
 *			   selects the path from the ESDM_EGD_SOCKET
 *			   environment variable, and failing that the socket
 *			   path this ESDM was built with.
 * @param [in] timeout_ms Bound in milliseconds on one step - the connection
 *			  setup, or one transfer. Every wait is a poll of its
 *			  own, so this covers the connect as well, which a
 *			  receive timeout cannot. 0 selects a default generous
 *			  enough for a blocking read to wait for a not yet
 *			  operational ESDM; large values are capped.
 *
 * @return 0 on success, < 0 when no client could be allocated - a failure to
 *	   connect is reported through the ESDM logger, not here
 */
int esdm_egd_client_alloc(struct esdm_egd_client **client,
			  const char *socket_path, unsigned int timeout_ms);

/**
 * @brief Close the connection and release the client
 *
 * @param [in] client Client to release, may be NULL
 */
void esdm_egd_client_free(struct esdm_egd_client *client);

/**
 * @brief Path of the EGD socket this client talks to
 *
 * @param [in] client Client to query
 *
 * @return The path, owned by the client
 */
const char *esdm_egd_client_socket_path(const struct esdm_egd_client *client);

/**
 * @brief Obtain random data, waiting for the ESDM to become operational
 *
 * Requests larger than one protocol transfer are split transparently. On
 * failure @buf is cleansed, so a partial transfer can never be mistaken for a
 * complete one.
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to obtain
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random(struct esdm_egd_client *client, uint8_t *buf,
			       size_t buflen);

/**
 * @brief Obtain random data without waiting
 *
 * The ESDM answers with as much data as it can deliver without blocking,
 * which is nothing at all while it is not operational yet. While its DRNGs
 * wait for a reseed, it holds the answer back for up to a second. Use this only where a short
 * answer is acceptable - a seed consumer wants esdm_egd_client_get_random().
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to ask for, at most
 *		      ESDM_EGD_MAX_TRANSFER
 * @param [out] generated Number of bytes actually delivered
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_nonblock(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated);

/**
 * @brief Query the amount of entropy the ESDM currently holds
 *
 * @param [in] client Client to use
 * @param [out] entropy_bits Available entropy in bits
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_entropy_count(struct esdm_egd_client *client,
				  uint32_t *entropy_bits);

/**
 * @brief Query the state of the ESDM
 *
 * @param [in] client Client to use
 * @param [out] flags ESDM_EGD_STATE_FLAG_* of esdm_egd_protocol.h, e.g.
 *		      ESDM_EGD_STATE_FLAG_OPERATIONAL while the ESDM serves
 *		      reads
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_state_flags(struct esdm_egd_client *client,
				    uint32_t *flags);

/**
 * @brief Extensions of the ESDM to the EGD protocol
 *
 * The functions from here to esdm_egd_client_insert() use the commands the ESDM
 * adds to the EGD protocol, see esdm_egd_protocol.h. They connect, reconnect
 * and time out like the functions above. A peer that does not know such a
 * command - another EGD, or an ESDM from before the command was added - closes
 * the connection: the function then fails with -EPIPE, or with -ECONNRESET
 * where it was still sending data, after its one retry on a fresh connection.
 *
 * The commands that change the entropy accounting or the DRNGs are carried out
 * for a privileged peer only, that is, a caller connected with UID 0. For any
 * other caller the ESDM refuses them and the function returns -EPERM; the
 * connection stays usable.
 */

/**
 * @brief The state of the ESDM as the get state command reports it
 */
struct esdm_egd_client_state {
	/** ESDM_EGD_STATE_FLAG_* of esdm_egd_protocol.h */
	uint32_t flags;
	/** Entropy of the auxiliary pool in bits */
	uint32_t entropy_count;
	/** Size of the auxiliary pool in bits */
	uint32_t poolsize;
	/** Write wakeup threshold in bits */
	uint32_t write_wakeup;
	/** Maximum time between two reseeds of a DRNG in seconds */
	uint32_t min_reseed_secs;
};

/**
 * @brief Query the state of the ESDM with all of its fields
 *
 * @param [in] client Client to use
 * @param [out] state The state, see struct esdm_egd_client_state
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_state(struct esdm_egd_client *client,
			      struct esdm_egd_client_state *state);

/**
 * @brief Obtain random data with prediction resistance, waiting for it
 *
 * As esdm_egd_client_get_random(), but served by the prediction resistance
 * DRNG whatever the socket: every request is preceded by a reseed from the
 * entropy sources and delivers no more than they just produced, so that it
 * takes as long as collecting that entropy does.
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to obtain
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_pr(struct esdm_egd_client *client, uint8_t *buf,
				  size_t buflen);

/**
 * @brief Obtain random data with prediction resistance without waiting
 *
 * As esdm_egd_client_get_random_nonblock(), but served by the prediction
 * resistance DRNG whatever the socket.
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to ask for, at most
 *		      ESDM_EGD_MAX_TRANSFER
 * @param [out] generated Number of bytes actually delivered
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_pr_nonblock(struct esdm_egd_client *client,
					   uint8_t *buf, size_t buflen,
					   size_t *generated);

/**
 * @brief Obtain random data without waiting for the DRNGs to be fully seeded
 *
 * The semantics of /dev/urandom: the ESDM answers from a DRNG that may not be
 * fully seeded yet. It hands out nothing before it is operational, the answer
 * is empty then; otherwise the answer is short only when the DRNG reached the
 * most it may generate without a full reseed, or on an error in the ESDM.
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to ask for, at most
 *		      ESDM_EGD_MAX_TRANSFER
 * @param [out] generated Number of bytes actually delivered
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_unseeded(struct esdm_egd_client *client,
					uint8_t *buf, size_t buflen,
					size_t *generated);

/**
 * @brief Obtain up to ESDM_EGD_MAX_BULK bytes of random data in one transfer
 *
 * The bulk read of the ESDM stands for one of the reads that do not wait and
 * is answered as that read, without the limit of 255 bytes per transfer.
 *
 * @param [in] client Client to use
 * @param [in] read_cmd The read it stands for: ESDM_EGD_CMD_READ_NONBLOCK
 *			(esdm_egd_client_get_random_nonblock()),
 *			ESDM_EGD_CMD_ESDM_PR_READ_NONBLOCK
 *			(esdm_egd_client_get_random_pr_nonblock()) or
 *			ESDM_EGD_CMD_ESDM_READ_UNSEEDED
 *			(esdm_egd_client_get_random_unseeded())
 * @param [out] buf Buffer to fill
 * @param [in] buflen Number of bytes to ask for, at most ESDM_EGD_MAX_BULK
 * @param [out] generated Number of bytes actually delivered
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_random_bulk(struct esdm_egd_client *client,
				    uint8_t read_cmd, uint8_t *buf,
				    size_t buflen, size_t *generated);

/**
 * @brief Obtain the status report of the ESDM as text
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer for the report, which is NUL terminated. A report
 *		    that does not fit is cut short. ESDM_EGD_MAX_STATUS + 1
 *		    bytes hold every report.
 * @param [in] buflen Size of the buffer
 *
 * @return 0 on success, -ENODATA when the ESDM could not produce the report,
 *	   < 0 on other errors
 */
int esdm_egd_client_status(struct esdm_egd_client *client, char *buf,
			   size_t buflen);

/**
 * @brief Obtain the status of the ESDM as JSON document
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer for the document, which is NUL terminated.
 *		    ESDM_EGD_MAX_STATUS + 1 bytes hold every document.
 * @param [in] buflen Size of the buffer
 *
 * @return 0 on success, -EMSGSIZE when the document does not fit the buffer -
 *	   nothing is returned then -, -ENODATA when the ESDM could not produce
 *	   it or it exceeds ESDM_EGD_MAX_STATUS, < 0 on other errors
 */
int esdm_egd_client_status_json(struct esdm_egd_client *client, char *buf,
				size_t buflen);

/**
 * @brief Credit entropy to the auxiliary pool (privileged)
 *
 * The counterpart of the RNDADDTOENTCNT ioctl. The ESDM never credits more
 * than the pool can hold.
 *
 * If the transfer fails after the command was sent, the function returns the
 * error without sending the command again, as the ESDM may have carried it
 * out and a second one would credit twice: the caller cannot tell then
 * whether the entropy was credited. The other privileged commands set a value
 * and are repeated on a fresh connection.
 *
 * @param [in] client Client to use
 * @param [in] entropy_bits Entropy to credit in bits
 *
 * @return 0 on success, -EPERM for an unprivileged caller, < 0 on other errors
 */
int esdm_egd_client_add_to_entropy_count(struct esdm_egd_client *client,
					 uint32_t entropy_bits);

/**
 * @brief Set the entropy of the auxiliary pool to zero (privileged)
 *
 * The counterpart of the RNDZAPENTCNT and RNDCLEARPOOL ioctls.
 *
 * @param [in] client Client to use
 *
 * @return 0 on success, -EPERM for an unprivileged caller, < 0 on other errors
 */
int esdm_egd_client_clear_pool(struct esdm_egd_client *client);

/**
 * @brief Have the DRNGs reseeded at their next use (privileged)
 *
 * The counterpart of the RNDRESEEDCRNG ioctl.
 *
 * @param [in] client Client to use
 *
 * @return 0 on success, -EPERM for an unprivileged caller, < 0 on other errors
 */
int esdm_egd_client_reseed(struct esdm_egd_client *client);

/**
 * @brief Set the write wakeup threshold (privileged)
 *
 * The counterpart of /proc/sys/kernel/random/write_wakeup_threshold.
 *
 * @param [in] client Client to use
 * @param [in] bits Threshold in bits
 *
 * @return 0 on success, -EPERM for an unprivileged caller, < 0 on other errors
 */
int esdm_egd_client_set_write_wakeup(struct esdm_egd_client *client,
				     uint32_t bits);

/**
 * @brief Set the maximum time between two reseeds of a DRNG (privileged)
 *
 * The counterpart of /proc/sys/kernel/random/urandom_min_reseed_secs. The ESDM
 * may adjust the value; esdm_egd_client_get_state() reports the one in effect.
 *
 * @param [in] client Client to use
 * @param [in] seconds Time in seconds
 *
 * @return 0 on success, -EPERM for an unprivileged caller, < 0 on other errors
 */
int esdm_egd_client_set_min_reseed_secs(struct esdm_egd_client *client,
					uint32_t seconds);

/**
 * @brief Insert up to ESDM_EGD_MAX_BULK bytes into the auxiliary pool
 *
 * The data is inserted without entropy credit, for every caller, and the ESDM
 * confirms the insertion - other than esdm_egd_client_write_entropy(), whose
 * command has no answer. A privileged caller credits entropy to it with
 * esdm_egd_client_add_to_entropy_count().
 *
 * @param [in] client Client to use
 * @param [in] buf Data to insert, at most ESDM_EGD_MAX_BULK bytes
 * @param [in] buflen Length of the data
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_insert(struct esdm_egd_client *client, const uint8_t *buf,
			   size_t buflen);

/**
 * @brief Insert data into the ESDM's auxiliary pool
 *
 * The protocol allows attaching an entropy claim to the data, which the ESDM
 * only honors for a privileged (UID 0) caller. An unprivileged caller passing
 * a non-zero @entropy_bits is not an error - the claim is simply dropped.
 *
 * @param [in] client Client to use
 * @param [in] buf Data to insert, at most ESDM_EGD_MAX_TRANSFER bytes
 * @param [in] buflen Length of the data
 * @param [in] entropy_bits Claimed entropy of the data in bits
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_write_entropy(struct esdm_egd_client *client,
				  const uint8_t *buf, size_t buflen,
				  uint32_t entropy_bits);

/**
 * @brief Query the PID of the daemon serving the socket
 *
 * @param [in] client Client to use
 * @param [out] pid PID reported by the peer
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_pid(struct esdm_egd_client *client, pid_t *pid);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_EGD_CLIENT_H */
