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
 *    handler closes every inherited connection in the child - leaking the
 *    state of an inherited TLS connection, which a parent thread may have
 *    been using -; should the fork bypass it - a direct clone(2) - the client
 *    notices at its next use.
 *
 *  - A network connection the server closed - one idle for long - shows as the
 *    end of its stream only, into which a write still succeeds. One that has
 *    anything to read before a request is replaced: an insertion, which is
 *    not answered, would otherwise be lost.
 *
 * Compared to the RPC client this needs nothing but a single Unix domain stream
 * socket, which makes it reachable from places the RPC interface is not, such
 * as a chroot. The price is a legacy protocol that cannot express transfers
 * above 255 bytes (split transparently); prediction resistance is reached
 * through a command of the ESDM's own, which other EGD daemons do not know.
 *
 * Syscall discipline
 * ------------------
 * Once connected, the operations stay within read(2), write(2), poll(2),
 * rt_sigprocmask(2), close(2), getpid(2), clock_gettime(2), nanosleep(2),
 * getsockopt(2) and - on a kernel without socket cookies - getpeername(2), the
 * latter two to confirm that the descriptor is still the connection made
 * earlier. That is the set a seccomp confined process is typically still
 * allowed, OpenSSH's pre-auth sandbox being the reference case. send(2)/recv(2)
 * are avoided as they are sendto(2)/recvfrom(2), which that filter answers with
 * SECCOMP_RET_KILL, so MSG_NOSIGNAL is unavailable: SIGPIPE is blocked around a
 * write instead. Should the peer vanish right before a write, the SIGPIPE it
 * raises is taken off with sigtimedwait(2) - unless SIGPIPE was ignored when
 * the connection was made, as it is in OpenSSH.
 *
 * Connecting needs socket(2) and connect(2), which such a sandbox kills the
 * process for. A client serving a sandboxed process must therefore be connected
 * before the sandbox is entered - and a process that forks into one cannot be
 * served at all, since the fork forces a reconnect.
 *
 * The esdm-server keeps such a connection open for as long as it sits idle,
 * unless it runs short of them: an idle connection is only closed once nearly
 * all connection slots or descriptors of the server are taken, or the UID of
 * the consumer is being refused further connections. A sandboxed consumer
 * whose connection is closed nevertheless - that way, or by a restart of the
 * daemon - is killed by its sandbox on the reconnect.
 *
 * Network modes
 * -------------
 * A client allocated with esdm_egd_client_alloc_net() speaks the same protocol
 * over TCP to an esdm-egd-net-server, which serves the EGD protocol of the
 * ESDM on its host to the network - see esdm-egd-net-server(8). Everything
 * above holds there as well: one connection per client, the serialized
 * operations, the reconnect and retry, the fork handling. The server treats
 * every client of the network as unprivileged.
 *
 *  - Plain TCP carries the protocol as it is, unencrypted and unauthenticated.
 *    It is meant for networks whose transport is protected underneath, by
 *    IPsec or WireGuard, say. Once connected, it keeps the syscall discipline
 *    above - read(2), write(2), poll(2) and the rest - so a sandboxed process
 *    may use it the way it uses the Unix domain socket, connected before it
 *    enters its sandbox. Mind that the server closes a connection idle for
 *    its idle timeout, which such a process cannot recover from.
 *
 *  - TLS mode is TLS 1.3 with mutual authentication by certificates, see
 *    struct esdm_egd_client_net_config. It does not keep the syscall
 *    discipline: the TLS stack sends and receives with send(2) and recv(2)
 *    and may use whatever else it needs. A sandboxed process uses the
 *    esdm-egd-net-relay through its local Unix domain socket instead, see
 *    esdm-egd-net-relay(8). The TLS is that of the crypto backend the ESDM is
 *    built with - OpenSSL, GnuTLS or Botan -, which the library does not
 *    link: the first client in TLS mode loads it with a module of the
 *    library, esdm-egd-tls.so in the ESDM directory of the libraries. A
 *    process that never allocates such a client has no TLS stack loaded,
 *    which a sandboxed process needs - a TLS stack makes syscalls of its own
 *    when it is loaded and unloaded.
 *
 * The network modes exist in a build with the egd-net option, the TLS mode in
 * one with a TLS stack as well (egd-net-tls); without, the allocation reports
 * -EOPNOTSUPP.
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
 * @brief Network mode of a client, see struct esdm_egd_client_net_config
 */
enum esdm_egd_client_net_mode {
	/** TLS 1.3 with mutual authentication */
	ESDM_EGD_CLIENT_NET_TLS = 1,
	/**
	 * Plain TCP - unencrypted and unauthenticated, for networks protected
	 * underneath only
	 */
	ESDM_EGD_CLIENT_NET_PLAIN = 2,
};

/** CA certificates of the server's chain need a CRL as well */
#define ESDM_EGD_CLIENT_NET_CRL_CHECK_ALL (1U << 0)
/** A CRL past its nextUpdate only causes a warning */
#define ESDM_EGD_CLIENT_NET_CRL_ALLOW_EXPIRED (1U << 1)

/** Most CRL files of a configuration */
#define ESDM_EGD_CLIENT_NET_MAX_CRL 16

/** Most files of trust anchors of a configuration, @ca_file included */
#define ESDM_EGD_CLIENT_NET_MAX_CA 8

/**
 * @brief Configuration of a client of an esdm-egd-net-server
 *
 * Fields are only ever appended. The library takes the ones @size covers and
 * zero for the rest, so a program built against an older header keeps working
 * with a newer library. Initialize the whole structure with zeros and set
 * @size to its sizeof.
 *
 * The files are read when the client is allocated. Each later connection
 * checks them for a change - their inode, size and modification time, so that
 * a file replaced by renaming another one into its place counts, as does a
 * symbolic link switched to another directory - and takes up what changed. A
 * change that does not load completely is logged, and the connections go on
 * with what was loaded before: a broken rotation does not take the client
 * down. All clients of a process with the same files share what they loaded.
 */
struct esdm_egd_client_net_config {
	/** sizeof(struct esdm_egd_client_net_config) of the caller */
	size_t size;
	/** ESDM_EGD_CLIENT_NET_TLS or ESDM_EGD_CLIENT_NET_PLAIN */
	enum esdm_egd_client_net_mode mode;
	/**
	 * The server: "host:port", "[IPv6 address]:port", or the same without
	 * the port for the port the ESDM was built with (meson option
	 * egd-net-port). The host is resolved with getaddrinfo(3) at every
	 * connection, and its addresses are tried in turn.
	 */
	const char *address;
	/** As the @timeout_ms of esdm_egd_client_alloc(). */
	unsigned int timeout_ms;

	/* TLS mode only - plain TCP refuses every one of them */

	/**
	 * Certificate of the client, PEM, optionally followed by the
	 * intermediate certificates of its chain
	 */
	const char *cert_file;
	/** Its private key, PEM, unencrypted PKCS#8 */
	const char *key_file;
	/**
	 * Trust anchors, PEM: the server's chain must lead to one of them, and
	 * the client's own certificate must as well
	 */
	const char *ca_file;
	/**
	 * Name the server's certificate has to be issued for - a DNS name, or
	 * an IPv4 or IPv6 address. NULL takes the host of @address.
	 */
	const char *server_name;
	/**
	 * CRLs, PEM, each file may hold several, NULL-terminated, at most
	 * ESDM_EGD_CLIENT_NET_MAX_CRL - NULL for none. With CRLs, the server's
	 * certificate needs a CRL of its issuer that does not list it; see
	 * esdm-egd-net-relay(8) for exactly what is checked.
	 */
	const char *const *crl_files;
	/** ESDM_EGD_CLIENT_NET_CRL_* */
	unsigned int crl_flags;
	/**
	 * More trust anchors, PEM, next to those of @ca_file and alike,
	 * NULL-terminated, at most ESDM_EGD_CLIENT_NET_MAX_CA - 1 files - for
	 * the rollover of a CA, the old one and the new one trusted at once.
	 * NULL for none.
	 */
	const char *const *ca_files;
};

/**
 * @brief Allocate a client of an esdm-egd-net-server and connect it
 *
 * As esdm_egd_client_alloc(), over the network: failing to connect is no
 * allocation failure, the operations retry. A configuration that is wrong -
 * an address that does not parse, a TLS file that does not load - is one.
 *
 * @param [out] client Allocated client, to be released with
 *		       esdm_egd_client_free()
 * @param [in] cfg The configuration; nothing of it is referenced after the
 *		   call returned
 *
 * @return 0 on success, -EOPNOTSUPP in a build without the network mode asked
 *	   for, -EINVAL for a configuration that is wrong, < 0 on other errors
 */
int esdm_egd_client_alloc_net(struct esdm_egd_client **client,
			      const struct esdm_egd_client_net_config *cfg);

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
 * @return The path, owned by the client - for a client of the network the
 *	   address of the server
 */
const char *esdm_egd_client_socket_path(const struct esdm_egd_client *client);

/**
 * @brief Obtain random data, waiting for the ESDM to become operational
 *
 * Requests larger than one protocol transfer are split transparently, the
 * commands of up to 64 KiB sent at once and their answers read after, which
 * takes one round trip per 64 KiB rather than one per transfer. On failure
 * @buf is cleansed, so a partial transfer can never be mistaken for a complete
 * one.
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
 * The ESDM answers with as much data as it can deliver right away, which is
 * nothing at all while it is not operational yet. Use this only where a short
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
 * @brief Obtain prediction resistant random data, waiting for it
 *
 * Like esdm_egd_client_get_random(), but served by the ESDM's prediction
 * resistance DRNG, which hands out no more than its entropy sources just
 * delivered - the answer takes as long as collecting that entropy does. The
 * ESDM-specific command this uses is unknown to other EGD daemons, which
 * close the connection on it: the call fails then.
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
 * @brief Obtain prediction resistant random data without waiting
 *
 * Like esdm_egd_client_get_random_nonblock(), but served by the prediction
 * resistance DRNG: the answer holds what its entropy sources can deliver
 * right away, often less than asked for.
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
 * @brief Obtain random data without waiting for all DRNGs to be seeded
 *
 * The semantics of /dev/urandom: the ESDM answers from its DRNG without
 * waiting for all of its DRNGs to be fully seeded. Before the ESDM is
 * operational it hands out nothing, which is no error - @generated is zero
 * then. The ESDM-specific command this uses is unknown to other EGD daemons.
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
 * @brief Query the state of the ESDM
 *
 * The fields of ESDM_EGD_CMD_ESDM_GET_STATE, indexed by ESDM_EGD_STATE_* of
 * esdm_egd_protocol.h. A newer ESDM may report more fields than the caller
 * knows of, an older one fewer.
 *
 * @param [in] client Client to use
 * @param [out] fields Room for @num_fields fields
 * @param [in,out] num_fields In: the room of @fields. Out: the number of
 *			      fields the ESDM reported, of which the first
 *			      ones up to the room were stored.
 *
 * @return 0 on success, < 0 on error
 */
int esdm_egd_client_get_state(struct esdm_egd_client *client, uint32_t *fields,
			      unsigned int *num_fields);

/**
 * @brief Obtain the status report of the ESDM as text
 *
 * @param [in] client Client to use
 * @param [out] buf Buffer for the report, NUL terminated - at most
 *		    ESDM_EGD_MAX_STATUS bytes plus the NUL
 * @param [in] buflen Size of @buf
 *
 * @return the length of the report on success, 0 if the ESDM had none,
 *	   -EMSGSIZE if it did not fit - @buf holds as much of it as did -, < 0
 *	   on other errors
 */
int esdm_egd_client_status(struct esdm_egd_client *client, char *buf,
			   size_t buflen);

/**
 * @brief Obtain the status report of the ESDM as JSON document
 *
 * As esdm_egd_client_status(), but a document that does not fit is not handed
 * out cut short: @buf is left empty with -EMSGSIZE. 0 means the ESDM had no
 * document - it did not fit into a transfer, see ESDM_EGD_MAX_STATUS.
 */
int esdm_egd_client_status_json(struct esdm_egd_client *client, char *buf,
				size_t buflen);

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
