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
 * What the esdm-egd-net-server and the esdm-egd-net-relay share: the files of
 * the TLS and their reload, the sockets handed over by socket activation, and
 * - for the server - the addresses of the network: the allowlist, the source a
 * connection is accounted to, and the bounds keyed by it.
 */

#ifndef EGD_NET_COMMON_H
#define EGD_NET_COMMON_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "esdm_tls.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Most --listen, --allow and LISTEN_FDS of a daemon */
#define EGD_NET_MAX_LISTEN 16
#define EGD_NET_MAX_ALLOW 64

/* Room for an address and port as text, see egd_net_addr_str() */
#define EGD_NET_ADDR_STR_LEN 64

/* Longest key of struct egd_net_limit: a fingerprint and its kind */
#define EGD_NET_KEY_LEN (1 + ESDM_TLS_FINGERPRINT_LEN)

/**
 * @brief A file named on the command line, as the daemon reads it
 *
 * A name without a slash is a credential of the service: it is looked up in
 * $CREDENTIALS_DIRECTORY, where systemd places what LoadCredential= names. A
 * path is taken as it is.
 *
 * @return the path, allocated; NULL if @name names a credential and there is
 *	   no $CREDENTIALS_DIRECTORY, or without memory
 */
char *egd_net_file(const char *name);

/**
 * @brief The files of the TLS of a daemon, as given on the command line
 */
struct egd_net_tls_files {
	char *cert;
	char *key;
	char *ca;
	char *crl[ESDM_TLS_MAX_CRL_FILES];
	unsigned int crl_num;
	bool crl_check_all;
	bool crl_allow_expired;
};

/**
 * @brief The configuration of the TLS layer for the files
 */
void egd_net_tls_config(const struct egd_net_tls_files *files,
			struct esdm_tls_config *cfg);

/**
 * @brief Resolve and check the TLS options of a daemon
 *
 * Plain TCP is never a default: with @plain, every TLS option is an error;
 * without it, the certificate, its key and the trust anchors are required -
 * from the options, or from the credentials "cert", "key" and "ca" of the
 * service where it has them. A build without a TLS stack refuses all of it.
 *
 * @return 0, or -EINVAL after telling what is wrong on stderr
 */
int egd_net_tls_files_resolve(struct egd_net_tls_files *files, bool plain,
			      bool tls_option_given);

void egd_net_tls_files_free(struct egd_net_tls_files *files);

/**
 * @brief Log that the traffic is in the clear - at the start of plain mode
 */
void egd_net_plain_warning(const char *daemon);

/**
 * @brief The sockets handed over by socket activation
 *
 * LISTEN_PID and LISTEN_FDS, as systemd sets them: the descriptors from 3 on,
 * if they are meant for this process. The variables are removed, so that no
 * child takes the descriptors for its own. Independent of the systemd option,
 * as the protocol is not systemd's alone - and the test suite hands sockets
 * over this way.
 *
 * @return the number of descriptors stored in @fds, at most @max
 */
int egd_net_listen_fds(int *fds, int max);

/**
 * @brief Make sure @fd is a listening stream socket - of TCP, or with @unix
 *	  of a Unix domain socket - and non-blocking
 *
 * @return 0, or a negative errno
 */
int egd_net_listener_check(int fd, bool unix_socket);

/**
 * @brief An address and port as text: "192.0.2.1:7378", "[2001:db8::1]:7378"
 */
void egd_net_addr_str(const struct sockaddr_storage *ss, char *buf, size_t len);

/**
 * @brief Map an IPv4-mapped IPv6 address to IPv4, in place
 */
void egd_net_addr_unmap(struct sockaddr_storage *ss);

/**
 * @brief The source a connection from @ss is accounted to
 *
 * The IPv4 address, or the /64 of an IPv6 address - a single host usually
 * holds a whole /64 and can connect from any address in it. An IPv4-mapped
 * address counts as the IPv4 address.
 *
 * @return the length of the key in @key, of EGD_NET_KEY_LEN bytes
 */
size_t egd_net_source_key(const struct sockaddr_storage *ss,
			  uint8_t key[EGD_NET_KEY_LEN]);

/**
 * @brief A network of the allowlist
 */
struct egd_net_cidr {
	int family;
	uint8_t addr[16];
	unsigned int prefix;
};

/**
 * @brief Parse "192.0.2.0/24", "2001:db8::/32" or a single address
 *
 * @return 0, or -EINVAL
 */
int egd_net_cidr_parse(const char *text, struct egd_net_cidr *cidr);

/**
 * @brief Is @ss in one of the @num networks of @list? Always, for none.
 */
bool egd_net_cidr_allowed(const struct egd_net_cidr *list, unsigned int num,
			  const struct sockaddr_storage *ss);

/**
 * @brief Split "host:port", "[v6]:port", ":port", or a port alone
 *
 * An empty host - or "*" - is any address.
 *
 * @return 0 with @host and @port allocated - @host NULL for any address -, or
 *	   -EINVAL
 */
int egd_net_split_listen(const char *text, char **host, char **port);

/**
 * @brief Concurrent connections, bounded per key
 *
 * Thread safe, and entries only exist while their key has connections.
 */
struct egd_net_limit_entry;

#define EGD_NET_LIMIT_BUCKETS 64

struct egd_net_limit {
	pthread_mutex_t lock;
	/* What a key stands for, for the log */
	const char *what;
	unsigned int max;
	struct egd_net_limit_entry *buckets[EGD_NET_LIMIT_BUCKETS];
};

#define EGD_NET_LIMIT_INIT(_what)                                              \
	{ .lock = PTHREAD_MUTEX_INITIALIZER, .what = _what, .max = 0 }

/**
 * @brief Account one more connection of @key
 *
 * @return true if admitted - to be released with egd_net_limit_put() -,
 *	   false if @key is at its limit, or without memory
 */
bool egd_net_limit_get(struct egd_net_limit *limit, const uint8_t *key,
		       size_t len);

void egd_net_limit_put(struct egd_net_limit *limit, const uint8_t *key,
		       size_t len);

/**
 * @brief The connections @key holds
 */
unsigned int egd_net_limit_count(struct egd_net_limit *limit,
				 const uint8_t *key, size_t len);

/**
 * @brief Parse a number of an option, 0 to @max
 *
 * @return 0, or -EINVAL after telling on stderr
 */
int egd_net_parse_uint(const char *opt, const char *arg, unsigned long max,
		       unsigned int *val);

#ifdef __cplusplus
}
#endif

#endif /* EGD_NET_COMMON_H */
