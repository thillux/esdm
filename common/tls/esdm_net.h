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
 * What the daemons of the ESDM serving the network share - the EGD protocol on
 * the network (meson option egd-net) and the external entropy sources on the
 * network (es-ext-net): the files of the TLS and how they are named, the
 * sockets handed over by socket activation, and for a server the addresses of
 * the network: the allowlist, the source a connection is accounted to, and the
 * bounds keyed by it.
 *
 * Built into the static common library only, for the daemons and the provider
 * server of libesdm_es_ext.
 */

#ifndef ESDM_NET_H
#define ESDM_NET_H

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
#define ESDM_NET_MAX_LISTEN 16
#define ESDM_NET_MAX_ALLOW 64

/* Room for an address and port as text, see esdm_net_addr_str() */
#define ESDM_NET_ADDR_STR_LEN 64

/* Longest key of struct esdm_net_limit: a fingerprint and its kind */
#define ESDM_NET_KEY_LEN (1 + ESDM_TLS_FINGERPRINT_LEN)

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
char *esdm_net_file(const char *name);

/**
 * @brief The files of the TLS of a daemon, as given on the command line
 */
struct esdm_net_tls_files {
	char *cert;
	char *key;
	/* The files of trust anchors, NULL-terminated, see esdm_tls.h */
	char *ca[ESDM_TLS_MAX_CA_FILES + 1];
	unsigned int ca_num;
	char *crl[ESDM_TLS_MAX_CRL_FILES];
	unsigned int crl_num;
	bool crl_check_all;
	bool crl_allow_expired;
};

/**
 * @brief The configuration of the TLS layer for the files - everything else
 *	  of it zero, its defaults
 */
void esdm_net_tls_config(const struct esdm_net_tls_files *files,
			 struct esdm_tls_config *cfg);

/**
 * @brief Take up one of the TLS options a daemon shares, by its name
 *
 * The options of struct esdm_net_tls_files: "cert", "key", "ca" and "crl" -
 * the latter two may be repeated -, "crl_check_all" and "crl_allow_expired" -
 * which take no @arg.
 *
 * @return 1 if @opt is one of them and was taken, 0 if it is none, -EINVAL
 *	   after telling on stderr what is wrong, -ENOMEM
 */
int esdm_net_tls_option(struct esdm_net_tls_files *files, const char *opt,
			const char *arg);

/**
 * @brief Resolve the TLS files of a daemon
 *
 * The certificate, its key and the trust anchors are required - from the
 * options, or from the credentials "cert", "key" and "ca" of the service where
 * it has them. A file named without a slash is a credential, see
 * esdm_net_file(). @hint is added to the message telling that a file is
 * missing, NULL for none.
 *
 * Several files of trust anchors are given with "ca" repeated - for the
 * rollover of a CA, see esdm_tls.h; the credential "ca" may hold several
 * trust anchors as well.
 *
 * @return 0, or -EINVAL after telling what is wrong on stderr
 */
int esdm_net_tls_files_resolve(struct esdm_net_tls_files *files,
			       const char *hint);

void esdm_net_tls_files_free(struct esdm_net_tls_files *files);

/**
 * @brief Take up the TLS files anew, if they changed
 *
 * Builds a complete new context of the files of @cfg - unless @force is false
 * and their stamp equals @stamp, see esdm_tls_stamp() - and stores the stamp
 * of the files it tried in @stamp, so that a rotation that does not load is
 * not tried again until the files change once more. What does not load is
 * logged, prefixed with @who.
 *
 * @return 1 with the new context in *@ctx, which the caller puts in place of
 *	   its old one - and checks its connections against, see
 *	   esdm_tls_peer_revoked(); 0 if the files did not change; a negative
 *	   errno if they do not load - the caller keeps its old context then
 */
int esdm_net_tls_reload(const char *who, bool server,
			const struct esdm_tls_config *cfg, bool force,
			uint8_t stamp[ESDM_TLS_STAMP_LEN],
			struct esdm_tls_ctx **ctx);

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
int esdm_net_listen_fds(int *fds, int max);

/* What esdm_net_listener_check() expects a listening socket to be */
enum esdm_net_listener {
	/* A Unix domain stream socket */
	ESDM_NET_LISTENER_UNIX,
	/* A TCP socket of IPv4 or IPv6 */
	ESDM_NET_LISTENER_TCP,
};

/**
 * @brief Make sure @fd is a listening socket of @kind, and non-blocking
 *
 * @return 0, or a negative errno
 */
int esdm_net_listener_check(int fd, enum esdm_net_listener kind);

/**
 * @brief Bind and listen on TCP "[HOST]:PORT", one socket per address it
 *	  resolves to
 *
 * The wildcard of IPv6 is bound for IPv6 only, as the one of IPv4 is bound as
 * well.
 *
 * @return 0 with the sockets stored from @fds[*@num] on and *@num advanced,
 *	   at most to @max, or a negative errno after telling on stderr
 */
int esdm_net_listen(const char *text, int backlog, int *fds, int *num, int max);

/**
 * @brief An address and port as text: "192.0.2.1:7378", "[2001:db8::1]:7378"
 */
void esdm_net_addr_str(const struct sockaddr_storage *ss, char *buf,
		       size_t len);

/**
 * @brief Map an IPv4-mapped IPv6 address to IPv4, in place
 */
void esdm_net_addr_unmap(struct sockaddr_storage *ss);

/**
 * @brief The source a connection from @ss is accounted to
 *
 * The IPv4 address, or the /64 of an IPv6 address - a single host usually
 * holds a whole /64 and can connect from any address in it. An IPv4-mapped
 * address counts as the IPv4 address.
 *
 * @return the length of the key in @key, of ESDM_NET_KEY_LEN bytes
 */
size_t esdm_net_source_key(const struct sockaddr_storage *ss,
			   uint8_t key[ESDM_NET_KEY_LEN]);

/**
 * @brief A network of the allowlist
 */
struct esdm_net_cidr {
	int family;
	uint8_t addr[16];
	unsigned int prefix;
};

/**
 * @brief Parse "192.0.2.0/24", "2001:db8::/32" or a single address
 *
 * @return 0, or -EINVAL
 */
int esdm_net_cidr_parse(const char *text, struct esdm_net_cidr *cidr);

/**
 * @brief Is @ss in one of the @num networks of @list? Always, for none.
 */
bool esdm_net_cidr_allowed(const struct esdm_net_cidr *list, unsigned int num,
			   const struct sockaddr_storage *ss);

/**
 * @brief Split "host:port", "[v6]:port", ":port", or a port alone
 *
 * An empty host - or "*" - is any address.
 *
 * @return 0 with @host and @port allocated - @host NULL for any address -, or
 *	   -EINVAL
 */
int esdm_net_split_listen(const char *text, char **host, char **port);

/**
 * @brief Split "host:port", "[v6]:port", "host", "[v6]" or an IPv6 address
 *	  alone - the server a client connects to
 *
 * @return 0 with @host and @port allocated - @port NULL without one -, or
 *	   -EINVAL
 */
int esdm_net_split_connect(const char *text, char **host, char **port);

/**
 * @brief Concurrent connections, bounded per key
 *
 * Thread safe, and entries only exist while their key has connections.
 */
struct esdm_net_limit_entry;

#define ESDM_NET_LIMIT_BUCKETS 64

struct esdm_net_limit {
	pthread_mutex_t lock;
	/* What a key stands for, for the log */
	const char *what;
	unsigned int max;
	struct esdm_net_limit_entry *buckets[ESDM_NET_LIMIT_BUCKETS];
};

#define ESDM_NET_LIMIT_INIT(_what)                                             \
	{ .lock = PTHREAD_MUTEX_INITIALIZER, .what = _what, .max = 0 }

/**
 * @brief Account one more connection of @key
 *
 * @return true if admitted - to be released with esdm_net_limit_put() -,
 *	   false if @key is at its limit, or without memory
 */
bool esdm_net_limit_get(struct esdm_net_limit *limit, const uint8_t *key,
			size_t len);

void esdm_net_limit_put(struct esdm_net_limit *limit, const uint8_t *key,
			size_t len);

/**
 * @brief The connections @key holds
 */
unsigned int esdm_net_limit_count(struct esdm_net_limit *limit,
				  const uint8_t *key, size_t len);

/**
 * @brief Release every entry of @limit - at the end of its user only
 */
void esdm_net_limit_clear(struct esdm_net_limit *limit);

/**
 * @brief Parse a number of an option, 0 to @max
 *
 * @return 0, or -EINVAL after telling on stderr
 */
int esdm_net_parse_uint(const char *opt, const char *arg, unsigned long max,
			unsigned int *val);

#ifdef __cplusplus
}
#endif

#endif /* ESDM_NET_H */
