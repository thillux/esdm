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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "esdm_logger.h"
#include "esdm_net.h"

char *esdm_net_file(const char *name)
{
	const char *dir;
	char *path;

	if (!name)
		return NULL;
	if (strchr(name, '/'))
		return strdup(name);

	dir = getenv("CREDENTIALS_DIRECTORY");
	if (!dir || !*dir)
		return NULL;
	if (asprintf(&path, "%s/%s", dir, name) < 0)
		return NULL;
	return path;
}

void esdm_net_tls_config(const struct esdm_net_tls_files *files,
			 struct esdm_tls_config *cfg)
{
	unsigned int i;

	memset(cfg, 0, sizeof(*cfg));
	cfg->cert_file = files->cert;
	cfg->key_file = files->key;
	for (i = 0; i < files->ca_num; i++)
		cfg->ca_files[i] = files->ca[i];
	cfg->ca_files_num = files->ca_num;
	for (i = 0; i < files->crl_num; i++)
		cfg->crl_files[i] = files->crl[i];
	cfg->crl_files_num = files->crl_num;
	cfg->crl_check_all = files->crl_check_all;
	cfg->crl_allow_expired = files->crl_allow_expired;
}

static int esdm_net_set_file(char **file, const char *arg)
{
	free(*file);
	*file = strdup(arg);
	return *file ? 1 : -ENOMEM;
}

int esdm_net_tls_option(struct esdm_net_tls_files *files, const char *opt,
			const char *arg)
{
	if (!strcmp(opt, "cert"))
		return esdm_net_set_file(&files->cert, arg);
	if (!strcmp(opt, "key"))
		return esdm_net_set_file(&files->key, arg);
	if (!strcmp(opt, "ca")) {
		if (files->ca_num >= ESDM_TLS_MAX_CA_FILES) {
			fprintf(stderr, "--ca may be given %u times at most\n",
				ESDM_TLS_MAX_CA_FILES);
			return -EINVAL;
		}
		files->ca[files->ca_num] = strdup(arg);
		if (!files->ca[files->ca_num])
			return -ENOMEM;
		files->ca_num++;
		return 1;
	}

	if (!strcmp(opt, "crl")) {
		if (files->crl_num >= ESDM_TLS_MAX_CRL_FILES) {
			fprintf(stderr, "--crl may be given %u times at most\n",
				ESDM_TLS_MAX_CRL_FILES);
			return -EINVAL;
		}
		files->crl[files->crl_num] = strdup(arg);
		if (!files->crl[files->crl_num])
			return -ENOMEM;
		files->crl_num++;
		return 1;
	}

	if (!strcmp(opt, "crl_check_all")) {
		files->crl_check_all = true;
		return 1;
	}
	if (!strcmp(opt, "crl_allow_expired")) {
		files->crl_allow_expired = true;
		return 1;
	}

	return 0;
}

/* A file of an option, or the credential @fallback of the service */
static int esdm_net_resolve_one(char **file, const char *opt,
				const char *fallback, const char *hint)
{
	const char *name = *file;
	char *path;

	if (!name) {
		if (!getenv("CREDENTIALS_DIRECTORY")) {
			fprintf(stderr,
				"--%s is required for TLS - or the credential \"%s\" of the service%s%s\n",
				opt, fallback, hint ? ", or " : "",
				hint ? hint : "");
			return -EINVAL;
		}
		name = fallback;
	}

	path = esdm_net_file(name);
	if (!path) {
		fprintf(stderr,
			"--%s %s names a credential, but $CREDENTIALS_DIRECTORY is not set\n",
			opt, name);
		return -EINVAL;
	}

	free(*file);
	*file = path;
	return 0;
}

int esdm_net_tls_files_resolve(struct esdm_net_tls_files *files,
			       const char *hint)
{
	unsigned int i;
	int ret;

	ret = esdm_net_resolve_one(&files->cert, "cert", "cert", hint);
	if (!ret)
		ret = esdm_net_resolve_one(&files->key, "key", "key", hint);
	/* No --ca: the credential, else every one given */
	if (!ret && !files->ca_num) {
		ret = esdm_net_resolve_one(&files->ca[0], "ca", "ca", hint);
		if (!ret)
			files->ca_num = 1;
	}
	for (i = 0; !ret && i < files->ca_num; i++)
		ret = esdm_net_resolve_one(&files->ca[i], "ca", "ca", hint);
	if (ret)
		return ret;

	for (i = 0; i < files->crl_num; i++) {
		char *path = esdm_net_file(files->crl[i]);

		if (!path) {
			fprintf(stderr,
				"--crl %s names a credential, but $CREDENTIALS_DIRECTORY is not set\n",
				files->crl[i]);
			return -EINVAL;
		}
		free(files->crl[i]);
		files->crl[i] = path;
	}

	return 0;
}

void esdm_net_tls_files_free(struct esdm_net_tls_files *files)
{
	unsigned int i;

	free(files->cert);
	free(files->key);
	for (i = 0; i < files->ca_num; i++)
		free(files->ca[i]);
	for (i = 0; i < files->crl_num; i++)
		free(files->crl[i]);
	memset(files, 0, sizeof(*files));
}

int esdm_net_tls_reload(const char *who, bool server,
			const struct esdm_tls_config *cfg, bool force,
			uint8_t stamp[ESDM_TLS_STAMP_LEN],
			struct esdm_tls_ctx **ctx)
{
	uint8_t now[ESDM_TLS_STAMP_LEN];
	int ret;

	*ctx = NULL;

	esdm_tls_stamp(cfg, now);
	if (!force && !memcmp(now, stamp, ESDM_TLS_STAMP_LEN))
		return 0;
	/* Not again for these files, whether they load or not */
	memcpy(stamp, now, ESDM_TLS_STAMP_LEN);

	ret = esdm_tls_ctx_alloc(server, cfg, ctx);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"%s: the TLS files do not load (%s) - keeping the ones loaded before\n",
			who, strerror(-ret));
		return ret;
	}

	return 1;
}

int esdm_net_listen_fds(int *fds, int max)
{
	const char *pid_env = getenv("LISTEN_PID");
	const char *fds_env = getenv("LISTEN_FDS");
	unsigned long pid, num;
	char *end;
	int i, n = 0;

	if (!fds_env)
		return 0;

	/* Meant for another process, and inherited by this one */
	if (pid_env) {
		errno = 0;
		pid = strtoul(pid_env, &end, 10);
		if (errno || *end || pid != (unsigned long)getpid())
			goto out;
	}

	errno = 0;
	num = strtoul(fds_env, &end, 10);
	if (errno || *end || !num)
		goto out;

	for (i = 0; i < (int)num && n < max; i++) {
		int fd = 3 + i;

		/* Not inherited by what this daemon executes */
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		fds[n++] = fd;
	}

out:
	unsetenv("LISTEN_PID");
	unsetenv("LISTEN_FDS");
	unsetenv("LISTEN_FDNAMES");
	return n;
}

int esdm_net_listener_check(int fd, enum esdm_net_listener kind)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(int), sslen = sizeof(ss);
	int type = 0, listening = 0, protocol = 0, flags;

	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) < 0 ||
	    type != SOCK_STREAM)
		return -ENOTSOCK;

	len = sizeof(int);
	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) < 0 ||
	    !listening)
		return -EINVAL;

	if (getsockname(fd, (struct sockaddr *)&ss, &sslen) < 0)
		return -errno;
	if (kind == ESDM_NET_LISTENER_UNIX ?
		    ss.ss_family != AF_UNIX :
		    (ss.ss_family != AF_INET && ss.ss_family != AF_INET6))
		return -EAFNOSUPPORT;

	if (kind != ESDM_NET_LISTENER_UNIX) {
		len = sizeof(int);
		if (getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &len) <
			    0 ||
		    protocol != IPPROTO_TCP)
			return -EPROTONOSUPPORT;
	}

	/* Accepting must not block when a client gave up meanwhile */
	flags = fcntl(fd, F_GETFL);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
		return -errno;

	return 0;
}

int esdm_net_listen(const char *text, int backlog, int *fds, int *num, int max)
{
	struct addrinfo hints, *res = NULL, *ai;
	char *host = NULL, *port = NULL;
	int ret, fd, one = 1, bound = 0;

	ret = esdm_net_split_listen(text, &host, &port);
	if (ret) {
		fprintf(stderr, "--listen %s does not parse\n", text);
		return ret;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(host, port, &hints, &res);
	if (ret) {
		fprintf(stderr, "--listen %s: %s\n", text, gai_strerror(ret));
		ret = -EINVAL;
		goto out;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (*num >= max) {
			fprintf(stderr, "Too many listening sockets\n");
			ret = -EINVAL;
			goto out;
		}

		fd = socket(ai->ai_family,
			    ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
			    IPPROTO_TCP);
		if (fd < 0) {
			ret = -errno;
			if (ret == -EPROTONOSUPPORT ||
			    ret == -ESOCKTNOSUPPORT) {
				fprintf(stderr, "--listen %s: %s\n", text,
					strerror(-ret));
				goto out;
			}
			continue;
		}
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
		/* The wildcard of IPv6 for IPv6 only, IPv4 has its own */
		if (ai->ai_family == AF_INET6)
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
				   sizeof(one));

		if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0 ||
		    listen(fd, backlog) < 0) {
			ret = -errno;
			fprintf(stderr, "--listen %s: %s\n", text,
				strerror(errno));
			close(fd);
			goto out;
		}

		fds[(*num)++] = fd;
		bound++;
	}

	ret = bound ? 0 : (ret ? ret : -EADDRNOTAVAIL);

out:
	if (res)
		freeaddrinfo(res);
	free(host);
	free(port);
	return ret;
}

void esdm_net_addr_unmap(struct sockaddr_storage *ss)
{
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in in4;

	if (ss->ss_family != AF_INET6 || !IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr))
		return;

	memset(&in4, 0, sizeof(in4));
	in4.sin_family = AF_INET;
	in4.sin_port = in6->sin6_port;
	memcpy(&in4.sin_addr, in6->sin6_addr.s6_addr + 12, 4);
	memset(ss, 0, sizeof(*ss));
	memcpy(ss, &in4, sizeof(in4));
}

void esdm_net_addr_str(const struct sockaddr_storage *ss, char *buf,
		       size_t len)
{
	char host[INET6_ADDRSTRLEN];

	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *in4 = (const struct sockaddr_in *)ss;

		inet_ntop(AF_INET, &in4->sin_addr, host, sizeof(host));
		snprintf(buf, len, "%s:%u", host, ntohs(in4->sin_port));
	} else if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)ss;

		inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
		snprintf(buf, len, "[%s]:%u", host, ntohs(in6->sin6_port));
	} else {
		snprintf(buf, len, "unknown");
	}
}

size_t esdm_net_source_key(const struct sockaddr_storage *ss,
			   uint8_t key[ESDM_NET_KEY_LEN])
{
	struct sockaddr_storage copy = *ss;

	esdm_net_addr_unmap(&copy);
	memset(key, 0, ESDM_NET_KEY_LEN);

	if (copy.ss_family == AF_INET) {
		const struct sockaddr_in *in4 =
			(const struct sockaddr_in *)&copy;

		key[0] = 4;
		memcpy(key + 1, &in4->sin_addr, 4);
		return 5;
	}

	if (copy.ss_family == AF_INET6) {
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)&copy;

		/* The /64 of the address */
		key[0] = 6;
		memcpy(key + 1, in6->sin6_addr.s6_addr, 8);
		return 9;
	}

	key[0] = 0;
	return 1;
}

int esdm_net_cidr_parse(const char *text, struct esdm_net_cidr *cidr)
{
	char buf[INET6_ADDRSTRLEN + 8];
	const char *slash = strchr(text, '/');
	unsigned long prefix;
	char *end;
	size_t len = slash ? (size_t)(slash - text) : strlen(text);
	unsigned int i, max;

	memset(cidr, 0, sizeof(*cidr));
	if (!len || len >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, text, len);
	buf[len] = '\0';

	if (inet_pton(AF_INET, buf, cidr->addr) == 1) {
		cidr->family = AF_INET;
		max = 32;
	} else if (inet_pton(AF_INET6, buf, cidr->addr) == 1) {
		cidr->family = AF_INET6;
		max = 128;
	} else {
		return -EINVAL;
	}

	if (slash) {
		errno = 0;
		prefix = strtoul(slash + 1, &end, 10);
		if (errno || end == slash + 1 || *end || prefix > max)
			return -EINVAL;
		cidr->prefix = (unsigned int)prefix;
	} else {
		cidr->prefix = max;
	}

	/* An IPv4-mapped network is the IPv4 network */
	if (cidr->family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED((struct in6_addr *)cidr->addr) &&
	    cidr->prefix >= 96) {
		memmove(cidr->addr, cidr->addr + 12, 4);
		memset(cidr->addr + 4, 0, 12);
		cidr->family = AF_INET;
		cidr->prefix -= 96;
	}

	/* The host bits do not count */
	for (i = cidr->prefix; i < max; i++)
		cidr->addr[i / 8] &= (uint8_t)~(0x80u >> (i % 8));

	return 0;
}

static bool esdm_net_cidr_match(const struct esdm_net_cidr *cidr,
				const uint8_t *addr)
{
	unsigned int full = cidr->prefix / 8, rest = cidr->prefix % 8;
	uint8_t mask;

	if (memcmp(cidr->addr, addr, full))
		return false;
	if (!rest)
		return true;

	mask = (uint8_t)(0xffu << (8 - rest));
	return (cidr->addr[full] & mask) == (addr[full] & mask);
}

bool esdm_net_cidr_allowed(const struct esdm_net_cidr *list, unsigned int num,
			   const struct sockaddr_storage *ss)
{
	struct sockaddr_storage copy = *ss;
	const uint8_t *addr;
	unsigned int i;

	if (!num)
		return true;

	esdm_net_addr_unmap(&copy);
	if (copy.ss_family == AF_INET)
		addr = (const uint8_t *)&((struct sockaddr_in *)&copy)
			       ->sin_addr;
	else if (copy.ss_family == AF_INET6)
		addr = ((struct sockaddr_in6 *)&copy)->sin6_addr.s6_addr;
	else
		return false;

	for (i = 0; i < num; i++) {
		if (list[i].family == copy.ss_family &&
		    esdm_net_cidr_match(&list[i], addr))
			return true;
	}

	return false;
}

int esdm_net_split_listen(const char *text, char **host, char **port)
{
	const char *p, *h = text;
	size_t hlen;

	*host = *port = NULL;

	if (text[0] == '[') {
		const char *close = strchr(text, ']');

		if (!close || close[1] != ':' || !close[2])
			return -EINVAL;
		h = text + 1;
		hlen = (size_t)(close - h);
		p = close + 2;
	} else {
		p = strrchr(text, ':');
		if (!p) {
			/* A port alone */
			hlen = 0;
			p = text;
		} else {
			/* More than one colon is an IPv6 address: brackets */
			if (memchr(text, ':', (size_t)(p - text)))
				return -EINVAL;
			hlen = (size_t)(p - text);
			p++;
		}
	}

	if (!*p)
		return -EINVAL;
	if (hlen == 1 && h[0] == '*')
		hlen = 0;

	if (hlen) {
		*host = strndup(h, hlen);
		if (!*host)
			return -ENOMEM;
	}
	*port = strdup(p);
	if (!*port) {
		free(*host);
		*host = NULL;
		return -ENOMEM;
	}

	return 0;
}

int esdm_net_split_connect(const char *text, char **host, char **port)
{
	const char *h = text, *p = NULL, *colon;
	size_t hlen;

	*host = *port = NULL;

	if (text[0] == '[') {
		const char *close = strchr(text, ']');

		if (!close || (close[1] && (close[1] != ':' || !close[2])))
			return -EINVAL;
		h = text + 1;
		hlen = (size_t)(close - h);
		if (close[1])
			p = close + 2;
	} else {
		colon = strchr(text, ':');
		if (colon && strchr(colon + 1, ':')) {
			/* An IPv6 address without brackets, and no port */
			hlen = strlen(text);
		} else if (colon) {
			hlen = (size_t)(colon - text);
			p = colon + 1;
			if (!*p)
				return -EINVAL;
		} else {
			hlen = strlen(text);
		}
	}

	if (!hlen)
		return -EINVAL;

	*host = strndup(h, hlen);
	if (!*host)
		return -ENOMEM;
	if (p) {
		*port = strdup(p);
		if (!*port) {
			free(*host);
			*host = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

struct esdm_net_limit_entry {
	struct esdm_net_limit_entry *next;
	uint8_t key[ESDM_NET_KEY_LEN];
	size_t len;
	unsigned int count;
	/* The limit was reported for this key already */
	bool warned;
};

static unsigned int esdm_net_limit_hash(const uint8_t *key, size_t len)
{
	/* FNV-1a: the keys are no secret, and short */
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < len; i++) {
		h ^= key[i];
		h *= 16777619u;
	}
	return h % ESDM_NET_LIMIT_BUCKETS;
}

static struct esdm_net_limit_entry **
esdm_net_limit_slot(struct esdm_net_limit *limit, const uint8_t *key,
		    size_t len)
{
	struct esdm_net_limit_entry **slot =
		&limit->buckets[esdm_net_limit_hash(key, len)];

	while (*slot &&
	       ((*slot)->len != len || memcmp((*slot)->key, key, len)))
		slot = &(*slot)->next;

	return slot;
}

bool esdm_net_limit_get(struct esdm_net_limit *limit, const uint8_t *key,
			size_t len)
{
	struct esdm_net_limit_entry **slot, *entry;
	bool admitted = false;

	if (len > ESDM_NET_KEY_LEN)
		return false;

	pthread_mutex_lock(&limit->lock);

	slot = esdm_net_limit_slot(limit, key, len);
	entry = *slot;
	if (!entry) {
		entry = calloc(1, sizeof(*entry));
		if (!entry)
			goto out;
		memcpy(entry->key, key, len);
		entry->len = len;
		*slot = entry;
	}

	if (entry->count >= limit->max) {
		/* Once per episode - a client at its limit retries a lot */
		if (!entry->warned) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ANY,
				"A %s reached its limit of %u connections, refusing further ones\n",
				limit->what, limit->max);
			entry->warned = true;
		}
		/* An entry without connections is not kept */
		if (!entry->count) {
			*slot = entry->next;
			free(entry);
		}
		goto out;
	}

	entry->count++;
	admitted = true;

out:
	pthread_mutex_unlock(&limit->lock);
	return admitted;
}

void esdm_net_limit_put(struct esdm_net_limit *limit, const uint8_t *key,
			size_t len)
{
	struct esdm_net_limit_entry **slot, *entry;

	pthread_mutex_lock(&limit->lock);

	slot = esdm_net_limit_slot(limit, key, len);
	entry = *slot;
	if (entry && entry->count) {
		entry->count--;
		if (!entry->count) {
			*slot = entry->next;
			free(entry);
		} else if (entry->count < limit->max) {
			entry->warned = false;
		}
	}

	pthread_mutex_unlock(&limit->lock);
}

unsigned int esdm_net_limit_count(struct esdm_net_limit *limit,
				  const uint8_t *key, size_t len)
{
	struct esdm_net_limit_entry *entry;
	unsigned int count;

	pthread_mutex_lock(&limit->lock);
	entry = *esdm_net_limit_slot(limit, key, len);
	count = entry ? entry->count : 0;
	pthread_mutex_unlock(&limit->lock);

	return count;
}

void esdm_net_limit_clear(struct esdm_net_limit *limit)
{
	unsigned int i;

	pthread_mutex_lock(&limit->lock);
	for (i = 0; i < ESDM_NET_LIMIT_BUCKETS; i++) {
		while (limit->buckets[i]) {
			struct esdm_net_limit_entry *entry = limit->buckets[i];

			limit->buckets[i] = entry->next;
			free(entry);
		}
	}
	pthread_mutex_unlock(&limit->lock);
}

int esdm_net_parse_uint(const char *opt, const char *arg, unsigned long max,
			unsigned int *val)
{
	unsigned long v;
	char *end;

	errno = 0;
	v = strtoul(arg, &end, 10);
	if (errno || end == arg || *end || arg[0] == '-' || v > max ||
	    v > UINT_MAX) {
		fprintf(stderr, "--%s takes a number from 0 to %lu, not \"%s\"\n",
			opt, max, arg);
		return -EINVAL;
	}

	*val = (unsigned int)v;
	return 0;
}
