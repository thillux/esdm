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
 * The addresses of the network as the esdm-egd-net-server sees them, from
 * common/esdm_net.c: the source a connection is accounted to - an IPv6 /64 is
 * one, which the loopback interface cannot show end to end -, the allowlist,
 * the --listen syntax and the keyed bounds.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esdm_net.h"

static int failures = 0;

#define CHECK(cond, ...)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("  FAIL (line %d): ", __LINE__);                \
			printf(__VA_ARGS__);                                   \
			printf("\n");                                          \
			failures++;                                            \
		}                                                              \
	} while (0)

static struct sockaddr_storage addr_of(const char *text, uint16_t port)
{
	struct sockaddr_storage ss;

	memset(&ss, 0, sizeof(ss));
	if (strchr(text, ':')) {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&ss;

		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		inet_pton(AF_INET6, text, &in6->sin6_addr);
	} else {
		struct sockaddr_in *in4 = (struct sockaddr_in *)&ss;

		in4->sin_family = AF_INET;
		in4->sin_port = htons(port);
		inet_pton(AF_INET, text, &in4->sin_addr);
	}
	return ss;
}

static bool same_source(const char *a, const char *b)
{
	struct sockaddr_storage sa = addr_of(a, 1), sb = addr_of(b, 2);
	uint8_t ka[ESDM_NET_KEY_LEN], kb[ESDM_NET_KEY_LEN];
	size_t la = esdm_net_source_key(&sa, ka), lb = esdm_net_source_key(&sb, kb);

	return la == lb && !memcmp(ka, kb, la);
}

static void test_sources(void)
{
	printf("Sources of connections\n");

	CHECK(same_source("2001:db8::1", "2001:db8::ffff:2"),
	      "two addresses of one /64 are two sources");
	CHECK(same_source("2001:db8:0:0:1234:5678:9abc:def0", "2001:db8::"),
	      "two addresses of one /64 are two sources");
	CHECK(!same_source("2001:db8:0:1::1", "2001:db8::1"),
	      "two /64 are one source");
	CHECK(same_source("::ffff:192.0.2.1", "192.0.2.1"),
	      "an IPv4-mapped address is not its IPv4 address");
	CHECK(!same_source("192.0.2.1", "192.0.2.2"),
	      "two IPv4 addresses are one source");
	CHECK(!same_source("::ffff:192.0.2.1", "::ffff:192.0.2.2"),
	      "two IPv4-mapped addresses are one source");
	CHECK(!same_source("192.0.2.1", "::ffff:c000:201:0"),
	      "an IPv4 address and an IPv6 one are one source");
}

static bool allowed(const char *const *list, const char *addr)
{
	struct esdm_net_cidr cidr[8];
	struct sockaddr_storage ss = addr_of(addr, 7378);
	unsigned int n = 0;

	for (; *list; list++) {
		if (esdm_net_cidr_parse(*list, &cidr[n])) {
			CHECK(0, "%s does not parse", *list);
			return false;
		}
		n++;
	}
	return esdm_net_cidr_allowed(cidr, n, &ss);
}

static void test_allowlist(void)
{
	static const char *const v4[] = { "192.0.2.0/24", "198.51.100.7",
					  NULL };
	static const char *const v6[] = { "2001:db8:1::/48", "::1", NULL };
	static const char *const mapped[] = { "::ffff:10.0.0.0/104", NULL };
	static const char *const none[] = { NULL };
	static const char *const bad[] = { "192.0.2.0/33", "2001:db8::/129",
					   "host.example", "192.0.2.0/",
					   "/24", "", NULL };
	struct esdm_net_cidr cidr;
	unsigned int i;

	printf("Allowlist\n");

	CHECK(allowed(v4, "192.0.2.200"), "a host of a /24 was refused");
	CHECK(allowed(v4, "198.51.100.7"), "a single address was refused");
	CHECK(!allowed(v4, "198.51.100.8"), "a neighbor was allowed");
	CHECK(!allowed(v4, "192.0.3.1"), "the next /24 was allowed");
	CHECK(allowed(v4, "::ffff:192.0.2.9"),
	      "an IPv4-mapped address of an allowed network was refused");
	CHECK(!allowed(v4, "2001:db8::1"), "IPv6 passed an IPv4 list");

	CHECK(allowed(v6, "2001:db8:1:ffff::1"), "a host of a /48 was refused");
	CHECK(!allowed(v6, "2001:db8:2::1"), "the next /48 was allowed");
	CHECK(allowed(v6, "::1"), "::1 was refused");
	CHECK(!allowed(v6, "127.0.0.1"), "IPv4 passed an IPv6 list");

	CHECK(allowed(mapped, "10.200.0.1"),
	      "an IPv4-mapped network does not allow its IPv4 addresses");
	CHECK(allowed(none, "203.0.113.1"), "an empty list refused");

	for (i = 0; bad[i]; i++)
		CHECK(esdm_net_cidr_parse(bad[i], &cidr) == -EINVAL,
		      "\"%s\" parsed", bad[i]);
}

static void test_listen_syntax(void)
{
	static const struct {
		const char *text, *host, *port;
	} good[] = {
		{ "127.0.0.1:7378", "127.0.0.1", "7378" },
		{ "[::1]:7378", "::1", "7378" },
		{ ":7378", NULL, "7378" },
		{ "*:7378", NULL, "7378" },
		{ "7378", NULL, "7378" },
		{ "egd.example:7378", "egd.example", "7378" },
	};
	static const char *const bad[] = { "::1:7378", "[::1]", "[::1]7378",
					   "host:", "", NULL };
	char *host, *port;
	unsigned int i;

	printf("Listening addresses\n");

	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		CHECK(!esdm_net_split_listen(good[i].text, &host, &port) &&
			      ((!host && !good[i].host) ||
			       (host && good[i].host &&
				!strcmp(host, good[i].host))) &&
			      port && !strcmp(port, good[i].port),
		      "%s does not split into %s and %s", good[i].text,
		      good[i].host ? good[i].host : "any", good[i].port);
		free(host);
		free(port);
	}
	for (i = 0; bad[i]; i++) {
		CHECK(esdm_net_split_listen(bad[i], &host, &port) == -EINVAL,
		      "\"%s\" was taken", bad[i]);
	}
}

static void test_limit(void)
{
	struct esdm_net_limit limit = ESDM_NET_LIMIT_INIT("test key");
	const uint8_t a[] = { 1, 2, 3 }, b[] = { 1, 2, 4 };

	printf("Keyed bounds\n");

	limit.max = 2;
	CHECK(esdm_net_limit_get(&limit, a, sizeof(a)), "first of a refused");
	CHECK(esdm_net_limit_get(&limit, a, sizeof(a)), "second of a refused");
	CHECK(!esdm_net_limit_get(&limit, a, sizeof(a)), "third of a admitted");
	CHECK(esdm_net_limit_get(&limit, b, sizeof(b)), "b refused for a");
	CHECK(esdm_net_limit_count(&limit, a, sizeof(a)) == 2, "count of a");
	esdm_net_limit_put(&limit, a, sizeof(a));
	CHECK(esdm_net_limit_get(&limit, a, sizeof(a)),
	      "a refused after one of it went");
	esdm_net_limit_put(&limit, a, sizeof(a));
	esdm_net_limit_put(&limit, a, sizeof(a));
	esdm_net_limit_put(&limit, b, sizeof(b));
	CHECK(!esdm_net_limit_count(&limit, a, sizeof(a)) &&
		      !esdm_net_limit_count(&limit, b, sizeof(b)),
	      "the counts did not return to zero");
}

int main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);

	test_sources();
	test_allowlist();
	test_listen_syntax();
	test_limit();

	printf("EGD network addresses: %s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
