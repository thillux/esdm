/*
 * The handshake of TLS and DTLS as the wire carries it, for the tests
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

/*
 * A test moving the records between the two ends of a connection reads them
 * with this: what passes in the clear - the handshake of DTLS 1.2 up to the
 * ChangeCipherSpec, the ClientHello and the ServerHello of TLS 1.3 -, the
 * suites, the groups, the signature algorithms, the key shares and the
 * extensions of the hellos, the suite and the group the server takes, and
 * which handshake messages pass. Every record is
 * counted, encrypted or not: what a peer sends after a point - a
 * NewSessionTicket of TLS 1.3, encrypted - shows as records.
 *
 * One struct test_tls_wire per direction of a connection. DTLS hands it a
 * message of the socket at a time, which holds whole records
 * (test_tls_wire_records()); TLS on a stream socket hands it the bytes as they
 * come, cut anywhere (test_tls_wire_stream()).
 *
 * Shared by tests/common/esdm_dtls_test.c, the local DTLS, and
 * tests/egd-net/tls_test.c, the TLS with certificates.
 */

#ifndef TEST_TLS_WIRE_H
#define TEST_TLS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The handshake messages looked at */
#define TEST_TLS_HS_CLIENT_HELLO 1
#define TEST_TLS_HS_SERVER_HELLO 2
#define TEST_TLS_HS_NEW_SESSION_TICKET 4
#define TEST_TLS_HS_CERTIFICATE 11
#define TEST_TLS_HS_SERVER_KEY_EXCHANGE 12
#define TEST_TLS_HS_SERVER_HELLO_DONE 14

/* The extensions looked at */
#define TEST_TLS_EXT_GROUPS 10
#define TEST_TLS_EXT_SIGALGS 13
#define TEST_TLS_EXT_HEARTBEAT 15
#define TEST_TLS_EXT_ETM 22
#define TEST_TLS_EXT_EMS 23
#define TEST_TLS_EXT_SESSION_TICKET 35
#define TEST_TLS_EXT_PRE_SHARED_KEY 41
#define TEST_TLS_EXT_EARLY_DATA 42
#define TEST_TLS_EXT_SUPPORTED_VERSIONS 43
#define TEST_TLS_EXT_POST_HANDSHAKE_AUTH 49
#define TEST_TLS_EXT_KEY_SHARE 51

/* TLS_EMPTY_RENEGOTIATION_INFO_SCSV, no suite */
#define TEST_TLS_SCSV 0x00ff

/* The content types of a record */
#define TEST_TLS_CT_CCS 20
#define TEST_TLS_CT_HANDSHAKE 22

/* Longest record, header included, with room for the expansion of DTLS */
#define TEST_TLS_MAX_RECORD (16384 + 2048 + 13)

struct test_tls_wire {
	/* DTLS records and handshake headers, else TLS ones */
	bool dtls;

	/* Of the ClientHello: the suites, groups and signatures it offers */
	uint16_t suites[16];
	unsigned int nsuites;
	uint16_t groups[16];
	unsigned int ngroups;
	uint16_t sigalgs[64];
	unsigned int nsigalgs;

	/*
	 * Of TLS 1.3: the groups of the key shares of the ClientHello, the one
	 * of a ServerHello - the share it takes, or the group a
	 * HelloRetryRequest asks for
	 */
	uint16_t shares[8];
	unsigned int nshares;

	/* Of the ServerHello and the ServerKeyExchange, 0 without */
	uint16_t suite;
	uint16_t group;

	/* Of either hello: the length of its session ID, and its extensions */
	unsigned int session_id_len;
	uint16_t exts[64];
	uint16_t ext_lens[64];
	unsigned int nexts;
	/* Encrypt-then-MAC among them */
	bool etm;

	/* The handshake messages in the clear, a bit per type */
	uint32_t hs_types;
	bool certificate;

	/* The records, encrypted or not, and the ChangeCipherSpecs of them */
	unsigned int records;
	unsigned int ccs;

	bool malformed;

	/* TLS on a stream: a record not yet complete */
	uint8_t partial[TEST_TLS_MAX_RECORD];
	size_t partial_len;
};

struct test_tls_reader {
	const uint8_t *p;
	size_t len, off;
	bool bad;
};

/* A big-endian number of @n bytes, 0 and bad past the end */
static inline uint32_t test_tls_get(struct test_tls_reader *r, size_t n)
{
	uint32_t v = 0;

	if (r->bad || n > r->len - r->off) {
		r->bad = true;
		return 0;
	}
	while (n--)
		v = (v << 8) | r->p[r->off++];
	return v;
}

static inline void test_tls_skip(struct test_tls_reader *r, size_t n)
{
	if (r->bad || n > r->len - r->off)
		r->bad = true;
	else
		r->off += n;
}

/* Is the extension @type among those of the hello read into @w? */
static inline bool test_tls_has_ext(const struct test_tls_wire *w,
				    uint16_t type)
{
	unsigned int i;

	for (i = 0; i < w->nexts; i++) {
		if (w->exts[i] == type)
			return true;
	}
	return false;
}

/* The length of the extension @type of the hello, -1 without it */
static inline int test_tls_ext_len(const struct test_tls_wire *w, uint16_t type)
{
	unsigned int i;

	for (i = 0; i < w->nexts; i++) {
		if (w->exts[i] == type)
			return w->ext_lens[i];
	}
	return -1;
}

/* Did a handshake message of @type pass in the clear? */
static inline bool test_tls_has_hs(const struct test_tls_wire *w, uint8_t type)
{
	return type < 32 && (w->hs_types & (1U << type));
}

/* A list of 16-bit values, all of an extension after its length of @n bytes */
static inline void test_tls_wire_list(struct test_tls_reader *ext, size_t n,
				      uint16_t *list, unsigned int *num,
				      unsigned int max, struct test_tls_wire *w)
{
	if (test_tls_get(ext, n) + n != ext->len || (ext->len - n) % 2) {
		w->malformed = true;
		return;
	}
	while (ext->off < ext->len && *num < max)
		list[(*num)++] = (uint16_t)test_tls_get(ext, 2);
}

/* The key shares of the ClientHello: group, length, key each */
static inline void test_tls_wire_shares(struct test_tls_reader *ext,
					struct test_tls_wire *w)
{
	if (test_tls_get(ext, 2) + 2 != ext->len) {
		w->malformed = true;
		return;
	}
	while (!ext->bad && ext->off < ext->len) {
		uint16_t group = (uint16_t)test_tls_get(ext, 2);

		test_tls_skip(ext, test_tls_get(ext, 2));
		if (w->nshares < sizeof(w->shares) / sizeof(w->shares[0]))
			w->shares[w->nshares++] = group;
	}
	w->malformed |= ext->bad;
}

/* The extensions of a hello, the rest of @r - of a ServerHello if @server */
static inline void test_tls_wire_exts(struct test_tls_reader *r,
				      struct test_tls_wire *w, bool server)
{
	struct test_tls_reader exts = { .p = r->p + r->off };

	/* A hello without any */
	if (r->off == r->len)
		return;
	exts.len = test_tls_get(r, 2);
	test_tls_skip(r, exts.len);
	if (r->bad)
		return;
	exts.p += 2;

	while (!exts.bad && exts.off < exts.len) {
		uint32_t type = test_tls_get(&exts, 2);
		struct test_tls_reader ext = { .len = test_tls_get(&exts, 2) };

		ext.p = exts.p + exts.off;
		test_tls_skip(&exts, ext.len);
		if (exts.bad)
			break;

		if (w->nexts < sizeof(w->exts) / sizeof(w->exts[0])) {
			w->ext_lens[w->nexts] = (uint16_t)ext.len;
			w->exts[w->nexts++] = (uint16_t)type;
		}
		switch (type) {
		case TEST_TLS_EXT_ETM:
			w->etm = true;
			break;
		case TEST_TLS_EXT_GROUPS:
			test_tls_wire_list(
				&ext, 2, w->groups, &w->ngroups,
				sizeof(w->groups) / sizeof(w->groups[0]), w);
			break;
		case TEST_TLS_EXT_SIGALGS:
			test_tls_wire_list(
				&ext, 2, w->sigalgs, &w->nsigalgs,
				sizeof(w->sigalgs) / sizeof(w->sigalgs[0]), w);
			break;
		case TEST_TLS_EXT_KEY_SHARE:
			/* Of a ServerHello and a HelloRetryRequest: a group */
			if (!server)
				test_tls_wire_shares(&ext, w);
			else if (ext.len >= 2 &&
				 w->nshares < sizeof(w->shares) /
						      sizeof(w->shares[0]))
				w->shares[w->nshares++] =
					(uint16_t)test_tls_get(&ext, 2);
			break;
		default:
			break;
		}
	}
	w->malformed |= exts.bad;
}

/* A handshake message of @type, its body in @r */
static inline void test_tls_wire_hs(uint8_t type, struct test_tls_reader *r,
				    struct test_tls_wire *w)
{
	uint32_t n;

	if (type < 32)
		w->hs_types |= 1U << type;

	switch (type) {
	case TEST_TLS_HS_CLIENT_HELLO:
		/* version, random, session ID, the cookie of DTLS */
		test_tls_skip(r, 34);
		w->session_id_len = test_tls_get(r, 1);
		test_tls_skip(r, w->session_id_len);
		if (w->dtls)
			test_tls_skip(r, test_tls_get(r, 1));
		n = test_tls_get(r, 2);
		if (n % 2)
			r->bad = true;
		for (; n >= 2 && !r->bad; n -= 2) {
			uint16_t suite = (uint16_t)test_tls_get(r, 2);

			if (suite != TEST_TLS_SCSV &&
			    w->nsuites <
				    sizeof(w->suites) / sizeof(w->suites[0]))
				w->suites[w->nsuites++] = suite;
		}
		test_tls_skip(r, test_tls_get(r, 1));
		test_tls_wire_exts(r, w, false);
		break;
	case TEST_TLS_HS_SERVER_HELLO:
		/* version, random, session ID */
		test_tls_skip(r, 34);
		w->session_id_len = test_tls_get(r, 1);
		test_tls_skip(r, w->session_id_len);
		w->suite = (uint16_t)test_tls_get(r, 2);
		test_tls_skip(r, 1);
		test_tls_wire_exts(r, w, true);
		break;
	case TEST_TLS_HS_CERTIFICATE:
		w->certificate = true;
		break;
	case TEST_TLS_HS_SERVER_KEY_EXCHANGE:
		/* ECDHE-PSK: the identity hint, then a named curve (3) */
		test_tls_skip(r, test_tls_get(r, 2));
		if (test_tls_get(r, 1) == 3)
			w->group = (uint16_t)test_tls_get(r, 2);
		else
			r->bad = true;
		break;
	default:
		break;
	}
	w->malformed |= r->bad;
}

/*
 * The handshake messages of a record in the clear, unfragmented - nothing is,
 * with the MTU the backends set and the size of the hellos
 */
static inline void test_tls_wire_fragment(struct test_tls_reader *frag,
					  struct test_tls_wire *w)
{
	while (!frag->bad && frag->off < frag->len) {
		/* type and length, for DTLS sequence and fragment */
		uint8_t type = (uint8_t)test_tls_get(frag, 1);
		uint32_t hlen = test_tls_get(frag, 3), foff = 0, flen = hlen;
		struct test_tls_reader body = { 0 };

		if (w->dtls) {
			test_tls_skip(frag, 2);
			foff = test_tls_get(frag, 3);
			flen = test_tls_get(frag, 3);
		}
		body.p = frag->p + frag->off;
		body.len = flen;
		test_tls_skip(frag, flen);
		if (frag->bad || foff || flen != hlen) {
			w->malformed = true;
			break;
		}
		test_tls_wire_hs(type, &body, w);
	}
	w->malformed |= frag->bad;
}

/*
 * The records of @len bytes at @buf, all whole: a message of the socket of
 * DTLS. The handshake is read in the records of epoch 0 of DTLS 1.2, and in
 * those of the content type handshake of TLS 1.3 - which encrypts its
 * handshake past the ServerHello into records of application data, so that a
 * record of the handshake is always in the clear. A ChangeCipherSpec of TLS
 * 1.3 is the one of its middlebox compatibility, not the end of the clear.
 */
static inline void test_tls_wire_records(const uint8_t *buf, size_t len,
					 struct test_tls_wire *w)
{
	struct test_tls_reader rec = { .p = buf, .len = len };

	while (!rec.bad && rec.off < rec.len) {
		/* type, version, for DTLS epoch and sequence number, length */
		uint32_t ctype = test_tls_get(&rec, 1), epoch = 0;
		struct test_tls_reader frag = { 0 };

		test_tls_skip(&rec, 2);
		if (w->dtls) {
			epoch = test_tls_get(&rec, 2);
			test_tls_skip(&rec, 6);
		}
		frag.len = test_tls_get(&rec, 2);
		frag.p = rec.p + rec.off;
		test_tls_skip(&rec, frag.len);
		if (rec.bad)
			break;

		w->records++;
		if (ctype == TEST_TLS_CT_CCS)
			w->ccs++;
		if (ctype == TEST_TLS_CT_HANDSHAKE && !epoch)
			test_tls_wire_fragment(&frag, w);
	}
	w->malformed |= rec.bad;
}

/* The next @len bytes of a TLS stream: the records completed by them */
static inline void test_tls_wire_stream(struct test_tls_wire *w,
					const uint8_t *buf, size_t len)
{
	while (len && !w->malformed) {
		size_t want = 5, n;

		/* The header first, then the record it tells the length of */
		if (w->partial_len >= 5)
			want += (size_t)w->partial[3] << 8 | w->partial[4];

		n = want - w->partial_len;
		if (n > len)
			n = len;
		memcpy(w->partial + w->partial_len, buf, n);
		w->partial_len += n;
		buf += n;
		len -= n;
		if (w->partial_len < 5)
			break;

		want = 5 + ((size_t)w->partial[3] << 8 | w->partial[4]);
		if (want > sizeof(w->partial)) {
			w->malformed = true;
			break;
		}
		if (w->partial_len == want) {
			test_tls_wire_records(w->partial, w->partial_len, w);
			w->partial_len = 0;
		}
	}
}

#endif /* TEST_TLS_WIRE_H */
