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
 * A test moving the records between the two ends of a DTLS connection reads
 * them with this: what passes in the clear - the handshake of DTLS 1.2 up to
 * the ChangeCipherSpec -, the suites, the groups and the extensions of the
 * hellos, the suite and the group the server takes, and which handshake
 * messages pass. Every record is counted, encrypted or not.
 *
 * One struct test_dtls_wire per direction of a connection, handed a message of
 * the socket at a time, which holds whole records (test_dtls_wire_records()).
 */

#ifndef TEST_DTLS_WIRE_H
#define TEST_DTLS_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The handshake messages looked at */
#define TEST_DTLS_HS_CLIENT_HELLO 1
#define TEST_DTLS_HS_SERVER_HELLO 2
#define TEST_DTLS_HS_NEW_SESSION_TICKET 4
#define TEST_DTLS_HS_CERTIFICATE 11
#define TEST_DTLS_HS_SERVER_KEY_EXCHANGE 12
#define TEST_DTLS_HS_SERVER_HELLO_DONE 14

/* The extensions looked at */
#define TEST_DTLS_EXT_GROUPS 10
#define TEST_DTLS_EXT_HEARTBEAT 15
#define TEST_DTLS_EXT_ETM 22
#define TEST_DTLS_EXT_EMS 23
#define TEST_DTLS_EXT_SESSION_TICKET 35
#define TEST_DTLS_EXT_PRE_SHARED_KEY 41
#define TEST_DTLS_EXT_EARLY_DATA 42

/* TLS_EMPTY_RENEGOTIATION_INFO_SCSV, no suite */
#define TEST_DTLS_SCSV 0x00ff

/* The content types of a record */
#define TEST_DTLS_CT_CCS 20
#define TEST_DTLS_CT_HANDSHAKE 22

struct test_dtls_wire {
	/* Of the ClientHello: the suites and groups it offers */
	uint16_t suites[16];
	unsigned int nsuites;
	uint16_t groups[16];
	unsigned int ngroups;

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
};

struct test_dtls_reader {
	const uint8_t *p;
	size_t len, off;
	bool bad;
};

/* A big-endian number of @n bytes, 0 and bad past the end */
static inline uint32_t test_dtls_get(struct test_dtls_reader *r, size_t n)
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

static inline void test_dtls_skip(struct test_dtls_reader *r, size_t n)
{
	if (r->bad || n > r->len - r->off)
		r->bad = true;
	else
		r->off += n;
}

/* Is the extension @type among those of the hello read into @w? */
static inline bool test_dtls_has_ext(const struct test_dtls_wire *w,
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
static inline int test_dtls_ext_len(const struct test_dtls_wire *w,
				    uint16_t type)
{
	unsigned int i;

	for (i = 0; i < w->nexts; i++) {
		if (w->exts[i] == type)
			return w->ext_lens[i];
	}
	return -1;
}

/* Did a handshake message of @type pass in the clear? */
static inline bool test_dtls_has_hs(const struct test_dtls_wire *w,
				    uint8_t type)
{
	return type < 32 && (w->hs_types & (1U << type));
}

/* A list of 16-bit values, all of an extension after its length of @n bytes */
static inline void test_dtls_wire_list(struct test_dtls_reader *ext, size_t n,
				       uint16_t *list, unsigned int *num,
				       unsigned int max,
				       struct test_dtls_wire *w)
{
	if (test_dtls_get(ext, n) + n != ext->len || (ext->len - n) % 2) {
		w->malformed = true;
		return;
	}
	while (ext->off < ext->len && *num < max)
		list[(*num)++] = (uint16_t)test_dtls_get(ext, 2);
}

/* The extensions of a hello, the rest of @r */
static inline void test_dtls_wire_exts(struct test_dtls_reader *r,
				       struct test_dtls_wire *w)
{
	struct test_dtls_reader exts = { .p = r->p + r->off };

	/* A hello without any */
	if (r->off == r->len)
		return;
	exts.len = test_dtls_get(r, 2);
	test_dtls_skip(r, exts.len);
	if (r->bad)
		return;
	exts.p += 2;

	while (!exts.bad && exts.off < exts.len) {
		uint32_t type = test_dtls_get(&exts, 2);
		struct test_dtls_reader ext = { .len = test_dtls_get(&exts,
								     2) };

		ext.p = exts.p + exts.off;
		test_dtls_skip(&exts, ext.len);
		if (exts.bad)
			break;

		if (w->nexts < sizeof(w->exts) / sizeof(w->exts[0])) {
			w->ext_lens[w->nexts] = (uint16_t)ext.len;
			w->exts[w->nexts++] = (uint16_t)type;
		}
		switch (type) {
		case TEST_DTLS_EXT_ETM:
			w->etm = true;
			break;
		case TEST_DTLS_EXT_GROUPS:
			test_dtls_wire_list(
				&ext, 2, w->groups, &w->ngroups,
				sizeof(w->groups) / sizeof(w->groups[0]), w);
			break;
		default:
			break;
		}
	}
	w->malformed |= exts.bad;
}

/* A handshake message of @type, its body in @r */
static inline void test_dtls_wire_hs(uint8_t type, struct test_dtls_reader *r,
				     struct test_dtls_wire *w)
{
	uint32_t n;

	if (type < 32)
		w->hs_types |= 1U << type;

	switch (type) {
	case TEST_DTLS_HS_CLIENT_HELLO:
		/* version, random, session ID, cookie */
		test_dtls_skip(r, 34);
		w->session_id_len = test_dtls_get(r, 1);
		test_dtls_skip(r, w->session_id_len);
		test_dtls_skip(r, test_dtls_get(r, 1));
		n = test_dtls_get(r, 2);
		if (n % 2)
			r->bad = true;
		for (; n >= 2 && !r->bad; n -= 2) {
			uint16_t suite = (uint16_t)test_dtls_get(r, 2);

			if (suite != TEST_DTLS_SCSV &&
			    w->nsuites <
				    sizeof(w->suites) / sizeof(w->suites[0]))
				w->suites[w->nsuites++] = suite;
		}
		test_dtls_skip(r, test_dtls_get(r, 1));
		test_dtls_wire_exts(r, w);
		break;
	case TEST_DTLS_HS_SERVER_HELLO:
		/* version, random, session ID */
		test_dtls_skip(r, 34);
		w->session_id_len = test_dtls_get(r, 1);
		test_dtls_skip(r, w->session_id_len);
		w->suite = (uint16_t)test_dtls_get(r, 2);
		test_dtls_skip(r, 1);
		test_dtls_wire_exts(r, w);
		break;
	case TEST_DTLS_HS_CERTIFICATE:
		w->certificate = true;
		break;
	case TEST_DTLS_HS_SERVER_KEY_EXCHANGE:
		/* ECDHE-PSK: the identity hint, then a named curve (3) */
		test_dtls_skip(r, test_dtls_get(r, 2));
		if (test_dtls_get(r, 1) == 3)
			w->group = (uint16_t)test_dtls_get(r, 2);
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
static inline void test_dtls_wire_fragment(struct test_dtls_reader *frag,
					   struct test_dtls_wire *w)
{
	while (!frag->bad && frag->off < frag->len) {
		/* type, length, sequence, fragment offset and length */
		uint8_t type = (uint8_t)test_dtls_get(frag, 1);
		uint32_t hlen = test_dtls_get(frag, 3), foff, flen;
		struct test_dtls_reader body = { 0 };

		test_dtls_skip(frag, 2);
		foff = test_dtls_get(frag, 3);
		flen = test_dtls_get(frag, 3);
		body.p = frag->p + frag->off;
		body.len = flen;
		test_dtls_skip(frag, flen);
		if (frag->bad || foff || flen != hlen) {
			w->malformed = true;
			break;
		}
		test_dtls_wire_hs(type, &body, w);
	}
	w->malformed |= frag->bad;
}

/*
 * The records of @len bytes at @buf, all whole: a message of the socket. The
 * handshake is read in the records of epoch 0.
 */
static inline void test_dtls_wire_records(const uint8_t *buf, size_t len,
					  struct test_dtls_wire *w)
{
	struct test_dtls_reader rec = { .p = buf, .len = len };

	while (!rec.bad && rec.off < rec.len) {
		/* type, version, epoch, sequence number, length */
		uint32_t ctype = test_dtls_get(&rec, 1), epoch;
		struct test_dtls_reader frag = { 0 };

		test_dtls_skip(&rec, 2);
		epoch = test_dtls_get(&rec, 2);
		test_dtls_skip(&rec, 6);
		frag.len = test_dtls_get(&rec, 2);
		frag.p = rec.p + rec.off;
		test_dtls_skip(&rec, frag.len);
		if (rec.bad)
			break;

		w->records++;
		if (ctype == TEST_DTLS_CT_CCS)
			w->ccs++;
		if (ctype == TEST_DTLS_CT_HANDSHAKE && !epoch)
			test_dtls_wire_fragment(&frag, w);
	}
	w->malformed |= rec.bad;
}

#endif /* TEST_DTLS_WIRE_H */
