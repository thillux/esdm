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
 * Test of the conditioning pool of the eBPF entropy sources: the XDRBG-256 it
 * is, its behaviour across an XOF failure, and the fetch and the reported
 * maximum of an uncredited source.
 *
 * An extraction whose XDRBG fails loses what the pool absorbed, and the
 * entropy credited for it. It must not lose the source: the pool once stayed
 * uninitialized after such a failure, every later insert was refused, and the
 * source never credited anything again until it was reset or reinitialized.
 *
 * The pool needs neither the eBPF programs nor privileges, but its functions
 * are internal to the glue, so the glue is compiled into the test. A source
 * that is not loaded fetches nothing from a ring buffer, which leaves the
 * credited events entirely to the test.
 */

/* The unit under test */
#include "esdm_es_ebpf.c"

#include "build_bug_on.h"
#include "common_test.h"

enum ebpf_pool_fail {
	ebpf_pool_fail_none,
	/* The extraction fails, starting the pool over succeeds */
	ebpf_pool_fail_final,
	/* Starting the pool over fails as well */
	ebpf_pool_fail_all,
};

static enum ebpf_pool_fail ebpf_pool_fail = ebpf_pool_fail_none;
static struct esdm_xof_cb ebpf_pool_xof_cb;
static const struct esdm_xof_cb *ebpf_pool_xof_real;

static int ebpf_pool_xof_init(void *xof)
{
	if (ebpf_pool_fail == ebpf_pool_fail_all)
		return -EFAULT;
	return ebpf_pool_xof_real->xof_init(xof);
}

static int ebpf_pool_xof_final(void *xof, uint8_t *out, size_t outlen)
{
	if (ebpf_pool_fail != ebpf_pool_fail_none)
		return -EFAULT;
	return ebpf_pool_xof_real->xof_final(xof, out, outlen);
}

static uint32_t ebpf_pool_rate_bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;

static uint32_t ebpf_pool_rate(void)
{
	return ebpf_pool_rate_bits;
}

/* Credit the pool with more than one output block costs */
static void ebpf_pool_credit(struct esdm_ebpf_es *es)
{
	es->credited_events = esdm_ebpf_events_per_block(es) * 2;
}

static uint32_t ebpf_pool_extract(struct esdm_ebpf_es *es)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_ebpf_get_ent(es, &eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS);

	return eb_es.e_bits;
}

/*
 * The pool is the XDRBG-256 as specified, with "ESDM eBPF pool " and the name
 * of the source as alpha: instantiated from the bytes 0x00 ... 0x3f, it
 * delivers the output of the XDRBG, reseeded from 0x40 ... 0x7f the output
 * after the reseed - the known answers are computed independently of the
 * ESDM.
 */
static void ebpf_pool_xdrbg(struct esdm_ebpf_es *es)
{
	static const uint8_t exp_instantiate[] = {
		0x42, 0x36, 0xb2, 0x42, 0xf1, 0x78, 0xe4, 0xf4,
		0xb0, 0x2b, 0x57, 0xbf, 0x08, 0x1c, 0x31, 0xa8,
		0xd9, 0x88, 0x07, 0x4d, 0xdb, 0xa6, 0x61, 0xb1,
		0x42, 0xa5, 0x09, 0x6a, 0xe2, 0x70, 0xac, 0xd5,
	};
	static const uint8_t exp_reseed[] = {
		0x1c, 0xf8, 0xf8, 0x29, 0xb4, 0xbc, 0x99, 0x8d,
		0xc0, 0x2e, 0xe6, 0xdf, 0x0d, 0x6b, 0x59, 0x59,
		0x5c, 0x4c, 0x44, 0xf1, 0xde, 0x19, 0x0d, 0xa7,
		0x4e, 0xea, 0xa8, 0x4c, 0x35, 0x53, 0x8c, 0x1d,
	};
	struct entropy_es eb_es;
	uint8_t seed[128];
	unsigned int i;

	BUILD_BUG_ON(sizeof(exp_instantiate) !=
		     ESDM_DRNG_SECURITY_STRENGTH_BYTES);

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	CHECK_EQ(esdm_ebpf_pool_insert(es, seed, 64), 0);
	memset(&eb_es, 0, sizeof(eb_es));
	esdm_ebpf_get_ent(es, &eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK(!memcmp(eb_es.e, exp_instantiate, sizeof(exp_instantiate)),
	      "the instantiated pool does not deliver XDRBG-256 output");

	CHECK_EQ(esdm_ebpf_pool_insert(es, seed + 64, 64), 0);
	memset(&eb_es, 0, sizeof(eb_es));
	esdm_ebpf_get_ent(es, &eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK(!memcmp(eb_es.e, exp_reseed, sizeof(exp_reseed)),
	      "the reseeded pool does not deliver XDRBG-256 output");
}

/*
 * An uncredited source (entropy rate of 0) once fetched nothing at all: its
 * fetch bound was the events one block costs to credit, which is none. The
 * bonus data it promises was never stirred in and the programs dropped every
 * event. It also reported a full digest as its maximum entropy, which made the
 * seeding treat it as validated and put its data into the seed buffer.
 *
 * The records are handed to the ring buffer callback directly, as
 * ring_buffer__consume() would until the callback stops it. libbpf has
 * consumed the record whose callback stops it, so that record must have been
 * taken in.
 */
static void ebpf_pool_uncredited(struct esdm_ebpf_es *es)
{
	struct esdm_ebpf_event_rec rec;
	uint64_t fed = 0;
	unsigned int i;
	int ret = 0;

	memset(&rec, 0, sizeof(rec));
	rec.type = esdm_ebpf_rec_event;
	rec.cpu = UINT32_MAX;
	rec.events = ESDM_EBPF_BATCH_EVENTS;
	rec.reset_gen = es->reset_gen;
	rec.health_epoch = es->health_epoch;
	for (i = 0; i < ESDM_EBPF_BATCH_EVENTS; i++)
		rec.delta[i] = i * 7919 + 13;

	es->loaded = true;
	CHECK(esdm_ebpf_max_entropy(es),
	      "a credited source reports no maximum entropy");
	ebpf_pool_rate_bits = 0;
	CHECK_EQ(esdm_ebpf_max_entropy(es), 0);
	es->loaded = false;

	es->credited_events = 0;
	CHECK(esdm_ebpf_fetch_bound(es),
	      "an uncredited source fetches nothing");
	CHECK(es->fetch_target, "an uncredited fetch has no bound");

	/* Twice the bound is on offer: the fetch must stop at the bound */
	for (i = 0; fed < es->fetch_target * 2; i++) {
		ret = esdm_ebpf_handle_record(es, &rec, sizeof(rec));
		if (ret)
			break;
		fed += rec.events;
	}
	CHECK_EQ(ret, ESDM_EBPF_FETCH_DONE);
	CHECK_EQ(es->ingested, fed + rec.events);
	CHECK(es->ingested >= es->fetch_target,
	      "the uncredited fetch stopped short of its bound");
	CHECK(es->ingested < es->fetch_target + ESDM_EBPF_BATCH_EVENTS,
	      "the uncredited fetch ran past its bound");
	CHECK_EQ(es->credited_events, 0);
	CHECK_EQ(ebpf_pool_extract(es), 0);

	ebpf_pool_rate_bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
}

int main(void)
{
	struct esdm_ebpf_es es = {
		.name = "test",
		.entropy_rate = ebpf_pool_rate,
		.osr = 1,
	};
	static const uint8_t data[64] = { 0x5a };

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ebpf_pool_xof_real = esdm_default_xof_cb;
	ebpf_pool_xof_cb = *ebpf_pool_xof_real;
	ebpf_pool_xof_cb.xof_init = ebpf_pool_xof_init;
	ebpf_pool_xof_cb.xof_final = ebpf_pool_xof_final;
	esdm_default_xof_cb = &ebpf_pool_xof_cb;

	CHECK_EQ(esdm_ebpf_pool_alloc(&es), 0);
	CHECK(esdm_xdrbg_started(&es.pool), "the pool was not started");

	ebpf_pool_xdrbg(&es);

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es), "a credited pool delivered no entropy");

	/* The extraction fails: what the pool held is lost, the pool is not */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_final;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(es.credited_events, 0);
	CHECK(esdm_xdrbg_started(&es.pool),
	      "the pool was not started over after a failed extraction");
	CHECK_EQ(esdm_ebpf_pool_insert(&es, data, sizeof(data)), 0);

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es),
	      "no entropy delivered after a failed extraction");

	/*
	 * Starting the pool over fails as well: the next extraction tries
	 * again, and so does the next insert.
	 */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_all;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	CHECK(!esdm_xdrbg_started(&es.pool),
	      "a pool that failed to start is in use");
	CHECK(esdm_ebpf_pool_insert(&es, data, sizeof(data)),
	      "a pool that cannot start took data");
	ebpf_pool_fail = ebpf_pool_fail_none;

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es),
	      "no entropy delivered once the pool can start again");

	ebpf_pool_fail = ebpf_pool_fail_all;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(esdm_ebpf_pool_insert(&es, data, sizeof(data)), 0);
	CHECK(esdm_xdrbg_started(&es.pool),
	      "an insert did not start the pool over");

	ebpf_pool_uncredited(&es);

	esdm_ebpf_pool_dealloc(&es);
	esdm_default_xof_cb = ebpf_pool_xof_real;

	return common_test_result("es_ebpf_pool");
}
