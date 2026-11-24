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
 * is, and its behaviour across an XOF failure.
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
#include "es_ebpf/esdm_es_ebpf.c"

#include "build_bug_on.h"
#include "common_test.h"

enum ebpf_pool_fail {
	ebpf_pool_fail_none,
	/* The extraction fails, initializing the pool anew succeeds */
	ebpf_pool_fail_final,
	/* Initializing the pool anew fails as well */
	ebpf_pool_fail_all,
	/* Absorbing data fails, and only that */
	ebpf_pool_fail_update,
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
	if (ebpf_pool_fail == ebpf_pool_fail_final ||
	    ebpf_pool_fail == ebpf_pool_fail_all)
		return -EFAULT;
	return ebpf_pool_xof_real->xof_final(xof, out, outlen);
}

static int ebpf_pool_xof_update(void *xof, const uint8_t *in, size_t inlen)
{
	if (ebpf_pool_fail == ebpf_pool_fail_update)
		return -EFAULT;
	return ebpf_pool_xof_real->xof_update(xof, in, inlen);
}

/* Hand the pool a record of @events deltas, as the ring buffer does */
static void ebpf_pool_events(struct esdm_ebpf_es *es, uint32_t events)
{
	struct esdm_ebpf_event_rec rec;

	memset(&rec, 0, sizeof(rec));
	rec.type = esdm_ebpf_rec_event;
	rec.reset_gen = es->reset_gen;
	rec.events = events;
	esdm_ebpf_handle_events(es, &rec, ESDM_EBPF_EVENT_REC_LEN(events));
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

/* Insert 64 bytes of seed at once, or in chunks */
static int ebpf_pool_insert_seed(struct esdm_ebpf_es *es, const uint8_t *seed,
				 bool chunked)
{
	static const size_t chunks[] = { 1, 7, 56 };
	size_t i;
	int ret;

	if (!chunked)
		return esdm_xdrbg_insert(&es->pool, seed, 64);

	for (i = 0; i < sizeof(chunks) / sizeof(chunks[0]); i++) {
		ret = esdm_xdrbg_insert(&es->pool, seed, chunks[i]);
		if (ret)
			return ret;
		seed += chunks[i];
	}

	return 0;
}

/*
 * The pool is the XDRBG-256 as specified, with "ESDM eBPF pool" and the name
 * of the source as alpha: instantiated from the bytes 0x00 ... 0x3f, it
 * delivers the output of the XDRBG, reseeded from 0x40 ... 0x7f the output
 * after the reseed - the known answers are computed independently of the
 * ESDM. The same with each seed inserted in chunks, into the pool zeroized.
 */
static void ebpf_pool_xdrbg(struct esdm_ebpf_es *es, bool chunked)
{
	static const uint8_t exp_instantiate[] = {
		0x9c, 0x30, 0xda, 0xfc, 0xd9, 0xf0, 0xf6, 0xc0,
		0xa7, 0xc1, 0x79, 0x6e, 0x3c, 0xf0, 0x51, 0xd6,
		0xfe, 0xd5, 0x29, 0x5c, 0xc4, 0x5a, 0xe8, 0xf6,
		0x85, 0x76, 0xc7, 0xd5, 0x7c, 0xe0, 0x8e, 0xbe,
	};
	static const uint8_t exp_reseed[] = {
		0x72, 0xaf, 0x87, 0x13, 0x96, 0x4f, 0xeb, 0x91,
		0xd3, 0xee, 0xdd, 0x24, 0x83, 0xed, 0x0e, 0x46,
		0x5a, 0x6d, 0xbb, 0x3b, 0x69, 0x1f, 0x19, 0xdd,
		0xd2, 0xe6, 0xd3, 0xe7, 0xe3, 0xde, 0x0f, 0xb6,
	};
	struct entropy_es eb_es;
	uint8_t seed[128];
	unsigned int i;

	BUILD_BUG_ON(sizeof(exp_instantiate) !=
		     ESDM_DRNG_SECURITY_STRENGTH_BYTES);

	for (i = 0; i < sizeof(seed); i++)
		seed[i] = (uint8_t)i;

	if (chunked)
		esdm_xdrbg_zero(&es->pool);

	CHECK_EQ(ebpf_pool_insert_seed(es, seed, chunked), 0);
	memset(&eb_es, 0, sizeof(eb_es));
	esdm_ebpf_get_ent(es, &eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK(!memcmp(eb_es.e, exp_instantiate, sizeof(exp_instantiate)),
	      "the instantiated pool does not deliver XDRBG-256 output (seed %s)",
	      chunked ? "in chunks" : "at once");

	CHECK_EQ(ebpf_pool_insert_seed(es, seed + 64, chunked), 0);
	memset(&eb_es, 0, sizeof(eb_es));
	esdm_ebpf_get_ent(es, &eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK(!memcmp(eb_es.e, exp_reseed, sizeof(exp_reseed)),
	      "the reseeded pool does not deliver XDRBG-256 output (seed %s)",
	      chunked ? "in chunks" : "at once");
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
	ebpf_pool_xof_cb.xof_update = ebpf_pool_xof_update;
	esdm_default_xof_cb = &ebpf_pool_xof_cb;

	/* As esdm_ebpf_init_es() sets the pool up */
	CHECK_EQ(esdm_xdrbg_alloc(&es.pool), 0);
	CHECK_EQ(esdm_xdrbg_seed_init(&es.pool), 0);

	ebpf_pool_xdrbg(&es, false);
	ebpf_pool_xdrbg(&es, true);

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es), "a credited pool delivered no entropy");

	/* The extraction fails: what the pool held is lost, the pool is not */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_final;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(es.credited_events, 0);
	CHECK(esdm_xdrbg_seed_initialized(&es.pool),
	      "the pool was not initialized anew after a failed extraction");
	CHECK_EQ(esdm_xdrbg_insert(&es.pool, data, sizeof(data)), 0);

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es),
	      "no entropy delivered after a failed extraction");

	/*
	 * Initializing the pool anew fails as well: the next extraction tries
	 * again, and so does the next insert.
	 */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_all;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	CHECK(!esdm_xdrbg_seed_initialized(&es.pool),
	      "a pool that failed to initialize is in use");
	CHECK(esdm_xdrbg_insert(&es.pool, data, sizeof(data)),
	      "a pool that cannot initialize took data");
	ebpf_pool_fail = ebpf_pool_fail_none;

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es),
	      "no entropy delivered once the pool can initialize again");

	ebpf_pool_fail = ebpf_pool_fail_all;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(esdm_xdrbg_insert(&es.pool, data, sizeof(data)), 0);
	CHECK(esdm_xdrbg_seed_initialized(&es.pool),
	      "an insert did not initialize the pool anew");

	/* A failing insert takes the credit of what the pool absorbed along */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_update;
	ebpf_pool_events(&es, 4);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(es.credited_events, 0);
	CHECK_EQ(ebpf_pool_extract(&es), 0);

	/* Uncredited, the events still stir: an extraction fetches them */
	ebpf_pool_rate_bits = 0;
	CHECK(esdm_ebpf_events_per_block(&es),
	      "an uncredited source fetches no events");
	ebpf_pool_events(&es, 4);
	CHECK_EQ(es.credited_events, 4);
	CHECK_EQ(esdm_ebpf_collected_entropy(&es), 0);
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_rate_bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;

	esdm_xdrbg_zero_free(&es.pool);
	esdm_default_xof_cb = ebpf_pool_xof_real;

	return common_test_result("es_ebpf_pool");
}
