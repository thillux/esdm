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
 * Test of the conditioning pool of the eBPF entropy sources across a hash
 * failure.
 *
 * An extraction whose hash chain fails loses what the pool absorbed, and the
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

#include "common_test.h"

enum ebpf_pool_fail {
	ebpf_pool_fail_none,
	/* The extraction fails, starting the pool over succeeds */
	ebpf_pool_fail_final,
	/* Starting the pool over fails as well */
	ebpf_pool_fail_all,
};

static enum ebpf_pool_fail ebpf_pool_fail = ebpf_pool_fail_none;
static struct esdm_hash_cb ebpf_pool_hash_cb;
static const struct esdm_hash_cb *ebpf_pool_hash_real;

static int ebpf_pool_hash_init(void *hash)
{
	if (ebpf_pool_fail == ebpf_pool_fail_all)
		return -EFAULT;
	return ebpf_pool_hash_real->hash_init(hash);
}

static int ebpf_pool_hash_final(void *hash, uint8_t *digest)
{
	if (ebpf_pool_fail != ebpf_pool_fail_none)
		return -EFAULT;
	return ebpf_pool_hash_real->hash_final(hash, digest);
}

static uint32_t ebpf_pool_rate(void)
{
	return ESDM_DRNG_SECURITY_STRENGTH_BITS;
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

int main(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct esdm_ebpf_es es = {
		.name = "test",
		.entropy_rate = ebpf_pool_rate,
		.osr = 1,
	};
	static const uint8_t data[64] = { 0x5a };

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	ebpf_pool_hash_real = drng->hash_cb;
	ebpf_pool_hash_cb = *ebpf_pool_hash_real;
	ebpf_pool_hash_cb.hash_init = ebpf_pool_hash_init;
	ebpf_pool_hash_cb.hash_final = ebpf_pool_hash_final;
	drng->hash_cb = &ebpf_pool_hash_cb;

	CHECK_EQ(esdm_ebpf_pool_alloc(&es), 0);
	CHECK(es.pool_initialized, "the pool was not initialized");

	ebpf_pool_credit(&es);
	CHECK(ebpf_pool_extract(&es), "a credited pool delivered no entropy");

	/* The extraction fails: what the pool held is lost, the pool is not */
	ebpf_pool_credit(&es);
	ebpf_pool_fail = ebpf_pool_fail_final;
	CHECK_EQ(ebpf_pool_extract(&es), 0);
	ebpf_pool_fail = ebpf_pool_fail_none;
	CHECK_EQ(es.credited_events, 0);
	CHECK(es.pool_initialized,
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
	CHECK(!es.pool_initialized, "a pool that failed to start is in use");
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
	CHECK(es.pool_initialized, "an insert did not start the pool over");

	esdm_ebpf_pool_dealloc(&es);
	drng->hash_cb = ebpf_pool_hash_real;

	return common_test_result("es_ebpf_pool");
}
