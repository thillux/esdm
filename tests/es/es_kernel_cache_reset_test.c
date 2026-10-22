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
 * Test that a reset of the interrupt or the scheduler entropy source discards
 * the blocks its cache took from the kernel before the reset - and that a
 * source holding nothing in the kernel, its cache filled, is still one the ES
 * manager credits.
 *
 * The reset of these sources has the kernel add-on throw away its pools and
 * their entropy estimate. The cache in user space holds blocks that were
 * taken from those pools earlier and carry the entropy the kernel credited
 * them with - left in place, the next seedings are credited with them as if
 * they had been collected after the reset.
 *
 * Both sources need the patched kernel to deliver anything, so the source is
 * compiled into the test and its cache is filled by hand: a credited block in
 * every slot, as the monitor leaves it. The interface to the kernel is not
 * open, which the reset copes with by leaving the kernel alone. Built once
 * per source, TEST_ES_SCHED selecting the scheduler one.
 */

/* O_PATH */
#define _GNU_SOURCE

#include "config.h"

#ifdef TEST_ES_SCHED
#include "esdm_es_sched.c"
#define TEST_ES esdm_es_sched
#define TEST_BUF sched_buf
#define TEST_BUF_ALLOCED sched_buf_alloced
#define TEST_FD esdm_sched_entropy_fd
#define TEST_MUTEX sched_mutex
#define TEST_BLOCKS ESDM_SCHED_ENTROPY_BLOCKS
#define TEST_NAME "ES scheduler cache reset"
#define TEST_RATE_SET esdm_config_es_sched_entropy_rate_set
#else
#include "esdm_es_irq.c"
#define TEST_ES esdm_es_irq
#define TEST_BUF irq_buf
#define TEST_BUF_ALLOCED irq_buf_alloced
#define TEST_FD esdm_irq_entropy_fd
#define TEST_MUTEX irq_mutex
#define TEST_BLOCKS ESDM_IRQ_ENTROPY_BLOCKS
#define TEST_NAME "ES interrupt cache reset"
#define TEST_RATE_SET esdm_config_es_irq_entropy_rate_set
#endif

#include "common_test.h"

#if (TEST_BLOCKS != 0)

/* What the monitor leaves in a slot it filled: data with credited entropy */
static void fill_cache(void)
{
	unsigned int i;

	for (i = 0; i < TEST_BUF.num_blocks; i++) {
		memset(TEST_BUF.blocks[i].e, 0x5a,
		       sizeof(TEST_BUF.blocks[i].e));
		TEST_BUF.blocks[i].e_bits = ESDM_DRNG_SECURITY_STRENGTH_BITS;
		atomic_store(&TEST_BUF.states[i], esdm_es_buf_filled);
	}
}

static void check_reset_discards_cache(void)
{
	struct entropy_es out;
	unsigned int i;

	CHECK_EQ(esdm_es_buf_alloc(&TEST_BUF, TEST_BLOCKS, TEST_ES.name, NULL,
				   NULL),
		 0);
	TEST_BUF_ALLOCED = true;

	fill_cache();

	/* The cache serves a filled block as it is */
	memset(&out, 0, sizeof(out));
	CHECK(esdm_es_buf_try_get(&TEST_BUF, &out,
				  ESDM_DRNG_SECURITY_STRENGTH_BITS, true),
	      "a filled cache served nothing");
	CHECK_EQ(out.e_bits, ESDM_DRNG_SECURITY_STRENGTH_BITS);

	fill_cache();
	TEST_ES.reset();

	for (i = 0; i < TEST_BUF.num_blocks; i++) {
		size_t j;

		CHECK(atomic_load(&TEST_BUF.states[i]) == esdm_es_buf_empty,
		      "slot %u survived the reset", i);
		for (j = 0; j < sizeof(TEST_BUF.blocks[i].e); j++) {
			if (TEST_BUF.blocks[i].e[j]) {
				CHECK(0, "slot %u was not scrubbed", i);
				break;
			}
		}
	}

	/* No block of before the reset is credited after it */
	for (i = 0; i < TEST_BUF.num_blocks; i++) {
		memset(&out, 0, sizeof(out));
		CHECK(!esdm_es_buf_try_get(&TEST_BUF, &out,
					   ESDM_DRNG_SECURITY_STRENGTH_BITS,
					   true),
		      "a block of before the reset was served");
		CHECK_EQ(out.e_bits, 0);
	}

	TEST_ES.fini();
}

/*
 * A reinit keeps the open descriptor and asks the kernel about it again. If
 * that fails, the descriptor is closed - and the global once kept pointing at
 * the closed number, so the source went on issuing ioctls on it, or on what
 * the number was reused for. The cache it filled is discarded with it.
 *
 * An O_PATH descriptor fails every ioctl with EBADF, /dev/null with ENOTTY:
 * the two failure paths a descriptor gets closed on without a kernel add-on.
 */
static void check_init_failure_drops_fd(const char *path, int flags, int expect)
{
	unsigned int i;
	int fd = open(path, flags | O_CLOEXEC);

	CHECK(fd >= 0, "cannot open %s", path);
	if (fd < 0)
		return;

	CHECK_EQ(esdm_es_buf_alloc(&TEST_BUF, TEST_BLOCKS, TEST_ES.name, NULL,
				   NULL),
		 0);
	TEST_BUF_ALLOCED = true;
	fill_cache();

	mutex_lock(&TEST_MUTEX);
	TEST_FD = fd;
	mutex_unlock(&TEST_MUTEX);

	CHECK_EQ(TEST_ES.init(), expect);
	CHECK_EQ(TEST_FD, -1);
	CHECK(fcntl(fd, F_GETFD) < 0, "the descriptor was left open");

	for (i = 0; i < TEST_BUF.num_blocks; i++) {
		if (atomic_load(&TEST_BUF.states[i]) != esdm_es_buf_empty) {
			CHECK(0, "slot %u survived the failed init", i);
			break;
		}
	}

	TEST_ES.fini();
}

/*
 * The monitor filled the cache, which drained the kernel: the kernel holds
 * nothing - which a descriptor of /dev/null, failing every ioctl, tells as
 * well. The source is credited all the same, so that the ES manager collects
 * it into the buffer credited with entropy, where the blocks of its cache
 * count: one credited with nothing was taken for a source that is not
 * validated, its cached blocks spent without being counted.
 */
static void check_drained_source_credited(void)
{
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);

	CHECK(fd >= 0, "cannot open /dev/null");
	if (fd < 0)
		return;

	CHECK_EQ(esdm_es_buf_alloc(&TEST_BUF, TEST_BLOCKS, TEST_ES.name, NULL,
				   NULL),
		 0);
	TEST_BUF_ALLOCED = true;
	fill_cache();

	mutex_lock(&TEST_MUTEX);
	TEST_FD = fd;
	mutex_unlock(&TEST_MUTEX);

	TEST_RATE_SET(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK_EQ(TEST_ES.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS), 0);
	CHECK_EQ(TEST_ES.max_entropy(), esdm_security_strength());

	/* Not credited, it is not validated, whatever it holds */
	TEST_RATE_SET(0);
	CHECK_EQ(TEST_ES.max_entropy(), 0);

	TEST_ES.fini();
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	check_reset_discards_cache();
	check_drained_source_credited();
	check_init_failure_drops_fd("/", O_PATH, -EAGAIN);
	check_init_failure_drops_fd("/dev/null", O_RDONLY, 0);

	return common_test_result(TEST_NAME);
}

#else /* TEST_BLOCKS == 0 */

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/* No cache in this build, nothing for a reset to discard */
	return 77;
}

#endif
