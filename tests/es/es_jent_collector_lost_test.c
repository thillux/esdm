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
 * A Jitter RNG whose collector the library could not bring back.
 *
 * jent_read_entropy_safe() answers a failed health test by freeing the
 * collector and allocating a new one, and leaves it NULL when that does not
 * work out. The ESDM stayed initialized and went on reporting the configured
 * rate as available entropy, and the periodic self test passed - it skipped the
 * NULL collector - while every read delivered nothing.
 *
 * Later releases keep the collector instead, and so does a permanent health
 * test failure: the collector fails every read from then on, which the ESDM
 * did not notice at all.
 *
 * The test defines jent_read_entropy_safe() and jent_entropy_collector_alloc()
 * itself, which take precedence over the library's. They hand the calls on to
 * the library until told to lose the collector the way the library does, to
 * fail it, or to fail the allocation of a new one.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "esdm.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_mgr.h"

struct rand_data;

ssize_t jent_read_entropy_safe(struct rand_data **ec, char *data, size_t len);
struct rand_data *jent_entropy_collector_alloc(unsigned int osr,
					       unsigned int flags);
void jent_entropy_collector_free(struct rand_data *ec);

static pthread_t main_thread;
/* Lose the collector on the next read of the main thread */
static bool jent_lose = false;
/*
 * Fail the next read of the main thread with jent_fail_err, and every later
 * one of the collector it was made with (jent_failed), as the library does
 */
static bool jent_fail = false;
static ssize_t jent_fail_err = 0;
static struct rand_data *jent_failed = NULL;
static bool jent_alloc_fail = false;

ssize_t jent_read_entropy_safe(struct rand_data **ec, char *data, size_t len)
{
	ssize_t (*real)(struct rand_data **, char *, size_t);

	/*
	 * The main thread reads the synchronous collector, the monitor thread
	 * the asynchronous one, which this leaves alone.
	 */
	if (jent_lose && pthread_equal(pthread_self(), main_thread)) {
		jent_lose = false;
		jent_entropy_collector_free(*ec);
		*ec = NULL;
		return -1;
	}

	if (pthread_equal(pthread_self(), main_thread) &&
	    (jent_fail || (*ec && *ec == jent_failed))) {
		jent_fail = false;
		jent_failed = *ec;
		return jent_fail_err;
	}

	*(void **)(&real) = dlsym(RTLD_NEXT, "jent_read_entropy_safe");
	if (!real)
		return -1;

	return real(ec, data, len);
}

struct rand_data *jent_entropy_collector_alloc(unsigned int osr,
					       unsigned int flags)
{
	struct rand_data *(*real)(unsigned int, unsigned int);

	if (jent_alloc_fail)
		return NULL;

	*(void **)(&real) = dlsym(RTLD_NEXT, "jent_entropy_collector_alloc");
	if (!real)
		return NULL;

	return real(osr, flags);
}

static uint32_t jent_credit(void)
{
	return esdm_es[esdm_ext_es_jitter]->curr_entropy(
		ESDM_DRNG_INIT_SEED_SIZE_BITS);
}

/* A read of the synchronous collector, past the cache */
static uint32_t jent_read(void)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	esdm_es[esdm_ext_es_jitter]->get_ent(
		&eb_es, ESDM_DRNG_INIT_SEED_SIZE_BITS, false);

	return eb_es.e_bits;
}

int main(void)
{
	uint32_t bits;
	int ret;

	main_thread = pthread_self();

	if (!dlsym(RTLD_NEXT, "jent_read_entropy_safe") ||
	    !dlsym(RTLD_NEXT, "jent_entropy_collector_alloc")) {
		printf("ES Jitter RNG - skip: the library's functions are out of reach\n");
		return 77;
	}

	esdm_config_es_jent_entropy_rate_set(256);

	ret = esdm_init();
	if (ret) {
		printf("ES Jitter RNG - fail: ESDM initialization failed: %d\n",
		       ret);
		return 1;
	}

	if (!jent_credit()) {
		printf("ES Jitter RNG - skip: not usable on this system\n");
		ret = 77;
		goto out;
	}

	/* The library loses the collector */
	jent_lose = true;
	bits = jent_read();
	if (bits || jent_lose) {
		printf("ES Jitter RNG - fail: the collector was not lost (%u bits)\n",
		       bits);
		ret = 1;
		goto out;
	}

	bits = jent_credit();
	if (bits) {
		printf("ES Jitter RNG - fail: still credited with %u bits without a collector\n",
		       bits);
		ret = 1;
	}

	if (esdm_es[esdm_ext_es_jitter]->active()) {
		printf("ES Jitter RNG - fail: active without a collector\n");
		ret = 1;
	}

	/* A self test that cannot bring a collector back fails */
	jent_alloc_fail = true;
	if (!esdm_es[esdm_ext_es_jitter]->selftest()) {
		printf("ES Jitter RNG - fail: the self test passed without a collector\n");
		ret = 1;
	}
	jent_alloc_fail = false;

	bits = jent_credit();
	if (bits) {
		printf("ES Jitter RNG - fail: credited with %u bits after the failed self test\n",
		       bits);
		ret = 1;
	}

	/* One that can, brings the source back */
	if (esdm_es[esdm_ext_es_jitter]->selftest()) {
		printf("ES Jitter RNG - fail: the self test did not recover the collector\n");
		ret = 1;
	}

	if (!jent_credit() || !esdm_es[esdm_ext_es_jitter]->active()) {
		printf("ES Jitter RNG - fail: not credited again with a new collector\n");
		ret = 1;
	}

	bits = jent_read();
	if (!bits) {
		printf("ES Jitter RNG - fail: delivered no entropy with a new collector\n");
		ret = 1;
	}

	/* A permanent RCT failure: the collector fails every read from now on */
	jent_fail_err = -6;
	jent_fail = true;
	bits = jent_read();
	if (bits || jent_fail) {
		printf("ES Jitter RNG - fail: the collector did not fail (%u bits)\n",
		       bits);
		ret = 1;
		goto out;
	}

	bits = jent_read();
	if (bits) {
		printf("ES Jitter RNG - fail: a failed collector delivered %u bits\n",
		       bits);
		ret = 1;
	}

	bits = jent_credit();
	if (bits) {
		printf("ES Jitter RNG - fail: still credited with %u bits with a failed collector\n",
		       bits);
		ret = 1;
	}

	if (esdm_es[esdm_ext_es_jitter]->active()) {
		printf("ES Jitter RNG - fail: active with a failed collector\n");
		ret = 1;
	}

	/* The self test passes once it has replaced the collector */
	if (esdm_es[esdm_ext_es_jitter]->selftest()) {
		printf("ES Jitter RNG - fail: the self test did not replace the failed collector\n");
		ret = 1;
	}

	if (!jent_credit() || !esdm_es[esdm_ext_es_jitter]->active() ||
	    !jent_read()) {
		printf("ES Jitter RNG - fail: not credited again with a collector replacing the failed one\n");
		ret = 1;
	}

	/*
	 * An intermittent failure the library could not replace the collector
	 * after - until a later read where it can.
	 */
	jent_fail_err = -2;
	jent_fail = true;
	bits = jent_read();
	if (bits || jent_credit() || esdm_es[esdm_ext_es_jitter]->active()) {
		printf("ES Jitter RNG - fail: credited after an intermittent failure without recovery (%u bits)\n",
		       bits);
		ret = 1;
	}

	jent_failed = NULL;
	if (!jent_read() || !jent_credit() ||
	    !esdm_es[esdm_ext_es_jitter]->active()) {
		printf("ES Jitter RNG - fail: not credited again once the collector delivers\n");
		ret = 1;
	}

	if (!ret)
		printf("ES Jitter RNG - pass: a lost or failed collector is credited with nothing until it delivers again or the self test replaces it\n");

out:
	esdm_fini();

	return ret;
}
