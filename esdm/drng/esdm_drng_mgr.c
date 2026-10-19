/*
 * ESDM DRNG management
 *
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

#include "build_bug_on.h"
#include "config.h"
#include "esdm.h"
#include "esdm_builtin_hash_drbg.h"
#include "esdm_builtin_chacha20.h"
#include "esdm_builtin_sha512.h"
#include "esdm_builtin_shake256.h"
#include "esdm_config.h"
#include "esdm_config_internal.h"
#include "esdm_crypto.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_aux.h"
#include "esdm_es_mgr.h"
#include "esdm_botan.h"
#include "esdm_gnutls.h"
#include "esdm_leancrypto.h"
#include "esdm_node.h"
#include "esdm_openssl.h"
#include "esdm_selftest.h"
#include "helper.h"
#include "memset_secure.h"
#include "os_random.h"
#include "queue.h"
#include "ret_checkers.h"
#include "threading_support.h"
#include "visibility.h"
#include "xoshiro_prng.h"

/*
 * Maximum number of seconds between DRNG reseed intervals of the DRNG. Note,
 * this is enforced with the next request of random numbers from the
 * DRNG. Setting this value to zero implies a reseeding attempt before every
 * generated random number.
 *
 * Atomic because it has no owning lock: esdm_set_reseed_max_time() writes it
 * from whichever thread services the request (the privileged RPC handler),
 * while the generate paths and the reseed worker read it without any lock.
 */
static _Atomic uint32_t esdm_drng_reseed_max_time = 600;

/*
 * Is ESDM for general-purpose use (i.e. is at least the esdm_drng_init
 * fully allocated)?
 */
static atomic_int esdm_avail = 0;

/* Guard protecting all crypto callback update operation of all DRNGs. */
DEFINE_MUTEX_W_UNLOCKED(esdm_crypto_cb_update);

/*
 * Default hash callback that provides the crypto primitive right from the
 * kernel start. It must not perform any memory allocation operation, but
 * simply perform the hash calculation.
 */
#if (defined(ESDM_HASH_SHA512) || defined(ESDM_HASH_SHA3_512))
#define ESDM_DEFAULT_HASH_CB &esdm_builtin_sha512_cb
#elif defined(ESDM_BOTAN)
#define ESDM_DEFAULT_HASH_CB &esdm_botan_hash_cb
#elif defined(ESDM_GNUTLS)
#define ESDM_DEFAULT_HASH_CB &esdm_gnutls_hash_cb
#elif defined(ESDM_LEANCRYPTO)
#define ESDM_DEFAULT_HASH_CB &esdm_leancrypto_hash_cb
#elif defined(ESDM_OPENSSL)
#define ESDM_DEFAULT_HASH_CB &esdm_openssl_hash_cb
#else
#error "Unknown default DRNG selected"
#endif

/* The SHAKE256 of the XDRBG-256 operating the auxiliary pool */
#if (defined(ESDM_HASH_SHA512) || defined(ESDM_HASH_SHA3_512))
#define ESDM_DEFAULT_XOF_CB &esdm_builtin_shake256_cb
#elif defined(ESDM_BOTAN)
#define ESDM_DEFAULT_XOF_CB &esdm_botan_xof_cb
#elif defined(ESDM_GNUTLS)
#define ESDM_DEFAULT_XOF_CB &esdm_gnutls_xof_cb
#elif defined(ESDM_LEANCRYPTO)
#define ESDM_DEFAULT_XOF_CB &esdm_leancrypto_xof_cb
#elif defined(ESDM_OPENSSL)
#define ESDM_DEFAULT_XOF_CB &esdm_openssl_xof_cb
#else
#error "Unknown default XOF selected"
#endif

const struct esdm_xof_cb *esdm_default_xof_cb = ESDM_DEFAULT_XOF_CB;

/*
 * Default DRNG callback that provides the crypto primitive.
 */
const struct esdm_drng_cb *esdm_default_drng_cb =
#if defined(ESDM_DRNG_HASH_DRBG)
	&esdm_builtin_hash_drbg_cb;
#elif defined(ESDM_BOTAN)
	&esdm_botan_drbg_cb;
#elif defined(ESDM_DRNG_CHACHA20)
	&esdm_builtin_chacha20_cb;
#elif defined(ESDM_GNUTLS)
	&esdm_gnutls_drbg_cb;
#elif defined(ESDM_LEANCRYPTO)
	&esdm_leancrypto_drbg_cb;
#elif defined(ESDM_OPENSSL)
	&esdm_openssl_drbg_cb;
#else
#error "Unknown default DRNG selected"
#endif

/* DRNG for non-atomic use cases */
static struct esdm_drng esdm_drng_init = { ESDM_DRNG_STATE_INIT(
	esdm_drng_init, NULL, NULL, ESDM_DEFAULT_HASH_CB) };

/* Prediction-resistance DRNG: only deliver as much data as received entropy */
static struct esdm_drng esdm_drng_pr = { ESDM_DRNG_STATE_INIT(
	esdm_drng_pr, NULL, NULL, ESDM_DEFAULT_HASH_CB) };

/* Wait queue to wait until the ESDM is initialized - can freely be used */
DECLARE_WAIT_QUEUE(esdm_init_wait);

static atomic_int esdm_drng_mgr_terminate = 0;

/*
 * Single throttle shared by the blocking and non-blocking prediction-resistant
 * entry points so that only one PR request is ever in flight - a precaution so
 * a caller cannot flood the slow PR DRNG and starve the others. It must be
 * file-scope: two separate function-local statics would each permit one call,
 * allowing two concurrent PR requests and weakening the rate limit.
 */
static DEFINE_MUTEX_W_UNLOCKED(esdm_pr_lock);

/*
 * Source of the seed time offsets that keep the DRNGs from all falling due for
 * a reseed at once - see esdm_drng_reseed_stagger().
 */
static struct xoshiro_state esdm_drng_stagger_prng;
static bool esdm_drng_stagger_avail = false;

/* The fork handler, defined with the asynchronous reseeding below */
static pthread_once_t esdm_drng_atfork_once = PTHREAD_ONCE_INIT;
static void esdm_drng_atfork_register(void);

/********************************** Helper ************************************/

bool esdm_get_available(void)
{
	return (atomic_load(&esdm_avail) == 2);
}

struct esdm_drng *esdm_drng_init_instance(void)
{
	return &esdm_drng_init;
}

/* Caller must call esdm_drng_put_instances! */
struct esdm_drng *esdm_drng_node_instance(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	uint32_t node = esdm_config_curr_node();

	/* Bound by the published array size - see esdm_drng_get_sleep() */
	if (esdm_drng && node < esdm_drng_node_count_get() && esdm_drng[node])
		return esdm_drng[node];

	return esdm_drng_init_instance();
}

/* Record the seed time (whole seconds, CLOCK_MONOTONIC). */
static void esdm_drng_set_seeded_now(struct esdm_drng *drng)
{
	atomic_store(&drng->last_seeded_time, esdm_monotonic_now());
}

/* The share of the reseed interval the seed times are spread over */
#define ESDM_DRNG_RESEED_STAGGER_DIV 10

/*
 * Seconds the seed time of a node DRNG is moved back by: a number drawn from
 * [0, a tenth of the reseed interval), so the DRNGs do not all fall due in the
 * same pass and collect their entropy at once.
 */
static long long esdm_drng_reseed_stagger(void)
{
	uint32_t range = atomic_load(&esdm_drng_reseed_max_time) /
			 ESDM_DRNG_RESEED_STAGGER_DIV;

	/*
	 * Nothing to spread if that share is below a second: the interval is
	 * then so short that the instances meet in a pass no matter how they
	 * are placed.
	 */
	if (!esdm_drng_stagger_avail || !range)
		return 0;

	return (long long)xoshiro_generate_interval(&esdm_drng_stagger_prng, 0,
						    range);
}

/*
 * Move the recorded seed time of a node DRNG back by the offset above. Back
 * and not forward: the reseed interval is the maximum time a seed may serve,
 * so the spread has to come out of it - a node DRNG falls due between nine
 * tenths of the interval and the whole of it after its seeding, never later.
 */
static void esdm_drng_stagger_seed_time(struct esdm_drng *drng)
{
	if (drng == &esdm_drng_init || drng == &esdm_drng_pr)
		return;

	atomic_fetch_sub(&drng->last_seeded_time, esdm_drng_reseed_stagger());
}

/*
 * Generate requests left before a reseed is due, given the value of
 * drng->requests. That counter runs down from ESDM_DRNG_RESEED_THRESH, so a
 * lower configured threshold is reached that much earlier.
 */
static int esdm_drng_requests_left(int requests)
{
	return requests - (int)(ESDM_DRNG_RESEED_THRESH -
				esdm_config_drng_reseed_thresh());
}

/* Count one generate request against the current seed of @drng */
static void esdm_drng_count_request(struct esdm_drng *drng)
{
	atomic_fetch_sub(&drng->requests, 1);
}

/* Record the wall clock time of a seeding. */
static void esdm_drng_set_seeded_wtime(struct esdm_drng *drng)
{
	struct timespec now;

	if (clock_gettime(CLOCK_REALTIME, &now) != -1)
		atomic_store(&drng->last_seeded_wtime, (long long)now.tv_sec);
}

/*
 * The fork generation of this process: zero in the process that set the ESDM
 * up, bumped in the child of every fork() - see esdm_drng_atfork_child(). A
 * DRNG last made unique to another generation holds a state its parent, or a
 * sibling, holds as well.
 */
static atomic_uint esdm_drng_fork_gen = 0;

/*
 * Make the state of @drng unique to this process if it was inherited across
 * fork(), before anything is generated from it or seeded into it. The child
 * starts out with the DRNG states of its parent, and the two would hand out
 * the same bytes until each reseeds - which neither does on account of the
 * fork, nor at a moment of its own.
 *
 * The state is reseeded with 32 bytes of the kernel RNG, which no two
 * processes share, together with the process ID and the time - the latter set
 * the child apart from its parent even should the kernel RNG fail. A reseed
 * from the entropy sources is forced to follow by the usual rules: at its next
 * request for a DRNG that cannot defer it, as soon as the pool lock is free
 * for a node DRNG - the child has no reseed worker, see
 * esdm_drng_atfork_child().
 *
 * A DRNG that never held a seed has nothing inherited to set apart: its first
 * seeding comes from the entropy sources of this process, stamped with the
 * time of their collection.
 *
 * Caller holds drng->lock.
 *
 * @return 0 on success, < 0 if the state could not be made unique - nothing
 *	   may be generated from it then
 */
static int esdm_drng_fork_stir_nolock(struct esdm_drng *drng)
{
	unsigned int gen = atomic_load(&esdm_drng_fork_gen);
	struct {
		uint8_t random[32];
		struct timespec mono, real;
		pid_t pid;
		unsigned int gen;
	} stir;
	int ret;

	if (atomic_load(&drng->fork_gen) == gen)
		return 0;

	if (!drng->drng || !atomic_load(&drng->seed_generation)) {
		atomic_store(&drng->fork_gen, gen);
		return 0;
	}

	memset(&stir, 0, sizeof(stir));
	ret = esdm_os_random(stir.random, sizeof(stir.random));
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"no data from the kernel RNG for a DRNG inherited across fork() (%d) - process ID and time set it apart until its reseed\n",
			ret);
	}
	clock_gettime(CLOCK_MONOTONIC, &stir.mono);
	clock_gettime(CLOCK_REALTIME, &stir.real);
	stir.pid = getpid();
	stir.gen = gen;

	ret = drng->drng_cb->drng_seed(drng->drng, (uint8_t *)&stir,
				       sizeof(stir), NULL, 0);
	memset_secure(&stir, 0, sizeof(stir));
	if (ret < 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"reseed of a DRNG inherited across fork() failed (%d)\n",
			ret);
		return ret;
	}

	atomic_store(&drng->fork_gen, gen);
	atomic_store(&drng->force_reseed, true);

	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "DRNG inherited across fork() reseeded\n");

	return 0;
}

/*
 * Reset the DRNG by clearing all meta data, but leave the state (which implies)
 * the state is credited with zero entropy, but is used to have a state other
 * than zero).
 */
void esdm_drng_reset(struct esdm_drng *drng)
{
	/*
	 * Ensure reseed during next call: no requests are left, whatever the
	 * threshold is.
	 */
	atomic_store(&drng->requests, 0);
	atomic_store(&drng->requests_since_fully_seeded, 0);
	atomic_store(&drng->request_bits_since_fully_seeded, 0);
	/*
	 * drng->seed_generation and drng->last_seeded_wtime are deliberately
	 * kept: they report what happened to this DRNG, and no seeding is
	 * undone here - only the reseed bookkeeping is restarted.
	 */
	esdm_drng_set_seeded_now(drng);
	atomic_store(&drng->fully_seeded, false);
	/* Do not set force, as this flag is used for the emergency reseeding */
	atomic_store(&drng->force_reseed, false);
	atomic_store(&drng->initiated, false);
	atomic_store(&drng->reseed_pending, false);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG, "reset DRNG\n");
}

/* Initialize the DRNG, except the mutex lock */
int esdm_drng_alloc_common(struct esdm_drng *drng,
			   const struct esdm_drng_cb *drng_cb)
{
	int ret = 0;

	if (!drng || !drng_cb)
		return -EINVAL;
	if (drng->drng)
		return 0;

	drng->drng_cb = drng_cb;
	CKINT(drng_cb->drng_alloc(&drng->drng,
				  ESDM_DRNG_SECURITY_STRENGTH_BYTES));
	esdm_drng_reset(drng);

out:
	return ret;
}

static void esdm_drng_dealloc_common(struct esdm_drng *drng)
{
	const struct esdm_drng_cb *drng_cb;

	if (!drng || !drng->drng)
		return;

	/* This only works with a robust mutex */
	mutex_w_lock(&drng->lock);
	drng_cb = drng->drng_cb;
	drng_cb->drng_dealloc(drng->drng);
	drng->drng = NULL;
	mutex_w_unlock(&drng->lock);
}

DSO_PUBLIC
bool esdm_drng_mgr_terminating(void)
{
	return !!atomic_load(&esdm_drng_mgr_terminate);
}

int esdm_drng_mgr_reinitialize(void)
{
	int ret;

	CKINT(esdm_selftest_crypto());

out:
	return ret;
}

/* Initialize the default DRNG during start time and perform its seeding */
int esdm_drng_mgr_initialize(void)
{
	int ret;

	/*
	 * If the esdm_avail is not 0, either the DRNG is initialized, or the
	 * initializiation process is in progress.
	 */
	int expected = 0;

	/*
	 * There is no second life after esdm_drng_mgr_finalize(): the DRNGs are
	 * freed, the terminate flags of this and the other managers stay set,
	 * and the seeding state the ESDM goes by is the one of before. Say so
	 * rather than report success for an ESDM that cannot hand out a byte.
	 */
	if (esdm_drng_mgr_terminating())
		return -ESHUTDOWN;

	if (!atomic_compare_exchange_strong(&esdm_avail, &expected, 1))
		return 0;

	/* Before the first DRNG is seeded - and a fork() could copy it */
	pthread_once(&esdm_drng_atfork_once, esdm_drng_atfork_register);

	ret = xoshiro_init(&esdm_drng_stagger_prng);
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"no seed for the reseed stagger available (%d) - the DRNGs reseed unstaggered\n",
			ret);
	} else {
		esdm_drng_stagger_avail = true;
	}

	/* Initialize the PR DRNG inside init lock as it guards esdm_avail. */
	ret = mutex_w_init(&esdm_drng_pr.lock, 1, 0);
	if (ret)
		goto out;
	ret = esdm_drng_alloc_common(&esdm_drng_pr, esdm_default_drng_cb);
	mutex_w_unlock(&esdm_drng_pr.lock);

	if (!ret) {
		esdm_logger(LOGGER_VERBOSE, LOGGER_C_DRNG,
			    "DRNG with prediction resistance allocated\n");
		ret = mutex_w_init(&esdm_drng_init.lock, 1, 0);
		if (ret)
			goto out;
		ret = esdm_drng_alloc_common(&esdm_drng_init,
					     esdm_default_drng_cb);
		mutex_w_unlock(&esdm_drng_init.lock);
		if (!ret) {
			atomic_store(&esdm_avail, 2);
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_DRNG,
				"DRNG without prediction resistance allocated\n");
		}
	}

	CKINT(ret);

	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "ESDM for general use is available\n");

	CKINT(esdm_selftest_crypto());

out:
	if (ret) {
		esdm_drng_dealloc_common(esdm_drng_init_instance());
		esdm_drng_dealloc_common(&esdm_drng_pr);
		atomic_store(&esdm_avail, 0);
	}
	return ret;
}

void esdm_drng_mgr_finalize(void)
{
	atomic_store(&esdm_drng_mgr_terminate, 1);
	esdm_drng_dealloc_common(esdm_drng_init_instance());
	esdm_drng_dealloc_common(&esdm_drng_pr);
}

DSO_PUBLIC
int esdm_es_oversampling(void)
{
#ifndef ESDM_OVERSAMPLE_ENTROPY_SOURCES
	return false;
#else
	/* Check whether the oversampling is requested. */
	return esdm_config_sp80090c_compliant();
#endif
}

DSO_PUBLIC
int esdm_sp80090c_compliant(void)
{
	/*
	 * A build to DRG.3 applies the oversampling without claiming SP800-90C
	 * with it. DRG.4 satisfies DRG.3 and so answers esdm_drg3_compliant()
	 * too, but the two options cannot both be set - which is what makes
	 * "satisfies DRG.3 and is not DRG.4" the test for the DRG.3 option
	 * alone. A DRG.4 build applies no oversampling of its own and answers
	 * here whenever SP800-90C was configured next to it.
	 */
	if (esdm_drg3_compliant() && !esdm_drg4_compliant())
		return false;

	return esdm_es_oversampling();
}

DSO_PUBLIC
int esdm_ntg1_compliant(void)
{
	/* Implies using of /dev/random with O_SYNC */
	return true;
}

DSO_PUBLIC
int esdm_ntg1_2024_compliant(void)
{
	return
#ifdef ESDM_AIS2031_NTG1_SEEDING_STRATEGY
		true
#else
		false
#endif
		;
}

DSO_PUBLIC
int esdm_drg3_compliant(void)
{
	return
#if defined(ESDM_AIS2031_DRG3) || defined(ESDM_AIS2031_DRG4)
		true
#else
		false
#endif
		;
}

DSO_PUBLIC
int esdm_drg4_compliant(void)
{
	return
#ifdef ESDM_AIS2031_DRG4
		true
#else
		false
#endif
		;
}

/*
 * Defined with the asynchronous reseeding below - the statistics report when
 * the next reseed of a DRNG falls due, and the paths that raise a reseed
 * condition out of band tell the worker about it.
 */
static uint64_t esdm_drng_reseed_in(struct esdm_drng *drng);
static void esdm_drng_reseed_notify(void);

DSO_PUBLIC
uint32_t esdm_get_reseed_max_time(void)
{
	return atomic_load(&esdm_drng_reseed_max_time);
}

DSO_PUBLIC
void esdm_set_reseed_max_time(uint32_t seconds)
{
	uint32_t val;

	/* We allow at most 1h reseed time */
	val = min_uint32(seconds, 60 * 60);
	atomic_store(&esdm_drng_reseed_max_time, val);

	/*
	 * Log what the ESDM ended up with, not what was asked for: a request
	 * above the maximum is answered with success and silently capped, and
	 * the reseeding behaviour that follows is the one of the capped value.
	 */
	if (!val) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"Maximum reseed interval of zero seconds - every request reseeds its DRNG before it is served\n");
	} else if (val != seconds) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"Maximum reseed interval of %u seconds capped to %u seconds\n",
			seconds, val);
	} else {
		esdm_logger(LOGGER_STATUS, LOGGER_C_DRNG,
			    "Maximum reseed interval set to %u seconds\n", val);
	}

	/*
	 * A worker has nothing to do ahead of requests that reseed themselves,
	 * so a zero interval sends it home - it sees the new interval through
	 * the notify below and leaves - and any other value puts one back on
	 * duty. Before the notify: a worker started here takes the interval
	 * from the store above, and one already on duty is woken either way.
	 */
	if (val)
		esdm_drng_mgr_reseed_worker_start();

	/*
	 * The worker sleeps until the reseed it knows about falls due, which
	 * the new interval may have moved into the past.
	 */
	esdm_drng_reseed_notify();
}

/******************************* Statistics ***********************************/

/* Snapshot the state of one DRNG and hand it to the caller's callback */
static void esdm_drng_stats_one(struct esdm_drng *drng, const char *type,
				uint32_t node, bool node_valid,
				esdm_drng_stats_cb_t cb, void *priv)
{
	struct esdm_drng_stats stats;
	struct timespec now;
	long long seeded;

	if (!drng)
		return;

	stats.type = type;
	stats.pr = (drng == &esdm_drng_pr);
	stats.node = node;
	stats.node_valid = node_valid;
	/*
	 * The callbacks are installed when the DRNG is allocated - a DRNG that
	 * has not reached that point yet is reported without a name instead of
	 * being dereferenced.
	 */
	stats.drng_name = drng->drng_cb ? drng->drng_cb->drng_name() : NULL;
	stats.fully_seeded = atomic_load(&drng->fully_seeded);
	stats.force_reseed = atomic_load(&drng->force_reseed);
	stats.reseed_pending = atomic_load(&drng->reseed_pending);
	stats.initiated = atomic_load(&drng->initiated);
	stats.requests_until_reseed =
		esdm_drng_requests_left(atomic_load(&drng->requests));
	stats.requests_since_fully_seeded =
		atomic_read_u32(&drng->requests_since_fully_seeded);
	stats.bits_since_fully_seeded =
		atomic_read_u32(&drng->request_bits_since_fully_seeded);
	stats.seed_generation = atomic_load(&drng->seed_generation);
	stats.seconds_until_reseed = (long long)esdm_drng_reseed_in(drng);

	/*
	 * Both reported times come from the wall clock stamp: the monotonic one
	 * is staggered across the nodes to spread their reseeds, which would
	 * show up here as a seeding further back than it happened.
	 */
	seeded = atomic_load(&drng->last_seeded_wtime);
	stats.seeded_wtime = seeded;
	stats.seeded_wtime_valid = (seeded != 0);
	stats.seeded_time_valid = stats.seeded_wtime_valid &&
				  (clock_gettime(CLOCK_REALTIME, &now) != -1);
	stats.seconds_since_reseed =
		stats.seeded_time_valid ? ((long long)now.tv_sec - seeded) : 0;

	cb(&stats, priv);
}

void esdm_drng_stats_foreach(esdm_drng_stats_cb_t cb, void *priv)
{
	struct esdm_drng **esdm_drng;

	if (!cb)
		return;

	esdm_drng = esdm_drng_get_instances();
	if (esdm_drng) {
		/*
		 * Bound by the published count and not by the config: the
		 * latter is recomputed live and may have grown past the size
		 * the array was allocated with.
		 */
		uint32_t nodes = esdm_drng_node_count_get(), node;

		for (node = 0; node < nodes; node++) {
			struct esdm_drng *drng = esdm_drng[node];
			/*
			 * The initial DRNG serves one of the nodes as well -
			 * report it as such instead of listing it twice.
			 */
			const char *type =
				(drng == &esdm_drng_init) ? "initial" : "node";

			esdm_drng_stats_one(drng, type, node, true, cb, priv);
		}
	} else {
		esdm_drng_stats_one(&esdm_drng_init, "initial", 0, false, cb,
				    priv);
	}
	esdm_drng_put_instances();

	esdm_drng_stats_one(&esdm_drng_pr, "prediction resistance", 0, false,
			    cb, priv);
}

void esdm_drng_stats_summary(esdm_drng_stats_cb_t cb, void *priv)
{
	struct esdm_drng **esdm_drng;

	if (!cb)
		return;

	/*
	 * The initial DRNG serves a node like the others once the node array
	 * exists, and is reported the way esdm_drng_stats_foreach() reports it
	 * there, so the two agree on what they say about the same instance.
	 */
	esdm_drng = esdm_drng_get_instances();
	esdm_drng_stats_one(&esdm_drng_init, "initial", 0, esdm_drng != NULL,
			    cb, priv);
	esdm_drng_put_instances();

	esdm_drng_stats_one(&esdm_drng_pr, "prediction resistance", 0, false,
			    cb, priv);
}

int esdm_drng_stats_node(uint32_t node, esdm_drng_stats_cb_t cb, void *priv)
{
	struct esdm_drng **esdm_drng;
	struct esdm_drng *drng;
	int ret = 0;

	if (!cb)
		return -EINVAL;

	esdm_drng = esdm_drng_get_instances();
	if (!esdm_drng) {
		/*
		 * Without the array there is one instance, and it serves every
		 * node - which is what a caller asking for node 0 wants, and
		 * all a caller asking for any other node can be told.
		 */
		if (node)
			ret = -ENODEV;
		else
			esdm_drng_stats_one(&esdm_drng_init, "initial", 0,
					    false, cb, priv);
		goto out;
	}

	/* Bound by the published count - see esdm_drng_stats_foreach() */
	if (node >= esdm_drng_node_count_get()) {
		ret = -ENODEV;
		goto out;
	}

	drng = esdm_drng[node];
	if (!drng) {
		ret = -ENODEV;
		goto out;
	}

	esdm_drng_stats_one(drng,
			    (drng == &esdm_drng_init) ? "initial" : "node",
			    node, true, cb, priv);

out:
	esdm_drng_put_instances();
	return ret;
}

void esdm_drng_stats_pr(esdm_drng_stats_cb_t cb, void *priv)
{
	if (!cb)
		return;

	esdm_drng_stats_one(&esdm_drng_pr, "prediction resistance", 0, false,
			    cb, priv);
}

/************************* Random Number Generation ***************************/

/* Inject a data buffer into the DRNG - caller must hold its lock. */
static bool esdm_drng_inject(struct esdm_drng *drng, const uint8_t *inbuf,
			     size_t inbuflen, const uint8_t *addtl,
			     size_t addtllen, bool fully_seeded,
			     const char *drng_type)
{
	BUILD_BUG_ON(ESDM_DRNG_RESEED_THRESH > INT_MAX);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "seeding %s DRNG with %zu bytes\n", drng_type, inbuflen);

	if (!drng->drng)
		return false;

	/*
	 * A seed collected in this process is no less likely to repeat one of
	 * the parent's - the auxiliary pool, a block an entropy source cached,
	 * are inherited as well - and a DRNG state made unique to it cannot.
	 */
	if (esdm_drng_fork_stir_nolock(drng)) {
		atomic_store(&drng->force_reseed, true);
		return false;
	}

	if (drng->drng_cb->drng_seed(drng->drng, inbuf, inbuflen, addtl,
				     addtllen) < 0) {
		esdm_logger(LOGGER_WARN, LOGGER_C_DRNG,
			    "seeding of %s DRNG failed\n", drng_type);
		atomic_store(&drng->force_reseed, true);
		return false;
	} else {
		int gc = ESDM_DRNG_RESEED_THRESH - atomic_load(&drng->requests);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_DRNG,
			"%s DRNG stats since last seeding: %lu secs; generate calls: %d\n",
			drng_type,
			esdm_time_after_now(
				(time_t)atomic_load(&drng->last_seeded_time)),
			gc);

		/* Count the numbers of generate ops and output bits
		 * since last fully seeded. The DRNG can be configured
		 * to stop operation, if too many generate ops and/or output bits
		 * were produced, without full reseeding again.
		 */
		if (fully_seeded) {
			atomic_store(&drng->requests_since_fully_seeded, 0);
			atomic_store(&drng->request_bits_since_fully_seeded, 0);
		} else
			atomic_fetch_add(&drng->requests_since_fully_seeded, gc);

		esdm_drng_set_seeded_now(drng);
		esdm_drng_stagger_seed_time(drng);
		esdm_drng_set_seeded_wtime(drng);
		atomic_store(&drng->requests, ESDM_DRNG_RESEED_THRESH);
		atomic_store(&drng->force_reseed, false);

		/*
		 * Whatever asked the worker for this reseed has it now -
		 * whoever performed it, the worker or not. A request left
		 * pending past it would keep the next one that runs into the
		 * reseed condition from telling the worker, see
		 * esdm_drng_reseed_async(), and the DRNG would run into its
		 * limit with nobody told about it. If this seed falls short of
		 * the condition, the next request asks again.
		 */
		atomic_store(&drng->reseed_pending, false);

		if (!atomic_load(&drng->fully_seeded)) {
			atomic_store(&drng->fully_seeded, fully_seeded);
			if (atomic_load(&drng->fully_seeded)) {
				atomic_store(&drng->initiated, true);
				esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
					    "%s DRNG fully seeded\n",
					    drng_type);
			}
		}
	}

	return true;
}

/*
 * Perform the seeding of the DRNG with data from entropy source.
 * The function returns the entropy injected into the DRNG in bits.
 *
 * The caller must hold the DRNG lock.
 */
static uint32_t esdm_drng_seed_es_nolock(struct esdm_drng *drng,
					 const char *drng_type)
{
	struct entropy_buf seedbuf __aligned(ESDM_KCAPI_ALIGN),
			   addtl __aligned(ESDM_KCAPI_ALIGN),
		collected_seedbuf;
	uint32_t requested_bits, collected_entropy = 0, pass_entropy;
	unsigned int i;
	bool seeded = false, injected, reachable;
	/*
	 * Which DRNG is instantiated rather than reseeded: the PR DRNG and the
	 * DRNG of a node once, until they were fully seeded the first time -
	 * a node DRNG that reached its maximum output without full reseed is
	 * spent, not uninstantiated, and takes a reseed of the security
	 * strength like any other, see esdm_drng_node_spent(). The initial
	 * DRNG takes the instantiation whenever it is not fully seeded: once
	 * it is spent, the ESDM is out of operation and is brought back the
	 * way it came up, the initial seeding policy included - see
	 * esdm_init_ops().
	 */
	bool do_full_init = (drng == &esdm_drng_init) ?
				    !atomic_load(&drng->fully_seeded) :
				    !atomic_load(&drng->initiated);
	bool forced = atomic_load(&drng->force_reseed) | do_full_init;
	/* The PR DRNG past its initial seeding aims for RBG3(RS) */
	bool full_entropy = !do_full_init && drng == &esdm_drng_pr;
	/*
	 * The entropy behind a PR DRNG output is collected for that output
	 * (see esdm_drng_reseed_async_capable()), which a block an entropy
	 * source cached ahead of the request is not: it may have been
	 * collected long before, while the PR DRNG asks for exactly the size
	 * the caches hold. Its seeding goes to the sources themselves.
	 */
	bool allow_cached = drng != &esdm_drng_pr;

	for_each_esdm_es (i)
		collected_seedbuf.entropy_es[i].e_bits = 0;

	/*
	 * This clearing is not strictly needed, but it silences
	 * valgrind.
	 */
	memset(&seedbuf, 0, sizeof(seedbuf));
	memset(&addtl, 0, sizeof(addtl));

	do {
		if (collected_entropy) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_DRNG,
				"Force fully seeding level for %s DRNG by repeatedly pull entropy from available entropy sources\n",
				drng_type);
		}

		requested_bits =
			esdm_get_seed_entropy_osr(do_full_init, full_entropy);

		/*
		 * Get the entropy and the additional data in one pass over the
		 * entropy sources.
		 *
		 * The PR DRNG should be a RBG3(RS) if properly seeded, therefore
		 * oversample ES by 64 bit, when seeding this DRNG instance.
		 * See SP800-90C sec. 6.5.1.2.
		 */
		esdm_get_seed_buffers(&seedbuf, &addtl, requested_bits, forced,
				      allow_cached);

		pass_entropy = esdm_entropy_rate_eb(&seedbuf);
		collected_entropy += pass_entropy;

		/* Sum iterations up. */
		for_each_esdm_es (i) {
			collected_seedbuf.entropy_es[i].e_bits +=
				seedbuf.entropy_es[i].e_bits;
		}
		reachable = esdm_fully_seeded_reachable(do_full_init, &seedbuf);

		/*
		 * Inject seed data into DRNG
		 *
		 * NOTE: SP800-90C mandates that the "Get_entropy_bitstring
		 * process shall not provide output for RBG operations unless
		 * the bit string contains sufficient entropy to fulfill that
		 * request." This is achieved by the fact that the output
		 * of esdm_fully_seeded (full entropy or not) defines whether
		 * the DRBG is considered seeded at all. During start-up time
		 * the DRBG remains unseeded until sufficient entropy is
		 * provided. Although several entropy gather/seed operations
		 * can take place in this loop, it is still an atomic seeding
		 * process from the DRBG perspective as the DRBG is locked
		 * during that time and cannot produce output.
		 *
		 * The RBG3(RS) seed only counts with the oversampling it was
		 * requested with: s + 64 bits of entropy for s bits of full
		 * entropy output.
		 */
		injected = esdm_drng_inject(
			drng, (uint8_t *)&seedbuf, sizeof(seedbuf),
			(uint8_t *)&addtl, sizeof(addtl),
			esdm_fully_seeded(do_full_init, collected_entropy,
					  &collected_seedbuf) &&
				(!full_entropy ||
				 collected_entropy >= requested_bits),
			"regular");
		seeded |= injected;

		/*
		 * A seed the DRNG implementation rejected never reached the
		 * DRNG: it must neither make the ESDM operational below nor be
		 * added up with the next pass of the emergency reseeding, and
		 * its entropy is not reported as injected. The DRNG is marked
		 * for a forced reseed already.
		 */
		if (!injected) {
			collected_entropy -= pass_entropy;
			break;
		}

		/*
		 * Set the seeding state of the ESDM - which is the state of
		 * the initial DRNG, the fallback for every request: the
		 * seeding of any other DRNG must not make the ESDM operational
		 * while the initial one is not seeded.
		 */
		if (drng == &esdm_drng_init)
			esdm_init_ops(&collected_seedbuf);

		/*
	 * Emergency reseeding: If we reached the min seed threshold now
	 * multiple times but never reached fully seeded level and we collect
	 * entropy, keep doing it until we reached fully seeded level for
	 * at least one DRNG. This operation is not continued if the
	 * ES do not deliver entropy such that we cannot reach the fully seeded
	 * level, see esdm_fully_seeded_reachable().
	 *
	 * The emergency reseeding implies that the consecutively injected
	 * entropy can be added up. This is applicable due to the fact that
	 * the entire operation is atomic which means that the DRNG is not
	 * producing data while this is ongoing.
	 */
	} while (forced && !atomic_load(&drng->fully_seeded) &&
		 reachable &&
		 !atomic_load(&esdm_drng_mgr_terminate));

	/*
	 * The emergency reseeding above can inject more than once, but the
	 * DRNG is locked throughout and produces nothing in between: that is
	 * one seeding operation to the outside and hence one generation.
	 */
	if (seeded)
		atomic_fetch_add(&drng->seed_generation, 1);

	memset_secure(&seedbuf, 0, sizeof(seedbuf));
	memset_secure(&addtl, 0, sizeof(addtl));

	return collected_entropy;
}

static void esdm_drng_seed_nolock(struct esdm_drng *drng)
{
	BUILD_BUG_ON(ESDM_FULL_SEED_ENTROPY_BITS >
		     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	/* (Re-)Seed DRNG */
	esdm_drng_seed_es_nolock(drng, "regular");
}

static void esdm_drng_seed(struct esdm_drng *drng)
{
	BUILD_BUG_ON(ESDM_FULL_SEED_ENTROPY_BITS >
		     ESDM_DRNG_SECURITY_STRENGTH_BITS);

	/* (Re-)Seed DRNG */
	mutex_w_lock(&drng->lock);
	esdm_drng_seed_nolock(drng);
	mutex_w_unlock(&drng->lock);
}

static void esdm_drng_seed_work_one(struct esdm_drng *drng, uint32_t node)
{
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "reseed triggered by system events for DRNG on node %d\n",
		    node);
	esdm_drng_seed(drng);
}

/* Defined with the asynchronous reseeding below */
static bool esdm_drng_node_reseed_by_worker(struct esdm_drng *drng);

/**
 * @brief Seeding of one not yet fully seeded DRNG
 *
 * Perform the seeding of a DRNG. The code seeds one DRNG that is currently
 * not (fully) seeded. The logic picks the DRNG to be seeded.
 *
 * @param [in] force Apply the forced seeding operation.
 */
/*
 * Seed at most one DRNG that is not yet fully seeded.
 *
 * Returns true if the pass made forward progress, i.e. the selected DRNG
 * reached the fully-seeded level, or all DRNGs are already fully seeded.
 * Returns false if a DRNG that needed seeding could not be brought to the
 * fully-seeded level (insufficient entropy for the configured policy) - the
 * caller can use this to break out of a retry loop instead of spinning.
 *
 * The node array is the caller's, and so is the lock over it: this runs under
 * the pool lock, and taking the node lock here would be the one place taking
 * the two in the order opposite to every other path - see
 * esdm_drng_seed_work_locked().
 */
static bool __esdm_drng_seed_work(struct esdm_drng **esdm_drng, bool force)
{
	bool progress = false;

	/*
	 * If the DRNG is not yet initialized, return early.
	 */
	if (!esdm_get_available()) {
		return false;
	}

	if (esdm_drng) {
		uint32_t node;

		for_each_online_node (node) {
			struct esdm_drng *drng = esdm_drng[node];

			if (!drng)
				continue;

			/*
			 * Spent, but instantiated, and its reseed is the
			 * worker's: it is neither brought up here nor keeps the
			 * state that all DRNGs are seeded from being declared -
			 * see esdm_drng_node_spent(). Under sustained load some
			 * node is spent at any moment, and the declaration
			 * would never come.
			 */
			if (esdm_drng_node_reseed_by_worker(drng))
				continue;

			if (drng && !atomic_load(&drng->fully_seeded)) {
				if (force)
					atomic_store(&drng->force_reseed, true);
				esdm_drng_seed_work_one(drng, node);
				progress = atomic_load(&drng->fully_seeded);
				goto out;
			}
		}
	} else {
		if (!atomic_load(&esdm_drng_init.fully_seeded)) {
			if (force)
				atomic_store(&esdm_drng_init.force_reseed, true);
			esdm_drng_seed_work_one(&esdm_drng_init, 0);
			progress =
				atomic_load(&esdm_drng_init.fully_seeded);
			goto out;
		}
	}

	/*
	 * The PR DRNG is brought up here once - its instantiation, which takes
	 * the initial seeding policy like every other DRNG - and left alone
	 * after that: every one of its outputs is preceded by a seed collected
	 * for it in the request, see esdm_drng_get(). Seeding it again here
	 * whenever a request spent it would only drain the entropy sources
	 * for a seed that the next request replaces before using it.
	 */
	if (!atomic_load(&esdm_drng_pr.initiated)) {
		if (force)
			atomic_store(&esdm_drng_pr.force_reseed, true);
		esdm_drng_seed_work_one(&esdm_drng_pr, 0);
		progress = atomic_load(&esdm_drng_pr.initiated);
		/* The nodes are all seeded, so with this one all DRNGs are */
		if (!progress)
			goto out;
	}

	/*
	 * All DRNGs of the array this went by, that is - which is not all of
	 * them if the node array was published since it was taken. That array
	 * comes with DRNGs of its own that nobody seeded, and the state is to
	 * stay cleared for them, see esdm_drngs_node_alloc(). No progress: a
	 * caller retrying with the same view would only get here again.
	 */
	if (!esdm_drng_instances_current(esdm_drng)) {
		progress = false;
		goto out;
	}

	esdm_pool_all_nodes_seeded(true);
	progress = true;

out:
	return progress;
}

/* Defined with the asynchronous reseeding below */

/*
 * The node lock before the pool lock, which is the order of every path holding
 * both: a request generating takes the node lock in esdm_drng_get_sleep() and
 * runs into the pool lock in esdm_drng_get(), and the reseed worker holds the
 * node lock across its whole pass.
 */
static void esdm_drng_seed_work_locked(bool force)
{
	struct esdm_drng **drngs = esdm_drng_get_instances();

	esdm_pool_lock();
	__esdm_drng_seed_work(drngs, force);
	esdm_pool_unlock();
	esdm_drng_put_instances();
}

/*
 * The same for a caller that would rather do nothing than wait: a seeding is
 * already under way when the pool lock is taken, and that one collects the
 * entropy this call would have collected.
 * @return true if a seeding was performed, false if one was already running
 */
bool esdm_drng_seed_work_try(void)
{
	struct esdm_drng **drngs = esdm_drng_get_instances();

	if (!esdm_pool_trylock()) {
		esdm_drng_put_instances();
		return false;
	}

	__esdm_drng_seed_work(drngs, false);
	esdm_pool_unlock();
	esdm_drng_put_instances();

	return true;
}

/**
 * @brief Check if DRNG has to be temporarily disabled because of failed seedings
 *
 * @param [in] drng DRNG instance
 *
 * @return
 * * true request or bit limit reached
 * * false no disable condition triggered
 */
static bool esdm_drng_check_disable_threshold(struct esdm_drng *drng)
{
	bool request_limit_reached =
		atomic_read_u32(&drng->requests_since_fully_seeded) >=
		esdm_config_drng_max_wo_reseed();
	bool bit_limit_reached =
		(esdm_config_drng_max_wo_reseed_bits() != UINT32_MAX) &&
		(atomic_read_u32(&drng->request_bits_since_fully_seeded) >=
		 esdm_config_drng_max_wo_reseed_bits());

	return request_limit_reached || bit_limit_reached;
}

/*
 * Bytes @drng may still generate before it reaches its disable threshold, that
 * is without a full reseed - zero once it is there.
 */
static uint32_t esdm_drng_bytes_left(struct esdm_drng *drng)
{
	uint32_t max_bits = esdm_config_drng_max_wo_reseed_bits();
	uint32_t bits;

	if (esdm_drng_check_disable_threshold(drng))
		return 0;
	if (max_bits == UINT32_MAX)
		return UINT32_MAX;

	bits = atomic_read_u32(&drng->request_bits_since_fully_seeded);
	return (max_bits - bits) >> 3;
}

/* Has @drng reached its disable threshold? */
static bool esdm_drng_spent(struct esdm_drng *drng)
{
	return !esdm_drng_bytes_left(drng);
}

/* Defined with the asynchronous reseeding below */
static bool esdm_drng_reseed_async_capable(struct esdm_drng *drng);
static bool esdm_drng_node_spent(struct esdm_drng *drng);

/*
 * Reseed @drng, which reached its maximum output without full reseed, in the
 * caller's thread - waiting for the pool lock, in the order of every seeding.
 * Returns whether it is reseeded: told under the DRNG lock, before other
 * requests may have generated it up to its limit once more - which under load
 * they do at once, and which is no reason to give up on it.
 *
 * The reseed is forced: unforced, a seeding of a fully seeded DRNG collects
 * nothing while the entropy sources report less than a reseed needs, see
 * esdm_get_seed_buffers() - which a source caching its entropy ahead does
 * while the reseeds drain it faster than it refills. Nothing is lost by asking
 * them anyway: a DRNG that cannot be reseeded now may generate nothing at all.
 */
static bool esdm_drng_reseed_spent(struct esdm_drng *drng)
{
	bool reseeded;

	esdm_pool_lock();
	mutex_w_lock(&drng->lock);
	/* Another path may have reseeded it in the meantime */
	if (esdm_drng_spent(drng)) {
		atomic_store(&drng->force_reseed, true);
		esdm_drng_seed_nolock(drng);
	}
	reseeded = !esdm_drng_spent(drng);
	mutex_w_unlock(&drng->lock);
	esdm_pool_unlock();

	return reseeded;
}

/*
 * May @drng generate output? If it reached its disable threshold, it reverts
 * to the unseeded state and is brought up again - by a forced seeding right
 * here only if the ESDM is not operational any more, that is for the initial
 * DRNG, see esdm_drng_bring_up_for_request(). Only a full reseed resets the
 * counters, so if the DRNG is still over the threshold afterwards, it is
 * spent: nothing may be generated from it. The same holds for the ESDM as a
 * whole if the initial DRNG could not be brought back.
 *
 * The PR DRNG takes a fresh seed for each of its outputs anyway: marking just
 * this instance unseeded is enough, clearing the state that all DRNGs are
 * seeded is not warranted by it - see the end of the generate loop. Neither is
 * it for the DRNG of a node whose reseed the worker looks after, see
 * esdm_drng_node_spent().
 */
static bool esdm_drng_may_generate(struct esdm_drng *drng, bool pr)
{
	if (esdm_drng_bytes_left(drng))
		return true;

	if (pr) {
		atomic_store(&drng->fully_seeded, false);
		return true;
	}

	if (esdm_drng_reseed_async_capable(drng))
		return esdm_drng_node_spent(drng);

	/*
	 * The initial DRNG is reseeded before it is given up on, the request
	 * waiting for the pool lock. It is the DRNG every request falls back
	 * to while the node DRNGs wait for their reseeds - all the time under
	 * sustained load in a build capping the output of a seed - and the
	 * pool lock is held by their seedings just as often: skipping its
	 * reseed for a busy pool, or another request generating it up to its
	 * limit between the reseed check of this one and here, ran it dry,
	 * which takes the ESDM out of operation. Waiting costs this request one
	 * seeding; running dry costs every request until the ESDM is back. It
	 * is spent only if that reseed did not bring it back either.
	 */
	if (drng == esdm_drng_init_instance() && esdm_drng_reseed_spent(drng))
		return true;

	/*
	 * Spent - unless a seeding brought it back while this request generated
	 * up to the limit: the reseed worker's of this very DRNG, say, which
	 * kept the request from the pool lock it needed for its own reseed.
	 * Looked at again under that lock, see esdm_unset_fully_seeded_if().
	 */
	if (!esdm_unset_fully_seeded_if(drng, esdm_drng_spent))
		return true;

	return esdm_drng_bytes_left(drng) &&
	       atomic_load(&drng->fully_seeded) && esdm_state_operational();
}

/* Force all DRNGs to reseed before next generation */
DSO_PUBLIC
void esdm_drng_force_reseed(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	uint32_t node;

	/*
	 * If the initial DRNG is over the reseed threshold, allow a forced
	 * reseed only for the initial DRNG as this is the fallback for all. It
	 * must be kept seeded before all others to keep the ESDM operational.
	 */
	if (!esdm_drng || esdm_drng_check_disable_threshold(&esdm_drng_init)) {
		atomic_store(&esdm_drng_init.force_reseed,
				atomic_load(&esdm_drng_init.fully_seeded));
		esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
			    "force reseed of initial DRNG = %i\n",
			    atomic_load(&esdm_drng_init.force_reseed));
		goto out;
	}

	for_each_online_node (node) {
		struct esdm_drng *drng = esdm_drng[node];

		if (!drng)
			continue;

		atomic_store(&drng->force_reseed,
				atomic_load(&drng->fully_seeded));
		esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
			    "force reseed of DRNG on CPU %u = %i\n", node,
			    atomic_load(&drng->force_reseed));
	}

out:
	esdm_drng_put_instances();

	/*
	 * The flag alone is only seen by a request or by the worker's next
	 * pass, and the worker waits for the reseed interval rather than
	 * polling.
	 */
	esdm_drng_reseed_notify();
}

/*
 * Is the reseed interval zero seconds? That is not a deadline but the request
 * that every generate operation reseeds first - see
 * esdm_set_reseed_max_time(). Nothing is left for the worker to do ahead of a
 * request then, and nothing may be deferred to it either: a reseed that lands
 * after the request it belongs to is not the reseed that was asked for.
 */
static bool esdm_drng_reseed_per_request(void)
{
	return !atomic_load(&esdm_drng_reseed_max_time);
}

/*
 * The reseed threshold in bits generated since the last full seeding. Those
 * bits saturate at INT_MAX - see esdm_drng_get() - so a threshold above that,
 * which the build option allows, would never be reached and the bit based
 * reseed would be off without saying so. Clamped to INT_MAX like the maximum
 * output without full reseed, see esdm_config_drng_max_wo_reseed_bits().
 * UINT32_MAX stays: it disables the threshold on purpose.
 */
static uint32_t esdm_drng_reseed_thresh_bits(void)
{
	if (ESDM_DRNG_RESEED_THRESH_BITS == UINT32_MAX)
		return UINT32_MAX;

	return min_uint32(ESDM_DRNG_RESEED_THRESH_BITS, INT_MAX);
}

/*
 * Is a reseed of @drng due? The generate requests served from its seed are
 * counted by the caller once the answer is acted upon - see
 * esdm_drng_count_request() - so that the request a reseed is made for counts
 * against the new seed, and a seed serves exactly the threshold of requests.
 */
static bool esdm_drng_must_reseed(struct esdm_drng *drng)
{
	time_t check_time = (time_t)atomic_load(&drng->last_seeded_time);
	uint32_t thresh_bits = esdm_drng_reseed_thresh_bits();
	bool request_bits_since_fully_seeded_reached =
		(thresh_bits != UINT32_MAX) &&
		(atomic_read_u32(&drng->request_bits_since_fully_seeded) >=
		 thresh_bits);
	/* Negative once requests go on while a deferred reseed is pending */
	bool requests_check =
		esdm_drng_requests_left(atomic_load(&drng->requests)) <= 0;

	/* The counters are beside the point - the answer is yes every time. */
	if (esdm_drng_reseed_per_request())
		return true;

	check_time += (time_t)atomic_load(&esdm_drng_reseed_max_time);

	/*
	 * A DRNG that may generate nothing more without a full reseed is due
	 * for one whatever the threshold says. A build sets the threshold no
	 * higher than that maximum, but a test lowering the maximum at run
	 * time does not move the threshold along.
	 */
	return (requests_check || atomic_load(&drng->force_reseed) ||
		request_bits_since_fully_seeded_reached ||
		esdm_time_after_now(check_time) || esdm_drng_spent(drng));
}

/* Seconds until the reseed of @drng falls due, zero if it is due already. */
static uint64_t esdm_drng_reseed_in(struct esdm_drng *drng)
{
	uint64_t due, now;

	/* Already due - nothing to wait for */
	if (esdm_drng_must_reseed(drng))
		return 0;

	due = (uint64_t)atomic_load(&drng->last_seeded_time) +
	      atomic_load(&esdm_drng_reseed_max_time);
	now = (uint64_t)esdm_monotonic_now();

	return (due > now) ? (due - now) : 0;
}

/******************** Asynchronous reseeding of node DRNGs ********************/

/*
 * Is a reseed worker on duty? Only the thread that flips this to true spawns
 * one, and the worker clears it when it leaves.
 */
static atomic_bool esdm_drng_reseed_worker_active = false;

/*
 * Where the worker waits between its passes. A reseed request wakes it so it
 * does not sit out the interval below, and so does the shutdown request.
 */
static DECLARE_WAIT_QUEUE(esdm_drng_reseed_wait);

/* Passes the worker completed. */
static _Atomic uint64_t esdm_drng_reseed_worker_passes = 0;

/*
 * When the worker comes back to look at the DRNGs, in whole seconds on
 * CLOCK_MONOTONIC, or zero while no wait is scheduled - before the first pass
 * and after the last one.
 */
static _Atomic uint64_t esdm_drng_reseed_worker_wakeup = 0;

/* A wakeup for the worker that must not be lost. */
static atomic_bool esdm_drng_reseed_wakeup_pending = false;

/*
 * Shutdown request for the worker, separate from esdm_drng_mgr_terminate: the
 * worker has to be gone before the threads are joined, which happens while the
 * DRNGs are still operating and must not be told to stop reseeding yet.
 */
static atomic_bool esdm_drng_reseed_worker_terminate = false;

/* Is the worker to stop what it is doing and leave? */
static bool esdm_drng_reseed_stop(void)
{
	return atomic_load(&esdm_drng_mgr_terminate) ||
	       atomic_load(&esdm_drng_reseed_worker_terminate);
}

bool esdm_drng_mgr_reseed_worker_running(void)
{
	return atomic_load(&esdm_drng_reseed_worker_active);
}

uint64_t esdm_drng_mgr_reseed_worker_passes(void)
{
	return atomic_load(&esdm_drng_reseed_worker_passes);
}

bool esdm_drng_mgr_reseed_worker_next_pass(uint64_t *secs)
{
	uint64_t wakeup = atomic_load(&esdm_drng_reseed_worker_wakeup);
	uint64_t now;

	if (!wakeup || !secs)
		return false;

	now = (uint64_t)esdm_monotonic_now();
	*secs = (wakeup > now) ? (wakeup - now) : 0;

	return true;
}

void esdm_drng_mgr_reseed_worker_stop(void)
{
	atomic_store(&esdm_drng_reseed_worker_terminate, true);
	atomic_store(&esdm_drng_reseed_wakeup_pending, true);
	thread_wake_all_locked(&esdm_drng_reseed_wait);
}

/*
 * May @drng leave a due reseed to the worker and carry on generating?
 *
 * This is about deferring a reseed that a request ran into, not about the
 * worker reseeding a DRNG early - see esdm_drng_reseed_due() for that, which
 * covers the initial DRNG as well.
 *
 * Not the initial DRNG: it is the fall-back every other instance and every
 * caller lands on, so it has to hold a current seed at the moment it is asked
 * for data rather than shortly afterwards. Deferring its reseed would also
 * defer the point at which it goes non-operational, which is what takes the
 * whole ESDM down.
 *
 * Not the PR DRNG either: its contract is that the entropy behind a request was
 * collected for that request, which an out-of-band reseed cannot express. Its
 * generate path seeds itself under its own lock for every output and never
 * comes through here - and for the same reason the worker leaves it alone
 * altogether, see esdm_drng_reseed_pass().
 *
 * With node support built out there is nothing left to defer: every request
 * lands on the initial DRNG. That is not a loss of throughput but the absence
 * of the thing that buys it - one DRNG cannot serve data and wait for its own
 * reseed at the same time, and deferring the reseed only moves it past the
 * maximum it may produce without one, at which point it leaves the fully
 * seeded state and takes the ESDM out of operation with it. The worker still
 * runs there, reseeding that one DRNG before a request runs into its interval.
 */
static bool esdm_drng_reseed_async_capable(struct esdm_drng *drng)
{
	return (!esdm_drng_reseed_per_request() &&
		drng != esdm_drng_init_instance() && drng != &esdm_drng_pr);
}

/* Has the reseed of @drng fallen due without a request asking for one? */
static bool esdm_drng_reseed_due(struct esdm_drng *drng)
{
	if (esdm_drng_reseed_per_request())
		return false;

	return atomic_load(&drng->fully_seeded) && esdm_drng_must_reseed(drng);
}

/* Collect entropy for @drng and inject it */
static void esdm_drng_reseed_one(struct esdm_drng *drng, uint32_t node,
				 bool requested)
{
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "%s reseed of DRNG on node %u\n",
		    requested ? "asynchronous" : "proactive", node);

	/*
	 * Pool lock before DRNG lock, the order the generate path and the ES
	 * monitor use.
	 */
	esdm_pool_lock();
	mutex_w_lock(&drng->lock);
	/* Another path may have reseeded it in the meantime */
	if (esdm_drng_must_reseed(drng))
		esdm_drng_seed_nolock(drng);
	mutex_w_unlock(&drng->lock);
	esdm_pool_unlock();
}

/*
 * Seed @drng, which is not fully seeded: a DRNG not instantiated yet, which
 * takes the initial seeding policy, or a spent node DRNG, which takes a reseed
 * - see esdm_drng_seed_es_nolock(). The emergency reseeding is forced, as the
 * DRNG serves no request before it is fully seeded.
 */
static void esdm_drng_reseed_bring_up(struct esdm_drng *drng, uint32_t node)
{
	esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
		    "bringing up DRNG on node %u\n", node);

	/* The order of esdm_drng_reseed_one() */
	esdm_pool_lock();
	mutex_w_lock(&drng->lock);
	/* Another path may have seeded it in the meantime */
	if (!atomic_load(&drng->fully_seeded)) {
		atomic_store(&drng->force_reseed, true);
		esdm_drng_seed_nolock(drng);
	}
	mutex_w_unlock(&drng->lock);
	esdm_pool_unlock();
}

/*
 * Is @drng a node DRNG that is spent - instantiated, but not fully seeded any
 * more - whose reseed the worker looks after? See esdm_drng_node_spent().
 */
static bool esdm_drng_node_reseed_by_worker(struct esdm_drng *drng)
{
	return esdm_drng_reseed_async_capable(drng) &&
	       atomic_load(&drng->initiated) &&
	       !atomic_load(&drng->fully_seeded) &&
	       esdm_drng_mgr_reseed_worker_running();
}

/*
 * Node the next pass of the worker starts at, see esdm_drng_reseed_pass(). Only
 * the worker uses it - atomic as two of them may overlap for the moment of a
 * handover.
 */
static _Atomic uint32_t esdm_drng_reseed_rotor = 0;

/* Fold the deadline of @drng into the earliest one seen in this pass. */
static void esdm_drng_reseed_next(struct esdm_drng *drng, uint64_t *next)
{
	uint64_t in;

	/* Due on every request, which is not a deadline the worker keeps */
	if (esdm_drng_reseed_per_request())
		return;

	in = esdm_drng_reseed_in(drng);

	if (in < *next)
		*next = in;
}

/*
 * Reseed every DRNG that asked for it, plus every one whose reseed fell due on
 * its own, and bring up every one that is not fully seeded.
 */
static uint64_t esdm_drng_reseed_pass(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	/* Bound by the published array size - see esdm_drng_get_sleep() */
	uint32_t num_nodes = min_uint32(esdm_config_online_nodes(),
					esdm_drng_node_count_get());
	/* A DRNG of the array is left not fully seeded after this pass */
	bool unseeded = false;
	uint64_t next = UINT64_MAX;
	uint32_t node, i, start;

	/*
	 * Without per-node DRNGs the initial DRNG is the only one to look at.
	 */
	if (!esdm_drng) {
		if (!esdm_drng_reseed_stop() &&
		    esdm_drng_reseed_due(&esdm_drng_init))
			esdm_drng_reseed_one(&esdm_drng_init, 0, false);

		if (atomic_load(&esdm_drng_init.fully_seeded))
			esdm_drng_reseed_next(&esdm_drng_init, &next);
	} else if (num_nodes) {
		/*
		 * Each pass starts at the node after the one the last pass
		 * started at. The DRNGs are seeded one after the other, each
		 * waiting for the pool lock, and a pass may be cut short: no
		 * node is to wait behind the same others every time, nor be
		 * the one a shortage of entropy always hits first.
		 */
		start = atomic_fetch_add(&esdm_drng_reseed_rotor, 1) %
			num_nodes;

		for (i = 0; i < num_nodes; i++) {
			struct esdm_drng *drng;
			bool requested;

			node = (start + i) % num_nodes;
			drng = esdm_drng[node];

			if (esdm_drng_reseed_stop())
				break;

			if (!drng)
				continue;

			/*
			 * A DRNG that is not fully seeded serves no request -
			 * it was never seeded, or it is a node DRNG that
			 * reached its maximum output without full reseed, see
			 * esdm_drng_node_spent(). Every one of them is seeded
			 * in this pass rather than one per pass: under
			 * sustained load in a build capping the output of a
			 * seed, a node DRNG is spent within microseconds of
			 * the reseed it asked for, and one brought back per
			 * pass leaves the others out of service for a pass
			 * each.
			 *
			 * Up to the first one that could not be brought up:
			 * the entropy sources would let the others down as
			 * well, and every further attempt only drains them.
			 * The next pass starts elsewhere, and follows soon.
			 */
			if (!atomic_load(&drng->fully_seeded)) {
				if (!unseeded)
					esdm_drng_reseed_bring_up(drng, node);
				if (!atomic_load(&drng->fully_seeded)) {
					unseeded = true;
					continue;
				}
			} else {
				/*
				 * Take a deferred request off the DRNG before
				 * servicing it
				 */
				requested =
					esdm_drng_reseed_async_capable(drng) &&
					atomic_exchange(&drng->reseed_pending,
							false);

				if (requested || esdm_drng_reseed_due(drng))
					esdm_drng_reseed_one(drng, node,
							     requested);
			}

			esdm_drng_reseed_next(drng, &next);
		}
	}

	/*
	 * The PR DRNG and - without the node array - the initial DRNG are not
	 * part of the loop above, and neither is a state that all DRNGs are
	 * seeded that went missing while each of them is: the requests and
	 * esdm_get_seed() leave all of that to the worker as well, see
	 * esdm_drng_bring_up_for_request(). A DRNG of the array the loop could
	 * not bring up is left to the next pass: this would only try it again.
	 */
	if (!unseeded && !esdm_pool_all_nodes_seeded_get() &&
	    !esdm_drng_reseed_stop()) {
		/*
		 * The node lock is held across the whole pass, so the pool lock
		 * is taken under it here - the order of
		 * esdm_drng_seed_work_locked().
		 */
		esdm_pool_lock();
		__esdm_drng_seed_work(esdm_drng, true);
		esdm_pool_unlock();

		if (!esdm_pool_all_nodes_seeded_get())
			unseeded = true;
	}

	/*
	 * An instance that could not be brought up for want of entropy stays
	 * where it is - there is work left, so the next pass follows as soon
	 * as the worker allows rather than at the next reseed deadline.
	 */
	if (unseeded)
		next = 0;

	/*
	 * The prediction resistance DRNG is not looked after at all, and its
	 * deadline is no reason to come back either: each of its outputs is
	 * generated from a seed that request collected, so a seed put in here
	 * would be replaced before it is used - or worse, if the request found
	 * it and went with it, deliver output from entropy collected for no
	 * request at all, up to a whole reseed interval earlier. What it needs
	 * before its first request, its instantiation, is part of the bring-up
	 * above.
	 */

	esdm_drng_put_instances();

	return next;
}

/* Upper bound of the wait between two passes. */
#define ESDM_DRNG_RESEED_PASS_MAX_SEC 20

/* Wait after a pass that reports work of its own left */
#define ESDM_DRNG_RESEED_PASS_BUSY_SEC 1

/* Is there a reason for the worker to end its wait between two passes? */
static bool esdm_drng_reseed_wakeup_due(void *unused)
{
	(void)unused;

	return atomic_load(&esdm_drng_reseed_wakeup_pending) ||
	       esdm_drng_reseed_stop();
}

/*
 * Look after the DRNGs pass by pass, until the worker is to leave: a stop
 * request, the DRNG manager terminating, or a reseed interval of zero seconds,
 * which hands the reseeding to the requests themselves.
 */
static void esdm_drng_reseed_worker_run(void)
{
	while (!esdm_drng_reseed_stop() && !esdm_drng_reseed_per_request()) {
		uint64_t next, max_wait;
		uint32_t interval;
		struct timespec deadline;
		int ret;

		/*
		 * Taken down before the pass, so a wakeup raised while it runs
		 * is kept rather than cleared by the pass it arrived during.
		 */
		atomic_store(&esdm_drng_reseed_wakeup_pending, false);

		next = esdm_drng_reseed_pass();
		atomic_fetch_add(&esdm_drng_reseed_worker_passes, 1);

		if (esdm_drng_reseed_stop())
			break;

		/*
		 * The reseed interval as it stands now, not as the pass found
		 * it: a shortened interval moves every deadline the pass
		 * computed forward, and the worker must not sit past the whole
		 * of the new interval waiting for a deadline of the old one.
		 * An interval of zero seconds is no deadline at all - the
		 * requests reseed themselves - so the worker keeps its own
		 * bound there.
		 */
		interval = atomic_load(&esdm_drng_reseed_max_time);
		max_wait = interval ? min_uint32(ESDM_DRNG_RESEED_PASS_MAX_SEC,
						 interval) :
				      ESDM_DRNG_RESEED_PASS_MAX_SEC;

		if (next > max_wait)
			next = max_wait;

		/*
		 * A pass that has work left - an instance that could not be
		 * brought up for want of entropy, a reseed that did not take -
		 * reports no wait at all. It is repeated a second later rather
		 * than at once: nothing it waits for arrives in no time, and a
		 * wait of zero seconds is not a wait but a spin.
		 */
		if (!next)
			next = ESDM_DRNG_RESEED_PASS_BUSY_SEC;

		atomic_store(&esdm_drng_reseed_worker_wakeup,
			     (uint64_t)esdm_monotonic_now() + next);

		esdm_logger(LOGGER_DEBUG, LOGGER_C_DRNG,
			    "next reseed worker pass in %" PRIu64 " seconds\n",
			    next);

		/*
		 * Bounded wait on a wakeup that was raised before its signal,
		 * so one delivered while the pass above ran ends the wait here
		 * instead of being lost. One raised while the worker is on its
		 * way into the wait is not lost either: the flag is checked
		 * under the lock of the queue and the signal sent under it -
		 * see esdm_drng_reseed_notify() - so it is either seen by the
		 * check or reaches a worker blocked in the wait. The loop
		 * covers a spurious wakeup.
		 */
		clock_gettime(CLOCK_MONOTONIC, &deadline);
		deadline.tv_sec += (time_t)next;
		do {
			ret = thread_wait_queue_wait_pred(
				&esdm_drng_reseed_wait, &deadline,
				esdm_drng_reseed_wakeup_due, NULL);
		} while (!ret && !esdm_drng_reseed_wakeup_due(NULL));
	}
}

/*
 * The worker left duty, and the node DRNGs it would have reseeded - spent, see
 * esdm_drng_node_spent() - go the way of DRNGs that are not seeded: the state
 * that all DRNGs are seeded goes, and with it the bring-up by the requests and
 * by the arrival of entropy takes over. Called after the duty was handed back,
 * so a request marking a DRNG spent from here on sees no worker and does the
 * same itself.
 */
static void esdm_drng_reseed_hand_back(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	/* Bound by the published array size - see esdm_drng_get_sleep() */
	uint32_t num_nodes = min_uint32(esdm_config_online_nodes(),
					esdm_drng_node_count_get());
	bool spent = false;
	uint32_t node;

	if (esdm_drng) {
		for (node = 0; node < num_nodes; node++) {
			struct esdm_drng *drng = esdm_drng[node];

			if (drng && !atomic_load(&drng->fully_seeded))
				spent = true;
		}
	}

	/* Under the pool lock, see esdm_unset_fully_seeded_if() */
	if (spent) {
		esdm_pool_lock();
		esdm_pool_all_nodes_seeded(false);
		esdm_pool_unlock();
	}

	esdm_drng_put_instances();
}

static int esdm_drng_reseed_worker(void *unused)
{
	bool handed_over = false;
	const char *reason;

	(void)unused;

	thread_set_name(drng_reseed, 0);

	/*
	 * The worker stays for the lifetime of the DRNG manager rather than
	 * leaving once nothing is pending: it is the thread that notices a
	 * reseed falling due without anybody asking for it, and no request can
	 * announce that moment. A reseed interval of zero seconds is the one
	 * thing that sends it home early - the requests reseed themselves then
	 * - and esdm_set_reseed_max_time() puts one back on duty when the
	 * interval grows again.
	 */
	do {
		esdm_drng_reseed_worker_run();

		/*
		 * The duty is handed back here, which is what lets a start
		 * spawn a successor. One that arrived just before this store
		 * saw this worker as active and spawned none - and if the
		 * interval it set asks for a worker, this one takes the duty
		 * back rather than leaving with nobody on it.
		 */
		atomic_store(&esdm_drng_reseed_worker_wakeup, 0);
		atomic_store(&esdm_drng_reseed_worker_active, false);
		esdm_drng_reseed_hand_back();

		if (esdm_drng_reseed_stop() || esdm_drng_reseed_per_request())
			break;

		handed_over =
			atomic_exchange(&esdm_drng_reseed_worker_active, true);
	} while (!handed_over);

	if (handed_over)
		reason = "another worker took the duty over";
	else if (atomic_load(&esdm_drng_reseed_worker_terminate))
		reason = "stop request";
	else if (atomic_load(&esdm_drng_mgr_terminate))
		reason = "DRNG manager terminating";
	else
		reason = "reseed interval of zero seconds";

	/*
	 * The worker is the thread that reseeds the DRNGs without being asked,
	 * so its departure is the moment that stops: from here on a DRNG is
	 * only reseeded when a request runs into its reseed condition.
	 */
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_DRNG,
		    "DRNG reseed worker leaves after %" PRIu64 " passes (%s)\n",
		    atomic_load(&esdm_drng_reseed_worker_passes), reason);

	return 0;
}

/*
 * In the child of fork(), only the thread that called it lives on, and none of
 * the ESDM's own - the reseed worker among them. The child starts a new
 * generation, so every DRNG is made unique to it before it is used again, see
 * esdm_drng_fork_stir_nolock(), and it is told that it has no worker: one it
 * believed on duty would be handed the reseeds of the node DRNGs, which nobody
 * would ever perform. Atomic stores only, as nothing else is safe here.
 */
static void esdm_drng_atfork_child(void)
{
	atomic_fetch_add(&esdm_drng_fork_gen, 1);
	atomic_store(&esdm_drng_reseed_worker_active, false);
	atomic_store(&esdm_drng_reseed_worker_wakeup, 0);
}

static void esdm_drng_atfork_register(void)
{
	if (pthread_atfork(NULL, NULL, esdm_drng_atfork_child)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"cannot install the fork handler - the child of a fork() hands out the random numbers of its parent until its DRNGs reseed\n");
	}
}

/*
 * Put the worker on duty. Called once while the ESDM is brought up - see
 * esdm_init_monitor() - rather than from the paths that have something for the
 * worker to do: those only tell it, which costs an atomic store and a signal
 * and needs no answer to the question whether a worker exists yet.
 */
bool esdm_drng_mgr_reseed_worker_start(void)
{
	if (esdm_drng_reseed_stop())
		return false;

	/*
	 * Not in the child of a fork(): the slots of the thread pool still tell
	 * of the parent's threads there, and a worker scheduled into one would
	 * never run. The requests reseed the DRNGs themselves in the child.
	 */
	if (atomic_load(&esdm_drng_fork_gen))
		return false;

	/* Nothing to do ahead of requests that reseed themselves */
	if (esdm_drng_reseed_per_request())
		return false;

	if (atomic_load(&esdm_drng_reseed_worker_active))
		return true;

	/*
	 * No thread pool in this process - a library user that never called
	 * thread_init() and never went through esdm_init_monitor(), which sets
	 * one up. There is no worker to be had.
	 */
	if (!thread_available())
		return false;

	if (atomic_exchange(&esdm_drng_reseed_worker_active, true))
		return true;

	if (thread_start(esdm_drng_reseed_worker, NULL, ESDM_THREAD_DRNG_RESEED,
			 NULL)) {
		/*
		 * No worker slot free. The generate path then reseeds each
		 * DRNG itself when a request runs into its reseed condition.
		 */
		atomic_store(&esdm_drng_reseed_worker_active, false);
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"No worker available for the DRNG reseeding - the DRNGs are only reseeded when a request runs into their reseed condition\n");
		return false;
	}

	return true;
}

/* Tell the worker to look at the DRNGs now instead of after its wait. */
static void esdm_drng_reseed_notify(void)
{
	/*
	 * Before the signal, and the signal under the lock of the queue, so a
	 * worker on its way into the wait sees this - see
	 * esdm_drng_reseed_worker_run().
	 */
	atomic_store(&esdm_drng_reseed_wakeup_pending, true);
	thread_wake_all_locked(&esdm_drng_reseed_wait);
}

/*
 * Hand the reseed of @drng to the worker and return at once. The caller keeps
 * generating from the DRNG until the reseed lands, or until the DRNG runs into
 * the configured maximum without a full reseed - which the generate path
 * enforces on its own and which no deferral relaxes.
 *
 * Returns false if there is no worker to hand the reseed to: the caller then
 * has to reseed the DRNG itself, or nothing ever would.
 */
static bool esdm_drng_reseed_async(struct esdm_drng *drng)
{
	/*
	 * The reseed condition holds on every loop iteration until the worker
	 * lands, so only the first of them queues the DRNG and looks at the
	 * worker.
	 */
	if (atomic_exchange(&drng->reseed_pending, true))
		return true;

	/*
	 * Nobody to service the request - do not leave it queued, or the DRNG
	 * would never ask again and never be reseeded out of band.
	 */
	if (!esdm_drng_mgr_reseed_worker_running()) {
		atomic_store(&drng->reseed_pending, false);
		return false;
	}

	esdm_drng_reseed_notify();

	return true;
}

/*
 * A node DRNG whose reseed is left to the worker reached its maximum output
 * without full reseed - which, in a build capping it at 2^17 bits, sustained
 * load makes it do all the time: the headroom between the reseed threshold and
 * the cap lasts a few microseconds of generation, and the reseed it asked for
 * takes milliseconds of entropy collection.
 *
 * It leaves the fully seeded state, so the requests go to another DRNG until
 * it is reseeded, and nothing is generated from it before - the bound above
 * holds for it as for any other. But nothing else changes: it is a DRNG that
 * needs its reseed now, not one that was never instantiated. The state that
 * all DRNGs are seeded stays, esdm_get_seed() keeps serving, the reseed on
 * entropy arrival and the initial seeding policy stay out of it, and the
 * worker reseeds it with the security strength like any other reseed - see
 * esdm_drng_seed_es_nolock(). The worker is told every time a request finds
 * it spent, which is the only way it learns about it in time.
 *
 * Decided under the DRNG lock, which a seeding of it holds throughout: a
 * reseed that lands meanwhile is seen, and the DRNG is not taken out of service
 * on what a request found before it. Not the pool lock - every seeding of any
 * DRNG holds that one, and a request would wait for all of them.
 *
 * Without a worker on duty, there is nobody to reseed it: then the DRNG goes
 * the way of one that is not seeded, see esdm_unset_fully_seeded_if(). The
 * check of the worker comes after the DRNG is marked, and the worker checks the
 * DRNGs after it left duty, see esdm_drng_reseed_worker(): one of the two
 * sees the other, and the DRNG is not left behind by both.
 *
 * @return true if @drng may generate - it was reseeded meanwhile
 */
static bool esdm_drng_node_spent(struct esdm_drng *drng)
{
	bool spent;

	mutex_w_lock(&drng->lock);
	spent = esdm_drng_spent(drng);
	if (spent)
		atomic_store(&drng->fully_seeded, false);
	mutex_w_unlock(&drng->lock);

	if (!spent)
		return true;

	if (!esdm_drng_mgr_reseed_worker_running()) {
		if (!esdm_unset_fully_seeded_if(drng, esdm_drng_spent))
			return true;
		return esdm_drng_bytes_left(drng) &&
		       atomic_load(&drng->fully_seeded);
	}

	esdm_drng_reseed_notify();

	return false;
}

/**
 * @brief Get random data out of the DRNG which is reseeded frequently.
 *
 * @param [in] drng DRNG instance
 * @param [in] outbuf buffer for storing random data
 * @param [in] outbuflen length of outbuf
 *
 * @return
 * * < 0 in error case (DRNG generation or update failed)
 * * >=0 returning the returned number of bytes
 */
static ssize_t esdm_drng_get(struct esdm_drng *drng, uint8_t *outbuf,
			     size_t outbuflen)
{
	/* produce max. 128 Byte in pr mode without yielding */
	const size_t pr_yield_iterations =
		128 / (esdm_security_strength() >> 3);
	/* should be greater than 1 for speedup */
	assert(pr_yield_iterations > 1);
	ssize_t processed = 0;
	size_t iterations = 0;
	bool pr = (drng == &esdm_drng_pr) ? true : false;
	/* The DRNG was reseeded for the first block below already */
	bool reseeded = false;

	if (!outbuf || !outbuflen)
		return 0;

	if (!esdm_get_available() || !esdm_state_operational())
		return -EOPNOTSUPP;

	/*
	 * No bits are handed out unless the crypto implementations producing
	 * them are known to work: neither before the self tests ran nor after
	 * one of them failed.
	 */
	if (!esdm_selftest_crypto_passed())
		return -EOPNOTSUPP;

	/*
	 * The periodic self tests are started on the way past: a process that
	 * produces random bits is one that has to keep verifying the
	 * implementation producing them, whether or not it ever set the ESDM up
	 * with esdm_init_monitor().
	 */
	esdm_selftest_periodic_start();

	outbuflen = min_size(outbuflen, SSIZE_MAX);

	/*
	 * try to reseed the last resort DRNG in a multi node setup
	 * before unsetting the fully seeded state in the next check.
	 *
	 * This helps to get low but consistent performance when
	 * operating in DRG.4 mode on request bursts
	 * (e.g. in esdm-tool --benchmark).
	 */
	if (drng == esdm_drng_init_instance()) {
		if (esdm_drng_must_reseed(drng)) {
			esdm_pool_lock();

			mutex_w_lock(&drng->lock);
			/* double check, as we did not lock the DRNG in the first check*/
			if (esdm_drng_must_reseed(drng)) {
				esdm_drng_seed_nolock(drng);
				reseeded = true;
			}
			mutex_w_unlock(&drng->lock);

			esdm_pool_unlock();
		}
	}

	/* Loop to collect random bits for the caller. */
	while (outbuflen) {
		/* Compared as size_t, a cast first wraps requests of 4 GiB */
		uint32_t todo =
			(uint32_t)min_size(outbuflen, ESDM_DRNG_MAX_REQSIZE);
		ssize_t ret;

		/*
		 * In normal operation, check whether to reseed - unless that
		 * happened just above: with a reseed interval of zero seconds
		 * the check says yes every time, and the first block would
		 * otherwise be generated after two seedings in a row.
		 */
		if (!pr && !reseeded && esdm_drng_must_reseed(drng)) {
			/*
			 * With a reseed interval of zero seconds every block
			 * is generated from a seed collected for it, so the
			 * reseed is neither handed to the worker nor skipped
			 * for a busy pool: the request waits for the pool lock
			 * instead. Read once, the lock below is taken by
			 * exactly one of the two branches.
			 */
			bool per_request = esdm_drng_reseed_per_request();

			if (esdm_drng_reseed_async_capable(drng) &&
			    esdm_drng_reseed_async(drng)) {
				/*
				 * Hand the entropy collection to the worker and
				 * keep generating. Under SP800-90C / AIS 20/31
				 * DRG.4 the reseed threshold sits at three
				 * quarters of the maximum number of bits allowed
				 * without a full reseed, so a quarter of it is
				 * left to cover the collection - and
				 * where it does not, the DRNG leaves the fully
				 * seeded state below and the request moves to
				 * another node instead of waiting here.
				 *
				 * Without a worker the DRNG is reseeded right
				 * here, like one that cannot defer.
				 */
			} else if (!per_request && !esdm_pool_trylock()) {
				/*
				 * Entropy pool cannot be locked, try to reseed
				 * next time, but continue to generate random
				 * bits.
				 */
				mutex_w_lock(&drng->lock);
				atomic_store(&drng->force_reseed, true);
				mutex_w_unlock(&drng->lock);
			} else { /* Perform synchronous reseed */
				if (per_request)
					esdm_pool_lock();
				mutex_w_lock(&drng->lock);
				/* double check, as we did not lock the DRNG in the first check*/
				if (esdm_drng_must_reseed(drng)) {
					esdm_drng_seed_nolock(drng);
				}
				mutex_w_unlock(&drng->lock);
				esdm_pool_unlock();
			}
		}

		/*
		 * If the DRNG ran without full reseed for too long, revert to
		 * the unseeded state and stop generating from it.
		 *
		 * Note a reseed requested by drng->force_reseed or
		 * esdm_drng_seed() does not imply that sufficient entropy was
		 * received to fill the DRNG. If this state persists, then this
		 * check applies - for every block, not once per request: the
		 * reseed above may be handed to the worker, be skipped for a
		 * busy pool or deliver less than full entropy, while a single
		 * request can be large enough to pass the threshold several
		 * times over.
		 */
		if (!esdm_drng_may_generate(drng, pr)) {
			esdm_logger(
				LOGGER_DEBUG, LOGGER_C_DRNG,
				"DRNG reached its maximum output without full reseed\n");
			/*
			 * Hand out what was generated so far. The DRNG is no
			 * longer fully seeded, so the next request moves to
			 * another node - and with nothing generated, so does
			 * this one, see esdm_drng_get_sleep(). If the initial
			 * DRNG is spent, the ESDM is not operational any more.
			 */
			if (processed)
				return processed;
			return (drng == esdm_drng_init_instance()) ?
				       -EOPNOTSUPP :
				       -EAGAIN;
		}

		mutex_w_lock(&drng->lock);

		if (!pr) {
			/*
			 * Generate no more than the threshold leaves. The check
			 * runs under the DRNG lock the output is accounted
			 * under below, so concurrent requests cannot pass the
			 * threshold together. Back to the check above if they
			 * used up what was left in the meantime.
			 */
			uint32_t left = esdm_drng_bytes_left(drng);

			if (!left) {
				mutex_w_unlock(&drng->lock);
				continue;
			}
			todo = min_uint32(todo, left);

			/*
			 * This block is generated from whatever seed the DRNG
			 * has now
			 */
			esdm_drng_count_request(drng);
		}

		/*
		 * Handle prediction resistance requests.
		 *
		 * Note, as we do not reseed before the generate call, it
		 * implies that this code path is only truly producing
		 * prediction resistance bits following the definition of
		 * SP800-90A with a separate DRBG instance that is dedicated to
		 * the PR operation. A DRBG instance that would be both used for
		 * non-PR and PR behavior would not comply with the definition
		 * of SP800-90A.
		 */
		if (pr) {
			uint32_t collected_ent_bits;

			/*
			 * Every block is preceded by a seed collected for it,
			 * whatever the DRNG holds already: a seed found in place
			 * was not collected for this request - it may be the
			 * one the DRNG was instantiated with at start up - and
			 * output from it would not be what this DRNG promises.
			 *
			 * If we cannot get the pool lock, try again.
			 */
			if (!esdm_pool_trylock()) {
				mutex_w_unlock(&drng->lock);
				/*
				 * Yield before retrying: another thread holds
				 * the pool lock only briefly, so do not
				 * hot-spin on drng->lock/pool-lock churn while
				 * waiting for it.
				 */
				sched_yield();
				continue;
			}

			collected_ent_bits =
				esdm_drng_seed_es_nolock(drng, "regular");

			esdm_pool_unlock();

			/*
			 * Not instantiated yet, the seeding above was the
			 * instantiation, and it fell short of the initial
			 * seeding policy: whatever entropy it collected, the
			 * DRNG has not got the initial seed its output rests
			 * on. Nothing from it, as with too little entropy below.
			 */
			if (!atomic_load(&drng->initiated)) {
				mutex_w_unlock(&drng->lock);
				goto out;
			}

			/*
			 * Cap output to the freshly collected entropy, less
			 * the 64 bits RBG3(RS) keeps back for full entropy
			 * output, see SP800-90C sec. 6.5.1.2.
			 */
			collected_ent_bits -= min_uint32(collected_ent_bits,
							 esdm_compress_osr());

			/*
			 * If less than a full byte of fresh entropy was
			 * received, stop now: otherwise todo would be capped
			 * to 0, drng_generate(0) fails, and the bytes already
			 * produced in earlier iterations would be discarded as
			 * -EFAULT.
			 */
			if (!(collected_ent_bits >> 3)) {
				mutex_w_unlock(&drng->lock);
				goto out;
			}

			todo = min_uint32(todo, collected_ent_bits >> 3);

			/* Do not produce more than DRNG security strength. */
			todo = min_uint32(todo, esdm_security_strength() >> 3);
		}

		/*
		 * Guard against a concurrent esdm_drng_mgr_finalize(), which
		 * deallocates drng->drng and NULLs it under drng->lock without
		 * clearing esdm_avail. Without this check the generate below
		 * would dereference a NULL DRNG state on the shutdown path.
		 */
		if (!drng->drng) {
			mutex_w_unlock(&drng->lock);
			return processed ? processed : -EOPNOTSUPP;
		}

		/* Nothing from a state the parent of a fork() holds as well */
		if (esdm_drng_fork_stir_nolock(drng)) {
			mutex_w_unlock(&drng->lock);
			return processed ? processed : -EFAULT;
		}

		/* Now, generate random bits from the properly seeded DRNG. */
		ret = drng->drng_cb->drng_generate(drng->drng,
						   outbuf + processed, todo);
		if (ret <= 0) {
			mutex_w_unlock(&drng->lock);
			esdm_logger(
				LOGGER_WARN, LOGGER_C_DRNG,
				"getting random data from DRNG failed (%zd)\n",
				ret);
			return -EFAULT;
		}
		/*
		 * Saturate at INT_MAX so the counter cannot wrap to a negative
		 * value: it is only reset on a full-entropy reseed, so with a
		 * finite reseed threshold but disabled max-reseed it would
		 * otherwise grow without bound. atomic_read_u32() already reads
		 * it unsigned, so a saturated value still forces a reseed. The
		 * overflow test runs in unsigned arithmetic: old + delta as a
		 * signed int would be undefined behavior at exactly the
		 * saturation point this check exists to catch.
		 *
		 * Accounted under the DRNG lock - see the threshold check
		 * above.
		 */
		if (((unsigned int)atomic_fetch_add(
			     &drng->request_bits_since_fully_seeded,
			     (int)ret << 3) +
		     ((unsigned int)ret << 3)) > INT_MAX)
			atomic_store(&drng->request_bits_since_fully_seeded,
				   INT_MAX);
		mutex_w_unlock(&drng->lock);
		processed += ret;
		outbuflen -= (size_t)ret;
		reseeded = false;

		if (pr) {
			/*
			 * Each output of the PR DRNG takes a fresh seed, which
			 * the next one collects above. Only this instance is
			 * marked: esdm_unset_fully_seeded() would also clear
			 * the state that all DRNGs are seeded, which says
			 * nothing about this one being spent on purpose, and
			 * esdm_get_seed(), the reseed on entropy arrival and
			 * the initial oversampling key off that state.
			 */
			atomic_store(&drng->fully_seeded, false);
			if (outbuflen &&
			    iterations++ % pr_yield_iterations == 0)
				sched_yield();
		}
	}

out:
	return processed;
}

static ssize_t esdm_drng_get_sleep(uint8_t *outbuf, size_t outbuflen, bool pr)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	struct esdm_drng *drng = &esdm_drng_init;
	/*
	 * Bound by the published array size, not only the live config:
	 * raising max_nodes via the public API after allocation grows
	 * esdm_config_online_nodes() but never the array.
	 */
	uint32_t num_nodes = min_uint32(esdm_config_online_nodes(),
					esdm_drng_node_count_get());
	uint32_t node = esdm_config_curr_node();
	bool found_drng = false;
	ssize_t ret;
	uint32_t i;
	uint32_t j;

	if (pr) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_DRNG,
			"Using prediction resistance DRNG instance to service generate request\n");
		drng = &esdm_drng_pr;
		found_drng = true;
	}

	if (!found_drng && esdm_drng) {
		for (i = 0; i < num_nodes; ++i) {
			/* every node starts probing at different offsets */
			j = ((uint32_t)i + node) % num_nodes;
			/* always try node 0 (init drng) last, as it can disable the operational state */
			if (j == 0)
				continue;
			if (esdm_drng[j] &&
			    mutex_w_trylock(&esdm_drng[j]->lock) == 0) {
				bool seeded =
					atomic_load(&esdm_drng[j]->fully_seeded);

				mutex_w_unlock(&esdm_drng[j]->lock);
				if (!seeded)
					continue;
				found_drng = true;
				drng = esdm_drng[j];
				esdm_logger(
					LOGGER_DEBUG, LOGGER_C_DRNG,
					"Using DRNG instance on node %u to service generate request\n",
					j);
				break;
			}
		}
	}

	if (!found_drng) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_DRNG,
			"Using DRNG instance on node 0 to service generate request\n");
	}

	ret = esdm_drng_get(drng, outbuf, outbuflen);

	/*
	 * A node DRNG that reached its maximum output without full reseed
	 * before generating anything answers -EAGAIN. It is no longer fully
	 * seeded and is skipped by the next request - serve this one from the
	 * initial DRNG right away, as the next request would be, instead of
	 * failing callers that do not retry. Once only, and with no more than
	 * the initial DRNG has left - or, if it has nothing left, than one of
	 * its seeds gives: it is reseeded first then, the request waiting for
	 * the pool lock, see esdm_drng_may_generate(). So the request waits
	 * for one seeding at most, and only a reseed that failed takes the
	 * ESDM out of operation - which the initial DRNG's next request would
	 * find just the same. Under sustained load in a build capping the
	 * output of a seed, every DRNG the request could go to is at its limit
	 * time and again, and -EAGAIN for it would be the rule for the callers
	 * that cannot block, the RPC server's.
	 */
	if (ret == -EAGAIN && drng != &esdm_drng_init) {
		uint32_t left = esdm_drng_bytes_left(&esdm_drng_init);

		if (!left)
			left = max_uint32(
				esdm_config_drng_max_wo_reseed_bits() >> 3, 1);

		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_DRNG,
			"Node DRNG spent, using DRNG instance on node 0 to service generate request\n");
		ret = esdm_drng_get(&esdm_drng_init, outbuf,
				    min_size(outbuflen, left));
	}

	esdm_drng_put_instances();
	return ret;
}

/*
 * Reset ESDM such that all existing entropy is gone.
 */
void esdm_reset(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();

	/*
	 * Everything below under the pool lock, which every seeding holds from
	 * the moment it looks at the DRNGs until it declares them all seeded in
	 * __esdm_drng_seed_work(). Without it, a seeding that found the DRNGs
	 * seeded before they were reset here declares them all seeded after
	 * esdm_reset_state() cleared that state: the next initial seeding then
	 * takes the reseed rules instead of the SP800-90C oversampling and the
	 * NTG.1 two-source rule, and the bring-up and the reseed on entropy
	 * arrival see nothing left to do. The node lock is taken first and
	 * the DRNG locks under the pool lock, the order of every other path.
	 */
	esdm_pool_lock();

	if (!esdm_drng) {
		mutex_w_lock(&esdm_drng_init.lock);
		esdm_drng_reset(&esdm_drng_init);
		mutex_w_unlock(&esdm_drng_init.lock);
	} else {
		uint32_t cpu;

		for_each_online_node (cpu) {
			struct esdm_drng *drng = esdm_drng[cpu];

			if (!drng)
				continue;
			mutex_w_lock(&drng->lock);
			esdm_drng_reset(drng);
			mutex_w_unlock(&drng->lock);
		}
	}

	mutex_w_lock(&esdm_drng_pr.lock);
	esdm_drng_reset(&esdm_drng_pr);
	mutex_w_unlock(&esdm_drng_pr.lock);

	esdm_set_entropy_thresh(ESDM_FULL_SEED_ENTROPY_BITS);

	esdm_reset_state();

	esdm_pool_unlock();
	esdm_drng_put_instances();
}

/******************* Generic ESDM kernel output interfaces ********************/

/* Force one DRBG to be fully seeded */
void esdm_force_fully_seeded(void)
{
	if (esdm_pool_all_nodes_seeded_get())
		return;

	esdm_drng_seed_work_locked(true);
}

/* only try to reach fully seeded level, does not block timeout read indefinitely */
void esdm_try_fully_seeded(void)
{
	if (esdm_pool_all_nodes_seeded_get())
		return;

	esdm_drng_seed_work_locked(false);
}

/* Force all DRBG to be fully seeded */
void esdm_force_fully_seeded_all_drbgs(void)
{
	struct esdm_drng **drngs;

	if (esdm_pool_all_nodes_seeded_get())
		return;

	/* The node lock first - see esdm_drng_seed_work_locked() */
	drngs = esdm_drng_get_instances();
	esdm_pool_lock();
	do {
		/*
		 * Each pass fully seeds at most one DRNG. If a pass cannot bring
		 * its DRNG to the fully-seeded level, the available entropy is
		 * insufficient for the configured policy (e.g. NTG.1 requires
		 * two entropy sources but only one delivers). Stop instead of
		 * spinning forever: otherwise a single, continuously refilled
		 * source keeps esdm_es_reseed_wanted() true while we hold the
		 * pool lock on the synchronous, pre-RPC startup path, hanging
		 * daemon startup. The terminate check additionally lets a
		 * shutdown break the loop.
		 */
		if (!__esdm_drng_seed_work(drngs, true))
			break;
	} while (esdm_es_reseed_wanted() &&
		 !atomic_load(&esdm_drng_mgr_terminate));
	esdm_pool_unlock();
	esdm_drng_put_instances();
}

/*
 * Bring up the DRNGs that are not fully seeded on the way into a request - or
 * into esdm_get_seed(), or when a request found the DRNG it was served from
 * spent, see esdm_unset_fully_seeded().
 *
 * An operational ESDM does not need them for the request: it is served by a
 * fully seeded node or by the initial DRNG. Their bring-up is then the reseed
 * worker's, which retries an instance it could not bring up every second on its
 * own and is only woken here when its next pass is further away than that.
 * Without a worker, the request seeds one only when the entropy sources report
 * enough for it, as their arrival does in esdm_es_add_entropy(). Seeding
 * regardless collects entropy in the caller's thread under the pool lock on
 * every request for as long as the entropy sources cannot fully seed one - a
 * non-blocking request blocking on it, and a server serving all its clients
 * from one thread, like the EGD server, stalling every one of them.
 */
void esdm_drng_bring_up_for_request(void)
{
	uint64_t wakeup;

	if (esdm_pool_all_nodes_seeded_get())
		return;

	if (!esdm_state_operational()) {
		esdm_force_fully_seeded();
		return;
	}

	if (!esdm_drng_mgr_reseed_worker_running()) {
		if (esdm_es_reseed_wanted())
			esdm_force_fully_seeded();
		return;
	}

	wakeup = atomic_load(&esdm_drng_reseed_worker_wakeup);
	if (wakeup > (uint64_t)esdm_monotonic_now() +
			     ESDM_DRNG_RESEED_PASS_BUSY_SEC)
		esdm_drng_reseed_notify();
}

/*
 * esdm_get_seed() hands out nothing before every DRNG is seeded, and it brings
 * them up the way a request does: it is served on the unprivileged RPC
 * interface, mostly without blocking, and seeding all of them right here with
 * the emergency reseeding kept the caller - and every request needing the
 * pool lock meanwhile - waiting on the collection.
 *
 * A caller that blocks is woken when the last DRNG is seeded. Without a worker
 * there is nobody to seed it, and the entropy sources reporting enough for a
 * seed - what a request waits for then - is no promise that they ever will:
 * under the NTG.1 seeding strategy a DRNG is instantiated from two sources of
 * 240 bits each, which the emergency reseeding collects over several passes,
 * while the sources together may never report that much at one time. Waiting
 * for the report, a blocking caller waits forever. It is the one prepared to
 * wait for the collection, so without a worker it brings the DRNGs up itself,
 * as the worker would, and looks again every second until they are.
 */
static int esdm_drng_sleep_while_not_all_nodes_seeded(unsigned int nonblock)
{
	while (!esdm_pool_all_nodes_seeded_get() &&
	       !atomic_load(&esdm_drng_mgr_terminate)) {
		struct timespec recheck = { .tv_sec = 1, .tv_nsec = 0 };
		/* Set by the wait below on a timeout */
		int ret = 0;

		if (!nonblock && !esdm_drng_mgr_reseed_worker_running())
			esdm_force_fully_seeded_all_drbgs();
		else
			esdm_drng_bring_up_for_request();
		if (esdm_pool_all_nodes_seeded_get())
			break;
		if (nonblock)
			return -EAGAIN;

		thread_timedwait_event(
			&esdm_init_wait,
			esdm_pool_all_nodes_seeded_get() ||
				atomic_load(&esdm_drng_mgr_terminate),
			&recheck);
	}

	return 0;
}

static int esdm_drng_sleep_while_nonoperational(unsigned int nonblock)
{
	esdm_drng_bring_up_for_request();
	if (esdm_state_operational())
		return 0;
	if (nonblock)
		return -EAGAIN;
	thread_wait_event(&esdm_init_wait,
			  esdm_state_operational() ||
				  atomic_load(&esdm_drng_mgr_terminate));
	return 0;
}

DSO_PUBLIC
ssize_t esdm_get_seed(uint64_t *buf, size_t nbytes,
		      enum esdm_get_seed_flags flags)
{
	static DEFINE_MUTEX_W_UNLOCKED(esdm_get_seed_lock);
	struct entropy_buf *eb = (struct entropy_buf *)(buf + 2);
	uint64_t buflen = sizeof(struct entropy_buf) + 2 * sizeof(uint64_t);
	uint64_t collected_bits = 0;
	uint32_t requested_bits;
	int ret = 0;

	/* Ensure buffer is aligned as required */
	BUILD_BUG_ON(sizeof(buflen) < ESDM_KCAPI_ALIGN);
	if (nbytes < sizeof(buflen))
		return -EINVAL;

	/* Write buffer size into first word */
	buf[0] = buflen;
	if (nbytes < buflen)
		return -EMSGSIZE;

	/*
	 * The seed material handed out here is conditioned with the very hash
	 * the self tests cover, so it is held back for the same reason as the
	 * DRNG output.
	 */
	if (!esdm_selftest_crypto_passed())
		return -EOPNOTSUPP;

	/*
	 * We only allow ONE caller at any time to prevent a DoS on the RPC
	 * interface considering this is a slow operation.
	 */
	if (mutex_w_trylock(&esdm_get_seed_lock) != 0)
		return -EAGAIN;

	for (;;) {
		CKINT(esdm_drng_sleep_while_not_all_nodes_seeded(
			flags & ESDM_GET_SEED_NONBLOCK));

		/* Try to get the pool lock and sleep on it to get it. */
		esdm_pool_lock();
		if (esdm_pool_all_nodes_seeded_get())
			break;
		esdm_pool_unlock();

		/*
		 * A DRNG became unseeded meanwhile and takes precedence. The
		 * buffer holds nothing but its size, so this is no answer of
		 * 0 bytes - which a caller would take for a filled buffer -
		 * but one to try again, the blocking caller waiting for it.
		 */
		if ((flags & ESDM_GET_SEED_NONBLOCK) ||
		    atomic_load(&esdm_drng_mgr_terminate)) {
			ret = -EAGAIN;
			goto out;
		}
	}

	/*
	 * Try to get seed data - a rarely used busyloop is cheaper than a wait
	 * queue that is constantly woken up by the hot code path of
	 * esdm_init_ops.
	 */
	for (;;) {
		requested_bits = esdm_get_seed_entropy_osr(
			!(flags & ESDM_GET_SEED_FULLY_SEEDED), false);
		/*
		 * What this hands back is seed material with an entropy count
		 * against it. Every source is asked, each into its own slot of
		 * the one buffer: the ones credited with entropy make up
		 * collected_bits below, the others are carried out to the
		 * caller alongside them, credited with nothing.
		 */
		esdm_get_seed_buffers(eb, eb, requested_bits, false, true);
		collected_bits = esdm_entropy_rate_eb(eb);

		/* Break the collection loop if we got entropy, ... */
		if (collected_bits ||
		    /* ... a DRNG becomes unseeded, give DRNG precedence, ... */
		    !esdm_pool_all_nodes_seeded_get() ||
		    /* ... when the DRNG manager terminates, or ... */
		    atomic_load(&esdm_drng_mgr_terminate) ||
		    /* ... if the caller does not want a blocking behavior. */
		    (flags & ESDM_GET_SEED_NONBLOCK))
			break;

		/*
		 * Release pool lock while sleeping to avoid starving DRNG
		 * reseeding operations that need the pool lock.
		 */
		esdm_pool_unlock();
		nanosleep(&poll_ts, NULL);
		esdm_pool_lock();
	}

	esdm_pool_unlock();

	/* Write collected entropy size into second word */
	buf[1] = collected_bits;

out:
	mutex_w_unlock(&esdm_get_seed_lock);
	return ret ? ret : (ssize_t)buflen;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr(uint8_t *buf, size_t nbytes)
{
	ssize_t ret;

	esdm_drng_sleep_while_nonoperational(0);

	/*
	 * We only allow one call in flight which is a precaution that
	 * a caller cannot flood the RPC lines with requests to the slow
	 * PR DRNG and cause a denial of service to the others.
	 */
	if (mutex_w_trylock(&esdm_pr_lock) != 0)
		return -EAGAIN;

	ret = esdm_drng_get_sleep(buf, nbytes, true);
	mutex_w_unlock(&esdm_pr_lock);
	return ret;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr_noblock(uint8_t *buf, size_t nbytes)
{
	ssize_t ret = esdm_drng_sleep_while_nonoperational(1);

	if (ret)
		return ret;

	/*
	 * We only allow one call in flight which is a precaution that
	 * a caller cannot flood the RPC lines with requests to the slow
	 * PR DRNG and cause a denial of service to the others.
	 */
	if (mutex_w_trylock(&esdm_pr_lock) != 0) {
		return -EAGAIN;
	}
	ret = esdm_drng_get_sleep(buf, nbytes, true);
	mutex_w_unlock(&esdm_pr_lock);

	return ret;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_full_noblock(uint8_t *buf, size_t nbytes)
{
	int ret = esdm_drng_sleep_while_nonoperational(1);

	if (ret)
		return ret;
	return esdm_drng_get_sleep(buf, nbytes, false);
}

/*
 * May a blocking request go on after esdm_drng_get_sleep() answered @ret? It
 * may not after an error that no wait cures - a self test that failed, an ESDM
 * that is not set up or that is shutting down - and not after one it does not
 * know, but it does after:
 *
 *   - -EAGAIN: the DRNG it went to reached its maximum output without full
 *     reseed before generating anything, and so did the initial DRNG it fell
 *     back to. Under sustained load in a build capping that output, this is
 *     the normal case rather than an exception. The reseed is on its way - the
 *     worker's of a node DRNG, and the initial DRNG's in the next request it
 *     serves, which reseeds it first, see esdm_drng_get().
 *   - -EOPNOTSUPP from an ESDM that left the operational state on the way: its
 *     initial DRNG reached that limit, and the request waits for it to come
 *     back, as for an ESDM that was never operational. Whether it still is out
 *     of operation when asked here says nothing: another request may have
 *     brought it back meanwhile.
 *   - 0, which nothing but a request of no bytes ought to be answered with.
 */
static bool esdm_drng_get_retry(ssize_t ret)
{
	if (atomic_load(&esdm_drng_mgr_terminate))
		return false;

	if (ret == -EAGAIN || !ret)
		return true;

	return ret == -EOPNOTSUPP && esdm_get_available() &&
	       esdm_selftest_crypto_passed();
}

/*
 * The first retry of a blocking request follows at once - it usually goes to
 * a DRNG that was reseeded meanwhile, or to the initial DRNG, which reseeds
 * itself first. Should that keep failing, the request waits a little more
 * before every further one rather than spinning on the DRNGs while their
 * reseeds collect entropy, up to ESDM_DRNG_GET_RETRY_MAX_NS.
 */
#define ESDM_DRNG_GET_RETRY_MAX_NS (10 * 1000 * 1000)

static void esdm_drng_get_backoff(unsigned int attempt)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 0 };
	long ns = 100 * 1000;

	if (attempt <= 1) {
		sched_yield();
		return;
	}

	while (--attempt > 1 && ns < ESDM_DRNG_GET_RETRY_MAX_NS)
		ns *= 2;
	ts.tv_nsec = (ns < ESDM_DRNG_GET_RETRY_MAX_NS) ?
			     ns :
			     ESDM_DRNG_GET_RETRY_MAX_NS;
	nanosleep(&ts, NULL);
}

/*
 * Blocks until the ESDM is operational, and until all of @nbytes are
 * generated: a DRNG reaching its maximum output without full reseed answers
 * with what it had left or with nothing at all, and that is not an answer the
 * caller of a blocking call is prepared for - see esdm_drng_get_retry(). Only
 * an error that no wait cures ends it early, with the bytes generated until
 * then, or with the error if there are none.
 */
DSO_PUBLIC
ssize_t esdm_get_random_bytes_full(uint8_t *buf, size_t nbytes)
{
	unsigned int attempt = 0;
	size_t done = 0;

	nbytes = min_size(nbytes, SSIZE_MAX);

	while (done < nbytes) {
		ssize_t ret;

		esdm_drng_sleep_while_nonoperational(0);
		ret = esdm_drng_get_sleep(buf + done, nbytes - done, false);
		if (ret > 0) {
			done += (size_t)ret;
			attempt = 0;
			continue;
		}

		if (!esdm_drng_get_retry(ret))
			return done ? (ssize_t)done : ret;

		esdm_drng_get_backoff(++attempt);
	}

	return (ssize_t)done;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes(uint8_t *buf, size_t nbytes)
{
	return esdm_drng_get_sleep(buf, nbytes, false);
}
