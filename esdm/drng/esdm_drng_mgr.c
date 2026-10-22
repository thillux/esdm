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
 * while the generate paths read it without any lock.
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
 * Turns at the prediction resistance DRNG, shared by the blocking and the
 * non-blocking entry points: one request is served at a time, as each block it
 * generates takes a seeding of its own, and the requests are served in the
 * order they arrived - a ticket each, served when esdm_pr_turn_serving reaches
 * it. A turn lasts one block - a seeding's worth, see esdm_drng_get() - while
 * another request waits for one, and as long as the request needs while none
 * does.
 *
 * A lock taken with a trylock used to stand here, and a request finding it
 * taken was answered -EAGAIN. Its callers - an EGD worker, an RPC worker -
 * took that for entropy not being there and came back later, while the request
 * holding it was served block after block, and its client could pipeline the
 * next one into the moment of the release: one client of one worker kept the
 * prediction resistant requests of every other worker out for as long as it
 * kept asking.
 */
static _Atomic uint64_t esdm_pr_turn_next = 0;
static _Atomic uint64_t esdm_pr_turn_serving = 0;
static DECLARE_WAIT_QUEUE(esdm_pr_turn_wait);

static bool esdm_pr_turn_mine(void *ticket)
{
	return atomic_load(&esdm_pr_turn_serving) == *(uint64_t *)ticket;
}

/* Wait for a turn at the prediction resistance DRNG */
static void esdm_pr_turn_take(void)
{
	uint64_t ticket = atomic_fetch_add(&esdm_pr_turn_next, 1);

	/*
	 * Checked under the lock of the queue that the turn is handed on
	 * under, so the handover cannot fall between check and wait.
	 */
	while (!esdm_pr_turn_mine(&ticket))
		thread_wait_queue_wait_pred(&esdm_pr_turn_wait, NULL,
					    esdm_pr_turn_mine, &ticket);
}

/* Hand the turn on to the next request */
static void esdm_pr_turn_give(void)
{
	atomic_fetch_add(&esdm_pr_turn_serving, 1);
	thread_wake_all_locked(&esdm_pr_turn_wait);
}

/* Does another request wait for a turn while this one has it? */
static bool esdm_pr_turn_wanted(void)
{
	return atomic_load(&esdm_pr_turn_next) -
		       atomic_load(&esdm_pr_turn_serving) >
	       1;
}

/*
 * Source of the seed time offsets that keep the DRNGs from all falling due for
 * a reseed at once - see esdm_drng_reseed_stagger().
 */
static struct xoshiro_state esdm_drng_stagger_prng;
static bool esdm_drng_stagger_avail = false;

/* The fork handler, defined with the DRNG bring-up below */
static pthread_once_t esdm_drng_atfork_once = PTHREAD_ONCE_INIT;
static void esdm_drng_atfork_register(void);

/*
 * The node DRNG the calling thread is mapped to - NULL for a thread that is
 * not - and its node, see esdm_drng_node_bind()
 */
static __thread struct esdm_drng *esdm_drng_node_mine = NULL;
static __thread uint32_t esdm_drng_node_mine_idx = 0;

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

/* Record the seed time (whole seconds of esdm_monotonic_now()). */
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
 * from the entropy sources is forced to follow by the usual rules, at the next
 * request of the DRNG.
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

/* Defined below - the statistics report when the next reseed falls due */
static uint64_t esdm_drng_reseed_in(struct esdm_drng *drng);

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
	 * strength like any other, see esdm_drng_may_generate(). The initial
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
	 * (see esdm_drng_get()), which a block an entropy source cached ahead
	 * of the request is not: it may have been collected long before, while
	 * the PR DRNG asks for exactly the size the caches hold. Its seeding
	 * goes to the sources themselves.
	 */
	bool allow_cached = drng != &esdm_drng_pr;
	/*
	 * A reseed may take a seed stashed ahead of it, for its first pass,
	 * and leave out a source with nothing cached when the others deliver
	 * its entropy: an instantiation goes by the initial seeding policy,
	 * and the PR DRNG not even by cached blocks - see esdm_seed_stash_get()
	 * and esdm_get_reseed_buffers().
	 */
	bool reseed = allow_cached && !do_full_init, stash = reseed;

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
		if (stash &&
		    esdm_seed_stash_get(&seedbuf, &addtl, requested_bits)) {
			/* Taken from the stash */
		} else if (reseed) {
			esdm_get_reseed_buffers(&seedbuf, &addtl,
						requested_bits, forced);
		} else {
			esdm_get_seed_buffers(&seedbuf, &addtl, requested_bits,
					      forced, allow_cached);
		}
		stash = false;

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
		if (drng == &esdm_drng_init) {
			/*
			 * Under the pool lock, as the paths taking the ESDM
			 * out of operation - esdm_unset_fully_seeded_if(),
			 * esdm_reset() - change the state there.
			 */
			esdm_pool_lock();
			esdm_init_ops(&collected_seedbuf);
			esdm_pool_unlock();
		}

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
 * The node array is the caller's, and so is the bring-up lock: the node lock
 * comes first, see esdm_drng_seed_work_locked(). The DRNG is seeded under its
 * own lock alone - the pool lock is only taken to declare all DRNGs seeded.
 */
static bool __esdm_drng_seed_work(struct esdm_drng **esdm_drng, bool force)
{
	/*
	 * Taken before any DRNG is looked at: a reset, a DRNG given up on or
	 * a new node array clear the seeded state, and each moves this on, so
	 * the declaration below is not made on the strength of what the DRNGs
	 * looked like before - see esdm_pool_all_nodes_seeded().
	 */
	unsigned int gen = esdm_pool_seeded_gen();
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
	esdm_pool_lock();
	progress = esdm_drng_instances_current(esdm_drng) &&
		   gen == esdm_pool_seeded_gen();
	if (progress)
		esdm_pool_all_nodes_seeded(true);
	esdm_pool_unlock();

out:
	return progress;
}

/*
 * One bring-up at a time: two would seed the same DRNG one after the other,
 * and the entropy sources reporting enough for one seed is no promise of two.
 * The lock order is node lock, bring-up lock, DRNG lock, pool lock: a request
 * takes the node lock in esdm_drng_get_sleep(), a seeding takes the pool lock
 * under the DRNG lock for the state it changes, and esdm_reset() takes every
 * DRNG lock and then the pool lock.
 */
static DEFINE_MUTEX_W_UNLOCKED(esdm_drng_bring_up_lock);

static void esdm_drng_seed_work_locked(bool force)
{
	struct esdm_drng **drngs = esdm_drng_get_instances();

	mutex_w_lock(&esdm_drng_bring_up_lock);
	__esdm_drng_seed_work(drngs, force);
	mutex_w_unlock(&esdm_drng_bring_up_lock);
	esdm_drng_put_instances();
}

/*
 * The same for a caller that would rather do nothing than wait: a bring-up is
 * already under way, and that one collects the entropy this call would have
 * collected.
 * @return true if a seeding was performed, false if one was already running
 */
bool esdm_drng_seed_work_try(void)
{
	struct esdm_drng **drngs = esdm_drng_get_instances();

	if (mutex_w_trylock(&esdm_drng_bring_up_lock)) {
		esdm_drng_put_instances();
		return false;
	}

	__esdm_drng_seed_work(drngs, false);
	mutex_w_unlock(&esdm_drng_bring_up_lock);
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

/*
 * Reseed @drng, which reached its maximum output without full reseed, in the
 * caller's thread - waiting for a seeding of it that is under way. Returns
 * whether it is reseeded: told under the DRNG lock, before other
 * requests may have generated it up to its limit once more - which under load
 * they do at once, and which is no reason to give up on it.
 *
 * The reseed is forced: unforced, a seeding of a fully seeded DRNG collects
 * nothing while the entropy sources report less than a reseed needs, see
 * esdm_get_seed_buffers() - which a source caching its entropy ahead does
 * while the reseeds drain it faster than it refills. Nothing is lost by asking
 * them anyway: a DRNG that cannot be reseeded now may generate nothing at all.
 * Under load, a seed stashed ahead of it spares the request the collection,
 * see esdm_seed_stash_get().
 */
static bool esdm_drng_reseed_spent(struct esdm_drng *drng)
{
	bool reseeded;

	mutex_w_lock(&drng->lock);
	/* Another path may have reseeded it in the meantime */
	if (esdm_drng_spent(drng)) {
		atomic_store(&drng->force_reseed, true);
		esdm_drng_seed_nolock(drng);
	}
	reseeded = !esdm_drng_spent(drng);
	mutex_w_unlock(&drng->lock);

	return reseeded;
}

/*
 * May @drng generate output? If it reached its disable threshold, it is
 * reseeded before it is given up on. Only a full reseed resets the counters,
 * so if the DRNG is still over the threshold afterwards, it reverts to the
 * unseeded state and is spent: nothing may be generated from it until it is
 * brought up again. The same holds for the ESDM as a whole if the initial DRNG
 * could not be brought back.
 *
 * The PR DRNG takes a fresh seed for each of its outputs anyway: marking just
 * this instance unseeded is enough, clearing the state that all DRNGs are
 * seeded is not warranted by it - see the end of the generate loop.
 */
static bool esdm_drng_may_generate(struct esdm_drng *drng, bool pr)
{
	if (esdm_drng_bytes_left(drng))
		return true;

	if (pr) {
		atomic_store(&drng->fully_seeded, false);
		return true;
	}

	/*
	 * Reseeded first, the request waiting for it. Under sustained load in
	 * a build capping the output of a seed, every DRNG reaches its limit
	 * time and again: skipping the reseed for another request generating
	 * the DRNG up to its limit between the reseed check of this one and
	 * here gives it up. For the
	 * initial DRNG, which every request falls back to, that takes the ESDM
	 * out of operation, and for a node DRNG it clears the state that all
	 * DRNGs are seeded, which esdm_get_seed() and the initial seeding
	 * policy go by. Waiting costs this request one seeding. It is spent
	 * only if that reseed did not bring it back either.
	 */
	if (esdm_drng_reseed_spent(drng))
		return true;

	/*
	 * Spent - unless a seeding brought it back while this request generated
	 * up to the limit: the ES monitor's bring-up of this very DRNG, say.
	 * Looked at again under the DRNG lock, see esdm_unset_fully_seeded_if().
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

	/* A seed stashed before this call is not the reseed asked for */
	esdm_seed_stash_flush();
}

/*
 * Is the reseed interval zero seconds? That is not a deadline but the request
 * that every generate operation reseeds first - see
 * esdm_set_reseed_max_time(). Nothing may be deferred then: a reseed that
 * lands after the request it belongs to is not the reseed that was asked for.
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
	/* Negative once requests go on while a busy pool defers the reseed */
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

/****************************** DRNG bring-up *********************************/

/*
 * Bring up every DRNG that is not fully seeded - called by the ES monitor on
 * each of its rounds, which looks after them between the requests. Each is
 * seeded with the emergency reseeding, up to the first one that could not be:
 * the entropy sources would let the others down as well, and the next round
 * follows soon. The bring-up lock is given up between two of them, so a
 * request bringing a DRNG up itself waits for one seeding at most.
 */
void esdm_drng_bring_up(void)
{
	struct esdm_drng **drngs;
	bool progress;

	if (esdm_pool_all_nodes_seeded_get())
		return;

	/* The node lock first - see esdm_drng_seed_work_locked() */
	drngs = esdm_drng_get_instances();
	do {
		mutex_w_lock(&esdm_drng_bring_up_lock);
		progress = __esdm_drng_seed_work(drngs, true);
		mutex_w_unlock(&esdm_drng_bring_up_lock);
	} while (progress && !esdm_pool_all_nodes_seeded_get() &&
		 !atomic_load(&esdm_drng_mgr_terminate));
	esdm_drng_put_instances();
}

/*
 * In the child of fork(), only the thread that called it lives on, and none of
 * the ESDM's own - the ES monitor among them. The child starts a new
 * generation, so every DRNG is made unique to it before it is used again, see
 * esdm_drng_fork_stir_nolock(), and neither the monitor nor the seeds it
 * stashed are the child's, see esdm_es_mgr_atfork_child(). Atomic stores only,
 * as nothing else is safe here.
 */
static void esdm_drng_atfork_child(void)
{
	atomic_fetch_add(&esdm_drng_fork_gen, 1);
	esdm_es_mgr_atfork_child();

	/*
	 * Whatever request held a turn at the PR DRNG or waited for one, it
	 * was one of the parent's threads - the next one is this process's.
	 */
	atomic_store(&esdm_pr_turn_serving, atomic_load(&esdm_pr_turn_next));
}

static void esdm_drng_atfork_register(void)
{
	if (pthread_atfork(NULL, NULL, esdm_drng_atfork_child)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_DRNG,
			"cannot install the fork handler - the child of a fork() hands out the random numbers of its parent until its DRNGs reseed\n");
	}
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
	ssize_t processed = 0;
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
			mutex_w_lock(&drng->lock);
			/* double check, as we did not lock the DRNG in the first check*/
			if (esdm_drng_must_reseed(drng)) {
				esdm_drng_seed_nolock(drng);
				reseeded = true;
			}
			mutex_w_unlock(&drng->lock);
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
			 * Reseeded right here, under the DRNG lock alone: the
			 * reseeds of other DRNGs go on meanwhile, and a source
			 * serializes its own collections.
			 */
			mutex_w_lock(&drng->lock);
			/* double check, as we did not lock the DRNG in the first check*/
			if (esdm_drng_must_reseed(drng))
				esdm_drng_seed_nolock(drng);
			mutex_w_unlock(&drng->lock);
		}

		/*
		 * If the DRNG ran without full reseed for too long, revert to
		 * the unseeded state and stop generating from it.
		 *
		 * Note a reseed requested by drng->force_reseed or
		 * esdm_drng_seed() does not imply that sufficient entropy was
		 * received to fill the DRNG. If this state persists, then this
		 * check applies - for every block, not once per request: the
		 * reseed above may deliver less than full entropy, while a
		 * single
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
			 */
			collected_ent_bits =
				esdm_drng_seed_es_nolock(drng, "regular");

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

			/*
			 * One block per turn while another request waits for
			 * one - see esdm_pr_turn_take(). What is left of this
			 * request is the caller's to ask for again.
			 */
			if (outbuflen && esdm_pr_turn_wanted())
				goto out;
		}
	}

out:
	return processed;
}

/*
 * The node DRNG the calling thread is mapped to, if it may serve a request -
 * NULL otherwise: no thread mapped, its DRNG not fully seeded - not brought up
 * yet, spent, or reset -, or its lock taken. The lock is held by a seeding of
 * the DRNG while it collects from the entropy sources, which takes
 * milliseconds with the oversampling of SP800-90C, and by a request of
 * another thread mapped to the same node, should there be one: a request
 * waiting for it would wait for that. The request is served the way it would
 * be without the mapping then, which skips a busy node DRNG just the same, see
 * esdm_drng_get_sleep(). Nobody but the threads mapped to the node and the
 * seedings take the lock, so trying it costs no cache line shared with the
 * other threads.
 */
static struct esdm_drng *esdm_drng_node_serving(void)
{
	struct esdm_drng *drng = esdm_drng_node_mine;

	if (!drng || !atomic_load(&drng->fully_seeded))
		return NULL;

	if (mutex_w_trylock(&drng->lock))
		return NULL;
	mutex_w_unlock(&drng->lock);

	return drng;
}

static ssize_t esdm_drng_get_sleep(uint8_t *outbuf, size_t outbuflen, bool pr)
{
	struct esdm_drng **esdm_drng;
	struct esdm_drng *drng = pr ? NULL : esdm_drng_node_serving();
	uint32_t num_nodes, node;
	bool found_drng = false;
	ssize_t ret;
	uint32_t i;
	uint32_t j;

	/*
	 * The node DRNG of the thread: neither the node array is taken nor the
	 * DRNGs probed. If it reached its maximum output without full reseed
	 * before it generated anything, and its reseed did not bring it back,
	 * the request is served as without the mapping - by another node DRNG,
	 * and by the initial DRNG only if none is fully seeded: sending each of
	 * those requests to the initial DRNG would spend that one in turn.
	 */
	if (drng) {
		ret = esdm_drng_get(drng, outbuf, outbuflen);
		if (ret != -EAGAIN)
			return ret;
	}

	esdm_drng = esdm_drng_get_instances();
	drng = &esdm_drng_init;
	/*
	 * Bound by the published array size, not only the live config:
	 * raising max_nodes via the public API after allocation grows
	 * esdm_config_online_nodes() but never the array.
	 */
	num_nodes = min_uint32(esdm_config_online_nodes(),
			       esdm_drng_node_count_get());
	node = esdm_config_curr_node();

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
	 * it, see esdm_drng_may_generate(). So the request waits
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

DSO_PUBLIC
int esdm_drng_node_bind(uint32_t worker, bool from_last)
{
	struct esdm_drng **drngs;
	uint32_t nodes, node;

	if (esdm_drng_node_mine)
		return (int)esdm_drng_node_mine_idx;

	/*
	 * Held until the thread unbinds: esdm_fini() frees the node array only
	 * once no thread is mapped to a node any more, see esdm_node_fini().
	 * The lock is reader-preferring, so neither the requests of this thread
	 * nor those of others wait for a finalization waiting for it.
	 */
	drngs = esdm_drng_get_instances();
	nodes = esdm_drng_node_count_get();

	/*
	 * Not the initial DRNG, which serves node 0: it is the one every
	 * request falls back to, and spending it takes the ESDM out of
	 * operation - so
	 * the requests reach it last, see esdm_drng_get_sleep(). The nodes
	 * past it are taken in turn, from the first or from the last, and
	 * wrapped around when there are more threads than nodes.
	 */
	if (!drngs || nodes < 2) {
		esdm_drng_put_instances();
		return -ENODEV;
	}

	node = worker % (nodes - 1);
	node = from_last ? nodes - 1 - node : node + 1;

	if (!drngs[node] || drngs[node] == &esdm_drng_init) {
		esdm_drng_put_instances();
		return -ENODEV;
	}

	esdm_drng_node_mine = drngs[node];
	esdm_drng_node_mine_idx = node;

	return (int)node;
}

DSO_PUBLIC
void esdm_drng_node_unbind(void)
{
	if (!esdm_drng_node_mine)
		return;

	esdm_drng_node_mine = NULL;
	esdm_drng_node_mine_idx = 0;
	esdm_drng_put_instances();
}

/*
 * Reset ESDM such that all existing entropy is gone.
 */
void esdm_reset(void)
{
	struct esdm_drng **esdm_drng = esdm_drng_get_instances();
	uint32_t nodes = esdm_drng ? esdm_drng_node_count_get() : 0, node;

	/*
	 * Every DRNG lock, then the pool lock: a seeding holds the lock of its
	 * DRNG throughout, the state it changes under the pool lock included,
	 * so none is half-way through while the DRNGs and the state are reset.
	 * A bring-up that found the DRNGs seeded before does not declare them
	 * all seeded after, as the reset moves the seeded generation on - see
	 * __esdm_drng_seed_work(). Otherwise the next initial seeding took the
	 * reseed rules instead of the SP800-90C oversampling and the NTG.1
	 * two-source rule. The DRNG locks are taken in the order of the nodes,
	 * the PR DRNG last.
	 */
	if (!esdm_drng) {
		mutex_w_lock(&esdm_drng_init.lock);
	} else {
		for (node = 0; node < nodes; node++) {
			if (esdm_drng[node])
				mutex_w_lock(&esdm_drng[node]->lock);
		}
	}
	mutex_w_lock(&esdm_drng_pr.lock);
	esdm_pool_lock();

	if (!esdm_drng) {
		esdm_drng_reset(&esdm_drng_init);
	} else {
		for (node = 0; node < nodes; node++) {
			if (esdm_drng[node])
				esdm_drng_reset(esdm_drng[node]);
		}
	}
	esdm_drng_reset(&esdm_drng_pr);

	esdm_set_entropy_thresh(ESDM_FULL_SEED_ENTROPY_BITS);

	esdm_reset_state();

	esdm_pool_unlock();
	mutex_w_unlock(&esdm_drng_pr.lock);
	if (!esdm_drng) {
		mutex_w_unlock(&esdm_drng_init.lock);
	} else {
		for (node = nodes; node > 0; node--) {
			if (esdm_drng[node - 1])
				mutex_w_unlock(&esdm_drng[node - 1]->lock);
		}
	}
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
	mutex_w_lock(&esdm_drng_bring_up_lock);
	do {
		/*
		 * Each pass fully seeds at most one DRNG. If a pass cannot bring
		 * its DRNG to the fully-seeded level, the available entropy is
		 * insufficient for the configured policy (e.g. NTG.1 requires
		 * two entropy sources but only one delivers). Stop instead of
		 * spinning forever: otherwise a single, continuously refilled
		 * source keeps esdm_es_reseed_wanted() true while we hold the
		 * bring-up lock on the synchronous, pre-RPC startup path, hanging
		 * daemon startup. The terminate check additionally lets a
		 * shutdown break the loop.
		 */
		if (!__esdm_drng_seed_work(drngs, true))
			break;
	} while (esdm_es_reseed_wanted() &&
		 !atomic_load(&esdm_drng_mgr_terminate));
	mutex_w_unlock(&esdm_drng_bring_up_lock);
	esdm_drng_put_instances();
}

/*
 * Bring up the DRNGs that are not fully seeded on the way into a request - or
 * into esdm_get_seed(), or when a request found the DRNG it was served from
 * spent, see esdm_unset_fully_seeded().
 *
 * An operational ESDM does not need them for the request: it is served by a
 * fully seeded node or by the initial DRNG. Their bring-up is then the ES
 * monitor's, which tries on each of its rounds, see esdm_drng_bring_up().
 * Without a monitor, the request seeds one only when the entropy sources
 * report enough for it, as their arrival does in esdm_es_add_entropy().
 * Seeding regardless collects entropy in the caller's thread under the pool
 * lock on every request for as long as the entropy sources cannot fully seed
 * one - a non-blocking request blocking on it, and a server serving all its
 * clients from one thread, like the EGD server, stalling every one of them.
 */
void esdm_drng_bring_up_for_request(void)
{
	if (esdm_pool_all_nodes_seeded_get())
		return;

	if (!esdm_state_operational()) {
		esdm_force_fully_seeded();
		return;
	}

	if (!esdm_es_mgr_monitor_active() && esdm_es_reseed_wanted())
		esdm_force_fully_seeded();
}

/*
 * esdm_get_seed() hands out nothing before every DRNG is seeded, and it brings
 * them up the way a request does: it is served on the unprivileged RPC
 * interface, mostly without blocking, and seeding all of them right here with
 * the emergency reseeding kept the caller - and every bring-up meanwhile -
 * waiting on the collection.
 *
 * A caller that blocks is woken when the last DRNG is seeded. Without the ES
 * monitor there is nobody to seed it, and the entropy sources reporting enough
 * for a seed - what a request waits for then - is no promise that they ever
 * will: under the NTG.1 seeding strategy a DRNG is instantiated from two
 * sources of 240 bits each, which the emergency reseeding collects over
 * several passes, while the sources together may never report that much at one
 * time. Waiting for the report, a blocking caller waits forever. It is the one
 * prepared to wait for the collection, so without a monitor it brings the
 * DRNGs up itself, as the monitor would, and looks again every second until
 * they are.
 */
static int esdm_drng_sleep_while_not_all_nodes_seeded(unsigned int nonblock)
{
	while (!esdm_pool_all_nodes_seeded_get() &&
	       !atomic_load(&esdm_drng_mgr_terminate)) {
		struct timespec recheck = { .tv_sec = 1, .tv_nsec = 0 };
		/* Set by the wait below on a timeout */
		int ret = 0;

		if (!nonblock && !esdm_es_mgr_monitor_active())
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

		if (esdm_pool_all_nodes_seeded_get())
			break;

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

		nanosleep(&poll_ts, NULL);
	}

	/* Write collected entropy size into second word */
	buf[1] = collected_bits;

out:
	mutex_w_unlock(&esdm_get_seed_lock);
	return ret ? ret : (ssize_t)buflen;
}

/*
 * Generate from the prediction resistance DRNG in turns, see
 * esdm_pr_turn_take(). A request that gave its turn to another one before it
 * was done takes the next turn when @block is set; without, it returns what it
 * got - the turn is waited for either way, which takes no longer than one
 * block of each request ahead of it.
 */
static ssize_t esdm_get_random_bytes_pr_turns(uint8_t *buf, size_t nbytes,
					      bool block)
{
	size_t done = 0;
	ssize_t ret;

	nbytes = min_size(nbytes, SSIZE_MAX);

	do {
		esdm_pr_turn_take();
		ret = esdm_drng_get_sleep(buf + done, nbytes - done, true);
		esdm_pr_turn_give();

		/* Nothing more: an error, or too little entropy just now */
		if (ret <= 0)
			break;
		done += (size_t)ret;
	} while (block && done < nbytes);

	return done ? (ssize_t)done : ret;
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr(uint8_t *buf, size_t nbytes)
{
	esdm_drng_sleep_while_nonoperational(0);

	return esdm_get_random_bytes_pr_turns(buf, nbytes, true);
}

DSO_PUBLIC
ssize_t esdm_get_random_bytes_pr_noblock(uint8_t *buf, size_t nbytes)
{
	ssize_t ret = esdm_drng_sleep_while_nonoperational(1);

	if (ret)
		return ret;

	return esdm_get_random_bytes_pr_turns(buf, nbytes, false);
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
 *     ES monitor's bring-up of a node DRNG, and the initial DRNG's in the next
 *     request it serves, which reseeds it first, see esdm_drng_get().
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
