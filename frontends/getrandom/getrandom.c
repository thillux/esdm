/*
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
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <stdatomic.h>
#include <stdbool.h>
#include "config.h"
#include "constructor.h"
#include "esdm_rpc_client.h"
#include "esdm_rpc_client_internal.h"
#include "esdm_rpc_service.h"
#include "math_helper.h"
#include "mutex.h"
#include "visibility.h"

/**
 * @brief GRND_SEED
 *
 * This flag requests to provide the data directly from the entropy sources.
 *
 * The behavior of the call is exactly as outlined for the function
 * esdm_get_seed in esdm.h.
 */
#define GRND_SEED 0x0010

/**
 * @brief GRND_FULLY_SEEDED
 *
 * This flag indicates whether the caller wants to reseed a DRNG that is already
 * fully seeded. See esdm_get_seed in esdm.h for details.
 */
#define GRND_FULLY_SEEDED 0x0020

static atomic_bool is_initialized = false;
/* Whether this library holds a reference on the RPC client */
static atomic_bool rpc_initialized = false;
static DEFINE_MUTEX_UNLOCKED(getrandom_mutex);

static void esdm_getrandom_lib_init(void)
{
	mutex_lock(&getrandom_mutex);

	// are we may already initialized from another thread?
	if (atomic_load(&is_initialized)) {
		goto out;
	}

#if ESDM_GETRANDOM_NUM_NODES > 0
	esdm_rpcc_set_max_online_nodes(ESDM_GETRANDOM_NUM_NODES);
#endif

	/*
	 * A failure is not fatal due to the fallback in the functions below,
	 * but it means there is no reference to drop at exit.
	 */
	if (esdm_rpcc_init_unpriv_service(NULL) == 0)
		atomic_store(&rpc_initialized, true);

	atomic_store(&is_initialized, true);

out:
	mutex_unlock(&getrandom_mutex);
}

/*
 * A thread of the parent may hold the lock in the middle of the initialization
 * when another one forks. It does not exist in the child, which would wait for
 * the lock forever on its first call. So the child creates the lock anew, and
 * is_initialized tells whether the initialization still has to be done.
 */
static void esdm_getrandom_fork_child(void)
{
	mutex_init(&getrandom_mutex, 0);
}

ESDM_DEFINE_CONSTRUCTOR(esdm_getrandom_lib_constructor);
static void esdm_getrandom_lib_constructor(void)
{
	pthread_atfork(NULL, NULL, esdm_getrandom_fork_child);
}

ESDM_DEFINE_DESTRUCTOR(esdm_getrandom_lib_exit);
static void esdm_getrandom_lib_exit(void)
{
	/*
	 * The RPC client is reference counted and shared with everybody else
	 * in this process. A fini for an init that never happened - the library
	 * was loaded but never called - would drop somebody else's reference.
	 */
	if (atomic_load(&rpc_initialized))
		esdm_rpcc_fini_unpriv_service();
}

ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags);

/*
 * How long one chunk of a GRND_NONBLOCK request for seeded randomness may take,
 * and how long a request that must not block may wait for a connection.
 *
 * esdm_getrandom_would_block() only tells how the ESDM was when it answered.
 * Should it stop being fully seeded before the data is requested - e.g. as an
 * entropy source failed its health test - the blocking RPC call would ask again
 * and again until it is seeded once more, which may be never. The timed call
 * ends there instead.
 *
 * A zero timeout does not do: the deadline has passed already when the RPC
 * client is about to send the request, so it gives up without asking the ESDM
 * at all. The timeout thus bounds how long a non-blocking caller may be held in
 * this case. It is generous next to the round trip of a request that is served
 * at once, so that a busy system does not report a seeded ESDM as EAGAIN.
 */
#define ESDM_GETRANDOM_NONBLOCK_TIMEOUT_NS 500000000L

/*
 * A request that must not block - GRND_NONBLOCK, GRND_INSECURE - does not wait
 * for a connection longer than ESDM_GETRANDOM_NONBLOCK_TIMEOUT_NS either.
 * The connections of the process are shared by all its threads, and a request
 * of another thread may hold the one this request would wait for for seconds:
 * prediction resistant data comes in parts of 32 bytes, each collected from
 * the entropy sources. Bounded, the request gives up as it does for an ESDM
 * that is not seeded. See esdm_rpcc_set_unpriv_checkout_deadline().
 *
 * Returns the deadline in place before, which esdm_getrandom_nonblock_end()
 * puts back.
 */
static const struct timespec *
esdm_getrandom_nonblock_begin(struct timespec *deadline)
{
	clock_gettime(CLOCK_MONOTONIC, deadline);
	deadline->tv_nsec += ESDM_GETRANDOM_NONBLOCK_TIMEOUT_NS;
	if (deadline->tv_nsec >= 1000000000L) {
		deadline->tv_sec++;
		deadline->tv_nsec -= 1000000000L;
	}
	return esdm_rpcc_set_unpriv_checkout_deadline(deadline);
}

static void esdm_getrandom_nonblock_end(const struct timespec *prev)
{
	esdm_rpcc_set_unpriv_checkout_deadline(prev);
}

/*
 * Whether a request for seeded randomness would block. The ESDM blocks such a
 * request until it is fully seeded, and its RPC client keeps asking until then,
 * so GRND_NONBLOCK has to be honored here, before the request is made.
 *
 * Returns 1 if it would block - also when no connection became free in time -,
 * 0 if not and < 0 if the ESDM cannot tell.
 */
static int esdm_getrandom_would_block(void)
{
	bool fully_seeded = false;
	const struct timespec *prev;
	struct timespec deadline;
	int ret;

	prev = esdm_getrandom_nonblock_begin(&deadline);
	esdm_invoke(esdm_rpcc_is_fully_seeded(&fully_seeded));
	esdm_getrandom_nonblock_end(prev);
	if (ret == -ETIMEDOUT)
		return 1;
	if (ret < 0)
		return ret;

	return !fully_seeded;
}

/*
 * Obtain seeded randomness without waiting for the ESDM to become seeded.
 *
 * The request is split into chunks of what one RPC carries, each with its own
 * timeout: a large request would otherwise run out of time on the way, and the
 * timed RPC call reports an error only, discarding what it obtained before.
 *
 * Returns the number of bytes obtained, which is less than @length only when
 * the ESDM stopped serving midway, -EAGAIN when it served nothing without
 * blocking, < 0 on other errors.
 */
static ssize_t esdm_getrandom_full_nonblock(uint8_t *buffer, size_t length)
{
	size_t done = 0;
	ssize_t ret = 0;

	while (done < length) {
		struct timespec ts = {
			.tv_sec = 0,
			.tv_nsec = ESDM_GETRANDOM_NONBLOCK_TIMEOUT_NS
		};
		size_t todo = min_size(ESDM_RPC_MAX_DATA, length - done);

		esdm_invoke(esdm_rpcc_get_random_bytes_full_timeout(
			buffer + done, todo, &ts));
		if (ret < 0)
			break;
		done += (size_t)ret;
	}

	/* What was obtained is returned, as a short read if need be */
	if (done)
		return (ssize_t)done;

	/* Not seeded any more is the ESDM's answer, nothing to cover for */
	if (ret == -ETIMEDOUT)
		return -EAGAIN;

	return ret;
}

DSO_PUBLIC
ssize_t __real_getrandom(void *__buffer, size_t __length, unsigned int __flags)
{
	return syscall(__NR_getrandom, __buffer, __length, __flags);
}

static ssize_t getrandom_common(void *buffer, size_t length, unsigned int flags)
{
	ssize_t ret;

	/*
	 * getrandom(2) semantics: -1 with errno on error, never a negative
	 * error code as return value.
	 */
	if (flags &
	    (unsigned int)(~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE |
			     GRND_SEED | GRND_FULLY_SEEDED)))
		goto inval;

	/*
	 * Requesting insecure and blocking randomness at the same time makes
	 * no sense.
	 */
	if ((flags & (GRND_INSECURE | GRND_RANDOM)) ==
	    (GRND_INSECURE | GRND_RANDOM))
		goto inval;
	if ((flags & (GRND_INSECURE | GRND_SEED)) ==
	    (GRND_INSECURE | GRND_SEED))
		goto inval;
	if ((flags & (GRND_RANDOM | GRND_SEED)) == (GRND_RANDOM | GRND_SEED))
		goto inval;

	/*
	 * Cap to INT_MAX to match the kernel getrandom() behavior which
	 * also limits the output to at most INT_MAX bytes per call.
	 */
	if (length > INT_MAX)
		length = INT_MAX;

	if (!atomic_load(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	/*
	 * getrandom(2) returns EAGAIN for GRND_NONBLOCK as long as it would
	 * block. Without an answer from the ESDM, the kernel decides - which
	 * also spares a non-blocking caller the wait for a second RPC that
	 * would fail the same way.
	 */
	if ((flags & GRND_NONBLOCK) && !(flags & (GRND_INSECURE | GRND_SEED))) {
		int rc = esdm_getrandom_would_block();

		if (rc > 0) {
			errno = EAGAIN;
			return -1;
		}
		if (rc < 0)
			return syscall(
				__NR_getrandom, buffer, length,
				flags & ~(unsigned int)GRND_FULLY_SEEDED);
	}

	if (flags & GRND_INSECURE) {
		const struct timespec *prev;
		struct timespec deadline;

		/* Without a connection in time, the kernel answers below */
		prev = esdm_getrandom_nonblock_begin(&deadline);
		esdm_invoke(esdm_rpcc_get_random_bytes(buffer, length));
		esdm_getrandom_nonblock_end(prev);
	} else if (flags & GRND_RANDOM) {
		if (!(flags & GRND_NONBLOCK)) {
			esdm_invoke(
				esdm_rpcc_get_random_bytes_pr(buffer, length));
		} else {
			const struct timespec *prev;
			struct timespec deadline;

			/*
			 * Seeded is not enough: the RPC client waits for as
			 * long as the PR DRNG is busy or not operational.
			 * That is the ESDM's answer, not a failure, so it is
			 * not handed to the kernel either - nor are the
			 * connections being busy beyond the deadline.
			 */
			prev = esdm_getrandom_nonblock_begin(&deadline);
			esdm_invoke(esdm_rpcc_get_random_bytes_pr_nonblock(
				buffer, length));
			esdm_getrandom_nonblock_end(prev);
			if (ret == -EAGAIN || ret == -ETIMEDOUT) {
				errno = EAGAIN;
				return -1;
			}
		}
	} else if (flags & GRND_SEED) {
		unsigned int seed_flags =
			(flags & GRND_NONBLOCK) ? ESDM_GET_SEED_NONBLOCK : 0;
		const struct timespec *prev = NULL;
		struct timespec deadline;

		seed_flags |= (flags & GRND_FULLY_SEEDED) ?
				      ESDM_GET_SEED_FULLY_SEEDED :
				      0;
		if (flags & GRND_NONBLOCK)
			prev = esdm_getrandom_nonblock_begin(&deadline);
		esdm_invoke(esdm_rpcc_get_seed(buffer, length, seed_flags));
		if (flags & GRND_NONBLOCK) {
			esdm_getrandom_nonblock_end(prev);
			/* The connections busy beyond the deadline */
			if (ret == -ETIMEDOUT)
				ret = -EAGAIN;
		}
		if (ret < 0) {
			errno = (int)(-ret);
			ret = -1;
		}
		return ret;
	} else if (flags & GRND_NONBLOCK) {
		/*
		 * Seeded a moment ago is no promise for the request: the ESDM
		 * may have stopped being fully seeded meanwhile, for which the
		 * blocking call would wait. That is the ESDM's answer, not a
		 * failure, so it is not handed to the kernel either.
		 */
		ret = esdm_getrandom_full_nonblock(buffer, length);
		if (ret == -EAGAIN) {
			errno = EAGAIN;
			return -1;
		}
	} else {
		esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	}

	if (ret >= 0)
		return ret;

	/* GRND_FULLY_SEEDED is ESDM's own, the kernel would refuse it */
	return syscall(__NR_getrandom, buffer, length,
		       flags & ~(unsigned int)GRND_FULLY_SEEDED);

inval:
	errno = EINVAL;
	return -1;
}

/* Declare the prototype even though libc declares it internally */
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags);
DSO_PUBLIC
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned int flags)
{
	return getrandom_common(buffer, length, flags);
}

DSO_PUBLIC
ssize_t getrandom(void *buffer, size_t length, unsigned int flags)
{
	return getrandom_common(buffer, length, flags);
}

/*
 * getentropy(3) from the kernel, filling the buffer or failing as the glibc and
 * musl implementations do: an interrupted system call is retried - a caller of
 * getentropy has no reason to expect EINTR - and a partial read continued.
 */
static int esdm_getentropy_kernel(void *buffer, size_t length)
{
	uint8_t *p = buffer;

	while (length) {
		ssize_t ret = syscall(__NR_getrandom, p, length, 0);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			/* the syscall already set errno */
			return -1;
		}

		/* No progress at all - fail the way getentropy(3) documents */
		if (ret == 0) {
			errno = EIO;
			return -1;
		}

		p += ret;
		length -= (size_t)ret;
	}

	return 0;
}

int __real_getentropy(void *__buffer, size_t __length);
DSO_PUBLIC
int __real_getentropy(void *__buffer, size_t __length)
{
	/* getentropy(3) semantics: 0 on success, -1 with errno on error. */
	if (__length > 256) {
		errno = EIO;
		return -1;
	}

	return esdm_getentropy_kernel(__buffer, __length);
}

static int getentropy_common(void *buffer, size_t length)
{
	ssize_t ret;

	/* getentropy(3) semantics: 0 on success, -1 with errno on error. */
	if (length > 256) {
		errno = EIO;
		return -1;
	}

	if (!atomic_load(&is_initialized)) {
		esdm_getrandom_lib_init();
	}

	esdm_invoke(esdm_rpcc_get_random_bytes_full(buffer, length));
	if (ret < 0)
		return esdm_getentropy_kernel(buffer, length);

	return 0;
}

/* Declare the prototype even though libc declares it internally */
int __wrap_getentropy(void *buffer, size_t length);
DSO_PUBLIC
int __wrap_getentropy(void *buffer, size_t length)
{
	return getentropy_common(buffer, length);
}

DSO_PUBLIC
int getentropy(void *buffer, size_t length)
{
	return getentropy_common(buffer, length);
}
