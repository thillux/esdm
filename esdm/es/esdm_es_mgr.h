/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
 */

#ifndef _ESDM_ES_MGR_H
#define _ESDM_ES_MGR_H

#include <stdatomic.h>
#include <stdbool.h>
#include "esdm_drng_mgr.h"
#include "esdm_es_mgr_cb.h"

/*************************** General ESDM parameter ***************************/

#define ESDM_DRNG_BLOCKSIZE 64 /* Maximum of DRNG block sizes */

/************************* Entropy sources management *************************/

extern struct esdm_es_cb *esdm_es[];

#define for_each_esdm_es(ctr) for ((ctr) = 0; (ctr) < esdm_ext_es_last; (ctr)++)

/*
 * Is @name the name of an entropy source in the ES table other than @self? A
 * name an external entropy source declares for itself must not be: whoever
 * reads the status could not tell the sources apart.
 */
bool esdm_es_name_taken(const char *name, const struct esdm_es_cb *self);

/*
 * _Atomic: written via the RPC set_write_wakeup_thresh handler and aux-pool
 * (re)init while read concurrently on the CUSE poll and avail-entropy paths;
 * plain accesses of the _Atomic object are seq_cst, so no call site changes.
 */
extern _Atomic uint32_t esdm_write_wakeup_bits;
void esdm_set_entropy_thresh(uint32_t new);
void esdm_reset_state(void);

void esdm_pool_lock(void);
void esdm_pool_unlock(void);
void esdm_pool_all_nodes_seeded(bool set);
bool esdm_pool_all_nodes_seeded_get(void);
unsigned int esdm_pool_seeded_gen(void);

bool esdm_fully_seeded(bool do_full_init, uint32_t collected_entropy,
		       struct entropy_buf *eb);
bool esdm_fully_seeded_reachable(bool do_full_init, struct entropy_buf *eb);
uint32_t esdm_entropy_rate_eb(struct entropy_buf *eb);
void esdm_unset_fully_seeded(struct esdm_drng *drng);
bool esdm_unset_fully_seeded_if(struct esdm_drng *drng,
				bool (*spent)(struct esdm_drng *drng));
void esdm_init_ops(struct entropy_buf *eb);
/*
 * Collect from the entropy sources in one pass, splitting the result over the
 * two buffers a reseed needs: @seedbuf takes the sources that may be credited
 * with entropy, @addtl the rest. @addtl may also be @seedbuf itself, which
 * collects every source into that one buffer.
 *
 * Pass NULL for @addtl to collect the creditable sources alone. The others are
 * then not fetched at all and their slots in @seedbuf are cleared.
 *
 * One pass rather than two: no source belongs in both buffers, so filling them
 * separately meant walking the sources twice and, where the fetch runs in
 * parallel, waiting out two rounds of the slowest one.
 *
 * @allow_cached false keeps the sources from serving blocks they collected
 * ahead of the request, see struct esdm_es_cb.get_ent.
 */
void esdm_get_seed_buffers(struct entropy_buf *seedbuf,
			   struct entropy_buf *addtl, uint32_t requested_bits,
			   bool force, bool allow_cached);

/*
 * As esdm_get_seed_buffers() with cached blocks allowed, for the reseed of a
 * DRNG: a source with a cache that has no block ready is left out if the other
 * sources deliver @requested_bits - see struct esdm_es_cb.get_cached. Neither
 * for the initial seeding, whose policy may ask for more than one source, nor
 * for the PR DRNG.
 */
void esdm_get_reseed_buffers(struct entropy_buf *seedbuf,
			     struct entropy_buf *addtl, uint32_t requested_bits,
			     bool force);

/*
 * Take a reseed of @requested_bits from the seed stash into @seedbuf and
 * @addtl - see esdm_es_mgr.c.
 *
 * @return true if a stashed seed was handed out, false if the caller has to
 *	   collect one itself
 */
bool esdm_seed_stash_get(struct entropy_buf *seedbuf, struct entropy_buf *addtl,
			 uint32_t requested_bits);

/* Discard the stashed seeds: a reseed asked for after this gets fresh ones */
void esdm_seed_stash_flush(void);

/* Stashed seeds and their number at most, for the status */
unsigned int esdm_seed_stash_filled(void);
unsigned int esdm_seed_stash_slots(void);

int esdm_es_mgr_reinitialize(void);
int esdm_es_mgr_initialize(void);
int esdm_es_mgr_monitor_initialize(void (*priv_init_completion)(void));
void esdm_es_mgr_monitor_wakeup(void);

/* The ES monitor runs a round at least this often, in nanoseconds */
#define ESDM_ES_MONITOR_INTERVAL_NS (1U << 29)
void esdm_es_mgr_monitor_pause(void);
void esdm_es_mgr_monitor_resume(void);
bool esdm_es_mgr_running(void);

/*
 * Is the ES monitor running its rounds? Only then are the DRNGs that are not
 * fully seeded brought up between the requests, see esdm_drng_bring_up().
 */
bool esdm_es_mgr_monitor_active(void);

/* The fork handler of the ES manager, called by the DRNG manager's */
void esdm_es_mgr_atfork_child(void);
void esdm_es_mgr_finalize(void);

#endif /* _ESDM_ES_MGR_H */
