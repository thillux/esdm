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

#ifndef _ESDM_NODE_H
#define _ESDM_NODE_H

#include <stdbool.h>
#include <stddef.h>

#include "config.h"
#include "esdm_config.h"

#ifdef ESDM_NODE
struct esdm_drng **esdm_drng_get_instances(void);
void esdm_drng_put_instances(void);
void esdm_drngs_node_alloc(void);
void esdm_node_fini(void);
uint32_t esdm_drng_node_count_get(void);

/*
 * Is @drngs, taken with esdm_drng_get_instances(), still the published node
 * array? It changes while held only from none to the array, which is published
 * under the pool lock: a caller holding that lock can tell whether the view it
 * took before the lock missed the array.
 */
bool esdm_drng_instances_current(struct esdm_drng **drngs);

/*
 * Iterate over the entries of the published per-node DRNG array. Bound by the
 * size the array was allocated with, not by esdm_config_online_nodes(): the
 * latter is recomputed live and grows if esdm_config_max_nodes_set() is raised
 * after the allocation.
 */
#define for_each_online_node(cpu)                                              \
	for (cpu = 0; cpu < esdm_drng_node_count_get(); cpu++)

#else /* ESDM_NODE */
static inline struct esdm_drng **esdm_drng_get_instances(void)
{
	return NULL;
}
static inline void esdm_drng_put_instances(void)
{
}
static inline void esdm_drngs_node_alloc(void)
{
}
static inline void esdm_node_fini(void)
{
}
static inline uint32_t esdm_drng_node_count_get(void)
{
	return 0;
}
static inline bool esdm_drng_instances_current(struct esdm_drng **drngs)
{
	(void)drngs;
	return true;
}

#define for_each_online_node(cpu) for (cpu = 0; cpu < 1; cpu++)

#endif /* ESDM_NODE */

#endif /* _ESDM_NODE_H */
