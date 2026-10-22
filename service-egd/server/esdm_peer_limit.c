/*
 * Per-user connection accounting of the server sockets
 *
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include <stdlib.h>

#include "esdm_logger.h"
#include "esdm_peer_limit.h"

/*
 * One account with connections, see esdm_peer_account.h - the uid member is
 * the account. Entries only exist while their account has connections, so the
 * table holds no more of them than there are connections.
 */
struct esdm_peer_limit_entry {
	struct esdm_peer_limit_entry *next;
	uid_t uid;
	unsigned int count;
	/* The limit was reported for this account already */
	bool warned;
};

static struct esdm_peer_limit_entry **
esdm_peer_limit_slot(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry **slot =
		&limit->buckets[uid % ESDM_PEER_LIMIT_BUCKETS];

	while (*slot && (*slot)->uid != uid)
		slot = &(*slot)->next;

	return slot;
}

bool esdm_peer_limit_get(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry **slot, *entry;
	bool admitted = false;

	if (!uid)
		return true;

	pthread_mutex_lock(&limit->lock);

	slot = esdm_peer_limit_slot(limit, uid);
	entry = *slot;

	if (!entry) {
		entry = calloc(1, sizeof(*entry));
		if (!entry)
			goto out;
		entry->uid = uid;
		*slot = entry;
	}

	if (entry->count >= limit->max_per_uid) {
		/* Once per episode - a peer at its limit retries a lot. */
		if (!entry->warned) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_SERVER,
				"%s: user %u reached its limit of %u connections, refusing further ones\n",
				limit->name, (unsigned int)uid,
				limit->max_per_uid);
			entry->warned = true;
		}
		goto out;
	}

	entry->count++;
	admitted = true;

out:
	pthread_mutex_unlock(&limit->lock);
	return admitted;
}

void esdm_peer_limit_put(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry **slot, *entry;

	if (!uid)
		return;

	pthread_mutex_lock(&limit->lock);

	slot = esdm_peer_limit_slot(limit, uid);
	entry = *slot;
	if (entry && entry->count) {
		entry->count--;
		if (!entry->count) {
			*slot = entry->next;
			free(entry);
		} else if (entry->count < limit->max_per_uid) {
			/* Below the limit again: the episode is over. */
			entry->warned = false;
		}
	}

	pthread_mutex_unlock(&limit->lock);
}

bool esdm_peer_limit_exhausted(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry *entry;
	bool exhausted;

	if (!uid)
		return false;

	pthread_mutex_lock(&limit->lock);

	/* A refusal starts the episode, see esdm_peer_limit_get(). */
	entry = *esdm_peer_limit_slot(limit, uid);
	exhausted = entry && entry->warned;

	pthread_mutex_unlock(&limit->lock);

	return exhausted;
}

unsigned int esdm_peer_limit_count(struct esdm_peer_limit *limit, uid_t uid)
{
	struct esdm_peer_limit_entry *entry;
	unsigned int count;

	if (!uid)
		return 0;

	pthread_mutex_lock(&limit->lock);

	entry = *esdm_peer_limit_slot(limit, uid);
	count = entry ? entry->count : 0;

	pthread_mutex_unlock(&limit->lock);

	return count;
}

unsigned int esdm_peer_limit_max_count(struct esdm_peer_limit *limit)
{
	struct esdm_peer_limit_entry *entry;
	unsigned int i, max = 0;

	pthread_mutex_lock(&limit->lock);

	/*
	 * Entries only exist while their account has connections, so the walk
	 * is bounded by the connections, not by the accounts ever seen.
	 */
	for (i = 0; i < ESDM_PEER_LIMIT_BUCKETS; i++) {
		for (entry = limit->buckets[i]; entry; entry = entry->next) {
			if (entry->count > max)
				max = entry->count;
		}
	}

	pthread_mutex_unlock(&limit->lock);

	return max;
}
