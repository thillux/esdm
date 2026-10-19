/*
 * ESDM Entropy Source: PKCS#11 token via libp11
 *
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

#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libp11.h>

#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_buf.h"
#include "esdm_es_mgr.h"
#include "esdm_es_pkcs11.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "visibility.h"

/*
 * Per call we ask the token for at most this many bytes. C_GenerateRandom is
 * not bounded by the standard but several tokens choke on large requests.
 */
#define ESDM_PKCS11_CHUNK_BYTES 32

static PKCS11_CTX *pkcs11_ctx = NULL;
static PKCS11_SLOT *pkcs11_slots = NULL;
static unsigned int pkcs11_nslots = 0;
static PKCS11_SLOT *pkcs11_slot = NULL;
static bool pkcs11_logged_in = false;
static bool pkcs11_module_loaded = false;
/*
 * Optional runtime override for the user PIN. NULL means "use the compile-time
 * default ESDM_PKCS11_PIN". Owned by this module: allocated with strdup and
 * scrubbed with memset_secure before free.
 */
static char *pkcs11_runtime_pin = NULL;
/*
 * Set once the token refused the compile-time PIN ESDM_PKCS11_PIN, cleared when
 * a PIN is set at runtime; a refused runtime PIN is discarded instead. Every
 * failed login uses up one of the retries of the token, after which it locks
 * its PIN: a PIN the token refused is not tried again - neither by the look-ups
 * for a token every ESDM_PKCS11_RETRY_INTERVAL_SEC nor by a re-open - until a
 * new one is set.
 */
static bool pkcs11_default_pin_refused = false;
/*
 * Optional runtime override for the token label. NULL means "use the
 * compile-time default ESDM_PKCS11_TOKEN_LABEL". Owned by this module.
 */
static char *pkcs11_runtime_token_label = NULL;
/*
 * Optional override of the module path, as given on the command line of the
 * server. NULL means "use the compile-time default ESDM_PKCS11_MODULE_PATH".
 * Unlike the PIN and the token label it is configuration rather than a secret
 * or a choice made at runtime, so it outlives esdm_fini() as the entropy rates
 * do: a re-init loads the module it names again. Owned by this module.
 */
static char *pkcs11_runtime_module_path = NULL;
/* Between init and fini - a new module path is loaded at once then */
static bool pkcs11_initialized = false;
static DEFINE_MUTEX_UNLOCKED(pkcs11_mutex);
/*
 * pkcs11_mutex is held across the calls into the module, which a network HSM
 * may take seconds to answer. What the readers that must not wait for them need
 * - the state of the source for the status, its entropy estimate and whether it
 * is active (esdm_es_mgr_cb.h) - is kept apart: the flags below are atomic, and
 * the label of the bound token and the module path are guarded by
 * pkcs11_status_mutex as well, which is held for no longer than it takes to
 * copy them. Lock order: pkcs11_mutex, then pkcs11_status_mutex.
 */
static DEFINE_MUTEX_UNLOCKED(pkcs11_status_mutex);
/* A PKCS#11 token label has 32 bytes, "(none)" without a token bound */
static char pkcs11_status_token[33] = "(none)";
/* Whether a token is bound - pkcs11_slot - once the login is done */
static atomic_bool pkcs11_bound = false;
/* Set by a self test that saw a repeated output, cleared by one that passes */
static atomic_bool pkcs11_selftest_failed = false;

/*
 * Earliest time to look for a token again (ESDM_PKCS11_RETRY_INTERVAL_SEC),
 * monotonic seconds, written under pkcs11_mutex.
 */
static time_t pkcs11_retry_at = 0;

/*
 * The effective user and group the source was initialized with. The module is
 * kept loaded across a failure and loaded anew only while they are the ones in
 * effect: once the server has dropped its privileges, a module needing them -
 * for a configuration or a device only root may open - would not load again,
 * and the source would have lost the one it had. Written under pkcs11_mutex.
 */
static uid_t pkcs11_init_uid = 0;
static gid_t pkcs11_init_gid = 0;

/* Can the module be loaded anew? Caller must hold pkcs11_mutex. */
static bool esdm_es_pkcs11_may_load_locked(void)
{
	return geteuid() == pkcs11_init_uid && getegid() == pkcs11_init_gid;
}

/* Caller must hold pkcs11_mutex (write lock). */
static const char *esdm_es_pkcs11_pin_locked(void)
{
	if (pkcs11_runtime_pin)
		return pkcs11_runtime_pin;
	return pkcs11_default_pin_refused ? "" : ESDM_PKCS11_PIN;
}

/* Caller must hold pkcs11_mutex (write lock). */
static const char *esdm_es_pkcs11_token_label_locked(void)
{
	return pkcs11_runtime_token_label ? pkcs11_runtime_token_label :
					    ESDM_PKCS11_TOKEN_LABEL;
}

/* Caller must hold pkcs11_mutex or pkcs11_status_mutex. */
static const char *esdm_es_pkcs11_module_path_locked(void)
{
	return pkcs11_runtime_module_path ? pkcs11_runtime_module_path :
					    ESDM_PKCS11_MODULE_PATH;
}

/*
 * Is a module configured at all? Caller must hold pkcs11_mutex or
 * pkcs11_status_mutex.
 */
static bool esdm_es_pkcs11_configured_locked(void)
{
	return esdm_es_pkcs11_module_path_locked()[0] != '\0';
}

/* Caller must hold pkcs11_mutex (write lock). */
static void esdm_es_pkcs11_clear_runtime_pin_locked(void)
{
	if (!pkcs11_runtime_pin)
		return;

	memset_secure(pkcs11_runtime_pin, 0, strlen(pkcs11_runtime_pin));
	free(pkcs11_runtime_pin);
	pkcs11_runtime_pin = NULL;
}

/* Caller must hold pkcs11_mutex (write lock). */
static void esdm_es_pkcs11_clear_runtime_token_label_locked(void)
{
	free(pkcs11_runtime_token_label);
	pkcs11_runtime_token_label = NULL;
}

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
static struct esdm_es_buf pkcs11_buf;
static bool pkcs11_buf_alloced = false;

/*
 * What a block of @requested_bits is credited with at present: the configured
 * rate, and nothing once a self test saw the token repeat its output. Unlike
 * esdm_es_pkcs11_entropylevel() it does not ask for a token bound now - a block
 * cached before the card was pulled was read from a token that delivered.
 */
static uint32_t esdm_es_pkcs11_buf_credit(uint32_t requested_bits)
{
	/* Without pkcs11_mutex, a cached block is not to wait for a read */
	if (pkcs11_selftest_failed)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_pkcs11_entropy_rate(), requested_bits);
}
#endif

static bool esdm_es_pkcs11_active(void);

/* The length of the valid UTF-8 sequence @s starts with, 0 if there is none */
static unsigned int esdm_es_pkcs11_utf8_len(const unsigned char *s)
{
	unsigned char lo = 0x80, hi = 0xbf;
	unsigned int len, i;

	if (s[0] < 0x80)
		return 1;
	if (s[0] < 0xc2) {
		/* A continuation byte, or the start of an overlong form */
		return 0;
	} else if (s[0] < 0xe0) {
		len = 2;
	} else if (s[0] < 0xf0) {
		len = 3;
		if (s[0] == 0xe0)
			lo = 0xa0; /* overlong */
		else if (s[0] == 0xed)
			hi = 0x9f; /* UTF-16 surrogates */
	} else if (s[0] < 0xf5) {
		len = 4;
		if (s[0] == 0xf0)
			lo = 0x90; /* overlong */
		else if (s[0] == 0xf4)
			hi = 0x8f; /* above U+10FFFF */
	} else {
		return 0;
	}

	/* Ends at the terminating NUL at the latest */
	for (i = 1; i < len; i++) {
		if (s[i] < lo || s[i] > hi)
			return 0;
		lo = 0x80;
		hi = 0xbf;
	}

	return len;
}

/*
 * Copy the token label @label for the status. PKCS#11 has a token report its
 * label in UTF-8, but nothing holds a token to that, and json-c writes the
 * bytes it is given: a label that is not UTF-8 made the whole JSON status
 * invalid. What is not, and a control character - which the text status hands
 * to the terminal of whoever reads it - is replaced by a '?' each.
 */
static void esdm_es_pkcs11_label_copy(char *dst, size_t dstlen,
				      const char *label)
{
	const unsigned char *s = (const unsigned char *)label;
	size_t i = 0;

	while (*s) {
		unsigned int len = esdm_es_pkcs11_utf8_len(s);
		bool control = (len == 1 && (s[0] < 0x20 || s[0] == 0x7f)) ||
			       /* C1: U+0080 to U+009F */
			       (len == 2 && s[0] == 0xc2 && s[1] < 0xa0);

		if (!len || control) {
			if (i + 1 >= dstlen)
				break;
			dst[i++] = '?';
			s += len ? len : 1;
			continue;
		}

		if (i + len >= dstlen)
			break;
		memcpy(dst + i, s, len);
		i += len;
		s += len;
	}

	dst[i] = '\0';
}

/*
 * Tell the readers that do not take pkcs11_mutex which token is bound now.
 * Caller must hold pkcs11_mutex (write lock).
 */
static void esdm_es_pkcs11_publish_locked(void)
{
	const char *label = "(none)";

	if (pkcs11_slot && pkcs11_slot->token && pkcs11_slot->token->label)
		label = pkcs11_slot->token->label;

	mutex_lock(&pkcs11_status_mutex);
	esdm_es_pkcs11_label_copy(pkcs11_status_token,
				  sizeof(pkcs11_status_token), label);
	mutex_unlock(&pkcs11_status_mutex);
	atomic_store(&pkcs11_bound, pkcs11_slot != NULL);
}

/*
 * Caller must hold pkcs11_mutex (write lock).
 * Drop just the bound slot. Keeps the loaded module so we can re-discover
 * tokens (e.g. after a smartcard is re-inserted) without paying the cost of a
 * full module unload/reload.
 */
static void esdm_es_pkcs11_drop_slot_locked(void)
{
	if (pkcs11_logged_in && pkcs11_slot)
		PKCS11_logout(pkcs11_slot);
	pkcs11_logged_in = false;
	pkcs11_slot = NULL;
	esdm_es_pkcs11_publish_locked();
}

/* Caller must hold pkcs11_mutex (write lock). */
static void esdm_es_pkcs11_finalize_locked(void)
{
	esdm_es_pkcs11_drop_slot_locked();

	if (pkcs11_slots && pkcs11_ctx) {
		PKCS11_release_all_slots(pkcs11_ctx, pkcs11_slots,
					 pkcs11_nslots);
	}
	pkcs11_slots = NULL;
	pkcs11_nslots = 0;

	if (pkcs11_ctx) {
		if (pkcs11_module_loaded)
			PKCS11_CTX_unload(pkcs11_ctx);
		PKCS11_CTX_free(pkcs11_ctx);
	}
	pkcs11_ctx = NULL;
	pkcs11_module_loaded = false;
}

static void esdm_es_pkcs11_finalize(void)
{
	mutex_lock(&pkcs11_mutex);
	esdm_es_pkcs11_finalize_locked();
	esdm_es_pkcs11_clear_runtime_pin_locked();
	pkcs11_default_pin_refused = false;
	esdm_es_pkcs11_clear_runtime_token_label_locked();
	pkcs11_initialized = false;
	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	if (pkcs11_buf_alloced) {
		esdm_es_buf_free(&pkcs11_buf);
		pkcs11_buf_alloced = false;
	}
#endif
}

/* Caller must hold pkcs11_mutex (write lock). */
static PKCS11_SLOT *esdm_es_pkcs11_pick_slot(void)
{
	const char *want_label = esdm_es_pkcs11_token_label_locked();
	PKCS11_SLOT *slot;
	unsigned int i;

	for (i = 0; i < pkcs11_nslots; i++) {
		slot = &pkcs11_slots[i];
		if (!slot->token)
			continue;
		if (!slot->token->initialized)
			continue;
		if (!slot->token->hasRng)
			continue;
		if (want_label[0] != '\0' &&
		    (!slot->token->label ||
		     strcmp(slot->token->label, want_label) != 0))
			continue;
		return slot;
	}

	return NULL;
}

/*
 * Log in to the token of the bound slot with the PIN in effect, if there is
 * one and the token asks for it. Caller must hold pkcs11_mutex (write lock).
 *
 * A PIN the token refuses is not tried again (pkcs11_default_pin_refused): the
 * runtime PIN is discarded, the compile-time one set aside until a PIN is set.
 *
 * Returns 0 when logged in or when no login is needed, -EACCES when the token
 * refused the PIN.
 */
static int esdm_es_pkcs11_login_locked(void)
{
	const char *pin = esdm_es_pkcs11_pin_locked();
	int logged_in = 0;

	if (pin[0] == '\0' || !pkcs11_slot->token->loginRequired)
		return 0;

	/* As before, a token that cannot tell is not logged in to */
	if (PKCS11_is_logged_in(pkcs11_slot, 0, &logged_in) || logged_in)
		return 0;

	if (PKCS11_login(pkcs11_slot, 0, pin) != 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"PKCS#11 entropy source: token '%s' refused the %s PIN, which is not tried again until a new one is set\n",
			pkcs11_slot->token->label ? pkcs11_slot->token->label :
						    "(no label)",
			pkcs11_runtime_pin ? "runtime" : "configured");
		if (pkcs11_runtime_pin)
			esdm_es_pkcs11_clear_runtime_pin_locked();
		else
			pkcs11_default_pin_refused = true;
		return -EACCES;
	}
	pkcs11_logged_in = true;

	return 0;
}

/*
 * Open the PKCS#11 module and select a usable slot. Caller must hold
 * pkcs11_mutex (write lock). Any previously held module/slot state is torn
 * down first. A module that loads stays loaded without a usable token, for
 * esdm_es_pkcs11_refresh_slot_locked() to look among its slots again.
 *
 * Returns 0 on success. Negative errno otherwise: -ENODEV when the module
 * cannot be loaded, -ENOENT when no matching token is found, -EACCES when
 * login fails.
 */
static int esdm_es_pkcs11_open_module_locked(void)
{
	const char *module_path = esdm_es_pkcs11_module_path_locked();
	int ret;

	esdm_es_pkcs11_finalize_locked();

	if (module_path[0] == '\0') {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: no module path configured\n");
		return -ENODEV;
	}

	pkcs11_ctx = PKCS11_CTX_new();
	if (!pkcs11_ctx) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: PKCS11_CTX_new failed\n");
		return -ENOMEM;
	}

	if (PKCS11_CTX_load(pkcs11_ctx, module_path) != 0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: failed to load module %s\n",
			module_path);
		PKCS11_CTX_free(pkcs11_ctx);
		pkcs11_ctx = NULL;
		return -ENODEV;
	}
	pkcs11_module_loaded = true;

	if (PKCS11_enumerate_slots(pkcs11_ctx, &pkcs11_slots, &pkcs11_nslots) <
	    0) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: failed to enumerate slots\n");
		pkcs11_slots = NULL;
		pkcs11_nslots = 0;
		return -EIO;
	}

	pkcs11_slot = esdm_es_pkcs11_pick_slot();
	if (!pkcs11_slot) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling PKCS#11 entropy source: no usable token with RNG found\n");
		return -ENOENT;
	}

	/* The refusal is logged there */
	ret = esdm_es_pkcs11_login_locked();
	if (ret) {
		pkcs11_slot = NULL;
		return ret;
	}
	esdm_es_pkcs11_publish_locked();

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "PKCS#11 entropy source using token '%s' (module %s)\n",
		    pkcs11_slot->token->label ? pkcs11_slot->token->label :
						"(no label)",
		    module_path);

	return 0;
}

static int esdm_es_pkcs11_init(void)
{
	mutex_lock(&pkcs11_mutex);
	pkcs11_init_uid = geteuid();
	pkcs11_init_gid = getegid();
	(void)esdm_es_pkcs11_open_module_locked();
	pkcs11_initialized = true;
	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	if (pkcs11_buf_alloced) {
		esdm_es_buf_reset(&pkcs11_buf);
	} else if (esdm_es_buf_alloc(&pkcs11_buf, ESDM_PKCS11_ENTROPY_BLOCKS,
				     "PKCS#11",
				     esdm_config_es_pkcs11_entropy_rate,
				     esdm_es_pkcs11_buf_credit) == 0) {
		pkcs11_buf_alloced = true;
	}
#endif

	return 0;
}

/* Without pkcs11_mutex, see pkcs11_status_mutex */
static uint32_t esdm_es_pkcs11_entropylevel(uint32_t requested_bits)
{
	if (!pkcs11_bound || pkcs11_selftest_failed)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_pkcs11_entropy_rate(), requested_bits);
}

static uint32_t esdm_es_pkcs11_poolsize(void)
{
	return esdm_es_pkcs11_entropylevel(esdm_security_strength());
}

/*
 * Caller must hold pkcs11_mutex (write lock).
 * Try to (re-)bind to a usable token without unloading the module. Used after
 * a read failure, when the smartcard has been physically removed and
 * re-inserted, and for a new token label: PKCS#11 only refreshes its slot view
 * via release_all_slots + enumerate_slots.
 *
 * The module is loaded anew only where that can work out
 * (esdm_es_pkcs11_may_load_locked()): when it is not loaded, or when its slots
 * carry no usable token - some modules, SoftHSM among them, only see a token
 * added after they were loaded once they are loaded again.
 *
 * Returns 0 on success, -ENODEV when the module is not loaded and reloading
 * fails, -EIO when slot enumeration fails, -ENOENT when no usable token is
 * present, and -EACCES when login fails.
 */
static int esdm_es_pkcs11_refresh_slot_locked(void)
{
	int ret = -ENODEV;

	/* Drop any previous slot binding before refreshing. */
	esdm_es_pkcs11_drop_slot_locked();

	if (!pkcs11_ctx)
		goto reload;

	/* Refresh the slot list so newly-inserted tokens become visible. */
	if (pkcs11_slots) {
		PKCS11_release_all_slots(pkcs11_ctx, pkcs11_slots,
					 pkcs11_nslots);
		pkcs11_slots = NULL;
		pkcs11_nslots = 0;
	}

	if (PKCS11_enumerate_slots(pkcs11_ctx, &pkcs11_slots, &pkcs11_nslots) <
	    0) {
		pkcs11_slots = NULL;
		pkcs11_nslots = 0;
		ret = -EIO;
		goto reload;
	}

	pkcs11_slot = esdm_es_pkcs11_pick_slot();
	if (!pkcs11_slot) {
		ret = -ENOENT;
		goto reload;
	}

	ret = esdm_es_pkcs11_login_locked();
	if (ret) {
		pkcs11_slot = NULL;
		return ret;
	}
	esdm_es_pkcs11_publish_locked();

	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "PKCS#11 entropy source using token '%s'\n",
		    pkcs11_slot->token->label ? pkcs11_slot->token->label :
						"(no label)");

	return 0;

reload:
	/* Without the privileges of the init, the loaded module is kept */
	if (!esdm_es_pkcs11_may_load_locked())
		return ret;
	return esdm_es_pkcs11_open_module_locked();
}

/*
 * Caller must hold pkcs11_mutex (write lock).
 * Look for a token again if none is bound, rate limited.
 */
static void esdm_es_pkcs11_reacquire_locked(void)
{
	struct timespec now;

	if (pkcs11_slot || !esdm_es_pkcs11_configured_locked())
		return;

	if (clock_gettime(CLOCK_MONOTONIC, &now) ||
	    now.tv_sec < pkcs11_retry_at)
		return;

	pkcs11_retry_at = now.tv_sec + ESDM_PKCS11_RETRY_INTERVAL_SEC;
	(void)esdm_es_pkcs11_refresh_slot_locked();
}

static void esdm_es_pkcs11_get_sync(struct entropy_es *eb_es,
				    uint32_t requested_bits)
{
	uint8_t buffer[ESDM_PKCS11_CHUNK_BYTES];
	uint32_t done_bits = 0;

	/*
	 * Take an exclusive lock: PKCS11_generate_random touches per-slot
	 * state and on errors we tear the connection down (write to shared
	 * state).
	 */
	mutex_lock(&pkcs11_mutex);

	esdm_es_pkcs11_reacquire_locked();
	if (!pkcs11_slot)
		goto err;

	while (done_bits < requested_bits) {
		uint32_t chunk_bits = min_uint32(ESDM_PKCS11_CHUNK_BYTES << 3,
						 requested_bits - done_bits);
		uint32_t chunk_bytes = chunk_bits >> 3;

		if (PKCS11_generate_random(pkcs11_slot, buffer,
					   ESDM_PKCS11_CHUNK_BYTES) != 0) {
			/*
			 * Don't tear the module down — a transient error (e.g.
			 * smartcard removed) just drops the slot binding, and
			 * the next request or monitor round re-acquires a
			 * token. This pass credits nothing.
			 */
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"PKCS#11 C_GenerateRandom failed, dropping slot for re-discovery\n");
			esdm_es_pkcs11_drop_slot_locked();
			goto err;
		}

		memcpy(eb_es->e + (done_bits >> 3), buffer, chunk_bytes);
		done_bits += chunk_bits;
	}

	eb_es->e_bits = esdm_es_pkcs11_entropylevel(requested_bits);
	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from PKCS#11 entropy source\n",
		    eb_es->e_bits);

	mutex_unlock(&pkcs11_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	return;

err:
	mutex_unlock(&pkcs11_mutex);
	memset_secure(buffer, 0, sizeof(buffer));
	eb_es->e_bits = 0;
}

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)

static void esdm_es_pkcs11_buf_fill(struct entropy_es *eb_es,
				    uint32_t requested_bits, void *ctx)
{
	(void)ctx;
	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

static int esdm_es_pkcs11_monitor(void)
{
	uint32_t requested_bits = esdm_get_seed_entropy_osr(false, true);
	bool configured, slot_present;

	mutex_reader_lock(&pkcs11_mutex);
	configured = esdm_es_pkcs11_configured_locked();
	slot_present = pkcs11_slot != NULL;
	mutex_reader_unlock(&pkcs11_mutex);

	if (!configured)
		return 0;

	/*
	 * If we lost the slot (read failure earlier, or smartcard was removed
	 * since startup), try to re-bind. Failure is silent here — the user is
	 * already aware of the original failure that dropped the slot, and the
	 * card may simply still be absent.
	 */
	if (!slot_present) {
		mutex_lock(&pkcs11_mutex);
		esdm_es_pkcs11_reacquire_locked();
		slot_present = pkcs11_slot != NULL;
		mutex_unlock(&pkcs11_mutex);
	}

	if (!slot_present)
		return 0;

	return esdm_es_buf_monitor(&pkcs11_buf, requested_bits,
				   esdm_es_pkcs11_buf_fill, NULL);
}

static void esdm_es_pkcs11_get(struct entropy_es *eb_es,
			       uint32_t requested_bits, bool allow_cached)
{
	/*
	 * A block the token delivered before a self test saw it repeat itself
	 * is credited no more than what it reads now.
	 */
	if (allow_cached &&
	    esdm_es_buf_try_get(&pkcs11_buf, eb_es, requested_bits,
				!!esdm_es_pkcs11_buf_credit(requested_bits)))
		return;

	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

#else /* ESDM_PKCS11_ENTROPY_BLOCKS == 0 */

static void esdm_es_pkcs11_get(struct entropy_es *eb_es,
			       uint32_t requested_bits,
			       bool __unused allow_cached)
{
	esdm_es_pkcs11_get_sync(eb_es, requested_bits);
}

#endif

static void esdm_es_pkcs11_es_state(struct json_object *obj)
{
	/* Without pkcs11_mutex, see pkcs11_status_mutex */
	uint32_t poolsize =
		esdm_es_pkcs11_entropylevel(esdm_security_strength());
	uint32_t entropy_rate = esdm_es_pkcs11_entropylevel(256);
	/* Copied, as a re-discovery replaces it once the lock is dropped */
	char token_label[sizeof(pkcs11_status_token)];
	/* Copied as well, as a new module path frees the old one */
	char module_path[PATH_MAX];

	mutex_reader_lock(&pkcs11_status_mutex);
	snprintf(module_path, sizeof(module_path), "%s",
		 esdm_es_pkcs11_module_path_locked());
	memcpy(token_label, pkcs11_status_token, sizeof(token_label));
	mutex_reader_unlock(&pkcs11_status_mutex);

	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(poolsize));
	json_object_object_add(obj, "entropy_rate_per_256_data_bits",
			       json_object_new_int64(entropy_rate));
	json_object_object_add(obj, "module",
			       json_object_new_string(module_path[0] != '\0' ?
							      module_path :
							      "(unset)"));
	json_object_object_add(obj, "token",
			       json_object_new_string(token_label));
}

static bool esdm_es_pkcs11_active(void)
{
	bool ret;

	/*
	 * Stay active as long as a module is configured, at compile time or
	 * on the command line. The monitor handles slot (re-)acquisition, so a
	 * temporarily absent smartcard does not turn the source off — it just
	 * delivers no entropy until the card comes back.
	 */
	mutex_reader_lock(&pkcs11_status_mutex);
	ret = esdm_es_pkcs11_configured_locked();
	mutex_reader_unlock(&pkcs11_status_mutex);

	return ret;
}

/*
 * Two reads of the token that have to succeed and have to differ. An absent
 * token is no failure: the source waits for one to come back.
 */
static int esdm_es_pkcs11_selftest(void)
{
	uint8_t first[16], second[16];
	int ret = 0;

	mutex_lock(&pkcs11_mutex);

	if (!pkcs11_module_loaded || !pkcs11_slot) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "PKCS11 ES: no token - nothing to test\n");
		goto out;
	}

	if (PKCS11_generate_random(pkcs11_slot, first, sizeof(first)) ||
	    PKCS11_generate_random(pkcs11_slot, second, sizeof(second))) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "PKCS11 ES: the token did not deliver\n");
		/* As a failed read does, see esdm_es_pkcs11_get_sync() */
		esdm_es_pkcs11_drop_slot_locked();
		ret = -EFAULT;
		goto out;
	}

	if (!memcmp(first, second, sizeof(first))) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ES,
			    "PKCS11 ES: the token repeated its output\n");
		pkcs11_selftest_failed = true;
#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
		/*
		 * What the cache holds was read before this test, from a token
		 * that has shown it repeats itself - not to be handed out as
		 * entropy, as esdm_jent_selftest() does with its cache.
		 */
		esdm_es_buf_reset(&pkcs11_buf);
#endif
		ret = -EFAULT;
		goto out;
	}

	pkcs11_selftest_failed = false;

out:
	mutex_unlock(&pkcs11_mutex);
	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));

	return ret;
}

struct esdm_es_cb esdm_es_pkcs11 = {
	.name = "PKCS#11",
	.init = esdm_es_pkcs11_init,
	.fini = esdm_es_pkcs11_finalize,
#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	.monitor_es = esdm_es_pkcs11_monitor,
#else
	.monitor_es = NULL,
#endif
	.get_ent = esdm_es_pkcs11_get,
	.curr_entropy = esdm_es_pkcs11_entropylevel,
	.max_entropy = esdm_es_pkcs11_poolsize,
	.state = esdm_es_pkcs11_es_state,
	.reset = NULL,
	.active = esdm_es_pkcs11_active,
	.selftest = esdm_es_pkcs11_selftest,
};

DSO_PUBLIC
int esdm_es_pkcs11_set_pin(const char *pin)
{
	char *new_copy = NULL;
	char *old;
	int ret = 0;

	if (!pin)
		return -EINVAL;

	if (pin[0] != '\0') {
		new_copy = strdup(pin);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&pkcs11_mutex);

	old = pkcs11_runtime_pin;
	pkcs11_runtime_pin = new_copy;
	/* A PIN is set: the compile-time one may be tried again, too */
	pkcs11_default_pin_refused = false;

	/*
	 * If the module is already initialized, the token requires login, and
	 * we have not logged in yet, log in now using the new PIN. If the new
	 * PIN is empty, do not attempt a login (this is a "clear PIN"
	 * request). A PIN the token refuses is discarded.
	 */
	if (new_copy && pkcs11_slot && !pkcs11_logged_in) {
		ret = esdm_es_pkcs11_login_locked();
		if (pkcs11_logged_in) {
			esdm_logger(
				LOGGER_VERBOSE, LOGGER_C_ES,
				"PKCS#11 entropy source: login with runtime PIN succeeded\n");
		}
	}

	mutex_unlock(&pkcs11_mutex);

	if (old) {
		memset_secure(old, 0, strlen(old));
		free(old);
	}

	return ret;
}

DSO_PUBLIC
int esdm_es_pkcs11_set_token_label(const char *label)
{
	char *new_copy = NULL;
	char *old;
	int ret;

	if (!label)
		return -EINVAL;

	if (label[0] != '\0') {
		new_copy = strdup(label);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&pkcs11_mutex);

	old = pkcs11_runtime_token_label;
	pkcs11_runtime_token_label = new_copy;

	/*
	 * Look for the token of the new label at once - among the slots of the
	 * module loaded, which may not load again with the privileges of the
	 * server dropped. One that is not loaded is loaded, as asked for.
	 */
	ret = pkcs11_ctx ? esdm_es_pkcs11_refresh_slot_locked() :
			   esdm_es_pkcs11_open_module_locked();

	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	if (pkcs11_buf_alloced)
		esdm_es_buf_reset(&pkcs11_buf);
#endif

	free(old);

	return ret;
}

DSO_PUBLIC
int esdm_es_pkcs11_set_module_path(const char *path)
{
	char *new_copy = NULL;
	char *old;
	bool reopened;
	int ret = 0;

	if (!path)
		return -EINVAL;

	if (path[0] != '\0') {
		new_copy = strdup(path);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&pkcs11_mutex);

	/* The status reads the path under pkcs11_status_mutex alone */
	mutex_lock(&pkcs11_status_mutex);
	old = pkcs11_runtime_module_path;
	pkcs11_runtime_module_path = new_copy;
	mutex_unlock(&pkcs11_status_mutex);

	/*
	 * Set before esdm_init(), as the server does, the module is loaded by
	 * the init of the source. Once the source runs, the module it uses is
	 * replaced right away, as a new token label is.
	 */
	reopened = pkcs11_initialized;
	if (reopened)
		ret = esdm_es_pkcs11_open_module_locked();

	mutex_unlock(&pkcs11_mutex);

#if (ESDM_PKCS11_ENTROPY_BLOCKS != 0)
	/* What the old module delivered is not credited for the new one */
	if (reopened && pkcs11_buf_alloced)
		esdm_es_buf_reset(&pkcs11_buf);
#endif

	free(old);

	return ret;
}
