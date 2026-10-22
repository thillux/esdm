/*
 * ESDM external entropy source: PKCS#11 token via libp11
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

/*
 * The random number generator of a PKCS#11 token as an external entropy
 * source, served by esdm-es-pkcs11(8) - see esdm_es_pkcs11.h.
 *
 * This was the PKCS#11 entropy source of the ESDM itself. In a process of its
 * own, the PKCS#11 module - code of the token vendor, loaded with dlopen(3) -
 * runs with the privileges the token needs rather than with those of the
 * ESDM, the PIN is a secret of this process alone, and a module that hangs or
 * crashes takes this process with it rather than the ESDM, which reconnects
 * once it is back.
 *
 * The provider server calls the callbacks below one at a time, from one
 * thread: the state of the source needs no lock.
 *
 * What is kept from the source of the ESDM:
 *
 * - The slot is the first one holding an initialized token with a random
 *   number generator - of the configured label, if one is configured.
 * - The user logs in (CKU_USER) only when a PIN is configured and the token
 *   asks for a login. Every failed login uses up one of the PIN retries of the
 *   token, after which it locks the PIN: a PIN the token refused is wiped and
 *   not tried again - neither by the look-ups for a token nor by a re-open -
 *   until the daemon is started anew with another one. A login failing for
 *   another reason - the token refusing no PIN - keeps the PIN, and the token
 *   is looked for again. A refusal is known to this process only: started
 *   anew with the same PIN, the daemon tries it once more - but not on a
 *   token whose user PIN is on its final try, so that a daemon restarted again
 *   and again with a wrong PIN does not lock the token.
 * - A token that is not there - pulled, not inserted yet, or lost to a failed
 *   C_GenerateRandom - is looked for again on demand, at most every
 *   ESDM_PKCS11_RETRY_INTERVAL_SEC. The module is loaded anew when its slots
 *   hold no usable token, as some modules - SoftHSM among them - only see a
 *   token added after they were loaded once they are loaded again.
 * - A token that repeats its output is credited with nothing until it passes
 *   a self test again.
 * - The token label goes into the status as valid UTF-8 without control
 *   characters, whatever the token reports.
 *
 * New is that a token is tested - two reads that have to differ - whenever it
 * is bound, before its data is credited: the ESDM tests a provider on its
 * first connection, which may well be before the token is there.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libp11.h>
#include <openssl/err.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_pkcs11.h"
#include "esdm_logger.h"
#include "memset_secure.h"

/*
 * Per call we ask the token for at most this many bytes. C_GenerateRandom is
 * not bounded by the standard but several tokens choke on large requests.
 */
#define ESDM_PKCS11_CHUNK_BYTES 32

/* What became of the PIN, for the status */
enum esdm_pkcs11_pin {
	/* None configured */
	ESDM_PKCS11_PIN_NONE,
	/* Configured, and not refused so far */
	ESDM_PKCS11_PIN_SET,
	/* The token refused it - wiped */
	ESDM_PKCS11_PIN_REFUSED,
	/* The token reported its user PIN locked - wiped, not tried */
	ESDM_PKCS11_PIN_LOCKED,
	/* The token reported its user PIN on its final try - wiped, not tried */
	ESDM_PKCS11_PIN_FINAL_TRY,
};

/* The verdict of the last test of the output of the token */
enum esdm_pkcs11_test {
	ESDM_PKCS11_TEST_NONE,
	ESDM_PKCS11_TEST_PASSED,
	ESDM_PKCS11_TEST_FAILED,
};

struct esdm_es_pkcs11 {
	/* The PIN of the configuration is owned by the source */
	struct esdm_es_pkcs11_config config;
	enum esdm_pkcs11_pin pin;

	PKCS11_CTX *ctx;
	bool module_loaded;
	PKCS11_SLOT *slots;
	unsigned int nslots;
	/* The slot of the token in use, NULL while there is none */
	PKCS11_SLOT *slot;
	bool logged_in;

	/* A token that repeated its output is credited with nothing */
	enum esdm_pkcs11_test test;

	/* Earliest time to look for a token again, monotonic seconds */
	time_t retry_at;

	/*
	 * Why there is no token in use, or why the last request failed - NULL
	 * once a token is bound and delivers. A string constant. The last one
	 * logged, so that a token away for long is not logged every
	 * ESDM_PKCS11_RETRY_INTERVAL_SEC.
	 */
	const char *last_error;
	const char *last_logged;
};

static struct esdm_es_pkcs11 pkcs11;

/* "PKCS#11 <token label>", see esdm_es_pkcs11_configure() */
static char esdm_es_pkcs11_name[ESDM_ES_EXT_NAME_MAX + 1];

static time_t esdm_es_pkcs11_now(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return now.tv_sec;
}

/*
 * Record @msg as the reason the source does not deliver, and log it at
 * @level unless it was what was logged last.
 */
static void esdm_es_pkcs11_error(struct esdm_es_pkcs11 *p,
				 enum esdm_logger_verbosity level,
				 const char *msg)
{
	p->last_error = msg;
	if (p->last_logged == msg)
		return;
	p->last_logged = msg;
	esdm_logger(level, LOGGER_C_ES, "PKCS#11 entropy source: %s\n", msg);
}

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
 * Copy the text @text - a token label, the module path - for the status.
 * PKCS#11 has a token report its label in UTF-8, but nothing holds a token to
 * that, and json-c writes the bytes it is given: a label that is not UTF-8
 * made the whole JSON status invalid. What is not, and a control character -
 * which a text status hands to the terminal of whoever reads it - is replaced
 * by a '?' each.
 */
static void esdm_es_pkcs11_text_copy(char *dst, size_t dstlen, const char *text)
{
	const unsigned char *s = (const unsigned char *)text;
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

static const char *esdm_es_pkcs11_slot_label(const PKCS11_SLOT *slot)
{
	return slot->token && slot->token->label ? slot->token->label :
						   "(no label)";
}

/* Wipe the PIN, which is not tried again - @why tells the status why not */
static void esdm_es_pkcs11_pin_drop(struct esdm_es_pkcs11 *p,
				    enum esdm_pkcs11_pin why)
{
	if (p->config.pin) {
		memset_secure(p->config.pin, 0, strlen(p->config.pin));
		free(p->config.pin);
		p->config.pin = NULL;
	}
	p->pin = why;
}

/*
 * Drop just the bound slot. Keeps the loaded module so that tokens can be
 * discovered again - e.g. after a smartcard is re-inserted - without paying
 * for a full module unload and reload.
 */
static void esdm_es_pkcs11_drop_slot(struct esdm_es_pkcs11 *p)
{
	if (p->logged_in && p->slot)
		PKCS11_logout(p->slot);
	p->logged_in = false;
	p->slot = NULL;
}

static void esdm_es_pkcs11_release_slots(struct esdm_es_pkcs11 *p)
{
	if (p->slots && p->ctx)
		PKCS11_release_all_slots(p->ctx, p->slots, p->nslots);
	p->slots = NULL;
	p->nslots = 0;
}

static void esdm_es_pkcs11_finalize(struct esdm_es_pkcs11 *p)
{
	esdm_es_pkcs11_drop_slot(p);
	esdm_es_pkcs11_release_slots(p);

	if (p->ctx) {
		if (p->module_loaded)
			PKCS11_CTX_unload(p->ctx);
		PKCS11_CTX_free(p->ctx);
	}
	p->ctx = NULL;
	p->module_loaded = false;
}

static PKCS11_SLOT *esdm_es_pkcs11_pick_slot(struct esdm_es_pkcs11 *p)
{
	const char *want_label = p->config.token_label;
	PKCS11_SLOT *slot;
	unsigned int i;

	for (i = 0; i < p->nslots; i++) {
		slot = &p->slots[i];
		if (!slot->token)
			continue;
		if (!slot->token->initialized)
			continue;
		if (!slot->token->hasRng)
			continue;
		if (want_label && want_label[0] != '\0' &&
		    (!slot->token->label ||
		     strcmp(slot->token->label, want_label) != 0))
			continue;
		return slot;
	}

	return NULL;
}

/*
 * Did the token refuse the PIN in the login that failed last - as wrong, as no
 * PIN it takes, as one of the wrong length, as locked or as expired - rather
 * than the login fail for another reason, a session that could not be opened,
 * a device error, a token pulled? PKCS11_login() returns -1 for anything that
 * goes wrong, but libp11 puts the CKR_ value a failed C_Login returned on the
 * OpenSSL error queue, as the reason of an error of its own library. The
 * queue is emptied.
 */
static bool esdm_es_pkcs11_pin_refused(void)
{
	/* The CKR_PIN_* values of PKCS#11, which libp11 does not export */
	static const unsigned long refused[] = {
		0xa0, /* CKR_PIN_INCORRECT */
		0xa1, /* CKR_PIN_INVALID */
		0xa2, /* CKR_PIN_LEN_RANGE */
		0xa3, /* CKR_PIN_EXPIRED */
		0xa4, /* CKR_PIN_LOCKED */
	};
	int lib = ERR_get_CKR_code();
	unsigned long err;
	bool ret = false;
	unsigned int i;

	while ((err = ERR_get_error())) {
		if (ERR_GET_LIB(err) != lib)
			continue;
		for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
			if ((unsigned long)ERR_GET_REASON(err) == refused[i])
				ret = true;
		}
	}

	return ret;
}

/*
 * Log in to the token of the bound slot with the PIN, if there is one and the
 * token asks for it.
 *
 * A PIN the token refuses is wiped, and so not tried again. Nor is a PIN tried
 * on a token reporting its user PIN locked, or on its final try: this process
 * does not know whether the PIN was refused by the daemon started before it,
 * and a refusal now would lock the PIN. A login that fails for another
 * reason keeps the PIN: the token is looked for again, and logged in to again,
 * as one lost to a failed read is.
 *
 * Returns 0 when logged in or when no login is needed, -EACCES when the token
 * refused the PIN, -EIO when the login failed otherwise.
 */
static int esdm_es_pkcs11_login(struct esdm_es_pkcs11 *p)
{
	PKCS11_TOKEN *token = p->slot->token;
	int logged_in = 0;

	if (!p->config.pin || !token->loginRequired)
		return 0;

	/* As before, a token that cannot tell is not logged in to */
	if (PKCS11_is_logged_in(p->slot, 0, &logged_in))
		return 0;
	if (logged_in) {
		p->logged_in = true;
		return 0;
	}

	if (token->userPinLocked) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"PKCS#11 entropy source: the user PIN of token '%s' is locked, the PIN is not tried\n",
			esdm_es_pkcs11_slot_label(p->slot));
		esdm_es_pkcs11_pin_drop(p, ESDM_PKCS11_PIN_LOCKED);
		/* Logged above */
		p->last_error = "the user PIN of the token is locked";
		p->last_logged = p->last_error;
		return -EACCES;
	}

	if (token->userPinFinalTry) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"PKCS#11 entropy source: the user PIN of token '%s' has one try left, the PIN is not tried - refused, it would lock the token\n",
			esdm_es_pkcs11_slot_label(p->slot));
		esdm_es_pkcs11_pin_drop(p, ESDM_PKCS11_PIN_FINAL_TRY);
		/* Logged above */
		p->last_error = "the user PIN of the token has one try left";
		p->last_logged = p->last_error;
		return -EACCES;
	}

	/* Refused since the last login - maybe by a daemon started before */
	if (token->userPinCountLow)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"PKCS#11 entropy source: token '%s' refused a user PIN since its last login, trying the PIN\n",
			esdm_es_pkcs11_slot_label(p->slot));

	/* What the login leaves on the queue is to be about the login */
	ERR_clear_error();
	if (PKCS11_login(p->slot, 0, p->config.pin) != 0) {
		if (!esdm_es_pkcs11_pin_refused()) {
			esdm_es_pkcs11_error(
				p, LOGGER_WARN,
				"the login to the token failed, the token is looked for again");
			return -EIO;
		}

		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"PKCS#11 entropy source: token '%s' refused the PIN, which is not tried again\n",
			esdm_es_pkcs11_slot_label(p->slot));
		esdm_es_pkcs11_pin_drop(p, ESDM_PKCS11_PIN_REFUSED);
		p->last_error = "the token refused the PIN";
		p->last_logged = p->last_error;
		return -EACCES;
	}
	p->logged_in = true;

	return 0;
}

/* Why a token is credited with nothing, until a test passes again */
static const char esdm_es_pkcs11_repeated[] = "the token repeated its output";

/*
 * Two reads of the bound token that have to succeed and have to differ. A
 * token that does not deliver is dropped, as a failed read does, and looked
 * for again.
 *
 * Returns 0 if the token passed, -EIO if it did not deliver, -EFAULT if it
 * repeated its output.
 */
static int esdm_es_pkcs11_test_token(struct esdm_es_pkcs11 *p)
{
	uint8_t first[16], second[16];
	int ret = 0;

	if (PKCS11_generate_random(p->slot, first, sizeof(first)) ||
	    PKCS11_generate_random(p->slot, second, sizeof(second))) {
		esdm_es_pkcs11_drop_slot(p);
		esdm_es_pkcs11_error(p, LOGGER_ERR,
				     "the token did not deliver");
		ret = -EIO;
		goto out;
	}

	if (!memcmp(first, second, sizeof(first))) {
		p->test = ESDM_PKCS11_TEST_FAILED;
		esdm_es_pkcs11_error(p, LOGGER_ERR, esdm_es_pkcs11_repeated);
		ret = -EFAULT;
		goto out;
	}

	p->test = ESDM_PKCS11_TEST_PASSED;
	if (p->last_error == esdm_es_pkcs11_repeated) {
		p->last_error = NULL;
		p->last_logged = NULL;
	}

out:
	memset_secure(first, 0, sizeof(first));
	memset_secure(second, 0, sizeof(second));
	return ret;
}

/*
 * Take a usable slot among the slots enumerated, log in to its token and test
 * it.
 *
 * Returns 0 with a token bound, -ENOENT when no matching token is present,
 * -EACCES when the token refused the PIN, -EIO when the login failed otherwise
 * or the token does not deliver.
 */
static int esdm_es_pkcs11_bind(struct esdm_es_pkcs11 *p)
{
	int ret;

	p->slot = esdm_es_pkcs11_pick_slot(p);
	if (!p->slot) {
		esdm_es_pkcs11_error(
			p, LOGGER_WARN,
			p->config.token_label && p->config.token_label[0] ?
				"no token of the configured label with a random number generator found, looked for again on demand" :
				"no usable token with a random number generator found, looked for again on demand");
		return -ENOENT;
	}

	/* The refusal is logged there */
	ret = esdm_es_pkcs11_login(p);
	if (ret) {
		p->slot = NULL;
		return ret;
	}

	p->last_error = NULL;
	p->last_logged = NULL;
	esdm_logger(LOGGER_VERBOSE, LOGGER_C_ES,
		    "PKCS#11 entropy source using token '%s' (module %s)\n",
		    esdm_es_pkcs11_slot_label(p->slot), p->config.module_path);

	/* A repeated output keeps the token bound, credited with nothing */
	ret = esdm_es_pkcs11_test_token(p);
	return ret == -EIO ? ret : 0;
}

/*
 * Open the PKCS#11 module and select a usable slot. Any previously held module
 * and slot state is torn down first. A module that loads stays loaded without
 * a usable token, for esdm_es_pkcs11_refresh_slot() to look among its slots
 * again.
 *
 * Returns 0 on success. Negative errno otherwise: -ENODEV when the module
 * cannot be loaded, -EIO when its slots cannot be enumerated, or what
 * esdm_es_pkcs11_bind() returns.
 */
static int esdm_es_pkcs11_open_module(struct esdm_es_pkcs11 *p)
{
	esdm_es_pkcs11_finalize(p);

	p->ctx = PKCS11_CTX_new();
	if (!p->ctx) {
		esdm_es_pkcs11_error(
			p, LOGGER_WARN,
			"PKCS11_CTX_new failed, retried on demand");
		return -ENOMEM;
	}

	if (PKCS11_CTX_load(p->ctx, p->config.module_path) != 0) {
		esdm_es_pkcs11_error(
			p, LOGGER_WARN,
			"the PKCS#11 module cannot be loaded, retried on demand");
		PKCS11_CTX_free(p->ctx);
		p->ctx = NULL;
		return -ENODEV;
	}
	p->module_loaded = true;

	if (PKCS11_enumerate_slots(p->ctx, &p->slots, &p->nslots) < 0) {
		esdm_es_pkcs11_error(
			p, LOGGER_WARN,
			"the slots of the module cannot be enumerated, retried on demand");
		p->slots = NULL;
		p->nslots = 0;
		return -EIO;
	}

	return esdm_es_pkcs11_bind(p);
}

/*
 * Try to (re-)bind to a usable token, keeping the module loaded where that
 * works out: after a read failure, and when the smartcard has been physically
 * removed and re-inserted. PKCS#11 only refreshes its slot view via
 * release_all_slots + enumerate_slots. The module is loaded anew when it is
 * not loaded, and when its slots carry no usable token - some modules,
 * SoftHSM among them, only see a token added after they were loaded once they
 * are loaded again.
 *
 * Returns 0 on success, a negative errno as esdm_es_pkcs11_open_module() does
 * otherwise.
 */
static int esdm_es_pkcs11_refresh_slot(struct esdm_es_pkcs11 *p)
{
	int ret;

	/* Drop any previous slot binding before refreshing. */
	esdm_es_pkcs11_drop_slot(p);

	if (!p->ctx)
		return esdm_es_pkcs11_open_module(p);

	/* Refresh the slot list so newly-inserted tokens become visible. */
	esdm_es_pkcs11_release_slots(p);
	if (PKCS11_enumerate_slots(p->ctx, &p->slots, &p->nslots) < 0) {
		p->slots = NULL;
		p->nslots = 0;
		return esdm_es_pkcs11_open_module(p);
	}

	ret = esdm_es_pkcs11_bind(p);
	if (ret == -ENOENT)
		return esdm_es_pkcs11_open_module(p);

	return ret;
}

/* Look for a token again if none is bound, rate limited. */
static void esdm_es_pkcs11_reacquire(struct esdm_es_pkcs11 *p)
{
	time_t now;

	if (p->slot)
		return;

	now = esdm_es_pkcs11_now();
	if (now < p->retry_at)
		return;

	p->retry_at = now + ESDM_PKCS11_RETRY_INTERVAL_SEC;
	(void)esdm_es_pkcs11_refresh_slot(p);
}

static int esdm_es_pkcs11_init(void **ctx)
{
	struct esdm_es_pkcs11 *p = &pkcs11;

	*ctx = p;
	p->retry_at = 0;
	p->test = ESDM_PKCS11_TEST_NONE;

	/*
	 * A module that does not load, or a token that is not there, is no
	 * reason to refuse to serve: the source looks for them again on
	 * demand, and the ESDM credits it with nothing until it delivers.
	 */
	(void)esdm_es_pkcs11_open_module(p);

	return 0;
}

static void esdm_es_pkcs11_fini(void *ctx)
{
	struct esdm_es_pkcs11 *p = ctx;

	esdm_es_pkcs11_finalize(p);
	esdm_es_pkcs11_pin_drop(p, p->pin);
}

static int esdm_es_pkcs11_get(void *ctx, uint8_t *buf, size_t buflen,
			      uint32_t *entropy_bits)
{
	struct esdm_es_pkcs11 *p = ctx;
	uint8_t chunk[ESDM_PKCS11_CHUNK_BYTES];
	size_t done = 0;
	int ret = 0;

	*entropy_bits = 0;

	esdm_es_pkcs11_reacquire(p);
	if (!p->slot)
		return -ENODEV;

	while (done < buflen) {
		size_t len = buflen - done;

		if (len > sizeof(chunk))
			len = sizeof(chunk);

		if (PKCS11_generate_random(p->slot, chunk, (unsigned int)len) !=
		    0) {
			/*
			 * Don't tear the module down - a transient error (e.g.
			 * smartcard removed) just drops the slot binding, and
			 * the next request looks for a token again. This
			 * request credits nothing.
			 */
			esdm_es_pkcs11_drop_slot(p);
			esdm_es_pkcs11_error(
				p, LOGGER_WARN,
				"C_GenerateRandom failed, the token is looked for again");
			ret = -EIO;
			goto out;
		}

		memcpy(buf + done, chunk, len);
		done += len;
	}

	/* A token that repeated its output is credited with nothing */
	if (p->test != ESDM_PKCS11_TEST_FAILED) {
		uint64_t bits = (uint64_t)buflen * 8 * p->config.entropy_rate /
				ESDM_ES_EXT_ENTROPY_RATE_MAX;

		*entropy_bits = (uint32_t)(bits > (uint64_t)buflen * 8 ?
						   (uint64_t)buflen * 8 :
						   bits);
	}

	esdm_logger(
		LOGGER_DEBUG, LOGGER_C_ES,
		"PKCS#11 entropy source: %zu bytes with %u bits of entropy\n",
		buflen, *entropy_bits);

out:
	memset_secure(chunk, 0, sizeof(chunk));
	return ret;
}

/*
 * Two reads of the token that have to succeed and have to differ. An absent
 * token is no failure: the source waits for one to come back, and tests it
 * when it is bound.
 */
static int esdm_es_pkcs11_selftest(void *ctx)
{
	struct esdm_es_pkcs11 *p = ctx;

	if (!p->slot) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"PKCS#11 entropy source: no token - nothing to test\n");
		return 0;
	}

	return esdm_es_pkcs11_test_token(p) ? -EFAULT : 0;
}

static const char *esdm_es_pkcs11_pin_state(enum esdm_pkcs11_pin pin)
{
	switch (pin) {
	case ESDM_PKCS11_PIN_SET:
		return "set";
	case ESDM_PKCS11_PIN_REFUSED:
		return "refused";
	case ESDM_PKCS11_PIN_LOCKED:
		return "locked";
	case ESDM_PKCS11_PIN_FINAL_TRY:
		return "final_try";
	case ESDM_PKCS11_PIN_NONE:
	default:
		return "none";
	}
}

static const char *esdm_es_pkcs11_test_state(enum esdm_pkcs11_test test)
{
	switch (test) {
	case ESDM_PKCS11_TEST_PASSED:
		return "passed";
	case ESDM_PKCS11_TEST_FAILED:
		return "failed";
	case ESDM_PKCS11_TEST_NONE:
	default:
		return "none";
	}
}

/* A string of the status, null for none */
static struct json_object *esdm_es_pkcs11_json_text(const char *text)
{
	char copy[PATH_MAX];

	if (!text || !text[0])
		return NULL;
	esdm_es_pkcs11_text_copy(copy, sizeof(copy), text);
	return json_object_new_string(copy);
}

/*
 * The status of the source - what helps whoever reads the ESDM status:
 *
 * { "module": "/usr/lib/softhsm/libsofthsm2.so", "token_label": null,
 *   "token": "my-token", "slot": 1, "token_present": true,
 *   "logged_in": true, "pin": "set", "repetition_test": "passed",
 *   "last_error": null }
 *
 * A module path too long for the status is shortened to its file name.
 */
static int esdm_es_pkcs11_status(void *ctx, char *buf, size_t buflen)
{
	struct esdm_es_pkcs11 *p = ctx;
	const char *module = p->config.module_path;
	unsigned int attempt;

	for (attempt = 0; attempt < 2; attempt++) {
		struct json_object *obj = json_object_new_object();
		const char *text;
		size_t len;

		if (!obj)
			return -ENOMEM;

		json_object_object_add(obj, "module",
				       esdm_es_pkcs11_json_text(module));
		json_object_object_add(
			obj, "token_label",
			esdm_es_pkcs11_json_text(p->config.token_label));
		json_object_object_add(
			obj, "token",
			p->slot ? esdm_es_pkcs11_json_text(
					  esdm_es_pkcs11_slot_label(p->slot)) :
				  NULL);
		json_object_object_add(
			obj, "slot",
			p->slot ?
				json_object_new_uint64(
					PKCS11_get_slotid_from_slot(p->slot)) :
				NULL);
		json_object_object_add(obj, "token_present",
				       json_object_new_boolean(p->slot !=
							       NULL));
		json_object_object_add(obj, "logged_in",
				       json_object_new_boolean(p->logged_in));
		json_object_object_add(
			obj, "pin",
			json_object_new_string(
				esdm_es_pkcs11_pin_state(p->pin)));
		json_object_object_add(
			obj, "repetition_test",
			json_object_new_string(
				esdm_es_pkcs11_test_state(p->test)));
		json_object_object_add(obj, "last_error",
				       esdm_es_pkcs11_json_text(p->last_error));

		text = json_object_to_json_string_ext(
			obj, JSON_C_TO_STRING_PLAIN |
				     JSON_C_TO_STRING_NOSLASHESCAPE);
		len = text ? strlen(text) : SIZE_MAX;
		if (len < buflen) {
			memcpy(buf, text, len + 1);
			json_object_put(obj);
			return 0;
		}
		json_object_put(obj);

		/* Once more with the file name of the module alone */
		if (module && strrchr(module, '/'))
			module = strrchr(module, '/') + 1;
	}

	return -EMSGSIZE;
}

static uint32_t esdm_es_pkcs11_entropy_rate(void *ctx)
{
	struct esdm_es_pkcs11 *p = ctx;

	return p->config.entropy_rate;
}

struct esdm_es_ext_plugin esdm_es_pkcs11_plugin = {
	.version = ESDM_ES_EXT_PLUGIN_VERSION,
	.name = ESDM_PKCS11_NAME,
	.init = esdm_es_pkcs11_init,
	.fini = esdm_es_pkcs11_fini,
	.get_entropy = esdm_es_pkcs11_get,
	.selftest = esdm_es_pkcs11_selftest,
	.status_json = esdm_es_pkcs11_status,
	.entropy_rate = esdm_es_pkcs11_entropy_rate,
};

void esdm_es_pkcs11_configure(struct esdm_es_pkcs11_config *config)
{
	pkcs11.config = *config;
	pkcs11.pin = config->pin ? ESDM_PKCS11_PIN_SET : ESDM_PKCS11_PIN_NONE;
	/* Owned by the source now */
	config->pin = NULL;

	/*
	 * The name the source declares: "PKCS#11", followed by the label of
	 * the token where one is configured - which tells one daemon from the
	 * next in the ESDM status and log - if that makes a valid name.
	 */
	esdm_es_pkcs11_plugin.name = ESDM_PKCS11_NAME;
	if (config->token_label && config->token_label[0]) {
		int len = snprintf(esdm_es_pkcs11_name,
				   sizeof(esdm_es_pkcs11_name), "%s %s",
				   ESDM_PKCS11_NAME, config->token_label);

		if (len > 0 && (size_t)len < sizeof(esdm_es_pkcs11_name) &&
		    esdm_es_ext_name_valid(esdm_es_pkcs11_name, (size_t)len))
			esdm_es_pkcs11_plugin.name = esdm_es_pkcs11_name;
	}
}
