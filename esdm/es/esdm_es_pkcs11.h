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

#ifndef _ESDM_ES_PKCS11_H
#define _ESDM_ES_PKCS11_H

#include <errno.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"
#include "visibility.h"

#ifdef ESDM_ES_PKCS11

/*
 * A token lost to a failed C_GenerateRandom, or not there yet, is looked for
 * again on demand, at most once per this many seconds: a pulled smartcard must
 * not take the source out for good, nor a broken token cost a slot
 * enumeration per request.
 */
#define ESDM_PKCS11_RETRY_INTERVAL_SEC 5

extern struct esdm_es_cb esdm_es_pkcs11;

/**
 * @brief Install a runtime user PIN for the PKCS#11 entropy source.
 *
 * The PIN replaces any previously configured runtime PIN. If the PKCS#11
 * module has already been initialized and the configured token requires a
 * login, this function additionally attempts CKU_USER login with the new PIN.
 *
 * Pass an empty string to clear the runtime PIN; subsequent re-inits then
 * fall back to the compile-time default (if any).
 *
 * The PIN is held in process memory only and is not persisted across server
 * restarts.
 *
 * @param [in] pin NUL-terminated user PIN, must not be NULL.
 *
 * @return 0 on success, -ENOMEM on allocation failure, -EACCES if the login
 *	   attempt against the token failed, -EINVAL if pin is NULL.
 */
DSO_PUBLIC
int esdm_es_pkcs11_set_pin(const char *pin);

/**
 * @brief Install a runtime token label for the PKCS#11 entropy source.
 *
 * The label replaces any previously configured runtime token label and
 * triggers a re-open of the PKCS#11 module so that a slot whose token label
 * matches is selected. Pass an empty string to clear the runtime override;
 * the module is then re-opened against the compile-time default (or the
 * first usable slot if none is configured).
 *
 * The label is held in process memory only and is not persisted across
 * server restarts.
 *
 * @param [in] label NUL-terminated token label, must not be NULL.
 *
 * @return 0 on success, -EINVAL if label is NULL, -ENOMEM on allocation
 *	   failure, or a negative errno from the module re-open: -ENODEV when
 *	   the module cannot be loaded, -ENOENT when no matching token is
 *	   present, -EACCES when login fails.
 */
DSO_PUBLIC
int esdm_es_pkcs11_set_token_label(const char *label);

/**
 * @brief Select the PKCS#11 provider module the entropy source loads.
 *
 * The path replaces the compile-time default ESDM_PKCS11_MODULE_PATH (meson
 * option es_pkcs11_module_path). Set before esdm_init(), as the server does for
 * its --pkcs11_module option, the module is loaded by the initialization of the
 * source; set later, the module in use is unloaded and the new one loaded right
 * away. Pass an empty string to go back to the compile-time default.
 *
 * Unlike the PIN and the token label, the path is kept across esdm_fini() and
 * applies to a later esdm_init() or esdm_reinit() again.
 *
 * @param [in] path NUL-terminated path of the PKCS#11 module, must not be NULL.
 *
 * @return 0 on success, -EINVAL if path is NULL, -ENOMEM on allocation
 *	   failure, or - when the source already runs - a negative errno from
 *	   the module re-open as for esdm_es_pkcs11_set_token_label().
 */
DSO_PUBLIC
int esdm_es_pkcs11_set_module_path(const char *path);

#else /* ESDM_ES_PKCS11 */

static inline int esdm_es_pkcs11_set_pin(const char *pin)
{
	(void)pin;
	return -ENOENT;
}

static inline int esdm_es_pkcs11_set_token_label(const char *label)
{
	(void)label;
	return -ENOENT;
}

static inline int esdm_es_pkcs11_set_module_path(const char *path)
{
	(void)path;
	return -ENOENT;
}

#endif /* ESDM_ES_PKCS11 */

#endif /* _ESDM_ES_PKCS11_H */
