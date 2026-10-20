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
 * The PKCS#11 entropy source of esdm-es-pkcs11(8): the random number generator
 * of a PKCS#11 token, read with C_GenerateRandom through libp11, as the
 * callbacks of a provider of libesdm_es_ext that the daemon serves - see
 * esdm_es_ext.h on struct esdm_es_ext_plugin and the provider server.
 */

#ifndef _ESDM_ES_PKCS11_H
#define _ESDM_ES_PKCS11_H

#include <stdint.h>

#include "esdm_es_ext.h"

/*
 * A token lost to a failed C_GenerateRandom, or not there yet, is looked for
 * again on demand, at most once per this many seconds: a pulled smartcard must
 * not take the source out for good, nor a broken token cost a slot
 * enumeration per request.
 */
#ifndef ESDM_PKCS11_RETRY_INTERVAL_SEC
#define ESDM_PKCS11_RETRY_INTERVAL_SEC 5
#endif

/* The name the source declares unless told otherwise - see esdm_es_ext.h */
#define ESDM_PKCS11_NAME "PKCS#11"

/**
 * struct esdm_es_pkcs11_config - what the source is told to use
 *
 * @module_path: Path of the PKCS#11 module, which must not be empty
 * @token_label: Label of the token to use; NULL or empty for the first slot
 *		 holding an initialized token with a random number generator
 * @pin: User PIN, NUL-terminated, NULL for none. The source takes it over: it
 *	 wipes and frees it once the token refused it, and at its fini.
 * @entropy_rate: Bits of entropy per 256 bits of data the source declares
 */
struct esdm_es_pkcs11_config {
	const char *module_path;
	const char *token_label;
	char *pin;
	uint32_t entropy_rate;
};

/**
 * @brief Configure the source before the provider server initializes it
 *
 * The strings @config points to, but for the PIN, are referenced, not copied:
 * they have to outlive the source.
 *
 * @param [in] config What the source is to use
 */
void esdm_es_pkcs11_configure(struct esdm_es_pkcs11_config *config);

/* The source, to be served by the provider program of libesdm_es_ext */
extern struct esdm_es_ext_plugin esdm_es_pkcs11_plugin;

#endif /* _ESDM_ES_PKCS11_H */
