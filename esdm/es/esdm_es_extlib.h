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

#ifndef _ESDM_ES_EXTLIB_H
#define _ESDM_ES_EXTLIB_H

#include <errno.h>

#include "config.h"
#include "esdm_es_mgr_cb.h"
#include "visibility.h"

/*
 * The plugin library sources: ESDM_EXT_LIB_NUM of them (meson option
 * es_ext_lib_num), each an entry of the ES table of its own, from
 * esdm_ext_es_extlib_first to esdm_ext_es_extlib_last. Its name in the ES
 * table, and in the ESDM status, carries the index of the source - unless the
 * source is the only one, which is ExternalLib, as it ever was.
 */
#if ESDM_EXT_LIB_NUM > 1
#define ESDM_ES_EXTLIB_NAME(i) "ExternalLib" #i
#else
#define ESDM_ES_EXTLIB_NAME(i) "ExternalLib"
#endif

#if ESDM_EXT_LIB_NUM > 0

/*
 * A plugin whose request failed is asked by the ES monitor again, at most once
 * per this many seconds, to find out whether it recovered.
 */
#ifndef ESDM_EXT_LIB_PROBE_INTERVAL_SEC
#define ESDM_EXT_LIB_PROBE_INTERVAL_SEC 5
#endif

extern struct esdm_es_cb esdm_es_extlib[ESDM_EXT_LIB_NUM];

/**
 * @brief Select the plugin library loaded as external entropy source
 *
 * The path replaces the compile-time default of the plugin library source @idx
 * (its entry in the meson option es_ext_lib_path). Set before esdm_init(), as
 * the server does for its --es_ext_lib option, the plugin is loaded and
 * initialized by the initialization of the source, while the daemon still has
 * its privileges; set later, the plugin in use is released and the new one
 * loaded right away. Pass an empty string to go back to the compile-time
 * default.
 *
 * The path is kept across esdm_fini() and applies to a later esdm_init() or
 * esdm_reinit() again. A plugin library serves one source: a source asked to
 * load the plugin another one uses refuses it. See libesdm_es_ext(3) on the
 * plugins.
 *
 * @param [in] idx Index of the plugin library source, below ESDM_EXT_LIB_NUM
 * @param [in] path NUL-terminated path of the plugin library, must not be NULL.
 *
 * @return 0 on success, -EINVAL if there is no source @idx or path is NULL,
 *	   -ENOMEM on allocation failure, or - when the source already runs - a
 *	   negative errno from loading the plugin: -ENOENT if the library cannot
 *	   be loaded, -ENOEXEC if it exports no plugin, -EPROTO if the plugin does
 *	   not fit, -EBUSY if another source uses it, or the error of the
 *	   plugin's init callback.
 */
DSO_PUBLIC
int esdm_es_ext_lib_set_path(unsigned int idx, const char *path);

#else /* ESDM_EXT_LIB_NUM */

/* No such source: -ENOENT without external sources, -EINVAL without this kind */
static inline int esdm_es_ext_lib_set_path(unsigned int idx, const char *path)
{
	(void)idx;
	(void)path;
#ifdef ESDM_ES_EXT
	return -EINVAL;
#else
	return -ENOENT;
#endif
}

#endif /* ESDM_EXT_LIB_NUM */

#endif /* _ESDM_ES_EXTLIB_H */
