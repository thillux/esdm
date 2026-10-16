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

#ifdef ESDM_ES_EXT

/*
 * A plugin whose request failed is asked by the ES monitor again, at most once
 * per this many seconds, to find out whether it recovered.
 */
#ifndef ESDM_EXT_LIB_PROBE_INTERVAL_SEC
#define ESDM_EXT_LIB_PROBE_INTERVAL_SEC 5
#endif

extern struct esdm_es_cb esdm_es_extlib;

/**
 * @brief Select the plugin library loaded as external entropy source
 *
 * The path replaces the compile-time default ESDM_EXT_LIB_PATH (meson option
 * es_ext_lib_path). Set before esdm_init(), as the server does for its
 * --es_ext_lib option, the plugin is loaded and initialized by the
 * initialization of the source, while the daemon still has its privileges; set
 * later, the plugin in use is released and the new one loaded right away. Pass
 * an empty string to go back to the compile-time default.
 *
 * The path is kept across esdm_fini() and applies to a later esdm_init() or
 * esdm_reinit() again. See libesdm_es_ext(3) on the plugins.
 *
 * @param [in] path NUL-terminated path of the plugin library, must not be NULL.
 *
 * @return 0 on success, -EINVAL if path is NULL, -ENOMEM on allocation
 *	   failure, or - when the source already runs - a negative errno from
 *	   loading the plugin: -ENOENT if the library cannot be loaded, -ENOEXEC
 *	   if it exports no plugin, -EPROTO if the plugin does not fit, or the
 *	   error of the plugin's init callback.
 */
DSO_PUBLIC
int esdm_es_ext_lib_set_path(const char *path);

#else /* ESDM_ES_EXT */

static inline int esdm_es_ext_lib_set_path(const char *path)
{
	(void)path;
	return -ENOENT;
}

#endif /* ESDM_ES_EXT */

#endif /* _ESDM_ES_EXTLIB_H */
