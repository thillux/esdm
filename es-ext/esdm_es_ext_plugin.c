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
 * Loading a plugin library for esdm_es_ext_server_alloc() - see esdm_es_ext.h.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>

#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_logger.h"
#include "visibility.h"

struct esdm_es_ext_plugin_handle {
	void *dl;
};

DSO_PUBLIC
int esdm_es_ext_plugin_load(const char *path,
			    struct esdm_es_ext_plugin_handle **handle,
			    const struct esdm_es_ext_plugin **plugin)
{
	struct esdm_es_ext_plugin_handle *h;
	const struct esdm_es_ext_plugin *p;

	if (!path || !handle || !plugin)
		return -EINVAL;
	*handle = NULL;
	*plugin = NULL;

	h = calloc(1, sizeof(*h));
	if (!h)
		return -ENOMEM;

	/*
	 * RTLD_LOCAL: the symbols of one plugin are no business of another one
	 * or of the program. RTLD_NOW: an unresolved symbol fails the load, not
	 * the first request.
	 */
	h->dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!h->dl) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "External ES: cannot load plugin %s: %s\n", path,
			    dlerror());
		free(h);
		return -ENOENT;
	}

	p = dlsym(h->dl, ESDM_ES_EXT_PLUGIN_SYMBOL);
	if (!p) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "External ES: %s exports no %s\n", path,
			    ESDM_ES_EXT_PLUGIN_SYMBOL);
		esdm_es_ext_plugin_unload(h);
		return -ENOEXEC;
	}

	if (esdm_es_ext_plugin_check(p)) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ANY,
			"External ES: plugin %s is of version %u, version %u with a get_entropy callback is supported\n",
			path, p->version, ESDM_ES_EXT_PLUGIN_VERSION);
		esdm_es_ext_plugin_unload(h);
		return -EPROTO;
	}

	*handle = h;
	*plugin = p;
	return 0;
}

DSO_PUBLIC
void esdm_es_ext_plugin_unload(struct esdm_es_ext_plugin_handle *handle)
{
	if (!handle)
		return;

	if (handle->dl)
		dlclose(handle->dl);
	free(handle);
}
