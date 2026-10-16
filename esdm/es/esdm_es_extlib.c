/*
 * ESDM External Entropy Source: plugin library loaded into the ESDM
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
 * A struct esdm_es_ext_plugin of a shared library - see libesdm_es_ext(3) -
 * called directly as entropy source.
 *
 * The plugin is loaded and initialized by the init of the source, which
 * esdm_init() runs while the server still has its privileges. Its callbacks
 * are called under extlib_mutex, so never concurrently, as the plugin API
 * promises.
 *
 * A block is credited with what the plugin claims for it, at most with what
 * the configured rate allows (esdm_config_es_ext_lib_entropy_rate()). A
 * plugin that fails to deliver - or claims more than the data can hold, which
 * counts as a failure - is credited with nothing until it delivers again: on
 * a seeding that asks it, its data then going into the additional data, or on
 * a probe of the ES monitor. A plugin failing its self test is credited with
 * nothing until a self test passes.
 */

#include <dlfcn.h>
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "build_bug_on.h"
#include "esdm_config.h"
#include "esdm_definitions.h"
#include "esdm_es_aux.h"
#include "esdm_es_ext.h"
#include "esdm_es_ext_proto.h"
#include "esdm_es_ext_status.h"
#include "esdm_es_extlib.h"
#include "esdm_es_mgr.h"
#include "esdm_logger.h"
#include "helper.h"
#include "memset_secure.h"
#include "mutex.h"
#include "visibility.h"

static DEFINE_MUTEX_UNLOCKED(extlib_mutex);

/*
 * Override of the plugin path, as given on the command line of the server.
 * NULL means "use the compile-time default ESDM_EXT_LIB_PATH". Configuration
 * like the entropy rates: it outlives esdm_fini().
 */
static char *extlib_runtime_path = NULL;

/* The plugin loaded and initialized, all NULL if none is */
static void *extlib_dl = NULL;
static const struct esdm_es_ext_plugin *extlib_plugin = NULL;
static void *extlib_ctx = NULL;
/* The path it was loaded from */
static char extlib_loaded_path[PATH_MAX];

/*
 * The last request to the plugin failed, or its last self test did. They are
 * kept apart: data delivered says nothing about the noise source a self test
 * found broken, so only a self test that passes clears its failure, and only
 * data delivered clears a failed request. Set and cleared under the write
 * lock, read under the reader lock.
 */
static bool extlib_read_failed = false;
static bool extlib_selftest_failed = false;

/* Earliest time to probe a plugin whose request failed, monotonic seconds */
static time_t extlib_probe_at = 0;

/* Between init and fini - a new path is loaded at once then */
static bool extlib_initialized = false;

/* The last status of the plugin was none and logged as such */
static bool extlib_status_warned = false;

/* Caller must hold extlib_mutex. */
static const char *esdm_es_extlib_path_locked(void)
{
	return extlib_runtime_path ? extlib_runtime_path : ESDM_EXT_LIB_PATH;
}

/* Caller must hold extlib_mutex (write lock). */
static void esdm_es_extlib_unload_locked(void)
{
	if (extlib_plugin && extlib_plugin->fini)
		extlib_plugin->fini(extlib_ctx);
	extlib_plugin = NULL;
	extlib_ctx = NULL;

	if (extlib_dl)
		dlclose(extlib_dl);
	extlib_dl = NULL;

	extlib_loaded_path[0] = '\0';
	extlib_read_failed = false;
	extlib_selftest_failed = false;
	extlib_status_warned = false;
}

/*
 * Initialize the plugin of the library already loaded. Caller must hold
 * extlib_mutex (write lock).
 */
static int esdm_es_extlib_init_plugin_locked(const struct esdm_es_ext_plugin *p)
{
	void *ctx = NULL;
	int ret = 0;

	if (p->init) {
		ret = p->init(&ctx);
		if (ret > 0)
			ret = -EIO;
		if (ret) {
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES plugin: initialization of %s failed: %s\n",
				p->name ? p->name : "the plugin",
				strerror(-ret));
			return ret;
		}
	}

	extlib_plugin = p;
	extlib_ctx = ctx;
	extlib_read_failed = false;
	extlib_selftest_failed = false;
	return 0;
}

/*
 * Load the plugin library of the configured path, replacing the one in use.
 * Caller must hold extlib_mutex (write lock).
 *
 * A plugin already loaded from the same path is initialized anew rather than
 * loaded again: a re-init of the ESDM runs after the server dropped its
 * privileges, which may no longer suffice to load the library.
 */
static int esdm_es_extlib_load_locked(void)
{
	const char *path = esdm_es_extlib_path_locked();
	const struct esdm_es_ext_plugin *p;
	void *dl;
	int ret;

	/* A library is only kept loaded with its plugin initialized */
	if (extlib_plugin && !strcmp(extlib_loaded_path, path)) {
		p = extlib_plugin;
		if (p->fini)
			p->fini(extlib_ctx);
		extlib_plugin = NULL;
		extlib_ctx = NULL;

		ret = esdm_es_extlib_init_plugin_locked(p);
		if (ret)
			esdm_es_extlib_unload_locked();
		return ret;
	}

	esdm_es_extlib_unload_locked();

	if (path[0] == '\0')
		return 0;

	if (strlen(path) >= sizeof(extlib_loaded_path))
		return -ENAMETOOLONG;

	/* See esdm_es_ext_plugin_load() of libesdm_es_ext on the flags */
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!dl) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin: cannot load %s: %s\n",
			path, dlerror());
		return -ENOENT;
	}

	p = dlsym(dl, ESDM_ES_EXT_PLUGIN_SYMBOL);
	if (!p) {
		esdm_logger(LOGGER_WARN, LOGGER_C_ES,
			    "Disabling external ES plugin: %s exports no %s\n",
			    path, ESDM_ES_EXT_PLUGIN_SYMBOL);
		dlclose(dl);
		return -ENOEXEC;
	}

	if (esdm_es_ext_plugin_check(p)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin: %s is of version %u, versions 1 to %u with a get_entropy callback are supported\n",
			path, p->version, ESDM_ES_EXT_PLUGIN_VERSION);
		dlclose(dl);
		return -EPROTO;
	}

	extlib_dl = dl;
	snprintf(extlib_loaded_path, sizeof(extlib_loaded_path), "%s", path);

	ret = esdm_es_extlib_init_plugin_locked(p);
	if (ret) {
		esdm_es_extlib_unload_locked();
		return ret;
	}

	/* Its claims are not assessed by the ESDM, which is worth a line */
	esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
		    "External ES plugin %s loaded from %s, its entropy claims credited with up to %u bits per 256 bits\n",
		    p->name ? p->name : "(unnamed)", path,
		    esdm_config_es_ext_lib_entropy_rate());

	return 0;
}

static int esdm_es_extlib_init(void)
{
	/* What a plugin delivers per request fits into a seed buffer */
	BUILD_BUG_ON(ESDM_DRNG_INIT_SEED_SIZE_BYTES >
		     ESDM_ES_EXT_PROTO_MAX_DATA);

	mutex_lock(&extlib_mutex);
	/* A plugin that cannot be loaded leaves the source switched off */
	(void)esdm_es_extlib_load_locked();
	extlib_initialized = true;
	mutex_unlock(&extlib_mutex);

	return 0;
}

static void esdm_es_extlib_fini(void)
{
	mutex_lock(&extlib_mutex);
	esdm_es_extlib_unload_locked();
	extlib_initialized = false;
	mutex_unlock(&extlib_mutex);
}

/* Caller must hold extlib_mutex. */
static uint32_t esdm_es_extlib_entropylevel_locked(uint32_t requested_bits)
{
	if (!extlib_plugin || extlib_read_failed || extlib_selftest_failed)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_ext_lib_entropy_rate(), requested_bits);
}

static uint32_t esdm_es_extlib_entropylevel(uint32_t requested_bits)
{
	uint32_t ret;

	mutex_reader_lock(&extlib_mutex);
	ret = esdm_es_extlib_entropylevel_locked(requested_bits);
	mutex_reader_unlock(&extlib_mutex);

	return ret;
}

static uint32_t esdm_es_extlib_poolsize(void)
{
	return esdm_es_extlib_entropylevel(esdm_security_strength());
}

static void esdm_es_extlib_get(struct entropy_es *eb_es,
			       uint32_t requested_bits,
			       bool __unused allow_cached)
{
	uint32_t claimed, len = requested_bits >> 3;
	int ret;

	eb_es->e_bits = 0;
	if (!len || len > sizeof(eb_es->e))
		return;

	/* Exclusive: the outcome of the request is recorded */
	mutex_lock(&extlib_mutex);

	if (!extlib_plugin)
		goto out;

	ret = esdm_es_ext_plugin_get(extlib_plugin, extlib_ctx, eb_es->e, len,
				     &claimed);
	if (ret) {
		if (!extlib_read_failed)
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES plugin: no entropy delivered: %s\n",
				strerror(-ret));
		extlib_read_failed = true;
		goto out;
	}

	extlib_read_failed = false;
	eb_es->e_bits = min_uint32(
		claimed, esdm_es_extlib_entropylevel_locked(requested_bits));

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from external ES plugin\n",
		    eb_es->e_bits);

out:
	mutex_unlock(&extlib_mutex);
}

/*
 * A plugin whose request failed is credited with nothing, which keeps it out
 * of what an unforced reseed waits for - and such a reseed asks no source at
 * all while too little entropy is available. The monitor asks it instead, at
 * most every ESDM_EXT_LIB_PROBE_INTERVAL_SEC seconds, and discards what it
 * delivers: data it delivers again makes it credited again.
 */
static int esdm_es_extlib_monitor(void)
{
	uint8_t probe[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	struct timespec now;
	uint32_t claimed;

	mutex_lock(&extlib_mutex);

	if (!extlib_plugin || !extlib_read_failed ||
	    clock_gettime(CLOCK_MONOTONIC, &now) ||
	    now.tv_sec < extlib_probe_at)
		goto out;
	extlib_probe_at = now.tv_sec + ESDM_EXT_LIB_PROBE_INTERVAL_SEC;

	if (!esdm_es_ext_plugin_get(extlib_plugin, extlib_ctx, probe,
				    sizeof(probe), &claimed)) {
		extlib_read_failed = false;
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "External ES plugin: delivering again\n");
	}

out:
	mutex_unlock(&extlib_mutex);
	memset_secure(probe, 0, sizeof(probe));
	return 0;
}

/*
 * The status the plugin reports of itself, NULL for none. Caller must hold
 * extlib_mutex (write lock): the callbacks of the plugin are never called
 * concurrently.
 */
static struct json_object *esdm_es_extlib_status_locked(void)
{
	char text[ESDM_ES_EXT_STATUS_MAX + 1];
	ssize_t len;

	if (!extlib_plugin)
		return NULL;

	len = esdm_es_ext_plugin_status(extlib_plugin, extlib_ctx, text,
					sizeof(text));
	if (len < 0) {
		if (len != -EOPNOTSUPP)
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "External ES plugin: no status: %s\n",
				    strerror((int)-len));
		return NULL;
	}

	return esdm_es_ext_status_parse(text, (size_t)len, "plugin",
					&extlib_status_warned);
}

static void esdm_es_extlib_es_state(struct json_object *obj)
{
	char path[PATH_MAX], name[64];
	struct json_object *provider = NULL;
	uint32_t poolsize, entropy_rate;
	const char *status;

	/*
	 * The status of the plugin, unless the plugin is busy - with a
	 * request of a seeding, which may take a while: the ESDM status is not
	 * to wait for the noise source.
	 */
	if (mutex_trylock(&extlib_mutex)) {
		provider = esdm_es_extlib_status_locked();
		mutex_unlock(&extlib_mutex);
	}

	mutex_reader_lock(&extlib_mutex);
	poolsize = esdm_es_extlib_entropylevel_locked(esdm_security_strength());
	entropy_rate = esdm_es_extlib_entropylevel_locked(256);
	snprintf(path, sizeof(path), "%s", esdm_es_extlib_path_locked());
	snprintf(name, sizeof(name), "%s",
		 extlib_plugin && extlib_plugin->name ? extlib_plugin->name :
							"(none)");
	status = !extlib_plugin		 ? "not loaded" :
		 extlib_selftest_failed ? "failing its self test" :
		 extlib_read_failed	 ? "failing" :
					   "delivering";
	mutex_reader_unlock(&extlib_mutex);

	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(poolsize));
	json_object_object_add(obj, "entropy_rate_per_256_data_bits",
			       json_object_new_int64(entropy_rate));
	json_object_object_add(obj, "plugin_library",
			       json_object_new_string(path[0] ? path :
								"(unset)"));
	json_object_object_add(obj, "plugin", json_object_new_string(name));
	json_object_object_add(obj, "status", json_object_new_string(status));
	if (provider)
		json_object_object_add(obj, "provider", provider);
}

static bool esdm_es_extlib_active(void)
{
	bool ret;

	mutex_reader_lock(&extlib_mutex);
	ret = extlib_plugin != NULL;
	mutex_reader_unlock(&extlib_mutex);

	return ret;
}

/* The self test of the plugin, if it has one */
static int esdm_es_extlib_selftest(void)
{
	int ret = 0;

	mutex_lock(&extlib_mutex);

	if (!extlib_plugin) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"External ES plugin: none loaded - nothing to test\n");
		goto out;
	}

	if (extlib_plugin->selftest) {
		ret = extlib_plugin->selftest(extlib_ctx);
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ES,
				"External ES plugin: self test failed: %d\n",
				ret);
			extlib_selftest_failed = true;
			ret = -EFAULT;
			goto out;
		}
	}
	extlib_selftest_failed = false;

out:
	mutex_unlock(&extlib_mutex);
	return ret;
}

DSO_PUBLIC
int esdm_es_ext_lib_set_path(const char *path)
{
	char *new_copy = NULL;
	char *old;
	int ret = 0;

	if (!path)
		return -EINVAL;

	if (path[0] != '\0') {
		new_copy = strdup(path);
		if (!new_copy)
			return -ENOMEM;
	}

	mutex_lock(&extlib_mutex);

	old = extlib_runtime_path;
	extlib_runtime_path = new_copy;

	/*
	 * Set before esdm_init(), as the server does, the plugin is loaded by
	 * the init of the source. Once the source runs, the plugin is replaced
	 * right away.
	 */
	if (extlib_initialized)
		ret = esdm_es_extlib_load_locked();

	mutex_unlock(&extlib_mutex);

	free(old);

	return ret;
}

struct esdm_es_cb esdm_es_extlib = {
	.name = "ExternalLib",
	.init = esdm_es_extlib_init,
	.fini = esdm_es_extlib_fini,
	.monitor_es = esdm_es_extlib_monitor,
	.get_ent = esdm_es_extlib_get,
	.curr_entropy = esdm_es_extlib_entropylevel,
	.max_entropy = esdm_es_extlib_poolsize,
	.state = esdm_es_extlib_es_state,
	.reset = NULL,
	.active = esdm_es_extlib_active,
	.selftest = esdm_es_extlib_selftest,
};
