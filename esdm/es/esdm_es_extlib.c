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
 * are called under the mutex of the source, so never concurrently, as the
 * plugin API promises. What the ESDM asks of the source while it may be busy
 * with a request - the entropy available, its state in the ESDM status - is
 * taken from what the source publishes whenever it releases that lock, not
 * waited for.
 *
 * A block is credited with what the plugin claims for it, at most with what
 * the configured rate allows (esdm_config_es_ext_lib_entropy_rate()). A
 * plugin that fails to deliver - or claims more than the data can hold, which
 * counts as a failure - is credited with nothing until it delivers again: on
 * a seeding that asks it, its data then going into the additional data, or on
 * a probe of the ES monitor. A plugin failing its self test is credited with
 * nothing until a self test passes - and a plugin is credited with nothing
 * before its first self test passed: at start up and on a re-init, the self
 * test pass of the ESDM runs before the first seeding; a plugin loaded while
 * the source runs is tested right away.
 */

#include <dlfcn.h>
#include <errno.h>
#include <json-c/json.h>
#include <limits.h>
#include <stdatomic.h>
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

/*
 * A plugin library source. All of its state is here: the ES manager calls the
 * source through callbacks that take no context, each of which hands the one
 * instance it belongs to to the functions below - see ESDM_ES_EXTLIB_CB.
 */
struct esdm_es_extlib {
	/*
	 * How the log messages name the source: by its name in the ES table if
	 * it is one of several of its kind, not at all otherwise - and what
	 * they call it for its status
	 */
	const char *tag;
	const char *who;

	/* Held for every request to the plugin, see above */
	mutex_t mutex;

	/*
	 * Override of the plugin path, as given on the command line of the
	 * server. NULL means "use the compile-time default ESDM_EXT_LIB_PATH".
	 * Configuration like the entropy rates: it outlives esdm_fini().
	 */
	char *runtime_path;

	/* The plugin loaded and initialized, all NULL if none is */
	void *dl;
	const struct esdm_es_ext_plugin *plugin;
	void *ctx;
	/* The path it was loaded from */
	char loaded_path[PATH_MAX];

	/* The plugin as claimed for this source, under extlib_claim_mutex */
	const struct esdm_es_ext_plugin *claimed;

	/*
	 * The last request to the plugin failed, or its last self test did.
	 * They are kept apart: data delivered says nothing about the noise
	 * source a self test found broken, so only a self test that passes
	 * clears its failure, and only data delivered clears a failed request.
	 * Set and cleared under the write lock, read under the reader lock.
	 */
	bool read_failed;
	bool selftest_failed;

	/*
	 * The plugin initialized has not been through a self test yet, and is
	 * credited with nothing until it was. Under the same lock as the
	 * failures.
	 */
	bool selftest_due;

	/* Earliest time to probe a plugin whose request failed, monotonic s */
	time_t probe_at;

	/* Between init and fini - a new path is loaded at once then */
	bool initialized;

	/* The last status of the plugin was none and logged as such */
	bool status_warned;

	/*
	 * What is read of the source without the mutex, which a request to the
	 * plugin holds for as long as the plugin takes: the ESDM status, and
	 * the entropy available, are not to wait for that - see
	 * esdm_es_mgr_cb.h. Published by esdm_es_extlib_unlock() whenever the
	 * write lock is released; the state and the status of the plugin under
	 * state_mutex, which is held for copying only.
	 */
	atomic_bool published_loaded;
	atomic_bool published_credited;
	mutex_t state_mutex;
	char state_path[PATH_MAX];
	char state_name[64];
	const char *state_status;
	struct esdm_es_ext_status_cache status;
};

#if ESDM_EXT_LIB_NUM > 1
#define ESDM_ES_EXTLIB_TAG(i) " " ESDM_ES_EXTLIB_NAME(i)
#else
#define ESDM_ES_EXTLIB_TAG(i) ""
#endif

#define ESDM_ES_EXTLIB_INSTANCE(i)                                             \
	[i] = {                                                                \
		.tag = ESDM_ES_EXTLIB_TAG(i),                                  \
		.who = "plugin" ESDM_ES_EXTLIB_TAG(i),                         \
		.mutex = MUTEX_UNLOCKED,                                       \
		.state_mutex = MUTEX_UNLOCKED,                                 \
		.state_name = "(none)",                                        \
		.state_status = "not loaded",                                  \
	},

/* The plugin library sources, ESDM_EXT_LIB_NUM of them */
static struct esdm_es_extlib extlib[ESDM_EXT_LIB_NUM] = {
	ESDM_EXT_LIB_INSTANCES(ESDM_ES_EXTLIB_INSTANCE)
};

/*
 * A plugin library serves one source. Its callbacks are never called
 * concurrently, as the plugin API promises - which two sources would break,
 * each calling it under its own lock - and a library loaded again is the one
 * already loaded, its state and all, see dlopen(3). Guards the plugin each
 * source claimed; taken under the mutex of a source, never the other way round.
 */
static DEFINE_MUTEX_UNLOCKED(extlib_claim_mutex);

/* The name of @lib in the ES table */
static const char *esdm_es_extlib_name(const struct esdm_es_extlib *lib)
{
	return esdm_es_extlib[lib - extlib].name;
}

/*
 * Claim @p for @lib, NULL for none. Caller must hold the mutex of @lib (write
 * lock).
 *
 * @return NULL if claimed, the source using the plugin otherwise
 */
static const struct esdm_es_extlib *
esdm_es_extlib_claim_locked(struct esdm_es_extlib *lib,
			    const struct esdm_es_ext_plugin *p)
{
	const struct esdm_es_extlib *other = NULL;
	unsigned int i;

	mutex_lock(&extlib_claim_mutex);
	for (i = 0; p && i < ESDM_EXT_LIB_NUM; i++) {
		if (&extlib[i] != lib && extlib[i].claimed == p) {
			other = &extlib[i];
			break;
		}
	}
	if (!other)
		lib->claimed = p;
	mutex_unlock(&extlib_claim_mutex);

	return other;
}

/* Caller must hold the mutex of @lib. */
static const char *esdm_es_extlib_path_locked(const struct esdm_es_extlib *lib)
{
	return lib->runtime_path ? lib->runtime_path : ESDM_EXT_LIB_PATH;
}

/* Is the plugin credited at all? Caller must hold the mutex of @lib. */
static bool esdm_es_extlib_credited_locked(const struct esdm_es_extlib *lib)
{
	return lib->plugin && !lib->read_failed && !lib->selftest_failed &&
	       !lib->selftest_due;
}

/*
 * Publish what is read of the source without the lock, see above. Caller must
 * hold the mutex of @lib (write lock).
 */
static void esdm_es_extlib_publish_locked(struct esdm_es_extlib *lib)
{
	const char *status = !lib->plugin	  ? "not loaded" :
			     lib->selftest_due	  ? "awaiting its self test" :
			     lib->selftest_failed ? "failing its self test" :
			     lib->read_failed	  ? "failing" :
						    "delivering";

	atomic_store(&lib->published_loaded, lib->plugin != NULL);
	atomic_store(&lib->published_credited,
		     esdm_es_extlib_credited_locked(lib));

	mutex_lock(&lib->state_mutex);
	snprintf(lib->state_path, sizeof(lib->state_path), "%s",
		 esdm_es_extlib_path_locked(lib));
	snprintf(lib->state_name, sizeof(lib->state_name), "%s",
		 lib->plugin && lib->plugin->name ? lib->plugin->name :
						    "(none)");
	lib->state_status = status;
	mutex_unlock(&lib->state_mutex);
}

/* Release the mutex of @lib (write lock), publishing what changed under it */
static void esdm_es_extlib_unlock(struct esdm_es_extlib *lib)
{
	esdm_es_extlib_publish_locked(lib);
	mutex_unlock(&lib->mutex);
}

/*
 * Forget the status of the plugin, which is another one now. Caller must hold
 * the mutex of @lib (write lock).
 */
static void esdm_es_extlib_status_forget_locked(struct esdm_es_extlib *lib)
{
	mutex_lock(&lib->state_mutex);
	esdm_es_ext_status_cache_set(&lib->status, NULL, 0);
	mutex_unlock(&lib->state_mutex);
}

/* Caller must hold the mutex of @lib (write lock). */
static void esdm_es_extlib_unload_locked(struct esdm_es_extlib *lib)
{
	if (lib->plugin && lib->plugin->fini)
		lib->plugin->fini(lib->ctx);
	lib->plugin = NULL;
	lib->ctx = NULL;

	if (lib->dl)
		dlclose(lib->dl);
	lib->dl = NULL;
	(void)esdm_es_extlib_claim_locked(lib, NULL);

	lib->loaded_path[0] = '\0';
	lib->read_failed = false;
	lib->selftest_failed = false;
	lib->selftest_due = false;
	lib->status_warned = false;
	esdm_es_extlib_status_forget_locked(lib);
}

/*
 * Initialize the plugin of the library already loaded. Caller must hold the
 * mutex of @lib (write lock).
 */
static int esdm_es_extlib_init_plugin_locked(struct esdm_es_extlib *lib,
					     const struct esdm_es_ext_plugin *p)
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
				"External ES plugin%s: initialization of %s failed: %s\n",
				lib->tag, p->name ? p->name : "the plugin",
				strerror(-ret));
			return ret;
		}
	}

	lib->plugin = p;
	lib->ctx = ctx;
	lib->read_failed = false;
	lib->selftest_failed = false;
	lib->selftest_due = true;
	esdm_es_extlib_status_forget_locked(lib);
	return 0;
}

/*
 * Load the plugin library of the configured path, replacing the one in use.
 * Caller must hold the mutex of @lib (write lock).
 *
 * A plugin already loaded from the same path is initialized anew rather than
 * loaded again: a re-init of the ESDM runs after the server dropped its
 * privileges, which may no longer suffice to load the library.
 */
static int esdm_es_extlib_load_locked(struct esdm_es_extlib *lib)
{
	const char *path = esdm_es_extlib_path_locked(lib);
	const struct esdm_es_extlib *other;
	const struct esdm_es_ext_plugin *p;
	void *dl;
	int ret;

	/* A library is only kept loaded with its plugin initialized */
	if (lib->plugin && !strcmp(lib->loaded_path, path)) {
		p = lib->plugin;
		if (p->fini)
			p->fini(lib->ctx);
		lib->plugin = NULL;
		lib->ctx = NULL;

		ret = esdm_es_extlib_init_plugin_locked(lib, p);
		if (ret)
			esdm_es_extlib_unload_locked(lib);
		return ret;
	}

	esdm_es_extlib_unload_locked(lib);

	if (path[0] == '\0')
		return 0;

	if (strlen(path) >= sizeof(lib->loaded_path))
		return -ENAMETOOLONG;

	/* See esdm_es_ext_plugin_load() of libesdm_es_ext on the flags */
	dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!dl) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin%s: cannot load %s: %s\n",
			lib->tag, path, dlerror());
		return -ENOENT;
	}

	p = dlsym(dl, ESDM_ES_EXT_PLUGIN_SYMBOL);
	if (!p) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin%s: %s exports no %s\n",
			lib->tag, path, ESDM_ES_EXT_PLUGIN_SYMBOL);
		dlclose(dl);
		return -ENOEXEC;
	}

	if (esdm_es_ext_plugin_check(p)) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin%s: %s is of version %u, versions 1 to %u with a get_entropy callback are supported\n",
			lib->tag, path, p->version, ESDM_ES_EXT_PLUGIN_VERSION);
		dlclose(dl);
		return -EPROTO;
	}

	other = esdm_es_extlib_claim_locked(lib, p);
	if (other) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling external ES plugin%s: %s is loaded by %s already, and a plugin library serves one source\n",
			lib->tag, path, esdm_es_extlib_name(other));
		dlclose(dl);
		return -EBUSY;
	}

	lib->dl = dl;
	snprintf(lib->loaded_path, sizeof(lib->loaded_path), "%s", path);

	ret = esdm_es_extlib_init_plugin_locked(lib, p);
	if (ret) {
		esdm_es_extlib_unload_locked(lib);
		return ret;
	}

	/* Its claims are not assessed by the ESDM, which is worth a line */
	esdm_logger(
		LOGGER_STATUS, LOGGER_C_ES,
		"External ES plugin%s: %s loaded from %s, its entropy claims credited with up to %u bits per 256 bits\n",
		lib->tag, p->name ? p->name : "(unnamed)", path,
		esdm_config_es_ext_lib_entropy_rate());

	return 0;
}

static int esdm_es_extlib_init(struct esdm_es_extlib *lib)
{
	/* What a plugin delivers per request fits into a seed buffer */
	BUILD_BUG_ON(ESDM_DRNG_INIT_SEED_SIZE_BYTES >
		     ESDM_ES_EXT_PROTO_MAX_DATA);

	mutex_lock(&lib->mutex);
	/* A plugin that cannot be loaded leaves the source switched off */
	(void)esdm_es_extlib_load_locked(lib);
	lib->initialized = true;
	esdm_es_extlib_unlock(lib);

	return 0;
}

static void esdm_es_extlib_fini(struct esdm_es_extlib *lib)
{
	mutex_lock(&lib->mutex);
	esdm_es_extlib_unload_locked(lib);
	lib->initialized = false;
	esdm_es_extlib_unlock(lib);
}

static uint32_t esdm_es_extlib_level(bool credited, uint32_t requested_bits)
{
	if (!credited)
		return 0;

	return esdm_fast_noise_entropylevel(
		esdm_config_es_ext_lib_entropy_rate(), requested_bits);
}

/* Caller must hold the mutex of @lib. */
static uint32_t
esdm_es_extlib_entropylevel_locked(const struct esdm_es_extlib *lib,
				   uint32_t requested_bits)
{
	return esdm_es_extlib_level(esdm_es_extlib_credited_locked(lib),
				    requested_bits);
}

/* As published: a request in progress is not waited for */
static uint32_t esdm_es_extlib_entropylevel(struct esdm_es_extlib *lib,
					    uint32_t requested_bits)
{
	return esdm_es_extlib_level(atomic_load(&lib->published_credited),
				    requested_bits);
}

static uint32_t esdm_es_extlib_poolsize(struct esdm_es_extlib *lib)
{
	return esdm_es_extlib_entropylevel(lib, esdm_security_strength());
}

static void esdm_es_extlib_get(struct esdm_es_extlib *lib,
			       struct entropy_es *eb_es,
			       uint32_t requested_bits)
{
	uint32_t claimed, len = requested_bits >> 3;
	int ret;

	eb_es->e_bits = 0;
	if (!len || len > sizeof(eb_es->e))
		return;

	/* Exclusive: the outcome of the request is recorded */
	mutex_lock(&lib->mutex);

	if (!lib->plugin)
		goto out;

	ret = esdm_es_ext_plugin_get(lib->plugin, lib->ctx, eb_es->e, len,
				     &claimed);
	if (ret) {
		if (!lib->read_failed)
			esdm_logger(
				LOGGER_WARN, LOGGER_C_ES,
				"External ES plugin%s: no entropy delivered: %s\n",
				lib->tag, strerror(-ret));
		lib->read_failed = true;
		goto out;
	}

	lib->read_failed = false;
	eb_es->e_bits = min_uint32(claimed, esdm_es_extlib_entropylevel_locked(
						    lib, requested_bits));

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "obtained %u bits of entropy from external ES plugin%s\n",
		    eb_es->e_bits, lib->tag);

out:
	esdm_es_extlib_unlock(lib);
}

/*
 * A plugin whose request failed is credited with nothing, which keeps it out
 * of what an unforced reseed waits for - and such a reseed asks no source at
 * all while too little entropy is available. The monitor asks it instead, at
 * most every ESDM_EXT_LIB_PROBE_INTERVAL_SEC seconds, and discards what it
 * delivers: data it delivers again makes it credited again.
 */
static int esdm_es_extlib_monitor(struct esdm_es_extlib *lib)
{
	uint8_t probe[ESDM_DRNG_SECURITY_STRENGTH_BYTES];
	struct timespec now;
	uint32_t claimed;

	mutex_lock(&lib->mutex);

	if (!lib->plugin || !lib->read_failed ||
	    clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < lib->probe_at)
		goto out;
	lib->probe_at = now.tv_sec + ESDM_EXT_LIB_PROBE_INTERVAL_SEC;

	if (!esdm_es_ext_plugin_get(lib->plugin, lib->ctx, probe, sizeof(probe),
				    &claimed)) {
		lib->read_failed = false;
		esdm_logger(LOGGER_STATUS, LOGGER_C_ES,
			    "External ES plugin%s: delivering again\n",
			    lib->tag);
	}

out:
	esdm_es_extlib_unlock(lib);
	memset_secure(probe, 0, sizeof(probe));
	return 0;
}

/*
 * The status the plugin reports of itself, NULL for none. Caller must hold the
 * mutex of @lib (write lock): the callbacks of the plugin are never called
 * concurrently.
 */
static struct json_object *
esdm_es_extlib_status_locked(struct esdm_es_extlib *lib)
{
	char text[ESDM_ES_EXT_STATUS_MAX + 1];
	ssize_t len;

	if (!lib->plugin)
		return NULL;

	len = esdm_es_ext_plugin_status(lib->plugin, lib->ctx, text,
					sizeof(text));
	if (len < 0) {
		if (len != -EOPNOTSUPP)
			esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
				    "External ES plugin%s: no status: %s\n",
				    lib->tag, strerror((int)-len));
		return NULL;
	}

	return esdm_es_ext_status_parse(text, (size_t)len, lib->who,
					&lib->status_warned);
}

static void esdm_es_extlib_es_state(struct esdm_es_extlib *lib,
				    struct json_object *obj)
{
	char path[PATH_MAX], name[64];
	struct json_object *provider;
	uint32_t poolsize, entropy_rate;
	time_t now = (time_t)esdm_monotonic_now();
	const char *status;
	bool due;

	mutex_lock(&lib->state_mutex);
	due = esdm_es_ext_status_cache_due(&lib->status, now);
	mutex_unlock(&lib->state_mutex);

	/*
	 * The status of the plugin is asked for anew once the last one is
	 * older than ESDM_ES_EXT_STATUS_INTERVAL_SEC - unless the plugin is
	 * busy with a request of a seeding, which may take a while: the ESDM
	 * status is not to wait for the noise source, and goes without the
	 * status of the plugin then.
	 */
	if (due && mutex_trylock(&lib->mutex)) {
		provider = esdm_es_extlib_status_locked(lib);
		mutex_lock(&lib->state_mutex);
		esdm_es_ext_status_cache_set(&lib->status, provider, now);
		mutex_unlock(&lib->state_mutex);
		esdm_es_extlib_unlock(lib);
		due = false;
	}

	mutex_lock(&lib->state_mutex);
	provider = due ? NULL : esdm_es_ext_status_cache_get(&lib->status);
	snprintf(path, sizeof(path), "%s", lib->state_path);
	snprintf(name, sizeof(name), "%s", lib->state_name);
	status = lib->state_status;
	mutex_unlock(&lib->state_mutex);

	poolsize = esdm_es_extlib_entropylevel(lib, esdm_security_strength());
	entropy_rate = esdm_es_extlib_entropylevel(lib, 256);

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

static bool esdm_es_extlib_active(struct esdm_es_extlib *lib)
{
	return atomic_load(&lib->published_loaded);
}

/*
 * The self test of the plugin, if it has one. Caller must hold the mutex of
 * @lib (write lock).
 */
static int esdm_es_extlib_selftest_locked(struct esdm_es_extlib *lib)
{
	int ret;

	if (!lib->plugin) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"External ES plugin%s: none loaded - nothing to test\n",
			lib->tag);
		return 0;
	}

	lib->selftest_due = false;

	if (lib->plugin->selftest) {
		ret = lib->plugin->selftest(lib->ctx);
		if (ret) {
			esdm_logger(
				LOGGER_ERR, LOGGER_C_ES,
				"External ES plugin%s: self test failed: %d\n",
				lib->tag, ret);
			lib->selftest_failed = true;
			return -EFAULT;
		}
	}
	lib->selftest_failed = false;

	return 0;
}

static int esdm_es_extlib_selftest(struct esdm_es_extlib *lib)
{
	int ret;

	mutex_lock(&lib->mutex);
	ret = esdm_es_extlib_selftest_locked(lib);
	esdm_es_extlib_unlock(lib);

	return ret;
}

DSO_PUBLIC
int esdm_es_ext_lib_set_path(const char *path)
{
	struct esdm_es_extlib *lib = &extlib[0];
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

	mutex_lock(&lib->mutex);

	old = lib->runtime_path;
	lib->runtime_path = new_copy;

	/*
	 * Set before esdm_init(), as the server does, the plugin is loaded by
	 * the init of the source, and tested by the self test pass following
	 * it. Once the source runs, the plugin is replaced right away - and
	 * tested right away, as it is credited with nothing until it was.
	 */
	if (lib->initialized) {
		ret = esdm_es_extlib_load_locked(lib);
		if (!ret)
			(void)esdm_es_extlib_selftest_locked(lib);
	}

	esdm_es_extlib_unlock(lib);

	free(old);

	return ret;
}

/*
 * The callbacks of the ES manager take no context: each source has a set of
 * its own, handing its instance to the functions above.
 */
#define ESDM_ES_EXTLIB_CB(i)                                                   \
	static int esdm_es_extlib_init_##i(void)                               \
	{                                                                      \
		return esdm_es_extlib_init(&extlib[i]);                        \
	}                                                                      \
	static void esdm_es_extlib_fini_##i(void)                              \
	{                                                                      \
		esdm_es_extlib_fini(&extlib[i]);                               \
	}                                                                      \
	static int esdm_es_extlib_monitor_##i(void)                            \
	{                                                                      \
		return esdm_es_extlib_monitor(&extlib[i]);                     \
	}                                                                      \
	static void esdm_es_extlib_get_##i(struct entropy_es *eb_es,           \
					   uint32_t requested_bits,            \
					   bool __unused allow_cached)         \
	{                                                                      \
		esdm_es_extlib_get(&extlib[i], eb_es, requested_bits);         \
	}                                                                      \
	static uint32_t esdm_es_extlib_entropylevel_##i(uint32_t bits)         \
	{                                                                      \
		return esdm_es_extlib_entropylevel(&extlib[i], bits);          \
	}                                                                      \
	static uint32_t esdm_es_extlib_poolsize_##i(void)                      \
	{                                                                      \
		return esdm_es_extlib_poolsize(&extlib[i]);                    \
	}                                                                      \
	static void esdm_es_extlib_es_state_##i(struct json_object *obj)       \
	{                                                                      \
		esdm_es_extlib_es_state(&extlib[i], obj);                      \
	}                                                                      \
	static bool esdm_es_extlib_active_##i(void)                            \
	{                                                                      \
		return esdm_es_extlib_active(&extlib[i]);                      \
	}                                                                      \
	static int esdm_es_extlib_selftest_##i(void)                           \
	{                                                                      \
		return esdm_es_extlib_selftest(&extlib[i]);                    \
	}

ESDM_EXT_LIB_INSTANCES(ESDM_ES_EXTLIB_CB)

#define ESDM_ES_EXTLIB_CB_ENTRY(i)                                             \
	[i] = {                                                                \
		.name = ESDM_ES_EXTLIB_NAME(i),                                \
		.init = esdm_es_extlib_init_##i,                               \
		.fini = esdm_es_extlib_fini_##i,                               \
		.monitor_es = esdm_es_extlib_monitor_##i,                      \
		.get_ent = esdm_es_extlib_get_##i,                             \
		.curr_entropy = esdm_es_extlib_entropylevel_##i,               \
		.max_entropy = esdm_es_extlib_poolsize_##i,                    \
		.state = esdm_es_extlib_es_state_##i,                          \
		.reset = NULL,                                                 \
		.active = esdm_es_extlib_active_##i,                           \
		.selftest = esdm_es_extlib_selftest_##i,                       \
	},

struct esdm_es_cb esdm_es_extlib[ESDM_EXT_LIB_NUM] = {
	/* The callbacks of the instances, see ESDM_ES_EXTLIB_CB */
	ESDM_EXT_LIB_INSTANCES(ESDM_ES_EXTLIB_CB_ENTRY)
};
