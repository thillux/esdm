/*
 * ESDM Slow Entropy Source: eBPF-based scheduler entropy source
 *
 * Collects entropy from the timing of scheduler context switches observed
 * via an eBPF program attached to the sched_switch tracepoint. In contrast
 * to the scheduler entropy source implemented by esdm_es_sched.c, no kernel
 * patch is required.
 *
 * Copyright (C) 2026, Jakub Zelenka <bukka@php.net>
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
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "esdm_config.h"
#include "esdm_es_aux.h"
#include "esdm_es_ebpf.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched_ebpf.h"
#include "esdm_logger.h"
#include "helper.h"
#include "math_helper.h"
#include "mutex.h"
#include "test_pertubation.h"

/* The bpftool-generated skeleton does not satisfy the strict warnings */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverlength-strings"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "esdm_es_sched_ebpf.skel.h"
#pragma GCC diagnostic pop

static struct esdm_es_sched_ebpf_bpf *esdm_sched_ebpf_skel = NULL;
static struct esdm_ebpf_es esdm_sched_ebpf_es = {
	.name = "SchedulerEBPF",
	.entropy_rate = esdm_config_es_sched_ebpf_entropy_rate,
	.osr = ESDM_SCHED_EBPF_OSR,
};

/*
 * Serializes the skeleton / ring buffer state between the monitor thread,
 * the seed buffer filler and (re)initialization.
 */
static DEFINE_MUTEX_UNLOCKED(sched_ebpf_mutex);

/* Loaded and credited - the kernel RNG entropy rate depends on it */
bool esdm_sched_ebpf_enabled(void)
{
	bool loaded;

	mutex_reader_lock(&sched_ebpf_mutex);
	loaded = esdm_sched_ebpf_es.loaded;
	mutex_reader_unlock(&sched_ebpf_mutex);

	return loaded && esdm_config_es_sched_ebpf_entropy_rate() > 0;
}

/* Caller must hold sched_ebpf_mutex (write lock). */
static void esdm_sched_ebpf_finalize_locked(void)
{
	/*
	 * Detach before the entropy source is torn down: the tear-down erases
	 * the collected events, and an attached program would go on collecting
	 * into what it just erased.
	 */
	if (esdm_sched_ebpf_skel)
		esdm_es_sched_ebpf_bpf__detach(esdm_sched_ebpf_skel);

	esdm_ebpf_fini_es(&esdm_sched_ebpf_es);

	if (esdm_sched_ebpf_skel) {
		esdm_es_sched_ebpf_bpf__destroy(esdm_sched_ebpf_skel);
		esdm_sched_ebpf_skel = NULL;
	}
}

static void esdm_sched_ebpf_finalize(void)
{
	mutex_lock(&sched_ebpf_mutex);
	esdm_sched_ebpf_finalize_locked();
	mutex_unlock(&sched_ebpf_mutex);
}

/*
 * Open, configure and load the eBPF object.
 *
 * @fatal is set when the failure is one the caller must not paper over by
 * running without this entropy source - see esdm_ebpf_prepare().
 */
static int esdm_sched_ebpf_open_load(struct esdm_es_sched_ebpf_bpf **skel_out,
				     bool *fatal)
{
	struct esdm_es_sched_ebpf_bpf *skel;
	int ret;

	skel = esdm_es_sched_ebpf_bpf__open();
	if (!skel) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Opening of eBPF scheduler entropy source object failed: %s\n",
			strerror(errno));
		return -errno;
	}

	ret = esdm_ebpf_prepare(&esdm_sched_ebpf_es, skel->obj,
				&skel->rodata->esdm_ebpf_cfg);
	if (ret) {
		*fatal = true;
		goto err;
	}

	ret = esdm_es_sched_ebpf_bpf__load(skel);
	if (ret)
		goto err;

	*skel_out = skel;
	return 0;

err:
	esdm_es_sched_ebpf_bpf__destroy(skel);
	esdm_ebpf_fini_es(&esdm_sched_ebpf_es);
	return ret;
}

static int esdm_sched_ebpf_initialize(void)
{
	struct esdm_es_sched_ebpf_bpf *skel = NULL;
	bool fatal = false;
	int ret;

	mutex_lock(&sched_ebpf_mutex);

	/* Allow the init function to be called multiple times */
	esdm_sched_ebpf_finalize_locked();

	if (!esdm_ebpf_btf_available()) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as the kernel does not expose BTF data\n");
		ret = 0;
		goto out;
	}

	if (!esdm_ebpf_highres_timer()) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as no high-resolution timer is available\n");
		ret = 0;
		goto out;
	}

	esdm_ebpf_setup_logging();

	ret = esdm_sched_ebpf_open_load(&skel, &fatal);
	if (ret && fatal) {
		/*
		 * The source could only run in a state where the raw samples
		 * it collects cannot be erased again. That is not a degraded
		 * mode to fall back to - fail the initialization, which fails
		 * esdm_init() and terminates the ESDM.
		 */
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"eBPF scheduler-based entropy source cannot be set up so that its collected events can be erased again - refusing to start: %d\n",
			ret);
		goto out;
	}
	if (ret) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as the program cannot be loaded (kernel too old or missing privileges?): %d\n",
			ret);
		ret = 0;
		goto out;
	}

	/*
	 * Set up the consumer side before anything is collected: an attached
	 * program deposits raw deltas in the per-CPU state and the ring buffer
	 * right away, and only an initialized entropy source can erase them
	 * again (esdm_ebpf_zeroize() does nothing for one that is not loaded).
	 * Initialized after the attach, a failure of the initialization left
	 * them behind unwiped.
	 */
	ret = esdm_ebpf_init_es(&esdm_sched_ebpf_es, skel->obj);
	if (ret) {
		/* Not attached yet, so nothing was collected to erase */
		esdm_es_sched_ebpf_bpf__destroy(skel);
		esdm_ebpf_fini_es(&esdm_sched_ebpf_es);
		goto out;
	}

	/*
	 * The source goes on operating its maps after the server dropped its
	 * privileges, which not every kernel permits. Where it does not, the
	 * source would neither see its health tests nor be able to erase what
	 * it collects: it is not attached at all. It is initialized already,
	 * so torn down as esdm_sched_ebpf_finalize_locked() does.
	 */
	ret = esdm_ebpf_check_unprivileged(&esdm_sched_ebpf_es);
	if (ret) {
		esdm_ebpf_fini_es(&esdm_sched_ebpf_es);
		esdm_es_sched_ebpf_bpf__destroy(skel);
		if (ret == -ENOTRECOVERABLE)
			goto out;
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ES,
			"Disabling eBPF scheduler-based entropy source as it cannot operate its BPF maps without privileges: %d\n",
			ret);
		ret = 0;
		goto out;
	}

	ret = esdm_es_sched_ebpf_bpf__attach(skel);
	if (ret) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"Attaching of eBPF scheduler entropy source program failed: %d\n",
			ret);
		/*
		 * The programs that did get attached may have collected
		 * already. As esdm_sched_ebpf_finalize_locked() does: detach,
		 * erase while the maps are still there, then destroy them.
		 */
		esdm_es_sched_ebpf_bpf__detach(skel);
		esdm_ebpf_fini_es(&esdm_sched_ebpf_es);
		esdm_es_sched_ebpf_bpf__destroy(skel);
		ret = 0;
		goto out;
	}

	esdm_sched_ebpf_skel = skel;

	esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
		    "eBPF scheduler-based entropy source initialized\n");

out:
	mutex_unlock(&sched_ebpf_mutex);
	return ret;
}

static int esdm_sched_ebpf_seed_monitor(void)
{
	uint32_t ent, max_ent;

	if (!esdm_sched_ebpf_es.loaded)
		return 0;

	/*
	 * Top the conditioning pool up while it has room for the entropy of
	 * more events. Once it has not, the fetching stops and the eBPF
	 * programs go back to collecting for nobody until an extraction has
	 * spent what is in the pool.
	 */
	mutex_lock(&sched_ebpf_mutex);
	esdm_ebpf_refill(&esdm_sched_ebpf_es);
	ent = esdm_ebpf_avail_entropy(&esdm_sched_ebpf_es);
	max_ent = esdm_ebpf_max_entropy(&esdm_sched_ebpf_es);
	mutex_unlock(&sched_ebpf_mutex);

	if (esdm_pool_all_nodes_seeded_get())
		return 0;

	if (!esdm_config_es_sched_ebpf_entropy_rate())
		return 0;

	if (ent >= min_uint32(esdm_security_strength(), max_ent)) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "Full entropy of eBPF scheduler ES detected\n");
		esdm_es_add_entropy();
		esdm_test_seed_entropy(ent);
	}

	return 0;
}

static uint32_t esdm_sched_ebpf_entropylevel(uint32_t requested_bits)
{
	uint32_t ent;

	(void)requested_bits;

	mutex_reader_lock(&sched_ebpf_mutex);
	ent = esdm_ebpf_avail_entropy(&esdm_sched_ebpf_es);
	mutex_reader_unlock(&sched_ebpf_mutex);

	return ent;
}

static uint32_t esdm_sched_ebpf_poolsize(void)
{
	uint32_t ent;

	mutex_reader_lock(&sched_ebpf_mutex);
	ent = esdm_ebpf_max_entropy(&esdm_sched_ebpf_es);
	mutex_reader_unlock(&sched_ebpf_mutex);

	return ent;
}

static void esdm_sched_ebpf_get(struct entropy_es *eb_es,
				uint32_t requested_bits, bool __unused unused)
{
	mutex_lock(&sched_ebpf_mutex);
	esdm_ebpf_get_ent(&esdm_sched_ebpf_es, eb_es, requested_bits);
	mutex_unlock(&sched_ebpf_mutex);
}

static void esdm_sched_ebpf_reset(void)
{
	mutex_lock(&sched_ebpf_mutex);
	esdm_ebpf_pool_reset(&esdm_sched_ebpf_es);
	mutex_unlock(&sched_ebpf_mutex);
}

static void esdm_sched_ebpf_es_state(struct json_object *obj)
{
	uint64_t health_failures;
	uint32_t ent;
	bool loaded, health_enabled, perm_failure;

	/*
	 * One snapshot under the lock the monitor and the extraction update the
	 * health state under: the failure count is 64 bits wide, which a read
	 * racing with the update may tear on a 32 bit machine. Taken as a
	 * reader, as the entropy level read always did.
	 */
	mutex_reader_lock(&sched_ebpf_mutex);
	ent = esdm_ebpf_avail_entropy(&esdm_sched_ebpf_es);
	loaded = esdm_sched_ebpf_es.loaded;
	health_enabled = esdm_sched_ebpf_es.health_enabled;
	health_failures = esdm_sched_ebpf_es.health_failures;
	perm_failure = esdm_sched_ebpf_es.perm_failure;
	mutex_reader_unlock(&sched_ebpf_mutex);

	json_object_object_add(obj, "available_entropy",
			       json_object_new_int64(ent));
	json_object_object_add(
		obj, "entropy_rate_per_256_data_bits",
		json_object_new_int64(
			esdm_config_es_sched_ebpf_entropy_rate()));
	json_object_object_add(
		obj, "oversampling_rate",
		json_object_new_int64(esdm_ebpf_osr(&esdm_sched_ebpf_es)));
	json_object_object_add(
		obj, "standards_compliance",
		json_object_new_string(health_enabled ? "SP800-90B" : ""));
	json_object_object_add(obj, "ebpf_programs_loaded",
			       json_object_new_boolean(loaded));
	json_object_object_add(obj, "health_test_failures",
			       json_object_new_int64((int64_t)health_failures));
	json_object_object_add(obj, "permanent_failure",
			       json_object_new_boolean(perm_failure));
}

static bool esdm_sched_ebpf_active(void)
{
	return esdm_sched_ebpf_es.loaded;
}

/*
 * The SP800-90B health tests of this source run in the eBPF program over every
 * event it observes; what a self test can do from here is report their verdict.
 */
static int esdm_sched_ebpf_selftest(void)
{
	bool loaded, health_enabled, perm_failure;

	mutex_reader_lock(&sched_ebpf_mutex);
	loaded = esdm_sched_ebpf_es.loaded;
	health_enabled = esdm_sched_ebpf_es.health_enabled;
	perm_failure = esdm_sched_ebpf_es.perm_failure;
	mutex_reader_unlock(&sched_ebpf_mutex);

	if (!loaded) {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_ES,
			    "SchedulerEBPF ES: not loaded - nothing to test\n");
		return 0;
	}

	if (!health_enabled) {
		esdm_logger(
			LOGGER_DEBUG, LOGGER_C_ES,
			"SchedulerEBPF ES: SP800-90B health tests not enabled\n");
		return 0;
	}

	if (perm_failure) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_ES,
			"SchedulerEBPF ES: SP800-90B health tests in permanent failure\n");
		return -EFAULT;
	}

	return 0;
}

struct esdm_es_cb esdm_es_sched_ebpf = {
	.name = "SchedulerEBPF",
	.init = esdm_sched_ebpf_initialize,
	.monitor_es = esdm_sched_ebpf_seed_monitor,
	.fini = esdm_sched_ebpf_finalize,
	.get_ent = esdm_sched_ebpf_get,
	.curr_entropy = esdm_sched_ebpf_entropylevel,
	.max_entropy = esdm_sched_ebpf_poolsize,
	.state = esdm_sched_ebpf_es_state,
	.reset = esdm_sched_ebpf_reset,
	.active = esdm_sched_ebpf_active,
	.selftest = esdm_sched_ebpf_selftest,
};
