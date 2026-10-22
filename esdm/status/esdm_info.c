/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esdm_config.h"
#include "esdm.h"
#include "esdm_es_aux.h"
#include "esdm_drng_mgr.h"
#include "esdm_es_irq.h"
#include "esdm_es_mgr.h"
#include "esdm_es_sched.h"
#include "esdm_logger.h"
#include "esdm_node.h"
#include "esdm_selftest.h"
#include "esdm_status_txt.h"
#include "test_pertubation.h"
#include "visibility.h"

/*
 * The DRNGs serving: the published node array, the initial DRNG being its
 * first entry, or the initial DRNG alone.
 */
static uint32_t esdm_drng_instances(void)
{
	return max_uint32(esdm_drng_node_count_get(), 1);
}

DSO_PUBLIC
void esdm_version(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "%slibrary version: %s\n", TESTMODE_STR, VERSION);
}

/*
 * Render a wall clock time given in seconds since the epoch as an ISO 8601
 * timestamp in UTC.
 */
static void esdm_time_str(long long wtime, char *buf, size_t buflen)
{
	time_t t = (time_t)wtime;
	struct tm tm;

	buf[0] = '\0';

	if (!gmtime_r(&t, &tm))
		return;

	if (!strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tm))
		buf[0] = '\0';
}

/****************************** JSON status ***********************************/

/*
 * A member of @stats that follows the requests the DRNG served: one of its
 * counters or seeding times. The prediction resistance DRNG is seeded anew for
 * every request, so for it these are the figures of the last requests - of
 * other users, while the status goes to every local user, who would learn from
 * them how much prediction resistant data was asked for, and when. For that
 * DRNG they are reported as null, the way a DRNG reports what it does not
 * have.
 */
static struct json_object *
esdm_drng_status_usage(const struct esdm_drng_stats *stats, long long val)
{
	return stats->pr ? NULL : json_object_new_int64(val);
}

/* Render the statistics of one DRNG instance as a JSON object. */
static struct json_object *
esdm_drng_status_obj(const struct esdm_drng_stats *stats)
{
	struct json_object *obj = json_object_new_object();
	char stamp[32] = "";

	if (!obj)
		return NULL;

	json_object_object_add(obj, "type",
			       json_object_new_string(stats->type));
	/*
	 * Every member is present on every DRNG: one the DRNG does not have -
	 * the node of the DRNG that is not bound to one, the seeding time of
	 * one that was never seeded - is reported as null rather than left out,
	 * so a consumer can address it without checking for its existence.
	 */
	json_object_object_add(
		obj, "node",
		stats->node_valid ? json_object_new_int((int32_t)stats->node) :
				    NULL);
	/* A DRNG that is not allocated yet has no name to report */
	json_object_object_add(
		obj, "name",
		stats->drng_name ? json_object_new_string(stats->drng_name) :
				   NULL);
	json_object_object_add(obj, "fully_seeded",
			       json_object_new_boolean(stats->fully_seeded));
	json_object_object_add(obj, "initiated",
			       json_object_new_boolean(stats->initiated));
	json_object_object_add(obj, "force_reseed",
			       json_object_new_boolean(stats->force_reseed));
	json_object_object_add(
		obj, "requests_until_reseed",
		json_object_new_int64(stats->requests_until_reseed));
	json_object_object_add(
		obj, "seconds_until_reseed",
		esdm_drng_status_usage(stats, stats->seconds_until_reseed));
	json_object_object_add(
		obj, "requests_since_fully_seeded",
		esdm_drng_status_usage(stats,
				       stats->requests_since_fully_seeded));
	json_object_object_add(
		obj, "generated_bits_since_fully_seeded",
		esdm_drng_status_usage(stats, stats->bits_since_fully_seeded));
	json_object_object_add(obj, "seed_generation",
			       esdm_drng_status_usage(stats,
						      stats->seed_generation));
	/* A seeding time - see esdm_drng_status_usage() */
	if (stats->seeded_wtime_valid && !stats->pr)
		esdm_time_str(stats->seeded_wtime, stamp, sizeof(stamp));
	json_object_object_add(obj, "last_seeding_time",
			       stamp[0] ? json_object_new_string(stamp) : NULL);
	json_object_object_add(
		obj, "seconds_since_last_reseed",
		stats->seeded_time_valid ?
			esdm_drng_status_usage(stats,
					       stats->seconds_since_reseed) :
			NULL);

	return obj;
}

/* Render one DRNG instance as an object of the "drngs" array */
static void esdm_drng_status_json(const struct esdm_drng_stats *stats,
				  void *priv)
{
	struct json_object *drngs = priv;
	struct json_object *obj = esdm_drng_status_obj(stats);

	if (obj)
		json_object_array_add(drngs, obj);
}

/* Collect the object of a single DRNG instance for the caller */
static void esdm_drng_status_json_one(const struct esdm_drng_stats *stats,
				      void *priv)
{
	struct json_object **out = priv;

	*out = esdm_drng_status_obj(stats);
}

/* Serialize the object of a single DRNG instance into the caller's buffer. */
static int esdm_json_write(const char *doc, char *buf, size_t buflen)
{
	int len;

	if (!doc)
		return -ENOMEM;

	len = snprintf(buf, buflen, "%s\n", doc);
	if (len < 0)
		return -EFAULT;

	/*
	 * A JSON document that is cut in half is not a JSON document at all,
	 * and a consumer that is handed one has no way to tell that from a
	 * document the ESDM meant to send.
	 */
	if ((size_t)len >= buflen) {
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Status document of %d bytes does not fit into the buffer of %zu bytes\n",
			len + 1, buflen);
		buf[0] = '\0';
		return -EMSGSIZE;
	}

	return 0;
}

static int esdm_drng_status_json_write(struct json_object *obj, char *buf,
				       size_t buflen)
{
	int ret;

	if (!obj)
		return -ENOMEM;

	ret = esdm_json_write(
		json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN),
		buf, buflen);

	json_object_put(obj);
	return ret;
}

DSO_PUBLIC
int esdm_status_drng_json(uint32_t node, char *buf, size_t buflen)
{
	struct json_object *obj = NULL;
	int ret;

	if (!buf || !buflen)
		return -EINVAL;

	buf[0] = '\0';

	ret = esdm_drng_stats_node(node, esdm_drng_status_json_one, &obj);
	if (ret)
		return ret;

	return esdm_drng_status_json_write(obj, buf, buflen);
}

DSO_PUBLIC
int esdm_status_drng_pr_json(char *buf, size_t buflen)
{
	struct json_object *obj = NULL;

	if (!buf || !buflen)
		return -EINVAL;

	buf[0] = '\0';

	esdm_drng_stats_pr(esdm_drng_status_json_one, &obj);

	return esdm_drng_status_json_write(obj, buf, buflen);
}

/*
 * The status of the ESDM, as one JSON object. Everything that reports the
 * status takes it from here: esdm_status_json() serializes it, esdm_status()
 * prints it as text.
 *
 * @return the object, NULL if it cannot be allocated
 */
static struct json_object *esdm_status_obj(void)
{
	struct esdm_drng *drng = esdm_drng_init_instance();
	struct json_object *root, *compliance, *sources, *drngs, *reseed,
		*selftest;
	uint32_t i;

	root = json_object_new_object();
	compliance = json_object_new_array();
	sources = json_object_new_array();
	drngs = json_object_new_array();
	reseed = json_object_new_object();
	selftest = json_object_new_object();
	if (!root || !compliance || !sources || !drngs || !reseed ||
	    !selftest) {
		json_object_put(root);
		root = NULL;
		goto out;
	}

	json_object_object_add(root, "library_version",
			       json_object_new_string(VERSION));
	json_object_object_add(root, "test_mode",
			       json_object_new_boolean(sizeof(TESTMODE_STR) >
						       1));
	/* The callbacks are only installed by esdm_init() */
	json_object_object_add(
		root, "drng_name",
		drng->drng_cb ?
			json_object_new_string(drng->drng_cb->drng_name()) :
			NULL);
	json_object_object_add(root, "security_strength_bits",
			       json_object_new_int64(esdm_security_strength()));
	json_object_object_add(root, "drng_instances",
			       json_object_new_int64(esdm_drng_instances()));

	if (esdm_config_fips_enabled())
		json_object_array_add(compliance,
				      json_object_new_string("FIPS 140"));
	/* A DRG.4 build satisfies DRG.3 and reports both */
	if (esdm_drg3_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("DRG.3"));
	if (esdm_drg4_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("DRG.4"));
	if (esdm_sp80090c_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("SP800-90C"));
	if (esdm_ntg1_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("NTG.1(2011)"));
	/*
	 * Only the NTG.1 seeding strategy makes the ESDM NTG.1(2024)
	 * compliant: without it a DRNG is seeded from 256/384 bits of any
	 * sources, whatever NTG.1 mode the Jitter RNG runs in. That mode is a
	 * property of the Jitter RNG, which its own entropy source reports.
	 */
	if (esdm_ntg1_2024_compliant())
		json_object_array_add(compliance,
				      json_object_new_string("NTG.1(2024)"));
	json_object_object_add(root, "standards_compliance", compliance);
	compliance = NULL;

	json_object_object_add(
		root, "fully_seeded",
		json_object_new_boolean(esdm_state_fully_seeded()));
	json_object_object_add(root, "entropy_level_bits",
			       json_object_new_int64(esdm_avail_entropy()));

	for_each_esdm_es (i) {
		struct json_object *es_obj = json_object_new_object();

		if (!es_obj)
			continue;

		json_object_object_add(es_obj, "id",
				       json_object_new_int((int32_t)i));
		json_object_object_add(
			es_obj, "name",
			json_object_new_string(esdm_es[i]->name));
		esdm_es[i]->state(es_obj);
		json_object_array_add(sources, es_obj);
	}
	json_object_object_add(root, "entropy_sources", sources);
	sources = NULL;

	/*
	 * The initial and the prediction resistance DRNG only: there is one
	 * node instance per CPU, so a status carrying them grows with the size
	 * of the machine and runs into the buffers it travels in. They are
	 * reported one at a time by esdm_status_drng_json().
	 */
	esdm_drng_stats_summary(esdm_drng_status_json, drngs);
	json_object_object_add(root, "drngs", drngs);
	drngs = NULL;

	/*
	 * The reseeding of the DRNGs, and the seeds stashed ahead of it while
	 * they reseed at a high rate.
	 */
	json_object_object_add(
		reseed, "reseed_interval_seconds",
		json_object_new_int64(esdm_get_reseed_max_time()));
	json_object_object_add(reseed, "seed_stash_slots",
			       json_object_new_int64(esdm_seed_stash_slots()));
	json_object_object_add(reseed, "stashed_seeds",
			       json_object_new_int64(esdm_seed_stash_filled()));
	json_object_object_add(reseed, "stashed_seed_max_age_seconds",
			       json_object_new_int64(ESDM_ES_BUF_MAX_AGE));
	json_object_object_add(root, "reseed", reseed);
	reseed = NULL;

	/*
	 * The self tests of the hash and the DRNG implementation and of the
	 * entropy sources.
	 */
	json_object_object_add(
		selftest, "state",
		json_object_new_string(esdm_selftest_crypto_state_name()));
	json_object_object_add(
		selftest, "running",
		json_object_new_boolean(esdm_selftest_periodic_running()));
	json_object_object_add(selftest, "completed_self_tests",
			       json_object_new_int64(esdm_selftest_passes()));
	json_object_object_add(
		selftest, "self_test_interval_seconds",
		json_object_new_int64(esdm_selftest_periodic_interval()));
	json_object_object_add(
		selftest, "entropy_source_state",
		json_object_new_string(esdm_selftest_es_state_name()));
	json_object_object_add(
		selftest, "entropy_sources_tested",
		json_object_new_int64(esdm_selftest_es_sources()));
	json_object_object_add(
		selftest, "entropy_sources_failed",
		json_object_new_int64(esdm_selftest_es_failures()));
	json_object_object_add(root, "periodic_self_test", selftest);
	selftest = NULL;

out:
	json_object_put(compliance);
	json_object_put(sources);
	json_object_put(drngs);
	json_object_put(reseed);
	json_object_put(selftest);

	return root;
}

/*
 * The labels of the text status where the member name does not make one - see
 * esdm_status_txt(). A member not listed is labelled with its name.
 */
static const struct esdm_status_txt_label esdm_status_labels[] = {
	{ "", "library_version", "ESDM library version" },
	{ "", "drng_name", "DRNG name" },
	{ "", "security_strength_bits", "ESDM security strength in bits" },
	{ "", "drng_instances", "Number of DRNG instances" },
	{ "", "fully_seeded", "ESDM fully seeded" },
	{ "", "entropy_level_bits", "ESDM entropy level" },
	{ "", "entropy_sources", "Entropy Source" },
	{ "", "drngs", "DRNG instance" },
	/* The index of the section says it already */
	{ "entropy_sources", "id", NULL },
	{ "reseed", "reseed_interval_seconds",
	  "Reseed interval in seconds" },
	{ "periodic_self_test", "self_test_interval_seconds",
	  "Self test interval in seconds" },

	/* Members of the entropy sources, and of the kernel add-on */
	{ NULL, "entropy_rate_per_256_data_bits",
	  "Entropy Rate per 256 data bits" },
	{ NULL, "oversampling_rate", "Oversampling Rate" },
	{ NULL, "ebpf_programs_loaded", "eBPF programs loaded" },
	{ NULL, "kernel_rng", "Kernel RNG" },
	{ NULL, "drbg_for_operating_entropy_pool",
	  "DRBG for operating entropy pool" },
	{ NULL, "per_cpu_interrupt_collection_size",
	  "per-CPU interrupt collection size" },
	{ NULL, "per_cpu_scheduler_event_collection_size",
	  "per-CPU scheduler event collection size" },
	{ NULL, "fips_mode_enabled", "FIPS mode enabled" },
	{ NULL, "high_resolution_timer", "High-resolution timer" },

	{ NULL, NULL, NULL }
};

DSO_PUBLIC
int esdm_status(char *buf, size_t buflen)
{
	struct json_object *root;
	int ret;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
	}
	buf[0] = '\0';

	root = esdm_status_obj();
	if (!root) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -ENOMEM;
	}

	/* A report that does not fit stays in the buffer as far as it got */
	ret = esdm_status_txt(root, esdm_status_labels, buf, buflen);
	json_object_put(root);

	if (ret == -EMSGSIZE)
		esdm_logger(
			LOGGER_WARN, LOGGER_C_ANY,
			"Status report does not fit into the buffer of %zu bytes\n",
			buflen);

	return ret;
}

DSO_PUBLIC
int esdm_status_json(char *buf, size_t buflen)
{
	struct json_object *root;
	int ret;

	if (!buf || !buflen) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -EINVAL;
	}
	buf[0] = '\0';

	root = esdm_status_obj();
	if (!root) {
		esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
			    "Status information cannot be created\n");
		return -ENOMEM;
	}

	ret = esdm_json_write(
		json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY),
		buf, buflen);
	json_object_put(root);

	return ret;
}

DSO_PUBLIC
void esdm_status_machine(struct esdm_status_st *status)
{
	status->es_irq_enabled = esdm_irq_enabled();
	status->es_sched_enabled = esdm_sched_enabled();
}
