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
 * The SP800-90B startup test of the eBPF entropy sources after an intermittent
 * health test failure.
 *
 * The failure restarts the startup test, but the RCT and APT counters go on -
 * the permanent cutoffs count on them. The APT window the failure fell into
 * thus runs to its end, and its close once counted as the first passed block
 * of the new startup test: the source delivered again after the rest of that
 * window and one more, about half the 1024 samples SP800-90B section 4.3 asks
 * for.
 *
 * The health tests are plain C that the eBPF programs include, so they are
 * included here as well, with the one map they use and the configuration
 * standing in for what the programs get from the kernel. Needs neither libbpf
 * nor a kernel that loads eBPF programs, so it runs in every build.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common_test.h"
#include "esdm_es_ebpf_shared.h"

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

/* What the eBPF programs find in esdm_es_ebpf_common.bpf.h */
static struct esdm_ebpf_health test_health;
static int esdm_ebpf_health_map;
static struct esdm_ebpf_config esdm_ebpf_cfg;

static void *bpf_map_lookup_elem(void *map, const void *key)
{
	(void)map;
	(void)key;
	return &test_health;
}

/* The unit under test */
#include "esdm_es_ebpf_health.bpf.h"

static struct esdm_ebpf_percpu_state state;
static uint64_t test_time;
static uint32_t test_lcg = 0x12345678;

/*
 * Feed one time stamp that passes: never stuck, and with low-order bits that
 * differ from what the APT counts against, so a window it is part of closes
 * without adding to the APT count.
 */
static void feed_good(void)
{
	uint32_t delta;

	do {
		test_lcg = test_lcg * 1103515245 + 12345;
		delta = 1000 + ((test_lcg >> 8) % 4096);
	} while (delta == state.stuck_last_delta ||
		 ((test_time + delta) & ESDM_EBPF_APT_WORD_MASK) ==
			 state.apt_base);

	test_time += delta;
	esdm_ebpf_health_test(&state, test_time);
}

/* Feed one time stamp that is not stuck, but adds to the APT count */
static void feed_apt_match(void)
{
	uint64_t delta = (uint64_t)ESDM_EBPF_APT_LSB * (1000 + (test_time & 7));
	uint64_t t;

	/* Multiples of the APT modulus keep the low-order bits */
	t = (test_time & ~(uint64_t)ESDM_EBPF_APT_WORD_MASK) + state.apt_base;
	while (t <= test_time)
		t += ESDM_EBPF_APT_LSB;
	if (t - test_time == state.stuck_last_delta)
		t += delta;

	test_time = t;
	esdm_ebpf_health_test(&state, test_time);
}

/* Events from now on until the startup test completes, bounded by @limit */
static unsigned int events_to_startup(unsigned int limit)
{
	unsigned int i;

	for (i = 0; i < limit && !state.startup_done; i++)
		feed_good();

	return i;
}

static void setup(void)
{
	memset(&state, 0, sizeof(state));
	memset(&test_health, 0, sizeof(test_health));
	esdm_ebpf_health_reset(&state);
	test_time = 1U << 20;
}

/* The startup test after a reset: ESDM_EBPF_STARTUP_SAMPLES events */
static void test_initial_startup(void)
{
	unsigned int events;

	setup();
	events = events_to_startup(4 * ESDM_EBPF_STARTUP_SAMPLES);

	CHECK(state.startup_done, "the startup test never completed");
	/* The first event only sets the APT base */
	CHECK_EQ(events, ESDM_EBPF_STARTUP_SAMPLES + 1);
	CHECK_EQ(state.health_failures, 0);
}

/*
 * An intermittent APT failure in the middle of a window: the startup test
 * completes only once ESDM_EBPF_STARTUP_BLOCKS full windows have passed after
 * the one the failure fell into.
 */
static void test_restart_after_apt_failure(void)
{
	unsigned int events, rest_of_window, i;

	setup();
	events_to_startup(4 * ESDM_EBPF_STARTUP_SAMPLES);
	CHECK(state.startup_done, "the startup test never completed");

	/* A window that has just begun */
	while (state.apt_trigger != ESDM_EBPF_APT_WINDOW_SIZE)
		feed_good();

	for (i = 0; i < ESDM_EBPF_APT_WINDOW_SIZE && !state.health_failures;
	     i++)
		feed_apt_match();

	CHECK_EQ(state.health_failures, 1);
	CHECK_EQ(state.health_test, esdm_ebpf_health_test_apt);
	CHECK(!state.permanent_failure,
	      "an intermittent failure was taken for a permanent one");
	CHECK(!state.startup_done, "the failure left the startup test passed");
	CHECK_EQ(test_health.epoch, 1);

	rest_of_window = state.apt_trigger;
	CHECK(rest_of_window > 0 && rest_of_window < ESDM_EBPF_APT_WINDOW_SIZE,
	      "the failure did not fall into the middle of a window: %u",
	      rest_of_window);

	events = events_to_startup(4 * ESDM_EBPF_STARTUP_SAMPLES);

	CHECK(state.startup_done,
	      "the startup test never completed after the failure");
	CHECK_EQ(events, rest_of_window + ESDM_EBPF_STARTUP_SAMPLES);
	CHECK(events >= ESDM_EBPF_STARTUP_SAMPLES,
	      "the startup test completed after %u events", events);
	CHECK_EQ(state.health_failures, 1);
}

/*
 * The permanent cutoff counts on the same APT counter, which the intermittent
 * failure must not have reset: a source that keeps repeating within the window
 * reaches it.
 */
static void test_permanent_failure_reachable(void)
{
	unsigned int i;

	setup();
	events_to_startup(4 * ESDM_EBPF_STARTUP_SAMPLES);
	while (state.apt_trigger != ESDM_EBPF_APT_WINDOW_SIZE)
		feed_good();

	for (i = 0; i < ESDM_EBPF_APT_WINDOW_SIZE && !state.permanent_failure;
	     i++)
		feed_apt_match();

	CHECK(state.permanent_failure,
	      "the permanent APT cutoff was never reached");
	CHECK(state.health_failures > 1,
	      "no intermittent failure preceded the permanent one");
	CHECK(!state.startup_done,
	      "the permanent failure left the startup test passed");
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	/* The cutoffs of an OSR of 1, see es_ebpf_health_test.c */
	esdm_ebpf_cfg.health_enabled = 1;
	esdm_ebpf_cfg.rct_cutoff = 30;
	esdm_ebpf_cfg.rct_cutoff_permanent = 60;
	esdm_ebpf_cfg.apt_cutoff = 325;
	esdm_ebpf_cfg.apt_cutoff_permanent = 355;

	test_initial_startup();
	test_restart_after_apt_failure();
	test_permanent_failure_reachable();

	return common_test_result("es_ebpf_health_startup");
}
