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
 * The entropy esdm-kernel-seeder credits an insertion into the kernel with.
 *
 * The kernel gets the entropy of the ESDM credited while the ESDM runs its
 * interrupt entropy source, which takes the interrupts away from the kernel
 * RNG, and nothing otherwise, where it would count the entropy of the kernel
 * RNG entropy source of the ESDM twice - unless the build configures a count.
 * The decision is taken from the JSON status of the ESDM, so it is checked
 * here against status documents of the shapes the ESDM produces. None of this
 * needs a server or the kernel.
 *
 * The translation unit is compiled into the test so its static functions can
 * be called directly; the build renames its main() out of the way.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "common_test.h"

/*
 * The unit under test. Its main() is renamed by the build; declare the renamed
 * one so it does not trip -Wmissing-prototypes, and put the name back
 * afterwards for our own.
 */
int esdm_kernel_seeder_main_unused(int argc, char **argv);
#include "seeder_main.c"

#undef main

/* The interrupt entropy source as the ESDM lists it with the add-on there */
#define TEST_IRQ_PRESENT                                                       \
	"{\"id\":0,\"name\":\"Interrupt\","                                    \
	"\"drbg_for_operating_entropy_pool\":\"xdrbg256\","                    \
	"\"available_entropy\":128}"

/* ... and without it */
#define TEST_IRQ_MISSING                                                       \
	"{\"id\":0,\"name\":\"Interrupt\","                                    \
	"\"disabled\":\"missing kernel support\"}"

#define TEST_JENT "{\"id\":1,\"name\":\"JitterRNG\"}"
#define TEST_IRQ_EBPF "{\"id\":2,\"name\":\"InterruptEBPF\"}"

#define TEST_STATUS(sources)                                                   \
	"{\"library_version\":\"1.2.4\",\"entropy_sources\":[" sources "]}"

static void check_bits(uint32_t configured, const char *status,
		       uint32_t expected, const char *what)
{
	uint32_t got = seeder_entropy_bits(configured, status);

	CHECK(got == expected, "%s: credited %u bits, expected %u", what, got,
	      expected);
}

static void test_follows_irq_es(void)
{
	check_bits(0, TEST_STATUS(TEST_IRQ_PRESENT "," TEST_JENT),
		   ESDM_SERVER_LINUX_ENTROPY_BITS, "interrupt ES running");
	check_bits(0, TEST_STATUS(TEST_JENT "," TEST_IRQ_PRESENT),
		   ESDM_SERVER_LINUX_ENTROPY_BITS,
		   "interrupt ES running, listed second");
	check_bits(0, TEST_STATUS(TEST_IRQ_MISSING "," TEST_JENT), 0,
		   "interrupt ES without kernel support");
	check_bits(0, TEST_STATUS(TEST_JENT), 0,
		   "interrupt ES not built");

	/*
	 * The eBPF interrupt source only observes the interrupts the kernel
	 * RNG keeps, so it is no reason to credit the kernel.
	 */
	check_bits(0, TEST_STATUS(TEST_IRQ_EBPF "," TEST_JENT), 0,
		   "eBPF interrupt ES");

	/* What the kernel gets credited is what the data fills its pool with */
	CHECK_EQ(ESDM_SERVER_LINUX_ENTROPY_BITS, 256);
	CHECK_EQ(ESDM_SERVER_LINUX_ENTROPY_BYTES * 8,
		 2 * ESDM_SERVER_LINUX_ENTROPY_BITS);
}

/* Without a status worth the name, nothing is credited */
static void test_no_status(void)
{
	check_bits(0, NULL, 0, "no status");
	check_bits(0, "", 0, "empty status");
	check_bits(0, "not a JSON document", 0, "garbled status");
	check_bits(0, "[]", 0, "status not an object");
	check_bits(0, "{\"entropy_sources\":{}}", 0,
		   "entropy sources not an array");
	check_bits(0, "{\"entropy_sources\":[{\"name\":5}]}", 0,
		   "entropy source name not a string");
}

/* A configured count is what is credited, whatever the status says */
static void test_configured(void)
{
	check_bits(128, TEST_STATUS(TEST_IRQ_PRESENT), 128,
		   "configured, interrupt ES running");
	check_bits(128, TEST_STATUS(TEST_JENT), 128,
		   "configured, no interrupt ES");
	check_bits(512, NULL, 512, "configured, no status");
}

int main(void)
{
	test_follows_irq_es();
	test_no_status();
	test_configured();

	return common_test_result("kernel_seeder_credit");
}
