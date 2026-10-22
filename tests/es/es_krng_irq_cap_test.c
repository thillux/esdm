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
 * The kernel RNG entropy source while the interrupt ES kernel add-on is there.
 *
 * The add-on's hook in random.c takes the interrupts away from the kernel RNG
 * as soon as the add-on registers - whatever rate user space credits the
 * interrupt ES with. The kernel RNG was capped only while that rate was not
 * zero, and with the interrupt ES configured uncredited it was credited at its
 * full rate although the kernel had lost its main source.
 *
 * The interrupt ES is compiled into the test, so the descriptor of the add-on
 * can be faked: one that is open is all the kernel RNG asks about. And so can
 * the add-on loaded after the ESDM started, which the ESDM holds no descriptor
 * of: the kernel shows its module in sysfs, a directory of the test here,
 * looked for anew on every call.
 */

#include "config.h"

#include <sys/stat.h>

static char test_dir[] = "/tmp/esdm-krng-irq-cap-XXXXXX";
static char test_module[sizeof(test_dir) + 16];

#define ESDM_IRQ_ADDON_SYSFS test_module
#define ESDM_IRQ_ADDON_PROBE_INTERVAL_MS 0

/* The unit whose state is faked */
#include "esdm_es_irq.c"

#include "common_test.h"
#include "esdm_config.h"
#include "esdm_es_krng.h"
#include "esdm_es_sched.h"

static uint32_t krng_credit(void)
{
	return esdm_es_krng.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS);
}

int main(int argc, char *argv[])
{
	uint32_t uncapped;
	int fd;

	(void)argc;
	(void)argv;

	if (esdm_es_oversampling() || esdm_sched_enabled()) {
		/* The kernel RNG is credited with nothing at all then */
		return 77;
	}

	if (!mkdtemp(test_dir)) {
		printf("cannot create a directory - skipping\n");
		return 77;
	}
	snprintf(test_module, sizeof(test_module), "%s/esdm_es", test_dir);

	esdm_config_es_irq_entropy_rate_set(0);
	esdm_config_es_krng_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	uncapped = krng_credit();
	if (uncapped <= ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY) {
		printf("the kernel RNG is not credited above the cap - skipping\n");
		rmdir(test_dir);
		return 77;
	}

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	CHECK(fd >= 0, "cannot open /dev/null");
	if (fd < 0)
		return common_test_result("ES kernel RNG IRQ cap");

	/* The add-on is there, its ES is not credited */
	mutex_lock(&irq_mutex);
	esdm_irq_entropy_fd = fd;
	mutex_unlock(&irq_mutex);

	CHECK(esdm_irq_present(), "the add-on is not reported present");
	CHECK(!esdm_irq_enabled(), "the uncredited add-on counts as credited");
	CHECK_EQ(krng_credit(), ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY);

	/* A rate set meanwhile is clamped the same way */
	esdm_config_es_krng_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK(esdm_config_es_krng_entropy_rate() <=
		      ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY,
	      "the kernel RNG rate was set to %u with the add-on present",
	      esdm_config_es_krng_entropy_rate());

	/* Gone again, the kernel RNG has its interrupts back */
	mutex_lock(&irq_mutex);
	esdm_irq_finalize_locked();
	mutex_unlock(&irq_mutex);

	CHECK(!esdm_irq_present(), "a closed add-on is reported present");
	esdm_config_es_krng_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK_EQ(krng_credit(), uncapped);

	/*
	 * Loaded after the ESDM started, not opened: the module is there, and
	 * the kernel RNG capped all the same - until it is unloaded
	 */
	CHECK(!mkdir(test_module, 0700), "cannot create %s", test_module);
	CHECK(esdm_irq_present(), "an add-on loaded later is not present");
	CHECK(!esdm_irq_enabled(), "an add-on not opened counts as credited");
	CHECK_EQ(krng_credit(), ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY);
	rmdir(test_module);
	CHECK(!esdm_irq_present(), "an add-on unloaded is reported present");
	CHECK_EQ(krng_credit(), uncapped);
	rmdir(test_dir);

	return common_test_result("ES kernel RNG IRQ cap");
}
