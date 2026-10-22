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
 * Test of the TPM 2.0 entropy source across a lost connection.
 *
 * Any write error or short read once closed the device for good, so one
 * resource manager hiccup took the source out until a reinitialization. A
 * regular file stands in for the device: the command write succeeds and the
 * response read finds the end of the file, which is such a short read. Whether
 * the source reopened shows in the file, which the next command lands in.
 *
 * The device path is compile-time, so the source is compiled into the test
 * with the path pointing at the file.
 */

#include "config.h"

static char tpm2_test_path[256];
#undef ESDM_TPM2_RM_PATH
#define ESDM_TPM2_RM_PATH tpm2_test_path

/* The unit under test */
#include "esdm_es_tpm2.c"

#include <sys/stat.h>

#include "common_test.h"
#include "esdm_logger.h"

static off_t tpm2_test_size(void)
{
	struct stat st;

	if (stat(tpm2_test_path, &st))
		return -1;
	return st.st_size;
}

static uint32_t tpm2_test_get(void)
{
	struct entropy_es eb_es;

	memset(&eb_es, 0, sizeof(eb_es));
	eb_es.e_bits = 1;
	esdm_es_tpm2.get_ent(&eb_es, ESDM_DRNG_SECURITY_STRENGTH_BITS, true);

	return eb_es.e_bits;
}

int main(void)
{
	const char *tmpdir = getenv("TMPDIR");
	int fd;

	esdm_logger_set_verbosity(LOGGER_DEBUG);

	snprintf(tpm2_test_path, sizeof(tpm2_test_path),
		 "%s/esdm-tpm2-reopen-XXXXXX",
		 tmpdir && *tmpdir ? tmpdir : "/tmp");
	fd = mkstemp(tpm2_test_path);
	if (fd < 0) {
		printf("cannot create the stand-in device - skipping\n");
		return 77;
	}
	close(fd);

	CHECK_EQ(esdm_es_tpm2.init(), 0);
	CHECK(esdm_es_tpm2.active(), "the stand-in device was not opened");

	/* The short read loses the connection and credits nothing */
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK(!esdm_es_tpm2.active(), "a short read left the device open");
	CHECK(tpm2_test_size() > 0, "no command was written");

	/* Within the interval the device stays closed */
	CHECK_EQ(truncate(tpm2_test_path, 0), 0);
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK_EQ(tpm2_test_size(), 0);

	/* Once it has passed, the next request reopens it */
	tpm2_reopen_at = 0;
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK(tpm2_test_size() > 0, "the lost device was not reopened");

	/* A device absent at init is not looked for again */
	esdm_es_tpm2.fini();
	CHECK_EQ(unlink(tpm2_test_path), 0);
	CHECK_EQ(esdm_es_tpm2.init(), 0);
	CHECK(!esdm_es_tpm2.active(), "an absent device was opened");
	fd = open(tpm2_test_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(fd >= 0, "cannot recreate the stand-in device");
	if (fd >= 0)
		close(fd);
	tpm2_reopen_at = 0;
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK_EQ(tpm2_test_size(), 0);

	esdm_es_tpm2.fini();
	unlink(tpm2_test_path);

	return common_test_result("es_tpm2_reopen");
}
