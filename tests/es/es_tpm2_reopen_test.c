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
 * Reopening the device then closed the one open first - which the server, by
 * then without the privileges the device asks for, could not open again. A
 * socket pair stands in for a device that answers again but cannot be opened
 * anew, the test answering its commands in advance.
 *
 * The state, the entropy estimate and the status of the source waited for an
 * exchange in progress, so a slow TPM held up every status request. A thread
 * holding the lock of the source stands in for the exchange.
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

#include <pthread.h>
#include <sys/socket.h>
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

struct tpm2_test_hold {
	int held[2], release[2];
};

/* An exchange in progress: holds tpm2_mutex until told to let go */
static void *tpm2_test_hold(void *arg)
{
	struct tpm2_test_hold *hold = arg;
	char c = 0;

	mutex_lock(&tpm2_mutex);
	CHECK_EQ(write(hold->held[1], &c, 1), 1);
	CHECK_EQ(read(hold->release[0], &c, 1), 1);
	mutex_unlock(&tpm2_mutex);

	return NULL;
}

/* None of them waits for the exchange, or the watchdog ends the test */
static void tpm2_test_status_nonblocking(void)
{
	struct tpm2_test_hold hold;
	struct json_object *obj;
	pthread_t holder;
	char c = 0;

	if (pipe(hold.held) || pipe(hold.release)) {
		printf("cannot create the pipes - skipping that part\n");
		return;
	}
	CHECK_EQ(pthread_create(&holder, NULL, tpm2_test_hold, &hold), 0);
	CHECK_EQ(read(hold.held[0], &c, 1), 1);

	alarm(10);
	CHECK(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS) > 0,
	      "no entropy reported while an exchange is in progress");
	CHECK(esdm_es_tpm2.max_entropy() > 0,
	      "no entropy reported while an exchange is in progress");
	CHECK(esdm_es_tpm2.active(),
	      "inactive while an exchange is in progress");
	obj = json_object_new_object();
	CHECK(obj != NULL, "cannot allocate the state");
	if (obj) {
		esdm_es_tpm2.state(obj);
		json_object_put(obj);
	}
	alarm(0);

	CHECK_EQ(write(hold.release[1], &c, 1), 1);
	pthread_join(holder, NULL);
	close(hold.held[0]);
	close(hold.held[1]);
	close(hold.release[0]);
	close(hold.release[1]);
}

/* Queue a successful answer to a TPM2 command with @payload_len bytes */
static void tpm2_test_answer(int fd, uint16_t payload_len)
{
	uint8_t rsp[10 + 2 + 32];
	uint32_t size = 10 + payload_len;

	memset(rsp, 0x5a, sizeof(rsp));
	be16_to_ptr(rsp, TPM2_ST_NO_SESSIONS);
	be32_to_ptr(rsp + 2, size);
	be32_to_ptr(rsp + 6, TPM2_RC_SUCCESS);
	if (payload_len)
		be16_to_ptr(rsp + 10, payload_len - 2);
	CHECK_EQ(send(fd, rsp, size, MSG_NOSIGNAL), (ssize_t)size);
}

/*
 * The device the source has open answers again, but cannot be opened anew -
 * as for a server that has dropped its privileges since.
 */
static void tpm2_test_retry_open_device(void)
{
	uint32_t expected =
		esdm_fast_noise_entropylevel(ESDM_DRNG_SECURITY_STRENGTH_BITS,
					     ESDM_DRNG_SECURITY_STRENGTH_BITS);
	int sv[2], fd;

	/* Each read takes one answer, an empty one is a 0-byte read */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		printf("cannot create the socket pair - skipping that part\n");
		return;
	}

	CHECK_EQ(esdm_es_tpm2.init(), 0);
	CHECK_EQ(unlink(tpm2_test_path), 0);
	mutex_lock(&tpm2_mutex);
	CHECK(tpm2_fd >= 0, "the stand-in device was not opened");
	if (tpm2_fd >= 0)
		close(tpm2_fd);
	tpm2_fd = sv[0];
	mutex_unlock(&tpm2_mutex);

	CHECK_EQ(send(sv[1], "", 0, MSG_NOSIGNAL), 0);
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK_EQ(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 0);
	CHECK(esdm_es_tpm2.selftest() < 0,
	      "a lost connection passed the self test");

	/* Once the interval has passed, the device open is tried again */
#ifdef ESDM_TPM2_STIR
	tpm2_test_answer(sv[1], 0);
#endif
	tpm2_test_answer(sv[1], 2 + 32);
	tpm2_reopen_at = 0;
	CHECK_EQ(tpm2_test_get(), expected);
	CHECK(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS) > 0,
	      "a TPM that delivers again is credited with nothing");

	/* Closes the source's end */
	esdm_es_tpm2.fini();
	close(sv[1]);

	/* For what follows */
	fd = open(tpm2_test_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(fd >= 0, "cannot recreate the stand-in device");
	if (fd >= 0)
		close(fd);
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

	esdm_config_es_tpm2_entropy_rate_set(ESDM_DRNG_SECURITY_STRENGTH_BITS);
	CHECK_EQ(esdm_es_tpm2.init(), 0);
	CHECK(esdm_es_tpm2.active(), "the stand-in device was not opened");

	tpm2_test_status_nonblocking();

	/* The short read loses the connection and credits nothing */
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK_EQ(esdm_es_tpm2.curr_entropy(ESDM_DRNG_SECURITY_STRENGTH_BITS),
		 0);
	CHECK(tpm2_test_size() > 0, "no command was written");

	/* Within the interval the device is left alone */
	CHECK_EQ(truncate(tpm2_test_path, 0), 0);
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK_EQ(tpm2_test_size(), 0);

	/* Once it has passed, the next request reopens it */
	tpm2_reopen_at = 0;
	CHECK_EQ(tpm2_test_get(), 0);
	CHECK(tpm2_test_size() > 0, "the lost device was not reopened");

	esdm_es_tpm2.fini();

	tpm2_test_retry_open_device();

	/* A device absent at init is not looked for again */
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
