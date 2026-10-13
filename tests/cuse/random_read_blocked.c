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
 * Many readers waiting for the ESDM must not stall the device for everybody
 * else.
 *
 * Each read holds a libfuse worker for its whole RPC. With the 10 workers
 * libfuse 3.12 starts by default, a handful of readers waiting for the ESDM -
 * at boot, for the seeding - kept every other request queued, rngd's
 * RNDADDENTROPY included, which the seeding may well be waiting for.
 *
 * The readers are made to wait by stopping the server: their RPCs then wait for
 * an answer until the RPC timeout. Meanwhile, a status ioctl, which needs no
 * RPC, has to be answered at once.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "env.h"
#include "esdm_rpc_service.h"

/* Well beyond the default of libfuse */
#define READERS 64

/* With the readers in its way, the status ioctl waits for an RPC timeout */
#define PROBE_MAX_MS 3000

static int64_t now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void reader(const char *path)
{
	uint8_t buf[32];
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		_exit(1);

	/* Its result does not matter, only that it waits */
	if (read(fd, buf, sizeof(buf)) < 0) {
		/* An RPC timed out without a fallback */
	}
	close(fd);
	_exit(0);
}

static int probe(const char *path)
{
	char buf[ESDM_SHM_STATUS_INFO_SIZE];
	int64_t start = now_ms(), took;
	int fd, ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		printf("Cannot open file %s: %s\n", path, strerror(errno));
		return 1;
	}

	ret = ioctl(fd, 42, buf);
	took = now_ms() - start;
	close(fd);

	/* EAGAIN is an answer as well: the server is not there for it */
	if (ret < 0 && errno != EAGAIN) {
		printf("Status ioctl failed: %s\n", strerror(errno));
		return 1;
	}

	printf("Status ioctl answered after %lld ms\n", (long long)took);
	if (took > PROBE_MAX_MS) {
		printf("The readers waiting for the ESDM stalled the device\n");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	static const struct timespec settle = { .tv_sec = 1 };
	pid_t readers[READERS];
	char devfile[20];
	unsigned int i, started = 0;
	bool started_ok = true;
	int ret;

	if (argc < 2)
		return 1;

	esdm_cuse_dev_file(devfile, sizeof(devfile), argv[1]);

	ret = env_init(1);
	if (ret)
		return ret;

	/* The status segment is attached by now, the server is up */
	env_signal_server(SIGSTOP);

	for (i = 0; i < READERS; i++) {
		pid_t pid = fork();

		if (pid < 0)
			break;
		if (!pid)
			reader(devfile);
		readers[started++] = pid;
	}

	/* Let the reads reach the daemon */
	nanosleep(&settle, NULL);

	/* Without the readers waiting, the probe would prove nothing */
	for (i = 0; i < started; i++) {
		if (waitpid(readers[i], NULL, WNOHANG) == readers[i]) {
			printf("Reader %u did not wait for the server\n", i);
			readers[i] = -1;
			started_ok = false;
		}
	}

	ret = (started == READERS && started_ok) ? probe(devfile) : 1;

	env_signal_server(SIGCONT);
	for (i = 0; i < started; i++) {
		if (readers[i] > 0)
			waitpid(readers[i], NULL, 0);
	}

	if (!env_daemons_alive())
		ret = 1;

	env_fini();

	return ret;
}
