/*
 * Copyright (C) 2019-2026, Stephan Mueller <smueller@chronox.de>
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
 * Compile:
 * gcc -Wall -pedantic -Wextra -o getrawentropy getrawentropy.c
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define RAWENTROPY_SAMPLES 1000
#define DEBUGFS_INTERFACE "/sys/kernel/debug/esdm_es/esdm_raw_sched_hires"

struct opts {
	uint64_t samples;
	char *debugfs_file;
	char *outfile;
};

static int getrawentropy(struct opts *opts)
{
#define BUFFER_SIZE (RAWENTROPY_SAMPLES * sizeof(uint64_t))
	/* main() bounds the samples so that this cannot wrap */
	uint64_t requested = opts->samples * sizeof(uint64_t);
	uint8_t *buffer_p, buffer[BUFFER_SIZE];
	ssize_t ret;
	int in_fd = -1;
	int out_fd = -1;

	in_fd = open(opts->debugfs_file, O_RDONLY);
	if (in_fd < 0)
		return errno;

	if (opts->outfile) {
		out_fd = open(opts->outfile, O_WRONLY | O_CREAT | O_EXCL, 0777);
	} else {
		out_fd = dup(STDOUT_FILENO);
	}

	if (out_fd < 0)
		return errno;

	while (requested) {
		unsigned int i;
		unsigned int gather =
			((BUFFER_SIZE > requested) ? requested : BUFFER_SIZE);

		buffer_p = buffer;

		ret = read(in_fd, buffer_p, gather);
		if (ret < 0) {
			ret = -errno;
			goto out;
		}

		/*
		 * The interface returns 0 when no data will arrive, e.g. with
		 * the collection disabled under lockdown or once the boot
		 * time data is drained - do not spin on it.
		 */
		if (!ret) {
			fprintf(stderr,
				"No more data from %s, still %" PRIu64
				" events missing\n",
				opts->debugfs_file, requested / sizeof(uint64_t));
			ret = -ENODATA;
			goto out;
		}

		for (i = 0; i < (uint32_t)ret / (sizeof(uint64_t)); i++) {
			uint64_t val;

			memcpy(&val, buffer_p, sizeof(uint64_t));
			dprintf(out_fd, "%" PRIu64 "\n", val);
			buffer_p += sizeof(uint64_t);
		}

		requested -= (uint32_t)ret;

		fprintf(stderr, "Fetched %zu events, still %" PRIu64 " to do\n",
			(size_t)ret / sizeof(uint64_t),
			requested / sizeof(uint64_t));
	}

	ret = 0;

out:
	if (in_fd >= 0)
		close(in_fd);

	if (out_fd >= 0)
		close(out_fd);

	return (int)ret;
}

static void usage(void)
{
	fprintf(stderr,
		"Usage: getrawentropy [--samples NUM] [--debugfs-file FILE] [--outfile FILE] [--help]\n");
}

int main(int argc, char *argv[])
{
	struct opts opts;
	int c = 0;

	opts.samples = RAWENTROPY_SAMPLES;
	opts.debugfs_file = DEBUGFS_INTERFACE;
	opts.outfile = NULL;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{ "help", 0, 0, 'h' },
			{ "samples", required_argument, 0, 's' },
			{ "debugfs-file", required_argument, 0, 'f' },
			{ "outfile", required_argument, 0, 'o' },
			{ 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "hf:s:o:", options, &opt_index);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			usage();
			return EXIT_FAILURE;
		case 's': {
			unsigned long long val;
			char *end;

			errno = 0;
			val = strtoull(optarg, &end, 10);
			if (errno || end == optarg || *end || strchr(optarg, '-') ||
			    val > UINT64_MAX / sizeof(uint64_t)) {
				fprintf(stderr, "Invalid number of samples: %s\n",
					optarg);
				return -EINVAL;
			}
			opts.samples = val;
			break;
		}
		case 'f':
			opts.debugfs_file = optarg;
			break;
		case 'o':
			opts.outfile = optarg;
			break;
		default:
			return -EINVAL;
		}
	}

	fprintf(stderr, "Try to collect %" PRIu64 " samples\n", opts.samples);
	fprintf(stderr, "Use debugfs file %s\n", opts.debugfs_file);
	if (opts.outfile) {
		fprintf(stderr, "Write to %s\n", opts.outfile);
	} else {
		fprintf(stderr, "Write to stdout\n");
	}

	return getrawentropy(&opts);
}
