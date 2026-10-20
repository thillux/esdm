/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esdm_rpc_client.h>

/*
 * Whether the PID file is held by @pid. The server keeps a lockf() lock on its
 * PID file for as long as it runs; a file nobody locks is stale - left behind
 * by a crash - and the PID in it may meanwhile belong to an unrelated process.
 * The lock owner also has to be the process named there.
 */
static bool pidfile_held_by(int fd, pid_t pid)
{
	struct flock fl = {
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start = 0,
		.l_len = 0,
	};

	if (fcntl(fd, F_GETLK, &fl) < 0) {
		perror("Cannot test the lock of the PID file");
		return false;
	}

	if (fl.l_type == F_UNLCK) {
		fprintf(stderr,
			"PID file is not locked, the ESDM server is not running\n");
		return false;
	}

	if (fl.l_pid != pid) {
		fprintf(stderr,
			"PID file names %d, but is locked by %d - refusing\n",
			(int)pid, (int)fl.l_pid);
		return false;
	}

	return true;
}

static bool signal_suspend(char *pidfile_path)
{
	char pid_string[30] = { 0 };
	FILE *pidfile = NULL;
	size_t read_ret;
	pid_t pid = -1;
	bool held;

	/* read PID */
	if (pidfile_path == NULL) {
		return false;
	}

	pidfile = fopen(pidfile_path, "re");
	if (pidfile == NULL) {
		return false;
	}
	read_ret = fread(&pid_string, 1, sizeof(pid_string) - 1, pidfile);
	if (read_ret == 0 || ferror(pidfile)) {
		fprintf(stderr, "Error reading PID");
		fclose(pidfile);
		return false;
	}

	errno = 0;
	pid = (pid_t)strtol(pid_string, NULL, 10);
	if (errno || pid <= 0) {
		perror("PID conversion failed");
		fclose(pidfile);
		return false;
	}

	held = pidfile_held_by(fileno(pidfile), pid);
	fclose(pidfile);
	if (!held)
		return false;

	fprintf(stdout, "Signal suspend to ESDM\n");
	return kill(pid, SIGUSR1) == 0;
}

/*
 * The DRNGs come out of a suspend with the seeds they took before it, and their
 * reseed interval alone would keep those in service for up to its whole length
 * afterwards - while the memory they lived in through the suspend, or a
 * hibernation image of it, may have been read meanwhile. Have the server
 * reseed every DRNG before its next use: the RNDRESEEDCRNG of the privileged
 * interface, which only root may ask for - the resume unit runs as root.
 * Writing data into the auxiliary pool, which an unprivileged caller may, only
 * stirs the pool and reseeds nothing.
 */
static bool signal_resume(void)
{
	int ret = -1;

	if (esdm_rpcc_init_priv_service(NULL) != 0)
		return false;
	fprintf(stdout, "Signal resume to ESDM\n");

	esdm_invoke(esdm_rpcc_rnd_reseed_crng());

	esdm_rpcc_fini_priv_service();

	if (ret) {
		fprintf(stderr, "The ESDM refused to reseed its DRNGs: %s\n",
			strerror(-ret));
		return false;
	}

	return true;
}

static void usage(void)
{
	fprintf(stderr,
		"esdm-server-signal-helper --suspend --pid PIDFILE | --resume | --help\n");
}

int main(int argc, char **argv)
{
	int c = 0;
	char *pidfile_path = NULL;
	bool suspend = false;
	bool resume = false;
	bool help = false;
	bool bad_opt = false;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = { { "pid", 1, 0, 0 },
						{ "suspend", 0, 0, 0 },
						{ "resume", 0, 0, 0 },
						{ "help", 0, 0, 0 },
						{ 0, 0, 0, 0 } };
		c = getopt_long(argc, argv, "p:srh", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* pid */
				pidfile_path = optarg;
				break;
			case 1:
				/* suspend */
				suspend = true;
				break;
			case 2:
				/* resume */
				resume = true;
				break;
			case 3:
				/* help */
				help = true;
				break;
			}
			break;
		case 'p':
			pidfile_path = optarg;
			break;
		case 's':
			suspend = true;
			break;
		case 'r':
			resume = true;
			break;
		case 'h':
			help = true;
			break;
		default:
			/* getopt_long() already named the offending option */
			bad_opt = true;
			break;
		}
	}

	/*
	 * Exactly one mode has to be asked for. The outcome is decided by the
	 * return value of the mode alone - errno is not reset on success and
	 * may hold anything left over from the work done on the way.
	 */
	if (help || bad_opt || optind < argc || suspend == resume) {
		usage();
		return EXIT_FAILURE;
	}

	if (suspend) {
		if (!signal_suspend(pidfile_path)) {
			fprintf(stderr, "Failure during suspend signaling\n");
			return EXIT_FAILURE;
		}
	} else {
		if (!signal_resume()) {
			fprintf(stderr, "Failure during resume signaling\n");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
