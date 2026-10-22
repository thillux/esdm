/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE

#include <esdm_rpc_client.h>

#include <json-c/json.h>
#include <poll.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/random.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "esdm_logger.h"
#include "esdm_rpc_service.h"
#include "helper.h"
#include "memset_secure.h"
#include "systemd_support.h"

static atomic_bool should_run = true;
static int notify_fd = -1; /* event fd used to notify in case of termination */
static bool force_pr =
	false; /* force seeding kernel from pr instance of esdm */
static bool had_one_sucessful_seed = false; /* used for ready notification */

static int64_t parse_int64_arg(const char *str, const char *name)
{
	char *endptr = NULL;
	long long val;

	errno = 0;
	val = strtoll(str, &endptr, 10);
	if (errno || endptr == str || (endptr && *endptr != '\0')) {
		/*
		 * Deliberately not esdm_logger(): the command line is still
		 * being parsed, so no -v has been applied and a LOGGER_ERR
		 * record sits below the default threshold. Logging it would
		 * swallow the only explanation for the exit below, and no -v
		 * could bring it back. A usage error belongs on stderr anyway.
		 */
		fprintf(stderr,
			"esdm-kernel-seeder: conversion of %s failed: %s\n",
			name, strerror(errno ? errno : EINVAL));
		exit(EXIT_FAILURE);
	}
	return (int64_t)val;
}

/*
 * The seeding interval waits in ppoll(): 0 would turn the daemon into a busy
 * loop draining the ESDM, a negative one fails the wait and ends the daemon.
 * The upper bound keeps it within a 32 bit time_t.
 */
static int64_t parse_interval_arg(const char *str)
{
	int64_t val = parse_int64_arg(str, "interval");

	if (val < 1 || val > INT32_MAX) {
		/* Not esdm_logger(), see parse_int64_arg() */
		fprintf(stderr,
			"esdm-kernel-seeder: interval %s out of range, it has to be between 1 and %d seconds\n",
			str, INT32_MAX);
		exit(EXIT_FAILURE);
	}

	return val;
}

/*
 * modern Linux kernels have a 256 Bit entropy pool, always provide
 * twice the amount for full entropy inside the pool after leftover hashing
 * on pool updates.
 */
#define ESDM_SERVER_LINUX_ENTROPY_BITS 256
#define ESDM_SERVER_LINUX_ENTROPY_BYTES (2 * ESDM_SERVER_LINUX_ENTROPY_BITS / 8)

/*
 * Whether the ESDM runs its interrupt entropy source, as its JSON status
 * @status_json says: the source is listed, and not as disabled for missing
 * kernel support. The kernel add-on it reads takes the interrupts away from
 * the kernel RNG as soon as it is there, whatever rate the ESDM credits the
 * source with - the ESDM caps its kernel RNG entropy source then as well.
 */
static bool seeder_irq_es_present(const char *status_json)
{
	struct json_object *root, *sources, *es, *name;
	bool present = false;
	size_t i, n;

	if (!status_json)
		return false;

	root = json_tokener_parse(status_json);
	if (!root)
		return false;

	if (!json_object_object_get_ex(root, "entropy_sources", &sources) ||
	    !json_object_is_type(sources, json_type_array))
		goto out;

	n = json_object_array_length(sources);
	for (i = 0; i < n; i++) {
		es = json_object_array_get_idx(sources, i);
		if (!json_object_object_get_ex(es, "name", &name) ||
		    !json_object_is_type(name, json_type_string) ||
		    strcmp(json_object_get_string(name), "Interrupt"))
			continue;

		present = !json_object_object_get_ex(es, "disabled", NULL);
		break;
	}

out:
	json_object_put(root);
	return present;
}

/*
 * The entropy one insertion credits the kernel with, in bits, given the
 * linux-reseed-entropy-count build option @configured and the JSON status of
 * the ESDM @status_json, NULL if there is none.
 *
 * A configured count is credited as it is. Left at 0, the count follows the
 * interrupt entropy source of the ESDM. While it runs, it deprives the kernel
 * RNG of its main entropy source, and the data of the ESDM is entropy the
 * kernel does not get otherwise: it is credited with as much as its pool
 * holds, which the data fills with full entropy. Without it, the kernel RNG
 * has its interrupts and the ESDM credits its kernel RNG entropy source with
 * what the kernel gathers from them - crediting the data again would count
 * that entropy twice, so it is credited with nothing.
 */
static uint32_t seeder_entropy_bits(uint32_t configured,
				    const char *status_json)
{
	if (configured)
		return configured;

	return seeder_irq_es_present(status_json) ?
		       ESDM_SERVER_LINUX_ENTROPY_BITS :
		       0;
}

/*
 * The entropy count of the next insertion, see seeder_entropy_bits(). The
 * status is asked for every time: the ESDM may take up its interrupt entropy
 * source later on, and may have been restarted with another configuration. A
 * status that cannot be obtained credits nothing.
 */
static uint32_t seeder_entropy_count(char *status, size_t statuslen)
{
	int ret = -ENOMEM;

	if (!ESDM_LINUX_RESEED_ENTROPY_COUNT && status) {
		esdm_invoke(esdm_rpcc_status_json(status, statuslen));
		if (ret)
			esdm_logger(LOGGER_WARN, LOGGER_C_SEEDER,
				    "Cannot obtain the ESDM status, crediting no entropy: %d\n",
				    ret);
	}

	return seeder_entropy_bits(ESDM_LINUX_RESEED_ENTROPY_COUNT,
				   ret ? NULL : status);
}

static bool pr_mode(void)
{
#if defined(ESDM_AIS2031_NTG1_SEEDING_STRATEGY) || defined(ESDM_JENT_NTG1)
	return true;
#else
	return force_pr;
#endif
}

static int esdm_rpcs_linux_insert_entropy(struct rand_pool_info *rpi,
					  bool force_crng_reseed)
{
	struct stat statfs;
	unsigned long esdm_rpcs_linux_ioctl = RNDADDENTROPY;
	int esdm_rpcs_linux_fd = -1;
	int errsv = 0;

	/*
	 * First we attempt to access the CUSE device node. If this exists, we
	 * know that the CUSE /dev/random server is active. In this case we
	 * give the data to the CUSE /dev/random server which sends the
	 * data to the kernel. Otherwise we use /dev/random directly.
	 */
	if (stat(ESDM_CUSE_RANDOM_DEVICE, &statfs) < 0) {
		if (errno == ENOENT) {
			/*
			 * If the CUSE device node does not exist, we assume we
			 * can open /dev/random directly.
			 */
			if (stat("/dev/random", &statfs) < 0) {
				errsv = errno;

				esdm_logger(
					LOGGER_ERR, LOGGER_C_SEEDER,
					"Error in accessing /dev/random: %s\n",
					strerror(errsv));
				return -errsv;
			}

			esdm_rpcs_linux_fd = open("/dev/random", O_WRONLY);
			if (esdm_rpcs_linux_fd < 0) {
				errsv = errno;

				esdm_logger(
					LOGGER_ERR, LOGGER_C_SEEDER,
					"Error in opening /dev/random: %s\n",
					strerror(errsv));
				return -errsv;
			}
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
				    "/dev/random opened to insert entropy\n");
		} else if (errno) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Error in accessing " ESDM_CUSE_RANDOM_DEVICE
				    ": %s\n",
				    strerror(errsv));
			return -errsv;
		}
	} else {
		esdm_rpcs_linux_fd = open(ESDM_CUSE_RANDOM_DEVICE, O_WRONLY);
		if (esdm_rpcs_linux_fd < 0) {
			errsv = errno;

			esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
				    "Error in opening " ESDM_CUSE_RANDOM_DEVICE
				    ": %s\n",
				    strerror(errsv));
			return -errsv;
		}
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
			    ESDM_CUSE_RANDOM_DEVICE
			    " opened to insert entropy\n");

		/* Use the special IOCTL from the CUSE server */
		esdm_rpcs_linux_ioctl = 43;
	}

	errsv = ioctl(esdm_rpcs_linux_fd, esdm_rpcs_linux_ioctl, rpi);
	if (errsv != 0) {
		errsv = errno;
		esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
			    "Error in adding entropy: %s\n", strerror(errsv));
	} else {
		esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
			    "Entropy data with rate %u bits added\n",
			    rpi->entropy_count);
	}

	/* only perform crng reseed, if entropy add was a success */
	if (errsv == 0 && force_crng_reseed) {
		/* need to use ESDM cuse interface? */
		if (esdm_rpcs_linux_ioctl == 43)
			esdm_rpcs_linux_ioctl = 44;
		else
			esdm_rpcs_linux_ioctl = RNDRESEEDCRNG;

		errsv = ioctl(esdm_rpcs_linux_fd, esdm_rpcs_linux_ioctl);
		if (errsv != 0) {
			errsv = errno;
			esdm_logger(
				LOGGER_ERR, LOGGER_C_SEEDER,
				"Error during forced Linux kernel CRNG reseed: %s\n",
				strerror(errno));
		} else {
			esdm_logger(LOGGER_DEBUG, LOGGER_C_SEEDER,
				    "Linux kernel CRNG forcefully reseeded\n");
		}
	}

	close(esdm_rpcs_linux_fd);

	return -errsv;
}

static void usage(void)
{
	printf("esdm-kernel-seeder [-i --interval SECS] [-h --help] [-v --verbosity] [-p --force-pr]\n");
}

static int handle_reseeding(int64_t seeding_interval_secs)
{
	uint8_t rpi_buf
		[sizeof(struct rand_pool_info) +
		 ESDM_SERVER_LINUX_ENTROPY_BYTES] __aligned(sizeof(uint32_t));
	struct rand_pool_info *rpi = (struct rand_pool_info *)rpi_buf;

	struct timespec ts;
	struct pollfd pfd;
	ssize_t ret;
	int pret;
	int fn_ret = EXIT_SUCCESS;
	/* The JSON status, only asked for when the count depends on it */
	char *status = ESDM_LINUX_RESEED_ENTROPY_COUNT ?
			       NULL :
			       malloc(ESDM_RPC_MAX_DATA);

	rpi->buf_size = ESDM_SERVER_LINUX_ENTROPY_BYTES;

	if (!ESDM_LINUX_RESEED_ENTROPY_COUNT && !status)
		esdm_logger(LOGGER_WARN, LOGGER_C_SEEDER,
			    "Cannot allocate the status buffer, crediting no entropy\n");

	while (atomic_load(&should_run)) {
		if (pr_mode()) {
			ret = esdm_rpcc_get_random_bytes_pr(
				(uint8_t *)rpi->buf, (size_t)rpi->buf_size);
		} else {
			ret = esdm_rpcc_get_random_bytes_full(
				(uint8_t *)rpi->buf, (size_t)rpi->buf_size);
		}

		if (ret < 0) {
			/* An RPC abandoned for the termination is no failure */
			if (atomic_load(&should_run))
				esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
					    "Failure in generating random bits: %zd\n",
					    ret);
		} else {
			rpi->entropy_count = (int)seeder_entropy_count(
				status, ESDM_RPC_MAX_DATA);
			if (pr_mode()) {
				/*
				 * Immediately force CRNG reseed in NTG.1/PR mode
				 *
				 * While not strictly necessary, this enables you
				 * to better reason, when your seeds take effect
				 * and allows control via the reseeding interval in secs,
				 * without using another small daemon.
				 */
				ret = esdm_rpcs_linux_insert_entropy(rpi, true);
			} else {
				ret = esdm_rpcs_linux_insert_entropy(rpi,
								     false);
			}
		}

		memset_secure(rpi->buf, 0, (size_t)rpi->buf_size);
		rpi->entropy_count = 0;

		if (ret == 0 && !had_one_sucessful_seed) {
			(void)systemd_notify_ready();
			systemd_notify_status("Running");
			had_one_sucessful_seed = true;
		}

		pfd.fd = notify_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		/* Wake up every 2 minutes by default and every 2 sec if not initially seeded kernel */
		/* parse_interval_arg() keeps it within a 32 bit time_t */
		ts.tv_sec = had_one_sucessful_seed ?
				    (time_t)seeding_interval_secs :
				    2;
		ts.tv_nsec = 0;

		pret = ppoll(&pfd, 1, &ts, NULL);

		/* error - the wait itself broke, which is a failure */
		if (pret == -1 && errno != EINTR) {
			esdm_logger(LOGGER_ERR, LOGGER_C_ANY,
				    "ppoll returned with error %s\n",
				    strerror(errno));
			fn_ret = EXIT_FAILURE;
			goto out;
		}

		/*
		 * Activity on the notification fd. Only sig_term() ever writes
		 * to it, so this is the requested shutdown and therefore a
		 * successful exit - reporting a failure here would make every
		 * ordinary "systemctl stop" mark the unit as failed.
		 */
		if (pret > 0) {
			uint64_t event;
			ssize_t read_ret;

			/* make compiler happy */
			read_ret = read(notify_fd, &event, sizeof(event));
			(void)read_ret;
			esdm_logger(LOGGER_VERBOSE, LOGGER_C_SEEDER,
				    "Termination requested, stopping\n");
			goto out;
		}
	}

out:
	free(status);
	return fn_ret;
}

/*
 * Abandon an RPC on termination: the get calls keep asking an unseeded ESDM
 * until it is seeded, which a stop must not wait for.
 */
static int seeder_interrupt(void *data)
{
	(void)data;

	return !atomic_load(&should_run);
}

/*
 * Terminate the daemon cleanly.
 *
 * Only async-signal-safe operations here: atomic flag set, write to eventfd.
 * Do NOT call esdm_logger() -- it uses vsnprintf/syslog which can deadlock.
 */
static void sig_term(int sig)
{
	static const uint64_t event_inc = 1;

	(void)sig;

	atomic_store(&should_run, false);
	if (notify_fd >= 0) {
		ssize_t write_ret;

		/* make compiler happy */
		write_ret = write(notify_fd, &event_inc, sizeof(event_inc));
		(void)write_ret;
	}
}

static void install_term(void)
{
	struct sigaction sa;

	esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER,
		    "Install termination signal handler\n");

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

/*
 * Helper tool to insert entropy into the kernel RNG occasionally. When the IRQ ES
 * is present, this is required as the kernel RNG is deprived of its main ES,
 * and the data is credited with entropy - see seeder_entropy_bits().
 * But also in any other case it is good to insert data into the kernel RNG
 * to provide data that is gathered from other entropy sources. Basically
 * the ESDM acts as an RNGd to top up the entropy in the kernel.
 */
int main(int argc, char **argv)
{
	int c = 0;
	int64_t seeding_interval_secs = ESDM_LINUX_RESEED_INTERVAL_SEC;
	bool help = false;
	int tool_ret = EXIT_SUCCESS;
	int verbosity = 0;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{ "interval", 1, 0, 0 },  { "help", 0, 0, 0 },
			{ "verbosity", 0, 0, 0 }, { "syslog", 0, 0, 0 },
			{ "force-pr", 0, 0, 0 },  { 0, 0, 0, 0 }
		};
		c = getopt_long(argc, argv, "i:hvsp", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* seeding interval */
				seeding_interval_secs =
					parse_interval_arg(optarg);
				break;
			case 1:
				/* help */
				help = true;
				break;
			case 2:
				/* verbosity */
				verbosity++;
				break;
			case 3:
				/* syslog */
				esdm_logger_enable_syslog("esdm-kernel-seeder");
				break;
			case 4:
				/* force_pr */
				force_pr = true;
				break;
			}
			break;
		case 'i':
			seeding_interval_secs = parse_interval_arg(optarg);
			break;
		case 'h':
			help = true;
			break;
		case 'v':
			verbosity++;
			break;
		case 's':
			esdm_logger_enable_syslog("esdm-kernel-seeder");
			break;
		case 'p':
			force_pr = true;
			break;
		}
	}

	/*
	 * The -v count is the verbosity level, but errors and warnings are
	 * logged in any case: without -v the count is 0, which as a level means
	 * LOGGER_NONE, and the logger's default of LOGGER_STATUS swallows the
	 * LOGGER_ERR diagnostics below as well - the daemon would fail without
	 * any output. The -vvv of the shipped unit has always meant warnings.
	 * This matches how esdm-server treats its -v count.
	 */
	esdm_logger_set_verbosity(verbosity > LOGGER_WARN ?
					  (enum esdm_logger_verbosity)verbosity :
					  LOGGER_WARN);

	if (help) {
		usage();
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	if (geteuid()) {
		esdm_logger(LOGGER_ERR, LOGGER_C_SEEDER,
			    "Program must start as root!\n");
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	systemd_notify_status("Starting");

	notify_fd = eventfd(0, EFD_CLOEXEC);
	if (notify_fd < 0) {
		esdm_logger(
			LOGGER_ERR, LOGGER_C_SEEDER,
			"Unable to create event fd for termination notification!\n");
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	if (esdm_rpcc_init_unpriv_service(seeder_interrupt) != 0) {
		printf("unable to initialize unprivileged ESDM service, exiting!");
		tool_ret = EXIT_FAILURE;
		goto out;
	}

	install_term();

	esdm_logger(LOGGER_STATUS, LOGGER_C_SEEDER,
		    "Start kernel (re-)seeding with %" PRId64 " s interval!\n",
		    seeding_interval_secs);
	if (pr_mode()) {
		esdm_logger(
			LOGGER_STATUS, LOGGER_C_SEEDER,
			"Using prediction resistant mode to seed kernel!\n");
	}

	systemd_notify_status("Waiting for initial kernel seed operation");

	tool_ret = handle_reseeding(seeding_interval_secs);

	esdm_rpcc_fini_unpriv_service();

	systemd_notify_stopping();

out:
	if (notify_fd >= 0)
		close(notify_fd);
	notify_fd = -1;
	return tool_ret;
}
