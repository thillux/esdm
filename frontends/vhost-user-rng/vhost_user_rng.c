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
 * esdm-vhost-user-rng: the back-end of a virtio entropy device for QEMU and
 * Cloud Hypervisor guests, serving the guest from the ESDM - see
 * esdm-vhost-user-rng(8).
 *
 * The daemon parses memory a guest writes, the most hostile input the ESDM
 * meets, and so it is a process of its own, one per VM: it reaches the ESDM
 * through the unprivileged RPC interface like any other client, and a guest
 * that took it over has gained nothing any local user does not have - not
 * the ESDM, and not the back-end of another guest.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "esdm_logger.h"
#include "esdm_rpc_client.h"
#include "esdm_server_socket.h"
#include "memset_secure.h"
#include "privileges.h"
#include "systemd_support.h"
#include "vhost_user_dev.h"

/* Polling interval of a ring without kick descriptor */
#define VU_RNG_POLL_MS 20

/* Reads of a kick descriptor in a row that make it no eventfd */
#define VU_RNG_KICK_READS 16

/* Wait between failed attempts to reach the ESDM, growing up to the second */
#define VU_RNG_BACKOFF_MIN_MS 100
#define VU_RNG_BACKOFF_MAX_MS 5000

/* Pending connections while one is served */
#define VU_RNG_BACKLOG 4

/* --max_bytes of --pr, unless given: 1 KiB per --period_ms, see main() */
#define VU_RNG_PR_MAX_BYTES 1024

struct vu_rng {
	struct vu_dev dev;
	/* Serve from the prediction resistant DRNG */
	bool pr;
	/* The ESDM failed the last request, see vu_rng_set_failing() */
	bool rpc_failing;
	/* Random bytes on their way into guest memory, see vu_rng_buf_alloc() */
	uint8_t *buf;
	pthread_t worker;
};

static struct vu_rng vu_rng;

/* Written by the signal handler to end the daemon */
static int vu_rng_stop_fd = -1;
static atomic_bool vu_rng_stopping;

/******************************************************************************
 * The ESDM
 ******************************************************************************/

/* What an RPC is interrupted for: the generation it was issued in passed */
struct vu_rng_intr {
	unsigned int gen;
};

/*
 * Registered with the RPC client: a request waiting for the ESDM - for its
 * seeding, or for it to come back - is abandoned once the request of the guest
 * it is for went stale, or the daemon ends. The client asks every time it
 * would go on waiting.
 */
static int vu_rng_rpc_interrupt(void *data)
{
	const struct vu_rng_intr *intr = data;

	if (!intr)
		return 0;

	return vu_dev_interrupted(&vu_rng.dev, intr->gen);
}

/*
 * Whether the ESDM fails the requests. The daemon says so when that starts and
 * when it ends, once each. The RPC client says so with every attempt - over and
 * over for as long as the ESDM is gone, several lines for every request a
 * socket left behind refuses -, so its messages are held back meanwhile,
 * unless debug messages were asked for: the logger logs the class of the
 * daemon alone, which is all the daemon logs besides once it serves.
 */
static void vu_rng_set_failing(struct vu_rng *rng, bool failing)
{
	if (rng->rpc_failing == failing)
		return;
	rng->rpc_failing = failing;

	if (esdm_logger_get_verbosity(LOGGER_C_VHOST) < LOGGER_DEBUG)
		esdm_logger_set_class(failing ? LOGGER_C_VHOST : LOGGER_C_ANY);
}

/* Sleep @ms, unless generation @gen passes first */
static void vu_rng_sleep(struct vu_rng *rng, unsigned int gen, unsigned int ms)
{
	static const struct timespec slice = { .tv_sec = 0,
					       .tv_nsec = 50 * 1000 * 1000 };
	unsigned int slept;

	for (slept = 0; slept < ms; slept += 50) {
		if (vu_dev_interrupted(&rng->dev, gen))
			return;
		nanosleep(&slice, NULL);
	}
}

/*
 * The random bytes of a request: from the fully seeded DRNG of the ESDM by
 * default, which hands out nothing before the ESDM is fully seeded - the
 * request waits until then -, or from the prediction resistant DRNG with
 * --pr, for guests crediting the device as full entropy. An ESDM that cannot
 * be reached is asked again until it can, the request of the guest waiting.
 */
static int vu_rng_fill(void *ctx, uint8_t *buf, size_t len, unsigned int gen)
{
	struct vu_rng *rng = ctx;
	struct vu_rng_intr intr = { .gen = gen };
	unsigned int backoff = VU_RNG_BACKOFF_MIN_MS;
	ssize_t ret;

	for (;;) {
		if (vu_dev_interrupted(&rng->dev, gen))
			return -EINTR;

		if (rng->pr)
			ret = esdm_rpcc_get_random_bytes_pr_int(buf, len,
								&intr);
		else
			ret = esdm_rpcc_get_random_bytes_full_int(buf, len,
								  &intr);

		if (ret == (ssize_t)len) {
			if (rng->rpc_failing)
				esdm_logger(LOGGER_STATUS, LOGGER_C_VHOST,
					    "The ESDM serves again\n");
			vu_rng_set_failing(rng, false);
			return 0;
		}

		memset_secure(buf, 0, len);

		if (vu_dev_interrupted(&rng->dev, gen))
			return -EINTR;

		if (!rng->rpc_failing)
			esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
				    "Cannot obtain random bytes from the ESDM: %s - the guest waits until it can\n",
				    strerror(ret < 0 ? (int)-ret : EIO));
		vu_rng_set_failing(rng, true);

		vu_rng_sleep(rng, gen, backoff);
		if (backoff < VU_RNG_BACKOFF_MAX_MS)
			backoff *= 2;
	}
}

/*
 * The buffer the random bytes pass through on their way into guest memory -
 * a mapping of its own, so it can be kept out of core dumps. It is wiped after
 * every request.
 */
static uint8_t *vu_rng_buf_alloc(void)
{
	void *buf = mmap(NULL, VU_REQ_MAX_BYTES, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (buf == MAP_FAILED)
		return NULL;

	(void)madvise(buf, VU_REQ_MAX_BYTES, MADV_DONTDUMP);

	return buf;
}

static void vu_rng_buf_free(uint8_t *buf)
{
	if (!buf)
		return;

	memset_secure(buf, 0, VU_REQ_MAX_BYTES);
	munmap(buf, VU_REQ_MAX_BYTES);
}

/******************************************************************************
 * The worker
 ******************************************************************************/

/* Read what an eventfd holds, so it is not readable any more */
static void vu_rng_drain(int fd)
{
	uint64_t v;
	ssize_t ret;

	do {
		ret = read(fd, &v, sizeof(v));
	} while (ret < 0 && errno == EINTR);
}

/*
 * Read what the kick descriptor holds. The eventfd a front-end hands over reads
 * as the count of the kicks since the last read, at least 1, and is not
 * readable again until the next kick. Anything else the front-end could hand
 * over instead is readable for good - a file reads its content and then its
 * end, /dev/zero zeros, /dev/urandom without end - and would keep the worker
 * going around at full speed: false for those. A descriptor that still reads
 * after VU_RNG_KICK_READS reads in a row is one of them, as a guest would have
 * to kick between every two of them to get there.
 */
static bool vu_rng_drain_kick(int fd)
{
	unsigned int reads = 0;

	while (reads < VU_RNG_KICK_READS) {
		uint64_t v = 0;
		ssize_t ret = read(fd, &v, sizeof(v));

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			return errno == EAGAIN;
		}
		if (ret != (ssize_t)sizeof(v) || !v)
			return false;
		reads++;
	}

	return false;
}

/*
 * Serve the ring whenever there is something to do: a kick of the guest, a
 * change the control thread made, the end of a wait for the rate limit, or -
 * for a ring without kick descriptor - the polling interval.
 */
static void *vu_rng_worker(void *arg)
{
	struct vu_rng *rng = arg;
	struct vu_worker_view view = { .kick_fd = -1 };
	const struct vu_source src = { .fill = vu_rng_fill, .ctx = rng };
	bool kick_dead = false;
	unsigned int kick_gen = 0;

	while (!atomic_load(&rng->dev.shutdown)) {
		struct pollfd pfd[2];
		nfds_t n = 1;
		int wait;

		vu_dev_worker_view(&rng->dev, &view);
		if (view.kick_gen != kick_gen) {
			kick_gen = view.kick_gen;
			kick_dead = false;
		}

		wait = vu_dev_serve(&rng->dev, &src, rng->buf);
		if (view.poll && (wait < 0 || wait > VU_RNG_POLL_MS))
			wait = VU_RNG_POLL_MS;

		pfd[0].fd = rng->dev.wake_fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		if (view.kick_fd >= 0 && !kick_dead) {
			pfd[1].fd = view.kick_fd;
			pfd[1].events = POLLIN;
			pfd[1].revents = 0;
			n = 2;
		}

		if (poll(pfd, n, wait) < 0) {
			if (errno != EINTR) {
				esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
					    "Worker cannot wait: %s\n",
					    strerror(errno));
				/* Do not spin on a poll(2) that keeps failing */
				nanosleep(&(struct timespec){ .tv_sec = 1 },
					  NULL);
			}
			continue;
		}

		if (pfd[0].revents & POLLIN)
			vu_rng_drain(pfd[0].fd);

		/*
		 * An eventfd never hangs up, and reads as one; whatever the
		 * front-end handed over instead would wake the worker for good.
		 * It is ignored until the front-end replaces it.
		 */
		if (n > 1 &&
		    (((pfd[1].revents & POLLIN) &&
		      !vu_rng_drain_kick(pfd[1].fd)) ||
		     (pfd[1].revents & (POLLERR | POLLHUP | POLLNVAL)))) {
			esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
				    "The kick descriptor of the front-end is no eventfd, ignoring it\n");
			kick_dead = true;
		}
	}

	if (view.kick_fd >= 0)
		close(view.kick_fd);

	return NULL;
}

/******************************************************************************
 * The socket
 ******************************************************************************/

static void vu_rng_sig_stop(int sig)
{
	static const uint64_t one = 1;
	ssize_t ret;

	(void)sig;

	/* Only async-signal-safe operations here */
	atomic_store(&vu_rng_stopping, true);
	if (vu_rng_stop_fd >= 0) {
		ret = write(vu_rng_stop_fd, &one, sizeof(one));
		(void)ret;
	}
}

static void vu_rng_install_signals(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = vu_rng_sig_stop;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);

	/* A front-end gone in the middle of a reply is no reason to end */
	signal(SIGPIPE, SIG_IGN);
}

/* The socket listened on, -1 if none */
static int vu_rng_listen_fd = -1;

/* The socket a --socket path was bound to, to remove it at the end */
static struct {
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	dev_t dev;
	ino_t ino;
	bool bound;
} vu_rng_bound;

static int vu_rng_listen_path(const char *path, mode_t mode, gid_t gid)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct stat sb;
	int fd, ret;

	if (strlen(path) >= sizeof(addr.sun_path))
		return -ENAMETOOLONG;
	memcpy(addr.sun_path, path, strlen(path) + 1);

	/*
	 * A socket left behind by an earlier instance is replaced - unless an
	 * instance still serves on it, which would lose its guest.
	 */
	if (lstat(path, &sb) == 0) {
		if (!S_ISSOCK(sb.st_mode))
			return -EEXIST;

		fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd < 0)
			return -errno;
		ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		close(fd);
		if (!ret)
			return -EADDRINUSE;

		unlink(path);
	}

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	ret = esdm_server_bind_unix_group(fd, &addr, mode, gid);
	if (ret)
		goto err;

	if (lstat(path, &sb) == 0) {
		memcpy(vu_rng_bound.path, addr.sun_path,
		       sizeof(vu_rng_bound.path));
		vu_rng_bound.dev = sb.st_dev;
		vu_rng_bound.ino = sb.st_ino;
		vu_rng_bound.bound = true;
	}

	if (listen(fd, VU_RNG_BACKLOG) < 0) {
		ret = -errno;
		goto err;
	}

	return fd;

err:
	close(fd);
	return ret;
}

/* Remove the socket file of --socket, if it is still the one bound to */
static void vu_rng_unlink(void)
{
	struct stat sb;

	if (!vu_rng_bound.bound)
		return;
	vu_rng_bound.bound = false;

	if (lstat(vu_rng_bound.path, &sb) == 0 && S_ISSOCK(sb.st_mode) &&
	    sb.st_dev == vu_rng_bound.dev && sb.st_ino == vu_rng_bound.ino)
		unlink(vu_rng_bound.path);
}

/*
 * Stop listening, before the front-end is let go when the daemon ends. A VMM
 * reconnects as soon as its connection is closed, and one that got into the
 * backlog of a socket about to be closed would find its connection reset in
 * the middle of the set-up - which Cloud Hypervisor does not retry. Refused,
 * it tries again until a new instance listens. With socket activation the
 * socket stays open in systemd, and the next instance takes the connection
 * over.
 */
static void vu_rng_stop_listening(void)
{
	if (vu_rng_listen_fd >= 0)
		close(vu_rng_listen_fd);
	vu_rng_listen_fd = -1;
	vu_rng_unlink();
}

/* Whether @fd is a Unix stream socket, and whether it listens */
static int vu_rng_check_socket(int fd, bool *listening)
{
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);
	int type = 0, acc = 0;
	socklen_t optlen = sizeof(type);

	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &optlen) < 0)
		return -errno;
	if (type != SOCK_STREAM)
		return -ESOCKTNOSUPPORT;

	if (getsockname(fd, (struct sockaddr *)&ss, &len) < 0)
		return -errno;
	if (ss.ss_family != AF_UNIX)
		return -EAFNOSUPPORT;

	optlen = sizeof(acc);
	if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &acc, &optlen) < 0)
		return -errno;
	*listening = !!acc;

	(void)fcntl(fd, F_SETFD, FD_CLOEXEC);

	return 0;
}

/* Accept the next front-end; -EINTR when the daemon is to end */
static int vu_rng_accept(int lfd)
{
	struct pollfd pfd[2] = {
		{ .fd = lfd, .events = POLLIN },
		{ .fd = vu_rng_stop_fd, .events = POLLIN },
	};

	for (;;) {
		int fd;

		if (atomic_load(&vu_rng_stopping))
			return -EINTR;

		if (poll(pfd, 2, -1) < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (pfd[1].revents)
			return -EINTR;
		if (!(pfd[0].revents & POLLIN))
			continue;

		fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
		if (fd >= 0)
			return fd;

		if (errno != EINTR && errno != EAGAIN &&
		    errno != ECONNABORTED) {
			esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
				    "Cannot accept a connection: %s\n",
				    strerror(errno));
			/* Out of descriptors, say: do not spin */
			poll(&pfd[1], 1, 100);
		}
	}
}

/* Serve one front-end until it goes away or the daemon ends */
static void vu_rng_serve_conn(int fd)
{
	struct timeval tv = { .tv_sec = VU_MSG_TIMEOUT_MS / 1000 };
	struct ucred cred;
	socklen_t len = sizeof(cred);
	int ret;

	/* A front-end not reading its replies does not hold the daemon up */
	(void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len))
		esdm_logger(LOGGER_STATUS, LOGGER_C_VHOST,
			    "Front-end connected: PID %d, UID %u, GID %u\n",
			    (int)cred.pid, (unsigned int)cred.uid,
			    (unsigned int)cred.gid);

	do {
		ret = vu_conn_serve(&vu_rng.dev, fd, vu_rng_stop_fd);
	} while (!ret);

	if (ret == -EINTR)
		vu_rng_stop_listening();

	if (ret == -ECONNRESET) {
		esdm_logger(LOGGER_STATUS, LOGGER_C_VHOST,
			    "Front-end disconnected\n");
	} else if (ret != -EINTR) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Closing the connection to the front-end: %s\n",
			    strerror(-ret));
	}

	/* Everything of the front-end goes, the next one starts afresh */
	vu_dev_disconnect(&vu_rng.dev);
	close(fd);
}

/******************************************************************************
 * Command line
 ******************************************************************************/

static void usage(void)
{
	fprintf(stderr, "\nESDM vhost-user back-end of a virtio entropy device\n\n");
	fprintf(stderr, "esdm-vhost-user-rng %s\n\n", VERSION);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr,
		"\t-s --socket <PATH>\tListen on a Unix domain socket at PATH\n");
	fprintf(stderr, "\t   --socket-path=<PATH>\tThe same\n");
	fprintf(stderr,
		"\t   --fd <N>\t\tServe the socket on descriptor N, listening\n");
	fprintf(stderr, "\t\t\t\tor connected\n");
	fprintf(stderr,
		"\t-m --mode <MODE>\tAccess mode of the --socket, octal (default 0600,\n");
	fprintf(stderr, "\t\t\t\t0660 with --socket_group)\n");
	fprintf(stderr,
		"\t   --socket_group <GROUP>\tGroup of the --socket\n");
	fprintf(stderr,
		"\t-p --pr\t\t\tServe from the prediction resistant DRNG\n");
	fprintf(stderr,
		"\t   --max_bytes <N>\tServe at most N bytes per period (default 0:\n");
	fprintf(stderr, "\t\t\t\tunlimited; %u with --pr)\n",
		VU_RNG_PR_MAX_BYTES);
	fprintf(stderr,
		"\t   --period_ms <MS>\tLength of the period (default 1000)\n");
	fprintf(stderr,
		"\t-u --user <USER>\tStarted as root: drop to USER (default nobody)\n");
	fprintf(stderr,
		"\t-g --group <GROUP>\tStarted as root: drop to GROUP (default the\n");
	fprintf(stderr, "\t\t\t\tgroup of USER)\n");
	fprintf(stderr, "\t   --syslog\t\tLog to syslog\n");
	fprintf(stderr,
		"\t-v --verbose\t\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr,
		"\t   --print-capabilities\tPrint the capabilities as JSON and exit\n");
	fprintf(stderr, "\t-h --help\t\tThis help information\n");
	fprintf(stderr, "\t   --version\t\tPrint version\n");
}

/* An unsigned number of the command line, or exit */
static uint64_t vu_rng_parse_u64(const char *arg, const char *name,
				 uint64_t max, int base)
{
	unsigned long long val;
	char *end;

	errno = 0;
	val = strtoull(arg, &end, base);
	if (errno || end == arg || *end || arg[0] == '-' || val > max) {
		fprintf(stderr, "esdm-vhost-user-rng: invalid %s \"%s\"\n",
			name, arg);
		exit(EXIT_FAILURE);
	}

	return (uint64_t)val;
}

enum {
	OPT_SOCKET_PATH = 256,
	OPT_FD,
	OPT_SOCKET_GROUP,
	OPT_MAX_BYTES,
	OPT_PERIOD_MS,
	OPT_SYSLOG,
	OPT_PRINT_CAPS,
	OPT_VERSION,
};

int main(int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "socket", required_argument, NULL, 's' },
		{ "socket-path", required_argument, NULL, OPT_SOCKET_PATH },
		{ "fd", required_argument, NULL, OPT_FD },
		{ "mode", required_argument, NULL, 'm' },
		{ "socket_group", required_argument, NULL, OPT_SOCKET_GROUP },
		{ "pr", no_argument, NULL, 'p' },
		{ "max_bytes", required_argument, NULL, OPT_MAX_BYTES },
		{ "period_ms", required_argument, NULL, OPT_PERIOD_MS },
		{ "user", required_argument, NULL, 'u' },
		{ "group", required_argument, NULL, 'g' },
		{ "syslog", no_argument, NULL, OPT_SYSLOG },
		{ "verbose", no_argument, NULL, 'v' },
		{ "print-capabilities", no_argument, NULL, OPT_PRINT_CAPS },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, OPT_VERSION },
		{ NULL, 0, NULL, 0 }
	};
	const char *socket_path = NULL, *user = NULL, *group = NULL;
	const char *socket_group = NULL;
	uint64_t max_bytes = 0, period_ms = 1000;
	int fd_arg = -1, lfd = -1, ret, c, verbosity = 0, nlisten;
	gid_t sgid = (gid_t)-1;
	bool mode_set = false, max_bytes_set = false, listening = true;
	bool worker = false;
	mode_t mode = 0600;
	char where[PATH_MAX + 32];

	while ((c = getopt_long(argc, argv, "s:m:pu:g:vh", opts, NULL)) != -1) {
		switch (c) {
		case 's':
		case OPT_SOCKET_PATH:
			socket_path = optarg;
			break;
		case OPT_FD:
			fd_arg = (int)vu_rng_parse_u64(optarg, "descriptor",
						       INT_MAX, 10);
			break;
		case 'm':
			mode = (mode_t)vu_rng_parse_u64(optarg, "mode", 0777, 8);
			mode_set = true;
			break;
		case OPT_SOCKET_GROUP:
			socket_group = optarg;
			break;
		case 'p':
			vu_rng.pr = true;
			break;
		case OPT_MAX_BYTES:
			max_bytes = vu_rng_parse_u64(optarg, "byte count",
						     UINT32_MAX, 10);
			max_bytes_set = true;
			break;
		case OPT_PERIOD_MS:
			period_ms = vu_rng_parse_u64(optarg, "period",
						     24ULL * 3600 * 1000, 10);
			break;
		case 'u':
			user = optarg;
			break;
		case 'g':
			group = optarg;
			break;
		case OPT_SYSLOG:
			esdm_logger_enable_syslog("esdm-vhost-user-rng");
			break;
		case 'v':
			verbosity++;
			break;
		case OPT_PRINT_CAPS:
			/* The convention of docs/interop/vhost-user.rst */
			printf("{\n  \"type\": \"rng\"\n}\n");
			return EXIT_SUCCESS;
		case OPT_VERSION:
			printf("esdm-vhost-user-rng %s\n", VERSION);
			return EXIT_SUCCESS;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			usage();
			return EXIT_FAILURE;
		}
	}

	if (optind != argc) {
		usage();
		return EXIT_FAILURE;
	}

	/* Errors and warnings are logged in any case, see esdm-server */
	esdm_logger_set_verbosity(verbosity > LOGGER_WARN ?
					  (enum esdm_logger_verbosity)verbosity :
					  LOGGER_WARN);

	/*
	 * Every 32 bytes of the prediction resistant DRNG are a reseed from
	 * the entropy sources, which a guest asking without end would keep
	 * busy at the expense of every other user of the ESDM. So --pr comes
	 * with a limit of 1 KiB per period unless --max_bytes sets one - 0 for
	 * none -, far above what a Linux guest asks for. The fully seeded DRNG
	 * costs the ESDM no more than any local user reading from it, and is
	 * not limited by default.
	 */
	if (vu_rng.pr && !max_bytes_set)
		max_bytes = VU_RNG_PR_MAX_BYTES;

	if (max_bytes && !period_ms) {
		fprintf(stderr,
			"esdm-vhost-user-rng: --period_ms has to be at least 1\n");
		return EXIT_FAILURE;
	}

	vu_rng_stop_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (vu_rng_stop_fd < 0) {
		perror("esdm-vhost-user-rng: eventfd");
		return EXIT_FAILURE;
	}
	vu_rng_install_signals();

	/*
	 * The socket: handed over by systemd, by whoever started the daemon
	 * (--fd), or created here (--socket).
	 */
	systemd_listen_fds_init();
	nlisten = systemd_listen_fds();
	if (nlisten > 0) {
		if (socket_path || fd_arg >= 0 || nlisten != 1) {
			esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
				    "Socket activation hands over %d sockets%s - one, and no --socket or --fd with it\n",
				    nlisten,
				    (socket_path || fd_arg >= 0) ?
					    " and the command line names one" :
					    "");
			return EXIT_FAILURE;
		}
		lfd = SYSTEMD_LISTEN_FDS_START;
		snprintf(where, sizeof(where), "the socket of systemd");
	} else if (fd_arg >= 0) {
		if (socket_path) {
			esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
				    "--fd and --socket exclude each other\n");
			return EXIT_FAILURE;
		}
		lfd = fd_arg;
		snprintf(where, sizeof(where), "descriptor %d", fd_arg);
	} else if (socket_path) {
		if (socket_group) {
			struct group *gr = getgrnam(socket_group);

			if (!gr) {
				esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
					    "Group %s unknown\n", socket_group);
				return EXIT_FAILURE;
			}
			sgid = gr->gr_gid;
			if (!mode_set)
				mode = 0660;
		}

		lfd = vu_rng_listen_path(socket_path, mode, sgid);
		if (lfd < 0) {
			esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
				    "Cannot listen on %s: %s\n", socket_path,
				    strerror(-lfd));
			return EXIT_FAILURE;
		}
		snprintf(where, sizeof(where), "%s", socket_path);
	} else {
		esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
			    "No socket: --socket, --fd or socket activation\n");
		usage();
		return EXIT_FAILURE;
	}

	ret = vu_rng_check_socket(lfd, &listening);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
			    "%s is no Unix stream socket: %s\n", where,
			    strerror(-ret));
		goto out;
	}

	/*
	 * Nothing below needs privileges: the socket is there, the guest
	 * memory and the notifiers are handed over as descriptors, and the
	 * ESDM is reached through its unprivileged interface.
	 */
	if (!geteuid()) {
		ret = drop_privileges_permanent(user ? user : "nobody", group);
		if (ret) {
			esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
				    "Cannot drop privileges: %s\n",
				    strerror(-ret));
			goto out;
		}
	} else if (user || group) {
		esdm_logger(LOGGER_WARN, LOGGER_C_VHOST,
			    "Not started as root - --user and --group are ignored\n");
	}

	vu_rng.buf = vu_rng_buf_alloc();
	if (!vu_rng.buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = vu_dev_init(&vu_rng.dev);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
			    "Cannot set up the device: %s\n", strerror(-ret));
		goto out;
	}
	vu_dev_set_ratelimit(&vu_rng.dev, max_bytes, period_ms);

	/* One worker, one request at a time: one connection to the ESDM */
	esdm_rpcc_set_max_online_nodes(1);
	ret = esdm_rpcc_init_unpriv_service(vu_rng_rpc_interrupt);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
			    "Cannot set up the ESDM RPC client: %s\n",
			    strerror(-ret));
		goto out_dev;
	}

	ret = -pthread_create(&vu_rng.worker, NULL, vu_rng_worker, &vu_rng);
	if (ret) {
		esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
			    "Cannot start the worker: %s\n", strerror(-ret));
		goto out_rpc;
	}
	worker = true;

	esdm_logger(LOGGER_STATUS, LOGGER_C_VHOST,
		    "Serving a virtio entropy device on %s from the %s DRNG of the ESDM%s\n",
		    where, vu_rng.pr ? "prediction resistant" : "fully seeded",
		    max_bytes ? ", rate limited" : "");
	if (max_bytes)
		esdm_logger(LOGGER_STATUS, LOGGER_C_VHOST,
			    "At most %llu bytes per %llu ms\n",
			    (unsigned long long)max_bytes,
			    (unsigned long long)period_ms);

	systemd_notify_ready();
	systemd_notify_status("Waiting for the front-end");

	if (listening) {
		vu_rng_listen_fd = lfd;
		lfd = -1;

		while (!atomic_load(&vu_rng_stopping) && vu_rng_listen_fd >= 0) {
			int fd = vu_rng_accept(vu_rng_listen_fd);

			if (fd < 0) {
				if (fd != -EINTR) {
					esdm_logger(LOGGER_ERR, LOGGER_C_VHOST,
						    "Cannot accept front-ends: %s\n",
						    strerror(-fd));
					ret = fd;
				}
				break;
			}

			systemd_notify_status("Serving the front-end");
			vu_rng_serve_conn(fd);
			systemd_notify_status("Waiting for the front-end");
		}
	} else {
		/* A connected socket serves one front-end, then the daemon ends */
		vu_rng_serve_conn(lfd);
		lfd = -1;
	}

	systemd_notify_stopping();

out_rpc:
	vu_dev_shutdown(&vu_rng.dev);
	if (worker)
		pthread_join(vu_rng.worker, NULL);
	esdm_rpcc_fini_unpriv_service();
out_dev:
	vu_dev_fini(&vu_rng.dev);
out:
	vu_rng_buf_free(vu_rng.buf);
	if (lfd >= 0)
		close(lfd);
	vu_rng_stop_listening();
	close(vu_rng_stop_fd);

	return ret ? EXIT_FAILURE : EXIT_SUCCESS;
}
