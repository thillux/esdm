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
 * Throughput of the unprivileged RPC interface, by the calls a consumer makes:
 * esdm_rpcc_get_random_bytes_full(), _pr() and the unseeded
 * esdm_rpcc_get_random_bytes(), getrandom(2) as libesdm-getrandom answers it,
 * and the getrandom(2) of the kernel as the baseline. Each in requests of the
 * sizes consumers ask for, from 1, 4 and 16 threads, and from several
 * processes at once.
 *
 * Informational: it measures, it does not judge. Every figure is the median
 * of several runs of a fixed time over all threads of all processes, next to
 * the slowest and the fastest run - the machine it runs on may be busy with
 * anything else. That makes the throughput vary with what else runs, so every
 * figure comes with the CPU time a request took as well, in the processes of
 * the bench and - for a server it started - in the esdm-server: what a change
 * of either saves shows there even on a busy machine. Next to it, the
 * connections a process of the bench held, and those the server held. A
 * second line has the latency of a request as its caller sees it, the median
 * and the 99th percentile of all requests of a run, and the requests per
 * second: the mean over the runs and their standard deviation.
 *
 * Each figure is taken by processes of its own, forked for it: a process sets
 * up its connections to the ESDM - and its DTLS - with one request of every
 * thread before the first run, as a long running consumer has them, and keeps
 * them over the runs. The processes wait for the start of each run, so that
 * all of them read at the same time.
 *
 * Registered as a benchmark: meson test --benchmark, which starts the
 * esdm-server named by ESDM_SERVER as the tests next to it do - taking root,
 * in namespaces of its own -, but without their debug logging, which would be
 * what is measured. Started by hand with -x, it measures the esdm-server that
 * serves the RPC socket already, which is what a profiler attached to that
 * server wants.
 *
 *	rpc_bench [-x] [-v] [-S server option] [-s sizes] [-t threads]
 *		  [-p processes] [-r runs] [-m ms] [path ...]
 *
 * The lists are comma separated. -S hands an option to the server it starts,
 * e.g. --no_dtls or --no_io_uring, and may be repeated. -v prints every run of
 * a figure as well, for figures to be put together from several invocations
 * - to compare two servers in turns, say. The paths are full, pr, unseeded,
 * getrandom and kernel; all but pr are taken without any - see bench_paths.
 * The getrandom(2) of libesdm-getrandom is looked up in the library named by
 * ESDM_GETRANDOM_LIB, and skipped without it.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "esdm_rpc_client.h"
#include "esdm_rpc_service.h"
#include "../test_env.h"
#include "../test_namespace.h"
#include "../test_wait.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define BENCH_MAX_LIST 16
#define BENCH_MAX_THREADS 256
#define BENCH_MAX_SERVER_ARGS 16

/* The options -S hands to the esdm-server */
static char *bench_server_args[BENCH_MAX_SERVER_ARGS];
static unsigned int bench_nserver_args;

typedef ssize_t (*bench_getrandom_t)(void *buf, size_t len, unsigned int flags);

/* getrandom(2) of libesdm-getrandom, see bench_getrandom() */
static bench_getrandom_t bench_esdm_getrandom;

/* One request of @len bytes into @buf: the bytes obtained, or a -errno */
typedef ssize_t (*bench_fn)(uint8_t *buf, size_t len);

static ssize_t bench_full(uint8_t *buf, size_t len)
{
	return esdm_rpcc_get_random_bytes_full(buf, len);
}

static ssize_t bench_pr(uint8_t *buf, size_t len)
{
	return esdm_rpcc_get_random_bytes_pr(buf, len);
}

static ssize_t bench_unseeded(uint8_t *buf, size_t len)
{
	return esdm_rpcc_get_random_bytes(buf, len);
}

/* getrandom(2) answers at most 32 MiB - 1 at a time, a short read is fine */
static ssize_t bench_getrandom(uint8_t *buf, size_t len)
{
	ssize_t ret = bench_esdm_getrandom(buf, len, 0);

	return ret < 0 ? -errno : ret;
}

static ssize_t bench_kernel(uint8_t *buf, size_t len)
{
	ssize_t ret = syscall(SYS_getrandom, buf, len, 0);

	return ret < 0 ? -errno : ret;
}

static const struct bench_path {
	const char *name;
	bench_fn fn;
	/* Does it speak to the ESDM through the RPC client itself? */
	bool rpc;
	/* Taken without a path given - see below */
	bool dflt;
	/* The largest request of the default sizes it is measured with */
	size_t max_default_size;
} bench_paths[] = {
	{ "full", bench_full, true, true, SIZE_MAX },
	/*
	 * Not by default: every 32 bytes collect a seed from the entropy
	 * sources, one request at a time for the whole ESDM, and a caller that
	 * finds the PR DRNG busy waits a second before it asks again. Sizes
	 * beyond 4 KiB take longer than a run.
	 */
	{ "pr", bench_pr, true, false, 4096 },
	{ "unseeded", bench_unseeded, true, true, SIZE_MAX },
	{ "getrandom", bench_getrandom, false, true, SIZE_MAX },
	{ "kernel", bench_kernel, false, true, SIZE_MAX },
};

static size_t bench_sizes[BENCH_MAX_LIST] = { 32, 256, 4096, 65536, 1048576 };
static unsigned int bench_nsizes = 5;
static bool bench_sizes_given = false;
static size_t bench_threads[BENCH_MAX_LIST] = { 1, 4, 16 };
static unsigned int bench_nthreads = 3;
static size_t bench_procs[BENCH_MAX_LIST] = { 1, 4 };
static unsigned int bench_nprocs = 2;
static unsigned int bench_runs = 5;
static unsigned int bench_run_ms = 400;
/* Print every run, see -v */
static bool bench_verbose = false;

static uint64_t bench_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * The latencies of the requests of a run, in a histogram of nanoseconds: the
 * values below BENCH_LAT_SUB each in a bucket of their own, above in
 * BENCH_LAT_SUB buckets per power of two - some 3% wide -, up to 2^40 ns.
 */
#define BENCH_LAT_SUB_BITS 5
#define BENCH_LAT_SUB (1U << BENCH_LAT_SUB_BITS)
#define BENCH_LAT_MAX_BITS 40
#define BENCH_LAT_BUCKETS                                                      \
	((BENCH_LAT_MAX_BITS - BENCH_LAT_SUB_BITS + 1) * BENCH_LAT_SUB)

static unsigned int bench_lat_bucket(uint64_t ns)
{
	unsigned int msb;

	if (ns < BENCH_LAT_SUB)
		return (unsigned int)ns;

	msb = 63U - (unsigned int)__builtin_clzll(ns);
	if (msb >= BENCH_LAT_MAX_BITS)
		return BENCH_LAT_BUCKETS - 1;

	return (msb - BENCH_LAT_SUB_BITS + 1) * BENCH_LAT_SUB +
	       (unsigned int)(ns >> (msb - BENCH_LAT_SUB_BITS)) - BENCH_LAT_SUB;
}

/* The middle of bucket @i in nanoseconds */
static double bench_lat_value(unsigned int i)
{
	unsigned int group = i / BENCH_LAT_SUB;

	if (!group)
		return (double)i;

	return ((double)(BENCH_LAT_SUB + i % BENCH_LAT_SUB) + 0.5) *
	       (double)(1ULL << (group - 1));
}

/* The latency at quantile @q of histogram @lat, in microseconds */
static double bench_lat_quantile(const uint64_t *lat, double q)
{
	uint64_t total = 0, sum = 0, rank;
	unsigned int i;

	for (i = 0; i < BENCH_LAT_BUCKETS; i++)
		total += lat[i];
	if (!total)
		return 0;

	rank = (uint64_t)(q * (double)total);
	if (rank >= total)
		rank = total - 1;

	for (i = 0; i < BENCH_LAT_BUCKETS; i++) {
		sum += lat[i];
		if (sum > rank)
			break;
	}

	return bench_lat_value(i) / 1000.0;
}

/* What a process reports of a run */
struct bench_result {
	uint64_t bytes;
	uint64_t requests;
	/* When its last request returned, CLOCK_MONOTONIC */
	uint64_t end_ns;
	/* CPU time the process spent in the run */
	uint64_t cpu_ns;
	/* Sockets the process holds - its connections to the ESDM */
	uint64_t sockets;
	/* A request failed: its -errno */
	int64_t error;
	/* The latencies of its requests, see bench_lat_bucket() */
	uint64_t lat[BENCH_LAT_BUCKETS];
};

/* The esdm-server the bench started, 0 for none */
static pid_t bench_server_pid;

/* Sockets of process @pid - 0 for the calling one */
static unsigned int bench_sockets(pid_t pid)
{
	char path[64];
	struct dirent *de;
	unsigned int n = 0;
	DIR *dir;

	if (pid)
		snprintf(path, sizeof(path), "/proc/%d/fd", (int)pid);
	else
		snprintf(path, sizeof(path), "/proc/self/fd");
	dir = opendir(path);
	if (!dir)
		return 0;
	while ((de = readdir(dir))) {
		char fd[64 + sizeof(de->d_name)], target[64];
		ssize_t len;

		if (de->d_name[0] == '.')
			continue;
		snprintf(fd, sizeof(fd), "%s/%s", path, de->d_name);
		len = readlink(fd, target, sizeof(target) - 1);
		if (len <= 0)
			continue;
		target[len] = '\0';
		if (!strncmp(target, "socket:", 7))
			n++;
	}
	closedir(dir);
	return n;
}

/*
 * CPU time of all threads of process @pid - 0 for the calling one - in
 * nanoseconds, as the scheduler accounts it.
 */
static uint64_t bench_cpu_ns(pid_t pid)
{
	char path[64];
	struct dirent *de;
	uint64_t sum = 0;
	DIR *dir;

	if (pid)
		snprintf(path, sizeof(path), "/proc/%d/task", (int)pid);
	else
		snprintf(path, sizeof(path), "/proc/self/task");
	dir = opendir(path);
	if (!dir)
		return 0;
	while ((de = readdir(dir))) {
		char stat[64 + sizeof(de->d_name) + 16];
		unsigned long long ns;
		FILE *fp;

		if (de->d_name[0] == '.')
			continue;
		snprintf(stat, sizeof(stat), "%s/%s/schedstat", path,
			 de->d_name);
		fp = fopen(stat, "r");
		if (!fp)
			continue;
		if (fscanf(fp, "%llu", &ns) == 1)
			sum += ns;
		fclose(fp);
	}
	closedir(dir);
	return sum;
}

/* A run as the processes are told about it */
struct bench_go {
	uint64_t start_ns;
	uint64_t end_ns;
	/* No run, the process is to leave */
	uint32_t quit;
};

struct bench_thread {
	pthread_t thread;
	const struct bench_path *path;
	size_t len;
	pthread_barrier_t *start, *done;
	const struct bench_go *go;
	struct bench_result result;
};

static void *bench_thread_main(void *arg)
{
	struct bench_thread *t = arg;
	uint8_t *buf = malloc(t->len);
	uint64_t prev = 0;
	ssize_t ret;

	if (!buf) {
		t->result.error = -ENOMEM;
		pthread_barrier_wait(t->start);
		return NULL;
	}

	/* The connection, its DTLS and the DRNG are there before the runs */
	ret = t->path->fn(buf, t->len);
	if (ret < 0) {
		t->result.error = ret;
		printf("The first request of a thread failed: %s\n",
		       strerror((int)-ret));
	}
	pthread_barrier_wait(t->start);

	for (;;) {
		struct bench_result *r = &t->result;

		/* The start of the next run, or of none */
		pthread_barrier_wait(t->start);
		if (t->go->quit)
			break;

		r->bytes = r->requests = 0;
		memset(r->lat, 0, sizeof(r->lat));
		while (!r->error && (prev = bench_now_ns()) < t->go->start_ns)
			;
		while (!r->error) {
			uint64_t now;

			ret = t->path->fn(buf, t->len);
			if (ret < 0) {
				r->error = ret;
				printf("A request failed after %llu of the run: %s\n",
				       (unsigned long long)r->requests,
				       strerror((int)-ret));
				break;
			}
			r->bytes += (uint64_t)ret;
			r->requests++;
			/* The requests follow each other, one starts as the last ended */
			now = bench_now_ns();
			r->lat[bench_lat_bucket(now - prev)]++;
			prev = now;
			if (now >= t->go->end_ns) {
				r->end_ns = now;
				break;
			}
		}
		pthread_barrier_wait(t->done);
	}

	memset(buf, 0, t->len);
	free(buf);
	return NULL;
}

static int bench_read_full(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len) {
		ssize_t n = read(fd, p, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -EIO;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int bench_write_full(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;

	while (len) {
		ssize_t n = write(fd, p, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return -EIO;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

/*
 * A process of a figure: @nthreads threads of requests on @path, run after run
 * as the parent says on @go_fd, each run's sum reported on @res_fd.
 */
static int bench_process(const struct bench_path *path, size_t len,
			 size_t nthreads, int go_fd, int res_fd)
{
	struct bench_thread *threads = calloc(nthreads, sizeof(*threads));
	pthread_barrier_t start, done;
	struct bench_go go = { 0 };
	struct bench_result sum;
	bool rpc_init = false;
	size_t i;
	int ret = 0;

	if (!threads)
		return 1;

	if (path->rpc) {
		if (esdm_rpcc_init_unpriv_service(NULL))
			return 1;
		rpc_init = true;
	}

	pthread_barrier_init(&start, NULL, (unsigned int)nthreads + 1);
	pthread_barrier_init(&done, NULL, (unsigned int)nthreads + 1);

	for (i = 0; i < nthreads; i++) {
		threads[i].path = path;
		threads[i].len = len;
		threads[i].start = &start;
		threads[i].done = &done;
		threads[i].go = &go;
		if (pthread_create(&threads[i].thread, NULL, bench_thread_main,
				   &threads[i]))
			return 1;
	}

	/* The warm-up requests are done */
	pthread_barrier_wait(&start);
	memset(&sum, 0, sizeof(sum));
	for (i = 0; i < nthreads; i++) {
		if (threads[i].result.error)
			sum.error = threads[i].result.error;
	}
	if (bench_write_full(res_fd, &sum, sizeof(sum)))
		ret = 1;

	for (;;) {
		uint64_t cpu;

		if (bench_read_full(go_fd, &go, sizeof(go)))
			go.quit = 1;
		cpu = bench_cpu_ns(0);
		pthread_barrier_wait(&start);
		if (go.quit)
			break;
		pthread_barrier_wait(&done);

		memset(&sum, 0, sizeof(sum));
		sum.cpu_ns = bench_cpu_ns(0) - cpu;
		sum.sockets = bench_sockets(0);
		for (i = 0; i < nthreads; i++) {
			struct bench_result *r = &threads[i].result;
			unsigned int b;

			sum.bytes += r->bytes;
			sum.requests += r->requests;
			if (r->end_ns > sum.end_ns)
				sum.end_ns = r->end_ns;
			if (r->error)
				sum.error = r->error;
			for (b = 0; b < BENCH_LAT_BUCKETS; b++)
				sum.lat[b] += r->lat[b];
		}
		if (bench_write_full(res_fd, &sum, sizeof(sum)))
			ret = 1;
	}

	for (i = 0; i < nthreads; i++)
		pthread_join(threads[i].thread, NULL);
	free(threads);

	if (rpc_init)
		esdm_rpcc_fini_unpriv_service();

	return ret;
}

static int bench_cmp(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

/* Mean and sample standard deviation of @n values */
static void bench_mean_sd(const double *v, unsigned int n, double *mean,
			  double *sd)
{
	double sum = 0, sq = 0;
	unsigned int i;

	for (i = 0; i < n; i++)
		sum += v[i];
	*mean = sum / n;

	for (i = 0; i < n; i++)
		sq += (v[i] - *mean) * (v[i] - *mean);
	*sd = n > 1 ? sqrt(sq / (n - 1)) : 0;
}

static unsigned int failures = 0;

/* One figure: @path with requests of @len from @nprocs x @nthreads */
static void bench(const struct bench_path *path, size_t len, size_t nprocs,
		  size_t nthreads)
{
	double mbs[64], reqs[64], cli_us[64], srv_us[64], p50[64], p99[64];
	double reqs_mean, reqs_sd, p50_mean, p50_sd, p99_mean, p99_sd;
	uint64_t lat[BENCH_LAT_BUCKETS];
	unsigned int max_sockets = 0, srv_sockets = 0;
	pid_t pids[BENCH_MAX_THREADS];
	int go_fd[BENCH_MAX_THREADS], res_fd[BENCH_MAX_THREADS];
	unsigned int run, ok_runs = 0;
	int64_t error = 0;
	size_t p, started = 0;

	for (p = 0; p < nprocs; p++) {
		int go[2], res[2];

		if (pipe(go) || pipe(res))
			goto out;

		pids[p] = fork();
		if (pids[p] < 0) {
			close(go[0]);
			close(go[1]);
			close(res[0]);
			close(res[1]);
			goto out;
		}
		if (!pids[p]) {
			size_t q;

			/* Only its own ends of the pipes */
			for (q = 0; q < started; q++) {
				close(go_fd[q]);
				close(res_fd[q]);
			}
			close(go[1]);
			close(res[0]);
			_exit(bench_process(path, len, nthreads, go[0],
					    res[1]));
		}
		close(go[0]);
		close(res[1]);
		go_fd[p] = go[1];
		res_fd[p] = res[0];
		started++;
	}

	/* The warm-up of every process */
	for (p = 0; p < started; p++) {
		struct bench_result r;

		if (bench_read_full(res_fd[p], &r, sizeof(r))) {
			error = -EIO;
			printf("Process %zu of the figure ended before its first request\n",
			       p);
		} else if (r.error) {
			error = r.error;
		}
	}
	if (error)
		goto out;

	for (run = 0; run < bench_runs && run < ARRAY_SIZE(mbs); run++) {
		struct bench_go go = { 0 };
		uint64_t bytes = 0, requests = 0, end = 0, cli_cpu = 0;
		uint64_t srv_cpu = bench_server_pid ?
					   bench_cpu_ns(bench_server_pid) :
					   0;

		/* A moment for the processes to get from their last report */
		go.start_ns = bench_now_ns() + 2000000ULL;
		go.end_ns = go.start_ns + (uint64_t)bench_run_ms * 1000000ULL;

		for (p = 0; p < started; p++) {
			if (bench_write_full(go_fd[p], &go, sizeof(go))) {
				error = -EIO;
				printf("Process %zu of the figure is gone\n", p);
			}
		}
		memset(lat, 0, sizeof(lat));
		for (p = 0; p < started; p++) {
			struct bench_result r;
			unsigned int b;

			if (bench_read_full(res_fd[p], &r, sizeof(r))) {
				error = -EIO;
				printf("Process %zu of the figure ended without its result\n",
				       p);
				continue;
			}
			if (r.error)
				error = r.error;
			bytes += r.bytes;
			requests += r.requests;
			cli_cpu += r.cpu_ns;
			if (r.sockets > max_sockets)
				max_sockets = (unsigned int)r.sockets;
			if (r.end_ns > end)
				end = r.end_ns;
			for (b = 0; b < BENCH_LAT_BUCKETS; b++)
				lat[b] += r.lat[b];
		}
		if (error)
			break;
		if (bench_server_pid) {
			unsigned int n = bench_sockets(bench_server_pid);

			srv_cpu = bench_cpu_ns(bench_server_pid) - srv_cpu;
			if (n > srv_sockets)
				srv_sockets = n;
		}
		if (!requests)
			requests = 1;
		cli_us[ok_runs] = (double)cli_cpu / 1000.0 / (double)requests;
		srv_us[ok_runs] = (double)srv_cpu / 1000.0 / (double)requests;

		mbs[ok_runs] = (double)bytes /
			       ((double)(end - go.start_ns) / 1e9) / 1e6;
		reqs[ok_runs] = (double)requests /
				((double)(end - go.start_ns) / 1e9);
		p50[ok_runs] = bench_lat_quantile(lat, 0.50);
		p99[ok_runs] = bench_lat_quantile(lat, 0.99);
		if (bench_verbose)
			printf("run %-6s %8zu %3zux%-3zu %11.0f req/s  latency p50 %.2f us p99 %.2f us  cpu/req server %.2f us\n",
			       path->name, len, nprocs, nthreads,
			       reqs[ok_runs], p50[ok_runs], p99[ok_runs],
			       srv_us[ok_runs]);
		ok_runs++;
	}

out:
	for (p = 0; p < started; p++) {
		/* EOF on the go pipe is the end */
		close(go_fd[p]);
		close(res_fd[p]);
		waitpid(pids[p], NULL, 0);
	}

	if (error || !ok_runs || started < nprocs) {
		printf("%-10s %8zu %3zux%-3zu  failed: %s\n", path->name, len,
		       nprocs, nthreads,
		       error ? strerror((int)-error) : "cannot start");
		failures++;
		return;
	}

	/* Before the sorting, which takes the values apart from their runs */
	bench_mean_sd(reqs, ok_runs, &reqs_mean, &reqs_sd);
	bench_mean_sd(p50, ok_runs, &p50_mean, &p50_sd);
	bench_mean_sd(p99, ok_runs, &p99_mean, &p99_sd);

	qsort(mbs, ok_runs, sizeof(mbs[0]), bench_cmp);
	qsort(reqs, ok_runs, sizeof(reqs[0]), bench_cmp);
	qsort(cli_us, ok_runs, sizeof(cli_us[0]), bench_cmp);
	qsort(srv_us, ok_runs, sizeof(srv_us[0]), bench_cmp);
	printf("%-10s %8zu %3zux%-3zu %10.2f MB/s %11.0f req/s  (%.2f .. %.2f)  cpu/req client %.2f us server %.2f us  sockets/process %u server %u\n",
	       path->name, len, nprocs, nthreads, mbs[ok_runs / 2],
	       reqs[ok_runs / 2], mbs[0], mbs[ok_runs - 1],
	       cli_us[ok_runs / 2], srv_us[ok_runs / 2], max_sockets,
	       srv_sockets);
	/*
	 * The latency of a request, as its caller sees it, over the runs: the
	 * mean of their medians and 99th percentiles, and the spread of them.
	 */
	printf("%-10s %8zu %3zux%-3zu %11.0f req/s sd %.0f  latency p50 %.2f us sd %.2f  p99 %.2f us sd %.2f  (mean of %u runs)\n",
	       path->name, len, nprocs, nthreads, reqs_mean, reqs_sd, p50_mean,
	       p50_sd, p99_mean, p99_sd, ok_runs);
}

/* A comma separated list of numbers into @list, at most BENCH_MAX_LIST */
static int bench_parse_list(const char *arg, size_t *list, unsigned int *n)
{
	char *copy = strdup(arg), *tok, *save = NULL;
	unsigned int i = 0;

	if (!copy)
		return -ENOMEM;

	for (tok = strtok_r(copy, ",", &save); tok;
	     tok = strtok_r(NULL, ",", &save)) {
		char *end;
		unsigned long long v = strtoull(tok, &end, 0);

		if (*end || !v || i >= BENCH_MAX_LIST) {
			free(copy);
			return -EINVAL;
		}
		list[i++] = (size_t)v;
	}
	free(copy);
	if (!i)
		return -EINVAL;
	*n = i;
	return 0;
}

/*
 * Start the esdm-server of ESDM_SERVER in namespaces of this process' own, as
 * tests/rpc_client/env.c does, but without its debug logging. Returns its PID,
 * or a -errno.
 */
static pid_t bench_server_start(void)
{
	const char *server = getenv("ESDM_SERVER");
	char *envp[TEST_ENV_MAX_VARS + 1];
	char *argv[BENCH_MAX_SERVER_ARGS + 3];
	unsigned int i;
	pid_t pid;
	int ret;

	if (getuid()) {
		printf("Program must be started as root\n");
		return -77;
	}

	ret = test_env_check_file(server);
	if (ret)
		return -ret;

	ret = test_isolate_namespaces();
	if (ret) {
		printf("Cannot isolate the test namespaces: %s\n",
		       strerror(-ret));
		return ret;
	}

	/*
	 * In the foreground, which the verbose logging of the tests implies:
	 * the daemon would otherwise outlive the bench.
	 */
	argv[0] = (char *)server;
	argv[1] = "-f";
	for (i = 0; i < bench_nserver_args; i++)
		argv[i + 2] = bench_server_args[i];
	argv[i + 2] = NULL;

	/* Built before the fork - see test_env_daemon_envp() */
	test_env_daemon_envp(envp, TEST_ENV_MAX_VARS + 1);

	pid = fork();
	if (pid < 0)
		return -errno;
	if (!pid) {
		execve(server, argv, envp);
		_exit(1);
	}

	if (!test_wait_for_type(ESDM_RPC_UNPRIV_SOCKET, S_IFSOCK,
				TEST_WAIT_TIMEOUT_MS)) {
		printf("The esdm-server did not start\n");
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
		return -ETIMEDOUT;
	}

	return pid;
}

/* Does the DRNG status @json say "fully_seeded": true? */
static bool bench_json_seeded(const char *json)
{
	const char *p = strstr(json, "\"fully_seeded\"");

	if (!p)
		return false;
	p += strlen("\"fully_seeded\"");
	while (*p == ' ' || *p == ':')
		p++;
	return !strncmp(p, "true", 4);
}

/*
 * Wait until the DRNG of every node is fully seeded, at most @max_ms. The
 * reseed worker brings them up one per pass after the start, and what is
 * measured before that is a server serving every request from the few that
 * are there yet - and collecting from the entropy sources for the others
 * meanwhile. Returns the milliseconds it took, or -1 if they were not seeded
 * in time.
 */
static long bench_wait_seeded(unsigned int max_ms)
{
	uint64_t start = bench_now_ns();
	struct timespec pause = { .tv_sec = 0, .tv_nsec = 50000000L };
	char buf[4096];

	if (esdm_rpcc_init_unpriv_service(NULL))
		return -1;

	for (;;) {
		uint32_t node;
		bool all = true;
		int ret;

		for (node = 0;; node++) {
			ret = esdm_rpcc_drng_status_json(node, buf,
							 sizeof(buf));
			if (ret == -ENODEV)
				break;
			/* A server without the JSON status cannot tell */
			if (ret) {
				esdm_rpcc_fini_unpriv_service();
				return -1;
			}
			if (!bench_json_seeded(buf)) {
				all = false;
				break;
			}
		}
		/* No node answered at all: the server is not up yet */
		if (all && node)
			break;

		if (bench_now_ns() - start >= (uint64_t)max_ms * 1000000ULL) {
			esdm_rpcc_fini_unpriv_service();
			return -1;
		}
		nanosleep(&pause, NULL);
	}

	esdm_rpcc_fini_unpriv_service();
	return (long)((bench_now_ns() - start) / 1000000ULL);
}

static void bench_usage(const char *name)
{
	fprintf(stderr,
		"Usage: %s [-x] [-v] [-S server option] [-s sizes] [-t threads] [-p processes] [-r runs] [-m ms] [path ...]\n"
		"\tpaths: full pr unseeded getrandom kernel\n"
		"\t-x: use the esdm-server running already\n"
		"\t-v: print every run\n",
		name);
}

int main(int argc, char *argv[])
{
	bool external = false, selected[ARRAY_SIZE(bench_paths)];
	const char *lib;
	unsigned int i, s, p, t;
	pid_t server = 0;
	int opt;

	setvbuf(stdout, NULL, _IOLBF, 0);

	while ((opt = getopt(argc, argv, "xvS:s:t:p:r:m:h")) != -1) {
		switch (opt) {
		case 'x':
			external = true;
			break;
		case 'v':
			bench_verbose = true;
			break;
		case 'S':
			if (bench_nserver_args >= BENCH_MAX_SERVER_ARGS)
				goto usage;
			bench_server_args[bench_nserver_args++] = optarg;
			break;
		case 's':
			if (bench_parse_list(optarg, bench_sizes,
					     &bench_nsizes))
				goto usage;
			bench_sizes_given = true;
			break;
		case 't':
			if (bench_parse_list(optarg, bench_threads,
					     &bench_nthreads))
				goto usage;
			break;
		case 'p':
			if (bench_parse_list(optarg, bench_procs,
					     &bench_nprocs))
				goto usage;
			break;
		case 'r':
			bench_runs = (unsigned int)strtoul(optarg, NULL, 0);
			if (!bench_runs || bench_runs > 64)
				goto usage;
			break;
		case 'm':
			bench_run_ms = (unsigned int)strtoul(optarg, NULL, 0);
			if (!bench_run_ms)
				goto usage;
			break;
		default:
			goto usage;
		}
	}

	for (i = 0; i < ARRAY_SIZE(bench_paths); i++)
		selected[i] = optind >= argc && bench_paths[i].dflt;
	for (; optind < argc; optind++) {
		for (i = 0; i < ARRAY_SIZE(bench_paths); i++) {
			if (!strcmp(argv[optind], bench_paths[i].name))
				break;
		}
		if (i == ARRAY_SIZE(bench_paths))
			goto usage;
		selected[i] = true;
	}

	for (p = 0; p < bench_nprocs; p++) {
		for (t = 0; t < bench_nthreads; t++) {
			if (bench_procs[p] > BENCH_MAX_THREADS ||
			    bench_threads[t] > BENCH_MAX_THREADS)
				goto usage;
		}
	}

	/* The path of libesdm-getrandom, its getrandom(2) only */
	lib = getenv("ESDM_GETRANDOM_LIB");
	if (lib) {
		void *h = dlopen(lib, RTLD_NOW | RTLD_LOCAL);

		/* The POSIX way around the cast ISO C forbids */
		if (h)
			*(void **)(&bench_esdm_getrandom) =
				dlsym(h, "getrandom");
		if (!bench_esdm_getrandom)
			printf("No getrandom in %s: %s\n", lib, dlerror());
	}

	if (!external) {
		long ms;

		server = bench_server_start();
		if (server < 0)
			return server == -77 ? 77 : 1;
		bench_server_pid = server;

		ms = bench_wait_seeded(300000);
		if (ms < 0)
			printf("Not every DRNG is fully seeded, measuring anyway\n");
		else
			printf("Every DRNG fully seeded %ld ms after the start\n",
			       ms);
	}

	printf("%-10s %8s %7s %15s %17s  %s\n", "path", "bytes", "procs",
	       "median", "", "(slowest .. fastest MB/s)");

	for (i = 0; i < ARRAY_SIZE(bench_paths); i++) {
		const struct bench_path *path = &bench_paths[i];

		if (!selected[i])
			continue;
		if (path->fn == bench_getrandom && !bench_esdm_getrandom) {
			printf("%-10s skipped, ESDM_GETRANDOM_LIB not usable\n",
			       path->name);
			continue;
		}

		for (s = 0; s < bench_nsizes; s++) {
			if (!bench_sizes_given &&
			    bench_sizes[s] > path->max_default_size)
				continue;
			for (p = 0; p < bench_nprocs; p++) {
				for (t = 0; t < bench_nthreads; t++)
					bench(path, bench_sizes[s],
					      bench_procs[p], bench_threads[t]);
			}
		}
	}

	if (server > 0) {
		kill(server, SIGTERM);
		waitpid(server, NULL, 0);
	}

	return failures ? 1 : 0;

usage:
	bench_usage(argv[0]);
	return 1;
}
