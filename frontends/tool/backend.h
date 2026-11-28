/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ESDM_TOOL_BACKEND_H
#define ESDM_TOOL_BACKEND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

/*
 * The interface of the esdm-server the tool works over. The commands of the
 * tool call the functions below, and one backend implements them:
 *
 * backend_rpc.c	the RPC interface through libesdm_rpc_client - every
 *			function is the esdm_rpcc_*() call of its name, repeated
 *			where that call was interrupted
 * backend_egd.c	the EGD interface through libesdm_egd_client, in a build
 *			without the RPC interface - what the EGD protocol with
 *			the extensions of the ESDM can express
 *
 * They return what the RPC client library returns: 0 or the number of bytes on
 * success, a negative errno otherwise.
 */

/* Size of the largest status report and the largest request for random data */
extern const size_t tool_be_max_data;

/*
 * What the commands the backend cannot carry out need and the build lacks, or
 * NULL for a backend that carries out every command. With it set, the functions
 * marked "may be missing" below return -EOPNOTSUPP.
 */
const char *tool_be_missing(void);

/* Backend specific part of the usage */
void tool_be_usage(void);

/*
 * The socket files of the server, NULL terminated: the server does not run
 * where one of them does not exist.
 */
const char *const *tool_be_sockets(void);

/* The connection of the unprivileged commands, once per process */
int tool_be_init(void);
void tool_be_fini(void);

/* The connection of the privileged commands, around each of them */
int tool_be_init_priv(void);
void tool_be_fini_priv(void);

int tool_be_status(char *buf, size_t buflen);
int tool_be_status_json(char *buf, size_t buflen);
int tool_be_is_fully_seeded(bool *fully_seeded);
int tool_be_get_ent_lvl(unsigned int *entlvl);
int tool_be_rnd_get_ent_cnt(unsigned int *entcnt);
int tool_be_get_min_reseed_secs(unsigned int *seconds);

ssize_t tool_be_get_random_bytes(uint8_t *buf, size_t buflen);
ssize_t tool_be_get_random_bytes_full(uint8_t *buf, size_t buflen);
ssize_t tool_be_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
					      struct timespec *ts);
ssize_t tool_be_get_random_bytes_pr(uint8_t *buf, size_t buflen);

/* Privileged */
int tool_be_rnd_add_entropy(const uint8_t *entropy_buf, size_t entropy_buf_len,
			    uint32_t entropy_cnt);
int tool_be_rnd_clear_pool(void);
int tool_be_rnd_reseed_crng(void);
int tool_be_set_min_reseed_secs(unsigned int seconds);

/* May be missing */
ssize_t tool_be_get_seed(uint8_t *buf, size_t buflen, bool fully_seeded);
int tool_be_drng_status_json(uint32_t node, char *buf, size_t buflen);
int tool_be_drng_status_pr_json(char *buf, size_t buflen);
int tool_be_jent_status(char *buf, size_t buflen);

/* May be missing, privileged */
int tool_be_set_es_rate(const char *es, uint32_t rate);

enum tool_be_selftest_state {
	tool_be_selftest_undone = 0,
	tool_be_selftest_passed = 1,
	tool_be_selftest_failed = 2,
};

struct tool_be_selftest_result {
	enum tool_be_selftest_state crypto_state;
	enum tool_be_selftest_state es_state;
	uint32_t es_sources;
	uint32_t es_failures;
};

int tool_be_selftest(struct tool_be_selftest_result *result);

#endif /* ESDM_TOOL_BACKEND_H */
