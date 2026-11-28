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

/*
 * The backend of esdm-tool for the RPC interface, see backend.h. Each function
 * is the call of the RPC client library of its name, wrapped in esdm_invoke()
 * to repeat a call that was interrupted.
 */

#include <errno.h>
#include <esdm_rpc_client.h>
#include <esdm_rpc_service.h>

#include "backend.h"

const size_t tool_be_max_data = ESDM_RPC_MAX_DATA;

const char *tool_be_missing(void)
{
	return NULL;
}

void tool_be_usage(void)
{
}

const char *const *tool_be_sockets(void)
{
	static const char *const sockets[] = { ESDM_RPC_UNPRIV_SOCKET,
					       ESDM_RPC_PRIV_SOCKET, NULL };

	return sockets;
}

int tool_be_init(void)
{
	return esdm_rpcc_init_unpriv_service(NULL);
}

void tool_be_fini(void)
{
	esdm_rpcc_fini_unpriv_service();
}

int tool_be_init_priv(void)
{
	return esdm_rpcc_init_priv_service(NULL);
}

void tool_be_fini_priv(void)
{
	esdm_rpcc_fini_priv_service();
}

int tool_be_status(char *buf, size_t buflen)
{
	int ret;

	esdm_invoke(esdm_rpcc_status(buf, buflen));
	return ret;
}

int tool_be_status_json(char *buf, size_t buflen)
{
	int ret;

	esdm_invoke(esdm_rpcc_status_json(buf, buflen));
	return ret;
}

int tool_be_drng_status_json(uint32_t node, char *buf, size_t buflen)
{
	int ret;

	esdm_invoke(esdm_rpcc_drng_status_json(node, buf, buflen));
	return ret;
}

int tool_be_drng_status_pr_json(char *buf, size_t buflen)
{
	int ret;

	esdm_invoke(esdm_rpcc_drng_status_pr_json(buf, buflen));
	return ret;
}

int tool_be_jent_status(char *buf, size_t buflen)
{
	int ret;

	esdm_invoke(esdm_rpcc_jent_status(buf, buflen));
	return ret;
}

int tool_be_is_fully_seeded(bool *fully_seeded)
{
	int ret;

	esdm_invoke(esdm_rpcc_is_fully_seeded(fully_seeded));
	return ret;
}

int tool_be_get_ent_lvl(unsigned int *entlvl)
{
	int ret;

	esdm_invoke(esdm_rpcc_get_ent_lvl(entlvl));
	return ret;
}

int tool_be_rnd_get_ent_cnt(unsigned int *entcnt)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_get_ent_cnt(entcnt));
	return ret;
}

int tool_be_get_min_reseed_secs(unsigned int *seconds)
{
	int ret;

	esdm_invoke(esdm_rpcc_get_min_reseed_secs(seconds));
	return ret;
}

ssize_t tool_be_get_random_bytes(uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes(buf, buflen));
	return ret;
}

ssize_t tool_be_get_random_bytes_full(uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes_full(buf, buflen));
	return ret;
}

ssize_t tool_be_get_random_bytes_full_timeout(uint8_t *buf, size_t buflen,
					      struct timespec *ts)
{
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes_full_timeout(buf, buflen, ts));
	return ret;
}

ssize_t tool_be_get_random_bytes_pr(uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_random_bytes_pr(buf, buflen));
	return ret;
}

ssize_t tool_be_get_seed(uint8_t *buf, size_t buflen, bool fully_seeded)
{
	unsigned int flags = fully_seeded ? ESDM_GET_SEED_FULLY_SEEDED : 0;
	ssize_t ret;

	esdm_invoke(esdm_rpcc_get_seed(buf, buflen, flags));
	return ret;
}

int tool_be_rnd_add_entropy(const uint8_t *entropy_buf, size_t entropy_buf_len,
			    uint32_t entropy_cnt)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_add_entropy(entropy_buf, entropy_buf_len,
					      entropy_cnt));
	return ret;
}

int tool_be_rnd_clear_pool(void)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_clear_pool());
	return ret;
}

int tool_be_rnd_reseed_crng(void)
{
	int ret;

	esdm_invoke(esdm_rpcc_rnd_reseed_crng());
	return ret;
}

int tool_be_set_min_reseed_secs(unsigned int seconds)
{
	int ret;

	esdm_invoke(esdm_rpcc_set_min_reseed_secs(seconds));
	return ret;
}

int tool_be_set_es_rate(const char *es, uint32_t rate)
{
	int ret;

	esdm_invoke(esdm_rpcc_set_es_rate(es, rate));
	return ret;
}

static enum tool_be_selftest_state
tool_be_selftest_state(enum esdm_rpcc_selftest_state state)
{
	switch (state) {
	case esdm_rpcc_selftest_undone:
		return tool_be_selftest_undone;
	case esdm_rpcc_selftest_passed:
		return tool_be_selftest_passed;
	case esdm_rpcc_selftest_failed:
		return tool_be_selftest_failed;
	}

	/* As the tool names a state it does not know: none of the three */
	return (enum tool_be_selftest_state)state;
}

int tool_be_selftest(struct tool_be_selftest_result *result)
{
	struct esdm_rpcc_selftest_result rpc_result;
	int ret;

	esdm_invoke(esdm_rpcc_selftest(&rpc_result));

	result->crypto_state = tool_be_selftest_state(rpc_result.crypto_state);
	result->es_state = tool_be_selftest_state(rpc_result.es_state);
	result->es_sources = rpc_result.es_sources;
	result->es_failures = rpc_result.es_failures;

	return ret;
}
