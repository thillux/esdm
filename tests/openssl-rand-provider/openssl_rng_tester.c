/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "env.h"

/* The GNU test protocol's hard error, never inverted by should_fail */
#define TEST_SETUP_ERROR 99

static bool test_random(void)
{
	unsigned char bytes[300];
	int ret;

	ret = RAND_bytes(bytes, 300);
	fprintf(stderr, "%i\n", ret);
	if (ret != 1)
		return false;

	EVP_PKEY *pkey = EVP_RSA_gen(4096);
	if (pkey == NULL)
		return false;
	EVP_PKEY_free(pkey);

	return true;
}

static bool test_instantiate(bool prediction_resistance)
{
	const size_t buffer_size = 100;
	unsigned int strength = 256;
	unsigned char bytes[100];
	OSSL_PARAM params[2];
	EVP_RAND_CTX *rctx;
	EVP_RAND *rand;
	int ret;

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
						     "AES-256-CTR", 0);
	params[1] = OSSL_PARAM_construct_end();

	rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
	if (rand == NULL)
		return false;
	rctx = EVP_RAND_CTX_new(rand, NULL);
	if (rctx == NULL) {
		EVP_RAND_free(rand);
		return false;
	}
	EVP_RAND_free(rand);

	ret = EVP_RAND_instantiate(
		rctx, strength, prediction_resistance ? 1 : 0, NULL, 0, params);
	if (ret != 1) {
		EVP_RAND_CTX_free(rctx);
		return false;
	}

	ret = EVP_RAND_generate(rctx, bytes, sizeof(bytes), strength,
				prediction_resistance ? 1 : 0, NULL, 0);
	if (ret != 1) {
		EVP_RAND_CTX_free(rctx);
		return false;
	}

	/* TODO: esdm_rand_nonce did not get called here
	ret = EVP_RAND_nonce(rctx, bytes, buffer_size);
	assert(ret > 0);
	assert(ret <= buffer_size);
	*/

	ret = EVP_RAND_reseed(rctx, prediction_resistance ? 1 : 0, bytes,
			      buffer_size, bytes, buffer_size);
	if (ret != 1) {
		EVP_RAND_CTX_free(rctx);
		return false;
	}

	EVP_RAND_CTX_free(rctx);
	return true;
}

/*
 * Returns EXIT_SUCCESS, EXIT_FAILURE if the test itself failed, or
 * TEST_SETUP_ERROR if it could not be run at all - a provider that does not
 * load must not count as the refusal one of the tests expects.
 */
static int performTest(char *test, char *type)
{
	OSSL_PROVIDER *prov_esdm = NULL;
	OSSL_PROVIDER *prov_default = NULL;
	const char *prov_name;
	int ret = TEST_SETUP_ERROR;

	if (strncmp(type, "rng", strlen("rng")) == 0) {
		prov_name = "libesdm-rng-provider";
	} else if (strncmp(type, "seed-src", strlen("seed-src")) == 0) {
		prov_name = "libesdm-seed-src-provider";
	} else if (strncmp(type, "egd", strlen("egd")) == 0) {
		/*
		 * The EGD provider reaches the ESDM over the EGD protocol
		 * instead of the RPC interface, so it is the one variant that
		 * works without the RPC client library at all - env_init() has
		 * the server serve EGD and points the client at that socket.
		 */
		prov_name = "libesdm-egd-provider";
	} else {
		fprintf(stderr, "Unknown provider type %s\n", type);
		return TEST_SETUP_ERROR;
	}

	prov_esdm = OSSL_PROVIDER_load(NULL, prov_name);
	if (prov_esdm == NULL) {
		fprintf(stderr, "Cannot load %s\n", prov_name);
		return TEST_SETUP_ERROR;
	}
	prov_default = OSSL_PROVIDER_load(NULL, "default");
	if (prov_default == NULL) {
		fprintf(stderr, "Cannot load the default provider\n");
		goto out;
	}

	if (strncmp(test, "random", strlen("random")) == 0) {
		ret = test_random() ? EXIT_SUCCESS : EXIT_FAILURE;
	} else if (strncmp(test, "instantiate_pr", strlen("instantiate_pr")) ==
		   0) {
		ret = test_instantiate(true) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else if (strncmp(test, "instantiate_full",
			   strlen("instantiate_full")) == 0) {
		ret = test_instantiate(false) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		fprintf(stderr, "Unknown test %s\n", test);
	}

out:
	if (prov_default)
		OSSL_PROVIDER_unload(prov_default);
	OSSL_PROVIDER_unload(prov_esdm);
	return ret;
}

int main(int argc, char **argv)
{
	char *provider_search_path;
	char *test;
	char *type;
	int ret;

	assert(argc == 4);
	provider_search_path = argv[1];
	test = argv[2];
	type = argv[3];

	/*
	 * A setup failure is reported as a hard error (99) rather than a plain
	 * failure: meson inverts a failure for a should_fail test, but takes
	 * 99 - like the skip code 77 - at face value. The test expecting the
	 * provider to refuse would otherwise pass without a server.
	 */
	ret = env_init();
	if (ret)
		return ret == 77 ? 77 : TEST_SETUP_ERROR;

	ret = OSSL_PROVIDER_set_default_search_path(NULL, provider_search_path);
	if (ret != 1) {
		env_fini();
		return TEST_SETUP_ERROR;
	}

	ret = performTest(test, type);

	env_fini();
	return ret;
}
