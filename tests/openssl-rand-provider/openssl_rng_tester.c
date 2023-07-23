#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "env.h"

static void test_random() {
    unsigned char bytes[300];
    int ret = RAND_bytes(bytes, 300);
    fprintf(stderr, "%i\n", ret);
    assert(ret == 1);

    EVP_PKEY *pkey = EVP_RSA_gen(4096);
    assert(pkey != NULL);
    EVP_PKEY_free(pkey);
}

static void test_instantiate(bool prediction_resistance)
{
    EVP_RAND *rand;
    EVP_RAND_CTX *rctx;
    const size_t buffer_size = 100;
    unsigned char bytes[100];
    unsigned int strength = 256;
    int ret;
    OSSL_PARAM params [2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();

    rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);
    assert(rand != NULL);
    rctx = EVP_RAND_CTX_new(rand, NULL);
    assert(rctx != NULL);
    EVP_RAND_free(rand);

    ret = EVP_RAND_instantiate(rctx, strength, prediction_resistance ? 1 : 0, NULL, 0, params);
    assert(ret == 1);

    ret = EVP_RAND_generate(rctx, bytes, sizeof(bytes), strength, prediction_resistance ? 1 : 0, NULL, 0);
    assert(ret == 1);

    /* TODO: esdm_rand_nonce did not get called here
    ret = EVP_RAND_nonce(rctx, bytes, buffer_size);
    assert(ret > 0);
    assert(ret <= buffer_size);
    */

    ret = EVP_RAND_reseed(rctx, prediction_resistance ? 1 : 0, bytes, buffer_size, bytes, buffer_size);
    assert(ret == 1);

    EVP_RAND_CTX_free(rctx);
}

static void performTest(char* test, char* type) {
    if (strncmp(type, "rng", strlen("rng"))) {
        OSSL_PROVIDER* prov_esdm = OSSL_PROVIDER_load(NULL, "libesdm-rng-provider");
        assert(prov_esdm != NULL);
        OSSL_PROVIDER* prov_default = OSSL_PROVIDER_load(NULL, "default");
        assert(prov_default != NULL);
    }

    if (strncmp(type, "seed-src", strlen("seed-src"))) {
        OSSL_PROVIDER* prov_esdm = OSSL_PROVIDER_load(NULL, "libesdm-seed-src-provider");
        assert(prov_esdm != NULL);
        OSSL_PROVIDER* prov_default = OSSL_PROVIDER_load(NULL, "default");
        assert(prov_default != NULL);
    }

    if (strncmp(test, "random", strlen("random")) == 0)
        test_random();
    if (strncmp(test, "instantiate_pr", strlen("instantiate_pr")) == 0)
        test_instantiate(true);
    if (strncmp(test, "instantiate_full", strlen("instantiate_full")) == 0)
        test_instantiate(false);
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    char *provider_search_path = argv[1];
    char *test = argv[2];
    char *type = argv[3];

	int ret = env_init();
	if (ret)
		return ret;

    ret = OSSL_PROVIDER_set_default_search_path(NULL, provider_search_path);
    assert(ret == 1);

    performTest(test, type);

    env_fini();

    return 0;
}