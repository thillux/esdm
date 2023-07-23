#include "botan-rng.hpp"
#include <cassert>
#include <cstdint>
#include <vector>
#include <botan/ecdsa.h>
#include <botan/rsa.h>

#include "env.h"

void performTest(std::shared_ptr<Botan::RandomNumberGenerator>& rng)
{
    std::vector<uint8_t> bytes(300);
    rng->randomize(bytes);

    Botan::ECDSA_PrivateKey key_ecdsa(*rng, Botan::EC_Group("secp521r1"));
    Botan::RSA_PrivateKey key_rsa(*rng, 2048);
}

int main(void)
{
    int ret = env_init();
	if (ret)
		return ret;

    std::shared_ptr<Botan::RandomNumberGenerator> rng_pr(new ESDM_RNG(true));
    assert(rng_pr->name() == "esdm_pr");
    std::shared_ptr<Botan::RandomNumberGenerator> rng_full(new ESDM_RNG(false));
    assert(rng_full->name() == "esdm_full");
    performTest(rng_pr);
    performTest(rng_full);

    env_fini();

    return 0;
}