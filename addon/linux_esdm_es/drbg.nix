{
  lib,
  kernel,
  ...
}:

[
  {
    name = "extra_config_drbg";
    patch = null;
    structuredExtraConfig =
      with lib.kernel;
      # 7.2 dropped the DRBG type menu: CRYPTO_DRBG is HMAC_DRBG only.
      if lib.versionOlder kernel.version "7.2" then
        {
          CRYPTO_DRBG_MENU = yes;
          CRYPTO_DRBG_HMAC = yes;
          CRYPTO_DRBG_HASH = yes;
          CRYPTO_DRBG_CTR = yes;
        }
      else
        {
          CRYPTO_DRBG = yes;
        };
  }
]
