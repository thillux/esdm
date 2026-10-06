{
  lib,
  kernel,
  ...
}:

let
  # drivers/misc/Makefile lost the ibmasm entry the 6.18 hooks used as patch
  # context in 7.3.
  hooksVersion =
    if lib.versionOlder kernel.version "6.18" then
      "6.6"
    else if lib.versionOlder kernel.version "7.3" then
      "6.18"
    else
      "7.3";
in
[
  {
    name = "esdm_sched_es_hook";
    patch = ./. + "/0001-ESDM-scheduler-entropy-source-hooks_${hooksVersion}.patch";
  }
  {
    name = "esdm_inter_es_hook";
    patch = ./. + "/0002-ESDM-interrupt-entropy-source-hooks_${hooksVersion}.patch";
  }
]
# Since 7.2 the kernel DRBG is a private HMAC_DRBG without the internals this
# patch exported; esdm_es brings its own HMAC_DRBG there (esdm_drbg_kcapi.c).
++ lib.optional (lib.versionOlder kernel.version "7.2") {
  name = "esdm_drbg_visibility";
  patch =
    if lib.versionOlder kernel.version "6.18" then
      ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.6.patch
    else
      ./0003-ESDM-crypto-DRBG-externalize-DRBG-functions-for-ESDM_6.18.patch;
}
