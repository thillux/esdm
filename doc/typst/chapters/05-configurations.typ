#import "../template.typ": *

= ESDM Specific Configurations <sec:configurations>

The ESDM offers a secure and appropriate set of features with the default
configuration. Yet, use cases may arise where the ESDM should exhibit a
different behavior. The flexibility of the ESDM allows a various
configurations that are intended to meet different requirements.

The compliance related build options discussed in this chapter interact as
follows (`common/meson.build`):

- `fips140` implies the SP800-90C compliance mode: a build with `fips140` is
  configured exactly as if `sp80090c` were set alongside it.

- `sp80090c`, `fips140` and `ais2031_drg3` compile in the oversampling of the
  entropy sources: the initial seed of a DRNG is requested with 128
  additional bits of entropy, and 64 additional bits of entropy are injected
  into the conditioning components (`ESDM_SEED_BUFFER_INIT_ADD_BITS`,
  `ESDM_OVERSAMPLE_ES_BITS`). These builds also compile out the asynchronous
  entropy source buffers unless `es_buf_force` is set.

- `sp80090c`, `fips140` and `ais2031_drg4` cap the request size based
  reseeding limits - unless `ais2031_drg3` is set, which skips them.

- `ais2031_drg3` and `ais2031_drg4` are mutually exclusive.

- `ais2031_ntg1` selects the NTG.1 seeding strategy independently of all
  others.

#par(first-line-indent: 0pt)[Where the oversampling is compiled in,
`esdm_init` enables it at runtime unconditionally - it does not depend on the
FIPS mode of the system (`esdm/esdm_lib.c`).]

The standards a running ESDM satisfies are listed in the `standards_compliance`
member of its JSON status and in the text status printed from it (see section
@sec:status): "FIPS 140", "DRG.3", "DRG.4", "SP800-90C", "NTG.1(2011)" and
"NTG.1(2024)", each only where it applies. The status is obtained with
`esdm-tool --status` (or `--status-json`), with the RPC API calls
`esdm_rpcc_status` and `esdm_rpcc_status_json`, or from the file
/proc/sys/kernel/random/esdm\_type provided by `esdm-proc`.

== SP800-90C Compliance <sec:sp80090c>

The specification of SP800-90C defines construction methods to design
non-deterministic as well as deterministic RNGs.

The specification defines different types of RNGs where the following mapping
to the ESDM applies:

- The ESDM follows the construction of RBG2(NP) with the following entropy
  sources whose outputs are concatenated:

  - Auxiliary external entropy sources, such as user-space rngd, if available.
    The administrator is responsible to guarantee that this entropy source is
    compliant to SP800-90B if it alters the entropy estimator maintained by
    the ESDM via the `RNDADDENTROPY` IOCTL or the `esdm_rpcc_rnd_add_entropy`
    RPC API call. Depending on the selected entropy source, this may be a
    physical or non-physical entropy source. Note, all data maintained by the
    auxiliary pool are processed with the XDRBG-256 discussed in section
    @sec:xdrbg. Thus, to achieve full SP800-90C compliance for such entropy
    sources, only one should feed data credited with entropy into the
    auxiliary pool.

  - The interrupt entropy source and the scheduler entropy source of the ESDM
    Linux kernel module in addon/linux\_esdm\_es are subject to a full entropy
    analysis following section @sec:sp80090b and chapter
    @sec:sched-assessment, respectively. The eBPF variants of both sources
    (section @sec:ebpf) are uncredited per default. At most one of the four
    timing-based entropy sources may be credited with entropy: the build
    refuses a configuration crediting more than one of `es_irq_entropy_rate`,
    `es_sched_entropy_rate`, `es_irq_ebpf_entropy_rate` and
    `es_sched_ebpf_entropy_rate`.

  - The Jitter RNG entropy source is used by the ESDM. This entropy source is
    a fully self-contained SP800-90B entropy source. Its SP800-90B compliance
    must be assessed separately. If SP800-90B compliance cannot be
    demonstrated, it must be awarded to credit zero bits of entropy with the
    configuration documented in section @sec:jent-entropy or by completely
    disabling it by not selecting the meson configuration option of `es_jent`.
    The same applies to the kernel Jitter RNG entropy source (section
    @sec:jent-kernel) with the options `es_jent_kernel_entropy_rate` and
    `es_jent_kernel`.

  - The CPU entropy source is used by the ESDM, if available. On Intel, this
    uses RDSEED. This entropy source is a fully self-contained SP800-90B
    entropy source. Its SP800-90B compliance must be assessed separately. If
    SP800-90B compliance cannot be demonstrated, it must be awarded to credit
    zero bits of entropy with the configuration documented in section
    @sec:cpu-entropy or by completely disabling it by not selecting the meson
    configuration option of `es_cpu`.

  - The Linux HWRAND entropy source (section @sec:hwrand), the TPM2 entropy
    source (section @sec:tpm2), the PKCS\#11 entropy source (section
    @sec:pkcs11) and the external entropy sources ExternalLib and
    ExternalSocket (section @sec:ext-es) are used by the ESDM, if enabled and
    available. Their SP800-90B compliance must be assessed separately. If
    SP800-90B compliance cannot be demonstrated, they must be awarded to
    credit zero bits of entropy with the meson configuration options of
    `es_hwrand_entropy_rate`, `es_tpm2_entropy_rate`,
    `es_pkcs11_entropy_rate`, `es_ext_lib_entropy_rate` and
    `es_ext_socket_entropy_rate` or by completely disabling them by not
    selecting the meson configuration options of `es_hwrand`, `es_tpm2`,
    `es_pkcs11` and `es_ext`.

  - The kernel RNG entropy source is never credited with entropy when the
    oversampling is compiled in, as the kernel RNG is not considered
    SP800-90B compliant (section @sec:krng-entropy).

  By applying Method 2 of section 3.3 in SP800-90C, the entropy provided by
  all entropy sources can be added which is applied when the ESDM constructs
  the temporary seed buffer as shown with equation @eq:t.

  Following SP800-90C section 2.6, only validated entropy sources are allowed
  to seed the DRBG, while the data of others may be inserted as additional
  input. The ESDM treats every entropy source that is credited with zero bits
  of entropy as a non-validated one: its data is not part of the seed but of
  a separate additional input buffer handed to the DRBG with the seed
  (`esdm_es_seed_slot` in `esdm/es/esdm_es_mgr.c`). An entropy rate of zero
  therefore does not disable an entropy source - its data is still collected
  and stirs the DRBG state, but it is not credited.

- During instantiation of the DRBG, the ESDM tries to seed the DRBG with at
  least (DRBG security strength) + 128 bits = 384 bits of entropy. Only when
  this amount of entropy was obtained to seed the DRBG is considered to be
  fully seeded and is allowed to produce output.

  If the SP800-90C construction is to be used as the “randomness source”
  to seed another DRBG with a security strength of 256 bits, the prediction
  resistance DRNG discussed below should be used.

- The prediction resistance DRNG serving the interfaces listed in section
  @sec:90c-config is operated as an RBG3(RS) following SP800-90C section
  6.5.1.2: before generating a block of at most 256 bits, it is reseeded with
  data requested with 64 additional bits of entropy, and the output is capped
  at the freshly collected entropy reduced by these 64 bits
  (`esdm_drng_mgr.c`).

- Reseeding of the DRBG can be triggered by the `RNDRESEEDCRNG` IOCTL or the
  `esdm_rpcc_rnd_reseed_crng` RPC API call. The ESDM guarantees that a reseed
  operation of a fully seeded DRBG is only performed if at least 256 bits of
  entropy are available. If this is not available, the reseed is attempted
  again later. Yet, the generate operation is conducted in any case.
  Nonwithstanding, the ESDM always attempts to obtain 256 bits of entropy for
  reseeding. This is considered appropriate because the upper limit when a
  reseed is ultimately triggered is $2^20$ generate operations or after 10
  minutes, whatever is reached earlier. In addition, the SP800-90C mode caps
  the request size based reseeding limits: a DRNG tries to reseed after
  98,304 output bits at the latest and loses its fully seeded state after
  $2^17$ output bits without a successful reseed (`drng_reseed_threshold_bits`
  and `drng_max_reseed_bits`, capped by `common/meson.build`). If the DRNG
  cannot be reseeded it will continue to operate until one of these limits
  is reached. The DRNG will revert to an unseeded stage if it cannot be
  reseeded by the time it serviced $2^30$ generate requests since the last
  successful seeding operation.

#par(first-line-indent: 0pt)[The requirements from section 6.3 of the draft
of SP800-90C from January 21, 2021 are met as follows:]

+ The administrator must use an SP800-90A DRBG as mentioned above to satisfy
  the requirement: the Hash DRBG of the builtin crypto backend
  (`drng_hash_drbg`), any DRBG of the OpenSSL backend, the HMAC DRBG of the
  Botan backend (`botan_drng_type=hmac`) or the CTR DRBG of the GnuTLS backend
  - see section @sec:backends.

+ The DRBG can be ACVTS-tested to show compliance to SP800-90A. The entropy
  sources are to be assessed pursuant to SP800-90B as outlined in the above
  listing.

+ See the above listing for the reseeding support.

+ If an entropy source is not validated, its entropy estimation must be set to
  zero as outlined in the above listing.

+ N/A as the ESDM is claimed to conform with RBG2(NP).

+ The entropy sources are listed above. By using concatenation of the output
  of all entropy sources, the Method 2 SP800-90C is implemented. The entropy
  of all entropy sources are added.

+ Technically it is possible that all DRBG security strengths can be chosen as
  the DRBG supports all security strengths. Yet, the ESDM interfaces currently
  only support the highest security strength of 256 bits to ensure that it can
  be used for all use cases.

+ The entropy source output is destroyed immediately after it was used to
  (re)seed the DRBG.

+ N/A as the ESDM does not use a CTR DRBG without derivation function: the
  CTR DRBG of the GnuTLS backend is operated with the SP800-90A
  Block\_Cipher\_df added by the ESDM.

+ The ESDM attempts to instantiate a DRBG with 3/2s bits of entropy. Only if
  this succeeds, the DRBG becomes available. The ESDM attempts to reseed a
  DRBG with s bits of entropy and only reseeds a fully seeded DRBG if s bits
  of entropy are available.

+ The DRBG only provides output once it is fully seeded as mandated by
  SP800-90C.

+ An error occurring in the interrupt or scheduler entropy source triggers a
  reset of that entropy source and a restart of its SP800-90B startup test as
  outlined in section @sec:health-tests (or a kernel panic if the kernel
  module is loaded with `esdm_panic_on_permanent_health_failure`). If
  the other entropy sources are subject to a health test failures, SP800-90B
  mandates that they do not produce entropy. Before the first initialization
  of the DRBG, it is subject to a power-on self test. The ESDM performs
  power-up self tests as outlined in section @sec:self-tests.

+ This requirement is implicitly met by the fact that the ESDM only provides
  DRBGs with the maximum security strength of 256 bits.

=== RBG2(P) Construction Method <sec:rbg2p>

It is possible to convert the ESDM into the SP800-90C type of RBG2(P). This
approach requires that only physical entropy sources are credited with
entropy. The following specific settings must be applied in addition to the
general configurations listed in the next section:

- Configure the interrupt and the scheduler entropy sources, kernel module
  and eBPF variants alike, to not credit entropy: compile the ESDM with the
  meson configuration options of `es_irq_entropy_rate=0`,
  `es_sched_entropy_rate=0`, `es_irq_ebpf_entropy_rate=0` and
  `es_sched_ebpf_entropy_rate=0`. This setting ensures that these entropy
  sources still collect data, but they are not credited with entropy. If they
  shall be completely disabled, the compile time options of `es_irq`,
  `es_sched`, `es_irq_ebpf` and `es_sched_ebpf` must be unset.

- Configure the Jitter RNG entropy sources to not credit entropy: compile the
  ESDM with the meson configuration options of `es_jent_entropy_rate=0` and
  `es_jent_kernel_entropy_rate=0`. If the value is set to 0, the entropy
  source still collects data, but it is not credited with entropy. If it
  shall be completely disabled, the compile time options of `es_jent` and
  `es_jent_kernel` must be unset.

- The kernel RNG entropy source is not credited with entropy in the SP800-90C
  mode anyway. If it shall be completely disabled, the compile time option of
  `es_kernel` must be unset.

- Adjust the entropy rate of the CPU entropy source as needed: compile the
  ESDM with the meson configuration option of `es_cpu_entropy_rate=256` when
  full entropy is assumed to be provided by the CPU entropy source. In
  general, set any value between 0 and 256 if the default value is not
  appropriate. If the value is set to 0, still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_cpu` must be unset.

- Adjust the entropy rate of the HWRAND entropy source as needed: compile the
  ESDM with the meson configuration option of `es_hwrand_entropy_rate=256`
  when full entropy is assumed to be provided by the configured HWRAND entropy
  source. Ensure that the intended HWRAND entropy source is set in
  /sys/devices/virtual/misc/hw\_random/rng\_current. In general, set any value
  between 0 and 256 if the default value is not appropriate. If the value is
  set to 0, still collects data, but it is not credited with entropy. If it
  shall be completely disabled, the compile time option of `es_hwrand` must be
  unset.

- Adjust the entropy rates of the TPM2, the PKCS\#11 and the external entropy
  sources the same way with the meson configuration options of
  `es_tpm2_entropy_rate`, `es_pkcs11_entropy_rate`, `es_ext_lib_entropy_rate`
  and `es_ext_socket_entropy_rate`, depending on whether the respective
  source is a physical entropy source.

- If other hardware entropy sources are considered deliver entropy, they may
  inject data into the ESDM via the IOCTL `RNDADDENTROPY` or the
  `esdm_rpcc_rnd_add_entropy` RPC API call. Note, only physical entropy
  sources must provide data that is credited with entropy. Any other data fed
  into the ESDM via those interfaces must not be credited with entropy.

#par(first-line-indent: 0pt)[Important note: The entropy rate provided by the
CPU entropy source plus all other physical entropy sources together must
ensure they provide sufficient entropy. “Sufficient entropy” is provided when
the entropy rate equals the state size of the XDRBG-256 of the entropy pools
used by the ESDM, i.e. 512 bits of entropy should be provided.]

Naturally, the hardware entropy sources that are credited with entropy must
be compliant to SP800-90B.

In case the RBG2(P) construction method is achieved, the following additional
requirement from section 6.3 SP800-90C is met:

- Requirement 5: With the required configuration mentioned before the ESDM
  will only count the physical entropy sources towards fulfilling the
  requested amount of entropy.

=== SP800-90C Compliant Configuration <sec:90c-config>

SP800-90C compliance is only achieved when all of the following settings are
achieved.

The following compile-time settings must be observed:

- The meson configuration option `sp80090c` (or `fips140`) is set. This
  option guarantees the following:

  - The final conditioning operation applied to the auxiliary pool, to the
    conditioning pools of the eBPF entropy sources and to the CPU entropy
    source require 64 additional bits of entropy when obtaining data for the
    temporary seed buffer. This complies with the requirement specified in
    section 4.3.2 SP800-90C about vetted conditioning components. This
    ensures the conditioning components provide full entropy. The interrupt
    and scheduler entropy sources of the kernel module apply an
    oversampling of their own when the kernel runs in FIPS mode.

  - When the DRNG is initially seeded, it is attempted to be seeded with 384
    bits of entropy at least. This complies with the requirement specified in
    section 6.2.1 bullet 2 of SP800-90C requiring 3/2s bits of entropy for the
    initial seeding. Only if this is achieved, the SP800-90C compliant-marked
    interfaces of the ESDM specified in section @sec:health-tests will produce
    random numbers.

  - The request size based reseeding limits of the previous section apply.

- Enable `es_irq` to use the interrupt entropy source compliant to SP800-90B
  as outlined in section @sec:90b-config if the interrupt entropy source is
  considered to be compliant to SP800-90B by accepting the assessment in
  chapter @sec:irq-assessment and by applying the testing of the entropy
  source as outlined in section @sec:90b-reuse on the target system. This also
  requires the compilation of the ESDM Linux kernel module documented in
  addon/linux\_esdm\_es/README.md.

- Enable `es_sched` configure the scheduler entropy source compliant to
  SP800-90B as outlined in section @sec:sched-assessment if the scheduler
  entropy source is considered to be compliant to SP800-90B by accepting the
  assessment in chapter @sec:sched-assessment and by applying the testing of
  the entropy source as outlined in this chapter on the target system. This
  also requires the compilation of the ESDM Linux kernel module documented in
  addon/linux\_esdm\_es/README.md.

- Credit the eBPF scheduler or interrupt entropy source with
  `es_sched_ebpf_entropy_rate` or `es_irq_ebpf_entropy_rate` only with an
  entropy rate determined for the target system with the measurement tools in
  addon/es\_ebpf\_testing (section @sec:ebpf).

- The ESDM must be compiled with the meson configuration option of
  `es_cpu_entropy_rate=0` or unset the option `es_cpu` unless the CPU-based
  entropy source (e.g. RDSEED on Intel) has an SP800-90B compliant entropy
  assessment and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_hwrand_entropy_rate=0` or unset the option `es_hwrand` unless the
  HWRAND entropy source has an SP800-90B compliant entropy assessment and
  comply with all requirements from SP800-90B. The same applies to the TPM2,
  PKCS\#11 and external entropy sources with their respective options.

- The ESDM must be compiled with the meson configuration options of
  `es_jent_entropy_rate=0` and `es_jent_kernel_entropy_rate=0` or unset the
  options `es_jent` and `es_jent_kernel` unless the Jitter RNG entropy source
  has an SP800-90B compliant entropy assessment and comply with all
  requirements from SP800-90B#footnote[At the time of writing, the user space
  Jitter RNG is SP800-90B compliant. Patches ensuring the in-kernel variant is
  SP800-90B compliant as well when into the kernel for version 5.8.]. In the
  SP800-90C mode, the ESDM operates the Jitter RNG with its FIPS mode forced
  on (`JENT_FORCE_FIPS`), enabling its health tests.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- Filling up the ESDM with entropy using either a user-space RNGD via the
  IOCTL `RNDADDENTROPY` or the `esdm_rpcc_rnd_add_entropy` RPC API call is
  allowed. However, the caller is only allowed to claim entropy associated
  with the data and thus increase the ESDM entropy estimation if the entropy
  source is SP800-90B compliant with its own entropy assessment.

- The kernel must be booted with `fips=1` when the interrupt or scheduler
  entropy source of the kernel module is credited with entropy, as the kernel
  module applies its health tests and its oversampling only in the FIPS mode
  of the kernel.

#par(first-line-indent: 0pt)[To verify that the SP800-90C compliance is
achieved, the status of the ESDM lists "SP800-90C" as outlined at the
beginning of this chapter. The SP800-90C compliant is ensured only for the
respectively marked ESDM interfaces specified in section @sec:health-tests.
All other interfaces are not providing SP800-90C compliant random numbers.]

It is permissible to use the ESDM DRBG output to seed another DRBG when using
the prediction resistance DRNG via the RPC API calls
`esdm_rpcc_get_random_bytes_pr` or `esdm_rpcc_get_random_bytes_pr_nonblock`,
using `getrandom(2)` with the `GRND_RANDOM` flag, opening /dev/random (or
/dev/urandom) of the CUSE daemons with the `O_SYNC` flag, reading from the
prediction resistance socket of the EGD interface (section @sec:egd), or
using the OpenSSL providers `libesdm-rng-provider-pr.so` and
`libesdm-egd-provider-pr.so`. See the details given for the API call
`esdm_get_random_bytes_pr` in section @sec:components.
// TODO(egd-esdm-commands): the EGD interface gets ESDM specific commands
// including a prediction resistance read and loses its separate prediction
// resistance socket - name the new command here instead of the PR socket.
// TODO(linux-esdm-cdev): list the devices of the kernel module
// addon/linux_esdm_cdev (/dev/esdm_random, /dev/esdm_urandom) here once it is
// merged, as far as they serve the prediction resistance DRNG.

=== FIPS 140 Compliant Configuration <sec:fips140-config>

FIPS 140 compliance is only achieved when all of the following settings are
achieved.

The following compile-time settings must be observed:

- The meson configuration option `fips140` is set. This option guarantees the
  following:

  - The build is configured as if the option `sp80090c` were set, including
    its oversampling and reseeding limits.

  - The FIPS mode support including the power-on self tests and the
    integrity test is compiled in (`esdm/fips.c`, `common/fips_integrity.c`).

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The ESDM must be operated in FIPS mode. The FIPS mode is active if the
  kernel reports it with /proc/sys/crypto/fips_enabled - i.e. the kernel is
  booted with the kernel command line option of `fips=1` -, or if the
  environment variable `ESDM_SERVER_FORCE_FIPS` is set when starting the ESDM
  server (which is only honored through `secure_getenv`). If
  /proc/sys/crypto/fips_enabled exists but cannot be read, the ESDM assumes
  the FIPS mode. The oversampling of the entropy sources does not depend on
  the FIPS mode: it is applied by every `fips140` build.

- In FIPS mode, the ESDM performs a power-on self test when it is loaded: a
  known-answer test of HMAC-SHA256 and an integrity test comparing the
  HMAC-SHA256 of the executable, of the shared object holding the ESDM and of
  the loaded libraries it was built against (the Jitter RNG and the library
  of the crypto backend) with the values stored in the files
  `.<file name>.hmac` next to them. A missing or mismatching file stops the
  process. These files are created with `esdm-tool --fips-checkfile` and
  `--fips-targetfile`.

- The interrupt and scheduler entropy sources of the kernel module must be
  operated with the kernel in FIPS mode as outlined in section
  @sec:90c-config.

#par(first-line-indent: 0pt)[In FIPS mode, the status of the ESDM lists
"FIPS 140".]

== AIS 20 / 31 <sec:ais2031>

The German BSI defines construction methods of RNGs with AIS 20/31 with the
revision from 2011 and the revision 3.0 from 2024. In particular, these
documents define different classes of RNGs where the ESDM is capable of
meeting the classes NTG.1, DRG.3 and DRG.4. The NTG.1 compliance following the
revision from 2011 is achieved when using the prediction resistance DRNG of
the ESDM via the interfaces listed in section @sec:90c-config: /dev/random
with the `O_SYNC` flag during opening, `getrandom(2)` with the `GRND_RANDOM`
flag, or the `esdm_rpcc_get_random_bytes_pr` RPC API call, for example.

The NTG.1 from AIS 20/31 of 2011 requirements are met as follows:

- NTG.1.1: The ESDM offers interfaces to collect raw unconditioned entropy as
  outlined in section @sec:test-interfaces.

- NTG.1.2: The ESDM maintains an entropy estimator for each entropy source.
  The credit operation of the ESDM is documented in section @sec:components.
  To outline the debit operation section @sec:90b-3151 provides several
  examples showing the approach. For each of the fast entropy sources, the
  ESDM obtains the entropy estimate when fetching data from them and applies
  this estimate when seeding the DRNG.

- NTG.1.3: The ESDM provides a compile-time switchable DRNG support using an
  SP800-90A Hash DRBG with a SHA-512 core. Furthermore, the ESDM allows using
  a ChaCha20-based DRNG which is documented in section @sec:chacha20, as well
  as the DRNGs of the other crypto backends listed in section @sec:backends.
  All those DRNGs are characterized as DRG.3 since they all support backward
  secrecy and use contemporary cryptographic primitives for the state
  transition as well as output generation.

- NTG.1.4: Due to the blocking behavior and only returning as many bits of
  data as entropy is available via the prediction resistance DRNG, the ESDM
  meets the requirement.

- NTG.1.5: The output functions of the offered DRNGs are all based on
  contemporary cryptographic primitives. Therefore, the output is assumed that
  it cannot be distinguished from random number output sequences of an ideal
  RNG. This is supported by the fact that the SP800-90A DRBGs are successfully
  passing the NIST CAVP test suite. The ChaCha20 DRNG can be tested using the
  #link("https://www.chronox.de/chacha20_drng.html")[ChaCha20 DRNG stand-alone
  implementation] which is derived from the ESDM implementation. The tester
  can verify that both operate identical because the power-on self test in the
  stand-alone ChaCha20 DRNG implementation is identical to the ESDM power-up
  self test of the ChaCha20 DRNG in esdm/crypto/esdm\_builtin\_chacha20.c,
  which esdm/esdm\_selftest.c invokes.

- NTG.1.6: Using the entropy analysis tools such as the NIST SP800-90B test
  tools, results shown in appendix @sec:measurements can be obtained for the
  interrupt entropy source. For the second entropy source, such assessment
  must be performed as well. For example, the
  #link("http://www.chronox.de/jent.html")[Jitter RNG] is provided with a
  complete independent entropy assessment. When comparing the results with the
  heuristic entropy estimate, it is clear that the ESDM collects more entropy
  than it credits. Further, considering the mathematical operations processing
  the raw entropy data outlined in section @sec:90b-315, the processing is
  considered to not destroy entropy.

=== NTG.1 (AIS 20/31 2011) Compliant Configuration <sec:ntg1-2011>

To achieve NTG.1 compliant operation, the following configuration must be
applied. It is permissible to use the configuration in parallel with the
SP800-90B and SP800-90C configurations.

The following compile-time settings must be observed:

- None.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The caller must use the prediction resistance DRNG: /dev/random of the CUSE
  daemon opened with `O_SYNC`, the `getrandom(2)` API call with the flag
  `GRND_RANDOM`, the `esdm_rpcc_get_random_bytes_pr` or
  `esdm_rpcc_get_random_bytes_pr_nonblock` RPC API calls, or the other
  interfaces listed in section @sec:90c-config.
  // TODO(egd-esdm-commands): replace the prediction resistance EGD socket
  // referenced through section 5.1.2 with the new EGD command.

#par(first-line-indent: 0pt)[The status of the ESDM always lists "NTG.1(2011)".
The NTG.1 compliant is ensured only for the respectively marked ESDM interfaces
specified in section @sec:90b-config. All other interfaces are not providing
NTG.1 compliant random numbers.]

=== NTG.1 (AIS 20/31 2024) Compliant Configuration <sec:ntg1-2022>

To achieve NTG.1 compliant operation following AIS 20/31 3.0 from 2024, the
following configuration must be applied. It is permissible to use the
configuration in parallel with the SP800-90B and SP800-90C configurations.

The following compile-time settings must be observed for AIS 20/31 3.0
(2024):

- The ESDM compile time option of `ais2031_ntg1` must be enabled. It selects
  the NTG.1 seeding strategy: on top of the 256 bits (384 bits with
  oversampling) of entropy required for the initial seeding of a DRNG, two
  entropy sources must deliver at least 240 bits of entropy each
  (`ESDM_AIS2031_NPTRNG_MIN_ENTROPY`). After the initial seeding, one entropy
  source is sufficient for reseeding (`esdm_fully_seeded` in
  `esdm/es/esdm_es_mgr.c`).

- The ESDM must have access to two entropy sources which are capable of
  delivering 240 bits of entropy each. For example, the interrupt entropy
  source of the kernel module, the Jitter RNG, the kernel Jitter RNG and the
  TPM2 entropy source are configured with 256 bits per default. An entropy
  source that shall not contribute to this seeding strategy must be
  configured to provide less than 240 bits of entropy. See section
  @sec:jent-entropy for details on the Jitter RNG entropy rate.

- The requirement of two entropy sources does not apply when the Jitter RNG
  is operated in its own NTG.1 mode with the option `es_jent_ntg1`, which
  requires jitterentropy 3.7.0 or later with support for secure memory. Such a
  Jitter RNG is NTG.1 conformant on its own: once it delivered 240 bits of
  entropy, it seeds a DRNG without a second entropy source.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- None.

#par(first-line-indent: 0pt)[To verify that the NTG.1 compliance is achieved,
the status of the ESDM lists "NTG.1(2024)". The NTG.1 compliant is ensured only
for the respectively marked ESDM interfaces specified in section
@sec:90b-config. All other interfaces are not providing NTG.1 compliant random
numbers.]

=== DRG.3 Compliant Configuration <sec:drg3>

The ESDM compile time option of `ais2031_drg3` applies the oversampling of the
entropy sources of the `sp80090c` option without its request size based
reseeding limits: `drng_reseed_threshold_bits` and `drng_max_reseed_bits`
keep whatever is configured and are not capped. Setting `sp80090c` alongside
does not bring the limits back. The status of the ESDM lists "DRG.3", but not
"SP800-90C", for such a build. The option is mutually exclusive with
`ais2031_drg4`.

=== DRG.4 / PTG.3 Compliant Configuration <sec:drg4-ptg3>

The ESDM compile time option of `ais2031_drg4` caps the request size based
reseeding limits to the values required by DRG.4.10 of AIS 20/31 3.0 from
2024: a DRNG instance loses its fully seeded state after $2^17$ output bits
without a successful reseed, and tries to reseed after three quarters of that
at the latest. Smaller values configured with `drng_reseed_threshold_bits` and
`drng_max_reseed_bits` are kept. The status of the ESDM lists "DRG.4" and
"DRG.3" for such a build.

The ESDM allows a configuration that would make the ESDM compliant to the
requirements of a PTG.3 as well. This is achieved by deconfiguring all
entropy sources except one that provides the data from a PTG.2 entropy
source. For example, a smart card that provides a PTG.2 entropy source can be
accessed with the PKCS\#11 entropy source, or an rngd having access to it can
feed the auxiliary pool. In this case, all other entropy sources must be
deactivated using the following configuration.

The PTG.3 naturally can only be claimed if the PTG.2 entropy source is part of
the validation. If the PTG.2 entropy source is not part of the validation, a
DRG.4 must be claimed instead.

For achieving such compliance claim, the following compile-time configuration
must be applied:

- Compile the ESDM with the option `ais2031_drg4`.

- Configure all entropy sources other than the PTG.2 entropy source to not
  credit entropy with the meson configuration options of
  `es_irq_entropy_rate=0`, `es_sched_entropy_rate=0`,
  `es_irq_ebpf_entropy_rate=0`, `es_sched_ebpf_entropy_rate=0`,
  `es_jent_entropy_rate=0`, `es_jent_kernel_entropy_rate=0`,
  `es_cpu_entropy_rate=0`, `es_kernel_entropy_rate=0`,
  `es_hwrand_entropy_rate=0`, `es_tpm2_entropy_rate=0`,
  `es_pkcs11_entropy_rate=0`, `es_ext_lib_entropy_rate=0` and
  `es_ext_socket_entropy_rate=0`. Note, an entropy source with an entropy rate
  of 0 is not disabled: its data is still collected and handed to the DRNG as
  additional input as outlined in section @sec:sp80090c, but it is not
  credited with entropy. An entropy source is disabled by unsetting its
  compile time option (`es_irq`, `es_sched`, `es_irq_ebpf`, `es_sched_ebpf`,
  `es_jent`, `es_jent_kernel`, `es_cpu`, `es_kernel`, `es_hwrand`, `es_tpm2`,
  `es_pkcs11`, `es_ext`).

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The PTG.2 entropy source delivers its entropy to the ESDM via the entropy
  source configured for it, or via either the `esdm_rpcc_rnd_add_entropy` RPC
  API call or the /dev/random IOCTL `RNDADDENTROPY` into the auxiliary pool.
  If only data with full entropy is inserted into the auxiliary pool, the
  option `aux-has-full-entropy` avoids the reduction of the entropy by the
  oversampling applied to it.
