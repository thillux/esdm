#import "../template.typ": *

= ESDM Specific Configurations <sec:configurations>

The ESDM offers a secure and appropriate set of features with the default
configuration. Yet, use cases may arise where the ESDM should exhibit a
different behavior. The flexibility of the ESDM allows a various
configurations that are intended to meet different requirements.

== SP800-90C Compliance <sec:sp80090c>

The specification of SP800-90C defines construction methods to design
non-deterministic as well as deterministic RNGs. As the specification is
currently in draft form, the latest available draft from January 21, 2021 is
applied.

The specification defines different types of RNGs where the following mapping
to the ESDM applies:

- The ESDM follows the construction of RBG2(NP) with the following entropy
  sources whose outputs are concatenated:

  - Auxiliary external entropy sources, such as user-space rngd, if available.
    The administrator is responsible to guarantee that this entropy source is
    compliant to SP800-90B if it alters the entropy estimator maintained by
    the ESDM via the `RNDADDENTROPY` IOCTL. Depending on the selected entropy
    source, this may be a physical or non-physical entropy source. Note, all
    data maintained by the auxiliary pool are processed with a vetted
    conditioning component. Thus, to achieve full SP800-90C compliance for
    such entropy sources, only one should feed data credited with entropy into
    the auxiliary pool.

  - Interrupt entropy source is the only entropy source that is fully
    maintained as part of the ESDM and is subject to a full entropy analysis
    following section @sec:sp80090b. Furthermore, it is claimed to be fully
    SP800-90B compliant.

  - Scheduler entropy source is the only entropy source that is fully
    maintained as part of the ESDM and is subject to a full entropy analysis
    following @sec:sched-assessment. Furthermore, it is claimed to be fully
    SP800-90B compliant.

  - The Jitter RNG entropy source is used by the ESDM. This entropy source is
    a fully self-contained SP800-90B entropy source. Its SP800-90B compliance
    must be assessed separately. If SP800-90B compliance cannot be
    demonstrated, it must be awarded to credit zero bits of entropy with the
    configuration documented in section @sec:jent-entropy or by completely
    disabling it by not selecting the meson configuration option of `es_jent`.

  - The CPU entropy source is used by the ESDM, if available. On Intel, this
    uses RDSEED. This entropy source is a fully self-contained SP800-90B
    entropy source. Its SP800-90B compliance must be assessed separately. If
    SP800-90B compliance cannot be demonstrated, it must be awarded to credit
    zero bits of entropy with the configuration documented in section
    @sec:cpu-entropy or by completely disabling it by not selecting the meson
    configuration option of `es_cpu`.

  - The Linux HWRAND entropy source is used by the ESDM, if available. Its
    SP800-90B compliance must be assessed separately. If SP800-90B compliance
    cannot be demonstrated, it must be awarded to credit zero bits of entropy
    with the configuration documented in section @sec:cpu-entropy or by
    completely disabling it by not selecting the meson configuration option of
    `es_hwrand`.

  By applying Method 2 of section 3.3 in SP800-90C, the entropy provided by
  all entropy sources can be added which is applied when the ESDM constructs
  the temporary seed buffer as shown with equation @eq:t.

- During instantiation of the DRBG, the ESDM tries to seed the DRBG with at
  least (DRBG security strength) + 128 bits = 384 bits of entropy. Only when
  this amount of entropy was obtained to seed the DRBG is considered to be
  fully seeded and is allowed to produce output.

  If the SP800-90C construction is to be used as the “randomness source”
  following bullet 5 of section “Note to Reviewer” in the SP800-90C document
  to seed another DRBG with a security strength of 256 bits, either the hash
  DRBG should be used as they are capable of transporting up to 512 bits of
  entropy and are initially seeded with 384 bits of entropy. Thus, the
  SP800-90C seeding requirement of providing 384 bits of entropy can be
  satisfied.

- Reseeding of the DRBG can be triggered by either writing data into
  /dev/random or by the `RNDRESEEDCRNG` IOCTL. The ESDM guarantees that the
  reseed operation is only performed if at least 256 bits of entropy is
  available if operated compliant to SP800-90C. If this is not available, the
  reseed is attempted during the next generate operation. Yet, the generate
  operation is conducted in any case. Nonwithstanding, the ESDM always
  attempts to obtain 256 bits of entropy for reseeding. This is considered
  appropriate because the upper limit when a reseed is ultimately triggered is
  $2^20$ generate operations or after 10 minutes, whatever is reached earlier.
  If the DRNG cannot be reseeded it will continue to operate until the next
  time this threshold is reached. The DRNG will revert to an unseeded stage if
  it cannot be reseeded by the time it serviced $2^30$ generate requests since
  the last successful seeding operation.

#par(first-line-indent: 0pt)[The requirements from section 6.3 SP800-90C are
met as follows:]

+ The administrator must use the SP800-90A DRBG ESDM extension as mentioned
  above to satisfy the requirement.

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
  (re)seed the DRBG. Note, the use of the seed for backward secrecy by
  injecting it into the auxiliary pool via the vetted conditioning operation
  is considered to not violate the requirement as the seed data is
  unrecoverable. Furthermore, the seed data is not credited with any entropy
  during the backward secrecy operation. Therefore, the seed data is only used
  to further mix the internal state of the ESDM.

+ N/A as the ESDM does not use a CTR DRBG without derivation function.

+ The ESDM attempts to instantiate a DRBG with 3/2s bits of entropy. Only if
  this succeeds, the DRBG becomes available. The ESDM attempts to reseed a
  DRBG with s bits of entropy. See the rationale above for the discussion
  about the minimum entropy size of the reseeding operation of 128 bits.

+ The DRBG only provides output once it is fully seeded as mandated by
  SP800-90C.

+ An error occurring in the interrupt entropy source triggers a full reset of
  the ESDM as outlined in section @sec:health-tests. If the other entropy
  sources are subject to a health test failures, SP800-90B mandates that they
  do not produce entropy. Before the first initialization of the DRBG, it is
  subject to a power-on self test. The ESDM performs power-up self tests as
  outlined in section @sec:self-tests.

+ This requirement is implicitly met by the fact that the ESDM only provides
  DRBGs with the maximum security strength of 256 bits.

=== RBG2(P) Construction Method <sec:rbg2p>

It is possible to convert the ESDM into the SP800-90C type of RBG2(P). This
approach requires that only physical entropy sources are credited with
entropy. The following specific settings must be applied in addition to the
general configurations listed in the next section:

- Configure the interrupt entropy source to not credited entropy: compile the
  ESDM with the kernel configuration option of `es_irq_entropy_rate=0`. This
  setting ensures that the interrupt entropy source still collects data, but
  it is not credited with entropy. If it shall be completely disabled, the
  compile time option of `es_irq` must be unset.

- Configure the scheduler entropy source to not credited entropy: compile the
  ESDM with the meson configuration option of `es_sched_entropy_rate=0`. This
  setting ensures that the scheduler entropy source still collects data, but
  it is not credited with entropy. If it shall be completely disabled, the
  compile time option of `es_sched` must be unset.

- Configure the Jitter RNG entropy source to not credit entropy: compile the
  ESDM with the meson configuration option of `es_jent_entropy_rate=0`. If the
  value is set to 0, the entropy source still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_jent` must be unset.

- Configure the kernel RNG entropy source to not credit entropy: compile the
  ESDM with the meson configuration option of `es_kernel_entropy_rate=0`. If
  the value is set to 0, the entropy source still collects data, but it is not
  credited with entropy. If it shall be completely disabled, the compile time
  option of `es_kernel` must be unset.

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

- If other hardware entropy sources are considered deliver entropy, they may
  inject data into the ESDM via the IOCTL `RNDADDENTROPY.` Note, only physical
  entropy sources must provide data that is credited with entropy. Any other
  data fed into the ESDM via those interfaces must not be credited with
  entropy.

#par(first-line-indent: 0pt)[Important note: The entropy rate provided by the
CPU entropy source plus all other physical entropy sources together must
ensure they provide sufficient entropy. “Sufficient entropy” is provided when
the entropy rate equals the hash type used by the ESDM. Considering the
default message digest of SHA2-512, 512 bits of entropy should be provided.]

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

- The meson configuration option `sp80090c` is set. This option guarantees the
  following:

  - The final conditioning operation applied to the interrupt entropy source
    as well as to the auxiliary pool require 64 additional bits of entropy
    when obtaining data for the temporary seed buffer. This complies with the
    requirement specified in section 4.3.2 SP800-90C about vetted conditioning
    components. This ensures the conditioning components provide full
    entropy.

  - When the DRNG is initially seeded, it is attempted to be seeded with 384
    bits of entropy at least. This complies with the requirement specified in
    section 6.2.1 bullet 2 of SP800-90C requiring 3/2s bits of entropy for the
    initial seeding. Note, the ESDM applies a stepwise seeding of 32, 128 and
    256 bits of entropy during initialization. When the final step of 256 bits
    is to be performed, the ESDM will guarantee that at least 384 bits of
    entropy are collectively pulled from all entropy sources. Only if this is
    achieved, the SP800-90C compliant-marked interfaces of the ESDM specified
    in section @sec:health-tests will produce random numbers.

- Enable `es_irq` to use the interrupt entropy source compliant to SP800-90B as
  outlined in section @sec:90b-config if the interrupt entropy source is
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

- The ESDM must be compiled with the meson configuration option of
  `es_cpu_entropy_rate=0` or unset the option `es_cpu` unless the CPU-based
  entropy source (e.g. RDSEED on Intel) has an SP800-90B compliant entropy
  assessment and comply with all requirements from SP800-90B.

- The ESDM must be compiled with the meson configuration option of
  `es_hwrand_entropy_rate=0` or unset the option `es_hwrand` unless the
  HWRAND entropy source has an SP800-90B compliant entropy assessment and
  comply with all requirements from SP800-90B.

- The ESDM must be compiled with the kernel configuration option of
  `es_jent_entropy_rate=0` or unset the option `es_jent` unless the Jitter RNG
  entropy source has an SP800-90B compliant entropy assessment and comply with
  all requirements from SP800-90B#footnote[At the time of writing, the user
  space Jitter RNG is SP800-90B compliant. Patches ensuring the in-kernel
  variant is SP800-90B compliant as well when into the kernel for version
  5.8.].

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- Filling up the ESDM with entropy using either a user-space RNGD via the
  IOCTL `RNDADDENTROPY` is allowed. However, the caller is only allowed to
  claim entropy associated with the data and thus increase the ESDM entropy
  estimation if the entropy source is SP800-90B compliant with its own entropy
  assessment.

#par(first-line-indent: 0pt)[To verify that the SP800-90C compliance is
achieved, the file /proc/sys/kernel/random/esdm\_type provides an appropriate
status indicator. The SP800-90C compliant is ensured only for the respectively
marked ESDM interfaces specified in section @sec:health-tests. All other
interfaces are not providing SP800-90C compliant random numbers.]

It is permissible to use the ESDM DRBG output to seed another DRBG when using
the prediction resistance `esdm_rpcc_get_random_bytes_pr` RPC API call, using
`getrandom(2)` with the `GRND_RANDOM` flag, or opening /dev/random with the
`O_SYNC` flag. See the details given for the API call
`esdm_get_entropy_bytes_pr` in section @sec:irq-assessment.

=== FIPS 140 Compliant Configuration <sec:fips140-config>

FIPS 140 compliance is only achieved when all of the following settings are
achieved.

The following compile-time settings must be observed:

- The meson configuration option `fips140` is set. This option guarantees the
  following:

  - The option `sp80090c` is automatically enabled.

  - Power-on self tests are performed

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The ESDM along with the scheduler and/or interrupt ES must be operated in
  FIPS mode to ensure the oversampling for the conditioning and the initial
  seeding of the DRBG is applied. This is achieved with the kernel command
  line option of `fips=1`, or the environment variable
  `ESDM_SERVER_FORCE_FIPS` is set when starting the ESDM server.

== AIS 20 / 31 <sec:ais2031>

The German BSI defines construction methods of RNGs with AIS 20/31 with the
revision from 2011. In particular, this document defines different classes of
RNGs where the ESDM is capable of meeting class NTG.1. The NTG.1 compliance is
achieved when using /dev/random with the `O_SYNC` flag during opening, by
using `getrandom(2)` with the `GRND_RANDOM` flag, or by using the
`esdm_rpcc_get_random_bytes_pr` RPC API call.

The NTG.1 from AIS 20/31 of 2011 requirements are met as follows:

- NTG.1.1: The ESDM offers interfaces to collect raw unconditioned entropy as
  outlined in section @sec:test-interfaces.

- NTG.1.2: The ESDM maintains an entropy estimator for the auxiliary pool as
  well as each entropy pool. The credit operation of the ESDM is documented in
  section @sec:components. To outline the debit operation section
  @sec:90b-3151 provides several examples showing the approach. For each of
  the fast entropy sources, the ESDM obtains the entropy estimate when
  fetching data from them and applies this estimate when seeding the DRNG.

- NTG.1.3: The ESDM provides a compile-time switchable DRNG support using an
  SP800-90A Hash DRBG with a SHA-512 core. Furthermore, the ESDM allows using
  a ChaCha20-based DRNG which is documented in section @sec:chacha20. All those
  DRNGs are characterized as DRG.3 since they all support backward secrecy and
  use contemporary cryptographic primitives for the state transition as well
  as output generation.

- NTG.1.4: Due to the blocking behavior and only returning as many bits of
  data as entropy is available via /dev/random opened with `O_SYNC`, or
  `getrandom(2)` with the flag `GRND_RANDOM` the ESDM meets the requirement.

- NTG.1.5: The output functions of the offered DRNGs are all based on
  contemporary cryptographic primitives. Therefore, the output is assumed that
  it cannot be distinguished from random number output sequences of an ideal
  RNG. This is supported by the fact that the SP800-90A DRBGs are successfully
  passing the NIST CAVP test suite. The ChaCha20 DRNG can be tested using the
  #link("https://www.chronox.de/chacha20_drng.html")[ChaCha20 DRNG stand-alone
  implementation] which is derived from the ESDM implementation. The tester
  can verify that both operate identical because the power-on self test in the
  stand-alone ChaCha20 DRNG implementation is identical to the ESDM power-up
  self test found in ESDM\_selftest.c.

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

- The caller must use /dev/random and open it with `O_SYNC`, the
  `getrandom(2)` API call with the flag `GRND_RANDOM`, or the
  `esdm_rpcc_get_random_bytes_pr` RPC API call is used.

#par(first-line-indent: 0pt)[To verify that the NTG.1 compliance is achieved,
the file /proc/sys/kernel/random/esdm\_type provides an appropriate status
indicator. The NTG.1 compliant is ensured only for the respectively marked
ESDM interfaces specified in section @sec:90b-config. All other interfaces are
not providing NTG.1 compliant random numbers.]

=== NTG.1 (AIS 20/31 2022) Compliant Configuration <sec:ntg1-2022>

To achieve NTG.1 compliant operation, the following configuration must be
applied. It is permissible to use the configuration in parallel with the
SP800-90B and SP800-90C configurations.

The following compile-time settings must be observed for AIS 20/31 (2022):

- The ESDM compile time option of `ais2031` must be enabled.

- The ESDM must have access to two entropy sources which are capable of
  delivering 220 bits of entropy each. For example, the interrupt entropy
  source can deliver 220 bits of entropy unless being operated with SHA-1 on
  old Linux kernels (see section @sec:data-processing for details on SHA-1).
  In addition, the Jitter RNG entropy source is capable of delivering 220 bits
  of entropy when booting the kernel with the kernel compile-time option of
  `es_jent_entropy_rate=220` or a larger value. See section @sec:jent-entropy
  for details on the Jitter RNG entropy rate.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- None.

#par(first-line-indent: 0pt)[To verify that the NTG.1 compliance is achieved,
the file /proc/sys/kernel/random/esdm\_type provides an appropriate status
indicator. The NTG.1 compliant is ensured only for the respectively marked
ESDM interfaces specified in section @sec:90b-config. All other interfaces are
not providing NTG.1 compliant random numbers.]

=== DRG.4 / PTG.3 Compliant Configuration <sec:drg4-ptg3>

The ESDM allows a configuration that would make the ESDM compliant to the
requirements of a DRG.4 as well as a PTG.3. This is achieved by deconfiguring
all entropy sources except one that provides the data from a PTG.2 entropy
source. For example, an rngd can be created having access to a smart card that
is provides a PTG.2 entropy source. In this case, all other entropy sources
must be deactivated using the following runtime configuration.

The PTG.3 naturally can only be claimed if the PTG.2 entropy source is part of
the validation. If the PTG.2 entropy source is not part of the validation, a
DRG.4 must be claimed instead.

For achieving such compliance claim, the following compile-time configuration
must be applied:

- The kernel command line must contain the following setting to ensure the
  interrupt entropy source is not credited with entropy:
  `es_irq_entropy_rate=0`.

- Configure the Jitter RNG entropy source to not credit entropy: boot the
  kernel with the ESDM compile-time option of `es_jent_entropy_rate=0`. If the
  value is set to 0, the entropy source is disabled.

- Adjust the entropy rate of the CPU entropy source to zero: boot the kernel
  with the ESDM compile-time option of `es_cpu_entropy_rate=0`. If the value
  is set to 0, the entropy source is disabled.

- Adjust the entropy rate of the HWRAND entropy source to zero: boot the
  kernel with the ESDM compile-time option of `es_hwrand_entropy_rate=0`. If
  the value is set to 0, the entropy source is disabled.

#par(first-line-indent: 0pt)[The following requirements apply to the runtime
configuration:]

- The PTG.2 entropy source delivers its entropy to the ESDM via either the
  `esdm_rpcc_rnd_add_entropy` RPC API call or via the /dev/random IOCTL
  `RNDADDENTROPY.`
