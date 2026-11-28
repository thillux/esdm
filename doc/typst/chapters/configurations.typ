#import "../template.typ": *

= Compliant Configurations <sec:configurations>

This chapter is for auditors and for those who configure the #ac("ESDM") for a
regulated environment. It states which interface meets which class of
#ac("SP") 800-90C, #ac("FIPS") 140-3 and #ac("AIS") 20/31 under which build
options (section @sec:interface-classes), gives each compliant configuration
with its compile-time settings, its runtime settings and how to verify it, shows
them as worked examples (section @sec:examples), and states what the #ac("ESDM")
does not claim (section @sec:limits).

== Interfaces and Classes <sec:interface-classes>

The #ac("ESDM") serves random numbers along four paths (figure @fig:paths).
Which class an interface meets follows from its path, from the build options and
from the output actually coming from the #ac("ESDM"): some interfaces fall back to
the kernel #ac("RNG").

/ Full: a node #ac("DRNG") or the initial #ac("DRNG") (section @sec:numa). The
  caller waits until the #ac("ESDM") is operational, i.e. until its initial
  #ac("DRNG") is fully seeded.

/ Plain: the same #ac("DRNG", pl: true), without waiting: before the #ac("ESDM")
  is operational, the request fails.

/ Prediction resistance: a #ac("DRNG") instance of its own, reseeded before
  every chunk of output. A chunk holds at most as many bits as fresh entropy
  went into the reseed – less the 64 bits of oversampling where it applies – and
  at most 256 bits. The caller waits until the #ac("ESDM") is operational.

/ Seed: the conditioned data of the entropy sources, for the #ac("DRNG") of the
  caller. The answer states the bits of entropy it carries, which may be
  fewer than requested.

#figure(
  image("../figures/paths.svg", width: 84%),
  caption: [The interfaces, their paths and the #ac("DRNG") instances behind
  them],
) <fig:paths>

#figure(
  table(columns: (1.6fr, 1fr, 1fr, 1fr, 1.2fr, 1.2fr),
    align: (x, y) => (if x == 0 { left } else { center }) + horizon,
    table.header([Path], [DRG.3], [DRG.4], [NTG.1], [#ac("SP", cap: true)
    800-90C],
      [Seeds a #ac("DRNG")]),
    [Full], [#yes[a]], [#yes[b]], [–], [#yes[c]], [–],
    [Plain], [#yes[a, d]], [#yes[b, d]], [–], [#yes[c, d]], [–],
    [Prediction resistance], [#yes[a]], [#yes[b]], [#yes[e]], [#yes[c]],
      [#yes[f]],
    [Seed], [–], [–], [–], [–], [#yes[g]],
  ),
  caption: [Classes of the four paths],
) <tab:path-classes>

#par(first-line-indent: 0pt)[The conditions of table @tab:path-classes:]

#[
#set enum(numbering: "(a)")
+ Built with `ais2031_drg3` or `ais2031_drg4`. All #ac("DRNG", pl: true) of the
  #ac("ESDM") implement DRG.3 (section @sec:ais2031); the options add the
  oversampling of the initial seed (section @sec:drg3-drg4).

+ Built with `ais2031_drg4`, and only physical entropy sources credited
  (section @sec:physical-es).

+ Built with `sp80090c`, `fips140` or `ais2031_drg4` – not `ais2031_drg3` –
  and with the entropy sources of section @sec:90c-config credited.

+ Only for output the #ac("ESDM") served: before the #ac("ESDM") is operational,
  the #ac("CUSE") `/dev/urandom` and `getrandom(2)` with `GRND_INSECURE` serve
  the kernel #ac("RNG") instead (table @tab:interfaces).

+ Built with `ais2031_ntg1`, where the #ac("ESDM") becomes operational only
  after two entropy sources have delivered 240 bits each, or with `es_jent_ntg1`,
  where the Jitter #acs("RNG") applies that rule internally (section
  @sec:ntg1-2022). No chunk carries more bits than entropy went into it.

+ The output may seed another #ac("DRBG"), in #ac("FIPS") mode as #ac("FIPS")
  140-3 #ac("IG") D.K allows, and the root #ac("DRNG") of a DRT.1 tree (section
  @sec:drt1).

+ Entropy for the #ac("DRNG") of the caller, no output of an #ac("RNG") class
  itself: check the bits of entropy the answer states.
]

#par(first-line-indent: 0pt)[Table @tab:interfaces assigns every interface
to its path and states what it serves while the #ac("ESDM") server cannot be
reached. Its output carries a claim of this chapter only when the #ac("ESDM")
served it.]

#figure(
  table(columns: (2fr, 1.1fr, 1.6fr), align: left + horizon,
    table.header([Interface], [Path], [#ac("ESDM", cap: true) server
    unreachable]), [#ac("CUSE", cap: true) `/dev/random`], [Full], [kernel
    `/dev/random`], [#ac("CUSE", cap: true) `/dev/urandom`], [Plain, then waits
    like Full while all #ac("DRNG", pl: true)
      reseed], [kernel `/dev/urandom`, also before the #ac("ESDM") is
      operational],
    [#ac("CUSE", cap: true) `/dev/random`, `/dev/urandom` with `O_SYNC`],
      [Prediction resistance], [kernel device],
    [`getrandom(2)` with flags 0, `getentropy(3)`], [Full],
      [kernel `getrandom(2)`],
    [`getrandom(2)` with `GRND_INSECURE`], [Plain],
      [kernel `getrandom(2)`, also before the #ac("ESDM") is operational],
    [`getrandom(2)` with `GRND_RANDOM`], [Prediction resistance],
      [kernel `getrandom(2)`],
    [`getrandom(2)` with `GRND_SEED`], [Seed], [fails],
    [`esdm_cdev` `/dev/esdm_random`], [Full], [waits],
    [`esdm_cdev` `/dev/esdm_urandom`], [Plain], [fails],
    [`esdm_cdev` devices with `O_SYNC`, `/dev/esdm_pr`],
      [Prediction resistance], [waits; `/dev/esdm_pr` with `O_NONBLOCK`:
      `EAGAIN`],
    [`esdm_rpcc_get_random_bytes_full`, `_noblock`, `_timeout`], [Full],
      [fails],
    [`esdm_rpcc_get_random_bytes`], [Plain], [fails],
    [`esdm_rpcc_get_random_bytes_pr`, `_noblock`],
      [Prediction resistance], [fails],
    [`esdm_rpcc_get_seed`], [Seed], [fails],
    [#ac("EGD", cap: true) commands 0x01, 0x02], [Full], [fails],
    [#ac("EGD", cap: true) 0xe0, 0xe1; 0x01, 0x02 on the prediction resistance
    socket],
      [Prediction resistance], [fails],
    [#ac("EGD", cap: true) 0xe2], [Plain, empty before the #ac("ESDM") is
    operational], [fails], [OpenSSL `libesdm-rng-provider.so`,
    `libesdm-seed-src-provider.so`],
      [Full; prediction resistance when OpenSSL asks for it],
      [OpenSSL error],
    [OpenSSL `libesdm-rng-provider-pr.so`, `libesdm-egd-provider-pr.so`],
      [Prediction resistance], [OpenSSL error],
    [OpenSSL `libesdm-egd-provider.so`], [Full; refuses prediction
      resistance], [OpenSSL error],
  ),
  caption: [The path of each interface],
) <tab:interfaces>

#par(first-line-indent: 0pt)[The status of the #ac("ESDM") lists the classes the
build provides in the line "Standards compliance" of `esdm-tool --status`,
`esdm_rpcc_status`, `/proc/sys/kernel/random/esdm_type` and
`/proc/esdm/status`, and in the array
`standards_compliance` of their #ac("JSON") form; section @sec:examples shows
the line for each configuration. The interfaces that deliver a class are those
of table @tab:path-classes.]

== SP 800-90C Compliance <sec:sp80090c>

#ac("SP", cap: true) 800-90C @sp80090c defines construction methods for
non-deterministic and deterministic #ac("RNG", pl: true). This section follows
its final version of September 2025.

#ac("SP", cap: true) 800-90C defines different types of #ac("RNG", pl: true).
They map to the #ac("ESDM") in these ways:

- The #ac("ESDM") follows the RBG2(NP) construction. It concatenates the outputs
  of these entropy sources:

  - Auxiliary external entropy sources, such as a user space rngd, if
    available. If such a source alters the entropy estimator of the #ac("ESDM")
    via the `RNDADDENTROPY` #ac("IOCTL") or the `esdm_rpcc_rnd_add_entropy`
    #ac("RPC") #ac("API") call, the administrator must ensure that it complies
    with #ac("SP") 800-90B. Depending on the selected source, it may be a
    physical or non-physical entropy source. A conditioning component, the
    XDRBG-256 based on SHAKE256, processes all data of the auxiliary pool. For
    full #ac("SP") 800-90C compliance, only one such source should therefore
    feed data credited with entropy into the auxiliary pool.

  - The interrupt and the scheduler entropy sources of the kernel module
    `esdm_es` are fully maintained as part of the #ac("ESDM"). They share one
    full entropy analysis following section @sec:sp80090b, and this document
    claims both to be compliant with #ac("SP") 800-90B, given the measurements
    of section @sec:90b-reuse on the target system. By default, the #ac("ESDM")
    credits the interrupt entropy source; the scheduler entropy source is
    neither built nor credited unless configured.

  - The #acs("eBPF")-based interrupt and scheduler entropy sources are fully
    maintained as part of the #ac("ESDM"). The administrator must determine
    their entropy rate for the deployment environment as outlined in chapter
    @sec:ebpf-assessment. Until then, the #ac("ESDM") credits them with no
    entropy, the default of the meson configuration options
    `es_irq_ebpf_entropy_rate` and `es_sched_ebpf_entropy_rate`. At most one
    of the four interrupt-based and scheduler-based entropy sources –
    `es_irq`, `es_sched`, `es_irq_ebpf` and `es_sched_ebpf` – may be
    credited with entropy: the build refuses two non-zero rates, and a
    non-zero rate set at runtime sets the other three to zero.

  - The #ac("ESDM") uses the Jitter #acs("RNG") entropy source, a fully
    self-contained #ac("SP") 800-90B entropy source. Its #ac("SP") 800-90B
    compliance must be assessed separately. If it cannot be demonstrated, the
    administrator must credit the Jitter #acs("RNG") with zero bits of entropy
    with the configuration documented in section @sec:jent-entropy, or disable
    it completely by not selecting the meson configuration option `es_jent`.

  - The #ac("ESDM") uses the kernel Jitter #acs("RNG") entropy source if the
    meson configuration option `es_jent_kernel` is selected. It obtains data
    from the Jitter #acs("RNG") of the kernel crypto #ac("API"). Its #ac("SP")
    800-90B compliance must be assessed separately. If it cannot be
    demonstrated, the administrator must credit it with zero bits of entropy
    with the meson configuration option `es_jent_kernel_entropy_rate=0`, or
    disable it completely.

  - The #ac("ESDM") uses the #ac("CPU") entropy source, if available. On Intel,
    it uses RDSEED. This entropy source is a fully self-contained #ac("SP")
    800-90B entropy source. Its #ac("SP") 800-90B compliance must be assessed
    separately. If it cannot be demonstrated, the administrator must credit it
    with zero bits of entropy with the configuration documented in section
    @sec:cpu-entropy, or disable it completely by not selecting the meson
    configuration option `es_cpu`.

  - The #ac("ESDM") uses the Linux kernel #ac("RNG") entropy source. As the
    kernel #ac("RNG") does not comply with #ac("SP") 800-90B, the #ac("ESDM")
    credits it with zero bits of entropy when operating in compliance with
    #ac("SP") 800-90C.

  - The #ac("ESDM") uses the Linux #ac("HWRAND") entropy source, if available.
    Its #ac("SP") 800-90B compliance must be assessed separately. If it cannot
    be demonstrated, the administrator must credit it with zero bits of entropy
    with the meson configuration option `es_hwrand_entropy_rate=0`, the
    default, or disable it completely by not selecting the meson
    configuration option `es_hwrand`.

  - The #ac("ESDM") uses the #ac("TPM") 2.0 entropy source, if available. Its
    #ac("SP") 800-90B compliance must be assessed separately. If it cannot be
    demonstrated, the administrator must credit it with zero bits of entropy
    with the meson configuration option `es_tpm2_entropy_rate=0`, the default,
    or disable it completely by not selecting the meson configuration option
    `es_tpm2`.

  - The #ac("ESDM") uses the external entropy source (section @sec:ext-es) if a
    provider socket is configured with the meson configuration option
    `es_ext_path` or the `esdm-server` option `--es_ext`. The provider is a
    separate process, such as `esdm-es-pkcs11` serving the random number
    generator of a #acs("PKCS")\#11 token or `esdm-es-pcsc` serving a smart
    card. Its #ac("SP") 800-90B compliance must be assessed separately. If it
    cannot be demonstrated, the administrator must credit it with zero bits of
    entropy with the meson configuration option `es_ext_entropy_rate=0` or the
    `esdm-server` option `--es_ext_entropy_rate 0`.

  Method 2 (non-physical inclusive) of #ac("SP") 800-90C section 2.3 adds the
  entropy of all entropy sources. The #ac("ESDM") applies it when it
  concatenates their output in the temporary seed buffer, as equation @eq:t
  shows (#ac("SP") 800-90C section 3.1 item 3). The data of the entropy sources
  credited with zero bits of entropy is not part of the seed: the #ac("ESDM")
  inserts it into the #ac("DRBG") as additional input, as #ac("SP") 800-90C
  section 2.6 item 2 allows for non-validated entropy sources. The #ac("ESDM")
  fetches this data into a buffer of its own, separate from the seed, as
  #ac("SP") 800-90C section 3.1 item 1 requires.

- When instantiating the #ac("DRBG"), the #ac("ESDM") tries to seed it with at
  least (#ac("DRBG") security strength) + 128 bits = 384 bits of entropy. Only
  after the #ac("DRBG") has obtained this amount of entropy does the #ac("ESDM")
  consider it fully seeded and let it produce output.

  The #ac("DRNG") instance of the prediction resistance path is reseeded before
  every chunk of output. Section @sec:90c-constructions gives the
  construction each path meets, section @sec:rbgc the #ac("DRBG") trees the
  #ac("ESDM") seeds.

- Writing data into `/dev/random` while not all #ac("DRNG", pl: true) are fully
  seeded, or the `RNDRESEEDCRNG` #ac("IOCTL"), triggers a reseed of the
  #ac("DRBG"). Operated in compliance with #ac("SP") 800-90C, the #ac("ESDM")
  reseeds only if at least 256 bits of entropy are available. Otherwise, it
  attempts the reseed during the next generate operation. The generate operation
  proceeds in any case until it reaches the request size based limits outlined
  below. Notwithstanding, the #ac("ESDM") always attempts to obtain 256 bits of
  entropy for reseeding. This is considered appropriate because a reseed is
  ultimately triggered after $2^20$ generate operations or after 10 minutes,
  whichever comes first. If the #ac("DRNG") cannot be reseeded, it continues to
  operate until it reaches this threshold the next time. The #ac("DRNG") reverts
  to an unseeded state if it cannot be reseeded by the time it has serviced $2^30$
  generate requests since the last successful seeding. In addition, an #ac("SP")
  800-90C compliant build applies request size based limits: a #ac("DRNG")
  starts no request after it has generated $2^17$ bits without a successful reseed –
  it completes a request started before – and attempts a reseed after 98,304
  bits, three quarters of that limit, unless smaller values are configured with
  the meson configuration options `drng_reseed_threshold_bits` and
  `drng_max_reseed_bits`. Furthermore, an asynchronous reseed worker reseeds
  every #ac("DRNG") once its reseed interval has elapsed, whether or not data is
  requested from it.

#par(first-line-indent: 0pt)[How the #ac("ESDM") meets the requirements for an
RBG2 construction of #ac("SP") 800-90C section 5.3:]

+ The administrator must use an #ac("SP") 800-90A #ac("DRBG"), such as the Hash
  #ac("DRBG") of the default configuration. Technically, any #ac("DRBG")
  security strength could be chosen, yet the #ac("ESDM") interfaces support only
  the highest security strength of 256 bits, so that the #ac("ESDM") suits all
  use cases.

+ The #ac("DRBG") can be #acs("ACVTS")-tested to show compliance with #ac("SP")
  800-90A. The entropy sources must be assessed pursuant to #ac("SP") 800-90B,
  as the list above outlines.

+ If an entropy source is not validated, its entropy estimate must be set
  to zero, as the list above outlines. Its data is then not part of the
  seed but additional input, as described above.

+ The #ac("DRBG") provides output only once it is fully seeded.

+ The #ac("ESDM") reseeds the #ac("DRBG") from the same entropy sources it
  instantiates it from; the list above describes the reseeding support.

+ An #ac("SP") 800-90C compliant build starts no generate request of a
  #ac("DRNG") after it has generated $2^17$ bits without a successful reseed (see
  the reseeding limits above).

+ Not applicable: the #ac("ESDM") does not use a #ac("CTR") #ac("DRBG") without
  a derivation function. With the GnuTLS crypto backend, whose #ac("CTR")
  #ac("DRBG") has none, the #ac("ESDM") applies the block cipher derivation
  function of #ac("SP") 800-90A and provides the #ac("CTR") #ac("DRBG") with
  seed material of exactly its seed length.

+ The #ac("ESDM") attempts to instantiate a #ac("DRBG") with $3s \/ 2$ bits of
  entropy. Only if this succeeds does the #ac("DRBG") become available. The
  #ac("ESDM") attempts to reseed a #ac("DRBG") with $s$ bits of entropy. The
  rationale above discusses the minimum entropy of 256 bits for a reseed.

+ RBG2(P): see section @sec:rbg2p for the configuration in which only
  physical entropy sources are credited with entropy (Method 1).

+ RBG2(NP): the list above names the entropy sources. By concatenating the
  output of all entropy sources, the #ac("ESDM") implements Method 2 of
  #ac("SP") 800-90C section 2.3: it adds the entropy of all entropy sources.

+ The #ac("ESDM") destroys the entropy source output immediately after using it
  to (re)seed the #ac("DRBG").

+ An error in the interrupt entropy source triggers a reset of that entropy
  source, as outlined in section @sec:health-tests. If the other entropy
  sources suffer a health test failure, #ac("SP") 800-90B mandates that they
  produce no entropy. Before it is seeded, the #ac("DRBG") undergoes a self
  test. The #ac("ESDM") performs the self tests of section @sec:self-tests at
  start-up, in every mode, and repeats them every 10 minutes. The #ac("ESDM")
  provides random numbers only as long as the self tests of the cryptographic
  primitives pass.

=== Constructions of the Paths <sec:90c-constructions>

Figure @fig:90c-constructions shows the #ac("ESDM") in the terms of #ac("SP")
800-90C. Every entropy source is an #ac("SP") 800-90B entropy source with a
security boundary of its own: a noise source, its health tests and, where it has
one, a conditioning component, such as the XDRBG-256 of the kernel module
`esdm_es` or the SHAKE-256 of the Jitter #acs("RNG"). #ac("SP", cap: true)
800-90B calls this conditioning internal. The #ac("ESDM") concatenates the
output of the entropy sources in the temporary seed buffer $T_n$ (equation
@eq:t), the Get_entropy_bitstring process of #ac("SP") 800-90C section 3.1, and
seeds a #ac("DRBG") with it. This seeding conditions the data a second time,
outside of the entropy sources: #ac("SP") 800-90C section 3.2 calls it external
conditioning. #ac("DRBG", cap: true) output holds full entropy when,
immediately before, at least 64 bits more fresh entropy went into the
#ac("DRBG") than it outputs (#ac("SP") 800-90C section 2.6 item 11).

#figure(
  image("../figures/sp80090c-constructions.svg", width: 85%),
  caption: [The constructions of #ac("SP") 800-90C in the #ac("ESDM") and the
  RBGC tree it
    seeds],
) <fig:90c-constructions>

#par(first-line-indent: 0pt)[Which construction a path meets depends on
the kind of the credited entropy sources (section @sec:physical-es):]

#figure(
  table(columns: (1.2fr, 1fr, 1.3fr), align: left + horizon,
    table.header([Path], [Only physical sources credited (Method 1)],
      [Non-physical sources credited (Method 2)]),
    [Full, plain], [RBG2(P)], [RBG2(NP)],
    [Prediction resistance], [RBG3(RS)],
      [RBG2(NP) with prediction resistance],
    [Seed], [–: entropy source data for the #ac("DRBG") of the caller], [–],
  ),
  caption: [#ac("SP", cap: true) 800-90C constructions of the paths],
) <tab:90c-constructions>

#ac("SP", cap: true) 800-90C grants full entropy only to RBG3 constructions,
which count the entropy of physical entropy sources alone (#ac("SP") 800-90C
section 6.3 requirement 1). With the default rates, the #ac("ESDM") credits
mostly non-physical sources: its prediction resistance path is then an RBG2(NP)
construction with prediction resistance and claims no full entropy under
#ac("SP") 800-90C. #ac("AIS", cap: true) 20/31 has no such restriction: section
@sec:ntg1-pr shows the same path as an NTG.1 #ac("RNG").

With only physical sources credited, the #ac("DRNG") instance of the prediction
resistance path meets the requirements of an RBG3(RS) construction of
#ac("SP") 800-90C sections 6.3 and 6.5.2:

#figure(
  table(columns: (auto, 1.3fr, 1.7fr), align: left + horizon,
    table.header([Requirement], [Gist], [#ac("ESDM", cap: true)]),
    [6.3 item 1], [Physical entropy sources, Method 1],
      [Credit only physical sources (section @sec:rbg2p)],
    [6.3 item 4], [#ac("DRBG", cap: true) at its highest security strength
    before first use],
      [256 bits, instantiated with $3s \/ 2 = 384$ bits before its first
      output],
    [6.3 item 6], [$3s \/ 2$ bits to instantiate, $s$ bits to reseed],
      [384 bits, then 320 bits for every reseed],
    [6.3 item 7], [Entropy source output used once],
      [The #ac("ESDM") destroys the seed buffer after each seeding],
    [6.5.2 item 1], [$s + 64$ bits of fresh entropy for $s$ bits of
      output], [A chunk holds at most the injected entropy less 64 bits,
      at most 256 bits],
    [6.5.2 item 2], [A request completes before the next starts],
      [One request at a time; a concurrent one gets `-EAGAIN`],
    [6.5.2 item 3], [Reseed before direct access to the #ac("DRBG")],
      [Not applicable: the #ac("DRBG") instance serves only this path],
  ),
  caption: [RBG3(RS) requirements and the prediction resistance path],
) <tab:rbg3rs>

=== DRBG Trees: RBGC <sec:rbgc>

#ac("SP", cap: true) 800-90C section 7 specifies trees of #ac("DRBG", pl: true)
on one computing platform, the RBGC construction; #ac("AIS") 20/31 calls them
DRT.1 (section @sec:drt1). The #ac("ESDM") serves as the initial randomness
source of the root RBGC construction, for which #ac("SP") 800-90C section
7.1.2.1 accepts an RBG2(P), RBG2(NP), RBG3(#ac("XOR")) or RBG3(RS) construction
(figure @fig:90c-constructions). Roots are, for example:

- the #ac("DRNG") of a caller seeded with `esdm_rpcc_get_random_bytes_pr` or
  with `getrandom(2)` and `GRND_RANDOM`;

- OpenSSL's primary #ac("DRBG") behind `libesdm-seed-src-provider.so` (section
  @sec:integration-openssl), whose public and private #ac("DRBG", pl: true) are
  non-root RBGC constructions.

#par(first-line-indent: 0pt)[The root and the #ac("ESDM") meet the requirements
of #ac("SP") 800-90C section 7.3 this way:]

- Seed the root from the prediction resistance path. It reseeds before every
  chunk, as section 7.3.2 requirement 3 asks of an RBG2 construction serving
  as initial randomness source, and one #ac("DRBG") instance serves it. The full
  path is served by whichever #ac("DRNG") instance is free (section @sec:numa)
  and reseeds on its own schedule; OpenSSL's primary #ac("DRBG") reads it unless
  OpenSSL asks for prediction resistance.

- Instantiate the root with $3s \/ 2 = 384$ bits and reseed it with
  $s = 256$ bits (section 7.3.2 requirement 1), at a security strength of
  at most 256 bits, that of the #ac("ESDM") (requirement 6). A chunk of the
  prediction resistance path holds at most 256 bits: the caller repeats the
  request until it holds the bits it needs.

- Keep the tree on one computing platform (section 7.3.1 requirements 8
  to 11): the root reads the #ac("ESDM") over its local sockets and devices,
  never over a network, and neither its seed nor its state leaves the platform.
  Section @sec:host-guest discusses a guest.

- Avoid seed loops (section 7.3.1 requirement 16): the output of a #ac("DRBG") of
  the tree never returns to the #ac("ESDM") as credited entropy, e.g. with
  `RNDADDENTROPY` or `esdm_rpcc_rnd_add_entropy`.

#par(first-line-indent: 0pt)[Table @tab:path-classes (condition (f)) states
when the output of the prediction resistance path may seed another #ac("DRBG")
in #ac("FIPS") mode.]

=== RBG2(P) Construction Method <sec:rbg2p>

The #ac("ESDM") can be configured as an RBG2(P) of #ac("SP") 800-90C. This
requires that only physical entropy sources are credited with entropy. In
addition to the general configuration of the next section, the administrator
must apply these settings:

- Configure the interrupt entropy source to be credited with no entropy:
  compile the #ac("ESDM") with the meson configuration option
  `es_irq_entropy_rate=0`. The
  interrupt entropy source then still collects data, but the #ac("ESDM") credits
  it with no entropy. To disable it completely, unset the compile-time option
  `es_irq`.

- Configure the scheduler entropy source to be credited with no entropy:
  compile the #ac("ESDM") with the meson configuration option
  `es_sched_entropy_rate=0`. The
  scheduler entropy source then still collects data, but the #ac("ESDM") credits
  it with no entropy. To disable it completely, unset the compile-time option
  `es_sched`.

- Configure the #acs("eBPF")-based interrupt and scheduler entropy sources to
  be credited with no entropy: compile the #ac("ESDM") with the meson
  configuration options `es_irq_ebpf_entropy_rate=0` and `es_sched_ebpf_entropy_rate=0`, the
  defaults. To disable them completely, unset the compile-time options
  `es_irq_ebpf` and `es_sched_ebpf`, the defaults.

- Configure the Jitter #acs("RNG") entropy source to be credited with no
  entropy: compile
  the #ac("ESDM") with the meson configuration option `es_jent_entropy_rate=0`.
  With the value 0, the entropy source still collects data, but the #ac("ESDM")
  credits it with no entropy. To disable it completely, unset the compile-time
  option `es_jent`.

- Configure the kernel #ac("RNG") entropy source to be credited with no
  entropy: compile the #ac("ESDM") with the meson configuration option
  `es_kernel_entropy_rate=0`. With the value 0, the entropy source still
  collects data, but the #ac("ESDM") credits it with no entropy. To disable it
  completely, unset the compile-time option `es_kernel`.

- Configure the kernel Jitter #acs("RNG") entropy source to be credited with
  no entropy: compile the #ac("ESDM") with the meson configuration option
  `es_jent_kernel_entropy_rate=0`. To disable it completely, unset the
  compile-time option `es_jent_kernel`, the default.

- Adjust the entropy rate of the #ac("CPU") entropy source as needed: compile
  the #ac("ESDM") with the meson configuration option `es_cpu_entropy_rate=256`
  when the #ac("CPU") entropy source is assumed to provide full entropy. In
  general, set any value between 0 and 256 if the default value is not
  appropriate. With the value 0, the entropy source still collects data, but the
  #ac("ESDM") credits it with no entropy. To disable it completely, unset the
  compile-time option `es_cpu`.

- Adjust the entropy rate of the #ac("HWRAND") entropy source as needed: compile
  the #ac("ESDM") with the meson configuration option
  `es_hwrand_entropy_rate=256` when the configured #ac("HWRAND") entropy source
  is assumed to provide full entropy. Ensure that the intended #ac("HWRAND")
  entropy source is set in `/sys/devices/virtual/misc/hw_random/rng_current`. In
  general, set any value between 0 and 256 if the default value is not
  appropriate. With the value 0, the entropy source still collects data, but the
  #ac("ESDM") credits it with no entropy. To disable it completely, unset the
  compile-time option `es_hwrand`.

- Adjust the entropy rate of the #ac("TPM") 2.0 entropy source as needed:
  compile the #ac("ESDM") with the meson configuration option
  `es_tpm2_entropy_rate=256` when the #ac("TPM") 2.0 is assumed to provide full
  entropy. In general, set any value between 0 and 256 if the default value of 0
  is not appropriate. To disable it completely, unset the compile-time option
  `es_tpm2`.

- Adjust the entropy rate of the external entropy source as needed: the
  #ac("ESDM") credits each block with the entropy its provider claims, capped at
  a rate per 256 bits of data. The meson configuration option
  `es_ext_entropy_rate` or the `esdm-server` option `--es_ext_entropy_rate` sets
  this cap. With the default of -1, the rate the provider declares is the cap,
  or 0 if it declares none. Only a provider serving a physical entropy source
  may be credited with entropy.

- If other hardware entropy sources are considered to deliver entropy, they
  may inject data into the #ac("ESDM") via the #ac("IOCTL") `RNDADDENTROPY`, the
  #ac("RPC") #ac("API") call `esdm_rpcc_rnd_add_entropy`, or as an external
  entropy source. Only data of physical entropy sources may be credited with
  entropy. Any other data fed into the #ac("ESDM") via those interfaces must not
  be credited with entropy.

#par(first-line-indent: 0pt)[Important note: the #ac("CPU") entropy source and
all other physical entropy sources together must provide sufficient entropy,
i.e. the security strength of the #ac("ESDM"): 256 bits, that of its
#ac("DRNG", pl: true). The XDRBG-256 based on SHAKE256 that conditions the
entropy does not lower it, as its state holds 512 bits. As the #ac("SP") 800-90C
configuration oversamples the initial seed of a #ac("DRNG"), they must provide
384 bits for it (section @sec:90c-config).]

The hardware entropy sources credited with entropy must comply with
#ac("SP") 800-90B.

With the RBG2(P) configuration, the #ac("ESDM") meets requirement 9 of #ac("SP")
800-90C section 5.3: it counts only the physical entropy sources toward the
requested amount of entropy (Method 1 of #ac("SP") 800-90C section 2.3). In this
configuration, the #ac("DRNG") with prediction resistance is also intended to
meet the RBG3(RS) construction.

=== SP 800-90C Compliant Configuration <sec:90c-config>

#ac("SP", cap: true) 800-90C compliance requires all settings of this section.

These compile-time settings must be observed:

- The meson configuration option `sp80090c` is set. With this option:

  - The final conditioning operations of the auxiliary pool and of the
    #acs("eBPF")-based entropy sources require 64 additional bits of entropy
    when obtaining data for the temporary seed buffer. The kernel module
    `esdm_es` requires 65 bits for the interrupt and scheduler entropy
    sources in a kernel booted with `fips=1`, one more for the update of its
    #ac("DRBG") (`kernel/esdm_es/esdm_definitions.h`). This complies with #ac("SP") 800-90C section 3.2.2.2
    and
    section 2.6 item 11, which require $"output_len" + 64$ bits of entropy
    for full-entropy output of a vetted conditioning function. The
    conditioning components thus provide full entropy.

  - The #ac("ESDM") attempts to seed the #ac("DRNG") initially with at least 384
    bits of entropy. This complies with requirement 8 of #ac("SP") 800-90C
    section 5.3, which requires $3s \/ 2$ bits of entropy for the initial
    seeding. The #ac("ESDM") applies no stepwise seeding during initialization:
    it pulls at least 384 bits of entropy collectively from all entropy sources
    before it considers the #ac("DRNG") fully seeded. Only then is the
    #ac("ESDM") operational and does it serve the interfaces of table
    @tab:path-classes.

  - The #ac("ESDM") applies the request size based reseeding limits outlined in
    section @sec:sp80090c.

- The meson configuration option `ais2031_drg3` must not be set. It applies
  the oversampling of the entropy sources without the request size based
  reseeding limits and without claiming #ac("SP") 800-90C compliance.

- Enable `es_irq` to use the interrupt entropy source compliant with
  #ac("SP") 800-90B as outlined in section @sec:90b-config, if the interrupt
  entropy source is considered compliant with #ac("SP") 800-90B by accepting the
  assessment in chapter @sec:kernel-es-assessment and by applying the testing of
  the entropy source as outlined in section @sec:90b-reuse on the target system.
  This also requires compiling the #ac("ESDM") Linux kernel module documented in
  `kernel/esdm_es/README.md`.

- Enable `es_sched` to use the scheduler entropy source compliant with
  #ac("SP") 800-90B as outlined in section @sec:90b-config, if the scheduler
  entropy source is considered compliant with #ac("SP") 800-90B by accepting the
  assessment in chapter @sec:kernel-es-assessment and by applying the
  testing of the entropy source as outlined in section @sec:90b-reuse on the
  target system. This also requires compiling the #ac("ESDM") Linux kernel
  module with `BUILD_ES_SCHED=1`. Only one of the two entropy sources may be
  credited.

- The #ac("ESDM") must be compiled with the meson configuration options
  `es_irq_ebpf_entropy_rate=0` and `es_sched_ebpf_entropy_rate=0`, the
  defaults, unless the #acs("eBPF")-based entropy source in question is
  considered compliant with #ac("SP") 800-90B by an assessment of the entropy
  source on the target system as outlined in chapter @sec:ebpf-assessment.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_cpu_entropy_rate=0` or without the option `es_cpu`, unless the
  #acs("CPU")-based entropy source (e.g. RDSEED on Intel) has an #ac("SP")
  800-90B compliant entropy assessment and complies with all requirements of
  #ac("SP") 800-90B.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_hwrand_entropy_rate=0`, the default, or without the option
  `es_hwrand`, unless the #ac("HWRAND") entropy source has an #ac("SP") 800-90B
  compliant entropy assessment and complies with all requirements of #ac("SP")
  800-90B.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_tpm2_entropy_rate=0`, the default, or without the option `es_tpm2`,
  unless the #ac("TPM") 2.0 entropy source has an #ac("SP") 800-90B compliant
  entropy assessment and complies with all requirements of #ac("SP") 800-90B.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_jent_kernel_entropy_rate=0` or without the option `es_jent_kernel`,
  the default, unless the kernel Jitter #acs("RNG") has an #ac("SP") 800-90B
  compliant entropy assessment and complies with all requirements of #ac("SP")
  800-90B.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_ext_entropy_rate=0` unless the external entropy source has an
  #ac("SP") 800-90B compliant entropy assessment and complies with all
  requirements of #ac("SP") 800-90B.

- The #ac("ESDM") must be compiled with the meson configuration option
  `es_jent_entropy_rate=0` or without the option `es_jent`, unless the
  Jitter #acs("RNG") entropy source has an #ac("SP") 800-90B compliant entropy
  assessment and complies with all requirements of #ac("SP") 800-90B#footnote[At
  the time of writing, the user space Jitter #acs("RNG") is #ac("SP") 800-90B
  compliant. Patches making the in-kernel variant #ac("SP") 800-90B compliant as
  well went into kernel version 5.8.].

One requirement applies to the runtime configuration. A user space rngd may fill the #ac("ESDM") with entropy via the #ac("IOCTL")
`RNDADDENTROPY` or the #ac("RPC") #ac("API") call `esdm_rpcc_rnd_add_entropy`.
However, the caller may claim entropy for the data, and thus increase the
entropy estimate of the #ac("ESDM"), only if the entropy source complies with
#ac("SP") 800-90B with an entropy assessment of its own.

#par(first-line-indent: 0pt)[To verify the #ac("SP") 800-90C compliance, check
that
the status lists "SP800-90C" (section @sec:examples). Table @tab:path-classes
gives the interfaces providing #ac("SP") 800-90C compliant random numbers; those
of the prediction resistance path may seed another #ac("DRBG") (section
@sec:components).]

=== FIPS 140 Compliant Configuration <sec:fips140-config>

#ac("FIPS", cap: true) 140 compliance – #ac("FIPS") 140-3 with its
implementation guidance @fips1403ig – requires all settings of this section.

One compile-time setting must be observed: the meson configuration option
`fips140` is set and `ais2031_drg3` is not,
as the latter removes the reseeding limits. `fips140` enables the option
`sp80090c` together with its request size based reseeding limits: the
#ac("ESDM") server applies the oversampling for the conditioning and the
initial seeding of the #ac("DRNG") in every mode.

One requirement applies to the runtime configuration. The #ac("ESDM") must be operated in #ac("FIPS") mode: set the kernel command
line option `fips=1` or, for the #ac("ESDM") server alone, the environment
variable `ESDM_SERVER_FORCE_FIPS` when starting the #ac("ESDM") server. The
kernel module `esdm_es` follows the kernel alone: with the variable and
without `fips=1`, its entropy sources run without their oversampling. In
#ac("FIPS") mode, and only then:

- The #ac("ESDM") performs an #acs("HMAC")-SHA256 known-answer test before it
  starts, in addition to the self tests of section @sec:self-tests, which run
  in every mode.

- The #ac("ESDM") verifies the integrity of the `esdm-server` executable and
  of the #ac("ESDM") library with #ac("HMAC") reference values. A missing
  reference value is a failed integrity test, and the server refuses to start.
  The #ac("ESDM") does not attest the Jitter #acs("RNG") and the crypto library
  of the backend. Write the reference values when installing the files as
  built, next to each file, under the name the loader resolves – the SONAME
  `libesdm.so.1`, not the versioned file behind it:

  ```sh
  esdm-tool --fips-targetfile /usr/bin/esdm-server \
            --fips-checkfile /usr/bin/.esdm-server.hmac
  esdm-tool --fips-targetfile /usr/lib64/libesdm.so.1 \
            --fips-checkfile /usr/lib64/.libesdm.so.1.hmac
  ```

  `esdm-tool` never overwrites a reference value: remove the old one when
  updating a file. For a library in a read-only location, whoever installs
  that location provides it.

- The kernel module `esdm_es` applies the oversampling for the
  conditioning of the scheduler and interrupt entropy sources and performs
  their #ac("SP") 800-90B health tests.

== AIS 20/31 <sec:ais2031>

The German #ac("BSI") defines functionality classes of #ac("RNG", pl: true) with
#ac("AIS") 20/31 version 3.0 from 2024 @ais2031. The #ac("ESDM") provides
configurations for the NTG.1 seeding strategy and for the classes DRG.3 and
DRG.4, given in the next sections. Appendix @sec:ais2031-requirements maps every
requirement of NTG.1, DRG.3, DRG.4 and DRT.1 to the part of the #ac("ESDM") that
meets it.

All #ac("DRNG", pl: true) of the #ac("ESDM") are characterized as DRG.3, since
they all support backward secrecy and use contemporary cryptographic primitives
for the state transition and the output generation: the #ac("SP") 800-90A Hash
#ac("DRBG") with a SHA-512 core of the builtin crypto backend, the ChaCha20
#ac("DRNG") documented in section @sec:chacha20, the #ac("SP") 800-90A
#ac("DRBG", pl: true) of the OpenSSL, Botan and GnuTLS backends, the
#ac("XDRBG") with SHAKE256 of leancrypto and the ChaCha20 #ac("DRNG") of Botan
from Botan 3.14.0 on, which operates it with fast key erasure.

Their output functions are therefore assumed to be indistinguishable from
the output of an ideal #ac("RNG"). The #ac("SP") 800-90A #ac("DRBG", pl: true)
pass the #ac("NIST") #ac("CAVP") test suite. The ChaCha20 #ac("DRNG") can be
tested with the
#link("https://www.chronox.de/chacha20_drng.html")[ChaCha20 #ac("DRNG") stand-alone
implementation] derived from the #ac("ESDM") implementation: both operate
identically, as the power-on self test of the stand-alone implementation is
identical to the #ac("ESDM") power-on self test in
esdm/esdm\_builtin\_chacha20.c.

=== NTG.1 (AIS 20/31 3.0 2024) Compliant Configuration <sec:ntg1-2022>

NTG.1 compliant operation requires the configuration of this section. It
may be combined with the #ac("SP") 800-90B and #ac("SP") 800-90C configurations.
With `es_jent_ntg1` and `ais2031_ntg1` combined, however, the Jitter #acs("RNG")
alone brings a #ac("DRNG") to the fully seeded level once it has delivered 240 bits
of entropy, without the #ac("ESDM") checking the 384 bits the #ac("SP") 800-90C
configuration requires for the initial seed (`esdm_fully_seeded`). In
combination with the #ac("SP") 800-90C configuration, the entropy rate of the
Jitter #acs("RNG") must therefore let it deliver the full seed – its default rate
does.

For #ac("AIS") 20/31 version 3.0 (2024), these compile-time settings must be
observed:

- The #ac("ESDM") compile-time option `ais2031_ntg1` or the meson configuration
  option `es_jent_ntg1` must be enabled.

- With `ais2031_ntg1`, the #ac("ESDM") must have access to two entropy sources
  that can deliver 240 bits of entropy each for the initial seeding of a
  #ac("DRNG") – after it, one entropy source suffices. For example, the
  interrupt entropy source can deliver 256 bits of entropy. The Jitter
  #acs("RNG") entropy source can deliver 240 bits of entropy when the #ac("ESDM")
  is compiled with the meson configuration option `es_jent_entropy_rate=240` or
  a larger value, such as its default of 256. See section @sec:jent-entropy for
  details on the Jitter #acs("RNG") entropy rate.

- Alternatively, `es_jent_ntg1` alone operates the Jitter #acs("RNG") in its own
  NTG.1 mode, which requires the Jitter #acs("RNG") library version 3.7.0 or
  later with support for secure memory. Such a Jitter #acs("RNG") is NTG.1
  conformant on its own: it applies the start-up rule of two noise sources with
  240 bits each internally, so no second entropy source is needed.

#par(first-line-indent: 0pt)[These requirements apply to the runtime
configuration:]

- The two entropy sources credited for the start-up employ different
  principles to provide randomness, e.g. interrupt timing and the
  execution timing of the Jitter #acs("RNG").

- When the interrupt or scheduler entropy source of the kernel module
  `esdm_es` is credited, boot the kernel with `fips=1`: only then does the
  module run its #ac("SP") 800-90B health tests (section @sec:health-tests). The
  #acs("eBPF")-based sources run theirs in an `ais2031_ntg1` build, the Jitter
  #acs("RNG") also with `es_jent_ntg1`.

#par(first-line-indent: 0pt)[To verify the NTG.1 compliance, check that the
status lists "NTG.1(2024)" (section @sec:examples). Only the interfaces of the
prediction resistance path deliver NTG.1 output (table @tab:path-classes):
NTG.1 admits a min-entropy of 0.98 up to $1 - 2^(-32)$ bits per output bit
@nistir8446, which only output backed by as much fresh entropy reaches. The
other paths deliver #ac("DRNG") output seeded by the NTG.1 entropy sources.]

=== NTG.1 of the Prediction Resistance Path <sec:ntg1-pr>

With `es_jent_ntg1`, the Jitter #acs("RNG") is an NTG.1 #ac("RNG") by itself. The
prediction resistance path of the #ac("ESDM") adds a second conditioning stage
behind it and keeps every NTG.1 property (figure @fig:ntg1-pr):

+ The NTG.1 mode of the Jitter #acs("RNG") implies its #ac("FIPS") mode. Its two
  noise sources, the timing of memory accesses and of the SHA-3 hash loop, each
  deliver their start-up block alone before they operate together
  (NTG.1.4). Its health tests check every time delta with the cut-offs of
  NTG.1 (NTG.1.1). SHAKE-256 absorbs $(256 + 65) dot "OSR"$ time deltas into
  the state of an XDRBG-256 for each 256-bit output block: 65 bits more
  entropy than output, the internal conditioning of #ac("SP") 800-90B and a
  post-processing with memory in #ac("AIS") 20/31 terms (NTG.1.2, NTG.1.3,
  NTG.1.5).

+ The #ac("ESDM") credits the Jitter #acs("RNG") at `es_jent_entropy_rate`, 256
  bits per 256 bits by default. Before every chunk of the prediction resistance
  path, it reseeds the #ac("DRNG") with fresh entropy and generates at most as
  many bits as the reseed brought, less the 64 bits of the #ac("SP") 800-90C
  oversampling where it applies, and at most 256 bits (NTG.1.2, NTG.1.5). The
  #ac("DRNG") is a DRG.3 #ac("DRNG") (NTG.1.3).

#figure(
  image("../figures/ntg1-jitter-pr.svg", width: 62%),
  caption: [NTG.1 of the prediction resistance path with the Jitter #acs("RNG")
  in
    its NTG.1 mode, with the #ac("SP") 800-90C oversampling],
) <fig:ntg1-pr>

The #ac("ESDM") thus acts as external conditioning of the Jitter #acs("RNG") in
the sense of #ac("SP") 800-90C section 3.2: it compresses the entropy of the
Jitter #acs("RNG") into output that is no longer, and it adds a second
post-processing stage with memory. #ac("AIS", cap: true) 20/31 asks an NTG.1
#ac("RNG") with several stateful stages to count the entropy consistently across
them: the Jitter #acs("RNG") outputs no more bits than its entropy, and the
#ac("ESDM") no more than it was credited. No NTG.1 requirement rests on the
#ac("ESDM") alone, and the #ac("ESDM") keeps each of them. The output of the
prediction resistance path is therefore NTG.1 output; the full and plain paths
generate more output than entropy and deliver DRG.3 output seeded by the NTG.1
#ac("RNG") (section @sec:drg3-drg4).

#paragraph[Other credited sources][The #ac("ESDM") counts the entropy of every
credited source. For an NTG.1 claim that rests on the Jitter #acs("RNG") alone,
credit no other source; otherwise each of them needs its own justification
and health tests (NTG.1.1, section @sec:ntg1-2022).]

#paragraph[SP 800-90C][The same chain is an RBG2(NP) construction with
prediction resistance, as the Jitter #acs("RNG") is a non-physical entropy source
(section @sec:90c-constructions): #ac("SP") 800-90C grants full entropy only to
RBG3 constructions with physical sources, while NTG.1 is the class of
non-physical true #ac("RNG", pl: true).]

=== DRG.3 / DRG.4 (AIS 20/31 3.0 2024) Compliant Configuration <sec:drg3-drg4>

#ac("AIS", cap: true) 20/31 version 3.0 from 2024 defines the classes DRG.3 and
DRG.4, which apply to the deterministic part of the #ac("ESDM"). The #ac("ESDM")
provides two mutually exclusive compile-time options for them, which can be
combined with the NTG.1 configuration of section @sec:ntg1-2022:

- `ais2031_drg3`: The #ac("ESDM") applies the oversampling of the entropy
  sources of the `sp80090c` option – 128 additional bits of entropy for the
  initial seed of a #ac("DRNG") and 64 additional bits of entropy from the
  conditioning components – without the request size based reseeding limits,
  which belong to DRG.4. Such a build does not claim #ac("SP") 800-90C
  compliance.

- `ais2031_drg4`: DRG.4 satisfies DRG.3, so the #ac("ESDM") applies the
  oversampling of the entropy sources of `ais2031_drg3`. In addition, the
  #ac("ESDM") caps the request size based reseeding limits to the values
  DRG.4.10 requires: a #ac("DRNG") instance starts no request after it has generated
  $2^17$ bits without a successful reseed – it completes a request started
  before, in generate operations of $2^19$ bits at most – and attempts a reseed
  after three quarters of that limit. The #ac("ESDM") keeps smaller values
  configured with the meson configuration options `drng_reseed_threshold_bits`
  and `drng_max_reseed_bits`. As such a build applies everything the `sp80090c`
  option does, it also claims #ac("SP") 800-90C compliance.

#par(first-line-indent: 0pt)[The #ac("DRNG") provides backward secrecy as
outlined in section @sec:ais2031. DRG.4 in addition requires a physical
randomness source for every seed and reseed: an `ais2031_drg4` build claims
DRG.4 only when no entropy but that of physical sources is credited (section
@sec:physical-es). DRG.3 is best seeded by an NTG.1 source: combine it with
`ais2031_ntg1` or `es_jent_ntg1`. To verify the DRG.3 or DRG.4 compliance,
check that the status lists DRG.3, and for DRG.4 also DRG.4 (section
@sec:examples) – the flag DRG.4 says that the reseeding limits are applied,
not which sources are credited.]

=== DRG.4 / PTG.3 Compliant Configuration <sec:drg4-ptg3>

The #ac("ESDM") allows a configuration that would make it compliant with the
requirements of a DRG.4 as well as a PTG.3. This configuration credits no
entropy source except one that provides the data of a PTG.2 entropy
source. For example, an rngd can access a smart card that provides a PTG.2
entropy source, or the external entropy source providers `esdm-es-pkcs11`
or `esdm-es-pcsc` can serve such a smart card. All other entropy sources
are then credited with no entropy by the compile-time configuration below;
they may stay enabled.

A PTG.3 can only be claimed if the PTG.2 entropy source is part of the
validation. If the PTG.2 entropy source is not part of the validation, a
DRG.4 must be claimed instead.

For such a compliance claim, this compile-time configuration must be
applied:

- The #ac("ESDM") compile-time option `ais2031_drg4` must be enabled to apply
  the reseeding limits of DRG.4 as outlined in section @sec:drg3-drg4.

- To credit the interrupt entropy source with no entropy, the #ac("ESDM") must
  be compiled with `es_irq_entropy_rate=0`. The same applies to the
  scheduler-based and the #acs("eBPF")-based entropy sources with
  `es_sched_entropy_rate=0`, `es_irq_ebpf_entropy_rate=0` and
  `es_sched_ebpf_entropy_rate=0`.

- Configure the Jitter #acs("RNG") entropy source to be credited with no
  entropy: compile
  the #ac("ESDM") with the compile-time option `es_jent_entropy_rate=0`. With
  the value 0, the #ac("ESDM") credits the entropy source with no entropy. The
  same applies to the kernel Jitter #acs("RNG") entropy source with
  `es_jent_kernel_entropy_rate=0`.

- Adjust the entropy rate of the #ac("CPU") entropy source to zero: compile the
  #ac("ESDM") with the compile-time option `es_cpu_entropy_rate=0`. With the
  value 0, the #ac("ESDM") credits the entropy source with no entropy.

- Adjust the entropy rate of the kernel #ac("RNG") entropy source to zero:
  compile the #ac("ESDM") with the compile-time option
  `es_kernel_entropy_rate=0`.

- Adjust the entropy rate of the #ac("HWRAND") and #ac("TPM") 2.0 entropy
  sources to zero: compile the #ac("ESDM") with the compile-time options
  `es_hwrand_entropy_rate=0` and `es_tpm2_entropy_rate=0`, the defaults. With
  the value 0, the #ac("ESDM") credits the entropy source with no entropy.

One requirement applies to the runtime configuration. The PTG.2 entropy source delivers its entropy to the #ac("ESDM") via the
`esdm_rpcc_rnd_add_entropy` #ac("RPC") #ac("API") call, the `/dev/random`
#ac("IOCTL") `RNDADDENTROPY`, or as the external entropy source.

=== Physical and Non-Physical Entropy Sources <sec:physical-es>

DRG.4 requires a physical randomness source for seeding and reseeding, such
as a PTG.2 or PTG.3 #ac("RNG")\; a non-physical true #ac("RNG") does not qualify
@nistir8446. DRG.3, NTG.1 and #ac("SP") 800-90C accept either kind. The entropy
sources of the #ac("ESDM") are of the following kinds; the rate is the default
of the meson option, in bits of entropy per 256 bits of data:

#figure(
  table(columns: (1.5fr, 1.7fr, 1.1fr, 1fr), align: left + horizon,
    table.header([Entropy source], [Noise source], [Kind], [Rate]),
    [Interrupts, scheduler events (`esdm_es`)], [timing of events],
      [non-physical], [256, 0],
    [Interrupts, scheduler events (#ac("eBPF"))], [timing of events],
      [non-physical], [0],
    [Jitter #acs("RNG"), kernel Jitter #acs("RNG")], [execution timing of the
    #ac("CPU")],
      [non-physical], [256],
    [#ac("CPU", cap: true): RDSEED or RDRAND, DARN, PRNO-#acs("TRNG"), RNDRRS,
    Zkr],
      [on-chip noise source], [physical], [8],
    [#ac("HWRAND", cap: true) (`/dev/hwrng`)], [the hardware #ac("RNG") behind
    it],
      [physical on bare metal; virtio-rng: from the host], [0],
    [#ac("TPM", cap: true) 2.0], [the #ac("RNG") of the #ac("TPM")], [physical;
    a vTPM is not], [0], [Kernel #ac("RNG")], [its own sources and #ac("DRNG")],
    [non-physical],
      [128, 0 with oversampling],
    [External (`es_ext`): #acs("PKCS")\#11, #ac("PC/SC") tokens, own providers],
      [that of the provider], [that of the provider, e.g. a PTG.2 smart
      card], [as the provider states],
    [Auxiliary pool], [data written by user space], [that of the writer],
      [privileged writers only],
  ),
  caption: [Kinds of the entropy sources],
) <tab:physical-es>

With the default rates, the #ac("ESDM") credits mostly non-physical sources –
the #ac("CPU") contributes 8 of every 256 bits. An `ais2031_drg4` build claims
DRG.4 only when the entropy of every seed and reseed is credited to physical
sources alone: set the rates of all non-physical sources to 0, as section
@sec:drg4-ptg3 lists, and credit a physical source at the rate its
assessment gives. The non-physical sources may stay enabled: they add data
without being relied on.

=== DRNG Trees: DRT.1 <sec:drt1>

DRT.1 covers #ac("DRNG", pl: true) that are seeded by other
#ac("DRNG", pl: true) @ais2031 @nistir8446:

- every #ac("DRNG") of the tree meets DRG.3; for Hash_DRBG and HMAC_DRBG,
  #ac("AIS") 20/31 waives the algorithmic verification;

- the root #ac("DRNG") is seeded by a PTG.2, PTG.3 or NTG.1 #ac("RNG"), or by a
  DRG.4 #ac("DRNG") given fresh entropy immediately before;

- apart from the root, a #ac("DRNG") is reseeded only by the #ac("DRNG") that
  seeded it or by a sibling of that #ac("DRNG")\;

- the initial randomness source and all #ac("DRNG", pl: true) of the tree stay
  within one security boundary.

#par(first-line-indent: 0pt)[The #ac("ESDM") serves as the initial randomness
source of such trees: built with `ais2031_ntg1` or `es_jent_ntg1`, its
prediction resistance path delivers NTG.1 output. A #ac("DRNG") seeded from it
is the root of its tree and may be reseeded from it again, for example:]

- a #ac("DRNG") of the caller seeded with `getrandom(2)` and `GRND_RANDOM` or
  with `esdm_rpcc_get_random_bytes_pr`;

- the #ac("DRNG", pl: true) of OpenSSL seeded through
  `libesdm-rng-provider-pr.so` or `libesdm-egd-provider-pr.so`;

- the #ac("DRNG", pl: true) of a guest (section @sec:host-guest).

#par(first-line-indent: 0pt)[Seed a root with at least 256 bits – 32 bytes –
of that output (DRT.1.6), as in this sketch of a #ac("DRNG") of the caller; with
the #ac("RPC") client, nothing falls back to the kernel #ac("RNG") while the
#ac("ESDM") server cannot be reached:]

```c
#include <esdm/esdm_rpc_client.h>

/* Seed the root DRNG of a DRT.1 tree from the prediction resistance path */
static int seed_root(struct my_drng *drng)
{
	uint8_t seed[32];	/* 256 bits of NTG.1 output (DRT.1.6) */
	ssize_t ret;

	if (esdm_rpcc_init_unpriv_service(NULL))
		return -EIO;
	ret = esdm_rpcc_get_random_bytes_pr(seed, sizeof(seed));
	esdm_rpcc_fini_unpriv_service();
	if (ret != sizeof(seed))
		return -EIO;

	return my_drng_seed(drng, seed, sizeof(seed));
}
```

#par(first-line-indent: 0pt)[`getrandom(seed, sizeof(seed), GRND_RANDOM)`
through `libesdm-getrandom.so` serves the same path, but falls back to the
kernel #ac("RNG") while the #ac("ESDM") server cannot be reached. Appendix
@sec:ais2031-requirements maps all requirements of DRT.1.
`esdm-kernel-seeder` uses this path in an `ais2031_ntg1` or `es_jent_ntg1`
build as well. The full and plain paths do
not serve as the seed source of a DRT.1 tree: they are served by whichever
#ac("DRNG") instance of the #ac("ESDM") is free (section @sec:numa). A
#ac("DRNG") seeded from them would have one instance as its seed predecessor and
be reseeded from others, which DRT.1 does not count as siblings: each instance
is seeded by the entropy sources, not by a common #ac("DRNG").]

== Host and Guest <sec:host-guest>

In a virtual machine, the entropy sources of the #ac("ESDM") observe virtualized
hardware:

- The interrupt and scheduler timing and the Jitter #acs("RNG") measure
  virtualized timers and events. Their assessments do not carry over to a guest:
  assess them there (section @sec:90b-reuse). Sections @sec:kvm-measurements and
  @sec:ebpf-kvm show such assessments in a #ac("KVM") guest. An idle guest
  receives almost no device interrupts – 1.6 per second in that guest – so the
  interrupt entropy sources collect almost nothing while it idles.

- The #ac("CPU") instructions run on the physical #ac("CPU") unless the
  hypervisor traps them. The #ac("ESDM") does not detect a hypervisor.

- A vTPM is software of the host, not a physical source.

- virtio-rng appears in the guest as `/dev/hwrng`, which the #ac("HWRAND")
  entropy source reads, without credit by default.

=== Entropy in Virtual Machines <sec:vm-entropy>

A study of the #ac("BSI") analyzes how a hypervisor affects noise sources and
measures the Linux kernel #ac("RNG") as a guest of #ac("KVM"), VirtualBox,
Hyper-V and ESXi @bsi-vm-rng. Its measurements concern the kernel #ac("RNG")
of 2016 and do not transfer to the #ac("ESDM"); its classification of noise
sources does, and it explains what to check in a guest:

- A noise source implemented in hardware below the hypervisor is not
  affected, but the interface through which the guest reads it can be. This
  is the case of the #ac("CPU") instructions and of a #ac("TPM").

- A noise source implemented in software that needs support from the
  hardware is the one most affected. The entropy sources that time events
  belong here: they need a high-resolution timestamp, and the hypervisor
  decides whether the guest reads it from the hardware or receives an emulated
  one. The study finds that the changed timing of a guest does not by itself
  lower the entropy of such a source, as long as the timestamp keeps its
  resolution.

- One or two of the three noise sources of the kernel #ac("RNG") were found
  not to operate in a guest, and the guest received a strong seed much later
  after boot than a system without hypervisor.

- State that a hypervisor duplicates – by a snapshot, a clone, a backup that
  is restored, or a migration that leaves two copies – is entropy lost: one
  copy predicts the other.

#par(first-line-indent: 0pt)[Table @tab:vm-guidance turns this into what the
operator of a guest with the #ac("ESDM") checks and configures. The appendix
of the study holds a questionnaire for a hypervisor it does not cover.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.8fr, 1.5fr, 1.6fr), align: left + top,
    table.header([Subject], [What to check or configure], [Why]),
    [Timestamp of the guest], [The guest reads the cycle counter of the
      #ac("CPU") without a trap into the hypervisor, and the clock source of
      the guest kernel is that counter
      (`/sys/devices/system/clocksource/clocksource0/current_clocksource`,
      e.g. `tsc`). Section @sec:kvm-measurements shows how to verify that
      reading the counter does not exit to the hypervisor], [The interrupt,
      scheduler and #ac("eBPF") entropy sources and the Jitter #acs("RNG")
      draw their entropy from the low bits of this timestamp. With an
      emulated or coarse timestamp they deliver little or nothing: the kernel
      module does not load without a high-resolution timer and credits no
      entropy when the greatest common divisor of its timestamps shows a
      coarse one; the #ac("eBPF") entropy sources are disabled without a
      high-resolution clock],
    [Entropy rate of the timing sources], [Measure the entropy source in the
      guest, in the load profile with the fewest events, before crediting it
      (sections @sec:90b-reuse and @sec:ebpf-config). Do not reuse the rate of
      another machine or of the host], [The assessment of a timing source
      holds for the system it was measured on (section
      @sec:measurement-limits)],
    [Idle and headless guests], [Do not rely on the interrupt or scheduler
      entropy source alone. Keep an entropy source that delivers on request
      credited: the Jitter #acs("RNG"), or entropy of the host over
      virtio-rng], [An idle guest has few events: the guest of section
      @sec:kvm-measurements received 1.6 device interrupts per second, and
      256 bits take 768 timestamps with the default oversampling rate],
    [Health tests], [Boot the guest with `fips=1` if it credits the interrupt
      or scheduler entropy source of the kernel module], [Without it, only
      the stuck test guards the timestamps, and a timer that the hypervisor
      degrades at runtime goes unnoticed (section @sec:health-tests)],
    [#ac("CPU") instruction], [Credit it only if the hypervisor passes the
      instruction through to the physical #ac("CPU"), and then at the rate
      its assessment supports], [The #ac("ESDM") cannot tell a trapped and
      emulated instruction from the real one],
    [Entropy from the host], [Feed virtio-rng from the #ac("ESDM") of the
      host and credit the #ac("HWRAND") entropy source in the guest (below).
      Credit it only when host and guest have the same operator], [The
      hypervisor is trusted in any case (section @sec:attacker-model), so the
      host is the one place that has entropy for a guest right after its
      boot],
    [Services at boot], [Order the services that need keys after
      `esdm-wait-until-fully-seeded.service` (section @sec:usage-boot-gate)],
      [A guest reaches the fully seeded level later than a system with
      devices; a service that starts earlier and reads through an interface
      that falls back receives output of the kernel #ac("RNG")],
    [Snapshots, clones, templates], [Take the image of a guest that is shut
      down. Where a running guest is cloned or restored, load the kernel
      module `esdm_es`, which reports the changed #ac("VM") generation to the
      #ac("ESDM"), or force a reseed in the procedure that resumes the guest
      (section @sec:vm-clone)], [The image of a running guest contains the
      state of every #ac("DRNG") instance and pool. Without the notification,
      two guests deliver the same random numbers until their next reseed],
    [Backups and migration], [Protect the image of a running guest like the
      keys it will generate. After a migration, make sure that only one copy
      continues], [The image holds the state from which the output can be
      predicted. A migration moves the state; two running copies are a clone],
  )
}
, caption: [Entropy in a virtual machine: what to check and to configure])
<tab:vm-guidance>

#paragraph[DRT.1 across host and guest][The #ac("ESDM") claims DRT.1 for a tree
spanning a host and its guests when one operator runs them within one
security boundary. The host #ac("ESDM") is the initial randomness source: its
NTG.1 output seeds the #ac("DRNG", pl: true) of the guest #ac("ESDM") over
virtio-rng, which are the roots of the tree; the consumers in the guest are
their children, seeded as section @sec:drt1 describes (figure
@fig:drt1-host-guest).]

#figure(
  image("../figures/drt1-host-guest.svg", width: 60%),
  caption: [A DRT.1 tree across host and guest],
) <fig:drt1-host-guest>

- Host: build with `ais2031_ntg1` or `es_jent_ntg1` and feed virtio-rng
  from `/dev/esdm_pr` of `esdm_cdev`, which always serves the prediction
  resistance path and never falls back to the kernel #ac("RNG"). QEMU and Cloud
  Hypervisor read it directly:

  ```sh
  qemu-system-x86_64 ... \
    -object rng-random,id=rng0,filename=/dev/esdm_pr \
    -device virtio-rng-pci,rng=rng0
  cloud-hypervisor ... --rng src=/dev/esdm_pr
  ```

  QEMU reads with `O_NONBLOCK` whenever `poll()` reports the device
  readable, and aborts on any error but `EAGAIN`: `/dev/esdm_pr` answers such
  a read with data or `EAGAIN` only, also while the #ac("ESDM") server cannot be
  reached. QEMU can do without `esdm_cdev` as well: its backend `rng-egd`
  speaks #ac("EGD") to the prediction resistance socket (section
  @sec:usage-egd-pr).

  ```sh
  qemu-system-x86_64 ... \
    -chardev socket,id=esdm,path=/run/esdm-egd-pr.socket \
    -object rng-egd,id=rng0,chardev=esdm \
    -device virtio-rng-pci,rng=rng0
  ```

  `/dev/esdm_random`, `/dev/random` and Cloud Hypervisor's default
  `/dev/urandom` serve the full or plain path, which does not seed a DRT.1
  tree.

- Guest: credit the #ac("HWRAND") entropy source with the entropy the host
  delivers, `es_hwrand_entropy_rate=256`, and no other source, so that only
  data of the host brings a guest #ac("DRNG") to the fully seeded level. The
  sources of the guest may stay enabled without credit.

#par(first-line-indent: 0pt)[#ac("SP", cap: true) 800-90C is ambiguous here: its
appendix A.3.3 accepts seed material that a #ac("DRBG") in a virtual machine
obtains from the hypervisor or the host of the same physical system, while its
definition of a computing platform, like #ac("NIST") #ac("IR") 8446 @nistir8446,
excludes components behind a peripheral bus, physical or virtual. The
#ac("ESDM") therefore claims no #ac("SP") 800-90C #ac("DRBG") tree across host
and guest, and no #ac("FIPS") 140-3 or #ac("SP") 800-90C claim of the host
carries into the guest.]

#paragraph[DRG.4 in a guest][DRG.4 needs a physical source in the guest: a
#ac("CPU") instruction the hypervisor passes through, assessed and credited as
section @sec:physical-es describes. virtio-rng and a vTPM do not qualify.]

== Worked Examples <sec:examples>

Each example gives the build, the runtime settings, the line of
`esdm-tool --status` that proves the configuration, and the interfaces that
then deliver the class; figure @fig:options summarizes them. The status
lists the standards in the order #ac("FIPS") 140, DRG.3, DRG.4, SP800-90C,
NTG.1(2011), NTG.1(2024); "NTG.1(2011)" appears in every build, and a flag
reports the build and the mode, not the class (table @tab:status-flags): the
entropy rates in the same status are part of the proof.

#figure(
  image("../figures/compliance-options.svg", width: 85%),
  caption: [Build options, the classes they give and the paths delivering
    them],
) <fig:options>

A script checks the classes in the #ac("JSON") form of the status:

```console
$ esdm-tool --status-json | jq -c .standards_compliance   # drg4 + ntg1
["DRG.3","DRG.4","SP800-90C","NTG.1(2011)","NTG.1(2024)"]
```

=== NTG.1 <sec:example-ntg1>

Two entropy sources must deliver 240 bits each at start-up. Without the
kernel module `esdm_es`, the Jitter #acs("RNG") in its NTG.1 mode covers that;
this mode needs the Jitter #acs("RNG") 3.7.0 or later with secure memory:

```sh
meson setup build -Dais2031_ntg1=true -Des_jent_ntg1=enabled
```

```console
Standards compliance: NTG.1(2011), NTG.1(2024)
```

The prediction resistance path delivers NTG.1 output; the full and plain
paths deliver #ac("DRNG") output seeded by it.

=== DRG.3 <sec:example-drg3>

DRG.3 seeded by an NTG.1 source:

```sh
meson setup build -Dais2031_drg3=true -Dais2031_ntg1=true \
  -Des_jent_ntg1=enabled
```

```console
Standards compliance: DRG.3, NTG.1(2011), NTG.1(2024)
```

The full, plain and prediction resistance paths deliver DRG.3 output, the
last also NTG.1 output.

=== DRG.4 <sec:example-drg4>

Only a physical source is credited, here the #ac("CPU") at the rate its
assessment gives:

```sh
meson setup build -Dais2031_drg4=true \
  -Des_irq_entropy_rate=0 -Des_sched_entropy_rate=0 \
  -Des_irq_ebpf_entropy_rate=0 -Des_sched_ebpf_entropy_rate=0 \
  -Des_jent_entropy_rate=0 -Des_jent_kernel_entropy_rate=0 \
  -Des_kernel_entropy_rate=0 -Des_cpu_entropy_rate=256
```

```console
Standards compliance: DRG.3, DRG.4, SP800-90C, NTG.1(2011)
```

The full, plain and prediction resistance paths deliver DRG.4 output, as
the reseeding limits of DRG.4 apply to every #ac("DRNG") instance.

=== SP 800-90C and FIPS 140-3 <sec:example-fips>

```sh
meson setup build -Dfips140=true
```

Boot the kernel with `fips=1` – or start the #ac("ESDM") server with
`ESDM_SERVER_FORCE_FIPS` set – and write the integrity reference values
(section @sec:fips140-config). Credit only entropy sources with an
#ac("SP") 800-90B assessment (section @sec:90c-config).

```console
Standards compliance: FIPS 140, SP800-90C, NTG.1(2011)
```

Without #ac("FIPS") mode, the build still applies the #ac("SP") 800-90C settings
and the line reads `SP800-90C, NTG.1(2011)`. The full, plain and prediction
resistance paths deliver #ac("SP") 800-90C output; the prediction resistance
path may seed another #ac("DRBG").

=== DRT.1 <sec:example-drt1>

Build as in section @sec:example-ntg1 and seed the #ac("DRNG", pl: true) of the
tree from the prediction resistance path (section @sec:drt1); across host and
guest, as section @sec:host-guest describes. The status shows no flag of its own
for DRT.1.

== Limits <sec:limits>

What this chapter does not claim:

- Output of the kernel #ac("RNG"). The #ac("CUSE") daemons and the
  `getrandom(2)` replacement serve the kernel #ac("RNG") while the #ac("ESDM")
  server cannot be reached, `/dev/urandom` and `GRND_INSECURE` also before the
  #ac("ESDM") is operational; process 1 and processes embedding the #ac("ESDM")
  library always use the kernel `getrandom(2)`. Where this matters, use
  `esdm_cdev`, the #ac("RPC") or the #ac("EGD") interface, which do not fall
  back.

- DRG.4 with credited non-physical sources (section @sec:physical-es),
  although the status lists DRG.4: the status flags report the build and the
  mode, not the class (table @tab:status-flags).

- Anything for the default build. Its entropy rates are a pragmatic choice
  and not an assessed configuration, it credits the interrupt entropy source
  of the kernel module without the #ac("SP") 800-90B health tests unless the
  kernel is booted with `fips=1`, and without the oversampling an output
  block of the kernel module holds one bit less than it is credited with
  (sections @sec:es-overview, @sec:health-tests and @sec:90b-3151).

- Independence of entropy sources beyond the rules the #ac("ESDM") enforces:
  a configuration that credits two entropy sources sharing a noise source
  counts entropy twice (section @sec:es-overview).

- Distinct output of cloned or restored virtual machines on a system without
  the kernel module `esdm_es` or without the #ac("VM") generation device,
  before their first reseed, and in the short time until the #ac("ESDM")
  has reacted to the #ac("VM") generation change otherwise (section
  @sec:vm-clone).

- That the drop-in interfaces deliver output of the #ac("ESDM") in the
  presence of a local user who provokes their fallback (section
  @sec:attacker-model).

- PTG.3 without a validated PTG.2 source (section @sec:drg4-ptg3).

- #ac("AIS", cap: true) 20/31 of 2011, although the status lists "NTG.1(2011)".

- #ac("FIPS", cap: true) 140-3 or #ac("SP") 800-90C in a guest by virtue of the
  host (section @sec:host-guest).

- Seed data as #ac("RNG") output: the seed path delivers entropy for the
  #ac("DRNG") of the caller, possibly less than requested.
