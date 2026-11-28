#import "../template.typ": *

= AIS 20/31 Requirements <sec:ais2031-requirements>

The tables map the requirements of the functionality classes NTG.1, DRG.3,
DRG.4 and DRT.1 of #ac("AIS") 20/31 version 3.0 @ais2031 to the parts of the
#ac("ESDM") that meet them, or to the integrator where the #ac("ESDM") cannot.
The requirements are abbreviated; their text is that of #ac("AIS") 20/31.

#let req-table(caption, ..rows) = figure(
  table(columns: (auto, 1.4fr, 2fr), align: left + horizon,
    table.header([Requirement], [Summary], [Met by]),
    ..rows),
  caption: caption,
)

#req-table([NTG.1 requirements],
  [NTG.1.1], [Collect and test the raw random numbers, estimate the
    entropy, detect failures],
    [The health tests of the entropy sources (section @sec:health-tests):
    the #acs("eBPF")-based sources and the Jitter #acs("RNG") run them in an
    `ais2031_ntg1` build, the kernel module `esdm_es` with `fips=1` only –
    the kernel is to be booted with it when its sources are credited],
  [NTG.1.2], [An entropy counter; never more output bits than it holds],
    [The prediction resistance path: no chunk carries more bits than the fresh
    entropy that went into it (section @sec:interface-classes); with
    `es_jent_ntg1` also the Jitter #acs("RNG") (section @sec:ntg1-pr)],
  [NTG.1.3], [Cryptographic post-processing with memory, DRG.3 as a hybrid
    #ac("DRNG")], [The prediction resistance #ac("DRNG"), a DRG.3 #ac("DRNG")
    (section @sec:ais2031) reseeded before every chunk; with `es_jent_ntg1` also
    the XDRBG-256 of the Jitter #acs("RNG") (section @sec:ntg1-pr)],
  [NTG.1.4], [No output before two noise sources of different principles
    have delivered 240 bits each], [`ais2031_ntg1` (section @sec:ntg1-2022):
    the integrator credits two sources of different principles, e.g.
    interrupt timing and the Jitter #acs("RNG"). Alternatively,
    `es_jent_ntg1`: the Jitter
    #acs("RNG") in its NTG.1 mode applies the rule to its own two noise sources],
  [NTG.1.5], [Min-entropy per output bit of 0.98 up to $1 - 2^(-32)$],
    [The prediction resistance path, as for NTG.1.2],
  [NTG.1.6], [Statistically inconspicuous output],
    [The #ac("DRNG", pl: true) of section @sec:ais2031, tested with the
    #ac("NIST") #ac("CAVP") suite],
)

#req-table([DRG.3 requirements],
  [DRG.3.1], [Seed material from a PTG.2, PTG.3 or NTG.1 #ac("RNG") or a DRG.4
    #ac("DRNG")], [The entropy sources of an `ais2031_ntg1` or `es_jent_ntg1`
    build (section
    @sec:drg3-drg4)],
  [DRG.3.2], [At most $2^19$ bits per request],
    [The #ac("DRNG") manager generates in chunks of 4096 bytes, of 65536 bytes
    in a build limiting the output without a full reseed (`sp80090c`,
    `fips140`, `ais2031_drg4` or `drng_max_reseed_bits`), of at most 32 bytes
    on the prediction resistance path],
  [DRG.3.3], [An effective internal state of at least 246 bits],
    [The #ac("DRNG", pl: true) of section @sec:crypto, all of a security
    strength of 256 bits],
  [DRG.3.4], [At least 240 bits of min-entropy after every (re)seed],
    [384 bits for the initial seed with `ais2031_drg3`, 240 bits from each
    of two sources with `ais2031_ntg1`, 256 bits for a reseed (section
    @sec:seeding)],
  [DRG.3.5, DRG.3.6], [Forward and backward secrecy],
    [The cryptographic #ac("DRNG", pl: true) of section @sec:crypto],
  [DRG.3.7], [Enhanced backward secrecy],
    [Backtracking resistance of the #ac("SP") 800-90A #ac("DRBG", pl: true) and
    the #ac("XDRBG"), fast key erasure of the ChaCha20 #ac("DRNG") (section
    @sec:chacha20)],
  [DRG.3.8], [Additional input does not weaken the #ac("DRNG")],
    [The additional input U (section @sec:seeding) enters a #ac("DRNG") through
    its cryptographic reseed function],
  [DRG.3.9], [Cryptographic state transition and output functions,
    one-way state transition], [The #ac("DRNG", pl: true) of section
    @sec:crypto],
  [DRG.3.10], [Statistically inconspicuous output], [As for NTG.1.6],
)

#req-table([DRG.4 requirements],
  [DRG.4.1], [Seed material and high-entropy additional input from a
    physical #ac("RNG")], [The integrator credits physical sources only (section
    @sec:physical-es)],
  [DRG.4.2 – DRG.4.9], [As DRG.3.2 – DRG.3.9, with the entropy of DRG.4.4
    from the physical sources], [As for DRG.3],
  [DRG.4.10], [Enhanced forward secrecy; at most $2^17$ bits until the
    next reseed], [The reseeding limits of `ais2031_drg4` (section
    @sec:drg3-drg4); on demand, the prediction resistance path],
  [DRG.4.11], [Statistically inconspicuous output], [As for NTG.1.6],
)

#req-table([DRT.1 requirements],
  [DRT.1.1], [A #ac("DRNG") tree with one distinguished root #ac("DRNG")],
    [The integrator: the #ac("ESDM") is the initial randomness source, not part
    of the tree (section @sec:drt1)],
  [DRT.1.2], [Initial randomness source and tree in one security
    boundary], [The integrator; across host and guest one operator
    (section @sec:host-guest)],
  [DRT.1.3], [Root seed material from a PTG.2, PTG.3 or NTG.1 #ac("RNG") or a
    DRG.4 #ac("DRNG")], [The prediction resistance path of an `ais2031_ntg1` or
    `es_jent_ntg1` build],
  [DRT.1.4, DRT.1.5], [At most $2^19$ bits per request, an effective
    internal state of at least 246 bits, for every #ac("DRNG") of the tree],
    [The integrator's #ac("DRNG", pl: true)],
  [DRT.1.6], [At least 240 bits of min-entropy in the root after every
    (re)seed], [The integrator seeds the root with at least 256 bits of
    the prediction resistance path],
  [DRT.1.7, DRT.1.8], [Children seeded with at least 256 bits by a #ac("DRNG")
    of the tree, seed material used only for seeding],
    [The integrator's #ac("DRNG", pl: true)],
  [DRT.1.9], [Reseeds only from the seed predecessor or its siblings],
    [The integrator; roots reseed from the #ac("ESDM") again (section
    @sec:drt1)],
  [DRT.1.10 – DRT.1.15], [The properties of DRG.3.5 – DRG.3.10 for every
    #ac("DRNG") of the tree], [The integrator's #ac("DRNG", pl: true)],
)
