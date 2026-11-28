#import "../template.typ": *

= Introduction <sec:introduction>

This document addresses the three audiences of #ac("SP") 800-90C @sp80090c:

- developers who design and implement random bit generators that are to be
  validated, by the #ac("CMVP") and the #ac("CAVP") of #ac("NIST") or in an
  evaluation according to #ac("AIS") 20/31 of the German #ac("BSI"), and who
  integrate the #ac("ESDM") or extend it, e.g. with an entropy source of their
  own;

- testing labs and auditors who perform the validation tests and evaluate
  the constructions, and who need to know how the #ac("ESDM") works and which
  configuration and which interface meets which requirement of #ac("FIPS")
  140-3, #ac("SP") 800-90 and #ac("AIS") 20/31;

- users who install the #ac("ESDM") in their systems, alongside or instead of
  the random number generator of the Linux kernel, and want to know what it
  offers and how to run it.

#par(first-line-indent: 0pt)[Section @sec:document-structure tells each of
them where to start.]

The #ac("ESDM") has three purposes. It is a random number generator for
Linux that manages its entropy sources and #ac("DRNG", pl: true) in user
space. It is a toolkit for random number generation in regulated
environments: its components, entropy sources, entropy rates, seeding
strategy and output paths are selected and configured, so that an integrator
tailors a random number generator to the requirements of #ac("FIPS") 140-3
and #ac("SP") 800-90 of #ac("NIST") or of #ac("AIS") 20/31 of the #ac("BSI"),
and to the system it runs on. And it provides, in its upstream source tree,
the integration for the most common consumers of random numbers, so that
these need no code of their own: the OpenSSL providers, the devices for a
hypervisor that passes random numbers to its guests, the replacements of
`/dev/random` and `getrandom()` for unmodified software, and the #ac("EGD")
interface for libgcrypt and sandboxed services. With these, the generation
of all keys of a system can be moved out of the kernel: the consumers in
user space – a TLS library, an SSH daemon, the key exchange daemon of a
VPN – obtain their key material from the #ac("ESDM"). What stays
with the random number generator of the kernel are the values the kernel
generates itself, which need not be secret, such as the #ac("IV", pl: true)
of AES-CBC that the XFRM stack generates for IPsec. As the kernel thus keeps
using its own generator, the #ac("ESDM") also seeds it, with
`esdm-kernel-seeder` (section @sec:usage-kernel-rng). Chapter
@sec:configurations states which configuration meets which requirement, section
@sec:if-deployment which components a system needs, and chapter
@sec:integrations how each consumer is connected.

The #ac("ESDM") originated from the
#link("https://www.chronox.de/lrng")[#ac("LRNG")] patch series. Managing
entropy sources inside the confines of a kernel has its limitations, and it
does not need the
privileges of kernel code. The #ac("ESDM") is therefore the #ac("LRNG") patch
series converted into user space. After its initialization, the #ac("ESDM") also
executes without privileges. This isolates its operation and adds to the overall
system security.

The design of the #ac("ESDM") has these goals:

+ The #ac("ESDM") manages the proper seeding and reseeding of
  #ac("DRNG", pl: true). It also provides internal entropy sources, which it
  fully controls, and interfaces to obtain data from external entropy sources.

+ The #ac("ESDM") provides an #ac("API") and #ac("ABI") compatible replacement
  for the Linux device files `/dev/random` and `/dev/urandom` and for the
  `getrandom(2)` and `getentropy(3)` calls of the C library. All code of these
  interfaces runs in user space with limited or no privileges. The
  replacement reaches the programs that open the device files or call the C
  library: a statically linked program, or one that invokes the system call
  directly, still obtains its random numbers from the kernel (section
  @sec:using-c).

+ The #ac("ESDM") is modular. Separate processes and libraries implement the
  Linux interfaces above, and the core library has few dependencies. The
  design aims at an #ac("ESDM") that can be ported to other operating
  systems; the present implementation builds and is tested on Linux only and
  uses Linux interfaces throughout.

+ The #ac("ESDM") provides all user-visible behavior of the kernel `/dev/random`
  as well, such as one #ac("DRNG") instance per #ac("CPU"), limited to the
  number of worker threads (section @sec:numa).

+ To limit the impact on massively parallel systems, the #ac("ESDM") takes no
  lock that all requests share exclusively: a request locks only the
  #ac("DRNG") instance that serves it, and there is one instance per
  #ac("CPU") up to the number of workers (section @sec:numa). The prediction
  resistance path is the exception, as it has one instance.

+ The #ac("ESDM") handles modern computing environments without a degradation of
  entropy, e.g. virtualized environments, systems with #ac("SSD", pl: true) and
  systems without #ac("HID", pl: true) or block devices.

+ The design of the #ac("ESDM") allows quantitative testing of the entropy
  behavior.

+ The #ac("ESDM") uses testable and widely accepted cryptography for
  conditioning.

+ The #ac("ESDM") allows cipher implementations backed by architecture-specific
  optimized assembler code or by hardware accelerators. They can lower the
  #ac("CPU") cost of generating random numbers, which saves power and battery
  time.

+ The #ac("ESDM") separates the cryptographic processing from the entropy source
  maintenance, so that either can be replaced.

+ The #ac("ESDM") offers configurations that let vendors apply the settings
  their environment needs.

#par(first-line-indent: 0pt)[Table @tab:goal-trace relates each goal to the
part of the design that implements it and to the evidence that it is met. A
goal without evidence is marked as such.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.1fr, 1.3fr, 1.5fr), align: left + top,
    table.header([Goal], [Subject], [Design], [Evidence]),
    [1], [Seeding and reseeding, entropy sources], [Sections @sec:seeding and
      @sec:es-overview], [Test suite (section @sec:test-suite); models of
      reseeding and of the auxiliary pool (chapter
      @sec:formal-verification)],
    [2], [Replacement of the Linux interfaces], [Sections @sec:interfaces and
      @sec:components], [#ac("CUSE") and `getrandom` tests, virtual machine
      tests (section @sec:vm-tests). Not covered: programs bypassing the C
      library],
    [3], [Modularity, portability], [Section @sec:flexible-design, chapter
      @sec:development], [Builds with each crypto backend and with entropy
      sources disabled. No evidence for another operating system],
    [4], [Behavior of `/dev/random`, #ac("DRNG") per #ac("CPU")], [Section
      @sec:numa], [Test suite; `esdm-cdev-check` for the kernel devices],
    [5], [No lock shared by all requests], [Sections @sec:numa and
      @sec:seeding-concurrency], [Latency benchmark (section
      @sec:usage-performance), one system],
    [6], [No degradation in virtualized and headless systems], [Sections
      @sec:irq-processing and @sec:health-tests], [Measurements in one
      #ac("KVM") guest (section @sec:kvm-measurements); limits in section
      @sec:measurement-limits],
    [7], [Quantitative testing of entropy], [Section @sec:test-interfaces],
      [Chapters @sec:kernel-es-assessment and @sec:ebpf-assessment],
    [8], [Accepted cryptography for conditioning], [Sections
      @sec:data-processing and @sec:crypto], [Known-answer tests and
      periodic self tests (section @sec:self-tests)],
    [9], [Optimized and accelerated ciphers], [Section @sec:backends],
      [Builds and tests per backend; no performance comparison of the
      backends],
    [10], [Crypto separated from entropy source management], [Section
      @sec:flexible-design], [The backends and entropy sources added through
      the interfaces of chapter @sec:development],
    [11], [Configurations for different environments], [Chapters
      @sec:configurations and @sec:build-options], [Worked examples (section
      @sec:examples). #ac("CI") builds only some of the modes (section
      @sec:test-gaps)],
  )
}
, caption: [Goals of the design, where they are implemented and what shows
  that they are met]) <tab:goal-trace>

== Properties Offered by the ESDM <sec:properties>

The #ac("ESDM") relieves users of managing the #ac("DRNG") and its seeding
status. It also has these properties:

- A toolkit for regulated environments, not a fixed system

  - The #ac("ESDM") is built and configured for the requirements at hand:
    build options select the configurations for #ac("SP") 800-90C,
    #ac("FIPS") 140-3 and the classes NTG.1, DRG.3 and DRG.4 of #ac("AIS")
    20/31; each entropy source is enabled and credited individually; the
    output path determines what a caller receives (chapter
    @sec:configurations).

  - The #ac("ESDM") consists of a generator and of optional components
    around it: frontends, entropy sources, kernel modules, client libraries
    and tools. An integrator chooses the subset a system needs. Only the
    generator is mandatory, as the server `esdm-server` or as the library
    `libesdm` linked into a program; an installation may consist of the
    server and one client library, or replace every random number interface
    of Linux. Section @sec:if-deployment shows what brings each interface
    into existence, minimal configurations, and when the kernel module
    `esdm_es` is needed.

- User space implementation with optional kernel components

  - The #ac("ESDM") and its Linux interfaces are implemented in user
    space. Optionally, the kernel module `esdm_cdev` serves the device files
    `/dev/esdm_random`, `/dev/esdm_urandom`, `/dev/esdm_pr` and `/proc/esdm`
    from the #ac("ESDM") via its #ac("EGD") socket. It leaves the device files
    of the kernel untouched.

  - For resource-constrained systems, the #ac("ESDM") offers two optional
    entropy sources: the scheduler-based and the interrupt-based entropy source.
    Both, however, use a kernel extension, as they hook into the scheduler
    or the interrupt handling code path: either the kernel module `esdm_es`
    with small kernel patches, or #ac("eBPF") programs attached to tracepoints
    of a stock Linux kernel.

  - The #ac("ESDM") server executes without any privilege after its
    initialization: it confines itself to namespaces of its own, initializes the
    entropy sources requiring privileges, creates its sockets and then
    permanently drops its privileges to an unprivileged user (`nobody` by
    default, to be replaced by a user of its own, see section
    @sec:attacker-model). The Linux interfaces providing `/dev/random`, `/dev/urandom` and
    the associated proc files execute with limited privileges.

- Sole use of cryptography for data processing

  - The #ac("ESDM") conditions entropy data only with cryptographic operations
    that have a clear mathematical description, as given in section
    @sec:data-processing: a hash, the XDRBG-256 of the entropy pools and the
    #ac("DRBG") of the kernel module `esdm_es`. It uses no non-cryptographic
    operations such as a #ac("LFSR").

  - The #ac("ESDM") uses only standardized cryptographic algorithms – the
    hash, the #ac("DRNG") and the #ac("XOF") of its crypto backend – and tests
    them with known-answer tests (section @sec:self-tests).

  - Hash operations use hash instances of their own – on the stack with the
    builtin crypto backend – to benefit large parallel systems.

  - The #ac("ESDM") uses a small number of post-processing steps, each with a
    mathematical description (section @sec:data-processing), so that the
    entropy can be followed through every step (section @sec:90b-3151).

- Performance

  - The interrupt and the scheduler entropy source of the kernel module do
    little per event: they read a timestamp, divide it, run the health tests
    and store 64 bits in a ring; the conditioning happens later, in process
    context (section @sec:irq-processing). The kernel module can record the
    cost per event (`boot_irq_perf`, `boot_sched_perf` in a build with
    `BUILD_TESTING=1`); this document reports no measurement of it and no
    comparison with the interrupt handler of the kernel #ac("RNG").

  - Section @sec:usage-performance gives the latency and the throughput of
    the #ac("RPC") interface on one system.

- Testing

  - Run-time health tests of the raw, unconditioned data of the
    scheduler-based and the interrupt-based entropy sources identify a
    degradation of the available entropy. Such health tests matter today, as
    virtual machine monitors reduce the resolution of the high-resolution
    timer or disable it. The kernel module always runs the stuck test; it runs
    the repetition count test, the adaptive proportion test and the startup
    test of #ac("SP") 800-90B only when the kernel is booted with `fips=1`.
    The #acs("eBPF")-based entropy sources run their health tests, the stuck
    test included, only in #ac("FIPS") mode, in #ac("SP") 800-90C mode or
    with the NTG.1 seeding strategy. None of the #ac("SP") 800-90B tests runs
    in the default configuration (section @sec:health-tests).

  - The heuristic entropy estimate of the interrupt-based entropy source
    rests on quantitative measurements and an analysis following #ac("SP")
    800-90B.

  - Self tests cover the critical deterministic components (#ac("DRNG"), hash
    and XDRBG-256 implementation) and every entropy source. The #ac("ESDM") runs
    them at start-up in every mode and repeats them every 10 minutes and on
    demand. In #ac("FIPS") mode, a power-on self test also verifies the
    integrity of the #ac("ESDM").

  - Test interfaces cover all operational stages of the #ac("ESDM"), including
    the sampling of raw entropy event data at boot time, as outlined in section
    @sec:test-interfaces.

  - The #ac("ESDM") test suite validates the software hash, #ac("XOF") and
    #ac("DRNG") implementations in use with known-answer tests.

  - Stress tests cover the code paths for data and mechanism (de)allocations
    and the code paths covered by locks. Fuzz harnesses cover the #ac("RPC") and
    #ac("EGD") interfaces.

  - Fully automated regression tests cover #ac("ESDM") functions in different
    configurations and allow an unattended functional verification
    (chapter @sec:testing).

- Entropy collection of the internal interrupt-based and scheduler-based
  entropy sources

  - The interrupt-based and scheduler-based entropy sources of the #ac("ESDM")
    kernel module ship with all required test tools and share one full
    #ac("SP") 800-90B assessment (chapter @sec:kernel-es-assessment). By
    default, the #ac("ESDM") credits the interrupt-based entropy source, and
    it credits at most one of the two.

  - The #acs("eBPF")-based scheduler and interrupt entropy sources apply the
    #ac("SP") 800-90B health tests inside their #ac("eBPF") programs in
    #ac("FIPS") mode, in #ac("SP") 800-90C mode or with the NTG.1 seeding
    strategy. By default, the #ac("ESDM") credits them with no entropy until
    their entropy rate has been measured with the provided tools in the environment
    they are deployed in (chapter @sec:ebpf-assessment).

  - Chapter @sec:kernel-es-assessment, specifically section @sec:90b-3151,
    provides the full entropy assessment and description.

  - The #ac("ESDM") provides a configuration compliant with #ac("SP") 800-90C
    @sp80090c following the RBG2(NP) and the RBG2(P) construction methods. The
    #ac("DRNG") instance operated with prediction resistance is intended to be
    an RBG3(RS) when only physical entropy sources are credited with entropy.

  - The #ac("ESDM") provides an interface for random numbers with prediction
    resistance, i.e. with an immediate reseed, returning only as many bits
    of data as there was entropy available. This supports chaining
    #ac("DRBG", pl: true) compliant with #ac("SP") 800-90C.

  - The #ac("ESDM") provides configurations for the NTG.1 seeding strategy and
    the classes DRG.3 and DRG.4 of the German #ac("AIS") 20/31 version 3.0
    @ais2031.

- Configurability

  - The build-time configuration adapts the #ac("ESDM") to different use cases.
    Optional code that is not compiled in folds into no-ops.

  - The #ac("ESDM") provides configurable seeding strategies following different
    concepts.

== Document Structure <sec:document-structure>

The document has two parts. Part I, Design and Assurance, documents what the
#ac("ESDM") is and why its claims hold:

- Chapter @sec:design documents the design of the #ac("ESDM"), with references
  to its publicly available source code.

- Chapters @sec:kernel-es-assessment and @sec:ebpf-assessment provide the
  statistical testing and the #ac("SP") 800-90B assessment of the interrupt, the
  scheduler and the #acs("eBPF")-based entropy sources.

- Chapter @sec:configurations gives the configurations meeting #ac("SP")
  800-90B, #ac("SP") 800-90C, #ac("FIPS") 140-3 and #ac("AIS") 20/31.

- Chapter @sec:hardening describes the secure implementation and the
  hardening, chapter @sec:formal-verification the model checking of its
  concurrent parts.

#par(first-line-indent: 0pt)[Part II, the Manual, explains how to build,
run, use, extend and test the #ac("ESDM"):]

- Chapter @sec:building-installing gives the requirements, the build, the
  installed files, the kernel modules and the packages, chapter
  @sec:build-options every build option.

- Chapter @sec:usage explains how to start, operate and harden the #ac("ESDM"),
  chapter @sec:tools the command line of every program.

- Chapter @sec:integrations describes the integrations with OpenSSL,
  Botan, libgcrypt, OpenSSH, strongSwan and the #ac("EGD") protocol, and with
  #ac("HSM", pl: true) and smart cards.

- Chapter @sec:development is for developers: the code structure, the
  processes, the entropy source and #ac("DRNG") managers, the client
  libraries, and how to add an entropy source, a crypto backend, an #ac("RPC")
  call or a build option.

- Chapter @sec:testing describes how the #ac("ESDM") is tested and how to run
  and write the tests.

- The appendices cover the entropy measurements, the glossary with the terms
  of #ac("NIST") and the #ac("BSI"), the acronyms, the symbols, the
  references, the license, the change log and the requirements of #ac("AIS")
  20/31.

#paragraph[Referencing this document][This document is a design document,
not the documentation of an evaluation. Its parts are arranged and labeled
so that such documentation can refer to them: interfaces, subsystems,
modules and security domains carry identifiers (IF-…, SS-…, M-…, D-…), and
table @tab:cc-map names the parts that the assurance families of the Common
Criteria ask about. The table is an orientation; it makes no claim of
conformance.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.9fr, 1.3fr, 1.8fr), align: left + top,
    table.header([Assurance family], [Subject], [Parts of this document]),
    [ADV_ARC], [Security architecture: domains, self-protection,
      non-bypassability, secure start-up], [Attacker model and security
      domains (sections @sec:attacker-model, @sec:security-domains),
      start-up and privilege drop (section @sec:isolation), protection of
      secrets (section @sec:secrets), output only after self tests and
      seeding (section @sec:output-gate), fallback of the drop-in
      interfaces (section @sec:attacker-model)],
    [ADV_FSP], [External interfaces], [Interface specification (chapter
      @sec:interface-spec), protocols in detail (sections @sec:rpc,
      @sec:egd, @sec:ext-es), command lines (chapter @sec:tools)],
    [ADV_TDS], [Subsystems, modules and their interactions], [Subsystems
      and modules (section @sec:decomposition), processes (section
      @sec:processes), data processing and seeding (sections
      @sec:data-processing, @sec:seeding), state machines (section
      @sec:state-machines), data structures (section @sec:data-structures)],
    [ADV_IMP], [Implementation], [Source code (appendix @sec:source-code),
      code structure (section @sec:code-structure)],
    [AGD], [Guidance for installation and operation], [Chapters
      @sec:building-installing, @sec:build-options, @sec:usage, @sec:tools;
      compliant configurations and their limits (chapter
      @sec:configurations)],
    [ALC], [Life cycle: build, updates, flaw reporting], [Sections
      @sec:usage-updating, @sec:protocol-compat, @sec:vuln-reporting,
      @sec:ci],
    [ATE], [Tests], [Chapter @sec:testing, with what is not tested
      automatically (section @sec:test-gaps); model checking (chapter
      @sec:formal-verification)],
    [AVA], [Vulnerability analysis], [Attacker model with residual risks
      (section @sec:attacker-model), limits (section @sec:limits), security
      tests and fuzzing (sections @sec:security-tests, @sec:fuzzing),
      findings of the model checking (section @sec:fv-findings)],
  )
}
, caption: [Parts of this document by the assurance families of the Common
  Criteria]) <tab:cc-map>

#par(first-line-indent: 0pt)[Where to start:]

/ Testing labs and auditors: chapter @sec:design for the architecture, the
  data processing and the seeding the claims rest on, chapter
  @sec:configurations for the compliant configurations and appendix
  @sec:ais2031-requirements for the requirements of #ac("AIS") 20/31, then the
  assessments of chapters @sec:kernel-es-assessment and @sec:ebpf-assessment,
  the measurements of appendix @sec:measurements, and chapters @sec:hardening
  and @sec:testing on how the #ac("ESDM") is built and tested.

/ Administrators and users: this introduction, chapters
  @sec:building-installing, @sec:usage, @sec:tools and @sec:integrations, and
  the interfaces of section @sec:interfaces.

/ Developers: chapter @sec:development, then the architecture and the
  data processing of chapter @sec:design, chapter @sec:testing and the test
  interfaces of section @sec:test-interfaces.
