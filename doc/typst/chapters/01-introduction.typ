#import "../template.typ": *

= Introduction <sec:introduction>

The ESDM originated from the #link("https://www.chronox.de/lrng")[Linux Random
Number Generator (LRNG)] patch series. Considering the limitations of
maintaining a proper entropy source management inside the confinements of a
kernel and the fact that such actions do not need the privileges of executing
inside the kernel, the LRNG patch series was converted into user space to form
the ESDM. Even in user space, the ESDM can execute completely unprivileged and
thus adds to the overall system security to isolate the operation.

Before discussing the design of the ESDM, the goals of the ESDM design are
enumerated:

+ The ESDM manages the proper seeding and reseeding of DRNGs. In addition, it
  provides internal entropy sources which the ESDM fully controls as well as
  interfaces to obtain data from external entropy sources.

+ The ESDM provides a full API and ABI drop-in replacement for the Linux device
  files of /dev/random and /dev/urandom as well as the Linux getrandom(2)
  system call and the getentropy(3) library calls. All code related to these
  interfaces is solely implemented in user space and executed with limited or
  no privileges.

+ The ESDM is modular consisting of a central server which is implemented with
  minimal dependencies: POSIX support along with `protobuf-c` and `json-c`.
  This allows the ESDM to execute on different operating systems. The
  aforementioned Linux interfaces are implemented with separate processes and
  libraries and therefore their absence do not affect the ESDM operation on
  operating systems other than Linux.

+ All user-visible behavior implemented by the kernel /dev/random – such as the
  per-CPU DRNG instances – is provided by the ESDM as well.

+ The ESDM must not use locking in hot code paths to limit the impact on
  massively parallel systems.

+ The ESDM must handle modern computing environments without a degradation of
  entropy. The ESDM therefore must work in virtualized environments, with
  SSDs, on systems without HIDs or block devices and so forth.

+ The ESDM must provide a design that allows quantitative testing of the
  entropy behavior.

+ The ESDM must use testable and widely accepted cryptography for
  conditioning.

+ The ESDM must allow the use of cipher implementations backed by architecture
  specific optimized assembler code or even hardware accelerators. This
  provides the potential for lowering the CPU costs when generating random
  numbers – less power is required for the operation and battery time is
  conserved.

+ The ESDM must separate the cryptographic processing from the entropy source
  maintenance to allow a replacement of these components.

+ The ESDM shall offer flexible configurations allowing vendors to apply the
  settings applicable to their environment.

== Properties Offered by the ESDM <sec:properties>

Apart from the fact that a user does not need to manage the DRNG and its
seeding status, the ESDM provides the following properties making the ESDM a
contemporary and future-proof entropy source and DRNG management framework:

- Pure user space implementation:

  - The entire ESDM as well as the Linux interfaces are fully implemented in
    user space.

  - Two additional but optional entropy sources are provided for
    resource-constrained systems: the scheduler-based entropy source and the
    interrupt-based entropy source. Both exist in two variants: one is
    provided by a kernel module (`kernel/esdm_es`) which hooks into the
    scheduler / the interrupt handling code path by means of small kernel
    patches, the other one by eBPF programs attached to tracepoints of a
    stock Linux kernel which needs no kernel patches.

  - The ESDM server performs its privileged initialization – creating its
    sockets and its status shared memory segment, loading the eBPF programs and
    initializing the entropy sources needing privileges – and then permanently
    drops its privileges to an unprivileged user (`nobody` by default). The
    Linux interfaces providing /dev/random, /dev/urandom and the associated
    proc files execute with limited privileges.

- Sole use of crypto for data processing:

  - Exclusive use of cryptographic mechanisms for conditioning entropy data
    with a clear mathematical description as given in section
    @sec:data-processing: an SP800-90A DRBG in the kernel module, an
    XDRBG-256 over SHAKE256 for the auxiliary pool and the conditioning pool
    of the eBPF entropy sources, and the conditioning hash for the
    compression of CPU entropy source data – non-cryptographic operations
    like LFSR are not used.

  - The ESDM uses only properly defined and implemented cryptographic
    algorithms unlike the use of the SHA-1 transformation in the legacy Linux
    kernel /dev/random implementation that is not compliant with SHA-1 as
    defined in FIPS 180-4.

  - Per-CPU DRNG instances serve the requests of large parallel systems
    side by side.

  - ESDM uses limited number of data post-processing steps as documented in
    section @sec:data-processing compared to the large variation of different
    post-processing steps in the legacy /dev/random implementation that have
    no apparent mathematical description.

- Performance

  - High-performance implementation of the scheduler entropy source of the
    kernel module requiring only a few cycles to collect entropy.

  - High-performance implementation of the interrupt entropy source of the
    kernel module requiring only a few cycles to collect entropy.

- Testing

  - Availability of run-time health tests of the raw unconditioned entropy
    source data of the scheduler-based and the interrupt-based entropy
    sources to identify degradation of the available entropy. Such health
    tests are important today due to virtual machine monitors reducing the
    resolution of or disabling the high-resolution timer.

  - Heuristic entropy estimation for the interrupt-based entropy source is
    based on quantitative measurements and analysis following SP800-90B; the
    measurement tooling is provided for the scheduler-based and the eBPF-based
    entropy sources as well.

  - Power-on self tests for the critical deterministic components (conditioning
    hash, XDRBG-256 with its SHAKE256, DRNG) and of each entropy source, which
    are repeated periodically at runtime – see section @sec:self-tests.

  - Availability of test interfaces to obtain the raw entropy event data of
    the scheduler-based and interrupt-based entropy sources including
    boot-time raw entropy event data sampling as outlined in section
    @sec:test-interfaces.

  - Availability of stress testing covering the different code paths for data
    and mechanism (de)allocations and code paths covered with locks
    (`esdm-tool` stress tests, fuzz harnesses of the `fuzzing` build option).

  - Availability of fully automated regression testing covering different
    ESDM functions in different configurations allow an unattended functional
    verification testing (meson test suite in the `tests` directory).

- Entropy collection of the internal interrupt and scheduler-based entropy
  source

  - The ESDM scheduler-based and interrupt-based entropy sources of the kernel
    module are designed as SP800-90B entropy sources with health tests applied
    in FIPS mode and are shipped with all required test tools.

  - Full entropy assessment and description of the interrupt entropy source is
    provided with chapter @sec:irq-assessment, specifically section
    @sec:90b-3151.

  - The ESDM provides a configuration to be compliant to SP800-90C following
    RBG2(NP) as well as RBG2(P) construction methods.

  - The ESDM provides an interface allowing the request of random numbers with
    prediction resistance, i.e. requiring an immediate reseed and only
    returning as many bits of data as entropy was available. This shall
    support chaining of DRBGs compliant to SP800-90C.

  - The ESDM provides configurations to be compliant to the German AIS 20/31
    NTG.1 (2011) considering the aforementioned prediction resistance
    interface, to NTG.1 of AIS 20/31 version 3.0 (2024) with its seeding
    strategy, and to the classes DRG.3 and DRG.4.

- Configurable

  - ESDM build-time configuration allows a flexible adoption of the ESDM to
    different use cases. Non-compiled additional code is folded into no-ops.

  - Configurable seeding strategies are provided following different concepts.

== Document Structure <sec:document-structure>

This paper covers the following topics in the subsequent chapters:

- The design of the ESDM is documented in chapter @sec:design. The design
  discussion references to the actual implementation whose source code is
  publicly available.

- The statistical testing of the internal interrupt entropy source including
  the SP800-90B compliance assessment is provided in chapter
  @sec:irq-assessment.

- The statistical testing of the internal scheduler entropy source including
  the SP800-90B compliance assessment is provided in chapter
  @sec:sched-assessment.

- The discussion of various configurations offered by the ESDM is given in
  chapter @sec:configurations.

- The various appendices cover miscellaneous topics supporting the general
  description.
