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
  minimal dependencies. This allows the ESDM to execute on different operating
  systems. The aforementioned Linux interfaces are implemented with separate
  processes and libraries and therefore their absence do not affect the ESDM
  operation on operating systems other than Linux.

+ All user-visible behavior implemented by the kernel /dev/random – such as the
  per-NUMA-node DRNG / per-CPU instances are provided by the ESDM as well.

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
    interrupt-based entropy source. Both, however, uses a kernel extension as
    it hooks into the scheduler / the interrupt handling code path.

  - The ESDM server executes without any privilege. The Linux interfaces
    providing /dev/random, /dev/urandom and the associated proc files execute
    with limited privileges.

- Sole use of crypto for data processing:

  - Exclusive use of a hash operation for conditioning entropy data with a
    clear mathematical description as given section @sec:data-processing –
    non-cryptographic operations like LFSR are not used.

  - The ESDM uses only properly defined and implemented cryptographic
    algorithms unlike the use of the SHA-1 transformation in the Linux kernel
    /dev/random implementation that is not compliant with SHA-1 as defined in
    FIPS 180-4.

  - Hash operations use on-stack hash instances to benefit large parallel
    systems.

  - ESDM uses limited number of data post-processing steps as documented in
    section @sec:data-processing compared to the large variation of different
    post-processing steps in the legacy /dev/random implementation that have
    no apparent mathematical description.

- Performance

  - High-performance implementation of scheduler entropy source requiring only
    a few cycles to collect entropy.

  - High-performance implementation of interrupt entropy source requiring only
    a few cycles to collect entropy which is significantly faster than the
    existing kernel interrupt handler.

- Testing

  - Availability of run-time health tests of the raw unconditioned entropy
    source data of the scheduler-based entropy source to identify degradation
    of the available entropy. Such health tests are important today due to
    virtual machine monitors reducing the resolution of or disabling the
    high-resolution timer.

  - Heuristic entropy estimation for the scheduler-based entropy source is
    based on quantitative measurements and analysis following SP800-90B.

  - Power-on self tests for critical deterministic components (DRNG, hash
    implementation, and entropy collection logic).

  - Availability of test interfaces for all operational stages of the ESDM
    including boot-time raw entropy event data sampling as outlined in section
    @sec:test-interfaces.

  - The ESDM offers a test interface to validate the used software hash
    implementation and in particular that the ESDM invokes the hash correctly,
    allowing a NIST ACVP-compliant test cycle – see section
    @sec:test-interfaces.

  - #link("https://github.com/smuellerDD/lrng/blob/master/test/swap_stress.sh")[Availability
    of stress testing] covering the different code paths for data and
    mechanism (de)allocations and code paths covered with locks.

  - #link("https://github.com/smuellerDD/lrng/blob/master/test/automation")[Availability
    of fully automated regression testing] covering different ESDM functions
    in different configurations allow an unattended functional verification
    testing.

- Entropy collection of the internal interrupt and scheduler-based entropy
  source

  - The ESDM scheduler-based and interrupt-based entropy sources are fully
    compliant to SP800-90B requirements and are shipped with a full SP800-90B
    assessment and all #link("https://www.chronox.de/lrng")[required test
    tools.]

  - Full entropy assessment and description is provided with chapter
    @sec:irq-assessment, specifically section @sec:90b-3151.

  - The ESDM provides a configuration to be compliant to SP800-90C following
    RBG2(NP) as well as RBG2(P) construction methods.

  - The ESDM provides an interface allowing the request of random numbers with
    prediction resistance, i.e. requiring an immediate reseed and only
    returning as many bits of data as entropy was available. This shall
    support chaining of DRBGs compliant to SP800-90C.

  - The ESDM provides a configuration to be compliant to the German AIS 20/31
    NTG.1 considering the aforementioned prediction resistance interface.

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
