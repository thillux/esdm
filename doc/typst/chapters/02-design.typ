#import "../template.typ": *

= ESDM Design <sec:design>

The ESDM can be characterized with figure @fig:big-picture which provides a
big picture of the ESDM processing and components.

#figure(
  image("../figures/big-picture.svg", width: 92%),
  caption: [ESDM Big Picture],
) <fig:big-picture>

The colors indicate the different entropy sources managed by the ESDM.

The ESDM introduces the concept of slow and fast entropy sources. Fast entropy
sources provide entropy at the time of request. A slow entropy source collects
data over time into an entropy pool.

The entropy source that is under full control of the ESDM, also called the
internal entropy source, comprises of the:

- The indigo marked parts refer to the scheduler entropy source that feeds
  per-CPU collection pools. These collection pools are hashed into per-CPU
  entropy pools when seeding of the DRNG is to be performed.

- The orange marked parts refer to the interrupt entropy source which has a
  very similar architecture compared to the scheduler-based entropy source:
  data is fed in per-CPU collection pools to hash them into per-CPU entropy
  pools.

#par(first-line-indent: 0pt)[The following external entropy sources are
present. These entropy sources are expected to be fully self-contained. The
ESDM only requests data from them and expects that the entropy estimate
provided with the data is correct:]

- The auxiliary pool collects data from external entropy sources which deliver
  data at times not controllable by the ESDM.

- The CPU entropy source obtains data from a potentially existing source in
  the CPU like RDSEED on Intel CPUs.

- The Jitter RNG entropy source is another external entropy source.

- The random number generator provided with the `getrandom` system call or the
  /dev/random device file can be enabled at compile time to serve as an
  entropy source.

- Using the Linux hardware random number generator (/dev/hwrng) as seed source
  that may obtain data from various hardware sources including TPM v2.0.

#par(first-line-indent: 0pt)[The ESDM treats all external and internal entropy
sources equally. It can handle the situations where one or more entropy
sources returns little or no entropy.]

The the scheduler entropy source is assessed in chapter @sec:sched-assessment
which provides its complete entropy assessment. All other entropy sources are
expected to provide their own entropy assessment supporting the claim of the
supplied entropy that is credited by the ESDM for these sources. The ESDM
treats these additional entropy sources as black boxes and take their claimed
entropy rate at face value. The ESDM, however, guarantees that all entropy
sources are processed in compliance with defined standards.

The different colors used in figure @fig:big-picture depict the different
entropy sources mentioned before.

The ESDM offers various interfaces to obtain random numbers as depicted in
figure @fig:interfaces.

#figure(
  image("../figures/interfaces.svg", width: 95%),
  caption: [ESDM Interfaces To Obtain Random Numbers],
) <fig:interfaces>

Based on this figure, the following types of interfaces are available which
are marked with the different colors in figure @fig:interfaces. Each type of
interface can be selectively enabled and disabled at compile time:

- Linux RNG interfaces: The common interfaces found from today's Linux kernels
  include /dev/random, /dev/urandom, the `getrandom` system call or the
  `getentropy` C-library wrapper. These interfaces behave identically to the
  Linux RNG and thus allow the ESDM to act as a drop-in replacement. When not
  compiling those, the ESDM can be operated in parallel with the Linux RNG and
  all user space software divert to use the ESDM.

- The ESDM also exports a set of Unix Domain Sockets to /var/run which can be
  used directly, albeit it is not advised to be used as the protocol offered
  by those sockets is defined to be not stable, i.e. it can change from one
  version to another.

- To wrap the mentioned Unix Domain Sockets, the ESDM RPC library is available
  which offers a stable API.

- The ESDM library provides the heart of the ESDM functionality. It could be
  directly used by a calling application. Yet, it is advised to use the RPC
  interface as it is provided by a daemon that uses the ESDM library already.

#par(first-line-indent: 0pt)[The ESDM consists of the following components:]

- `libesdm.so`: The ESDM provides a library with the core of the ESDM. The
  DRNG and entropy source managers together with all entropy sources and
  cryptograpphic algorithm implementations are implemented with this library.
  This library is wrapped by the `esdm-server` listed below. The API for using
  the library is exported by and documented with `esdm.h`.

  The library is provided in case a user wants to employ the ESDM in his
  projects instead of the `esdm-server`. Yet, the `esdm-server` provides a
  wrapping daemon to the ESDM library that is intended to be commonly used.

  In addition, the ESDM can be configured with the options specified in
  `esdm_config.h`. This would need to be performed by the consuming
  application. When using the tools below, this library can be ignored.

- `esdm-server`: The ESDM server provides the RPC server that encapsulates the
  ESDM with its random number generator and the entropy source management.
  When starting the server, the mentioned Unix Domain Sockets are created that
  allows clients to request services including random numbers.

  The ESDM server can either be started manually or with the provided (and
  installed) systemd unit file. When using systemd, start the server with
  ‘systemctl start esdm-server‘.

  A wrapper library to access the ESDM server RPC interface is provided with
  `libesdm_rpc_client.so`. Its API is specified and documented with
  `esdm_rpc_client.h`.

  The `esdm-server` is the backend to all of the following ESDM components.

  Note: The Unix domain sockets of the `esdm-server` are only visible in the
  respective mount namespace. If you have multiple mount namespaces, you need
  to start the daemon in each mount namespace or make the files otherwise
  available if its services shall be available there.

- `esdm-cuse-random`: The ESDM CUSE daemon creates a device file that behaves
  identically to /dev/random. It must be started as root. Reading, writing and
  IOCTLs are implemented in an ABI-compatible way.

  The ESDM CUSE daemon can either be started manually or with the provided
  (and installed) systemd unit file. When using systemd, start the server with
  ‘systemctl start esdm-cuse-random‘. Although the daemon creates a
  /dev/random device, the actual visible operation is atomic (a bind mount)
  for both creation and destruction of the new device file which implies that
  the daemon can be started and stopped at any time during runtime of the
  Linux OS.

  Note: The bind mount is only visible in the respective mount namespace. If
  you have multiple mount namespaces, you need to start these daemons in each
  mount namespace or make the files otherwise available if their services
  shall be available there.

- `esdm-cuse-urandom`: Same as esdm-cuse-random but behaving like
  /dev/urandom.

- `esdm-proc`: This FUSE file system implements all files found on a Linux
  system under /proc/sys/kernel/random but pointing to the ESDM server. This
  process is required to ensure that all interfaces are provided by ESDM. For
  details about the provided files, see the `random(4)` man page. Note, the
  kernel exports the /proc/sys/kernel/random information also as
  `sysctl(8)`. This interface is not covered by ‘esdm-proc‘.

- `libesdm-getrandom.so`: The library provides a wrapper to the `getrandom`
  and `getentropy` Linux C-library calls. To use the library for other
  consumers, use one of the following considerations:

  - Use `LD_PRELOAD="/path/to/libesdm-getentropy.so"` with the intended
    application.

  - Compile the application or library with the following options:

    - `LDFLAGS += -Wl,--wrap=getrandom,--wrap=getentropy`
    - `LDFLAGS += -lesdm-getrandom`

== ESDM Components <sec:components>

The ESDM consists of the following components shown in figure
@fig:big-picture:

+ The ESDM implements a DRNG. Unless using the interface providing prediction
  resistance, the DRNG always generates the requested amount of output. When
  using the SP800-90A terminology it operates without prediction resistance.
  The DRNG maintains a counter of how many bytes were generated since last
  re-seed and a timer of the elapsed time since last re-seed. If either the
  counter or the timer reaches a threshold, the DRNG is seeded from the
  entropy sources with the available entropy.

  In case the Linux kernel detects a NUMA system, one DRNG instance per NUMA
  node is maintained.

  Depending on the used interface to request data from the DRNG, the caller
  may be put to sleep until the ESDM is fully seeded:

  + All interfaces using the `esdm_get_entropy_bytes` function always
    generates data including when the ESDM is not properly seeded.

  + All interfaces using the `esdm_get_entropy_bytes_full` function generate
    data only when the ESDM is fully seeded and fully initialized.

  + When using the `esdm_get_entropy_bytes_pr` function, the special DRNG
    instance which operates with prediction resistance is used such that it is
    reseeded from the entropy sources and generates at most as much data as
    entropy was added. This implies the DRNG operates with
    prediction-resistance (SP800-90A terminology) or is NTG.1 compliant
    (German BSI AIS 20/31 from 2011). In addition, when the ESDM executes in
    FIPS mode, the behavior complies with all FIPS requirements allowing the
    output of the API to be claimed to be from a vetted conditioning
    component. I.e. the caller may safely use this data to seed another DRBG.
    To achieve this, the following checks are applied in the function
    `esdm_drng_get`:

    - Require a reseed - in FIPS mode, the ESDM requires the availability of
      at least 256 bits of entropy in its entropy sources for the reseed to
      commence.

    - Produce at most only 256 bits of random bits from the DRNG (i.e. the
      security strength of the DRNG).

+ The DRNG is seeded by concatenating the data from the following sources in
  case they are enabled at compile time:

  + the output of the auxiliary pool,
  + the output of the per-CPU interrupt entropy pools,
  + the output of the per-CPU scheduler entropy pools,
  + the Jitter RNG if available,
  + the CPU-based entropy source such as Intel RDSEED if available,
  + the kernel RNG output, and
  + the Linux kernel HWRAND framework (/dev/hwrng).

  The entropy estimate of the data of all entropy sources are added to form
  the entropy estimate of the data used to seed the DRNG with. The ESDM
  ensures, however, that the DRNG after seeding is at maximum the security
  strength of the used DRNG implementation of 256 bits.

  The ESDM is designed such that none of these entropy sources can dominate
  the other entropy sources to provide seed data to the DRNG due to the
  following:

  + During boot time, the amount of available entropy is the trigger point to
    (re)seed the DRNG following the explanation in the next section.

  + At runtime, the the DRNG reseed is triggered by either the DRNG due to
    hitting the aforementioned thresholds or by a user space caller. The
    reseed is never triggered by the entropy sources.

+ To support backward secrecy, the following steps are applied:

  + The temporary seed buffer holding the concatenation of data from all
    entropy sources to seed the DRNG is injected into the auxiliary pool like
    other data by hashing it together with the existing auxiliary pool data to
    form the new auxiliary pool content. The injection of the temporary seed
    buffer will not alter the entropy estimation of the auxiliary pool.

  + The message digest created for each per-CPU entropy pool of the scheduler
    and interrupt entropy sources is inserted into the corresponding per-CPU
    entropy pool.

#par(first-line-indent: 0pt)[The ESDM allows the DRNG mechanism and the used
hash to be changed at compile time. Per default, an SP800-90A Hash DRBG
implementation along with a SHA-512 hash implementation is available. Both are
standard C implementations which were tested against NIST's ACVP service.]

The following subsections cover the different components of the ESDM from the
bottom to the top.

== ESDM Data Processing <sec:data-processing>

The processing of entropic data from the different entropy source before
injecting them into the DRNG is performed with the following mathematical
operations. The operation $"SHA"()$ refers to the hash operation using the
message digest implementation that is currently present, i.e. SHA-512.

=== Scheduler and Interrupt Entropy Sources <sec:dp-sched-irq>

+ Truncation: The time stamps received by the IRQ as well as the scheduler
  entropy sources are truncated to 8 least significant bits (or 32 least
  significant bits during boot time) – note the GCD is a value calculated
  during initialization and is fixed thereafter which implies that the time
  stamp divided by the GCD is the raw entropy value: $t_8$ (or $t_32$)

+ Concatenation: The time stamps received and truncated by the IRQ and
  scheduler entropy sources as well as auxiliary 32 bit words $a_32$ are
  concatenated to fill the per-CPU collection pool that is capable of holding
  1,024 8-bit words#footnote[The ESDM collection size is compile-time
  configurable where 1,024 is a default value. When configuring a different
  value, the number of the concatenated data must be adjusted as needed.
  However, this modification has no impact to the illustration of the data
  processing.] - the order of the data $a_32$ or $t_8$ present in the
  concatenation depends on the occurrence of events - the following formula
  depicts one possible order for illustration - the implementation is provided
  with functions `_esdm_pcpu_array_add_u32` and `esdm_pcpu_array_add_slot`:

  $ "CP" = t_(8_(n-1019)) || a_(32_n) || t_(8_(n-1018)) || ... || t_(8_n) $
  <eq:cp>

  Note: In case the continuous compression operation is disabled for the IRQ
  entropy source, the auxiliary 32 bit words $a_32$ are discarded and are not
  injected into the collection pool. This approach is taken to prevent
  non-entropy data to potentially overwrite entropy data in the collection
  pool when the array wraps. The scheduler entropy source only records time
  stamps.

=== Interrupt Entropy Source <sec:dp-irq>

+ Hashing: For the IRQ entropy source all concatenated time stamp data
  received from the interrupts since the last output generation of the
  per-CPU entropy pool $"EP"_("CPU"_(n-1))$ are hashed together with that last
  output $"EP"_("CPU"_(n-1))$ to generate new per-CPU entropy pool output of
  $"EP"_("CPU"_n)$. The following steps are performed:

  + One filled per-CPU collection pool for the interrupt entropy source
    $"CP"_("IRQ"_m)$ is inserted into the per-CPU entropy pool using a hash
    update operation.

  + To generate data from the entropy pool $"EP"_("CPU"_n)$ as used by
    function @eq:ep-all, a hash final operation is performed.

  + Once a hash final operation is performed it is followed by an immediate
    re-initialization of the hash state with a hash init operation and adding
    the just calculated message digest with the first hash update.

  The implementation is provided with function `esdm_pcpu_array_compress`
  together with the function `esdm_pcpu_pool_hash_one` generating data from
  the per-CPU entropy pool:

  $ "EP"_("CPU"_n) = "SHA"("EP"_("CPU"_(n-1)) || "CP"_("IRQ"_(m-(n-1)))
    || ... \ || "CP"_("IRQ"_(m-1)) || "CP"_("IRQ"_m)) $ <eq:ep-cpu>

  Note: The hash update operation is performed at the following occasions:

  + Continuous compression enabled: The hash update is performed every time
    the collection pool is full. This operation therefore is performed in
    interrupt context. In addition, the operation is performed at the time
    operation of equation @eq:ep-all is invoked which is in process context.

  + Continuous compression enabled and disabled: The hash update is performed
    at the time the operation of equation @eq:ep-all is invoked, i.e. at the
    time the DRNG is reseeded. This operation therefore is performed in
    process context. This guarantees that all unprocessed entropy data in the
    collection pool is added to the entropy pool at the time the entropy pool
    is requested for random data.

  This implies that in case of disabled continuous compression, the oldest
  entries in the collection pool are overwritten with newer entropy event data
  when more entropy events are collected than can be held in the collection
  pool between DRNG reseeds.

+ Hashing: For the IRQ entropy source, a message digest of all per-CPU entropy
  pools is calculated. This message digest is used to fill the interrupt
  entropy source output buffer $S$ discussed in the following - the
  implementation is provided with function `esdm_pcpu_pool_hash`:

  $ "EP"_("all"_n) = "SHA"("EP"_("CPU0"_n) || "EP"_("CPU1"_n) || ...
    || "EP"_("CPUX"_n)) $ <eq:ep-all>

+ Truncation: For the interrupt entropy pool, the most-significant bits (MSB)
  defined by the requested number of bits (commonly equal to the security
  strength of the DRBG) or the entropy available transported with the buffer
  (which is the minimum of the message digest size and the available entropy
  in all entropy pools), whatever is smaller, are obtained from the interrupt
  entropy source output buffer $S$ - the implementation is provided with
  function `ESDM_pcpu_pool_hash`:

  $ E_n = "MSB"_(min("entropy", "security strength"))("EP"_("all"_n)) $
  <eq:e>

=== Scheduler Entropy Source <sec:dp-sched>

+ Hashing: For the scheduler-based entropy source, all concatenated time stamp
  data received from the interrupts since the last output generation of the
  per-CPU entropy pool $"SP"_("CPU"_(n-1))$ are hashed together with that last
  output $"SP"_("CPU"_(n-1))$ to generate new per-CPU entropy pool output of
  $"SP"_("CPU"_n)$. The following steps are performed:

  + One filled per-CPU collection pool for the interrupt entropy source
    $"CP"_("SCHED"_m)$ is inserted into the per-CPU entropy pool using a hash
    update operation.

  + To generate data from the entropy pool $"SP"_("CPU"_n)$ as used by
    function @eq:sp-all, a hash final operation is performed.

  + Once a hash final operation is performed it is followed by an immediate
    re-initialization of the hash state with a hash init operation and adding
    the just calculated message digest with the first hash update.

  The implementation is provided with function `esdm_sched_pool_hash_one`
  generating data from the per-CPU entropy pool:

  $ "SP"_("CPU"_n) = "SHA"("SP"_("CPU"_(n-1)) || "CP"_("SCHED"_(m-(n-1)))
    || ... \ || "CP"_("SCHED"_(m-1)) || "CP"_("SCHED"_m)) $ <eq:sp-cpu>

  Note: The hash update is performed at the time the operation of equation
  @eq:sp-all is invoked, i.e. at the time the DRNG is reseeded. This operation
  therefore is performed in process context. This guarantees that all
  unprocessed entropy data in the collection pool is added to the entropy
  pool at the time the entropy pool is requested for random data. This implies
  that he oldest entries in the collection pool are overwritten with newer
  entropy event data when more entropy events are collected than can be held
  in the collection pool between DRNG reseeds.

+ Hashing: For the scheduler-based entropy source, a message digest of all
  per-CPU entropy pools is calculated. This message digest is used to fill the
  interrupt entropy source output buffer $S$ discussed in the following - the
  implementation is provided with function `esdm_sched_pool_hash`:

  $ "SP"_("all"_n) = "SHA"("SP"_("CPU0"_n) || "SP"_("CPU1"_n) || ...
    || "SP"_("CPUX"_n)) $ <eq:sp-all>

+ Truncation: Just like the interrupt entropy source, the scheduler entropy
  source applies a truncation to the generated data as implemented by the
  function `esdm_sched_pool_hash`:

  $ S_n = "MSB"_(min("entropy", "security strength"))("SP"_n) $ <eq:s>

=== Auxiliary Entropy Pool <sec:dp-aux>

+ Hashing: When new data $D_m$ is added to the auxiliary pool $"AP"$, the data
  is inserted into the auxiliary pool with a hash update operation - the
  implementation is provided with function `ESDM_pool_insert_aux`. The message
  digest generation is performed at the time entropy from the auxiliary pool
  is requested. To ensure backward secrecy, the temporary seed buffer
  $T_(n-1)$ that holds among others the auxiliary pool digest from the
  previous generation round as depicted with equation @eq:t is concatenated
  with the received data:

  $ "AP"_n = "SHA"(T_(n-1) || D_(m-(n-1)) || ... || D_(m-1) || D_m) $ <eq:ap>

+ Truncation: The MSB of the auxiliary pool of the size of the DRNG security
  strength are used for the seed buffer:

  $ A_n = "MSB"_(min("digest size", "security strength"))("AP"_n) $ <eq:a>

=== CPU Entropy Source <sec:dp-cpu>

+ Hashing: If the CPU entropy source provides less than full entropy, a
  message digest of the amount of data to be requested from it is calculated:

  $ C_"cond" = "SHA"(C_1 || ... || C_m) $ <eq:c-cond>

+ Truncation: If the CPU entropy source provides less than full entropy, the
  MSB defined by the requested number of bits (commonly equal to the security
  strength of the DRBG) or the applied message digest size, what ever is
  smaller, are obtained - the implementation is provided with function
  `ESDM_get_arch_data_compress` – otherwise $C_n$ is the data obtained
  directly from the CPU entropy source:

  $ C_n = "MSB"_(min("digest size", "security strength"))(C_"cond") $ <eq:c>

=== Temporary Seed Buffer Construction <sec:dp-seed-buffer>

+ Concatenation: The temporary seed buffer $T$ used to seed the DRNG at the
  time $n$ is a concatenation of one or more of the following entropy source
  data sets, depending on the compile-time configuration:

  + the auxiliary pool entropy source $A$,
  + the interrupt entropy source buffer $E$,
  + the scheduler entropy source buffer $S$,
  + the Jitter RNG output $J$,
  + the CPU entropy source output $C$,
  + the kernel RNG entropy source output $K$,
  + the Linux HWRAND framework $H$,and
  + the current time $t$

  with the implementation is provided with function `esdm_fill_seed_buffer`:

  $ T_n = A_n || E_n || S_n || J_n || C_n || K_n || H_n || t $ <eq:t>

== ESDM Architecture <sec:architecture>

Before going into the details of the ESDM processing, the concept underlying
the ESDM shown in figure @fig:big-picture is provided here.

The entropy derived from the slow entropy sources is collected and accumulated
in the entropy pools which contain already compressed entropy data, supported
by the collection pools which contain uncompressed, but only concatenated
entropy data.

At the time the DRNG shall be seeded, the all entropy pools, any
non-compressed data in the collection pools and the auxiliary pool are
processed with a cryptographic hash function which can be chosen at runtime.

For the entropy pool, if the digest of the hash and the available entropy are
larger than requested by the caller, the digest is truncated to the
appropriate size. For the auxiliary pool, always 256 bits of data are returned
irrespective of the entropy rate of this pool. This ensures that also data
that is not credited with entropy but injected into the ESDM is used to stir
the seed for the DRNG.

The DRNG always tries to seed itself with 256 bits of entropy, except during
boot. In any case, if the entropy sources cannot deliver that amount, the
available entropy is used and the DRNG keeps track on how much entropy it was
seeded with. The entropy implied by the ESDM available in the entropy pool may
be too conservative. To ensure that during boot time all available entropy
from the entropy pool is transferred to the DRNG, the hash function always
generates 256 data bits during boot to seed the DRNG. During boot, the DRNG is
seeded as follows:

+ The DRNG is reseeded from the entropy sources if all entropy sources
  collectively have at least 256 bits of entropy available.

#par(first-line-indent: 0pt)[The ESDM also implements a forced seeding
operation. This is performed when a blocking interface has blocked a request 5
times because the DRNG is not fully seeded. The forced seeding performs a
continuous reseeding of the DRNG in an atomic operation with existing entropy.
This means that a regular reseeding is triggered repeatedly as often as needed
to obtain 256 bits of entropy to reach the fully seeded level. In this case,
the entropy obtained from the entropy sources is added up. This is permissible
because the multiple reseeding operations are performed while the DRNG is
locked, i.e. the DRNG will not produce output in that time.]

At the time of the reseeding steps, the DRNG requests as much entropy as is
available in order to skip certain steps and reach the seeding level of 256
bits. This may imply that one or more of the aforementioned steps are skipped.

In all listed steps, the DRNG is (re)seeded with a number of random bytes from
the entropy pool that is at most the amount of entropy present in the entropy
pool. This means that when the entropy pool contains 128 or more bits of
entropy, the DRNG is seeded with that amount of entropy as well.

Before the DRNG is seeded with 256 bits of entropy in the last step, requests
of random data from the blocking interfaces are not processed.

At runtime the DRNG operates as deterministic random number generator with the
following properties:

- The maximum number of random bytes that can be generated with one DRNG
  generate operation is limited to 4096 bytes. When longer random numbers are
  requested, multiple DRNG generate operations are performed. The used DRNGs
  implement an update of their state during the generation operation for
  backward secrecy.

- The DRNG is reseeded with whatever entropy is available, but at least 128
  bits (256 bits if SP800-90C compliance is enabled) – in the worst case where
  no additional entropy can be provided by the entropy sources, the DRNG is
  not re-seeded and continues its operation to try to reseed again after again
  the expiry of one of these thresholds:

  - If the last reseeding of the DRNG is more than 600 seconds
    ago#footnote[Note, this value will not empty the entropy pool even on a
    completely quiet system. Testing of the ESDM was performed on a KVM
    without fast entropy sources and with a minimal user space, where only the
    SSH daemon was running, During the testing, no operation was performed by
    a user. Yet, the system collected more than 256 bits of entropy from the
    interrupt entropy source within that time frame, satisfying the DRNG
    reseed requirement.], or

  - $2^20$ DRNG generate operations are performed, whatever comes first, or

  - the DRNG is forced to reseed before the next generation of random numbers
    if data has been injected into the ESDM by writing data into /dev/random
    or /dev/urandom or the respective RPC interfaces.

  The chosen values prevent high-volume requests from user space to cause
  frequent reseeding operations which drag down the performance of the
  DRNG#footnote[Considering that the maximum request size is 4096 bytes
  defined by `ESDM_DRNG_MAX_REQSIZE` (i.e. each request is segmented into 4096
  byte chunks) and at most $2^20$ requests defined by
  `ESDM_DRNG_RESEED_THRESH` can be made before a forced reseed takes place, at
  most $4096 dot 2^20 = 4,294,967,296$ bytes can be obtained from the DRNG
  without a reseed operation.].

- If the DRNG was not reseeded for the last $2^30$ DRNG generate operations –
  i.e. the reseeding requests discussed in the previous bullets were
  unsuccessful – the DRNG reverts back to an unseeded state. This applies that
  the DRNG will not produce random numbers when accessed via the blocking
  interfaces. In this case, the DRNG behaves like during boot time.

#par(first-line-indent: 0pt)[With the automatic reseeding after 600 seconds,
the ESDM is triggered to reseed itself before the first request after a
suspend that put the hardware to sleep for longer than 600 seconds.]

=== Minimally Versus Fully Seeded Level <sec:seed-levels>

The ESDM's DRNG is reseeded when the first 128 bits / 256 bits of entropy are
received during boot as indicated above. The 128 bits level defines that that
the DRNG is considered “minimally” seeded whereas reaching the 256 bits level
is defined as the DRNG is “fully” seeded.

Both seed levels have the following implications:

- Upon reaching the minimally seeded level, the kernel-space callers waiting
  for a seeded DRNG via the API calls of either `esdm_get_random_bytes_min` is
  woken up.

- When reaching the fully seeded level, the user-space callers waiting for a
  fully seeded DRNG via the `getrandom` system call or /dev/random are woken
  up. Using the ESDM API of `esdm_get_random_bytes_full`, the caller is
  waiting synchronously until the fully seeded level is reached.

=== NUMA Systems <sec:numa>

To prevent bottlenecks in large systems, the DRNG will be instantiated once
for each NUMA node. The instantiations of the DRNGs happen all at the same
time when the ESDM is initialized.

The question now arises how are the different DRNGs seeded without re-using
entropy or relying on random numbers from a yet insufficiently seeded ESDM.
The ESDM seeds the DRNGs sequentially starting with the one for NUMA node zero
– the DRNG for NUMA node zero is seeded with the approach of 256 bits of
entropy stepping discussed above. Once the DRNG for NUMA node 0 is seeded with
256 bits of entropy, the ESDM will seed the DRNG of node one when having again
256 bits of entropy available. This is followed by seeding the DRNG of node
two after having again collected 256 bits of entropy, and so on. Figure
@fig:numa illustrates the seeding strategy showing that each DRNG instance is
freshly seeded with a separate seed buffer.

#figure(
  image("../figures/numa-drng.svg", width: 83%),
  caption: [DRNG Instances on NUMA systems with seeding strategy],
) <fig:numa>

When producing random numbers, the ESDM tries to obtain the random numbers
from the NUMA node-local DRNG. If that DRNG is not yet seeded, it falls back
to using the DRNG for node zero.

Note, to prevent draining the entropy pool on quiet systems, the time-based
reseed trigger, which is 600 seconds per default, will be increased by 100
seconds for each activated NUMA node beyond node zero. Still, the
administrator is able to change the default value at runtime.

=== Flexible Design <sec:flexible-design>

Albeit the preceding sections look like the DRNG and the management logic are
highly interrelated, the ESDM code allows for an easy replacement of the DRNG
with another deterministic random number generator. This flexible design
allowed the implementation of the ChaCha20 DRNG if the SP800-90A DRBG is not
desired.

To implement another DRNG, all functions in `struct esdm_drng_cb` in
“esdm\_crypto.h” must be implemented. These functions cover the
allocation/deallocation of the DRNG as well as its usage. Similarly, all
functions in `struct esdm_hash_cb` from “esdm\_crypto.h” must be implemented
to provide the the conditioning hash.

The implementations can be changed at compile time. The default
implementation is the SP800-90A Hash-DRBG using a software-implementation of
the used SHA-512 message digest for accessing the entropy pools.

In addition, the ESDM allows the addition of new entropy sources.

== ESDM Data Structures <sec:data-structures>

The ESDM uses the following main data structures:

- The data from the interrupt entropy source is processed with a per-CPU
  entropy pool. In addition, a per-CPU collection pool that can hold the
  concatenated time stamps is maintained. Both are accessed lockless since the
  currently executing CPU's entropy pool and collection pool is used. During
  access to the entropy pool, the ESDM though takes a lock since the entropy
  pool is also read when the hash is calculated for filling the seed buffer.
  As the filling of the seed buffer is very infrequently (see above for the
  reseed periods of the DRNG), the lock is hardly contented which allows the
  conclusion that the entropy collection operates quasi-lockless.

- The scheduler entropy source defines per-CPU collection pools. The entropy
  pools are not maintained as compression of scheduler-based entropy sources
  is only performed when the DRNG shall be (re)seeded. The entire
  scheduler-based entropy source operates lock-less.

- The cryptographic algorithm data structures hold the reference to the DRNG
  instance and the hash instance and associated meta data needed for its
  operation. When using the DRNG, a full read/write lock is used to guard (a)
  against replacement of the DRNG reference while operating on the DRNG state,
  and (b) to read/write the DRNG state. Contrarily when using the hash, only a
  read-lock is used to guard against the replacement of the hash reference.
  This implies that the hash state is kept on the stack of the calling
  application.

== Interrupt Processing - ESDM-internal Entropy Source <sec:irq-processing>

The ESDM hooks a callback into the bottom half interrupt handler at the same
location where the legacy /dev/random places its callback hook.

The ESDM interrupt processing callback is a void function that also does not
receive any input from the interrupt handler. That interrupt processing
callback is the hot code path in the ESDM and special care is taken that it is
as short as possible and that it operates without locking.

Figure @fig:irq-processing illustrates the interrupt processing performed by
the ESDM. The figure specifies which parts of the interrupt processing execute
in IRQ context and which executes in process context. The operations executed
in interrupt context are all completely listed in this section. All steps
executed in process context are illustrated in section @sec:seeding.

The figure depicts the example when one interrupt arrives on CPU 0. If an
interrupt arrives on another CPU, the same operation is applied, but the
respective CPU-local collection pool and entropy pool is used. The entropy
pools from other CPUs in the figure therefore are filled with the same
processing steps, which, however, are not shown.

#figure(
  image("../figures/irq-processing.svg", width: 83%),
  caption: [Interrupt Processing],
) <fig:irq-processing>

The following processing happens when an interrupt is received and the ESDM
is triggered:

+ A high-resolution time stamp is obtained using the service
  `random_get_entropy` kernel function. This integer value is divided by a GCD
  to eliminate bits that do not change. Although that function returns a
  64-bit integer, only the bottom 8 bits, i.e. the fast moving bits, are used
  for further processing. To ensure fast processing, these 8 bits are
  concatenated and stored in the operating CPU's data collection pool. After
  the receipt of 1,024 time stamps, the data collection pool with all
  concatenated time stamps is inserted into the currently executing CPU's
  entropy pool. During boot time until the ESDM completed the calculation of
  the GCD, the 32 least significant bits of the data are directly inserted
  into the CPU's entropy pool. Entropy is contained in the variations of the
  time of events and its time delta variations. Figure @fig:big-picture
  depicts the time stamp array holding the 8-bit time stamp values.

+ The health tests discussed in section @sec:health-tests are performed on
  each received time stamp where the truncated time stamp value is forwarded
  to the health test. Unless 1,024 time stamps have been received, the
  processing of an interrupt stops now.

+ The per-CPU collection pool is added to the same CPU's entropy pool by
  performing a hash update operation. This approach works as the per-CPU
  entropy pool is managed as the message digest state. When data of the
  per-CPU entropy is to be extracted, a hash final operation is performed
  followed by an immediate re-initialization of the state buffer using the
  message digest of the previous extraction. This operation is depicted in
  figure @fig:collection-pool for the entropy pool maintained by CPU 0. The
  other CPUs perform the same processing with their independent copy of the
  collection pool and the entropy pool. In case the continuous compression
  support is disabled, the hash operation is not performed. Instead, the
  oldest entropy values in the collection pool are overwritten with the latest
  entropy value. In case the continuous compression operation is disabled,
  the hash update operation is conducted in process context at the time of
  obtaining random numbers from the entropy pool requested to seed the DRNG
  documented in section @sec:seeding.

  #figure(
    image("../figures/collection-pool-processing.svg", width: 62%),
    caption: [Collection Pool Processing],
  ) <fig:collection-pool>

+ The ESDM increases the per-CPU counter of the received interrupt events by
  the number of healthy interrupts stored in the per-CPU collection pool. This
  counter is translated into an entropy statement when the ESDM wants to know
  how much entropy is present in the entropy pool. This counter is also
  adjusted when reading data from the entropy.

+ The ESDM server implements a monitor thread that polls the interrupt ES for
  its entropy level until all DRNGs become fully seeded. While the poll
  monitor is active, every time the interrupt ES entropy rate reaches the
  security strength of the ESDM, a reseed is triggered as discussed in section
  @sec:seeding.

+ If all DRNG instances are fully seeded, the poll monitor stops. This implies
  that only during boot time the next step is triggered. At runtime, the
  entropy sources will not trigger a reseeding of the DRNG.

#par(first-line-indent: 0pt)[The entropy collection mechanism is available
immediately after the kernel RNG reached full entropy. This shall guarantee
that the kernel RNG is fully seeded before hijacking its main entropy source.
To prevent starving the kernel RNG, the ESDM server starts a thread that
reseeds the kernel RNG once every 2 minutes with 256 bits of data.]

In case the underlying system does not support a high-resolution time stamp,
step 2 in the aforementioned list is changed to fold the following 32 bit
values each into one bit and XOR all of those bits to obtain one final bit:

- IRQ number,
- High 32 bits of the instruction pointer,
- Low 32 bits of the instruction pointer,
- A 32 bit value obtained from a register value – the ESDM iterates through
  all registers present on the system.

=== Entropy Amount of Scheduling Events <sec:entropy-sched-events>

The discussion of the entropy content of interrupt events in section
@sec:entropy-interrupts applies to the scheduler-based entropy. The only
difference is the use of a different compile-time entropy value of
`ESDM_IRQ_ENTROPY_RATE.`

=== Health Tests <sec:irq-health-tests>

The health tests documented in section @sec:health-tests are applied to the
scheduler entropy source as well. The ESDM ensures that the health tests for
the interrupt and the scheduler entropy sources are strictly separated. This
separation applies to the SP800-90B as well.

== Scheduler Events - ESDM-internal Entropy Source <sec:sched-events>

The ESDM hooks into the scheduling operation of the Linux kernel which is
triggered every time a context switch is performed as initiated by the
scheduler. The ESDM handling of a scheduling event is depicted with figure
@fig:sched-processing.

#figure(
  image("../figures/sched-processing.svg", width: 73%),
  caption: [Scheduler-event Processing],
) <fig:sched-processing>

When a context switch occurs, the ESDM callback is invoked which obtains a
high-resolution time stamp that is concatenated into the CPU-local collection
pool. When the CPU-local collection pool is full, the oldest entries are
overwritten by the latest time stamp.

At the time the DRNG shall be (re)seeded, a message digest of each scheduler
per-CPU collection pool is calculated to fill the per-CPU scheduler entropy
pool as outlined in figure @fig:sched-pool. This figure shows that first the
collection pool is inserted into a per-CPU scheduler entropy pool which then
is inserted into the temporary seed buffer. This guarantees that “unused
entropy” is appropriately protected by the per-CPU scheduler entropy pool. The
data processing concepts between the scheduler ES and the interrupt ES are
identical when comparing the figures in this section to section
@sec:irq-processing.

#figure(
  image("../figures/sched-pool-management.svg", width: 62%),
  caption: [Scheduler per-CPU Entropy Pool Management],
) <fig:sched-pool>

This entire message digest calculation is performed in the process context.
Therefore, the hashing operation is not performed as part of the scheduling
operation. The message digest is truncated to the entropy available in all
scheduler per-CPU collection pools or the requested amount of entropy,
whatever is smaller. Note, the requested amount of entropy is always smaller
or equal to the size of the message digest of the used hashing algorithm.

As a side note, the scheduler entropy source potentially has some
relationship with the IRQ entropy source because an IRQ may trigger a
scheduler event (e.g. with the flag `TIF_NEED_RESCHED`). Therefore, both
entropy sources cannot be used at the same time and credit entropy to both.
It is permissible to use both, but only one is credited with entropy.

=== Entropy Amount of Interrupts <sec:entropy-interrupts>

The question now arises, how much entropy is generated with the scheduler
entropy source. The current implementation implicitly assumes one bit of
entropy per time stamp obtained for one scheduling event.

With the kernel compile time parameter of `ESDM_SCHED_ENTROPY_RATE` the number
of interrupts that must be collected to obtain 256 bits of entropy can be
specified. This value is forced by the ESDM to be at least the aforementioned
limit, i.e. 256 interrupts.

The entropy of high-resolution time stamps is provided with the fast-moving
least significant bits of a time stamp which is supported by the quantitative
measurements shown in section @sec:sched-assessment. Although only one bit of
entropy is assumed to be delivered with a given time stamp the ESDM uses the 8
least significant bits (LSB) of the time stamp to provide a cushion for
ensuring that at any given time stamp there is always at least one bit of
entropy collected on all types of environments.

However, the question may be raised of why not use more data of the time
stamp, i.e. why not using 32 bits or the full 64 bits of the time stamp to
increase that cushion? There main answer is performance and memory
consumption. The collection of a time stamp is performed as part of an
scheduling function. Therefore, the performance of the ESDM in this code
section is highly performance-critical. To limit the impact on the scheduler,
the ESDM concatenates the 8 LSB of 1,024 time stamps received by the current
CPU. The second aspect is that the higher bits of the time stamp must always
be considered to have zero bits of entropy when considering the worst case of
a skilled attacker. As the ESDM cannot identify whether it is under attack by
a skilled attacker, it always assumes it is under attack.

The Linux kernel allows unprivileged user space processes to monitor the
scheduling events of interrupts by reading the process listing with a certain
degree of accuracy. The ESDM uses a high-resolution time stamp that executes
with nanosecond precision on 1 GHz systems. Local attackers are expected to be
measure the occurrence of a scheduling event with a microsecond precision. The
distance between a microsecond and a nanosecond is $2^10$. Thus, when the
attacker is assumed to predict the interrupt occurrence with a microsecond
precision and the time stamp operates with nanosecond precision, 10 bits of
uncertainty remains that cannot be predicted by that attacker. Hence, only
these 10 bits can deliver entropy.

To ensure the ESDM interrupt handling code has the maximum performance, it
processes time stamp values with a number of bits equal to a power of two.
Thus, the ESDM implementation uses 8 LSB of the time stamp (after the time
stamp was divided by its GCD).

During boot time, the presence of attackers is considered to be very limited
as no remote access is yet possible and no local attack applications are
assumed to execute. On the other hand, the performance of the interrupt
handler is not considered to be very critical during the boot process. Thus,
the ESDM uses the 32 LSB of the time stamp that is injected into the per-CPU
collection pool when the time stamp is collected – the ESDM still awards this
time stamp one bit of entropy. Once the ESDM completed the calculation of the
GCD the aforementioned runtime behavior of concatenating the 8 LSB of 1,024
time stamps before mixing them into the per-CPU entropy pool is enabled.

=== Health Tests <sec:health-tests>

The ESDM implements the following health tests:

- Stuck Test
- Repetition Count Test (RCT)
- Adaptive Proportion Test (APT)

#par(first-line-indent: 0pt)[Those tests are detailed in the following
sections.]

Please note that these health tests are only performed for the internal
entropy sources. Other entropy sources like the entropy sources feeding the
auxiliary pool, the Jitter RNG, or the CPU-based entropy sources are not
covered by these tests as they are fully self-contained entropy sources where
the ESDM does not have access to the raw noise data and does not include a
model of the entropy source to implement appropriate health tests. The ESDM
considers both as external entropy source. Thus, the user must ensure that
either those other entropy sources implement all health tests as needed or
the kernel must be started such that these entropy sources are credited with
zero bits of entropy. Not crediting any entropy to these other entropy
sources can be achieved with the following kernel configuration options:

- Sources feeding the auxiliary entropy pool: The interface functions to
  provide entropy data have to be invoked with the value 0 for the entropy
  rate.

- CPU-based entropy source: `ESDM_CPU_ENTROPY_RATE=0`

- Jitter RNG: `ESDM_JENT_ENTROPY_RATE=0`

#par(first-line-indent: 0pt)[These options ensure that random data from the
entropy sources are pulled, but are not credited with any entropy.]

The RCT, and the APT health test are only performed when the kernel is booted
with `fips=1` and the kernel detects a high-resolution time stamp generator
during boot.

In addition, the health tests are only enabled if a high-resolution time
stamp is found. Systems with a low-resolution time stamp will not deliver
sufficient entropy for the interrupt entropy source which implies that also
the health tests are not applicable.

#paragraph[Stuck Test][The stuck test calculates the first, second and third
discrete derivative of the time stamp to be processed by the per-CPU
collection pool. Only if all three values are non-zero, the received time
delta is considered to be non-stuck. The first derivative calculated by the
stuck test verifies that two successive time stamps are not equal, i.e. are
“stuck”. The second derivative calculates that there is no linear repetitive
signal.]

The third derivative of the time stamp is considered relevant based on the
following: The entropy is delivered with the variations of the occurrence of
interrupt events, i.e. it is mathematically present in the time differences
of successive events. The time difference, however, is already the first
discrete derivative of time. Now, if the time difference delivers the actual
entropy, the stuck test shall catch that the time differences are not stuck,
i.e. the first derivative of the time difference (or the second derivative of
the absolute time stamp) shall not be zero. In addition, the stuck test shall
ensure that the time differences do not show a linear repetitive signal –
i.e. the second discrete derivative of the time difference (or the third
discrete derivative of the absolute time stamp) shall not be zero.

#paragraph[Repetition Count Test][The ESDM uses an enhanced version of the
Repetition Count Test (RCT) specified in SP800-90B @sp80090b section 4.4.1.
Instead of counting identical back-to-back values, the input to the RCT is the
counting of the stuck values during the processing of received interrupt
events. The data that is mixed into the entropy pool is the time stamp. As the
stuck result includes the comparison of two back-to-back time stamps by
computing the first discrete derivative of the time stamp, the RCT simply
checks whether the first discrete derivative of the time stamp is zero. If it
is zero, the RCT counter is increased. Otherwise, the RCT counter is reset to
zero.]

The RCT is applied with $alpha = 2^(-30)$ compliant to the recommendation of
FIPS 140-2 IG 9.8.

During the counting operation, the ESDM always calculates the RCT cut-off
value of C. If that value exceeds the allowed cut-off value, the ESDM will
trigger the health test failure discussed below. An error is logged to the
kernel log that such RCT failure occurred.

This test is only applied and enforced in FIPS mode.

#paragraph[Adaptive Proportion Test][Compliant to SP800-90B @sp80090b section
4.4.2 the ESDM implements the Adaptive Proportion Test (APT). Considering that
the entropy is present in the least significant bits of the time stamp, the
APT is applied only to those least significant bits. The APT is applied to the
four least significant bits.]

The APT is calculated over a window size of 512 time deltas that are to be
mixed into the entropy pool. By assuming that each time stamp has (at least)
one bit of entropy and the APT-input data is non-binary, the cut-off value
C = 325 as defined in SP800-90B section 4.4.2.

This test is only applied and enforced in FIPS mode.

#paragraph[Runtime Health Test Failures][If either the RCT, or the APT health
test fails irrespective whether during initialization or runtime, the
following actions occur:]

+ The entropy of the entire entropy pool is invalidated.

+ All DRNGs are reset which imply that they are treated as being not seeded
  and require a reseed during next invocation.

+ The SP800-90B startup health test are initiated with all implications
  discussed in section @sec:health-tests. That implies that from that point
  on, new events must be observed and its entropy must be inserted into the
  entropy pool before random numbers are calculated from the entropy pool.

#paragraph[SP800-90B Startup Tests][The aforementioned health tests are
applied to the first 1,024 time stamps obtained from scheduler events. In case
one error is identified for either the RCT, or the APT, the collected entropy
is invalidated and the SP800-90B startup health test is restarted.]

As long as the SP800-90B startup health test is not completed, all ESDM random
number output interfaces that may block will block and not generate any data.
This implies that only those potentially blocking interfaces are defined to
provide random numbers that are seeded with the interrupt entropy source being
SP800-90B compliant. All other output interfaces will not be affected by the
SP800-90B startup test and thus are not considered SP800-90B compliant.

To summarize, the following rules apply:

- SP800-90B compliant output interfaces

  - `/dev/random`
  - `getrandom(2)` system call when called with a flag that does not include
    `GRND_INSECURE`
  - `esdm_get_random_bytes_full` API call
  - `esdm_get_random_bytes_pr` API call

- SP800-90B non-compliant output interfaces

  - `/dev/urandom`
  - `getrandom(2)` system call when called with `GRND_INSECURE`
  - `esdm_get_random_bytes` API call
  - `esdm_get_random_bytes_min` API call

== Auxiliary Entropy Pool - ESDM-external Entropy Sources <sec:aux>

The ESDM also supports obtaining entropy from the following data sources and
entropy sources that are external to the ESDM. The data is injected into the
auxiliary pool.

During the reseeding operation of the DRNG, any user-space entropy provider
waiting via select(2) are triggered to provide one buffer full of data. This
data is mixed into the auxiliary pool. This approach shall ensure that the
ESDM-external entropy sources may provide entropy at least once each DRNG
reseed operation.

=== Injecting Data From User Space <sec:aux-injecting>

User space can take the following actions to inject data into the DRNG:

- When writing data into /dev/random or /dev/urandom, the data is added to the
  auxiliary pool and triggers a reseed of the DRNGs at the time the next random
  number is about to be generated. The ESDM assumes it has zero bits of
  entropy.

- When using the privileged IOCTL of `RNDADDENTROPY` with /dev/random, the
  caller can inject entropic data into the auxiliary pool and define the
  amount of entropy associated with that data.

=== Auxiliary Pool <sec:aux-pool>

The auxiliary pool is maintained as a separate entropy source that eventually
is concatenated with all other entropy sources in compliance with SP800-90C.

The auxiliary pool is processed with the available hash as follows:

+ Data is inserted the same way as data is added into the per-CPU entropy
  pools. The auxiliary pool technically is the message digest state where new
  data is inserted into the pool by performing a hash update operation.

+ When entropy is to be extracted from the auxiliary pool, a hash final
  operation is performed which is immediately followed by a hash init
  operation to initialize the hash context for new data.

+ The generated message digest is truncated to the amount of data requested
  by the DRNG (e.g. either 256 or 384 bits) and returned to the caller. Note,
  the auxiliary pool output is not truncated to the amount of entropy the data
  contains because the entropy provider may add data to the auxiliary pool
  without entropy, e.g. by simply writing to /dev/random. Thus, it may be
  possible that the auxiliary pool contains zero bits of entropy but yet
  contains data that should be used to “stir” the DRNG state.

#par(first-line-indent: 0pt)[Figure @fig:aux-pool illustrates the auxiliary
pool operation for the case when user space inserts three separate buffers.]

#figure(
  image("../figures/aux-pool-processing.svg", width: 50%),
  caption: [Auxiliary Pool Processing],
) <fig:aux-pool>

In addition, the ESDM maintains an entropy estimator for the auxiliary pool
counting the received entropy. The entropy estimator is capped to a maximum
of the digest size of the used hash as this hash cannot maintain more
entropy.

The auxiliary pool message digest is copied into the seed buffer when
generating random numbers to seed the DRNG. The entire seed buffer is mixed
back into the auxiliary pool for backward secrecy as shown in figure
@fig:aux-pool. The copy operation as well as the backtracking operation is
atomic with respect to the auxiliary pool. This implies that both operations
will always be fully completed before the next operation can commence. This
ensures that the same auxiliary pool state can only be used once for a given
seeding operation. Thus, both, the entropy pool and the auxiliary pool, are
simultaneously used as noise data provider to seed the DRNG.

The entropy estimator is decreased by the amount of data read via the message
digest.

== Jitter RNG - ESDM-external Entropy Source <sec:jent>

The Jitter RNG is treated as an external entropy source which is requested for
random bits at the time the DRNG shall be seeded.

=== Entropy of CPU Jitter RNG Entropy Source <sec:jent-entropy>

The CPU Jitter RNG entropy source is assumed provide 16th bit of entropy per
generated data bit. Albeit studies have shown that significant more entropy is
provided by this entropy source, a conservative estimate is applied.

The entropy value can be altered by changing the meson configuration option of
`es_jent_entropy_rate`.

== CPU-base Entropy Source - ESDM-external Entropy Source <sec:cpu>

The CPU-based entropy source is treated as an external entropy source which is
requested for random bits at the time the DRNG shall be seeded. Depending on
the underlying CPU, only one such source is available like RDSEED on Intel x86
(or RDRAND if RDSEED is not available), the POWER CPU DARN instruction, etc.

Depending whether the the CPU entropy source is documented to full entropy,
the following data collection methods are applied. This approach is
orthogonal to the amount of entropy the ESDM awards to the CPU entropy source.

- CPU entropy source provides full entropy: The CPU entropy source is queried
  for the amount of data which is stored in the temporary seed buffer.

- CPU entropy source provides less than full entropy: For this entropy source,
  the ESDM contains the information about how much data must be fetched from
  the CPU entropy source to get full entropy. The required amount of data is
  pulled from the CPU entropy source and conditioned with the hash currently
  in use by the ESDM. The calculated message digest is truncated to the
  requested amount of data which is stored in the temporary seed buffer.

=== Entropy of CPU Entropy Source <sec:cpu-entropy>

The entropy source of the CPU is assumed to have one 32th of the generated
data size – 8 bits of entropy. The reason for that conservative estimate is
that the design and implementation of those entropy sources is not commonly
known and reviewable. The entropy value can be altered by changing the meson
configuration option of `es_cpu_entropy_rate`.

== Kernel RNG Entropy Source - ESDM-external Entropy Source <sec:krng>

The ESDM offers the use of the kernel RNG as an entropy source. The kernel RNG
derives its entropy from sampling of interrupts.

The legacy RNG is queried for random numbers using the `getrandom(2)` system
call.

=== Entropy of Kernel RNG Entropy Source <sec:krng-entropy>

When the lernel RNG is enabled, the ESDM applies the entropy rate defined at
compile time with `es_kernel_entropy_rate` which is a value between 0 and 256
bits of entropy when 256 data bits are pulled from the legacy RNG.

If the ESDM is operated in FIPS mode, i.e. the kernel command line contains
“fips=1”, the kernel RNG entropy source's entropy rate is set to zero. The
reason is that the legacy RNG is known to not comply with FIPS 140 rules like
SP800-90B and thus must be assumed to provide no entropy.

When the interrupt entropy source is present, the kernel entropy source
entropy rate is capped to `ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY` bits of
entropy. This is due to the fact that the presence of IRQ entropy source takes
away the kernel RNG's main entropy source. Yet, some other entropy sources are
present which may or may not deliver entropy. Thus a safe entropy value is
applied by the ESDM.

== DRNG Seeding Operation <sec:seeding>

The seeding operation obtains random data from all available entropy sources.

The (re)seeding logic tries to obtain 256 bits of entropy from the entropy
sources. However, if less entropy can only be delivered, the DRNG reseeding is
only performed if at least 128 bits of entropy collectively from all entropy
sources can be obtained.

For efficiency reasons, the seeding operation uses a seed buffer depicted in
figure @fig:big-picture that is the following set of blocks of 256 bits each.
If SP800-90C compliance is enabled, the initial seeding of the DRNG is seeded
with a seed buffer that pulls 384 bits in the following blocks. Each block is
dedicated to an entropy source. As each entropy source can be disabled at
compile time, the different bullets in the following list only applies if the
corresponding entropy source is enabled.

+ One block is filled with the message digest from the auxiliary pool.

+ One block contains the message digest calculated from all per-CPU interrupt
  entropy pools as depicted in figure @fig:irq-processing That buffer receives
  as much data from the hash operation as entropy can be pulled from the
  entropy pools. In the worst case when no new interrupts are received a zero
  buffer will be injected into the DRNG. This is performed by iterating over
  all per-CPU entropy pools and:

  + Perform a hash update operation to inject the current content of the
    per-CPU collection pool into the per-CPU entropy pool.

  + Perform a hash final operation on the per-CPU entropy pool to obtain the
    message digest.

  + That message digest is used to re-initialize the per-CPU entropy pool with
    a hash init and hash update operation to ensure backward secrecy.

  + Also, the message digest is fed into the hash operation to collect the
    output from all entropy pools.

  Once the message digest from all is obtained, it is truncated to the amount
  of entropy present in all entropy pools.

+ Another block is filled with the message digest of all scheduler per-CPU
  entropy pools with the same approach as outlined for the interrupt ES.

+ One block is filled with the data from the kernel RNG entropy source.

+ The next block is filled by the Jitter RNG entropy source.

+ Finally, a block is filled by the fast entropy source of the CPU entropy
  source.

#par(first-line-indent: 0pt)[Finally, also a 32 bit time stamp indicating the
time of the request is mixed into the DRNG. That time stamp, however, is not
assumed to have entropy and is only there to further stir the state of the
DRNG.]

The filled seed buffer is handed to the DRNG as a seed string. In addition,
the seed buffer is inserted back into the auxiliary pool for backward secrecy.
The seed buffer will not alter the entropy estimation of the auxiliary pool.

=== DRNG May Become Not Fully Seeded <sec:not-fully-seeded>

The ESDM maintains a counter for each DRNG instance how many generate
operation are performed without performing a reseed that has full entropy. If
this counter exceeds the threshold of $2^30$ generate operations, i.e. the
DRNG did not receive a seed with full entropy for that many generate
operations, the DRNG is set to not fully seeded. This setting implies that the
DRNG instance will not be used any more for generating random numbers until
the ESDM received sufficient entropy to reseed the DRNG with full entropy.

If the DRNG that becomes not fully seeded is the initial DRNG instance that
was seeded during boot time as outlined in section @sec:seed-levels, the
entire ESDM is marked as not operational. This setting blocks all blocking
interfaces just like during boot time when the ESDM is not yet fully seeded.

The ESDM automatically tries to recover from it when it received sufficient
entropy.

== Cryptographic Primitives Used By ESDM <sec:crypto>

The following subsections explain the cryptographic primitives that may be
used by the ESDM.

=== DRBG <sec:drbg>

If the SP800-90A DRBG implementation is used, the default DRBG used by the
ESDM is the CTR DRBG with AES-256. The reason for the choice of a CTR DRBG is
its speed. The source code allows the use of other types of DRBG by simply
defining a DRBG reference using the kernel crypto API DRBG string – see the
top part of the source code for examples covering all types of DRBG.

All DRNGs are always instantiated with the same DRNG type.

The implementation of the DRBG is taken from the Linux kernel crypto API. The
use of the kernel crypto API to provide the cipher primitives allows using
assembler or even hardware-accelerator backed cipher primitives. Such support
should relieve the CPU from processing the cryptographic operation as much as
possible.

The input with the seed and re-seed of the DRBG has been explained above and
does not need to be re-iterated here. Mathematically speaking, the seed and
re-seed data obtained from the entropy sources and the ESDM external sources
are mixed into the DRBG using the DRBG “update” function as defined by
SP800-90A.

The DRBG generates output with the DRBG “generate” function that is specified
in SP800-90A. The DRBG used to generate two types of output that are
discussed in the following subsections.

#paragraph[/dev/urandom and `esdm_get_random_bytes`][Users that want to obtain
data via the /dev/urandom interface or the `esdm_get_random_bytes` API are
delivered data that is obtained from the DRNG “generate” function. I.e. the
DRNG generates the requested random numbers on demand.]

Data requests on either interface is segmented into blocks of maximum 4096
bytes. For each block, the DRNG “generate” function is invoked individually.
According to SP800-90A, the maximum numbers of bytes per DRBG “generate”
request is $2^19$ bits or $2^16$ bytes which is significantly more than
enforced by the ESDM.

In addition to the slicing of the requests into blocks, the ESDM maintains a
counter for the number of DRNG “generate” requests since the last reseed.
According to SP800-90A, the number of allowed requests before a forceful
reseed is $2^48$ – a number that is very high. The ESDM uses a much more
conservative threshold of $2^20$ requests as a maximum. When that threshold
is reached, the DRBG will be reseeded by using the operation documented in
section @sec:seeding before the next DRNG “generate” operation commences.

The handling of the reseed threshold as well as the capping of the amount of
random numbers generated with one DRNG “generate” operation ensures that the
DRNG is operated compliant to all constraints in SP800-90A.

#paragraph[/dev/random and `esdm_get_random_bytes_full`][The random numbers to
be generated for /dev/random as well as `esdm_get_random_bytes_full` are
defined to have a special property: it only provides data once at least 256
bits of entropy have been collected by the ESDM. In addition, the ESDM must be
fully initialized before random numbers are generated, including the
completion of the SP800-90B heath test if entropy from internal entropy
sources is gathered.]

=== ChaCha20 DRNG <sec:chacha20>

If the SP800-90A DRBG is not desired, the ESDM can use a standalone C
implementations for ChaCha20 to provide a DRNG.

The ChaCha20 DRNG is implemented with the components discussed in the
following section. All of those components rest on a state defined by
@rfc7539, section 2.3.

The operation of the ChaCha20 DRNG can be characterized with figure
@fig:chacha20. This figure outlines the initialization of the DRNG, its
seeding using the state update operation and the invocation of one generate
operation that is requested to obtain more than 512 bits of data.

#figure(
  image("../figures/chacha20-drng.svg", width: 86%),
  caption: [ChaCha20 DRNG Operation],
) <fig:chacha20>

#paragraph[State Update Function][The state update function's purpose is to
update the state of the ChaCha20 DRNG. That is achieved by]

+ generating one output block of ChaCha20,
+ partition the generated ChaCha20 block into two key-sized chunks,
+ and XOR both chunks with the key part of the ChaCha20 state.

#par(first-line-indent: 0pt)[In addition, the nonce part of the state is
incremented by one to ensure the uniqueness requirement of @rfc7539 chapter
4.]

#paragraph[Seeding Operation][The seeding operation processes a seed of
arbitrary lengths. The seed is segmented into ChaCha20 key size chunks which
are sequentially processed by the following steps:]

+ The key-size seed chunk is XORed into the ChaCha20 key location of the
  state.
+ This operation is followed by invoking the state update function.
+ Repeat the previous steps for all unprocessed key-sized seed chunks.

#par(first-line-indent: 0pt)[If the last seed chunk is smaller than the
ChaCha20 key size, only the available bytes of the seed are XORed into the key
location. This is logically equivalent to padding the right side of the seed
with zeroes until that block is equal in size to the ChaCha20 key.]

The invocation of the state update function is intended to eliminate any
potentially existing dependencies between the seed chunks.

#paragraph[Generate Operation][The random numbers from the ChaCha20 DRNG are
the data stream produced by ChaCha20, i.e. without the final XOR of the data
stream with plaintext. Thus, the DRNG generate function simply invokes the
ChaCha20 to produce the data stream as often as needed to produce the
requested number of random bytes.]

After the conclusion of the generate operation, the state update function is
invoked to ensure enhanced backward secrecy of the ChaCha20 state that was
used to generate the random numbers.

== ESDM External Interfaces <sec:interfaces>

The following ESDM interfaces are provided:

- ESDM library API: The API is documented in ‘esdm.h‘.

- ESDM server RPC API: The RPC API is documented in ‘esdm\_rpc\_client.h‘.

- /dev/random and /dev/urandom device files: See the Linux man page
  `random(4)`. In addition, when opening the /dev/random device with with the
  O\_SYNC flag, the DRNG is managed with prediction resistance enabled. When
  using /dev/random with `O_SYNC`, the ESDM API call of
  `esdm_get_entropy_bytes_pr` is used to service the request. Therefore all
  considerations outlined for this API apply to /dev/random and `O_SYNC` as
  well.

- /proc/sys/kernel/random/\* interfaces: See the Linux man page random(4).

- getrandom and getentropy APIs: See Linux man pages `getrandom(2)` and
  `getentropy(3)`. When `getrandom(2)` is invoked with the flag of
  `GRND_RANDOM`, the ESDM API call of `esdm_get_entropy_bytes_pr` is used to
  service the request. In addition when `getrandom(2)` is invoked with
  `GRND_SEED`, the ESDM API call of `esdm_get_seed` is used to fulfill the
  request.

== ESDM Self-Tests <sec:self-tests>

All cryptographic primitives are self-tested during the startup phase of the
ESDM.

== ESDM Test Interfaces <sec:test-interfaces>

During kernel compilation, the following interfaces may be enabled allowing
direct access to non-deterministic aspects. It is not advisable to enable
these interfaces for production systems. Yet, these interfaces are considered
to be protected against misuse by allowing only the root user to access them.
In addition, any data obtained through these interfaces is not used by the
ESDM to feed the entropy pool. Thus, even when leaving these interfaces
enabled on production systems, the impact on security is considered to be
limited.

- Interrupt Entropy Source:

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_hires` allows
    reading of the raw unconditioned noise data collected while the read
    operation is in progress by providing the time stamps of the events
    collected by the ESDM that otherwise are injected into the entropy pool.
    When booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_hires_test=1`, the time stamps of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_raw_hires` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_jiffies` allows
    reading of the raw unconditioned Jiffies collected while the read
    operation is in progress by providing the Jiffies values collected by the
    ESDM that otherwise are injected into the entropy pool (if no
    high-resolution time stamp is detected). When booting the kernel with the
    kernel command line option `esdm_testing.boot_raw_jiffies_test=1`, the
    time stamps of the first 1,024 events recorded by the ESDM are stored. The
    first read of the `esdm_raw_jiffies` file after boot provides this data in
    this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_irq` allows reading
    of the raw unconditioned interrupt numbers collected while the read
    operation is in progress by providing the interrupt number values
    collected by the ESDM that otherwise are injected into the entropy pool
    (if no high-resolution time stamp is detected) or into the random32 PRNG
    external to the ESDM. When booting the kernel with the kernel command line
    option `esdm_testing.boot_raw_irq_test=1`, the time stamps of the first
    1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_irq` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_irqflags` allows
    reading of the raw unconditioned interrupt flags collected while the read
    operation is in progress by providing the interrupt flag values collected
    by the ESDM that otherwise are injected into the entropy pool (if no
    high-resolution time stamp is detected) or into the random32 PRNG external
    to the ESDM. When booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_irqflag_test=1`, the time stamps of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_raw_irqflags` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_retip` allows
    reading of the raw unconditioned return instruction pointer collected
    while the read operation is in progress by providing the instruction
    pointer 32 LSB values collected by the ESDM that otherwise are injected
    into the entropy pool (if no high-resolution time stamp is detected) or
    into the random32 PRNG external to the ESDM. When booting the kernel with
    the kernel command line option `esdm_testing.boot_raw_retip_test=1`, the
    time stamps of the first 1,024 events recorded by the ESDM are stored. The
    first read of the `esdm_raw_retip` file after boot provides this data in
    this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_regs` allows
    reading of the raw unconditioned interrupt register state collected while
    the read operation is in progress by providing the selected register 32
    LSB values collected by the ESDM that otherwise are injected into the
    entropy pool (if no high-resolution time stamp is detected). When booting
    the kernel with the kernel command line option
    `esdm_testing.boot_raw_regs_test=1`, the time stamps of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_raw_regs` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_array` allows
    reading of the raw noise data that has been stored in the per-CPU
    collection pool collected while the read operation is in progress. When
    booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_array=1`, the array content of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_raw_array` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_irq_perf` allows
    reading of the number of cycles used to process one interrupt event. This
    allows measuring the performance impact of the ESDM on the interrupt
    handler. When booting the kernel with the kernel command line option
    `esdm_testing.boot_irq_perf=1`, the performance data of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_irq_perf` file after boot provides this data in this case.

- Scheduler Entropy Source:

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_sched_hires` allows
    reading of the raw unconditioned noise data collected while the read
    operation is in progress by providing the time stamps of the events
    collected by the ESDM that otherwise are injected into the entropy pool.
    When booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_sched_hires_test=1`, the time stamps of the first
    1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_sched_hires` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_sched_pid` allows
    reading of the PID value of the task that are about to be scheduled to
    collected while the read operation is in progress. The PID values are
    extracted which are collected by the ESDM that otherwise are injected into
    the entropy pool (if no high-resolution time stamp is detected). When
    booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_sched_pid_test=1`, the time stamps of the first
    1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_sched_pid` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_starttime_pid`
    allows reading of the start time value of the task that are about to be
    scheduled to collected while the read operation is in progress. The start
    time values are extracted which are collected by the ESDM that otherwise
    are injected into the entropy pool (if no high-resolution time stamp is
    detected). When booting the kernel with the kernel command line option
    `esdm_testing.boot_raw_sched_starttime_test=1`, the time stamps of the
    first 1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_starttime_pid` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_raw_nvcsw_pid` allows
    reading of the numbers of context switches of the task that are about to
    be scheduled to collected while the read operation is in progress. The
    context switch values are extracted which are collected by the ESDM that
    otherwise are injected into the entropy pool (if no high-resolution time
    stamp is detected). When booting the kernel with the kernel command line
    option `esdm_testing.boot_raw_sched_nvcsw_test=1`, the time stamps of the
    first 1,024 events recorded by the ESDM are stored. The first read of the
    `esdm_raw_nvcsw_pid` file after boot provides this data in this case.

  - The interface `/sys/kernel/debug/esdm_testing/esdm_sched_perf` allows
    reading of the number of cycles used to process one scheduler event. This
    allows measuring the performance impact of the ESDM on the scheulder. When
    booting the kernel with the kernel command line option
    `esdm_testing.boot_sched_perf=1`, the performance data of the first 1,024
    events recorded by the ESDM are stored. The first read of the
    `esdm_sched_perf` file after boot provides this data in this case.

#par(first-line-indent: 0pt)[The helper tool getrawentropy.c is provided to
read the files and format the data for post-processing.]
