#import "../template.typ": *

= ESDM Design <sec:design>

The ESDM can be characterized with figure @fig:big-picture which provides a
big picture of the ESDM processing and components.

#figure(
  image("../figures/big-picture.svg", width: 100%),
  caption: [ESDM Big Picture],
) <fig:big-picture>

The colors indicate the different entropy sources managed by the ESDM.

The ESDM introduces the concept of slow and fast entropy sources. Fast entropy
sources provide entropy at the time of request. A slow entropy source collects
data over time into an entropy pool.

The entropy sources that are under full control of the ESDM, also called the
internal entropy sources, comprise of the following. At most one of them may be
credited with entropy, as they all measure the timing of related events - the
build system refuses a configuration crediting two of them, and setting the
entropy rate of one of them at runtime sets the others to zero
(`esdm_config_timing_es_rate_set`):

- The indigo marked parts refer to the scheduler entropy source of the kernel
  module `kernel/esdm_es` that records the time stamps of context switches
  in per-CPU rings. The recorded time stamps are post-processed with a
  DRBG of the kernel module when seeding of the DRNG is to be
  performed.

- The orange marked parts refer to the interrupt entropy source of the same
  kernel module which has an identical architecture compared to the
  scheduler-based entropy source: the time stamps of interrupts are recorded
  in per-CPU rings and post-processed with a DRBG.

- The eBPF-based scheduler and interrupt entropy sources collect the same
  event timing on a stock Linux kernel: eBPF programs attached to the
  `sched_switch` and `irq_handler_entry` tracepoints record the time between
  successive events, which the ESDM server conditions with an XDRBG-256 pool of
  its own.

#par(first-line-indent: 0pt)[The following external entropy sources are
present. These entropy sources are expected to be fully self-contained. The
ESDM only requests data from them and expects that the entropy estimate
provided with the data is correct:]

- The auxiliary pool collects data from external entropy sources which deliver
  data at times not controllable by the ESDM.

- The CPU entropy source obtains data from a potentially existing source in
  the CPU like RDSEED on Intel CPUs.

- The Jitter RNG entropy source is another external entropy source, provided
  by the Jitter RNG library in user space, and by the Jitter RNG of the Linux
  kernel crypto API.

- The random number generator provided with the `getrandom` system call can be
  enabled at compile time to serve as an entropy source.

- Using the Linux hardware random number generator (/dev/hwrng) as seed source
  that may obtain data from various hardware sources.

- The random number generator of a TPM 2.0 accessed via its resource manager
  device.

- External entropy sources developed outside of the ESDM which are loaded as a
  plugin library or which are served by a process of their own over a Unix
  domain socket - among them `esdm-es-pkcs11`, which serves the random number
  generator of a PKCS\#11 token.

#par(first-line-indent: 0pt)[The ESDM treats all external and internal entropy
sources equally. It can handle the situations where one or more entropy
sources returns little or no entropy.]

The interrupt entropy source is assessed in chapter @sec:irq-assessment which
provides its complete entropy assessment; an assessment of the scheduler
entropy sources is not provided yet (chapter @sec:sched-assessment). All other
entropy sources are
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
  image("../figures/interfaces.svg", width: 100%),
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

- The ESDM exports two Unix Domain Sockets to /run - the unprivileged
  `esdm-rpc-unpriv.socket` and the privileged `esdm-rpc-priv.socket`, the
  directories being configurable with the meson options
  `esdm-server-rpc-path-unprivileged` and `esdm-server-rpc-path-privileged`.
  They can be used directly, albeit it is not advised to be used as the
  protocol offered by those sockets is defined to be not stable, i.e. it can
  change from one version to another.

- To wrap the mentioned Unix Domain Sockets, the ESDM RPC library is available
  which offers a stable API.

- The ESDM server optionally serves the protocol of the Entropy Gathering
  Daemon (EGD) on a socket of its own for legacy consumers. ESDM-specific
  commands on the same socket read from the prediction resistance DRNG
  (0xe0, 0xe1), alongside the other commands the EGD protocol cannot
  express.

- OpenSSL 3 RAND providers route the random number requests of OpenSSL to the
  ESDM, either over the RPC interface or over the EGD interface.

- The ESDM library provides the heart of the ESDM functionality. It could be
  directly used by a calling application. Yet, it is advised to use the RPC
  interface as it is provided by a daemon that uses the ESDM library already.

#par(first-line-indent: 0pt)[The ESDM consists of the following components:]

- `libesdm.so`: The ESDM provides a library with the core of the ESDM. The
  DRNG and entropy source managers together with all entropy sources and
  cryptographic algorithm implementations are implemented with this library.
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

  The server must be started as root. It creates its sockets and its status
  shared memory segment while privileged, initializes the entropy sources
  requiring privileges - e.g. it loads the eBPF programs or an external
  entropy source plugin - and then permanently drops its
  privileges to an unprivileged user (option `--username`, `nobody` by
  default).

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
  system under /proc/sys/kernel/random but pointing to the ESDM server:
  `boot_id`, `uuid`, `entropy_avail`, `poolsize`, `write_wakeup_threshold`,
  `urandom_min_reseed_secs` and, in addition, `esdm_type` which provides the
  status of the ESDM. This process is required to ensure that all interfaces
  are provided by ESDM. For details about the provided files, see the
  `random(4)` man page. Note, the kernel exports the /proc/sys/kernel/random
  information also as `sysctl(8)`. This interface is not covered by
  ‘esdm-proc‘.

- `libesdm-getrandom.so`: The library provides a wrapper to the `getrandom`
  and `getentropy` Linux C-library calls. To use the library for other
  consumers, use one of the following considerations:

  - Use `LD_PRELOAD="/path/to/libesdm-getrandom.so"` with the intended
    application.

  - Compile the application or library with the following options:

    - `LDFLAGS += -Wl,--wrap=getrandom,--wrap=getentropy`
    - `LDFLAGS += -lesdm-getrandom`

- `esdm-kernel-seeder`: The daemon draws random data from the ESDM server and
  inserts it into the Linux kernel RNG periodically - required when the
  interrupt entropy source of the kernel module deprives the kernel RNG of its
  main entropy input.

- `esdm-tool`: The tool interacts with the ESDM server: it shows the status of
  the ESDM, triggers its self tests, runs performance and stress tests and
  creates the reference values of the FIPS integrity test. The systemd unit
  `esdm-wait-until-fully-seeded.service` is implemented with it.

- `esdm-server-signal-helper`: The tool notifies the ESDM server about the
  suspend and the resume of the system.

- `libesdm_aux_client.so`: The library allows an external entropy provider to
  wait until the ESDM server requests entropy for its auxiliary pool
  (`esdm_aux_client.h`).

- `libesdm_egd_client.so`: A client library for the EGD interface of the ESDM
  server (`esdm_egd_client.h`).

- OpenSSL providers: `libesdm-rng-provider.so`, `libesdm-rng-provider-pr.so`
  and `libesdm-seed-src-provider.so` talk the RPC protocol,
  `libesdm-egd-provider.so` and `libesdm-egd-provider-pr.so` the EGD protocol.

- `libesdm_es_ext.so` and `esdm-es-ext-serve`: The library defines the plugin
  interface of external entropy sources (`esdm_es_ext.h`) and their socket
  protocol; `esdm-es-ext-serve` serves such a plugin on a Unix domain socket
  the ESDM server reads from.

- `esdm-getrawentropy`, `esdm-extractlsb` and `esdm-ebpf-collect`: Tools to
  obtain and process the raw noise data of the internal entropy sources for
  their entropy assessment, see section @sec:test-interfaces.

- `esdm_cdev` (`kernel/esdm_cdev`): A kernel module serving the random
  numbers of the ESDM through the character devices `/dev/esdm_random` and
  `/dev/esdm_urandom` and the directory `/proc/esdm` - the counterpart of the
  CUSE daemons in the kernel, which leaves the kernel's own devices untouched.
  It talks to the ESDM over the EGD interface, see section @sec:egd.

- `esdm-vhost-user-rng`: The vhost-user back-end of a virtio entropy device,
  giving QEMU and Cloud Hypervisor guests a virtio-rng device served from the
  fully seeded or the prediction resistant DRNG. It parses the memory of the
  guest, so it is a process of its own per VM without privileges, which
  reaches the ESDM server over the unprivileged RPC interface like any other
  client; the template units `esdm-vhost-user-rng@.socket` and `@.service` run
  it, see `esdm-vhost-user-rng(8)`.

== ESDM Components <sec:components>

The ESDM consists of the following components shown in figure
@fig:big-picture:

+ The ESDM implements a DRNG. Unless using the interface providing prediction
  resistance, the DRNG always generates the requested amount of output. When
  using the SP800-90A terminology it operates without prediction resistance.
  The DRNG maintains a counter of how many generate requests were served since
  last re-seed and a timer of the elapsed time since last re-seed. If either
  the counter or the timer reaches a threshold, the DRNG is seeded from the
  entropy sources with the available entropy.

  The ESDM maintains one DRNG instance per CPU as discussed in section
  @sec:numa.

  Depending on the used interface to request data from the DRNG, the caller
  may be put to sleep until the ESDM is fully seeded:

  + All interfaces using the `esdm_get_random_bytes` function generate data
    without waiting - but only once the ESDM is operational, i.e. its initial
    DRNG instance is fully seeded, and its cryptographic self tests passed.
    Otherwise the function returns an error.

  + All interfaces using the `esdm_get_random_bytes_full` function generate
    data only when the ESDM is fully seeded and fully initialized, and wait
    until then. The function `esdm_get_random_bytes_full_noblock` returns an
    error instead of waiting.

  + When using the `esdm_get_random_bytes_pr` function, the special DRNG
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

    - Require a reseed with entropy collected for this very request before
      every output block - data the entropy sources cached ahead of the
      request is not used.

    - Produce at most the freshly collected entropy, less the 64 bits kept back
      for full entropy output with the SP800-90C oversampling in effect
      (SP800-90C section 6.5.1.2), and at most 256 bits of random bits per
      block from the DRNG (i.e. the security strength of the DRNG).

    - Serve only one prediction resistance request at a time.

    The function `esdm_get_random_bytes_pr_noblock` returns an error instead of
    waiting for the ESDM to become operational or for another prediction
    resistance request to complete.

+ The DRNG is seeded by concatenating the data from the following sources in
  case they are enabled at compile time, in this order:

  + the output of the interrupt entropy source of the kernel module,
  + the output of the scheduler entropy source of the kernel module,
  + the output of the eBPF-based interrupt entropy source,
  + the output of the eBPF-based scheduler entropy source,
  + the Jitter RNG if available,
  + the CPU-based entropy source such as Intel RDSEED if available,
  + the kernel RNG output,
  + the Linux kernel HWRAND framework (/dev/hwrng),
  + the TPM 2.0,
  + the Jitter RNG of the Linux kernel crypto API,
  + the external entropy sources served by a plugin library and by a provider
    socket, and
  + the output of the auxiliary pool.

  The entropy estimate of the data of all entropy sources are added to form
  the entropy estimate of the data used to seed the DRNG with. The data of an
  entropy source configured to be credited with zero bits of entropy is not
  part of the seed but handed to the DRNG as additional input (SP800-90C
  section 2.6), see section @sec:dp-seed-buffer.

  The ESDM is designed such that none of these entropy sources can dominate
  the other entropy sources to provide seed data to the DRNG due to the
  following:

  + During boot time, the amount of available entropy is the trigger point to
    (re)seed the DRNG following the explanation in the next section.

  + At runtime, the the DRNG reseed is triggered by either the DRNG due to
    hitting the aforementioned thresholds or by a user space caller. The
    reseed is never triggered by the entropy sources.

+ To support backward secrecy, the following steps are applied:

  + The auxiliary pool and the conditioning pools of the eBPF entropy sources
    are each an XDRBG-256: an extraction reseeds the XDRBG and generates its
    output together with its new state, so that the output never reveals the
    state of the pool.

  + The kernel module post-processes the recorded time stamps with an
    SP800-90A DRBG whose state update provides backtracking resistance.

  + The DRNGs implement an update of their state during the generation
    operation.

#par(first-line-indent: 0pt)[The ESDM allows the DRNG mechanism and the used
hash to be changed at compile time by selecting one of the crypto backends
listed in section @sec:backends. Per default, an SP800-90A Hash DRBG
implementation along with a SHA-512 hash implementation is available. Both are
standard C implementations which were tested against NIST's ACVP service.]

The following subsections cover the different components of the ESDM from the
bottom to the top.

== ESDM Data Processing <sec:data-processing>

The processing of entropic data from the different entropy source before
injecting them into the DRNG is performed with the following mathematical
operations. The operation $"SHAKE256"(x, l)$ refers to the extendable output
function SHAKE256 provided by the crypto backend returning $l$ bits of output,
the operation $"SHA"()$ to the conditioning hash of the crypto backend
(SHA-512 or SHA3-512, see section @sec:backends), the operations
$"DRBG.Seed"$ and $"DRBG.Generate"$ to the DRBG of the kernel module.

=== Scheduler and Interrupt Entropy Sources of the Kernel Module <sec:dp-sched-irq>

+ Time stamp: The time stamps of the events received by the IRQ as well as the
  scheduler entropy sources are obtained with `random_get_entropy` and divided
  by the GCD - a value calculated from the first 100 time stamps and fixed
  thereafter, which implies that the time stamp divided by the GCD is the raw
  entropy value $t$, a 64-bit integer. Until the GCD is calculated, the time
  stamp is used undivided.

+ Health test: Each time stamp is subject to the health tests of section
  @sec:health-tests. Only time stamps passing them are recorded.

+ Concatenation: The time stamps received by the IRQ and the scheduler entropy
  sources are concatenated in a per-CPU ring - the implementation is provided
  with the function `esdm_es_ring_add` in `kernel/esdm_es/esdm_es_ring.h`.
  The ring holds 4096 time stamps for the default oversampling rate of 3
  (`ESDM_ES_OSR` of the Makefile of the module). When the ring is full, newly
  received time stamps are dropped:

  $ "CP"_("CPU") = t_(n-k) || t_(n-k+1) || ... || t_n $ <eq:cp>

=== Interrupt Entropy Source <sec:dp-irq>

+ DRBG seeding: When data is requested from the interrupt entropy source, the
  time stamps needed for one output block of the size of the security strength
  $s$ = 256 bits of the DRBG are collected from all per-CPU rings and handed to
  the DRBG of the kernel module as seed - the implementation is provided with
  the function `esdm_es_drbg_pool_extract_block` in
  `kernel/esdm_es/esdm_es_drbg.c`. These are $(s + o) dot r \/ 256$ time
  stamps, $r$ being the number of time stamps per 256 bits of entropy and $o$
  the oversampling of 65 bits (129 bits for the instantiation of the DRBG) in
  the FIPS mode of a kernel built with `CONFIG_CRYPTO_FIPS`, 0 otherwise. The
  first seed instantiates the DRBG, all later ones reseed it:

  $ "EP"_n = "DRBG.Seed"("EP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
    || "CP"_("CPUX")) $ <eq:ep-cpu>

  The DRBG is the XDRBG-256 of the ESDM (`esdm/crypto/esdm_xdrbg.c`), which
  the kernel module compiles, over the SHAKE256 of the kernel's SHA-3 library
  (`CONFIG_CRYPTO_LIB_SHA3`), which Linux 7.2 and later require. On an older kernel without that library, it is the HMAC_DRBG with
  SHA-512 of the kernel crypto API.

+ Generation: An output block is generated from the DRBG with the additional
  input "ESDM_IRQ_DRBG" for domain separation:

  $ B_n = "DRBG.Generate"("EP"_n, s, "\"ESDM_IRQ_DRBG\"") $ <eq:ep-all>

+ Concatenation: As many blocks are generated as needed for the requested
  number of bits $b$ (256 or 384 bits) - the implementation is provided with
  function `esdm_es_drbg_pool_extract`:

  $ E_n = B_(n,1) || ... || B_(n, ceil(b \/ s)) $ <eq:e>

=== Scheduler Entropy Source <sec:dp-sched>

The scheduler entropy source applies the same processing as the interrupt
entropy source with a DRBG instance of its own and the additional input
"ESDM_SCH_DRBG":

$ "SP"_n = "DRBG.Seed"("SP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
  || "CP"_("CPUX")) $ <eq:sp-cpu>

$ B_n = "DRBG.Generate"("SP"_n, s, "\"ESDM_SCH_DRBG\"") $ <eq:sp-all>

$ S_n = B_(n,1) || ... || B_(n, ceil(b \/ s)) $ <eq:s>

=== eBPF-based Scheduler and Interrupt Entropy Sources <sec:dp-ebpf>

+ Time delta: The eBPF programs obtain the time stamp of an event with
  `bpf_ktime_get_ns`, divide it by the GCD of the first 100 time stamps and
  subject it to the health tests. Of the time stamps passing them, the
  difference to the time stamp of the preceding event of the same CPU, a
  64-bit integer $d$, is recorded.

+ Concatenation: The deltas are concatenated in a per-CPU batch of 64 deltas
  which is handed to a BPF ring buffer when it is full, or after an idle
  deadline of 250 ms if the CPU falls quiet.

+ Insertion: The ESDM server reads the batches from the ring buffer and
  inserts the deltas into the XDRBG-256 conditioning pool $"XP"$ of the source
  as seed data of its next reseed - the implementation is provided with the
  functions `esdm_ebpf_consume` and `esdm_xdrbg_insert`.

+ Extraction: The pool is extracted as specified for the auxiliary pool in
  section @sec:dp-aux with the additional input $alpha$ = "ESDM eBPF pool "
  followed by the name of the source - the implementation is provided with the
  function `esdm_ebpf_get_ent`:

  $ E^"eBPF"_n = "XDRBG.Extract"("XP", d_(m-k) || ... || d_m, alpha) $
  <eq:ebpf>

=== Auxiliary Entropy Pool <sec:dp-aux>

The auxiliary pool $"AP"$ is an XDRBG-256 - the XDRBG over SHAKE256 (Kelsey,
Lucks, Müller, IACR ToSC 2024(1)) with a state $V$ of 512 bits - implemented in
`esdm/crypto/esdm_xdrbg.c`. The number of auxiliary pools is configurable
(meson option `num-aux-pools`, one per default), each of them with the
additional input $alpha$ = "ESDM aux pool" followed by the index of the pool in
two bytes.

+ Insertion: When new data $D_m$ is added to the auxiliary pool $"AP"$, it is
  absorbed into the SHAKE256 context of the pool and becomes part of the seed
  of its next reseed - the implementation is provided with function
  `esdm_pool_insert_aux` in `esdm/es/esdm_es_aux.c`. Data without entropy is
  inserted into all pools, data with entropy into the one pool that can take
  it.

+ Reseed: When entropy is requested from the auxiliary pool, the seed data
  received since the last extraction is used to reseed the XDRBG, where
  $"encode"(alpha, n) = alpha || (85 n + |alpha|)$ appends one byte to
  $alpha$ and $V'_(n-1)$ is the state left by the previous extraction:

  $ V_n = "SHAKE256"(V'_(n-1) || D_(m-k) || ... || D_m || "encode"(alpha, 1),
    512) $ <eq:ap>

  The first extraction instantiates the XDRBG with
  $V_1 = "SHAKE256"(D_1 || ... || D_m || "encode"(alpha, 0), 512)$.

+ Generation: The output $A_n$ of the size requested by the DRNG - at most the
  seed size of 256 or 384 bits - is generated together with the new state
  $V'_n$, with which the SHAKE256 context of the pool is started again - the
  implementation is provided with the function `esdm_xdrbg_extract`:

  $ V'_n || A_n = "SHAKE256"(V_n || "encode"(alpha, 2), 512 + |A_n|) $
  <eq:a>

=== CPU Entropy Source <sec:dp-cpu>

+ Hashing: If the CPU entropy source requires an oversampling - its data
  multiplier $m$ is larger than one - a message digest of $m$ times the amount
  of data to be requested from it is calculated, plus $64 dot m$ bits with the
  SP800-90C oversampling in effect:

  $ C_"cond" = "SHA"(C_1 || ... || C_m) $ <eq:c-cond>

+ Truncation: The MSB defined by the requested number of bits are obtained -
  the implementation is provided with function `esdm_get_cpu_data_compress` in
  `esdm/es/esdm_es_cpu.c` – otherwise, with a multiplier of one, $C_n$ is the
  data obtained directly from the CPU entropy source:

  $ C_n = "MSB"_("requested bits")(C_"cond") $ <eq:c>

=== Temporary Seed Buffer Construction <sec:dp-seed-buffer>

+ Concatenation: The temporary seed buffer $T$ used to seed the DRNG at the
  time $n$ is a concatenation of one slot per entropy source compiled in, in
  the order of section @sec:components, each slot holding the data of the
  entropy source and its entropy estimate, followed by the current time $t$
  (`CLOCK_MONOTONIC`). The implementation is provided with function
  `esdm_get_seed_buffers` in `esdm/es/esdm_es_mgr.c`:

  $ T_n = & E_n || S_n || E^"eBPF"_n || S^"eBPF"_n || J_n || C_n || K_n
    || H_n \
    & || M_n || J^"K"_n || X^"L"_n || X^"S"_n || A_n || t $ <eq:t>

  with the Jitter RNG output $J$, the kernel RNG output $K$, the HWRAND output
  $H$, the TPM 2.0 output $M$, the output of the kernel Jitter RNG $J^"K"$
  and of the external entropy sources $X^"L"$ and $X^"S"$ - the PKCS\#11
  token among the latter.

+ Separation: The data of an entropy source that is configured with an entropy
  rate of zero is placed in the slot of a second buffer of the same layout,
  the additional input $U_n$, and its slot of $T_n$ is left empty. The DRNG is
  seeded with $T_n$ as seed and $U_n$ as additional input.

== ESDM Architecture <sec:architecture>

Before going into the details of the ESDM processing, the concept underlying
the ESDM shown in figure @fig:big-picture is provided here.

The entropy derived from the slow entropy sources is collected and accumulated
in the per-CPU rings of the kernel module, the conditioning pools of the eBPF
entropy sources and the auxiliary pool.

At the time the DRNG shall be seeded, all entropy sources are requested for
data - in parallel threads with the meson option `es_parallel_fetch`, which is
enabled per default. The kernel module post-processes the recorded time stamps
with its DRBG, the XDRBG-256 pools are extracted.

The entropy sources generate data of the requested size which is credited with
at most the available entropy. For the auxiliary pool, the requested size of
data is always returned irrespective of the entropy rate of this pool. This
ensures that also data that is not credited with entropy but injected into the
ESDM is used to stir the seed for the DRNG.

The Jitter RNG, the HWRAND, the TPM 2.0, the kernel Jitter RNG and the
entropy sources of the kernel module may collect their data
asynchronously ahead of the request into a cache of blocks filled by the
entropy source monitor (meson options `es_*_entropy_blocks`). The cache is
compiled out with the options `sp80090c`, `fips140` or `ais2031_drg3` unless
the option `es_buf_force` is set.

The DRNG always tries to seed itself with 256 bits of entropy, or 384 bits for
the initial seeding with the SP800-90C oversampling in effect. In any case, if
the entropy sources cannot deliver that amount, the available entropy is used
and the DRNG keeps track on how much entropy it was seeded with. During boot,
the DRNG is seeded as follows:

+ The DRNG is reseeded from the entropy sources if all entropy sources
  collectively have at least 256 bits of entropy available (384 bits with the
  SP800-90C oversampling in effect). The initialization of the ESDM performs a
  forced seeding of all DRNG instances right away.

#par(first-line-indent: 0pt)[The ESDM also implements a forced seeding
operation, called emergency reseeding. It is performed during the
initialization of the ESDM and for a request while the ESDM is not
operational. The forced seeding performs a continuous reseeding of the DRNG
in an atomic operation with existing entropy. This means that a regular
reseeding is triggered repeatedly as often as needed to reach the fully seeded
level. In this case, the entropy obtained from the entropy sources is added
up. This is permissible because the multiple reseeding operations are
performed while the DRNG is locked, i.e. the DRNG will not produce output in
that time. The repetition stops when the entropy sources cannot deliver the
entropy needed to reach the fully seeded level any more - the implementation
is provided with the functions `esdm_drng_seed_es_nolock` and
`esdm_fully_seeded_reachable`. Figure @fig:seeding illustrates the seeding
operation of a DRNG.]

#figure(
  image("../figures/drng-seeding.svg", width: 72%),
  caption: [DRNG Seeding Operation],
) <fig:seeding>

Before the DRNG is fully seeded, requests of random data from the blocking
interfaces are not processed.

At runtime the DRNG operates as deterministic random number generator with the
following properties:

- The maximum number of random bytes that can be generated with one DRNG
  generate operation is limited to 4096 bytes. When longer random numbers are
  requested, multiple DRNG generate operations are performed. The used DRNGs
  implement an update of their state during the generation operation for
  backward secrecy.

- The DRNG is reseeded only if at least 256 bits of entropy are available
  from the entropy sources – in the worst case where no additional entropy can
  be provided by the entropy sources, the DRNG is not re-seeded and continues
  its operation to try to reseed again after again the expiry of one of these
  thresholds:

  - If the last reseeding of the DRNG is more than 600 seconds
    ago#footnote[Note, this value will not empty the entropy pool even on a
    completely quiet system. Testing of the ESDM was performed on a KVM
    without fast entropy sources and with a minimal user space, where only the
    SSH daemon was running, During the testing, no operation was performed by
    a user. Yet, the system collected more than 256 bits of entropy from the
    interrupt entropy source within that time frame, satisfying the DRNG
    reseed requirement.] - the interval can be set at runtime to at most 3600
    seconds, where an interval of 0 seconds reseeds the DRNG before every
    request -, or

  - $2^20$ DRNG generate operations are performed, whatever comes first, or

  - the number of bits generated since the last full reseed reaches the
    threshold of the meson option `drng_reseed_threshold_bits` (disabled per
    default, 98,304 bits with the options `sp80090c`, `fips140` or
    `ais2031_drg4`), or

  - the DRNG is forced to reseed before the next generation of random numbers
    with the `RNDRESEEDCRNG` IOCTL or the respective RPC interface.

  The chosen values prevent high-volume requests from user space to cause
  frequent reseeding operations which drag down the performance of the
  DRNG#footnote[Considering that the maximum request size is 4096 bytes
  defined by `ESDM_DRNG_MAX_REQSIZE` (i.e. each request is segmented into 4096
  byte chunks) and at most $2^20$ requests defined by
  `ESDM_DRNG_RESEED_THRESH` can be made before a forced reseed takes place, at
  most $4096 dot 2^20 = 4,294,967,296$ bytes can be obtained from the DRNG
  without a reseed operation.].

- The reseed of the per-CPU DRNG instances is performed by a reseed worker
  thread ahead of the requests, so that a request does not wait for the
  collection of entropy: the worker reseeds the DRNG instances whose reseed
  interval elapsed. The seed times of the per-CPU DRNG instances are staggered
  by a random offset of up to a tenth of the reseed interval, so that the
  DRNG instances do not all fall due at once. The initial DRNG instance and
  the prediction resistance DRNG instance are reseeded synchronously.

- If the DRNG was not reseeded with full entropy for the last $2^30$ DRNG
  generate operations, or the number of bits generated since then reaches the
  meson option `drng_max_reseed_bits` (disabled per default, $2^17$ bits with
  the options `sp80090c`, `fips140` or `ais2031_drg4`) – i.e. the reseeding
  requests discussed in the previous bullets were unsuccessful – the DRNG
  reverts back to an unseeded state, see section @sec:not-fully-seeded.

#par(first-line-indent: 0pt)[With the automatic reseeding after 600 seconds,
the ESDM is triggered to reseed itself before the first request after a
suspend that put the hardware to sleep for longer than 600 seconds.]

=== Fully Seeded Level <sec:seed-levels>

The ESDM's DRNG is considered “fully” seeded when it received at least 256
bits of entropy, or 384 bits of entropy for the initial seeding with the
SP800-90C oversampling in effect - the implementation is provided with the
function `esdm_fully_seeded`. With the AIS 20/31 NTG.1 seeding strategy
(meson option `ais2031_ntg1`), the initial seeding requires in addition that
two entropy sources deliver at least 240 bits of entropy each, or the Jitter
RNG operated in its own NTG.1 mode alone delivers 240 bits of entropy.

The ESDM is operational once its initial DRNG instance is fully seeded. This
level has the following implications:

- When reaching the fully seeded level, the user-space callers waiting for a
  fully seeded DRNG via the `getrandom` system call or /dev/random are woken
  up. Using the ESDM API of `esdm_get_random_bytes_full`, the caller is
  waiting synchronously until the fully seeded level is reached.

=== DRNG Instances <sec:numa>

To prevent bottlenecks in large systems, the DRNG will be instantiated once
for each CPU (meson option `node`), limited to the number of worker threads of
the meson option `threading_max_worker_threads` (64 per default), and at
runtime with `esdm_config_max_nodes_set` or the option `--small_memory` of the
server. The instantiations of the DRNGs happen all at the same time when the
ESDM is initialized. Next to them, the ESDM maintains the initial DRNG
instance, which serves as the DRNG of node zero, and the DRNG instance
operated with prediction resistance.

The question now arises how are the different DRNGs seeded without re-using
entropy or relying on random numbers from a yet insufficiently seeded ESDM.
The ESDM seeds the DRNGs sequentially starting with the one for node zero –
the DRNG for node zero is seeded with the approach discussed above. Once the
DRNG for node 0 is fully seeded, the ESDM will seed the DRNG of node one when
having again sufficient entropy available. This is followed by seeding the DRNG
of node two after having again collected entropy, and so on. The prediction
resistance DRNG is instantiated last. Figure @fig:numa illustrates the seeding
strategy showing that each DRNG instance is freshly seeded with a separate
seed buffer.

#figure(
  image("../figures/numa-drng.svg", width: 90%),
  caption: [DRNG Instances with seeding strategy],
) <fig:numa>

When producing random numbers, the ESDM probes the DRNG instances starting
with the one of the current CPU and uses the first one that is fully seeded.
If no such DRNG instance is found, it falls back to using the DRNG for node
zero - the implementation is provided with the function
`esdm_drng_get_sleep`.

=== Flexible Design <sec:flexible-design>

Albeit the preceding sections look like the DRNG and the management logic are
highly interrelated, the ESDM code allows for an easy replacement of the DRNG
with another deterministic random number generator. This flexible design
allowed the implementation of the ChaCha20 DRNG if the SP800-90A DRBG is not
desired, as well as of the different crypto backends.

To implement another DRNG, all functions in `struct esdm_drng_cb` in
`esdm/crypto/esdm_crypto.h` must be implemented. These functions cover the
allocation/deallocation of the DRNG as well as its usage, the seeding taking
the seed and the additional input. Similarly, all functions in
`struct esdm_hash_cb` must be implemented to provide the conditioning hash,
and all functions in `struct esdm_xof_cb` to provide the SHAKE256 of the
XDRBG-256 pools.

The implementations can be changed at compile time. The default
implementation is the SP800-90A Hash DRBG with SHA-512 and a
software-implementation of SHA-512 and SHAKE256.

In addition, the ESDM allows the addition of new entropy sources, also outside
of the ESDM code as external entropy sources (section @sec:ext-es).

== ESDM Data Structures <sec:data-structures>

The ESDM uses the following main data structures:

- The data from the interrupt and scheduler entropy sources of the kernel
  module is recorded in per-CPU rings. The rings are written lockless since
  the currently executing CPU's ring is used. Reading the rings for seeding
  the DRBG of the kernel module is serialized with a lock which is not used by
  the writers.

- The eBPF entropy sources collect their data in per-CPU maps of the eBPF
  programs; their conditioning pools as well as the auxiliary pools are each
  protected by a lock.

- The cryptographic algorithm data structures hold the reference to the DRNG
  instance and the hash instance and associated meta data needed for its
  operation. Each DRNG instance is protected by a lock of its own which guards
  its state. The seeding of the DRNG instances is serialized with the lock of
  the entropy pool.

== Interrupt Processing - ESDM-internal Entropy Source <sec:irq-processing>

The interrupt entropy source is provided by the kernel module
`kernel/esdm_es` (`esdm_es.ko`, built with `BUILD_ES_IRQ=1`, which is the
default). The kernel patch `0002-ESDM-interrupt-entropy-source-hooks` hooks a
callback of the module into the interrupt handling of the Linux kernel. The
ESDM reads the entropy source via the IOCTLs of the device `/dev/esdm_es`
(`kernel/shared/esdm_es_ioctl.h`).

The ESDM interrupt processing callback is the hot code path in the ESDM and
special care is taken that it is as short as possible and that it operates
without locking.

Figure @fig:irq-processing illustrates the interrupt processing performed by
the ESDM. The figure specifies which parts of the interrupt processing execute
in IRQ context and which executes in process context. The operations executed
in interrupt context are all completely listed in this section. All steps
executed in process context are illustrated in section @sec:seeding.

The figure depicts the example when one interrupt arrives on CPU 0. If an
interrupt arrives on another CPU, the same operation is applied, but the
respective CPU-local ring is used. The rings from other CPUs in the figure
therefore are filled with the same processing steps, which, however, are not
shown.

#figure(
  image("../figures/irq-processing.svg", width: 100%),
  caption: [Interrupt Processing],
) <fig:irq-processing>

The following processing happens when an interrupt is received and the ESDM
is triggered:

+ A high-resolution time stamp is obtained using the service
  `random_get_entropy` kernel function. This integer value is divided by a GCD
  to eliminate bits that do not change. The GCD is calculated from the first
  100 time stamps; a GCD of 1000 or more indicates a timer too coarse to
  deliver entropy, which stops the crediting of entropy. Until the GCD is
  calculated, the undivided time stamp is processed.

+ The health tests discussed in section @sec:health-tests are performed on
  each received time stamp. A time stamp not passing them is dropped.

+ The time stamp is stored in the operating CPU's ring. When the ring is full,
  the time stamp is dropped. Entropy is contained in the variations of the
  time of events and its time delta variations.

+ The number of time stamps recorded in all rings is translated into an
  entropy statement when the ESDM wants to know how much entropy is present
  in the entropy source.

+ When the ESDM requests data from the interrupt entropy source with the
  `ESDM_IRQ_ENT_BUF` IOCTL, the recorded time stamps are post-processed with
  the DRBG of the kernel module as specified in section @sec:dp-irq and
  depicted in figure @fig:collection-pool. This is performed in process
  context.

  #figure(
    image("../figures/collection-pool-processing.svg", width: 70%),
    caption: [Kernel Entropy Source Data Extraction],
  ) <fig:collection-pool>

+ The ESDM server implements a monitor thread that polls all entropy sources
  every $2^29$ nanoseconds. Every time the entropy sources collected enough
  entropy while not all DRNG instances are fully seeded, a reseed is triggered
  as discussed in section @sec:seeding.

+ If all DRNG instances are fully seeded, the arrival of entropy does not
  trigger a reseed any more. At runtime, the entropy sources will not trigger
  a reseeding of the DRNG.

#par(first-line-indent: 0pt)[As the interrupt entropy source takes away the
main entropy source of the kernel RNG, the `esdm-kernel-seeder` reseeds the
kernel RNG every 120 seconds (meson option `linux-reseed-interval`) with 512
bits of data obtained from the ESDM server, credited with the entropy of the
meson option `linux-reseed-entropy-count` (0 per default).]

In case the underlying system does not support a high-resolution time stamp,
the entropy source is not credited with entropy.

=== Entropy Amount of Interrupts <sec:entropy-sched-events>

The discussion of the entropy content of scheduling events in section
@sec:entropy-interrupts applies to interrupts as well. The kernel
module records $256 dot "ESDM_ES_OSR"$ interrupts for 256 bits of entropy
(`CONFIG_ESDM_IRQ_ENTROPY_RATE`, 768 with the default oversampling rate of 3).
The meson option `es_irq_entropy_rate` (256 per default) caps the entropy
credited by the ESDM: the kernel module never credits more entropy than the
rate it was loaded with.

=== Health Tests <sec:irq-health-tests>

The health tests documented in section @sec:health-tests are applied to the
interrupt entropy source as well. The ESDM ensures that the health tests for
the interrupt and the scheduler entropy sources are strictly separated. This
separation applies to the SP800-90B as well.

== Scheduler Events - ESDM-internal Entropy Source <sec:sched-events>

The scheduler entropy source is provided by the kernel module as well, built
with `BUILD_ES_SCHED=1` (disabled per default). The kernel patch
`0001-ESDM-scheduler-entropy-source-hooks` hooks it into the scheduling
operation of the Linux kernel which is triggered every time a context switch
is performed as initiated by the scheduler. The ESDM handling of a scheduling
event is depicted with figure @fig:sched-processing.

#figure(
  image("../figures/sched-processing.svg", width: 100%),
  caption: [Scheduler-event Processing],
) <fig:sched-processing>

When a context switch occurs, the ESDM callback is invoked which obtains a
high-resolution time stamp that is processed like the time stamp of an
interrupt as outlined in figure @fig:sched-pool: it is divided by the GCD,
subjected to the health tests and stored in the CPU-local ring. When the
CPU-local ring is full, the time stamp is dropped.

#figure(
  image("../figures/sched-pool-management.svg", width: 62%),
  caption: [Scheduler Event Recording],
) <fig:sched-pool>

At the time the DRNG shall be (re)seeded, the time stamps of the per-CPU rings
are post-processed with the DRBG of the scheduler entropy source as specified
in section @sec:dp-sched. The data processing concepts between the scheduler
ES and the interrupt ES are identical when comparing the figures in this
section to section @sec:irq-processing.

This entire post-processing is performed in the process context. Therefore,
the DRBG operation is not performed as part of the scheduling operation.

As a side note, the scheduler entropy source potentially has some
relationship with the IRQ entropy source because an IRQ may trigger a
scheduler event (e.g. with the flag `TIF_NEED_RESCHED`). Therefore, both
entropy sources cannot be used at the same time and credit entropy to both.
It is permissible to use both, but only one is credited with entropy.

=== Entropy Amount of Scheduling Events <sec:entropy-interrupts>

The question now arises, how much entropy is generated with the scheduler
entropy source. The kernel module records $256 dot "ESDM_ES_OSR"$ scheduling
events for 256 bits of entropy (`CONFIG_ESDM_SCHED_ENTROPY_RATE`), i.e. it
assumes $1 \/ "ESDM_ES_OSR"$ bits of entropy per time stamp - one third of a
bit with the default oversampling rate of 3. The meson option
`es_sched_entropy_rate` caps the entropy credited by the ESDM; it is 0 per
default, i.e. the scheduler entropy source is not credited with entropy unless
configured.

The entropy of high-resolution time stamps is provided with the fast-moving
least significant bits of a time stamp which is supported by the quantitative
measurements of interrupt time stamps shown in chapter @sec:irq-assessment.
The ESDM records the
entire time stamp after its division by the GCD and leaves its compression to
the DRBG post-processing.

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

=== Health Tests <sec:health-tests>

The ESDM implements the following health tests:

- Stuck Test
- Repetition Count Test (RCT)
- Adaptive Proportion Test (APT)

#par(first-line-indent: 0pt)[Those tests are detailed in the following
sections. They are implemented in `kernel/esdm_es/esdm_health.c` for the
entropy sources of the kernel module and in
`esdm/es/ebpf/esdm_es_ebpf_health.bpf.h` for the eBPF entropy sources.]

Please note that these health tests are only performed for the internal
entropy sources. Other entropy sources like the entropy sources feeding the
auxiliary pool, the Jitter RNG, or the CPU-based entropy sources are not
covered by these tests as they are fully self-contained entropy sources where
the ESDM does not have access to the raw noise data and does not include a
model of the entropy source to implement appropriate health tests. The ESDM
considers both as external entropy source. Thus, the user must ensure that
either those other entropy sources implement all health tests as needed - the
ESDM operates the Jitter RNG with its health tests forced (`JENT_FORCE_FIPS`)
with the SP800-90C oversampling in effect, in FIPS mode or with the NTG.1
seeding strategy - or the ESDM must be configured such that these entropy
sources are credited with zero bits of entropy. Not crediting any entropy to
these other entropy sources can be achieved with the following configuration
options:

- Sources feeding the auxiliary entropy pool: The interface functions to
  provide entropy data have to be invoked with the value 0 for the entropy
  rate.

- CPU-based entropy source: `es_cpu_entropy_rate=0`

- Jitter RNG: `es_jent_entropy_rate=0`

#par(first-line-indent: 0pt)[These options ensure that random data from the
entropy sources are pulled, but are not credited with any entropy.]

The kernel module performs the health tests on every time stamp and drops
stuck time stamps. The RCT, the APT and the SP800-90B startup test are only
enforced when the kernel is booted with `fips=1`. The health tests of the eBPF
entropy sources are enabled in FIPS mode, with the SP800-90C oversampling in
effect or with the NTG.1 seeding strategy.

In addition, the entropy sources are only credited if a high-resolution time
stamp is found. Systems with a low-resolution time stamp will not deliver
sufficient entropy for the interrupt entropy source which implies that also
the health tests are not applicable.

#paragraph[Stuck Test][The stuck test calculates the first, second and third
discrete derivative of the time stamp to be recorded in the per-CPU ring.
Only if all three values are non-zero, the received time delta is considered
to be non-stuck. The first derivative calculated by the stuck test verifies
that two successive time stamps are not equal, i.e. are “stuck”. The second
derivative calculates that there is no linear repetitive signal.]

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
counting of the stuck values during the processing of received events. As the
stuck result includes the comparison of two back-to-back time stamps by
computing the first discrete derivative of the time stamp, the RCT simply
checks whether the first discrete derivative of the time stamp is zero. If it
is zero, the RCT counter is increased. Otherwise, the RCT counter is reset to
zero.]

The RCT is applied with $alpha = 2^(-30)$ compliant to the recommendation of
FIPS 140-2 IG 9.8. Considering the assumed entropy of $1 \/ "OSR"$ bits per
time stamp, the cut-off value is $30 dot "OSR"$ for an intermittent failure
and $60 dot "OSR"$ for a permanent failure.

This test is only enforced in FIPS mode.

#paragraph[Adaptive Proportion Test][Compliant to SP800-90B @sp80090b section
4.4.2 the ESDM implements the Adaptive Proportion Test (APT). Considering that
the entropy is present in the least significant bits of the time stamp, the
APT is applied only to those least significant bits. The APT is applied to the
four least significant bits.]

The APT is calculated over a window size of 512 time stamps. The cut-off value
depends on the assumed entropy of $1 \/ "OSR"$ bits per time stamp: with one
bit of entropy per time stamp and non-binary APT-input data, the cut-off value
is C = 325 as defined in SP800-90B section 4.4.2 (355 for a permanent
failure); with the default oversampling rate of 3 of the kernel module it is
459.

This test is only enforced in FIPS mode.

#paragraph[Runtime Health Test Failures][If either the RCT, or the APT health
test fails irrespective whether during initialization or runtime, the
following actions occur:]

+ The entropy collected by the entropy source is invalidated.

+ The SP800-90B startup health test are initiated with all implications
  discussed in section @sec:health-tests. That implies that from that point
  on, new events must be observed and its entropy must be collected before
  data is provided by the entropy source.

#par(first-line-indent: 0pt)[On a permanent failure, the kernel module panics
the kernel if the module parameter `esdm_panic_on_permanent_health_failure`
is set.]

#paragraph[SP800-90B Startup Tests][In FIPS mode, the aforementioned health
tests are applied to the first 1,024 time stamps obtained from the events. In
case one error is identified for either the RCT, or the APT, the collected
entropy is invalidated and the SP800-90B startup health test is restarted.]

As long as the SP800-90B startup health test is not completed, the entropy
source does not deliver data. This implies that the ESDM random number output
interfaces that may block will block until the DRNG is fully seeded from
other entropy sources or the startup health test completed.

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

== eBPF-based Entropy Sources - ESDM-internal Entropy Sources <sec:ebpf>

The eBPF-based scheduler and interrupt entropy sources (meson options
`es_sched_ebpf` and `es_irq_ebpf`, disabled per default) collect the event
timing of the scheduler and the interrupt entropy sources on a stock Linux
kernel without kernel patches. They require a kernel with BTF support and
libbpf 1.2 or later; the eBPF programs are loaded during the privileged
initialization of the ESDM server. Figure @fig:ebpf illustrates their
processing.

#figure(
  image("../figures/ebpf-processing.svg", width: 100%),
  caption: [eBPF Entropy Source Processing],
) <fig:ebpf>

+ The eBPF programs are attached to the `tp_btf/sched_switch` and the
  `tp_btf/irq_handler_entry` tracepoints. They obtain the time stamp of the
  event, divide it by the GCD of the time source and apply the health tests of
  section @sec:health-tests to it.

+ The difference of the time stamp to the one of the preceding event of the
  same CPU is collected in a per-CPU batch of 64 deltas, which is handed to a
  BPF ring buffer when it is full, or after an idle deadline of 250 ms.

+ The ESDM server reads the batches when it wants entropy and inserts them
  into the XDRBG-256 conditioning pool of the source as specified in section
  @sec:dp-ebpf. It stops reading once that pool holds all the entropy one
  output block can carry; deltas collected while nobody reads fill the buffers
  up and are dropped.

+ An extraction reseeds the XDRBG-256 with the inserted deltas and generates
  the output block.

#par(first-line-indent: 0pt)[The entropy rate of the meson options
`es_sched_ebpf_entropy_rate` and `es_irq_ebpf_entropy_rate` (0 per default)
is applied to the 64 bits of each delta and capped at $1 \/ "OSR"$ bits per
event with the oversampling rate of the meson options `es_sched_ebpf_osr` and
`es_irq_ebpf_osr` (1 per default), which also parameterizes the cut-off values
of the health tests. The rates are to be determined with the measurement
tooling in `tests/es_ebpf_testing` before crediting the sources. When the
sources are unloaded, every collected raw sample is zeroized.]

== Auxiliary Entropy Pool - ESDM-external Entropy Sources <sec:aux>

The ESDM also supports obtaining entropy from the following data sources and
entropy sources that are external to the ESDM. The data is injected into the
auxiliary pool.

When the ESDM needs entropy for its auxiliary pool, it signals a semaphore of
its status shared memory segment. Any user-space entropy provider waiting for
it with `esdm_aux_timedwait_for_need_entropy` of `libesdm_aux_client`, as well
as a caller of `select(2)` / `poll(2)` waiting for /dev/random to become
writable, is woken up to provide data. This approach shall ensure that the
ESDM-external entropy sources may provide entropy whenever the auxiliary pool
can take it.

=== Injecting Data From User Space <sec:aux-injecting>

User space can take the following actions to inject data into the DRNG:

- When writing data into /dev/random or /dev/urandom, or using the
  `esdm_rpcc_write_data` RPC API call, the data is added to the auxiliary pool.
  The ESDM assumes it has zero bits of entropy.

- When using the privileged IOCTL of `RNDADDENTROPY` with /dev/random, or the
  privileged `esdm_rpcc_rnd_add_entropy` RPC API call, the caller can inject
  entropic data into the auxiliary pool and define the amount of entropy
  associated with that data.

- When using the write entropy command of the EGD interface, the data is added
  to the auxiliary pool; the entropy claimed for it is only honored for a
  privileged (UID 0) caller.

=== Auxiliary Pool <sec:aux-pool>

The auxiliary pool is maintained as a separate entropy source that eventually
is concatenated with all other entropy sources in compliance with SP800-90C.

The auxiliary pool is an XDRBG-256 as specified in section @sec:dp-aux, the
XDRBG over SHAKE256 with a state of 512 bits whose SHAKE256 is provided by the
crypto backend:

+ Data is inserted by absorbing it into the SHAKE256 context of the pool: it
  becomes part of the seed of the next reseed of the XDRBG.

+ When entropy is to be extracted from the auxiliary pool, the XDRBG is
  reseeded - or instantiated with the first extraction - with the inserted
  data, and the output is generated together with the new state of the pool,
  with which the SHAKE256 context is started again.

+ The output is generated with the size of the data requested by the DRNG
  (e.g. either 256 or 384 bits) and returned to the caller. Note, the auxiliary
  pool output is not truncated to the amount of entropy the data contains
  because the entropy provider may add data to the auxiliary pool without
  entropy, e.g. by simply writing to /dev/random. Thus, it may be possible
  that the auxiliary pool contains zero bits of entropy but yet contains data
  that should be used to “stir” the DRNG state.

#par(first-line-indent: 0pt)[Figure @fig:aux-pool illustrates the auxiliary
pool operation for the case when user space inserts three separate buffers.]

#figure(
  image("../figures/aux-pool-processing.svg", width: 62%),
  caption: [Auxiliary Pool Processing],
) <fig:aux-pool>

In addition, the ESDM maintains an entropy estimator for the auxiliary pool
counting the received entropy. The entropy estimator is capped to a maximum
of the size of the state of the XDRBG, 512 bits, as the pool cannot maintain
more entropy. With the SP800-90C oversampling in effect, the entropy
estimator credits 64 bits less than the pool holds unless the meson option
`aux-has-full-entropy` is enabled.

The output of the auxiliary pool is copied into the seed buffer when
generating random numbers to seed the DRNG. As the output never reveals the
state of the pool, the seed buffer is not inserted back into the auxiliary
pool. An extraction is atomic with respect to the auxiliary pool. This
implies that it will always be fully completed before the next operation can
commence. This ensures that the same auxiliary pool state can only be used
once for a given seeding operation.

The entropy estimator is decreased by the amount of entropy read from the
pool. If the XOF fails during an operation, the state of the pool is discarded
and its entropy estimator set to zero.

During the initialization of the ESDM, the current time together with data of
the CPU entropy source, and a machine-specific personalization string if one is
available, are inserted into the auxiliary pool without being credited with
entropy.

== Jitter RNG - ESDM-external Entropy Source <sec:jent>

The Jitter RNG is treated as an external entropy source which is requested for
random bits at the time the DRNG shall be seeded. With the meson option
`es_jent_entropy_blocks` (128 per default) a separate thread collects blocks
of the Jitter RNG asynchronously into a cache.

The Jitter RNG is allocated with the oversampling rate of the meson option
`es_jent_osr` (3 per default). Its memory size, its hash loop count and its
cache logic can be adjusted with the meson options `es_jent_max_mem`,
`es_jent_hash_loop_count` and `es_jent_all_caches`. With the meson option
`es_jent_ntg1` and a Jitter RNG of version 3.7.0 or later providing secure
memory, the Jitter RNG is operated in its own NTG.1 mode (`JENT_NTG1`): it is
then an NTG.1 conformant RNG by itself.

=== Entropy of CPU Jitter RNG Entropy Source <sec:jent-entropy>

The CPU Jitter RNG entropy source is credited with one bit of entropy per
generated data bit per default.

The entropy value can be altered by changing the meson configuration option of
`es_jent_entropy_rate` (256 per default).

=== Kernel Jitter RNG Entropy Source <sec:jent-kernel>

The ESDM can read the Jitter RNG of the Linux kernel crypto API via the
`libkcapi` library (meson option `es_jent_kernel`, disabled per default). The
kernel crypto API RNG is named with the meson option `es_jent_kernel_name`
(`jitterentropy_rng` per default) or at runtime with the option
`--es_jent_kernel_name` of the ESDM server, e.g. for a jitterentropy kernel
module registering its RNG under another name. The entropy rate is defined
with the meson option `es_jent_kernel_entropy_rate` (256 per default).

== CPU-base Entropy Source - ESDM-external Entropy Source <sec:cpu>

The CPU-based entropy source is treated as an external entropy source which is
requested for random bits at the time the DRNG shall be seeded. Depending on
the underlying CPU, only one such source is available like RDSEED on Intel x86
(or RDRAND if RDSEED is not available), the POWER CPU DARN instruction, the
seed CSR of RISC-V, the PRNO TRNG function of IBM Z or the RNDRRS register of
ARMv8.

Depending on the data multiplier of the CPU entropy source, the following data
collection methods are applied. This approach is orthogonal to the amount of
entropy the ESDM awards to the CPU entropy source.

- Data multiplier of one: The CPU entropy source is queried for the amount of
  data which is stored in the temporary seed buffer.

- Data multiplier larger than one: For this entropy source, the ESDM contains
  the information about how much data must be fetched from the CPU entropy
  source to get full entropy: 2048 times the requested data for RDRAND, twice
  the requested data for DARN and the RISC-V seed CSR. The required amount of
  data is pulled from the CPU entropy source and conditioned with the hash
  currently in use by the ESDM. The calculated message digest is truncated to
  the requested amount of data which is stored in the temporary seed buffer.

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
call with the flag `GRND_NONBLOCK`.

=== Entropy of Kernel RNG Entropy Source <sec:krng-entropy>

When the kernel RNG is enabled, the ESDM applies the entropy rate defined at
compile time with `es_kernel_entropy_rate` (128 per default) which is a value
between 0 and 256 bits of entropy when 256 data bits are pulled from the
legacy RNG.

If the SP800-90C oversampling is in effect, the kernel RNG entropy source's
entropy rate is set to zero. The reason is that the legacy RNG is known to not
comply with FIPS 140 rules like SP800-90B and thus must be assumed to provide
no entropy. The same applies when a scheduler entropy source is credited,
because interrupts may trigger scheduling events, and when a self test of the
entropy source saw a repeated output.

When the interrupt entropy source of the kernel module is present, or the
eBPF-based interrupt entropy source is credited, the kernel entropy source
entropy rate is capped to `ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY` (4) bits of
entropy. This is due to the fact that the presence of IRQ entropy source takes
away the kernel RNG's main entropy source, or credits the same events. Yet,
some other entropy sources are present which may or may not deliver entropy.
Thus a safe entropy value is applied by the ESDM.

== Linux HWRAND Entropy Source - ESDM-external Entropy Source <sec:hwrand>

The ESDM reads the Linux hardware random number generator framework via
`/dev/hwrng` (meson option `es_hwrand`), which provides the data of the
hardware RNG selected in /sys/devices/virtual/misc/hw\_random/rng\_current.
The entropy rate is defined with the meson option `es_hwrand_entropy_rate`
(128 per default).

== TPM 2.0 Entropy Source - ESDM-external Entropy Source <sec:tpm2>

The ESDM obtains random numbers from a TPM 2.0 with the `TPM2_GetRandom`
command sent to the TPM resource manager device of the meson option
`es_tpm2_rm_path` (`/dev/tpmrm0` per default) without using a TSS library
(meson option `es_tpm2`). With the meson option `es_tpm2_stir`, a
`TPM2_StirRandom` command with the current time precedes each request. A
device absent at initialization leaves the entropy source disabled. The entropy
rate is defined with the meson option `es_tpm2_entropy_rate` (256 per default).

== External Entropy Sources - ESDM-external Entropy Sources <sec:ext-es>

Noise sources that are not part of the ESDM are written against
`esdm_es_ext.h` of `libesdm_es_ext` as a `struct esdm_es_ext_plugin` with an
`init`, `fini`, `get_entropy`, `selftest` and `status_json` callback (meson
option `es_ext`). Such a plugin is handed to the ESDM in one of two ways:

- ExternalLib: As a plugin library loaded into the ESDM server
  (`--es_ext_lib` option of the server or meson option `es_ext_lib_path`). Its
  initialization runs while the server still has its privileges.

- ExternalSocket: As a provider process the ESDM server reads from over a Unix
  domain socket (`--es_ext_socket` option of the server or meson option
  `es_ext_socket_path`), e.g. `esdm-es-ext-serve` serving a plugin library.
  The ESDM server accepts the provider only if it runs as root, or as the user
  given with `--es_ext_socket_uid` (meson option `es_ext_socket_peer_uid`).
  The ESDM server asks the provider for DTLS on the connection as discussed in
  section @sec:rpc.

#par(first-line-indent: 0pt)[A block is credited with the entropy the source
claims for it, capped by the rate of the source: the one configured with
`es_ext_lib_entropy_rate` or `es_ext_socket_entropy_rate` (or the options of
the server), else the one the source declares - the `entropy_rate` callback of
a plugin, or the answer of a provider to INFO - else 256 for
a plugin and 0 for a provider, which is credited only once it declares or is
configured a rate. Accepting the user a provider runs as means trusting the
rate it declares; the status shows the rate of each source as `entropy_rate`
and where it comes from as `entropy_rate_source`. A source claiming more than the block holds, or
failing, is credited with nothing until it delivers again, and one failing its
self test until a self test passes.]

The ESDM has `es_ext_lib_num` plugin library sources and `es_ext_socket_num`
provider socket sources, one each by default and up to 16 each. Each is an
entropy source of its own with a slot of its own in the seed buffer, its own
plugin or provider, entropy rate, accepted user and state, so that the ES
manager, its monitor, the NTG.1 seeding strategy, the status and the seeding
treat it like any other entropy source. A kind with one source calls it
ExternalLib or ExternalSocket; with several, the names carry the index:
ExternalLib0, ExternalLib1 and so on. The meson options above take comma
separated lists whose i-th entry configures the i-th source - a single rate or
uid applies to all sources of the kind - and each option of the ESDM server
may be given once per source, its n-th occurrence configuring the n-th
source. A plugin library serves one source, as the callbacks of a plugin are
never called concurrently; several providers are served by several
`esdm-es-ext-serve` processes on sockets of their own.

A plugin declares the name of its source with the `name` member of its
struct, a provider in its answer to the INFO request of the socket protocol,
which the ESDM asks once per connection - `esdm-es-ext-serve` answers with the
name of its plugin or the one given with `--name`. The ESDM shows the source
under that name in its status and log, if it is 1 to 32 bytes of UTF-8
without control characters and not the name of another entropy source; the
name of its entry in the ES table, ExternalLib1 say, remains its `instance`
in the status. Two sources may declare the same name.

The status a plugin reports with its `status_json` callback, a JSON object of
up to 512 bytes, appears as the `provider` member of its source in the ESDM
status. A provider answers the STATUS request with one of up to 1024 bytes:
`esdm-es-ext-serve`, as any provider served by `libesdm_es_ext`, with
`{"server": {...}, "plugin": ...}` - fields of the server, such as the name
and the rate it declares, the DTLS of the connection, its clients, the
requests served, the verdict of the last self test of its plugin and its
uptime, next to the status of its plugin, null where there is none. The ESDM
asks each source for its status at most every 5 seconds, never waiting for a
source busy with a request.

=== External Entropy Sources on the Network <sec:ext-es-net>

A noise source on another host is read by the ESDM through an ExternalSocket
source as well (meson option `es-ext-net`, disabled per default, Linux only,
with the TLS stack of OpenSSL, GnuTLS or Botan). The ESDM server itself does
not change: it leaves the network namespace of the host as it starts, so it
reaches no network, and it parses no certificate. The `esdm-es-ext-relay` of
its host serves it a local provider socket, which the ESDM reads and checks
as any other provider - by the user the relay runs as -, and forwards each
request to a provider served on the network by the provider server of
`libesdm_es_ext`, i.e. `esdm-es-ext-serve` or `esdm-es-pkcs11` started with
`--listen` or by socket activation, as depicted in figure @fig:dtls-sctp.

#par(first-line-indent: 0pt)[The relay forwards the requests INFO, SELFTEST,
GET_ENTROPY and STATUS one to one rather than serving them from a plugin of
its own: the name and the rate the ESDM credits a connection with are those
the remote provider declared on that very connection - each local connection
has an upstream connection of its own, opened when the ESDM asks INFO, which
has to come first - and the status is the remote provider's, unwrapped. Every
answer is checked as the ESDM checks it before it is passed back, so that the
remote side can do nothing a local provider could not. A provider that is not
reachable has INFO answered with an errno, so that the ESDM shows the source
as not connected; a provider lost while idle closes the local connection, and
the ESDM connects anew with its next request; every step upstream is bounded
below the 2 seconds the ESDM gives a request. Accepting the user of the relay
means trusting the rate every holder of a certificate the relay accepts for
the provider declares, unless a rate is configured for the source.]

The transport is SCTP of the one-to-one style with DTLS 1.2 as RFC 6083 maps
it onto SCTP (`common/esdm_tls_sctp.c`, `common/esdm_tls.h`): every DTLS
record is one SCTP message on stream 0, ordered, the DTLS does not retransmit,
and every message is DTLS from the first one on - the STARTDTLS of the Unix
domain socket has no place there. Both sides authenticate with certificates,
the client checks the name of the server, and CRLs are checked within the
verification of the TLS stack with the code of the EGD protocol over the
network: the TLS with certificates, its rotation on SIGHUP and when the files
change, and its revocation checks are one implementation for TLS over TCP and
DTLS over SCTP, for every TLS stack, the transport an option of the context.

#par(first-line-indent: 0pt)[The SCTP association authenticates its DATA and
FORWARD-TSN chunks with SCTP-AUTH (RFC 4895): both ends require it with
`SCTP_AUTH_CHUNK` before they connect or listen, and refuse an association
whose peer does not authenticate them. The handshake runs under key 0, the
empty key. Before it sends its ChangeCipherSpec, each side waits until the peer
acknowledged all it sent (`SCTP_SENDER_DRY_EVENT`, RFC 6083 section 4.7) and
installs key 1, the 64 bytes of the TLS exporter `EXPORTER_DTLS_OVER_SCTP`
without a context; the server makes it the active key after its
ChangeCipherSpec, the client after its Finished, and both delete key 0 once
the handshake is complete - the key handling of
draft-ietf-tsvwg-dtls-over-sctp-bis for DTLS 1.2, and the one of OpenSSL's own
DTLS over SCTP, with which all three TLS stacks interoperate. The key comes
from `SSL_export_keying_material()` of OpenSSL and `gnutls_prf_rfc5705()` of
GnuTLS; Botan exports keys only once its channel is active, so its key is
computed with the TLS 1.2 PRF of the session from the master secret and the
randoms of the handshake, and compared with Botan's export once the handshake
completed - as the exports of the other stacks are, a mismatch failing the
connection. The DTLS is not renegotiated, so the key is set once per
association. Linux enables SCTP-AUTH per socket (`SCTP_AUTH_SUPPORTED`) since
5.4; on an older kernel without the sysctl `net.sctp.auth_enable=1`, the
daemons fail with an error naming it.]

#figure(
  image("../figures/dtls-sctp-auth.svg", width: 85%),
  caption: [External Entropy Source on the Network: DTLS over SCTP with
    SCTP-AUTH],
) <fig:dtls-sctp>

The listener of the provider faces the network, so it bounds its connections
as the EGD network server does: in all, in their handshake in all and per
source address, per client certificate, by a handshake and an idle timeout,
and by an allowlist of source networks. Its status tells `sctp` as the
`transport` of the server and the SHA-256 of the client certificate as its
`peer`. After every reload of the TLS files, provider and relay check their
established connections against the new CRLs and close those of a revoked
peer, and every 30 seconds those of an expired one.

== PKCS\#11 Entropy Source - ESDM-external Entropy Source <sec:pkcs11>

The random number generator of a PKCS\#11 token is read with
`C_GenerateRandom` via the `libp11` library by `esdm-es-pkcs11` (meson option
`es_pkcs11`, disabled per default), a provider of its own served by
`libesdm_es_ext` as discussed in section @sec:ext-es: the ESDM reads it
through one of its ExternalSocket sources and contains no PKCS\#11 code. The
PKCS\#11 module of the token vendor runs in that process with the privileges
the token needs, and the PIN is a secret of that process alone.

The daemon takes the token of a configured label (`--token_label`, meson
option `es_pkcs11_token_label`) or the first token with a random number
generator among the slots of its module (`--module`, meson option
`es_pkcs11_module_path`). It logs in as user only if a PIN is configured and
the token asks for a login; the PIN is read from a file or a systemd
credential, never from the command line or the build. As every failed login
uses up one of the PIN retries of the token, a PIN the token refused is wiped
and never tried again. A token that is not there, or lost to a failed
`C_GenerateRandom`, is looked for again at most every 5 seconds, loading the
module anew where its slots hold no usable token. A token is tested whenever
it is bound - two reads that have to differ - and one repeating its output is
credited with nothing until a later test passes.

The daemon declares "PKCS\#11" and the token label as the name of the source
and the entropy rate of the meson option `es_pkcs11_entropy_rate` (128 per
default, `--entropy_rate`), which the ESDM credits unless a rate is configured
for the source. Its status reports the module, the token label, the token and
its slot, whether it is present and logged in to, what became of the PIN and
the last error.

== DRNG Seeding Operation <sec:seeding>

The seeding operation obtains random data from all available entropy sources.

The (re)seeding logic tries to obtain 256 bits of entropy from the entropy
sources. However, a reseed is only performed if at least 256 bits of entropy
collectively from all entropy sources are available.

For efficiency reasons, the seeding operation uses a seed buffer depicted in
figure @fig:big-picture that consists of one slot of 256 bits per entropy
source, 384 bits with the SP800-90C oversampling in effect. Each slot is
dedicated to an entropy source. As each entropy source can be disabled at
compile time, only the slots of the entropy sources enabled at compile time
are present. The slots are filled in the order given in section
@sec:components:

+ The slots of the interrupt and scheduler entropy sources of the kernel module
  are filled with the output of their DRBG as depicted in figure
  @fig:collection-pool. A slot receives as much data from the DRBG as entropy
  can be pulled from the per-CPU rings. In the worst case when no new events
  are received, no data is delivered.

+ The slots of the eBPF entropy sources are filled with the output of their
  XDRBG-256 conditioning pools.

+ The slots of the fast entropy sources - the Jitter RNG, the CPU, the kernel
  RNG, the HWRAND, the TPM 2.0, the PKCS\#11 token, the kernel Jitter RNG and
  the external entropy sources - are filled with their data, or with a block
  from their cache collected ahead of the request.

+ Finally, one slot is filled with the output of the auxiliary pool.

#par(first-line-indent: 0pt)[Finally, also a time stamp (`struct timespec` of
`CLOCK_MONOTONIC`) indicating the time of the request is mixed into the DRNG.
That time stamp, however, is not assumed to have entropy and is only there to
further stir the state of the DRNG.]

The filled seed buffer is handed to the DRNG as a seed string together with
the additional input buffer holding the data of the entropy sources not
credited with entropy. The seeding of the prediction resistance DRNG does not
use the caches of the entropy sources, as its seed must be collected for the
very request it serves.

=== DRNG May Become Not Fully Seeded <sec:not-fully-seeded>

The ESDM maintains a counter for each DRNG instance how many generate
operation are performed without performing a reseed that has full entropy. If
this counter exceeds the threshold of $2^30$ generate operations, or the
number of bits generated reaches the threshold of the meson option
`drng_max_reseed_bits`, i.e. the DRNG did not receive a seed with full entropy
for that many generate operations, the DRNG is set to not fully seeded. This
setting implies that the DRNG instance will not be used any more for
generating random numbers until the ESDM received sufficient entropy to
reseed the DRNG with full entropy. A request served by a per-CPU DRNG instance
in this state is served by the initial DRNG instance instead.

If the DRNG that becomes not fully seeded is the initial DRNG instance that
was seeded during boot time as outlined in section @sec:seed-levels, the
entire ESDM is marked as not operational. This setting blocks all blocking
interfaces just like during boot time when the ESDM is not yet fully seeded.

The ESDM automatically tries to recover from it when it received sufficient
entropy, with a forced seeding while the ESDM is not operational.

== Cryptographic Primitives Used By ESDM <sec:crypto>

The following subsections explain the cryptographic primitives that may be
used by the ESDM.

=== Crypto Backends <sec:backends>

The ESDM obtains its cryptographic primitives - the DRNG, the conditioning
hash and the SHAKE256 of the XDRBG-256 pools - from the crypto backend
selected with the meson option `crypto_backend` as listed in table
@tab:backends. The implementations are found in `esdm/crypto`, the builtin
primitives in `crypto`.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(left + top)
    table(
      columns: (auto, 1fr, auto, auto),
      table.header(
        [Backend], [DRNG], [Hash], [SHAKE256],
        table.hline(stroke: 1.5pt),
      ),
      [builtin (default)],
      [SP800-90A Hash DRBG with SHA-512 (`drng_hash_drbg`, default) or
        ChaCha20 DRNG (`drng_chacha20`)],
      [SHA-512 (`hash_sha512`) or \ SHA3-512 (`hash_sha3_512`)],
      [builtin],
      [OpenSSL],
      [SP800-90A Hash DRBG with SHA-512 (default), CTR DRBG with AES-256 or
        HMAC DRBG with SHA-512 (`openssl_drng_type`)],
      [SHA3-512], [OpenSSL],
      [Botan],
      [SP800-90A HMAC DRBG with SHA-512 (default) or ChaCha20 RNG
        (`botan_drng_type`)],
      [SHA3-512], [Botan 3.2 \ or later],
      [GnuTLS],
      [SP800-90A CTR DRBG with AES-256 and the Block_Cipher_df derivation
        function added by the ESDM],
      [SHA-512 (nettle)], [nettle 3.6 \ or later],
      [leancrypto],
      [XDRBG-256 with SHAKE256],
      [SHA3-512], [leancrypto],
    )
  },
  caption: [ESDM Crypto Backends],
) <tab:backends>

All DRNG instances are always instantiated with the same DRNG type. The
backends based on libraries allow using assembler or even hardware-accelerator
backed cipher primitives.

=== DRBG <sec:drbg>

If the SP800-90A DRBG implementation is used, the default DRBG used by the
ESDM is the builtin Hash DRBG with SHA-512 (`crypto/hash_drbg.c`). Other DRBG
types are provided by the crypto backends listed in section @sec:backends.

The input with the seed and re-seed of the DRBG has been explained above and
does not need to be re-iterated here. Mathematically speaking, the seed and
re-seed data obtained from the entropy sources and the ESDM external sources
are mixed into the DRBG using the DRBG instantiate and reseed functions as
defined by SP800-90A, the data of the entropy sources not credited with
entropy as additional input.

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
defined to have a special property: it only provides data once the ESDM is
fully seeded as outlined in section @sec:seed-levels. In addition, the ESDM
must be fully initialized before random numbers are generated, including the
completion of the SP800-90B heath test if entropy from internal entropy
sources is gathered.]

=== ChaCha20 DRNG <sec:chacha20>

If the SP800-90A DRBG is not desired, the ESDM can use a standalone C
implementations for ChaCha20 to provide a DRNG (meson option
`drng_chacha20` of the builtin crypto backend).

The ChaCha20 DRNG is implemented with the components discussed in the
following section. All of those components rest on a state defined by
@rfc7539, section 2.3.

The operation of the ChaCha20 DRNG can be characterized with figure
@fig:chacha20. This figure outlines the initialization of the DRNG, its
seeding using the state update operation and the invocation of one generate
operation that is requested to obtain more than 512 bits of data.

#figure(
  image("../figures/chacha20-drng.svg", width: 100%),
  caption: [ChaCha20 DRNG Operation],
) <fig:chacha20>

#paragraph[State Update Function][The state update function's purpose is to
update the state of the ChaCha20 DRNG - the implementation is provided with
the function `esdm_cc20_drng_update` in `crypto/chacha20_drng.c`. That is
achieved by]

+ XOR the key-sized part of the last output block of the generate operation
  that was not handed out with the key part of the ChaCha20 state, or,
+ if less than a key-sized part of it is left, generating one output block of
  ChaCha20 and XOR its first key-sized part with the key part of the ChaCha20
  state.

#par(first-line-indent: 0pt)[In addition, the nonce part of the state is
incremented by one to ensure the uniqueness requirement of @rfc7539 chapter
4.]

#paragraph[Seeding Operation][The seeding operation processes a seed of
arbitrary lengths. The seed is segmented into ChaCha20 key size chunks which
are sequentially processed by the following steps:]

+ The key-size seed chunk is XORed into the ChaCha20 key location of the
  state.
+ This operation is followed by invoking the state update function with a
  fresh output block.
+ Repeat the previous steps for all unprocessed key-sized seed chunks.

#par(first-line-indent: 0pt)[If the last seed chunk is smaller than the
ChaCha20 key size, only the available bytes of the seed are XORed into the key
location. This is logically equivalent to padding the right side of the seed
with zeroes until that block is equal in size to the ChaCha20 key. The
additional input is processed the same way after the seed.]

The invocation of the state update function is intended to eliminate any
potentially existing dependencies between the seed chunks.

#paragraph[Generate Operation][The random numbers from the ChaCha20 DRNG are
the data stream produced by ChaCha20, i.e. without the final XOR of the data
stream with plaintext. Thus, the DRNG generate function simply invokes the
ChaCha20 to produce the data stream as often as needed to produce the
requested number of random bytes - in chunks of at most $2^30$ bytes with a
state update in between.]

After the conclusion of the generate operation, the state update function is
invoked to ensure enhanced backward secrecy of the ChaCha20 state that was
used to generate the random numbers.

=== XDRBG-256 <sec:xdrbg>

The auxiliary pool and the conditioning pools of the eBPF entropy sources are
each an XDRBG-256 - the XDRBG over SHAKE256 with a state of 512 bits as
specified in section @sec:dp-aux. The implementation is provided with
`esdm/crypto/esdm_xdrbg.c`, the SHAKE256 is that of the crypto backend
(`struct esdm_xof_cb`). The additional input $alpha$ of at most 84 bytes
separates the different pools. An XDRBG-256 generates at most the seed size of
the DRNG with one extraction.

== ESDM External Interfaces <sec:interfaces>

The following ESDM interfaces are provided:

- ESDM library API: The API is documented in ‘esdm.h‘.

- ESDM server RPC API: The RPC API is documented in ‘esdm\_rpc\_client.h‘, see
  section @sec:rpc.

- EGD interface: See section @sec:egd.

- /dev/random and /dev/urandom device files: See the Linux man page
  `random(4)`. In addition, when opening the /dev/random or the /dev/urandom
  device with the `O_SYNC` flag, the prediction resistance DRNG is used to
  service the request with the ESDM API call of `esdm_get_random_bytes_pr`
  (`esdm_get_random_bytes_pr_noblock` with `O_NONBLOCK`). Therefore all
  considerations outlined for this API apply to the device files with `O_SYNC`
  as well. If the ESDM server cannot be reached, the CUSE daemons serve the
  read from the device file of the kernel. The privileged IOCTLs require the
  capability `CAP_SYS_ADMIN`.

- /proc/sys/kernel/random/\* interfaces: See the Linux man page random(4) and
  the description of `esdm-proc` in chapter @sec:design.

- getrandom and getentropy APIs: See Linux man pages `getrandom(2)` and
  `getentropy(3)`. The flags select the ESDM API call to service the request:

  - `GRND_INSECURE`: `esdm_get_random_bytes`,
  - `GRND_RANDOM`: `esdm_get_random_bytes_pr`,
  - `GRND_SEED` (0x0010, a flag of the ESDM): `esdm_get_seed` to obtain the
    data of the entropy sources directly, with the ESDM flag
    `GRND_FULLY_SEEDED` (0x0020) indicating that the caller's DRNG is already
    fully seeded, i.e. that the entropy for a reseed and not for the initial
    seeding is requested,
  - otherwise: `esdm_get_random_bytes_full`.

- OpenSSL RAND providers (meson option `openssl-rand-provider`):
  `libesdm-rng-provider.so` serves the RAND algorithms of OpenSSL from the
  ESDM over the RPC interface and honors the prediction resistance flag of
  OpenSSL, `libesdm-rng-provider-pr.so` serves all requests from the
  prediction resistance DRNG, `libesdm-seed-src-provider.so` provides the ESDM
  as seed source, and `libesdm-egd-provider.so` and
  `libesdm-egd-provider-pr.so` obtain the data over the EGD interface - the
  former honors the prediction resistance flag of OpenSSL with the prediction
  resistance read of the ESDM, the latter serves all requests with it.

- Kernel character devices (kernel module `esdm_cdev`, section @sec:egd):
  `/dev/esdm_random` is served from `esdm_get_random_bytes_full`, waiting until
  the ESDM is operational, `/dev/esdm_urandom` from `esdm_get_random_bytes`;
  opened with `O_SYNC`, either one is served from the prediction resistance
  DRNG. `/proc/esdm` offers the files of `/proc/sys/kernel/random` and the
  status. When the ESDM is not reachable, the module serves from the kernel's
  RNG.

- Status: See section @sec:status.

=== RPC Interface <sec:rpc>

The ESDM server provides two RPC interfaces on Unix domain sockets of the type
`SOCK_SEQPACKET`: the unprivileged one on `esdm-rpc-unpriv.socket`, which
everybody may access, and the privileged one on `esdm-rpc-priv.socket`, whose
operations are only executed for a caller with the user ID 0 as reported by
`SO_PEERCRED`. The messages are encoded with protobuf-c behind a header with
the method index, the message length and a request identifier
(`service-rpc/service/esdm_rpc_protocol.h`).

- Unprivileged operations: obtaining random numbers (`GetRandomBytes`,
  `GetRandomBytesFull`, `GetRandomBytesPr`), seed data (`GetSeed`), writing
  data without entropy (`WriteData`), the status (`Status`, `StatusJson`,
  `DrngStatusJson`, `JentStatus`) and the entropy levels and settings of the
  Linux interfaces.

- Privileged operations: inserting entropy (`RndAddEntropy`,
  `RndAddToEntCnt`), clearing the entropy estimates (`RndClearPool`), forcing a
  reseed (`RndReseedCRNG`), changing the Linux interface settings and running
  the self tests (`Selftest`). The slot of a call that configured the
  PKCS\#11 entropy source of earlier development versions is kept, answered
  with `-EOPNOTSUPP`, so that the calls after it keep their index on the wire.

#par(first-line-indent: 0pt)[With the meson option `dtls` (disabled per
default), the connections between the processes of the ESDM are protected
with opportunistic DTLS 1.2 provided by the TLS stack of the crypto backend -
OpenSSL, GnuTLS or Botan - as depicted in figure @fig:dtls
(`common/esdm_dtls.h`): the client asks for it with a `STARTDTLS` request on
every new connection, followed by a probe request which changes nothing, and
goes on in the clear with a server that does not know or refuses DTLS (ESDM
1.2.3 and before, or a server started with `--no_dtls`). The DTLS uses an
ephemeral ECDH key exchange and AEAD ciphers only, with an ephemeral
self-signed server certificate the client does not verify: what a peer is
trusted for is what `SO_PEERCRED` says, as without DTLS. The DTLS keeps the
data from being read off the connection. One DTLS record is sent per message
of the socket. The same DTLS protects the connection of the ExternalSocket
entropy source to its provider.]

#figure(
  image("../figures/dtls-handshake.svg", width: 85%),
  caption: [Opportunistic DTLS of an RPC Connection],
) <fig:dtls>

=== EGD Interface <sec:egd>

The ESDM server optionally serves the protocol of the Entropy Gathering Daemon
on a Unix domain socket of the type `SOCK_STREAM`, enabled with the systemd
socket unit `esdm-server-egd.socket` or the option `--egd_socket` of the
server (`/run/esdm-egd.socket` per default, meson option
`esdm-server-egd-socket-path`). The socket is accessible by all users. It
offers the commands of the EGD protocol (`service-egd/esdm_egd_protocol.h`):

- 0x00: the available entropy in bits,
- 0x01: reading up to the requested number of bytes without blocking,
- 0x02: reading the requested number of bytes, blocking,
- 0x03: writing data with an entropy claim into the auxiliary pool - the
  claim is only honored for a caller with the user ID 0,
- 0x04: the PID of the server.

#par(first-line-indent: 0pt)[A transfer is limited to 255 bytes. The random
numbers are served from `esdm_get_random_bytes_full_noblock`. What the EGD
protocol cannot express, the ESDM offers with commands of its own on the same
socket, far away from the standard ones so that no EGD client sends one by
accident; a peer that does not know them closes the connection, which a client
takes for "not supported". They are framed like EGD - a command byte, fixed
size big endian arguments, an answer whose size is known from the request or
announced by a length prefix:]

- 0xe0 and 0xe1: reading as 0x01 and 0x02, but from the prediction resistance
  DRNG (`esdm_get_random_bytes_pr_noblock`); a server worker generates
  prediction resistant bytes within a budget per connection and round of its
  event loop,
- 0xe2: reading as 0x01, but without waiting for all DRNGs to be fully seeded
  - the semantics of `/dev/urandom`,
- 0xe3: the state - flags (operational, fully seeded), the entropy and the
  size of the auxiliary pool, `write_wakeup_threshold` and
  `urandom_min_reseed_secs`, as a count of 4 byte fields to which new ones are
  only ever appended,
- 0xe4 and 0xe5: the status report as text and as JSON document, with a 4 byte
  length of at most 64 KiB,
- 0xe6 to 0xea, only for a caller with the user ID 0 and refused with -EPERM
  otherwise: crediting entropy to the auxiliary pool, clearing its entropy,
  reseeding the DRNGs, setting `write_wakeup_threshold` and setting
  `urandom_min_reseed_secs`.

#par(first-line-indent: 0pt)[The commands are defined in
`service-egd/esdm_egd_protocol.h`. The client library `libesdm_egd_client`
offers the prediction resistance reads with `esdm_egd_client_get_random_pr`;
it owns one connection, serializes the requests on it and reconnects after a
restart of the server or a `fork()` of the caller. The kernel module
`esdm_cdev` uses the extensions to serve `/dev/esdm_random`,
`/dev/esdm_urandom` and `/proc/esdm` together with the ioctls of the kernel's
random devices.]

=== ESDM Status <sec:status>

The ESDM keeps its status as JSON documents only (`esdm/status/esdm_info.c`):
the general status (`esdm_status_json`) with the version of the library, the
DRNG, the security strength, the satisfied standards, the seeding state, the
entropy level, the state of every entropy source, the DRNG instances, the
reseed worker and the periodic self tests, and the state of the DRNG instances
(`esdm_status_drng_json`, `esdm_status_drng_pr_json`). The text form of the
status (`esdm_status`) is printed from the JSON document
(`esdm/status/esdm_status_txt.c`), so the two cannot tell different stories.
The status is available via the RPC interface, `esdm-tool --status` and the
file `/proc/sys/kernel/random/esdm_type`. The status flags of the satisfied
standards are “FIPS 140”, “SP800-90C”, “NTG.1(2011)”, “NTG.1(2024)”, “DRG.3”
and “DRG.4”.

The ESDM server also maintains a status shared memory segment with semaphores
that the CUSE daemons and the auxiliary client use to learn about the
operational state and the need for entropy without an RPC call.

== ESDM Self-Tests <sec:self-tests>

All cryptographic primitives are self-tested during the startup phase of the
ESDM with known-answer tests including negative tests - the implementation is
provided with `esdm/esdm_selftest.c`:

- the conditioning hash of the crypto backend,
- the XDRBG-256 together with its SHAKE256,
- the DRNG including a reseed.

#par(first-line-indent: 0pt)[In addition, every entropy source is asked to
test itself without consuming entropy - for the SP800-90B entropy sources the
on-demand health test. The self tests are repeated every 600 seconds by a
periodic worker and can be triggered with the privileged `esdm_rpcc_selftest`
RPC API call or `esdm-tool --selftest`. No random numbers are generated while
the cryptographic self tests have not passed. A failed self test of an entropy
source removes the entropy source from crediting entropy until a self test
passes.]

In FIPS mode, i.e. if `/proc/sys/crypto/fips_enabled` is set or the environment
variable `ESDM_SERVER_FORCE_FIPS` is present, a power-on self test is
performed before the ESDM starts (`esdm/fips.c`): an HMAC-SHA256 known-answer
test and the integrity test of the ESDM server executable, `libesdm.so.1`, the
Jitter RNG library and the library of the crypto backend against the reference
value of the HMAC file next to each of them, which is created with
`esdm-tool --fips-targetfile` and `--fips-checkfile`. A missing reference value
is a failed integrity test.

== ESDM Test Interfaces <sec:test-interfaces>

When compiling the kernel module with `BUILD_TESTING=1`, the following
interfaces are enabled allowing direct access to non-deterministic aspects.
It is not advisable to enable these interfaces for production systems. Yet,
these interfaces are considered to be protected against misuse by allowing
only the root user to access them. In addition, any data obtained through
these interfaces is not used by the ESDM to feed the entropy pool. Thus, even
when leaving these interfaces enabled on production systems, the impact on
security is considered to be limited.

- Interrupt Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_hires` allows reading
    of the raw unconditioned noise data collected while the read operation is
    in progress by providing the time deltas of the events collected by the
    ESDM that otherwise are injected into the entropy pool. When loading the
    module with the module parameter `boot_raw_hires_test=1`, the time deltas
    of the first 1,024 events recorded by the ESDM are stored. The first read
    of the `esdm_raw_hires` file after loading the module provides this data in
    this case.

  - The interface `/sys/kernel/debug/esdm_es/esdm_irq_perf` allows reading of
    the number of cycles used to process one interrupt event. This allows
    measuring the performance impact of the ESDM on the interrupt handler.
    When loading the module with the module parameter `boot_irq_perf=1`, the
    performance data of the first 1,024 events recorded by the ESDM are
    stored. The first read of the `esdm_irq_perf` file provides this data in
    this case.

- Scheduler Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires` allows
    reading of the raw unconditioned noise data of the scheduler entropy
    source, with the module parameter `boot_raw_sched_hires_test=1` for the
    first 1,024 events.

  - The interface `/sys/kernel/debug/esdm_es/esdm_sched_perf` allows reading
    of the number of cycles used to process one scheduler event, with the
    module parameter `boot_sched_perf=1` for the first 1,024 events.

#par(first-line-indent: 0pt)[The helper tool `esdm-getrawentropy`
(`tests/validation-helpers`, meson option `validation-helpers`) is provided to read the
files and format the data for post-processing, `esdm-extractlsb` extracts the
least significant bits of the time stamps for the SP800-90B tools. No data is
collected while the debugfs is locked down by the kernel lockdown mode.]

For the eBPF entropy sources, the collector `esdm-ebpf-collect` together with
the scripts `analyze_non_iid.sh` and `analyze_restart.sh` in
`tests/es_ebpf_testing` (meson option `es_ebpf_testing`) obtains the raw time
deltas and performs the SP800-90B assessment including the restart test. The
collector refuses to run in FIPS mode, and the ESDM server itself never records
raw data.
