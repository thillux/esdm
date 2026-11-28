#import "../template.typ": *
#import "../packet.typ": exchange, exchanges, field, command

= ESDM Design <sec:design>

Figure @fig:big-picture gives an overview of the #ac("ESDM") processing and
its components.

#figure(
  image("../figures/big-picture.svg", width: 92%),
  caption: [#ac("ESDM", cap: true) Overview],
) <fig:big-picture>

The shades sort the entropy sources that the #ac("ESDM") manages: darker shades
mark the internal ones of the kernel module, lighter shades the internal
#acs("eBPF")-based ones and gray the external ones. The auxiliary pool and the
timestamp follow.

The #ac("ESDM") introduces the concept of slow and fast entropy sources. Fast
entropy sources provide entropy at the time of request. A slow entropy source
collects data over time into an entropy pool.

The entropy sources under full control of the #ac("ESDM") are called the
internal entropy sources. They all measure the timing of related events, so at
most one of them may be credited with entropy: the build system refuses a
configuration crediting two of them, and setting the entropy rate of one of them
at runtime sets the others to zero (`esdm_config_timing_es_rate_set`). The
internal entropy sources are:

- The column Sched refers to the scheduler entropy source of the kernel
  module `esdm_es` (`kernel/esdm_es`) that feeds per-#acs("CPU") rings with the
  timestamps of task wakeups. When the #ac("ESDM") seeds the #ac("DRNG"), a
  #ac("DRBG") of the kernel module post-processes the timestamps of these
  rings.

- The column #ac("IRQ") refers to the interrupt entropy source of the same
  kernel module. It has the same architecture as the scheduler-based entropy
  source: it feeds the timestamps of interrupts into per-#acs("CPU") rings and
  post-processes them with a #ac("DRBG").

- The lighter columns #ac("IRQ") #ac("eBPF") and Sched #ac("eBPF") refer to the
  #acs("eBPF")-based interrupt and scheduler entropy sources that collect the
  same event timing on a Linux kernel without patches: #ac("eBPF") programs
  record the time between successive context switches or interrupts, which the
  #ac("ESDM") conditions with an XDRBG-256 pool of its own.

#par(first-line-indent: 0pt)[The #ac("ESDM") expects its external entropy
sources to be fully self-contained. It only requests data from them and expects
the entropy estimate provided with the data to be correct. The external entropy
sources are:]

- The auxiliary pool collects data from external entropy sources that deliver
  data at times the #ac("ESDM") cannot control.

- The #ac("CPU") entropy source obtains data from a source in the #ac("CPU"), if
  present, such as RDSEED on Intel #ac("CPU", pl: true).

- The Jitter #acs("RNG") entropy source is another external entropy source,
  provided by the Jitter #acs("RNG") library in user space and by the Jitter
  #acs("RNG") of the Linux kernel crypto #ac("API").

- A compile-time option turns the random number generator behind the
  `getrandom` system call into an entropy source.

- The Linux hardware random number generator (`/dev/hwrng`) serves as a seed
  source. It may obtain data from various hardware sources, including a
  #ac("TPM") 2.0.

- The random number generator of a #ac("TPM") 2.0, accessed via its resource
  manager device.

- An external entropy source developed outside of the #ac("ESDM") and served by
  a process of its own over a Unix domain socket – such as `esdm-es-pkcs11`,
  which serves the random number generator of a #acs("PKCS")\#11 token.

#par(first-line-indent: 0pt)[The #ac("ESDM") requests data from all external and
internal entropy sources in the same way and concatenates it; sections
@sec:dp-seed-buffer and @sec:seed-levels name the exceptions. It handles
situations in which one or more entropy
sources return little or no entropy.]

Chapter @sec:kernel-es-assessment provides the complete entropy assessment of
the interrupt and the scheduler entropy sources of the kernel module, chapter
@sec:ebpf-assessment that of the #ac("eBPF") entropy sources. The #ac("ESDM")
expects all other
entropy sources to provide their own entropy assessment, which supports the
entropy the #ac("ESDM") credits for them. The #ac("ESDM") treats these
additional entropy sources as black boxes and takes their claimed entropy rate
at face value. The #ac("ESDM") processes the data of all entropy sources as
specified in section @sec:data-processing, which follows #ac("SP") 800-90C
for the concatenation and the conditioning.

The #ac("ESDM") offers various interfaces to obtain random numbers, shown in
figure @fig:interfaces.

#figure(
  image("../figures/interfaces.svg", width: 95%),
  caption: [#ac("ESDM", cap: true) Interfaces To Obtain Random Numbers],
) <fig:interfaces>

Figure @fig:interfaces shows the Linux #ac("RNG") interfaces on the left and the
additional ones on the right. Compile-time options enable or disable each type
of interface selectively; the #ac("EGD") interface is enabled at runtime instead
(section @sec:usage-egd). The types of interfaces are:

- Linux #ac("RNG") interfaces: The common interfaces of today's Linux kernels
  include `/dev/random`, `/dev/urandom`, the `getrandom` system call and the
  `getentropy` C-library wrapper. These interfaces behave identically to the
  Linux #ac("RNG"), so the #ac("ESDM") can act as a drop-in replacement: the
  #ac("CUSE") daemons bind-mount their device files over `/dev/random` and
  `/dev/urandom`, and `libesdm-getrandom.so` replaces `getrandom` and
  `getentropy` in the processes that load it, so the #ac("ESDM") serves
  unmodified software. When those are not compiled (meson options
  `linux-devfiles` and `linux-getrandom`), the #ac("ESDM") operates in parallel
  with the Linux #ac("RNG"): it serves only software that uses the interfaces
  below, and all other software keeps using the Linux #ac("RNG").

- The #ac("ESDM") also exports a set of Unix domain sockets to `/run`.
  Applications can use them directly, but this is not advised: the protocol of
  those sockets is not stable and can change from one version to another. These
  are the #ac("RPC") sockets `esdm-rpc-unpriv.socket` and
  `esdm-rpc-priv.socket`. The meson options `esdm-server-rpc-path-unprivileged`
  and `esdm-server-rpc-path-privileged` configure their directories.

- The #ac("ESDM") #ac("RPC") library wraps these Unix domain sockets and offers
  a stable #ac("API").

- The #ac("ESDM") server optionally serves the protocol of the #ac("EGD") on the
  sockets `esdm-egd.socket` and `esdm-egd-pr.socket` (section @sec:egd). The
  protocol is minimal – a one-byte command, a one-byte length – so its parser
  in the server is small and its attack surface low. The client library `libesdm_egd_client`, the OpenSSL RAND
  providers based on it and the kernel module `esdm_cdev` use this interface.
  It is enabled with the options
  `--egd_socket` and `--egd_socket_pr` of the #ac("ESDM") server or with its
  systemd socket units.

- OpenSSL 3 RAND providers route the random number requests of OpenSSL to the
  #ac("ESDM"), either over the #ac("RPC") interface or over the #ac("EGD")
  interface.

- The #ac("ESDM") library provides the core of the #ac("ESDM") functionality. A
  calling application could use it directly. Yet, the #ac("RPC") interface is
  the advised choice, as a daemon that already uses the #ac("ESDM") library
  provides it.

#par(first-line-indent: 0pt)[The #ac("ESDM") consists of these components:]

- `libesdm.so`: This library holds the core of the #ac("ESDM"). It implements
  the #ac("DRNG") and entropy source managers together with all entropy sources
  and cryptographic algorithms. The `esdm-server` listed below wraps this
  library. `esdm.h` exports and documents its #ac("API").

  The library serves users who want to employ the #ac("ESDM") in their own
  projects instead of the `esdm-server`. Yet, the intended common use is the
  `esdm-server`, a daemon that wraps the #ac("ESDM") library.

  In addition, the consuming application can configure the #ac("ESDM") with the
  options specified in `esdm_config.h`. Users of the tools below can ignore
  this library.

- `esdm-server`: The #ac("ESDM") server provides the #ac("RPC") server that
  encapsulates the #ac("ESDM") with its random number generator and the entropy
  source management. On startup, the server creates the Unix domain sockets
  mentioned above, which allow clients to request services including random
  numbers.

  The server must be started as root. It isolates itself into new mount,
  cgroup and network namespaces, initializes the #ac("ESDM") – including the
  entropy sources requiring privileges, e.g. it loads the #ac("eBPF") programs –
  and its status shared memory segment, creates its sockets and then permanently
  drops its privileges to an unprivileged user (option `--username`, `nobody` by
  default; the attacker model of section @sec:attacker-model requires a user
  that nothing else uses).

  Start the #ac("ESDM") server either manually or with the provided (and
  installed) systemd unit file. With systemd, run `systemctl start esdm-server`.

  The wrapper library `libesdm_rpc_client.so` accesses the #ac("RPC") interface
  of the #ac("ESDM") server. `esdm_rpc_client.h` specifies and documents its
  #ac("API").

  The `esdm-server` is the backend of all #ac("ESDM") components listed below.

  Note: The Unix domain sockets of the `esdm-server` are only visible in their
  mount namespace. If its services are required in multiple mount namespaces,
  start the daemon in each mount namespace or make the files available
  otherwise.

- `esdm-cuse-random`: The #ac("ESDM") #ac("CUSE") daemon creates a device file
  that behaves identically to `/dev/random`. It must be started as root. It
  implements reading, writing and #ac("IOCTL", pl: true) in an
  #acs("ABI")-compatible way.

  Start the #ac("ESDM") #ac("CUSE") daemon either manually or with the provided
  (and installed) systemd unit file. With systemd, run
  `systemctl start esdm-cuse-random`. Although the daemon creates a
  `/dev/random` device, the visible operation is atomic (a bind mount) for both
  the creation and the destruction of the new device file. Therefore, the
  daemon can be started and stopped at any time while the Linux #ac("OS") runs.

  Note: The bind mount is only visible in its mount namespace. If the services
  of these daemons are required in multiple mount namespaces, start the daemons
  in each mount namespace or make the files available otherwise.

- `esdm-cuse-urandom`: The same as `esdm-cuse-random`, but it behaves like
  `/dev/urandom`.

- `esdm-proc`: This #ac("FUSE") file system implements all files found on a
  Linux system under `/proc/sys/kernel/random` but points them to the
  #ac("ESDM") server: `boot_id`, `uuid`, `entropy_avail`, `poolsize`,
  `write_wakeup_threshold`, `urandom_min_reseed_secs` and, in addition,
  `esdm_type`, which provides the status of the #ac("ESDM"). The #ac("ESDM")
  needs this process to provide all interfaces. For details about the files, see
  the `random(4)` man page. The kernel also exports the
  `/proc/sys/kernel/random` information as `sysctl(8)`; `esdm-proc` does not
  cover this interface.

- `libesdm-getrandom.so`: The library provides a wrapper to the `getrandom`
  and `getentropy` Linux C-library calls. To use the library for other
  consumers, choose one of these options:

  - Use `LD_PRELOAD="/path/to/libesdm-getrandom.so"` with the intended
    application.

  - Add the library to `/etc/ld.so.preload` for a system-wide replacement.

  - Compile the application or library with these options:

    - `LDFLAGS += -Wl,--wrap=getrandom,--wrap=getentropy`
    - `LDFLAGS += -lesdm-getrandom`

  Process 1 and processes embedding `libesdm.so`, such as the `esdm-server`,
  use the `getrandom` system call of the kernel.

- `esdm-kernel-seeder`: The daemon draws random data from the #ac("ESDM") server
  and inserts it into the Linux kernel #ac("RNG") periodically – required when
  the interrupt entropy source of the kernel module deprives the kernel
  #ac("RNG") of its interrupt entropy.

- `esdm-tool`: The tool interacts with the #ac("ESDM") server: it shows the
  status of the #ac("ESDM"), obtains random numbers, triggers the self tests,
  runs performance and stress tests and creates the reference values of the
  #ac("FIPS") integrity test. The systemd unit
  `esdm-wait-until-fully-seeded.service` is built on it.

- `esdm-server-signal-helper`: The tool notifies the #ac("ESDM") server about
  the suspend and the resume of the system.

- `libesdm_aux_client.so`: The library allows an external entropy provider to
  wait until the #ac("ESDM") server needs entropy for its auxiliary pool
  (`esdm_aux_client.h`).

- `libesdm_egd_client.so`: A client library for the #ac("EGD") interface of the
  #ac("ESDM") server (`esdm_egd_client.h`).

- OpenSSL providers: `libesdm-rng-provider.so`, `libesdm-rng-provider-pr.so`
  and `libesdm-seed-src-provider.so` use the #ac("RPC") interface,
  `libesdm-egd-provider.so` and `libesdm-egd-provider-pr.so` the #ac("EGD")
  interface.

- `libesdm_es_ext.so`: The library that external entropy sources are developed
  against (`esdm_es_ext.h`), see section @sec:ext-es. `esdm-es-pkcs11` and
  `esdm-es-pcsc` are providers based on it.

- `esdm-getrawentropy`, `esdm-ebpf-collect` and `esdm-extractlsb`: Tools to
  obtain and process the raw noise data of the entropy sources of the kernel
  module and of the #acs("eBPF")-based entropy sources for their entropy
  assessment, see section @sec:test-interfaces.

- `esdm_es` (`kernel/esdm_es`): The kernel module providing the interrupt and
  the scheduler entropy sources, see sections @sec:irq-processing and
  @sec:sched-events.

- `esdm_cdev` (`kernel/esdm_cdev`): A kernel module serving the random
  numbers of the #ac("ESDM") through the character devices `/dev/esdm_random`,
  `/dev/esdm_urandom` and `/dev/esdm_pr` and the directory `/proc/esdm` – the
  counterpart of
  the #ac("CUSE") daemons in the kernel, which leaves the kernel's own devices
  untouched. It obtains its data from the #ac("ESDM") over the #ac("EGD")
  interface, see section @sec:egd.

== Attacker Model and Non-Goals <sec:attacker-model>

The #ac("ESDM") protects three assets:

/ State: the internal states of the #ac("DRNG") instances, of the auxiliary
  and conditioning pools and of the entropy sources, including the seed
  buffers – confidentiality and integrity.
/ Output: the random numbers delivered to a consumer – unpredictability to
  everybody but that consumer.
/ Availability: random numbers for the consumers that wait for them, and no
  output before the #ac("ESDM") is operational.

#par(first-line-indent: 0pt)[The #ac("ESDM") trusts the kernel, the hardware,
the hypervisor, root, the crypto backend, the systemd configuration and the
provider of an external entropy source once accepted (section @sec:ext-es).
Table @tab:attackers lists the attackers within the scope of the design, their
capabilities and the countermeasures.]

#figure(
  table(columns: (1fr, 1.3fr, 1.7fr), align: left + horizon,
    table.header([Attacker], [Capabilities], [Countermeasures]),
    [Unprivileged local user], [Connects to the unprivileged #ac("RPC") and
      #ac("EGD") sockets, requests random numbers at any rate, writes data,
      reads the status, runs code on the same #ac("CPU", pl: true)],
      [Privileged operations only for #ac("UID") 0 by `SO_PEERCRED`; data of
      other users credited with no entropy; the server runs without
      privileges in namespaces of its own (section @sec:isolation); no
      internal state on any interface; one prediction resistance request at a
      time, the server never waiting within a request (section @sec:rpc)],
    [Attacker who learned the state of a #ac("DRNG")], [Knows the state at
      one point in time, e.g. through a memory disclosure], [Backtracking
      resistance of the #ac("DRNG", pl: true) (section @sec:crypto); reseeds
      after $2^20$ requests, 600 seconds or a bit threshold (section
      @sec:seeding-triggers); a reseed before every output block on the prediction
      resistance path; secrets wiped after use (section @sec:secrets)],
    [Attacker who influences entropy sources], [Predicts or controls some
      noise sources, e.g. interrupts through network traffic, or degrades a
      timer], [Health tests on the raw data (section @sec:health-tests);
      conservative entropy rates, e.g. 8 of 256 bits for the #ac("CPU")\;
      the data of all entropy sources concatenated and conditioned together,
      so that the data of one entropy source cannot cancel the entropy of
      another],
    [Malicious client], [Sends malformed or oversized requests], [Bounded,
      fuzzed parsers; a malformed request closes its connection (sections
      @sec:rpc and @sec:bounded-input)],
    [Stalling device], [A #ac("TPM"), `/dev/hwrng` or a provider that blocks],
      [A deadline of 2 seconds per read; the entropy source is skipped until
      a probe succeeds (section @sec:seeding-slow)],
    [Local user forcing the fallback], [Opens connections to the
      unprivileged #ac("RPC") socket, which every user may use, until the
      requests of other clients time out], [None in the interfaces that fall
      back: the #ac("CUSE") daemons and `libesdm-getrandom.so` then serve the
      kernel #ac("RNG") (see below). The #ac("RPC") and #ac("EGD") client
      libraries, the OpenSSL providers and `esdm_cdev` report an error
      instead],
  ),
  caption: [Attackers within the scope of the design],
) <tab:attackers>

#par(first-line-indent: 0pt)[These are explicit non-goals of the design:]

- Attackers with the privileges of root, of the user the #ac("ESDM") runs as,
  or of the kernel or the hypervisor: they read the state or replace the code.
  This non-goal covers every process of the user the daemons drop to. With
  the default user `nobody`, these are processes the operator does not
  associate with the #ac("ESDM"), as other software runs as `nobody` too: such
  a process can signal the daemons, access the semaphores and the shared
  memory segment they synchronize with and, where the kernel permits it, trace
  them. The attacker model therefore holds only for an installation that runs
  the daemons as a user that nothing else uses (option `--username`, section
  @sec:usage-hardening); the default configuration does not meet it.

- Physical attacks – fault injection, power and electromagnetic analysis – and
  timing side channels beyond the properties of the crypto backend.

- The quality of a noise source beyond its assessment: the #ac("ESDM") cannot
  verify the claim of a vendor, and the entropy rate credited is a decision of
  the integrator (chapter @sec:configurations).

- Network attackers: the #ac("ESDM") offers no network interface; all its
  sockets are local.

- Availability under an overload by local users beyond the limits above.

- The random numbers after their delivery, and the output of the kernel
  #ac("RNG") that the #ac("CUSE") daemons and `libesdm-getrandom.so` serve
  while the #ac("ESDM") cannot be reached (table @tab:interfaces).

#paragraph[Fallback to the kernel][The drop-in interfaces fail open. The
#ac("CUSE") daemons serve the kernel device on every error of a request but
`EAGAIN` – the server unreachable, a timeout, a failed self test, for
`/dev/urandom` also an #ac("ESDM") that is not operational – and
`libesdm-getrandom.so` calls the kernel on every error but `EAGAIN` with
`GRND_NONBLOCK`; a seed request (`GRND_SEED`) never reaches the kernel. This
keeps a system running whose #ac("ESDM") stopped, which is the purpose of a
replacement of `/dev/random`. The price is that a consumer of these
interfaces cannot tell the generators apart, and that the downgrade can be
provoked: the unprivileged socket is open to every user (mode 0666), the
server limits the connections per worker (1024) but not per user, closes only idle connections, and a client
whose connection attempts time out falls back. A local user who keeps enough
connections busy can therefore move the consumers of the drop-in interfaces to the
kernel #ac("RNG"). The fallback is not visible by default: the #ac("CUSE")
daemons log it at a verbosity above the one of their units, and the shim logs
nothing (section @sec:usage-monitoring). No option of a production build
disables it – `--disable_fallback` of the #ac("CUSE") daemons exists in test
mode builds only. A consumer that must not receive output of the kernel
#ac("RNG") uses an interface without fallback: the #ac("RPC") or the
#ac("EGD") client library, an OpenSSL provider or `esdm_cdev` (section
@sec:limits).]

#paragraph[Entropy consumption by unprivileged users][Two calls that every
local user may make consume entropy of the entropy sources instead of
#ac("DRNG") output: the seed call (`RpcGetSeed`, `GRND_SEED`) and the
prediction resistance path, which reseeds before every output block. The #ac("ESDM")
limits neither per user. A user who calls them in a loop empties the slow
entropy sources – the rings of the kernel module, the auxiliary pool, the
#ac("eBPF") pools – as fast as they fill, and occupies the collectors of the
fast ones. The effects are bounded: other callers of the same two
paths receive less than they ask for or wait; the reseeds of the #ac("DRNG")
instances that fall due find too little entropy and are repeated with the
current time only, until entropy is available again or the limits of section
@sec:architecture stop the instance. Requests on the ordinary paths are
served throughout, from #ac("DRNG") instances that were fully seeded before.
An on-demand entropy source such as the Jitter #acs("RNG") limits the
starvation to the time its collectors are busy. The design has no analysis of
how long an attacker can keep every instance from its reseed, and no quota;
where untrusted local users exist, this is a residual risk for the
prediction resistance and seed paths (non-goal “availability under an
overload”).]

== Security Domains <sec:security-domains>

The #ac("ESDM") is not one program but several, which run with different
rights and hold different data. Table @tab:domains lists the security
domains – the units that have an address space and a set of privileges of
their own – with what each holds and how it is separated from the others;
figure @fig:server-startup of section @sec:isolation shows how the server
enters its domain. Each domain has an identifier for reference.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.55fr, 1fr, 1.25fr, 1.5fr), align: left + top,
    table.header([Domain], [Runs as], [Holds], [Separated by]),
    [D-KERNEL], [The kernel: the modules `esdm_es` and `esdm_cdev`, the
      #ac("eBPF") programs], [The timestamps in the per-#acs("CPU") rings,
      the #ac("DRBG") of the kernel module; `esdm_cdev` holds connections,
      no generator state], [The user and kernel boundary. `/dev/esdm_es` is
      opened with `CAP_SYS_ADMIN` only; the #ac("eBPF") programs pass the
      verifier of the kernel and are loaded by the server before it drops
      its privileges],
    [D-SERVER], [`esdm-server` after its start-up: an unprivileged user, in
      mount, cgroup and network namespaces of its own, optionally in a
      #ac("PID") namespace, under the systemd sandbox], [Every #ac("DRNG")
      state, the auxiliary and conditioning pools, the seed buffers: all
      secrets of the #ac("ESDM") in user space], [Its address space, locked
      in memory and kept out of core dumps (section @sec:secrets). The
      permanent privilege drop, the namespaces and the sandbox of the unit
      (sections @sec:isolation and @sec:systemd-sandbox). Nothing but the
      interfaces below leads into it],
    [D-SUPERVISOR], [The parent of the server with `--pid_namespace`:
      root, outside the #ac("PID") namespace], [Nothing of the generator. It
      forwards signals and removes the #ac("IPC") objects at the end], [A
      process of its own; its only channels to the server are signals, the
      exit status and a pipe that carries no data and tells the server of
      the end of the supervisor, on which the server shuts down],
    [D-FRONTEND], [The #ac("CUSE") daemons and `esdm-proc`: started as
      root, running with dropped privileges that they take back for single
      device operations. `esdm-kernel-seeder`: root with the one capability
      it needs to credit the kernel #ac("RNG")], [Random numbers in transit to their caller; no generator
      state], [Processes of their own, each under a unit with a capability
      bounding set. They reach the server over the #ac("RPC") sockets like
      any client and over the status segment],
    [D-PROVIDER], [A provider of an external entropy source, e.g.
      `esdm-es-pkcs11` as a system user of its own], [Its noise source or
      token session, e.g. a #ac("PIN")], [A process of its own. The server
      connects to its socket and accepts it only as root or as the
      configured user (`SO_PEERCRED`, `es_ext_peer_uid`). It sends data and
      an entropy claim to the server and receives nothing from it],
    [D-CLIENT], [A consumer: any local process, with the client libraries,
      the OpenSSL providers or `libesdm-getrandom.so` in its address
      space], [The random numbers delivered to it], [The process boundary.
      The unprivileged socket (mode 0666) offers output, status and
      uncredited writes; whatever a client sends, it receives no state],
    [D-ADMIN], [A process of root], [Nothing of the generator], [The
      privileged socket (mode 0600) and, on every privileged call, the check
      that the peer is root (`SO_PEERCRED`): crediting entropy, clearing the
      pool, forcing a reseed, changing thresholds, running the self tests; in
      test mode and debug builds also setting entropy rates],
  )
}
, caption: [Security domains of the #ac("ESDM")]) <tab:domains>

#paragraph[What crosses a boundary][Secrets exist in D-KERNEL and D-SERVER
only. From D-KERNEL to D-SERVER flow conditioned seed blocks with their
entropy and the event counts of section @sec:vm-clone, over
#ac("IOCTL", pl: true) on a descriptor the server opened as root. From
D-PROVIDER to D-SERVER flows data with an entropy claim, capped by the
configured rate. From D-SERVER to D-CLIENT and D-FRONTEND flows output of
the #ac("DRNG", pl: true) or seed data, never state, and the status: over
the sockets, and through the status shared memory segment, which the server
owns and others can read but not write (mode 0644), and which carries the
operational state and the need for entropy, no secret. From D-CLIENT to
D-SERVER flow requests and data that is mixed in without credit; from
D-ADMIN the privileged calls. The domains D-FRONTEND and D-CLIENT need not
be trusted for the confidentiality of the state: a compromised frontend
serves wrong output to its own callers, but learns nothing of the server.]

#paragraph[What is not separated][Within D-SERVER there is one address
space: the entropy source manager, the #ac("DRNG") manager, the #ac("RPC")
and the #ac("EGD") server and the crypto backend are not isolated from each
other, so a memory error in a parser reaches the #ac("DRNG") states. The
defenses against it are those of chapter @sec:hardening, not a boundary.
Processes of the user the server drops to belong to its domain for the
purposes of section @sec:attacker-model. A process that embeds
`libesdm.so` instead of using the server has no D-SERVER at all: the
generator shares the domain of the application.]

== Design Rationale and Alternatives <sec:rationale>

The #ac("ESDM") is not the only way to obtain well-seeded random numbers on
Linux. This section names the alternatives and what decides between them.

#figure(
  table(columns: (1fr, 1.5fr, 1.5fr), align: left + top,
    table.header([Alternative], [What it offers], [What the #ac("ESDM") adds,
      and at what cost]),
    [The kernel #ac("RNG") alone, with `getrandom(2)` and its #ac("vDSO")
      implementation], [Present on every system, fast – the #ac("vDSO")
      variant generates in the process without a system call –, well
      reviewed], [Selectable entropy sources with an entropy rate each, a
      status that names them, #ac("DRNG", pl: true) and conditioning from
      approved algorithms, #ac("SP") 800-90C and #ac("AIS") 20/31
      configurations, a prediction resistance path. Cost: a request is a
      round trip to another process (section @sec:usage-performance)],
    [An in-kernel replacement, the #ac("LRNG")], [The same concepts as the
      #ac("ESDM"), which descends from it, at the speed of the kernel
      interfaces and for every consumer, static binaries and early boot
      included], [No patched kernel for the core: the #ac("LRNG") is not part
      of the mainline kernel. The #ac("ESDM") runs unprivileged after its
      start-up, uses the crypto backend of the system and is updated like
      any daemon. Cost: the drop-in interfaces need daemons of their own and
      do not reach consumers that bypass them],
    [The kernel #ac("RNG") plus a Jitter #acs("RNG") in each application],
      [No daemon; each application seeds its own #ac("DRBG")], [One place
      where entropy is accounted, configured, health-tested and reported,
      instead of one per application; entropy sources an application cannot
      reach (kernel module, #ac("TPM"), smart card). Cost: a dependency on a
      running service],
  ),
  caption: [Alternatives to the #ac("ESDM")],
) <tab:alternatives>

#paragraph[A process of its own][The generator runs in a server process and
is reached through a socket. The boundary keeps the #ac("DRNG") states and
the seed material out of the address space of every consumer: a memory
disclosure in a consumer does not reveal them, and one implementation,
configured and audited once, serves all consumers. The boundary costs a round
trip per request, which section @sec:usage-performance quantifies, and it
makes the server a single point of failure, which the drop-in interfaces
answer with the fallback of section @sec:attacker-model.]

#paragraph[Several DRNG instances][Behind the boundary, requests are served
from one #ac("DRNG") instance per #ac("CPU") up to the number of workers
(section @sec:numa), each with a lock of its own. Parallel requests thus do
not wait for one lock, and the reseed of one instance does not hold up the
others. The cost is entropy: every instance needs its own seed, so a system
with slow entropy sources takes longer until all instances are fully seeded,
and serves from the initial instance until then.]

#paragraph[User space instead of the kernel][Entropy management needs kernel
privileges only where it observes the kernel: the interrupt and scheduler
hooks. Everything else – conditioning, the #ac("DRNG", pl: true), the
seeding strategy, the interfaces – runs without privileges, can use a
validated crypto library and can be replaced without a reboot. The price is
paid at the edges: no service before the server runs, i.e. not in early boot,
and none for programs that call the kernel directly.]

== ESDM Components <sec:components>

Figure @fig:big-picture shows these components of the #ac("ESDM"):

+ The #ac("ESDM") implements a #ac("DRNG"). Unless the caller uses the interface
  providing prediction resistance, the amount of output does not depend on
  the entropy available at the time of the request: an operational
  #ac("ESDM") serves the request from a seeded #ac("DRNG") instance. Only
  `esdm_get_random_bytes_full` completes every request; the non-waiting
  functions may return fewer bytes than requested, or `-EAGAIN` while the
  #ac("DRNG") instances wait for their reseed. In #ac("SP") 800-90A
  @sp80090a terminology, the #ac("DRNG")
  operates without prediction resistance. The #ac("DRNG") maintains a counter of
  the generate operations since the last reseed, a counter of the bits generated
  since the last reseed with full entropy and a timer of the time elapsed since
  the last reseed. If a counter or the timer reaches a threshold, the
  #ac("ESDM") seeds the #ac("DRNG") from the entropy sources with the available
  entropy.

  The #ac("ESDM") maintains one #ac("DRNG") instance per #ac("CPU") as discussed
  in section @sec:numa.

  Depending on the interface the caller uses to request data from the
  #ac("DRNG"), the #ac("ESDM") may put the caller to sleep until it is fully
  seeded:

  + All interfaces using the `esdm_get_random_bytes` function generate data
    without waiting – but only once the #ac("ESDM") is operational, i.e. its
    initial #ac("DRNG") instance is fully seeded and its cryptographic self
    tests passed. Otherwise, the function returns an error.

  + All interfaces using the `esdm_get_random_bytes_full` function generate
    data under the same condition, but wait until the #ac("ESDM") is
    operational instead of returning an error, and continue until the request
    is complete. After a failed self test, the function returns an error. The
    function `esdm_get_random_bytes_full_noblock` returns `-EAGAIN` instead
    of waiting.

  + The `esdm_get_random_bytes_pr` function uses the special #ac("DRNG")
    instance that operates with prediction resistance: the #ac("ESDM") reseeds
    it from the entropy sources, and it generates at most as much data as
    entropy was added. Thus, the #ac("DRNG") operates with prediction resistance
    (#ac("SP") 800-90A terminology). In addition, when the #ac("ESDM") executes
    in #ac("FIPS") mode, the behavior complies with all #ac("FIPS")
    requirements, so the output of the #ac("API") can be claimed to come from a
    vetted conditioning component. That is, the caller may safely use this data
    to seed another #ac("DRBG"). To achieve this, the functions `esdm_drng_get`
    and `esdm_get_random_bytes_pr` apply these checks:

    - Require a reseed before every output block – the reseed only commences
      when at least 256 bits of entropy are available in the entropy sources
      of the #ac("ESDM").

    - Produce at most 256 random bits from the #ac("DRNG") (i.e. the security
      strength of the #ac("DRNG")) per reseed, and at most the entropy the
      reseed injected. With the #ac("SP") 800-90C oversampling in effect, a
      reseed requests 64 bits of entropy in addition (#ac("SP") 800-90C section
      6.5.2 requirement 1, RBG3(RS)), and the output is at most the injected
      entropy less these 64 bits.

    - Serve only one prediction resistance request at a time – the #ac("ESDM")
      answers a concurrent request with `-EAGAIN`.

    As the function may thus generate less data than requested, the caller
    must be prepared to receive no data at all. The function
    `esdm_get_random_bytes_pr_noblock` returns `-EAGAIN` instead of waiting
    for the #ac("ESDM") to become operational and instead of returning no data.

+ The #ac("ESDM") seeds the #ac("DRNG") with the concatenated data of these
  sources, if they are enabled at compile time, in this order (`esdm_es` in
  `esdm/esdm_es_mgr.c`):

  + the output of the interrupt entropy source of the kernel module,
  + the output of the scheduler entropy source of the kernel module,
  + the output of the #acs("eBPF")-based interrupt entropy source,
  + the output of the #acs("eBPF")-based scheduler entropy source,
  + the Jitter #acs("RNG") if available,
  + the #acs("CPU")-based entropy source such as Intel RDSEED if available,
  + the kernel #ac("RNG") output,
  + the Linux kernel #ac("HWRAND") framework (`/dev/hwrng`),
  + the #ac("TPM") 2.0,
  + the Jitter #acs("RNG") of the Linux kernel crypto #ac("API"),
  + the external entropy source served by a provider over a Unix domain
    socket, and
  + the output of the auxiliary pool.

  The #ac("ESDM") adds the entropy estimates of the data of all entropy sources
  to form the entropy estimate of the seed data. However, the #ac("ESDM")
  ensures that the entropy credited to the #ac("DRNG") after seeding is at most
  the security strength of the #ac("DRNG") implementation in use, 256 bits. The
  data of an entropy
  source configured with an entropy rate of zero, or not able to deliver any
  entropy at the time, is not part of the seed: the #ac("ESDM") hands it to the
  #ac("DRNG") as additional input (#ac("SP") 800-90C section 2.6 item 2), see
  section @sec:dp-seed-buffer. The data of the #acs("eBPF")-based entropy
  sources is part of the seed once their #ac("eBPF") programs are loaded,
  whatever their entropy rate.

  By design, none of these entropy sources can dominate the others in
  providing seed data to the #ac("DRNG"), because:

  + During boot time, the amount of available entropy triggers the (re)seed
    of the #ac("DRNG"), as the next section explains.

  + At runtime, either the #ac("DRNG"), when it hits the thresholds above, or a
    user space caller triggers the reseed. The entropy sources do not trigger
    the reseed of a fully seeded #ac("DRNG").

+ To support backward secrecy, the #ac("ESDM") applies these steps:

  + The auxiliary pool and the conditioning pools of the #ac("eBPF") entropy
    sources are each an XDRBG-256: an extraction reseeds the #ac("XDRBG") and
    generates its output together with its new state, so that the output never
    reveals the state of the pool.

  + The kernel module post-processes the recorded timestamps of the
    scheduler and interrupt entropy sources with a #ac("DRBG") – an XDRBG-256 as
    well, or the HMAC_DRBG of the kernel crypto #ac("API") on kernels without
    the SHA-3 library – whose state update provides backtracking resistance.

#par(first-line-indent: 0pt)[The crypto backend, selected at compile time from
those listed in section @sec:backends, determines the #ac("DRNG") mechanism and
the hash. By default, an #ac("SP") 800-90A Hash #ac("DRBG") implementation along
with a SHA-512 hash implementation is available. Both are C implementations
without external dependencies, verified with known-answer tests (section
@sec:self-tests).]

The next subsections cover the components of the #ac("ESDM") from the bottom to
the top.

== Subsystems and Modules <sec:decomposition>

For the reader who needs the structure rather than the behavior, table
@tab:subsystems decomposes the #ac("ESDM") into subsystems and table
@tab:modules the core subsystem into modules. Each has an identifier, the
code it consists of, the security domain it runs in (section
@sec:security-domains) and the section that describes it. Chapter
@sec:interface-spec enumerates the external interfaces; the interfaces
between the subsystems are the ones the last column names. Figure
@fig:subsystems shows the subsystems where they run with these interfaces,
figure @fig:core-modules the modules of the core subsystem with the main
calls between them. In both figures an arrow points from the caller or client
to what it uses; a dashed arrow stands for shared memory or an event that is
read, not for a call.

#figure(
  image("../figures/subsystems.svg", width: 92%),
  caption: [The subsystems of the #ac("ESDM") and the interfaces between
    them],
) <fig:subsystems>

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.6fr, 1.2fr, 0.9fr, 0.55fr, 1.3fr), align: left + top,
    table.header([Subsystem], [Purpose], [Code], [Domain], [Interfaces to
      other subsystems; described in]),
    [SS-CORE], [The generator: entropy source manager, #ac("DRNG") manager,
      configuration, status, self tests], [`esdm/`], [D-SERVER],
      [`esdm.h` to SS-RPC, SS-EGD and SS-SERVER; the callbacks
      `struct esdm_es_cb` to SS-ES and `struct esdm_drng_cb`,
      `struct esdm_hash_cb` to SS-CRYPTO. Sections @sec:architecture,
      @sec:seeding, @sec:es-manager, @sec:drng-manager],
    [SS-ES], [The entropy sources: one module per source], [`esdm/esdm_es_*.c`,
      `esdm/es_cpu/`, `esdm/es_ebpf/`], [D-SERVER], [Called by SS-CORE
      through `struct esdm_es_cb`; #ac("IOCTL", pl: true) to SS-KMOD-ES,
      system calls and devices of the kernel, the socket of SS-ESEXT.
      Sections @sec:irq-processing to @sec:ext-es],
    [SS-CRYPTO], [#ac("DRNG"), hash and #ac("XOF") implementations: builtin
      or a crypto library], [`esdm/esdm_builtin_*.c`, `esdm/esdm_openssl.c`
      and the other backends, `crypto/`], [D-SERVER], [Called by SS-CORE
      through the crypto callbacks. Section @sec:crypto],
    [SS-RPC], [The #ac("RPC") protocol: server in `esdm-server`, client
      library], [`service-rpc/`], [D-SERVER; client part in D-CLIENT,
      D-FRONTEND, D-ADMIN], [Calls SS-CORE through `esdm.h`; the two Unix
      domain sockets. Section @sec:rpc],
    [SS-EGD], [The #ac("EGD") protocol: server in `esdm-server`, client
      library], [`service-egd/`], [D-SERVER; client part in D-CLIENT,
      D-KERNEL (`esdm_cdev`)], [Calls SS-CORE through `esdm.h`; the
      #ac("EGD") sockets. Section @sec:egd],
    [SS-SERVER], [The process around the generator: start-up, namespaces,
      privilege drop, supervisor, signals], [`frontends/server/`,
      `common/linux_support.c`], [D-SERVER, D-SUPERVISOR], [Starts SS-CORE,
      SS-RPC and SS-EGD. Sections @sec:isolation and @sec:fv-supervisor],
    [SS-FRONTEND], [The Linux interfaces and tools: #ac("CUSE") daemons,
      `esdm-proc`, `libesdm-getrandom.so`, OpenSSL providers, kernel seeder,
      auxiliary client, `esdm-tool`, signal helper], [`frontends/`],
      [D-FRONTEND, D-CLIENT, D-ADMIN], [Clients of SS-RPC and SS-EGD;
      readers of the status segment of SS-CORE. Section @sec:interfaces,
      chapter @sec:tools],
    [SS-ESEXT], [External entropy sources: the provider library, the
      #acs("PKCS")\#11 and #ac("PC/SC") providers], [`es-ext/`],
      [D-PROVIDER], [The provider socket, read by SS-ES. Section
      @sec:ext-es],
    [SS-KMOD-ES], [The kernel module `esdm_es`: interrupt and scheduler
      entropy sources, system events], [`kernel/esdm_es/`,
      `kernel/shared/`], [D-KERNEL], [`/dev/esdm_es` to SS-ES and SS-CORE.
      Sections @sec:irq-processing, @sec:sched-events, @sec:vm-clone],
    [SS-KMOD-CDEV], [The kernel module `esdm_cdev`: character devices
      served from the #ac("ESDM")], [`kernel/esdm_cdev/`], [D-KERNEL],
      [Client of SS-EGD. Section @sec:egd],
    [SS-COMMON], [Shared support: logging, threads, locks, buffers, the
      #ac("FIPS") integrity test], [`common/`], [Every domain in user
      space], [Linked into the other subsystems. Chapter @sec:hardening],
  )
}
, caption: [Subsystems of the #ac("ESDM")]) <tab:subsystems>

#figure(
  image("../figures/core-modules.svg", width: 100%),
  caption: [The modules of the core subsystem SS-CORE and the main calls
    between them],
) <fig:core-modules>

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.6fr, 1fr, 1.6fr, 1fr), align: left + top,
    table.header([Module], [Code], [Purpose], [Described in]),
    [M-LIB], [`esdm/esdm_lib.c`], [Initialization, re-initialization and
      finalization of the library; starts the worker threads], [Section
      @sec:architecture],
    [M-ESMGR], [`esdm/esdm_es_mgr.c`], [Entropy source manager: the list of
      entropy sources, the seed buffers, the fully seeded and operational
      state, the monitor thread], [Sections @sec:seeding, @sec:es-manager],
    [M-DRNGMGR], [`esdm/esdm_drng_mgr.c`], [#ac("DRNG") manager: the
      instances, seeding and reseeding, the reseed worker, the output
      functions, the fork handler], [Sections @sec:seeding,
      @sec:drng-manager, @sec:state-machines],
    [M-NODE], [`esdm/esdm_node.c`], [The #ac("DRNG") instances per node],
      [Section @sec:numa],
    [M-AUX], [`esdm/esdm_es_aux.c`], [The auxiliary pools and the calls that
      write into them], [Section @sec:aux],
    [M-CONFIG], [`esdm/esdm_config.c`], [Entropy rates, limits and switches,
      with the rules between the entropy rates], [Section @sec:es-overview],
    [M-INFO], [`esdm/esdm_info.c`], [The status as #ac("JSON") and text],
      [Section @sec:status],
    [M-SELFTEST], [`esdm/esdm_selftest.c`, `esdm/fips.c`], [Self tests of
      the primitives and entropy sources, the verdict that gates the output,
      the integrity test], [Section @sec:self-tests],
    [M-SHM], [`esdm/esdm_shm_status.c`], [The status shared memory segment
      and its semaphores], [Sections @sec:status, @sec:fv-shm-status],
    [M-EVENTS], [`esdm/esdm_es_events.c`], [System events of the kernel
      module], [Section @sec:vm-clone],
  )
}
, caption: [Modules of the core subsystem SS-CORE]) <tab:modules>

== ESDM Data Processing <sec:data-processing>

The #ac("ESDM") processes the entropic data of the different entropy sources
with these mathematical operations before injecting it into the #ac("DRNG"). The
operation
$"SHA"()$ refers to the hash operation using the message digest implementation
that is currently present, i.e. SHA-512 or SHA3-512 depending on the crypto
backend (see section @sec:backends). The operation $"SHAKE256"(x, l)$ refers
to the extendable output function SHAKE256 of the crypto backend returning $l$
bits of output for the input $x$. The operation $"XDRBG.Extract"$ refers to
the extraction of an XDRBG-256 pool specified in section @sec:dp-aux. The
operations $"DRBG.Seed"$ and $"DRBG.Generate"$ refer to the #ac("DRBG") of the kernel
module `esdm_es`.

=== Scheduler and Interrupt Entropy Sources <sec:dp-sched-irq>

+ Timestamp: The #ac("IRQ") and the scheduler entropy sources of the kernel
  module obtain their timestamps with `random_get_entropy` and divide them by
  the #ac("GCD"). The kernel module calculates the #ac("GCD") from the first 100
  timestamps after loading the module or after a reset of the entropy source
  and fixes it thereafter. Thus, the timestamp divided by the #ac("GCD") is the
  raw entropy value $t$, a 64-bit integer. Until the #ac("GCD") is calculated,
  the timestamp is used undivided. The function `esdm_time_process` implements
  this step.

+ Health test: Each timestamp is subject to the health tests of section
  @sec:health-tests. Only timestamps passing them are recorded.

+ Concatenation: The #ac("IRQ") and scheduler entropy sources concatenate the
  received timestamps in a per-#acs("CPU") ring of 4,096 slots, which holds up
  to 4,095 timestamps#footnote[The size of the ring derives from the
  compile-time configurable oversampling rate `ESDM_ES_OSR` of the kernel
  module, which defaults to 3: the ring has the smallest of 4,096, 8,192,
  16,384 and 32,768 slots that holds the timestamps of the largest request.
  It always holds one timestamp less than it has slots. However, this
  modification has no impact on the illustration of the data processing.].
  When the ring is full, they drop newly received timestamps. The function
  `esdm_es_ring_add` implements this step:

  $ "CP"_"CPU" = t_(n-k) || t_(n-k+1) || ... || t_(n-1) || t_n $ <eq:cp>

=== Interrupt Entropy Source <sec:dp-irq>

+ #ac("DRBG", cap: true) seeding: When the #ac("ESDM") requests data from the
  interrupt entropy source, the kernel module collects the timestamps needed
  for one output block of the size of the security strength $s = 256$ bits of
  the #ac("DRBG") from the per-#acs("CPU") rings of all #ac("CPU", pl: true). It
  hands them to its #ac("DRBG") as seed. These are $ceil((s + o) dot r \/ 256)$
  timestamps, where $r$ is the number of timestamps credited with 256 bits of entropy ($256 dot "ESDM_ES_OSR"$ by
  default) and $o$ the oversampling. When the kernel is built with
  `CONFIG_CRYPTO_FIPS` and booted with `fips=1`, $o$ is the #ac("SP") 800-90C
  oversampling of 64 bits (128 bits for the instantiation of the #ac("DRBG"), as
  for the initial seed of 384 bits) plus one bit, so that the #ac("DRBG") state
  holds full entropy after its update: 65 bits (129 bits); otherwise, $o$ is 0.
  If the rings hold fewer timestamps, the kernel module generates no data
  and the timestamps remain in the rings. The first seed instantiates the
  #ac("DRBG"), all later ones reseed it. The function
  `esdm_es_drbg_pool_extract_block` implements this step:

  $ "EP"_n = "DRBG.Seed"("EP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
    || "CP"_("CPUX")) $ <eq:ep-cpu>

  The #ac("DRBG") is the XDRBG-256 of section @sec:xdrbg, which the kernel
  module compiles from `esdm/crypto/esdm_xdrbg.c`, over the SHAKE256 of the
  SHA-3 library of the kernel (`CONFIG_CRYPTO_LIB_SHA3`). From Linux 7.2 on,
  the module requires this library. On an older kernel without it, the
  #ac("DRBG") is the HMAC_DRBG
  with SHA-512 of the kernel crypto #ac("API").

+ Generation: The #ac("DRBG") generates one output block with the additional
  input
  "ESDM_IRQ_DRBG" for domain separation, which is also its personalization
  string:

  $ B_n = "DRBG.Generate"("EP"_n, s, "\"ESDM_IRQ_DRBG\"") $ <eq:ep-all>

+ Concatenation: The #ac("DRBG") generates as many blocks as needed for the
  number of bits $b$ the #ac("ESDM") requests (256, 320 or 384 bits), each with
  a seed of its own. The kernel module only delivers the data if the rings hold
  the timestamps of all blocks; the data is then credited with $b$ bits of
  entropy. The function `esdm_es_drbg_pool_extract` implements this step:

  $ E_n = "MSB"_b (B_(n,1) || ... || B_(n, ceil(b \/ s))) $ <eq:e>

=== Scheduler Entropy Source <sec:dp-sched>

The scheduler entropy source applies the same processing as the interrupt
entropy source, with per-#acs("CPU") rings and a #ac("DRBG") instance of its
own, and with
the additional input "ESDM_SCH_DRBG":

$ "SP"_n = "DRBG.Seed"("SP"_(n-1), "CP"_("CPU0") || "CP"_("CPU1") || ...
  || "CP"_("CPUX")) $ <eq:sp-cpu>

$ B_n = "DRBG.Generate"("SP"_n, s, "\"ESDM_SCH_DRBG\"") $ <eq:sp-all>

$ S_n = "MSB"_b (B_(n,1) || ... || B_(n, ceil(b \/ s))) $ <eq:s>

The kernel module performs this operation in process context when the
#ac("ESDM") requests random data from the entropy source.

=== eBPF-based Scheduler and Interrupt Entropy Sources <sec:dp-ebpf>

+ Time delta: The #ac("eBPF") programs obtain the timestamp of an event with
  `bpf_ktime_get_ns` and divide it by the #ac("GCD") of the first 100 timestamps of the #ac("CPU"). The timestamp is subject to the health tests of
  section @sec:health-tests. For each timestamp passing them, the programs
  record the difference to the preceding passing timestamp of the same
  #ac("CPU"), a 64-bit integer $d$.

+ Concatenation: The #ac("eBPF") programs concatenate the deltas in a
  per-#acs("CPU") batch of 64 deltas. They hand the batch to a #ac("BPF") ring
  buffer when it is full, or when no delta was collected for 250 ms.

+ Insertion: The #ac("ESDM") reads the batches from the ring buffer and inserts
  the
  deltas into the XDRBG-256 conditioning pool $"XP"$ of the entropy source as
  seed data of its next reseed. The functions `esdm_ebpf_consume` and
  `esdm_xdrbg_insert` implement this step.

+ Extraction: The #ac("ESDM") extracts the pool as specified for the auxiliary
  pool
  in section @sec:dp-aux, with the additional input $alpha$ = "ESDM eBPF pool"
  followed by the name of the entropy source. The function `esdm_ebpf_get_ent`
  implements this step:

  $ E^"eBPF"_n = "XDRBG.Extract"("XP", d_(m-k) || ... || d_m, alpha) $
  <eq:ebpf>

=== Auxiliary Entropy Pool <sec:dp-aux>

The auxiliary pool $"AP"$ is an XDRBG-256 – the #ac("XDRBG") over SHAKE256 @xdrbg
with a state $V$ of 512 bits – implemented in `esdm/crypto/esdm_xdrbg.c`. The
meson option `num-aux-pools` configures the number of auxiliary pools (one by
default). Each pool uses the additional input $alpha$ = "ESDM aux pool"
followed by the index of the pool in two bytes, which separates the pools.

+ Insertion: When new data $D_m$ is added to the auxiliary pool $"AP"$, the
  SHAKE256 context of the pool absorbs the data, and the data becomes part of
  the seed of its next reseed. The functions `esdm_pool_insert_aux` and
  `esdm_xdrbg_insert` implement this step. The #ac("ESDM") inserts data without
  entropy into all pools, and data with entropy into one pool: the first one
  with room for its entropy, else the one with the most room.

+ Reseed: When the #ac("ESDM") requests entropy from the auxiliary pool, it
  reseeds the #ac("XDRBG") with the data inserted since the last extraction,
  where
  $"encode"(alpha, n) = alpha || (85 n + |alpha|)$ appends one byte to $alpha$
  and $V'_(n-1)$ is the state left by the previous extraction:

  $ V_n = "SHAKE256"(V'_(n-1) || D_(m-k) || ... || D_m || "encode"(alpha, 1),
    512) $ <eq:ap>

  The first extraction instantiates the #ac("XDRBG") with

  $ V_1 = "SHAKE256"(D_1 || ... || D_m || "encode"(alpha, 0), 512) $

+ Generation: The #ac("XDRBG") generates the output $A_n$ of the size the
  #ac("DRNG") requests – at most the seed size of 256 or 384 bits – together
  with the new state $V'_n$, which starts the SHAKE256 context of the pool for
  the next reseed. The function `esdm_xdrbg_extract` implements this step:

  $ V'_n || A_n = "SHAKE256"(V_n || "encode"(alpha, 2), 512 + |A_n|) $ <eq:a>

#par(first-line-indent: 0pt)[The reseed and the generation together form the
operation]

$ A_n = "XDRBG.Extract"("AP", D_(m-k) || ... || D_m, alpha) $

=== CPU Entropy Source <sec:dp-cpu>

Two independent values govern the #ac("CPU") entropy source (section
@sec:cpu):

- The data multiplier $m$ is a property of the #ac("CPU") instruction: by its
  documentation, $m$ data bits carry at least one bit of entropy. It is 1 for
  RDSEED, RNDRRS and PRNO, 2 for DARN and the seed #ac("CSR") of RISC-V, and
  2,048 for RDRAND, whose output comes from a #ac("DRBG") that reseeds at the
  latest after 512 blocks of 128 bits. The meson option `es_cpu_multiplier`
  sets a lower bound.

- The entropy rate $r_C$ is the entropy the #ac("ESDM") credits to 256 bits of
  output (meson option `es_cpu_entropy_rate`, 8 by default). The claim of the
  vendor behind $m$ cannot be verified, so the #ac("ESDM") believes only a
  fraction of it (section @sec:cpu-entropy).

#par(first-line-indent: 0pt)[For a request of $b$ bits, $b$ capped at the
digest size of the hash, the #ac("ESDM") processes the data in these steps
(`esdm_cpu_get` with `esdm_get_cpu_data` and, for $m > 1$,
`esdm_get_cpu_data_compress` in `esdm/esdm_es_cpu.c`):]

+ Collection: With $m = 1$, the #ac("ESDM") reads $b$ bits and uses them as
  they are, $C_n = C_1$. With $m > 1$, it reads $m dot b$ bits – with the
  #ac("SP") 800-90C oversampling $m dot (b + 64)$ bits – in blocks
  $C_1, ..., C_k$ of $b$ bits, the last one shorter. The oversampling scales
  with $m$ because it counts entropy, not data: the hash needs 64 bits of
  entropy more than it outputs (#ac("SP") 800-90C section 3.2.2.2), and 64 bits
  of entropy take $64 dot m$ data bits.

+ Hashing ($m > 1$):

  $ C_"cond" = "SHA"(C_1 || ... || C_k) $ <eq:c-cond>

+ Truncation ($m > 1$):

  $ C_n = "MSB"_b (C_"cond") $ <eq:c>

+ Crediting: whatever $m$ is, the #ac("ESDM") credits $C_n$ with

  $ h_C = min(r_C dot b \/ 256, b) $ <eq:h-c>

  bits of entropy. Only $r_C = 256$ claims full entropy, and only for it are
  the 64 bits of oversampling required; with the default $r_C = 8$ they add
  margin.

#par(first-line-indent: 0pt)[For example, RDRAND with $b = 256$ and the
oversampling: the #ac("ESDM") reads $2048 dot 320$ bits, i.e. 80 KiB, hashes
them, keeps 256 bits and credits them with $min(8 dot 256 \/ 256, 256) = 8$
bits.]

=== Temporary Seed Buffer Construction <sec:dp-seed-buffer>

+ Concatenation: The temporary seed buffer $T$ used to seed the #ac("DRNG") at
  the time $n$ is a concatenation of one or more of these entropy source data
  sets, depending on the compile-time configuration, each one held in a slot
  of its own together with its entropy estimate:

  + the interrupt entropy source buffer $E$,
  + the scheduler entropy source buffer $S$,
  + the #acs("eBPF")-based interrupt entropy source buffer $E^"eBPF"$,
  + the #acs("eBPF")-based scheduler entropy source buffer $S^"eBPF"$,
  + the Jitter #acs("RNG") output $J$,
  + the #ac("CPU") entropy source output $C$,
  + the kernel #ac("RNG") entropy source output $K$,
  + the Linux #ac("HWRAND") framework $H$,
  + the #ac("TPM") 2.0 output $M$,
  + the output of the Jitter #acs("RNG") of the kernel crypto #ac("API") $J^"K"$,
  + the output of the external entropy source $X$,
  + the auxiliary pool entropy source $A$, and
  + the current time $t$ (`CLOCK_MONOTONIC`).

  The function `esdm_get_seed_buffers` implements this step:

  $ T_n = E_n || S_n || E^"eBPF"_n || S^"eBPF"_n || J_n || C_n || K_n || H_n
    || M_n || J^"K"_n || X_n || A_n || t $ <eq:t>

+ Separation: The #ac("ESDM") places the data of an entropy source other than an
  #acs("eBPF")-based one that is configured with an entropy rate of zero, or not
  able to deliver any entropy at the time, in the slot of a second buffer of the
  same layout, the additional input $U_n$. It leaves the slot of that entropy
  source in $T_n$ empty. The function `esdm_es_seed_slot` implements this
  step. The #ac("ESDM") seeds the #ac("DRNG") with $T_n$ as seed and $U_n$ as
  additional input.

  The separation follows #ac("SP") 800-90C section 2.6: only validated entropy
  sources seed the #ac("DRBG"), and the #ac("ESDM") takes an entropy source
  credited with no entropy for a non-validated one. The #acs("eBPF")-based
  entropy sources are the exception: a loaded #ac("eBPF") entropy source
  reports its pool size as the maximum entropy whatever its entropy rate
  (`esdm_ebpf_max_entropy`), so its data stays in $T_n$ even with the default
  rate of zero, credited with no entropy. The code gives no reason for this
  difference. It does not change the entropy accounting, as the data is
  credited with zero bits, but it places the data of an entropy source that
  is treated as non-validated into the seed. An #ac("SP") 800-90C
  configuration therefore either credits the #ac("eBPF") entropy source after
  its assessment or leaves it out of the build (section @sec:90c-config).

== ESDM Architecture <sec:architecture>

Before the details of the #ac("ESDM") processing, this section outlines the
concept underlying the #ac("ESDM") shown in figure @fig:big-picture.

The slow entropy sources collect and accumulate their entropy in the
per-#acs("CPU") rings of the kernel module, which hold uncompressed, only
concatenated entropy data, in the conditioning pools of the #ac("eBPF") entropy
sources and in the auxiliary pool.

When the #ac("DRNG") is to be seeded, the #ac("ESDM") requests data from all
entropy sources – in parallel threads with the meson option `es_parallel_fetch`,
which is enabled by default. The kernel module post-processes the recorded
timestamps with its #ac("DRBG"), and the #ac("ESDM") extracts the XDRBG-256
pools.

The entropy sources generate data of the size the caller requests and credit
it with at most the available entropy. The auxiliary pool always returns the
requested size of data, irrespective of its entropy rate. Thus, data that is
injected into the #ac("ESDM") without entropy credit also stirs the seed for the
#ac("DRNG").

The #ac("DRNG") always tries to seed itself with 256 bits of entropy, or 384
bits for the initial seeding with the #ac("SP") 800-90C oversampling in effect.
If the entropy sources cannot deliver that amount, the #ac("DRNG") uses the
available entropy and keeps track of how much entropy it was seeded with. During
boot, the #ac("ESDM") reseeds the #ac("DRNG") from the entropy sources if all
entropy sources collectively have at least 256 bits of entropy available (384
bits with the #ac("SP") 800-90C oversampling in effect). The initialization of
the #ac("ESDM") performs a forced seeding right away, of the initial
#ac("DRNG") instance first and of the further instances as long as the
entropy sources deliver (`esdm_force_fully_seeded_all_drbgs`).

#par(first-line-indent: 0pt)[The #ac("ESDM") additionally implements a forced
seeding operation, also called emergency reseeding. The #ac("ESDM") performs it for
every seeding of a #ac("DRNG") that is not fully seeded, for the reseed of a
#ac("DRNG") that reached its maximum output without a full reseed, and for a
reseed requested with `esdm_drng_force_reseed`. The forced
seeding continuously reseeds the #ac("DRNG") with existing entropy in one atomic
operation. That is, the #ac("ESDM") triggers a regular reseed as often as needed
to obtain 256 bits of entropy and reach the fully seeded level, and it adds up
the entropy obtained from the entropy sources. This is permissible because the
#ac("DRNG") produces no output between these reseeds: a #ac("DRNG") being
brought up stays locked throughout, and one that reached its maximum output
is locked for each injection and serves no request until the seeding is
complete. The repetition stops as soon as no entropy source delivers entropy
anymore (fewer than two for the initial seeding with the NTG.1 seeding
strategy, unless the Jitter #acs("RNG") operates in its own NTG.1 mode). The
function `esdm_drng_seed_es` implements this. A reseed of a fully seeded
#ac("DRNG") collects the entropy without holding the lock of the #ac("DRNG"),
which keeps serving requests meanwhile, and locks it only to inject the seed
(`esdm_drng_reseed_seed_locked`). Figure @fig:seeding illustrates the seeding
operation of a #ac("DRNG").]

#figure(
  image("../figures/drng-seeding.svg", width: 72%),
  caption: [#ac("DRNG", cap: true) Seeding Operation],
) <fig:seeding>

In each (re)seed, the #ac("DRNG") requests the full seed from all entropy
sources, and each entropy source credits its data with at most the entropy it
holds. Thus, a single seeding reaches the seeding level of 256 bits when the
entropy sources can deliver that much entropy; otherwise, the forced seeding
adds up the entropy of several seedings.

Before the initial #ac("DRNG") instance is fully seeded, the #ac("ESDM")
delivers no random data: the waiting interfaces wait, the others return an
error.

At runtime, the #ac("DRNG") operates as a deterministic random number generator
with these properties:

- One #ac("DRNG") generate operation produces at most 4096 bytes – $2^16$ bytes
  in a build that limits the output without a full reseed (see below). For
  longer random numbers, the #ac("ESDM") performs multiple #ac("DRNG") generate
  operations. The #ac("DRNG", pl: true) update their state during the generate
  operation for backward secrecy.

- The #ac("ESDM") reseeds the #ac("DRNG") from the entropy sources only if they
  collectively hold at least 256 bits of entropy, unless the reseed is forced
  (section @sec:seeding). Otherwise, it reseeds the #ac("DRNG") with the current
  time only. The #ac("DRNG") continues its operation and tries to reseed again
  when one of these conditions is met again:

  - the last reseeding of the #ac("DRNG") is more than 600 seconds
    ago#footnote[In one test, this interval did not empty the rings of the
    interrupt entropy source on a quiet system: a #ac("KVM") guest without
    fast entropy sources and with a minimal user space, where only the
    #ac("SSH") daemon was running and no user performed any operation,
    collected more than 256 bits of entropy from the interrupt entropy source
    within that time frame, satisfying the #ac("DRNG") reseed requirement.] – a caller can set the interval at runtime to at most
    3600 seconds (`esdm_set_reseed_max_time`), where an interval of 0 seconds
    reseeds the #ac("DRNG") before every request – or

  - $2^20$ #ac("DRNG") generate operations are performed, whichever comes first,
    or

  - the number of bits generated since the last reseed with full entropy
    reaches the threshold of the meson option `drng_reseed_threshold_bits`
    (disabled by default; at most 98,304 bits in a build with the meson
    option `sp80090c`, `fips140` or `ais2031_drg4` and without
    `ais2031_drg3`), or

  - the #ac("DRNG") is forced to reseed before the next generation of random
    numbers with the `RNDRESEEDCRNG` #ac("IOCTL") or the matching #ac("RPC") and
    #ac("EGD") interfaces (`esdm_drng_force_reseed`).

  The chosen values prevent high-volume requests from user space from causing
  frequent reseeding operations that drag down the performance of the
  #ac("DRNG")#footnote[The maximum request size is 4096 bytes, defined by
  `ESDM_DRNG_MAX_REQSIZE` (i.e. the #ac("ESDM") segments each request into
  4096-byte chunks), and at most $2^20$ requests, defined by
  `ESDM_DRNG_RESEED_THRESH`, can be made before a forced reseed takes place.
  Thus, at most $4096 dot 2^20 = 4,294,967,296$ bytes can be obtained from
  the #ac("DRNG") without a reseed operation.].

- A reseed worker thread reseeds the per-#acs("CPU") #ac("DRNG") instances
  discussed in section @sec:numa ahead of the requests, so that a request does
  not wait for the collection of entropy: in each pass, the worker reseeds the
  #ac("DRNG") instances whose reseed is due and brings up the #ac("DRNG")
  instances that are not fully seeded, each seeding on a thread of its own, at
  most as many at once as there are Jitter #acs("RNG") collectors (section
  @sec:jent). The seed time of a per-#acs("CPU") #ac("DRNG") instance is pushed
  out by a random offset of up to a tenth of the reseed interval, so that the
  #ac("DRNG") instances do not all fall due at once. The worker sleeps until the
  next reseed falls due, at most 20 seconds. The function
  `esdm_drng_reseed_worker` implements it. Both the worker and a request reseed
  the initial #ac("DRNG") instance when its reseed is due. Only a request
  reseeds the prediction resistance #ac("DRNG") instance, for every output
  block.

- If the #ac("DRNG") was not reseeded with full entropy for the last $2^30$
  #ac("DRNG") generate operations – i.e. the reseeding requests discussed in the
  previous bullets were unsuccessful – the #ac("DRNG") reverts to an unseeded
  state and produces no random numbers. If it is the initial #ac("DRNG")
  instance, the #ac("ESDM") is no longer operational and behaves as during
  boot time, see section @sec:not-fully-seeded.

  This limit is loose. It is chosen for availability alone. A reseed
  with the current time adds no entropy: the seed buffers are empty but for
  the timestamp, and the #ac("DRNG") is not marked as reseeded with full
  entropy (`esdm_get_seed_buffers`, `esdm_drng_inject`). Between two reseeds
  with full entropy, a #ac("DRNG") of the default build can thus serve $2^30$
  generate operations of up to 4096 bytes, i.e. up to 4 TiB. During that
  time, its output rests on the 256 bits of its last full seed and on the
  backtracking resistance of the #ac("DRNG") alone: an attacker who learned
  the state in between predicts all output until the next full reseed, which
  the reseeds after $2^20$ operations or 600 seconds are meant to prevent and
  do prevent only while the entropy sources deliver. The default favors a
  system that keeps serving when its entropy sources stall over one that
  blocks its consumers. A system that has to bound the output per full seed
  builds with the meson option `sp80090c`, `fips140` or `ais2031_drg4`, which
  let a #ac("DRNG") start no further generate operation once it produced
  $2^17$ bits without a full reseed (next bullet), or
  sets `drng_max_reseed_bits` itself.

- If the number of bits generated since the last reseed with full entropy
  reaches the threshold of the meson option `drng_max_reseed_bits` (disabled
  by default; at most $2^17$ bits in a build with the meson option
  `sp80090c`, `fips140` or `ais2031_drg4` and without `ais2031_drg3`), the
  #ac("DRNG") starts no further generate operation until the reseed worker
  reseeds it with full entropy. The initial #ac("DRNG") instance, which already
  stops at the threshold of `drng_reseed_threshold_bits`, is also reseeded by
  the next request. Without a reseed worker, a per-#acs("CPU") #ac("DRNG")
  instance reverts to an unseeded state instead.

#par(first-line-indent: 0pt)[The reseed interval is measured with
`CLOCK_MONOTONIC_COARSE`, which does not advance while the system is
suspended: the time of a suspend does not count toward the 600 seconds.]

=== Fully Seeded Level <sec:seed-levels>

The #ac("ESDM") reseeds its #ac("DRNG") when it receives the first 256 bits of
entropy during boot, as indicated above. The #ac("DRNG") is “fully” seeded when
it reaches the 256-bit level, or 384 bits for the initial seeding with the
#ac("SP") 800-90C oversampling in effect. The function `esdm_fully_seeded`
implements this check. With the #ac("AIS") 20/31 NTG.1 seeding strategy (meson
option `ais2031_ntg1`), the initial seeding instead requires that two entropy
sources deliver at least 240 bits of entropy each, or that the Jitter
#acs("RNG"), operated in its own NTG.1 mode, alone delivers 240 bits of entropy.

The #ac("ESDM") is operational once its initial #ac("DRNG") instance is fully
seeded. It generates random numbers once the self tests of its cryptographic
primitives have passed as well. When the #ac("DRNG") reaches the fully seeded level, the #ac("ESDM") wakes up
the user-space callers waiting for a fully seeded #ac("DRNG") via the
`getrandom` system call or `/dev/random`. A caller of the #ac("ESDM")
#ac("API") function `esdm_get_random_bytes_full` waits synchronously until the
#ac("DRNG") reaches the fully seeded level.

=== DRNG Instances <sec:numa>

To prevent bottlenecks in large systems, the #ac("ESDM") instantiates the
#ac("DRNG") once for each #ac("CPU") (meson option `node`, enabled by default),
limited to the number of worker threads of the meson option
`threading_max_worker_threads` (64 by default), and at runtime with
`esdm_config_max_nodes_set` or the option `--small_memory` of the #ac("ESDM")
server, which uses one #ac("DRNG") instance. The #ac("DRNG") instance of node
zero is the initial #ac("DRNG") instance. The #ac("ESDM") instantiates all
#ac("DRNG", pl: true) at the same time when it initializes. Next to them, the
#ac("ESDM") maintains the #ac("DRNG") instance operated with prediction
resistance, which is seeded for every output block it generates.

The #ac("ESDM") seeds the different #ac("DRNG", pl: true) without reusing
entropy and without relying on random numbers from a not yet sufficiently seeded
#ac("ESDM"). It seeds the
#ac("DRNG", pl: true) starting with the one for node zero, using the approach
discussed above. Once the #ac("DRNG") for node zero is fully seeded, the
#ac("ESDM") seeds the #ac("DRNG") of node one when it again has 256 bits of
entropy available. Next, it seeds the #ac("DRNG") of node two after again
collecting 256 bits of entropy, and so on – with the reseed worker, several
#ac("DRNG") instances are brought up side by side, each from entropy collected
for it. Figure @fig:numa illustrates the seeding strategy: each #ac("DRNG")
instance is freshly seeded with a separate seed buffer.

#figure(
  image("../figures/numa-drng.svg", width: 90%),
  caption: [#ac("DRNG", cap: true) Instances with seeding strategy],
) <fig:numa>

When producing random numbers, the #ac("ESDM") tries to obtain the random
numbers from the #ac("DRNG") of the current #ac("CPU"): it probes the
#ac("DRNG") instances starting with that one, leaves out the instance of node
zero, skips the instances that are busy, not fully seeded or out of their
output budget, and uses the first one that is left. If none is found, or if
the chosen instance produces nothing, the #ac("DRNG") of node zero serves the
request. The function `esdm_drng_get_sleep_live` implements this. A worker
thread of the #ac("RPC") interfaces of the #ac("ESDM") server starts the probing
with a #ac("DRNG") instance of its own instead of the one of its #ac("CPU"):
worker $i$ with node $1 + (i mod (N - 1))$ for $N$ #ac("DRNG") instances
(`esdm_config_thread_node_set`).

=== Replaceable Components <sec:flexible-design>

Although the preceding sections suggest that the #ac("DRNG") and the management
logic are highly interrelated, the #ac("ESDM") code allows an easy replacement
of the #ac("DRNG") with another deterministic random number generator. This
design allowed the implementation of the ChaCha20 #ac("DRNG"), for when the
#ac("SP") 800-90A #ac("DRBG") is not desired, as well as of the different crypto
backends.

To implement another #ac("DRNG"), an integrator must implement all functions in
`struct esdm_drng_cb` in `esdm/esdm_crypto.h`. These functions cover the
allocation and deallocation of the #ac("DRNG") as well as its usage. Similarly,
the integrator must implement all functions in `struct esdm_hash_cb` from
`esdm/esdm_crypto.h` to provide the conditioning hash, and all functions in
`struct esdm_xof_cb` from `esdm/crypto/esdm_xof.h` to provide the SHAKE256 of
the XDRBG-256 pools.

The build selects the implementations at compile time. The default
implementation is the #ac("SP") 800-90A Hash-#acs("DRBG") using a software
implementation of the SHA-512 message digest, together with a software
implementation of SHAKE256 for the XDRBG-256 pools.

In addition, the #ac("ESDM") allows adding new entropy sources, also outside of
the #ac("ESDM") code as an external entropy source (section @sec:ext-es).

== ESDM Data Structures <sec:data-structures>

The #ac("ESDM") uses these main data structures:

- The interrupt and scheduler entropy sources of the kernel module record
  their data in per-#acs("CPU") rings. The rings are written lockless, since
  only a single writer uses the ring of the currently executing #ac("CPU"). The
  lock of the #ac("IOCTL") interface of the kernel module serializes the reading
  of the rings for seeding the #ac("DRBG") of the kernel module, while a spin
  lock that the writers do not use orders a reset of the rings against a reading
  of them. As the seed buffer is filled very infrequently (see above for the
  reseed periods of the #ac("DRNG")), the lock is hardly contended. Thus, the
  entropy collection operates quasi-lockless.

- The #ac("eBPF") entropy sources collect their data in per-#acs("CPU") maps of
  the #ac("eBPF") programs, which operate lockless. A lock of their own protects
  each of their conditioning pools and each of the auxiliary pools.

- The cryptographic algorithm data structures hold the reference to the
  #ac("DRNG") instance and the hash instance and associated metadata needed for
  its operation. A lock of its own guards the state of each #ac("DRNG")
  instance, and a second lock serializes its seedings, so that the entropy for
  one #ac("DRNG") is collected once. The seedings of different #ac("DRNG")
  instances run side by side, as the entropy sources lock themselves. A
  read-write lock guards the array of the per-#acs("CPU") #ac("DRNG") instances;
  it is only taken for writing to release the array during shutdown. The
  #ac("ESDM") does not replace the hash references at runtime, so it uses the
  hash without a lock: the caller keeps the hash state – on its stack for the
  built-in hash.

== Interrupt Processing – ESDM-internal Entropy Source <sec:irq-processing>

The kernel module `esdm_es` (`kernel/esdm_es`, built with `BUILD_ES_IRQ=1`,
which is the default of its Makefile) provides the interrupt entropy source.
With the kernel patch `0002-ESDM-interrupt-entropy-source-hooks`, the
#ac("ESDM") hooks a callback into the interrupt handler at the same location
where the kernel #ac("RNG") places its callback hook
(`add_interrupt_randomness`). While the callback is registered, the kernel
#ac("RNG") no longer receives the interrupt events. The #ac("ESDM") reads the
entropy source via the #ac("IOCTL", pl: true) of the device `/dev/esdm_es` of
the kernel module (`kernel/shared/esdm_es_ioctl.h`).

The #ac("ESDM") interrupt processing callback receives the number of the
interrupt from the interrupt handler, which it does not use. This callback is
the hot code path in the #ac("ESDM"), so it is kept as short as possible and
operates without locking.

Figure @fig:irq-processing illustrates the interrupt processing of the
#ac("ESDM"). The figure specifies which parts of the interrupt processing
execute in #ac("IRQ") context and which execute in process context. This section
lists all operations executed in interrupt context. Section @sec:seeding
illustrates all steps executed in process context.

The figure depicts the example of one interrupt arriving on #ac("CPU") 0. An
interrupt on another #ac("CPU") undergoes the same operation, but uses the
#acs("CPU")-local ring of that #ac("CPU"). Therefore, the same processing steps
fill the rings of the other #ac("CPU", pl: true) in the figure; the figure does
not show them.

#figure(
  image("../figures/irq-processing.svg", width: 100%),
  caption: [Interrupt Processing],
) <fig:irq-processing>

When an interrupt triggers the #ac("ESDM"), these steps are executed:

+ The callback obtains a high-resolution timestamp with the kernel service
  function `random_get_entropy`. It divides this integer value by a #ac("GCD")
  to eliminate bits that do not change. The #ac("GCD") is calculated from the
  first 100 timestamps; a #ac("GCD") of 1,000 or more indicates a timer too
  coarse to deliver entropy and stops the crediting of entropy. Until the
  #ac("GCD") is calculated, the callback processes the undivided timestamp. The
  entropy lies in the variations of the time of events and in their time delta
  variations.

+ The callback runs the health tests discussed in section @sec:health-tests
  on each received timestamp and drops a timestamp that does not pass them.

+ The callback stores the timestamp as a 64-bit value in the operating
  #acs("CPU")'s ring. When the ring is full, it drops the timestamp.

+ When the #ac("ESDM") asks how much entropy the entropy source holds, the
  kernel module translates the number of timestamps recorded in the rings of
  all #ac("CPU", pl: true) into an entropy statement.

+ When the #ac("ESDM") requests data from the interrupt entropy source with the
  `ESDM_IRQ_ENT_BUF_IOCTL` #ac("IOCTL"), the kernel module post-processes the recorded
  timestamps with its #ac("DRBG"), as specified in section @sec:dp-irq and
  depicted in figure @fig:collection-pool. This happens in process context.

  #figure(
    image("../figures/collection-pool-processing.svg", width: 70%),
    caption: [Kernel Entropy Source Data Extraction],
  ) <fig:collection-pool>

+ The #ac("ESDM") server implements a monitor thread that polls the interrupt
  #ac("ES") for its entropy level about every 0.54 seconds ($2^29$ ns,
  `ESDM_ES_MONITOR_INTERVAL_NS`) until all
  #ac("DRNG", pl: true) become fully seeded. While the poll monitor is active,
  every time the interrupt #ac("ES") entropy level reaches the entropy rate
  configured for the interrupt #ac("ES") (the meson option
  `es_irq_entropy_rate`, 256 bits by default), the monitor triggers a reseed as
  discussed in section @sec:seeding.

+ If all #ac("DRNG") instances are fully seeded, the poll monitor stops polling
  the interrupt #ac("ES"). Thus, the monitor triggers the reseed of the previous
  step only while a #ac("DRNG") instance is not fully seeded: during boot, and
  again after an instance left the fully seeded state (section
  @sec:not-fully-seeded). The entropy sources do not trigger the reseed of a
  fully seeded #ac("DRNG").

#par(first-line-indent: 0pt)[The entropy collection mechanism is available
immediately after the kernel #ac("RNG") has reached full entropy. This ensures
that the kernel #ac("RNG") is fully seeded before the #ac("ESDM") takes over its
main entropy source. To prevent starving the kernel #ac("RNG"), the
`esdm-kernel-seeder` reseeds the kernel #ac("RNG") periodically with 512 bits of
data obtained from the #ac("ESDM") server, every 120 seconds by default (meson
option `linux-reseed-interval`, the systemd unit of the daemon sets 10 seconds),
credited with the entropy of the meson option `linux-reseed-entropy-count` (0 by
default).]

If the underlying system does not support a high-resolution timestamp, the
kernel module refuses to load.

=== Entropy Amount of Interrupts <sec:entropy-interrupts>

The discussion of the entropy content of scheduling events in section
@sec:entropy-sched-events applies to the interrupt-based entropy. The only
difference is the use of the compile-time entropy value of
`CONFIG_ESDM_IRQ_ENTROPY_RATE`, which is $256 dot "ESDM_ES_OSR"$ as well, and
the meson option `es_irq_entropy_rate` (256 bits by default).

=== Health Tests of the Interrupt Entropy Source <sec:irq-health-tests>

The kernel module applies the health tests documented in section
@sec:health-tests to the interrupt entropy source as well. The #ac("ESDM")
strictly separates the health tests of the interrupt and the scheduler entropy
sources. This separation applies to the #ac("SP") 800-90B health tests as well.

== Scheduler Events – ESDM-internal Entropy Source <sec:sched-events>

The kernel module `esdm_es` provides the scheduler entropy source as well,
built with `BUILD_ES_SCHED=1` (disabled by default in its Makefile). With the
kernel patch `0001-ESDM-scheduler-entropy-source-hooks`, the #ac("ESDM") hooks
into the scheduling operation of the Linux kernel that runs every time a task is
woken up (`ttwu_stat` called by `try_to_wake_up`). Figure
@fig:sched-processing depicts how the #ac("ESDM") handles a scheduling event.

#figure(
  image("../figures/sched-processing.svg", width: 100%),
  caption: [Scheduler-event Processing],
) <fig:sched-processing>

When a task is woken up, the kernel invokes the #ac("ESDM") callback. The
callback obtains a high-resolution timestamp and processes it like the timestamp of an interrupt, as outlined in figure @fig:sched-pool: it divides the
timestamp by the #ac("GCD"), subjects it to the health tests and stores it in
the #acs("CPU")-local ring. When the #acs("CPU")-local ring is full, it drops
the timestamp.

#figure(
  image("../figures/sched-pool-management.svg", width: 62%),
  caption: [Scheduler Event Recording],
) <fig:sched-pool>

When the #ac("DRNG") is to be (re)seeded, the #ac("DRBG") of the scheduler
entropy source post-processes the timestamps of the per-#acs("CPU") rings, as
specified in section @sec:dp-sched. Entropy that a request does not use remains in the
state of the #ac("DRBG") and in the rings. A comparison of the figures in this section with
section @sec:irq-processing shows that the scheduler #ac("ES") and the interrupt
#ac("ES") share the same data processing concepts.

The entire post-processing happens in process context. Therefore, the
#ac("DRBG") operation is not part of the scheduling operation.

The scheduler entropy source may relate to the #ac("IRQ") entropy source,
because an #ac("IRQ") may trigger a scheduler event (e.g. with the flag
`TIF_NEED_RESCHED`). Therefore, the #ac("ESDM") cannot use both entropy sources
at the same time and credit entropy to both. Using both is permissible, but only
one is credited with entropy.

=== Entropy Amount of Scheduling Events <sec:entropy-sched-events>

The kernel module assumes 1/`ESDM_ES_OSR` bits of entropy per timestamp
obtained for one scheduling event, i.e. one third of a bit with the default
oversampling rate of 3.

The compile-time parameter `CONFIG_ESDM_SCHED_ENTROPY_RATE` of the kernel
module specifies the number of scheduling events needed to obtain 256 bits of
entropy: $256 dot "ESDM_ES_OSR"$. The #ac("ESDM") asks the kernel module to credit
the rate of the meson option `es_sched_entropy_rate` (0 by default, i.e. the
scheduler entropy source receives no entropy credit unless configured), but
the kernel module never credits more entropy than its own rate.

The fast-moving least significant bits of a high-resolution timestamp
provide its entropy, as the quantitative measurements of interrupt and
scheduler timestamps in chapter @sec:kernel-es-assessment support. The
#ac("ESDM") records the entire 64-bit timestamp after its division by the
#ac("GCD") and leaves its compression to the #ac("DRBG") post-processing.

The Linux kernel allows unprivileged user space processes to monitor
scheduling events by reading the process listing with a certain degree of
accuracy. How precisely a local attacker observes or predicts the time of a
scheduling event bounds the entropy of its timestamp from above: with a
timestamp of nanosecond resolution and an attacker who knows the time of the
event to the microsecond, a factor of $2^10$ lies between the two, so that at
most 10 bits of the timestamp are unknown to this attacker. The microsecond
is an assumption for illustration, not a measured property of an attacker; a
more precise observer leaves fewer bits. The entropy credited does not rest on
this bound: the kernel module credits a third of a bit per timestamp, which
is justified by the measurements of chapter @sec:kernel-es-assessment and
stays below one bit, i.e. it holds as long as the attacker cannot predict the
timestamp to its last bit.

=== Health Tests of the Internal Entropy Sources <sec:health-tests>

The #ac("ESDM") implements these health tests:

- Stuck Test
- #ac("RCT", cap: true)
- #ac("APT", cap: true)

#par(first-line-indent: 0pt)[The next sections detail those tests. They are
implemented in `kernel/esdm_es/esdm_health.c` for the entropy sources of the
kernel module and in `esdm/es_ebpf/esdm_es_ebpf_health.bpf.h` for the
#ac("eBPF") entropy sources, both with the cut-off values of
`kernel/shared/esdm_health_cutoffs.h`. The kernel module runs the #ac("RCT") and
the #ac("APT") over the timestamps of all #ac("CPU", pl: true), while the
#ac("eBPF") entropy sources run every test, the startup test included, for each
#ac("CPU") on the timestamps of that #ac("CPU").]

The #ac("ESDM") performs these health tests only for the internal entropy
sources. They do not cover other entropy sources, such as the entropy sources
feeding the auxiliary pool, the Jitter #acs("RNG") or the #acs("CPU")-based
entropy sources: these are fully self-contained entropy sources, the #ac("ESDM")
has no access to their raw noise data, and it includes no model of them to
implement appropriate health tests. The #ac("ESDM") considers all of them
external entropy sources. Thus, the user must ensure either that those other
entropy sources implement all health tests as needed – the #ac("ESDM") operates
the Jitter #acs("RNG") with its health tests enforced (`JENT_FORCE_FIPS`) with
the #ac("SP") 800-90C oversampling in effect, in #ac("FIPS") mode or with the
NTG.1 seeding strategy – or that the #ac("ESDM") is configured to credit these
entropy sources with zero bits of entropy. These configuration options credit no
entropy to the other entropy sources:

- Sources feeding the auxiliary entropy pool: Invoke the interface functions
  that provide entropy data with the value 0 for the entropy rate.

- #acs("CPU")-based entropy source: `es_cpu_entropy_rate=0`

- Jitter #acs("RNG"): `es_jent_entropy_rate=0`

#par(first-line-indent: 0pt)[With these options, the #ac("ESDM") pulls random
data from the entropy sources, but credits it with no entropy.]

The kernel module performs the stuck test on every timestamp and drops stuck
timestamps. It performs the #ac("RCT"), the #ac("APT") and the #ac("SP")
800-90B startup test only when the kernel is booted with `fips=1`. The
#ac("eBPF") entropy sources perform their health tests only in #ac("FIPS") mode,
in #ac("SP") 800-90C mode or with the NTG.1 seeding strategy.

#paragraph[Default configuration][The default build credits the interrupt
entropy source of the kernel module with 256 bits (meson option
`es_irq_entropy_rate`), and a kernel booted without `fips=1` runs none of the
three #ac("SP") 800-90B tests on it. In this configuration, only the stuck
test, the check for a high-resolution timer at load time and the #ac("GCD")
analysis guard the raw data: a timer that degrades at runtime without
delivering identical or linearly spaced values goes unnoticed, and the
entropy stays credited. A system that credits the interrupt or the scheduler
entropy source and has to detect such a degradation boots with `fips=1`.]

In addition, the #ac("ESDM") credits the entropy sources only if it finds a
high-resolution timestamp. Systems with a low-resolution timestamp do not
deliver sufficient entropy for the interrupt entropy source, so the health
tests are not applicable either.

#paragraph[Stuck Test][The stuck test calculates the first, second and third
discrete derivatives of the timestamp to be recorded in the per-#acs("CPU")
ring. It considers the timestamp non-stuck only if all three values are
non-zero. The first derivative verifies that two successive timestamps are not
equal, i.e. not “stuck”. The second derivative verifies that two successive time
differences are not equal. The third derivative verifies that the time
differences do not change by the same amount twice in a row.]

The third derivative of the timestamp is relevant for this reason: the
entropy lies in the variations of the occurrence of the events, i.e. it is
mathematically present in the time differences of successive events. The
time difference, however, is already the first discrete derivative of time.
If the time difference delivers the actual entropy, the stuck test checks
that the time differences are not stuck, i.e. that the first derivative of
the time difference (or the second derivative of the absolute timestamp) is
not zero. In addition, the stuck test checks that the time differences do not
form a linear signal, i.e. do not grow or shrink by a constant step – that
is, that the second discrete derivative of the time difference (or the third
discrete derivative of the absolute timestamp) is not zero.

#paragraph[Repetition Count Test][The #ac("ESDM") uses an enhanced version of
the #ac("RCT") specified in #ac("SP") 800-90B @sp80090b section 4.4.1.
Instead of counting identical back-to-back values, the #ac("RCT") counts the
stuck values during the processing of received events. The recorded data is the
timestamp. As the stuck test compares two back-to-back timestamps by
computing the discrete derivatives of the timestamp, the #ac("RCT") only
checks whether the stuck test found the timestamp stuck. If so, it increments
the #ac("RCT") counter. Otherwise, it resets the #ac("RCT") counter to zero.]

The #ac("RCT") uses $alpha = 2^(-30)$, within the range of $2^(-40)$ to
$2^(-20)$ that #ac("SP") 800-90B @sp80090b section 4.3 recommends. With the
assumed entropy of
1/OSR bits per timestamp, the cut-off value is $30 dot "OSR"$ for an
intermittent failure and $60 dot "OSR"$ for a permanent failure.

During the counting operation, the #ac("ESDM") compares the #ac("RCT") counter
with the cut-off value. If the counter reaches it, the #ac("ESDM") triggers the
health test failure discussed below. The kernel module logs an error to the
kernel log that names the entropy source and tells a startup, a runtime and a
permanent failure apart, but not the test that failed; the #ac("eBPF")
entropy sources log the failing test (#ac("RCT") or #ac("APT")) to the log of
the #ac("ESDM") server.

This test is only applied and enforced in #ac("FIPS") mode (for the #ac("eBPF")
entropy sources also in #ac("SP") 800-90C mode or with the NTG.1 seeding
strategy).

#paragraph[Adaptive Proportion Test][In compliance with #ac("SP") 800-90B
@sp80090b section 4.4.2, the #ac("ESDM") implements the #ac("APT"). As the
entropy is present in the least significant bits of the timestamp, the
#ac("APT") covers only those bits: the four least significant bits.]

The #ac("APT") uses a window size of 512 timestamps. The cut-off value depends
on the assumed entropy of 1/OSR bits per timestamp: assuming that each
timestamp has (at least) one bit of entropy and the #ac("APT") input data is
non-binary, the cut-off value is C = 325 as defined in #ac("SP") 800-90B section
4.4.2 (355 for a permanent failure); with the default oversampling rate of 3
of the kernel module, it is 459 (479 for a permanent failure).

This test is only applied and enforced in #ac("FIPS") mode (for the #ac("eBPF")
entropy sources also in #ac("SP") 800-90C mode or with the NTG.1 seeding
strategy).

#paragraph[Runtime Health Test Failures][If the #ac("RCT") or the #ac("APT")
health test fails, whether during initialization or at runtime, these actions
occur:]

+ The entropy source invalidates the entropy it collected.

+ The entropy source starts the #ac("SP") 800-90B startup health test
  described below. From that point on,
  the entropy source has to observe new events and collect their entropy
  before it provides data.

#par(first-line-indent: 0pt)[On a permanent failure, the kernel module panics
the kernel if the module parameter `esdm_panic_on_permanent_health_failure`
is set. After a permanent failure, the #ac("ESDM") no longer credits an
#ac("eBPF") entropy source with entropy until it is reset, and its self test
fails.]

#paragraph[SP 800-90B Startup Tests][The startup test applies the health
tests above to the first 1,024 timestamps obtained from the events of the
entropy source. If the #ac("RCT") or the #ac("APT") identifies one error, the
entropy source invalidates the collected entropy and restarts the #ac("SP")
800-90B startup health test.]

Until the #ac("SP") 800-90B startup health test completes, the entropy source
delivers no data. All #ac("ESDM") random number output interfaces only generate
data once the #ac("ESDM") is operational, i.e. its initial #ac("DRNG") is fully
seeded (section @sec:seed-levels). Thus, none of them provides random numbers
before the #ac("DRNG") is seeded from entropy sources that completed their
#ac("SP") 800-90B startup test or from other entropy sources.

To summarize, these rules apply:

- Output interfaces covered by the health tests: they deliver data only
  under the rules above. They are #ac("DRNG") output, not #ac("SP") 800-90B
  entropy sources; table @tab:path-classes gives their #ac("SP") 800-90C
  classes.

  - `/dev/random`
  - `/dev/urandom`
  - `getrandom(2)` system call irrespective of `GRND_INSECURE`
  - `esdm_get_random_bytes_full` #ac("API") call
  - `esdm_get_random_bytes_pr` #ac("API") call
  - `esdm_get_random_bytes` #ac("API") call

- Output interfaces bypassing the health tests

  - the fallback of the #ac("CUSE") daemons and of `libesdm-getrandom.so` to the
    kernel #ac("RNG") while the #ac("ESDM") server cannot be reached or refuses
    a request, for `/dev/urandom` and `GRND_INSECURE` also while the #ac("ESDM")
    is not operational
  - `libesdm-getrandom.so` in #ac("PID") 1 and in a process running the
    #ac("ESDM") itself, which always use the kernel #ac("RNG")

== eBPF-based Entropy Sources – ESDM-internal Entropy Sources <sec:ebpf>

The #acs("eBPF")-based scheduler and interrupt entropy sources (meson options
`es_sched_ebpf` and `es_irq_ebpf`, disabled by default) collect the event
timing of the scheduler and the interrupt entropy sources on a Linux kernel
without kernel patches. They require libbpf 1.2 or later, and at runtime a
kernel with #ac("BTF") information (`/sys/kernel/btf/vmlinux`) and a
high-resolution clock – otherwise the entropy source is disabled. On a kernel
where the collected raw samples could not be erased again, the #ac("ESDM")
refuses to start. The #ac("ESDM") server loads the #ac("eBPF") programs during
its privileged initialization, which requires root or the capabilities `CAP_BPF`
and `CAP_PERFMON`. Figure @fig:ebpf illustrates their processing.

#figure(
  image("../figures/ebpf-processing.svg", width: 100%),
  caption: [#ac("eBPF", cap: true) Entropy Source Processing],
) <fig:ebpf>

+ The #ac("eBPF") programs are attached to the `tp_btf/sched_switch` and the
  `tp_btf/irq_handler_entry` tracepoints. They obtain the timestamp of the
  event, divide it by the #ac("GCD") of the time source and apply the health
  tests of section @sec:health-tests to it.

+ The #ac("eBPF") programs collect the difference of each passing timestamp
  to the preceding passing one of the same #ac("CPU") in a per-#acs("CPU")
  batch of 64 deltas. They hand the batch to a #ac("BPF") ring buffer when it is full, or
  when no delta was collected for 250 ms.

+ The #ac("ESDM") server reads the batches from the ring buffer and inserts them
  into the XDRBG-256 conditioning pool of the entropy source as specified in
  section @sec:dp-ebpf. It stops reading once that pool holds all the entropy
  one output block can carry; batches arriving at a full ring buffer are
  dropped.

+ An extraction reseeds the XDRBG-256 with the inserted deltas and generates
  the output block.

#par(first-line-indent: 0pt)[The entropy rate of the meson options
`es_sched_ebpf_entropy_rate` and `es_irq_ebpf_entropy_rate` (0 by default)
is applied to the 64 bits of each delta and capped at 1/OSR bits per
event with the oversampling rate of the meson options `es_sched_ebpf_osr` and
`es_irq_ebpf_osr` (1 by default), which also determines the cut-off values
of the health tests. The integrator must determine the rates with the
measurement tooling in `tests/es_ebpf_testing` before crediting the entropy
sources. Of these and the interrupt and scheduler entropy sources of the
kernel module, at most one is credited with entropy: the build refuses more
than one non-zero entropy rate, and a non-zero rate set at runtime zeroes the
others. When the entropy sources are unloaded, the #ac("ESDM") zeroizes every
collected raw sample – the per-#acs("CPU") state of the #ac("eBPF") programs and
the ring buffer included.]

== Auxiliary Entropy Pool – ESDM-external Entropy Sources <sec:aux>

The #ac("ESDM") also supports obtaining entropy from the data sources and
entropy sources external to the #ac("ESDM") that are described below. It injects
their data into the auxiliary pool.

During the reseeding operation of the #ac("DRNG"), the #ac("ESDM") triggers any
user-space entropy provider to provide data if the auxiliary pool holds less
entropy than the write wakeup threshold (`write_wakeup_threshold`, by default
the entropy all auxiliary pools can hold). It evaluates this need also after
data with entropy was inserted, after an insert that failed and discarded the
state of a pool, and when the threshold is changed. This applies to the providers waiting
via select(2) or poll(2) for `/dev/random` to become writable, or with the
function `esdm_aux_timedwait_for_need_entropy` of `libesdm_aux_client` for a
semaphore of the status shared memory segment of the #ac("ESDM") server. The
#ac("ESDM") mixes this data into the auxiliary pool. This approach lets the
#acs("ESDM")-external entropy sources provide entropy at least once per
#ac("DRNG") reseed operation.

=== Injecting Data From User Space <sec:aux-injecting>

User space can inject data into the #ac("DRNG") in these ways:

- When user space writes data into `/dev/random` or `/dev/urandom`, or uses the
  matching #ac("RPC") (`esdm_rpcc_write_data`) or #ac("EGD") interfaces, the
  #ac("ESDM") adds the data to the auxiliary pool. The #ac("ESDM") assumes it
  has zero bits of entropy.

- With the privileged #ac("IOCTL") `RNDADDENTROPY` on `/dev/random`,
  or the privileged #ac("RPC") #ac("API") call `esdm_rpcc_rnd_add_entropy`, the
  caller can inject entropic data into the auxiliary pool and define the
  amount of entropy associated with that data. The write command of the
  #ac("EGD") protocol carries an entropy claim as well, which is only honored
  for a caller with the user #ac("ID") 0. The #ac("IOCTL") and the #ac("RPC")
  call refuse a claim of more than 8 bits per byte of data, the former with
  `EINVAL`, the latter with `-EINVAL`.

=== Auxiliary Pool <sec:aux-pool>

The #ac("ESDM") maintains the auxiliary pool as a separate entropy source and
eventually concatenates it with all other entropy sources in compliance with
#ac("SP") 800-90C.

The auxiliary pool is an XDRBG-256 as specified in section @sec:dp-aux; the
crypto backend provides its SHAKE256. The #ac("ESDM") processes it in these
steps:

+ The #ac("ESDM") inserts data by absorbing it into the SHAKE256 context of the
  pool, where it becomes part of the seed of the next reseed of the
  #ac("XDRBG").

+ To extract entropy from the auxiliary pool, the #ac("ESDM") reseeds the
  #ac("XDRBG") – or instantiates it with the first extraction – with the
  inserted data. The #ac("XDRBG") generates the output together with the new
  state of the pool, which starts the SHAKE256 context again for the next
  insertions.

+ The #ac("XDRBG") generates the amount of data the #ac("DRNG") requests (e.g.
  either 256 or 384 bits) and returns it to the caller. The #ac("ESDM") does not
  truncate the auxiliary pool output to the amount of entropy the data contains,
  because the entropy provider may add data without entropy to the auxiliary
  pool, e.g. by writing to `/dev/random`. Thus, the auxiliary pool may
  contain zero bits of entropy, yet contain data that should “stir” the
  #ac("DRNG") state.

#par(first-line-indent: 0pt)[Figure @fig:aux-pool illustrates the auxiliary
pool operation for the case when user space inserts three separate buffers.]

#figure(
  image("../figures/aux-pool-processing.svg", width: 62%),
  caption: [Auxiliary Pool Processing],
) <fig:aux-pool>

In addition, the #ac("ESDM") maintains an entropy estimator that counts the
entropy the auxiliary pool receives. The entropy estimator is capped at the size
of the state of the #ac("XDRBG"), 512 bits, as the pool cannot hold more
entropy. With the #ac("SP") 800-90C oversampling in effect, the entropy
estimator credits 64 bits less than the pool holds unless the meson option
`aux-has-full-entropy` is enabled. With several auxiliary pools (meson option
`num-aux-pools`, 1 by default), the #ac("ESDM") takes the data of one extraction
from one pool: the first one holding the requested entropy, else the one holding
the most entropy. It also inserts data with entropy into one pool: the first one
with room for its entropy, else the one with the most room. It inserts data
without entropy into all of them.

The #ac("ESDM") copies the output of the auxiliary pool into the seed buffer
when it generates random numbers to seed the #ac("DRNG"). As the output never
reveals the state of the pool, the #ac("ESDM") does not mix the seed buffer back
into the auxiliary pool. The extraction operation is atomic with respect to the
auxiliary pool: it always completes fully before the next operation can
commence. Thus, the same auxiliary pool state can only be used once for a
given seeding operation.

The #ac("ESDM") decreases the entropy estimator by the amount of entropy read
from the pool. If the SHAKE256 fails during an operation, the #ac("ESDM")
discards the state of the pool and sets its entropy estimator to zero.

During its initialization, the #ac("ESDM") inserts the current time together
with data of the #ac("CPU") entropy source, and a machine-specific
personalization string if one is available, into the auxiliary pool without
crediting entropy (`esdm_es_mgr_initialize`).

== Jitter RNG – ESDM-external Entropy Source <sec:jent>

The #ac("ESDM") treats the Jitter #acs("RNG") @jent as an external entropy
source and requests random bits from it when the #ac("DRNG") is to be seeded. It collects
no data ahead of the request.

The #ac("ESDM") allocates the number of Jitter #acs("RNG") collectors of the
meson option `es_jent_instances` or the option `--es_jent_instances` of the
#ac("ESDM") server (meson option 0 to 64, where the default 0 selects 4 in a
build with the meson option `sp80090c`, `fips140` or `ais2031_drg4` without
`ais2031_drg3`, and 1 otherwise; server option 1 to 64),
each with a lock of its own, so that the seedings of several #ac("DRNG")
instances collect side by side. The #ac("ESDM") allocates the Jitter #acs("RNG")
with the oversampling rate of the meson option `es_jent_osr` (3 by default).
With a Jitter #acs("RNG") of version 3.7.0 or later, the meson options
`es_jent_max_mem` and `es_jent_hash_loop_count` adjust its memory size and its
hash loop count. With the meson option `es_jent_ntg1` and a Jitter #acs("RNG") of
version 3.7.0 or later providing secure memory, the #ac("ESDM") operates the
Jitter #acs("RNG") in its own NTG.1 mode (`JENT_NTG1`): it is then an NTG.1
conformant #ac("RNG") by itself, as it applies the start-up rule of NTG.1 – 240
bits from each of its two noise sources – internally. Such a build therefore
meets NTG.1 without `ais2031_ntg1`, and its status lists
"NTG.1(2024)". While a collector fails, the #ac("ESDM") credits the
Jitter #acs("RNG") with no entropy.

=== Entropy of CPU Jitter RNG Entropy Source <sec:jent-entropy>

By default, the #ac("ESDM") credits the #ac("CPU") Jitter #acs("RNG") entropy
source with one bit of entropy per generated data bit. The documentation of
the library @jent provides the entropy assessment behind this rate; this
document does not repeat it.

The meson option `es_jent_entropy_rate` changes this entropy value.

=== Kernel Jitter RNG Entropy Source <sec:jent-kernel>

The #ac("ESDM") can read the Jitter #acs("RNG") of the Linux kernel crypto
#ac("API") via the `libkcapi` library @libkcapi (meson option `es_jent_kernel`, disabled
by default). The meson option `es_jent_kernel_name` (`jitterentropy_rng` by
default) or, at runtime, the option `--es_jent_kernel_name` of the #ac("ESDM")
server names the kernel crypto #ac("API") #ac("RNG"), e.g. for a jitterentropy
kernel module registering its #ac("RNG") under another name. The meson option
`es_jent_kernel_entropy_rate` (256 by default) defines the entropy rate.

== CPU-based Entropy Source – ESDM-external Entropy Source <sec:cpu>

The #ac("ESDM") treats the #acs("CPU")-based entropy source as an external
entropy source and requests random bits from it when the #ac("DRNG") is to be
seeded. Depending on the underlying #ac("CPU"), only one such source is
available, such as RDSEED on Intel x86 (or RDRAND if RDSEED is not available),
the POWER #ac("CPU") DARN instruction, the seed #ac("CSR") of RISC-V, the PRNO
#ac("TRNG") function of IBM Z or the RNDRRS register of ARMv8.

Depending on whether the #ac("CPU") entropy source is documented to provide full
entropy, expressed by its data multiplier, the #ac("ESDM") applies one of these
data collection methods. This approach is orthogonal to the amount of entropy
the #ac("ESDM") credits to the #ac("CPU") entropy source.

- #ac("CPU", cap: true) entropy source provides full entropy: The #ac("ESDM")
  queries the #ac("CPU") entropy source for the amount of data that is stored in
  the temporary seed buffer.

- #ac("CPU", cap: true) entropy source provides less than full entropy: The
  #ac("ESDM") knows how much data it has to fetch from this #ac("CPU") entropy
  source to get full entropy – 2,048 times the requested data for RDRAND, twice
  the requested data for DARN and the seed #ac("CSR") of RISC-V. It pulls the
  required amount of data from the #ac("CPU") entropy source and conditions it
  with the hash it currently uses. It truncates the calculated message digest to
  the requested amount of data, which is stored in the temporary seed buffer.

=== Entropy of CPU Entropy Source <sec:cpu-entropy>

The #ac("ESDM") assumes that the output of the #ac("CPU") entropy source holds
one 32nd of its size in entropy – 8 bits per 256 bits – whatever its data
multiplier (section @sec:dp-cpu). The reason for this conservative
estimate is that the design and implementation of those entropy sources are
not commonly known and reviewable. The meson option `es_cpu_entropy_rate`
changes this entropy value.

== Kernel RNG Entropy Source – ESDM-external Entropy Source <sec:krng>

The #ac("ESDM") can use the kernel #ac("RNG") as an entropy source. The kernel
#ac("RNG") collects entropy from the timing of interrupts, input and disk
events and from the #ac("RNG") instruction of the #ac("CPU"), conditions it
with BLAKE2s and generates its output with a ChaCha20 #ac("DRNG") (Linux 5.17
and later). It is an independent second source: it runs in another security
boundary, the kernel, and observes events the #ac("ESDM") does not.

The #ac("ESDM") queries the kernel #ac("RNG") for random numbers with the
`getrandom(2)` system call and the flag `GRND_NONBLOCK`.

=== Entropy of Kernel RNG Entropy Source <sec:krng-entropy>

When the kernel #ac("RNG") is enabled, the #ac("ESDM") applies the entropy rate
defined at compile time with `es_kernel_entropy_rate` (128 by default), a value
between 0 and 256 bits of entropy when 256 data bits are pulled from the
kernel #ac("RNG").

If the #ac("SP") 800-90C oversampling is in effect, the #ac("ESDM") sets the
entropy rate of the kernel #ac("RNG") entropy source to zero. The reason is
that the kernel #ac("RNG") has no #ac("SP") 800-90B assessment and applies no
health tests of #ac("SP") 800-90B to its noise sources, so the #ac("ESDM")
assumes for #ac("SP") 800-90C that it provides no entropy. The
same applies while the scheduler entropy source of the kernel module is credited
with entropy, because interrupts may trigger scheduling events, and after a self
test of the entropy source found a repeated output.

When the interrupt entropy source of the kernel module is present, the
#ac("ESDM") sets the entropy rate of the kernel #ac("RNG") entropy source to
`ESDM_ES_IRQ_MAX_KERNEL_RNG_ENTROPY` (4) bits of entropy, because the #ac("IRQ")
entropy source takes away the main entropy source of the kernel #ac("RNG"). Yet,
some other entropy sources are present, which may or may not deliver
entropy. Thus, the #ac("ESDM") applies a safe entropy value. While the
#acs("eBPF")-based interrupt entropy source is credited, the #ac("ESDM") caps an
entropy rate of the kernel #ac("RNG") entropy source set at runtime at the same
value.

== Linux HWRAND Entropy Source – ESDM-external Entropy Source <sec:hwrand>

The #ac("ESDM") reads the Linux hardware random number generator framework via
`/dev/hwrng` (meson option `es_hwrand`, enabled by default), which provides
the data of the hardware #ac("RNG") selected by the kernel, e.g. a #ac("TPM") or
a virtio-rng device. A thread of its own reads the device with a deadline of 2
seconds, so that a stalled device does not stall the seeding. A device
failing a read is not credited with entropy, and the seedings no longer read
it; the #ac("ES") monitor probes it at most every 10 seconds until it delivers
again. The meson option `es_hwrand_entropy_rate` (0 by default) defines the
entropy rate. With an entropy rate of zero, the data is only part of the
additional input of the #ac("DRNG"), and the seeding skips the device when it is
busy with another seeding.

== TPM 2.0 Entropy Source – ESDM-external Entropy Source <sec:tpm2>

The #ac("ESDM") reads the #ac("RNG") of a #ac("TPM") 2.0 with the command
`TPM2_GetRandom`, sent to the resource manager device `/dev/tpmrm0` (meson
options `es_tpm2` and `es_tpm2_rm_path`) without a #ac("TSS") library. The
kernel can expose the same #ac("TPM") through `/dev/hwrng` (section
@sec:hwrand). The #ac("ESDM") nevertheless addresses the #ac("TPM") directly:

- The #ac("HWRAND") interface offers no `TPM2_StirRandom`. Only the command
  interface of the #ac("TPM") can make it reseed its internal #ac("RNG")
  before it delivers data.

- The #ac("HWRAND") framework has one active backend. Read directly, the
  #ac("TPM") leaves `/dev/hwrng` to another hardware #ac("RNG"), e.g.
  virtio-rng or an #acs("RNG") of the chipset, and both feed the #ac("ESDM") as
  independent entropy sources.

- The command protocol reports the transient states `TPM_RC_RETRY`,
  `TPM_RC_YIELDED` and `TPM_RC_TESTING`, which the #ac("ESDM") retries;
  `/dev/hwrng` returns data or an error number.

#par(first-line-indent: 0pt)[Table @tab:tpm2-hwrand compares the two entropy
sources.]

#figure(
  table(columns: (auto, 1fr, 1fr), align: left + horizon,
    table.header([Property], [#ac("TPM", cap: true) 2.0 entropy source],
      [#ac("HWRAND", cap: true) entropy source]),
    [Device], [`/dev/tpmrm0` (configurable), read and write], [`/dev/hwrng`,
      read only],
    [#ac("RNG", cap: true)], [the #ac("TPM")], [the backend the kernel
      selected],
    [Protocol], [`TPM2_GetRandom`, response code checked, transient states
      retried], [`read()` of 32-byte chunks],
    [Stir], [`TPM2_StirRandom`, optional], [none],
    [Self test], [two reads must differ], [the last read did not fail],
    [Entropy rate], [`es_tpm2_entropy_rate`, 0 by default],
      [`es_hwrand_entropy_rate`, 0 by default],
  ),
  caption: [#ac("TPM", cap: true) 2.0 and #ac("HWRAND") entropy sources],
) <tab:tpm2-hwrand>

#paragraph[Commands][One `TPM2_GetRandom` command requests 32 bytes: a
header of 10 bytes – the tag `TPM_ST_NO_SESSIONS` (0x8001), the size and the
command code 0x17B – and the requested size of 2 bytes, all big-endian. The
#ac("ESDM") repeats the command until the request is filled, accepts a response
only if its size and the size of the returned buffer match the request, and
sends a command answered with a transient state up to five times, with a
back-off of 10 to 40 ms between the attempts
(`esdm_es_tpm2_transceive` in `esdm/esdm_es_tpm2.c`).]

#paragraph[Stir][With the meson option `es_tpm2_stir` (disabled by default),
a `TPM2_StirRandom` command precedes every `TPM2_GetRandom`. The #ac("TPM")
mixes the given data into the state of its #ac("RNG") and reseeds it, so that
every 32 bytes come from a freshly reseeded #ac("RNG") – at the cost of a second
command per 32 bytes. The stirred data is the time of the request as two
`struct timespec` in host byte order, of `CLOCK_REALTIME` and of
`CLOCK_MONOTONIC` – 32 bytes on 64-bit Linux – credited with no entropy. It
separates the requests of different systems and times; no output of the
#ac("ESDM") enters the #ac("TPM"), so the state of the #ac("ESDM") does not
leave its security boundary:]

```c
/* inject real and monotonic time as additional input without entropy */
(void)clock_gettime(CLOCK_REALTIME, &stir_clock_real);
(void)clock_gettime(CLOCK_MONOTONIC, &stir_clock_monotonic);
memcpy(stir_buf + sizeof(uint16_t), &stir_clock_real,
       sizeof(stir_clock_real));
memcpy(stir_buf + sizeof(uint16_t) + sizeof(stir_clock_real),
       &stir_clock_monotonic, sizeof(stir_clock_monotonic));
```

#par(first-line-indent: 0pt)[A #ac("TPM") rejecting the stir fails the read
like any other error.]

#paragraph[Failures][A #ac("TPM") blocks while it executes a long command of
another process, and a hung virtual #ac("TPM") blocks for good. The
#ac("ESDM") therefore reads it on a thread of its own and waits at most 2
seconds for all commands of one read (section @sec:seeding). A read that times
out or fails leaves the entropy source uncredited and unread by the seedings;
the #ac("ES") monitor probes it at most every 10 seconds until it delivers
again. The self test, repeated every 10 minutes, requires two reads of 32 bytes
to differ; a repetition withholds the credit until a later self test passes. A
device absent at initialization leaves the entropy source disabled.]

#paragraph[Crediting][The meson option `es_tpm2_entropy_rate` defines the
entropy rate, 0 by default: the #ac("TPM") executes one command at a time, so a
seeding that waits for it waits for every other seeding – in an #ac("SP")
800-90C build, the credited #ac("TPM") limited all seedings together to some
180 per second. Credited with nothing, its data is additional input, and a
seeding skips the #ac("TPM") while another one reads it. Credit it only with
the rate its assessment gives.]

== External Entropy Source – ESDM-external Entropy Source <sec:ext-es>

The external entropy source (meson option `es_ext`, enabled by default)
connects a noise source that is not part of the #ac("ESDM") – an #ac("HSM"), a
smart card, the #ac("RNG") of a key management system – through a provider: a
process of its own that serves the noise source on a Unix domain socket of the
type `SOCK_SEQPACKET`. The option `--es_ext` of the #ac("ESDM") server or the
meson option `es_ext_path` configures the path of the socket; without it, the
entropy source is inactive. Section @sec:hsm describes the providers
`esdm-es-pkcs11` and `esdm-es-pcsc`, section @sec:writing-es-ext how to write
one. The design follows from three requirements:

- Isolation: the code of a vendor – a #acs("PKCS")\#11 module, a #ac("PC/SC")
  stack – runs in the provider with the privileges its device needs. The
  #ac("ESDM") loads no foreign code into its address space and keeps its
  privileges dropped; a provider that crashes takes only itself down.

- Message boundaries: `SOCK_SEQPACKET` delivers one message per datagram, so
  the protobuf messages need no framing of their own, and a message is never
  read in part.

- Trust: whoever can create the socket could feed the #ac("ESDM") data credited
  as entropy. The #ac("ESDM") therefore accepts a provider only if
  `SO_PEERCRED` reports root or the user given with `--es_ext_uid` (meson
  option `es_ext_peer_uid`). It trusts the reports of an accepted provider and
  caps only its credit.

#par(first-line-indent: 0pt)[Figure @fig:es-ext shows one connection and
table @tab:es-ext-requests the requests. The messages are the protobuf
messages `EsExtRequest` and `EsExtResponse` of `es-ext/pb/es_ext.proto`:]

```protobuf
message EsExtRequest {
	uint32 version = 1;
	EsExtType type = 2;    /* GET_ENTROPY, SELFTEST, STATUS or INFO */
	uint32 length = 3;     /* the bytes asked for */
}

message EsExtResponse {
	uint32 version = 1;
	EsExtType type = 2;
	sint32 status = 3;     /* 0 or a negative errno */
	uint32 entropy_bits = 4;
	bytes data = 5;
	uint32 rate = 6;
	bytes name = 7;
}
```

#figure(
  image("../figures/es-ext-sequence.svg", width: 46%),
  caption: [One connection to the provider of the external entropy source],
) <fig:es-ext>

#figure(
  table(columns: (auto, 1.2fr, 1.6fr), align: left + horizon,
    table.header([Request], [Answer], [Use]),
    [INFO], [Declared entropy rate or none, name of up to 32 bytes],
      [First request of every connection; the rate applies if none is
      configured],
    [SELFTEST], [Status], [Second request of every connection, then
      periodically; a failure withholds the credit until a self test passes],
    [GET_ENTROPY], [1 to 512 bytes and their entropy, at most 8 bits per
      byte], [Seeding],
    [STATUS], [#ac("JSON", cap: true) object of up to 1024 bytes], [Part of
      the status of the #ac("ESDM"), asked for by the #ac("ES") monitor],
  ),
  caption: [Requests of the external entropy source protocol],
) <tab:es-ext-requests>

#paragraph[Crediting][The #ac("ESDM") credits a block with the entropy the
provider claims for it, capped by the entropy rate of the entropy source: the
one configured with the meson option `es_ext_entropy_rate` or the option
`--es_ext_entropy_rate` of the #ac("ESDM") server, else the one the provider
declares in its answer to INFO, else 0. A provider claiming more entropy than
the block holds breaks the protocol.]

#paragraph[Failures][The connection carries one request at a time. A request
gets 2 seconds; an error, a timeout or an answer breaking the protocol closes
the connection, as a late answer would be taken for the next one. The
#ac("ESDM") connects again on demand, at most every 5 seconds after a failure,
starting with INFO and a self test: the provider may have been restarted with
its noise source set up anew. A failing provider is credited with nothing until
it delivers again, and the #ac("ES") monitor probes it meanwhile. A seeding
waits at most 2 seconds for the connection – behind a reconnection, a self test
or another seeding – and otherwise skips the provider without counting a
failure. A provider not answering STATUS within 500 ms is disconnected and not
asked again for a minute, so that a slow provider does not delay the status.]

== Entropy Sources: Rates, Health Tests and Independence <sec:es-overview>

Table @tab:es-overview lists every entropy source with the entropy the
default build credits to 256 bits of its data, the health tests that run on
its raw data, the evidence behind the rate and the other entropy sources it
shares a noise source with.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (1.1fr, 0.95fr, 1.4fr, 1.4fr, 1.4fr), align: left + top,
    table.header([Entropy source], [Default rate], [Health tests on the raw
      data], [Evidence for the rate], [Shares its noise with]),
    [Interrupt, kernel module], [256], [Stuck test always; #ac("RCT"),
      #ac("APT") and startup test with `fips=1` only], [#ac("SP") 800-90B
      assessment of chapter @sec:kernel-es-assessment, within the limits of
      section @sec:measurement-limits], [Scheduler and #ac("eBPF") timing
      sources (at most one credited); kernel #ac("RNG") (capped at 4 bits)],
    [Scheduler, kernel module], [0], [As above], [As above], [As above;
      kernel #ac("RNG") (set to 0 while credited)],
    [Interrupt and scheduler, #ac("eBPF")], [0], [All tests in the
      #ac("eBPF") programs, in #ac("FIPS") mode, #ac("SP") 800-90C mode or
      with the NTG.1 seeding strategy only], [Measurements of chapter
      @sec:ebpf-assessment on one system; to be measured on the target],
      [The other timing sources (at most one credited); kernel #ac("RNG")],
    [Jitter #acs("RNG")], [256], [Those of the library, enforced with the
      oversampling in effect, in #ac("FIPS") mode or with the NTG.1 seeding
      strategy], [Assessment of the Jitter #acs("RNG") library @jent, outside
      of this document], [Kernel Jitter #acs("RNG") (same #ac("CPU"), no rule)],
    [Kernel Jitter #acs("RNG")], [256; not built by default], [Those of the
      kernel], [As above], [Jitter #acs("RNG") (no rule)],
    [#ac("CPU")], [8], [None in the #ac("ESDM")], [Claim of the vendor, not
      verifiable; hence 8 instead of 256], [Kernel #ac("RNG"), which mixes
      the same instruction in (no rule)],
    [Kernel #ac("RNG")], [128; 4 with the interrupt entropy source of the kernel
      module present; 0 with oversampling or a credited scheduler entropy
      source], [None of
      #ac("SP") 800-90B], [None: no assessment], [Interrupt sources (cap),
      #ac("CPU") (no rule)],
    [#ac("HWRAND")], [0], [None in the #ac("ESDM")], [Assessment of the
      device, to be supplied by the integrator], [#ac("TPM") 2.0 when
      `/dev/hwrng` is backed by the #ac("TPM") (no rule)],
    [#ac("TPM") 2.0], [0], [None in the #ac("ESDM")], [Certification of the
      #ac("TPM"), to be supplied by the integrator], [#ac("HWRAND") (no
      rule)],
    [External entropy source], [Declared by the provider, or the configured cap], [Those of the provider], [Assessment of the provider],
      [Depends on the provider],
    [Auxiliary pool], [Credited by the writer (root)], [None],
      [Responsibility of the writer], [Depends on the writer],
  )
}
, caption: [Entropy sources, default entropy rates, health tests, evidence
  and shared noise sources]) <tab:es-overview>

#paragraph[The defaults][The default rates follow no single rule, and the
table shows the consequence. The interrupt entropy source carries its full
rate on the strength of its assessment. The Jitter #acs("RNG") carries its
full rate on the strength of an assessment that belongs to the library, not
to the #ac("ESDM"). The #ac("CPU") entropy source is cut to 8 bits because
its design cannot be reviewed. The kernel #ac("RNG") is credited 128 bits
although it has no assessment at all, a value that is a convention of the
default build rather than a result. The default build is thus a pragmatic
configuration for a general-purpose system: it reaches the fully seeded
level from the Jitter #acs("RNG") alone and does not depend on the rate of
the kernel #ac("RNG"). It is not an assessed configuration. A configuration
with a claim – #ac("SP") 800-90C, #ac("FIPS") 140-3, #ac("AIS") 20/31 – sets
every rate deliberately (chapter @sec:configurations); with the oversampling
in effect, the #ac("ESDM") sets the rate of the kernel #ac("RNG") to zero
itself.]

#paragraph[Summing presumes independence][The entropy of a seed is the plain
sum of the entropy the entropy sources credit (`esdm_entropy_rate_eb`,
equation @eq:h-t-buffer); the sum is not capped. A sum of entropy values is
valid only for independent sources. The #ac("ESDM") enforces independence
where it knows a dependency:]

- The four timing sources – interrupt and scheduler, kernel module and
  #ac("eBPF") – observe related events. The build refuses a configuration
  that credits more than one of them, and setting the rate of one of them at
  runtime sets the others to zero (`esdm_config_timing_es_rate_set`).

- The kernel #ac("RNG") draws on interrupt timing. Its rate is set to zero
  while the scheduler entropy source of the kernel module is credited, and
  capped at 4 bits once the kernel module provides the interrupt entropy
  source. With the #ac("eBPF") interrupt entropy source, the cap applies only
  to a rate set at runtime afterwards, not to the rate of the build.

#par(first-line-indent: 0pt)[It enforces nothing for these pairs, whose
entropy it adds although they overlap:]

- The #ac("CPU") entropy source and the kernel #ac("RNG"), which mixes the
  same #ac("CPU") instruction into its pool: of the 128 + 8 bits of the
  default build, up to 8 bits are counted twice.

- The Jitter #acs("RNG") in user space and the Jitter #acs("RNG") of the
  kernel, which measure the execution timing of the same #ac("CPU"). They
  are separate implementations with separate memory, yet no analysis shows
  their outputs to be independent: a build that enables both and credits
  both with 256 bits counts up to 256 bits twice.

- The #ac("HWRAND") and the #ac("TPM") 2.0 entropy source, when the kernel
  backs `/dev/hwrng` with the same #ac("TPM").

- The #acs("eBPF")-based scheduler entropy source and the kernel #ac("RNG").

#par(first-line-indent: 0pt)[For these pairs, the integrator credits one
entropy source of the pair and sets the other to zero, whose data then still
enters the #ac("DRNG") as additional input. Independence of the remaining
combinations – e.g. the Jitter #acs("RNG") and the interrupt entropy source –
is an assumption of this design: they observe different physical effects
through different code, but share the #ac("CPU") and its clock. The
concatenation and joint conditioning of all data ensures that a dependent or
malicious entropy source cannot reduce the entropy of another one; it does
not make the sum of dependent credits valid.]

== System Events: Clones, Suspend, Resume and Shutdown <sec:vm-clone>

Four events of the system change what the state of the #ac("ESDM") is worth.
A snapshot, a clone or a restore of a virtual machine duplicates the memory
of the #ac("ESDM") server, and with it the state of every #ac("DRNG")
instance and of the pools: two machines, or one machine twice, continue from
the same state and deliver the same random numbers until their states
diverge. A suspend stops the system for an unknown time, during which its
memory may have been read. A shutdown ends the consumers that wait for the
#ac("ESDM"). Table @tab:system-events lists what the #ac("ESDM") does on
each event and how it learns of it.

#figure(
  table(columns: (0.9fr, 1.5fr, 1.6fr), align: left + top,
    table.header([Event], [Reported by], [Reaction of the #ac("ESDM")]),
    [#ac("VM") generation change: snapshot restored, clone started], [The
      kernel module `esdm_es`, from the #ac("VM") generation notification of
      the kernel (`CONFIG_VMGENID`)], [All credited entropy is dropped,
      every #ac("DRNG") instance is taken back to not fully seeded and
      seeded anew (`esdm_reset`, `esdm_force_fully_seeded_all_drbgs`). The
      blocking interfaces serve again once the initial instance is fully
      seeded from entropy collected after the event],
    [Suspend, hibernation], [The kernel module, from the power management
      notification; or `esdm-server-signal-helper --suspend`, which signals
      the server], [The suspend notification of the status shared memory
      segment wakes the waiters of the #ac("CUSE") daemons and of the
      auxiliary clients],
    [Resume], [The kernel module, from the power management notification; or
      `esdm-server-signal-helper --resume` over the privileged #ac("RPC")
      interface], [A reseed of every fully seeded #ac("DRNG") instance is forced
      (`esdm_drng_force_reseed`): the initial instance reseeds before its
      next output; the reseed worker is woken to reseed the node instances,
      which serve from their previous seed until that reseed is injected],
    [Shutdown, reboot, halt], [The kernel module, from the reboot
      notification], [As for a suspend],
  ),
  caption: [System events, their source and the reaction of the #ac("ESDM")],
) <tab:system-events>

#paragraph[The kernel module as the source][The kernel module `esdm_es`
counts each event since it was loaded and offers the counts to the holder of
a descriptor of `/dev/esdm_es` (#ac("IOCTL") `ESDM_ES_EVENTS`,
`kernel/shared/esdm_es_ioctl.h`); `poll` reports the descriptor readable
while a count differs from the one the descriptor last read. The module
resets its own entropy sources for the event before it increments the count,
so entropy read after a new count was collected after the event. This part
of the module does not depend on its entropy sources: built with neither of
them (`BUILD_ES_IRQ=0 BUILD_ES_SCHED=0`), the module needs no kernel patch,
no #ac("DRBG") and no high-resolution timer, builds against an unmodified
kernel and only reports the events. A kernel without `CONFIG_VMGENID` does
not report the #ac("VM") generation, which the first word the #ac("IOCTL")
returns states.]

#paragraph[The server][When the #ac("ESDM") starts its threads
(`esdm_init_monitor`), it opens the device – which takes `CAP_SYS_ADMIN`,
hence before the privileges are dropped – and starts a thread that waits in
`poll` for the events (`esdm/esdm_es_events.c`). The thread logs each event
and carries out the reaction of table @tab:system-events. Without the
module, or with a module that does not know the #ac("IOCTL"), no thread is
started and the #ac("ESDM") behaves as before: the systemd units of
`esdm-server-signal-helper` then remain the way to tell the server about a
suspend and a resume, and nothing reports a #ac("VM") generation change.
Both paths may be active at once; a reaction carried out twice does no
harm.]

#paragraph[Limits][The reaction to a #ac("VM") generation change is not
instantaneous: between the resumption of the clone and the reaction lie the
notification of the kernel, the wakeup of the thread and the locks of the
#ac("DRNG") instances. A request that a #ac("DRNG") instance serves in this
window still draws on the duplicated state. The window is short – the thread
blocks in `poll` and does not sample – but it is not zero, and the
#ac("ESDM") cannot close it from user space. Random numbers delivered before
the snapshot was taken and still held by a consumer, such as the internal
state of a consumer's own generator, are duplicated as well and out of the
reach of the #ac("ESDM"). A hypervisor that does not provide the #ac("VM")
generation device, or a system without the kernel module, leaves the clone
undetected: the #ac("DRNG") instances then diverge only with their next
reseed with entropy collected after the clone – at the latest after 600
seconds or $2^20$ generate operations, provided the entropy sources deliver –
and the procedure that clones or restores the machine has to force a reseed
itself, with `esdm-server-signal-helper --resume`, the `RNDRESEEDCRNG`
#ac("IOCTL") or a restart of the server (chapter @sec:tools). Only the
restart ensures that no output after it rests on the duplicated state: a
forced reseed leaves the node instances serving from their previous seed
until the reseed worker has reseeded them.]

#paragraph[Fork][A fork has the same effect within one system as a clone has
between systems. A process that embeds `libesdm.so` and forks hands a copy of
every #ac("DRNG") state to its child, which would repeat the output of the
parent, and the child has none of the threads that seed. The #ac("ESDM")
therefore does not continue across a fork: a fork handler
(`pthread_atfork`, registered by `esdm_drng_mgr_initialize`) marks the
child, takes every #ac("DRNG") instance back to not fully seeded and clears
the copied states of the built-in #ac("DRNG", pl: true). In the child, every
call for random data or for a seed fails with `-EOPNOTSUPP`, and `esdm_fini`
returns at once. States held by another crypto backend, the auxiliary pools
and the buffers of the entropy sources remain in the memory of the child –
releasing them would call into code whose locks the fork may have caught
held – but are never handed out. The child cannot initialize the #ac("ESDM")
again: an application that needs it in its children initializes it after the
fork, or uses the #ac("RPC") client library. A `clone` system call that
bypasses the fork handlers is not detected. The #ac("ESDM") server is not
affected, as it initializes the #ac("ESDM") after its own forks.]

#paragraph[Containers][A container shares the kernel of its host. The
kernel module and the #ac("eBPF") entropy sources exist once per kernel, and
the sockets of the server are visible only where its mount namespace is. A
container that has the sockets bind-mounted uses the #ac("ESDM") of the host
with the rights of an unprivileged local user of table @tab:attackers;
running a server per container gives each one #ac("DRNG") instances of its
own, which then compete for the entropy sources of the one kernel. The
#ac("ESDM") keeps no state per container.]

== DRNG Seeding Operation <sec:seeding>

A seeding collects the data of the entropy sources in the seed buffer $T_n$ and
the additional input $U_n$ (section @sec:dp-seed-buffer) and injects both into
one #ac("DRNG") instance; figure @fig:seeding shows its control flow. This
section describes what triggers a seeding, how much entropy it requests, how it
collects the data in parallel, how it bounds slow and failing entropy sources,
and how concurrent seedings are kept apart. The code is in `esdm/esdm_es_mgr.c`
(collection) and `esdm/esdm_drng_mgr.c` (triggers and injection).

=== Triggers <sec:seeding-triggers>

Table @tab:seeding-triggers lists the events that start a seeding.

#figure(
  table(columns: (1fr, 2fr, auto), align: left + horizon,
    table.header([Trigger], [Condition], [Function]),
    [Reseed worker], [A fully seeded node #ac("DRNG") whose reseed is due, or
      a #ac("DRNG") not yet fully seeded], [`esdm_drng_reseed_pass`],
    [Due reseed], [$2^20$ generate requests, `drng_reseed_threshold_bits`
      generated bits, 600 seconds since the last seeding, or a forced reseed],
      [`esdm_drng_must_reseed`],
    [Request], [The initial #ac("DRNG"), or any #ac("DRNG") without a reseed
      worker, reseeds inline; a node #ac("DRNG") wakes the worker and keeps
      serving], [`esdm_drng_get_reseed`],
    [Prediction resistance], [Every chunk of output], [`esdm_drng_seed_es`],
    [Forced reseed], [`RNDRESEEDCRNG`, `RpcRndReseedCRNG`, the #ac("EGD")
      command 0xe8], [`esdm_drng_force_reseed`],
    [Entropy arrives], [Data inserted into the auxiliary pool or reported by
      an entropy source while not all #ac("DRNG", pl: true) are fully seeded],
      [`esdm_es_add_entropy`],
  ),
  caption: [Triggers of a seeding],
) <tab:seeding-triggers>

The reseed worker runs the seedings on threads of their own, as many at a time
as there are Jitter #acs("RNG") collectors (`es_jent_instances`): collecting the
data takes most of the time of a seeding, so a seeding starts as soon as it is
due and a collector is free, not after the slowest one of a round.

=== Requested Entropy <sec:seeding-request>

A seeding requests the security strength of 256 bits from every entropy
source. With the #ac("SP") 800-90C oversampling, the initial seeding of a
#ac("DRNG") requests 128 bits more (#ac("SP") 800-90C section 2.6 item 11:
$3s \/ 2$ bits), and the reseed of the prediction resistance #ac("DRNG") 64
bits more (#ac("SP") 800-90C section 6.5.2 requirement 1):

```c
static inline uint32_t esdm_get_seed_entropy_osr(bool do_full_init,
                                                 bool full_entropy)
{
	uint32_t requested_bits = esdm_security_strength();

	/* Apply oversampling during initialization according to SP800-90C */
	if (esdm_es_oversampling() && do_full_init)
		requested_bits += ESDM_SEED_BUFFER_INIT_ADD_BITS;  /* 128 */
	/* RBG3(RS), see SP800-90C sec. 6.5.2 requirement 1 */
	if (esdm_es_oversampling() && full_entropy)
		requested_bits += ESDM_OVERSAMPLE_ES_BITS;         /* 64 */
	return requested_bits;
}
```

#par(first-line-indent: 0pt)[A regular reseed thus requests 256 bits, the
reseed of the prediction resistance #ac("DRNG") 320 bits and the initial
seeding 384 bits (`esdm/esdm_es_aux.h`). Each slot of $T_n$ and $U_n$ holds 32
bytes, 48 bytes in a build with the oversampling compiled in.]

=== Collection <sec:seeding-collection>

`esdm_get_seed_buffers` always writes the current time (`CLOCK_MONOTONIC`)
into both buffers, credited with no entropy. It reads the entropy sources only
if one of these holds: the reseed is forced, the initial #ac("DRNG") is not yet
fully seeded, the entropy sources together report at least 256 bits, or a
Jitter #acs("RNG") or #ac("CPU") entropy source failed its last read – these
recover only by being read. Otherwise the seeding injects the time alone, so
that a #ac("DRNG") is reseeded with the security strength as #ac("SP") 800-90A
section 9.2 demands, or not with entropy at all:

```c
if (!force && fully_seeded && (esdm_avail_entropy() < req_ent) &&
    !esdm_es_read_failed()) {
	for_each_esdm_es (i) {
		seedbuf->entropy_es[i].e_bits = 0;
		if (addtl)
			addtl->entropy_es[i].e_bits = 0;
	}
	goto wakeup;
}

esdm_es_fetch(seedbuf, addtl, requested_bits);
```

#par(first-line-indent: 0pt)[`esdm_es_seed_slot` assigns each entropy source
its slot: an entropy source with a maximum entropy above zero writes into
$T_n$, every other one into $U_n$ – one configured with an entropy rate of zero,
as well as one that currently fails or is not credited. Each slot is wiped
before its entropy source is read.]

#paragraph[Parallel fetch][With the meson option `es_parallel_fetch` (enabled
by default), `esdm_es_fetch` reads all entropy sources at the same time – the
credited ones, those of $U_n$ and the auxiliary pool – on one thread each, and
joins them once:]

```c
/*
 * The slots are cleared here before the threads fetching into them
 * are started. One join for both buffers: the wait is for the slowest
 * source there is rather than for the slowest of each buffer.
 */
for_each_esdm_es (i) {
	struct entropy_es *eb_es = esdm_es_seed_slot(seedbuf, addtl, i);

	if (!eb_es)
		continue;

	args[n].es_idx = i;
	args[n].eb_es = eb_es;
	args[n].requested_bits = requested_bits;
	n++;
}
thread_fork_join(esdm_es_get_ent_thread, args, sizeof(args[0]), n);
```

#par(first-line-indent: 0pt)[A seeding thus lasts as long as its slowest entropy
source, not as long as all of them together. `thread_fork_join`
(`common/threading_support.c`) starts plain threads rather than taking them from
the thread pool of the #ac("ESDM"): the join then waits for exactly the threads
of this seeding, which cannot deadlock behind unrelated work in the pool. The
entropy sources are read one after the other on a system with one #ac("CPU"),
during the shutdown – where threads not visible to the cancellation could
outlive the buffers they write into –, and for an entropy source whose thread
cannot be started.]

=== Slow and Failing Entropy Sources <sec:seeding-slow>

A seeding holds the seed lock of its #ac("DRNG"), and the initial seeding the
#ac("DRNG") lock as well, so an entropy source that blocks would block the
#ac("DRNG"). Some devices block a read indefinitely: `/dev/hwrng` waits for a
kernel mutex held across a virtio-rng request without timeout, `/dev/tpmrm0`
for any process using the #ac("TPM"). Table @tab:seeding-slow lists how each
kind of entropy source is bounded.

#figure(
  table(columns: (1fr, 1.6fr, 1.6fr), align: left + horizon,
    table.header([Entropy source], [Skipped by a seeding], [Recovery]),
    [#ac("HWRAND", cap: true), #ac("TPM") 2.0], [After a read failed or
      exceeded the deadline of 2 s; while another read runs and the source is
      credited with nothing; while a timed-out read is still stuck in the
      kernel], [The #ac("ES") monitor probes it at most every 10 s],
    [External], [After a request failed or exceeded 2 s; for this seeding
      only, if the connection is not free within 2 s], [Reconnection by the
      #ac("ES") monitor, at most every 5 s],
    [Jitter #acs("RNG"), #ac("CPU")], [Never: a failed read credits no
      entropy, but the next seeding reads again], [The next successful read],
    [Interrupts, scheduler], [The kernel module delivers no data while its
      rings hold fewer timestamps than the request needs], [New events],
  ),
  caption: [Bounds of slow and failing entropy sources],
) <tab:seeding-slow>

`esdm/esdm_es_reader.c` reads #ac("HWRAND") and the #ac("TPM") on a thread of
its own per read; the seeding waits for it until the deadline only, then cancels
it. A thread that the kernel holds in an uninterruptible wait leaves once the
device returns; until then every request gets `-EBUSY` at once, without
counting a failure. A failing entropy source credits no entropy, so its data,
if any, moves to $U_n$.

=== Concurrency <sec:seeding-concurrency>

- The seed lock of a #ac("DRNG") serializes its seedings, so that the entropy is
  collected once rather than by every path that finds the reseed due. Seedings
  of different #ac("DRNG", pl: true) run side by side.

- A fully seeded #ac("DRNG") keeps serving requests while its seeding collects
  data, which takes milliseconds with a slow source, and is locked only to
  inject the seed. A #ac("DRNG") being brought up, and the prediction resistance
  #ac("DRNG"), stay locked throughout. One prediction resistance request is
  served at a time.

- The entropy sources lock themselves, so that two seedings never obtain the
  same data: the auxiliary pools with a lock per pool and an atomic exchange of
  their entropy count, the interrupt and scheduler entropy sources with a mutex
  each, #ac("HWRAND") and the #ac("TPM") with one read at a time, the external
  entropy source with one request at a time, and the Jitter #acs("RNG") with
  `es_jent_instances` collectors, each with its own lock, of which a seeding
  takes a free one.

=== Injection <sec:seeding-injection>

`esdm_drng_inject` hands both buffers to the seed callback of the
#ac("DRNG") (section @sec:crypto), $T_n$ as seed and $U_n$ as additional
input:

```c
if (drng->drng_cb->drng_seed(drng->drng, inbuf, inbuflen, addtl,
			     addtllen) < 0) {
	esdm_logger(LOGGER_WARN, LOGGER_C_DRNG,
		    "seeding of %s DRNG failed\n", drng_type);
	atomic_store(&drng->force_reseed, true);
	return false;
}
```

#par(first-line-indent: 0pt)[A failed seed operation forces the next reseed.
The seeding wipes both buffers with `memset_secure` once the #ac("DRNG") holds
them. It marks the #ac("DRNG") fully seeded when the collected entropy reaches
the requested amount (section @sec:seed-levels); otherwise the initial seeding
repeats the collection as long as entropy sources deliver.]

=== DRNG May Become Not Fully Seeded <sec:not-fully-seeded>

For each #ac("DRNG") instance, the #ac("ESDM") counts the generate operations
performed without a reseed that has full entropy. If this counter reaches the
threshold of $2^30$ generate operations, or the number of bits generated
reaches the threshold of the meson option `drng_max_reseed_bits`, i.e. the
#ac("DRNG") did not receive a seed with full entropy for that many generate
operations, the #ac("ESDM") marks the #ac("DRNG") as not fully seeded. The
#ac("ESDM") then no longer uses the #ac("DRNG") instance for generating random
numbers until it has received sufficient entropy to reseed the #ac("DRNG") with
full entropy. A per-#acs("CPU") #ac("DRNG") instance that reached the threshold
of `drng_max_reseed_bits` remains fully seeded while the reseed worker is
active, but serves no request until the reseed worker has reseeded it; another
#ac("DRNG") instance serves the requests meanwhile. The initial #ac("DRNG")
instance already stops serving requests at the threshold of
`drng_reseed_threshold_bits`, which leaves the remaining output for its reseed.

If the #ac("DRNG") that becomes not fully seeded is the initial #ac("DRNG")
instance that was seeded during boot time as outlined in section
@sec:seed-levels, the #ac("ESDM") marks itself as not operational. This blocks
all blocking interfaces, as during boot time when the #ac("ESDM") is not
yet fully seeded.

The #ac("ESDM") automatically tries to recover once it has received sufficient
entropy.

== State Machines <sec:state-machines>

Much of the behavior of the #ac("ESDM") is that of a few finite state
machines: whether a call delivers data, waits or fails follows from their
states. This section gives each of them with its state variables, its
transitions and what each state permits. The states are those of the code;
where the code keeps a state as flags and counters, the state is the
predicate over them that the code tests. Chapter @sec:formal-verification
model checks the concurrent execution of these machines; the graphs here
show one instance at a time.

=== The ESDM as a Whole <sec:sm-esdm>

The state of the library is held in `esdm_avail` (`esdm/esdm_drng_mgr.c`)
and in the flags `esdm_operational`, `esdm_fully_seeded` and
`all_online_nodes_seeded` of `esdm_state` (`esdm/esdm_es_mgr.c`). Figure
@fig:sm-esdm shows the states.

#figure(
  image("../figures/fsm-esdm.svg", width: 86%),
  caption: [States of the #ac("ESDM") as a whole],
) <fig:sm-esdm>

- Loaded to available: `esdm_init` allocates the initial and the prediction
  resistance #ac("DRNG") instance and runs the crypto self test. A failure of
  either returns to the loaded state, and `esdm_init` fails.

- Available to operational: the initial #ac("DRNG") instance reaches the
  fully seeded level (`esdm_init_ops`), normally within `esdm_init`, which
  seeds it synchronously. The waiters of the blocking calls are woken, and
  the status segment reports the operational state.

- Operational to available: the initial #ac("DRNG") instance loses the fully
  seeded level – it exceeded the limit of generate operations without a full
  reseed, or `esdm_reset` ran after a change of the #ac("VM") generation
  (section @sec:vm-clone). A node #ac("DRNG") instance that loses its seed
  only leaves the state with all nodes seeded.

- Finalized is absorbing: after `esdm_fini`, `esdm_init` and `esdm_reinit`
  return `-ESHUTDOWN`. The forked child is absorbing as well: a fork handler
  marks the child, in which every output call fails (section @sec:vm-clone).

#par(first-line-indent: 0pt)[Table @tab:sm-calls gives the result of the
output calls in each state. A failed self test (section @sec:sm-selftest)
overrides the state: every call then returns `-EOPNOTSUPP`.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (1.35fr, 0.9fr, 1.2fr, 1.35fr, 0.9fr), align: left + top,
    table.header([Call], [Loaded], [Available, not operational],
      [Operational], [Finalized, forked child]),
    [`esdm_get_random_bytes`], [`-EOPNOTSUPP`], [`-EOPNOTSUPP`], [Data;
      `-EAGAIN` if the #ac("DRNG") instances await their reseed],
      [`-EOPNOTSUPP`],
    [`esdm_get_random_bytes_full`], [Waits], [Seeds, then waits until
      operational], [Data], [`-EOPNOTSUPP`],
    [`esdm_get_random_bytes_full_noblock`], [`-EAGAIN`], [`-EAGAIN`], [Data
      or `-EAGAIN`], [`-EOPNOTSUPP`],
    [`esdm_get_random_bytes_pr`], [Waits], [Waits until operational], [As
      many bytes as fresh entropy allows, possibly none; `-EAGAIN` while
      another request holds the instance], [`-EOPNOTSUPP`],
    [`esdm_get_random_bytes_pr_noblock`], [`-EAGAIN`], [`-EAGAIN`], [Data or
      `-EAGAIN`], [`-EOPNOTSUPP`],
    [`esdm_get_seed`], [`-EAGAIN` or waits], [Waits until all #ac("DRNG")
      instances are seeded; `-EAGAIN` without waiting], [Seed data once all
      #ac("DRNG") instances are seeded; `-EAGAIN` during another seed request
      and, unless the call waits, when an instance lost its seed level],
      [`-EOPNOTSUPP`],
  )
}
, caption: [Result of the output calls in the states of the #ac("ESDM")])
<tab:sm-calls>

=== A DRNG Instance <sec:sm-drng>

Every #ac("DRNG") instance – the initial one, one per node, the prediction
resistance one – is a `struct esdm_drng` (`esdm/esdm_drng_mgr.h`) with the
flags `fully_seeded`, `initiated` and `force_reseed`, a counter of the
generate operations left until the next reseed, the generate operations and
bits since the last full seed, and the time of the last seeding. Figure
@fig:sm-drng shows the states of an instance other than the prediction
resistance one; "reseed due" and "budget spent" are predicates over the
counters, not stored states.

#figure(
  image("../figures/fsm-drng.svg", width: 88%),
  caption: [States of a #ac("DRNG") instance],
) <fig:sm-drng>

- Seeding: every injection resets the counter of generate operations and the
  time. Only an injection that reaches the fully seeded level sets
  `fully_seeded` and clears the counts since the last full seed. An instance
  that is not fully seeded is seeded by the emergency reseeding of section
  @sec:architecture, which repeats collections until the level is reached or
  the entropy sources deliver nothing more.

- Reseed due: the counter of $2^20$ generate operations ran out, the reseed
  interval elapsed, the bit threshold was reached, or a reseed was forced
  (`esdm_drng_force_reseed`, a failed seed operation of the #ac("DRNG")). A
  node #ac("DRNG") instance is then reseeded by the reseed worker, the
  initial one by the next request or by the worker.

- Reseed with the time only: when the entropy sources hold less than the
  seed needs, the injection carries the current time alone. It clears the
  counter and the time, but neither sets nor clears `fully_seeded`, and it
  does not clear the bits since the last full seed. An instance in this
  situation stays in the state "reseed due" as far as the bit threshold is
  concerned.

- Loss of the seed: after $2^30$ generate operations or the maximum of bits
  without a full reseed, the instance returns to not fully seeded
  (`esdm_unset_fully_seeded`). The count of generate operations advances at
  each injection that is not a full one, by the operations since the
  injection before it.

- Budget spent: a node #ac("DRNG") instance whose output budget is used up
  while the reseed worker runs keeps its flag but serves nothing until the
  worker reseeds it; requests are served by the initial instance meanwhile.

#par(first-line-indent: 0pt)[The prediction resistance instance has three
states of its own: not initiated, fresh and spent. Every block of a request
seeds it under its lock; if the collection does not initiate it, the request
ends without data. A block delivers at most as many bits as the seeding
injected, less the oversampling, and the generate operation sets the
instance to spent again. The instance has no reseed worker, no reseed
threshold and no limit of generate operations: its output never rests on an
older seed.]

=== The Self Test Verdict <sec:sm-selftest>

The verdict of the crypto self tests is one variable,
`esdm_selftest_result` (`esdm/esdm_selftest.c`), with three values (figure
@fig:sm-selftest). Every pass of the self tests – at initialization, every
10 minutes, on demand over the privileged #ac("RPC") interface – records its
outcome: a pass moves the verdict from undone to passed and otherwise changes
nothing; a failure sets it to failed from any value. Failed is final for the
life of the process. Output requires the verdict passed, so that the undone
state gates the output like the failed one; seeding is refused only once the
verdict is failed. The operational state of section @sec:sm-esdm is not
changed by a failure: the #ac("ESDM") stays operational and refuses output.

#figure(
  image("../figures/fsm-selftest.svg", width: 88%),
  caption: [States of the self test verdict],
) <fig:sm-selftest>

=== Delivery of an Entropy Source <sec:sm-es>

An entropy source that reads a device or a provider can fail and recover.
Figure @fig:sm-es shows the two machines the #ac("ESDM") keeps for this:
that of the #ac("HWRAND") and the #ac("TPM") 2.0 entropy source, and that of
the external entropy source. A source in a state without credit reports no
entropy, and what it still delivers enters the #ac("DRNG") as additional
input.

#figure(
  image("../figures/fsm-es-delivery.svg", width: 92%),
  caption: [Delivery states of the device and the external entropy
    sources],
) <fig:sm-es>

- #ac("HWRAND"), #ac("TPM") 2.0: a read that fails or delivers nothing
  within 2 seconds marks the source failed. A failed source is not read for
  seeding; the monitor probes it at most every 10 seconds and returns it to
  the delivering state when a probe succeeds. A read still in progress when
  its deadline passes is abandoned, and further requests find the reader
  busy until it ends.

- External entropy source: a connection is credited only after the provider
  passed its self test. An error of a read withholds the credit until the
  provider delivers again; a timeout of 2 seconds or a violation of the
  protocol drops the connection, which is set up again after 5 seconds. A
  status query that is not answered within 500 ms is not repeated for a
  minute; requests for entropy resume with the next connection.

- #ac("CPU") and Jitter #acs("RNG"): a failed read withholds the credit
  until the next successful read. These sources are read on every seeding,
  so they recover at once; a failed collector of the Jitter #acs("RNG")
  withholds the credit of the whole entropy source.

- Each entropy source also keeps the outcome of its own self test: a source
  whose self test failed is credited with no entropy until a later self
  test passes.

=== Health Tests of the Kernel Module <sec:sm-health>

In #ac("FIPS") mode, each entropy source of the kernel module has a startup
test: a counter of #ac("APT") windows that still have to pass
(`sp80090b_startup_blocks` in `kernel/esdm_es/esdm_health.c`). Figure
@fig:sm-health shows its states. Two windows of 512 timestamps make the
startup test. A failure of the #ac("RCT") or the #ac("APT") sets the counter
to three: the window the failure fell into, which does not count, and a new
startup test. The rings are reset at the first failure of a window and again
when that window completes, so that nothing collected around a failure is
delivered. While a change of the counter and its reset are in progress, the
startup test counts as not passed (section @sec:fv-kernel-es).

#figure(
  image("../figures/fsm-health.svg", width: 78%),
  caption: [States of the startup test of an entropy source of the kernel
    module],
) <fig:sm-health>

The entropy source collects timestamps in every state, but delivers entropy
in the passed state only: the reader checks the state before it collects
and again after the last block (section @sec:dp-irq). A failure that reaches
the cut-off of a permanent failure restarts the #ac("RCT") and the
#ac("APT") in addition, and panics the kernel if the module was loaded with
`esdm_panic_on_permanent_health_failure`. Outside of #ac("FIPS") mode the
machine does not run, and the startup test counts as passed.

The timestamps pass a second machine first: the #ac("GCD") of the timer is
unknown until 100 timestamps are collected, during which the timestamps are
used undivided; it is then known, or found too coarse (1,000 or more), in
which case the entropy sources credit no entropy. A reset of an entropy
source returns the #ac("GCD") to unknown. Once a timer was found too coarse,
the kernel module credits no entropy until it is loaded again.

=== Further State Machines <sec:sm-other>

Three further machines are described where they belong: the start-up of
`esdm-server` up to the privilege drop in figure @fig:server-startup, its
supervisor in section @sec:fv-supervisor, and the operational flag and the
connections of the kernel module `esdm_cdev` in sections @sec:fv-kernel-cdev
and @sec:fv-kernel-cdev-conn. An #ac("RPC") connection of the server has no
state beyond open and closed: a request is read, carried out and answered
within one event, and a connection idle for the idle timeout is closed.

== Cryptographic Primitives Used By ESDM <sec:crypto>

The next subsections explain the cryptographic primitives the #ac("ESDM") may
use.

=== Crypto Backends <sec:backends>

The #ac("ESDM") obtains its cryptographic primitives – the #ac("DRNG"), the
conditioning hash and the SHAKE256 of the XDRBG-256 pools – from the crypto
backend selected with the meson option `crypto_backend` as listed in table
@tab:backends. The glue code is in `esdm/esdm_*.c` and
`esdm/esdm_botan.cpp`, the built-in primitives in `crypto`.

#figure(
  {
    set par(justify: false, first-line-indent: 0pt)
    set text(size: 9pt)
    show table.cell: set align(left + top)
    table(
      columns: (auto, 1fr, auto, auto),
      table.header(
        [Backend], [#ac("DRNG", cap: true)], [Hash], [SHAKE256],
        table.hline(stroke: 0.8pt),
      ),
      [builtin (default)],
      [#ac("SP", cap: true) 800-90A Hash #ac("DRBG") with SHA-512
      (`drng_hash_drbg`, default) or
        ChaCha20 #ac("DRNG") (`drng_chacha20`)],
      [SHA-512 (`hash_sha512`) or \ SHA3-512 (`hash_sha3_512`)],
      [builtin],
      [OpenSSL 3.0 \ or later],
      [#ac("SP", cap: true) 800-90A Hash #ac("DRBG") with SHA-512 (default),
      #ac("CTR") #ac("DRBG") with AES-256 or
        #ac("HMAC") #ac("DRBG") with SHA-512 (`openssl_drng_type`)],
      [SHA3-512], [OpenSSL],
      [Botan 3.2 \ or later],
      [#ac("SP", cap: true) 800-90A #ac("HMAC") #ac("DRBG") with SHA-512
      (default) or ChaCha20 #ac("RNG"), with fast
        key erasure with Botan 3.14 or later (`botan_drng_type`)],
      [SHA3-512], [Botan],
      [GnuTLS 3.6.7 \ or later],
      [#ac("SP", cap: true) 800-90A #ac("CTR") #ac("DRBG") with AES-256 and the
      Block_Cipher_df derivation
        function added by the #ac("ESDM")],
      [SHA-512], [nettle 3.6 \ or later],
      [leancrypto @leancrypto 1.6 \ or later],
      [XDRBG-256 with SHAKE256],
      [SHA3-512], [leancrypto],
    )
  },
  caption: [#ac("ESDM", cap: true) Crypto Backends],
) <tab:backends>

The library-based backends can use assembler or even hardware-accelerated
cipher primitives. Such support should relieve the #ac("CPU") of processing the
cryptographic operations as much as possible.

#paragraph[Callback interface][The #ac("ESDM") reaches every primitive
through a table of callbacks (`esdm/esdm_crypto.h`), never through a library
call of its own. The seed management – entropy accounting, thresholds,
locking – is therefore the same code for every backend, and a backend can be
replaced, e.g. by a library validated for #ac("FIPS") 140-3, without touching
it (sections @sec:flexible-design and @sec:adding-backend). A #ac("DRNG") is
defined by:]

```c
struct esdm_drng_cb {
	const char *(*drng_name)(void);
	int (*drng_selftest)(void);
	int (*drng_alloc)(void **drng, uint32_t sec_strength);
	void (*drng_dealloc)(void *drng);
	int (*drng_seed)(void *drng, const uint8_t *inbuf, size_t inbuflen,
			 const uint8_t *addtl, size_t addtllen);
	ssize_t (*drng_generate)(void *drng, uint8_t *outbuf, size_t outbuflen);
};
```

#par(first-line-indent: 0pt)[`struct esdm_hash_cb` defines the hash of the
compression of the #ac("CPU") entropy source in the same way
(`hash_init()`, `hash_update()`, `hash_final()`, `hash_desc_zero()` and the
allocation),
`struct esdm_xof_cb` the SHAKE256 of the XDRBG-256 pools (`esdm/crypto/esdm_xof.h`).
The builtin backend fills the table with its Hash #ac("DRBG")
(`esdm/esdm_builtin_hash_drbg.c`), and the build selects one table at compile
time (`esdm/esdm_drng_mgr.c`), so that no backend can be switched at runtime:]

```c
const struct esdm_drng_cb esdm_builtin_hash_drbg_cb = {
	.drng_name = esdm_hash_drbg_name,
	.drng_selftest = esdm_hash_drbg_selftest,
	.drng_alloc = esdm_hash_drbg_alloc,
	.drng_dealloc = esdm_hash_drbg_dealloc,
	.drng_seed = esdm_hash_drbg_seed,
	.drng_generate = esdm_hash_drbg_generate,
};

const struct esdm_drng_cb *esdm_default_drng_cb =
#if defined(ESDM_DRNG_HASH_DRBG)
	&esdm_builtin_hash_drbg_cb;
#elif defined(ESDM_BOTAN)
	&esdm_botan_drbg_cb;
/* ... ChaCha20, GnuTLS, leancrypto, OpenSSL */
#endif
```

#par(first-line-indent: 0pt)[`drng_seed()` receives $T_n$ and $U_n$ of a
seeding (section @sec:seeding-injection). The self test of a #ac("DRNG")
compares its output for a known seed with the known answer and, as a negative
test, requires the output for a seed differing in its first byte to differ
(`esdm_hash_drbg_selftest`); section @sec:self-tests states when the self tests
run.]

=== DRBG <sec:drbg>

With the #ac("SP") 800-90A #ac("DRBG") implementation, the default #ac("DRBG")
of the #ac("ESDM") is the built-in Hash #ac("DRBG") with SHA-512
(`crypto/hash_drbg.c`). The crypto backends listed in section @sec:backends
provide other #ac("DRBG") types.

The #ac("ESDM") always instantiates all #ac("DRNG", pl: true) with the same
#ac("DRNG") type.

The sections above explain the seed and reseed input of the #ac("DRBG").
Mathematically speaking, the #ac("ESDM") mixes the seed and reseed data obtained
from the entropy sources and the #acs("ESDM")-external sources into the
#ac("DRBG") with the #ac("DRBG") instantiate and reseed functions defined by
#ac("SP") 800-90A, and the data of the entropy sources configured with an
entropy rate of zero as additional input.

The #ac("DRBG") generates output with the #ac("DRBG") “generate” function
specified in #ac("SP") 800-90A. It generates two types of output, discussed in
the next subsections.

#paragraph[`/dev/urandom` and `esdm_get_random_bytes`][Users obtaining data via
the `/dev/urandom` interface or the `esdm_get_random_bytes` #ac("API") receive
data from the #ac("DRNG") “generate” function. That is, the #ac("DRNG")
generates the requested random numbers on demand.]

The #ac("ESDM") segments data requests on either interface into blocks of at
most 4096 bytes, or $2^16$ bytes in a build limiting the output without a full
reseed. It invokes the #ac("DRNG") “generate” function individually for each
block. According to #ac("SP") 800-90A, the maximum output per
#ac("DRBG") “generate” request is $2^19$ bits or $2^16$ bytes, which the
#ac("ESDM") does not exceed.

In addition to the slicing of the requests into blocks, the #ac("ESDM") counts
the #ac("DRNG") “generate” requests since the last reseed. According to
#ac("SP") 800-90A, the number of allowed requests before a forced reseed is
$2^48$ – a very high number. The #ac("ESDM") uses a much more conservative
maximum of $2^20$ requests. When the counter reaches that threshold, the
#ac("ESDM") reseeds the #ac("DRBG") with the operation documented in section
@sec:seeding before the next #ac("DRNG") “generate” operation commences – the
reseed worker reseeds a per-#acs("CPU") #ac("DRNG") instance instead while it
continues to generate.

The reseed threshold and the cap on the random numbers generated with one
#ac("DRNG") “generate” operation ensure that the #ac("DRNG") operates in
compliance with all constraints of #ac("SP") 800-90A.

#paragraph[`/dev/random` and `esdm_get_random_bytes_full`][The random numbers
generated for `/dev/random` and `esdm_get_random_bytes_full` have a special
property: these interfaces only provide data once the #ac("ESDM") is fully
seeded as outlined in section @sec:seed-levels. In addition, the #ac("ESDM")
generates random numbers only after it is fully initialized, including the
completion of the #ac("SP") 800-90B health test if it gathers entropy from
internal entropy sources.]

=== ChaCha20 DRNG <sec:chacha20>

If the #ac("SP") 800-90A #ac("DRBG") is not desired, the #ac("ESDM") can use a
standalone C implementation of ChaCha20 as #ac("DRNG") (meson option
`drng_chacha20` of the builtin crypto backend).

The ChaCha20 #ac("DRNG") consists of the components discussed below. All of them
rest on a state defined by @rfc7539, section 2.3.

Figure @fig:chacha20 characterizes the operation of the ChaCha20 #ac("DRNG"). It
outlines the initialization of the #ac("DRNG"), its seeding with the state
update operation and one generate operation that is requested to obtain more
than 512 bits of data.

#figure(
  image("../figures/chacha20-drng.svg", width: 90%),
  caption: [ChaCha20 #ac("DRNG") Operation],
) <fig:chacha20>

#paragraph[State Update Function][The state update function updates the
state of the ChaCha20 #ac("DRNG"). The function `esdm_cc20_drng_update` in
`crypto/chacha20_drng.c` implements it by]

+ XORing the key-sized part of the last output block of the generate
  operation that was not handed out with the key part of the ChaCha20 state,
  or,
+ if less than a key-sized part of it is left or no output block was
  generated, generating one output block of ChaCha20 and XORing its first
  key-sized part with the key part of the ChaCha20 state.

#par(first-line-indent: 0pt)[In addition, the function increments the nonce
part of the state by one to meet the uniqueness requirement of @rfc7539
chapter 4.]

#paragraph[Seeding Operation][The seeding operation processes a seed of
arbitrary length. It segments the seed into chunks of the ChaCha20 key size
and processes them sequentially in these steps:]

+ #acs("XOR") the key-sized seed chunk into the ChaCha20 key location
  of the state.
+ Invoke the state update function with a fresh output block.
+ Repeat the previous steps for all unprocessed key-sized seed chunks.

#par(first-line-indent: 0pt)[If the last seed chunk is smaller than the
ChaCha20 key size, only the available bytes of the seed are XORed into the key
location. This is logically equivalent to padding the right side of the seed
with zeroes until that block is equal in size to the ChaCha20 key. The
seeding operation processes the additional input the same way after the
seed.]

The invocation of the state update function is meant to eliminate any
possible dependencies between the seed chunks.

#paragraph[Generate Operation][The random numbers from the ChaCha20 #ac("DRNG")
are the data stream produced by ChaCha20, i.e. without the final #ac("XOR") of
the data stream with plaintext. Thus, the #ac("DRNG") generate function
invokes ChaCha20 to produce the data stream as often as needed for the requested
number of random bytes.]

After the generate operation concludes, the #ac("DRNG") invokes the state update
function to ensure enhanced backward secrecy of the ChaCha20 state that was
used to generate the random numbers.

=== XDRBG-256 <sec:xdrbg>

The auxiliary pool and the conditioning pools of the #ac("eBPF") entropy sources
are each an XDRBG-256 – the #ac("XDRBG") over SHAKE256 with a state of 512 bits
as specified in section @sec:dp-aux. `esdm/crypto/esdm_xdrbg.c` implements it
with the SHAKE256 of the crypto backend (`struct esdm_xof_cb`). The kernel
module `esdm_es` compiles the same implementation over the SHAKE256 of the
kernel, where the kernel provides it (`CONFIG_CRYPTO_LIB_SHA3`), to
post-process the timestamps of its entropy sources. The additional input
$alpha$ of at most 84 bytes separates the different pools. One generate step
produces at most 344 bytes; a longer output takes several steps, each one
with the state the previous one left.

== ESDM External Interfaces <sec:interfaces>

The #ac("ESDM") provides these interfaces; table @tab:interfaces gives for each
the path that serves it, whether it waits, and what it serves while the
#ac("ESDM") server cannot be reached:

- #ac("ESDM", cap: true) library #ac("API"): The #ac("API") is documented in
  `esdm.h`.

- #ac("ESDM", cap: true) server #ac("RPC") #ac("API"): The #ac("RPC") #ac("API")
  is documented in `esdm_rpc_client.h`, see section @sec:rpc.

- #ac("EGD", cap: true) interface: See section @sec:egd.

- `/dev/random` and `/dev/urandom` device files: See the Linux man page
  `random(4)`. In addition, when a caller opens the `/dev/random` or the
  `/dev/urandom` device of the #ac("CUSE") daemons with the `O_SYNC` flag, the
  #ac("DRNG") is managed with prediction resistance enabled: the #ac("ESDM")
  #ac("API") call `esdm_get_random_bytes_pr` services the request. Therefore,
  all considerations outlined for this #ac("API") apply to both devices with
  `O_SYNC` as well. If the #ac("ESDM") server cannot be reached or answers with
  an error – for `/dev/urandom` also while the #ac("ESDM") is not yet
  operational – the #ac("CUSE") daemons serve the request from the device file
  of the kernel. The privileged #ac("IOCTL", pl: true) require the capability
  `CAP_SYS_ADMIN` of the caller. `RNDADDTOENTCNT` refuses a negative count
  with `EINVAL`, `RNDADDENTROPY` a negative size, a negative count and a
  count above 8 bits per byte of data. When the #ac("RPC") call of one of
  these two #ac("IOCTL", pl: true) fails with another error than a timeout,
  the daemon issues the #ac("IOCTL") on the device file of the kernel and
  returns its result; a daemon that has no device file of the kernel open
  returns the error of the #ac("RPC") call.

- `/proc/sys/kernel/random/*` interfaces: See the Linux man page `random(4)` and
  the description of `esdm-proc` in chapter @sec:design.

- getrandom and getentropy #ac("API", pl: true): See the Linux man pages
  `getrandom(2)` and `getentropy(3)`. The flags of `getrandom(2)` select the
  #ac("ESDM") #ac("API") call servicing the request:

  - `GRND_INSECURE`: `esdm_get_random_bytes`,
  - `GRND_RANDOM`: `esdm_get_random_bytes_pr`,
  - `GRND_SEED` (0x0010, a flag of the #ac("ESDM")): `esdm_get_seed` to obtain
    the data of the entropy sources directly, where the #ac("ESDM") flag
    `GRND_FULLY_SEEDED` (0x0020) indicates that the #ac("DRNG") of the caller is
    already fully seeded,
  - otherwise: `esdm_get_random_bytes_full`.

  With `GRND_NONBLOCK`, the non-blocking variants of these calls are used.
  If the #ac("ESDM") server cannot be reached or answers with an error – e.g.
  for `GRND_INSECURE` while the #ac("ESDM") is not yet operational, but not
  `EAGAIN` under `GRND_NONBLOCK`, which is returned to the caller – the
  `getrandom` system call of the kernel serves the request; a `GRND_SEED`
  request fails instead.

- OpenSSL RAND providers (meson option `openssl-rand-provider`):
  `libesdm-rng-provider.so` serves the RAND algorithms of OpenSSL from the
  #ac("ESDM") over the #ac("RPC") interface and honors the prediction resistance
  flag of OpenSSL with `esdm_get_random_bytes_pr`, `libesdm-rng-provider-pr.so`
  serves all requests with it, `libesdm-seed-src-provider.so` provides the
  #ac("ESDM") as seed source. `libesdm-egd-provider.so` and
  `libesdm-egd-provider-pr.so` obtain the data over the #ac("EGD") interface:
  the former from the socket `esdm-egd.socket`, refusing requests asking for
  prediction resistance, the latter from the socket `esdm-egd-pr.socket`.

- Kernel character devices of the kernel module `esdm_cdev`:
  `/dev/esdm_random` is served like `esdm_get_random_bytes_full`, waiting
  until the #ac("ESDM") is operational, `/dev/esdm_urandom` like
  `esdm_get_random_bytes`; opened with `O_SYNC`, either one is served from
  the prediction resistance #ac("DRNG"), as `/dev/esdm_pr` always is – for
  readers that cannot open with `O_SYNC`, such as the virtio-rng backends of
  QEMU and Cloud Hypervisor. `/proc/esdm` offers the files
  `entropy_avail`, `poolsize`, `write_wakeup_threshold`,
  `urandom_min_reseed_secs`, `status` and `status.json`. The module supports
  the #ac("IOCTL", pl: true) of the random devices of the kernel. While the
  #ac("ESDM") cannot be reached, nothing is served from elsewhere: the requests
  wait or fail.

- External entropy sources: the #ac("ESDM") server reads the providers of
  external entropy sources over a Unix domain socket, see section @sec:ext-es.

- Status: See section @sec:status.

=== RPC Interface <sec:rpc>

The #ac("ESDM") server provides two #ac("RPC") interfaces on Unix domain sockets
of the type `SOCK_SEQPACKET`: the unprivileged one on `esdm-rpc-unpriv.socket`,
which everybody may access, and the privileged one on `esdm-rpc-priv.socket`,
which only root can access and whose operations the server only executes for a
caller with the user #ac("ID") 0, as reported by `SO_PEERCRED`. The
#ac("RPC") interfaces separate the security domains: the consumers, the
#ac("CUSE") daemons and the server run as processes of their own and share
nothing but these sockets.

#paragraph[Why protobuf][The messages are protobuf messages, described by
schemas (`service-rpc/service/pb/*.proto`) from which protoc-c generates the C
code. This has four consequences the #ac("ESDM") relies on:]

- No parser written by hand for most messages: `protobuf_c_message_unpack`
  decodes a request with bounds checks and fails on a malformed one.

- A custom allocator: protobuf-c unpacks into a fixed buffer of the worker
  thread, which the server wipes after each request. That was the reason to
  replace the transport protobuf-c-rpc by a server of its own (version 0.3.0):
  protobuf-c-rpc allocated memory per request that could not be wiped, and it
  was not thread-aware. The wire protocol stayed that of protobuf-c-rpc.

- Compatibility: a decoder skips the fields it does not know, so a message of
  a newer peer still decodes. The calls are addressed by their index in the
  service definition, to which new calls are only appended, so an installed
  client keeps invoking the call it was built for.

- Portability: libprotobuf-c is a C library without dependencies of its own,
  available on every #ac("POSIX") system the #ac("ESDM") targets, and the
  external entropy source protocol uses the same toolchain (section
  @sec:ext-es).

#par(first-line-indent: 0pt)[The responses to the random number requests are
the exception: their encoder and decoder are written by hand, to copy the
random bytes once instead of twice. They check at runtime that
`RandValResponse` still has the expected two fields and fall back to the
generated code otherwise, and a fuzz harness covers them (chapter
@sec:testing).]

#paragraph[Framing][One datagram carries one message: a header of 32-bit
little-endian fields, followed by the protobuf message
(`service-rpc/service/esdm_rpc_protocol.h`). A datagram holds at most 64 KiB,
of which at most 65,512 bytes are payload data. A status call renders at most
65,504 bytes (`ESDM_RPC_MAX_STATUS`), the terminating zero byte included, so
that its response fits into one message also with a negative return code.]

```c
struct esdm_rpc_proto_cs_header {	/* client to server */
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));

struct esdm_rpc_proto_sc_header {	/* server to client */
	uint32_t status_code;
	uint32_t method_index;
	uint32_t message_length;
	uint32_t request_id;
} __attribute__((packed));
```

#par(first-line-indent: 0pt)[The client sends the request identifier 0; it
matches the responses to its requests by their order, as a connection carries
one request at a time.]

#paragraph[Messages][The three random number calls share one request and one
response (`unpriv_access.proto`), a privileged call has messages of its own
(`priv_access.proto`):]

```protobuf
message GetRandomBytesRequest {
	uint64 len = 1;          /* number of random bytes requested */
}

message RandValResponse {
	int64 ret = 1;           /* bytes generated, or a negative errno */
	bytes randval = 2;
}

message RndAddEntropyRequest {
	bytes randval = 1;
	uint32 entcnt = 2;       /* entropy claimed, in bits */
}
```

#par(first-line-indent: 0pt)[Table @tab:rpc-wire shows the datagrams of
`esdm_rpcc_get_random_bytes(buf, 32)`, the call `RpcGetRandomBytes` with the
index 5 of the service `UnprivAccess`. A protobuf field
starts with a tag, the field number shifted left by three bits ORed with the
wire type: 0x08 is field 1 as a varint, 0x12 field 2 as a length-delimited
byte string.]

// Kept on one page: the table is short, and broken it can leave its caption
// alone at the foot of a page.
#block(breakable: false)[#figure(
  table(columns: (auto, auto, 1fr), align: left + horizon,
    table.header([Bytes], [Field], [Meaning]),
    table.cell(colspan: 3)[_Request, 14 bytes_],
    [`05 00 00 00`], [`method_index`], [`RpcGetRandomBytes`],
    [`02 00 00 00`], [`message_length`], [2 bytes of protobuf],
    [`00 00 00 00`], [`request_id`], [0],
    [`08 20`], [`len`], [field 1, varint 32],
    table.cell(colspan: 3)[_Response, 52 bytes_],
    [`00 00 00 00`], [`status_code`], [success],
    [`05 00 00 00`], [`method_index`], [`RpcGetRandomBytes`],
    [`24 00 00 00`], [`message_length`], [36 bytes of protobuf],
    [`00 00 00 00`], [`request_id`], [0],
    [`08 20`], [`ret`], [field 1, varint 32],
    [`12 20 …`], [`randval`], [field 2, 32 bytes, followed by them],
  ),
  caption: [Datagrams of a request for 32 random bytes],
) <tab:rpc-wire>]

#paragraph[Validation][The server discards a request whose header or length
does not match the datagram, whose message exceeds the maximum size, whose
method index is unknown or whose message does not decode, and closes the
connection without an answer (`esdm_rpcs_process` in
`service-rpc/server/esdm_rpc_server.c`). The handlers check the content: a
privileged call by a caller other than root fails with `-EPERM`, a prediction
resistance request for more than 32 bytes with `-EINVAL`, an insertion of
entropy that claims more bits than the data holds with `-EINVAL`. The client
library never repeats a call that changes the state of the #ac("ESDM") –
inserting data, clearing the entropy, reseeding, running the self tests – after
a timeout or a reset of the connection, as the server may have executed it.]

- Unprivileged operations: obtaining random numbers (`RpcGetRandomBytes`,
  `RpcGetRandomBytesFull`, `RpcGetRandomBytesPr`), seed data (`RpcGetSeed`),
  writing data without entropy (`RpcWriteData`), the status (`RpcStatus`,
  `RpcStatusJson`, `RpcDrngStatusJson`, `RpcJentStatus`), the seeding state
  (`RpcIsFullySeeded`, the result of `esdm_state_fully_seeded`: whether the
  initial #ac("DRNG") instance is fully seeded) and the entropy levels and
  settings of the Linux interfaces.

- Privileged operations: inserting entropy (`RpcRndAddEntropy`,
  `RpcRndAddToEntCnt`), clearing the entropy estimates (`RpcRndClearPool`),
  forcing a reseed (`RpcRndReseedCRNG`), changing the Linux interface settings,
  running the self tests (`RpcSelftest`) and, only in a build with the meson
  option `testmode` or of the build type `debug`, setting the entropy rates of
  the entropy sources (`RpcSetEsRate`).

#par(first-line-indent: 0pt)[The server never waits within a request: it
serves the random numbers with the non-blocking #ac("API") calls, and the client
library waits and asks again. A prediction resistance request obtains at most
32 bytes; a caller with the user #ac("ID") 0 that found the prediction
resistance #ac("DRNG") busy has the next turn, the other callers are turned away
for up to 3 seconds meanwhile. One worker thread serves the privileged
interface, and one worker thread per #ac("DRNG") instance serves the
unprivileged one, each serving its connections one request after the other in an
event loop of its own (`service-rpc/server/esdm_rpc_server.c`).]

=== EGD Interface <sec:egd>

The #ac("ESDM") server optionally serves the protocol of the Entropy Gathering
Daemon on Unix domain sockets of the type `SOCK_STREAM`, accessible by all
users: `esdm-egd.socket`, enabled with the systemd socket unit
`esdm-server-egd.socket` or the option `--egd_socket` of the server
(`/run/esdm-egd.socket` by default, meson option
`esdm-server-egd-socket-path`), and `esdm-egd-pr.socket`, enabled with the
systemd socket unit `esdm-server-egd-pr.socket` or the option
`--egd_socket_pr` (`/run/esdm-egd-pr.socket` by default, meson option
`esdm-server-egd-pr-socket-path`). As the #ac("EGD") protocol cannot ask for
prediction resistance per request, it is a property of the socket: the second
socket serves the reads of the #ac("EGD") protocol from the prediction
resistance #ac("DRNG"). Both sockets offer the commands of the #ac("EGD")
protocol (`service-egd/esdm_egd_protocol.h`, figures @fig:egd-read and
@fig:egd-write):

- 0x00: the available entropy in bits,
- 0x01: reading up to the requested number of bytes without blocking,
- 0x02: reading the requested number of bytes, blocking,
- 0x03: writing data with an entropy claim into the auxiliary pool – the
  claim is only honored for a caller with the user #ac("ID") 0 and capped at
  8 bits per byte,
- 0x04: the #ac("PID") of the server.

#par(first-line-indent: 0pt)[A transfer is limited to 255 bytes. The server
serves the random numbers from `esdm_get_random_bytes_full_noblock`, or
`esdm_get_random_bytes_pr_noblock` on the second socket; its event loop,
which never waits within a request, completes a blocking read.
What the #ac("EGD") protocol cannot express, the #ac("ESDM") offers with
commands of its own, 0xe0 to 0xec (figures @fig:egd-state, @fig:egd-priv and
@fig:egd-bulk): prediction resistant reads, a read with the semantics of
`/dev/urandom` (`esdm_get_random_bytes`), the state of the
#ac("ESDM"), the status as text and as #ac("JSON") document, reads and
insertions of up to 64 KiB and, only for a caller with the user #ac("ID") 0 as
reported by `SO_PEERCRED`, crediting entropy to the auxiliary pool, clearing its
entropy, reseeding the #ac("DRNG", pl: true), and setting
`write_wakeup_threshold` and `urandom_min_reseed_secs`.]

#paragraph[Wire format][A message is a sequence of bytes without padding;
strings carry no terminating NUL. Numbers are unsigned and big-endian, a status
is signed in two's complement: 0 or a negative errno, `-EPERM` for a privileged
command of a caller other than root. Bit 0 of the ruler is the most significant
bit of the first byte. A field drawn open to the right has the variable length
its label names. The protocol carries no request identifiers: the server
answers the requests of a connection in their order, one at a time.]

#figure(kind: image, exchanges(
  exchange([`0x00` entropy count],
    [Request], (command("0x00"),),
    [Reply], (field(32)[Available entropy in bits],),
  ),
  exchange([`0x01` read without blocking, likewise `0xe0` and `0xe2`],
    [Request], (command("0x01"), field(8)[Length]),
    [Reply], (field(8)[Count], field(auto)[Count bytes of random numbers]),
  ),
  exchange([`0x02` read, blocking, likewise `0xe1`],
    [Request], (command("0x02"), field(8)[Length]),
    [Reply], (field(auto)[Length bytes of random numbers],),
  ),
), caption: [Entropy count and reads of the #ac("EGD") protocol]) <fig:egd-read>

#figure(kind: image, exchanges(
  exchange([`0x03` write entropy],
    [Request], (command("0x03"), field(16)[Entropy claim in bits],
      field(8)[Length], field(auto)[Length bytes of data]),
    [Reply], none,
  ),
  exchange([`0x04` get #acs("PID")],
    [Request], (command("0x04"),),
    [Reply], (field(8)[Length],
      field(auto)[#acs("PID") in Length decimal digits]),
  ),
), caption: [Write and #ac("PID") commands of the #ac("EGD") protocol])
<fig:egd-write>

#paragraph[Short and failed requests][The protocol has no error reply. A
non-blocking read answers with fewer bytes than requested when the #ac("DRNG")
delivers fewer – the prediction resistance #ac("DRNG") hands out no more than
its entropy sources just delivered – and with none while the #ac("ESDM") is not
operational or after a failed generation; one that finds the regular
#ac("DRNG", pl: true) waiting for a reseed is held back until the reseed, for
at most 1 second. A blocking read is answered once all requested bytes are
available, a request for 0 bytes not at all; a failed generation closes the
connection. A text status beyond 65,536 bytes is cut off there, a #ac("JSON")
status beyond it is replaced by one of length 0. An unknown command byte, a read
byte of 0xeb other than 0x01, 0xe0 or 0xe2 and a length of 0xeb or 0xec above
65,536 bytes leave the stream out of sync: the server closes the connection
without a reply.]

#figure(kind: image, exchanges(
  exchange([`0xe3` get state],
    [Request], (command("0xe3"),),
    [Reply], (field(8)[N = 5],
      field(32, short: [Flags])[Flags: 1 operational, 2 fully seeded],
      field(32, short: [Entropy])[Entropy of the auxiliary pool in bits],
      field(32, short: [Size])[Size of the auxiliary pool in bits],
      field(32, short: [Threshold])[`write_wakeup_threshold` in bits],
      field(32, short: [Seconds])[`urandom_min_reseed_secs`]),
  ),
  exchange([`0xe4` status as text, likewise `0xe5` as #acs("JSON")],
    [Request], (command("0xe4"),),
    [Reply], (field(32)[Length, at most 65,536],
      field(auto)[Length bytes of the status]),
  ),
), caption: [State and status commands of the #ac("ESDM")]) <fig:egd-state>

#par(first-line-indent: 0pt)[The reply to 0xe3 starts with the number N of
the 32-bit fields that follow; later versions of the protocol only append
fields, and a client ignores the ones it does not know. The flag "fully
seeded" is the result of `esdm_state_fully_seeded`: the initial #ac("DRNG")
instance is fully seeded, while the instances of the nodes may still be
seeding.]

#figure(kind: image, exchanges(
  exchange([`0xe6` add to entropy count, likewise `0xe9` and `0xea`],
    [Request], (command("0xe6"),
      field(32, short: [Argument])[Argument: bits, seconds for `0xea`]),
    [Reply], (field(32)[Status],),
  ),
  exchange([`0xe7` clear pool, likewise `0xe8` reseed],
    [Request], (command("0xe7"),),
    [Reply], (field(32)[Status],),
  ),
), caption: [Privileged commands of the #ac("ESDM")]) <fig:egd-priv>

#figure(kind: image, exchanges(
  exchange([`0xeb` bulk read],
    [Request], (command("0xeb"), field(8)[Read: `0x01`, `0xe0`, `0xe2`],
      field(32, short: [Length])[Length, at most 65,536]),
    [Reply], (field(32)[Count], field(auto)[Count bytes of random numbers]),
  ),
  exchange([`0xec` bulk insert],
    [Request], (command("0xec"),
      field(32, short: [Length])[Length, at most 65,536],
      field(auto)[Length bytes of data]),
    [Reply], (field(32)[Status],),
  ),
), caption: [Bulk transfers of the #ac("ESDM")]) <fig:egd-bulk>

The client library `libesdm_egd_client` (`esdm_egd_client.h`) owns one
connection, serializes the requests on it and reconnects after a restart of
the server or a `fork()` of the caller. The OpenSSL providers
`libesdm-egd-provider.so` and `libesdm-egd-provider-pr.so` are based on it.
The kernel module `esdm_cdev` connects to `esdm-egd.socket` with a kernel
socket and uses the commands of the #ac("ESDM") to serve `/dev/esdm_random`,
`/dev/esdm_urandom`, `/dev/esdm_pr` and `/proc/esdm` together with the #ac("IOCTL", pl: true) of
the random devices of the kernel.

=== ESDM Status <sec:status>

The #ac("ESDM") keeps its status as #ac("JSON") documents (`esdm/esdm_info.c`):
the general status (`esdm_status_json`) with the version of the library, the
#ac("DRNG"), the security strength, the satisfied standards, the seeding state,
the entropy level, the state of every entropy source, the #ac("DRNG") instances,
the reseed worker and the periodic self tests, and the state of a single
#ac("DRNG") instance (`esdm_status_drng_json`, `esdm_status_drng_pr_json`). The
#ac("ESDM") renders the text form of the status (`esdm_status`) from the
#ac("JSON") document. It answers a request for a status that does not fit into
the buffer of the caller with `-EMSGSIZE`. The status is available via the
#ac("RPC") and the #ac("EGD") interfaces, `esdm-tool --status` and the files
`/proc/sys/kernel/random/esdm_type` and `/proc/esdm/status`. The status flags of
the satisfied standards are “#ac("FIPS") 140”, “DRG.3”, “DRG.4”, “SP800-90C”,
“NTG.1(2011)” and “NTG.1(2024)”. “NTG.1(2011)” refers to the superseded version
of #ac("AIS") 20/31 @ais2031-2011 and is kept for the consumers of the status;
this document covers version 3.0 only.

#paragraph[What the flags mean][The flags report how the #ac("ESDM") was
built and started, not that the running configuration meets the class. Table
@tab:status-flags gives the condition the code evaluates for each flag
(`esdm_status_json`, `esdm/esdm_drng_mgr.c`) and what the flag does not
check. Two flags report more than this document claims: “NTG.1(2011)”
appears in every build, and “DRG.4” appears in every build with the meson
option `ais2031_drg4`, also when non-physical entropy sources are credited,
which DRG.4 does not allow (section @sec:physical-es). An auditor therefore
reads the flags together with the entropy rates of the entropy sources in
the same status, as the worked examples of section @sec:examples do; the
flags alone prove no class. That the status over-reports is a defect of the
code, which this document records instead of repeating the claim.]

#figure(
  table(columns: (auto, 1.2fr, 1.4fr), align: left + horizon,
    table.header([Flag], [Condition in the code], [Not checked]),
    [#ac("FIPS") 140], [#ac("FIPS") mode is active (`fips140` build with the
      kernel in #ac("FIPS") mode, or forced)], [The entropy rates
      configured],
    [DRG.3], [Built with `ais2031_drg3` or `ais2031_drg4`], [The entropy
      sources credited],
    [DRG.4], [Built with `ais2031_drg4`], [Whether only physical entropy
      sources are credited],
    [SP800-90C], [The oversampling is in effect, and the build is not a
      DRG.3 build without DRG.4], [Whether the credited entropy sources
      have an #ac("SP") 800-90B validation],
    [NTG.1(2011)], [None: always listed], [Everything],
    [NTG.1(2024)], [Built with `ais2031_ntg1`, or the Jitter #acs("RNG")
      operates in its own NTG.1 mode], [Whether two entropy sources are
      configured with at least 240 bits each],
  ),
  caption: [Status flags of the satisfied standards and the conditions behind
    them],
) <tab:status-flags>

The #ac("ESDM") server also maintains a status shared memory segment with
semaphores that the #ac("CUSE") daemons and `libesdm_aux_client` use to learn
about the operational state and the need for entropy without an #ac("RPC") call.

== ESDM Self-Tests <sec:self-tests>

During its startup phase, the #ac("ESDM") self-tests all cryptographic
primitives with known-answer tests, each accompanied by negative tests,
implemented in `esdm/esdm_selftest.c`:

- the conditioning hash of the crypto backend,
- the XDRBG-256 together with its SHAKE256,
- the #ac("DRNG") including a reseed.

#par(first-line-indent: 0pt)[In addition, the #ac("ESDM") asks every entropy
source to test itself. A periodic worker repeats the self tests every 600
seconds; the privileged `esdm_rpcc_selftest` #ac("RPC") #ac("API") call or
`esdm-tool --selftest` triggers them as well. The #ac("ESDM") generates no
random numbers and hands out no seed data while the cryptographic self tests
have not passed; their failure is final. The #ac("ESDM") logs an entropy
source failing its self test, reports it in the status and credits it with no
entropy until a later self test passes.]

In #ac("FIPS") mode, i.e. in a build with the meson option `fips140` if
`/proc/sys/crypto/fips_enabled` is set or the environment variable
`ESDM_SERVER_FORCE_FIPS` is present, the #ac("ESDM") performs a power-on self
test before it starts (`esdm/fips.c`): an #acs("HMAC")-SHA256 known-answer test
and the integrity test of the executable and of the #ac("ESDM") library against
the reference value of the #ac("HMAC") file next to each of them, which
`esdm-tool --fips-targetfile` and `--fips-checkfile` create. A missing
reference value counts as a failed integrity test.

== ESDM Test Interfaces <sec:test-interfaces>

Compiling the kernel module `esdm_es` with `BUILD_TESTING=1` enables these
interfaces for the entropy sources built into the module, which allow direct
access to non-deterministic aspects. These interfaces are not advisable on
production systems. Yet, only the root user can access them, which is
considered to protect them against misuse. In addition, the #ac("ESDM") does not
use any data obtained through these interfaces to feed the entropy pool. Thus,
even when these interfaces stay enabled on production systems, the impact on
security is considered limited. The interfaces provide no data while the
lockdown mode of the kernel locks down the debugfs.

- Interrupt Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_hires` allows reading
    the raw unconditioned noise data collected while the read operation is in
    progress: it provides the time deltas of the events collected by the
    #ac("ESDM") that are otherwise injected into the entropy pool. With the
    module parameter `boot_raw_hires_test=1`, the module stores the time deltas
    of the first 1,024 events recorded by the #ac("ESDM"). The first read of the
    `esdm_raw_hires` file after loading the module then provides this data.

  - The interface `/sys/kernel/debug/esdm_es/esdm_irq_perf` allows reading
    the number of cycles used to process one interrupt event, which measures
    the performance impact of the #ac("ESDM") on the interrupt handler. With the
    module parameter `boot_irq_perf=1`, the module stores the performance
    data of the first 1,024 events recorded by the #ac("ESDM"). The first read
    of the `esdm_irq_perf` file after loading the module then provides this
    data.

- Scheduler Entropy Source:

  - The interface `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires` allows
    reading the raw unconditioned noise data collected while the read
    operation is in progress: it provides the time deltas of the events
    collected by the #ac("ESDM") that are otherwise injected into the entropy
    pool. With the module parameter `boot_raw_sched_hires_test=1`, the module
    stores the time deltas of the first 1,024 events recorded by the
    #ac("ESDM"). The first read of the `esdm_raw_sched_hires` file after loading
    the module then provides this data.

  - The interface `/sys/kernel/debug/esdm_es/esdm_sched_perf` allows reading
    the number of cycles used to process one scheduler event, which measures
    the performance impact of the #ac("ESDM") on the scheduler. With the module
    parameter `boot_sched_perf=1`, the module stores the performance data of
    the first 1,024 events recorded by the #ac("ESDM"). The first read of the
    `esdm_sched_perf` file after loading the module then provides this data.

#par(first-line-indent: 0pt)[The helper tool `esdm-getrawentropy` reads the
files and formats the data for post-processing; `esdm-extractlsb` converts
the data into the input of the #ac("SP") 800-90B assessment tools (meson option
`validation-helpers`, `tests/validation-helpers`).]

For the #ac("eBPF") entropy sources, the collector `esdm-ebpf-collect` together
with the scripts `analyze_non_iid.sh` and `analyze_restart.sh` in
`tests/es_ebpf_testing` (meson option `es_ebpf_testing`) obtains the raw time
deltas and performs the #ac("SP") 800-90B assessment including the restart test.
The collector refuses to run in #ac("FIPS") mode, and the #ac("ESDM") server
itself never records raw data.
