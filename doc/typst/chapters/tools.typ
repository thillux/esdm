#import "../template.typ": *

= Command-Line Tools <sec:tools>

This chapter documents the command line of every program the #ac("ESDM")
installs: what it does, how it is invoked, its options, its exit status and
the signals it handles. It describes what the code parses. Each program also
ships a man page, installed with it and named at the end of its section.
Table @tab:tools lists the programs with the meson option that builds them;
chapter @sec:build-options describes the options.

#figure(
  table(columns: (auto, 1.6fr, auto), align: left + horizon,
    table.header([Program], [Purpose], [Meson option]),
    [`esdm-server`], [The daemon holding the #ac("ESDM")], [`esdm-server`],
    [`esdm-tool`], [Status, random numbers, administration, benchmarks],
      [`esdm-tool`],
    [`esdm-cuse-random`], [Serves `/dev/random` from the #ac("ESDM")],
      [`linux-devfiles`],
    [`esdm-cuse-urandom`], [Serves `/dev/urandom` from the #ac("ESDM")],
      [`linux-devfiles`],
    [`esdm-proc`], [Serves `/proc/sys/kernel/random` from the #ac("ESDM")],
      [`linux-devfiles`],
    [`esdm-kernel-seeder`], [Seeds the kernel #ac("RNG") from the
      #ac("ESDM")], [`esdm-server`],
    [`esdm-server-signal-helper`], [Notifies the server of suspend and
      resume], [`esdm-server`],
    [`esdm-es-pkcs11`], [External entropy source: the #ac("RNG") of a
      #acs("PKCS")\#11 token], [`es_pkcs11`],
    [`esdm-es-pcsc`], [External entropy source: the #ac("RNG") of a smart
      card over #ac("PC/SC")], [`es_pcsc`],
    [`esdm-getrawentropy`], [Reads the raw samples of the kernel module
      `esdm_es`], [`validation-helpers`],
    [`esdm-extractlsb`], [Turns raw samples into the input of the
      #ac("SP") 800-90B tools], [`validation-helpers`],
    [`esdm-ebpf-collect`], [Collects the raw deltas of the #ac("eBPF")
      entropy sources], [`es_ebpf_testing`],
    [`esdm-cdev-check`], [Checks the kernel module `esdm_cdev`],
      [`esdm-cdev-check`],
  ),
  caption: [The programs of the #ac("ESDM")],
) <tab:tools>

The options `esdm-server`, `esdm-tool` and `linux-devfiles` are enabled by
default; the others are disabled. All programs are installed in the `bindir` of
meson, `/usr/local/bin` with the default prefix – the daemons as well,
although their man pages are in section 8 (section @sec:installed-files).
The systemd units start them from there.

Most programs parse their command line with `getopt_long(3)`: a long option
may be abbreviated as long as it stays unique, and takes its argument as the
next word or after `=`. The #ac("CUSE") daemons and `esdm-proc` parse theirs
with libfuse, which accepts an option only in the forms their tables give and
passes everything else to the #ac("FUSE") library.

The daemons and `esdm-tool` log through the logger of the #ac("ESDM"), to
standard error or, with their syslog option, to syslog. Its levels are
numbered: 0 nothing, 1 status messages, 2 errors, 3 warnings, 4 verbose, 5
debug, 6 detailed debug, 7 trace. A level shows the messages of its own and
of all lower levels. The tables state how the verbosity options of a program
set the level.

== esdm-server <sec:tool-esdm-server>

`esdm-server` is the daemon of the #ac("ESDM"): it runs the entropy sources
and the #ac("DRNG", pl: true) of `libesdm` and serves them over the
#ac("RPC") sockets and, if configured, the #ac("EGD") sockets (section
@sec:interfaces). It must be started as root; it performs its setup and then
drops its privileges permanently (section @sec:isolation). Meson option
`esdm-server`; systemd unit `esdm-server.service` with the socket units
`esdm-server-priv.socket`, `esdm-server-unpriv.socket`,
`esdm-server-egd.socket` and `esdm-server-egd-pr.socket` (section
@sec:usage-systemd).

Each of the two interfaces can be left out of the build, with the meson
options `esdm-server-rpc` and `esdm-server-egd` (section
@sec:if-deployment). A server built without the #ac("RPC") interface opens
no #ac("RPC") socket and always serves the #ac("EGD") interface: on the
sockets it is given, and on the socket of `esdm-server-egd-socket-path`,
`/run/esdm-egd.socket` by default, when neither `--egd_socket` nor systemd
gives it the regular socket – also next to a socket of `--egd_socket_pr`, as
`esdm-tool` and the resume helper reach the server there. Its usage names it "ESDM server (EGD interface only)". A server
built without the #ac("EGD") interface rejects the two #ac("EGD") options.

```console
$ esdm-server [OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-h`, `--help`], [Print the usage and exit with status 1.],
    [`--version`], [Print the version of `libesdm` to standard error and exit
      with status 0.],
    [`-v`, `--verbose`], [Raise the log level by one, repeatable: the number
      of `-v` is the level, `-vvv` logs warnings. Implies `-f`. Without it,
      the server logs nothing.],
    [`-f`, `--foreground`], [Do not detach from the terminal. Required when
      systemd passes the sockets: the server then refuses to detach.],
    [`-p`, `--pid` _FILE_], [Create _FILE_, lock it and write the #ac("PID")
      into it. A lock held by a running instance aborts the start. With
      `--pid_namespace`, the file names the supervisor.],
    [`-u`, `--username` _USER_], [User to drop to after the privileged
      setup; default `nobody`.],
    [`-g`, `--groupname` _GROUP_], [The one supplementary group to keep after
      the drop; default none. The primary group is that of _USER_.],
    [`-S`, `--syslog`], [Log to syslog instead of standard error.],
    [`-P`, `--raise_sched_priority`], [Set the nice level to -15.],
    [`-m`, `--memlock`], [Lock all memory with `mlockall(2)`, mark the
      process as not dumpable and set its core size limit to 0 (section
      @sec:secrets). A failure aborts the start.],
    [`-M`, `--small_memory`], [Reduce the memory footprint: 2 MiB thread
      stacks, a single #ac("DRNG") node and, with glibc, one malloc arena
      returning freed memory early.],
    [`-i`, `--force_irqes`], [Keep the interrupt entropy source active while
      its kernel interface `/dev/esdm_es` is missing and retry opening it,
      e.g. when `esdm_es` is loaded after the server has started.],
    [`-s`, `--force_schedes`], [The same for the scheduler entropy source.],
    [`--es_jent_instances` _N_], [Collect from the Jitter #acs("RNG") with
      _N_ collectors side by side, 1 to 64. Default: `es_jent_instances`; its
      value 0 selects 4 with `sp80090c`, `fips140` or `ais2031_drg4` unless
      `ais2031_drg3` is set, and 1 otherwise.],
    [`--keep_ipc`], [Leave the #ac("RPC") sockets the server bound, the status
      shared memory segment and its semaphores in place at shutdown, so that
      running #ac("CUSE") daemons survive a restart. Only the supervisor of
      `--pid_namespace` removes them: without it, the server, having dropped
      its privileges, leaves them in place anyway.],
    [`--pid_namespace`], [Fork the daemon into a #ac("PID") namespace of its
      own. The starting process remains as the privileged supervisor: it
      forwards the signals, removes the #ac("IPC") objects once the daemon has
      ended and exits with the status of the daemon. A daemon whose
      supervisor ends before it, as by `SIGKILL`, shuts down as on `SIGTERM`;
      the #ac("IPC") objects and the #ac("PID") file then stay in place.],
    [`-e`, `--egd_socket` _PATH_], [Serve the #ac("EGD") protocol on the Unix
      domain socket _PATH_ (section @sec:usage-egd); disabled by default. A
      build without `esdm-server-rpc` serves the socket of
      `esdm-server-egd-socket-path` without the option. Refused by a build
      without `esdm-server-egd`.],
    [`-E`, `--egd_socket_pr` _PATH_], [The same, served by the prediction
      resistance #ac("DRNG") (section @sec:usage-egd-pr); disabled by default
      in every build. Refused by a build without `esdm-server-egd`.],
    [`--es_ext` _PATH_], [Read the external entropy source of the provider on
      the Unix domain socket _PATH_ (section @sec:ext-es); default
      `es_ext_path`, empty. Refused by a build without `es_ext`.],
    [`--es_ext_entropy_rate` _BITS_], [Credit a block of the provider with at
      most _BITS_ per 256 bits, 0 to 256, or with `auto` at the rate the
      provider declares, 0 if it declares none. Default:
      `es_ext_entropy_rate`, `auto`.],
    [`--es_ext_uid` _USER_], [Accept a provider running as _USER_, a
      #ac("UID") or a user name, besides root; `none` accepts root only.
      Default: `es_ext_peer_uid`, root only.],
    [`--es_jent_kernel_name` _NAME_], [Read the kernel crypto #ac("API")
      #ac("RNG") _NAME_, its name or driver name in `/proc/crypto`, for the
      kernel Jitter #acs("RNG") entropy source (section @sec:jent-kernel).
      Default: `es_jent_kernel_name`, `jitterentropy_rng`. Refused by a build
      without `es_jent_kernel`.],
  ),
  caption: [Options of `esdm-server`],
) <tab:tool-esdm-server-options>

#paragraph[Exit status][0 after a shutdown by signal. 1 after `--help`, for
an unknown option or an invalid argument, when not started as root, when a
running instance holds the lock of the #ac("PID") file, and when asked to
detach while systemd passes sockets. A failed setup, and an #ac("RPC") worker
thread that ends on a failure while the server runs, end the server with
another non-zero status; in a build without the #ac("RPC") interface, so
does a failure of the #ac("EGD") worker thread, and a start by systemd with
sockets of which none is an #ac("EGD") socket. With `--pid_namespace`, the
supervisor exits with the status of the daemon.]

#paragraph[Signals][`SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM` shut the
server down. `SIGUSR1` counts up the suspend generation in the status shared memory
segment and wakes the clients waiting on it, the #ac("CUSE") daemons among
them; `esdm-server-signal-helper --suspend` sends it. With
`--pid_namespace`, the supervisor forwards these signals to the daemon, and
the further ones IF-SIG.1 lists (section @sec:if-sig); the end of the
supervisor shuts the daemon down.]

#block(breakable: false)[
#paragraph[Examples][The unit starts the server as follows; a drop-in that
sets `ESDM_SERVER_OPTIONS` adds options:]

```sh
esdm-server -f --pid /run/esdm-server.pid --syslog --memlock --keep_ipc \
  -vvv $ESDM_SERVER_OPTIONS
```
]

```ini
# /etc/systemd/system/esdm-server.service.d/options.conf
[Service]
Environment="ESDM_SERVER_OPTIONS=--es_jent_instances 4"
```

Without systemd, in the foreground with verbose logging and the #ac("EGD")
interface:

```sh
esdm-server -f -vvvv --egd_socket /run/esdm-egd.socket
```

Man page: `esdm-server`(8).

== esdm-tool <sec:tool-esdm-tool>

`esdm-tool` is the command-line client of `esdm-server`: it queries the state
of the #ac("ESDM"), obtains random numbers, administers the server, runs
benchmarks and stress tests and creates the reference values of the
#ac("FIPS") integrity test. It communicates with the server over the #ac("RPC")
interface, for the administrative commands over the privileged socket; in a
build without that interface it communicates over the #ac("EGD") interface
and offers the commands the protocol can express (see below). Meson
option `esdm-tool`; `esdm-wait-until-fully-seeded.service` runs
`esdm-tool --wait-until-seeded -1 --use-syslog` (section
@sec:usage-boot-gate).

```console
$ esdm-tool [OPTION]... COMMAND
```

The commands are options as well; table @tab:tool-esdm-tool-options groups
them apart from the options that modify them. An invocation runs one command:
if several are given, only the first in a fixed order runs – `--help` before the
status queries, these before `--get-random` and the administration. The
administrative commands, `--endless-stress`, `--seed-via-os` and
`--reseed-via-os` require root; for any other user, the tool refuses them with
status 1. Messages go to standard error, the output of `--status`,
`--entropy-count`, `--entropy-level` and `--is-fully-seeded` among them;
data – #ac("JSON") documents, the Jitter #acs("RNG") status, random numbers,
seeds, benchmark results – to standard output.

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    table.cell(colspan: 2)[_General options_],
    [`-h`, `--help`], [Print the usage and exit with status 1, as without a
      command.],
    [`-v`, `--verbose`], [Raise the log level by one, repeatable; the default
      is 3, warnings.],
    [`-V`, `--decrease-verbosity`], [Lower the log level by one, repeatable,
      not below 1.],
    [`--use-syslog`], [Log to syslog instead of standard error.],
    table.cell(colspan: 2)[_Commands: status_],
    [`-s`, `--status`], [Print the status of the #ac("ESDM") and of every
      entropy source (section @sec:usage-check).],
    [`--status-json`], [The same as a #ac("JSON") document (section
      @sec:status).],
    [`--drng-status[=NODE|pr]`], [Print the status of the #ac("DRNG")
      instances as an indented #ac("JSON") document: without an argument an
      array of every node instance and the prediction resistance instance,
      with _NODE_ the instance of that node, with `pr` the prediction
      resistance instance. The argument is optional, so it follows `=`.],
    [`--drng-status-json[=NODE|pr]`], [The same on one line.],
    [`-J`, `--jent-status`], [Print the internal status of the Jitter
      #acs("RNG") entropy source.],
    [`-S`, `--is-fully-seeded`], [Exit with 0 if the initial #ac("DRNG")
      instance of the #ac("ESDM") is fully seeded, else with 1.],
    [`--is-running`], [Exit with 0 if both #ac("RPC") sockets exist and the
      #ac("ESDM") serves a request for random bytes, else with 1 – also for a
      running server that is not operational yet.],
    [`-e`, `--entropy-count`], [Print the entropy of the auxiliary pool in
      bits.],
    [`-E`, `--entropy-level`], [Print the entropy level of the #ac("ESDM") in
      bits.],
    [`-w`, `--wait-until-seeded` _TRIES_], [Check once per second, at most
      _TRIES_ times, whether the #ac("ESDM") is fully seeded, requesting one
      random byte per round to trigger the seeding; a negative _TRIES_ waits
      without limit. Exit with 0 once fully seeded, with 1 when the tries are
      exhausted.],
    table.cell(colspan: 2)[_Commands: random numbers_],
    [`-r`, `--get-random` _BYTES_], [Print _BYTES_ random bytes as upper-case
      hex digits on one line. By default from the full path
      (`esdm_rpcc_get_random_bytes_full()`), waiting until the #ac("ESDM") is
      operational.],
    [`--get-seed`], [Print the result of a get-seed operation
      (`esdm_get_seed()`): the size of the seed and its entropy in bits as two
      64-bit words, followed by the seed. It waits until all #ac("DRNG")
      instances are fully seeded.],
    table.cell(colspan: 2)[_Modifiers of `--get-random` and `--get-seed`_],
    [`--raw-bytes`], [Write the bytes unencoded instead of as hex digits.],
    [`--use-pr`], [`--get-random` from the prediction resistance #ac("DRNG")
      (`esdm_rpcc_get_random_bytes_pr()`).],
    [`--timeout-msec` _MSEC_], [`--get-random` with a timeout of _MSEC_
      milliseconds for each request of up to 8192 bytes
      (`esdm_rpcc_get_random_bytes_full_timeout()`).],
    [`--allow-unseeded`], [`--get-random` with
      `esdm_rpcc_get_random_bytes()`, which fails at once while the
      #ac("ESDM") is not operational. If the #ac("ESDM") is operational and
      delivers less than requested because its #ac("DRNG", pl: true) await a
      reseed, the tool obtains the rest with the waiting request.
      `--get-seed` asks for the entropy of an initial
      seed instead of a reseed. The last of `--use-pr`, `--timeout-msec` and
      `--allow-unseeded` given applies.],
    table.cell(colspan: 2)[_Commands: administration, root only_],
    [`-W`, `--write-to-aux-pool` _DATA_], [Write the string _DATA_ itself into
      the auxiliary pool.],
    [`-B`, `--write-entropy-bits` _BITS_], [Modifier: credit the write of
      `-W` with _BITS_ of entropy; default 0.],
    [`--clear-pool`], [Clear the entropy pool, for testing.],
    [`--reseed-crng`], [Force a reseed of the #ac("DRNG", pl: true), for
      testing.],
    [`--max-reseed-secs` _SECS_], [Set the maximum interval between two
      reseeds of a #ac("DRNG"); 0 reseeds before every request. The
      #ac("ESDM") caps the value; the tool prints the value in effect.],
    [`--selftest`], [Run the self tests of the crypto implementations and of
      the entropy sources now and print both results (section
      @sec:self-tests). Exit with 0 only if all passed and the #ac("ESDM")
      delivers random numbers: a failed crypto self test stops the output
      permanently.],
    [`--set-es-rate ES=BITS`], [Set the entropy rate of the entropy source
      _ES_, named as by `--status` without regard to case, to _BITS_ per 256
      bits; `all` sets every source but the auxiliary pool. Only a server
      built with `testmode` or `buildtype=debug` accepts it.],
    table.cell(colspan: 2)[_Commands: benchmark and stress tests_],
    [`-b`, `--benchmark`], [Measure the request and data rates: full path
      with 1 to 65,512 bytes per request (powers of two, the last capped at
      the largest request), prediction resistance path with 1
      to 64 bytes.],
    [`--benchmark-mode` _MODE_], [The benchmark of one path only: `full`,
      `pr` or `both` (default). Implies `--benchmark`.],
    [`--stress-delay`], [Measure the delay of requests in one thread.],
    [`--stress-thread`], [The same in one thread per online #ac("CPU").],
    [`--stress-process`], [The same in one process per online #ac("CPU").],
    [`--stress-fork`], [Check that the client library serves processes forked
      from a client: five generations, 200 requests each.],
    [`--stress-init-fini`], [Stress the reference counting of the
      initialization and finalization of the client library from one thread
      per online #ac("CPU").],
    [`--endless-stress`], [Root only: write 64 bytes credited with 512 bits
      into the auxiliary pool and read 64 bytes of the prediction resistance
      #ac("DRNG"), in a loop that ends at the first failure. For tests only:
      it credits data with entropy it does not have.],
    table.cell(colspan: 2)[_Modifiers of the stress tests_],
    [`--stress-duration` _SECS_], [Duration of `--stress-delay`,
      `--stress-thread`, `--stress-process` and `--stress-init-fini` in whole
      seconds; default 65.],
    [`--stress-request-size` _BYTES_], [Bytes per request; default 4.],
    [`--stress-cpu-usage`], [Show the #ac("CPU") usage during the test.],
    [`--continue-on-failure`], [Let `--endless-stress` continue after failures,
      e.g. while the server is stopped and started.],
    table.cell(colspan: 2)[_Command: #ac("FIPS") integrity reference value_],
    [`-F`, `--fips-targetfile` _PATH_ \ `-C`, `--fips-checkfile` _CHECK_],
      [Given together: write the #ac("HMAC") SHA-256 of the file _PATH_ as hex
      digits into _CHECK_, which must not exist; `-` writes to standard
      output. The integrity test of a `fips140` build reads it from
      `.NAME.hmac` next to the file `NAME`. Without `fips140`, the command
      fails.],
    table.cell(colspan: 2)[_Commands: test helpers of the auxiliary pool,
      root only, builds with `esdm-aux-client`_],
    [`--seed-via-os`], [Write 64 bytes of `getentropy(3)` credited with 512
      bits into the auxiliary pool, once.],
    [`--reseed-via-os`], [The same whenever the #ac("ESDM") reports that it
      needs entropy, or after 100 seconds, until a failure.],
    [`--reseed-delay-ms` _MSEC_], [Modifier: wait _MSEC_ milliseconds, less
      than one second, before each write of `--reseed-via-os`, to emulate a
      slow source such as a smart card or a #ac("TPM").],
  ),
  caption: [Options and commands of `esdm-tool`],
) <tab:tool-esdm-tool-options>

#warning-note[`--seed-via-os`, `--reseed-via-os` and `--endless-stress`
credit the auxiliary pool with entropy the #ac("ESDM") cannot account for. Do
not use them in production.]

#paragraph[Without the #ac("RPC") interface][A build with `esdm-server-rpc`
disabled has no #ac("RPC") client library. `esdm-tool` then uses
`libesdm_egd_client` and the commands of the #ac("EGD") protocol with the
extensions of the #ac("ESDM") (section @sec:if-egd), on one socket for all
commands: the one the environment variable `ESDM_EGD_SOCKET` names, else
the socket of `esdm-server-egd-socket-path`, which a server of such a build
serves when it is given none. The server carries out the administrative
commands for a peer connected as root. Table @tab:tool-esdm-tool-egd lists
what the tool does over this interface; the usage of such a tool names the
interface, the socket and the commands it lacks.]

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Command], [Over the #ac("EGD") interface]),
    [`--status`, `--status-json`], [The status commands 0xe4 and 0xe5.],
    [`--is-fully-seeded`, `--wait-until-seeded`, `--entropy-count`], [The
      state, command 0xe3.],
    [`--entropy-level`], [The entropy count of #ac("EGD"), command 0x00.],
    [`--get-random`], [The blocking read 0x02; with `--use-pr` the
      prediction resistance read 0xe1; with `--allow-unseeded` the read
      0xe2 and the blocking read for what it did not deliver. A request of
      more than 255 bytes first takes what a bulk read 0xeb delivers.],
    [`--timeout-msec`], [The read 0x01, as bulk read, repeated until all
      bytes are delivered or the time is up. The server holds such a read
      back for up to one second while its #ac("DRNG", pl: true) await a
      reseed; the timeout may be exceeded by that.],
    [`--write-to-aux-pool`, `--write-entropy-bits`], [The insertion 0xec,
      which the server confirms, followed for a claim by the credit 0xe6: the
      pool holds no credit for data that is not yet in it, and a failed
      insertion is reported. A claim is checked for the privilege before any
      data is sent, and one of more than 8 bits per byte is refused.],
    [`--clear-pool`, `--reseed-crng`, `--max-reseed-secs`], [The privileged
      commands 0xe7, 0xe8 and 0xea; the interval in effect is read from the
      state.],
    [`--is-running`], [The socket exists and the #ac("ESDM") serves an
      unseeded read or reports that it is operational.],
    [`--benchmark`, `--stress-delay`, `--stress-thread`, `--stress-process`,
      `--stress-fork`, `--endless-stress`, `--seed-via-os`,
      `--reseed-via-os`], [With the reads and the write above. The full path
      of the benchmark runs up to 65,536 bytes per request. Every thread
      has a connection of its own.],
    [`--drng-status`, `--drng-status-json`, `--jent-status`, `--get-seed`,
      `--selftest`, `--set-es-rate`, `--stress-init-fini`], [Not available:
      the protocol has no command for them. The tool names the option and
      the reason and exits with status 1, for every user.],
  ),
  caption: [`esdm-tool` in a build without the #ac("RPC") interface],
) <tab:tool-esdm-tool-egd>

#paragraph[Exit status][0 on success. 1 when a command fails or answers in the
negative (`--is-fully-seeded`, `--is-running`, `--wait-until-seeded`), after
`--help` or without a command, for an invalid argument, for a command the
interface of the build cannot express, and for an
administrative command of a user other than root. `--status`, `--status-json`,
`--jent-status`, `--stress-delay`, `--stress-thread`, `--stress-process` and
`--endless-stress` exit with 0 even when they fail.]

#paragraph[Examples][Wait up to a minute for the #ac("ESDM"), then draw 32
raw bytes; list the #ac("DRNG") instances that are not fully seeded:]

```sh
esdm-tool --wait-until-seeded 60 &&
  esdm-tool --get-random 32 --raw-bytes > seed.bin
esdm-tool --drng-status-json | jq '.[] | select(.fully_seeded == false) | .node'
```

Create the reference value of the integrity test for an installed server
built with `fips140`:

```sh
esdm-tool --fips-targetfile /usr/local/bin/esdm-server \
  --fips-checkfile /usr/local/bin/.esdm-server.hmac
```

Man page: `esdm-tool`(1).

== esdm-cuse-random <sec:tool-esdm-cuse-random>

`esdm-cuse-random` serves `/dev/random` from the #ac("ESDM"): it registers
the #ac("CUSE") device `/dev/esdm` and bind-mounts it over `/dev/random`, so
that applications, including their `ioctl(2)` and `poll(2)` calls, reach the
#ac("ESDM") unchanged (section @sec:usage-cuse). Its reads wait until the
#ac("ESDM") is operational. Before the overlay, it opens the kernel's
`/dev/random` and serves from it while the server cannot be reached. It must
be started as root; it drops its privileges transiently once the device
exists and regains them only for the operations that need them (section
@sec:isolation). Meson option `linux-devfiles`, which requires `esdm-server`;
systemd unit `esdm-cuse-random.service`, wanted by
`esdm-linux-compat.target`.

```console
$ esdm-cuse-random [OPTION]... [FUSE-OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-h`, `--help`], [Print the usage and exit with status 1; libfuse adds an
      error message about the option `-ho`.],
    [`-n` _NAME_, `--name=NAME`], [Name of the #ac("CUSE") device below
      `/dev` that is bind-mounted; default `esdm`, with `esdm-cuse-urandom`
      `uesdm`.],
    [`-M` _MAJ_, `--maj=MAJ` \ `-m` _MIN_, `--min=MIN`], [Accepted, but
      without effect: the kernel assigns the device numbers.],
    [`-v` _NUM_, `--verbosity=NUM`], [Set the log level to _NUM_; default 1.],
    [`-S`, `--syslog`], [Log to syslog instead of standard error.],
    [`-u` _USER_, `--username` _USER_], [User to drop to; default `nobody`.
      The long form takes the user as the next word only.],
    [`--pid_namespace`], [Fork the daemon into a #ac("PID") namespace of its
      own, the starting process staying as supervisor. The daemon then
      cannot look up the capabilities of its callers and accepts the
      privileged #ac("IOCTL", pl: true) from #ac("UID") 0 instead of from
      callers with `CAP_SYS_ADMIN`. A daemon whose supervisor ends before
      it, as by `SIGKILL`, ends as on `SIGTERM` and removes its bind
      mount.],
    [`--disable_fallback=N`], [Test mode builds only: with 1, never serve
      from the kernel's device.],
    table.cell(colspan: 2)[_Options of libfuse_],
    [`-f`], [Stay in the foreground.],
    [`-d`, `-o debug`], [Log the #ac("FUSE") requests; implies `-f`.],
    [`-s`], [Serve the requests in one thread instead of a pool of worker
      threads.],
  ),
  caption: [Options of `esdm-cuse-random` and `esdm-cuse-urandom`],
) <tab:tool-esdm-cuse-random-options>

#paragraph[Exit status][0 after a shutdown by signal, non-zero when the
options, the kernel's device, the #ac("CUSE") setup or the bind mount fail.]

#paragraph[Signals][`SIGHUP`, `SIGINT`, `SIGQUIT`, `SIGTERM` and the other
signals of IF-SIG.1 (section @sec:if-sig) end the daemon cleanly: it leaves
the #ac("FUSE") loop and removes the bind mount, so that the kernel's device
is visible again. `SIGPIPE` and the signals that report a fault (`SIGSEGV`,
`SIGBUS`, `SIGILL`, `SIGFPE`, `SIGABRT`, `SIGSYS`, `SIGTRAP`) keep their
default action; a daemon ended by one of them leaves the bind mount in
place. With `--pid_namespace`, the supervisor forwards the signals sent to
it as IF-SIG.1 states, and its end ends the daemon cleanly.]

#paragraph[Example][The unit starts the daemon as follows:]

```sh
esdm-cuse-random -f --syslog -v 3
```

Man page: `esdm-cuse-random`(8).

== esdm-cuse-urandom <sec:tool-esdm-cuse-urandom>

`esdm-cuse-urandom` is the counterpart of `esdm-cuse-random` for
`/dev/urandom`: it registers the #ac("CUSE") device `/dev/uesdm` and
bind-mounts it over `/dev/urandom`. Its reads do not wait: while the
#ac("ESDM") is not operational or the server cannot be reached, it serves
them from the kernel's `/dev/urandom`, which it opened before the overlay.
It takes the options, exit status and signals of `esdm-cuse-random` (table
@tab:tool-esdm-cuse-random-options). Meson option `linux-devfiles`; systemd
unit `esdm-cuse-urandom.service`, wanted by `esdm-linux-compat.target`.

```console
$ esdm-cuse-urandom [OPTION]... [FUSE-OPTION]...
```

The unit starts it as `esdm-cuse-urandom -f --syslog -v 3`. Man page:
`esdm-cuse-urandom`(8), which refers to `esdm-cuse-random`(8).

== esdm-proc <sec:tool-esdm-proc>

`esdm-proc` is a #ac("FUSE") file system serving the files of
`/proc/sys/kernel/random` from the #ac("ESDM"), mounted over the kernel's
directory: `boot_id`, `uuid`, `entropy_avail`, `poolsize`, the writable
`write_wakeup_threshold` and `urandom_min_reseed_secs`, and `esdm_type`,
which the kernel does not have and which indicates to a consumer that the
#ac("ESDM") answers. It must be started as root to mount there and runs as
`nobody`, regaining its privileges for the writes. Meson option
`linux-devfiles`; systemd unit `esdm-proc.service`, wanted by
`esdm-linux-compat.target`.

```console
$ esdm-proc [OPTION]... [FUSE-OPTION]... MOUNTPOINT
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-h`, `--help`], [Print the usage and the options of libfuse and exit
      with status 0.],
    [`-v` _NUM_, `--verbosity=NUM`], [Set the log level to _NUM_; default 0.],
    [`--syslog`], [Log to syslog instead of standard error.],
    [`--relabel`], [Mount with the SELinux context of
      `/proc/sys/kernel/random/poolsize`, so that the files carry the context
      of those they replace. Without effect in a build without `selinux`.],
    table.cell(colspan: 2)[_Options of libfuse_],
    [`-f`], [Stay in the foreground.],
    [`-d`, `-o debug`], [Log the #ac("FUSE") requests; implies `-f`.],
    [`-s`], [Serve with one thread.],
    [`-o allow_other`], [Let users other than the one running the daemon
      access the mount; required over `/proc/sys/kernel/random`.],
  ),
  caption: [Options of `esdm-proc`],
) <tab:tool-esdm-proc-options>

#paragraph[Exit status][0 once the file system is unmounted, non-zero when
the options or the mount fail.]

#paragraph[Example][The unit mounts it as follows:]

```sh
esdm-proc --relabel --syslog -f -o allow_other /proc/sys/kernel/random -v 3
```

Man page: `esdm-proc`(8).

== esdm-kernel-seeder <sec:tool-esdm-kernel-seeder>

`esdm-kernel-seeder` seeds the kernel #ac("RNG") from the #ac("ESDM"), as
`rngd` does from other sources. This seeding is required when the #ac("ESDM")
runs the interrupt entropy source, which deprives the kernel #ac("RNG") of its
main input (section @sec:usage-systemd). Each insertion is 64 bytes from the
full path of the #ac("ESDM"), credited with the `linux-reseed-entropy-count`
bits of the build, 0 by default. It hands them to the #ac("CUSE") device
`/dev/esdm`, which passes them on to the kernel, if that device exists, and
otherwise to `/dev/random` with `RNDADDENTROPY`. Until the first insertion has
succeeded, it retries every 2 seconds. It must be started as root. Meson option
`esdm-server`, together with `esdm-server-rpc`, as it obtains the bytes over
the #ac("RPC") interface; systemd unit `esdm-kernel-seeder.service`, which starts it as
`esdm-kernel-seeder -i 10 --syslog -vvv` and which a build with `systemd`
reports ready after the first insertion.

```console
$ esdm-kernel-seeder [OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-h`, `--help`], [Print the usage and exit with status 1.],
    [`-i`, `--interval` _SECS_], [Seconds between two insertions after the
      first; default `linux-reseed-interval`, 120.],
    [`-p`, `--force-pr`], [Draw from the prediction resistance #ac("DRNG") and
      force a reseed of the kernel #ac("RNG") after every insertion. Always
      on in a build with `ais2031_ntg1` or `es_jent_ntg1`.],
    [`-v`, `--verbosity`], [Raise the log level, repeatable: the number of
      `-v` is the level. Without it, the level is 1.],
    [`-s`, `--syslog`], [Log to syslog instead of standard error.],
  ),
  caption: [Options of `esdm-kernel-seeder`],
) <tab:tool-esdm-kernel-seeder-options>

#paragraph[Exit status][0 after a shutdown by signal. 1 after `--help`, for
an interval that is not a number, when not started as root, and when its
setup or the wait between two insertions fails.]

#paragraph[Signals][`SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM` end the
daemon at once, also during the wait between two insertions and while a
request waits for the #ac("ESDM").]

#paragraph[Example][Seed the kernel every minute from the prediction
resistance #ac("DRNG"), as root:]

```sh
esdm-kernel-seeder --interval 60 --force-pr -vvvv
```

Man page: `esdm-kernel-seeder`(8).

== esdm-server-signal-helper <sec:tool-esdm-server-signal-helper>

`esdm-server-signal-helper` notifies `esdm-server` that the system suspends or
has resumed. On suspend, it reads the #ac("PID") of the server from its
#ac("PID") file and, if that process holds the lock of the file, sends it
`SIGUSR1`, which wakes the clients waiting on the server. On resume, it asks
the server over the privileged #ac("RPC") interface to reseed every
#ac("DRNG") (`esdm_rpcc_rnd_reseed_crng`, as the #ac("IOCTL") `RNDRESEEDCRNG`
does). Both require root: the first for the right to send the server a signal,
the second for a privileged call. In a build without the #ac("RPC")
interface, the resume sends the reseed command 0xe8 of the #ac("EGD")
interface instead (`esdm_egd_client_reseed`), to the socket the environment
variable `ESDM_EGD_SOCKET` names or else the socket of
`esdm-server-egd-socket-path`; the server carries it out for a peer
connected as root. Meson option `esdm-server`; systemd units
`esdm-server-suspend.service` and `esdm-server-resume.service` (section
@sec:usage-systemd).

With the kernel module `esdm_es` loaded, the server learns of suspend,
resume, shutdown and a change of the #ac("VM") generation from the module
itself (section @sec:vm-clone, table @tab:system-events); this also holds for a
module built without an entropy source, which needs no kernel patch. The
helper and its units remain for systems without the module, and both paths
together are harmless.

```console
$ esdm-server-signal-helper --suspend --pid PIDFILE
$ esdm-server-signal-helper --resume
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-s`, `--suspend`], [Signal the suspend; requires `--pid`.],
    [`-p`, `--pid` _PIDFILE_], [The #ac("PID") file of the server, as written
      by `esdm-server --pid`.],
    [`-r`, `--resume`], [Signal the resume. Given with `--suspend`, only
      the suspend is signaled.],
    [`-h`, `--help`], [Without `--suspend` and `--resume`: print the usage
      and exit with status 1.],
  ),
  caption: [Options of `esdm-server-signal-helper`],
) <tab:tool-esdm-server-signal-helper-options>

#paragraph[Exit status][0 when the notification was delivered, 1 otherwise:
no running server named in the #ac("PID") file, no `--pid` with
`--suspend`, a server that cannot be reached or refuses the reseed on
resume, no mode, `--help`.]

#paragraph[Example][The units call it as follows:]

```sh
esdm-server-signal-helper --suspend --pid /run/esdm-server.pid
esdm-server-signal-helper --resume
```

Man page: `esdm-server-signal-helper`(8).

// The options every provider of libesdm_es_ext takes, after --socket
#let es-ext-provider-rows = (
  [`-m`, `--mode` _MODE_], [Access mode of the socket, octal; default 0666.
    Every user who can connect can fill the backlog the #ac("ESDM") connects
    through: restricting it to a group of the user of the #ac("ESDM") is
    safer.],
  [`-u`, `--client_uid` _USER_], [Serve clients running as _USER_, a
    #ac("UID") or a user name, besides root; up to 8 times. Default `nobody`,
    the user `esdm-server` drops to, or root only without such a user.],
  [`--name` _NAME_], [Declare the name _NAME_, 1 to 32 bytes of UTF-8 without
    control characters, instead of the name of the source.],
  [`--entropy_rate` _BITS_], [Declare _BITS_ per 256 bits of data, 0 to 256,
    instead of the rate of the source. `esdm-server --es_ext_entropy_rate`
    overrides it.],
  [`-v`, `--verbose`], [Raise the log level by one from 1, repeatable.],
  [`-h`, `--help`], [Print the usage and exit with status 0.],
  [`--version`], [Print the version and exit with status 0.],
)

== esdm-es-pkcs11 <sec:tool-esdm-es-pkcs11>

`esdm-es-pkcs11` serves the #ac("RNG") of a #acs("PKCS")\#11 token – a smart
card, a #ac("USB") token, an #ac("HSM"), SoftHSM – as an external entropy
source, which `esdm-server --es_ext` reads (sections @sec:ext-es and
@sec:hsm). It calls `C_GenerateRandom` through libp11 and runs the vendor's
module in its own process. It uses the first slot holding an initialized
token with an #ac("RNG"), of the given label if one is set, and looks for it
again on demand, at most every 5 seconds. The source declares the name
"PKCS\#11", followed by the label configured with `--token_label` if that
makes a valid name, and the
rate `es_pkcs11_entropy_rate`, 128 bits per 256 bits by default. Meson option
`es_pkcs11`, which requires `esdm-es-ext`; systemd unit
`esdm-es-pkcs11.service`, which runs it as the system user `esdm-es-pkcs11`,
ordered before `esdm-server.service`, as
`esdm-es-pkcs11 -vvv $ESDM_ES_PKCS11_OPTIONS`.

```console
$ esdm-es-pkcs11 [OPTION]...
```

The #ac("PIN") is never taken from the command line, which every user can
read in `/proc`. The #ac("PIN") is the single line of the file of `--pin_file`
or of a systemd credential: that of `--pin_credential`, otherwise `pkcs11-pin`
if the daemon has it. A file that is empty, longer than one line of 256 bytes or
not a regular file is refused; a file that every user can read causes a warning.
The daemon logs in only if the token requests it; a failed login is not repeated
before a restart, as each one uses up a retry of the token. Errors in the
command line are reported without repeating it, as it may hold a #ac("PIN") by
mistake.

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-M`, `--module` _PATH_], [The #acs("PKCS")\#11 module to load; default
      `es_pkcs11_module_path`; required if that is empty, which is its
      default.],
    [`-t`, `--token_label` _LABEL_], [Use only the token of _LABEL_; default
      `es_pkcs11_token_label`, empty: the first token with an #ac("RNG").],
    [`-p`, `--pin_file` _PATH_], [Read the #ac("PIN") from _PATH_; excludes
      `--pin_credential`.],
    [`--pin_credential` _NAME_], [Read the #ac("PIN") from the systemd
      credential _NAME_ in `$CREDENTIALS_DIRECTORY`, which then has to
      exist.],
    [`-s`, `--socket` _PATH_], [Unix domain socket to serve on, replacing a
      socket there but no other file; default
      `/run/esdm-es-pkcs11/esdm-es-pkcs11.socket`.],
    ..es-ext-provider-rows,
  ),
  caption: [Options of `esdm-es-pkcs11`],
) <tab:tool-esdm-es-pkcs11-options>

#paragraph[Exit status][0 when a signal ended the service, and after
`--help` and `--version`; 1 otherwise.]

#paragraph[Signals][`SIGTERM`, `SIGINT` and `SIGHUP` stop the service between
two requests. A source stuck in a call is granted 5 seconds; a second signal or
the end of that time ends the daemon at once with status 1. A signal while the
source sets up ends it with status 1.]

#paragraph[Example][A SoftHSM token, and the server reading it:]

```sh
softhsm2-util --init-token --free --label my-token --so-pin 1234 --pin 5678
(umask 077; echo 5678 > /etc/esdm/pkcs11-pin)
esdm-es-pkcs11 --module /usr/lib/softhsm/libsofthsm2.so \
  --token_label my-token --pin_file /etc/esdm/pkcs11-pin \
  --socket /run/esdm-es-pkcs11.socket
esdm-server --es_ext /run/esdm-es-pkcs11.socket
```

With systemd, drop-ins configure both units, as the head of
`esdm-es-pkcs11.service` shows:

```ini
# /etc/systemd/system/esdm-es-pkcs11.service.d/token.conf
[Service]
Environment="ESDM_ES_PKCS11_OPTIONS=--module /usr/lib/softhsm/libsofthsm2.so --token_label my-token"

# /etc/systemd/system/esdm-server.service.d/pkcs11.conf
[Service]
Environment="ESDM_SERVER_OPTIONS=--es_ext /run/esdm-es-pkcs11/esdm-es-pkcs11.socket --es_ext_uid esdm-es-pkcs11"
```

Man page: `esdm-es-pkcs11`(8); the options of every provider are in
`libesdm_es_ext`(3).

== esdm-es-pcsc <sec:tool-esdm-es-pcsc>

`esdm-es-pcsc` asks a smart card for random bytes with the command GET
CHALLENGE of ISO/IEC 7816-4 through `pcscd` and serves them as an external
entropy source, which `esdm-server --es_ext` reads (section @sec:ext-es).
Nearly every card answers this command without an application or a
#ac("PIN"). `esdm-es-pcsc` uses the card in the first reader holding one and,
on the next request, sets up anew a card that was removed, reset or lost
through a restart of `pcscd`.
The source declares the name "PC/SC" and no entropy rate unless started with
`--entropy_rate`. Meson option `es_pcsc`, which requires `esdm-es-ext`; no
systemd unit.

```console
$ esdm-es-pcsc --socket PATH [OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-r`, `--reader` _NAME_], [Use only the reader whose name contains
      _NAME_; default the first one holding a card.],
    [`-l`, `--challenge_len` _N_], [Bytes asked for with one GET CHALLENGE, 1
      to 255; default 32.],
    [`-s`, `--socket` _PATH_], [Unix domain socket to serve on, replacing a
      socket there but no other file; required.],
    ..es-ext-provider-rows,
  ),
  caption: [Options of `esdm-es-pcsc`],
) <tab:tool-esdm-es-pcsc-options>

#paragraph[Exit status and signals][As for `esdm-es-pkcs11`.]

#paragraph[Example][Serve a card declared at 128 bits per 256 bits:]

```sh
esdm-es-pcsc --socket /run/esdm-es-pcsc.socket --entropy_rate 128
esdm-server --es_ext /run/esdm-es-pcsc.socket
```

Man page: `esdm-es-pcsc`(8).

== esdm-getrawentropy <sec:tool-esdm-getrawentropy>

`esdm-getrawentropy` reads the raw samples of the interrupt or scheduler
entropy source from a debugfs file of the kernel module `esdm_es` and writes
them as decimal numbers, one 64-bit sample per line – the input of
`esdm-extractlsb` (section @sec:test-interfaces). The module provides the
files only when built with its testing support; reading them requires root.
Progress goes to standard error. Meson option `validation-helpers`; for
measurements only.

```console
$ esdm-getrawentropy [OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-s`, `--samples` _NUM_], [Number of samples; default 1000. An
      #ac("SP") 800-90B assessment needs at least 1,000,000.],
    [`-f`, `--debugfs-file` _FILE_], [The file to read; default
      `/sys/kernel/debug/esdm_es/esdm_raw_sched_hires`, the scheduler source.
      The interrupt source is
      `/sys/kernel/debug/esdm_es/esdm_raw_hires`.],
    [`-o`, `--outfile` _FILE_], [Write to _FILE_, which must not exist,
      instead of standard output.],
    [`-h`, `--help`], [Print the usage and exit with status 1.],
  ),
  caption: [Options of `esdm-getrawentropy`],
) <tab:tool-esdm-getrawentropy-options>

#paragraph[Exit status][0 on success, non-zero otherwise.]

#paragraph[Example][Collect and convert a million samples of the interrupt
source and assess them with the #ac("NIST") tool:]

```sh
esdm-getrawentropy -f /sys/kernel/debug/esdm_es/esdm_raw_hires \
  -s 1000000 -o /tmp/data.out
esdm-extractlsb /tmp/data.out /tmp/data.bin 1000000 FF
ea_non_iid /tmp/data.bin 8
```

Man page: `esdm-getrawentropy`(8).

== esdm-extractlsb <sec:tool-esdm-extractlsb>

`esdm-extractlsb` turns the decimal samples of `esdm-getrawentropy` or
`esdm-ebpf-collect` into the byte stream the #ac("SP") 800-90B tools of the
#ac("NIST") assess: from the first number of each line, it keeps the bits
of a mask, packs them into one byte and writes that byte. The entropy of
these sources lies in the low-order bits, so `FF`, the lowest 8, is the usual
mask. Meson option `validation-helpers`; for measurements only.

```console
$ esdm-extractlsb INPUTFILE OUTFILE MAXEVENTS MASK
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Argument], [Description]),
    [_INPUTFILE_], [Decimal samples, one per line.],
    [_OUTFILE_], [Binary output, one byte per sample. It must not exist; the
      mask is checked before either file is opened.],
    [_MAXEVENTS_], [Stop after this many samples.],
    [_MASK_], [Up to 16 hex digits naming the bits to keep, at most 8 of
      them set.],
  ),
  caption: [Arguments of `esdm-extractlsb`],
) <tab:tool-esdm-extractlsb-options>

On standard output, the tool reports the number of samples, the mask and the
bits it selects, and the bits that were 0 or 1 in every sample. A selected
bit that never changes carries no entropy; selected bits that are mostly
constant indicate a clock too coarse for the source to be credited.

#paragraph[Exit status][0 on success; 1 for a wrong number of arguments, a
file that cannot be opened, a malformed mask, a mask with more than 8 bits
set, or a failed write.]

#paragraph[Example][See `esdm-getrawentropy` and `esdm-ebpf-collect`.]

Man page: `esdm-extractlsb`(8).

== esdm-ebpf-collect <sec:tool-esdm-ebpf-collect>

`esdm-ebpf-collect` obtains the raw time deltas of the #ac("eBPF") scheduler
and interrupt entropy sources for their #ac("SP") 800-90B assessment
(chapter @sec:ebpf-assessment). It loads and attaches its own copy of the
#ac("eBPF") programs, so that every run starts from a freshly initialized
source, and writes one decimal delta per line, with the timer granularity
already divided out, as the server does. It requires the privileges to load
#ac("eBPF") programs, root in practice, and refuses to run while the kernel is
in #ac("FIPS") mode. Meson option `es_ebpf_testing`, which requires
`es_sched_ebpf` or `es_irq_ebpf`; never for a production build.

```console
$ esdm-ebpf-collect --source sched|irq --out FILE [OPTION]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Option], [Description]),
    [`-s`, `--source` _SOURCE_], [The entropy source: `sched` or `irq`,
      provided that the build includes it; required.],
    [`-o`, `--out` _FILE_], [Output file, which must not exist; required.],
    [`-e`, `--events` _N_], [Stop after _N_ deltas written, a positive
      number; default 10000000.],
    [`-c`, `--cpu` _N_], [Write only the deltas of #ac("CPU") _N_; the
      collector moves itself off that #ac("CPU"), which for `sched` has to
      succeed. Without it, the deltas of all #ac("CPU", pl: true) form one
      stream in arrival order, which mixes separate noise sources: do not
      assess it.],
    [`-h`, `--help`], [Print the usage and exit with status 0.],
  ),
  caption: [Options of `esdm-ebpf-collect`],
) <tab:tool-esdm-ebpf-collect-options>

#paragraph[Exit status][0 when the deltas were written, also after a stop by
signal; 1 for a missing or invalid option, in #ac("FIPS") mode, when the
programs cannot be loaded or attached, and after write errors.]

#paragraph[Signals][`SIGINT` and `SIGTERM` end the collection; the deltas
collected so far are kept.]

#paragraph[Example][A million deltas of #ac("CPU") 0 of the scheduler source,
converted and assessed:]

```sh
esdm-ebpf-collect --source sched --cpu 0 --events 1000000 --out sched-cpu0.txt
esdm-extractlsb sched-cpu0.txt sched-cpu0.bin 1000000 FF
ea_non_iid sched-cpu0.bin 8
```

Man page: `esdm-ebpf-collect`(8).

== esdm-cdev-check <sec:tool-esdm-cdev-check>

`esdm-cdev-check` runs the checks of the kernel module `esdm_cdev`, which
serves `/dev/esdm_random`, `/dev/esdm_urandom`, `/dev/esdm_pr` and
`/proc/esdm` from the #ac("ESDM") over its #ac("EGD") socket. Each check is a
subcommand that communicates with the loaded module and with the #ac("ESDM")
serving it, reports what it found, and ends with a line starting with `FAIL:` if
the module does not behave as specified. Most checks expect the #ac("ESDM") to
be reachable over `/run/esdm-egd.socket`; some change its state and are meant
for a machine set up for them, as in the virtual machine test of the flake
(section @sec:vm-tests). The program is built with the test suite, whose suite
`esdm_cdev` runs the checks that hold next to an ordinary #ac("ESDM"); the meson
option `esdm-cdev-check` installs it. It is a test program.

```console
$ esdm-cdev-check CHECK [ARG]...
```

#figure(
  table(columns: (auto, 1.6fr), align: left + horizon,
    table.header([Check], [Description]),
    table.cell(colspan: 2)[_The devices_],
    [`reads` \[`sync`\]], [Reads of 1 byte to 1 MiB from both devices are
      random and differ, and single bytes take more than a few values. With
      `sync`, opened with `O_SYNC` and served by the prediction resistance
      #ac("DRNG"), up to 64 bytes each.],
    [`nonblock`], [A read with `O_NONBLOCK` of an operational #ac("ESDM")
      gets random data.],
    [`poll`], [`/dev/esdm_random` is readable once the #ac("ESDM") is
      operational; `/dev/esdm_urandom` has no `poll()` and is readable and
      writable as any such file.],
    [`pr`], [`/dev/esdm_pr` serves the prediction resistance #ac("DRNG")
      without `O_SYNC`: blocking reads of up to 64 bytes are random and
      differ; with `O_NONBLOCK`, a read gives data or `EAGAIN`, and `poll()`
      reports the device readable again within a second.],
    [`writes`], [Writes of zero bytes up to 300 KiB are accepted in full, each
      in one `write()`.],
    table.cell(colspan: 2)[_The ioctls and `/proc/esdm`_],
    [`ioctl-priv`], [Needs `CAP_SYS_ADMIN`. Every #ac("IOCTL") of `random(4)`
      does to the pool of the #ac("ESDM") what it does to the kernel's, and
      the arguments the kernel refuses are refused. Credits entropy nobody
      delivered and clears the pool of the #ac("ESDM").],
    [`ioctl-unpriv`], [Without `CAP_SYS_ADMIN`, the entropy count can be read
      and nothing else is done. A caller with the capability gives it up
      first.],
    [`proc`], [Needs `CAP_SYS_ADMIN`. The files of `/proc/esdm` with the
      #ac("ESDM") reachable: their content, the two writable ones, what is
      refused. Sets `write_wakeup_threshold` and `urandom_min_reseed_secs`
      of the #ac("ESDM") and restores them.],
    [`unreachable`], [With the #ac("ESDM") unreachable, nothing is served from
      elsewhere: `/dev/esdm_urandom` fails with `ENOTCONN`, `/dev/esdm_random`
      and `/dev/esdm_pr` wait, with `O_NONBLOCK` `EAGAIN`; writes, the
      #ac("IOCTL", pl: true) and `/proc/esdm` fail with `ENOTCONN`.],
    table.cell(colspan: 2)[_Readers in the background, and speed_],
    [`loop` _DEV_ _SECONDS_], [Reads of 4096 bytes from _DEV_ for that long
      get random data and no error, also across a restart of the
      #ac("ESDM"). Ends with the line `loop reads=... errors=...`.],
    [`block` _DEV_], [A reader staying in `read()` until it is killed. Prints
      `blocking` once the device is open; from then on, the module cannot be
      unloaded.],
    [`throughput` \[_SOCKET_\]], [Informational: the speed of reads of 32
      bytes, 255 bytes, a page and 64 KiB through each device, and through
      the #ac("EGD") socket _SOCKET_ from user space; default
      `/run/esdm-egd.socket`.],
    [`stalled-writers`], [Writers whose data never arrives, more of them than
      the module has connections, do not keep other callers from the
      #ac("ESDM").
      Needs `CAP_SYS_PTRACE` or `vm.unprivileged_userfaultfd=1` for
      `userfaultfd(2)`.],
    table.cell(colspan: 2)[_Against a fake #ac("EGD") server_],
    [`fake-egd` _SOCKET_ _LOG_ `notop`|`mute`], [An #ac("EGD") server on
      _SOCKET_ in place of the #ac("ESDM"): answering like an #ac("ESDM") that
      is not operational (`notop`), or accepting connections and never
      answering (`mute`). Logs `listening`, then every connection, read and
      changing command to _LOG_. The module parameter `egd_socket` points the
      module at it.],
    [`addentropy` _LOG_], [Needs `CAP_SYS_ADMIN`; against `notop`.
      `RNDADDENTROPY` inserts all data without an entropy claim and credits
      it afterwards in a single step, with no more than the data has bits.],
    [`write-notop` _LOG_], [Against `notop`: a `write()` of either device by
      root inserts all data and sends nothing else, no credit.],
    [`addtoentcnt-signal` _LOG_], [Needs `CAP_SYS_ADMIN`; against `notop`,
      which answers the credit a second late. A signal during the wait must
      not restart the #ac("IOCTL"), which would credit once more.],
    [`poll-notop`], [Against `notop`: `poll()` of `/dev/esdm_random` reports it
      readable only when a read with `O_NONBLOCK` gets data, that is, never.],
    [`block-notop` _LOG_], [Against `notop`: the reads of either device, also
      with `O_SYNC`, wait for the #ac("ESDM"). A signal with `SA_RESTART`
      restarts them, one without ends them with `EINTR` and no data; with
      `O_NONBLOCK`, they give `EAGAIN`.],
    [`proc-notop`], [Against `notop`: the files of `/proc/esdm` hold what the
      fake server reports.],
    [`backoff` _LOG_ _SECONDS_], [Against `mute`: the reads fail, with
      `ETIMEDOUT` once a connection is made and with `ENOTCONN` while the
      module waits up to 2 seconds before the next.],
  ),
  caption: [Checks of `esdm-cdev-check`],
) <tab:tool-esdm-cdev-check-options>

#paragraph[Exit status][0: the check passed. 1: it failed, as the line
`FAIL:` says. 2: unknown check or wrong arguments; the usage lists every
check. 77: skipped, as the line `SKIP:` says – the module is not loaded, or
the check needs a capability that the caller does not have; `meson test` counts
77 as skipped.]

#block(breakable: false)[
#paragraph[Example][The checks of the meson suite, next to an #ac("ESDM")
serving its #ac("EGD") socket, as root:]

```sh
modprobe esdm_cdev
for c in reads "reads sync" nonblock poll pr writes ioctl-unpriv proc \
    stalled-writers; do
  esdm-cdev-check $c || break
done
```
]

Man page: `esdm-cdev-check`(8).
