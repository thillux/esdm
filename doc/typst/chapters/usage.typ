#import "../template.typ": *

= Using the ESDM <sec:usage>

This chapter addresses those who install and operate the #ac("ESDM"). It
describes how to start the #ac("ESDM") and check that it runs, how to read
random numbers, how the #ac("CUSE") daemons behave on a restart and under load,
how to serve consumers over the minimal #ac("EGD") interface, and how to harden
the setup. The compliant
configurations are the subject of chapter @sec:configurations.

== Starting the ESDM with systemd <sec:usage-systemd>

The #ac("ESDM") installs systemd units for all its components. Start them and
enable them for the next boot as follows:

```sh
systemctl enable --now esdm-server
systemctl enable esdm-server-suspend esdm-server-resume
systemctl enable --now esdm-linux-compat.target
```

The suspend helper keeps consumers from waiting on a suspended #ac("ESDM")
server; the resume helper makes it reseed its #ac("DRNG", pl: true) after the
resume. `esdm-linux-compat.target` starts the #ac("CUSE") daemons that serve
`/dev/random` and `/dev/urandom`, the `esdm-proc` daemon serving
`/proc/sys/kernel/random` and `esdm-kernel-seeder`. The latter seeds the kernel
#ac("RNG") from the #ac("ESDM") (section @sec:usage-kernel-rng).

Figure @fig:systemd-units shows how the units relate. The sockets activate
`esdm-server.service`, so it starts on the first request as well as at
boot; the #ac("EGD") sockets remain inactive until they are enabled. The
frontends want the server rather than require it: they keep running while the
server restarts and reconnect afterwards.

#figure(
  image("../figures/systemd-units.svg", width: 100%),
  caption: [The systemd units of the #ac("ESDM") – solid: requires, dashed:
  wants,
    dotted: a socket activating its service],
) <fig:systemd-units>

The #ac("ESDM") server starts early during boot. If its executable lies on a
file system mounted later – on Btrfs, for example, a separate subvolume for
`/usr/local` – the server is not started during boot. Install it on the root
file system.

The sockets of the #ac("ESDM") server lie in `/run`, where systemd expects them.
Without systemd and on systems using `/var/run`, configure their directory at
build time:

```sh
meson setup build -Desdm-server-rpc-path-unprivileged=/var/run \
  -Desdm-server-rpc-path-privileged=/var/run
```

With `-Dsystemd=enabled`, the default, the #ac("ESDM") server supports socket
activation.

== The Random Number Generator of the Kernel <sec:usage-kernel-rng>

The #ac("ESDM") does not replace the random number generator of the kernel
for the kernel itself. With the #ac("ESDM") installed, the consumers in user
space obtain their random numbers, and in particular their key material,
from the #ac("ESDM"): through the replaced devices and `getrandom()`, the
OpenSSL providers, the #ac("EGD") interface or the client libraries (chapter
@sec:integrations). The generation of keys can thereby be moved out of the
kernel altogether. A TLS library, an SSH daemon and the key exchange daemon
of a VPN generate their keys in user space, and for IPsec the daemon
hands the negotiated keys to the kernel.

The kernel keeps using its own generator for what it generates itself:
values that need not be secret but must not repeat or be predictable, such
as the #ac("IV", pl: true) of AES-CBC that the XFRM stack generates for the
packets of IPsec, sequence numbers and the randomization of addresses. Code
in the kernel cannot call the #ac("ESDM").

The generator of the kernel should therefore be seeded as well as the
system permits, and `esdm-kernel-seeder` does that from the #ac("ESDM")
(section @sec:tool-esdm-kernel-seeder): it writes 64 bytes from the full
path of the #ac("ESDM") into the kernel when it starts and then at the
interval it is given, 10 seconds in the delivered unit. The kernel mixes the
data in in every case; it credits them with the entropy the meson option
`linux-reseed-entropy-count` states, which is 0 by default, so that the
kernel's own accounting is unchanged unless the integrator decides
otherwise. The seeding is required when the #ac("ESDM") runs the interrupt
entropy source of `esdm_es`, which deprives the generator of the kernel of
its main entropy input, and it is advisable in every other configuration:
the kernel then never holds less than what its own sources gave it, and
with a seeded #ac("ESDM") it holds the output of a generator that all
configured entropy sources seeded. A build without the #ac("RPC") interface
has no kernel seeder (section @sec:if-deployment); the kernel then relies on
its own sources.

== Holding Back the Boot Until the ESDM Is Seeded <sec:usage-boot-gate>

`esdm-wait-until-fully-seeded.service` runs
`esdm-tool --wait-until-seeded -1` in a sandbox: the service ends once the
#ac("ESDM") is fully seeded and never earlier. A unit that is ordered after
this service starts only with a fully seeded #ac("ESDM") – e.g. `sshd`, which
generates its host keys at its first start:

```ini
# /etc/systemd/system/sshd.service.d/esdm.conf
[Unit]
Requires=esdm-wait-until-fully-seeded.service
After=esdm-wait-until-fully-seeded.service
```

Run `systemctl daemon-reload` afterwards. This approach works with every build
and holds back exactly the services that need random numbers at their start.

Holding back the whole boot requires a build without socket activation
(`-Dsystemd=disabled`). With socket activation, the default,
`esdm-server.service` keeps the default dependencies of systemd and starts
after `basic.target`, too late to hold back the services ordered after it.
Without socket activation, the server starts immediately after
`local-fs.target`; ordering the wait before `basic.target` then holds back
every service with the default dependencies, as these services start after
`basic.target`:

```ini
# /etc/systemd/system/esdm-wait-until-fully-seeded.service.d/boot.conf
[Unit]
DefaultDependencies=no
After=local-fs.target esdm-server.service
Before=basic.target
```

The wait has no limit: if the entropy sources never deliver, the boot stops
at this point, which is what an environment that must not run unseeded
requires. To let the boot continue after a timeout instead, override
`ExecStart=` with
`esdm-tool --wait-until-seeded 300`; the #ac("ESDM") interfaces that wait (table
@tab:interfaces) still serve nothing before the #ac("ESDM") is seeded. Test the
ordering on the target system: `systemd-analyze critical-chain` shows what
waited for what.

== Checking That the ESDM Runs <sec:usage-check>

`esdm-tool` queries the #ac("ESDM") server for its state. "Fully seeded: true"
indicates that the #ac("ESDM") is operational, "Standards compliance" lists the
classes the build provides (section @sec:examples), and every entropy source
reports the entropy it holds and the rate it is credited with. An excerpt of a
default build:

```console
$ esdm-tool --status
Library version: 1.2.4
Test mode: false
DRNG name: builtin SP800-90A Hash DRBG
Security strength bits: 256
DRNG instances: 16
Standards compliance: NTG.1(2011)
Fully seeded: true
Entropy level bits: 392
Entropy sources:
 Interrupt (ID 0):
  Disabled: missing kernel support
 JitterRNG (ID 2):
  Available entropy: 256
  Entropy rate per 256 data bits: 256
 CPU (ID 3):
  Available entropy: 8
  Entropy rate per 256 data bits: 8
...
```

`esdm-tool --wait-until-seeded 60` waits up to 60 seconds for the #ac("ESDM") to
become operational, e.g. in a boot script, and `esdm-tool --status-json`
provides the same information as a #ac("JSON") document.

== Reading Random Numbers <sec:usage-reading>

Unmodified software keeps using the Linux interfaces, which the #ac("ESDM")
serves once its frontends run. Which interface serves which path is listed
in table @tab:interfaces:

```sh
head -c 32 /dev/random | od -An -tx1    # CUSE daemon, full path
head -c 32 /dev/esdm_pr | od -An -tx1   # esdm_cdev, prediction resistance
esdm-tool --get-random 32               # RPC interface, hex encoded
```

A C program calls `getrandom(2)` as on any Linux system;
`libesdm-getrandom.so` serves it from the #ac("ESDM"):

```c
#include <sys/random.h>

uint8_t key[32];

/* full path; GRND_RANDOM selects the prediction resistance path */
if (getrandom(key, sizeof(key), 0) != sizeof(key))
	abort();
```

OpenSSL 3 draws its random numbers from the #ac("ESDM") with the RAND provider:

```ini
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
random = random_sect

[provider_sect]
esdm = esdm_sect
default = default_sect

[default_sect]
activate = 1

[esdm_sect]
activate = 1
module = /usr/lib64/libesdm-rng-provider.so

[random_sect]
random = CTR-DRBG
properties = provider=esdm
seed = SEED-SRC
seed_properties = provider=esdm
```

The `default` provider stays active, as the rest of OpenSSL needs its
algorithms; only the random section is redirected
(`esdm-openssl-provider`(7)).

== The CUSE Daemons <sec:usage-cuse>

=== Restarting a CUSE Daemon <sec:usage-cuse-restart>

A daemon that waits in `select(2)` or `poll(2)` on `/dev/random` or
`/dev/urandom` of the #ac("CUSE") daemons `esdm-cuse-random` and
`esdm-cuse-urandom` loses access to the #ac("ESDM") when the #ac("CUSE") daemon
restarts:

+ The daemon waits in `select(2)` or `poll(2)`.

+ The #ac("CUSE") daemon terminates, which wakes the daemon without an error.

+ The next operation of the daemon, e.g. injecting entropy with the #ac("IOCTL")
  `RNDADDENTROPY`, fails with `ENOTCONN`.

+ If the daemon now reopens the device file while the #ac("CUSE") daemon is
  still restarting, it opens the device file of the kernel and no longer
  communicates with the #ac("ESDM").

#par(first-line-indent: 0pt)[Declare a dependency on `esdm-cuse-random`
and `esdm-cuse-urandom` in the systemd unit of such a daemon: systemd then
stops and restarts it together with the #ac("CUSE") daemons.]

=== Response Times <sec:usage-cuse-latency>

Reading `/dev/random` or `/dev/urandom` of the #ac("CUSE") daemons may take
longer than reading the device files of the kernel – waits of 200 ms have been
observed. Two measures shorten these waits, at a cost.

#paragraph[Shorter timeouts][The client of the #ac("ESDM") server abandons a
connection after $2^n$ nanoseconds and reconnects. The meson options
`client-connect-timeout-exponent` and `client-rx-tx-timeout-exponent` set
$n$, 28 by default; a value of 22 reduces the timeout to about 4 ms.
Reconnecting takes time itself: raise `client-reconnect-attempts` when
lowering the timeouts.]

#paragraph[Higher priority][The following settings in the units
`esdm-cuse-random.service`, `esdm-cuse-urandom.service` and
`esdm-server.service` give the daemons precedence over all other
applications:]

```ini
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=99
Nice=-20
```

== The EGD Interface <sec:usage-egd>

The #ac("ESDM") server can serve the protocol of the Entropy Gathering Daemon
(#ac("EGD"), `egd.pl` and re-implementations such as `prngd`) as described in
section @sec:egd. Consumers that can obtain entropy only from an
#ac("EGD") – libgcrypt built with `--enable-random=egd` or OpenSSL's
`RAND_egd()` – are then served by the #ac("ESDM") without modification.

The interface is disabled by default, unless the server is built without the
#ac("RPC") interface: such a server has no other interface and serves the
socket without further configuration (section @sec:if-deployment). Enable it
with the socket unit, which defines the path and the access mode of the
socket:

```sh
systemctl enable --now esdm-server-egd.socket
systemctl restart esdm-server
```

The #ac("ESDM") server takes over the socket when it starts, so a running server
has to be restarted once; `esdm-server.service` is only ordered after the
socket unit and does not require it. The meson option
`esdm-server-egd-socket-path` sets the path, `/run/esdm-egd.socket` by
default. Without systemd, the server binds the socket itself:

```sh
esdm-server --egd_socket /run/esdm-egd.socket
```

The socket is accessible to all users – mode 0666, or the `SocketMode=` of
the unit – like the unprivileged #ac("RPC") socket, and so are its operations:

- Reading random numbers is equivalent to the unprivileged #ac("RPC") interface.

- Data written with the #ac("EGD") command "write entropy" goes into the
  auxiliary pool. Its entropy claim is honored for a caller with #ac("UID") 0
  only; the data of other callers is inserted without entropy credit, as on the
  #ac("RPC") interface.

#par(first-line-indent: 0pt)[The protocol is minimal: a one-byte command and
a one-byte length, at most 255 bytes at a time – 64 KiB with the bulk and
status commands of the #ac("ESDM"), section @sec:egd – in the clear over a
local socket. It needs no serialization library on either side, which keeps the
parser in the server small. A sandboxed process, the OpenSSL #ac("EGD")
providers and the kernel module `esdm_cdev` use the protocol because of this
small attack surface. Applications that require the full interface use the
#ac("RPC") interface, the device files or `getrandom(2)`. Point a consumer at
the socket, e.g. libgcrypt at build time with
`--with-egd-socket=/run/esdm-egd.socket` or at runtime with
`gcry_control(GCRYCTL_SET_RNDEGD_SOCKET, "/run/esdm-egd.socket")`.]

=== Clients of the ESDM <sec:usage-egd-clients>

Two components of the #ac("ESDM") use the #ac("EGD") interface where the
#ac("RPC") interface cannot be reached, e.g. in a chroot that can be given
exactly one socket:

- `libesdm_egd_client` (`esdm_egd_client.h`) is a client library for the
  protocol. A client owns one connection, serializes the requests on it,
  bounds every wait and reconnects after a restart of the #ac("ESDM") server or
  a `fork()` of the calling process.

- `libesdm-egd-provider.so` is an OpenSSL 3 RAND provider built on this library.
  Unlike `libesdm-rng-provider.so`, it needs no #ac("RPC") client; it tags its
  algorithms with `provider=esdm-egd`, so both can be loaded side by side.
  `libesdm-egd-provider-pr.so` is served by the prediction resistance socket
  and tags its algorithms with `provider=esdm-egd-pr`.

```ini
[provider_sect]
esdm_egd = esdm_egd_sect

[esdm_egd_sect]
activate = 1
module = /usr/lib64/libesdm-egd-provider.so
egd_socket = /run/esdm-egd.socket

[random_sect]
random = CTR-DRBG
properties = provider=esdm-egd
seed = SEED-SRC
seed_properties = provider=esdm-egd
```

Without the key `egd_socket`, `libesdm-egd-provider.so` takes the socket
from the environment variable `ESDM_EGD_SOCKET` – ignored in a process that
runs with raised privileges (`secure_getenv`) – and otherwise uses the path
of the meson option `esdm-server-egd-socket-path`.
`libesdm-egd-provider-pr.so` does not read the variable: without the key it
uses the path of `esdm-server-egd-pr-socket-path`.

=== Prediction Resistance <sec:usage-egd-pr>

The #ac("EGD") protocol cannot request prediction resistance per request. A
second socket provides it: it serves the reads 0x01 and 0x02, and the bulk
read 0xeb of 0x01, with `esdm_get_random_bytes_pr_noblock()` instead of
`esdm_get_random_bytes_full_noblock()`\; all other commands behave as on the
first socket.

```sh
systemctl enable --now esdm-server-egd-pr.socket
```

Without systemd, `esdm-server --egd_socket_pr <path>` binds it; the meson
option `esdm-server-egd-pr-socket-path` sets its path. Either socket can be
enabled on its own. The ordinary provider refuses a request asking for
prediction resistance instead of serving ordinary random numbers, while
`libesdm-egd-provider-pr.so` accepts it. Its answers take as long as the
entropy sources need to deliver the entropy, as it delivers no more than
the entropy sources have just produced.

=== Sandboxed Consumers <sec:usage-egd-sandbox>

The #ac("EGD") interface reaches consumers that confine themselves after
start-up. OpenSSH is the reference case: sshd hands the key exchange to a
privilege-separated child, which re-executes itself and is then confined by a
seccomp filter permitting little more than `read`, `write`, `poll`, `close`
and `getpid`; `socket`, `connect`, `sendto` and `recvfrom` kill it. The client
therefore writes with `write` and blocks SIGPIPE with `rt_sigprocmask`
instead of using `MSG_NOSIGNAL`.

The #ac("EGD") provider works in this environment, as its client connects when
OpenSSL loads the provider – before the child confines itself – and stays within
the permitted calls afterwards. Setting `OPENSSL_CONF` for the units `sshd` and
`sshd-keygen` suffices; on NixOS:

```nix
let conf = "/etc/ssl/openssl-esdm-egd.cnf"; in {
  systemd.services.sshd.environment.OPENSSL_CONF = conf;
  systemd.services.sshd-keygen.environment.OPENSSL_CONF = conf;
}
```

`nix build .#checks.<system>.egd_openssh` tests this setup. A confined
process cannot open a connection: after a restart of the #ac("ESDM") server,
and in a child forked after the confinement, which gives up the connection
it inherited, its client reports a failure, whereas an unconfined consumer
reconnects transparently.

== Performance <sec:usage-performance>

Every request to the #ac("ESDM") leaves the process of the consumer, which
determines its cost:

- A call of the #ac("RPC") client library is one round trip over a Unix
  domain socket for up to about 64 KiB of data; larger requests take several.
- `getrandom()` through the shim is at least one such round trip per call,
  however small the request, whereas the kernel answers a system call
  directly.
- A read of a #ac("CUSE") device takes two hops: from the kernel to the
  daemon over #ac("FUSE") and from the daemon to the server over the
  #ac("RPC") interface.
- The prediction resistance path seeds before every chunk and delivers at
  most the fresh entropy, so its rate is that of the entropy sources, not
  that of the #ac("DRNG").
- A request that coincides with a reseed waits for it; a build with `sp80090c`
  or `ais2031_drg4` attempts a reseed of a #ac("DRNG") instance after 98,304
  output bits, i.e. after 384 requests of 32 bytes or 3 requests of 4096
  bytes.

#par(first-line-indent: 0pt)[Two tools measure this cost.
`esdm-tool --benchmark` reports the request and data rates of a running server
for the full and the prediction resistance path (section @sec:tool-esdm-tool).
The benchmark `rpc_latency_bench` of the test suite starts a server of its own
and measures `esdm_rpcc_get_random_bytes_full` with 32 bytes per request from 1,
4 and 8 threads for 10 seconds each, three times, keeping every latency:]

```sh
meson setup build -Dtestmode=enabled && meson compile -C build
meson test -C build --benchmark          # results in meson-logs/testlog.txt
```

Table @tab:rpc-latency shows one such run. It is the measurement of one
machine, not a specification: an Intel Core i7-1355U notebook with 10
#ac("CPU", pl: true), Linux 7.3, the default build with the builtin Hash
#ac("DRBG") and test mode, on 2026-11-27, with client and server on the same
machine and other workloads running concurrently.

#figure(
  table(columns: (auto, 1fr, 1fr, 1fr, 1fr, 1fr), align: left + horizon,
    table.header([Threads], [Requests/s], [Median], [99 %], [99.99 %],
      [Maximum]),
    [1], [97,000], [10.5 µs], [15.6 µs], [0.27 ms], [1.1 ms],
    [4], [285,000], [13.3 µs], [29.1 µs], [0.35 ms], [2.8 ms],
    [8], [401,000], [17.9 µs], [46.5 µs], [0.74 ms], [3.3 ms],
  ),
  caption: [Latency of 32-byte requests over the #ac("RPC") interface on one
    machine: the middle of three runs, the maximum over all three],
) <tab:rpc-latency>

#paragraph[Output paths][`esdm-tool --benchmark` on the same machine and
build, against a server seeded by the Jitter #acs("RNG") and the #ac("CPU")
source, yields table @tab:perf-paths and figure @fig:perf-rate. The full path
is bounded by the round trip for small requests and by the #ac("DRNG") for
large ones. The prediction resistance path serves about 143 calls per second
regardless of the request size up to 32 bytes, the most one call delivers,
and therefore at most about 4.5 kB/s: every call waits for fresh entropy,
here from the Jitter #acs("RNG").]

#figure(
  table(columns: (1fr, auto, auto, auto), align: left + horizon,
    table.header([Path], [Request], [Requests/s], [Data rate]),
    [Full, `esdm_rpcc_get_random_bytes_full`], [32 bytes], [113,000],
      [3.6 MB/s],
    [], [4096 bytes], [26,000], [107 MB/s],
    [], [65,512 bytes], [3,100], [206 MB/s],
    [Prediction resistance, `esdm_rpcc_get_random_bytes_pr`], [32 bytes],
      [143], [4.6 kB/s],
    [], [64 bytes], [70], [4.5 kB/s],
  ),
  caption: [Rates of the output paths over the #ac("RPC") interface, one
    client thread, on one machine],
) <tab:perf-paths>

#let perf-plot = {
  // Data rate in bytes per second over the request size, both logarithmic
  let full = ((1, 74836), (2, 293889), (4, 572780), (8, 1172000),
    (16, 2313000), (32, 3614000), (64, 5622000), (128, 11692000),
    (256, 20937000), (512, 38796000), (1024, 56113000), (2048, 81061000),
    (4096, 107467000), (8192, 143730000), (16384, 216168000),
    (32768, 168936000), (65512, 205938000))
  let pr = ((1, 145), (2, 289), (4, 578), (8, 1144), (16, 2289), (32, 4581),
    (64, 4485))
  let (w, h) = (120mm, 52mm)
  let x(size) = calc.log(size, base: 2) / 16 * w
  let y(rate) = h - (calc.log(rate, base: 10) - 2) / 7 * h
  let series(points, color, dash) = {
    for i in range(points.len() - 1) {
      let (a, b) = (points.at(i), points.at(i + 1))
      place(line(start: (x(a.at(0)), y(a.at(1))),
        end: (x(b.at(0)), y(b.at(1))),
        stroke: (paint: color, thickness: 1.2pt, dash: dash)))
    }
    for q in points {
      place(dx: x(q.at(0)) - 1.5pt, dy: y(q.at(1)) - 1.5pt,
        circle(radius: 1.5pt, fill: color))
    }
  }
  set text(font: sans-font, size: 8pt, fill: muted)
  block(width: w + 24mm, height: h + 12mm, inset: (left: 18mm, top: 2mm), {
    for (rate, label) in ((1000, "1 kB/s"), (1000000, "1 MB/s"),
      (1000000000, "1 GB/s")) {
      place(line(start: (0mm, y(rate)), end: (w, y(rate)),
        stroke: 0.5pt + rule))
      place(dx: -17mm, dy: y(rate) - 3pt, box(width: 15mm, align(right,
        label)))
    }
    place(line(start: (0mm, h), end: (w, h), stroke: 0.6pt + muted))
    place(line(start: (0mm, 0mm), end: (0mm, h), stroke: 0.6pt + muted))
    for size in (1, 16, 256, 4096, 65536) {
      place(dx: x(size) - 8mm, dy: h + 2pt, box(width: 16mm, align(center,
        str(size))))
    }
    place(dx: w / 2 - 20mm, dy: h + 5mm, box(width: 40mm, align(center,
      [request size in bytes])))
    series(full, accent, "solid")
    series(pr, source-strong, "dashed")
    place(dx: x(600), dy: y(300000000), text(fill: accent-text)[full path])
    place(dx: x(100), dy: y(40000), text(fill: source-strong)[prediction
      resistance path])
  })
}

#figure(perf-plot,
  caption: [Data rate over the request size for the full path (solid) and the
    prediction resistance path (dashed), one client thread, on one machine],
) <fig:perf-rate>

#paragraph[CUSE devices][The #ac("CUSE") devices require root and were measured
in a #ac("KVM") guest of the same machine: 4 virtual #ac("CPU", pl: true),
Linux 6.18, the release build without test mode, the Jitter #acs("RNG") as
the only credited source, `dd` reading the devices three times each (table
@tab:perf-cuse). `/dev/random` and `/dev/urandom` do not differ. In the same
guest, `esdm-tool` reaches 21,700 requests of 32 bytes per second over the
#ac("RPC") interface and 47 on the prediction resistance path: a read of a
device costs about one and a half times as much as the #ac("RPC") call behind
it, and large reads stay near 3.5 MB/s.]

#figure(
  table(columns: (1fr, auto, auto), align: left + horizon,
    table.header([Read size], [Reads/s], [Data rate]),
    [32 bytes], [14,000], [0.45 MB/s],
    [4096 bytes], [640], [2.6 MB/s],
    [65,536 bytes], [54], [3.5 MB/s],
  ),
  caption: [Reads of the #ac("CUSE") `/dev/random` and `/dev/urandom` in a
    #ac("KVM") guest, one reader],
) <tab:perf-cuse>

#paragraph[Seeding time and memory][On the machine of table
@tab:rpc-latency, `esdm-server` is operational 58 ms after its start, in
each of seven starts, with the 256 bits of the Jitter #acs("RNG")\; in the
guest, systemd reports 284 ms for the start of `esdm-server.service`. The
time depends on the entropy sources: a source that has to collect first –
the interrupt and scheduler sources after boot – takes as long as its events
take. The server holds 7.1 MB of resident memory when idle and peaked at
8.1 MB during the benchmark, with 10 #ac("DRNG") instances and 16 to 18
threads; with `--small_memory` it held 5.0 MB with 7 threads. The memory of
the #ac("CUSE") daemons was not measured.]

== Updating <sec:usage-updating>

The #ac("RPC") protocol carries no version and no handshake: a request names
its call by position and nothing indicates to a client that the server belongs
to another release. Its wire format is not stable between releases. The client
libraries, the programs built on them – the #ac("CUSE") daemons, `esdm-proc`,
`esdm-kernel-seeder`, `esdm-tool`, the `getrandom` shim, the OpenSSL providers –
and `esdm-server` are therefore updated together, and long-running consumers are
restarted after an update. The interfaces that do check a version are the status
in shared memory, which a reader ignores unless its version matches, and the
protocol of the external entropy sources, where server and provider reject a
message of another version. The #ac("EGD") commands of section
@sec:integration-egd are fixed and carry no version either; the kernel module
`esdm_cdev` and other #ac("EGD") clients keep working across an update of the
server.

== Monitoring <sec:usage-monitoring>

The #ac("ESDM") raises no alert of its own; an operator watches its log and
its status:

/ Self test failure: `esdm-server` logs "Self test failed" as an error and
  stops all output; `periodic_self_test` in `esdm-tool --status-json` then
  reports the state `failed`. Only a restart of the server ends this state.
/ Not operational or not fully seeded: `esdm-tool --is-running` exits with
  status 1 while the server cannot be reached or is not operational; the
  status shows `fully_seeded` for the #ac("ESDM"), for its initial and its
  prediction resistance #ac("DRNG"), and the entropy available per source;
  `esdm-tool --drng-status` shows every #ac("DRNG") instance.
/ Entropy source failures: a source that cannot deliver credits nothing and
  logs a warning – the sources of the kernel module `esdm_es` "failed to
  obtain entropy from ES", the external entropy source "not reachable, no
  entropy until it is"\; the
  #ac("eBPF") sources report `health_test_failures` and `permanent_failure`
  in their status, the kernel module `esdm_es` reports health test failures
  in the kernel log.
/ System events: with the kernel module `esdm_es` loaded, `esdm-server` logs
  "Kernel reports suspend", "resume", "shutdown" or "VM generation change"
  with a count, as a warning. On suspend and shutdown it raises the suspend
  notification of the status segment, as `SIGUSR1` from
  `esdm-server-signal-helper` does; on resume it forces a reseed of every
  #ac("DRNG")\; on a change of the #ac("VM") generation, which a clone or a
  restored snapshot causes, it drops all credited entropy, marks every
  #ac("DRNG") as not fully seeded and seeds all of them anew (section @sec:vm-clone, table @tab:system-events).
/ Fallback to the kernel: the #ac("CUSE") daemons log a read served by the
  kernel device only at the verbose level 4, above the level 3 of their
  units, and the `getrandom` shim logs nothing: with the defaults a fallback
  is not visible. An operator who needs this information checks that
  `esdm-server` is active and `esdm-tool --is-running` succeeds, raises the
  level of the #ac("CUSE") units to 4, or uses the interfaces that do not fall
  back: the #ac("RPC") client library, the #ac("EGD") sockets and `esdm_cdev`
  (table @tab:integration-gate).

== Hardening <sec:usage-hardening>

`esdm-server`, the #ac("CUSE") daemons and `esdm-proc` drop their privileges
to the user "nobody". Run `esdm-server` and the #ac("CUSE") daemons as a
dedicated user instead, which nothing else uses (option `--username`): other
processes running as "nobody" then can neither trace these daemons with
`ptrace(2)` nor access the semaphores and the shared memory segment the
daemons synchronize with, and these daemons cannot access the objects of such
processes either. `esdm-proc` has no such option and stays "nobody".
Chapter @sec:hardening describes the hardening that the #ac("ESDM") itself
provides.
