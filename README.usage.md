# User Guidance

This document contains some hints about special cases that should be considered
when using the ESDM.

## CUSE Daemon Restart and Select/Poll

Assume you have a daemon that has a select(2) or a poll(2) on either
`/dev/random` or `/dev/urandom` where the device file is served by the ESDM
CUSE helper (i.e. `esdm-cuse-random` or `esdm-cuse-urandom`).

Now, you need to restart the ESDM CUSE daemon. The following happens:

1. The user daemon sleeps in select(2) or poll(2).

2. The ESDM CUSE daemon terminates.

3. The user daemon is woken up by the ESDM CUSE daemon termination, i.e. the
   select(2)/poll(2) returns without an error.

4. The user daemon now tries, for example, to inject entropy using the `ioctl`
   of `RNDADDENTROPY`. This now *fails* with the error code `ENOTCONN`. Now,
   it is possible that the user daemon tries to close and re-open the file
   descriptor for the device file. Yet, since the ESDM CUSE daemon is
   either stopped or in the process of restarting, the user daemon now *may*
   open the "real" device file from the kernel. Thus, when the user daemon
   waits with select(2)/poll(2), it is not interfacing with the ESDM any more.

This situation can be remedied if such user daemon has a `systemd` unit file
which declares a dependency on the `esdm-cuse-random` and/or `esdm-cuse-urandom`
`systemd` units. This implies that by stopping or restarting the ESDM CUSE
daemons, the user daemon is equally stopped/restarted.

## CUSE Daemon Connection Duration

It is possible that when requesting data from `/dev/random` or `/dev/urandom`
that are provided by the CUSE daemons, a wait time that is longer than with
the Linux kernel device files is visible. For example, it is possible that
wait times of 200ms may be observed.

If guaranteed lower wait times are required, then the following approach
can be taken. However, that approach implies that the priority of the CUSE
daemons increase such that they have precedence over other applications. Also,
the change in the reconnection timeout implies that it is more likely that
a reconnection is performed which in itself requires some overhead.

The following subsections outlined the possible options which partially or
all can be applied.

### Lower Connection Timeout

The waits of the connection to the ESDM server can be lowered with the
configuration options `client-connect-timeout-exponent` (the pause between two
connection attempts) and `client-rx-tx-timeout-exponent` (the wait for the
socket to take a request, and the interval at which a client waiting for an
answer checks whether to give up). Setting them to, for example, 22 implies
waits of 4ms. The wait for an answer itself is fixed: an unprivileged request
is sent again on a new connection after about 1.6 seconds, and given up after
about 6.4.

### Increase Scheduling Priority of ESDM Daemons

The following options can be added to the `systemd` unit files of
`esdm-cuse-random.service`, `esdm-cuse-urandom.service`, and/or
`esdm-server.service` which increase the scheduling priorities of those
daemons compared to other applications:

```
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=99
Nice=-20
```
## FIPS 140 Compliance

To ensure FIPS 140 compliance, enable the compile time option `fips140`.
In addition, the FIPS 140 mode must be enabled by either:

* Setting the environment variable `ESDM_SERVER_FORCE_FIPS`, or

* Booting the Linux kernel with the kernel command line option `fips=1`

This requires an HMAC file next to every component of the module. They hold the
reference values of the pre-operational integrity test, and the server refuses
to start without them - a missing reference value is a failed integrity test,
not a prompt to compute one over whatever is on disk.

The components are:

* the `esdm-server` executable,

* the ESDM library it loads, `libesdm.so.1`,

* the Jitter RNG, `libjitterentropy.so.3`, where the build uses it as an
  entropy source, and

* the library providing the cryptography where that is not the built-in
  implementation: `libcrypto.so` (OpenSSL), `libgnutls.so` together with
  `libnettle.so`, `libbotan-3.so` or `libleancrypto.so`.

The last two are attested wherever they are loaded from. The server stops at
the first component whose reference value is missing or does not match, and
names that one only - so write the reference values of all of them when the
module is installed, over the files as they were built, rather than finding
them one start at a time:

```
esdm-tool --fips-targetfile /usr/bin/esdm-server \
          --fips-checkfile /usr/bin/.esdm-server.hmac
esdm-tool --fips-targetfile /usr/lib64/libesdm.so.1 \
          --fips-checkfile /usr/lib64/.libesdm.so.1.hmac
esdm-tool --fips-targetfile /usr/lib64/libjitterentropy.so.3 \
          --fips-checkfile /usr/lib64/.libjitterentropy.so.3.hmac
```

Use the library path the loader resolves - the SONAME (`libesdm.so.1`), not the
versioned file behind it - as that is the name the integrity test looks up. The
reference value has to sit in the same directory as the file it covers, so a
library in a read-only location has to receive it from whoever installs that
location. `esdm-tool` never overwrites an existing HMAC file, so remove the old
one when a component is updated.

## SP800-90C Compliance

When enabling the compile time option of either `fips140` or `sp80090c`,
the ESDM server operates compliant to SP800-90C right away when using the
interfaces that are documented to block until sufficient initial entropy
is present.

## AIS 20/31 (2024) Compliance

When enabling the compile time option of `ais2031_ntg1`, the ESDM server
operates NTG.1 compliant to AIS 20/31 (2024, version 3.0) right away when using
the interfaces that are documented to block until sufficient initial entropy
is present. On top of the 256 bits of entropy the initial seeding of a DRNG
needs in any case - 384 bits with the SP800-90C oversampling of an `sp80090c`,
`fips140` or `ais2031_drg3` build - two entropy sources have to deliver 240 bits
of entropy each before a DRNG is considered fully seeded.

If the jitter RNG is operated in its own NTG.1 mode - the compile time option
`es_jent_ntg1` together with jitterentropy 3.7.0 or later providing secure
memory - then it is an NTG.1 conformant RNG by itself. In that case a second
entropy source adds nothing to the NTG.1 property and the ESDM server seeds
from the jitter RNG without one, once it delivered at least 240 bits of entropy
and the entropy sources together the 256 (384) bits of the initial seeding:
unless other entropy sources make up the difference, the jitter RNG has to
deliver all of them itself. The requirement is bound to the jitter RNG: another
entropy source delivering the same amount of entropy does not replace it.

The compile time option of `ais2031_drg4` is independent of it and caps the
request size based reseeding limits to the values required by DRG.4.10 of the
same standard, i.e. the fully seeded state is lost after 2**17 output bits
without a successful reseed, and a reseed is attempted after three quarters of
that, 98304 output bits. The option `ais2031_drg3` skips these caps.

## AIS 20/31 (2011) Compliance

The ESDM server operates NTG.1 compliant to AIS 20/31 (2011 version)
right away when using one of the following interfaces:

* `esdm_get_random_bytes_pr` ESDM library interface,

* `esdm_rpcc_get_random_bytes_pr` ESDM RPC interface,

* open the CUSE daemon provided `/dev/random` or `/dev/urandom` with the flag
  `O_SYNC`

* request random numbers from the getrandom(2) system call ESDM replacement
  with the flag `GRND_RANDOM`

## SystemD-based Startup

To start up the different ESDM components with systemd, execute the following
commands:

1. Start server: `systemctl start esdm-server`

2. Enable server: `systemctl enable esdm-server`

3. Enable the suspend helper: `systemctl enable esdm-server-suspend`

4. Enable the resume helper: `systemctl enable esdm-server-resume`

5. Start the different clients: `systemctl start esdm-linux-compat.target`

6. Enable the different clients: `systemctl enable esdm-linux-compat.target`

7. Optional (if the esdm_es_irq kernel patch is applied and thus the kernel
   random number generator must be seeded from user space):
   `systemctl start esdm-kernel-seeder`

8. Optional (if step 7 identified that it needs to be started):
   `systemctl enable esdm-kernel-seeder`

Note, a pitfall may be the use of BtrFS where `/usr/local` is a separate
subvolume. The `esdm-server` wants to be invoked very early in the boot cycle
at a time the `/usr/local` is not yet mounted which leads to the situation that
the `esdm-server` is not started during boot. Thus, the `esdm-server` should
not be deployed on a BtrFS subvolumes.

In order to support systemd by default, the IPC path is set to `/run` as a preset.
If your system uses e.g. `/var/run` and no systemd, set instead:

```
   -Desdm-server-rpc-path-unprivileged=/var/run
   -Desdm-server-rpc-path-privileged=/var/run
```

In order to use systemd socket activation with esdm, compile esdm with `-Dsystemd=enabled` (default).

## EGD Compatibility Interface

The `esdm-server` can additionally serve the protocol of the Entropy Gathering
Daemon (EGD, `egd.pl` and its re-implementations like `prngd`). It allows
consumers which only know how to obtain entropy from an EGD - such as
libgcrypt built with `--enable-random=egd` or OpenSSL's `RAND_egd()` - to be
served by the ESDM without any modification.

The interface is disabled by default. It is enabled in either of two ways:

* With systemd, by starting the socket unit that carries it - this is the
  recommended way, as the unit defines the path and the access mode of the
  socket:

```
   systemctl enable --now esdm-server-egd.socket
   systemctl restart esdm-server
```

  The `esdm-server.service` is only ordered after that socket unit and does not
  require it, so the EGD interface stays off until the socket unit is started.
  Because the descriptor is handed over when the server starts, an already
  running `esdm-server` has to be restarted once after enabling the socket.
  The socket path is set at build time with
  `-Desdm-server-egd-socket-path=/run/esdm-egd.socket`.

* Without systemd, by naming the Unix domain socket on the command line:

```
   esdm-server --egd_socket /run/esdm-egd.socket
```

The socket carries access rights for all users - taken from the `SocketMode=`
of the socket unit, or set to 0666 for a socket bound by the server itself,
just like the unprivileged RPC socket. The operations reachable through it are
unprivileged as well:

* Obtaining random numbers is equivalent to what the unprivileged RPC
  interface offers.

* Data written by a caller with the EGD "write entropy" command is inserted
  into the auxiliary pool. The entropy claim the protocol allows the caller to
  attach to that data is only honored for a privileged (UID 0) caller - the
  data of an unprivileged caller is inserted without any entropy credit. This
  mirrors the rule of the RPC interface, where inserting data with an entropy
  claim is reserved for the privileged interface.

* The ESDM's own commands changing the entropy accounting or the DRNGs, see
  below, are refused to everybody but a privileged (UID 0) caller in the same
  way.

Note that the EGD protocol transfers data in the clear over the socket and
caps every single transfer at 255 bytes. It exists for compatibility with
legacy consumers - new applications should use the ESDM RPC interface, the
device files or `getrandom(2)`.

Point the consumers at the socket, e.g. for libgcrypt at build time with
`--with-egd-socket=/run/esdm-egd.socket` or at runtime with
`gcry_control(GCRYCTL_SET_RNDEGD_SOCKET, "/run/esdm-egd.socket")`.

### ESDM extensions of the protocol

What the EGD protocol cannot express, the socket offers with commands of the
ESDM's own. Their codes lie far from the five standard ones, so no EGD client
sends one by accident, and an EGD daemon that does not know them closes the
connection as it does for any unknown command. Numbers are big endian, like
those of EGD; `service-egd/esdm_egd_protocol.h` holds the wire format.

| Command | Request | Answer |
|---------|---------|--------|
| `0xe0` PR read non-blocking | length byte | like `0x01`, from the prediction resistance DRNG |
| `0xe1` PR read blocking | length byte | like `0x02`, from the prediction resistance DRNG |
| `0xe2` read unseeded | length byte | like `0x01`, `/dev/urandom` semantics; empty before the ESDM is operational |
| `0xe3` get state | - | count byte, then that many 4 byte fields: flags (operational, fully seeded), entropy count, pool size, write wakeup threshold, reseed seconds |
| `0xe4` status | - | 4 byte length (at most 65536), the status text |
| `0xe5` status JSON | - | 4 byte length, the status as JSON document (empty if it does not fit) |
| `0xe6` add to entropy count | 4 byte bits | 4 byte status - privileged |
| `0xe7` clear pool | - | 4 byte status - privileged |
| `0xe8` reseed | - | 4 byte status - privileged |
| `0xe9` set write wakeup threshold | 4 byte bits | 4 byte status - privileged |
| `0xea` set reseed seconds | 4 byte seconds | 4 byte status - privileged |

The privileged ones change the entropy accounting or the DRNGs and are only
carried out for a peer connected with UID 0 - the same rule as for the entropy
claim of the standard write command. Anybody else is answered `-EPERM`, and the
connection stays usable. The status is 0 or a negative errno.

### Own consumers of the EGD interface

Two components of the ESDM use the interface themselves, and both are useful
where the RPC interface cannot be reached - a chroot that can be given exactly
one socket, for instance:

* `libesdm_egd_client` (`esdm_egd_client.h`) is a small client library for the
  protocol. A client owns one connection, serializes the requests on it, bounds
  every wait, and reconnects on its own after a restart of the daemon or a
  `fork()` of the calling process.

* `libesdm-egd-provider.so` is an OpenSSL 3 RAND provider built on it. Unlike
  `libesdm-rng-provider.so` it needs no RPC client, and it tags its algorithms
  with `provider=esdm-egd` so both can be loaded side by side. Its counterpart
  `libesdm-egd-provider-pr.so` serves every request with prediction resistance,
  as described below, and tags its algorithms `provider=esdm-egd-pr`:

```
   [provider_sect]
   esdm_egd = esdm_egd_sect

   [esdm_egd_sect]
   activate = 1
   module = /usr/local/lib64/libesdm-egd-provider.so
   egd_socket = /run/esdm-egd.socket

   [random_sect]
   random = CTR-DRBG
   properties = provider=esdm-egd
   seed = SEED-SRC
   seed_properties = provider=esdm-egd
```

  Without the `egd_socket` key the socket is taken from the `ESDM_EGD_SOCKET`
  environment variable and, failing that, from the path the provider was built
  with. Both providers use the same socket.

### Prediction resistance

The EGD protocol has no notion of prediction resistance and therefore no way to
ask for it. The ESDM serves it on the same socket with read commands of its
own, answered from `esdm_get_random_bytes_pr()` rather than from
`esdm_get_random_bytes_full()` (see "ESDM extensions of the protocol" below and
`esdm_egd_client_get_random_pr()`). An EGD daemon other than the ESDM does not
know them and closes the connection, so a request for prediction resistance
fails there rather than being served ordinary random data.

`libesdm-egd-provider.so` serves a request that asks for prediction resistance
with that command, and `libesdm-egd-provider-pr.so` serves every request with
it. Note that this generator hands out no more than the entropy sources just
produced, so answers take as long as collecting that entropy does; the server
generates such answers within a budget per connection and round of its event
loop, so that they cannot hold up the other clients.

### Sandboxed consumers

The EGD interface reaches consumers that confine themselves after startup.
OpenSSH is the reference case: sshd hands the pre-authentication protocol,
including the key exchange, to a privilege separated child that re-execs itself
and is then confined by a seccomp filter which permits little more than `read`,
`write`, `poll`, `close` and `getpid` - `socket` and `connect` are answered with
`SECCOMP_RET_KILL`, as are `sendto` and `recvfrom`.

Pointing sshd at the EGD provider works because the client establishes its
connection when it is allocated, which happens while OpenSSL loads the provider
and therefore before the child confines itself, and because everything it does
afterwards stays within those permitted calls. Setting `OPENSSL_CONF` on the
`sshd` and `sshd-keygen` units is all it takes:

```
   systemd.services.sshd.environment.OPENSSL_CONF = "/etc/ssl/openssl-esdm-egd.cnf";
   systemd.services.sshd-keygen.environment.OPENSSL_CONF = "/etc/ssl/openssl-esdm-egd.cnf";
```

The corresponding check is `nix build .#checks.<system>.egd_openssh`.

The one thing such a consumer cannot do is reconnect, and the client cannot tell
that it runs confined. When its connection is gone - closed by a restart of the
ESDM, or by the server running short of connection slots - or when it runs in a
child forked after connecting, which drops the inherited connection, the next
request calls `socket` and `connect` to open a new connection, and the seccomp
filter kills the process for that rather than failing the call. A confined
consumer therefore has to be connected before it confines itself, and a process
forking into the sandbox cannot be served at all; an unconfined consumer sees a
restarted ESDM transparently.

### EGD over the network

Built with the meson option `egd-net`, the EGD protocol of an ESDM reaches the
hosts of a network: `esdm-egd-net-server` serves it on TCP, port 7378 by
default, and answers it through the unprivileged RPC interface of the
`esdm-server` - nothing of the network reaches the `esdm-server` itself, and
every client is unprivileged. On a host without an ESDM, `esdm-egd-net-relay`
serves the EGD socket where the consumers above look for it, so libgcrypt,
`RAND_egd()` and the EGD provider use the ESDM on the network unchanged -
sandboxed consumers included, as they keep speaking to a Unix domain socket.
`libesdm_egd_client` reaches the server directly with
`esdm_egd_client_alloc_net()`.

There are two modes:

* TLS 1.3 with mutual authentication: both sides present a certificate of one
  private CA, the clients are identified by the fingerprint of theirs, and
  CRLs are checked the same way with every TLS stack. Certificates, trust
  anchors and CRLs are taken up while the daemons run. The TLS stack is that
  of the crypto backend - OpenSSL, GnuTLS or Botan. The key exchange prefers
  the post-quantum SecP384r1MLKEM1024 and MLKEM1024 to (EC)DHE,
  and certificates and CAs may be on ML-DSA-87, as far as the TLS stack has them -
  see `esdm-egd-net-server(8)`.

* Plain TCP, neither encrypted nor authenticated. It is meant only for
  networks that protect the traffic underneath - IPsec, WireGuard - and has to
  be asked for with `--plain`; the daemons refuse to start with neither TLS
  files nor `--plain`. It needs no TLS stack and builds with every backend.

On the host of the ESDM, with the TLS files of the server in
`/etc/esdm/egd-net/` (`server.crt`, `server.key`, and `ca.crt`, the CA of the
clients):

```
   systemctl enable --now esdm-egd-net-server.socket
```

On a host without an ESDM, with `client.crt`, `client.key` and `ca.crt` there
and the server in `/etc/esdm/egd-net-relay.env`:

```
   echo 'ESDM_EGD_NET_RELAY_ARGS="--connect egd.example"' > /etc/esdm/egd-net-relay.env
   systemctl enable --now esdm-egd-net-relay.socket
```

`esdm-egd-net-server(8)` and `esdm-egd-net-relay(8)` describe the options, the
bounds of the connections, the rotation of the files, exactly what the CRLs are
checked for and the timer downloading them; the check of both hosts together
is `nix build .#checks.<system>.egd_net`.

## Additional Hardening Measures

The ESDM already executes with different execution domains and without any
privileges. Yet, the following measures may be taken to additionally harden
the setup:

* Create a separate unprivileged user ID only for the ESDM daemons. Then
start all ESDM daemons such that they switch to this user instead of the user
"nobody". The ESDM-specific user shall not be used by anyone else. This
special user first ensures that ESDM cannot access other "nobody" processes.
Vice versa, other "nobody" processes cannot access the ESDM resources, notably
the processes themselves (via ptrace(2)) as well as the IPC mechanisms used
for synchronization between the ESDM daemons (semaphore / shared memory
segment).
