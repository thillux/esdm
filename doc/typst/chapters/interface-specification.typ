#import "../template.typ": *

= Interface Specification <sec:interface-spec>

This chapter enumerates the external interfaces of the #ac("ESDM") completely,
so that other documents can reference them; it is not itself the functional
specification of an evaluation. The enumeration is the maximum over
all builds and configurations: an installation offers the subset its
components bring (section @sec:if-deployment). An external interface is every point at which
a process, a user or the kernel outside of the component passes data or
control to a component of the #ac("ESDM"), or obtains data from it. Section
@sec:interfaces describes the interfaces from the view of the design, table
@tab:interfaces the path that serves each of them. This chapter states for
each interface its purpose, how it is used, its parameters with their types
and ranges, its effect and its errors.

#paragraph[Identifiers][Every interface has an identifier, and every call,
command, file or parameter within it a number in the order of its definition
in the source code: IF-RPC-P.4 is the fourth call of the privileged #ac("RPC")
service. The numbers are stable: the wire protocols only append (section
@sec:protocol-compat), and a later version of this chapter appends as well.]

#paragraph[Conventions][An error is a negative `errno` value where an
interface returns a status, and the positive value in `errno` where it has the
conventions of a system call. Sizes are in bytes and entropy is in bits unless
stated otherwise. A build with the meson option `testmode` uses other socket
paths and #ac("IPC") names; this chapter gives those of a regular build.]

== Inventory <sec:if-inventory>

Table @tab:if-inventory lists all external interfaces. The column _Used by_
states who may use the interface and the privilege it requires.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.3fr, 0.9fr, 1.3fr, 1.5fr, auto),
    align: left + horizon,
    table.header([Identifier], [Interface], [Kind], [Used by],
      [Implemented in], [Section]),
    [IF-RPC-U], [`esdm-rpc-unpriv.socket`], [Socket protocol], [Every local
      user], [`service-rpc/server/`], [@sec:if-rpc-u],
    [IF-RPC-P], [`esdm-rpc-priv.socket`], [Socket protocol], [User
      #ac("ID") 0], [`service-rpc/server/`], [@sec:if-rpc-p],
    [IF-EGD], [`esdm-egd.socket`], [Socket protocol], [Every local user;
      five commands and the entropy claim only with user #ac("ID") 0],
      [`service-egd/server/esdm_egd_server.c`], [@sec:if-egd],
    [IF-EGD-PR], [`esdm-egd-pr.socket`], [Socket protocol], [As IF-EGD],
      [`service-egd/server/esdm_egd_server.c`], [@sec:if-egd],
    [IF-ESEXT], [Socket of an external entropy source provider], [Socket
      protocol], [The #ac("ESDM") server as client; a provider running as
      root or as the accepted user], [`esdm/esdm_es_extsock.c`, `es-ext/`],
      [@sec:if-esext],
    [IF-CUSE-RANDOM], [`/dev/random`], [Device file], [Every user; the
      privileged #ac("IOCTL", pl: true) with `CAP_SYS_ADMIN`],
      [`frontends/cuse/cuse_device.c`, `cuse_random.c`], [@sec:if-cuse],
    [IF-CUSE-URANDOM], [`/dev/urandom`], [Device file], [As IF-CUSE-RANDOM],
      [`frontends/cuse/cuse_device.c`, `cuse_urandom.c`], [@sec:if-cuse],
    [IF-PROC], [`/proc/sys/kernel/random/`], [Virtual files], [Every user
      reads; user #ac("ID") 0 writes], [`frontends/cuse/proc_files.c`],
      [@sec:if-proc],
    [IF-GETRANDOM], [`getrandom()`, `getentropy()`], [System call wrapper],
      [Every process that preloads or links the library],
      [`frontends/getrandom/getrandom.c`], [@sec:if-getrandom],
    [IF-LIB-ESDM], [`esdm.h`], [Library #ac("API")], [The process linking
      `libesdm`], [`esdm/`], [@sec:if-lib],
    [IF-LIB-RPCC], [`esdm_rpc_client.h`], [Library #ac("API")], [Every
      process; the privileged calls with user #ac("ID") 0],
      [`service-rpc/client/`], [@sec:if-lib],
    [IF-LIB-AUX], [`esdm_aux_client.h`], [Library #ac("API")], [A process
      of the owner of the semaphore IF-SHM.4, see section
      @sec:if-shm-lifecycle], [`frontends/aux-client/`], [@sec:if-lib],
    [IF-LIB-EGDC], [`esdm_egd_client.h`], [Library #ac("API")], [Every
      process], [`service-egd/client/`], [@sec:if-lib],
    [IF-LIB-ESEXT], [`esdm_es_ext.h`], [Library #ac("API")], [The provider
      of an external entropy source], [`es-ext/`], [@sec:if-lib],
    [IF-OSSL], [OpenSSL providers], [Library #ac("API")], [Every process
      that loads a provider], [`frontends/openssl-provider/`],
      [@sec:if-ossl],
    [IF-SHM], [Status segment and semaphores], [Shared memory], [The server
      writes; every local user reads], [`esdm/esdm_shm_status.c`],
      [@sec:if-shm],
    [IF-KMOD-ES], [`/dev/esdm_es`, debugfs files, module parameters],
      [Kernel #ac("IOCTL")], [`CAP_SYS_ADMIN` at `open()`],
      [`kernel/esdm_es/`, `kernel/shared/esdm_es_ioctl.h`],
      [@sec:if-kmod-es],
    [IF-KMOD-CDEV], [`/dev/esdm_random`, `/dev/esdm_urandom`, `/dev/esdm_pr`,
      `/proc/esdm`, module parameters], [Device file], [Every user; the
      privileged #ac("IOCTL", pl: true) and writes to `/proc/esdm` with
      `CAP_SYS_ADMIN`], [`kernel/esdm_cdev/`], [@sec:if-kmod-cdev],
    [IF-CLI], [Command lines of the programs], [Command line], [The user
      starting the program], [See chapter @sec:tools],
      [@sec:if-cli],
    [IF-SIG], [Signals to the daemons], [Signal], [Whoever may signal the
      process], [`frontends/server/server_main.c`,
      `frontends/cuse/cuse_device.c`, `common/linux_support.c`],
      [@sec:if-sig],
    [IF-ENV], [Environment variables and files read at start],
      [Configuration], [Whoever starts the process or owns the files],
      [`esdm/fips.c`, `common/fips_integrity.c`,
      `common/systemd_support.c`], [@sec:if-env],
  )
}
, caption: [The external interfaces of the #ac("ESDM")]) <tab:if-inventory>

The entropy sources the #ac("ESDM") reads from the kernel and from devices –
`getrandom()`, `/dev/hwrng`, the #ac("TPM"), the kernel crypto #ac("API") –
are interfaces of other components that the #ac("ESDM") uses. They are
described with the entropy sources in chapter @sec:design and are not part of
this inventory.

== Interfaces of a Deployment <sec:if-deployment>

The #ac("ESDM") is a toolkit: a generator with a set of frontends, entropy
sources, kernel modules, libraries and tools around it, of which an
integrator chooses the subset a system needs. Only the generator is
mandatory – `esdm-server`, or `libesdm` linked into a program – and every
other component can be left out without affecting the rest. The inventory is
accordingly the maximum: it lists every interface any build and any
configuration of the #ac("ESDM") can offer. No installation has to offer all
of them, and few do. An interface exists on a system only if the component
that implements it is built, installed and started, and for some of them
only with an option of the server. A document that references this chapter
for a product names the configuration of that product and thereby the subset
of the interfaces that apply; the interfaces of components that are not
installed do not exist there and need neither a description nor a test.

Table @tab:if-conditions states for each interface what brings it into
existence. The meson options are those of chapter @sec:build-options; the
kernel modules are built apart from the meson build (section
@sec:build-kernel-modules).

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.75fr, 1.2fr, 1.6fr), align: left + top,
    table.header([Interface], [Built with], [Present at run time when]),
    [IF-RPC-U, IF-RPC-P], [`esdm-server-rpc` (default)], [`esdm-server`
      runs. A server built with the option opens both sockets and has no
      option to turn them off],
    [IF-SHM], [`esdm-server`], [`esdm-server` runs, whether or not a
      consumer reads the segment],
    [IF-SIG], [The daemon concerned], [The daemon runs],
    [IF-CLI, IF-ENV], [The program concerned], [The program is installed;
      they are used when it is started],
    [IF-EGD], [`esdm-server-egd` (default)], [The server is started with
      `--egd_socket`, or systemd passes the socket of
      `esdm-server-egd.socket`. Off by default. A server built without
      `esdm-server-rpc` always serves it, see below],
    [IF-EGD-PR], [`esdm-server-egd`], [As IF-EGD, with `--egd_socket_pr` or
      `esdm-server-egd-pr.socket`. Off by default in every build],
    [IF-ESEXT], [`es_ext` (default)], [The server is started with
      `--es_ext` and a provider runs],
    [IF-LIB-ESEXT], [`esdm-es-ext` (default); the providers with `es_pkcs11`
      and `es_pcsc` (off by default)], [A provider program is installed and started],
    [IF-CUSE-RANDOM, IF-CUSE-URANDOM], [`linux-devfiles` (default), which
      needs `esdm-server-rpc`],
      [`esdm-cuse-random` or `esdm-cuse-urandom` runs. Without it the device
      file is the one of the kernel],
    [IF-PROC], [`linux-devfiles`], [`esdm-proc` runs],
    [IF-GETRANDOM], [`linux-getrandom` (default), which needs
      `esdm-server-rpc`], [A process preloads or
      links `libesdm-getrandom.so`; it applies to that process only],
    [IF-OSSL], [`openssl-rand-provider` (off by default): IF-OSSL.1 to
      IF-OSSL.3 with `esdm-server-rpc`, IF-OSSL.4 and IF-OSSL.5 with
      `esdm-server-egd`], [The OpenSSL configuration of a process loads one
      of the provider modules],
    [IF-LIB-RPCC], [`esdm-server-rpc`], [A program links
      `libesdm_rpc_client`],
    [IF-LIB-EGDC], [`esdm-server-egd`], [A program links
      `libesdm_egd_client`; it needs IF-EGD],
    [IF-LIB-AUX], [`esdm-aux-client` (default)], [A program links
      `libesdm_aux_client`],
    [IF-LIB-ESDM], [Always], [A program links `libesdm` and thereby runs a
      generator of its own; `esdm-server` is such a program],
    [IF-KMOD-ES], [`make -C kernel/esdm_es`], [The module `esdm_es` is
      loaded],
    [IF-KMOD-CDEV], [`make -C kernel/esdm_cdev`], [The module `esdm_cdev`
      is loaded; it needs IF-EGD],
  )
},
  caption: [What brings each interface into existence],
) <tab:if-conditions>

#paragraph[The two interfaces of the server][The #ac("RPC") interface and
the #ac("EGD") interface of `esdm-server` are each a meson option,
`esdm-server-rpc` and `esdm-server-egd`. Both are enabled by default, and a
build of the server needs at least one of them. A disabled interface is not
part of the build: the server contains none of its code and opens none of
its sockets, and its client library, its socket units and the tests of the
interface are not built.]

- Without `esdm-server-rpc`, the server serves the #ac("EGD") interface
  alone and serves it always: on the sockets it is given with `--egd_socket`
  and `--egd_socket_pr` or by systemd, and on the socket of
  `esdm-server-egd-socket-path` when it is not given the regular one.
  `esdm-server.service` then requires `esdm-server-egd.socket`. Neither
  IF-RPC-U, IF-RPC-P nor IF-LIB-RPCC exists, and what uses IF-LIB-RPCC is
  not built: `esdm-kernel-seeder` and the provider modules IF-OSSL.1 to
  IF-OSSL.3. `linux-devfiles` and `linux-getrandom` have to be disabled.
  `esdm-tool` and the resume notification of `esdm-server-signal-helper`
  work over IF-EGD (sections @sec:tool-esdm-tool and
  @sec:tool-esdm-server-signal-helper).
- Without `esdm-server-egd`, the server rejects `--egd_socket` and
  `--egd_socket_pr`. Neither IF-EGD, IF-EGD-PR nor IF-LIB-EGDC exists, the
  provider modules IF-OSSL.4 and IF-OSSL.5 are not built, and the kernel
  module `esdm_cdev`, which is built apart from meson, finds no server to
  read.

=== Minimal Configurations <sec:if-minimal>

The following configurations are examples of small installations, each with
the interfaces it has. In all of them the server takes its entropy from the
sources that need no further component – the Jitter #acs("RNG"), the
#ac("CPU"), the kernel #acs("RNG") and, where present, `/dev/hwrng` and the
#ac("TPM") (section @sec:es-overview).

#paragraph[Server with #ac("RPC") clients][`esdm-server`, `esdm-tool` and the
OpenSSL provider: applications obtain their random numbers through OpenSSL,
and the administrator uses the tool. No kernel module is loaded, and the
devices of the kernel and `getrandom()` remain those of the kernel.]

```sh
meson setup build -Dopenssl-rand-provider=enabled \
  -Desdm-server-egd=disabled \
  -Dlinux-devfiles=disabled -Dlinux-getrandom=disabled \
  -Desdm-aux-client=disabled -Desdm-es-ext=disabled -Des_ext=disabled
systemctl enable --now esdm-server.service
```

#par(first-line-indent: 0pt)[The interfaces are IF-RPC-U and IF-RPC-P,
IF-LIB-RPCC as used by the tool and the provider, IF-OSSL.1 to IF-OSSL.3,
IF-SHM, IF-SIG.1 and IF-SIG.2 for the server, and IF-CLI and IF-ENV for
`esdm-server` and `esdm-tool`. IF-SHM exists without a reader. With
`esdm-server-egd` disabled, the server has no #ac("EGD") code and the two
#ac("EGD") provider modules are not built. Section
@sec:integration-openssl has the OpenSSL configuration.]

#paragraph[Server and `esdm_cdev`][`esdm-server` with the #ac("EGD")
interface alone and the kernel module `esdm_cdev`: applications read
`/dev/esdm_random`, `/dev/esdm_urandom` or `/dev/esdm_pr`, for example a
hypervisor that passes the device to its guests. No daemon besides the
server runs in user space, the server contains no #ac("RPC") code, and the
module needs no kernel patch.]

```sh
meson setup build -Desdm-server-rpc=disabled \
  -Dlinux-devfiles=disabled -Dlinux-getrandom=disabled \
  -Desdm-aux-client=disabled -Desdm-es-ext=disabled -Des_ext=disabled
make -C kernel/esdm_cdev KERNEL_DIR=/lib/modules/$(uname -r)/build
systemctl enable --now esdm-server-egd.socket esdm-server.service
modprobe esdm_cdev
```

#par(first-line-indent: 0pt)[The interfaces are IF-EGD, IF-KMOD-CDEV,
IF-SHM, IF-SIG, IF-LIB-EGDC as used by the tool, and IF-CLI and IF-ENV for
`esdm-server` and `esdm-tool`. No #ac("RPC") socket exists. `esdm-tool`
works over IF-EGD and reports the status, the seeding state and the entropy
counts, obtains random numbers and carries out the administrative commands
of the #ac("EGD") protocol (section @sec:tool-esdm-tool); the status is
also read from `/proc/esdm` (IF-KMOD-CDEV) and the journal. With
`-Desdm-tool=disabled`, IF-LIB-EGDC has no user and the interfaces of the
tool do not exist.]

#paragraph[Replacement of the kernel interfaces][The delivered default:
`esdm-server`, the two #ac("CUSE") daemons, `esdm-proc` and
`libesdm-getrandom.so`, so that unmodified applications obtain the random
numbers of the #ac("ESDM") from `/dev/random`, `/dev/urandom` and
`getrandom()` (section @sec:usage-systemd). This adds IF-CUSE-RANDOM,
IF-CUSE-URANDOM, IF-PROC and IF-GETRANDOM to the interfaces of the first
configuration, and the #ac("CUSE") daemons are the readers of IF-SHM.]

#paragraph[A library without a server][A program that links `libesdm` runs
the generator in its own process and offers IF-LIB-ESDM to itself alone
(meson option `esdm-server` disabled). Of this chapter only IF-LIB-ESDM,
IF-ENV and, with the kernel module, IF-KMOD-ES apply.]

=== When the Kernel Module esdm_es Is Needed <sec:if-when-esdm-es>

None of the configurations above loads `esdm_es`. The module has two
functions, which can be had separately, and each has a reason of its own:

- The interrupt and the scheduler entropy source (sections
  @sec:irq-processing and @sec:sched-events). They are needed where the
  other entropy sources do not suffice: on a system without a
  high-resolution timer good enough for the Jitter #acs("RNG") and without a
  #ac("CPU") or hardware source the operator credits; where a second
  non-physical entropy source with an #ac("SP") 800-90B assessment and
  health tests is required next to the Jitter #acs("RNG"), as for the rule
  of two independent sources of NTG.1 (section @sec:ntg1-2022); and where
  entropy is wanted early in the boot, before user space starts, which only
  a source in the kernel collects. The price is a patched kernel: the hooks
  of `kernel/esdm_es/` have to be applied to the kernel the module is built
  for. On a kernel that cannot be patched, the #ac("eBPF") entropy sources
  (section @sec:ebpf) observe the same events with a stock kernel and
  without a module.
- The system events (section @sec:vm-clone): the module reports a restored
  snapshot or a clone of a virtual machine, a suspend, a resume and a
  shutdown to the server. It is needed on a virtual machine that may be
  cloned or restored from a snapshot, as nothing else tells the server that
  its state exists twice; for suspend and resume alone the units of
  `esdm-server-signal-helper` do the same. Built without its entropy sources
  (`BUILD_ES_IRQ=0 BUILD_ES_SCHED=0`), the module needs no kernel patch.

The module is not needed on a system whose other entropy sources deliver the
entropy the configuration requires and that is neither cloned nor restored.
With the module loaded, IF-KMOD-ES is added to the interfaces, with
`CAP_SYS_ADMIN` as the only way in; the server opens the device before it
drops its privileges.

== RPC Interfaces <sec:if-rpc>

The #ac("ESDM") server offers two services on Unix domain sockets of the type
`SOCK_SEQPACKET`: `UnprivAccess` on `ESDM_RPC_UNPRIV_SOCKET`, by default
`/run/esdm-rpc-unpriv.socket`, and `PrivAccess` on `ESDM_RPC_PRIV_SOCKET`, by
default `/run/esdm-rpc-priv.socket`. The meson options
`esdm-server-rpc-path-unprivileged` and `esdm-server-rpc-path-privileged` set
the two directories. Section @sec:rpc describes the design and the wire format
with an example; this section specifies the calls.

A call is one request datagram answered by one response datagram. The request
names the call by its index in the service definition, which is the number of
the call in the tables below less one. All messages are protobuf messages of
`service-rpc/service/pb/unpriv_access.proto`, `priv_access.proto` and
`common.proto`. `EmptyRequest` has no fields. Every response carries the field
`ret`: 0 or a positive count on success, a negative `errno` value on error.
The handlers are the functions `esdm_rpc_<call>` in
`service-rpc/server/esdm_rpc_<call>_s.c`, the client functions the functions
`esdm_rpcc_<call>` of `esdm_rpc_client.h` (IF-LIB-RPCC).

=== Unprivileged Service <sec:if-rpc-u>

Every local user may connect to the socket: the server sets its mode to 0666,
as does the systemd socket unit. Table @tab:if-rpc-u lists the 15 calls.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, auto, 1.4fr, 1.6fr), align: left + horizon,
    table.header([Identifier], [Call], [Request → response],
      [Client function]),
    [IF-RPC-U.1], [`RpcStatus`], [`StatusRequest` → `StatusResponse`],
      [`esdm_rpcc_status`],
    [IF-RPC-U.2], [`RpcGetEntLvl`], [`EmptyRequest` → `ValResponse`],
      [`esdm_rpcc_get_ent_lvl`],
    [IF-RPC-U.3], [`RpcIsFullySeeded`], [`EmptyRequest` →
      `IsFullySeededResponse`], [`esdm_rpcc_is_fully_seeded`],
    [IF-RPC-U.4], [`RpcGetRandomBytesFull`], [`GetRandomBytesRequest` →
      `RandValResponse`], [`esdm_rpcc_get_random_bytes_full`,
      `esdm_rpcc_get_random_bytes_full_timeout`,
      `esdm_rpcc_get_random_bytes_full_noblock`],
    [IF-RPC-U.5], [`RpcGetRandomBytesPr`], [`GetRandomBytesRequest` →
      `RandValResponse`], [`esdm_rpcc_get_random_bytes_pr`,
      `esdm_rpcc_get_random_bytes_pr_noblock`],
    [IF-RPC-U.6], [`RpcGetRandomBytes`], [`GetRandomBytesRequest` →
      `RandValResponse`], [`esdm_rpcc_get_random_bytes`],
    [IF-RPC-U.7], [`RpcGetSeed`], [`GetSeedRequest` → `RandValResponse`],
      [`esdm_rpcc_get_seed`],
    [IF-RPC-U.8], [`RpcWriteData`], [`WriteDataRequest` → `RetResponse`],
      [`esdm_rpcc_write_data`],
    [IF-RPC-U.9], [`RpcRndGetEntCnt`], [`EmptyRequest` → `ValResponse`],
      [`esdm_rpcc_rnd_get_ent_cnt`],
    [IF-RPC-U.10], [`RpcGetPoolsize`], [`EmptyRequest` → `ValResponse`],
      [`esdm_rpcc_get_poolsize`],
    [IF-RPC-U.11], [`RpcGetWriteWakeupThresh`], [`EmptyRequest` →
      `ValResponse`], [`esdm_rpcc_get_write_wakeup_thresh`],
    [IF-RPC-U.12], [`RpcGetMinReseedSecs`], [`EmptyRequest` →
      `ValResponse`], [`esdm_rpcc_get_min_reseed_secs`],
    [IF-RPC-U.13], [`RpcJentStatus`], [`StatusRequest` → `StatusResponse`],
      [`esdm_rpcc_jent_status`],
    [IF-RPC-U.14], [`RpcStatusJson`], [`StatusRequest` → `StatusResponse`],
      [`esdm_rpcc_status_json`],
    [IF-RPC-U.15], [`RpcDrngStatusJson`], [`DrngStatusRequest` →
      `StatusResponse`], [`esdm_rpcc_drng_status_json`,
      `esdm_rpcc_drng_status_pr_json`],
  )
}
, caption: [Calls of the unprivileged #ac("RPC") service `UnprivAccess`])
<tab:if-rpc-u>

#paragraph[Shared messages][Four messages serve several calls.
`StatusRequest` has the field `uint32 maxlen`, the size of the buffer the
server renders into; the server uses at most `ESDM_RPC_MAX_STATUS` (65,504)
and at least 1. `StatusResponse` has `int32 ret` and `string buffer`.
`ValResponse` has `int32 ret` and `uint32 val`; the handlers of the calls
using it always set `ret` to 0. `GetRandomBytesRequest` has `uint64 len`, the
number of bytes requested. `RandValResponse` has `int64 ret` and
`bytes randval`: `ret` is the number of bytes in `randval`, a negative `errno`
value, or the negated maximum of `len`, by which the server asks the client to
request less. A negated maximum is below -255 and therefore no `errno`
value.]

#paragraph[IF-RPC-U.1 RpcStatus][Obtains the status of the #ac("ESDM") as
text (section @sec:status). The handler calls `esdm_status`. `ret` is 0, or
`-EMSGSIZE` if the text did not fit into `maxlen` bytes, in which case
`buffer` holds the text as far as it fit, or `-ENOMEM`. The client function
requests `ESDM_RPC_MAX_STATUS` bytes and reports `-EMSGSIZE` as well if the text
does not fit into the buffer of its caller.]

#paragraph[IF-RPC-U.2 RpcGetEntLvl][Obtains the entropy available in all
entropy sources. The handler calls `esdm_avail_entropy`\; `val` is the
entropy in bits. No error.]

#paragraph[IF-RPC-U.3 RpcIsFullySeeded][Obtains the seeding state. The
response has `int32 ret`, always 0, and `bool fully_seeded`, the result of
`esdm_state_fully_seeded`. No error.]

#paragraph[IF-RPC-U.4 RpcGetRandomBytesFull][Obtains random numbers from a
fully seeded #ac("DRNG"). `len` is 0 to 65,512. The handler calls
`esdm_get_random_bytes_full_noblock` and never waits. `ret` is the number of
bytes generated, which may be less than `len`\; -65,512 for a larger `len`\;
`-EAGAIN` while the #ac("ESDM") is not operational or all
#ac("DRNG", pl: true) wait for their reseed\; `-EOPNOTSUPP` after a failed
self test of the cryptographic implementations.
`esdm_rpcc_get_random_bytes_full`
splits a request, repeats it after `-EAGAIN` with waits of 1 to 16 ms and
returns once all bytes are delivered; the `_timeout` variant gives up with
`-ETIMEDOUT` after the time its caller sets, the `_noblock` variant issues
one call and returns `-EAGAIN`.]

#paragraph[IF-RPC-U.5 RpcGetRandomBytesPr][Obtains random numbers from the
prediction resistance #ac("DRNG"), which reseeds before it generates and
delivers no more data than its entropy sources just provided. `len` is 0 to
`ESDM_RPC_MAX_PR_REQUEST_SIZE` (32). The handler calls
`esdm_get_random_bytes_pr_noblock`. `ret` is the number of bytes generated,
which may be less than `len`\; `-EINVAL` for a larger `len`, as the negated
maximum would read as an `errno` value\; `-EAGAIN` while the
#ac("ESDM") is not operational, while another prediction resistance request
is in progress, when the entropy sources delivered nothing, and for a peer
other than root during the 3 seconds a root peer that received `-EAGAIN`
has the next turn\; `-EOPNOTSUPP` as for IF-RPC-U.4. The client functions
request at most 32 bytes per call; `esdm_rpcc_get_random_bytes_pr` repeats
until all bytes are delivered.]

#paragraph[IF-RPC-U.6 RpcGetRandomBytes][Obtains random numbers without
the guarantee that all #ac("DRNG", pl: true) are fully seeded, with the
semantics of `/dev/urandom`. `len` is 0 to 65,512. The handler calls
`esdm_get_random_bytes`. `ret` is the number of bytes generated\; -65,512
for a larger `len`\; `-EAGAIN` when all #ac("DRNG", pl: true) wait for their
reseed\; `-EOPNOTSUPP` while the #ac("ESDM") is not operational and after a
failed self test. `esdm_rpcc_get_random_bytes` returns the bytes delivered so
far, or `-EAGAIN` if there are none.]

#paragraph[IF-RPC-U.7 RpcGetSeed][Obtains seed data directly from the
entropy sources for a #ac("DRNG") of the caller. The request has
`uint64 len`, the size of the buffer of the caller, 8 to 65,512, and
`uint32 flags`, a bit mask of `ESDM_GET_SEED_NONBLOCK` (0x1) and
`ESDM_GET_SEED_FULLY_SEEDED` (0x2, the #ac("DRNG") of the caller is already
fully seeded and asks for the regular instead of the initial amount of
entropy). The handler calls `esdm_get_seed` and always adds
`ESDM_GET_SEED_NONBLOCK`. On success, `ret` is the number of bytes in
`randval`, which holds a 64-bit word with this number, a 64-bit word with
the entropy of the seed in bits, and the seed buffer. `ret` is -65,512 for a
larger `len`\; `-EINVAL` for a `len` below 8\; `-EMSGSIZE` for a buffer too
small for the seed, with the required size as a 64-bit word in `randval`\;
`-EAGAIN` while another seed request is in progress or not all
#ac("DRNG", pl: true) are fully seeded\; `-EOPNOTSUPP` unless the self tests
of the cryptographic implementations passed. Once the collection began, a #ac("DRNG") that loses its seed level only
ends it: the call returns what was collected until then, with the entropy
stated in the second word, which may be 0.
`esdm_rpcc_get_seed` repeats the call after `-EAGAIN` unless its caller set
`ESDM_GET_SEED_NONBLOCK`.]

#paragraph[IF-RPC-U.8 RpcWriteData][Inserts data into the auxiliary pools
without crediting entropy. The request has `bytes data` of at most 65,512
bytes. The handler calls `esdm_pool_insert_aux` with an entropy of 0. `ret`
is 0\; `-EFAULT` for a request without data\; `-EINVAL` for more than 65,512
bytes\; otherwise the error of the insertion. `esdm_rpcc_write_data` splits
larger data into several calls.]

#paragraph[IF-RPC-U.9 RpcRndGetEntCnt][Obtains the entropy of the auxiliary
pool, the value the #ac("IOCTL") `RNDGETENTCNT` and the file `entropy_avail`
report. The handler calls `esdm_avail_entropy_aux`\; `val` is the entropy in
bits. No error.]

#paragraph[IF-RPC-U.10 RpcGetPoolsize][Obtains the size of the auxiliary
pool, the value of the file `poolsize`. The handler calls
`esdm_avail_poolsize_aux`\; `val` is the size in bits. No error.]

#paragraph[IF-RPC-U.11 RpcGetWriteWakeupThresh][Obtains the entropy level of
the auxiliary pool below which the #ac("ESDM") reports that it needs entropy,
the value of the file `write_wakeup_threshold`. The handler calls
`esdm_get_write_wakeup_bits`\; `val` is the threshold in bits. No error.]

#paragraph[IF-RPC-U.12 RpcGetMinReseedSecs][Obtains the maximum time between
two reseeds of a #ac("DRNG"), the value of the file
`urandom_min_reseed_secs`. The handler calls `esdm_get_reseed_max_time`\;
`val` is the time in seconds, 600 unless IF-RPC-P.6 changed it. No error.]

#paragraph[IF-RPC-U.13 RpcJentStatus][Obtains the status of the Jitter
#acs("RNG") entropy source as text. The handler calls `esdm_jent_status`
with a buffer of `maxlen` bytes, at least 1 and at most
`ESDM_RPC_MAX_STATUS`. `ret` is 0 with the text in `buffer`, or the error of that function or
`-ENOMEM` with an empty `buffer`. The client function reports `-EMSGSIZE` if
the text does not fit into the buffer of its caller.]

#paragraph[IF-RPC-U.14 RpcStatusJson][Obtains the status of the #ac("ESDM")
as #ac("JSON") document (section @sec:status). The handler calls
`esdm_status_json`. `ret` is 0\; `-EMSGSIZE` if the document did not fit into
`maxlen` bytes, with an empty `buffer`, as half a document is no document\;
or `-ENOMEM`.]

#paragraph[IF-RPC-U.15 RpcDrngStatusJson][Obtains the status of one
#ac("DRNG") instance as #ac("JSON") object. The request has `uint32 maxlen`
as in `StatusRequest`, `uint32 node`, the node whose instance is asked for,
and `bool prediction_resistance`, which selects the prediction resistance
instance and makes the server ignore `node`. The handler calls
`esdm_status_drng_json` or `esdm_status_drng_pr_json`. `ret` is 0\;
`-ENODEV` for a node without an instance, by which a client walking the
nodes finds their end\; `-EMSGSIZE` as for IF-RPC-U.14\; or `-ENOMEM`.]

=== Privileged Service <sec:if-rpc-p>

The socket has the mode 0600 and the owner root. In addition, every handler
obtains the credentials of the peer with `SO_PEERCRED`, which reports those
the peer connected with, when it serves a call and answers `-EPERM` unless the user #ac("ID") of the peer is 0
(`esdm_rpc_client_is_privileged` in `service-rpc/server/esdm_rpc_server.c`).
All responses but that of IF-RPC-P.7 are `RetResponse` with the field
`int32 ret`. Table @tab:if-rpc-p lists the 8 calls.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, auto, 1.75fr, 1.25fr), align: left + horizon,
    table.header([Identifier], [Call], [Request → response],
      [Client function]),
    [IF-RPC-P.1], [`RpcRndAddToEntCnt`], [`RndAddToEntCntRequest` →
      `RetResponse`], [`esdm_rpcc_rnd_add_to_ent_cnt`],
    [IF-RPC-P.2], [`RpcRndAddEntropy`], [`RndAddEntropyRequest` →
      `RetResponse`], [`esdm_rpcc_rnd_add_entropy`],
    [IF-RPC-P.3], [`RpcRndClearPool`], [`EmptyRequest` → `RetResponse`],
      [`esdm_rpcc_rnd_clear_pool`],
    [IF-RPC-P.4], [`RpcRndReseedCRNG`], [`EmptyRequest` → `RetResponse`],
      [`esdm_rpcc_rnd_reseed_crng`],
    [IF-RPC-P.5], [`RpcSetWriteWakeupThresh`],
      [`SetWriteWakeupThreshRequest` → `RetResponse`],
      [`esdm_rpcc_set_write_wakeup_thresh`],
    [IF-RPC-P.6], [`RpcSetMinReseedSecs`], [`SetMinReseedSecsRequest` →
      `RetResponse`], [`esdm_rpcc_set_min_reseed_secs`],
    [IF-RPC-P.7], [`RpcSelftest`], [`EmptyRequest` → `SelftestResponse`],
      [`esdm_rpcc_selftest`],
    [IF-RPC-P.8], [`RpcSetEsRate`], [`SetEsRateRequest` → `RetResponse`],
      [`esdm_rpcc_set_es_rate`],
  )
}
, caption: [Calls of the privileged #ac("RPC") service `PrivAccess`])
<tab:if-rpc-p>

#paragraph[IF-RPC-P.1 RpcRndAddToEntCnt][Credits entropy to the data already
in the auxiliary pool, as the #ac("IOCTL") `RNDADDTOENTCNT` does. The
request has `uint32 entcnt`, the entropy in bits. The handler calls
`esdm_pool_add_entropy`, which adds the bits to the entropy of the first
auxiliary pool up to the most a pool holds (`esdm_get_digestsize`); 0 changes
nothing, and a pool that holds no data – after `esdm_reinit` or a failed
#ac("XOF") operation, until the next insertion – is credited with nothing.
`ret` is 0 in all these cases, or `-EPERM`.]

#paragraph[IF-RPC-P.2 RpcRndAddEntropy][Inserts data into the auxiliary pool
and credits it with entropy, as the #ac("IOCTL") `RNDADDENTROPY` does. The
request has `bytes randval` of at most 65,512 bytes and `uint32 entcnt`, the
entropy claimed in bits, at most 8 bits per byte of data. The handler calls
`esdm_pool_insert_aux`, which caps the claim at the most a pool holds. `ret`
is 0\; `-EFAULT` for a request without data\; `-EPERM`\; `-EINVAL` for more
than 65,512 bytes or a claim above 8 bits per byte, which the client function
returns without sending the request\; otherwise the error of the insertion.]

#paragraph[IF-RPC-P.3 RpcRndClearPool][Sets the entropy of all auxiliary
pools to 0, as the #ac("IOCTL", pl: true) `RNDCLEARPOOL` and `RNDZAPENTCNT`
do. The handler calls `esdm_pool_set_entropy` with 0. `ret` is 0 or
`-EPERM`.]

#paragraph[IF-RPC-P.4 RpcRndReseedCRNG][Forces a reseed of all
#ac("DRNG", pl: true), as the #ac("IOCTL") `RNDRESEEDCRNG` does. The handler
calls `esdm_drng_force_reseed`, which marks every #ac("DRNG") for a reseed
at its next use. `ret` is 0 or `-EPERM`.]

#paragraph[IF-RPC-P.5 RpcSetWriteWakeupThresh][Sets the value IF-RPC-U.11
reports. The request has `uint32 wakeup`, the threshold in bits. The handler
calls `esdm_set_write_wakeup_bits`, which ignores 0, caps the value at the
size of the auxiliary pool and publishes the resulting need for entropy
(IF-SHM). `ret` is 0 or `-EPERM`.]

#paragraph[IF-RPC-P.6 RpcSetMinReseedSecs][Sets the value IF-RPC-U.12
reports. The request has `uint32 seconds`. The handler calls
`esdm_set_reseed_max_time`, which caps the value at 3600\; with 0, every
request reseeds its #ac("DRNG") before it is served. `ret` is 0 or
`-EPERM`.]

#paragraph[IF-RPC-P.7 RpcSelftest][Runs the self tests of the #ac("ESDM")
(section @sec:self-tests) and reports their outcome. The handler calls
`esdm_selftest_run`. The response has `int32 ret`, `uint32 crypto_state` and
`uint32 es_state` – each 0 for a test that has not run, 1 for passed, 2 for
failed –, `uint32 es_sources`, the number of entropy sources tested, and
`uint32 es_failures`, the number of those that failed. `ret` is 0 if every
self test passed and the #ac("ESDM") hands out random numbers\; `-EPERM`\;
the error of the failing test\; `-EOPNOTSUPP` if this run passed but an
earlier failure of the cryptographic self tests still holds the output
back.]

#paragraph[IF-RPC-P.8 RpcSetEsRate][Sets the entropy rate of an entropy
source, for tests. The request has `string es`, the name of the entropy
source as the status reports it, compared without regard to case – `CPU`,
`ExternalSocket`, `Interrupt`, `InterruptEBPF`, `JitterRNG`,
`KernelJitterRNG`, `KernelRNG`, `LinuxHWRand`, `Scheduler`, `SchedulerEBPF`,
`TPM2.0` – or `all`, and `uint32 rate`, the entropy in bits per 256 bits of
data. `ret` is 0\; `-EFAULT` for a request without a name\; `-EPERM`\;
`-EOPNOTSUPP` unless the server was built with the meson option `testmode` or
the build type `debug`\; `-EINVAL` for an unknown name.]

=== Framing, Limits and Errors of the Transport <sec:if-rpc-framing>

One datagram carries one message: a header followed by the protobuf message.
Section @sec:rpc shows the two header structures of
`service-rpc/service/esdm_rpc_protocol.h` and table @tab:rpc-wire an example.
All header fields are unsigned 32-bit numbers in little-endian byte order:

- `method_index`: the index of the call in its service, 0 to 14 for
  `UnprivAccess` and 0 to 7 for `PrivAccess`. The response repeats it.

- `message_length`: the length of the protobuf message that follows, at most
  `ESDM_RPC_MAX_INTERNAL_MSG_SIZE`.

- `request_id`: an identifier the server copies into the response without
  interpreting it. The client library sends 0 and assigns the responses to
  its requests by their order.

- `status_code`, response only: 0 for success
  (`PROTOBUF_C_RPC_STATUS_CODE_SUCCESS`). The server sends 1
  (`PROTOBUF_C_RPC_STATUS_CODE_SERVICE_FAILED`) with a message length of 0 if
  it cannot encode the response of a handler. The value 2 is defined and
  never sent.

#figure(
  table(columns: (1.5fr, auto, 1.6fr), align: left + horizon,
    table.header([Constant], [Value], [Meaning]),
    [`ESDM_RPC_MAX_MSG_SIZE`], [65,536], [Largest datagram, header
      included],
    [`ESDM_RPC_MAX_INTERNAL_MSG_SIZE`], [65,520], [Largest protobuf message
      in either direction: the datagram less the 16 bytes of the response
      header],
    [`ESDM_RPC_MAX_DATA`], [65,512], [Largest byte or text field of a
      message],
    [`ESDM_RPC_MAX_STATUS`], [65,504], [Largest status text, with its
      terminating zero byte],
    [`ESDM_RPC_MAX_PR_REQUEST_SIZE`], [32], [Largest request of
      IF-RPC-U.5],
    [`ESDM_RPCS_MAX_CONN_PER_WORKER`], [1024], [Connections one worker
      thread of the server serves],
    [`ESDM_RPC_IDLE_TIMEOUT_USEC`], [2,000,000], [Time after which the
      server closes an unused connection; meson option
      `esdm-server-rpc-idle-timeout-usec`],
    [`ESDM_CLIENT_RX_TX_TIMEOUT_EXPONENT`], [28], [The client waits
      2#super[28] ns, about 268 ms, for one send or receive; meson option
      `client-rx-tx-timeout-exponent`, 20 to 29],
    [`ESDM_CLIENT_CONNECT_TIMEOUT_EXPONENT`], [28], [The client waits
      2#super[28] ns between two attempts to connect; meson option
      `client-connect-timeout-exponent`, 20 to 29],
    [`ESDM_CLIENT_RECONNECT_ATTEMPTS`], [10], [Attempts to connect; meson
      option `client-reconnect-attempts`, 5 to 30],
    [`ESDM_MAX_RX_TX_RETRIES`], [5], [Repetitions of a timed out send or
      receive],
    [`ESDM_CLIENT_RESET_RETRIES`], [2], [Connection resets after which the
      client gives up a call],
  ),
  caption: [Limits and timeouts of the #ac("RPC") transport],
) <tab:if-rpc-limits>

#paragraph[Malformed requests][The server closes the connection without a
response when a datagram is shorter than the request header of 12 bytes, when
`message_length` exceeds 65,520 or the bytes received, when `method_index`
names no call of the service, and when the message does not decode
(`esdm_rpcs_process`). It also closes the connection when it cannot send a
response. A request with valid framing whose content a handler rejects is
answered with the error in `ret`\; the connection stays usable.]

#paragraph[Connections][One worker thread serves the privileged socket, and
one worker thread per #ac("DRNG") node, at most the value of the meson
option `threading_max_worker_threads` (64 by default), the unprivileged one. A worker
serving 1024 connections accepts no further one until one of them closes; the
clients beyond wait in the backlog of the socket, for which the server asks
for 4096 entries. A worker closes a connection that carried no request for 2
seconds. The client library therefore reconnects before a call when it last
used the connection 1 second or longer ago.]

#paragraph[Errors of the client library][The functions `esdm_rpcc_<call>`
return the `ret` of the response, or an error of their own: `-ETIMEDOUT`
when no response arrived within the bound of one call – three times six
receive timeouts, about 4.8 seconds –, the `errno` value of a failed
connect or transfer, `-EPROTO` or `-EOVERFLOW` for a response with an invalid
header, and `-EINTR` when the interrupt function of the caller ended the
call. The library repeats a call after a timeout or a reset of the
connection, on a new connection. It never repeats IF-RPC-U.8, IF-RPC-P.1 to
IF-RPC-P.4 and IF-RPC-P.7, which the server may already have executed: for
them it returns `-ETIMEDOUT` after a timeout or an interruption and
`-ECONNRESET` after a reset of the connection.]

== EGD Sockets <sec:if-egd>

Section @sec:egd specifies both sockets: their paths and how they are
enabled, the commands, the wire format of every request and reply (figures
@fig:egd-read to @fig:egd-bulk), the limits of 255 bytes per transfer and
65,536 bytes per bulk transfer and status, and the treatment of short and
failed requests. Section @sec:integration-egd describes the consumers.
IF-EGD-PR offers the same commands as IF-EGD and differs in one point: it
serves the commands 0x01 and 0x02, and 0xeb for 0x01, from the prediction
resistance #ac("DRNG"). Table @tab:if-egd assigns the identifiers; IF-EGD-PR.n
is the command IF-EGD.n on the second socket.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, auto, 1.5fr, 1fr, 1.5fr), align: left + horizon,
    table.header([Identifier], [Byte], [Command], [Peer], [Effect in the
      #ac("ESDM")]),
    [IF-EGD.1], [0x00], [Entropy count], [Every], [Reads the available
      entropy],
    [IF-EGD.2], [0x01], [Read without blocking], [Every],
      [`esdm_get_random_bytes_full_noblock`],
    [IF-EGD.3], [0x02], [Read, blocking], [Every], [As 0x01, completed by
      the event loop],
    [IF-EGD.4], [0x03], [Write entropy], [Every; the claim only for user
      #ac("ID") 0], [`esdm_pool_insert_aux`],
    [IF-EGD.5], [0x04], [Get #ac("PID")], [Every], [None],
    [IF-EGD.6], [0xe0], [Prediction resistance read without blocking],
      [Every], [`esdm_get_random_bytes_pr_noblock`],
    [IF-EGD.7], [0xe1], [Prediction resistance read, blocking], [Every],
      [As 0xe0, completed by the event loop],
    [IF-EGD.8], [0xe2], [Read with the semantics of `/dev/urandom`],
      [Every], [`esdm_get_random_bytes`],
    [IF-EGD.9], [0xe3], [Get state], [Every], [Reads the state flags and
      the four values of IF-RPC-U.9 to IF-RPC-U.12],
    [IF-EGD.10], [0xe4], [Status as text], [Every], [`esdm_status`],
    [IF-EGD.11], [0xe5], [Status as #ac("JSON")], [Every],
      [`esdm_status_json`],
    [IF-EGD.12], [0xe6], [Add to entropy count], [User #ac("ID") 0],
      [`esdm_pool_add_entropy`],
    [IF-EGD.13], [0xe7], [Clear pool], [User #ac("ID") 0],
      [`esdm_pool_set_entropy` with 0],
    [IF-EGD.14], [0xe8], [Reseed], [User #ac("ID") 0],
      [`esdm_drng_force_reseed`],
    [IF-EGD.15], [0xe9], [Set write wakeup threshold], [User #ac("ID") 0],
      [`esdm_set_write_wakeup_bits`],
    [IF-EGD.16], [0xea], [Set minimum reseed seconds], [User #ac("ID") 0],
      [`esdm_set_reseed_max_time`],
    [IF-EGD.17], [0xeb], [Bulk read], [Every], [As the read it names: 0x01,
      0xe0 or 0xe2],
    [IF-EGD.18], [0xec], [Bulk insert], [Every], [`esdm_pool_insert_aux`
      without entropy],
  )
}
, caption: [Commands of the #ac("EGD") sockets
  (`service-egd/esdm_egd_protocol.h`)]) <tab:if-egd>

In addition to section @sec:egd, the following applies:

- Privileges: both sockets have the mode 0666. The server reads the user
  #ac("ID") of the peer once, with `SO_PEERCRED` when it accepts the
  connection; a peer that drops its privileges afterwards keeps the
  credentials it connected with. A connection whose credentials cannot be
  read is closed.

- Errors: the commands 0x00 to 0x04 have no error reply. The commands 0xe6 to
  0xea answer with a status of 0 or `-EPERM`, and a refused command leaves
  the connection usable. The status of 0xec is 0 or the first error of an
  insertion. Command 0x03 of a peer other than root is carried out with an
  entropy claim of 0; a claim above 8 bits per byte is reduced to that, and a
  failed insertion is not reported.

- Limits: the server serves at most 2048 connections
  (`ESDM_EGD_MAX_CONNECTIONS`)\; further clients wait in the backlog of the
  socket. A connection whose reply the peer does not read for 30 seconds
  (`ESDM_EGD_WRITE_TIMEOUT_MS`) is closed. A non-blocking read that finds the
  #ac("DRNG", pl: true) waiting for a reseed is held back for at most 1
  second (`ESDM_EGD_PARK_MS`). The sockets have no idle timeout.

- Client: `esdm_egd_client.h` (IF-LIB-EGDC) and the kernel module `esdm_cdev`
  (IF-KMOD-CDEV) issue these commands.

== External Entropy Source Socket <sec:if-esext>

Section @sec:ext-es specifies the protocol between the #ac("ESDM") server and
the provider of an external entropy source: the socket, the messages
`EsExtRequest` and `EsExtResponse`, the four requests (table
@tab:es-ext-requests), the crediting and the handling of failures with their
time limits. Section @sec:writing-es-ext describes how to write a provider.
On this interface the #ac("ESDM") server is the client and the provider the
server. Table @tab:if-esext assigns the identifiers in the order of the
request types in `es-ext/pb/es_ext.proto`.

#figure(
  table(columns: (auto, auto, auto, 1.6fr), align: left + horizon,
    table.header([Identifier], [Request], [Type], [`length` of the
      request]),
    [IF-ESEXT.1], [`ES_EXT_GET_ENTROPY`], [1], [1 to
      `ESDM_ES_EXT_PROTO_MAX_DATA` (512), the bytes asked for],
    [IF-ESEXT.2], [`ES_EXT_SELFTEST`], [2], [0],
    [IF-ESEXT.3], [`ES_EXT_STATUS`], [4], [1 to
      `ESDM_ES_EXT_PROTO_STATUS_MAX` (1024), the largest answer],
    [IF-ESEXT.4], [`ES_EXT_INFO`], [5], [0],
  ),
  caption: [Requests of the external entropy source protocol],
) <tab:if-esext>

In addition to section @sec:ext-es, the following applies:

- Version: both messages carry `ESDM_ES_EXT_PROTO_VERSION` (1) in the field
  `version`\; either side rejects a message with another value.

- Privileges, #ac("ESDM") side: the server connects with its privileges
  dropped and accepts the provider only if `SO_PEERCRED` reports the user
  #ac("ID") 0 or the one configured with `--es_ext_uid` or the meson option
  `es_ext_peer_uid` (`esdm/esdm_es_extsock.c`).

- Privileges, provider side: `libesdm_es_ext` creates the socket file with
  the mode its caller passes; the provider programs use 0666 unless their
  option `--mode` sets another. A provider serves every client unless it
  allowed user #ac("ID", pl: true) with `esdm_es_ext_server_allow_uid`, up
  to `ESDM_ES_EXT_MAX_CLIENT_UIDS` (8); it then serves root and those. It
  serves `ESDM_ES_EXT_MAX_CLIENTS` (8) connections at a time.

- Errors: the field `status` of a response is 0 or a negative `errno` value
  down to -4095\; a response with another status than 0 carries nothing else.
  The #ac("ESDM") treats as a break of the protocol (`-EPROTO`) a response of
  another version or type than the request, a status outside of that range,
  data of another length than requested for `ES_EXT_GET_ENTROPY`, an empty
  or too long answer to `ES_EXT_STATUS`, a name longer than
  `ESDM_ES_EXT_NAME_MAX` (32) and an entropy above 8 bits per byte
  (`es-ext/esdm_es_ext_proto.h`). A provider disconnects a client that sends
  a request of another version, of an unknown type or with a `length` outside
  of the ranges of table @tab:if-esext.

- Limits: a declared entropy rate is at most `ESDM_ES_EXT_ENTROPY_RATE_MAX`
  (256) bits per 256 bits of data; the value `ESDM_ES_EXT_PROTO_RATE_NONE`
  declares none. A request is given `ESDM_EXT_TIMEOUT_MS` (2000 ms),
  `ES_EXT_STATUS` a quarter of it; after a failure the server connects again
  after `ESDM_EXT_RETRY_INTERVAL_SEC` (5 seconds) at the earliest.

== CUSE Devices /dev/random and /dev/urandom <sec:if-cuse>

`esdm-cuse-random` and `esdm-cuse-urandom` (sections
@sec:tool-esdm-cuse-random and @sec:tool-esdm-cuse-urandom) register the
#ac("CUSE") devices `/dev/esdm` and `/dev/uesdm` and bind-mount them over
`/dev/random` and `/dev/urandom`. Before that, each daemon opens the device
of the kernel it replaces and keeps it as fallback. Both devices have the
semantics of `random(4)`\; sections @sec:usage-cuse and @sec:fv-cuse describe
their behavior on a restart and their model. Table @tab:if-cuse lists the
operations. IF-CUSE-URANDOM.n is the operation IF-CUSE-RANDOM.n on
`/dev/urandom`\; the two devices differ in `read()` and `poll()` only.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, auto, 0.9fr, 1.2fr, 1.9fr), align: left + horizon,
    table.header([Identifier], [Operation], [Privilege], [#ac("RPC") call],
      [Errors and fallback to the device of the kernel]),
    [IF-CUSE-RANDOM.1], [`read()`], [None], [IF-RPC-U.4; with `O_SYNC`
      IF-RPC-U.5; on `/dev/urandom` IF-RPC-U.6], [See below],
    [IF-CUSE-RANDOM.2], [`write()`], [None], [IF-RPC-U.8], [On an error,
      the whole buffer is written to the device of the kernel; `EIO` if
      that write is short],
    [IF-CUSE-RANDOM.3], [`poll()`], [None], [None: IF-SHM], [`EINVAL`
      without requested events; see below],
    [IF-CUSE-RANDOM.4], [`RNDGETENTCNT`], [None], [IF-RPC-U.9], [The error
      of the call; no fallback],
    [IF-CUSE-RANDOM.5], [`RNDADDTOENTCNT`], [`CAP_SYS_ADMIN`],
      [IF-RPC-P.1], [`EINVAL` for a negative count\; `EPERM`\; on an error
      other than `ETIMEDOUT`, the #ac("IOCTL") is issued on the device of
      the kernel and its result returned\; without that device, the error
      of the call],
    [IF-CUSE-RANDOM.6], [`RNDADDENTROPY`], [`CAP_SYS_ADMIN`], [IF-RPC-P.2],
      [`EINVAL` for a negative size or entropy count and for a count above
      8 bits per byte; `EPERM`\; fallback as `RNDADDTOENTCNT`],
    [IF-CUSE-RANDOM.7], [`RNDZAPENTCNT`], [`CAP_SYS_ADMIN`], [IF-RPC-P.3],
      [`EPERM`\; the error of the call; after a successful call,
      `RNDCLEARPOOL` is issued on the device of the kernel as well and its
      error returned],
    [IF-CUSE-RANDOM.8], [`RNDCLEARPOOL`], [`CAP_SYS_ADMIN`], [IF-RPC-P.3],
      [As `RNDZAPENTCNT`],
    [IF-CUSE-RANDOM.9], [`RNDRESEEDCRNG`], [`CAP_SYS_ADMIN`], [IF-RPC-P.4],
      [`EPERM`\; the error of the call; after a successful call, the
      #ac("IOCTL") is issued on the device of the kernel as well and its
      error returned],
    [IF-CUSE-RANDOM.10], [#ac("IOCTL") 42], [None], [None: IF-SHM], [Returns
      the status text of the status segment; `EAGAIN` without a segment],
    [IF-CUSE-RANDOM.11], [#ac("IOCTL") 43], [`CAP_SYS_ADMIN`], [None],
      [`RNDADDENTROPY` on the device of the kernel only; `EINVAL` for a
      negative size; `EPERM`],
    [IF-CUSE-RANDOM.12], [#ac("IOCTL") 44], [`CAP_SYS_ADMIN`], [None],
      [`RNDRESEEDCRNG` on the device of the kernel only; `EPERM`],
  )
}
, caption: [Operations of the #ac("CUSE") devices
  (`frontends/cuse/cuse_device.c`)]) <tab:if-cuse>

#paragraph[Privilege][For a privileged #ac("IOCTL"), the daemon requires the
capability `CAP_SYS_ADMIN` of the calling thread, as the kernel does for its
devices. A daemon started with `--pid_namespace`, which cannot look up its
callers, and a call for which #ac("FUSE") reports no #ac("PID"), require the
user #ac("ID") 0 instead. For the duration of a privileged call the daemon
raises its own privileges, because the privileged #ac("RPC") socket only
serves root. Any other #ac("IOCTL") number fails with `EINVAL`, a
32-bit compatibility #ac("IOCTL") with `ENOSYS`.]

#paragraph[read()][The daemon requests at most 65,512 bytes per call and
fills the buffer of the reader. When the server answers `-EAGAIN`, it waits
1 to 16 ms and asks again; with `O_NONBLOCK` it returns what it has, or
`EAGAIN` with nothing; a reader interrupted by a signal gets `EINTR`. On any
other error of a call the daemon reads the outstanding bytes from the device
of the kernel and returns an error only if that read fails as well. For
`/dev/urandom` this includes the time before the #ac("ESDM") is operational,
which IF-RPC-U.6 answers with `-EOPNOTSUPP`.]

#paragraph[poll()][The daemon reports a device readable while the status
segment (IF-SHM) reports the #ac("ESDM") operational, and writable while it
reports that the #ac("ESDM") needs entropy. `/dev/urandom` is in addition
readable while the device of the kernel is. While no server publishes a
status, both devices report what the device of the kernel reports. The
suspend notification of the status segment (`suspend_gen`) wakes every waiting caller.]

== Files of esdm-proc <sec:if-proc>

`esdm-proc` (section @sec:tool-esdm-proc) serves a #ac("FUSE") file system
that replaces `/proc/sys/kernel/random`. The directory has the mode 0555.
Every user may open every file for reading; only the user #ac("ID") 0 may
open the two files of mode 0644 for writing, any other open fails with
`EACCES`. For a write, the daemon raises its privileges and issues the
privileged call. Table @tab:if-proc lists the files.

// Kept on one page: the table is short, and broken it leaves its caption
// alone at the foot of the page.
#block(breakable: false)[#figure(
  table(columns: (auto, auto, auto, 1fr, 1fr), align: left + horizon,
    table.header([Identifier], [File], [Mode], [Read], [Write]),
    [IF-PROC.1], [`boot_id`], [0444], [The value of the kernel's file, read
      once at start; a random #ac("UUID") if it cannot be read], [–],
    [IF-PROC.2], [`uuid`], [0444], [A new random #ac("UUID") of version 4
      per open: IF-RPC-U.6, completed with IF-RPC-U.4], [–],
    [IF-PROC.3], [`entropy_avail`], [0444], [IF-RPC-U.9], [–],
    [IF-PROC.4], [`poolsize`], [0444], [IF-RPC-U.10], [–],
    [IF-PROC.5], [`write_wakeup_threshold`], [0644], [IF-RPC-U.11],
      [IF-RPC-P.5],
    [IF-PROC.6], [`urandom_min_reseed_secs`], [0644], [IF-RPC-U.12],
      [IF-RPC-P.6],
    [IF-PROC.7], [`esdm_type`], [0444], [IF-RPC-U.1: the status text, cut
      off after 4096 bytes], [–],
  ),
  caption: [Files of `esdm-proc` (`frontends/cuse/proc_files.c`)],
) <tab:if-proc>]

A written value is a number as `strtoul()` with the base 0 parses it. A write
of no bytes or of 32 or more bytes fails with `EINVAL`, a value that does not
fit below 2#super[32] - 1 with `ERANGE`\; otherwise the write returns the
error of the call.

== getrandom() and getentropy() <sec:if-getrandom>

`libesdm-getrandom.so` (meson option `linux-getrandom`,
`libesdm_getrandom`(3)) replaces the two functions of the C library, either
preloaded with `LD_PRELOAD` or linked with `--wrap=getrandom` and
`--wrap=getentropy`. It exports `getrandom`, `getentropy`,
`__wrap_getrandom` and `__wrap_getentropy`, and `__real_getrandom` and
`__real_getentropy`, which issue the system call. A process with the
#ac("PID") 1 and a process that contains `libesdm` itself are always served
by the system call.

#paragraph[IF-GETRANDOM.1 getrandom()][
`ssize_t getrandom(void *buffer, size_t length, unsigned int flags)`.
`flags` is a bit mask of
`GRND_NONBLOCK`, `GRND_RANDOM`, `GRND_INSECURE` and the two flags of the
#ac("ESDM"), `GRND_SEED` (0x0010) and `GRND_FULLY_SEEDED` (0x0020). Any other
bit and any two of `GRND_INSECURE`, `GRND_RANDOM` and `GRND_SEED` together
fail with `EINVAL`. `length` is capped at `INT_MAX`. The library selects the
call in this order:]

- `GRND_INSECURE`: `esdm_rpcc_get_random_bytes` (IF-RPC-U.6),

- `GRND_NONBLOCK` without `GRND_SEED`:
  `esdm_rpcc_get_random_bytes_pr_noblock` with `GRND_RANDOM` (IF-RPC-U.5),
  else `esdm_rpcc_get_random_bytes_full_noblock` (IF-RPC-U.4), repeated
  while data arrives; `EAGAIN` if none arrived,

- `GRND_RANDOM`: `esdm_rpcc_get_random_bytes_pr` (IF-RPC-U.5),

- `GRND_SEED`: `esdm_rpcc_get_seed` (IF-RPC-U.7) with
  `ESDM_GET_SEED_NONBLOCK` for `GRND_NONBLOCK` and
  `ESDM_GET_SEED_FULLY_SEEDED` for `GRND_FULLY_SEEDED`\; an error of the call
  is returned in `errno`,

- otherwise: `esdm_rpcc_get_random_bytes_full` (IF-RPC-U.4).

#par(first-line-indent: 0pt)[A request for 0 bytes without `GRND_INSECURE`
and `GRND_SEED` asks whether the #ac("ESDM") delivers random numbers: it
waits and returns 0, or with `GRND_NONBLOCK` returns 0 or fails with
`EAGAIN`. The
function returns the number of bytes delivered. If the call fails for
another reason than the ones named, the library issues the system call
`getrandom` with the same arguments and returns its result. A `GRND_SEED`
request has no fallback: it fails with `EOPNOTSUPP` where the library does
not use the #ac("ESDM").]

#paragraph[IF-GETRANDOM.2 getentropy()][
`int getentropy(void *buffer, size_t length)`. A `length` above 256 fails with `EIO`. The library calls
`esdm_rpcc_get_random_bytes_full` (IF-RPC-U.4) and, if that fails, the system
call `getrandom` with the flags 0\; it returns the error of the system call,
or `EFAULT` if the system call delivered fewer bytes.]

== Library APIs <sec:if-lib>

Table @tab:if-lib lists the headers the #ac("ESDM") installs for other
programs with their function groups. The headers document every function;
the man pages give the overview. Sections @sec:using-c and
@sec:using-languages show their use.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1fr, 2.4fr, auto), align: left + horizon,
    table.header([Identifier], [Header, library], [Function groups],
      [Man page]),
    [IF-LIB-ESDM], [`esdm/esdm.h`, `libesdm`], [Life cycle (`esdm_init`,
      `esdm_reinit`, `esdm_init_monitor`, `esdm_fini`); random numbers
      (`esdm_get_random_bytes`, `esdm_get_random_bytes_full`,
      `esdm_get_random_bytes_pr` and their `_noblock` variants); seed data
      (`esdm_get_seed`); status (`esdm_status`, `esdm_status_json`,
      `esdm_status_drng_json`, `esdm_status_drng_pr_json`,
      `esdm_status_machine`, `esdm_version`); auxiliary pool
      (`esdm_pool_insert_aux`, `esdm_pool_add_entropy`,
      `esdm_pool_set_entropy`, `esdm_avail_entropy`,
      `esdm_avail_entropy_aux`, `esdm_avail_poolsize_aux`,
      `esdm_get_aux_ent`, `esdm_get_digestsize`); reseeding
      (`esdm_drng_force_reseed`, `esdm_get_reseed_max_time`,
      `esdm_set_reseed_max_time`, `esdm_get_write_wakeup_bits`,
      `esdm_set_write_wakeup_bits`); state and compliance
      (`esdm_state_operational`, `esdm_state_fully_seeded`,
      `esdm_sp80090c_compliant`, `esdm_es_oversampling`,
      `esdm_ntg1_compliant`, `esdm_ntg1_2024_compliant`,
      `esdm_drg3_compliant`, `esdm_drg4_compliant`)], [`libesdm`(3)],
    [IF-LIB-RPCC], [`service-rpc/client/esdm_rpc_client.h`,
      `libesdm_rpc_client`], [Connections (`esdm_rpcc_init_unpriv_service`,
      `esdm_rpcc_fini_unpriv_service`, `esdm_rpcc_get_unpriv_service`,
      `esdm_rpcc_put_unpriv_service`, `esdm_rpcc_force_fini_unpriv_service`,
      their `priv` counterparts,
      `esdm_rpcc_set_max_online_nodes`); one function per call of tables
      @tab:if-rpc-u and @tab:if-rpc-p, each with an `_int` variant that takes
      the data for the interrupt function of the caller; `esdm_invoke`, a
      macro repeating a call up to 5 times after `-EINTR`],
      [`libesdm_rpc_client`(3)],
    [IF-LIB-AUX], [`frontends/aux-client/esdm_aux_client.h`,
      `libesdm_aux_client`], [Waiting for the need of entropy
      (`esdm_aux_init_wait_for_need_entropy`,
      `esdm_aux_timedwait_for_need_entropy`,
      `esdm_aux_fini_wait_for_need_entropy`), based on IF-SHM],
      [`libesdm_aux_client`(3)],
    [IF-LIB-EGDC], [`service-egd/client/esdm_egd_client.h`,
      `libesdm_egd_client`], [Connection (`esdm_egd_client_alloc`,
      `esdm_egd_client_free`, `esdm_egd_client_socket_path`); random numbers
      (`esdm_egd_client_get_random`, `esdm_egd_client_get_random_nonblock`);
      state (`esdm_egd_client_entropy_count`,
      `esdm_egd_client_get_state_flags`, `esdm_egd_client_get_pid`);
      insertion (`esdm_egd_client_write_entropy`). For the commands the
      #ac("ESDM") adds to the protocol (IF-EGD.6 to IF-EGD.18): random
      numbers (`esdm_egd_client_get_random_pr`,
      `esdm_egd_client_get_random_pr_nonblock`,
      `esdm_egd_client_get_random_unseeded`,
      `esdm_egd_client_get_random_bulk`); state and status
      (`esdm_egd_client_get_state`, `esdm_egd_client_status`,
      `esdm_egd_client_status_json`); the privileged commands
      (`esdm_egd_client_add_to_entropy_count`, `esdm_egd_client_clear_pool`,
      `esdm_egd_client_reseed`, `esdm_egd_client_set_write_wakeup`,
      `esdm_egd_client_set_min_reseed_secs`), which return `-EPERM` for a
      peer other than root; bulk insertion (`esdm_egd_client_insert`)],
      [`libesdm_egd_client`(3)],
    [IF-LIB-ESEXT], [`es-ext/esdm_es_ext.h`, `libesdm_es_ext`], [The
      callbacks of a noise source (`struct esdm_es_ext_plugin`); the
      provider server (`esdm_es_ext_server_alloc`,
      `esdm_es_ext_server_allow_uid`, `esdm_es_ext_server_set_name`,
      `esdm_es_ext_server_set_entropy_rate`, `esdm_es_ext_server_run`,
      `esdm_es_ext_server_stop`, `esdm_es_ext_server_free`); the `main()` of
      a provider program (`esdm_es_ext_provider_main`)],
      [`libesdm_es_ext`(3)],
  )
}
, caption: [Library #ac("API", pl: true) of the #ac("ESDM")]) <tab:if-lib>

#paragraph[libesdm after a fork][`libesdm` holds the #ac("DRNG") states in
the address space of its process. A `fork()` would copy them, and parent and
child would generate the same random numbers. The library therefore registers
a handler with `pthread_atfork()` that marks the child as forked and
releases the #ac("DRNG") states of the built-in backends there; the state of
a backend from another cryptographic library remains in memory, as releasing
it could block in the child. A forked process gets no output: the functions
that generate random numbers
or seed data return `-EOPNOTSUPP` in a forked process
(`esdm_drng_mgr_check_forked` in `esdm/esdm_drng_mgr.c`). The client
libraries of IF-LIB-RPCC and IF-LIB-EGDC hold no such state and reconnect in
the child.]

#paragraph[Errors of libesdm][The functions of IF-LIB-ESDM return the errors
the #ac("RPC") calls pass on (section @sec:if-rpc-u): `-EAGAIN` from a
`_noblock` variant that would have to wait, `-EOPNOTSUPP` while the
#ac("ESDM") gives no output, `-EMSGSIZE` for a status or seed that does not
fit. `esdm_init` fails with `-ESHUTDOWN` after `esdm_fini`.]

== OpenSSL Providers <sec:if-ossl>

Section @sec:integration-openssl specifies the five provider modules (meson
option `openssl-rand-provider`, `esdm-openssl-provider`(7)), table
@tab:openssl-providers their properties and what each serves. Table
@tab:if-ossl assigns the identifiers and adds the names and the algorithms
the modules register.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.4fr, 1.2fr, 1.4fr, auto), align: left + horizon,
    table.header([Identifier], [Module], [Provider name], [RAND
      algorithms], [Based on]),
    [IF-OSSL.1], [`libesdm-rng-provider.so`], [ESDM RNG Provider],
      [`CTR-DRBG`, `HASH-DRBG`, `HMAC-DRBG`, `SEED-SRC`], [IF-LIB-RPCC],
    [IF-OSSL.2], [`libesdm-rng-provider-pr.so`], [ESDM RNG Provider (PR)],
      [As IF-OSSL.1], [IF-LIB-RPCC],
    [IF-OSSL.3], [`libesdm-seed-src-provider.so`], [ESDM RNG Provider],
      [`SEED-SRC`], [IF-LIB-RPCC],
    [IF-OSSL.4], [`libesdm-egd-provider.so`], [ESDM RNG Provider (EGD)],
      [As IF-OSSL.1], [IF-LIB-EGDC],
    [IF-OSSL.5], [`libesdm-egd-provider-pr.so`], [ESDM RNG Provider (EGD,
      PR)], [As IF-OSSL.1], [IF-LIB-EGDC],
  )
}
, caption: [The OpenSSL providers and their algorithms
  (`frontends/openssl-provider/`)]) <tab:if-ossl>

#paragraph[Parameters][A RAND context of every provider reports three
parameters: `OSSL_RAND_PARAM_MAX_REQUEST` with 256, `OSSL_RAND_PARAM_STRENGTH`
with 256 and `OSSL_RAND_PARAM_STATE`. The providers on IF-LIB-RPCC derive the
state from IF-RPC-U.3: ready if the #ac("ESDM") is fully seeded,
uninitialized if not, error if the call fails. A provider reports the
parameters `OSSL_PROV_PARAM_NAME`, `OSSL_PROV_PARAM_VERSION`,
`OSSL_PROV_PARAM_BUILDINFO` – both the version of the #ac("ESDM") – and
`OSSL_PROV_PARAM_STATUS` with 1. No parameter can be set. The providers on
IF-LIB-EGDC read one key from their section of the OpenSSL configuration,
`egd_socket`, the path of the socket. Without it, IF-OSSL.4 uses the
environment variable of IF-ENV.2 and then the path of the #ac("EGD") socket
the #ac("ESDM") was built with; IF-OSSL.5 does not read the variable and
uses the path of the prediction resistance socket it was built with.]

#paragraph[Requests][The providers on IF-LIB-RPCC serve a request with
`esdm_rpcc_get_random_bytes_full` (IF-RPC-U.4), or with
`esdm_rpcc_get_random_bytes_pr` (IF-RPC-U.5) when OpenSSL sets the prediction
resistance argument and, in IF-OSSL.2, always. IF-OSSL.4 fails a request with
that argument. A failed or short request returns 0 to OpenSSL with an entry
on its error stack.]

== Status Shared Memory Segment and Semaphores <sec:if-shm>

The #ac("ESDM") server publishes its state in a System V shared memory
segment and announces changes with three #ac("POSIX") named semaphores
(`esdm/esdm_shm_status.c`, `struct esdm_shm_status` in
`service-rpc/service/esdm_rpc_service.h`). The consumers wait for a change
without a request to the server. Section @sec:fv-shm-status describes the
model of the protocol. Table @tab:if-shm lists the objects.

#figure(
  table(columns: (auto, 1.5fr, 1.6fr), align: left + horizon,
    table.header([Identifier], [Object], [Used by]),
    [IF-SHM.1], [Segment with the key `ftok()` derives from the path `/` and
      the project identifier `ESDM_SHM_STATUS`, mode 0644], [Server writes;
      the #ac("CUSE") daemons and `libesdm_aux_client` read],
    [IF-SHM.2], [Semaphore `esdm-random-shm-status-semaphore`
      (`ESDM_SEM_RANDOM_NAME`)], [`esdm-cuse-random`],
    [IF-SHM.3], [Semaphore `esdm-urandom-shm-status-semaphore`
      (`ESDM_SEM_URANDOM_NAME`)], [`esdm-cuse-urandom`],
    [IF-SHM.4], [Semaphore `esdm-need-entropy-level-semaphore`
      (`ESDM_SEM_NEED_ENTROPY_LEVEL`)], [`libesdm_aux_client` (IF-LIB-AUX)],
  ),
  caption: [The status segment and its semaphores],
) <tab:if-shm>

#figure(
  image("../figures/shm-status.svg", width: 100%),
  caption: [Writer and readers of the status segment and its semaphores],
) <fig:shm-status>

Figure @fig:shm-status shows who writes and who reads. The server is the
only writer of the segment and the only process that posts the semaphores on
its own account; the consumers read the segment and wait on one semaphore
each. No data that is secret is in the segment: it holds states, a status
text and counters.

=== Objects and Names <sec:if-shm-objects>

The segment is a System V shared memory segment. Its key is
`ftok("/", ESDM_SHM_STATUS)` with the project identifier `0x6d647365`
(`ESDM_SHM_NAME`, `ESDM_SHM_STATUS`); `ftok()` uses the low eight bits of
the identifier, `0x65`, together with the device and inode number of `/`, so
that the key is the same for every process that sees the same root directory
and differs in a mount namespace with another one. The size is
`sizeof(struct esdm_shm_status)`, 4,128 bytes on a 64-bit system, and the
mode is 0644. The semaphores are #ac("POSIX") named semaphores, which Linux
keeps as files `sem.`_name_ below `/dev/shm`; their mode is 0644 and their
initial value 0. A build with the meson option `testmode` uses the project
identifier `0x6573646d` (low eight bits `0x6d`) and appends `-testmode` to
the three names, so that a test build does not meet the objects of an
installed #ac("ESDM").

A process finds the segment with `ipcs -m` under its key and the semaphores
in `/dev/shm`. `ipcs -m -i` _id_ shows the creator, the owner and the number
of attached processes.

=== Layout of the Segment <sec:if-shm-layout>

The segment holds exactly one `struct esdm_shm_status`, from its first byte
on. Table @tab:if-shm-layout lists the fields in their order with the offset
and size the #ac("ABI") of a 64-bit Linux system gives them; the padding is
that of the C compiler and carries no data. On a 32-bit system `size_t` has
4 bytes, and the offsets after `info` differ. The byte order is that of the
host. The layout is not a wire format: writer and readers are built from the
same header, and a change of the layout changes `ESDM_SHM_STATUS_VERSION`.

#figure(
{
  set text(size: 9pt)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, auto, auto, 1fr), align: left + top,
    table.header([Offset], [Size], [Field], [Content]),
    [0], [4], [`uint32_t version`], [`ESDM_SHM_STATUS_VERSION` (3) while a
      server publishes a complete status; 0 while a server sets the segment
      up, after it exited, and in a segment a consumer created. Any other
      value is a segment of another version of the #ac("ESDM")],
    [4], [4,096], [`char info[ESDM_SHM_STATUS_INFO_SIZE]`], [The status text
      `esdm_status()` returns, taken once at the start of the server, as far
      as it fits, terminated by a zero byte. It is not updated afterwards],
    [4,100], [4], [padding], [],
    [4,104], [8], [`size_t infolen`], [The length of the text in `info`
      without the zero byte, at most 4,095],
    [4,112], [4], [`uint32_t unpriv_threads`], [The number of #ac("DRNG")
      nodes of the server. IF-RPC-U has as many worker threads, at most the
      value of the meson option `threading_max_worker_threads`. No program
      of the #ac("ESDM") reads the field],
    [4,116], [1], [`atomic_bool operational`], [True while the #ac("ESDM")
      is operational (section @sec:state-machines): requests for random
      numbers are served],
    [4,117], [1], [`atomic_bool need_entropy`], [True while the entropy of
      the auxiliary pools is below the write wakeup threshold (section
      @sec:aux): data written with entropy would be credited],
    [4,118], [2], [padding], [],
    [4,120], [4], [`atomic_uint suspend_gen`], [The number of suspend
      notifications so far, counted modulo $2^32$: a suspend (IF-SIG.2, or
      the event of the kernel module, table @tab:system-events) and every
      exit of a server],
    [4,124], [4], [padding], [],
  )
},
  caption: [Layout of `struct esdm_shm_status` on a 64-bit system, version
    3],
) <tab:if-shm-layout>

#paragraph[Versions][Version 2 enlarged the status text from 1,536 to 4,096
bytes. Version 3 replaced the flag `suspend_trigger`, which a reader
cleared, by the counter `suspend_gen`. A reader uses a
segment only while `version` has the value it was built with, and treats
every other value as "no server publishes a status". A server and consumers
of different versions therefore do not misread each other; the consumers
then behave as without a server until they are restarted with the matching
version.]

=== Writing the Segment <sec:if-shm-writer>

Only the server writes the segment (`esdm/esdm_shm_status.c`). The rules per
field are:

- `version`: set to 0 when the server attaches the segment, before anything
  else is written, and to `ESDM_SHM_STATUS_VERSION` as the last step of the
  initialization, after `info`, `infolen`, `unpriv_threads`, `operational`
  and `need_entropy` hold the values of this server. A memory barrier
  precedes and follows each of the two stores. At the exit the server sets
  it to 0 before it counts up `suspend_gen` and posts. A reader that finds
  the valid version therefore finds the fields of the server that published
  it, not those of a predecessor whose segment the server took over.
- `info`, `infolen`, `unpriv_threads`: written once per start, while
  `version` is 0. They are plain fields without atomic access; the version
  is what makes them safe to read.
- `operational`: stored with an atomic operation whenever the operational
  state of the #ac("ESDM") changes (`esdm_shm_status_set_operational`, called
  under the lock of the initial #ac("DRNG") instance, under which that state
  changes), and at the start.
- `need_entropy`: evaluated and stored under one lock of the server
  (`esdm_shm_status_set_need_entropy`), so that the last store is that of the
  last evaluation. It is evaluated after data with entropy was inserted into
  the auxiliary pool, after an insertion that failed, after a seeding took
  entropy from the pool, when the write wakeup threshold is set, and at the
  start.
- `suspend_gen`: counted up with an atomic operation by the handler of
  `SIGUSR1` (IF-SIG.2), by the thread that reads the events of the kernel
  module, and at the exit. A starting server keeps the value it finds in a
  segment it takes over: the readers compare it with the value they acted
  on, and a reset could return it to just that value.

Each change of `operational` or `need_entropy`, the publication of the
version and each count of `suspend_gen` is followed by posts as section
@sec:if-shm-sem specifies. The store precedes the post, so that a reader
woken by a post finds the value that caused it.

=== Life Cycle and Access Rights <sec:if-shm-lifecycle>

#paragraph[Creation][The server creates or takes over the segment during the
initialization of the library, before it drops its privileges, and then the
three semaphores. It looks the segment up by its key. A segment that exists
and whose creator is the effective user #ac("ID") of the server – root in
the delivered configuration – is kept and reused: it is the one a previous
server left, and the consumers attached to it stay attached. A segment
created by another user is removed and created anew, because every local
user can compute the key and could otherwise place a segment whose content
the #ac("CUSE") daemons act on. A segment of another size, which an
#ac("ESDM") of another version left, is removed and created anew as well.]

#paragraph[Consumers that start first][A #ac("CUSE") daemon and
`libesdm_aux_client` attach the segment when they start and create it, with
the mode 0644, if none exists, so that they can attach; `version` of a new
segment is 0. They never remove a segment. They open their semaphore and
create it if it does not exist. A consumer attaches once: when the segment
it is attached to is removed and another one created under the key, it stays
on the removed one, which nobody writes any more. For that reason the
removal skips a segment that has attached processes, and a server reuses the
segment of its predecessor.]

#paragraph[Exit and removal][A server that exits sets `version` to 0,
counts up `suspend_gen`, posts the three semaphores, detaches the segment and
closes the semaphores. It does not remove them: after the privilege drop it
has no right to. The supervisor of `--pid_namespace` removes the segment and
unlinks the semaphores after the daemon ended, unless `--keep_ipc` is given,
and leaves the segment and the semaphores in place while a process is
attached to the segment (section @sec:tool-esdm-server). A server that is
killed withdraws nothing: `version` keeps its value and the fields those of
the dead server until a server starts again (section @sec:fv-cuse). The
re-initialization of the library (`esdm_reinit`) detaches and attaches the
segment anew and removes nothing.]

#paragraph[Access rights][The mode 0644 of the segment and of the semaphores
permits the owner to write and every local user to read. The consumers of
the #ac("ESDM") attach the segment read-only (`shmat(id, NULL, SHM_RDONLY)`
in `frontends/cuse/cuse_device.c` and
`frontends/aux-client/esdm_aux_need_entropy.c`): a consumer cannot change
what the server and the other consumers see, and every local user can attach
and read the fields. A semaphore is different: a waiter decrements it, so
that `sem_open()` opens it for reading and writing, which requires the write
permission of the file. Waiting on a semaphore therefore takes the user that
owns it, root in the delivered configuration, or the capability
`CAP_DAC_OVERRIDE`; a process of another user reads the segment and cannot
wait for a change. The mode is not widened, as every user could then take
the notifications of the consumers.]

#paragraph[What a reader may rely on][The content of a segment with the valid
version stems from a server that ran with the user #ac("ID") of the creator
of the segment, as the server removes a segment of another creator when it
starts. Before a server has started, a reader cannot tell a segment a local
user placed from one a consumer created; the version of a segment a consumer
created is 0. A consumer acts on the segment for availability only – whether
to report a device readable or writable, when to wake a waiter – and never
for the random numbers themselves, which it obtains over IF-RPC-U.]

=== Reading the Segment <sec:if-shm-readers>

A reader proceeds as follows; the consumers of the #ac("ESDM") do so:

+ Look the segment up with `shmget(ftok("/", ESDM_SHM_STATUS),
  sizeof(struct esdm_shm_status), 0444)` and attach it. A size that does not
  match is another version of the #ac("ESDM").
+ Before every use, compare `version` with `ESDM_SHM_STATUS_VERSION`. With
  another value no server publishes a status: use nothing else of the
  segment.
+ Read `operational`, `need_entropy` and `suspend_gen` with atomic loads.
  They may change at any time; a value read is a snapshot.
+ Read `info` up to `infolen` bytes, and bound `infolen` by the size of the
  field.
+ To wait for a change, wait on the semaphore assigned to the reader
  (section @sec:if-shm-sem) and read the fields again after every return. A
  wakeup carries no information of its own.

Table @tab:if-shm-readers lists what the consumers of the #ac("ESDM") do
with the fields.

#figure(
{
  set text(size: 9pt)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.9fr, 2fr), align: left + top,
    table.header([Consumer], [Use of the segment]),
    [`esdm-cuse-random`, `esdm-cuse-urandom`: `poll()` (IF-CUSE-RANDOM,
      IF-CUSE-URANDOM)], [With the valid version: readable while
      `operational` is true, writable while `need_entropy` is true. Without
      it: what the device of the kernel reports. While `operational` is
      false, `/dev/urandom` is readable while the device of the kernel is,
      as its reads fall back to it. A value of `suspend_gen` other than the one the daemon
      acted on last reports the device readable and writable once, to wake
      every waiting caller],
    [The poll checker thread of the #ac("CUSE") daemons], [Waits on the
      semaphore of the daemon; after each return it evaluates the fields for
      every registered poll and notifies those whose events are reported,
      then stores the value of `suspend_gen` it used as acted on. The value
      is kept in the daemon, not in the segment, as both daemons read the
      same counter. Without the valid version it does not wait on the
      semaphore but looks again every second, because the device of the
      kernel, which `poll()` then follows, posts nothing],
    [The #ac("CUSE") daemons: #ac("IOCTL") 42 (IF-CUSE-RANDOM.10)],
      [Returns `info` with `infolen` bytes, `infolen` bounded by the size of
      the field; `EAGAIN` when no segment is attached. The version is not
      checked: after the exit of a server the text of that server is still
      returned],
    [`libesdm_aux_client`: `esdm_aux_timedwait_for_need_entropy()`
      (IF-LIB-AUX)], [Waits until the version is valid, looking every 50 ms
      and at most until the deadline of the call; returns at once while
      `need_entropy` is true; otherwise waits on IF-SHM.4 and reads
      `need_entropy` again after each return. It logs `info` once, at the
      debug level, when it first finds the valid version],
  )
},
  caption: [Use of the status segment by the consumers of the #ac("ESDM")],
) <tab:if-shm-readers>

=== Semaphores <sec:if-shm-sem>

The three semaphores are an interface of their own: they are the only way a
process learns of a change of the #ac("ESDM") without a request to the
server. Table @tab:if-shm-sem lists them. A semaphore carries no data; its
meaning is "read the segment again".

#figure(
{
  set text(size: 9pt)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (0.5fr, 1.5fr, 1fr, 1.4fr), align: left + top,
    table.header([Identifier], [Name; file], [Waiter], [Posted by the
      server]),
    [IF-SHM.2], [`esdm-random-shm-status-semaphore`
      (`ESDM_SEM_RANDOM_NAME`); `/dev/shm/sem.esdm-random-shm-status-semaphore`],
      [The poll checker of `esdm-cuse-random`, with `sem_wait()`], [After a
      change of `operational` or `need_entropy`; once after the version was
      published at the start; after each count of `suspend_gen`, which
      includes the exit; when the server opens a semaphore that exists],
    [IF-SHM.3], [`esdm-urandom-shm-status-semaphore`
      (`ESDM_SEM_URANDOM_NAME`); `/dev/shm/sem.esdm-urandom-shm-status-semaphore`],
      [The poll checker of `esdm-cuse-urandom`, with `sem_wait()`], [As
      IF-SHM.2, in the same step],
    [IF-SHM.4], [`esdm-need-entropy-level-semaphore`
      (`ESDM_SEM_NEED_ENTROPY_LEVEL`); `/dev/shm/sem.esdm-need-entropy-level-semaphore`],
      [The callers of `esdm_aux_timedwait_for_need_entropy()`, with
      `sem_clockwait()` on `CLOCK_MONOTONIC`], [After every evaluation of
      the need that finds entropy needed, whether or not `need_entropy`
      changed; after each count of `suspend_gen`; when the server opens a
      semaphore that exists],
  )
},
  caption: [The semaphores of the status segment],
) <tab:if-shm-sem>

#paragraph[Creation][The server and each consumer open a semaphore with
`sem_open(name, O_CREAT | O_EXCL, 0644, 0)` and, if it exists, with
`sem_open(name, O_CREAT, 0644, 0)`: whoever starts first creates it with the
value 0, and the others use it with the value it has. A semaphore outlives
the processes that use it until it is unlinked (section
@sec:if-shm-lifecycle). A server that finds the semaphore existing posts it
once, unless a notification is pending, so that a waiter left from a
previous server reads the segment of the new one.]

#paragraph[Binary use][The server posts a semaphore only while its value is
0 (`sem_getvalue()`, then `sem_post()`): the value is 0 or 1 at
any time. A semaphore therefore states that something changed since the waiter
last looked, not how often; a waiter that was not waiting finds one pending
notification. The posts of the server are combined: a thread that finds
another one posting the same semaphore leaves its notification to that one,
which looks at the value again after its post, so that two concurrent
changes never raise the value above 1 and none is lost. Nothing in a post
blocks, which lets the signal handler of IF-SIG.2 post as well.]

#paragraph[Edge and level][IF-SHM.2 and IF-SHM.3 are posted on a change:
after the post the waiter reads the fields and waits again, and the next
post comes with the next change. IF-SHM.4 is posted as a level: every
evaluation of the need that finds entropy needed posts it again, so that a
provider of entropy that returned from the wait, wrote its data and waits
again returns as long as the need lasts. As one post wakes one waiter, a
caller of `esdm_aux_timedwait_for_need_entropy()` that finds `need_entropy`
true after its wait posts IF-SHM.4 once itself, if its value is 0, and
thereby passes the notification on to the next waiter; this is the only
post a consumer issues. A caller woken while `need_entropy` is false – by a
post left from a need that ended, or by a suspend notification – waits
again; the wait ends at the deadline of the call with `ETIMEDOUT`.]

#paragraph[One waiter per semaphore][IF-SHM.2 and IF-SHM.3 have one waiter
each, the poll checker of one daemon. A post wakes one waiter: a second
process waiting on one of them would take every other notification from the
daemon, whose callers in `poll()` would then sleep through a change. The two
semaphores are therefore reserved for the two daemons; the delivered
configuration starts one instance of each. A program that wants to follow
`operational` uses `poll()` on `/dev/random`, and one that provides entropy
uses IF-LIB-AUX, which is built for several waiters.]

#paragraph[Suspend, exit and restart][Each count of `suspend_gen` posts all
three semaphores, so that no consumer sleeps through a suspend of the
machine or the end of the server. At the exit the server withdraws the
version first: a poll checker woken by the exit finds no valid version,
notifies its pollers with what the device of the kernel reports and from
then on looks every second instead of waiting on the semaphore. A starting
server publishes the version and posts IF-SHM.2 and IF-SHM.3 after it, so
that a poll checker that looked while the version was withdrawn and then
finds it valid is not left waiting for a post that was issued before. A
consumer needs no restart across a restart of the server, provided the
segment and the semaphores are kept (`--keep_ipc`, or attached consumers).
Section @sec:fv-shm-status has the model of this protocol and the defects
found in earlier revisions of it.]

#paragraph[Failure modes][A waiter that is killed between its wakeup and its
reading of the segment leaves the semaphore at 0 and loses nothing but its
own notification. A semaphore that is unlinked while a process has it open
stays usable for that process, but a server that starts afterwards creates a
new one under the name and posts that: the consumer then waits on an object
nobody posts and has to be restarted. The same holds for a segment that is
removed while attached. Removing the files below `/dev/shm` or the segment
with `ipcrm` while consumers run therefore disconnects them from the
server.]

== Kernel Module esdm_es <sec:if-kmod-es>

The kernel module `esdm_es` provides the interrupt and the scheduler entropy
source and the system events (sections @sec:irq-processing, @sec:sched-events
and @sec:vm-clone). The #ac("ESDM") server is its consumer; the module has
no interface for other programs but the test files. It registers the
character device `/dev/esdm_es`.

#paragraph[IF-KMOD-ES.12 open()][`open()` requires the capability
`CAP_SYS_ADMIN` and fails with `EPERM` without it. The #ac("IOCTL", pl: true)
are not checked again, so a process may drop its privileges after the open,
as the #ac("ESDM") server does. Every open file has settings of its own: the
requested entropy and the entropy rate of each entropy source, and the event
counts it has seen. The collected events are shared by all open files. The
device offers no `read()` and no `write()`.]

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.5fr, auto, 2.2fr), align: left + horizon,
    table.header([Identifier], [#ac("IOCTL")], [Number], [Argument and
      effect]),
    [IF-KMOD-ES.1], [`ESDM_IRQ_AVAIL_ENTROPY`], [0x00, read], [`__u32`: the
      entropy the interrupt entropy source holds, in bits, at the entropy
      rate of the open file],
    [IF-KMOD-ES.2], [`ESDM_IRQ_ENT_BUF_SIZE`], [0x01, read], [`__u32[2]`:
      the size of the entropy buffer and the number of the entropy source],
    [IF-KMOD-ES.3], [`ESDM_IRQ_ENT_BUF_IOCTL`], [0x02, read], [The entropy
      buffer of the size IF-KMOD-ES.2 reports: reads entropy, which is gone
      for all other open files],
    [IF-KMOD-ES.4], [`ESDM_IRQ_CONF`], [0x03, write], [`__u32[2]`. Word 1:
      `ESDM_ES_MGR_RESET_BIT` (bit 31) discards the collected events; the
      low 9 bits (`ESDM_ES_MGR_REQ_BITS_MASK`) set the entropy a read asks
      for, 0 for unchanged, else one of the seed sizes of the build. Word 2:
      the number of events credited with 256 bits of entropy, 0 for
      unchanged; the entropy source never credits more than the rate the
      module was loaded with, and 0xffffffff credits none. `EINVAL` for
      another requested entropy, before anything is carried out],
    [IF-KMOD-ES.5], [`ESDM_SCHED_AVAIL_ENTROPY`], [0x05, read], [As
      IF-KMOD-ES.1 for the scheduler entropy source],
    [IF-KMOD-ES.6], [`ESDM_SCHED_ENT_BUF_SIZE`], [0x06, read], [As
      IF-KMOD-ES.2],
    [IF-KMOD-ES.7], [`ESDM_SCHED_ENT_BUF_IOCTL`], [0x07, read], [As
      IF-KMOD-ES.3],
    [IF-KMOD-ES.8], [`ESDM_SCHED_CONF`], [0x08, write], [As IF-KMOD-ES.4],
    [IF-KMOD-ES.9], [`ESDM_IRQ_STATUS_JSON`], [0x0a, read], [`char[500]`:
      the status of the interrupt entropy source as #ac("JSON") object],
    [IF-KMOD-ES.10], [`ESDM_SCHED_STATUS_JSON`], [0x0b, read], [As
      IF-KMOD-ES.9 for the scheduler entropy source],
    [IF-KMOD-ES.11], [`ESDM_ES_EVENTS`], [0x0c, read],
      [`__u32[ESDM_ES_EVENTS_WORDS]`, 5 words: a bit mask of the events this
      kernel reports, then the count of each event since the module was
      loaded – #ac("VM") generation change (0), suspend (1), resume (2),
      shutdown (3). Marks the counts as seen by the open file],
  )
}
, caption: [#ac("IOCTL", pl: true) of `/dev/esdm_es`, type `ESDMIO` (0xE0)
  (`kernel/shared/esdm_es_ioctl.h`)]) <tab:if-kmod-es>

#par(first-line-indent: 0pt)[The numbers 0x04 and 0x09 are no longer
assigned. The #ac("IOCTL", pl: true) of an entropy source the module was
built without, and every unknown number, return `-ENOIOCTLCMD` in the
module, which the caller receives as `ENOTTY`. A failed copy from or to the memory of the caller returns `EFAULT`.
IF-KMOD-ES.11 works in a module built with neither entropy source. Table
@tab:system-events states how the #ac("ESDM") reacts to each event.]

#paragraph[IF-KMOD-ES.13 poll()][`poll()` reports an open file readable
(`EPOLLIN`, `EPOLLRDNORM`) while a count of an event differs from the one
IF-KMOD-ES.11 last returned on this file. A file that never issued it starts
with the counts at its open.]

#paragraph[Test files][A module built with the test interfaces creates the
directory `esdm_es` in debugfs with up to four files of the mode 0400, each
with `read()` only (section @sec:test-interfaces,
`kernel/esdm_es/esdm_testing.c`):
IF-KMOD-ES.14 `esdm_raw_hires`, the raw time stamps of the interrupt events;
IF-KMOD-ES.15 `esdm_irq_perf`, the performance data of the interrupt entropy
source; IF-KMOD-ES.16 `esdm_raw_sched_hires`, the raw time stamps of the
scheduler events; IF-KMOD-ES.17 `esdm_sched_perf`, the performance data of
the scheduler entropy source. `esdm-getrawentropy` reads them (section
@sec:tool-esdm-getrawentropy).]

#figure(
  table(columns: (auto, 1.6fr, auto, 2fr), align: left + horizon,
    table.header([Identifier], [Parameter], [Type, mode], [Meaning]),
    [IF-KMOD-ES.18], [`irq_entropy`], [`uint`, 0444], [Interrupts credited
      with 256 bits of entropy; only in a module built with the run-time
      configuration of the entropy sources],
    [IF-KMOD-ES.19], [`sched_entropy`], [`uint`, 0444], [Context switches
      credited with 256 bits of entropy; as above],
    [IF-KMOD-ES.20], [`esdm_panic_on_permanent_health_failure`], [`bool`,
      0444], [Panic of the kernel on a permanent health test failure;
      default off],
    [IF-KMOD-ES.21], [`esdm_major`], [`int`, 0], [Major number of the
      device; 0, the default, lets the kernel assign one],
    [IF-KMOD-ES.22], [`boot_raw_hires_test`], [`uint`, 0644], [Record the
      raw data of IF-KMOD-ES.14 from the first interrupt events on],
    [IF-KMOD-ES.23], [`boot_irq_perf`], [`uint`, 0644], [Record the data of
      IF-KMOD-ES.15],
    [IF-KMOD-ES.24], [`boot_raw_sched_hires_test`], [`uint`, 0644], [Record
      the raw data of IF-KMOD-ES.16 from the first scheduler events on],
    [IF-KMOD-ES.25], [`boot_sched_perf`], [`uint`, 0644], [Record the data
      of IF-KMOD-ES.17],
  ),
  caption: [Module parameters of `esdm_es`],
) <tab:if-kmod-es-params>

#par(first-line-indent: 0pt)[The parameters IF-KMOD-ES.22 to IF-KMOD-ES.25
exist only in a module built with the corresponding test file.]

== Kernel Module esdm_cdev <sec:if-kmod-cdev>

The kernel module `esdm_cdev` serves random numbers of the #ac("ESDM") from
kernel devices (sections @sec:interfaces and @sec:fv-kernel-cdev). It is a
client of IF-EGD: it connects to the #ac("EGD") socket with up to 4 kernel
sockets and holds no #ac("RNG") of its own. While the #ac("ESDM") cannot be
reached, nothing is served from the kernel #ac("RNG") instead. Table
@tab:if-kmod-cdev lists its interfaces; `esdm-cdev-check` exercises them
(section @sec:tool-esdm-cdev-check).

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.3fr, 0.9fr, 1.1fr, 1.8fr), align: left + horizon,
    table.header([Identifier], [Interface], [Privilege], [#ac("EGD")
      command], [Behavior and errors]),
    [IF-KMOD-CDEV.1], [`/dev/esdm_random`, mode 0666], [None], [`read()`:
      IF-EGD.17 for 0x01; with `O_SYNC` for 0xe0. `write()`: IF-EGD.18],
      [`read()` waits until the #ac("ESDM") is operational, also while it
      cannot be reached; `EAGAIN` with `O_NONBLOCK`. `poll()`: readable once
      operational, writable before],
    [IF-KMOD-CDEV.2], [`/dev/esdm_urandom`, mode 0666], [None], [`read()`:
      IF-EGD.17 for 0xe2; with `O_SYNC` for 0xe0. `write()`: IF-EGD.18],
      [`read()` waits until the #ac("ESDM") is operational and fails while
      it cannot be reached. No `poll()`],
    [IF-KMOD-CDEV.3], [`/dev/esdm_pr`, mode 0666], [None], [`read()`:
      IF-EGD.17 for 0xe0. `write()`: IF-EGD.18], [A `read()` with
      `O_NONBLOCK` returns data, `EAGAIN` or, for an inaccessible buffer,
      `EFAULT`. `poll()`: readable once operational, but not for 50 ms after
      a read found no data or a read with `O_NONBLOCK` got no memory; always
      writable],
    [IF-KMOD-CDEV.4], [`RNDGETENTCNT`], [None], [IF-EGD.9], [`int`: the
      entropy of the auxiliary pool],
    [IF-KMOD-CDEV.5], [`RNDADDTOENTCNT`], [`CAP_SYS_ADMIN`], [IF-EGD.12],
      [`EPERM`\; `EINVAL` for a negative count],
    [IF-KMOD-CDEV.6], [`RNDADDENTROPY`], [`CAP_SYS_ADMIN`], [IF-EGD.18,
      then IF-EGD.12], [`EPERM`\; `EINVAL` for a negative count or size;
      a size of 0 does nothing. The credit is at most 8 bits per byte and is
      given only after all data was inserted],
    [IF-KMOD-CDEV.7], [`RNDZAPENTCNT`], [`CAP_SYS_ADMIN`], [IF-EGD.13],
      [`EPERM`],
    [IF-KMOD-CDEV.8], [`RNDCLEARPOOL`], [`CAP_SYS_ADMIN`], [IF-EGD.13],
      [`EPERM`],
    [IF-KMOD-CDEV.9], [`RNDRESEEDCRNG`], [`CAP_SYS_ADMIN`], [IF-EGD.14],
      [`EPERM`],
    [IF-KMOD-CDEV.10], [`/proc/esdm/entropy_avail`, 0444], [None],
      [IF-EGD.9], [Entropy of the auxiliary pool in bits],
    [IF-KMOD-CDEV.11], [`/proc/esdm/poolsize`, 0444], [None], [IF-EGD.9],
      [Size of the auxiliary pool in bits],
    [IF-KMOD-CDEV.12], [`/proc/esdm/write_wakeup_threshold`, 0644],
      [`CAP_SYS_ADMIN` to write], [IF-EGD.9; write: IF-EGD.15], [Write:
      `EPERM`\; `ERANGE` for 2#super[32] - 1; the error of the number
      parser],
    [IF-KMOD-CDEV.13], [`/proc/esdm/urandom_min_reseed_secs`, 0644],
      [`CAP_SYS_ADMIN` to write], [IF-EGD.9; write: IF-EGD.16], [As
      IF-KMOD-CDEV.12],
    [IF-KMOD-CDEV.14], [`/proc/esdm/status`, 0444], [None], [IF-EGD.10],
      [Status as text],
    [IF-KMOD-CDEV.15], [`/proc/esdm/status.json`, 0444], [None],
      [IF-EGD.11], [Status as #ac("JSON") document],
    [IF-KMOD-CDEV.16], [Parameter `egd_socket`, `charp`, 0444], [Root, at
      load time], [–], [Path of the #ac("EGD") socket; default
      `/run/esdm-egd.socket`],
    [IF-KMOD-CDEV.17], [Parameter `timeout_ms`, `uint`, 0644], [Root], [–],
      [Bound on connecting and on each transfer in milliseconds, limited to
      100 to 60,000; default 5000],
  )
}
, caption: [Interfaces of the kernel module `esdm_cdev`
  (`kernel/esdm_cdev/`)]) <tab:if-kmod-cdev>

#paragraph[Reads][A device opened with `O_SYNC` is served from the
prediction resistance #ac("DRNG")\; `O_DSYNC` alone does not select it. A
read requests at most 65,536 bytes from the #ac("ESDM") at a time and
returns the bytes read so far when a signal arrives; without any, the call
is restarted or fails with `EINTR`, as the disposition of the signal
determines.]

#paragraph[Privilege][The module connects as root, so the #ac("ESDM")
carries out every command it sends. The check of `CAP_SYS_ADMIN` in the
module is therefore what keeps an unprivileged caller from the privileged
#ac("IOCTL", pl: true) and from writing the two files in `/proc/esdm`. Any
other #ac("IOCTL") number fails with `EINVAL`.]

#paragraph[Unreachable ESDM][While the #ac("ESDM") cannot be reached, the
#ac("IOCTL", pl: true), the writes and the reads of `/dev/esdm_urandom` fail
with `ENOTCONN` if no connection can be made, `ETIMEDOUT` if the #ac("ESDM")
does not answer or none of the connections becomes free in time, `ECONNRESET` or `EPIPE` if it closes the connection, and
`EPROTO` for an answer that does not fit.]

== Command Lines <sec:if-cli>

Chapter @sec:tools specifies the command line of every program: its options
with their arguments, its exit status and its signals. Table @tab:if-cli
assigns the identifiers in the order of table @tab:tools.

#figure(
  table(columns: (auto, auto, auto, 1fr), align: left + horizon,
    table.header([Identifier], [Program], [Section], [Privilege]),
    [IF-CLI.1], [`esdm-server`], [@sec:tool-esdm-server], [Started as root],
    [IF-CLI.2], [`esdm-tool`], [@sec:tool-esdm-tool], [Root for the
      commands on IF-RPC-P; see the section],
    [IF-CLI.3], [`esdm-cuse-random`], [@sec:tool-esdm-cuse-random], [See
      the section],
    [IF-CLI.4], [`esdm-cuse-urandom`], [@sec:tool-esdm-cuse-urandom], [See
      the section],
    [IF-CLI.5], [`esdm-proc`], [@sec:tool-esdm-proc], [See the section],
    [IF-CLI.6], [`esdm-kernel-seeder`], [@sec:tool-esdm-kernel-seeder],
      [See the section],
    [IF-CLI.7], [`esdm-server-signal-helper`],
      [@sec:tool-esdm-server-signal-helper], [Root],
    [IF-CLI.8], [`esdm-es-pkcs11`], [@sec:tool-esdm-es-pkcs11], [See the
      section],
    [IF-CLI.9], [`esdm-es-pcsc`], [@sec:tool-esdm-es-pcsc], [See the
      section],
    [IF-CLI.10], [`esdm-getrawentropy`], [@sec:tool-esdm-getrawentropy],
      [See the section],
    [IF-CLI.11], [`esdm-extractlsb`], [@sec:tool-esdm-extractlsb], [See
      the section],
    [IF-CLI.12], [`esdm-ebpf-collect`], [@sec:tool-esdm-ebpf-collect], [See
      the section],
    [IF-CLI.13], [`esdm-cdev-check`], [@sec:tool-esdm-cdev-check], [See the
      section],
  ),
  caption: [Command lines of the programs of the #ac("ESDM")],
) <tab:if-cli>

== Signals <sec:if-sig>

The daemons act on two kinds of signals. The sections of chapter @sec:tools
state the signals of every program.

#paragraph[IF-SIG.1 Termination][`esdm-server` and `esdm-kernel-seeder` shut
down on `SIGHUP`, `SIGINT`, `SIGQUIT` and `SIGTERM`
(`frontends/server/server_main.c`, `frontends/kernel-seeder/seeder_main.c`).
The #ac("CUSE") daemons shut down on every signal of the set
`linux_term_signals` (`common/linux_support.c`) returns: `SIGHUP`, `SIGINT`,
`SIGQUIT`, `SIGTERM`, `SIGALRM`, `SIGIO`, `SIGPOLL`, `SIGPROF`, `SIGPWR`,
`SIGUSR1`, `SIGUSR2`, `SIGVTALRM`, `SIGXCPU`, `SIGXFSZ`, `SIGSTKFLT` where
it exists, and the real-time signals. Their handler only ends the
#ac("FUSE") loop; the daemon then removes its bind mount. The signals that
report a fault keep their default action. The provider programs of
IF-LIB-ESEXT stop on `SIGTERM`, `SIGINT` and `SIGHUP`. A daemon started with
`--pid_namespace` runs under a supervisor process that forwards every signal
of the set `linux_term_signals` returns to it, also those the daemon has no
handler for. The supervisor also forwards `SIGABRT`, `SIGBUS`, `SIGFPE`, `SIGILL`,
`SIGPIPE`, `SIGSEGV`, `SIGSYS`, `SIGTRAP` and, where it exists, `SIGEMT`
when another process sends them, so that none of them ends the supervisor
and leaves the daemon without it; raised by a fault of the supervisor itself,
such a signal keeps its default action. The daemon, as the init process of
its namespace, drops a forwarded signal it has no handler for. `SIGKILL` and
`SIGSTOP` cannot be forwarded. A supervisor that ends before its daemon, by
`SIGKILL` or by a fault of its own, ends the daemon as `SIGTERM` does: the
daemon sends itself that signal once the pipe it shares with the supervisor
reports the hang-up, or receives it from the kernel as its parent-death
signal (`PR_SET_PDEATHSIG`). `esdm-server` sets the parent-death signal
again after its privilege drop, which clears it; a #ac("CUSE") daemon has a
thread wait at the pipe, as its changes of the effective user #ac("ID")
keep clearing it. Nothing mirrors the exit status of such a daemon, and the
objects the supervisor of `esdm-server` removes stay in place (IF-SHM).]

#paragraph[IF-SIG.2 Suspend trigger][`SIGUSR1` to `esdm-server` counts up
`suspend_gen` in the status segment and posts the three semaphores
(IF-SHM), which wakes the #ac("CUSE") daemons and the clients of IF-LIB-AUX.
It changes nothing else in the #ac("ESDM").
`esdm-server-signal-helper --suspend` sends it to the process that holds the lock of the #ac("PID")
file (IF-CLI.7). The server ignores the signal from its start until `libesdm`
has installed the handler. Sending it requires the right to signal the
server process.]

== Environment Variables and Files Read at Start <sec:if-env>

Table @tab:if-env lists the environment variables the programs and libraries
of the #ac("ESDM") read, and the files they read at their start without
being told to on the command line.

#figure(
{
  set text(size: 9pt, hyphenate: true)
  set par(justify: false, first-line-indent: 0pt)
  table(columns: (auto, 1.5fr, 1.1fr, 2.2fr), align: left + horizon,
    table.header([Identifier], [Variable or file], [Read by], [Effect]),
    [IF-ENV.1], [`ESDM_SERVER_FORCE_FIPS`], [`libesdm` (`esdm/fips.c`)],
      [If set, to any value, a build with the meson option `fips140`
      operates in #ac("FIPS") mode without reading IF-ENV.6. Read with
      `secure_getenv()`, which ignores it in a process with raised
      privileges],
    [IF-ENV.2], [`ESDM_EGD_SOCKET`], [`libesdm_egd_client`], [Path of the
      #ac("EGD") socket when the caller passes none; read with
      `secure_getenv()`],
    [IF-ENV.3], [`ESDM_STARTUP_MARKER`], [`libesdm`
      (`esdm/esdm_es_mgr.c`)], [If set, the process prints the line
      `ESDM_RNG_OPERATIONAL` to standard output when the #ac("ESDM")
      becomes operational; for test harnesses],
    [IF-ENV.4], [`NO_COLOR`], [Logger (`common/esdm_logger.c`)], [If set
      and not empty, the log is not colored],
    [IF-ENV.5], [`LISTEN_PID`, `LISTEN_FDS`, `LISTEN_FDNAMES`,
      `NOTIFY_SOCKET`], [`esdm-server`,
      `esdm-kernel-seeder`, the provider programs
      (`common/systemd_support.c`)], [The socket activation and readiness
      protocols of systemd. The server takes over the sockets named
      `ESDM_RPC_UNPRIV_SOCKET`, `ESDM_RPC_PRIV_SOCKET`, `ESDM_EGD_SOCKET`
      and `ESDM_EGD_PR_SOCKET`],
    [IF-ENV.6], [`/proc/sys/crypto/fips_enabled`], [`libesdm`
      (`esdm/fips.c`)], [A build with `fips140` operates in #ac("FIPS") mode
      if the file starts with the character 1. A missing file means no
      #ac("FIPS") mode],
    [IF-ENV.7], [`.NAME.hmac` next to the executable `NAME` and next to the
      shared object of `libesdm`], [`libesdm` at load time
      (`esdm/fips.c`, `common/fips_integrity.c`)], [In #ac("FIPS") mode,
      the #ac("HMAC")-#acs("SHA")-256 reference values of the integrity
      test. A missing file or a mismatch ends the process before `main()`],
    [IF-ENV.8], [`CREDENTIALS_DIRECTORY`], [`esdm-es-pkcs11`], [The
      directory of the systemd credential that holds the #ac("PIN")
      (section @sec:tool-esdm-es-pkcs11)],
  )
}
, caption: [Environment variables and files read at start]) <tab:if-env>

Section @sec:fips140-config describes the #ac("FIPS") mode and
`esdm-tool` (section @sec:tool-esdm-tool) the command that writes the
reference values of IF-ENV.7. The #ac("ESDM") reads no configuration file:
everything else is set at build time with the meson options (chapter
@sec:build-options) or on the command lines (IF-CLI).
