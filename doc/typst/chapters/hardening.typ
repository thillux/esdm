#import "../template.typ": *

= Secure Implementation and Hardening <sec:hardening>

This chapter is for auditors and integrators: how the #ac("ESDM") protects
itself and the secrets it holds – from the compiler flags of its build to the
systemd sandbox, the isolation and privilege drop of the server, the
handling of secrets in memory, the bounds on its input and the conditions
on its output. Section @sec:attacker-model gives the attacker model these
measures address; figure @fig:hardening-layers shows the layers.

#figure(
  image("../figures/hardening-layers.svg", width: 100%),
  caption: [The layers around the core of the #ac("ESDM") and the boundaries its
    clients and sources cross],
) <fig:hardening-layers>

== Compiler and Linker Defaults <sec:compiler-flags>

The build hardens every binary without requiring any option to be set
(`meson.build`):

```meson
# Hardening Compiler flags
add_global_arguments([ '-fstack-protector-strong',
		       '-fwrapv',
		       '--param', 'ssp-buffer-size=4',
		       '-fvisibility=hidden',
		       '-Wconversion', '-Wcast-align', '-Wshadow',
		       '-Wmissing-prototypes', '-Wswitch-enum', '-Wformat=2',
		       ... ], language : 'c')
```

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Flag], [Effect]),
    [`-fstack-protector-strong`], [Stack canaries in every function with
      arrays or address-taken locals],
    [`-D_FORTIFY_SOURCE=3`], [Checked string and memory functions, with
      sizes known at run time; with optimization only],
    [`-fstack-clash-protection`], [Stack probes against jumping the guard
      page; where the compiler supports it],
    [`-fcf-protection=full`], [Indirect branch tracking and shadow stack
      markers (Intel #ac("CET")); where supported],
    [`-fzero-call-used-regs=used-gpr`], [Registers cleared on return, which
      leaks less and leaves fewer gadgets; where supported],
    [`-fwrapv`], [Signed overflow wraps instead of being undefined],
    [`-fvisibility=hidden`, version scripts], [Only the #ac("API") is exported:
      `libesdm` and `libesdm_es_ext` list their symbols],
    [#ac("PIE", cap: true), `-z relro -z now`], [Address space layout
    randomization of the
      executables, read-only relocations resolved at start],
    [`-z noexecstack`], [No executable stack],
    [`--gc-sections`, #ac("LTO")], [Unused code removed],
  ),
  caption: [The hardening flags of the build],
) <tab:compiler-flags>

The warnings are those of meson's level 3 (`-Wall -Wextra -Wpedantic`) and
more; the kernel modules build with `W=1` and every warning as an error
against each supported kernel. Chapter @sec:testing describes the
sanitizers, the fuzzers and the static analysis that check the code in
addition.

== Secrets in Memory <sec:secrets>

Seed buffers, #ac("DRNG") states, keys and the buffers of every #ac("RPC")
request are wiped as soon as they are no longer needed, with a `memset` the
compiler cannot remove as a dead store (`common/memset_secure.h`):

```c
static inline void memset_secure(void *s, int c, size_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r"(s) : "memory");
}
```

`esdm-server --memlock`, which the systemd unit passes, locks all memory of
the server against being swapped out and makes the process not dumpable,
so that neither swap nor a core dump holds a secret. The privilege drop
later resets the dumpable flag to `fs.suid_dumpable`, which
systemd-coredump sets to 2; a core size limit of 0, which `--memlock` and
the unit set as well, survives the drop, and core files and
systemd-coredump honor it. The
state of the builtin ChaCha20 #ac("DRNG") is locked as well, and the
#acs("PKCS")\#11 provider wipes its #ac("PIN") after the login and keeps itself
out of core dumps and `ptrace(2)`. The kernel modules free their buffers with
`kvfree_sensitive` and clear them with `memzero_explicit`.

== Privileges and Isolation <sec:isolation>

`esdm-server` uses its root privileges only to set itself up, in the order
of figure @fig:server-startup, and drops them permanently before it serves
any client.

#figure(
  image("../figures/server-startup.svg", width: 50%),
  caption: [The start-up of `esdm-server`],
) <fig:server-startup>

After the drop, the server cannot regain root: it changes its real,
effective and saved user and group #ac("ID", pl: true) and drops its
supplementary groups. The drop isolates the server from the other users of
the system, not from the processes of the user it drops to: with the default
`nobody`, which other software shares, the isolation is weaker than the
attacker model assumes (section @sec:attacker-model), and the daemons are to
run as a user that nothing else uses (section @sec:usage-hardening). Every
privileged #ac("RPC") call – crediting entropy,
clearing the pool, forcing a reseed, changing thresholds, running the self tests
– checks, in addition to the socket mode of 0600, that the peer is root
(`SO_PEERCRED`);
the #ac("EGD") interface credits written data and accepts its administrative
commands for root only as well. The #ac("CUSE") daemons give up their privileges
transiently and take them back only for the device operations that need them,
and accept the privileged #ac("IOCTL", pl: true) only from callers with
`CAP_SYS_ADMIN`.

With `--pid_namespace`, the server and the #ac("CUSE") daemons run as the
init process of a #ac("PID") namespace of their own, in which they see no
other process, and the process that was started stays outside as the
supervisor that forwards the signals (IF-SIG.1, section @sec:if-sig). No
daemon serves on behind a supervisor that ended: it is told of the end by the
kernel, whatever ended the supervisor, and shuts down (section
@sec:fv-supervisor).

== The systemd Sandbox <sec:systemd-sandbox>

The units confine the daemons further than the code can. `esdm-server`
runs with a capability bounding set of `CAP_SYS_ADMIN`, `CAP_SETUID`,
`CAP_SETGID`, `CAP_KILL` and `CAP_SYS_RESOURCE`, a read-only file system
except `/run` (`ProtectSystem=strict`), no network (`PrivateNetwork`,
`IPAddressDeny=any`, `RestrictAddressFamilies=AF_UNIX`, with `AF_ALG` added in a build with
`es_jent_kernel`), protected kernel
tunables, modules, logs and clock, a strict device policy, a system call
filter, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `LockPersonality` and
`RestrictSUIDSGID`. The comments in the units explain the gaps: `@privileged`
stays allowed, as it holds the system calls of the privilege drop, and
`ProcSubset=pid` is not set, as it would hide
`/proc/sys/crypto/fips_enabled`. The #ac("CUSE") daemons and `esdm-proc` mount
over `/dev` and `/proc`, which must reach the host, so they forgo the
mount namespacing options; the kernel seeder (which keeps `CAP_SYS_ADMIN`
for the #ac("IOCTL", pl: true) of the kernel), the suspend helper (which keeps
`CAP_KILL` to signal the server), the resume helper and the unit waiting for
the seeding keep these options, the last two without any capability and the
last one as a dynamic user.

== Bounded Input <sec:bounded-input>

An #ac("RPC") message has at most 64 KiB; the header length and the method index
are checked before anything is unpacked, and unpacking allocates from an
overflow-checked area of fixed size. A worker serves at most 1024
connections and closes idle ones after 2 seconds. The #ac("EGD") server accepts
at most 2048 connections, transfers at most 255 bytes per command of the
original protocol and 64 KiB per bulk or status command, gives up on
a client stalling a write for 30 seconds, and never blocks its single
worker on a client. An external entropy source provider must run as root or
as `es_ext_peer_uid`, is self tested on every connection and timed out
after 2 seconds. Signal handlers only set flags, and every error path of
the C code goes through the same checking macros (`common/ret_checkers.h`).

== Output Only After Self Tests and Seeding <sec:output-gate>

The #ac("ESDM") hands out no random number before its known-answer tests of the
hash, the #ac("XDRBG") and the #ac("DRNG") have passed and its initial
#ac("DRNG") is
fully seeded; a failed self test stops all output permanently. The tests run at
start-up, every 600 seconds and on request; a passing test never clears a
failure. With the build option `fips140`, a constructor also checks the
integrity of the server and the library against their #ac("HMAC") reference
values before anything else runs. Chapter @sec:integrations shows how the
integrations keep this guarantee toward their callers.

== Build Options That Weaken Hardening <sec:weakening-options>

#warning-note[`testmode` compiles in fault injection and test hooks and
moves the sockets to `/tmp`, `memory-debug` changes the allocator,
`fuzzing` exposes entry points for the fuzzers: none of them belongs in a
production build.]

The SELinux policy of `esdm-proc` in `addon/` declares its domain
permissive: it logs, but does not enforce. The #ac("CUSE") daemons fall back to
the kernel devices while the #ac("ESDM") server cannot be reached (table
@tab:interfaces).
