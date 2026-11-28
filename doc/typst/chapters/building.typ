#import "../template.typ": *

= Building and Installing <sec:building-installing>

This chapter is for administrators and packagers: what the build of the
#ac("ESDM") needs, how to configure, build and install it, what it installs
where, how to build the kernel modules, and which packages exist. Chapter
@sec:build-options lists every build option, chapter @sec:configurations the
option sets of the compliant configurations, and chapter @sec:usage describes
how to run the result.

== Requirements <sec:build-requirements>

The build needs a C compiler for C17 with GNU extensions (gcc or clang),
meson, ninja and pkg-config, and the libraries protobuf-c and json-c. Further
dependencies come with the features that need them (table
@tab:build-dependencies); a feature whose dependency is missing fails the
configuration rather than being left out silently.

#figure(
  table(columns: (1.15fr, 1fr, 1.35fr), align: left + horizon,
    table.header([Dependency], [Needed for], [Build option]),
    [The Jitter #acs("RNG") library `libjitterentropy` @jent; its NTG.1
      mode needs 3.7.0 or later built with secure memory],
      [The Jitter #acs("RNG") entropy source], [`es_jent`, `es_jent_ntg1`],
    [libkcapi @libkcapi], [The kernel Jitter #acs("RNG") entropy source],
      [`es_jent_kernel`],
    [libbpf 1.2 or later, clang and bpftool; at run time a kernel with
      #ac("BTF")],
      [The #ac("eBPF") entropy sources], [`es_sched_ebpf`, `es_irq_ebpf`],
    [FUSE 3], [The #ac("CUSE") daemons], [`linux-devfiles`],
    [libselinux], [The labels of the #ac("CUSE") devices], [`selinux`],
    [OpenSSL 3.0 or later],
      [The OpenSSL backend, the OpenSSL providers],
      [`crypto_backend=openssl`, `openssl-rand-provider`],
    [Botan 3.2 or later and a C++ compiler], [The Botan backend],
      [`crypto_backend=botan`],
    [leancrypto @leancrypto 1.6.0 or later], [The leancrypto backend],
      [`crypto_backend=leancrypto`],
    [GnuTLS 3.6.7 or later with its #ac("SP") 800-90A CTR #ac("DRBG") symbols,
      nettle 3.6 or later],
      [The GnuTLS backend], [`crypto_backend=gnutls`],
    [libp11], [The #acs("PKCS")\#11 entropy source provider], [`es_pkcs11`],
    [pcsc-lite], [The #ac("PC/SC") entropy source provider], [`es_pcsc`],
  ),
  caption: [The dependencies of the optional features],
) <tab:build-dependencies>

The interrupt and scheduler entropy sources need the kernel module `esdm_es`
in a patched kernel (section @sec:build-kernel-modules), the #ac("TPM") and
hardware #ac("RNG") sources only the kernel's devices `/dev/tpmrm0` and
`/dev/hwrng`.

== Configuring, Building and Installing <sec:build-steps>

```sh
meson setup build --prefix=/usr       # configure, -D<option>=<value>
meson configure build                 # the options and their values
meson configure build -Des_jent_ntg1=enabled   # change one
meson compile -C build
meson install -C build --destdir /tmp/staging
```

The build sets meson's `warning_level=3`, `optimization=2` and
`c_std=gnu17`, and the hardening of section @sec:compiler-flags. A feature
option takes `enabled` or `disabled`, a boolean option `true` or `false`. The
defaults build the server with the builtin crypto backend and every entropy
source except the #ac("eBPF") ones, the kernel Jitter #acs("RNG") and the
#acs("PKCS")\#11 and #ac("PC/SC") providers; they also build the #ac("CUSE")
daemons, the `getrandom` shim, the auxiliary and external entropy source
libraries and `esdm-tool`. The server is built with both of its interfaces,
the #ac("RPC") and the #ac("EGD") interface; `esdm-server-rpc` and
`esdm-server-egd` leave one of them out of the build, with its client
library and what needs it (section @sec:if-deployment). Section @sec:examples gives
complete command lines for the compliant configurations; `meson dist` runs the
release checks of `addon/sanity_checks.sh` on the source archive.

#warning-note[`testmode`, `memory-debug` and `fuzzing` are for development
only (section @sec:options-testing); a production build leaves them
disabled.]

== What Is Installed <sec:installed-files>

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Location], [Content]),
    [`bin/`], [The programs of chapter @sec:tools: `esdm-server`,
      `esdm-tool`, the #ac("CUSE") daemons, `esdm-kernel-seeder`,
      `esdm-server-signal-helper`, the entropy source providers and the
      measurement tools, each with its build option],
    [`lib/`], [`libesdm`, the client libraries `libesdm_rpc_client`,
      `libesdm_egd_client`, `libesdm_aux_client` and `libesdm_es_ext`, the
      shim `libesdm-getrandom.so` and the OpenSSL providers, each client library
      and provider with a pkg-config file of its name],
    [`include/esdm/`], [The headers of the libraries],
    [`lib/systemd/system/`], [The units of the programs built: the server with
      its #ac("RPC") and #ac("EGD") sockets, the #ac("CUSE") daemons, the
      kernel seeder, the suspend and resume helper, the boot gate
      `esdm-wait-until-fully-seeded.service` and the #acs("PKCS")\#11 provider,
      whose user is created by `lib/sysusers.d/esdm-es-pkcs11.conf`],
    [`share/man/`], [The man pages of the programs, the libraries and the
      OpenSSL providers],
  ),
  caption: [What `meson install` installs, below the prefix],
) <tab:installed-files>

The units are installed with their programs and enabled by the
administrator (section @sec:usage-systemd). The SELinux policy of `esdm-proc`
in `addon/esdm-proc-selinux/` is built and loaded by hand.

== Kernel Modules <sec:build-kernel-modules>

The two kernel modules are built outside the meson build, with `make` in their
directory of the source tree, from which they take the code they share with
the #ac("ESDM")\; `KERNEL_DIR` points to the build directory of the target
kernel, by default the running one:

```sh
make -C kernel/esdm_cdev KERNEL_DIR=/lib/modules/$(uname -r)/build
make -C kernel/esdm_es        # in a patched kernel, see below
```

/ `esdm_cdev`: The character devices `/dev/esdm_random`, `/dev/esdm_urandom`
  and `/dev/esdm_pr`, served over the #ac("EGD") socket of the #ac("ESDM").
  It needs no kernel patch and builds on Linux 6.1 and later
  (`kernel/esdm_cdev/README.md`).

/ `esdm_es`: The interrupt and scheduler entropy sources. The kernel needs
  the patches of `kernel/esdm_es/` – the scheduler and interrupt hooks, and, up
  to Linux 7.1 without the SHA-3 library, the export of the #ac("DRBG")
  functions – in the version not newer than the kernel;
  `kernel/esdm_es/kernelPatches.nix` holds the mapping. `ESDM_ES_OSR` of its
  `Makefile` sets the oversampling rate. The module is best loaded early, in
  the initramfs, and before `esdm-server` starts (`kernel/esdm_es/README.md`,
  chapter @sec:kernel-es-assessment).

== Packages <sec:packages>

/ Nix: The flake of the repository builds the #ac("ESDM") (`esdm`) and
  variants of it (`esdm-ebpf`, `esdm-leancrypto`, `esdm-ais2031`,
  `esdm-drg3`), the kernel modules for every kernel it knows (`esdm_es_<version>`,
  `esdm_cdev_<version>`) and this document (`esdm-doc`). NixOS has a module:
  `services.esdm.enable = true`, with `enableLinuxCompatServices` for the
  kernel seeder, the #ac("CUSE") devices and `esdm-proc`.

/ RPM: `esdm.spec` builds the packages `esdm`, `esdm-cuse`, `esdm-openssl`,
  `esdm-devel` and `esdm-devel-static`; the openSUSE Build Service builds them
  in the project `home:smuellerDD`.

/ Arch Linux: The package `esdm-git` of the Arch User Repository builds the
  master branch.

#par(first-line-indent: 0pt)[`esdm-tool --status` on the installed system
shows the version, the crypto backend, the entropy sources and the compliance
classes the build reached (section @sec:usage-check).]
