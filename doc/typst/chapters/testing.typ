#import "../template.typ": *

= Testing the ESDM <sec:testing>

This chapter addresses auditors and developers. It describes how the
#ac("ESDM") is tested, from the functional test suite to fuzzing, the security
tests, sanitizers and static analysis, virtual machines and coverage, and what
is not tested automatically. The entropy assessments of chapters @sec:kernel-es-assessment and
@sec:ebpf-assessment, the self tests the #ac("ESDM") runs itself (section
@sec:self-tests) and the model checking of chapter @sec:formal-verification
complement it. Figure @fig:testing shows where each kind
of test runs.

#figure(
  image("../figures/testing.svg", width: 100%),
  caption: [Where the tests run],
) <fig:testing>

== The Test Suite <sec:test-suite>

`meson test` runs about 160 tests in 21 suites, one per directory below
`tests/` (`core` for `tests/esdm`): unit tests and known-answer tests of
the cryptographic primitives, every entropy source, the #ac("ESDM") core with
its seeding, reseeding, status and compliance modes, every #ac("RPC") call, the
#ac("CUSE"), `getrandom` and `/proc` frontends, the #ac("EGD") server and
client, the kernel seeder, the OpenSSL providers, `esdm_cdev`, the external
entropy source providers, `esdm-tool` and `esdm-server`:

```sh
meson setup build -Dtestmode=enabled
meson test -C build                      # every suite
meson test -C build --suite core         # one suite
sudo meson test -C build --suite cuse    # the tests that need root
```

A test that lacks root rights, a device or test mode is skipped (exit code 77)
instead of failing. The tests of the servers start an `esdm-server` of their
own per test and wait for its socket; as root they isolate themselves in
mount and #ac("IPC") namespaces with a private `/dev/shm` and `/tmp`
(`tests/test_namespace.h`), the in-process tests in an #ac("IPC") namespace of
their own (`tests/test_ipc_ns.c`), so that tests running in parallel do not
share the shared memory segment or the semaphores of the #ac("ESDM").

#paragraph[Test mode][The build option `testmode` compiles the hooks the
suite needs into the #ac("ESDM"): recording the seed entropy, failing the next
reads of the Jitter #acs("RNG") or the #ac("CPU") source, disabling the fallback
of the #ac("CUSE") daemons, setters for the reseed thresholds, self test failure
injection, a self test interval of 1 second instead of 600, and an #ac("RPC")
server in the process of the test. It moves the sockets, the shared memory
and the #ac("CUSE") devices to names of their own, so that a test build does not
interfere with an installed #ac("ESDM").]

#warning-note[Never enable `testmode` in production: its hooks inject
faults and its sockets are located in `/tmp`, a directory every user can write
to.]

== Running and Writing Tests <sec:writing-tests>

```sh
meson test -C build --list               # the tests and their suites
meson test -C build 'ESDM status text' -v   # one test, its output shown
meson test -C build --suite core --repeat 20   # flaky ones show up
meson test -C build --gdb 'ESDM status text'   # under the debugger
```

`build/meson-logs/testlog.txt` keeps the output of every test of the last
run. A new test is a program in the directory of its component below
`tests/`, registered in that directory's `meson.build` with `test()` and the
suite of the directory; it returns 0 on success, 77 when it cannot run – no
root, no device, no test mode – and any other value on failure. The headers at
the top of `tests/` support the tests:

/ `test_run.h`: Runs an installed program with arguments and collects its
  output, for tests of the command lines.
/ `test_wait.h`: Waits until a daemon the test started has created its socket
  or device, of the right type, instead of sleeping for a fixed time.
/ `test_namespace.h`, `test_ipc_ns.c`: Give a test that runs as root mount
  and #ac("IPC") namespaces of its own, and an unprivileged in-process test an
  #ac("IPC") namespace, so that tests running in parallel share no socket,
  shared memory segment or semaphore.
/ `status_json_check.h`, `es_state_check.h`: Check the #ac("JSON") status
  of the #ac("ESDM") and the state an entropy source reports.
/ `test_plan.h`: Prints the plan of a test – its steps and the conditions it
  checks, with their values – for the report of the security tests (section
  @sec:security-tests).

== Fuzzing <sec:fuzzing>

The build option `fuzzing` builds libFuzzer harnesses for the input the
#ac("ESDM") takes from others: the #ac("RPC") requests and responses and their
codec, the #ac("RPC") client, the #ac("EGD") server and client, the library
#ac("API") and, with `openssl-rand-provider`, the five OpenSSL providers. Every
harness has a replay driver that needs no fuzzing engine; `meson test` replays
seed inputs generated in code with it (suite `fuzz`):

```sh
CC=clang meson setup build-fuzz -Dfuzzing=enabled \
    -Dopenssl-rand-provider=enabled \
    -Db_sanitize=address,undefined -Db_lundef=false
ninja -C build-fuzz
mkdir corpus
build-fuzz/tests/fuzz/rpc_response_fuzz_replay --dump-corpus corpus
build-fuzz/tests/fuzz/rpc_response_fuzz corpus
```

A finding can be replayed with any compiler:
`rpc_response_fuzz_replay crash-<hash>`.
`tests/fuzz/README.md` gives the details and the throughput of each harness.

== Security Tests <sec:security-tests>

The suite `security` checks one security property per test, in test mode,
unprivileged: the output reaches more than 6 bits of min-entropy per byte
(#ac("SP") 800-90B non-#ac("IID") estimate of 1 MiB, skipped without
`ea_non_iid`); a failed self test stops all output and the periodic self test
worker; with the Jitter #acs("RNG") as the only credited source, output stops
once it fails,
also for OpenSSL through the provider – random bits and #ac("ECDSA") keys; the
#ac("DRNG") reseeds on its interval and on a lowered request threshold. Each
test prints its property, plan and steps, which
`nix build .#esdm-security-report` typesets into a report: per test its
headline, description, plan, output and code.

== Sanitizers and Static Analysis <sec:sanitizers>

#ac("CI", cap: true) builds the #ac("ESDM") with the address and undefined
behavior sanitizers, runs the suite and a stress run of `esdm-tool` against a
server as root, and searches the server log for findings. The package
`esdm-tsan` runs the suite with the thread sanitizer. The build option
`memory-debug` turns on the consistency checks of the glibc allocator. CodeQL
analyzes every push to the master branch, every pull request against it and,
weekly, the master branch. The compiler
warnings are those of meson's warning level 3 and further ones; the kernel
modules build
with `W=1` and every warning as an error, against each supported kernel.

== Virtual Machine Tests <sec:vm-tests>

The Nix flake boots NixOS virtual machines for the tests that need a kernel:

#figure(
  table(columns: (auto, 1fr), align: left + horizon,
    table.header([Check], [Boots and asserts]),
    [`live_*`], [The patched kernel with `esdm_es` and a #ac("TPM"), the latest
    kernel in addition with `fips=1`: the
      #ac("ESDM") fully seeded, the interrupt and scheduler sources credited,
      the #ac("CUSE") `/dev/random`, 25 start-up loops],
    [`ebpf_*`], [A stock kernel: the #ac("eBPF") programs load, the scheduler
      source reaches its level and stays bounded, wiped buffers on stop],
    [`cdev_*`], [`esdm_cdev`: about 20 subtests of the devices, the
    #ac("IOCTL", pl: true),
      restarts, an unreachable #ac("ESDM") and a fake #ac("EGD") server, no
      oops],
    [`events_*`], [A stock kernel with `esdm_es` built without an entropy
      source: the server logs a suspend and the resume the module reports and
      reseeds its #ac("DRNG", pl: true) after the resume],
    [`ebpf_raw`], [One million raw deltas through the #ac("SP") 800-90B tool],
    [`egd_gnupg`], [libgcrypt with #ac("EGD") as its only source: random
    numbers,
      key generation, encryption, a restart of the #ac("ESDM")],
    [`egd_openssh`], [`sshd` through the #ac("EGD") provider under its seccomp
      filter: four key exchanges, no SIGSYS],
  ),
  caption: [The virtual machine tests of the Nix flake],
) <tab:vm-tests>

== Continuous Integration <sec:ci>

On every push to the master branch and on every pull request, #ac("CI")
builds and tests on Ubuntu 22.04, 24.04 and 26.04, on x86_64 and arm64, with
every crypto backend (builtin, OpenSSL, Botan, leancrypto, GnuTLS), with the
external entropy source providers, with the Jitter #acs("RNG") 3.6.3, 3.7.0
and its master branch, with the sanitizers and with the #acs("eBPF")-based
scheduler entropy source including a raw collection. It builds the kernel
modules against every supported kernel on x86_64 and arm64 and boots the
`live`, `ebpf` and `cdev` machines of each on x86_64. It builds this
documentation when the documentation or the flake changes.

== Coverage <sec:coverage>

The packages `esdm-coverage` and `esdm-coverage-ebpf` build the #ac("ESDM") with
gcov and the sanitizers, run the suite and report the line coverage with
gcovr, as #ac("HTML") and text; `esdm-coverage-vm` runs the suite as root in a
virtual machine with the patched kernel, `fips=1`, #ac("CUSE") and a software
#ac("TPM"), so that the tests needing root are counted as well.

== What Is Not Tested Automatically <sec:test-gaps>

#ac("CI", cap: true) covers one family of builds: test mode with `fips140`,
which includes the build adjustments of `sp80090c`, without the `ais2031_*`
modes, compiled with gcc, on every crypto backend; one build disables
`fips140`, and two build the server with one of its interfaces only
(`esdm-server-rpc`, `esdm-server-egd`). Table @tab:ci-coverage
contrasts what the workflows of `.github/workflows/` run with what they do not
run.

#figure(
  table(columns: (1fr, 1fr), align: left + top,
    table.header([Run by #ac("CI") on pushes to master and on pull requests],
      [Not run by #ac("CI")]),
    [The suite as an unprivileged user, per runner and crypto backend
      (`test_ci.yml`); as root only the tests of the #ac("EGD") server
      interface and of the server with an external entropy source],
    [The tests that need root otherwise: the #ac("CUSE") devices, the
      #ac("RPC") calls against an installed server (`sudo meson test`)],
    [The address and undefined behavior sanitizers with the suite and a
      stress run against a server],
    [The thread sanitizer (`esdm-tsan`), the coverage packages],
    [The #acs("eBPF")-based scheduler entropy source with a raw collection],
    [The `events_*`, `ebpf_raw`, `egd_gnupg` and `egd_openssh` machines; the
      #acs("eBPF")-based interrupt entropy source outside the `ebpf_*`
      machines],
    [The kernel modules against every supported kernel with their `live`,
      `ebpf` and `cdev` machines, and the model checking of the flake check
      `tla` (`nix.yml`)],
    [The slow configurations of the model checking (chapter
      @sec:formal-verification)],
    [CodeQL; this documentation with its identifier and option checks
      (`doc.yml`)],
    [The fuzzers and, as no build enables `fuzzing`, the replay of their
      seed inputs; the security report],
    [],
    [Builds with `ais2031_ntg1`, `ais2031_drg3` or `ais2031_drg4`, and with
      `sp80090c` without `fips140`; builds with clang],
  ),
  caption: [What #ac("CI") runs and what it does not],
) <tab:ci-coverage>

A claim of chapter @sec:configurations for an #ac("AIS") 20/31 class
therefore rests on a build that #ac("CI") did not produce. Before a release, the following is run by hand;
nothing enforces it:

```sh
nix flake check                          # VM tests and models
TLA_ALL=1 nix shell nixpkgs#tlaplus18 -c tests/tla/check.sh   # slow models
nix build .#esdm-ais2031 .#esdm-drg3 .#esdm-tsan .#esdm-coverage
meson setup build-90c -Dtestmode=enabled -Dsp80090c=true && meson test -C build-90c
sudo meson test -C build                 # the tests that need root
```

The models are kept consistent with the code by hand (section
@sec:fv-limitations): a change of modeled code requires its model to be changed
and checked again, which no check enforces either.
