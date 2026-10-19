{
  description = "ESDM testing/development flake";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:

    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
    flake-utils.lib.eachSystem systems (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        lib = pkgs.lib;

        kernelDebug = false;
        kernelFips = true;
        debugEsdm = false;
        startEsdm = false;
        startCompat = false;

        baseModule =
          {
            kernel,
            lib,
            config,
            pkgs,
            ...
          }:
          {
            boot.kernelPackages = kernel;

            boot.kernelModules = [
              "jitterentropy_rng"
              "esdm_es"
            ];
            boot.kernelParams = [
              "fips=1"
            ];
            boot.extraModulePackages = [ config.boot.kernelPackages.esdm_es.out ];

            users.motd = ''
               _____ ____  ____  __  __   _____ _____ ____ _____  __     ____  __
              | ____/ ___||  _ \|  \/  | |_   _| ____/ ___|_   _| \ \   / /  \/  |
              |  _| \___ \| | | | |\/| |   | | |  _| \___ \ | |    \ \ / /| |\/| |
              | |___ ___) | |_| | |  | |   | | | |___ ___) || |     \ V / | |  | |
              |_____|____/|____/|_|  |_|   |_| |_____|____/ |_|      \_/  |_|  |_|
            ''
            + lib.optionalString (startEsdm) ''

              ESDM is already started via systemd. Disable again if necessary.
            ''
            + lib.optionalString (startCompat) ''

              ESDM compat services already started via systemd. Disable again if necessary.
            ''
            + ''

            '';

            users.users.root.initialPassword = "root";
            services.getty.autologinUser = lib.mkForce "root";

            services.esdm = {
              enable = startEsdm;
              enableLinuxCompatServices = startCompat;
              package = self.packages.${system}.esdm;
            };

            environment.systemPackages = with pkgs; [
              htop
              mc
              tmux
              vim
              self.packages.${system}.esdm
              gdb
              sp800-90b-entropyassessment
            ];

            console.keyMap = "de";
          };

        mkLiveSystem =
          { kernel, esdm }:
          nixpkgs.lib.nixosSystem {
            inherit system;
            modules = [
              { _module.args.kernel = kernel; }
              baseModule
              (
                {
                  lib,
                  config,
                  modulesPath,
                  ...
                }:
                {
                  # modulesPath rather than "${pkgs.path}/...": interpolating
                  # the path copies nixpkgs into the store once more, which
                  # nix flake check --no-build does not do and then fails on.
                  imports = [
                    (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
                  ];
                  isoImage = {
                    isoName = "esdm-live.iso";
                    volumeID = "CUSTOM_LIVE";
                  };
                }
              )
            ];
          };

        addEsdmToKernel = lpself: lpsuper: {
          kernel = lpsuper.kernel.override {
            # Keep nixpkgs' own patches (bridge-stp-helper, request-key-helper
            # and fixes such as 6.1's c23-compat-libbpf), override replaces the
            # list rather than appending to it.
            kernelPatches =
              lpsuper.kernel.kernelPatches
              ++ lpself.callPackage ./kernel/esdm_es/kernelPatches.nix { inherit (lpsuper) kernel; }
              ++ lib.optionals kernelFips (
                lpself.callPackage ./kernel/esdm_es/fipsConfig.nix { inherit (lpsuper) kernel; }
              )
              ++ lib.optionals kernelDebug (lpself.callPackage ./kernel/esdm_es/debug.nix { })
              ++ lpself.callPackage ./kernel/esdm_es/drbg.nix { inherit (lpsuper) kernel; };
          };
          esdm_es = lpself.callPackage ./kernel/esdm_es { };
          esdm_cdev = lpself.callPackage ./kernel/esdm_cdev { };
        };

        # 6.1 is the first kernel version supported by ESDM.
        minKernel = {
          major = 6;
          minor = 1;
        };

        # The stock (unpatched) kernel package sets of nixpkgs, enumerated like
        # jitterentropy-library does: the numbered linuxKernel.packages sets
        # plus linux_testing, the flavored variants (hardened, zen, ...) are of
        # no interest. tryEval guards the sets that do not evaluate on the
        # current system and the end-of-life aliases that throw. Restricted to
        # the versions ESDM supports (>= minKernel), linux_testing always
        # included. Keyed by the suffix used for the generated outputs, e.g.
        # linux_6_18 -> "6_18" -> live_6_18-<system> / esdm_es_6_18,
        # linux_testing -> "testing". The rolling "latest" alias is added on top.
        stockKernels =
          let
            usable =
              ps:
              let
                r = builtins.tryEval (lib.isAttrs ps && ps ? kernel && lib.isDerivation ps.kernel);
              in
              r.success && r.value;

            supported =
              name:
              let
                m = builtins.match "linux_([0-9]+)_([0-9]+)" name;
                major = lib.toInt (builtins.elemAt m 0);
                minor = lib.toInt (builtins.elemAt m 1);
              in
              name == "linux_testing"
              || (
                m != null && (major > minKernel.major || (major == minKernel.major && minor >= minKernel.minor))
              );

            sets = lib.filterAttrs (name: ps: supported name && usable ps) pkgs.linuxKernel.packages;
          in
          lib.mapAttrs' (name: ps: lib.nameValuePair (lib.removePrefix "linux_" name) ps) sets
          // {
            latest = pkgs.linuxPackages_latest;
          };

        # The same kernels with the esdm_es patches applied.
        kernels = lib.mapAttrs (name: lp: lp.extend addEsdmToKernel) stockKernels;

        # VM check of the eBPF entropy sources: the ESDM server (built with
        # es_sched_ebpf/es_irq_ebpf) must load the eBPF programs and report
        # both sources as available on every supported kernel. The check
        # deliberately runs on the stock (unpatched) kernel - not requiring
        # kernel patches is the point of the eBPF entropy sources.
        mkEbpfCheck =
          kernel:
          let
            esdm-ebpf = self.packages.${system}.esdm-ebpf;
          in
          pkgs.testers.nixosTest {
            name = "eBPF entropy source test";

            nodes.machine =
              { ... }:
              {
                boot.kernelPackages = kernel;

                # The test framework forces clocksource=acpi_pm, which has no
                # vDSO: every clock read traps to the hypervisor and the eBPF
                # sources' high-resolution-timer probe fails on the read latency
                # alone, disabling them before they load. The TSC is vDSO-backed
                # and is what these sources time against on bare metal, so it is
                # also the more faithful thing to measure. mkAfter puts this
                # last, where the final clocksource= wins.
                boot.kernelParams = lib.mkAfter [ "clocksource=tsc" ];

                environment.systemPackages = [ esdm-ebpf ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 4;
                };
              };

            # Note, esdm-tool prints the status through the ESDM logger
            # which writes to stderr.
            testScript = ''
              machine.wait_for_unit("multi-user.target")
              # Trace level (-v past LOGGER_TRACE, the increment saturates)
              # logs one line per fetch that brought events, which is what
              # the fetch rate is measured with below.
              machine.succeed(
                  "${esdm-ebpf}/bin/esdm-server -f --pid /run/esdm-server.pid "
                  "-vvvvvvvvvv >/tmp/esdm.log 2>&1 & echo started"
              )
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -q SchedulerEBPF", 60
              )

              # The libbpf the sources actually loaded against decides which
              # program constructs are available to them, so it is reported.
              machine.succeed("grep -q 'using libbpf v' /tmp/esdm.log")
              machine.succeed(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -q InterruptEBPF"
              )

              # The programs have to load and attach on the stock kernel ...
              for source in ["SchedulerEBPF", "InterruptEBPF"]:
                  machine.wait_until_succeeds(
                      f"${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A6 'Name: {source}' "
                      "| grep -q 'eBPF programs loaded: true'", 60
                  )

              # ... and the collected events have to reach the conditioning
              # pool. Three digits distinguishes a real drain from a stray event
              # trickling in. Only the scheduler source is credited - the
              # interrupt source is built with an entropy rate of 0.
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A2 'Name: SchedulerEBPF' "
                  "| grep -qE 'Available entropy: [1-9][0-9][0-9]'", 60
              )

              # Fetching entropy must not ramp the accounting past what the
              # conditioning pool can deliver, but must still reach a full
              # digest: one output block costs a digest plus the SP800-90C
              # oversampling surcharge, so capping at the digest alone would
              # clip the surcharge and leave it stuck below.
              machine.wait_until_succeeds(
                  "${esdm-ebpf}/bin/esdm-tool -s 2>&1 | grep -A2 'Name: SchedulerEBPF' "
                  "| grep -q 'Available entropy: 512'", 60
              )

              def avail():
                  return int(machine.succeed(
                      "${esdm-ebpf}/bin/esdm-tool -s 2>&1 "
                      "| grep -A2 'Name: SchedulerEBPF' "
                      "| sed -n 's/.*Available entropy: //p'"
                  ))

              peak = avail()
              for _ in range(20):
                  machine.succeed(
                      "${esdm-ebpf}/bin/esdm-tool --use-pr -r 32 >/dev/null 2>&1 || true"
                  )
                  peak = max(peak, avail())
              print(f"peak available entropy of the eBPF pool: {peak} bits")
              # The pool is an XDRBG-256 whose state of 512 bits is the most
              # entropy it holds (SP800-90B section 3.1.5.1 table 1).
              assert peak <= 512, (
                  f"available entropy reached {peak} bits, more than the "
                  "conditioning pool can hold - the ingest credits events whose "
                  "entropy the pool has no capacity for"
              )

              # Once the pool holds everything one extraction can deliver the
              # monitor stops asking, so the hand-over has to go quiet - the
              # point of fetching on demand rather than being streamed at. A
              # monitor draining unconditionally produces ~220 batches in this
              # window on this VM, an idle demand-driven one a handful.
              def fetches():
                  return int(machine.succeed(
                      "grep -c 'SchedulerEBPF ES: fetched' /tmp/esdm.log || true"
                  ))

              before = fetches()
              machine.sleep(30)
              fetched = fetches() - before
              print(f"fetches while idle: {fetched} in 30s")
              assert fetched < 40, (
                  f"{fetched} fetches in 30s while the pool was full - the "
                  "server is reading the ring buffer instead of leaving the "
                  "events in it until it needs them"
              )

              # Unloading the sources has to erase the raw samples. User space
              # clears the collection buffers; the ring buffer - the one it
              # cannot write itself - is overwritten by the wipe program. The
              # message below is logged only once the filler has covered the
              # whole ring, so it reports load, run and wrap-around.
              machine.succeed("kill -TERM $(cat /run/esdm-server.pid)")
              for source in ["SchedulerEBPF", "InterruptEBPF"]:
                  machine.wait_until_succeeds(
                      f"grep -q '{source} ES: ring buffer erased' /tmp/esdm.log", 30
                  )
              for complaint in [
                  "ring buffer erased over",
                  "cannot run the ring buffer wipe",
                  "cannot clear the per-CPU state map",
                  "does not support BPF syscall programs",
              ]:
                  machine.fail(f"grep -q '{complaint}' /tmp/esdm.log")
            '';
          };

        # End-to-end raw entropy measurement of the eBPF scheduler source:
        # esdm-ebpf-collect gathers unconditioned time stamps in the VM and the
        # analysis scripts drive the NIST SP800-90B non-IID estimator over them.
        # This tests the measurement tooling, NOT a validation grade assessment
        # - a claim must be measured on the deployment environment, which a qemu
        # VM is not (see tests/es_ebpf_testing/README.md), so nothing is
        # asserted about the magnitude. Single kernel on purpose: the estimator
        # dominates the run time and nothing here is kernel specific.
        mkEbpfRawCheck =
          kernel:
          let
            esdm-ebpf = self.packages.${system}.esdm-ebpf;

            # The estimator is named explicitly rather than put on $PATH: a run
            # that silently picked up some other ea_non_iid would be
            # indistinguishable from the CI stub used elsewhere.
            eaNonIid = "${pkgs.sp800-90b-entropyassessment}/bin/ea_non_iid";

            # The example scripts live next to the collector and are what this
            # check drives - the pipeline is only worth testing as the tooling
            # a user would actually run.
            tools = lib.cleanSource ./tests/es_ebpf_testing;

            # Deltas to collect from the one CPU this assesses - the CPUs are
            # separate noise sources, so a collection is never split across
            # them. The estimator warns below 1,000,000 samples, which is the
            # count a real assessment starts at.
            events = 1000000;

            # The collection takes the events of one CPU out of a machine of
            # this width, so a wider VM would starve it.
            cores = 2;


          in
          pkgs.testers.nixosTest {
            name = "eBPF raw entropy measurement with SP800-90B assessment";

            nodes.machine =
              { ... }:
              {
                boot.kernelPackages = kernel;

                environment.systemPackages = [ esdm-ebpf ];

                virtualisation = {
                  memorySize = 4096;
                  inherit cores;
                  # The raw records are 32 bytes each and the per-CPU delta
                  # files add another byte per delta on top.
                  diskSize = 4096;
                };
              };

            testScript = ''
              import re

              machine.wait_for_unit("multi-user.target")

              # The scheduler source only observes events that happen, and an
              # idle VM switches a few hundred times per second - stress-ng's
              # context switch stressor reaches the requested count in seconds
              # instead of hours. The store path rather than a bare name:
              # systemd-run resolves against its own PATH, not a login shell's.
              machine.succeed(
                  "systemd-run --unit=esdm-load --collect "
                  "${pkgs.stress-ng}/bin/stress-ng "
                  "--switch ${toString cores} --timeout 600s"
              )

              # Raw sampling is a code path none of the entropy source tests
              # take, and one the eBPF verifier has to accept. The example
              # script drives it: collect one CPU, push the deltas through
              # esdm-extractlsb and assess both bit widths.
              out = machine.succeed(
                  "EA_NON_IID=${eaNonIid} "
                  "${tools}/analyze_non_iid.sh --source sched --cpu 0 "
                  "--events ${toString events} /tmp/ea-out 2>&1",
                  timeout=3600,
              )
              print(out)

              # The script passes the estimator's output through. Reaching
              # this without an estimate means the collection was not
              # something ea_non_iid could assess.
              m = re.search(
                  r"min\(H_original,[^)]*\)\s*:\s*(\d+(?:\.\d+)?)", out
              )
              assert m, "analyze_non_iid.sh produced no min-entropy estimate"

              # The magnitude is a property of this VM, not of the code, so it
              # is reported rather than asserted on - only the range is.
              h = float(m.group(1))
              assert 0.0 <= h <= 8.0, f"min-entropy out of range: {h}"
              print(f"per-event min-entropy (8 LSB) on this VM: {h} bits")

              machine.succeed("systemctl stop esdm-load.service")

              # analyze_restart.sh is deliberately not run here. ea_restart
              # takes nothing but a 1,000,000 sample matrix, which is 1000
              # loads of the eBPF programs plus 1000 collections - far beyond
              # what a check should spend, and anything smaller it rejects
              # outright rather than assesses. It stays example tooling.
            '';
          };

        # The esdm package credits the interrupt and scheduler ES with nothing,
        # so it seeds fully whatever esdm_es delivers. These credit one of
        # them each (only one may be), for mkCheck to show the module's
        # entropy is credited.
        esdmCreditingKernelEs =
          source:
          self.packages.${system}.esdm.overrideAttrs (prev: {
            pname = "esdm-credit-${source}";
            mesonFlags =
              (builtins.filter (
                x: !(lib.hasInfix "es_irq_entropy_rate" x || lib.hasInfix "es_sched_entropy_rate" x)
              ) prev.mesonFlags)
              ++ [
                "-Des_irq_entropy_rate=${if source == "irq" then "256" else "0"}"
                "-Des_sched_entropy_rate=${if source == "sched" then "256" else "0"}"
              ];
          });

        mkCheck =
          kernel:
          let
            esdm-irq = esdmCreditingKernelEs "irq";
            esdm-sched = esdmCreditingKernelEs "sched";
          in
          pkgs.testers.nixosTest {
            name = "basic test with esdm-tool";

            nodes.machine =
              { ... }:
              {
                imports = [
                  (
                    { ... }:
                    {
                      _module.args.kernel = kernel;
                    }
                  )
                  baseModule
                  (
                    { lib, pkgs, ... }:
                    {
                      # baseModule leaves the daemon disabled (startEsdm =
                      # false) for the interactive live images; the check must
                      # actually run it, otherwise there is nothing to test.
                      services.esdm.enable = lib.mkForce true;
                      services.esdm.enableLinuxCompatServices = lib.mkForce true;

                      # Make the startup-hang regression harness (and a Python
                      # to run it) available inside the VM so the check can
                      # execute it instead of letting it rot.
                      environment.systemPackages = [
                        pkgs.python3
                        pkgs.jq
                      ];
                      environment.etc."esdm-startup-loop.py".source = ./tests/startup/esdm_startup_loop.py;

                      # kmemleak and page_owner only take effect on a kernel
                      # built with kernelDebug = true (DEBUG_KMEMLEAK,
                      # PAGE_OWNER - see kernel/esdm_es/debug.nix), and the
                      # check reads neither of their reports.
                      boot.kernelParams = [
                        "kmemleak=on"
                        "page_owner=on"
                        "log_buf_len=32M"
                      ];

                      virtualisation = {
                        efi.OVMF = pkgs.OVMFFull.fd;
                        useEFIBoot = true;
                        tpm = {
                          enable = true;
                        };
                        memorySize = 2048;
                        cores = 10;
                        qemu.options = [
                          "-smbios type=1,uuid=2715dd9b-5684-4eeb-ae88-a62bb4232563"
                        ];
                      };
                    }
                  )
                ];
              };

            testScript = ''
              machine.wait_for_unit("multi-user.target")

              # The kernel entropy-source module (irq/sched hooks) must load.
              machine.succeed("test -c /dev/esdm_es")

              # The daemon must come up and reach a fully-seeded DRNG. This is
              # the code path that the irq/sched deferred-logging deadlock fix
              # (commit c428c59) and the reinit locking work touch, so a
              # regression here should fail the check rather than pass silently.
              machine.wait_for_unit("esdm-server.service")
              machine.succeed("esdm-tool --wait-until-seeded 60")
              machine.succeed("esdm-tool --is-fully-seeded")
              machine.succeed("esdm-tool --status")

              # Draw random data over the RPC interface; 32 bytes are printed
              # hex-encoded, so expect at least 64 characters back.
              out = machine.succeed("esdm-tool --get-random 32").strip()
              assert len(out) >= 64, f"short random output: {out!r}"

              # Linux-compat frontends: /dev/random and /dev/urandom are served
              # by the CUSE daemons, /proc/sys/kernel/random by esdm-proc, once
              # the compat target is up. Their units are of Type=simple, so
              # the target is up as soon as the daemons are started - and the
              # kernel's own /dev/random (1:8) serves a read just as well - so
              # wait for the takeover itself: the device of the CUSE daemon
              # bind mounted over the kernel's, and the FUSE file system of
              # esdm-proc mounted over the kernel's directory.
              machine.wait_for_unit("esdm-linux-compat.target")
              for unit in ["esdm-cuse-random", "esdm-cuse-urandom", "esdm-proc"]:
                  machine.wait_for_unit(f"{unit}.service")
                  machine.succeed(f"systemctl is-active --quiet {unit}.service")
              for dev, kernel_dev in [("random", "1:8"), ("urandom", "1:9")]:
                  machine.wait_until_succeeds(f"findmnt -n -M /dev/{dev}", timeout=60)
                  devno = machine.succeed(f"stat -c %t:%T /dev/{dev}").strip()
                  assert devno != kernel_dev, (
                      f"/dev/{dev} is still the kernel's device ({devno})"
                  )
              machine.wait_until_succeeds(
                  "findmnt -n -M /proc/sys/kernel/random -o FSTYPE | grep -q '^fuse'",
                  timeout=60,
              )
              machine.succeed("test \"$(head -c 32 /dev/random | wc -c)\" = 32")
              machine.succeed("test \"$(head -c 32 /dev/urandom | wc -c)\" = 32")
              machine.succeed("grep -qx '[0-9][0-9]*' /proc/sys/kernel/random/entropy_avail")

              # A clean shutdown must not deadlock.
              machine.succeed("systemctl stop esdm-server.service")

              # The service credits the kernel ES with nothing, so it seeds
              # whether esdm_es delivers or not. A server crediting one of
              # them in turn has to see that source report credited entropy.
              # 128 bits net of the FIPS oversampling are some 800 events at
              # the module's OSR of 3, after the 1024 of its startup health
              # test - little even for an idle VM, so the timeout is only
              # generous. The socket units go too, so the server binds the
              # paths itself.
              machine.succeed(
                  "systemctl stop esdm-server-priv.socket esdm-server-unpriv.socket"
              )
              for source, esdm in [
                  ("Interrupt", "${esdm-irq}"),
                  ("Scheduler", "${esdm-sched}"),
              ]:
                  machine.succeed(
                      f"{esdm}/bin/esdm-server -f >/tmp/esdm-{source}.log 2>&1 "
                      f"& echo $! >/tmp/esdm-{source}.pid"
                  )
                  machine.wait_until_succeeds(
                      f"{esdm}/bin/esdm-tool --status-json | jq -e "
                      f"'.entropy_sources[] | select(.name == \"{source}\") "
                      "| .available_entropy >= 128'",
                      timeout=600,
                  )
                  machine.succeed(f"kill $(cat /tmp/esdm-{source}.pid)")
                  machine.wait_until_fails(
                      f"kill -0 $(cat /tmp/esdm-{source}.pid)", timeout=30
                  )

              # Now exercise the dedicated startup-hang regression harness
              # against the same binary. It repeatedly starts esdm-server in the
              # foreground, waits for the operational marker, fetches entropy
              # over RPC and checks for a clean SIGTERM shutdown - the exact
              # start/seed/teardown cycle the irq/sched deadlock fix touched.
              # The systemd instance is stopped above so the RPC sockets are
              # free for the harness to bind.
              server = machine.succeed("command -v esdm-server").strip()
              tool = machine.succeed("command -v esdm-tool").strip()
              machine.succeed(
                  f"python3 /etc/esdm-startup-loop.py --iterations 25 "
                  f"--binary {server} --tool {tool} --stop-on-failure"
              )
            '';
          };

        # The ESDM's EGD compatibility interface, exercised by a real consumer:
        # GnuPG through libgcrypt, rebuilt with --enable-random=egd so the EGD
        # is its ONLY entropy gathering module. libgcrypt then log_fatal()s as
        # soon as it cannot reach the socket, leaving no kernel RNG to paper
        # over a broken implementation - see the negative control at the end.
        # Defined once rather than per kernel: nothing here is kernel specific.
        mkEgdCheck =
          let
            esdm = self.packages.${system}.esdm;

            # Must agree with the ListenStream= of esdm-server-egd.socket,
            # i.e. with the esdm-server-egd-socket-path meson option, as
            # libgcrypt gets the path compiled in.
            egdSocket = "/run/esdm-egd.socket";

            libgcryptEgd = pkgs.libgcrypt.overrideAttrs (old: {
              configureFlags = old.configureFlags ++ [
                "--enable-random=egd"
                "--with-egd-socket=${egdSocket}"
              ];

              # The test suite draws random numbers, which this build can only
              # do through an EGD - and there is none in the build sandbox.
              doCheck = false;
            });

            # Only gnupg's own libgcrypt is swapped, so the rest of the
            # closure keeps the regular one and this stays a cheap rebuild.
            gnupgEgd = (pkgs.gnupg.override { libgcrypt = libgcryptEgd; }).overrideAttrs (_: {
              # Same reason as above - gnupg's test suite generates keys.
              doCheck = false;
            });

            gpgHome = "/root/gnupg-egd";
            gpg = "GNUPGHOME=${gpgHome} ${gnupgEgd}/bin/gpg --batch --no-tty";
          in
          pkgs.testers.nixosTest {
            name = "EGD interface serving GnuPG/libgcrypt";

            nodes.machine =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  # Not needed here - this check is about the EGD socket, and
                  # the CUSE daemons would only add startup surface.
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                # The EGD interface is opt-in: esdm-server.service only orders
                # itself after this socket unit, so enabling the unit is what
                # turns the interface on. This one line is the entire
                # administrative step the check is meant to cover.
                systemd.sockets."esdm-server-egd".wantedBy = [ "sockets.target" ];

                environment.systemPackages = [
                  esdm
                  gnupgEgd
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              machine.wait_for_unit("multi-user.target")

              # The socket unit creates the socket, the server picks the
              # descriptor up during its startup.
              machine.wait_for_unit("esdm-server-egd.socket")
              machine.wait_for_unit("esdm-server.service")
              machine.succeed("test -S ${egdSocket}")

              # Distinguish "systemd created the socket" from "the ESDM serves
              # it": only the latter logs this.
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")

              # Guard against testing the wrong libgcrypt: a gpg linked against
              # the stock one would happily pass everything below without ever
              # touching the EGD socket.
              machine.succeed(
                  "ldd ${gnupgEgd}/bin/gpg | grep -q '${libgcryptEgd.lib}'"
              )

              machine.succeed("mkdir -p ${gpgHome} && chmod 700 ${gpgHome}")

              # Raw output of libgcrypt's CSPRNG, which can only be seeded
              # through the ESDM here. Level 2 is GCRY_VERY_STRONG_RANDOM.
              out = machine.succeed(
                  "${gpg} --gen-random 2 32 | wc -c"
              ).strip()
              assert out == "32", f"gpg --gen-random returned {out} bytes"

              # Two consecutive draws must differ - a stuck or all-zero
              # response would satisfy the length check above.
              first = machine.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
              second = machine.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
              assert first != second, "gpg returned identical random data twice"

              # A request larger than the 255 byte cap of a single EGD transfer,
              # so the client has to issue several of them.
              out = machine.succeed("${gpg} --gen-random 2 4096 | wc -c").strip()
              assert out == "4096", f"gpg --gen-random returned {out} bytes"

              # The real thing: key generation consumes entropy through the
              # same path and is what a consumer actually does. The key is
              # generated with an empty passphrase, so no pinentry is
              # involved. (Single quoted Python strings here - an apostrophe
              # pair would end the Nix string this script lives in.)
              machine.succeed(
                  '${gpg} --pinentry-mode loopback --passphrase "" '
                  '--quick-generate-key "ESDM EGD test <egd@example.com>" '
                  'default default never'
              )
              machine.succeed("${gpg} --list-keys egd@example.com")

              # Encrypt/decrypt round trip on top of that key.
              machine.succeed(
                  'echo "entropy from the ESDM" | ${gpg} --yes --armor '
                  '--recipient egd@example.com --encrypt > /root/msg.asc'
              )
              out = machine.succeed(
                  "${gpg} --yes --decrypt /root/msg.asc"
              ).strip()
              assert out == "entropy from the ESDM", f"decryption returned {out!r}"

              # Negative control: without the EGD interface the same gpg must
              # fail. Both units have to go - stopping only the server would
              # leave systemd listening with nobody accepting, making clients
              # wait rather than fail. The socket file stays behind (systemd's
              # RemoveOnStop= defaults to no), but with nobody listening the
              # connect is refused, which is what libgcrypt trips over.
              machine.succeed("systemctl stop esdm-server-egd.socket esdm-server.service")
              machine.fail("${gpg} --gen-random 2 32 > /dev/null")

              # ... and it recovers once the interface is back, which also
              # covers the descriptor handover on a restart.
              machine.succeed("systemctl start esdm-server-egd.socket")
              machine.succeed("systemctl start esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              out = machine.succeed("${gpg} --gen-random 2 32 | wc -c").strip()
              assert out == "32", f"gpg --gen-random returned {out} bytes after restart"
            '';
          };

        # OpenSSH served through the EGD OpenSSL RAND provider, with the
        # emphasis on sshd's pre-authentication child: its seccomp filter kills
        # socket, connect, sendto and recvfrom. Serving it requires the EGD
        # client to connect at allocation time - while OpenSSL loads the
        # provider, before the child confines itself - and to then use
        # read/write rather than send/recv. The key exchanges are exercised
        # individually: curve25519 and sntrup761 live inside OpenSSH, while
        # ecdh-sha2-nistp256 and dh-group14-sha256 draw through libcrypto.
        mkEgdOpensshCheck =
          let
            esdm = self.packages.${system}.esdm;
            egdSocket = "/run/esdm-egd.socket";

            # Pin OpenSSL's DRBG and its seed source to the EGD provider.
            # Merely activating it would leave the choice to OpenSSL, and a
            # fallback to the default provider would make this check vacuous -
            # which is what the control at the end rules out.
            egdConf = pkgs.writeTextFile {
              name = "openssl-esdm-egd.cnf";
              text = ''
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
                module = ${esdm}/lib/libesdm-egd-provider.so
                egd_socket = ${egdSocket}

                [random_sect]
                random = CTR-DRBG
                properties = provider=esdm-egd
                seed = SEED-SRC
                seed_properties = provider=esdm-egd
              '';
            };

            kexAlgorithms = [
              "sntrup761x25519-sha512@openssh.com"
              "curve25519-sha256"
              "ecdh-sha2-nistp256"
              "diffie-hellman-group14-sha256"
            ];
          in
          pkgs.testers.nixosTest {
            name = "OpenSSH with the ESDM EGD OpenSSL provider";

            nodes.machine =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                systemd.sockets."esdm-server-egd".wantedBy = [ "sockets.target" ];

                services.openssh = {
                  enable = true;
                  settings = {
                    PermitRootLogin = "prohibit-password";
                    LogLevel = "DEBUG1";
                    KexAlgorithms = kexAlgorithms;
                  };
                };

                # sshd and its host key generation draw from the ESDM. Only
                # the server side is wired up here - the client is pointed at
                # the provider per command below, so the two can be told
                # apart.
                systemd.services.sshd.environment.OPENSSL_CONF = "${egdConf}";
                systemd.services.sshd-keygen.environment.OPENSSL_CONF = "${egdConf}";

                environment.systemPackages = [
                  esdm
                  pkgs.openssl.bin
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              machine.wait_for_unit("esdm-server-egd.socket")
              machine.wait_for_unit("esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")
              machine.succeed("OPENSSL_CONF=${egdConf} openssl rand -out /dev/null 32")

              # The host keys were generated by sshd-keygen through the
              # provider - the RSA one goes through libcrypto's RAND.
              machine.wait_for_unit("sshd.service")
              machine.wait_for_open_port(22)
              machine.succeed("test -s /etc/ssh/ssh_host_rsa_key")
              machine.succeed("test -s /etc/ssh/ssh_host_ed25519_key")

              machine.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
              machine.succeed(
                  'OPENSSL_CONF=${egdConf} ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519'
              )
              pubkey = machine.succeed("cat /root/.ssh/id_ed25519.pub").strip()
              machine.succeed(f"echo '{pubkey}' > /root/.ssh/authorized_keys")
              machine.succeed("chmod 600 /root/.ssh/authorized_keys")

              # -n: the client must not read the standard input it inherits
              # from the test driver's shell. Reading it, it hung now and then
              # after the session had ended, waiting on input that never
              # comes.
              opts = (
                  "-n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                  "-o IdentitiesOnly=yes -i /root/.ssh/id_ed25519"
              )
              kex_algorithms = ${builtins.toJSON kexAlgorithms}

              # Both ends drawing from the ESDM.
              for kex in kex_algorithms:
                  out = machine.succeed(
                      f"OPENSSL_CONF=${egdConf} ssh {opts} -o KexAlgorithms={kex} "
                      f"root@localhost 'echo ok'"
                  ).strip()
                  assert out == "ok", f"{kex}: unexpected ssh output {out!r}"

              # The same with a plain client, so that only the server side -
              # and with it the sandboxed pre-auth child - is on the ESDM.
              for kex in kex_algorithms:
                  out = machine.succeed(
                      f"ssh {opts} -o KexAlgorithms={kex} root@localhost 'echo ok'"
                  ).strip()
                  assert out == "ok", f"{kex}: unexpected ssh output {out!r}"

              # Nothing was killed by the seccomp filter on the way. This is
              # the assertion that would catch a client reaching for a
              # forbidden syscall inside the sandbox - a lazily opened
              # connection, or send/recv instead of write/read.
              machine.fail("journalctl -b | grep -iE 'sigsys|type=1326'")

              # Control: the sessions above really were served by the ESDM.
              # With it stopped the pinned provider has no source left, so a
              # plain client must now fail to connect - the failure can only
              # come from the server side.
              machine.succeed(
                  "systemctl stop esdm-server-egd.socket esdm-server-priv.socket "
                  "esdm-server-unpriv.socket esdm-server.service"
              )
              machine.fail("OPENSSL_CONF=${egdConf} openssl rand -out /dev/null 32")
              machine.fail(
                  f"ssh {opts} -o KexAlgorithms=ecdh-sha2-nistp256 "
                  "root@localhost 'echo unreachable'"
              )

              # ... and it comes back with the ESDM, which also exercises the
              # provider against a daemon that was restarted underneath it.
              machine.succeed("systemctl start esdm-server-egd.socket")
              machine.succeed("systemctl start esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")
              out = machine.succeed(
                  f"ssh {opts} -o KexAlgorithms=ecdh-sha2-nistp256 "
                  "root@localhost 'echo recovered'"
              ).strip()
              assert out == "recovered", f"unexpected ssh output: {out!r}"
            '';
          };

        # The PKCS#11 entropy source as an operator sets it up: esdm-es-pkcs11
        # started by its systemd unit as its system user, the PIN a systemd
        # credential imported from the credential store, serving a SoftHSM
        # token - and esdm-server reading it through its ExternalSocket
        # source, told about the socket and the user with ESDM_SERVER_OPTIONS
        # of its unit, nothing in it knowing of PKCS#11. The source has to be
        # credited in the status, deliver on a reseed, and be read again once
        # the daemon was restarted. Not kernel specific, so defined once.
        mkPkcs11Check =
          let
            esdm = self.packages.${system}.esdm;
            socket = "/run/esdm-es-pkcs11/esdm-es-pkcs11.socket";
            label = "esdm-vm-token";
            pin = "648219";
            # nixpkgs' SoftHSM has no configuration at the path it compiles
            # in, so the daemon and the token setup get this one. The token
            # directory is the one the sandbox of the daemon lets it write.
            softhsmConf = pkgs.writeText "softhsm2.conf" ''
              directories.tokendir = /var/lib/softhsm/tokens
              objectstore.backend = file
              log.level = ERROR
            '';
          in
          pkgs.testers.nixosTest {
            name = "PKCS#11 entropy source served by esdm-es-pkcs11";

            nodes.machine =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                # The user the unit runs as. The package ships it as a
                # sysusers.d file, which a NixOS without systemd-sysusers does
                # not read - an administrator declares it like this.
                users.users.esdm-es-pkcs11 = {
                  isSystemUser = true;
                  group = "esdm-es-pkcs11";
                };
                users.groups.esdm-es-pkcs11 = { };

                # The token, created once, as the user of the daemon, before
                # the daemon starts
                systemd.services.softhsm-token = {
                  wantedBy = [ "multi-user.target" ];
                  before = [ "esdm-es-pkcs11.service" ];
                  environment.SOFTHSM2_CONF = "${softhsmConf}";
                  path = [ pkgs.softhsm ];
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                    User = "esdm-es-pkcs11";
                    StateDirectory = "softhsm/tokens";
                  };
                  script = ''
                    softhsm2-util --show-slots | grep -q 'Label: *${label}' ||
                      softhsm2-util --init-token --free --label ${label} \
                        --so-pin 1234567890 --pin ${pin}
                  '';
                };

                # What the unit of the package leaves to the site: the module,
                # the token, and SoftHSM's configuration
                systemd.services.esdm-es-pkcs11 = {
                  wantedBy = [ "multi-user.target" ];
                  environment = {
                    SOFTHSM2_CONF = "${softhsmConf}";
                    ESDM_ES_PKCS11_OPTIONS = "--module ${pkgs.softhsm}/lib/softhsm/libsofthsm2.so --token_label ${label}";
                  };
                };

                # The PIN, imported by the unit (ImportCredential=pkcs11-pin)
                environment.etc."credstore/pkcs11-pin" = {
                  text = pin;
                  mode = "0400";
                };

                # The ESDM reads the daemon through its provider socket source
                systemd.services.esdm-server.environment.ESDM_SERVER_OPTIONS =
                  "--es_ext_socket ${socket} --es_ext_socket_uid esdm-es-pkcs11";

                environment.systemPackages = [
                  esdm
                  pkgs.softhsm
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              import json
              import time

              machine.wait_for_unit("multi-user.target")
              machine.wait_for_unit("esdm-es-pkcs11.service")
              machine.wait_for_unit("esdm-server.service")

              # Installed by the package, next to the unit
              machine.succeed("test -f ${esdm}/lib/sysusers.d/esdm-es-pkcs11.conf")
              machine.succeed("test -f ${esdm}/lib/systemd/system/esdm-es-pkcs11.service")

              # Ordered before the ESDM, and ready - socket served, token
              # looked for - before the ESDM was started
              ready = int(machine.succeed(
                  "systemctl show -P ActiveEnterTimestampMonotonic esdm-es-pkcs11.service"
              ).strip())
              started = int(machine.succeed(
                  "systemctl show -P InactiveExitTimestampMonotonic esdm-server.service"
              ).strip())
              assert 0 < ready <= started, f"esdm-es-pkcs11 ready at {ready}, esdm-server started at {started}"

              # The PIN is nowhere on a command line or in the environment
              pid = machine.succeed("systemctl show -P MainPID esdm-es-pkcs11.service").strip()
              machine.fail(f"tr '\\0' ' ' < /proc/{pid}/cmdline | grep -q ${pin}")
              machine.fail("systemctl show -P Environment esdm-es-pkcs11.service | grep -q ${pin}")
              # ... and the credential is not taken for a file open to all
              machine.fail("journalctl -b -u esdm-es-pkcs11.service | grep -q 'open to every user'")

              uid = machine.succeed("id -u esdm-es-pkcs11").strip()

              def pkcs11_source():
                  status = json.loads(machine.succeed("esdm-tool --status-json"))
                  for es in status["entropy_sources"]:
                      if es.get("instance") == "ExternalSocket":
                          return es
                  raise Exception(f"no ExternalSocket source in {status}")

              # The provider status is asked for at most every 5 seconds, and
              # not while a request is in progress
              def credited_source(what):
                  es = None
                  for _ in range(30):
                      es = pkcs11_source()
                      plugin = (es.get("provider") or {}).get("plugin") or {}
                      if (f"connected (uid {uid})" in es["status"]
                              and "failing" not in es["status"]
                              and es["available_entropy"] > 0
                              and plugin.get("token") == "${label}"):
                          return es
                      time.sleep(1)
                  raise Exception(f"{what}: the PKCS#11 source is not credited: {es}")

              es = credited_source("at start up")
              print(json.dumps(es, indent=2))
              assert es["name"] == "PKCS#11 ${label}", es["name"]
              assert es["entropy_rate"] == 128, es["entropy_rate"]
              assert es["entropy_rate_source"] == "provider", es["entropy_rate_source"]
              plugin = es["provider"]["plugin"]
              assert plugin["token_present"] and plugin["logged_in"], plugin
              assert plugin["pin"] == "set", plugin
              assert plugin["repetition_test"] == "passed", plugin
              assert plugin["last_error"] is None, plugin

              # A reseed reads the token: still credited, and not failing,
              # with the daemon having served requests since
              requests = es["provider"]["server"]["requests"]
              machine.succeed("esdm-tool --reseed-crng")
              time.sleep(6)
              es = credited_source("after a reseed")
              assert es["provider"]["server"]["requests"] > requests, es
              machine.succeed("esdm-tool --wait-until-seeded 60")

              # The daemon restarted is read again, without the ESDM being
              # restarted
              server = machine.succeed("systemctl show -P MainPID esdm-server.service").strip()
              machine.succeed("systemctl restart esdm-es-pkcs11.service")
              machine.wait_for_unit("esdm-es-pkcs11.service")
              machine.succeed("esdm-tool --reseed-crng")
              time.sleep(6)
              es = credited_source("after a restart of the daemon")
              assert es["provider"]["server"]["uptime_seconds"] < 60, es
              assert machine.succeed("systemctl show -P MainPID esdm-server.service").strip() == server
            '';
          };

        # The EGD protocol over the network, between two hosts: "server" runs
        # the ESDM and the esdm-egd-net-server in front of it, "client" has no
        # ESDM and serves its EGD socket with the esdm-egd-net-relay. GnuPG -
        # with the EGD-only libgcrypt of mkEgdCheck - and OpenSSL with the EGD
        # provider draw from the relay, unaware of the network behind it.
        #
        # Phases: TLS through the shipped units; rotation of the relay's client
        # certificate, revocation of an established connection by a CRL taken
        # up while the server runs, rotation of the server certificate and a
        # broken rotation that has to leave the service up; plain TCP with a
        # second server and relay, and the refusals of a plain mode not asked
        # for explicitly.
        mkEgdNetCheck =
          let
            esdm = self.packages.${system}.esdm;
            egdSocket = "/run/esdm-egd.socket";
            port = 7378;

            # The test PKI of the tree, issued for the name of the server
            pki = pkgs.runCommand "esdm-egd-net-vm-pki" {
              nativeBuildInputs = [
                pkgs.openssl
                pkgs.gawk
              ];
              ESDM_PKI_SERVER_SAN = "DNS:server";
            } "bash ${./tests/egd-net/pki/gen.sh} $out";

            libgcryptEgd = pkgs.libgcrypt.overrideAttrs (old: {
              configureFlags = old.configureFlags ++ [
                "--enable-random=egd"
                "--with-egd-socket=${egdSocket}"
              ];
              doCheck = false;
            });
            gnupgEgd = (pkgs.gnupg.override { libgcrypt = libgcryptEgd; }).overrideAttrs (_: {
              doCheck = false;
            });
            gpg = "GNUPGHOME=/root/gnupg-egd ${gnupgEgd}/bin/gpg --batch --no-tty";

            # OpenSSL pinned to the EGD provider on the socket @sock
            egdConf =
              sock:
              pkgs.writeText "openssl-esdm-egd.cnf" ''
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
                module = ${esdm}/lib/libesdm-egd-provider.so
                egd_socket = ${sock}

                [random_sect]
                random = CTR-DRBG
                properties = provider=esdm-egd
                seed = SEED-SRC
                seed_properties = provider=esdm-egd
              '';
            opensslTls = "OPENSSL_CONF=${egdConf egdSocket} openssl rand -out /dev/null 32";
            opensslPlain = "OPENSSL_CONF=${egdConf "/run/egd-plain/egd.sock"} openssl rand -out /dev/null 32";

            # A consumer holding its connection to the relay, asking for the
            # entropy count - answered by the server - every half second
            holdScript = pkgs.writeText "egd-hold.py" ''
              import socket, sys, time
              s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
              s.connect(sys.argv[1])
              while True:
                  s.sendall(b"\x00")
                  answer = b""
                  while len(answer) < 4:
                      chunk = s.recv(4 - len(answer))
                      if not chunk:
                          print("closed", flush=True)
                          sys.exit(1)
                      answer += chunk
                  print("ok", flush=True)
                  time.sleep(0.5)
            '';

            # Files the daemons take up while they run: plain paths, readable
            # by their dynamic users, rather than the credentials of the units
            dir = "/var/lib/egd-net-test";
          in
          pkgs.testers.nixosTest {
            name = "EGD protocol over the network, TLS and plain TCP";

            nodes.server =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                # The credentials of the shipped unit, which the daemon is
                # given plain paths of instead - see above
                environment.etc."esdm/egd-net/server.crt".source = "${pki}/server.crt";
                environment.etc."esdm/egd-net/server.key".source = "${pki}/server.key";
                environment.etc."esdm/egd-net/ca.crt".source = "${pki}/ca.crt";
                environment.etc."esdm/egd-net-server.env".text = ''
                  ESDM_EGD_NET_SERVER_ARGS="-v --cert ${dir}/server.crt --key ${dir}/server.key --ca ${dir}/ca.crt --crl ${dir}/crl.pem --reload_interval 2 --allow 192.168.1.0/24 --allow 2001:db8:1::/64"
                '';

                networking.firewall.allowedTCPPorts = [
                  port
                  (port + 1)
                ];
                environment.systemPackages = [ esdm ];
                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            nodes.client =
              { ... }:
              {
                # No ESDM here: the units of the package, the relay's only
                systemd.packages = [ esdm ];

                environment.etc."esdm/egd-net/client.crt".source = "${pki}/client1.crt";
                environment.etc."esdm/egd-net/client.key".source = "${pki}/client1.key";
                environment.etc."esdm/egd-net/ca.crt".source = "${pki}/ca.crt";
                environment.etc."esdm/egd-net-relay.env".text = ''
                  ESDM_EGD_NET_RELAY_ARGS="-v --connect server --cert ${dir}/client.crt --key ${dir}/client.key --ca ${dir}/ca.crt --crl ${dir}/ca.crl"
                '';

                environment.systemPackages = [
                  esdm
                  gnupgEgd
                  pkgs.openssl.bin
                  pkgs.python3
                ];
                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              def install(machine, src, dst):
                  # A rotation: written next to the file, renamed into place
                  machine.succeed(f"cp {src} {dst}.new && chmod 0644 {dst}.new && mv -f {dst}.new {dst}")

              start_all()

              server.wait_for_unit("esdm-server.service")
              server.succeed("esdm-tool --wait-until-seeded 60")
              server.succeed("install -d -m 0755 ${dir}")
              install(server, "${pki}/server.crt", "${dir}/server.crt")
              install(server, "${pki}/server.key", "${dir}/server.key")
              install(server, "${pki}/ca.crt", "${dir}/ca.crt")
              install(server, "${pki}/int-empty.crl", "${dir}/crl.pem")
              server.succeed("systemctl start esdm-egd-net-server.socket")
              server.wait_for_open_port(${toString port})

              client.wait_for_unit("multi-user.target")
              client.fail("systemctl is-active esdm-server.service")
              client.succeed("install -d -m 0755 ${dir}")
              install(client, "${pki}/client1.crt", "${dir}/client.crt")
              install(client, "${pki}/client1.key", "${dir}/client.key")
              install(client, "${pki}/ca.crt", "${dir}/ca.crt")
              install(client, "${pki}/ca.crl", "${dir}/ca.crl")
              client.succeed("systemctl start esdm-egd-net-relay.socket")
              client.wait_for_unit("esdm-egd-net-relay.socket")
              client.succeed("test -S ${egdSocket}")

              with subtest("TLS: GnuPG and OpenSSL draw from the relay"):
                  client.succeed("ldd ${gnupgEgd}/bin/gpg | grep -q '${libgcryptEgd.lib}'")
                  client.succeed("mkdir -p /root/gnupg-egd && chmod 700 /root/gnupg-egd")
                  out = client.succeed("${gpg} --gen-random 2 32 | wc -c").strip()
                  assert out == "32", f"gpg --gen-random returned {out} bytes"
                  first = client.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
                  second = client.succeed("${gpg} --gen-random 2 32 | base64 -w0").strip()
                  assert first != second, "gpg returned identical random data twice"
                  out = client.succeed("${gpg} --gen-random 2 4096 | wc -c").strip()
                  assert out == "4096", f"gpg --gen-random returned {out} bytes"
                  client.succeed(
                      '${gpg} --pinentry-mode loopback --passphrase "" '
                      '--quick-generate-key "ESDM EGD net test <egd@example.com>" '
                      'default default never'
                  )
                  client.succeed("${opensslTls}")
                  server.succeed("journalctl -u esdm-egd-net-server.service | grep -q 'serving the EGD protocol'")

              with subtest("Rotation and revocation"):
                  # The relay takes up the certificate to be revoked for its
                  # next upstream connection, held open by a consumer
                  install(client, "${pki}/client-revoked.key", "${dir}/client.key")
                  install(client, "${pki}/client-revoked.crt", "${dir}/client.crt")
                  client.succeed("${opensslTls}")
                  client.succeed("python3 ${holdScript} ${egdSocket} > /tmp/hold.log 2>&1 &")
                  client.wait_until_succeeds("grep -q ok /tmp/hold.log", 30)

                  # The CRL revoking it is taken up by the server, which
                  # closes the established connection
                  install(server, "${pki}/int.crl", "${dir}/crl.pem")
                  server.wait_until_succeeds(
                      "journalctl -u esdm-egd-net-server.service | grep -q 'closing the connection of .*revoked'", 30
                  )
                  client.wait_until_succeeds("grep -q closed /tmp/hold.log", 30)
                  client.fail("${opensslTls}")

                  # A good certificate again
                  install(client, "${pki}/client2.key", "${dir}/client.key")
                  install(client, "${pki}/client2.crt", "${dir}/client.crt")
                  client.succeed("${opensslTls}")

                  # A renewed server certificate, taken up by itself
                  install(server, "${pki}/server-renewed.key", "${dir}/server.key")
                  install(server, "${pki}/server-renewed.crt", "${dir}/server.crt")
                  server.wait_until_succeeds(
                      "test $(journalctl -u esdm-egd-net-server.service | grep -c 'loaded the TLS files') -ge 2", 30
                  )
                  client.succeed("${opensslTls}")

                  # A broken rotation leaves the service up
                  install(server, "${pki}/server.key", "${dir}/server.key")
                  server.wait_until_succeeds(
                      "journalctl -u esdm-egd-net-server.service | grep -q 'do not load'", 30
                  )
                  client.succeed("${opensslTls}")
                  client.succeed("${gpg} --gen-random 2 32 > /dev/null")

              with subtest("Plain TCP"):
                  # Never without asking: no credentials and no --plain, or
                  # --plain with TLS options, is refused
                  server.fail("esdm-egd-net-server --listen :${toString (port + 2)}")
                  server.fail("esdm-egd-net-server --plain --cert ${dir}/server.crt --listen :${toString (port + 2)}")
                  client.fail("esdm-egd-net-relay --connect server:${toString (port + 1)} --socket /tmp/x.sock")

                  server.succeed(
                      "systemd-run --unit=egd-net-plain --property=DynamicUser=yes "
                      "${esdm}/bin/esdm-egd-net-server -v --plain --listen :${toString (port + 1)} "
                      "--allow 192.168.1.0/24 --allow 2001:db8:1::/64"
                  )
                  server.wait_for_open_port(${toString (port + 1)})
                  server.succeed("journalctl -u egd-net-plain.service | grep -q 'neither encrypted nor authenticated'")
                  client.succeed(
                      "systemd-run --unit=egd-relay-plain --property=DynamicUser=yes "
                      "--property=RuntimeDirectory=egd-plain --property=RuntimeDirectoryMode=0755 "
                      "${esdm}/bin/esdm-egd-net-relay -v --plain --connect server:${toString (port + 1)} "
                      "--socket /run/egd-plain/egd.sock"
                  )
                  client.wait_until_succeeds("test -S /run/egd-plain/egd.sock", 30)
                  client.succeed("${opensslPlain}")
                  client.succeed("${opensslPlain}")

                  # The source not allowed is refused by the server
                  server.succeed("systemctl stop egd-net-plain.service")
                  server.succeed(
                      "systemd-run --unit=egd-net-plain2 --property=DynamicUser=yes "
                      "${esdm}/bin/esdm-egd-net-server -v --plain --listen :${toString (port + 1)} "
                      "--allow 10.0.0.0/8"
                  )
                  server.wait_for_open_port(${toString (port + 1)})
                  client.fail("${opensslPlain}")
                  server.succeed("journalctl -u egd-net-plain2.service | grep -q 'which is not allowed'")
            '';
          };

        # External entropy sources on the network, between two hosts: "source"
        # serves the example plugin of the tree, reading /dev/urandom, on SCTP
        # with the esdm-es-ext-serve-net units of the OpenSSL build; "esdm"
        # runs the ESDM (Botan) and reads it through the esdm-es-ext-relay of
        # its unit. Neither host sets a sysctl for SCTP-AUTH: the daemons
        # enable it per socket.
        #
        # Phases: the source credited at the rate it declares, the status of
        # the remote provider passed through; the TLS stacks against each
        # other - the relay of OpenSSL against the provider of GnuTLS, GnuTLS
        # against Botan - and against OpenSSL's own DTLS over SCTP
        # (s_client and s_server -sctp, which need net.sctp.auth_enable);
        # rotation of the relay's and of the provider's certificate, and a
        # broken rotation that leaves the service up; revocation of the
        # relay's certificate by a CRL taken up while the provider runs; a
        # client outside the allowlist refused.
        mkEsExtNetCheck =
          let
            esdm = self.packages.${system}.esdm;
            port = 7379;
            relaySocket = "/run/esdm-es-ext-relay/esdm-es-ext-relay.socket";

            # The ESDM with another crypto backend, for its TLS stack
            esdmWith =
              backend: inputs:
              esdm.overrideAttrs (prev: {
                pname = "esdm-${backend}";
                buildInputs = prev.buildInputs ++ inputs;
                mesonFlags =
                  (builtins.filter (x: !lib.hasInfix "crypto_backend" x) prev.mesonFlags)
                  ++ [ "-Dcrypto_backend=${backend}" ];
              });
            # OpenSSL is there already, for the OpenSSL providers
            esdmOpenssl = esdmWith "openssl" [ ];
            # The GnuTLS backend needs a GnuTLS built for FIPS 140
            esdmGnutls = esdmWith "gnutls" [
              (pkgs.gnutls.overrideAttrs (prev: {
                configureFlags = prev.configureFlags ++ [ "--enable-fips140-mode" ];
                doCheck = false;
              }))
            ];

            # OpenSSL with its own DTLS over SCTP, to check against
            opensslSctp = pkgs.openssl.overrideAttrs (prev: {
              pname = "openssl-sctp";
              configureFlags = prev.configureFlags ++ [ "enable-sctp" ];
              buildInputs = (prev.buildInputs or [ ]) ++ [ pkgs.lksctp-tools ];
              doCheck = false;
            });
            openssl = "${opensslSctp.bin}/bin/openssl";

            # The example plugin of the tree, built against the installed
            # header as a plugin of its own would be, reading a device the
            # sandbox of the unit has
            plugin = "${
              pkgs.runCommandCC "esdm-es-ext-example" { } ''
                mkdir -p $out/lib
                $CC -shared -fPIC -fvisibility=hidden -O2 \
                  -DESDM_ES_EXT_EXAMPLE_DEVICE='"/dev/urandom"' \
                  -I${esdmOpenssl}/include \
                  -o $out/lib/esdm_es_ext_example.so \
                  ${./es-ext/example/esdm_es_ext_example.c}
              ''
            }/lib/esdm_es_ext_example.so";
            pluginName = "example (/dev/urandom)";

            # The test PKI of the tree, the provider issued for "source"
            pki = pkgs.runCommand "esdm-es-ext-net-vm-pki" {
              nativeBuildInputs = [
                pkgs.openssl
                pkgs.gawk
              ];
              ESDM_PKI_SERVER_SAN = "DNS:source";
            } "bash ${./tests/egd-net/pki/gen.sh} $out";

            # Where the units load their credentials from. Copies rather
            # than links into the store, so that the test can rotate them,
            # and given to the daemons by their paths as well, as they take
            # up a rotation of these while they run, but not of the copies
            # LoadCredential= makes. Open to all: a test key.
            dir = "/etc/esdm/es-ext-net";
            etcFiles = lib.mapAttrs' (
              dst: src:
              lib.nameValuePair "esdm/es-ext-net/${dst}" {
                source = "${pki}/${src}";
                mode = "0644";
              }
            );

            # A client of the provider protocol, as the ESDM speaks it on a
            # local provider socket: INFO, then GET_ENTROPY of 32 bytes
            providerClient = pkgs.writeText "es-ext-client.py" ''
              import json, socket, struct, sys

              MAGIC = 0x58455345
              GET_ENTROPY, INFO = 1, 5

              def request(s, typ, length):
                  s.send(struct.pack("<IHHI", MAGIC, 1, typ, length))
                  answer = s.recv(70000)
                  magic, _, rtype, status, bits = struct.unpack("<IHHiI", answer[:16])
                  if magic != MAGIC or rtype != typ:
                      raise Exception(f"no answer to {typ}: {answer!r}")
                  return status, bits, answer[16:]

              s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
              s.settimeout(10)
              s.connect(sys.argv[1])
              out = {}
              out["info"], _, data = request(s, INFO, 0)
              if not out["info"]:
                  out["rate"] = struct.unpack("<I", data[:4])[0]
                  out["name"] = data[4:].decode()
                  out["get_entropy"], out["bits"], data = request(s, GET_ENTROPY, 32)
                  out["bytes"] = len(data)
              print(json.dumps(out))
            '';
          in
          pkgs.testers.nixosTest {
            name = "External entropy sources on the network, DTLS over SCTP";

            nodes.esdm =
              { ... }:
              {
                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };
                boot.kernelModules = [ "sctp" ];

                # The user the relay runs as, which the ESDM accepts. The
                # package ships it as a sysusers.d file, which a NixOS
                # without systemd-sysusers does not read.
                users.users.esdm-es-ext-relay = {
                  isSystemUser = true;
                  group = "esdm-es-ext-relay";
                };
                users.groups.esdm-es-ext-relay = { };

                # What the unit of the package leaves to the site: the
                # provider, and the ESDM told about the relay
                systemd.services.esdm-es-ext-relay.wantedBy = [ "multi-user.target" ];
                environment.etc =
                  etcFiles {
                    "client.crt" = "client1.crt";
                    "client.key" = "client1.key";
                    "ca.crt" = "ca.crt";
                    "ca.crl" = "ca.crl";
                  }
                  // {
                    "esdm/es-ext-relay.env".text = ''
                      ESDM_ES_EXT_RELAY_ARGS="-vv --connect source --cert ${dir}/client.crt --key ${dir}/client.key --ca ${dir}/ca.crt --crl ${dir}/ca.crl --reload_interval 2"
                    '';
                  };
                systemd.services.esdm-server.environment.ESDM_SERVER_OPTIONS =
                  "--es_ext_socket ${relaySocket} --es_ext_socket_uid esdm-es-ext-relay";

                environment.systemPackages = [
                  esdm
                  pkgs.python3
                ];
                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            nodes.source =
              { ... }:
              {
                boot.kernelModules = [ "sctp" ];

                # No ESDM here: the units of the package, the provider's
                systemd.packages = [ esdmOpenssl ];
                systemd.services.esdm-es-ext-serve-net.wantedBy = [ "multi-user.target" ];
                systemd.sockets.esdm-es-ext-serve-net.wantedBy = [ "sockets.target" ];
                environment.etc =
                  etcFiles {
                    "server.crt" = "server.crt";
                    "server.key" = "server.key";
                    "ca.crt" = "ca.crt";
                    "crl.pem" = "int-empty.crl";
                  }
                  // {
                    # The ESDM host only, by its addresses
                    "esdm/es-ext-serve-net.env".text = ''
                      ESDM_ES_EXT_SERVE_NET_ARGS="-v --plugin ${plugin} --cert ${dir}/server.crt --key ${dir}/server.key --ca ${dir}/ca.crt --crl ${dir}/crl.pem --reload_interval 2 --allow 192.168.1.1 --allow 2001:db8:1::1"
                    '';
                  };

                # SCTP, which a rule for TCP does not pass: the provider of
                # the units, and the ones of the other TLS stacks
                networking.firewall.extraCommands = ''
                  ip46tables -A nixos-fw -p sctp --dport ${toString port}:${toString (port + 2)} -j nixos-fw-accept
                '';

                environment.systemPackages = [ pkgs.python3 ];
                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              import hashlib
              import json
              import ssl
              import time

              def install(machine, src, dst):
                  # A rotation: written next to the file, renamed into place
                  machine.succeed(f"cp {src} {dst}.new && chmod 0644 {dst}.new && mv -f {dst}.new {dst}")

              def fingerprint(name):
                  # SHA-256 of the first certificate of the file, as the
                  # daemons tell it
                  with open(f"${pki}/{name}") as f:
                      pem = f.read()
                  end = "-----END CERTIFICATE-----"
                  der = ssl.PEM_cert_to_DER_cert(pem[: pem.index(end) + len(end)])
                  return hashlib.sha256(der).hexdigest()

              # How often @unit logged @text so far, and waiting for it to
              # log it once more
              def count(machine, unit, text):
                  return int(machine.succeed(
                      f"journalctl -u {unit} | grep -c -- '{text}' || true"
                  ).strip() or 0)

              def logs_again(machine, unit, text, before, timeout=60):
                  machine.wait_until_succeeds(
                      f"test $(journalctl -u {unit} | grep -c -- '{text}') -gt {before}", timeout
                  )

              def ask(machine, sock):
                  return json.loads(machine.succeed(f"python3 ${providerClient} {sock}"))

              def source_es():
                  status = json.loads(esdm.succeed("esdm-tool --status-json"))
                  for es in status["entropy_sources"]:
                      if es.get("instance") == "ExternalSocket":
                          return es
                  raise Exception(f"no ExternalSocket source in {status}")

              # Connected through the relay, credited, and asked by the
              # client certificate @peer if given. The provider status is
              # asked for at most every 5 seconds.
              def credited(what, peer=None):
                  es = None
                  for _ in range(90):
                      es = source_es()
                      server = (es.get("provider") or {}).get("server") or {}
                      if (f"connected (uid {relay_uid}), DTLS" in es["status"]
                              and "failing" not in es["status"]
                              and es["available_entropy"] > 0
                              and server.get("transport") == "sctp"
                              and (peer is None or server.get("peer") == peer)):
                          return es
                      time.sleep(1)
                  raise Exception(f"{what}: the source on the network is not credited: {es}")

              start_all()

              source.wait_for_unit("esdm-es-ext-serve-net.service")
              source.succeed("systemctl is-active esdm-es-ext-serve-net.socket")
              esdm.wait_for_unit("esdm-server.service")
              esdm.wait_for_unit("esdm-es-ext-relay.service")
              relay_uid = esdm.succeed("id -u esdm-es-ext-relay").strip()

              # Nothing set for SCTP-AUTH
              for m in (esdm, source):
                  m.succeed("test $(cat /proc/sys/net/sctp/auth_enable) = 0")

              # Installed by the package, next to the units
              esdm.succeed("test -f ${esdm}/lib/sysusers.d/esdm-es-ext-relay.conf")
              for unit in ("esdm-es-ext-relay.service", "esdm-es-ext-serve-net.service",
                           "esdm-es-ext-serve-net.socket"):
                  esdm.succeed(f"test -f ${esdm}/lib/systemd/system/{unit}")
              esdm.succeed("ls ${esdm}/share/man/man8 | grep -q esdm-es-ext-relay")

              # The relay is ordered before the ESDM, and ready before it
              # was started
              ready = int(esdm.succeed(
                  "systemctl show -P ActiveEnterTimestampMonotonic esdm-es-ext-relay.service"
              ).strip())
              started = int(esdm.succeed(
                  "systemctl show -P InactiveExitTimestampMonotonic esdm-server.service"
              ).strip())
              assert 0 < ready <= started, f"relay ready at {ready}, esdm-server started at {started}"

              with subtest("The source on the network, credited"):
                  es = credited("at start up", fingerprint("client1.crt"))
                  print(json.dumps(es, indent=2))
                  assert es["name"] == "${pluginName}", es["name"]
                  assert es["entropy_rate"] == 32, es["entropy_rate"]
                  assert es["entropy_rate_source"] == "provider", es["entropy_rate_source"]
                  assert es["provider"]["server"]["dtls"] is True, es
                  assert es["provider"]["plugin"]["device"] == "/dev/urandom", es

                  # A reseed reads it: requests served since
                  requests = es["provider"]["server"]["requests"]
                  esdm.succeed("esdm-tool --reseed-crng")
                  time.sleep(6)
                  es = credited("after a reseed")
                  assert es["provider"]["server"]["requests"] > requests, es
                  esdm.succeed("esdm-tool --wait-until-seeded 60")

              with subtest("The TLS stacks against each other"):
                  # Providers of Botan and GnuTLS next to the one of OpenSSL
                  for name, pkg, p in (("botan", "${esdm}", ${toString (port + 1)}),
                                       ("gnutls", "${esdmGnutls}", ${toString (port + 2)})):
                      source.succeed(
                          f"systemd-run --unit=serve-{name} --property=DynamicUser=yes "
                          f"{pkg}/bin/esdm-es-ext-serve -v --plugin ${plugin} --listen :{p} "
                          "--cert ${dir}/server.crt --key ${dir}/server.key --ca ${dir}/ca.crt "
                          "--allow 192.168.1.1 --allow 2001:db8:1::1"
                      )
                      source.wait_until_succeeds(
                          f"journalctl -u serve-{name}.service | grep -q 'on the network'", 30
                      )

                  # Relays of OpenSSL and GnuTLS against them
                  for name, pkg, p in (("openssl", "${esdmOpenssl}", ${toString (port + 2)}),
                                       ("gnutls", "${esdmGnutls}", ${toString (port + 1)})):
                      esdm.succeed(
                          f"systemd-run --unit=relay-{name} --property=DynamicUser=yes "
                          f"--property=RuntimeDirectory=relay-{name} --property=RuntimeDirectoryMode=0755 "
                          f"{pkg}/bin/esdm-es-ext-relay -v --connect source:{p} "
                          f"--socket /run/relay-{name}/relay.sock "
                          "--cert ${dir}/client.crt --key ${dir}/client.key --ca ${dir}/ca.crt"
                      )
                      esdm.wait_until_succeeds(f"test -S /run/relay-{name}/relay.sock", 30)
                      out = ask(esdm, f"/run/relay-{name}/relay.sock")
                      print(name, out)
                      assert out["info"] == 0 and out["name"] == "${pluginName}", out
                      assert out["rate"] == 32 and out["get_entropy"] == 0, out
                      assert out["bytes"] == 32 and out["bits"] == 32, out

              with subtest("Against OpenSSL's own DTLS over SCTP"):
                  # OpenSSL enables SCTP-AUTH by the sysctl only
                  esdm.succeed("sysctl -w net.sctp.auth_enable=1")

                  # s_client against the providers of all three TLS stacks,
                  # asking INFO - the byte in front, as every message has -
                  # until it is stopped, after the answer
                  for p in (${toString port}, ${toString (port + 1)}, ${toString (port + 2)}):
                      out = esdm.succeed(
                          "{ (printf '\\000ESEX\\001\\000\\005\\000\\000\\000\\000\\000'; sleep 3) | "
                          f"timeout 15 ${openssl} s_client -sctp -dtls1_2 -connect source:{p} "
                          "-cert ${dir}/client.crt -key ${dir}/client.key -cert_chain ${dir}/client.crt "
                          "-CAfile ${dir}/ca.crt -verify_return_error -verify_hostname source "
                          "-ign_eof 2>&1 || true; } | tr -c '[:print:]\\n' '.'"
                      )
                      assert "Verify return code: 0 (ok)" in out, out
                      assert "${pluginName}" in out, out

                  # s_server, the relays of all three TLS stacks connecting
                  # to it: it answers nothing, but receives their INFO. Its
                  # input held open, as it ends with it - by a sleep named by
                  # its path, which the PATH of a unit does not find.
                  esdm.succeed(
                      "systemd-run --unit=s-server sh -c '${pkgs.coreutils}/bin/sleep 3600 | "
                      "${openssl} s_server -sctp -dtls1_2 -accept 127.0.0.1:7390 "
                      "-cert ${pki}/server.crt -key ${pki}/server.key -CAfile ${pki}/ca.crt "
                      "-Verify 2 -verify_return_error > /run/s_server.log 2>&1'"
                  )
                  esdm.wait_until_succeeds("grep -q ACCEPT /run/s_server.log", 30)
                  for i, (name, pkg) in enumerate((("botan", "${esdm}"),
                                                   ("openssl", "${esdmOpenssl}"),
                                                   ("gnutls", "${esdmGnutls}"))):
                      esdm.succeed(
                          f"systemd-run --unit=relay-native-{name} --property=DynamicUser=yes "
                          f"--property=RuntimeDirectory=relay-native-{name} "
                          "--property=RuntimeDirectoryMode=0755 "
                          f"{pkg}/bin/esdm-es-ext-relay -v --connect 127.0.0.1:7390 "
                          f"--server_name source --socket /run/relay-native-{name}/relay.sock "
                          "--cert ${dir}/client.crt --key ${dir}/client.key --ca ${dir}/ca.crt"
                      )
                      esdm.wait_until_succeeds(f"test -S /run/relay-native-{name}/relay.sock", 30)
                      out = ask(esdm, f"/run/relay-native-{name}/relay.sock")
                      # The relay gives up on the answer in time
                      if out["info"] != -110:
                          print(esdm.succeed("cat -v /run/s_server.log"))
                          print(esdm.succeed(f"journalctl -u relay-native-{name}.service"))
                      assert out["info"] == -110, out
                      esdm.wait_until_succeeds(
                          f"test $(grep -a -c ESEX /run/s_server.log) -ge {i + 1}", 30
                      )
                  esdm.succeed("systemctl stop s-server.service")
                  esdm.succeed("sysctl -w net.sctp.auth_enable=0")

              relay = "esdm-es-ext-relay.service"
              provider = "esdm-es-ext-serve-net.service"

              with subtest("Rotation"):
                  # The relay takes up a renewed client certificate for its
                  # next upstream connection - made once the provider was
                  # restarted, as the ESDM connects anew
                  loaded = count(esdm, relay, "loaded the TLS files")
                  install(esdm, "${pki}/client2.key", "${dir}/client.key")
                  install(esdm, "${pki}/client2.crt", "${dir}/client.crt")
                  logs_again(esdm, relay, "loaded the TLS files", loaded)
                  source.succeed(f"systemctl restart {provider}")
                  credited("with the renewed client certificate", fingerprint("client2.crt"))

                  # A renewed provider certificate, taken up by the provider
                  # by itself, for the next connection of the relay
                  loaded = count(source, provider, "loaded the TLS files")
                  install(source, "${pki}/server-renewed.key", "${dir}/server.key")
                  install(source, "${pki}/server-renewed.crt", "${dir}/server.crt")
                  logs_again(source, provider, "loaded the TLS files", loaded)
                  renewed = fingerprint("server-renewed.crt")
                  esdm.succeed(f"systemctl restart {relay}")
                  esdm.wait_until_succeeds(
                      f"journalctl -u {relay} | grep -q 'SHA-256 {renewed}'", 60
                  )
                  credited("with the renewed provider certificate")

                  # A broken rotation - a key not of the certificate - leaves
                  # the provider up with what it had
                  broken = count(source, provider, "do not load")
                  install(source, "${pki}/server.key", "${dir}/server.key")
                  logs_again(source, provider, "do not load", broken)
                  source.succeed(f"systemctl is-active {provider}")
                  esdm.succeed(f"systemctl restart {relay}")
                  credited("after a broken rotation of the provider")

                  # Repaired - a provider started with the broken files
                  # would not start
                  loaded = count(source, provider, "loaded the TLS files")
                  install(source, "${pki}/server-renewed.key", "${dir}/server.key")
                  logs_again(source, provider, "loaded the TLS files", loaded)

              with subtest("Revocation"):
                  # The certificate to be revoked, taken up by the relay for
                  # its next upstream connection
                  loaded = count(esdm, relay, "loaded the TLS files")
                  install(esdm, "${pki}/client-revoked.key", "${dir}/client.key")
                  install(esdm, "${pki}/client-revoked.crt", "${dir}/client.crt")
                  logs_again(esdm, relay, "loaded the TLS files", loaded)
                  source.succeed(f"systemctl restart {provider}")
                  credited("with the certificate to be revoked", fingerprint("client-revoked.crt"))

                  # The CRL revoking it, taken up by the provider, closes the
                  # established connection and refuses the next ones: the
                  # relay finds the provider unreachable, and the ESDM is
                  # served nothing
                  unreachable = count(esdm, relay, "is not reachable")
                  install(source, "${pki}/int.crl", "${dir}/crl.pem")
                  source.wait_until_succeeds(
                      f"journalctl -u {provider} | grep -q 'closing the connection of .*revoked'", 30
                  )
                  logs_again(esdm, relay, "is not reachable", unreachable)
                  esdm.succeed(
                      f"journalctl -u {relay} | grep -q 'handshake with source failed: .*certificate_revoked'"
                  )
                  for _ in range(30):
                      es = source_es()
                      if es["status"] == "not connected" or es.get("name") != "${pluginName}":
                          break
                      time.sleep(1)
                  else:
                      raise Exception(f"the source is served with a revoked certificate: {es}")

                  # A good certificate again
                  install(esdm, "${pki}/client2.key", "${dir}/client.key")
                  install(esdm, "${pki}/client2.crt", "${dir}/client.crt")
                  credited("with a good certificate again", fingerprint("client2.crt"))

              with subtest("A client outside the allowlist"):
                  # The source host itself, which the provider does not serve
                  source.succeed(
                      "systemd-run --unit=relay-outside --property=DynamicUser=yes "
                      "--property=RuntimeDirectory=relay-outside --property=RuntimeDirectoryMode=0755 "
                      "${esdm}/bin/esdm-es-ext-relay -v --connect source "
                      "--socket /run/relay-outside/relay.sock "
                      "--cert ${pki}/client2.crt --key ${pki}/client2.key --ca ${pki}/ca.crt"
                  )
                  source.wait_until_succeeds("test -S /run/relay-outside/relay.sock", 30)
                  out = ask(source, "/run/relay-outside/relay.sock")
                  assert out["info"] != 0, out
                  source.succeed(
                      "journalctl -u esdm-es-ext-serve-net.service | grep -q 'which is not allowed'"
                  )
                  credited("after all")
            '';
          };

        # The esdm_cdev kernel module: /dev/esdm_random, /dev/esdm_urandom and
        # /proc/esdm served by the ESDM over its EGD socket. On the stock
        # rolling kernel - the module needs no kernel patches - and once only,
        # the per kernel builds below check that it compiles everywhere.
        mkEsdmCdevCheck =
          kernel:
          let
            esdm = self.packages.${system}.esdm;
            # The checks of tests/esdm_cdev, one subcommand each, installed
            # with the ESDM by its option esdm-cdev-check. The ones running
            # in the background are stopped by pkill -f 'esdm-cdev-check
            # [b]lock' and the like, which matches their command line only:
            # the brackets keep the pattern from matching one that holds the
            # pattern itself, such as that of a shell running pkill.
            check = "${esdm}/bin/esdm-cdev-check";
          in
          pkgs.testers.nixosTest {
            name = "esdm_cdev character devices";

            nodes.machine =
              { config, ... }:
              {
                boot.kernelPackages = kernel;
                boot.extraModulePackages = [
                  (config.boot.kernelPackages.callPackage ./kernel/esdm_cdev { })
                ];

                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                # The module talks to the EGD socket, which is opt-in.
                systemd.sockets."esdm-server-egd".wantedBy = [ "sockets.target" ];

                environment.systemPackages = [ esdm ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              import time

              def bounded(cmd, limit):
                  start = time.monotonic()
                  out = machine.succeed(cmd)
                  took = time.monotonic() - start
                  assert took < limit, f"{cmd} took {took:.1f} s"
                  return out

              machine.wait_for_unit("multi-user.target")
              machine.wait_for_unit("esdm-server-egd.socket")
              machine.wait_for_unit("esdm-server.service")
              machine.wait_until_succeeds(
                  "journalctl -b -u esdm-server.service | grep -q 'EGD server: serving'", 30
              )
              machine.succeed("esdm-tool --wait-until-seeded 60")

              with subtest("devices and proc files with the ESDM running"):
                  machine.succeed("modprobe esdm_cdev")
                  for dev in ["esdm_random", "esdm_urandom"]:
                      machine.succeed(f"test -c /dev/{dev}")
                      mode = machine.succeed(f"stat -c %a /dev/{dev}").strip()
                      assert mode == "666", f"/dev/{dev} has mode {mode}"
                  # The kernel's own devices stay as they are
                  machine.succeed("test \"$(stat -c %t:%T /dev/urandom)\" = 1:9")
                  machine.succeed("test \"$(stat -c %t:%T /dev/random)\" = 1:8")
                  print(machine.succeed("cat /proc/esdm/status"))

              with subtest("reads, poll, O_NONBLOCK, O_SYNC and writes"):
                  machine.succeed("${check} reads")
                  machine.succeed("${check} reads sync")
                  machine.succeed("${check} nonblock")
                  machine.succeed("${check} poll")
                  machine.succeed("${check} writes")

              with subtest("throughput, informational"):
                  # Logged, never asserted on: the VM shares its host with
                  # whatever else runs there. Whether it runs with KVM, and
                  # the figures with the clocksource the test framework pins,
                  # acpi_pm - every read of it traps to QEMU, as it has no
                  # vDSO - and with kvm-clock, which a KVM guest runs with
                  # otherwise.
                  print("virtualization: " + machine.succeed("systemd-detect-virt || true"))
                  print(machine.succeed("${check} throughput"))
                  cs = "/sys/devices/system/clocksource/clocksource0"
                  pinned = machine.succeed(f"cat {cs}/current_clocksource").strip()
                  if "kvm-clock" in machine.succeed(f"cat {cs}/available_clocksource"):
                      machine.succeed(f"echo kvm-clock > {cs}/current_clocksource")
                      print(machine.succeed("${check} throughput"))
                      machine.succeed(f"echo {pinned} > {cs}/current_clocksource")

              with subtest("/proc/esdm"):
                  machine.succeed("${check} proc")

              with subtest("ioctls as root, as nobody and without CAP_SYS_ADMIN"):
                  machine.succeed("${check} ioctl-priv")
                  machine.succeed(
                      "setpriv --reuid=nobody --regid=nogroup --clear-groups "
                      "--inh-caps=-all ${check} ioctl-unpriv"
                  )
                  machine.succeed(
                      "setpriv --bounding-set=-sys_admin --inh-caps=-sys_admin "
                      "${check} ioctl-unpriv"
                  )
                  # As root, as meson test runs it there: the check gives up
                  # CAP_SYS_ADMIN itself
                  machine.succeed("${check} ioctl-unpriv")

              with subtest("writers whose data does not come keep nobody waiting"):
                  machine.succeed("timeout 60 ${check} stalled-writers")

              with subtest("reconnect after a restart of the ESDM"):
                  machine.succeed(
                      "nohup ${check} loop /dev/esdm_urandom 20 > /tmp/loop.log 2>&1 &"
                  )
                  machine.sleep(3)
                  machine.succeed("systemctl restart esdm-server.service")
                  machine.wait_until_succeeds("grep -q 'loop reads' /tmp/loop.log", 90)
                  print(machine.succeed("cat /tmp/loop.log"))
                  machine.succeed("grep -q 'errors=0' /tmp/loop.log")
                  machine.wait_until_succeeds(
                      "grep -q 'ESDM library version' /proc/esdm/status", 60
                  )
                  machine.succeed("${check} proc")

              with subtest("unloading is refused while a reader blocks"):
                  # A frozen ESDM keeps the reader waiting for its answer
                  machine.succeed("systemctl kill -s SIGSTOP esdm-server.service")
                  machine.succeed(
                      "nohup ${check} block /dev/esdm_random > /tmp/block.log 2>&1 &"
                  )
                  machine.wait_until_succeeds("grep -q blocking /tmp/block.log", 30)
                  machine.sleep(1)
                  machine.fail("rmmod esdm_cdev")
                  machine.succeed("systemctl kill -s SIGCONT esdm-server.service")
                  machine.succeed("pkill -f 'esdm-cdev-check [b]lock'")
                  machine.wait_until_fails("pgrep -f 'esdm-cdev-check [b]lock'", 30)
                  machine.wait_until_succeeds(
                      "grep -q 'ESDM library version' /proc/esdm/status", 60
                  )

              with subtest("the ESDM unreachable: the kernel's RNG serves"):
                  machine.succeed("systemctl stop esdm-server-egd.socket esdm-server.service")
                  bounded("${check} reads", 120)
                  machine.succeed("${check} nonblock")
                  machine.succeed("${check} writes")
                  machine.succeed("${check} proc-empty")
                  machine.succeed("${check} ioctl-unreachable")
                  machine.succeed("dmesg | grep -q 'esdm_cdev: cannot connect to the ESDM'")

              with subtest("loading with the ESDM stopped returns at once"):
                  machine.succeed("rmmod esdm_cdev")
                  bounded("modprobe esdm_cdev", 10)
                  machine.succeed("test -c /dev/esdm_random")
                  machine.succeed(
                      "cmp /proc/esdm/boot_id /proc/sys/kernel/random/boot_id"
                  )
                  bounded("head -c 4096 /dev/esdm_random > /dev/null", 30)

              with subtest("the ESDM comes back"):
                  machine.succeed("systemctl start esdm-server-egd.socket esdm-server.service")
                  machine.wait_until_succeeds(
                      "grep -q 'ESDM library version' /proc/esdm/status", 60
                  )
                  machine.succeed("${check} reads")
                  machine.succeed("${check} ioctl-priv")

              # The module against the fake EGD server of esdm-cdev-check, for
              # what the ESDM cannot be made to do: see its fake-egd command.
              def fake_egd(mode, params=""):
                  machine.succeed("rmmod esdm_cdev")
                  machine.succeed("rm -f /tmp/fake-egd.log")
                  machine.succeed(
                      "nohup ${check} fake-egd /run/fake-egd.socket "
                      f"/tmp/fake-egd.log {mode} > /dev/null 2>&1 &"
                  )
                  machine.wait_until_succeeds("grep -q listening /tmp/fake-egd.log", 30)
                  machine.succeed(
                      f"modprobe esdm_cdev egd_socket=/run/fake-egd.socket {params}"
                  )

              def real_egd():
                  machine.succeed("rmmod esdm_cdev")
                  machine.succeed("pkill -f 'esdm-cdev-check [f]ake-egd'")
                  machine.succeed("modprobe esdm_cdev")

              with subtest("an ESDM that accepts but does not answer is backed off from"):
                  fake_egd("mute", "connections=1 timeout_ms=200")
                  machine.succeed("${check} backoff /tmp/fake-egd.log 8")
                  real_egd()

              with subtest("RNDADDENTROPY credits once all of the data is in, writes never"):
                  fake_egd("notop")
                  machine.succeed("${check} addentropy /tmp/fake-egd.log")
                  machine.succeed("${check} write-notop /tmp/fake-egd.log")
                  real_egd()

              with subtest("RNDADDTOENTCNT is not carried out twice for a signal"):
                  fake_egd("notop")
                  machine.succeed("${check} addtoentcnt-signal /tmp/fake-egd.log")
                  real_egd()

              with subtest("poll() reports what a read does of an ESDM not operational"):
                  fake_egd("notop")
                  # The watcher, kicked at load, learned the state
                  machine.sleep(1)
                  machine.succeed("${check} poll-notop")
                  real_egd()

              with subtest("reads waiting for an ESDM not operational wait, until a signal"):
                  fake_egd("notop")
                  machine.succeed("timeout 60 ${check} block-notop")
                  real_egd()

              with subtest("/proc/esdm of an ESDM not operational, uuid from the kernel's RNG"):
                  fake_egd("notop")
                  machine.succeed("${check} proc-notop")
                  real_egd()

              with subtest("unloading once the reader is gone"):
                  machine.succeed(
                      "nohup ${check} block /dev/esdm_urandom > /tmp/block2.log 2>&1 &"
                  )
                  machine.wait_until_succeeds("grep -q blocking /tmp/block2.log", 30)
                  machine.fail("rmmod esdm_cdev")
                  machine.succeed("pkill -f 'esdm-cdev-check [b]lock'")
                  machine.wait_until_fails("pgrep -f 'esdm-cdev-check [b]lock'", 30)
                  machine.succeed("rmmod esdm_cdev")
                  machine.fail("test -e /dev/esdm_random")
                  machine.fail("test -e /proc/esdm")

              with subtest("no oops, BUG or WARN"):
                  kmsg = machine.succeed("dmesg")
                  for bad in ["BUG:", "WARNING:", "Oops", "Call Trace", "general protection"]:
                      assert bad not in kmsg, f"dmesg holds {bad}:\n{kmsg}"
            '';
          };

        # The guest of the vhost-user RNG checks: the stock kernel, booted
        # directly, and an initrd of busybox, kmod and the virtio modules. Its
        # init does what a guest does with an entropy device - load the driver,
        # see it become the current hwrng, read /dev/hwrng - and reports each
        # step on the serial console, prefixed with "VURNG: ". Then it goes on
        # reading 64 bytes a second, "VURNG: loop <n>", for the checks to stall
        # and resume. A VMM with an entropy device of its own (Cloud
        # Hypervisor) is handled with vurng_keep=<PCI address> on the kernel
        # command line: every other virtio-rng is unbound, so the one of the
        # ESDM is what /dev/hwrng reads.
        vhostUserRngGuest =
          let
            kernel = stockKernels.latest.kernel;
            modules = pkgs.makeModulesClosure {
              kernel = lib.getOutput "modules" kernel;
              firmware = pkgs.emptyDirectory;
              rootModules = [
                "virtio_pci"
                "virtio_mmio"
                "virtio_rng"
              ];
            };
            init = pkgs.writeScript "vhost-user-rng-guest-init" ''
              #!${pkgs.busybox}/bin/sh
              export PATH=${pkgs.busybox}/bin
              say() { echo "VURNG: $*"; }
              hold() { say "$@"; while true; do sleep 3600; done; }

              mkdir -p /proc /sys /dev /tmp
              mount -t proc proc /proc
              mount -t sysfs sysfs /sys
              mount -t devtmpfs devtmpfs /dev 2>/dev/null

              for m in virtio_pci virtio_mmio virtio_rng; do
                ${pkgs.kmod}/bin/modprobe -d ${modules} $m || say "cannot load $m"
              done

              # Up to 30 s for a virtio-rng to become the current hwrng and
              # its device to show up bound to the driver: on virtio-mmio,
              # the guest under TCG gets there well after modprobe returned
              drv=/sys/bus/virtio/drivers/virtio_rng
              cur=
              wait_current() {
                i=0
                while [ $i -lt 300 ]; do
                  cur=$(cat /sys/class/misc/hw_random/rng_current 2>/dev/null)
                  case "$cur" in
                    virtio_rng.*) [ -n "$(ls -d $drv/virtio* 2>/dev/null)" ] && return ;;
                  esac
                  sleep 0.1
                  i=$((i + 1))
                done
              }

              wait_current
              keep=$(sed -n 's/.*vurng_keep=\([^ ]*\).*/\1/p' /proc/cmdline)
              for d in $drv/virtio*; do
                [ -e "$d" ] || continue
                path=$(readlink -f "$d")
                say "device: ''${d##*/} at $path"
                if [ -n "$keep" ]; then
                  case "$path" in
                    */$keep/*) ;;
                    *) echo "''${d##*/}" > $drv/unbind; say "unbound ''${d##*/}" ;;
                  esac
                fi
              done
              # The hwrng core moves on to the one kept
              wait_current

              say "available: $(cat /sys/class/misc/hw_random/rng_available)"
              say "current: $cur"
              case "$cur" in
                virtio_rng.*) ;;
                *) hold "FAIL no virtio-rng is the current hwrng" ;;
              esac
              n=$(ls -d $drv/virtio* 2>/dev/null | wc -l)
              [ "$n" = 1 ] || hold "FAIL $n virtio-rng devices bound"

              say "reading /dev/hwrng"
              head -c 4096 /dev/hwrng > /tmp/a
              head -c 4096 /dev/hwrng > /tmp/b
              size=$(wc -c < /tmp/a)
              distinct=$(od -An -v -tx1 /tmp/a | tr -s ' ' '\n' | grep . | sort -u | wc -l)
              if [ "$size" -eq 4096 ] && ! cmp -s /tmp/a /tmp/b && [ "$distinct" -gt 200 ]; then
                say "OK $size bytes of /dev/hwrng, $distinct distinct byte values"
              else
                hold "FAIL $size bytes of /dev/hwrng, $distinct distinct byte values"
              fi

              i=0
              while true; do
                if head -c 64 /dev/hwrng > /dev/null; then
                  i=$((i + 1))
                  say "loop $i"
                fi
                sleep 1
              done
            '';
          in
          {
            kernel = "${kernel}/bzImage";
            initrd = "${
              pkgs.makeInitrd {
                contents = [
                  {
                    object = init;
                    symlink = "/init";
                  }
                ];
              }
            }/initrd";
            cmdline = "console=ttyS0 panic=-1 loglevel=4";
          };

        # One check of esdm-vhost-user-rng: the ESDM and the socket units of
        # the daemon on a NixOS VM, a VMM running as the unprivileged user
        # "vmm" in the group the sockets belong to, and @script driving it.
        # The helpers of the script: start_vm(name, cmd) starts the socket of
        # the VM and the VMM as a transient unit; wait_ok(name) waits for the
        # guest to read /dev/hwrng; loops(name) counts its reads since;
        # stall_and_resume(name) shows the bytes come from the ESDM - the guest
        # stalls while the ESDM is stopped and resumes once it is back;
        # hmp(name, cmd...) sends commands to the monitor of a QEMU started
        # with "-monitor unix:/var/lib/vmm/<name>.mon,server=on,wait=off".
        mkVhostUserRngCheck =
          {
            name,
            script,
            node ? { },
          }:
          let
            esdm = self.packages.${system}.esdm;
            connect = pkgs.writeText "vhost-user-rng-connect.py" ''
              import socket, sys
              s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
              s.connect(sys.argv[1])
            '';
            hmp = pkgs.writeText "vhost-user-rng-hmp.py" ''
              import socket, sys
              s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
              s.settimeout(30)
              s.connect(sys.argv[1])
              def prompt():
                  buf = b""
                  while not buf.endswith(b"(qemu) "):
                      data = s.recv(4096)
                      if not data:
                          sys.exit("the monitor closed the connection")
                      buf += data
                  return buf.decode(errors="replace")
              prompt()
              for cmd in sys.argv[2:]:
                  s.sendall(cmd.encode() + b"\n")
                  print(prompt())
            '';
          in
          pkgs.testers.nixosTest {
            inherit name;

            nodes.machine =
              { lib, ... }:
              {
                imports = [ node ];

                services.esdm = {
                  enable = true;
                  enableLinuxCompatServices = false;
                  package = esdm;
                };

                users.users.vmm = {
                  isSystemUser = true;
                  group = "vmm";
                  extraGroups = [ "kvm" ];
                  home = "/var/lib/vmm";
                  createHome = true;
                };
                users.groups.vmm = { };

                environment.systemPackages = [
                  esdm
                  pkgs.python3
                ];

                virtualisation = {
                  memorySize = 2048;
                  cores = 2;
                };
              };

            testScript = ''
              import time

              def serial_log(name):
                  return f"/var/lib/vmm/{name}.log"

              def start_vm(name, cmd):
                  sock = f"/run/esdm-vhost-user-rng/{name}.sock"
                  machine.succeed(f"systemctl start esdm-vhost-user-rng@{name}.socket")
                  machine.succeed(f"test -S {sock}")
                  # The VMM user connects through the group of the socket
                  mode = machine.succeed(f"stat -c '%a %G' {sock}").strip()
                  assert mode == "660 kvm", f"{sock}: {mode}"
                  print(f"{name}: {cmd}")
                  machine.succeed(
                      f"systemd-run --unit=vm-{name} -p User=vmm -p Group=vmm -- {cmd}"
                  )

              def wait_ok(name):
                  try:
                      machine.wait_until_succeeds(
                          f"grep -a -q -e 'VURNG: OK' -e 'VURNG: FAIL' {serial_log(name)}", 600
                      )
                  except Exception:
                      # What the guest got to, and the VMM said
                      print(machine.execute(f"tail -c 4000 {serial_log(name)}")[1])
                      print(machine.execute(f"journalctl -b -u vm-{name} --no-pager")[1])
                      raise
                  # -a and tr: the serial port may put a stray byte that is
                  # no text before a line, and grep then holds back the line
                  out = machine.succeed(
                      f"grep -a VURNG: {serial_log(name)} | tr -cd '[:print:]\\n'"
                  )
                  print(out)
                  assert "VURNG: FAIL" not in out, f"{name} failed:\n{out}"
                  assert "VURNG: current: virtio_rng." in out, out
                  return out

              def loops(name):
                  out = machine.succeed(f"grep -a -c 'VURNG: loop' {serial_log(name)} || true")
                  return int(out.strip() or "0")

              def wait_loops(name, n, timeout=120):
                  machine.wait_until_succeeds(
                      f"[ $(grep -a -c 'VURNG: loop' {serial_log(name)}) -ge {n} ]", timeout
                  )

              esdm_units = "esdm-server-unpriv.socket esdm-server-priv.socket esdm-server.service"

              def stall_and_resume(name):
                  wait_loops(name, loops(name) + 2)
                  machine.succeed(f"systemctl stop {esdm_units}")
                  # A read under way when the ESDM went may still complete
                  time.sleep(3)
                  before = loops(name)
                  time.sleep(8)
                  after = loops(name)
                  assert after == before, \
                      f"{name} read {after - before} times without the ESDM"
                  machine.succeed(f"systemctl start {esdm_units}")
                  wait_loops(name, after + 2)

              def daemon_unprivileged(name):
                  user = machine.succeed(
                      f"systemctl show -P MainPID esdm-vhost-user-rng@{name}.service"
                      " | xargs ps -o user= -p"
                  ).strip()
                  assert user and user != "root", f"daemon of {name} runs as {user!r}"

              def hmp(name, *cmds):
                  return machine.succeed(
                      f"python3 ${hmp} /var/lib/vmm/{name}.mon " + " ".join(cmds)
                  )

              def others_refused(name):
                  machine.fail(
                      "setpriv --reuid=nobody --regid=nogroup --clear-groups "
                      f"python3 ${connect} /run/esdm-vhost-user-rng/{name}.sock"
                  )

              machine.wait_for_unit("multi-user.target")
              machine.wait_for_unit("esdm-server.service")
              machine.succeed("esdm-tool --wait-until-seeded 60")

              ${script}

              machine.succeed("systemctl stop 'vm-*'")
              machine.succeed("journalctl -b -u 'esdm-vhost-user-rng@*' --no-pager >&2")
              machine.fail("journalctl -b -u 'esdm-vhost-user-rng@*' | grep -q -e 'Not processing' -e 'Malformed'")
            '';
          };

        # QEMU's vhost-user-rng-pci on a q35 guest, under TCG - no nested KVM
        # needed. The chardev has no reconnect-ms: QEMU 11.1's vhost-user-rng
        # does not wait for a reconnecting chardev to connect before it talks
        # to the back-end, and fails at start up with it ("Failed to set msg
        # fds"), and its reconnect re-starts the vhost device it tore down
        # without setting it up again, which QEMU aborts on. So the check has
        # the next VM take over the daemon instead of the same one reconnect.
        mkVhostUserRngQemuCheck =
          let
            g = vhostUserRngGuest;
            qemu = "${pkgs.qemu_test}/bin/qemu-system-x86_64";
            cmd =
              log:
              lib.concatStringsSep " " [
                qemu
                "-machine q35,memory-backend=mem -accel tcg -cpu max -smp 1 -m 256M"
                "-object memory-backend-memfd,id=mem,size=256M,share=on"
                "-kernel ${g.kernel} -initrd ${g.initrd} -append '${g.cmdline}'"
                "-chardev socket,id=rng0,path=/run/esdm-vhost-user-rng/pci.sock"
                "-device vhost-user-rng-pci,chardev=rng0"
                "-nodefaults -no-user-config -display none -serial file:/var/lib/vmm/${log}.log"
                "-monitor unix:/var/lib/vmm/${log}.mon,server=on,wait=off"
              ];
          in
          mkVhostUserRngCheck {
            name = "vhost-user RNG with QEMU vhost-user-rng-pci";
            script = ''
              start_vm("pci", "${cmd "pci"}")
              wait_ok("pci")
              daemon_unprivileged("pci")
              others_refused("pci")

              with subtest("the guest waits for the ESDM"):
                  stall_and_resume("pci")

              # A stopped VM stops its vhost device - GET_VRING_BASE - and
              # cont starts it again, with new kick and call notifiers but
              # not a new err notifier: QEMU sets that once, at realize
              with subtest("the device serves again once the VM continues"):
                  wait_loops("pci", loops("pci") + 2)
                  hmp("pci", "stop")
                  time.sleep(3)
                  hmp("pci", "cont")
                  wait_loops("pci", loops("pci") + 3)

              with subtest("the daemon serves the next VM"):
                  machine.succeed("systemctl stop vm-pci")
                  machine.wait_until_succeeds(
                      "journalctl -b -u esdm-vhost-user-rng@pci.service"
                      " | grep -q 'Front-end disconnected'", 30
                  )
                  machine.succeed(
                      "systemd-run --unit=vm-pci-next -p User=vmm -p Group=vmm -- ${cmd "pci-next"}"
                  )
                  wait_ok("pci-next")
                  wait_loops("pci-next", 3)
            '';
          };

        # QEMU's microvm machine: virtio-mmio rather than PCI, the device as
        # vhost-user-rng on the virtio-mmio bus, under TCG. Twice: the legacy
        # virtio-mmio transport microvm defaults to, found through ACPI, and
        # the virtio 1.0 one, found through the kernel command line QEMU
        # extends with acpi=off.
        #
        # The guests get the TSC frequency on the command line. microvm's
        # ACPI is hardware-reduced, and Linux then sets up neither the PIT
        # nor the PIC as its tick: it has the TSC and the local APIC timer
        # only, and has to know the TSC frequency for both. microvm has no
        # HPET or ACPI PM timer to measure it against, and TCG no kvmclock,
        # which leaves polling the PIT - and that fails when TCG runs in a
        # busy VM ("tsc: Unable to calibrate against PIT"), with the guest
        # waiting for a jiffy that never comes. TCG's TSC is the one of the
        # test VM, so its frequency is the one the test VM's kernel found.
        mkVhostUserRngMicrovmCheck =
          let
            g = vhostUserRngGuest;
            qemu = "${pkgs.qemu_test}/bin/qemu-system-x86_64";
            cmd =
              name: machineOpts: extra:
              lib.concatStringsSep " " (
                [
                  qemu
                  "-machine microvm,memory-backend=mem${machineOpts} -accel tcg -cpu max -smp 1 -m 256M"
                  "-object memory-backend-memfd,id=mem,size=256M,share=on"
                ]
                ++ extra
                ++ [
                  "-kernel ${g.kernel} -initrd ${g.initrd} -append '${g.cmdline} tsc_early_khz={tsc_khz}'"
                  "-chardev socket,id=rng0,path=/run/esdm-vhost-user-rng/${name}.sock"
                  "-device vhost-user-rng,chardev=rng0"
                  "-nodefaults -no-user-config -display none -serial file:/var/lib/vmm/${name}.log"
                ]
              );
            legacy = cmd "mmio-legacy" "" [ ];
            modern = cmd "mmio-modern" ",acpi=off" [ "-global virtio-mmio.force-legacy=false" ];
          in
          mkVhostUserRngCheck {
            name = "vhost-user RNG with QEMU microvm";
            script = ''
              import re

              mhz = re.findall(
                  r"tsc: (?:Detected|Refined TSC clocksource calibration:) ([0-9.]+) MHz",
                  machine.succeed("dmesg"),
              )
              assert mhz, "the kernel of the test VM logged no TSC frequency"
              tsc_khz = int(float(mhz[-1]) * 1000)

              start_vm("mmio-legacy", f"${legacy}")
              start_vm("mmio-modern", f"${modern}")
              for name in ["mmio-legacy", "mmio-modern"]:
                  out = wait_ok(name)
                  assert "virtio-mmio" in out or "LNRO0005" in out, \
                      f"{name}: the device is not on virtio-mmio:\n{out}"
                  daemon_unprivileged(name)

              with subtest("the guests wait for the ESDM"):
                  stall_and_resume("mmio-modern")
                  wait_loops("mmio-legacy", loops("mmio-legacy") + 2)
            '';
          };

        # Cloud Hypervisor's generic vhost-user device. It needs KVM, so the VM
        # of the check needs nested virtualization: the host has to allow it
        # (kvm_amd/kvm_intel nested=1), the test VM passes the CPU on with
        # -cpu max. Cloud Hypervisor has an entropy device of its own besides,
        # on /dev/urandom of the VM; the guest unbinds it, keeping the
        # generic device at PCI slot 10.
        mkVhostUserRngChCheck =
          let
            g = vhostUserRngGuest;
            cmd = lib.concatStringsSep " " [
              "${pkgs.cloud-hypervisor}/bin/cloud-hypervisor"
              "--kernel ${g.kernel} --initramfs ${g.initrd}"
              "--cmdline '${g.cmdline} vurng_keep=0000:00:0a.0'"
              "--cpus boot=1 --memory size=256M,shared=on"
              "--generic-vhost-user 'socket=/run/esdm-vhost-user-rng/ch.sock,device_type=rng,queue_sizes=[256],pci_device_id=10'"
              "--serial file=/var/lib/vmm/ch.log --console off"
            ];
          in
          mkVhostUserRngCheck {
            name = "vhost-user RNG with Cloud Hypervisor";
            node = {
              boot.kernelModules = [
                "kvm-amd"
                "kvm-intel"
              ];
            };
            script = ''
              machine.succeed(
                  "test -c /dev/kvm || "
                  "{ echo 'no /dev/kvm in the VM: this check needs nested virtualization' >&2; false; }"
              )
              start_vm("ch", "${cmd}")
              out = wait_ok("ch")
              assert "unbound" in out, f"the built-in virtio-rng was not there:\n{out}"
              daemon_unprivileged("ch")

              with subtest("the guest waits for the ESDM"):
                  stall_and_resume("ch")

              with subtest("Cloud Hypervisor reconnects to a restarted daemon"):
                  machine.succeed("systemctl restart esdm-vhost-user-rng@ch.service")
                  wait_loops("ch", loops("ch") + 3)
            '';
          };

      in
      {
        # nix fmt
        formatter = pkgs.nixfmt-tree;

        # One check per defined kernel version, e.g.:
        #   nix run .#checks.x86_64-linux.live_6_18.driverInteractive
        #   nix flake check
        checks =
          lib.mapAttrs' (name: kernel: lib.nameValuePair "live_${name}" (mkCheck kernel)) kernels
          // lib.mapAttrs' (name: kernel: lib.nameValuePair "ebpf_${name}" (mkEbpfCheck kernel)) stockKernels
          // {
            # Only for the rolling kernel - see mkEbpfRawCheck on why this is
            # not instantiated per kernel version.
            ebpf_raw = mkEbpfRawCheck stockKernels.latest;

            # Not per kernel version either - see mkEgdCheck.
            egd_gnupg = mkEgdCheck;

            # Nor is the EGD OpenSSL provider kernel specific.
            egd_openssh = mkEgdOpensshCheck;

            # Nor the EGD protocol over the network - see mkEgdNetCheck.
            egd_net = mkEgdNetCheck;

            # Nor the external entropy sources on the network - see
            # mkEsExtNetCheck.
            es_ext_net = mkEsExtNetCheck;

            # The character device module, on the rolling kernel - see
            # mkEsdmCdevCheck.
            esdm_cdev = mkEsdmCdevCheck stockKernels.latest;

            # esdm-es-pkcs11 from its unit, read by esdm-server - see
            # mkPkcs11Check.
            pkcs11 = mkPkcs11Check;

            # The test suite in a build without fips140 - see esdm-plain.
            plain = self.packages.${system}.esdm-plain;
          }
          # The test suite on a 32-bit system - see esdm-i686.
          // lib.optionalAttrs (system == "x86_64-linux") {
            i686 = self.packages.${system}.esdm-i686;
            i686-openssl = self.packages.${system}.esdm-i686-openssl;

            # esdm-vhost-user-rng serving real guests, see
            # mkVhostUserRngCheck - the QEMU ones under TCG, Cloud
            # Hypervisor with nested KVM.
            vhost_user_rng_qemu = mkVhostUserRngQemuCheck;
            vhost_user_rng_microvm = mkVhostUserRngMicrovmCheck;
            vhost_user_rng_ch = mkVhostUserRngChCheck;
          };

        packages =
          let
            # The FIPS integrity self test (esdm/fips.c) attests every ESDM
            # executable, libesdm and the libraries of the module that are
            # loaded - the jitter RNG and the crypto backend - against a
            # reference HMAC in .<name>.hmac next to each file, which whoever
            # builds and installs the module provides. The key and format are
            # those of common/fips_integrity.c (fipscheck).
            #
            # A file is checked under the name it was loaded by, so a library
            # symlink needs a reference value of its own.
            fipsHmac = pkgs.writeShellScript "esdm-fips-hmac" ''
              for f in "$@"; do
                [ -f "$f" ] || continue
                hmac="$(${pkgs.openssl}/bin/openssl dgst -sha256 \
                  -hmac orboDeJITITejsirpADONivirpUkvarP -r "$f")"
                printf '%s\n' "''${hmac%% *}" \
                  >"$(dirname "$f")/.$(basename "$f").hmac"
              done
            '';

            # A dependency carrying reference values for its shared objects.
            # postFixup, as stripping and patchelf change the files before.
            withFipsHmac =
              pkg:
              pkg.overrideAttrs (prev: {
                postFixup = (prev.postFixup or "") + ''
                  # getAllOutputNames, as $outputs is no list of names
                  # with __structuredAttrs (botan3)
                  for o in $(getAllOutputNames); do
                    find "''${!o}" \( -type f -o -type l \) \
                      \( -name '*.so' -o -name '*.so.*' \) ! -name '*.hmac' \
                      -exec ${fipsHmac} {} +
                  done
                '';
              });

            # gcov occasionally emits a negative branch count for the Botan C++
            # backend (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=68080).
            # gcovr treats that as fatal and produces no report at all, so warn
            # once per affected file and keep the rest of the data.
            #
            # The same for counts gcovr finds suspiciously high (2^32 and up):
            # in the VMs booted with fips=1, every program runs the FIPS
            # integrity self test, which hashes the files of the module - so
            # the compression of crypto/sha256.c runs billions of times in one
            # suite, and gcovr 8 aborted on it with SuspiciousHits, leaving no
            # report. Such a line is counted as not executed, and named in the
            # warning.
            gcovrIgnoreParseErrors = lib.concatMapStringsSep " " (e: "--gcov-ignore-parse-errors ${e}") [
              "negative_hits.warn_once_per_file"
              "suspicious_hits.warn_once_per_file"
            ];

            # Turn one of the esdm packages above into a coverage build of
            # itself: instrument with gcov, run "meson test" and export the HTML
            # report as the derivation output.
            #
            #   nix build .#esdm-coverage
            #   xdg-open result/share/doc/esdm/coverage/index.html
            #
            # The tests run unprivileged inside the nix sandbox, so everything
            # needing root (CUSE device files, the RPC and getrandom frontends,
            # the esdm-server driven tests) is skipped and missing from the
            # report; see esdm-coverage-root and -vm for those.
            coverageOf =
              coveragePname: pkg:
              pkg.overrideAttrs (prev: {
              pname = coveragePname;

              nativeBuildInputs = prev.nativeBuildInputs ++ [
                pkgs.gcovr
              ];

              # Coverage needs unoptimized, unstripped objects without LTO: with
              # LTO the arc counters can no longer be attributed to source
              # lines. The address and undefined behaviour sanitizers run
              # alongside, so the same execution also decides whether the code
              # it covered was well defined. Both abort on the first finding
              # (see ASAN_OPTIONS / UBSAN_OPTIONS below), failing the test.
              mesonFlags =
                (builtins.filter (
                  x:
                  (!lib.hasInfix "b_lto" x)
                  && (!lib.hasInfix "b_sanitize" x)
                  && (!lib.hasInfix "optimization" x)
                  && (!lib.hasInfix "strip" x)
                  # replaced below
                  && (x != "-Des_kernel=disabled")
                  && (x != "-Des_jent_kernel=disabled")
                ) prev.mesonFlags)
                ++ [
                  "-Db_coverage=true"
                  "-Db_sanitize=address,undefined"
                  "-Db_lto=false"
                  "-Doptimization=0"
                  "-Dstrip=false"
                  # Several tests drive the ESDM through its test perturbation
                  # hooks and are compiled out without this.
                  "-Dtestmode=enabled"

                  # Every entropy source that can be compiled in. Most disable
                  # themselves at runtime for want of a TPM, a /dev/hwrng or a
                  # patched kernel, but their initialization, configuration
                  # and refusal paths are code like any other. The eBPF
                  # sources are left out on purpose - esdm-coverage-ebpf
                  # covers those, since enabling them changes the credited
                  # source. esdm-es-pkcs11 comes with the package already.
                  "-Des_kernel=enabled"
                  "-Des_jent_kernel=enabled"

                  # The default module of esdm-es-pkcs11: SoftHSM, which needs
                  # no hardware. Its tests take the SoftHSM next to the
                  # softhsm2-util on the path in any case, creating the tokens
                  # with it in a directory of their own.
                  "-Des_pkcs11_module_path=${pkgs.softhsm}/lib/softhsm/libsofthsm2.so"
                ];

              # es_jent_kernel reaches the kernel crypto API through libkcapi.
              # es_pkcs11 needs libp11, which is already among the inputs;
              # softhsm supplies the module esdm-es-pkcs11 is tested with plus
              # the softhsm2-util its tests create their tokens with.
              # ea_non_iid assesses the output's min-entropy.
              buildInputs = prev.buildInputs ++ [ self.packages.${system}.libkcapi ];
              nativeCheckInputs = (prev.nativeCheckInputs or [ ]) ++ [
                pkgs.softhsm
                pkgs.sp800-90b-entropyassessment
              ];

              mesonBuildType = "debug";
              dontStrip = true;
              separateDebugInfo = false;

              doCheck = true;
              checkPhase = ''
                runHook preCheck

                # The builder may be busy and is not necessarily fast - give the
                # tests that wait for entropy room before they time out.
                meson test --print-errorlogs --timeout-multiplier 5

                # Turn the .gcda files into the report. gcovr is driven directly
                # rather than through meson's coverage-html target, which offers
                # no way to pass excludes: the tests themselves, the out-of-tree
                # add-ons, esdm-tool's stress drivers and the generated libbpf
                # skeletons all stay out of the report.
                mkdir -p meson-logs/coveragereport
                gcovr \
                  --root .. \
                  --exclude '.*/tests/.*' \
                  --exclude '.*/addon/.*' \
                  --exclude '.*/frontends/tool/stress_.*' \
                  --exclude '.*\.skel\.h' \
                  --exclude-unreachable-branches \
                  ${gcovrIgnoreParseErrors} \
                  --html-details meson-logs/coveragereport/index.html \
                  --html-title 'ESDM ${prev.version} test coverage' \
                  --txt meson-logs/coveragereport/coverage.txt \
                  --print-summary

                runHook postCheck
              '';

              installPhase = ''
                runHook preInstall

                mkdir -p $out/share/doc/esdm/coverage
                cp -r meson-logs/coveragereport/. $out/share/doc/esdm/coverage/

                # Keep the test log next to the report: it records which tests
                # were skipped and therefore which parts of the tree the numbers
                # say nothing about.
                cp meson-logs/testlog.txt $out/share/doc/esdm/coverage/

                runHook postInstall
              '';

              # The output holds a report, not the programs - so there is no
              # esdm-server for the inherited FIPS integrity fixup to sign.
              postFixup = "";

              meta = prev.meta // {
                description = "HTML test coverage report of the ESDM meson test suite";
              };
            });

            # A coverage run packaged as a script instead of a sandboxed build,
            # so it can be started with root privileges:
            #
            #   sudo "$(nix build --no-link --print-out-paths .#esdm-coverage-root)/bin/esdm-coverage-run"
            #
            # As root the tests the sandbox has to skip do run, so the report
            # also covers the frontends and the RPC server. The script works in
            # a temporary directory of its own and never touches a checkout.
            coverageRunnerOf =
              {
                name,
                cov,
                extraRuntimeInputs ? [ ],
              }:
              let
                # Every output of every dependency, not just the one in
                # buildInputs: those carry a selected output (usually "dev") and
                # lib.getLib/getDev hand such a package back unchanged, while
                # headers and libraries live in different outputs - jitterentropy
                # is found with cc.find_library() and needs the shared object.
                deps = lib.concatMap (d: d.all or [ d ]) (
                  cov.buildInputs ++ cov.propagatedBuildInputs
                );
                pkgConfigPath = lib.concatStringsSep ":" (
                  lib.concatMap (d: [
                    "${d}/lib/pkgconfig"
                    "${d}/share/pkgconfig"
                  ]) deps
                );
                # The compiler wrapper is not driven by the stdenv setup hooks
                # here, so the search paths the buildInputs would contribute have
                # to be handed to it explicitly. It reads them from variables
                # carrying its own suffix salt - the unsalted names are what the
                # setup hooks consume, and are ignored by the wrapper itself.
                salt = pkgs.stdenv.cc.suffixSalt;
                cflags = lib.concatMapStringsSep " " (d: "-isystem ${d}/include") deps;
                ldflags = lib.concatMapStringsSep " " (d: "-L${d}/lib") deps;
              in
              pkgs.writeShellApplication {
                inherit name;
                # Order matters: the gcc wrapper has to come before anything that
                # also ships a "cc", or meson would configure the build around a
                # different compiler than the one gcov below is matched to.
                runtimeInputs = [
                  pkgs.meson
                  pkgs.ninja
                  pkgs.pkg-config
                  pkgs.gcovr
                  pkgs.stdenv.cc
                  pkgs.coreutils
                  pkgs.gnugrep
                  # for the "who holds the socket" hint of the preflight check
                  pkgs.iproute2
                  # pkill and umount for the cleanup of a failed run
                  pkgs.procps
                  pkgs.util-linux
                  # softhsm2-util, which the tests of esdm-es-pkcs11 create
                  # their tokens with - without it they skip the token part
                  pkgs.softhsm
                  # ea_non_iid for the output min-entropy test, which skips without it
                  pkgs.sp800-90b-entropyassessment
                ]
                ++ extraRuntimeInputs;
                text = ''
                  report_dir="''${1:-$PWD/esdm-coverage-report}"
                  shift || true

                  export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
                  export NIX_CFLAGS_COMPILE_${salt}="${cflags} ''${NIX_CFLAGS_COMPILE_${salt}:-}"
                  export NIX_LDFLAGS_${salt}="${ldflags} ''${NIX_LDFLAGS_${salt}:-}"

                  if [ "$(id -u)" -ne 0 ]; then
                    echo "esdm-coverage-run: not running as root - every test that"
                    echo "  needs an esdm-server, the CUSE device files or the kernel"
                    echo "  entropy interfaces will report itself as skipped, and the"
                    echo "  code behind it will show up as uncovered."
                    echo
                  fi

                  # A test mode ESDM binds these fixed paths, so a leftover one -
                  # or a second coverage run - owns them and this run's clients
                  # connect to it instead. Nothing fails outright, the tests just
                  # wait for their timeout, so say so up front instead.
                  stale=0
                  for sock in /tmp/esdm-rpc-unpriv-testmode.socket \
                              /tmp/esdm-rpc-priv-testmode.socket; do
                    if [ -e "$sock" ]; then
                      echo "esdm-coverage-run: $sock is already there:"
                      ss -xlp 2>/dev/null | grep -F "$sock" || \
                        echo "  (no listener - a stale socket file)"
                      stale=1
                    fi
                  done
                  if [ "$stale" -ne 0 ]; then
                    echo
                    echo "  The test suite binds those paths itself, so it cannot run"
                    echo "  next to whatever holds them. Stop that ESDM (or remove the"
                    echo "  stale files) and try again; set ESDM_COVERAGE_FORCE=1 to"
                    echo "  run anyway."
                    if [ "''${ESDM_COVERAGE_FORCE:-0}" != 1 ]; then
                      exit 1
                    fi
                    echo "  ESDM_COVERAGE_FORCE is set - continuing."
                    echo
                  fi

                  for dev in /dev/tst-random /dev/tst-urandom; do
                    if [ -e "$dev" ]; then
                      echo "esdm-coverage-run: warning: $dev is left over from an" \
                           "interrupted CUSE test run."
                    fi
                  done

                  # The ESDM status segment is a System V singleton keyed by a
                  # fixed ftok() value. One left behind by a root run denies an
                  # unprivileged run write access, and then every test that brings
                  # up an ESDM fails with esdm_init() = -13 - which reads like a
                  # code failure and is not one.
                  if [ "$(id -u)" -ne 0 ]; then
                    ipcs -m 2>/dev/null \
                      | awk '$1 ~ /^0x(6d|65)/ && $3 != "'"$(id -un)"'" {
                               print "esdm-coverage-run: warning: shared memory " \
                                     "segment " $1 " (id " $2 ") belongs to " $3 \
                                     " - ESDM tests will fail with -13 until it " \
                                     "is removed: sudo ipcrm -m " $2 }' || true
                  fi

                  work="$(mktemp -d -t esdm-coverage-XXXXXX)"

                  # shellcheck disable=SC2329  # run from the EXIT trap below
                  cleanup() {
                    # A failed CUSE or RPC test leaves its esdm-server and
                    # frontends holding the fixed socket paths and /dev bind
                    # mounts, which every later test would talk to instead. Match
                    # on the work directory in their command line, so only this
                    # run's processes are hit.
                    pkill -TERM -f "$work" 2>/dev/null || true
                    sleep 2
                    pkill -KILL -f "$work" 2>/dev/null || true

                    # The frontends unmount these themselves when they shut down
                    # cleanly; after a kill they are left behind.
                    if [ "$(id -u)" -eq 0 ]; then
                      for dev in /dev/tst-random /dev/tst-urandom; do
                        umount "$dev" 2>/dev/null || true
                      done
                    fi

                    # Stopping the daemons above is always right; deleting the
                    # evidence is not. A run that failed - or was interrupted
                    # before it wrote a report - is exactly the one whose build
                    # tree and test log are still needed, so keep it and say
                    # where. keep_work is cleared once the report is safely out.
                    if [ "''${keep_work:-1}" = 1 ]; then
                      echo
                      echo "esdm-coverage-run: build tree kept for inspection at" \
                           "$work"
                      echo "  test log: $work/build/meson-logs/testlog.txt"
                      echo "  remove it with: rm -rf $work"
                    else
                      rm -rf "$work"
                    fi
                  }
                  keep_work=1
                  trap cleanup EXIT

                  # The sources come out of the store read-only, and the build
                  # writes the coverage counters next to the objects.
                  cp -r --no-preserve=mode,ownership ${cov.src}/. "$work/source"

                  meson setup "$work/build" "$work/source" \
                    --buildtype=${cov.mesonBuildType} \
                    ${lib.escapeShellArgs cov.mesonFlags}
                  ninja -C "$work/build"

                  # The VM boots with fips=1, so every program of the suite
                  # runs the FIPS integrity self test - against reference
                  # values for the build tree, as fipsHmac provides them for
                  # an installation.
                  find "$work/build" ! -name '*.hmac' \( \
                    \( -type f -perm -u+x \) -o \
                    \( \( -type f -o -type l \) \
                       \( -name '*.so' -o -name '*.so.*' \) \) \
                    \) -exec ${fipsHmac} {} +

                  # The esdm-server and the CUSE frontends drop privileges, and
                  # libgcov writes their counters into the build tree as the
                  # dropped user. mktemp's 0700 root owned directory is not even
                  # traversable for them, so those counters would be lost with
                  # "Cannot create directory". Only needed as root, and the
                  # directory is a throwaway that is removed again on exit.
                  if [ "$(id -u)" -eq 0 ]; then
                    chmod -R a+rwX "$work"
                  fi

                  # The chmod above only covers what exists now; the .gcda files
                  # appear during the run. Created 0644 by a root process, the
                  # privilege-dropped ones cannot open them to merge their
                  # counters, so make them 0666 for the duration and the merge
                  # works in either order. The RPC sockets are unaffected - the
                  # server chmod()s them explicitly rather than using the umask.
                  old_umask="$(umask)"
                  if [ "$(id -u)" -eq 0 ]; then
                    umask 0000
                  fi

                  # A failing test still leaves usable counters behind, so the
                  # report is written either way and the failure is reported at
                  # the end.
                  test_status=0
                  meson test -C "$work/build" --print-errorlogs \
                    --timeout-multiplier 5 "$@" || test_status=$?

                  umask "$old_umask"

                  # Get the test log out first: it is the thing needed to explain
                  # a failure, and it must not be lost if the report generation
                  # below is what goes wrong.
                  mkdir -p "$report_dir" "$work/report"
                  cp "$work/build/meson-logs/testlog.txt" "$report_dir/" || true

                  # gcov ships with the compiler itself rather than with its
                  # wrapper, and has to be the one matching the compiler that
                  # produced the notes - so name it instead of searching $PATH.
                  #
                  # Its status is kept apart from the suite's: a failing gcovr
                  # must neither end the script before the status of the suite
                  # is out, nor be mistaken for a failed test.
                  report_status=0
                  gcovr \
                    --gcov-executable '${pkgs.stdenv.cc.cc}/bin/gcov' \
                    --root "$work/source" \
                    --exclude '.*/tests/.*' \
                    --exclude '.*/addon/.*' \
                    --exclude '.*/frontends/tool/stress_.*' \
                    --exclude '.*\.skel\.h' \
                    --exclude-unreachable-branches \
                    ${gcovrIgnoreParseErrors} \
                    --html-details "$work/report/index.html" \
                    --html-title 'ESDM ${cov.version} test coverage' \
                    --txt "$work/report/coverage.txt" \
                    --print-summary \
                    "$work/build" || report_status=$?

                  cp -r "$work/report/." "$report_dir/"
                  chmod -R u+w "$report_dir"
                  echo "$test_status" >"$report_dir/suite-status"
                  echo "$report_status" >"$report_dir/report-status"

                  echo
                  if [ "$report_status" -ne 0 ]; then
                    echo "WARNING: gcovr failed (exit $report_status) - no or" \
                         "only a partial report in $report_dir"
                  else
                    echo "Coverage report written to $report_dir/index.html"
                  fi
                  if [ "$test_status" -ne 0 ]; then
                    echo "WARNING: the test run failed (exit $test_status) - see" \
                         "$report_dir/testlog.txt"
                  elif [ "$report_status" -eq 0 ]; then
                    # Everything is out and every test passed - nothing left in
                    # the build tree that anybody would want to look at.
                    keep_work=0
                  fi
                  # The suite's status first; a run whose tests passed still
                  # fails without its report.
                  if [ "$test_status" -ne 0 ]; then
                    exit "$test_status"
                  fi
                  exit "$report_status"
                '';
              };

            # One of the runners above, started inside a VM instead of on the
            # developer's machine, with the report copied back out:
            #
            #   nix build .#esdm-coverage-vm
            #   xdg-open result/coverage/index.html
            #
            # That build fails when a test failed - see coverageVmResultOf.
            #
            # As root the run binds fixed socket paths, creates CUSE device
            # files, writes to the kernel entropy interfaces and leaves daemons
            # behind on failure - in a VM all of that is free of consequence.
            # The VM also carries the patched kernel and its esdm_es module,
            # without which the kernel entropy source disables itself.
            # A package rather than a check on purpose: a full build plus the
            # whole suite under ASan/UBSan in an emulated machine is not work
            # `nix flake check` should be doing.
            coverageVmOf =
              {
                name,
                runner,
                kernel,
                extraConfig ? { },
              }:
              pkgs.testers.nixosTest {
                inherit name;

                # A full build plus a sanitized run of the whole suite, emulated.
                # The default hour is not enough for that.
                globalTimeout = 4 * 60 * 60;

                nodes.machine =
                  { ... }:
                  {
                    imports = [
                      { _module.args.kernel = kernel; }
                      baseModule
                      (
                        { ... }:
                        {
                          # baseModule leaves the daemon disabled (startEsdm =
                          # false), which is what this needs: the suite brings up
                          # test mode ESDMs of its own on fixed socket paths, and
                          # the runner's preflight check refuses to start if a
                          # running server already holds them.

                          # The CUSE frontends reach their device files through
                          # /dev/cuse. Without the module they cannot start, and
                          # every test driving /dev/random through them skips.
                          boot.kernelModules = [ "cuse" ];

                          environment.systemPackages = [ runner ];

                          virtualisation = {
                            # A software TPM, so the TPM 2.0 entropy source has
                            # a /dev/tpmrm0 to talk to. Without one its test
                            # only covers what the source does when the device
                            # is absent, and the command exchange, the response
                            # parsing and the block cache in front of it stay
                            # unreached in the report.
                            tpm.enable = true;
                            # meson runs the suite in parallel, and several
                            # tests spend their time waiting for entropy rather
                            # than on the CPU - cores are what this is short of.
                            cores = 8;
                            # The sanitizer shadow map alongside a parallel run.
                            memorySize = 8192;
                            # The instrumented tree is unoptimized and unstripped
                            # and carries a coverage note next to every object.
                            # The image is sparse, so this is a ceiling rather
                            # than a cost.
                            diskSize = 30 * 1024;
                          };
                        }
                      )
                      extraConfig
                    ];
                  };

                testScript = ''
                  machine.wait_for_unit("multi-user.target")

                  # What the VM is here for. Checked up front: the run takes
                  # long enough that finding out from the report afterwards
                  # would be an expensive way to learn the module is missing.
                  machine.succeed("test -c /dev/esdm_es")

                  machine.succeed("mkdir -p /var/coverage")

                  # TMPDIR puts the build tree on the VM disk sized above; no
                  # timeout, as execute() defaults to 15 minutes and this is a
                  # full build.
                  status, _ = machine.execute(
                      "TMPDIR=/var/tmp ${lib.getExe runner} /var/coverage"
                      " > /var/coverage/coverage-run.log 2>&1",
                      timeout=None,
                  )

                  # A failed suite is recorded in the report rather than
                  # asserted on. A failing run is the one whose numbers and test
                  # log are wanted most - asserting here would fail the
                  # derivation, and nix discards $out of a failed build, so
                  # exactly those runs would come back empty. coverageVmResultOf
                  # turns the recorded status into the result instead. Which
                  # tests failed is in coverage/testlog.txt.
                  machine.succeed(f"echo {status} >/var/coverage/status")
                  machine.copy_from_machine("/var/coverage")

                  if status != 0:
                      print(
                          f"WARNING: the coverage suite failed (exit {status})"
                          " - see coverage/coverage-run.log and"
                          " coverage/testlog.txt in the output"
                      )
                '';
              };

            # The VM run above succeeds whatever the suite did, so that the
            # report of a failed suite is kept. This makes its status the
            # result: it fails when the suite failed - naming the failed tests
            # and the report of that run, which stays in the store - and links
            # the report otherwise. The run itself, failed or not, is
            #
            #   nix build .#esdm-coverage-vm.run
            coverageVmResultOf =
              run:
              pkgs.runCommand "${run.name}-result" { passthru = { inherit run; }; } ''
                status="$(cat ${run}/coverage/status)"
                if [ "$status" != 0 ]; then
                  echo "The coverage run as root failed (exit $status) - failed tests:"
                  grep -E '^ *[0-9]+/[0-9]+ .* (FAIL|TIMEOUT|ERROR) ' \
                    ${run}/coverage/coverage-run.log || true
                  report_status="$(cat ${run}/coverage/report-status 2>/dev/null || echo 0)"
                  if [ "$report_status" != 0 ]; then
                    echo "gcovr failed (exit $report_status), see coverage-run.log"
                  fi
                  echo "Report and test log of the run: ${run}/coverage"
                  exit 1
                fi
                mkdir -p $out
                ln -s ${run}/coverage $out/coverage
              '';
          in
          {
          jitterentropy = pkgs.jitterentropy.overrideAttrs (_: {
            version = "3.8.0-pre";
            src = pkgs.fetchFromGitHub {
              owner = "smuellerDD";
              repo = "jitterentropy-library";
              rev = "4b90f5bfaa6cdb60617a22089f09e12d082cc69c";
              hash = "sha256-evEeuo0ZigYh+IivbR+xNGPJHvPcGYdhzWoFnRtSUAs=";
            };
            patches = [ ];
            cmakeFlags = [
              "-DINTERNAL_TIMER=OFF"
              "-DBUILD_SHARED_LIBS=ON"
            ];
          });

          # libkcapi master: its RNG tests are adjusted to kernels 7.2+, after
          # the 1.5.1 that nixpkgs ships
          libkcapi = pkgs.libkcapi.overrideAttrs (_: {
            version = "1.5.1-unstable-2026-09-19";
            src = pkgs.fetchFromGitHub {
              owner = "smuellerDD";
              repo = "libkcapi";
              rev = "6af53720de505aef4a104d2ce80d1aee5beab3e6";
              hash = "sha256-CQzXxvYo/eb5onIliNxkJQOFiiWszkXP/myhh19T65w=";
            };
          });

          # this currently defaults to the botan crypto backend
          esdm =
            (pkgs.esdm.override {
              selinux = false;
              esSched = true;
              esSchedEntropyRate = 0;
              esCPU = true;
              esCPUEntropyRate = 0;
              esIRQ = true;
              esIRQEntropyRate = 0;
              esHwrand = true;
              esHwrandEntropyRate = 0;
              esKernel = false;
              fips140 = true;
              # remove later, for testing with NTG.1 capable jitterentropy
              jitterentropy = withFipsHmac self.packages.${system}.jitterentropy;
              botan3 = withFipsHmac pkgs.botan3;
            }).overrideAttrs
              (prev: {
                buildInputs = prev.buildInputs ++ [
                  pkgs.libp11
                  pkgs.json_c
                ];
                mesonFlags =
                  # nixpkgs still knows the combined 'ais2031' option, which
                  # this tree split into 'ais2031_ntg1' and 'ais2031_drg4';
                  # drop the flag it passes and set the successors below.
                  # Its es_jent_osr default is replaced below as well, so
                  # that only one value reaches meson.
                  (builtins.filter (
                    x:
                    (!lib.hasInfix "max_threads" x)
                    && (!lib.hasInfix "term-on-signal" x)
                    && (!lib.hasInfix "ais2031" x)
                    && (!lib.hasInfix "es_jent_osr" x)
                  ) prev.mesonFlags)
                  ++ lib.optionals debugEsdm [
                    "-Db_sanitize=address,undefined"
                    "-Dstrip=false"
                  ]
                  ++ [
                    "-Des_jent_osr=4"
                    "-Dbotan_drng_type=chacha20"
                    "-Dais2031_ntg1=false"
                    "-Dais2031_drg4=false"
                    # Opportunistic DTLS of the RPC and external entropy
                    # source connections, by the TLS stack of Botan
                    "-Ddtls=enabled"
                    # esdm-es-pkcs11, the PKCS#11 entropy source - a provider
                    # of its own, the only part of the ESDM linking libp11 -
                    # with its systemd unit. It needs a --module, as no
                    # default is built in. See mkPkcs11Check.
                    "-Des_pkcs11=enabled"
                    # The vhost-user back-end of a virtio entropy device
                    "-Dvhost-user-rng=enabled"
                    # The EGD protocol over the network, its TLS mode by
                    # Botan as well
                    "-Degd-net=enabled"
                    # esdm-cdev-check, the checks of the esdm_cdev kernel
                    # module, which the VM of mkEsdmCdevCheck runs
                    "-Desdm-cdev-check=enabled"
                    # External entropy sources on the network: the provider
                    # server on SCTP with DTLS and certificates, and
                    # esdm-es-ext-relay. See mkEsExtNetCheck.
                    "-Des-ext-net=enabled"
                  ];
                mesonBuildType = if debugEsdm then "debug" else "release";
                doCheck = false;
                src = lib.cleanSource ./.;
                # Keep the derivation version in sync with the local tree
                # (parsed from meson.build) instead of inheriting nixpkgs'
                # pinned version, which produced misleading esdm-1.2.3 store
                # paths and modinfo for a 1.2.4 checkout.
                version =
                  let
                    lines = lib.splitString "\n" (builtins.readFile ./meson.build);
                    matches = builtins.filter (m: m != null) (
                      map (l: builtins.match "[[:space:]]*version: '([0-9.]+)',?[[:space:]]*" l) lines
                    );
                  in
                  builtins.head (builtins.head matches);
                dontStrip = debugEsdm;
                # Every program and library, not only esdm-server as nixpkgs
                # signs it - see fipsHmac.
                postFixup = ''
                  find $out/bin \( -type f -o -type l \) ! -name '*.hmac' \
                    -exec ${fipsHmac} {} +
                  find $out/lib -maxdepth 1 \( -type f -o -type l \) \
                    \( -name '*.so' -o -name '*.so.*' \) ! -name '*.hmac' \
                    -exec ${fipsHmac} {} +
                '';
              });

          # ESDM with the eBPF-based scheduler and interrupt entropy sources
          # (plus the raw measurement tooling). The eBPF programs only use
          # UAPI headers, so no kernel BTF is needed at build time.
          esdm-ebpf = self.packages.${system}.esdm.overrideAttrs (prev: {
            buildInputs = prev.buildInputs ++ [ pkgs.libbpf ];
            nativeBuildInputs = prev.nativeBuildInputs ++ [
              pkgs.clang
              pkgs.bpftools
            ];
            mesonFlags = prev.mesonFlags ++ [
              "-Des_sched_ebpf=enabled"
              "-Des_irq_ebpf=enabled"
              "-Des_ebpf_testing=enabled"
              "-Des_sched_ebpf_entropy_rate=256"
              "-Des_sched_ebpf_osr=3"
              "-Des_ebpf_testing=enabled"
              "-Dvalidation-helpers=enabled"
            ];
          });


          # ESDM under the German AIS 20/31 3.0 (2024) regime: the NTG.1 seeding
          # strategy and the DRG.4 reseeding limits. Both are off in the package
          # above, so the code behind them - the two-source seeding decision of
          # esdm_es_mgr.c and the capped reseed thresholds of esdm_drng_mgr.c -
          # is compiled out there and cannot be covered.
          #
          # FIPS needs nothing here: fips140 is already set on the base package,
          # and the VM boots with fips=1 (see baseModule), so
          # /proc/sys/crypto/fips_enabled makes fips_enabled() answer true for
          # everything this runs.
          #
          # NTG.1 wants two entropy sources delivering 240 bits each. The base
          # package zeroes the rates of the scheduler, CPU, interrupt and
          # hwrand sources, which leaves the jitter RNG and - through the
          # coverage build's -Des_jent_kernel=enabled - its kernel counterpart
          # as the two that qualify at 256 bits. Should that ever stop being
          # enough, es_jent_ntg1 makes a 3.7.0+ jitter RNG NTG.1 conformant on
          # its own (the jitterentropy pinned above is a 3.8.0 prerelease)
          # and one source then suffices.
          esdm-ais2031 = self.packages.${system}.esdm.overrideAttrs (prev: {
            mesonFlags =
              (builtins.filter (x: !lib.hasInfix "ais2031" x) prev.mesonFlags)
              ++ [
                "-Dais2031_ntg1=true"
                "-Dais2031_drg4=true"
              ];
          });


          # The ESDM without fips140 and sp80090c, running the meson test suite
          # as its check phase. The package above sets fips140, which implies
          # the full SP800-90C configuration - reseeding caps and oversampling
          # on, the entropy source buffers compiled out - as does every variant
          # built from it. This is the one that compiles and runs what a build
          # without those options does instead.
          esdm-plain = self.packages.${system}.esdm.overrideAttrs (prev: {
            pname = "esdm-plain";

            mesonFlags =
              (builtins.filter (
                x: (!lib.hasInfix "fips140" x) && (!lib.hasInfix "sp80090c" x)
              ) prev.mesonFlags)
              ++ [
                "-Dfips140=false"
                "-Dsp80090c=false"
                # Compiles in the test hooks the suite needs.
                "-Dtestmode=enabled"
              ];

            doCheck = true;
            # softhsm2-util for the tests of esdm-es-pkcs11, which skip their
            # token part without it
            nativeCheckInputs = (prev.nativeCheckInputs or [ ]) ++ [ pkgs.softhsm ];

            meta = prev.meta // {
              description = "ESDM built without fips140 and sp80090c, running the meson test suite";
            };
          });


          # The ESDM under the thread sanitizer, running the meson test suite
          # as its check phase: a race produces data rather than a failing
          # test, so the suite alone says nothing about one. A build of its
          # own - the sanitizer needs the whole program instrumented, and it
          # cannot be linked next to the address sanitizer of the coverage
          # build.
          esdm-tsan = self.packages.${system}.esdm.overrideAttrs (prev: {
            pname = "esdm-tsan";

            mesonFlags =
              (builtins.filter (
                x:
                (!lib.hasInfix "b_lto" x)
                && (!lib.hasInfix "b_sanitize" x)
                && (!lib.hasInfix "optimization" x)
                && (!lib.hasInfix "strip" x)
              ) prev.mesonFlags)
              ++ [
                "-Db_sanitize=thread"
                # The sanitizer needs to see the calls it instruments, and with
                # link time optimization it no longer does reliably.
                "-Db_lto=false"
                # Enough optimization to keep a 10x slower suite bearable,
                # little enough to keep the frames in a report nameable.
                "-Doptimization=1"
                "-Dstrip=false"
                # Compiles in the test perturbation hooks, and shortens the
                # worker intervals so the threads meet during a test.
                "-Dtestmode=enabled"
              ];

            mesonBuildType = "debug";
            dontStrip = true;
            separateDebugInfo = false;

            doCheck = true;
            # softhsm2-util for the tests of esdm-es-pkcs11, see esdm-plain
            nativeCheckInputs = (prev.nativeCheckInputs or [ ]) ++ [ pkgs.softhsm ];
            checkPhase = ''
              runHook preCheck

              # Report every race of a run rather than only the first (the
              # exit code 66 fails the test), with both sides of a lock order
              # inversion.
              export TSAN_OPTIONS="halt_on_error=0 second_deadlock_stack=1 history_size=7"

              # The sanitizer costs an order of magnitude in run time. The
              # reports are collected from the full log afterwards, as
              # --print-errorlogs only shows the tail of a failing test.
              if ! meson test --print-errorlogs --timeout-multiplier 10; then
                echo
                echo "=== every ThreadSanitizer report of this run ==="
                awk '/^WARNING: ThreadSanitizer/,/^SUMMARY: ThreadSanitizer/' \
                  meson-logs/testlog.txt
                exit 1
              fi

              runHook postCheck
            '';

            # The suite's log next to the binaries it ran.
            postInstall = (prev.postInstall or "") + ''
              mkdir -p $out/share/doc/esdm
              cp meson-logs/testlog.txt $out/share/doc/esdm/tsan-testlog.txt
            '';

            meta = prev.meta // {
              description = "ESDM built with the thread sanitizer, running the meson test suite";
            };
          });

          esdm-coverage = coverageOf "esdm-coverage" self.packages.${system}.esdm;

          # The same, for the build carrying the eBPF entropy sources. A separate
          # report rather than more flags on the one above, because enabling them
          # changes which source is credited (es_sched_ebpf_entropy_rate against
          # a zeroed es_sched), so the numbers should not be pooled. The eBPF
          # programs themselves are not instrumented - clang builds them via a
          # custom_target that meson's b_coverage never reaches - so what the
          # report adds is the userspace side.
          esdm-coverage-ebpf =
            coverageOf "esdm-coverage-ebpf" self.packages.${system}.esdm-ebpf;

          # Likewise its own report rather than more flags on the default one:
          # NTG.1 changes when a DRNG counts as fully seeded and DRG.4 changes
          # how often it reseeds, so the two runs do not exercise the same
          # state machine and their numbers should not be pooled.
          esdm-coverage-ais2031 =
            coverageOf "esdm-coverage-ais2031" self.packages.${system}.esdm-ais2031;


          esdm-coverage-root = coverageRunnerOf {
            name = "esdm-coverage-run";
            cov = self.packages.${system}.esdm-coverage;
          };

          # clang and bpftool are only build time tools of the eBPF variant, so
          # they have to be on the path of the script that does the building -
          # esdm/es/ebpf/meson.build looks both of them up with find_program().
          esdm-coverage-ebpf-root = coverageRunnerOf {
            name = "esdm-coverage-ebpf-run";
            cov = self.packages.${system}.esdm-coverage-ebpf;
            extraRuntimeInputs = [
              pkgs.clang
              pkgs.bpftools
            ];
          };

          esdm-coverage-ais2031-root = coverageRunnerOf {
            name = "esdm-coverage-ais2031-run";
            cov = self.packages.${system}.esdm-coverage-ais2031;
          };

          # The runners above in a VM of their own - see coverageVmOf.
          # Tracking the rolling kernel for the same reason liveIso does: a
          # specific versioned attribute is one nixpkgs bump away from being
          # dropped.
          esdm-coverage-vm = coverageVmResultOf (coverageVmOf {
            name = "esdm coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-root;
            kernel = kernels.latest;
          });

          # The AIS 20/31 build on the patched kernel: NTG.1 counts entropy
          # sources, so it wants the kernel ones present rather than disabling
          # themselves for want of /dev/esdm_es.
          esdm-coverage-vm-ais2031 = coverageVmResultOf (coverageVmOf {
            name = "esdm AIS 20/31 coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-ais2031-root;
            kernel = kernels.latest;
          });

          # Unlike the ebpf_* checks - where running on a stock kernel is the
          # point, as needing no kernel patches is what the eBPF sources are
          # for - this one takes the patched kernel as well. The eBPF sources
          # are only part of what it covers, and es_kernel next to them needs
          # the module like it does in the run above.
          esdm-coverage-vm-ebpf = coverageVmResultOf (coverageVmOf {
            name = "esdm eBPF coverage run as root in a VM";
            runner = self.packages.${system}.esdm-coverage-ebpf-root;
            kernel = kernels.latest;
            extraConfig =
              { lib, ... }:
              {
                # See mkEbpfCheck: the test framework pins clocksource=acpi_pm,
                # which has no vDSO, so the eBPF sources' high resolution timer
                # probe fails and disables both of them before they ever load -
                # leaving the code this variant exists to cover unexecuted.
                boot.kernelParams = lib.mkAfter [ "clocksource=tsc" ];
              };
          });

          openssl-config =
            let
              esdm = self.packages.${system}.esdm;
            in
            pkgs.writeTextFile {
              name = "openssl.cnf";
              text = ''
                HOME                    = .
                RANDFILE                = $ENV::HOME/.rnd

                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect

                [provider_sect]
                esdm = esdm_sect
                default = default_sect

                [default_sect]
                activate = 1

                [esdm_sect]
                activate = 1
                module = ${esdm}/lib/libesdm-rng-provider.so
              '';
            };

          openssl-config-pr =
            let
              esdm = self.packages.${system}.esdm;
            in
            pkgs.writeTextFile {
              name = "openssl.cnf";
              text = ''
                HOME                    = .
                RANDFILE                = $ENV::HOME/.rnd

                openssl_conf = openssl_init

                [openssl_init]
                providers = provider_sect

                [provider_sect]
                esdm = esdm_sect
                default = default_sect

                [default_sect]
                activate = 1

                [esdm_sect]
                activate = 1
                module = ${esdm}/lib/libesdm-rng-provider-pr.so
              '';
            };

        }
        # One out-of-tree esdm_es module build per defined kernel, e.g.
        # esdm_es_6_6 / esdm_es_latest, with the warnings of W=1 as errors.
        # These carry the debugfs testing interfaces, so they stay compiled
        # on every kernel; the module the checks and live systems load comes
        # from the kernel package set and leaves them out.
        // lib.mapAttrs' (
          name: kernel:
          lib.nameValuePair "esdm_es_${name}" (
            pkgs.callPackage ./kernel/esdm_es {
              inherit (pkgs) lib;
              inherit (kernel) kernel;
              enableTesting = true;
              werror = true;
            }
          )
        ) kernels
        # One esdm_cdev module build per defined kernel, e.g. esdm_cdev_6_1 /
        # esdm_cdev_latest, with the warnings of W=1 as errors. Against the
        # stock kernels: the module needs no kernel patches.
        // lib.mapAttrs' (
          name: kernel:
          lib.nameValuePair "esdm_cdev_${name}" (
            pkgs.callPackage ./kernel/esdm_cdev {
              inherit (pkgs) lib;
              inherit (kernel) kernel;
              werror = true;
            }
          )
        ) stockKernels
        # The ESDM on a 32-bit system, running the meson test suite as its

        # check phase: size_t and long are 32 bits wide there, which none of
        # the packages above sees. The builtin backend, as the Hash DRBG and
        # the other builtin primitives are where the tree computes limits and
        # alignments itself.
        // lib.optionalAttrs (system == "x86_64-linux") {
          esdm-i686 =
            let
              p32 = pkgs.pkgsi686Linux;
              jitterentropy = p32.jitterentropy.overrideAttrs (_: {
                inherit (self.packages.${system}.jitterentropy)
                  version
                  src
                  patches
                  cmakeFlags
                  ;
              });
            in
            (p32.esdm.override {
              inherit jitterentropy;
              selinux = false;
              openSSLRandProvider = false;
              ais2031 = false;
              sp80090c = false;
            }).overrideAttrs
              (prev: {
                pname = "esdm-i686";
                inherit (self.packages.${system}.esdm) src version;
                # botan3 is the backend nixpkgs builds with, not needed here
                buildInputs = [
                  jitterentropy
                  p32.fuse3
                  p32.json_c
                ];
                mesonFlags =
                  (builtins.filter (
                    x:
                    (!lib.hasInfix "crypto_backend" x)
                    && (!lib.hasInfix "max_threads" x)
                    && (!lib.hasInfix "term-on-signal" x)
                    && (!lib.hasInfix "ais2031" x)
                    # The builtin backend has no TLS stack for the DTLS
                    && (x != "-Ddtls=enabled")
                  ) prev.mesonFlags)
                  ++ [
                    "-Dcrypto_backend=builtin"
                    "-Dais2031_ntg1=false"
                    "-Dais2031_drg4=false"
                    # Compiles in the test hooks the suite needs.
                    "-Dtestmode=enabled"
                    # Plain TCP only - the builtin backend has no TLS stack,
                    # which the auto_features=enabled of nixpkgs would ask for
                    "-Degd-net=enabled"
                    "-Degd-net-tls=disabled"
                  ];
                doCheck = true;
                meta = prev.meta // {
                  description = "ESDM built for i686, running the meson test suite";
                };
              });

          # The same with the OpenSSL backend, whose DRBG self test depends on
          # the nonce length it hands to OpenSSL.
          esdm-i686-openssl = self.packages.${system}.esdm-i686.overrideAttrs (prev: {
            pname = "esdm-i686-openssl";
            buildInputs = prev.buildInputs ++ [ pkgs.pkgsi686Linux.openssl ];
            mesonFlags =
              (builtins.filter (
                x: !lib.hasInfix "crypto_backend" x && x != "-Degd-net-tls=disabled"
              ) prev.mesonFlags)
              ++ [
                "-Dcrypto_backend=openssl"
                # The DTLS and the TLS of egd-net by OpenSSL, which the
                # builtin backend has not - and the DTLS over SCTP of the
                # external entropy sources on the network, whose tests skip
                # where the kernel of the build host has no SCTP
                "-Ddtls=enabled"
                "-Degd-net-tls=enabled"
                "-Des-ext-net=enabled"
              ];
            meta = prev.meta // {
              description = "ESDM built for i686 with the OpenSSL backend, running the meson test suite";
            };
          });

          # The documentation from its Typst sources in doc/typst: the
          # PlantUML figures are rendered here, the draw.io ones are taken
          # from their committed SVGs as drawio needs a display.
          #   nix build .#esdm-doc
          esdm-doc = pkgs.stdenvNoCC.mkDerivation {
            pname = "esdm-doc";
            version = "1.2.4";
            src = lib.fileset.toSource {
              root = ./doc/typst;
              fileset = ./doc/typst;
            };
            nativeBuildInputs = [
              pkgs.plantuml
              pkgs.typst
            ];
            buildPhase = ''
              runHook preBuild
              export HOME="$TMPDIR"
              export SOURCE_DATE_EPOCH="${toString self.lastModified}"
              export FONTCONFIG_FILE="${
                pkgs.makeFontsConf { fontDirectories = [ pkgs.liberation_ttf ]; }
              }"
              export TYPST_FONT_PATHS="${pkgs.liberation_ttf}/share/fonts"
              export TYPST_IGNORE_SYSTEM_FONTS=true
              SKIP_DRAWIO=1 OUT_DIR="$out/share/doc/esdm" bash ./build.sh
              runHook postBuild
            '';
            dontInstall = true;
          };
        };

        # One live system per defined kernel version, e.g. live_6_18. Only
        # collected here: nixosConfigurations is not a per system output, see
        # the end of this file.
        legacyPackages.liveSystems = lib.mapAttrs' (
          name: kernel:
          lib.nameValuePair "live_${name}" (mkLiveSystem {
            inherit (self.packages.${system}) esdm;
            inherit kernel;
          })
        ) kernels;

        # nix develop
        devShells = {
          default = pkgs.mkShell {
            buildInputs = with pkgs; [
              libp11
              botan3
              fuse3
              gnutls
              json_c
              libbpf
              libselinux
              openssl
              protobufc
              self.packages.${system}.jitterentropy
              self.packages.${system}.libkcapi
            ];
            nativeBuildInputs = with pkgs; [
              bpftools
              clang
              cmake
              meson
              ninja
              pkg-config
            ];
            packages = with pkgs; [
              bpftop
              bpftools
              bpftrace
              # softhsm2-util for the tests of esdm-es-pkcs11
              softhsm
              sp800-90b-entropyassessment
            ];
          };
        };

        # shortcut for development - track the rolling "latest" kernel so this
        # does not break when nixpkgs drops a specific versioned attribute.
        liveIso = self.nixosConfigurations."live_latest-${system}".config.system.build.isoImage;
      }
    )
    // {
      # nix expects nixosConfigurations.<name>, without a system level in
      # between, so the live systems of every system share one attribute set
      # with the system in the name, e.g. live_6_18-x86_64-linux.
      nixosConfigurations = nixpkgs.lib.concatMapAttrs (
        system: legacyPackages:
        nixpkgs.lib.mapAttrs' (
          name: nixpkgs.lib.nameValuePair "${name}-${system}"
        ) legacyPackages.liveSystems
      ) self.legacyPackages;
    };
}
