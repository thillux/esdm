{
  lib,
  stdenv,
  kernel,
  kmod,
  esdm,
  # The debugfs raw entropy and performance interfaces (esdm_testing.c) are
  # for entropy assessments, nothing a regular system should carry.
  enableTesting ? false,
}:

stdenv.mkDerivation rec {
  pname = "esdm_es";

  # The release of the tree, parsed from meson.build like the flake's esdm
  # package does, so the two cannot drift apart again.
  version =
    let
      lines = lib.splitString "\n" (builtins.readFile ../../meson.build);
      matches = builtins.filter (m: m != null) (
        map (l: builtins.match "[[:space:]]*version: '([0-9.]+)',?[[:space:]]*" l) lines
      );
    in
    builtins.head (builtins.head matches);
  # The sources of the module and those it shares with the ESDM
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ./Makefile
      (lib.fileset.fileFilter (file: file.hasExt "c" || file.hasExt "h") ./.)
      ../shared
      ../../esdm/crypto/esdm_xdrbg.c
      ../../esdm/crypto/esdm_xdrbg.h
      ../../esdm/crypto/esdm_xof.h
      ../../common/esdm_portable.h
      ../../common/selftest_kat.h
    ];
  };
  sourceRoot = "${src.name}/kernel/esdm_es";

  preBuild = ''
    sed -i '/depmod/d' Makefile
  '';

  nativeBuildInputs = [ kmod ] ++ kernel.moduleBuildDependencies;

  makeFlags = [
    "KBUILD_OUTPUT=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "KERNELRELEASE=${kernel.modDirVersion}"
    "KERNEL_DIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    "INSTALL_MOD_PATH=${placeholder "out"}"
    "BUILD_TESTING=${if enableTesting then "1" else "0"}"
    "BUILD_ES_IRQ=1"
    "BUILD_ES_SCHED=1"
  ];
  installFlags = makeFlags;

  enableParallelBuilding = true;

  meta = with lib; {
    description = "A kernel module for esdm entropy gathering";
    homepage = "http://www.chronox.de/esdm.html";
    license = [
      licenses.gpl2Only
      licenses.bsd2
    ];
    maintainers = with maintainers; [ thillux ];
    platforms = platforms.linux;
    broken = versionOlder kernel.version "6.1";
  };
}
