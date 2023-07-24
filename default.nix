let
    sources = import ./nix/sources.nix;
    pkgs = import sources.nixpkgs {};
in
pkgs.stdenv.mkDerivation {
  name = "esdm";
  src = ./.;

  buildInputs = with pkgs; [
    protobufc
    jitterentropy
    fuse3
    botan3
    openssl
  ];
  nativeBuildInputs = with pkgs; [
    meson
    pkg-config
    ninja
    cmake
  ];

  mesonFlags = [
    "-Dselinux=disabled"
    "-Db_lto=false"
  ];
}
