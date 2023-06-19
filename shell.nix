{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    # nativeBuildInputs is usually what you want -- tools you need to run
    nativeBuildInputs = with pkgs; [ ninja meson pkgconfig cmake  ];
    buildInputs = with pkgs; [ protobufc fuse3 jitterentropy ];
}
