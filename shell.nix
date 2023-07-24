let
    sources = import ./nix/sources.nix;
    pkgs = import sources.nixpkgs {};
in
pkgs.mkShell {
    buildInputs = with pkgs; [ esdm.buildInputs openssl_3 botan3 ];
    nativeBuildInputs = with pkgs; [ esdm.nativeBuildInputs cmake ];
}