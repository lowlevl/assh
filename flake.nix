{
  description = "A nix flake for `qube`";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix.url = "github:numtide/treefmt-nix";

    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = inputs @ {
    flake-parts,
    nixpkgs,
    treefmt-nix,
    fenix,
    self,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = ["x86_64-linux"];

      perSystem = {
        system,
        pkgs,
        ...
      }: let
        treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
      in {
        formatter = treefmt.config.build.wrapper;
        checks.formatting = treefmt.config.build.check;

        devShells.default = let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [fenix.overlays.default];
          };
        in
          pkgs.mkShell {
            buildInputs = let
              toolchain = pkgs.fenix.stable.withComponents [
                "cargo"
                "rustc"
                "clippy"
                "rustfmt"
                "rust-src"
                "rust-std"
                "rust-analyzer"
              ];
            in [toolchain];
          };
      };

      flake = {};
    };
}
