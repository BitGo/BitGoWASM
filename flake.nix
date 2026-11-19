{
  description = "Development environment for BitGoWASM";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    nixpkgs-nodejs.url = "github:nixos/nixpkgs/1d4c88323ac36805d09657d13a5273aea1b34f0c";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    nixpkgs-nodejs,
    rust-overlay,
    ...
  }: let
    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-darwin"
      "x86_64-linux"
    ];
    forEachSystem = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forEachSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default];
      };
      rustToolchain = pkgs.rust-bin.nightly."2025-10-23".default.override {
        extensions = ["clippy" "rustfmt"];
        targets = ["wasm32-unknown-unknown"];
      };
    in {
      default = pkgs.mkShell {
        packages = [
          nixpkgs-nodejs.legacyPackages.${system}.nodejs_24
          rustToolchain
          pkgs.binaryen
          pkgs.gnumake
          pkgs.wasm-pack
        ];

        shellHook = ''
          export PATH="$(pwd)/node_modules/.bin:$PATH"
        '';
      };
    });
  };
}
