{
  description = "BitGoWASM - WebAssembly libraries for BitGo";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        overlays = [(import rust-overlay)];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Use nightly Rust as specified in the README
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          targets = ["wasm32-unknown-unknown"];
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            # Rust toolchain (nightly with wasm support)
            rustToolchain
            pkgs.wasm-pack
            pkgs.binaryen # For wasm-opt used in the Makefile

            # Node.js (required dependency in README)
            pkgs.nodejs

            # Make (used in build scripts)
            pkgs.gnumake
          ];

          shellHook = ''
            echo "BitGoWASM development environment"
            echo "Rust: $(rustc --version)"
            echo "wasm-pack: $(wasm-pack --version)"
            echo "Node.js: $(node --version)"

            # Set PATH to include node_modules/.bin for lerna and other tools
            export PATH="$PWD/node_modules/.bin:$PATH"
          '';
        };
      }
    );
}
