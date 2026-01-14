# wasm-solana

WASM bindings for Solana cryptographic operations. This package provides Rust-based bindings for Ed25519 keypair generation, public key operations, and signature verification for Solana.

## Building

### Mac

Requires Homebrew LLVM (Apple's Clang doesn't support WASM targets):

```bash
brew install llvm
npm run build
```

### Docker (optional)

If you prefer a containerized build environment:

```bash
make -f Container.mk build-image
make -f Container.mk build-wasm
```
