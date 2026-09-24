# wasm-solana

WASM bindings for Solana cryptographic operations. This package provides Rust-based bindings for Ed25519 keypair generation, public key operations, and signature verification for Solana.

## Reviewing imported transactions

`StakeInitialize` parser results include the complete Stake Program lockup:
`unixTimestamp` and `epoch` are lossless `bigint` values, and `custodian` is
its base58 public key. The WebUI displays all three terms and warns whenever
the lockup differs from Solana's default.

For approval flows, parse and review a `Transaction` instance and use that
same instance's `signablePayload()` as the approval/signing message. Parsed
instructions are a semantic view; signing and serialization preserve the
original message bytes. This package does not implement an approval policy.

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
