# wasm-solana

## Legacy transaction decoding

`Transaction.fromBytes()` accepts canonical, structurally valid legacy transaction
bytes up to Solana's 1232-byte packet limit. `signablePayload()` returns the
serialized Solana message; `toBytes()` preserves the transaction and signature
slots. The required signers are the first `numSignatures` entries of
`accountKeys()`, in the same order as `signatures`. Signature bytes are not
verified, and structural validity does not imply that a transaction can execute.

`parseTransaction(tx)` is a best-effort semantic decoder, not an admission or
complete review result. Unrecognized instructions are returned as `Unknown` with
their data and message-requested account roles; recognized decodings may also
have limitations. Callers must explicitly determine whether the transaction is
supported. A reference legacy native-payment vector and its regeneration
procedure are documented in `test/fixtures/README.md`.

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
