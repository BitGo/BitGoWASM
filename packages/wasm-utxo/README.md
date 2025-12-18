# wasm-utxo

This project is the successor of the Javascript `utxo-lib` package.

It provides WASM bindings for the `rust-bitcoin` and `rust-miniscript` crates
that help verify and co-sign transactions built by the BitGo Wallet Platform API.

## Documentation

- **[`src/wasm-bindgen.md`](src/wasm-bindgen.md)** - Guide for creating WASM bindings using the namespace pattern
- **[`js/README.md`](js/README.md)** - TypeScript wrapper layer architecture and best practices
- **[`cli/README.md`](cli/README.md)** - Command-line interface for address and PSBT operations

## Status

This project is under active development.

| Feature                                 | Bitcoin     | BitcoinCash | BitcoinGold | Dash        | Doge        | Litecoin    | Zcash       |
| --------------------------------------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- | ----------- |
| Descriptor Wallet: Address Support      | ✅ Complete | 🚫          | 🚫          | 🚫          | 🚫          | 🚫          | 🚫          |
| Descriptor Wallet: Transaction Support  | ✅ Complete | 🚫          | 🚫          | 🚫          | 🚫          | 🚫          | 🚫          |
| FixedScript Wallet: Address Generation  | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete | ✅ Complete |
| FixedScript Wallet: Transaction Support | ✅ Complete | ✅ Complete | ✅ Complete | ⏳ TODO     | ⏳ TODO     | ✅ Complete | ⏳ TODO     |

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
