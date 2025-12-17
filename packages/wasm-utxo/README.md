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

If your system has problems with `wasm-pack` (Mac M1), you can use the `Container.mk` Makefile to build the wasm files:

```bash
cd packages/wasm-utxo
make -f Container.mk build-image
make -f Container.mk build-wasm
```
