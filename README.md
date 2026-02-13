# BitGoWASM

This repo is the home of BitGo's WASM libraries.

# Dependencies

- [Rust](https://www.rust-lang.org/) nightly
- [wasm-pack](https://rustwasm.github.io/wasm-pack/) (install with `cargo install wasm-pack`)
- [Node.js](https://nodejs.org/en/)

# Developer Setup

```bash
npm install
```

This will:

- Install all dependencies
- Set up pre-commit hooks via Husky

Pre-commit hooks automatically run on staged files:

- **JS/TS**: Prettier formatting + ESLint
- **Rust**: `cargo fmt` + `cargo clippy`

# Package Management

This monorepo uses [Lerna](https://lerna.js.org/) for managing package versions and publishing to npm.

## Versioning

Packages use **independent versioning** with [Conventional Commits](https://www.conventionalcommits.org/) to automatically determine version bumps:

- `fix:` commits trigger patch releases (0.0.x)
- `feat:` commits trigger minor releases (0.x.0)
- `BREAKING CHANGE:` in commit body triggers major releases (x.0.0)

## Publishing

Publishing is automated via GitHub Actions when changes are pushed to `master` or `beta` branches. The workflow:

1. Builds all packages
2. Runs tests
3. Uses Lerna to analyze commits since last release
4. Automatically versions and publishes changed packages

To manually publish (if needed):

```bash
npx lerna publish
```

To see what would be published without actually publishing:

```bash
npx lerna changed
```

# Packages

## wasm-utxo

This is a wrapper around the
[rust-bitcoin](https://github.com/rust-bitcoin/rust-miniscript) and
[rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) crates that is
compiled to WebAssembly.

### wasm-utxo-web

A live playground for the wasm-utxo crate.

Go to https://bitgo.github.io/wasm-utxo to see a live demo of the wasm-utxo library in action. _WIP_
