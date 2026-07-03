# wasm-utxo-cli

A command-line interface for Bitcoin UTXO operations, built on top of the `wasm-utxo` library.

This CLI provides utilities for address encoding/decoding and PSBT inspection across multiple UTXO-based cryptocurrencies.

## Installation

### Building from source

```bash
cd cli
cargo build --release
```

The binary will be available at `target/release/wasm-utxo-cli`.

### Installing to system

```bash
cargo install --path .
```

## Usage

### Address Operations

#### Decode an address to output script (hex)

```bash
wasm-utxo-cli address decode <ADDRESS> [--network <NETWORK>]
```

**Examples:**

```bash
# Decode a Bitcoin P2PKH address
wasm-utxo-cli address decode 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
# Output: 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac

# Decode a Bitcoin SegWit address
wasm-utxo-cli address decode bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
# Output: 0014e8df018c7e326cc253faac7e46cdc51e68542c42

# Decode a testnet address
wasm-utxo-cli address decode tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx --network testnet
```

#### Encode an output script to an address

```bash
wasm-utxo-cli address encode <HEX_SCRIPT> [--network <NETWORK>]
```

**Examples:**

```bash
# Encode to Bitcoin address
wasm-utxo-cli address encode 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac
# Output: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

# Encode to Litecoin address
wasm-utxo-cli address encode 76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac --network litecoin
# Output: LUEweDxDA4WhvWiNXXSxjM9CYzHPJv4QQF

# Encode SegWit script
wasm-utxo-cli address encode 0014e8df018c7e326cc253faac7e46cdc51e68542c42
# Output: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
```

#### Derive an address from a descriptor

```bash
wasm-utxo-cli address from-descriptor <DESCRIPTOR> --network <NETWORK>
```

The descriptor may name a plain public key or embed a private key directly (e.g. a WIF) —
either way, the resulting address is derived from the corresponding public key. Works for any
network, not just Bitcoin.

**Examples:**

```bash
# BTC: derive a P2PKH address from a public key
wasm-utxo-cli address from-descriptor "pkh(039ab0771c5f88913208a26f81ab8223e98d25176e4648a5a2bb8ff79cf1c5198b)" --network btc
# Output: 1GwwqAWsJzDHMZ9ceJqrJDfch4gsro4c3x

# Zcash: derive a t-address directly from a WIF private key (e.g. for zebrad's miner_address on
# regtest — Zcash regtest reuses testnet address prefixes, so pass --network tzec)
wasm-utxo-cli address from-descriptor "pkh(KzEGYtKcbhYwUWcZygbsqmF31f3iV7HC3iUQug7MBecwCz9hm1Tv)" --network tzec
# Output: tmRfJALRQfyWP6SPxFTxiHhSHYhxn7rwkLv
```

### PSBT Operations

#### Parse and inspect a PSBT

```bash
wasm-utxo-cli psbt parse <FILE_PATH> [--no-color]
```

The parser supports multiple input formats:

- Raw binary PSBT files
- Base64-encoded PSBT strings
- Hex-encoded PSBT strings

**Examples:**

```bash
# Parse a PSBT from file
wasm-utxo-cli psbt parse transaction.psbt

# Parse from stdin (useful for piping)
echo "cHNidP8BA..." | wasm-utxo-cli psbt parse -

# Parse without color output
wasm-utxo-cli psbt parse transaction.psbt --no-color
```

The output displays a hierarchical tree view of the PSBT structure, including:

- Global fields (version, transaction, extended public keys)
- Per-input fields (UTXOs, signatures, scripts, derivation paths)
- Per-output fields (scripts, derivation paths)
- Decoded transaction details

### Supported Networks

The CLI supports the following networks (use with `--network` flag):

- **Bitcoin**: `bitcoin`, `btc` (default)
- **Bitcoin Testnet**: `testnet`, `test`, `testnet3`
- **Bitcoin Testnet4**: `testnet4`
- **Bitcoin Signet**: `signet`
- **Litecoin**: `litecoin`, `ltc`
- **Litecoin Testnet**: `litecointestnet`, `ltctest`
- **Bitcoin Cash**: `bitcoincash`, `bch`
- **Bitcoin Cash Testnet**: `bitcoincashtestnet`, `bchtest`
- **Bitcoin SV**: `bitcoinsv`, `bsv`
- **Bitcoin SV Testnet**: `bitcoinsvtestnet`, `bsvtest`
- **Bitcoin Gold**: `bitcoingold`, `btg`
- **Bitcoin Gold Testnet**: `bitcoingoldtestnet`, `btgtest`
- **Dash**: `dash`
- **Dash Testnet**: `dashtestnet`, `dashtest`
- **Zcash**: `zcash`, `zec`
- **Zcash Testnet**: `zcashtestnet`, `zectest`
- **Dogecoin**: `dogecoin`, `doge`
- **Dogecoin Testnet**: `dogecointestnet`, `dogetest`
- **eCash**: `ecash`, `xec`
- **eCash Testnet**: `ecashtestnet`, `xectest`

## Development

### Running tests

```bash
cargo test
```

### Building for production

```bash
cargo build --release
```

## License

Same license as the parent `wasm-utxo` crate.
