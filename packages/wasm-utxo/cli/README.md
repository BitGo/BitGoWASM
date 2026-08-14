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

#### Build and sign a transparent transaction

Four composable subcommands — `create`, `add-input`, `add-output`, `sign` — each read a PSBT
from a file or stdin (`-`) and print the result as hex, so they pipe together into a full
build-and-sign flow for a single-key transparent (non-segwit) transaction. Works for any
network; the sighash algorithm used by `sign` (plain, FORKID, or Zcash ZIP-243) is selected by
`--network`.

```bash
wasm-utxo-cli psbt create [--version <VERSION>] [--lock-time <LOCK_TIME>]
wasm-utxo-cli psbt add-input <PATH> --network <NETWORK> --txid <TXID> --vout <VOUT> \
  --value <VALUE> --script <SCRIPT_HEX> --descriptor <DESCRIPTOR> [--prev-tx <PREV_TX_HEX>]
wasm-utxo-cli psbt add-output <PATH> (--address <ADDRESS> --network <NETWORK> | --script <SCRIPT_HEX>) --value <VALUE>
wasm-utxo-cli psbt sign <PATH> --network <NETWORK> --privkey <PRIVKEY> [--consensus-branch-id <ID>]
```

`add-input` requires `--prev-tx` (the full previous transaction, hex-encoded) unless
`--network` is a value-committing network (Zcash, BCH family) whose sighash already commits the
spent amount — see `Network::requires_prev_tx_for_legacy_input` in the `wasm-utxo` library.

**Examples:**

```bash
# BTC: spend a P2PKH coinbase-style output, providing the full previous transaction
wasm-utxo-cli psbt create \
  | wasm-utxo-cli psbt add-input - --network btc \
      --txid e6a6e7f5551af932bc3813d920c52d61ec39fbad2e5585a018cce7dcbdd4ec72 --vout 0 \
      --value 50000000 --script 76a914aeee1e6ae364e64b1b36acd53df55bd8d750485888ac \
      --descriptor "pkh(039ab0771c5f88913208a26f81ab8223e98d25176e4648a5a2bb8ff79cf1c5198b)" \
      --prev-tx 010000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0180f0fa02000000001976a914aeee1e6ae364e64b1b36acd53df55bd8d750485888ac00000000 \
  | wasm-utxo-cli psbt add-output - --script 76a914aeee1e6ae364e64b1b36acd53df55bd8d750485888ac --value 49990000 \
  | wasm-utxo-cli psbt sign - --network btc --privkey KzEGYtKcbhYwUWcZygbsqmF31f3iV7HC3iUQug7MBecwCz9hm1Tv
# Output: a plain-sighash signed BTC transaction, hex-encoded

# Zcash: spend a transparent P2PKH coinbase output for regtest fixture generation
# (e.g. for a zebrad-mined UTXO to broadcast via sendrawtransaction). No --prev-tx needed —
# ZIP-243 sighash commits the input amount.
wasm-utxo-cli psbt create --lock-time 0 \
  | wasm-utxo-cli psbt add-input - --network tzec \
      --txid a8c685478265f4c14dada651969c45a65e1aeb8cd6791f2f5bb6a1d9952104d9 --vout 0 \
      --value 50000000 --script 76a914aeee1e6ae364e64b1b36acd53df55bd8d750485888ac \
      --descriptor "pkh(039ab0771c5f88913208a26f81ab8223e98d25176e4648a5a2bb8ff79cf1c5198b)" \
  | wasm-utxo-cli psbt add-output - --script 76a914aeee1e6ae364e64b1b36acd53df55bd8d750485888ac --value 49990000 \
  | wasm-utxo-cli psbt sign - --network tzec --privkey KzEGYtKcbhYwUWcZygbsqmF31f3iV7HC3iUQug7MBecwCz9hm1Tv \
      --consensus-branch-id 0xc2d6d0b4
# Output: a signed Zcash overwintered (NU5) transaction, hex-encoded
```

#### Build and sign a Zcash v6 (Ironwood) shielding transaction

Six composable subcommands — `create-zcash-v6`, `add-input`, `add-output`, `add-shielded-output`,
`sign-v6-input`, `combine-ironwood-proof` — each read a PSBT from a file or stdin (`-`) and print
the result as hex, so they pipe together into a full build-and-sign flow for a **transparent →
shielded** ("shielding") v6 transaction.

```bash
wasm-utxo-cli psbt create-zcash-v6 --network <NETWORK> --consensus-branch-id <ID> [--lock-time <LOCK_TIME>] [--expiry-height <HEIGHT>]
wasm-utxo-cli psbt add-input <PATH> --network <NETWORK> --txid <TXID> --vout <VOUT> --value <VALUE> --script <SCRIPT_HEX> --descriptor <DESCRIPTOR>
wasm-utxo-cli psbt add-output <PATH> (--address <ADDRESS> --network <NETWORK> | --script <SCRIPT_HEX>) --value <VALUE>
wasm-utxo-cli psbt add-shielded-output <PATH> --network <NETWORK> --recipient <HEX43> --value <ZATOSHI> --anchor <HEX32> [--ovk <HEX32>] [--memo <HEX512>]
wasm-utxo-cli psbt sign-v6-input <PATH> --network <NETWORK> --index <INDEX> --privkey <PRIVKEY>
wasm-utxo-cli psbt combine-ironwood-proof <PATH> --network <NETWORK> (--proof <HEX> | --local-proof)
```

`add-output` is optional (a fully-shielding transaction may spend its whole input to the shielded
output plus fee). `add-shielded-output` supports exactly one shielded output. `sign-v6-input` is
called once per required signature — each spent transparent input's redeem script must be a 2-of-3
CHECKMULTISIG script (BitGo's fixed-script wallet shape); a plain single-key (`pkh(...)`) input is
not supported on this path. `combine-ironwood-proof` either splices in a proof obtained from an
external prover (`--proof`) or produces one locally (`--local-proof`, heavier — builds a halo2
proving key and synthesizes the circuit).

**Example:**

```bash
# Zcash testnet: shield 1.9 TAZ from a 2-of-3 P2SH multisig transparent input into an
# Ironwood/Orchard note, leaving no transparent change (fee = input - shielded amount).
wasm-utxo-cli psbt create-zcash-v6 --network tzec --consensus-branch-id 0x37a5165b --expiry-height 4253200 \
  | wasm-utxo-cli psbt add-input - --network tzec \
      --txid 1ebd1da314f021d7c7b2ced6c0340067ebf3ce422bf8c53daa626d72cbd9fe73 --vout 1 \
      --value 2000000 --script a914ed68766fe37d9e2325758ed209ac78db505425a987 \
      --descriptor "sh(multi(2,023b4221b042fa25af6609d7e65d322fcb64c497b79ffc8f1891ea6b23d4e7d84a,02feaf8248a2f8dcc34f2e2f520201801bb88d20ab549baf47b48bc9f2f4dfcc93,030b82f01fd53e7dabe2d904938d64294e3352e9e836240af6ba2cfb9df8f837da))" \
  | wasm-utxo-cli psbt add-shielded-output - --network tzec \
      --recipient 4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d \
      --value 1900000 --anchor 179fa4ebcadd3006a14b0ea80380e6e14287e453fc468fa93c7f73c88f87b408 \
  | wasm-utxo-cli psbt sign-v6-input - --network tzec --index 0 --privkey cQ2ws3NRbFQVR3LUDxZoF1gvCHYM215QsiQ1gCHygJi1Jvdp1qzK \
  | wasm-utxo-cli psbt sign-v6-input - --network tzec --index 0 --privkey cU7jx2bsp3Vj3DDi2v9vFJLuU777M9TcpFFa6Ga9qkKBsT4vbJHf \
  | wasm-utxo-cli psbt combine-ironwood-proof - --network tzec --local-proof
# Output: a broadcast-ready Zcash v6 (Ironwood) transaction, hex-encoded. This exact command was
# submitted to a live Zcash testnet node and accepted into its mempool
# (txid aa7d9d9401cf70901cf76c81cab06e7001879607f60e1a2ffa4d4afa4a786238).
```

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
