# integrationLocalRpc

Local regtest-node tests for `@bitgo/wasm-utxo`, modeled on
[`utxo-lib/test/integration_local_rpc`](https://github.com/BitGo/BitGoJS/tree/master/modules/utxo-lib/test/integration_local_rpc)
and the docker harness in
[`indexer-utxo/containers`](https://github.com/BitGo/indexer-utxo/tree/master/containers).

## Design

- Same AcidTest kitchen-sink withdrawal loop for every wasm-utxo coin (as many
  input/output script types as the coin permits), validated against a live
  regtest node via RPC.
- **Not run on CI.** Default `npm test` / `test:mocha` ignores this directory.
- When run locally, the generator spins up Docker (or a reachable node), runs
  the suite, and writes fixtures under `fixtures/<coin>/` for commit.

## Pearl notes

`pearld` is a walletless btcd fork:

- Mine with `generate` only (no `generatetoaddress`) — coinbases go to `--miningaddr`
- No wallet RPC; fund destinations by signing spends off-node with the known
  mining key (`pearlConstants.ts`, privkey `0x01`)
- Taproot-only; regtest uses CoinName `tpearlreg` (HRP `rprl`)
- Default image: `319156457634.dkr.ecr.us-west-2.amazonaws.com/pearl-fullnode:1.0.2`
  (override with `WASM_UTXO_PEARL_DOCKER_IMAGE`, e.g. local `prl-pearld:latest`)

### Apple Silicon / amd64 Docker

ZK-PoW mining in `pearld` **segfaults under amd64→arm64 Docker emulation**
(see `coins-sandbox/prl/prl_wasm_indexer_report.md`). On macOS arm64, use the
native binary from Pearl's GitHub release:

```bash
gh release download pearl-wallet-v1.0.0 \
  --repo pearl-research-labs/pearl \
  --pattern "go-binaries-darwin-arm64*" \
  --dir /tmp/pearl
tar -xzf /tmp/pearl/go-binaries-darwin-arm64-v1.0.2.tar.gz -C /tmp/pearl
```

## Commands

```bash
# Offline fixture checks (no Docker) — still local-only, not in default mocha
npm run test:integrationLocalRpc

# Native pearld (recommended on Apple Silicon)
WASM_UTXO_PEARLD_BIN=/path/to/pearld \
  WASM_UTXO_TESTS_LOG_DOCKER=1 \
  npm run test:integrationLocalRpc:generate

# Docker (linux/amd64 native hosts)
npm run test:integrationLocalRpc:generate

# Local docker image override
WASM_UTXO_PEARL_DOCKER_IMAGE=prl-pearld:latest npm run test:integrationLocalRpc:generate
```
