/**
 * Fixed mining keypair used with pearld `--miningaddr` (regtest).
 *
 * Matches indexer-utxo PearlTransactionSigner / docker-compose.develop-pearl.yml
 * so coinbase UTXOs are spendable with a known Taproot key-path key.
 */

/** Raw 32-byte Schnorr private key (NOT WIF). */
export const PEARL_MINING_PRIVKEY_HEX =
  "0000000000000000000000000000000000000000000000000000000000000001";

/** X-only pubkey for secp256k1 generator G (privkey 0x01). */
export const PEARL_MINING_XONLY_PUBKEY =
  "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/** BIP-341 tweaked output key for tr(PEARL_MINING_XONLY_PUBKEY) with empty tree. */
export const PEARL_MINING_TWEAKED_PUBKEY =
  "da4710964f7852695de2da025290e24af6d8c281de5a0b902b7135fd9fd74d21";

/** OP_1 <tweaked x-only pubkey> */
export const PEARL_MINING_TAPROOT_SCRIPT = "5120" + PEARL_MINING_TWEAKED_PUBKEY;

/**
 * bech32m(P2TR, HRP=rprl). Must match --miningaddr in regtestNode.ts /
 * indexer-utxo docker-compose.develop-pearl.yml.
 */
export const PEARL_MINING_REGTEST_ADDRESS =
  "rprl1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssgn706v";

/** Descriptor used for off-node key-path spends of mining UTXOs. */
export const PEARL_MINING_DESCRIPTOR = `tr(${PEARL_MINING_XONLY_PUBKEY})`;

/** Coin name used for sighash / addresses when talking to wasm-utxo (HRP `rprl`). */
export const PEARL_SIGN_COIN = "tpearlreg" as const;

/** Coinbase maturity + buffer before spending mining outputs. */
export const PEARL_MIN_HEIGHT = 101;

export const PEARL_FEE_SATOSHIS = 10_000n;
