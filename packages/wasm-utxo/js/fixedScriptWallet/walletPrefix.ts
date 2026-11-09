import { BIP32, type BIP32Arg } from "../bip32.js";
import type { Triple } from "../triple.js";
import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";
import { RootWalletKeys, type WalletKeysArg } from "./RootWalletKeys.js";

/**
 * The three wallet root keys in `[user, backup, bitgo]` order.
 *
 * Accepts everything {@link RootWalletKeys.from} accepts, plus a triple of any {@link BIP32Arg}
 * (xpub/xprv strings, `BIP32` instances, `BIP32Interface` objects). Private keys are neutered
 * before use: the result is the same for an xprv and the matching xpub.
 */
export type WalletPrefixKeysArg = WalletKeysArg | Triple<BIP32Arg>;

function toBIP32Triple(keys: WalletPrefixKeysArg): Triple<BIP32> {
  if (keys instanceof RootWalletKeys) {
    return [keys.userKey(), keys.backupKey(), keys.bitgoKey()];
  }
  if (Array.isArray(keys)) {
    return (keys as Triple<BIP32Arg>).map((key) => BIP32.from(key)) as Triple<BIP32>;
  }
  return keys.triple.map((key) => BIP32.from(key)) as Triple<BIP32>;
}

/**
 * Compute the `[h1, h2]` account indices of a wallet from its three root keys.
 *
 * ```
 * d  = sha256("BitGo/utxo/wallet-prefix/v1" || K_user || K_backup || K_bitgo)
 * K  = compressed public key (33 bytes) || chain code (32 bytes)    (of the neutered root key)
 * h1 = u32be(d[0..4]) & 0x7fffffff
 * h2 = u32be(d[4..8]) & 0x7fffffff
 * ```
 *
 * Both are valid non-hardened BIP32 indices (`0..=2^31-1`). The result depends on the key order
 * `[user, backup, bitgo]`. These are indices, not amounts, hence `number`.
 *
 * @param keys - The three wallet root keys `[user, backup, bitgo]`
 */
export function deriveWalletAccount(keys: WalletPrefixKeysArg): [number, number] {
  const [user, backup, bitgo] = toBIP32Triple(keys);
  const account = FixedScriptWalletNamespace.derive_wallet_account(
    user.wasm,
    backup.wasm,
    bitgo.wasm,
  );
  return [account[0], account[1]];
}

/**
 * Compute the relative per-wallet derivation prefix `44/<coinType>/<h1>/<h2>` (no leading `/` or
 * `m/`), see {@link deriveWalletAccount}. Addresses of a wallet using this prefix derive at
 * `<prefix>/<chain>/<index>` from each of the three root keys.
 *
 * @param keys - The three wallet root keys `[user, backup, bitgo]`
 * @param coinType - BIP44 coin type of the coin family, an integer in `0..=2^31-1`. wasm-utxo has
 *   no coin registry: the caller supplies it (e.g. `coin.bip44CoinType` from `@bitgo/statics`).
 * @throws a `WasmUtxoError` with code `WalletPrefixError.CoinTypeOutOfRange` if `coinType` is
 *   larger than `2^31-1`
 */
export function deriveWalletPrefix(keys: WalletPrefixKeysArg, coinType: number): string {
  // wasm-bindgen wraps numbers into u32, so reject what cannot be a u32 before it gets there;
  // values in (2^31-1, 2^32-1] are rejected by the Rust side with a typed error.
  if (!Number.isInteger(coinType) || coinType < 0 || coinType > 0xffffffff) {
    throw new RangeError(`coinType must be an integer in 0..=2^31-1, got ${coinType}`);
  }
  const [user, backup, bitgo] = toBIP32Triple(keys);
  return FixedScriptWalletNamespace.derive_wallet_prefix(
    user.wasm,
    backup.wasm,
    bitgo.wasm,
    coinType,
  );
}
