import {
  zcashHasOrchardReceiver,
  zcashHasTransparentReceiver,
  zcashToShieldedReceiverWithCoin,
  zcashToTransparentReceiverWithCoin,
} from "./wasm/wasm_utxo.js";
import type { CoinName } from "./coinName.js";

/**
 * Convert `address` to its scriptPubKey bytes for `coin`'s network. When `address` is a ZIP-316
 * unified address, resolves its transparent receiver -- same as any other transparent address --
 * rather than rejecting the UA string outright. A UA with no transparent receiver (e.g.
 * Orchard-only) throws rather than falling back to a shielded one.
 *
 * `js/address.ts`'s `toOutputScriptWithCoin` dispatches here for zcash/tzec; call this directly
 * only if you already know `coin` is a Zcash coin.
 */
export function toTransparentReceiverWithCoin(address: string, coin: CoinName): Uint8Array {
  return zcashToTransparentReceiverWithCoin(address, coin);
}

/**
 * Resolve the Orchard/Ironwood receiver of a ZIP-316 unified address for `coin`'s network, as its
 * raw 43 bytes (diversifier + `pk_d`) -- there is no scriptPubKey for a shielded output, so this
 * returns raw receiver bytes rather than a scriptPubKey.
 *
 * `address` must be a unified address; an ordinary transparent address is rejected, since it can
 * never carry a shielded receiver. A UA that has no Orchard/Ironwood receiver (e.g. Sapling-only)
 * throws rather than falling back to the transparent receiver. If `address` merely looks like a
 * unified address for this coin's network (right Bech32m HRP) but is malformed, this also throws.
 * Use {@link toOutputScriptWithCoin} from `js/address.ts` for the transparent case.
 */
export function toShieldedReceiverWithCoin(address: string, coin: CoinName): Uint8Array {
  return zcashToShieldedReceiverWithCoin(address, coin);
}

/**
 * Whether `address` is a ZIP-316 unified address for `coin`'s network carrying an
 * Orchard/Ironwood receiver.
 *
 * A plain membership check, not a decoder: never throws. Returns `false` for a malformed or
 * wrong-network unified address, an ordinary (non-UA) address, or a UA with no Orchard/Ironwood
 * receiver (e.g. Sapling-only). Use {@link toShieldedReceiverWithCoin} when the raw receiver bytes
 * are needed.
 */
export function hasOrchardReceiver(address: string, coin: CoinName): boolean {
  return zcashHasOrchardReceiver(address, coin);
}

/**
 * Whether `address` has a usable transparent receiver for `coin`'s network: either `address` is
 * a ZIP-316 unified address carrying a transparent receiver, or `address` is itself an ordinary
 * transparent address that decodes for `coin`.
 *
 * A plain membership check, not a decoder: never throws. Returns `false` for a malformed or
 * wrong-network unified address, a UA with no transparent receiver (e.g. Orchard-only), or an
 * address that is neither a unified address nor a valid transparent address for `coin`. Use
 * {@link toOutputScriptWithCoin} from `js/address.ts` when the scriptPubKey bytes are needed.
 */
export function hasTransparentReceiver(address: string, coin: CoinName): boolean {
  return zcashHasTransparentReceiver(address, coin);
}
