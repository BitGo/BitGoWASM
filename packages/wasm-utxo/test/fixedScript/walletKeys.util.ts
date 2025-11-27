import * as utxolib from "@bitgo/utxo-lib";
import type { Triple } from "../../js/triple.js";

/**
 * Convert utxolib BIP32 keys to WASM wallet keys format (Triple<string>)
 */
export function toWasmWalletKeys(
  keys: [utxolib.BIP32Interface, utxolib.BIP32Interface, utxolib.BIP32Interface],
): Triple<string> {
  return [
    keys[0].neutered().toBase58(),
    keys[1].neutered().toBase58(),
    keys[2].neutered().toBase58(),
  ];
}

/**
 * Get standard replay protection configuration
 */
export function getStandardReplayProtection(): { outputScripts: Uint8Array[] } {
  const replayProtectionScript = Buffer.from(
    "a91420b37094d82a513451ff0ccd9db23aba05bc5ef387",
    "hex",
  );
  return { outputScripts: [replayProtectionScript] };
}
