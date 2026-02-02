/**
 * PSBT signing utilities for descriptor wallets.
 * Moved from @bitgo/utxo-core.
 */
import { Psbt, BIP32 } from "../../index.js";
import type { BIP32Interface } from "../../bip32.js";
import { ECPair } from "../../ecpair.js";

/** These can be replaced when @bitgo/wasm-utxo is updated */
export type SignPsbtInputResult = { Schnorr: string[] } | { Ecdsa: string[] };
export type SignPsbtResult = {
  [inputIndex: number]: SignPsbtInputResult;
};

/**
 * @param signResult
 * @return the number of new signatures created by the signResult for a single input
 */
export function getNewSignatureCountForInput(signResult: SignPsbtInputResult): number {
  if ("Schnorr" in signResult) {
    return signResult.Schnorr.length;
  }
  if ("Ecdsa" in signResult) {
    return signResult.Ecdsa.length;
  }
  throw new Error(`Unknown signature type ${Object.keys(signResult).join(", ")}`);
}

/**
 * @param signResult
 * @return the number of new signatures created by the signResult
 */
export function getNewSignatureCount(signResult: SignPsbtResult): number {
  return Object.values(signResult).reduce(
    (sum, signatures) => sum + getNewSignatureCountForInput(signatures),
    0,
  );
}

type Key =
  | Uint8Array
  | BIP32Interface
  | BIP32
  | ECPair
  | { privateKey?: Uint8Array; toBase58?(): string };

/** Convenience function to sign a PSBT with a key */
export function signWithKey(psbt: Psbt, key: Key): SignPsbtResult {
  // Handle Uint8Array (raw private key)
  if (key instanceof Uint8Array) {
    return psbt.signWithPrv(key) as unknown as SignPsbtResult;
  }

  // Handle BIP32 wrapper class
  if (key instanceof BIP32) {
    return psbt.signAll(key.wasm) as unknown as SignPsbtResult;
  }

  // Handle ECPair wrapper class
  if (key instanceof ECPair) {
    return psbt.signAllWithEcpair(key.wasm) as unknown as SignPsbtResult;
  }

  // Handle objects with toBase58 (BIP32Interface from utxolib)
  if ("toBase58" in key && typeof key.toBase58 === "function") {
    return psbt.signWithXprv(key.toBase58()) as unknown as SignPsbtResult;
  }

  // Handle objects with privateKey (ECPairInterface)
  if ("privateKey" in key && key.privateKey) {
    return psbt.signWithPrv(key.privateKey) as unknown as SignPsbtResult;
  }

  throw new Error("Invalid key type for signing");
}
