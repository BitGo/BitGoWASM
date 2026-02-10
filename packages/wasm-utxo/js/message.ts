/**
 * Bitcoin message signing and verification (BIP-137)
 *
 * This module provides functions for signing and verifying Bitcoin messages
 * using the standard Bitcoin Signed Message format (BIP-137).
 *
 * @example
 * ```typescript
 * import { message, ECPair } from '@bitgo/wasm-utxo';
 *
 * // Sign a message
 * const key = ECPair.fromWIF('L1TnU2zbNaAqMoVh65Cyvmcjzbrj41Gs9iTLcWbpJCpV1iNMXpuR');
 * const signature = message.signMessage('Hello, Bitcoin!', key);
 *
 * // Verify a message
 * const isValid = message.verifyMessage('Hello, Bitcoin!', key, signature);
 * ```
 */

import { MessageNamespace } from "./wasm/wasm_utxo.js";
import { ECPair, type ECPairArg } from "./ecpair.js";

/**
 * Sign a message using Bitcoin message signing (BIP-137)
 *
 * @param message - The message to sign
 * @param key - The key to sign with (must have a private key)
 * @returns 65-byte signature (1-byte header + 64-byte signature)
 */
export function signMessage(message: string, key: ECPairArg): Uint8Array {
  const ecpair = ECPair.from(key);
  return new Uint8Array(MessageNamespace.sign_message(ecpair.wasm, message));
}

/**
 * Verify a Bitcoin message signature (BIP-137)
 *
 * @param message - The message that was signed
 * @param key - The key to verify against
 * @param signature - 65-byte signature (1-byte header + 64-byte signature)
 * @returns True if the signature is valid for this key
 */
export function verifyMessage(message: string, key: ECPairArg, signature: Uint8Array): boolean {
  const ecpair = ECPair.from(key);
  return MessageNamespace.verify_message(ecpair.wasm, message, signature);
}
