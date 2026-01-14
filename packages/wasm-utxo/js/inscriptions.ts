/**
 * Inscription support for Bitcoin Ordinals
 *
 * This module provides functionality for creating and signing inscription
 * reveal transactions following the Ordinals protocol.
 *
 * @see https://docs.ordinals.com/inscriptions.html
 */

import { InscriptionsNamespace } from "./wasm/wasm_utxo.js";
import { Transaction } from "./transaction.js";
import { type ECPairArg, ECPair } from "./ecpair.js";

/**
 * Taproot leaf script data needed for spending
 */
export type TapLeafScript = {
  /** Leaf version (typically 0xc0 for TapScript) */
  leafVersion: number;
  /** The compiled script bytes */
  script: Uint8Array;
  /** Control block for script path spending */
  controlBlock: Uint8Array;
};

/**
 * Prepared data for an inscription reveal transaction
 */
export type PreparedInscriptionRevealData = {
  /** The commit output script (P2TR, network-agnostic) */
  outputScript: Uint8Array;
  /** Estimated virtual size of the reveal transaction */
  revealTransactionVSize: number;
  /** Tap leaf script for spending the commit output */
  tapLeafScript: TapLeafScript;
};

/**
 * Create inscription reveal data including the commit output script and tap leaf script
 *
 * This function creates all the data needed to perform an inscription:
 * 1. A P2TR output script for the commit transaction (network-agnostic)
 * 2. The tap leaf script needed to spend from that output
 * 3. An estimate of the reveal transaction's virtual size for fee calculation
 *
 * @param key - The key pair (ECPairArg: Uint8Array, ECPair, or WasmECPair). The x-only public key will be extracted.
 * @param contentType - MIME type of the inscription (e.g., "text/plain", "image/png")
 * @param inscriptionData - The inscription data bytes
 * @returns PreparedInscriptionRevealData containing output script, vsize estimate, and tap leaf script
 *
 * @example
 * ```typescript
 * const revealData = createInscriptionRevealData(
 *   ecpair,
 *   "text/plain",
 *   new TextEncoder().encode("Hello, Ordinals!"),
 * );
 * // Use address.fromOutputScriptWithCoin() to get address for a specific network
 * console.log(`Estimated reveal vsize: ${revealData.revealTransactionVSize}`);
 * ```
 */
export function createInscriptionRevealData(
  key: ECPairArg,
  contentType: string,
  inscriptionData: Uint8Array,
): PreparedInscriptionRevealData {
  // Convert to ECPair and extract x-only public key (strip parity byte from compressed pubkey)
  const ecpair = ECPair.from(key);
  const compressedPubkey = ecpair.publicKey;
  const xOnlyPubkey = compressedPubkey.slice(1); // Remove first byte (parity)

  // Call snake_case WASM method (traits output camelCase)
  return InscriptionsNamespace.create_inscription_reveal_data(
    xOnlyPubkey,
    contentType,
    inscriptionData,
  ) as PreparedInscriptionRevealData;
}

/**
 * Sign a reveal transaction
 *
 * Creates and signs the reveal transaction that spends from the commit output
 * and sends the inscription to the recipient.
 *
 * @param key - The private key (ECPairArg: Uint8Array, ECPair, or WasmECPair)
 * @param tapLeafScript - The tap leaf script from createInscriptionRevealData
 * @param commitTx - The commit transaction
 * @param commitOutputScript - The commit output script (P2TR)
 * @param recipientOutputScript - Where to send the inscription (output script)
 * @param outputValueSats - Value in satoshis for the inscription output
 * @returns The signed transaction as bytes (ready to broadcast)
 *
 * @example
 * ```typescript
 * const txBytes = signRevealTransaction(
 *   privateKey,
 *   revealData.tapLeafScript,
 *   commitTx,
 *   revealData.outputScript,
 *   recipientOutputScript,
 *   10000n, // 10,000 sats
 * );
 * ```
 */
export function signRevealTransaction(
  key: ECPairArg,
  tapLeafScript: TapLeafScript,
  commitTx: Transaction,
  commitOutputScript: Uint8Array,
  recipientOutputScript: Uint8Array,
  outputValueSats: bigint,
): Uint8Array {
  // Convert to ECPair to get private key bytes
  const ecpair = ECPair.from(key);
  const privateKey = ecpair.privateKey;
  if (!privateKey) {
    throw new Error("ECPair must have a private key for signing");
  }

  // Call snake_case WASM method
  return InscriptionsNamespace.sign_reveal_transaction(
    privateKey,
    tapLeafScript,
    commitTx.wasm,
    commitOutputScript,
    recipientOutputScript,
    outputValueSats,
  );
}
