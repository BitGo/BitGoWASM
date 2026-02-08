/**
 * Versioned Transaction Building from Raw MessageV0 Data.
 *
 * This module provides `buildFromVersionedData` for building versioned transactions
 * from pre-compiled MessageV0 data. This is used for:
 * - WalletConnect/Jupiter pre-compiled versioned transactions
 * - Custom transaction pass-through (customTx intent)
 *
 * Unlike the intent-based builder, this takes already-compiled instruction
 * data with account indexes, not high-level instructions.
 */

import { BuilderNamespace } from "./wasm/wasm_solana.js";
import { VersionedTransaction } from "./versioned.js";

// =============================================================================
// Address Lookup Table Types
// =============================================================================

/**
 * Address Lookup Table data for versioned transactions.
 *
 * ALTs allow transactions to reference more accounts than the legacy format
 * by storing account addresses in on-chain lookup tables.
 */
export interface AddressLookupTable {
  /** The lookup table account address (base58) */
  accountKey: string;
  /** Indices of writable accounts in the lookup table */
  writableIndexes: number[];
  /** Indices of readonly accounts in the lookup table */
  readonlyIndexes: number[];
}

// =============================================================================
// Raw Versioned Transaction Data Types
// =============================================================================

/**
 * A pre-compiled versioned instruction (uses indexes, not pubkeys).
 * This is the format used in MessageV0 transactions.
 */
export interface VersionedInstruction {
  /** Index into the account keys array for the program ID */
  programIdIndex: number;
  /** Indexes into the account keys array for instruction accounts */
  accountKeyIndexes: number[];
  /** Instruction data (base58 encoded) */
  data: string;
}

/**
 * Message header for versioned transactions.
 * Describes the structure of the account keys array.
 */
export interface MessageHeader {
  /** Number of required signatures */
  numRequiredSignatures: number;
  /** Number of readonly signed accounts */
  numReadonlySignedAccounts: number;
  /** Number of readonly unsigned accounts */
  numReadonlyUnsignedAccounts: number;
}

/**
 * Raw versioned transaction data for direct serialization.
 * This is used when we have pre-formed MessageV0 data that just needs to be serialized.
 * No instruction compilation is needed - just serialize the raw structure.
 */
export interface RawVersionedTransactionData {
  /** Static account keys (base58 encoded public keys) */
  staticAccountKeys: string[];
  /** Address lookup tables */
  addressLookupTables: AddressLookupTable[];
  /** Pre-compiled instructions with index-based account references */
  versionedInstructions: VersionedInstruction[];
  /** Message header */
  messageHeader: MessageHeader;
  /** Recent blockhash (base58) */
  recentBlockhash: string;
}

// =============================================================================
// buildFromVersionedData function
// =============================================================================

/**
 * Build a versioned transaction directly from raw MessageV0 data.
 *
 * This function is used for the `fromVersionedTransactionData()` path where we already
 * have pre-compiled versioned data (indexes + ALT refs). No instruction compilation
 * is needed - we just serialize the raw structure.
 *
 * @param data - Raw versioned transaction data
 * @returns A VersionedTransaction object that can be inspected, signed, and serialized
 * @throws Error if the data is invalid
 *
 * @example
 * ```typescript
 * import { buildFromVersionedData } from '@bitgo/wasm-solana';
 *
 * const tx = buildFromVersionedData({
 *   staticAccountKeys: ['pubkey1', 'pubkey2', ...],
 *   addressLookupTables: [
 *     { accountKey: 'altPubkey', writableIndexes: [0, 1], readonlyIndexes: [2] }
 *   ],
 *   versionedInstructions: [
 *     { programIdIndex: 0, accountKeyIndexes: [1, 2], data: 'base58EncodedData' }
 *   ],
 *   messageHeader: {
 *     numRequiredSignatures: 1,
 *     numReadonlySignedAccounts: 0,
 *     numReadonlyUnsignedAccounts: 3
 *   },
 *   recentBlockhash: 'blockhash'
 * });
 *
 * // Inspect, sign, and serialize
 * console.log(tx.feePayer);
 * tx.addSignature(signerPubkey, signature);
 * const txBytes = tx.toBytes();
 * ```
 */
export function buildFromVersionedData(data: RawVersionedTransactionData): VersionedTransaction {
  const wasm = BuilderNamespace.build_from_versioned_data(data);
  return VersionedTransaction.fromWasm(wasm);
}
