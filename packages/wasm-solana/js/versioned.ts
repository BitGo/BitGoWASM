/**
 * Versioned Transaction Support
 *
 * Handles both legacy and versioned (MessageV0) Solana transactions.
 * Versioned transactions use Address Lookup Tables (ALTs) to compress
 * transaction size by referencing accounts via lookup table indices.
 */

import {
  WasmVersionedTransaction,
  is_versioned_transaction,
  BuilderNamespace,
} from "./wasm/wasm_solana.js";
import type { RawVersionedTransactionData } from "./builder.js";

/**
 * Address Lookup Table data extracted from versioned transactions.
 */
export interface AddressLookupTableData {
  /** The lookup table account address (base58) */
  accountKey: string;
  /** Indices of writable accounts in the lookup table */
  writableIndexes: Uint8Array;
  /** Indices of readonly accounts in the lookup table */
  readonlyIndexes: Uint8Array;
}

/**
 * Account metadata for instructions.
 */
export interface VersionedAccountMeta {
  /** Account index within the transaction */
  index: number;
  /** Account pubkey (only present for static accounts) */
  pubkey?: string;
  /** Whether this account is from an Address Lookup Table */
  isLookupTable: boolean;
  /** Whether this account is a signer */
  isSigner: boolean;
}

/**
 * Instruction from a versioned transaction.
 */
export interface VersionedInstruction {
  /** Program ID */
  programId: string;
  /** Accounts used by the instruction */
  accounts: VersionedAccountMeta[];
  /** Instruction data */
  data: Uint8Array;
}

/**
 * Detect if transaction bytes represent a versioned transaction (MessageV0).
 *
 * @param bytes - Raw transaction bytes
 * @returns true if versioned, false if legacy
 */
export function isVersionedTransaction(bytes: Uint8Array): boolean {
  return is_versioned_transaction(bytes);
}

/**
 * Versioned Transaction class.
 *
 * Handles both legacy and versioned (MessageV0) transactions.
 * Provides access to Address Lookup Table data for versioned transactions.
 */
export class VersionedTransaction {
  private inner: WasmVersionedTransaction;

  private constructor(inner: WasmVersionedTransaction) {
    this.inner = inner;
  }

  /**
   * Deserialize a transaction from raw bytes.
   * Automatically handles both legacy and versioned formats.
   */
  static fromBytes(bytes: Uint8Array): VersionedTransaction {
    return new VersionedTransaction(WasmVersionedTransaction.from_bytes(bytes));
  }

  /**
   * Create a VersionedTransaction from a WasmVersionedTransaction instance.
   * @internal Used by builder functions
   */
  static fromWasm(wasm: WasmVersionedTransaction): VersionedTransaction {
    return new VersionedTransaction(wasm);
  }

  /**
   * Create a versioned transaction from raw MessageV0 data.
   *
   * This is used for the `fromVersionedTransactionData()` path where we have
   * pre-compiled versioned data (indexes + ALT refs). No instruction compilation
   * is needed - this just constructs the transaction from the raw structure.
   *
   * @param data - Raw versioned transaction data
   * @returns A VersionedTransaction instance
   *
   * @example
   * ```typescript
   * const tx = VersionedTransaction.fromVersionedData({
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
   * ```
   */
  static fromVersionedData(data: RawVersionedTransactionData): VersionedTransaction {
    // Build the transaction using WASM and wrap in TypeScript class
    const wasm = BuilderNamespace.build_from_versioned_data(data);
    return VersionedTransaction.fromWasm(wasm);
  }

  /**
   * Check if this is a versioned transaction (MessageV0).
   */
  get isVersioned(): boolean {
    return this.inner.is_versioned;
  }

  /**
   * Get the fee payer address.
   */
  get feePayer(): string | undefined {
    return this.inner.fee_payer ?? undefined;
  }

  /**
   * Get the recent blockhash.
   */
  get recentBlockhash(): string {
    return this.inner.recent_blockhash;
  }

  /**
   * Get the number of instructions.
   */
  get numInstructions(): number {
    return this.inner.num_instructions;
  }

  /**
   * Get the number of signatures.
   */
  get numSignatures(): number {
    return this.inner.num_signatures;
  }

  /**
   * Get the transaction ID (first signature as base58).
   *
   * For Solana, the transaction ID is the first signature.
   * Returns "UNSIGNED" if the transaction has no valid signatures.
   */
  get id(): string {
    return this.inner.id;
  }

  /**
   * Get the signable message payload.
   */
  signablePayload(): Uint8Array {
    return this.inner.signable_payload();
  }

  /**
   * Serialize the message portion of the transaction.
   * Alias for signablePayload() - provides compatibility with @solana/web3.js API.
   * @returns The serialized message bytes
   */
  serializeMessage(): Uint8Array {
    return this.signablePayload();
  }

  /**
   * Serialize the transaction to bytes.
   */
  toBytes(): Uint8Array {
    return this.inner.to_bytes();
  }

  /**
   * Serialize to network broadcast format.
   * @returns The transaction as bytes ready for broadcast
   */
  toBroadcastFormat(): Uint8Array {
    return this.toBytes();
  }

  /**
   * Get static account keys (accounts stored directly in the message).
   * For versioned transactions, additional accounts may be referenced via ALTs.
   */
  staticAccountKeys(): string[] {
    return Array.from(this.inner.static_account_keys()) as string[];
  }

  /**
   * Get Address Lookup Table data.
   * Returns empty array for legacy transactions.
   */
  addressLookupTables(): AddressLookupTableData[] {
    const alts = this.inner.address_lookup_tables();
    return Array.from(alts).map((alt: AddressLookupTableData) => ({
      accountKey: alt.accountKey,
      writableIndexes: alt.writableIndexes,
      readonlyIndexes: alt.readonlyIndexes,
    }));
  }

  /**
   * Get all signatures as byte arrays.
   * Provides compatibility with @solana/web3.js Transaction.signatures API.
   */
  get signatures(): Uint8Array[] {
    return Array.from(this.inner.signatures()) as Uint8Array[];
  }

  /**
   * Add a signature for a given public key.
   *
   * @param pubkey - The public key as base58 string
   * @param signature - The 64-byte Ed25519 signature
   */
  addSignature(pubkey: string, signature: Uint8Array): void {
    this.inner.add_signature(pubkey, signature);
  }

  /**
   * Get the signer index for a public key.
   * Returns undefined if the pubkey is not a required signer.
   */
  signerIndex(pubkey: string): number | undefined {
    return this.inner.signer_index(pubkey) ?? undefined;
  }

  /**
   * Get all instructions.
   * Note: For versioned transactions, account indices may reference
   * accounts from Address Lookup Tables.
   */
  instructions(): VersionedInstruction[] {
    const instructions = this.inner.instructions();
    return Array.from(instructions) as VersionedInstruction[];
  }
}
