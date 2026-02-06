import { WasmTransaction } from "./wasm/wasm_solana.js";
import { Pubkey } from "./pubkey.js";

/**
 * Account metadata for an instruction
 */
export interface AccountMeta {
  /** The account public key as a base58 string */
  pubkey: string;
  /** Whether this account is a signer */
  isSigner: boolean;
  /** Whether this account is writable */
  isWritable: boolean;
}

/**
 * A decoded Solana instruction
 */
export interface Instruction {
  /** The program ID (base58 string) that will execute this instruction */
  programId: string;
  /** The accounts required by this instruction */
  accounts: AccountMeta[];
  /** The instruction data */
  data: Uint8Array;
}

/**
 * Solana Transaction wrapper for low-level deserialization and inspection.
 *
 * This class provides low-level access to transaction structure.
 * For high-level semantic parsing with decoded instructions, use `parseTransaction()` instead.
 *
 * @example
 * ```typescript
 * import { Transaction, parseTransaction } from '@bitgo/wasm-solana';
 *
 * // Low-level access:
 * const tx = Transaction.fromBytes(txBytes);
 * console.log(tx.feePayer);
 *
 * // High-level parsing (preferred):
 * const parsed = parseTransaction(txBytes);
 * console.log(parsed.instructionsData); // Decoded instruction types
 * ```
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from raw bytes
   * @param bytes - The raw transaction bytes
   * @returns A Transaction instance
   */
  static fromBytes(bytes: Uint8Array): Transaction {
    const wasm = WasmTransaction.from_bytes(bytes);
    return new Transaction(wasm);
  }

  /**
   * Create a Transaction from a WasmTransaction instance.
   * @internal Used by builder functions
   */
  static fromWasm(wasm: WasmTransaction): Transaction {
    return new Transaction(wasm);
  }

  /**
   * Get the fee payer address as a base58 string
   * Returns null if there are no account keys (shouldn't happen for valid transactions)
   */
  get feePayer(): string | null {
    return this._wasm.fee_payer ?? null;
  }

  /**
   * Get the recent blockhash as a base58 string
   */
  get recentBlockhash(): string {
    return this._wasm.recent_blockhash;
  }

  /**
   * Get the number of signatures in the transaction
   */
  get numSignatures(): number {
    return this._wasm.num_signatures;
  }

  /**
   * Get the transaction ID (first signature as base58).
   *
   * For Solana, the transaction ID is the first signature.
   * Returns `undefined` if the transaction is unsigned (no signatures or all-zeros signature).
   *
   * @example
   * ```typescript
   * const tx = Transaction.fromBytes(txBytes);
   * tx.addSignature(pubkey, signature);
   * console.log(tx.id); // Base58 encoded signature
   * ```
   */
  get id(): string | undefined {
    return this._wasm.id;
  }

  /**
   * Get the signable message payload (what gets signed)
   * This is the serialized message that signers sign
   * @returns The message bytes
   */
  signablePayload(): Uint8Array {
    return this._wasm.signable_payload();
  }

  /**
   * Serialize the message portion of the transaction.
   * Alias for signablePayload() - provides compatibility with @solana/web3.js API.
   * Returns a Buffer for compatibility with code expecting .toString('base64').
   * @returns The serialized message bytes as a Buffer
   */
  serializeMessage(): Buffer {
    return Buffer.from(this.signablePayload());
  }

  /**
   * Serialize the transaction to bytes
   * @returns The serialized transaction bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Serialize to network broadcast format.
   * @returns The transaction as bytes ready for broadcast
   */
  toBroadcastFormat(): Uint8Array {
    return this.toBytes();
  }

  /**
   * Get all account keys as Pubkey instances
   * @returns Array of account public keys
   */
  accountKeys(): Pubkey[] {
    const keys = Array.from(this._wasm.account_keys()) as string[];
    return keys.map((k) => Pubkey.fromBase58(k));
  }

  /**
   * Get all signatures as byte arrays.
   * Provides compatibility with @solana/web3.js Transaction.signatures API.
   * @returns Array of signature byte arrays
   */
  get signatures(): Uint8Array[] {
    return Array.from(this._wasm.signatures()) as Uint8Array[];
  }

  /**
   * Get all signatures as byte arrays (method form).
   * Alias for the `signatures` property getter.
   * @returns Array of signature byte arrays
   */
  getSignatures(): Uint8Array[] {
    return this.signatures;
  }

  /**
   * Get all instructions in the transaction.
   * Returns an array with programId, accounts, and data for each instruction.
   *
   * Note: This is a getter property to provide compatibility with code
   * expecting @solana/web3.js Transaction.instructions API. If you need
   * to call this as a method, use `getInstructions()` instead.
   */
  get instructions(): Instruction[] {
    const rawInstructions = this._wasm.instructions();
    return Array.from(rawInstructions) as Instruction[];
  }

  /**
   * Get all instructions in the transaction (method form).
   * Alias for the `instructions` property getter.
   * @returns Array of instructions with programId, accounts, and data
   */
  getInstructions(): Instruction[] {
    return this.instructions;
  }

  /**
   * Add a signature for a given public key.
   *
   * The pubkey must be one of the required signers in the transaction.
   * The signature must be exactly 64 bytes (Ed25519 signature).
   *
   * @param pubkey - The public key as a base58 string
   * @param signature - The 64-byte signature as Uint8Array
   * @throws Error if pubkey is not a signer or signature is invalid
   *
   * @example
   * ```typescript
   * // Add a pre-computed signature (e.g., from TSS)
   * tx.addSignature(signerPubkey, signatureBytes);
   *
   * // Serialize and broadcast
   * const signedTxBytes = tx.toBytes();
   * ```
   */
  addSignature(pubkey: string, signature: Uint8Array): void {
    this._wasm.add_signature(pubkey, signature);
  }

  /**
   * Get the signer index for a public key.
   *
   * Returns the index in the signatures array where this pubkey's
   * signature should be placed, or null if the pubkey is not a signer.
   *
   * @param pubkey - The public key as a base58 string
   * @returns The signer index, or null if not a signer
   */
  signerIndex(pubkey: string): number | null {
    const idx = this._wasm.signer_index(pubkey);
    return idx ?? null;
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
