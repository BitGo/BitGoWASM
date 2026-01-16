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
   * Get the signable message payload (what gets signed)
   * This is the serialized message that signers sign
   * @returns The message bytes
   */
  signablePayload(): Uint8Array {
    return this._wasm.signable_payload();
  }

  /**
   * Serialize the transaction to bytes
   * @returns The serialized transaction bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
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
   * Get all signatures as byte arrays
   * @returns Array of signature byte arrays
   */
  signatures(): Uint8Array[] {
    return Array.from(this._wasm.signatures()) as Uint8Array[];
  }

  /**
   * Get all instructions in the transaction
   * @returns Array of instructions with programId, accounts, and data
   */
  instructions(): Instruction[] {
    const rawInstructions = this._wasm.instructions();
    return Array.from(rawInstructions) as Instruction[];
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
