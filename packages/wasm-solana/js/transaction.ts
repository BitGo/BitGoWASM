import { WasmTransaction } from "./wasm/wasm_solana.js";

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
 * Solana Transaction wrapper for deserialization and inspection
 *
 * This class wraps a deserialized Solana transaction and provides
 * accessors for its components (instructions, signatures, etc.).
 */
export class Transaction {
  private constructor(private _wasm: WasmTransaction) {}

  /**
   * Deserialize a transaction from a base64-encoded string
   * This is the format used by @solana/web3.js Transaction.serialize()
   * @param base64 - The base64-encoded transaction
   * @returns A Transaction instance
   */
  static fromBase64(base64: string): Transaction {
    const wasm = WasmTransaction.from_base64(base64);
    return new Transaction(wasm);
  }

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
   * Get the number of instructions in the transaction
   */
  get numInstructions(): number {
    return this._wasm.num_instructions;
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
   * Serialize the transaction to base64
   * @returns The base64-encoded transaction
   */
  toBase64(): string {
    return this._wasm.to_base64();
  }

  /**
   * Get all account keys as an array of base58 strings
   * @returns Array of account public keys
   */
  accountKeys(): string[] {
    return Array.from(this._wasm.account_keys()) as string[];
  }

  /**
   * Get a signature at the given index as a base58 string
   * @param index - The signature index
   * @returns The signature as a base58 string, or null if index is out of bounds
   */
  signatureAt(index: number): string | null {
    return this._wasm.signature_at(index) ?? null;
  }

  /**
   * Get a signature at the given index as bytes
   * @param index - The signature index
   * @returns The signature bytes, or null if index is out of bounds
   */
  signatureBytesAt(index: number): Uint8Array | null {
    return this._wasm.signature_bytes_at(index) ?? null;
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
   * Get an instruction at the given index
   * @param index - The instruction index
   * @returns The instruction, or null if index is out of bounds
   */
  instructionAt(index: number): Instruction | null {
    const instr = this._wasm.instruction_at(index);
    return (instr as Instruction) ?? null;
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }
}
