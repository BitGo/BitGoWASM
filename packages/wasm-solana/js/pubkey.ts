import { WasmPubkey } from "./wasm/wasm_solana.js";

/**
 * Solana public key (address)
 *
 * A Solana address is a 32-byte Ed25519 public key, typically represented as a base58 string.
 */
export class Pubkey {
  private constructor(private _wasm: WasmPubkey) {}

  /**
   * Create a Pubkey from a base58 string
   * @param address - The base58-encoded address
   * @returns A Pubkey instance
   */
  static fromBase58(address: string): Pubkey {
    const wasm = WasmPubkey.from_base58(address);
    return new Pubkey(wasm);
  }

  /**
   * Create a Pubkey from raw bytes (32 bytes)
   * @param bytes - The 32-byte public key
   * @returns A Pubkey instance
   */
  static fromBytes(bytes: Uint8Array): Pubkey {
    const wasm = WasmPubkey.from_bytes(bytes);
    return new Pubkey(wasm);
  }

  /**
   * Convert to base58 string (the standard Solana address format)
   * @returns The address as a base58 string
   */
  toBase58(): string {
    return this._wasm.to_base58();
  }

  /**
   * Get as raw bytes (32 bytes)
   * @returns The public key as a Uint8Array
   */
  toBytes(): Uint8Array {
    return this._wasm.to_bytes();
  }

  /**
   * Check if two pubkeys are equal
   * @param other - The other Pubkey to compare
   * @returns true if the pubkeys are equal
   */
  equals(other: Pubkey): boolean {
    return this._wasm.equals(other._wasm);
  }

  /**
   * Check if this public key is on the Ed25519 curve.
   *
   * Regular Solana keypair addresses are on the curve, while Program Derived Addresses (PDAs)
   * are intentionally off the curve to ensure they can only be signed by programs.
   *
   * This is equivalent to `@solana/web3.js` `PublicKey.isOnCurve()`.
   *
   * @returns true if the public key is on the Ed25519 curve
   */
  isOnCurve(): boolean {
    return this._wasm.is_on_curve();
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmPubkey {
    return this._wasm;
  }
}
