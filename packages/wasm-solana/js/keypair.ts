import { WasmKeypair } from "./wasm/wasm_solana.js";

/**
 * Solana Ed25519 Keypair for address generation and signing
 *
 * A keypair consists of a 32-byte secret key and a 32-byte public key.
 * The public key (base58-encoded) is the Solana address.
 */
export class Keypair {
  private constructor(private _wasm: WasmKeypair) {}

  /**
   * Generate a new random keypair
   * @returns A new Keypair instance with randomly generated keys
   */
  static generate(): Keypair {
    const wasm = WasmKeypair.generate();
    return new Keypair(wasm);
  }

  /**
   * Create a keypair from a 32-byte secret key
   * @param secretKey - The 32-byte Ed25519 secret key
   * @returns A Keypair instance
   */
  static fromSecretKey(secretKey: Uint8Array): Keypair {
    const wasm = WasmKeypair.from_secret_key(secretKey);
    return new Keypair(wasm);
  }

  /**
   * Create a keypair from a 64-byte Solana secret key (secret + public concatenated)
   * This is the format used by @solana/web3.js Keypair.fromSecretKey()
   * @param secretKey - The 64-byte Solana secret key
   * @returns A Keypair instance
   */
  static fromSolanaSecretKey(secretKey: Uint8Array): Keypair {
    const wasm = WasmKeypair.from_solana_secret_key(secretKey);
    return new Keypair(wasm);
  }

  /**
   * Get the public key as a 32-byte Uint8Array
   */
  get publicKey(): Uint8Array {
    return this._wasm.public_key;
  }

  /**
   * Get the secret key as a 32-byte Uint8Array
   */
  get secretKey(): Uint8Array {
    return this._wasm.secret_key;
  }

  /**
   * Get the Solana address (base58-encoded public key)
   * @returns The address as a base58 string
   */
  getAddress(): string {
    return this._wasm.address();
  }

  /**
   * Get the public key as a base58 string
   * @returns The public key as a base58 string
   */
  toBase58(): string {
    return this._wasm.to_base58();
  }

  /**
   * Sign a message with this keypair
   * @param message - The message bytes to sign
   * @returns The 64-byte Ed25519 signature
   */
  sign(message: Uint8Array): Uint8Array {
    return this._wasm.sign(message);
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmKeypair {
    return this._wasm;
  }
}
