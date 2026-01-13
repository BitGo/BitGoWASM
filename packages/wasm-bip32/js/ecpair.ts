import { WasmECPair } from "./wasm/wasm_bip32.js";

/**
 * ECPairArg represents the various forms that ECPair keys can take
 * before being converted to a WasmECPair instance
 */
export type ECPairArg =
  /** Private key (32 bytes) or compressed public key (33 bytes) as Buffer/Uint8Array */
  | Uint8Array
  /** ECPair instance */
  | ECPair
  /** WasmECPair instance */
  | WasmECPair;

/**
 * ECPair interface for elliptic curve key pair operations
 */
export interface ECPairInterface {
  publicKey: Uint8Array;
  privateKey?: Uint8Array;
  toWIF(): string;
  sign?(messageHash: Uint8Array): Uint8Array;
  verify?(messageHash: Uint8Array, signature: Uint8Array): boolean;
  signMessage?(message: string): Uint8Array;
  verifyMessage?(message: string, signature: Uint8Array): boolean;
}

/**
 * ECPair wrapper class for elliptic curve key pair operations
 */
export class ECPair implements ECPairInterface {
  private constructor(private _wasm: WasmECPair) {}

  /**
   * Create an ECPair instance from a WasmECPair instance (internal use)
   * @internal
   */
  static fromWasm(wasm: WasmECPair): ECPair {
    return new ECPair(wasm);
  }

  /**
   * Convert ECPairArg to ECPair instance
   * @param key - The ECPair key in various formats
   * @returns ECPair instance
   */
  static from(key: ECPairArg): ECPair {
    // Short-circuit if already an ECPair instance
    if (key instanceof ECPair) {
      return key;
    }
    // If it's a WasmECPair instance, wrap it
    if (key instanceof WasmECPair) {
      return new ECPair(key);
    }
    // Parse from Buffer/Uint8Array
    // Check length to determine if it's a private key (32 bytes) or public key (33 bytes)
    if (key.length === 32) {
      const wasm = WasmECPair.from_private_key(key);
      return new ECPair(wasm);
    } else if (key.length === 33) {
      const wasm = WasmECPair.from_public_key(key);
      return new ECPair(wasm);
    } else {
      throw new Error(
        `Invalid key length: ${key.length}. Expected 32 bytes (private key) or 33 bytes (compressed public key)`,
      );
    }
  }

  /**
   * Create an ECPair from a private key (always uses compressed keys)
   * @param buffer - The 32-byte private key
   * @returns An ECPair instance
   */
  static fromPrivateKey(buffer: Uint8Array): ECPair {
    const wasm = WasmECPair.from_private_key(buffer);
    return new ECPair(wasm);
  }

  /**
   * Create an ECPair from a compressed public key
   * @param buffer - The compressed public key bytes (33 bytes)
   * @returns An ECPair instance
   */
  static fromPublicKey(buffer: Uint8Array): ECPair {
    const wasm = WasmECPair.from_public_key(buffer);
    return new ECPair(wasm);
  }

  /**
   * Create an ECPair from a WIF string (auto-detects network from WIF)
   * @param wifString - The WIF-encoded private key string
   * @returns An ECPair instance
   */
  static fromWIF(wifString: string): ECPair {
    const wasm = WasmECPair.from_wif(wifString);
    return new ECPair(wasm);
  }

  /**
   * Create an ECPair from a mainnet WIF string
   * @param wifString - The WIF-encoded private key string
   * @returns An ECPair instance
   */
  static fromWIFMainnet(wifString: string): ECPair {
    const wasm = WasmECPair.from_wif_mainnet(wifString);
    return new ECPair(wasm);
  }

  /**
   * Create an ECPair from a testnet WIF string
   * @param wifString - The WIF-encoded private key string
   * @returns An ECPair instance
   */
  static fromWIFTestnet(wifString: string): ECPair {
    const wasm = WasmECPair.from_wif_testnet(wifString);
    return new ECPair(wasm);
  }

  /**
   * Get the private key as a Uint8Array (if available)
   */
  get privateKey(): Uint8Array | undefined {
    return this._wasm.private_key;
  }

  /**
   * Get the public key as a Uint8Array
   */
  get publicKey(): Uint8Array {
    return this._wasm.public_key;
  }

  /**
   * Convert to WIF string (mainnet)
   * @returns The WIF-encoded private key
   */
  toWIF(): string {
    return this._wasm.to_wif();
  }

  /**
   * Convert to mainnet WIF string
   * @returns The WIF-encoded private key
   */
  toWIFMainnet(): string {
    return this._wasm.to_wif_mainnet();
  }

  /**
   * Convert to testnet WIF string
   * @returns The WIF-encoded private key
   */
  toWIFTestnet(): string {
    return this._wasm.to_wif_testnet();
  }

  /**
   * Sign a 32-byte message hash (raw ECDSA)
   * @param messageHash - The 32-byte message hash to sign
   * @returns The signature as a Uint8Array
   */
  sign(messageHash: Uint8Array): Uint8Array {
    return this._wasm.sign(messageHash);
  }

  /**
   * Verify a signature against a 32-byte message hash (raw ECDSA)
   * @param messageHash - The 32-byte message hash
   * @param signature - The signature to verify
   * @returns True if the signature is valid
   */
  verify(messageHash: Uint8Array, signature: Uint8Array): boolean {
    return this._wasm.verify(messageHash, signature);
  }

  /**
   * Sign a message using Bitcoin message signing (BIP-137)
   * @param message - The message to sign
   * @returns 65-byte signature (1-byte header + 64-byte signature)
   */
  signMessage(message: string): Uint8Array {
    return new Uint8Array(this._wasm.sign_message(message));
  }

  /**
   * Verify a Bitcoin message signature (BIP-137)
   * @param message - The message that was signed
   * @param signature - 65-byte signature (1-byte header + 64-byte signature)
   * @returns True if the signature is valid for this key
   */
  verifyMessage(message: string, signature: Uint8Array): boolean {
    return this._wasm.verify_message(message, signature);
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmECPair {
    return this._wasm;
  }
}
