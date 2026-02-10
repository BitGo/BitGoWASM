import { WasmBIP32 } from "./wasm/wasm_utxo.js";

/**
 * BIP32Arg represents the various forms that BIP32 keys can take
 * before being converted to a WasmBIP32 instance
 */
export type BIP32Arg =
  /** base58-encoded extended key string (xpub/xprv/tpub/tprv) */
  | string
  /** BIP32 instance */
  | BIP32
  /** WasmBIP32 instance */
  | WasmBIP32
  /** BIP32Interface compatible object */
  | BIP32Interface;

/**
 * BIP32 interface for extended key operations
 */
export interface BIP32Interface {
  chainCode: Uint8Array;
  depth: number;
  index: number;
  parentFingerprint: number;
  privateKey?: Uint8Array;
  publicKey: Uint8Array;
  identifier: Uint8Array;
  fingerprint: Uint8Array;
  isNeutered(): boolean;
  neutered(): BIP32Interface;
  toBase58(): string;
  toWIF(): string;
  derive(index: number): BIP32Interface;
  deriveHardened(index: number): BIP32Interface;
  derivePath(path: string): BIP32Interface;
}

/**
 * BIP32 wrapper class for extended key operations
 */
export class BIP32 implements BIP32Interface {
  private constructor(private _wasm: WasmBIP32) {}

  /**
   * Create a BIP32 instance from a WasmBIP32 instance (internal use)
   * @internal
   */
  static fromWasm(wasm: WasmBIP32): BIP32 {
    return new BIP32(wasm);
  }

  /**
   * Convert BIP32Arg to BIP32 instance
   * @param key - The BIP32 key in various formats
   * @returns BIP32 instance
   */
  static from(key: BIP32Arg): BIP32 {
    // Short-circuit if already a BIP32 instance
    if (key instanceof BIP32) {
      return key;
    }
    // If it's a WasmBIP32 instance, wrap it
    if (key instanceof WasmBIP32) {
      return new BIP32(key);
    }
    // If it's a string, parse from base58
    if (typeof key === "string") {
      const wasm = WasmBIP32.from_base58(key);
      return new BIP32(wasm);
    }
    // If it's an object (BIP32Interface), use from_bip32_interface
    if (typeof key === "object" && key !== null) {
      const wasm = WasmBIP32.from_bip32_interface(key);
      return new BIP32(wasm);
    }
    throw new Error("Invalid BIP32Arg type");
  }

  /**
   * Create a BIP32 key from a base58 string (xpub/xprv/tpub/tprv)
   * @param base58Str - The base58-encoded extended key string
   * @returns A BIP32 instance
   */
  static fromBase58(base58Str: string): BIP32 {
    const wasm = WasmBIP32.from_base58(base58Str);
    return new BIP32(wasm);
  }

  /**
   * Create a BIP32 master key from a seed
   * @param seed - The seed bytes
   * @param network - Optional network string
   * @returns A BIP32 instance
   */
  static fromSeed(seed: Uint8Array, network?: string | null): BIP32 {
    const wasm = WasmBIP32.from_seed(seed, network);
    return new BIP32(wasm);
  }

  /**
   * Create a BIP32 master key from a string by hashing it with SHA256.
   * Useful for deterministic test key generation.
   * @param seedString - The seed string to hash
   * @param network - Optional network string
   * @returns A BIP32 instance
   */
  static fromSeedSha256(seedString: string, network?: string | null): BIP32 {
    const wasm = WasmBIP32.from_seed_sha256(seedString, network);
    return new BIP32(wasm);
  }

  /**
   * Get the chain code as a Uint8Array
   */
  get chainCode(): Uint8Array {
    return this._wasm.chain_code;
  }

  /**
   * Get the depth
   */
  get depth(): number {
    return this._wasm.depth;
  }

  /**
   * Get the child index
   */
  get index(): number {
    return this._wasm.index;
  }

  /**
   * Get the parent fingerprint
   */
  get parentFingerprint(): number {
    return this._wasm.parent_fingerprint;
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
   * Get the identifier as a Uint8Array
   */
  get identifier(): Uint8Array {
    return this._wasm.identifier;
  }

  /**
   * Get the fingerprint as a Uint8Array
   */
  get fingerprint(): Uint8Array {
    return this._wasm.fingerprint;
  }

  /**
   * Check if this is a neutered (public) key
   * @returns True if the key is public-only (neutered)
   */
  isNeutered(): boolean {
    return this._wasm.is_neutered();
  }

  /**
   * Get the neutered (public) version of this key
   * @returns A new BIP32 instance containing only the public key
   */
  neutered(): BIP32 {
    const wasm = this._wasm.neutered();
    return new BIP32(wasm);
  }

  /**
   * Serialize to base58 string
   * @returns The base58-encoded extended key string
   */
  toBase58(): string {
    return this._wasm.to_base58();
  }

  /**
   * Get the WIF encoding of the private key
   * @returns The WIF-encoded private key
   */
  toWIF(): string {
    return this._wasm.to_wif();
  }

  /**
   * Derive a normal (non-hardened) child key
   * @param index - The child index
   * @returns A new BIP32 instance for the derived key
   */
  derive(index: number): BIP32 {
    const wasm = this._wasm.derive(index);
    return new BIP32(wasm);
  }

  /**
   * Derive a hardened child key (only works for private keys)
   * @param index - The child index
   * @returns A new BIP32 instance for the derived key
   */
  deriveHardened(index: number): BIP32 {
    const wasm = this._wasm.derive_hardened(index);
    return new BIP32(wasm);
  }

  /**
   * Derive a key using a derivation path (e.g., "0/1/2" or "m/0/1/2")
   * @param path - The derivation path string
   * @returns A new BIP32 instance for the derived key
   */
  derivePath(path: string): BIP32 {
    const wasm = this._wasm.derive_path(path);
    return new BIP32(wasm);
  }

  /**
   * Check equality with another BIP32 key.
   * Two keys are equal if they have the same type (public/private) and identical
   * BIP32 metadata (depth, parent fingerprint, child index, chain code, key data).
   * This is a fast comparison that does not require serialization.
   *
   * @param other - The other key to compare with. Accepts BIP32, or any BIP32Interface.
   * @returns True if the keys are equal
   */
  equals(other: BIP32Interface): boolean {
    const otherWasm = other instanceof BIP32 ? other._wasm : BIP32.from(other)._wasm;
    return this._wasm.equals(otherWasm);
  }

  /**
   * Custom JSON representation for debugging.
   * Always serializes the public key (xpub) to avoid leaking private keys.
   * Includes a `hasPrivateKey` flag to indicate whether the key is neutered.
   */
  toJSON(): { xpub: string; hasPrivateKey: boolean } {
    return { xpub: this.neutered().toBase58(), hasPrivateKey: !this.isNeutered() };
  }

  /**
   * Custom inspect representation for Node.js util.inspect and console.log.
   * Always shows the public key (xpub) to avoid leaking private keys.
   */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    const flag = this.isNeutered() ? "" : ", hasPrivateKey";
    return `BIP32(${this.neutered().toBase58()}${flag})`;
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmBIP32 {
    return this._wasm;
  }
}

/**
 * Type guard to check if a value is a BIP32Arg
 *
 * @param key - The value to check
 * @returns true if the value is a BIP32Arg (string, BIP32, WasmBIP32, or BIP32Interface)
 */
export function isBIP32Arg(key: unknown): key is BIP32Arg {
  return (
    typeof key === "string" ||
    key instanceof BIP32 ||
    key instanceof WasmBIP32 ||
    (typeof key === "object" &&
      key !== null &&
      "derive" in key &&
      typeof (key as BIP32Interface).derive === "function")
  );
}
