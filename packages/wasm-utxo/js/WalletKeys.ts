import type { BIP32Interface } from "./bip32.js";
import { BIP32 } from "./bip32.js";
import { Triple } from "./triple.js";
import { WasmRootWalletKeys, WasmBIP32 } from "./wasm/wasm_utxo.js";

/**
 * IWalletKeys represents the various forms that wallet keys can take
 * before being converted to a RootWalletKeys instance
 */
export type IWalletKeys = {
  triple: Triple<BIP32Interface>;
  derivationPrefixes: Triple<string>;
};

export type WalletKeysArg =
  /** Just an xpub triple, will assume default derivation prefixes  */
  | Triple<string>
  /** Compatible with utxolib RootWalletKeys */
  | IWalletKeys
  /** RootWalletKeys instance */
  | RootWalletKeys;

/**
 * Convert WalletKeysArg to a triple of WasmBIP32 instances
 */
function toBIP32Triple(keys: WalletKeysArg): Triple<WasmBIP32> {
  if (keys instanceof RootWalletKeys) {
    return [keys.userKey().wasm, keys.backupKey().wasm, keys.bitgoKey().wasm];
  }

  // Check if it's an IWalletKeys object
  if (typeof keys === "object" && "triple" in keys) {
    // Extract BIP32 keys from the triple
    return keys.triple.map((key) => BIP32.from(key).wasm) as Triple<WasmBIP32>;
  }

  // Otherwise it's a triple of strings (xpubs)
  return keys.map((xpub) => WasmBIP32.from_xpub(xpub)) as Triple<WasmBIP32>;
}

/**
 * Extract derivation prefixes from WalletKeysArg, if present
 */
function extractDerivationPrefixes(keys: WalletKeysArg): Triple<string> | null {
  if (typeof keys === "object" && "derivationPrefixes" in keys) {
    return keys.derivationPrefixes;
  }
  return null;
}

/**
 * RootWalletKeys represents a set of three extended public keys with their derivation prefixes
 */
export class RootWalletKeys {
  private constructor(private _wasm: WasmRootWalletKeys) {}

  /**
   * Create a RootWalletKeys from various input formats
   * @param keys - Can be a triple of xpub strings, an IWalletKeys object, or another RootWalletKeys instance
   * @returns A RootWalletKeys instance
   */
  static from(keys: WalletKeysArg): RootWalletKeys {
    if (keys instanceof RootWalletKeys) {
      return keys;
    }

    const [user, backup, bitgo] = toBIP32Triple(keys);
    const derivationPrefixes = extractDerivationPrefixes(keys);

    const wasm = derivationPrefixes
      ? WasmRootWalletKeys.with_derivation_prefixes(
          user,
          backup,
          bitgo,
          derivationPrefixes[0],
          derivationPrefixes[1],
          derivationPrefixes[2],
        )
      : new WasmRootWalletKeys(user, backup, bitgo);

    return new RootWalletKeys(wasm);
  }

  /**
   * Create a RootWalletKeys from three xpub strings
   * Uses default derivation prefix of m/0/0 for all three keys
   * @param xpubs - Triple of xpub strings
   * @returns A RootWalletKeys instance
   */
  static fromXpubs(xpubs: Triple<string>): RootWalletKeys {
    const [user, backup, bitgo] = xpubs.map((xpub) =>
      WasmBIP32.from_xpub(xpub),
    ) as Triple<WasmBIP32>;
    const wasm = new WasmRootWalletKeys(user, backup, bitgo);
    return new RootWalletKeys(wasm);
  }

  /**
   * Create a RootWalletKeys from three xpub strings with custom derivation prefixes
   * @param xpubs - Triple of xpub strings
   * @param derivationPrefixes - Triple of derivation path strings (e.g., ["0/0", "0/0", "0/0"])
   * @returns A RootWalletKeys instance
   */
  static withDerivationPrefixes(
    xpubs: Triple<string>,
    derivationPrefixes: Triple<string>,
  ): RootWalletKeys {
    const [user, backup, bitgo] = xpubs.map((xpub) =>
      WasmBIP32.from_xpub(xpub),
    ) as Triple<WasmBIP32>;
    const wasm = WasmRootWalletKeys.with_derivation_prefixes(
      user,
      backup,
      bitgo,
      derivationPrefixes[0],
      derivationPrefixes[1],
      derivationPrefixes[2],
    );
    return new RootWalletKeys(wasm);
  }

  /**
   * Get the user key (first xpub)
   * @returns The user key as a BIP32 instance
   */
  userKey(): BIP32 {
    const wasm = this._wasm.user_key();
    return BIP32.fromWasm(wasm);
  }

  /**
   * Get the backup key (second xpub)
   * @returns The backup key as a BIP32 instance
   */
  backupKey(): BIP32 {
    const wasm = this._wasm.backup_key();
    return BIP32.fromWasm(wasm);
  }

  /**
   * Get the BitGo key (third xpub)
   * @returns The BitGo key as a BIP32 instance
   */
  bitgoKey(): BIP32 {
    const wasm = this._wasm.bitgo_key();
    return BIP32.fromWasm(wasm);
  }

  /**
   * Get the underlying WASM instance (internal use only)
   * @internal
   */
  get wasm(): WasmRootWalletKeys {
    return this._wasm;
  }
}
