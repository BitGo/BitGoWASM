import { BIP32 } from "../bip32.js";
import { RootWalletKeys } from "../fixedScriptWallet/RootWalletKeys.js";
import type { Triple } from "../triple.js";

/**
 * Generate a deterministic BIP32 key from a seed string.
 * Uses SHA256 hash of the seed to create the key, matching utxo-lib's implementation.
 *
 * @param seed - Seed string for deterministic key generation
 * @returns BIP32 key derived from the seed
 *
 * @example
 * ```typescript
 * const key = getKey("user");
 * const xpub = key.neutered().toBase58();
 * ```
 */
export function getKey(seed: string): BIP32 {
  return BIP32.fromSeedSha256(seed);
}

/**
 * Generate a triple of BIP32 keys for a 2-of-3 multisig wallet.
 * Keys are generated deterministically from the seed string with suffixes .0, .1, .2
 * for user, backup, and bitgo keys respectively.
 *
 * @param seed - Base seed string for key generation
 * @returns Triple of BIP32 keys [user, backup, bitgo]
 *
 * @example
 * ```typescript
 * const keys = getKeyTriple("default");
 * const [user, backup, bitgo] = keys;
 * ```
 */
export function getKeyTriple(seed: string): Triple<BIP32> {
  return [getKey(seed + ".0"), getKey(seed + ".1"), getKey(seed + ".2")];
}

/**
 * Create RootWalletKeys from a seed string.
 * Uses standard derivation prefixes ["m/0/0", "m/0/0", "m/0/0"].
 *
 * @param seed - Seed string for key generation
 * @returns RootWalletKeys instance
 *
 * @example
 * ```typescript
 * const walletKeys = getWalletKeysForSeed("default");
 * ```
 */
export function getWalletKeysForSeed(seed: string): RootWalletKeys {
  const triple = getKeyTriple(seed);
  return RootWalletKeys.from({
    triple,
    derivationPrefixes: ["m/0/0", "m/0/0", "m/0/0"],
  });
}

/**
 * Get the default wallet keys for testing.
 * Equivalent to getWalletKeysForSeed("default").
 *
 * @returns RootWalletKeys instance with default seed
 *
 * @example
 * ```typescript
 * const walletKeys = getDefaultWalletKeys();
 * ```
 */
export function getDefaultWalletKeys(): RootWalletKeys {
  return getWalletKeysForSeed("default");
}

/**
 * Get the key name (user, backup, or bitgo) for a given key in a triple.
 *
 * @param triple - Triple of BIP32 keys
 * @param key - Key to find in the triple
 * @returns "user", "backup", "bitgo", or undefined if not found
 */
export function getKeyName(
  triple: Triple<BIP32>,
  key: BIP32,
): "user" | "backup" | "bitgo" | undefined {
  const index = triple.findIndex((k) => {
    const kb58 = k.toBase58();
    const keyb58 = key.toBase58();
    return kb58 === keyb58;
  });

  if (index === 0) return "user";
  if (index === 1) return "backup";
  if (index === 2) return "bitgo";
  return undefined;
}

/**
 * Get the default cosigner for a given signer key.
 * - If signer is user, returns bitgo
 * - If signer is backup, returns bitgo
 * - If signer is bitgo, returns user
 *
 * @param keyset - Triple of keys [user, backup, bitgo]
 * @param signer - The signing key
 * @returns The default cosigner key
 */
export function getDefaultCosigner<T>(keyset: Triple<T>, signer: T): T {
  const [user, backup, bitgo] = keyset;

  if (signer === user) {
    return bitgo;
  }
  if (signer === backup) {
    return bitgo;
  }
  if (signer === bitgo) {
    return user;
  }

  throw new Error("signer not in keyset");
}
