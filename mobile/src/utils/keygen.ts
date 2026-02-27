import { Capacitor } from "@capacitor/core";
import { HDKey } from "@scure/bip32";
import SecureKeyStore from "../plugins/secureKeyStore";

/**
 * Generate 32 bytes of cryptographically secure entropy.
 * Uses the native SecureKeyStore plugin on iOS (SecRandomCopyBytes / hardware TRNG)
 * and Android (SecureRandom.getInstanceStrong), falls back to crypto.getRandomValues on web.
 */
export async function generateEntropy(): Promise<Uint8Array> {
  if (Capacitor.isNativePlatform()) {
    const { entropy } = await SecureKeyStore.generateEntropy({ bytes: 32 });
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      bytes[i] = parseInt(entropy.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Derive an xprv (BIP32 master private key) from raw entropy bytes.
 * Uses the entropy as the seed for HDKey derivation.
 */
export function entropyToXprv(entropy: Uint8Array): string {
  const hdkey = HDKey.fromMasterSeed(entropy);
  if (!hdkey.privateExtendedKey) {
    throw new Error("Failed to derive xprv from entropy");
  }
  return hdkey.privateExtendedKey;
}

/**
 * Derive the xpub from an xprv string.
 */
export function deriveXpubFromXprv(xprv: string): string {
  const hdkey = HDKey.fromExtendedKey(xprv);
  if (!hdkey.publicExtendedKey) {
    throw new Error("Failed to derive xpub from xprv");
  }
  return hdkey.publicExtendedKey;
}
