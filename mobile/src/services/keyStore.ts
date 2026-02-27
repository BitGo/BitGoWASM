// WARNING: localStorage is NOT secure for storing private keys.
// Production must use Secure Enclave (iOS Keychain / Android Keystore)
// gated behind biometric authentication via @capacitor-community/biometric-auth.

const STORAGE_PREFIX = "bitgo-signer-key-";

function storageKey(walletId: string): string {
  return `${STORAGE_PREFIX}${walletId}`;
}

export const keyStore = {
  async store(walletId: string, xprv: string): Promise<void> {
    // TODO: Production — use Capacitor Secure Storage with biometric gate
    console.warn("[keyStore] Storing key in localStorage — NOT SECURE for production");
    localStorage.setItem(storageKey(walletId), xprv);
  },

  async retrieve(walletId: string): Promise<string> {
    // TODO: Production — trigger biometric authentication before returning key
    console.warn("[keyStore] Retrieving key from localStorage — NOT SECURE for production");
    const xprv = localStorage.getItem(storageKey(walletId));
    if (xprv === null) {
      throw new Error(`No key stored for wallet ${walletId}`);
    }
    return xprv;
  },

  async remove(walletId: string): Promise<void> {
    localStorage.removeItem(storageKey(walletId));
  },

  async has(walletId: string): Promise<boolean> {
    return localStorage.getItem(storageKey(walletId)) !== null;
  },
};
