import { Capacitor } from "@capacitor/core";
import SecureKeyStore from "../plugins/secureKeyStore";

const STORAGE_PREFIX = "bitgo-signer-key-";

function storageKey(walletId: string): string {
  return `${STORAGE_PREFIX}${walletId}`;
}

const isNative = Capacitor.isNativePlatform();

export const keyStore = {
  async store(walletId: string, xprv: string): Promise<void> {
    if (isNative) {
      await SecureKeyStore.store({ key: storageKey(walletId), value: xprv });
    } else {
      console.warn("[keyStore] Storing key in localStorage — NOT SECURE for production");
      localStorage.setItem(storageKey(walletId), xprv);
    }
  },

  async retrieve(walletId: string): Promise<string> {
    if (isNative) {
      const { value } = await SecureKeyStore.retrieve({
        key: storageKey(walletId),
        prompt: "Authenticate to sign transaction",
      });
      return value;
    }
    console.warn("[keyStore] Retrieving key from localStorage — NOT SECURE for production");
    const xprv = localStorage.getItem(storageKey(walletId));
    if (xprv === null) {
      throw new Error(`No key stored for wallet ${walletId}`);
    }
    return xprv;
  },

  async remove(walletId: string): Promise<void> {
    if (isNative) {
      await SecureKeyStore.remove({ key: storageKey(walletId) });
    } else {
      localStorage.removeItem(storageKey(walletId));
    }
  },

  async has(walletId: string): Promise<boolean> {
    if (isNative) {
      const { exists } = await SecureKeyStore.has({
        key: storageKey(walletId),
      });
      return exists;
    }
    return localStorage.getItem(storageKey(walletId)) !== null;
  },
};
