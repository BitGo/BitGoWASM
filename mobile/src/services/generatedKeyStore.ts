import { Preferences } from "@capacitor/preferences";
import { Capacitor } from "@capacitor/core";
import SecureKeyStore from "../plugins/secureKeyStore";
import { GeneratedKeyState, type GeneratedKey } from "../types/index.ts";

const STORAGE_KEY = "bitgo-signer-generated-keys";
const GENERATED_KEY_PREFIX = "bitgo-signer-generated-";
const WALLET_KEY_PREFIX = "bitgo-signer-key-";

const isNative = Capacitor.isNativePlatform();

async function loadAll(): Promise<GeneratedKey[]> {
  const { value } = await Preferences.get({ key: STORAGE_KEY });
  if (!value) return [];
  return JSON.parse(value) as GeneratedKey[];
}

async function saveAll(keys: GeneratedKey[]): Promise<void> {
  await Preferences.set({ key: STORAGE_KEY, value: JSON.stringify(keys) });
}

export const generatedKeyStore = {
  async getKeys(): Promise<GeneratedKey[]> {
    return loadAll();
  },

  async getKey(id: string): Promise<GeneratedKey | null> {
    const keys = await loadAll();
    return keys.find((k) => k.id === id) ?? null;
  },

  async findByXpub(xpub: string): Promise<GeneratedKey | null> {
    const keys = await loadAll();
    return keys.find((k) => k.xpub === xpub) ?? null;
  },

  async addKey(xpub: string): Promise<GeneratedKey> {
    const keys = await loadAll();
    const newKey: GeneratedKey = {
      id: crypto.randomUUID(),
      xpub,
      createdAt: new Date().toISOString(),
      state: GeneratedKeyState.Unlinked,
      linkedWalletId: null,
    };
    keys.push(newKey);
    await saveAll(keys);
    return newKey;
  },

  async storeXprv(keyId: string, xprv: string): Promise<void> {
    const storageKey = `${GENERATED_KEY_PREFIX}${keyId}`;
    if (isNative) {
      await SecureKeyStore.store({ key: storageKey, value: xprv });
    } else {
      console.warn("[generatedKeyStore] Storing key in localStorage — NOT SECURE for production");
      localStorage.setItem(storageKey, xprv);
    }
  },

  async retrieveXprv(keyId: string): Promise<string> {
    const storageKey = `${GENERATED_KEY_PREFIX}${keyId}`;
    if (isNative) {
      const { value } = await SecureKeyStore.retrieve({
        key: storageKey,
        prompt: "Authenticate to export private key",
      });
      return value;
    }
    console.warn(
      "[generatedKeyStore] Retrieving key from localStorage — NOT SECURE for production",
    );
    const xprv = localStorage.getItem(storageKey);
    if (xprv === null) {
      throw new Error(`No xprv stored for generated key ${keyId}`);
    }
    return xprv;
  },

  /**
   * Link a generated key to a wallet: move the xprv from generated-{keyId}
   * to key-{walletId} (the format used by keyStore), and update metadata.
   */
  async linkToWallet(keyId: string, walletId: string): Promise<GeneratedKey> {
    // Retrieve the xprv (triggers biometric on native)
    const xprv = await this.retrieveXprv(keyId);

    // Store under the wallet key prefix (same format as keyStore.store)
    const walletStorageKey = `${WALLET_KEY_PREFIX}${walletId}`;
    if (isNative) {
      await SecureKeyStore.store({ key: walletStorageKey, value: xprv });
    } else {
      localStorage.setItem(walletStorageKey, xprv);
    }

    // Remove the generated key storage
    const generatedStorageKey = `${GENERATED_KEY_PREFIX}${keyId}`;
    if (isNative) {
      await SecureKeyStore.remove({ key: generatedStorageKey });
    } else {
      localStorage.removeItem(generatedStorageKey);
    }

    // Update metadata
    const keys = await loadAll();
    const idx = keys.findIndex((k) => k.id === keyId);
    if (idx === -1) {
      throw new Error(`Generated key not found: ${keyId}`);
    }
    keys[idx] = {
      ...keys[idx],
      state: GeneratedKeyState.Linked,
      linkedWalletId: walletId,
    };
    await saveAll(keys);
    return keys[idx];
  },

  async deleteKey(keyId: string): Promise<void> {
    // Remove secure storage
    const storageKey = `${GENERATED_KEY_PREFIX}${keyId}`;
    if (isNative) {
      await SecureKeyStore.remove({ key: storageKey });
    } else {
      localStorage.removeItem(storageKey);
    }

    // Remove metadata
    const keys = await loadAll();
    await saveAll(keys.filter((k) => k.id !== keyId));
  },
};
