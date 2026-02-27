import { Preferences } from "@capacitor/preferences";
import type { Wallet } from "../types/index.ts";

const STORAGE_KEY = "bitgo-signer-wallets";

async function loadAll(): Promise<Wallet[]> {
  const { value } = await Preferences.get({ key: STORAGE_KEY });
  if (!value) return [];
  return JSON.parse(value) as Wallet[];
}

async function saveAll(wallets: Wallet[]): Promise<void> {
  await Preferences.set({ key: STORAGE_KEY, value: JSON.stringify(wallets) });
}

export const walletStore = {
  async getWallets(): Promise<Wallet[]> {
    return loadAll();
  },

  async getWallet(id: string): Promise<Wallet | null> {
    const wallets = await loadAll();
    return wallets.find((w) => w.id === id) ?? null;
  },

  async addWallet(wallet: Omit<Wallet, "id" | "createdAt">): Promise<Wallet> {
    const wallets = await loadAll();
    const newWallet: Wallet = {
      ...wallet,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    };
    wallets.push(newWallet);
    await saveAll(wallets);
    return newWallet;
  },

  async updateWallet(id: string, updates: Partial<Wallet>): Promise<Wallet> {
    const wallets = await loadAll();
    const idx = wallets.findIndex((w) => w.id === id);
    if (idx === -1) {
      throw new Error(`Wallet not found: ${id}`);
    }
    wallets[idx] = { ...wallets[idx], ...updates, id };
    await saveAll(wallets);
    return wallets[idx];
  },

  async deleteWallet(id: string): Promise<void> {
    const wallets = await loadAll();
    await saveAll(wallets.filter((w) => w.id !== id));
  },
};
