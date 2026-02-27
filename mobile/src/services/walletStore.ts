import type { Wallet } from "../types/index.ts";

const STORAGE_KEY = "bitgo-signer-wallets";

function loadAll(): Wallet[] {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  return JSON.parse(raw) as Wallet[];
}

function saveAll(wallets: Wallet[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(wallets));
}

export const walletStore = {
  async getWallets(): Promise<Wallet[]> {
    return loadAll();
  },

  async getWallet(id: string): Promise<Wallet | null> {
    return loadAll().find((w) => w.id === id) ?? null;
  },

  async addWallet(wallet: Omit<Wallet, "id" | "createdAt">): Promise<Wallet> {
    const wallets = loadAll();
    const newWallet: Wallet = {
      ...wallet,
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
    };
    wallets.push(newWallet);
    saveAll(wallets);
    return newWallet;
  },

  async updateWallet(id: string, updates: Partial<Wallet>): Promise<Wallet> {
    const wallets = loadAll();
    const idx = wallets.findIndex((w) => w.id === id);
    if (idx === -1) {
      throw new Error(`Wallet not found: ${id}`);
    }
    wallets[idx] = { ...wallets[idx], ...updates, id };
    saveAll(wallets);
    return wallets[idx];
  },

  async deleteWallet(id: string): Promise<void> {
    const wallets = loadAll().filter((w) => w.id !== id);
    saveAll(wallets);
  },
};
