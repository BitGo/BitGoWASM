import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { createElement } from "react";
import type { Wallet } from "../types/index.ts";
import { walletStore } from "../services/walletStore.ts";

interface WalletContextValue {
  wallets: Wallet[];
  loading: boolean;
  addWallet: (wallet: Omit<Wallet, "id" | "createdAt">) => Promise<Wallet>;
  updateWallet: (id: string, updates: Partial<Wallet>) => Promise<Wallet>;
  deleteWallet: (id: string) => Promise<void>;
  refresh: () => Promise<void>;
}

const WalletContext = createContext<WalletContextValue | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [wallets, setWallets] = useState<Wallet[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const loaded = await walletStore.getWallets();
    setWallets(loaded);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const addWallet = useCallback(
    async (wallet: Omit<Wallet, "id" | "createdAt">) => {
      const created = await walletStore.addWallet(wallet);
      await refresh();
      return created;
    },
    [refresh],
  );

  const updateWallet = useCallback(
    async (id: string, updates: Partial<Wallet>) => {
      const updated = await walletStore.updateWallet(id, updates);
      await refresh();
      return updated;
    },
    [refresh],
  );

  const deleteWallet = useCallback(
    async (id: string) => {
      await walletStore.deleteWallet(id);
      await refresh();
    },
    [refresh],
  );

  return createElement(
    WalletContext.Provider,
    { value: { wallets, loading, addWallet, updateWallet, deleteWallet, refresh } },
    children,
  );
}

export function useWallets(): WalletContextValue {
  const ctx = useContext(WalletContext);
  if (!ctx) {
    throw new Error("useWallets must be used within a WalletProvider");
  }
  return ctx;
}
