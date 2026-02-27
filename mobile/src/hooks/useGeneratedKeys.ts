import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { createElement } from "react";
import type { GeneratedKey } from "../types/index.ts";
import { generatedKeyStore } from "../services/generatedKeyStore.ts";

interface GeneratedKeyContextValue {
  keys: GeneratedKey[];
  loading: boolean;
  refresh: () => Promise<void>;
}

const GeneratedKeyContext = createContext<GeneratedKeyContextValue | null>(null);

export function GeneratedKeyProvider({ children }: { children: ReactNode }) {
  const [keys, setKeys] = useState<GeneratedKey[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const loaded = await generatedKeyStore.getKeys();
    setKeys(loaded);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return createElement(
    GeneratedKeyContext.Provider,
    { value: { keys, loading, refresh } },
    children,
  );
}

export function useGeneratedKeys(): GeneratedKeyContextValue {
  const ctx = useContext(GeneratedKeyContext);
  if (!ctx) {
    throw new Error("useGeneratedKeys must be used within a GeneratedKeyProvider");
  }
  return ctx;
}
