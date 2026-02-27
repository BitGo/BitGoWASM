import { registerPlugin } from "@capacitor/core";

export interface SecureKeyStorePlugin {
  store(options: { key: string; value: string }): Promise<void>;
  retrieve(options: { key: string; prompt: string }): Promise<{ value: string }>;
  remove(options: { key: string }): Promise<void>;
  has(options: { key: string }): Promise<{ exists: boolean }>;
  isBiometricAvailable(): Promise<{
    available: boolean;
    biometryType: string;
  }>;
  generateEntropy(options: { bytes?: number }): Promise<{ entropy: string }>;
}

const SecureKeyStore = registerPlugin<SecureKeyStorePlugin>("SecureKeyStore");

export default SecureKeyStore;
