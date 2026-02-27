import { Capacitor } from "@capacitor/core";
import SecureKeyStore from "../plugins/secureKeyStore";

export function useBiometric() {
  async function authenticate(): Promise<boolean> {
    if (!Capacitor.isNativePlatform()) {
      console.warn("[useBiometric] No biometric available in browser — auto-approving");
      return true;
    }
    // Pre-check: verify biometric is enrolled. The actual Face ID prompt
    // happens during keyStore.retrieve() via Keychain access control.
    const { available } = await SecureKeyStore.isBiometricAvailable();
    return available;
  }

  async function isAvailable(): Promise<boolean> {
    if (!Capacitor.isNativePlatform()) return false;
    const { available } = await SecureKeyStore.isBiometricAvailable();
    return available;
  }

  return { authenticate, isAvailable };
}
