// TODO: Production — use @capacitor-community/biometric-auth for native biometric gating.
// In browser dev mode, biometric is not available and authenticate() always resolves true.

export function useBiometric() {
  async function authenticate(): Promise<boolean> {
    console.warn("[useBiometric] No biometric available in browser — auto-approving");
    return true;
  }

  async function isAvailable(): Promise<boolean> {
    return false;
  }

  return { authenticate, isAvailable };
}
