/**
 * Helpers for testing satisfiability of descriptors in PSBTs.
 *
 * They are mostly a debugging aid - if an input cannot be satisified, the `finalizePsbt()` method will fail, but
 * the error message is pretty vague.
 *
 * The methods here have the goal of catching certain cases earlier and with a better error message.
 *
 * The goal is not an exhaustive check, but to catch common mistakes.
 *
 * Moved from @bitgo/utxo-core.
 */
import { Descriptor, Psbt } from "../../index.js";

export const FINAL_SEQUENCE = 0xffffffff;

/**
 * Get the required locktime for a descriptor.
 * @param descriptor
 */
export function getRequiredLocktime(descriptor: unknown): number | undefined {
  if (descriptor instanceof Descriptor) {
    return getRequiredLocktime(descriptor.node());
  }
  if (typeof descriptor !== "object" || descriptor === null) {
    return undefined;
  }
  if ("Wsh" in descriptor) {
    return getRequiredLocktime((descriptor as { Wsh: unknown }).Wsh);
  }
  if ("Sh" in descriptor) {
    return getRequiredLocktime((descriptor as { Sh: unknown }).Sh);
  }
  if ("Ms" in descriptor) {
    return getRequiredLocktime((descriptor as { Ms: unknown }).Ms);
  }
  if ("AndV" in descriptor) {
    const andV = (descriptor as { AndV: unknown }).AndV;
    if (!Array.isArray(andV)) {
      throw new Error("Expected an array");
    }
    if (andV.length !== 2) {
      throw new Error("Expected exactly two elements");
    }
    const [a, b] = andV as [unknown, unknown];
    return getRequiredLocktime(a) ?? getRequiredLocktime(b);
  }
  if ("Drop" in descriptor) {
    return getRequiredLocktime((descriptor as { Drop: unknown }).Drop);
  }
  if ("Verify" in descriptor) {
    return getRequiredLocktime((descriptor as { Verify: unknown }).Verify);
  }
  if ("After" in descriptor) {
    const after = (descriptor as { After: unknown }).After;
    if (typeof after === "object" && after !== null) {
      if (
        "absLockTime" in after &&
        typeof (after as { absLockTime: unknown }).absLockTime === "number"
      ) {
        return (after as { absLockTime: number }).absLockTime;
      }
    }
  }
  return undefined;
}

export function assertSatisfiable(psbt: Psbt, _inputIndex: number, descriptor: Descriptor): void {
  // If the descriptor requires a locktime, the input must have a non-final sequence number
  const requiredLocktime = getRequiredLocktime(descriptor);
  if (requiredLocktime !== undefined) {
    // Note: We cannot easily check sequence from wasm-utxo Psbt without additional methods
    // For now, we just check the locktime
    const psbtLocktime = psbt.lockTime();
    if (psbtLocktime !== requiredLocktime) {
      throw new Error(
        `psbt locktime (${psbtLocktime}) does not match required locktime (${requiredLocktime})`,
      );
    }
  }
}
