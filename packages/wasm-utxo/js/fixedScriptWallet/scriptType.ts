/**
 * All output script types for fixed-script wallets (2-of-3 multisig)
 *
 * This represents the abstract script type, independent of chain (external/internal).
 * Use this for checking network support or when you need the script type without derivation info.
 */
export const outputScriptTypes = [
  "p2sh",
  "p2shP2wsh",
  "p2wsh",
  "p2trLegacy",
  "p2trMusig2",
] as const;

/**
 * Output script type for fixed-script wallets
 *
 * Note: "p2tr" is an alias for "p2trLegacy" for backward compatibility.
 */
export type OutputScriptType = (typeof outputScriptTypes)[number] | "p2tr";

/**
 * All input script types for fixed-script wallets
 *
 * These are more specific than output types and include single-sig and taproot variants.
 */
export const inputScriptTypes = [
  "p2shP2pk",
  "p2sh",
  "p2shP2wsh",
  "p2wsh",
  "p2trLegacy",
  "p2trMusig2ScriptPath",
  "p2trMusig2KeyPath",
] as const;

/**
 * Input script type for fixed-script wallets
 */
export type InputScriptType = (typeof inputScriptTypes)[number];

/**
 * Union of all script types that can be checked for network support
 */
export type ScriptType = OutputScriptType | InputScriptType;
