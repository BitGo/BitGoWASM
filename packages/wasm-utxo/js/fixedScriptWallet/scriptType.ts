/**
 * Fixed-script wallet output script types (2-of-3 multisig)
 *
 * This type represents the abstract script type, independent of chain (external/internal).
 * Use this for checking network support or when you need the script type without derivation info.
 */
export type OutputScriptType =
  | "p2sh"
  | "p2shP2wsh"
  | "p2wsh"
  | "p2tr" // alias for p2trLegacy
  | "p2trLegacy"
  | "p2trMusig2";

/**
 * Input script types for fixed-script wallets
 *
 * These are more specific than output types and include single-sig and taproot variants.
 */
export type InputScriptType =
  | "p2shP2pk"
  | "p2sh"
  | "p2shP2wsh"
  | "p2wsh"
  | "p2trLegacy"
  | "p2trMusig2ScriptPath"
  | "p2trMusig2KeyPath";

/**
 * Union of all script types that can be checked for network support
 */
export type ScriptType = OutputScriptType | InputScriptType;
