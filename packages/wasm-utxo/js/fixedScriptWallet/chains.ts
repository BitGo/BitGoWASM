/**
 * Chain code utilities for BitGo fixed-script wallets.
 *
 * Chain codes define the derivation path component for different script types
 * and scopes (external/internal) in the format `m/0/0/{chain}/{index}`.
 */
import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";
import type { OutputScriptType } from "./scriptType.js";

/** All valid chain codes as a const tuple */
export const chainCodes = [0, 1, 10, 11, 20, 21, 30, 31, 40, 41] as const;

/** A valid chain code value */
export type ChainCode = (typeof chainCodes)[number];

/** Whether a chain is for receiving (external) or change (internal) addresses */
export type Scope = "internal" | "external";

// Build static lookup tables once at module load time
const chainCodeSet = new Set<number>(chainCodes);
const chainToMeta = new Map<ChainCode, { scope: Scope; scriptType: OutputScriptType }>();
const scriptTypeToChain = new Map<OutputScriptType, { internal: ChainCode; external: ChainCode }>();

/**
 * Assert that a number is a valid chain code.
 * @throws Error if the number is not a valid chain code
 */
export function assertChainCode(n: number): ChainCode {
  if (!chainCodeSet.has(n)) {
    throw new Error(`Invalid chain code: ${n}`);
  }
  return n as ChainCode;
}

function assertScope(s: string): Scope {
  if (s !== "internal" && s !== "external") {
    throw new Error(`Invalid scope from WASM: ${s}`);
  }
  return s;
}

for (const tuple of FixedScriptWalletNamespace.chain_code_table() as unknown[]) {
  if (!Array.isArray(tuple) || tuple.length !== 3) {
    throw new Error(`Invalid chain_code_table entry: expected [number, string, string]`);
  }
  const [rawCode, rawScriptType, rawScope] = tuple as [unknown, unknown, unknown];

  if (typeof rawCode !== "number") {
    throw new Error(`Invalid chain code type: ${typeof rawCode}`);
  }
  if (typeof rawScriptType !== "string") {
    throw new Error(`Invalid scriptType type: ${typeof rawScriptType}`);
  }
  if (typeof rawScope !== "string") {
    throw new Error(`Invalid scope type: ${typeof rawScope}`);
  }

  const code = assertChainCode(rawCode);
  const scriptType = rawScriptType as OutputScriptType;
  const scope = assertScope(rawScope);

  chainToMeta.set(code, { scope, scriptType });

  let entry = scriptTypeToChain.get(scriptType);
  if (!entry) {
    entry = {} as { internal: ChainCode; external: ChainCode };
    scriptTypeToChain.set(scriptType, entry);
  }
  entry[scope] = code;
}

/**
 * ChainCode namespace with utility functions for working with chain codes.
 */
export const ChainCode = {
  /**
   * Check if a value is a valid chain code.
   *
   * @example
   * ```typescript
   * if (ChainCode.is(maybeChain)) {
   *   // maybeChain is now typed as ChainCode
   *   const scope = ChainCode.scope(maybeChain);
   * }
   * ```
   */
  is(n: unknown): n is ChainCode {
    return typeof n === "number" && chainCodeSet.has(n);
  },

  /**
   * Get the chain code for a script type and scope.
   *
   * @example
   * ```typescript
   * const externalP2wsh = ChainCode.value("p2wsh", "external"); // 20
   * const internalP2tr = ChainCode.value("p2trLegacy", "internal"); // 31
   * ```
   */
  value(scriptType: OutputScriptType | "p2tr", scope: Scope): ChainCode {
    // legacy alias for p2trLegacy
    if (scriptType === "p2tr") {
      scriptType = "p2trLegacy";
    }

    const entry = scriptTypeToChain.get(scriptType);
    if (!entry) {
      throw new Error(`Invalid scriptType: ${scriptType}`);
    }
    return entry[scope];
  },

  /**
   * Get the scope (external/internal) for a chain code.
   *
   * @example
   * ```typescript
   * ChainCode.scope(0);  // "external"
   * ChainCode.scope(1);  // "internal"
   * ChainCode.scope(20); // "external"
   * ```
   */
  scope(chainCode: ChainCode): Scope {
    const meta = chainToMeta.get(chainCode);
    if (!meta) throw new Error(`Invalid chainCode: ${chainCode}`);
    return meta.scope;
  },

  /**
   * Get the script type for a chain code.
   *
   * @example
   * ```typescript
   * ChainCode.scriptType(0);  // "p2sh"
   * ChainCode.scriptType(20); // "p2wsh"
   * ChainCode.scriptType(40); // "p2trMusig2"
   * ```
   */
  scriptType(chainCode: ChainCode): OutputScriptType {
    const meta = chainToMeta.get(chainCode);
    if (!meta) throw new Error(`Invalid chainCode: ${chainCode}`);
    return meta.scriptType;
  },
};
