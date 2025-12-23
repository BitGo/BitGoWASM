/**
 * Parse Node - TypeScript bindings for PSBT and Transaction parsing
 *
 * Provides typed wrappers around the WASM parse_node functions that return
 * hierarchical node structures suitable for display as collapsible trees.
 */

import {
  parsePsbtToJson as wasmParsePsbtToJson,
  parseTxToJson as wasmParseTxToJson,
  parsePsbtRawToJson as wasmParsePsbtRawToJson,
  isParseNodeEnabled as wasmIsParseNodeEnabled,
} from "./wasm/wasm_utxo.js";

import type { CoinName } from "./coinName.js";

/** Re-export CoinName for convenience */
export type { CoinName };

/** All supported networks in order of parsing priority */
export const allNetworks: CoinName[] = [
  "btc",
  "tbtc",
  "tbtc4",
  "tbtcsig",
  "tbtcbgsig",
  "ltc",
  "tltc",
  "bch",
  "tbch",
  "bcha",
  "tbcha",
  "btg",
  "tbtg",
  "bsv",
  "tbsv",
  "dash",
  "tdash",
  "doge",
  "tdoge",
  "zec",
  "tzec",
];

/**
 * Primitive value types that can appear in a Node.
 * Buffer values are hex-encoded strings, Integer is a decimal string for BigInt support.
 */
export type PrimitiveType =
  | "String"
  | "Buffer"
  | "Integer"
  | "U8"
  | "U16"
  | "U32"
  | "U64"
  | "I8"
  | "I16"
  | "I32"
  | "I64"
  | "Boolean"
  | "None";

/**
 * A tagged union representing primitive values in the parse tree.
 */
export interface Primitive {
  type: PrimitiveType;
  value?: string | number | boolean;
}

/**
 * A node in the parse tree representing a PSBT or transaction element.
 */
export interface Node {
  label: string;
  value: Primitive;
  children: Node[];
}

/**
 * Parse a PSBT and return a typed node tree.
 *
 * @param psbtBytes - The raw PSBT bytes
 * @param network - The network coin name (e.g., "btc", "ltc", "bch")
 * @returns A Node tree representing the parsed PSBT structure
 * @throws If the PSBT bytes are invalid or network is unknown
 */
export function parsePsbtToNode(psbtBytes: Uint8Array, network: CoinName): Node {
  const json = wasmParsePsbtToJson(psbtBytes, network);
  return JSON.parse(json) as Node;
}

/**
 * Parse a transaction and return a typed node tree.
 *
 * @param txBytes - The raw transaction bytes
 * @param network - The network coin name (e.g., "btc", "ltc", "bch")
 * @returns A Node tree representing the parsed transaction structure
 * @throws If the transaction bytes are invalid or network is unknown
 */
export function parseTxToNode(txBytes: Uint8Array, network: CoinName): Node {
  const json = wasmParseTxToJson(txBytes, network);
  return JSON.parse(json) as Node;
}

/**
 * Try to parse a PSBT with all networks and return the first one that succeeds.
 *
 * @param psbtBytes - The raw PSBT bytes
 * @param networks - Optional list of networks to try (defaults to all networks)
 * @returns An object with the parsed Node and detected network, or null if all fail
 */
export function tryParsePsbt(
  psbtBytes: Uint8Array,
  networks: CoinName[] = allNetworks,
): { node: Node; network: CoinName } | null {
  for (const network of networks) {
    try {
      const node = parsePsbtToNode(psbtBytes, network);
      return { node, network };
    } catch {
      // Try next network
    }
  }
  return null;
}

/**
 * Try to parse a transaction with all networks and return the first one that succeeds.
 *
 * @param txBytes - The raw transaction bytes
 * @param networks - Optional list of networks to try (defaults to all networks)
 * @returns An object with the parsed Node and detected network, or null if all fail
 */
export function tryParseTx(
  txBytes: Uint8Array,
  networks: CoinName[] = allNetworks,
): { node: Node; network: CoinName } | null {
  for (const network of networks) {
    try {
      const node = parseTxToNode(txBytes, network);
      return { node, network };
    } catch {
      // Try next network
    }
  }
  return null;
}

/**
 * Parse a PSBT at the raw byte level and return a typed node tree.
 *
 * Unlike `parsePsbtToNode`, this function exposes the raw key-value pair
 * structure as defined in BIP-174, showing:
 * - Raw key type IDs and their human-readable names
 * - Proprietary keys with their structured format
 * - Unknown/unrecognized keys that standard parsers might skip
 *
 * @param psbtBytes - The raw PSBT bytes
 * @param network - The network coin name (e.g., "btc", "ltc", "zec")
 * @returns A Node tree representing the raw PSBT key-value structure
 * @throws If the PSBT bytes are invalid or network is unknown
 */
export function parsePsbtRawToNode(psbtBytes: Uint8Array, network: CoinName): Node {
  const json = wasmParsePsbtRawToJson(psbtBytes, network);
  return JSON.parse(json) as Node;
}

/**
 * Try to parse a raw PSBT with all networks and return the first one that succeeds.
 *
 * @param psbtBytes - The raw PSBT bytes
 * @param networks - Optional list of networks to try (defaults to all networks)
 * @returns An object with the parsed Node and detected network, or null if all fail
 */
export function tryParsePsbtRaw(
  psbtBytes: Uint8Array,
  networks: CoinName[] = allNetworks,
): { node: Node; network: CoinName } | null {
  for (const network of networks) {
    try {
      const node = parsePsbtRawToNode(psbtBytes, network);
      return { node, network };
    } catch {
      // Try next network
    }
  }
  return null;
}

/**
 * Check if the parse_node feature is enabled in the WASM build.
 *
 * @returns true if the feature is enabled, false otherwise
 */
export function isParseNodeEnabled(): boolean {
  return wasmIsParseNodeEnabled();
}

