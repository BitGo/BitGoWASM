import { AddressNamespace } from "./wasm/wasm_dot.js";
import { AddressFormat } from "./types.js";

/**
 * Result of decoding an SS58 address
 */
export interface DecodedAddress {
  publicKey: Uint8Array;
  prefix: number;
}

/**
 * Encode a public key to SS58 address format.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param format - Address format (Polkadot, Kusama, or Substrate)
 * @returns SS58-encoded address string
 */
export function encodeSs58(publicKey: Uint8Array, format: AddressFormat): string {
  return AddressNamespace.encodeSs58(publicKey, format);
}

/**
 * Decode an SS58 address to its public key and network prefix.
 *
 * @param address - SS58-encoded address string
 * @returns The decoded public key and network prefix
 */
export function decodeSs58(address: string): DecodedAddress {
  return AddressNamespace.decodeSs58(address) as DecodedAddress;
}

/**
 * Validate an SS58 address.
 *
 * @param address - SS58-encoded address string
 * @param format - Optional expected address format to check against
 * @returns true if the address is valid (and matches format if provided)
 */
export function validateAddress(address: string, format?: AddressFormat): boolean {
  return AddressNamespace.validateAddress(address, format);
}
