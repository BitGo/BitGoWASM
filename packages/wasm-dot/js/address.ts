import { AddressNamespace } from "./wasm/wasm_dot.js";

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
 * @param prefix - Network prefix (e.g. 0 = Polkadot, 2 = Kusama, 42 = Substrate)
 * @returns SS58-encoded address string
 */
export function encodeSs58(publicKey: Uint8Array, prefix: number): string {
  return AddressNamespace.encodeSs58(publicKey, prefix);
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
 * @param prefix - Optional expected network prefix to check against
 * @returns true if the address is valid (and matches prefix if provided)
 */
export function validateAddress(address: string, prefix?: number): boolean {
  return AddressNamespace.validateAddress(address, prefix);
}
