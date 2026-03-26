import { AddressNamespace } from "./wasm/wasm_ton.js";

/**
 * Result of decoding a TON address
 */
export interface DecodedAddress {
  workchainId: number;
  hash: Uint8Array;
  bounceable: boolean;
  testnet: boolean;
}

/**
 * Encode a V4R2 wallet address from an Ed25519 public key.
 *
 * Derives the wallet's StateInit from the public key, hashes it,
 * and encodes as a user-friendly base64url address with the specified flags.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param bounceable - Whether the address should be bounceable (default: true)
 * @param testnet - Whether the address is for testnet (default: false)
 * @returns User-friendly base64url-encoded TON address
 */
export function encodeAddress(publicKey: Uint8Array, bounceable = true, testnet = false): string {
  return AddressNamespace.encodeAddress(publicKey, bounceable, testnet);
}

/**
 * Decode a TON address to its components.
 *
 * Accepts both user-friendly (base64url) and raw (workchain:hex_hash) formats.
 *
 * @param address - TON address string
 * @returns Decoded address components including flags
 */
export function decodeAddress(address: string): DecodedAddress {
  return AddressNamespace.decodeAddress(address) as DecodedAddress;
}

/**
 * Validate a TON address string.
 *
 * Accepts both user-friendly (base64url) and raw (workchain:hex_hash) formats.
 *
 * @param address - TON address string to validate
 * @returns true if the address is valid
 */
export function validateAddress(address: string): boolean {
  return AddressNamespace.validateAddress(address);
}

/**
 * Convert a TON address to raw format (workchain:hex_hash).
 *
 * @param address - User-friendly (base64url) TON address
 * @returns Raw address string in format "workchain:hex_hash"
 */
export function toRawAddress(address: string): string {
  return AddressNamespace.toRawAddress(address);
}
