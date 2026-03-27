import { AddressNamespace } from "./wasm/wasm_ton.js";

/**
 * Result of decoding a TON address
 */
export interface DecodedAddress {
  workchainId: number;
  hash: Uint8Array;
  bounceable: boolean;
}

/**
 * Encode a 32-byte Ed25519 public key to a TON user-friendly address.
 *
 * Derives the WalletV4R2 address by computing the StateInit hash.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param bounceable - whether the address should be bounceable (default: true)
 * @param workchainId - workchain ID (default: 0 for basechain)
 * @param walletId - optional wallet sub-ID (default: 0x29a9a317 for V4R2)
 * @returns User-friendly base64url-encoded TON address
 */
export function encodeAddress(
  publicKey: Uint8Array,
  bounceable = true,
  workchainId = 0,
  walletId?: number,
): string {
  return AddressNamespace.encodeAddress(publicKey, bounceable, workchainId, walletId);
}

/**
 * Decode a TON address to its components.
 *
 * Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
 *
 * @param address - TON address string
 * @returns The decoded workchain ID, hash, and bounceable flag
 */
export function decodeAddress(address: string): DecodedAddress {
  return AddressNamespace.decodeAddress(address) as DecodedAddress;
}

/**
 * Validate a TON address string.
 *
 * Accepts both user-friendly (base64url) and raw (workchain:hex) formats.
 *
 * @param address - TON address string
 * @returns true if the address is valid
 */
export function validateAddress(address: string): boolean {
  return AddressNamespace.validateAddress(address);
}

/**
 * Convert any valid TON address to user-friendly base64url format.
 *
 * @param address - TON address string (raw or user-friendly)
 * @param bounceable - whether the output should be bounceable (default: true)
 * @returns User-friendly base64url-encoded address
 */
export function toUserFriendly(address: string, bounceable = true): string {
  return AddressNamespace.toUserFriendly(address, bounceable);
}

/**
 * Convert any valid TON address to raw format (workchain:hex_hash).
 *
 * @param address - TON address string (user-friendly or raw)
 * @returns Raw address string
 */
export function toRaw(address: string): string {
  return AddressNamespace.toRaw(address);
}
