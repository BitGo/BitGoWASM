import { AddressNamespace } from "./wasm/wasm_ton.js";

/**
 * Result of decoding a TON address
 */
export interface DecodedAddress {
  workchainId: number;
  addressHash: Uint8Array;
  isBounceable: boolean;
  isTestnet: boolean;
}

/**
 * Encode a raw Ed25519 public key to a TON user-friendly address.
 *
 * Computes the wallet v4r2 StateInit hash internally (workchain 0, default wallet ID).
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param bounceable - Whether the address is bounceable (default: true)
 * @returns User-friendly base64url address string (EQ for bounceable, UQ for non-bounceable)
 */
export function encodeAddress(publicKey: Uint8Array, bounceable = true): string {
  return AddressNamespace.encodeAddress(publicKey, bounceable);
}

/**
 * Encode an address hash and workchain into a user-friendly TON address.
 *
 * @param workchainId - The workchain ID (0 for basechain)
 * @param addressHash - 32-byte address hash
 * @param bounceable - Whether the address is bounceable (default: true)
 * @returns User-friendly base64url address string
 */
export function encode(workchainId: number, addressHash: Uint8Array, bounceable = true): string {
  return AddressNamespace.encode(workchainId, addressHash, bounceable);
}

/**
 * Decode a TON address string into its components.
 *
 * @param address - TON address (user-friendly or raw hex)
 * @returns Decoded address components
 */
export function decode(address: string): DecodedAddress {
  return AddressNamespace.decode(address) as DecodedAddress;
}

/**
 * Validate a TON address string.
 *
 * @param address - TON address to validate
 * @returns true if valid
 */
export function validate(address: string): boolean {
  return AddressNamespace.validate(address);
}
