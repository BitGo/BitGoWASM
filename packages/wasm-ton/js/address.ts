import { AddressNamespace } from "./wasm/wasm_ton.js";

export interface AddressInfo {
  workchain: number;
  hash: Uint8Array;
  bounceable: boolean;
}

/**
 * Encode a public key into a TON user-friendly address.
 *
 * Uses v4R2 wallet contract with the default wallet ID (698983191).
 * Returns a base64url-encoded user-friendly address.
 *
 * @param pubkey - 32-byte Ed25519 public key
 * @param bounceable - whether the address should be bounceable (EQ prefix) or non-bounceable (UQ prefix)
 */
export function encode(pubkey: Uint8Array, bounceable: boolean): string {
  return AddressNamespace.encode(pubkey, bounceable);
}

/**
 * Encode a public key with a custom wallet ID.
 *
 * @param pubkey - 32-byte Ed25519 public key
 * @param bounceable - whether the address should be bounceable
 * @param walletId - custom wallet ID (default is 698983191)
 */
export function encodeWithWalletId(
  pubkey: Uint8Array,
  bounceable: boolean,
  walletId: number,
): string {
  return AddressNamespace.encode_with_wallet_id(pubkey, bounceable, walletId);
}

/**
 * Decode a TON user-friendly address into its components.
 *
 * @param address - base64url-encoded TON address
 * @returns AddressInfo with workchain, hash, and bounceable flag
 */
export function decode(address: string): AddressInfo {
  return AddressNamespace.decode(address) as AddressInfo;
}

/**
 * Validate whether a string is a valid TON address.
 *
 * Accepts base64url user-friendly, standard base64, and raw hex formats.
 */
export function validate(address: string): boolean {
  return AddressNamespace.validate(address);
}

/**
 * Check if a user-friendly address is bounceable.
 */
export function isBounceable(address: string): boolean {
  return AddressNamespace.is_bounceable(address);
}

/**
 * Re-encode an address with a different bounceable flag.
 *
 * @param address - existing TON address
 * @param bounceable - new bounceable flag
 * @returns re-encoded address with the new flag
 */
export function setBounceable(address: string, bounceable: boolean): string {
  return AddressNamespace.set_bounceable(address, bounceable);
}
