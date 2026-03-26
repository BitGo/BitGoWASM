import { AddressNamespace } from "./wasm/wasm_ton.js";

/**
 * Supported wallet versions for TON address derivation.
 */
export type WalletVersion = "V3R2" | "V4R2" | "V5R1";

/**
 * Options for encoding a TON address from a public key.
 */
export interface EncodeAddressOptions {
  /** Whether the address should be bounceable (default: true) */
  bounceable?: boolean;
  /** Wallet contract version (default: "V4R2") */
  walletVersion?: WalletVersion;
}

/**
 * Result of decoding a TON address.
 */
export interface DecodedAddress {
  /** Workchain ID (0 for basechain, -1 for masterchain) */
  workchain: number;
  /** 32-byte hash part of the address */
  hashPart: Uint8Array;
  /** Whether the address is bounceable */
  bounceable: boolean;
}

/**
 * Encode a public key to a TON address.
 *
 * Uses the wallet contract version to compute the state init hash,
 * then encodes as base64url with bounceable/non-bounceable flag.
 *
 * @param publicKey - 32-byte Ed25519 public key
 * @param options - Encoding options (bounceable, walletVersion)
 * @returns Base64url-encoded TON address
 */
export function encodeAddress(publicKey: Uint8Array, options?: EncodeAddressOptions): string {
  const bounceable = options?.bounceable ?? true;
  const walletVersion = options?.walletVersion ?? "V4R2";
  return AddressNamespace.encodeAddress(publicKey, bounceable, walletVersion);
}

/**
 * Decode a TON address to its components.
 *
 * @param address - Base64url-encoded TON address
 * @returns The decoded workchain, hash part, and bounceable flag
 */
export function decodeAddress(address: string): DecodedAddress {
  return AddressNamespace.decodeAddress(address) as DecodedAddress;
}

/**
 * Validate a TON address string.
 *
 * @param address - Base64url-encoded TON address
 * @returns true if the address is valid
 */
export function validateAddress(address: string): boolean {
  return AddressNamespace.validateAddress(address);
}
