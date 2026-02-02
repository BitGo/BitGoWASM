import { FixedScriptWalletNamespace } from "../wasm/wasm_utxo.js";

/**
 * Subtype constants for BitGo proprietary PSBT key-values.
 * Values are loaded from the Rust enum at module init time — no duplication.
 * The type shape is declared here for IDE support.
 */
export type BitGoKeySubtypeMap = {
  readonly ZecConsensusBranchId: number;
  readonly Musig2ParticipantPubKeys: number;
  readonly Musig2PubNonce: number;
  readonly Musig2PartialSig: number;
  readonly PayGoAddressAttestationProof: number;
  readonly Bip322Message: number;
  readonly WasmUtxoSignedWith: number;
};

export const BitGoKeySubtype =
  FixedScriptWalletNamespace.get_bitgo_key_subtypes() as BitGoKeySubtypeMap;
export type BitGoKeySubtype = BitGoKeySubtypeMap[keyof BitGoKeySubtypeMap];

/**
 * A composable PSBT key for use with `setKV` / `getKV` / `setInputKV` / `getInputKV` etc.
 *
 * - `"unknown"`: stored in the PSBT `unknown` map (raw BIP-174 key-value pair)
 * - `"proprietary"`: stored in the PSBT `proprietary` map with an arbitrary prefix
 * - `"bitgo"`: stored in the PSBT `proprietary` map with the `BITGO` prefix
 */
export type PsbtKvKey =
  | { type: "unknown"; keyType: number; data?: Uint8Array }
  | { type: "proprietary"; prefix: Uint8Array; subtype: number; key?: Uint8Array }
  | { type: "bitgo"; subtype: number; key?: Uint8Array };
