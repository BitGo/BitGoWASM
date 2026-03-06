/**
 * TypeScript wrapper for WasmTransaction
 */

import { WasmTransaction, MaterialJs, ValidityJs, ParseContextJs } from "./wasm/wasm_dot.js";
import type { Material, Validity, Era } from "./types.js";
import { AddressFormat } from "./types.js";

/**
 * DOT Transaction wrapper
 *
 * Provides a high-level interface for working with DOT transactions.
 * Handles signing context and serialization — parsing is separate
 * (use `parseTransactionData()` from parser.ts).
 */
export class DotTransaction {
  private _wasm: WasmTransaction;

  private constructor(inner: WasmTransaction) {
    this._wasm = inner;
  }

  /**
   * Create a transaction from raw bytes.
   *
   * @param bytes - Raw extrinsic bytes
   * @param material - Chain material from the fullnode. See {@link fromHex}
   *   for why material is needed at deserialization time.
   */
  static fromBytes(bytes: Uint8Array, material?: Material): DotTransaction {
    const ctx = material ? createContext(material) : undefined;
    const inner = new WasmTransaction(bytes, ctx);
    return new DotTransaction(inner);
  }

  /**
   * Create a transaction from a hex-encoded string.
   *
   * Handles both '0x'-prefixed and bare hex strings. This method exists
   * because Node.js `Buffer.from('0x...', 'hex')` silently produces an
   * EMPTY buffer when the input has a '0x' prefix — it doesn't error,
   * it just returns zero bytes. By the time `fromBytes()` receives the
   * Uint8Array, the original hex string is gone and there's nothing to
   * recover. The '0x' prefix is stripped in the Rust/WASM layer before
   * hex decoding, avoiding this JavaScript footgun entirely.
   *
   * Substrate tooling (txwrapper, polkadot.js) always produces 0x-prefixed
   * hex, so this is the primary entry point for deserialization in BitGoJS.
   * Use `fromBytes()` only when you already have raw bytes (not hex strings).
   *
   * ## Why material is passed here and not to `parseTransaction()`
   *
   * Substrate extrinsics encode signed extensions between the signature
   * and the call data. The set of extensions varies per runtime — e.g.
   * Westend adds `AuthorizeCall` and `StorageWeightReclaim` which are
   * not present on Polkadot mainnet. The deserializer needs the runtime
   * metadata (inside material) to know how many bytes the extensions
   * occupy so it can find where call_data starts.
   *
   * If you deserialize without material and the chain has non-standard
   * extensions, the call_data boundary lands in the wrong place. At that
   * point the damage is done — `tx.callData` returns wrong bytes, and no
   * amount of context passed later to `parseTransaction()` can fix it.
   * That function only uses context for name resolution (pallet index →
   * name) and address formatting, not for re-parsing the byte layout.
   *
   * TL;DR: material must be available at deserialization time, which is
   * here in `fromHex`/`fromBytes`, not later in `parseTransaction`.
   *
   * @param hex - Hex-encoded extrinsic bytes (with or without 0x prefix)
   * @param material - Chain material from the fullnode (genesisHash,
   *   chainName, specName, specVersion, txVersion, metadata)
   */
  static fromHex(hex: string, material?: Material): DotTransaction {
    const ctx = material ? createContext(material) : undefined;
    const inner = WasmTransaction.fromHex(hex, ctx);
    return new DotTransaction(inner);
  }

  /**
   * Get the transaction ID (hash) if signed
   */
  get id(): string | undefined {
    return this._wasm.id ?? undefined;
  }

  /**
   * Get sender address (SS58 encoded)
   *
   * @param format - Address format (Polkadot, Kusama, or Substrate)
   */
  sender(format: AddressFormat = AddressFormat.Polkadot): string | undefined {
    return this._wasm.sender(format) ?? undefined;
  }

  /**
   * Get account nonce
   */
  get nonce(): number {
    return this._wasm.nonce;
  }

  /**
   * Get tip amount as bigint
   */
  get tip(): bigint {
    return this._wasm.tip;
  }

  /**
   * Check if transaction is signed
   */
  get isSigned(): boolean {
    return this._wasm.isSigned;
  }

  /**
   * Get the call data
   */
  get callData(): Uint8Array {
    return this._wasm.callData();
  }

  /**
   * Get the signable payload
   *
   * Returns the bytes that should be signed with Ed25519.
   * Requires context to be set via `setContext()`.
   */
  signablePayload(): Uint8Array {
    return this._wasm.signablePayload();
  }

  /**
   * Set the signing context (material, validity, reference block)
   *
   * Required before calling signablePayload if transaction was created without context
   */
  setContext(material: Material, validity: Validity, referenceBlock: string): void {
    const materialJs = new MaterialJs(
      material.genesisHash,
      material.chainName,
      material.specName,
      material.specVersion,
      material.txVersion,
      material.metadata,
    );
    const validityJs = new ValidityJs(validity.firstValid, validity.maxDuration);
    this._wasm.setContext(materialJs, validityJs, referenceBlock);
  }

  /**
   * Set account nonce (mutates in-place, reflected on next toBytes)
   */
  setNonce(nonce: number): void {
    this._wasm.setNonce(nonce);
  }

  /**
   * Set tip amount (mutates in-place, reflected on next toBytes)
   */
  setTip(tip: bigint): void {
    this._wasm.setTip(tip);
  }

  /**
   * Add a signature to the transaction
   *
   * @param signature - 64-byte Ed25519 signature
   * @param pubkey - 32-byte public key
   */
  addSignature(signature: Uint8Array, pubkey: Uint8Array): void {
    this._wasm.addSignature(signature, pubkey);
  }

  /**
   * Serialize to bytes
   */
  toBytes(): Uint8Array {
    return this._wasm.toBytes();
  }

  /**
   * Serialize to broadcast-ready 0x-prefixed hex string.
   */
  toBroadcastFormat(): string {
    return this._wasm.toHex();
  }

  /**
   * Get era information
   */
  get era(): Era {
    return this._wasm.era as Era;
  }

  /**
   * Get the underlying WASM transaction
   * @internal
   */
  get wasm(): WasmTransaction {
    return this._wasm;
  }

  /**
   * Create a DotTransaction from an inner WasmTransaction
   * @internal
   */
  static fromInner(inner: WasmTransaction): DotTransaction {
    return new DotTransaction(inner);
  }
}

function createContext(material: Material): ParseContextJs {
  const m = new MaterialJs(
    material.genesisHash,
    material.chainName,
    material.specName,
    material.specVersion,
    material.txVersion,
    material.metadata,
  );
  return new ParseContextJs(m, null);
}
