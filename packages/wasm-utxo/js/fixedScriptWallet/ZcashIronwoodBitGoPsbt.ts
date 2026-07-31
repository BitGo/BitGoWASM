import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import {
  IRONWOOD_VERSION_GROUP_ID,
  ZcashBitGoPsbt,
  type ZcashNetworkName,
} from "./ZcashBitGoPsbt.js";

/**
 * Options for creating an empty Zcash v6 (Ironwood) shielding PSBT.
 *
 * Deliberately narrower than `CreateEmptyZcashOptions`: `version` and `versionGroupId` are fixed by
 * the v6 format, so accepting them would only let a caller ask for something that is then ignored.
 */
export type CreateEmptyIronwoodOptions = {
  /** Block height to determine the consensus branch ID automatically (at/after NU6.3 activation) */
  blockHeight: number;
  /** Lock time (default: 0) */
  lockTime?: number;
  /** Zcash transaction expiry height */
  expiryHeight?: number;
};

/**
 * Options for creating an empty Zcash v6 (Ironwood) shielding PSBT with an explicit consensus
 * branch ID.
 *
 * Like {@link CreateEmptyIronwoodOptions}, this omits `version` and `versionGroupId` — both are
 * fixed by the v6 format. The consensus branch ID is *not* fixed: it tracks the active network
 * upgrade, so it stays a caller-supplied parameter exactly as it is for v4.
 */
export type CreateEmptyIronwoodWithConsensusBranchIdOptions = {
  /** Zcash consensus branch ID (e.g. the NU6.3 branch ID) */
  consensusBranchId: number;
  /** Lock time (default: 0) */
  lockTime?: number;
  /** Zcash transaction expiry height */
  expiryHeight?: number;
};

/**
 * A fresh ZIP-302 "no memo" memo field: the `0xf6` marker byte followed by 511 zero bytes. The
 * default for {@link ZcashIronwoodBitGoPsbt.addShieldedOutput}'s `memo` option.
 *
 * Not the same as an all-zeros memo, which decodes as a *text* memo holding the empty string and is
 * rendered as such by wallets. Exported so callers can pass it explicitly, and so the distinction is
 * visible rather than buried in a default.
 *
 * A function rather than a shared constant: a module-level `Uint8Array` is mutable, so one caller
 * writing into it would silently change the default memo for every later output.
 */
export function zip302NoMemo(): Uint8Array {
  const memo = new Uint8Array(512);
  memo[0] = 0xf6;
  return memo;
}

/**
 * A Zcash **v6 (Ironwood / NU6.3)** shielding PSBT.
 *
 * Distinct from the generic `ZcashBitGoPsbt` (v4/Sapling-shaped transactions): a v6 PSBT carries
 * its shielded side as an orchard PCZT in the proprietary map rather than Sapling fields, and its
 * lifecycle mirrors the microservice build → sign → combine flow rather than the v4 ZIP-243
 * signing path.
 *
 * Method names carry no `ironwood` prefix — the class name already says it. They follow the base
 * `BitGoPsbt` vocabulary (`createEmpty`, `fromBytes`, `addOutput`-style adders, `getId`) so the v6
 * surface reads the same as the v4 one; the wasm bindings keep their `ironwood_v6_*` names because
 * they live on the single flat `BitGoPsbt` struct, where the prefix is what disambiguates them.
 *
 * @example
 * ```typescript
 * const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcash", walletKeys, { blockHeight });
 * psbt.addWalletInput(...);
 * psbt.addWalletOutput(...);
 * psbt.addShieldedOutput(recipient, amount, { anchor });
 * const sighash = psbt.transparentSighash(0);
 * // ... sign sighash externally, then:
 * psbt.addTransparentSignature(0, pubkey, sig);
 * const tx = psbt.combineProof(proof);
 * ```
 */
export class ZcashIronwoodBitGoPsbt extends ZcashBitGoPsbt {
  /**
   * Create an empty Zcash **v6 (Ironwood)** shielding PSBT, with the consensus branch ID
   * determined from block height.
   *
   * Add transparent inputs/outputs with the usual `addWalletInput` / `addWalletOutput`, the
   * shielded output with {@link addShieldedOutput}, then sign the transparent inputs over
   * {@link transparentSighash} and finish with {@link combineProof}.
   *
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys (sets global xpubs in the PSBT)
   * @param options - Options including blockHeight (at/after NU6.3 activation)
   */
  static override createEmpty(
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    options: CreateEmptyIronwoodOptions,
  ): ZcashIronwoodBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const wasm = WasmBitGoPsbt.create_empty_zcash_v6_at_height(
      network,
      keys.wasm,
      options.blockHeight,
      options.lockTime,
      options.expiryHeight,
    );
    return new ZcashIronwoodBitGoPsbt(wasm);
  }

  /**
   * Create an empty Zcash **v6 (Ironwood)** shielding PSBT with an explicit consensus branch ID.
   *
   * **Advanced use only.** Prefer {@link createEmpty}, which derives the branch ID from a block
   * height and rejects heights before NU6.3 activation. Reach for this only when you already know
   * the branch ID — regtest, a future upgrade, or replaying a known-good value.
   *
   * Only the *version group ID* is fixed by the v6 format; the consensus branch ID tracks the active
   * network upgrade and remains caller-supplied, exactly as for v4.
   *
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param walletKeys - The wallet's root keys (sets global xpubs in the PSBT)
   * @param options - Options including the required consensusBranchId
   */
  static override createEmptyWithConsensusBranchId(
    network: ZcashNetworkName,
    walletKeys: WalletKeysArg,
    options: CreateEmptyIronwoodWithConsensusBranchIdOptions,
  ): ZcashIronwoodBitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const wasm = WasmBitGoPsbt.create_empty_zcash_v6(
      network,
      keys.wasm,
      options.consensusBranchId,
      options.lockTime,
      options.expiryHeight,
    );
    return new ZcashIronwoodBitGoPsbt(wasm);
  }

  /**
   * Not applicable to v6, and not implementable: a broadcast v6 transaction carries the shielded
   * side as a proof plus a binding signature, while every v6 operation here needs the PCZT — which
   * holds witness data (`rseed`, `rcv`, `alpha`, the note plaintext) that is deliberately *not*
   * recoverable from the transaction. Decoding the transparent skeleton alone would yield a PSBT
   * that `getId`, `transparentSighash`, `combineProof`, and even `serialize`/{@link fromBytes} all
   * reject. Inherited only because JS statics are inherited.
   */
  static override fromNetworkFormat(): never {
    throw new Error(
      "not supported for v6 (Ironwood): the PCZT witness data cannot be recovered from a broadcast " +
        "transaction; rebuild the PSBT with createEmpty",
    );
  }

  /**
   * Not applicable to v6: the legacy half-signed format is a v4-era p2ms encoding with no way to
   * carry the PCZT, and no v6 transaction has ever been produced in it. Inherited only because JS
   * statics are inherited.
   */
  static override fromHalfSignedLegacyTransaction(): never {
    throw new Error(
      "not supported for v6 (Ironwood): the legacy half-signed format is v4-only; " +
        "rebuild the PSBT with createEmpty",
    );
  }

  /**
   * Deserialize a v6 (Ironwood) Zcash PSBT from bytes.
   *
   * @param bytes - The PSBT bytes
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @throws Error if the deserialized PSBT is not a v6 (Ironwood) PSBT
   * @returns A ZcashIronwoodBitGoPsbt instance
   */
  static override fromBytes(bytes: Uint8Array, network: ZcashNetworkName): ZcashIronwoodBitGoPsbt {
    const wasm = WasmBitGoPsbt.from_bytes(bytes, network);
    const psbt = new ZcashIronwoodBitGoPsbt(wasm);
    if (psbt.versionGroupId !== IRONWOOD_VERSION_GROUP_ID) {
      throw new Error(
        "not a v6 (Ironwood) PSBT: use ZcashBitGoPsbt.fromBytes for v4/Sapling-shaped PSBTs",
      );
    }
    return psbt;
  }

  /**
   * Add the shielded output (Constructor role). Stores the orchard PCZT in the PSBT.
   *
   * Named for the shielded/transparent split rather than the note type, leaving room for a
   * transparent-output variant alongside the inherited `addOutput` / `addWalletOutput`.
   *
   * @param recipient - 43-byte raw Orchard/Ironwood address
   * @param amount - note value in zatoshi
   * @param options.anchor - 32-byte Ironwood note-commitment-tree root
   * @param options.memo - optional 512-byte memo (defaults to the ZIP-302 "no memo" encoding)
   * @param options.ovk - optional 32-byte outgoing viewing key (omit for a keyless build)
   */
  addShieldedOutput(
    recipient: Uint8Array,
    amount: bigint,
    options: { anchor: Uint8Array; memo?: Uint8Array; ovk?: Uint8Array },
  ): void {
    const memo = options.memo ?? zip302NoMemo();
    this.wasm.add_ironwood_output(recipient, amount, options.ovk, options.anchor, memo);
  }

  /**
   * The canonical (display-order) ZIP-244 v6 txid as a lowercase hex string, matching
   * `ITransaction.getId()`. Defined once the transparent inputs/outputs and the shielded output are
   * in place; unchanged by signing or proving.
   */
  getId(): string {
    return this.wasm.ironwood_v6_txid();
  }

  /**
   * The ZIP-244 per-input transparent sighash (32 bytes) the key controlling transparent input
   * `index` must sign.
   */
  transparentSighash(index: number): Uint8Array {
    return this.wasm.ironwood_v6_transparent_sighash(index);
  }

  /**
   * Ingest a transparent-input signature returned by the client/HSM, after verifying it against
   * {@link transparentSighash} for that input.
   *
   * @param index - transparent input index
   * @param pubkey - the signing public key
   * @param sig - DER ECDSA signature with the trailing SIGHASH_ALL byte (as in a scriptSig)
   */
  addTransparentSignature(index: number, pubkey: Uint8Array, sig: Uint8Array): void {
    this.wasm.add_ironwood_v6_signature(index, pubkey, sig);
  }

  /**
   * Transaction Extractor role: given the external prover's `proof` bytes, finalize the
   * transparent inputs, apply the shielded binding signature, and return the broadcast-ready v6
   * transaction bytes. Requires every transparent input to be signed via
   * {@link addTransparentSignature}.
   *
   * Terminal: the wasm binding drops the stored PCZT on success, so any later v6 call on this PSBT
   * throws — including after a `serialize`/{@link fromBytes} round-trip, since the PCZT is gone
   * from the bytes too. Build a fresh PSBT instead. On failure nothing is dropped, so a call that
   * errors (bad proof, unsigned input) leaves the PSBT retryable.
   */
  combineProof(proof: Uint8Array): Uint8Array {
    return this.wasm.combine_ironwood_proof(proof);
  }
}
