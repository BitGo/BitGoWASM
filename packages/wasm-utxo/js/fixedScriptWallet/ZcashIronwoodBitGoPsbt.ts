import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { type BIP32Arg, BIP32, isBIP32Arg } from "../bip32.js";
import { type ECPairArg } from "../ecpair.js";
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
   * Client-managed `ovk`: re-encrypt the shielded output's `out_ciphertext` under **this wallet's**
   * `ovk`, derived as the ECDH agreement of `rootWalletKeys.bitgoKey()` and `userKey`. Both are root
   * keys, so the `ovk` does not depend on which inputs the transaction spends, and the server can
   * re-derive the identical value from its own private key plus the user's public key in order to
   * validate `out_ciphertext` before countersigning. The server never sees `userKey` or the `ovk`.
   *
   * `userKey` must be the wallet's user root key — passing the backup or BitGo key throws, since an
   * `ovk` derived from those is one neither the user nor the server can reproduce, and the resulting
   * transaction would broadcast fine while leaving the shielded output permanently unrecoverable.
   *
   * Normally you do not call this directly: {@link sign} performs it on the first signing round.
   *
   * Must be called **before** signing: `out_ciphertext` is committed by the ZIP-244 sighash, so
   * calling this after any transparent signature has been added (via
   * {@link addTransparentSignature}) throws rather than silently invalidating that signature.
   *
   * @param actionIndex - index of the Ironwood action whose output to re-encrypt (always `0`: only
   *   one shielded output per transaction is supported, see {@link addShieldedOutput})
   * @param userKey - the wallet's user root key (an xpriv)
   * @param rootWalletKeys - the wallet's root keys, supplying the BitGo cosigner pubkey
   */
  setShieldedOutCiphertext(
    actionIndex: number,
    userKey: BIP32Arg,
    rootWalletKeys: WalletKeysArg,
  ): void {
    this.wasm.set_ironwood_out_ciphertext(
      actionIndex,
      BIP32.from(userKey).wasm,
      RootWalletKeys.from(rootWalletKeys).wasm,
    );
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
   * Sign every transparent input `key` resolves a private key for, over the ZIP-244 transparent
   * sighash. The v6 (Ironwood) counterpart to the inherited `sign(key)` — that base implementation
   * rejects v6 PSBTs outright, since it only knows the ZIP-243 digest.
   *
   * If no transparent signature has been added to this PSBT yet, this is the first signing round and
   * `key` must be the wallet's user root key: it is used with `rootWalletKeys.bitgoKey()` to derive
   * this wallet's `ovk` and finalize `out_ciphertext` — the client-managed-`ovk` flow — before any
   * sighash is computed. Once a signature exists, that step is a no-op, so a caller passes
   * `rootWalletKeys` on every signing round unconditionally: `psbt.sign(userXpriv, rootWalletKeys)`
   * and later `psbt.sign(bitgoXpriv, rootWalletKeys)` — only the first call actually uses it.
   * `rootWalletKeys` is mandatory precisely so that step can never be silently skipped by omission.
   *
   * **The user must sign first**, and this is enforced: a first round opened by any other key throws
   * rather than deriving an `ovk` that neither the user nor the server can reproduce. One consequence
   * is that a backup-key recovery cannot open the first signing round of a shielding transaction.
   *
   * `rootWalletKeys` is typed optional only so this override type-checks against the inherited
   * `sign(key)` signature — omitting it throws at runtime rather than silently signing without the
   * `ovk` step.
   *
   * @param key - an xpriv (BIP32Arg); raw privkeys (ECPairArg) are not meaningful here, since
   *   `out_ciphertext` derivation needs the key's `bip32_derivation` path
   * @param rootWalletKeys - the wallet's root keys (required). Any {@link WalletKeysArg} form, same
   *   as {@link setShieldedOutCiphertext} and {@link createEmpty} — an xpub triple, a utxo-lib
   *   `RootWalletKeys`, or this package's own — so it is never sensitive to which copy of the class
   *   a caller's `RootWalletKeys` came from.
   * @returns the transparent input indices that were signed
   */
  override sign(key: BIP32Arg | ECPairArg, rootWalletKeys?: WalletKeysArg): number[];
  /**
   * @deprecated Not supported for v6 (Ironwood): always throws. Inherited only because the base
   * class's single-input overload must be preserved for the override to type-check; use
   * {@link sign} (all matching inputs) instead.
   */
  override sign(inputIndex: number, key: BIP32Arg | ECPairArg): void;
  // The second parameter is `WalletKeysArg` in the public (first) overload above — the only form
  // callers see. It widens here solely to stay assignable to the deprecated `(inputIndex, key)`
  // overload, whose own second parameter is a key; narrowing it to `WalletKeysArg` is TS2394.
  override sign(
    keyOrIndex: BIP32Arg | ECPairArg | number,
    keyOrRootWalletKeys?: BIP32Arg | ECPairArg | WalletKeysArg,
  ): number[] | void {
    if (typeof keyOrIndex === "number") {
      throw new Error(
        "not supported for v6 (Ironwood): single-input sign(inputIndex, key) has no ZIP-244 " +
          "equivalent; use sign(key) to sign all matching inputs",
      );
    }
    if (!isBIP32Arg(keyOrIndex)) {
      throw new Error(
        "not supported for v6 (Ironwood): a raw privkey (ECPairArg) has no bip32_derivation path " +
          "to resolve out_ciphertext's ovk from; pass an xpriv",
      );
    }
    if (keyOrRootWalletKeys === undefined) {
      throw new Error(
        "rootWalletKeys is required for v6 (Ironwood) signing: sign(key, rootWalletKeys) — pass it " +
          "on every signing round, even Bitgo's, so the client-managed-ovk step is never silently " +
          "skipped",
      );
    }
    const wasmKey = BIP32.from(keyOrIndex).wasm;
    const keys = RootWalletKeys.from(keyOrRootWalletKeys as WalletKeysArg);
    return Array.from(this.wasm.sign_ironwood_v6(wasmKey, keys.wasm), Number);
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

  /**
   * The raw serialized orchard PCZT (Partially Created Zcash Transaction) bundle stored in this
   * PSBT, or `undefined` if none is present.
   *
   * A PCZT is the shielded-bundle counterpart to a PSBT: it accumulates the orchard action
   * (spend + output), the ZIP-244-committed `out_ciphertext`, and — once {@link combineProof} has
   * run — the Halo2 `zkproof` and binding signature, bridging this PSBT to the external proof
   * service and back.
   *
   * Present only after {@link addShieldedOutput} has been called; `undefined` beforehand, and
   * `undefined` again after {@link combineProof} succeeds, since that call drops the stored PCZT
   * to make extraction terminal (see its doc comment).
   */
  getPczt(): Uint8Array | undefined {
    return this.wasm.ironwood_pczt_bytes();
  }
}
