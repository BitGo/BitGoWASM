import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { type BIP32Arg, BIP32, isBIP32Arg } from "../bip32.js";
import { ECPair, type ECPairArg } from "../ecpair.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import {
  IRONWOOD_VERSION_GROUP_ID,
  ZcashBitGoPsbt,
  type ZcashNetworkName,
  type ZcashParsedInput,
  type ZcashParsedOutput,
} from "./ZcashBitGoPsbt.js";
import {
  type ParsedTransaction,
  type ParseOutputsOptions,
  type ParseTransactionOptions,
} from "./BitGoPsbt.js";
import {
  type IronwoodShieldedStatus,
  type IronwoodVerificationReport,
  type ZcashShieldedOutputRequest,
  type ZcashShieldedSpend,
  type ZcashShieldedSpendRequest,
} from "./ZcashIronwoodTypes.js";
import { type ZcashIronwoodWitness } from "./ZcashIronwoodWitness.js";
import { Zip317Dimensions } from "./Zip317Dimensions.js";

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
 * Options for creating an empty Zcash v6 (Ironwood) shielding PSBT **without** wallet keys —
 * the MPC-shielded build, where no fixed-script xpub triple exists to stamp.
 *
 * Shape matches {@link CreateEmptyIronwoodOptions} minus `walletKeys`.
 */
export type CreateEmptyKeylessOptions = {
  /** Block height to determine the consensus branch ID automatically (at/after NU6.3 activation) */
  blockHeight: number;
  /** Zcash transaction expiry height */
  expiryHeight?: number;
  /** Lock time (default: 0) */
  lockTime?: number;
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
 * The parsed shape of a Zcash output through the Ironwood parse: the Zcash output shape plus
 * the PCZT action index (`null` for transparent outputs) and, for shielded outputs, the
 * change marker.
 */
export type ZcashIronwoodParsedOutput = ZcashParsedOutput & {
  actionIndex: number | null;
  /**
   * For a shielded output: whether it pays back to a spent note's own address (see
   * `verifyShieldedBundle`'s report); such outputs are excluded from the parse's
   * `spendAmount`. Always `false` for transparent outputs, whose wallet ownership is the
   * `scriptId` they carry.
   */
  isChange: boolean;
};

/**
 * The parsed shape of a v6 (Ironwood) transaction. A discriminated union on `inputKind`:
 * a shielded-input PSBT has no transparent inputs at all, and a transparent-input PSBT has
 * no shielded spends. `valueBalance` is the orchard bundle's value balance (Σv_spend −
 * Σv_out), `0` when there is no bundle.
 */
export type ZcashIronwoodParsedTransaction =
  | (IronwoodParsedBase & { inputKind: "transparent"; shieldedSpends: [] })
  | (IronwoodParsedBase & {
      inputKind: "shielded";
      inputs: [];
      shieldedSpends: ZcashShieldedSpend[];
    });

/**
 * The keyless parse of a v6 (Ironwood) transaction — the MPC-shielded shape, and the
 * wallet-keys-free counterpart to {@link ZcashIronwoodParsedTransaction}. The key-free
 * verifier runs first: a tampered bundle throws with the failing check's `err.code`.
 */
export type ZcashShieldedParsedTransaction = {
  /** The verified shielded spends, in action order. */
  shieldedSpends: ZcashShieldedSpend[];
  /**
   * Every output: transparent first (tx output order), then the shielded ones (action
   * order) — the same order {@link parseOutputsWithWalletKeys} reports. A transparent
   * output's address is its stored `unifiedAddress` (when `addTransparentOutput` was given
   * one) or the address decoded from the scriptPubKey; the wallet-ownership fields
   * (`scriptId`, `derivationPath`) are always null.
   */
  outputs: ZcashIronwoodParsedOutput[];
  /** The orchard bundle's value balance (Σv_spend − Σv_out); `0` without a bundle. */
  valueBalance: bigint;
  /**
   * Fee: total input value (transparent inputs + shielded spends) − total output value.
   * Transparent input values come from the PSBT's utxo fields as-is.
   */
  fee: bigint;
};

/** The parse fields shared by both `inputKind` arms. */
type IronwoodParsedBase = ParsedTransaction<ZcashIronwoodParsedOutput, ZcashParsedInput> & {
  valueBalance: bigint;
};

/**
 * A Zcash **v6 (Ironwood / NU6.3)** PSBT covering both shielded flows:
 *
 * - **Shielding** (transparent inputs → shielded outputs): `createEmpty`, the usual
 *   `addWalletInput` / `addWalletOutput`, then {@link addShieldedOutput}, transparent signing
 *   over {@link transparentSighash}, and {@link combineProof}.
 * - **Shielded spends** (deshield / shielded→shielded): `createEmpty` (transparent outputs
 *   only — a spend PSBT has no transparent *inputs*), then {@link addShieldedSpends}, which is
 *   **keyless**: no viewing key is needed to build it. The ciphertext round
 *   ({@link getOutCiphertextRequest} → viewing-key holder → {@link addOutCiphertexts}), the
 *   FROST round
 *   ({@link addSpendRandomizers} → {@link spendSighash} → FROST →
 *   {@link addSpendSignatures}), and the proof round ({@link getProofRequest} → prover →
 *   {@link combineProof}) follow, in that order, with the anchor refresh
 *   ({@link updateAnchorAndWitnesses}) allowed at any point before the proof request — a
 *   build whose approval sat long enough re-witnesses every spend under a fresh anchor
 *   without re-signing. Before signing, the client checks the bundle
 *   against its own spend-validating key and randomizers with {@link verifyShieldedBundle}.
 *
 * For custodial MPC shielded wallets — no fixed-script xpub triple at all — the constructor
 * is {@link createEmptyKeyless} (no `walletKeys`), and {@link parseShieldedTransaction}
 * surfaces the built transaction (`shieldedSpends` / `outputs` / `valueBalance` / `fee`)
 * without ever needing the keys.
 *
 * **Sign first, prove last.** Spend signatures are made over {@link spendSighash}, which
 * commits `rk` but neither the proof nor the randomizers `alpha`; the alphas reach the prover
 * out of band via {@link getProofRequest}. Signing freezes the bundle, so the proof is always
 * made over the final action data and can never go stale, and an unapproved build never costs
 * a proof.
 *
 * The ordering is enforced in Rust, and each violation surfaces as a typed `err.code`
 * (`IronwoodPsbtError.*`):
 *
 * - **One input kind** — a v6 PSBT spends either transparent inputs or shielded notes,
 *   never both (`MixedInputKinds`);
 * - **Ciphertexts first** — every real output's `out_ciphertext` before any randomizer,
 *   sighash or proof request (`OutCiphertextPending`);
 * - **Randomizers next** — every real spend's randomized `rk` before any sighash or
 *   signature (`RandomizerPending`);
 * - **Frozen once signed** — ciphertexts and randomizers rejected after any signature
 *   (`AlreadySigned`); the anchor is not sighash-committed, so its refresh stays open;
 * - **Signed before proven** — the proof is requested only once every real spend is signed
 *   (`SpendSignaturePending`).
 *
 * {@link shieldedStatus} reports where a PSBT stands in that sequence.
 *
 * Distinct from the generic `ZcashBitGoPsbt` (v4/Sapling-shaped transactions): a v6 PSBT carries
 * its shielded side as an orchard PCZT in the proprietary map rather than Sapling fields, and its
 * lifecycle follows a build → sign → combine flow rather than the v4 ZIP-243
 * signing path.
 *
 * Method names carry no `ironwood` prefix — the class name already says it. They follow the base
 * `BitGoPsbt` vocabulary (`createEmpty`, `fromBytes`, `addOutput`-style adders, `getId`) so the v6
 * surface reads the same as the v4 one; the wasm bindings keep an `ironwood` prefix because
 * they live on the single flat `BitGoPsbt` struct, where the prefix is what disambiguates them.
 *
 * @example shielding
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
 *
 * @example deshielding (one note → a transparent payout)
 * ```typescript
 * const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcash", walletKeys, { blockHeight });
 * psbt.addTransparentOutput(payoutScript, payoutValue); // no transparent inputs
 * const { spendActionIndices } = psbt.addShieldedSpends([note], [], { anchor });
 * // Ciphertext round: ciphertexts first
 * const { pczt, actionIndices } = psbt.getOutCiphertextRequest();
 * psbt.addOutCiphertexts(await reEncryptOutputs(pczt, actionIndices));
 * // FROST round: randomizers (only rk is stored), then signatures
 * psbt.addSpendRandomizers(frostRandomizers, { spendValidatingKey: ak });
 * psbt.addSpendSignatures(await frostSign(psbt.spendSighash()));
 * // Proof round: alphas patched into the returned bytes, never stored
 * const proofRequest = psbt.getProofRequest(frostRandomizers);
 * const tx = psbt.combineProof(await prove(proofRequest));
 * ```
 */
export class ZcashIronwoodBitGoPsbt extends ZcashBitGoPsbt<
  ZcashIronwoodParsedOutput,
  ZcashParsedInput
> {
  /**
   * Parse the transaction through the Zcash parse, which surfaces the shielded side the
   * generic parse refuses to drop: per-action output indices, the shielded spends, and the
   * bundle's value balance. The key-free verifier checks the bundle before any plaintext
   * value is returned.
   */
  override parseTransactionWithWalletKeys(
    walletKeys: WalletKeysArg,
    options: ParseTransactionOptions,
  ): ZcashIronwoodParsedTransaction {
    return super.parseTransactionWithWalletKeys(
      walletKeys,
      options,
    ) as ZcashIronwoodParsedTransaction;
  }

  /**
   * Parse outputs through the Zcash parse: every output carries `isShielded` and, for
   * shielded outputs, its `actionIndex` and `isChange`.
   */
  override parseOutputsWithWalletKeys(
    walletKeys: WalletKeysArg,
    options?: ParseOutputsOptions,
  ): ZcashIronwoodParsedOutput[] {
    return super.parseOutputsWithWalletKeys(walletKeys, options);
  }

  /**
   * The keyless parse — the MPC-shielded shape, and the wallet-keys-free counterpart to
   * {@link parseTransactionWithWalletKeys}: the verified shielded spends, every output, the
   * bundle's value balance, and the fee. Transparent inputs are not surfaced (a spend bundle
   * has none) and transparent outputs are decoded without keys, so the wallet-ownership
   * fields (`scriptId`, `derivationPath`) stay null.
   *
   * Transparent input values are taken from the PSBT's utxo fields as-is — nothing here
   * can verify them against the chain — so a transparent-input parse's `fee` trusts those
   * fields; the MPC spend shapes carry no transparent inputs, so their `fee` is fully
   * verified.
   *
   * Throws `ZcashParseTransactionError.NotIronwoodV6` on a non-v6 PSBT, and
   * `ZcashParseTransactionError.MixedInputKinds` when transparent inputs ride alongside
   * shielded spends. After {@link combineProof} the PCZT is gone (that call is terminal),
   * so the parse throws `ZcashParseTransactionError.Shielded` rather than reporting no
   * shielded side.
   */
  parseShieldedTransaction(): ZcashShieldedParsedTransaction {
    return this.wasm.parse_shielded_transaction() as ZcashShieldedParsedTransaction;
  }

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
   * Create an empty Zcash **v6 (Ironwood)** shielding PSBT **without** wallet keys — the
   * MPC-shielded constructor, with the consensus branch ID determined from block height.
   *
   * A custodial MPC shielded wallet has no fixed-script xpub triple, so there are no global
   * xpubs to stamp: the xpubs {@link createEmpty} embeds are purely informational metadata,
   * and every other v6 method reads/writes only the proprietary-map fields this constructor
   * also sets. The transparent side uses `addWalletInput` / `addWalletOutput`, the shielded
   * side {@link addShieldedSpends} / {@link addShieldedOutput};
   * {@link parseShieldedTransaction} surfaces what was built, without needing any keys.
   *
   * @param network - Zcash network name ("zcash", "zcashTest", "zec", "tzec")
   * @param options - Options including blockHeight (at/after NU6.3 activation)
   */
  static createEmptyKeyless(
    network: ZcashNetworkName,
    options: CreateEmptyKeylessOptions,
  ): ZcashIronwoodBitGoPsbt {
    const wasm = WasmBitGoPsbt.create_empty_zcash_v6_bare_at_height(
      network,
      options.blockHeight,
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

  /** @internal Create from a parsed WASM instance without reparsing the bytes. */
  static override fromWasm(wasm: WasmBitGoPsbt): ZcashIronwoodBitGoPsbt {
    return new ZcashIronwoodBitGoPsbt(wasm);
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
   * @param options.ovk - optional 32-byte outgoing viewing key (omit for a keyless build). Has no
   *   effect in the normal flow: {@link sign}'s first round re-encrypts every action's
   *   `out_ciphertext` under the wallet `ovk`, replacing whatever this produced
   * @param options.unifiedAddress - optional full Unified Address string this output was addressed
   *   to. Its Orchard receiver must equal `recipient`. The PCZT itself only carries the raw 43-byte
   *   receiver — a lossy encoding for a multi-receiver UA, since any transparent/Sapling receiver
   *   can't be recovered from it — so passing this stores the original UA verbatim, letting a later
   *   `parseOutputsWithWalletKeys`/`parseTransactionWithWalletKeys` (even after a
   *   serialize/deserialize round-trip) return it in full instead of a re-encoded single-receiver UA.
   */
  addShieldedOutput(
    recipient: Uint8Array,
    amount: bigint,
    options: { anchor: Uint8Array; memo?: Uint8Array; ovk?: Uint8Array; unifiedAddress?: string },
  ): void {
    const memo = options.memo ?? zip302NoMemo();
    this.wasm.add_ironwood_output(
      recipient,
      amount,
      options.ovk,
      options.anchor,
      memo,
      options.unifiedAddress,
    );
  }

  /**
   * Add one or more shielded outputs (Constructor role) as a single orchard PCZT — the
   * multi-recipient counterpart to {@link addShieldedOutput}. Every recipient must be passed in
   * one call: only one call to `addShieldedOutput`/`addShieldedOutputs` is supported per PSBT (see
   * {@link addShieldedOutput}).
   *
   * @param outputs - one entry per recipient; `memo` defaults per-entry to the ZIP-302 "no memo"
   *   encoding, exactly as {@link addShieldedOutput}'s does, and `ovk` is likewise replaced by
   *   {@link sign}'s first round
   * @param anchor - 32-byte Ironwood note-commitment-tree root, shared by every output
   * @returns the action index assigned to each output, in the same order as `outputs` — the
   *   orchard builder pads/reorders actions, so any caller correlating per-action data (a stored
   *   unified address, an explicit `setShieldedOutCiphertext` call) must use these indices, not the
   *   position in `outputs` — though note {@link sign}'s first round already patches every action's
   *   `out_ciphertext` with the wallet `ovk` on its own.
   */
  addShieldedOutputs(
    outputs: Array<{
      recipient: Uint8Array;
      amount: bigint;
      memo?: Uint8Array;
      ovk?: Uint8Array;
      unifiedAddress?: string;
    }>,
    anchor: Uint8Array,
  ): number[] {
    return Array.from(
      this.wasm.add_ironwood_outputs(
        outputs.map((o) => ({
          recipient: o.recipient,
          amount: o.amount,
          memo: o.memo ?? zip302NoMemo(),
          ovk: o.ovk,
          unifiedAddress: o.unifiedAddress,
        })),
        anchor,
      ),
    );
  }
  // ---- The shielded-spend flow: build → ciphertexts → sign → prove ----

  /**
   * Add the shielded spends (and optionally shielded outputs) as a single **keyless** orchard
   * PCZT stored in the PSBT — the deshield and shielded→shielded Constructor for a build
   * service that holds no viewing keys.
   *
   * One input kind: a v6 PSBT spends either transparent inputs or shielded notes, never both —
   * this throws if a transparent input is already present, and the transparent input adders
   * throw once real shielded spends exist. One call per PSBT.
   *
   * Every real spend carries the placeholder `rk` and no `alpha`; the signer installs the
   * randomized `rk` via {@link addSpendRandomizers} before any sighash is computed. Every
   * output's `out_ciphertext` is a random placeholder, replaced under the FVK's `ovk` (see
   * {@link getOutCiphertextRequest}). No key material is accepted or stored.
   *
   * @param spends - one entry per spent note: the note's plaintext (`recipient`, `value`,
   *   `rho`, `rseed`, `cmx`), its {@link ZcashIronwoodWitness} (validated against
   *   `options.anchor`), and the nullifier (from the note store or derived by the viewing-key
   *   holder)
   * @param outputs - zero or more requested shielded outputs; every amount must be > 0, and
   *   there is no `ovk` — encryption belongs to the viewing-key holder in the spend flow. `memo` defaults per-entry to
   *   the ZIP-302 "no memo" encoding, as {@link addShieldedOutput}'s does
   * @param options.anchor - the Ironwood note-commitment-tree root every spend's witness
   *   commits to (32 bytes)
   * @param options.change - optional `{ amount, spendIndex }`: one more shielded output paying
   *   `amount` back to `spends[spendIndex]`'s own address — the only shielded change a keyless
   *   client can recognize (its address is derived from the wallet's spend-authorizing key, so a
   *   note back to it is spendable only by this wallet). Without it every shielded output is an
   *   external send. Only an exact address match counts: change to another diversified address
   *   of the same wallet is reported as an external send.
   * @returns the action index each requested spend/output landed at, and the change output's
   *   action index when requested. With change, `outputActionIndices` has one more entry than
   *   `outputs`: its last entry is `changeActionIndex`. The actions are shuffled, so request
   *   order does not equal action order: any caller correlating per-action data (a stored
   *   Unified Address, an out-ciphertext) must go through these indices.
   */
  addShieldedSpends(
    spends: ZcashShieldedSpendRequest[],
    outputs: ZcashShieldedOutputRequest[],
    options: {
      anchor: Uint8Array;
      change?: { amount: bigint; spendIndex: number };
    },
  ): {
    spendActionIndices: number[];
    outputActionIndices: number[];
    changeActionIndex: number | null;
  } {
    const map = this.wasm.add_ironwood_shielded_spends(
      spends.map((spend) => ({
        recipient: spend.recipient,
        value: spend.value,
        rho: spend.rho,
        rseed: spend.rseed,
        cmx: spend.cmx,
        nullifier: spend.nullifier,
        witness: { position: spend.witness.position, authPath: spend.witness.authPath },
      })),
      outputs.map((output) => ({
        recipient: output.recipient,
        amount: output.amount,
        memo: output.memo ?? zip302NoMemo(),
        unifiedAddress: output.unifiedAddress,
      })),
      options.anchor,
      options.change
        ? { amount: options.change.amount, spendIndex: options.change.spendIndex }
        : null,
    ) as {
      spendActionIndices: number[];
      outputActionIndices: number[];
      changeActionIndex: number | null;
    };
    return {
      spendActionIndices: Array.from(map.spendActionIndices),
      outputActionIndices: Array.from(map.outputActionIndices),
      changeActionIndex: map.changeActionIndex,
    };
  }

  /**
   * The out-ciphertext request: the raw PCZT bytes plus the real outputs still pending their
   * `out_ciphertext`. The viewing-key holder re-encrypts each pending output under its FVK
   * `ovk` and returns one 80-byte ciphertext per action index, applied with {@link addOutCiphertexts}.
   *
   * Throws when the PSBT is not a spend bundle (`IronwoodPsbtError.NotSpendBundle`) or
   * nothing is pending (`IronwoodPsbtError.NothingPending`, e.g. a pure deshield, whose only
   * output is transparent and carries no ciphertext).
   */
  getOutCiphertextRequest(): { pczt: Uint8Array; actionIndices: number[] } {
    const request = this.wasm.ironwood_out_ciphertext_request() as {
      pczt: Uint8Array;
      actionIndices: number[];
    };
    return { pczt: request.pczt, actionIndices: Array.from(request.actionIndices) };
  }

  /**
   * Apply the out-ciphertext response: one `{ actionIndex, outCiphertext }` entry per
   * pending real output. **Atomic** — every entry is validated before anything is written, so
   * one bad entry stores nothing. Idempotent for identical bytes; different bytes for an
   * already-set index throw (`IronwoodPsbtError.OutCiphertextConflict`). Frozen once signed:
   * rejected once any signature exists (`IronwoodPsbtError.AlreadySigned`).
   */
  addOutCiphertexts(entries: Array<{ actionIndex: number; outCiphertext: Uint8Array }>): void {
    this.wasm.add_ironwood_out_ciphertexts(entries);
  }

  /** Single-output counterpart to {@link addOutCiphertexts}. */
  addOutCiphertext(actionIndex: number, outCiphertext: Uint8Array): void {
    this.addOutCiphertexts([{ actionIndex, outCiphertext }]);
  }

  /**
   * Refresh the bundle's anchor and every real spend's Merkle witness — the re-witness step a
   * build whose approval sat too long runs before proving: the anchor is read once, fresh
   * witnesses are built for every spent note ({@link ZcashIronwoodWitness.build} against the
   * new anchor), and both land in one call. Allowed before **and after** signing: the v6
   * sighash does not commit the anchor (it sits in the authorizing digest, bound by the
   * proof), so the spend-auth signatures stay valid and no re-sign is needed. A refresh does
   * invalidate any proof request already handed out — call {@link getProofRequest} after the
   * last refresh, or {@link combineProof} gets a proof over the old anchor.
   *
   * `entries` carries exactly one `{ actionIndex, witness }` per real spend
   * (`IronwoodPsbtError.WitnessMissing` otherwise — the anchor is bundle-level, so a spend
   * left on its old witness would make the bundle internally inconsistent). Every witness is
   * re-validated against the new anchor over the spend's own note commitment: a stale
   * witness for the old anchor throws (`IronwoodBuildError.WitnessAnchorMismatch`), and
   * nothing is written unless every entry validates (**atomic** — one bad entry stores
   * nothing).
   *
   * @param anchor - the new Ironwood note-commitment-tree root (32 bytes)
   * @param entries - one `{ actionIndex, witness }` per real spend; the action indices are
   *   the `spendActionIndices` {@link addShieldedSpends} returned
   */
  updateAnchorAndWitnesses(
    anchor: Uint8Array,
    entries: Array<{ actionIndex: number; witness: ZcashIronwoodWitness }>,
  ): void {
    this.wasm.update_ironwood_anchor_and_witnesses(
      anchor,
      entries.map((entry) => ({
        actionIndex: entry.actionIndex,
        witness: { position: entry.witness.position, authPath: entry.witness.authPath },
      })),
    );
  }

  /**
   * Install the signer's randomized `rk`s: one `{ actionIndex, alpha, rk }` entry per real
   * spend, with `rk = ak.randomize(alpha)`. **Only `rk` is stored** — the PSBT never carries
   * `alpha` or the wallet's `ak` (with `rk`, an `alpha` would reveal `ak`).
   *
   * `options.spendValidatingKey` (the wallet's spend-validating key `ak`, 32 bytes, optional)
   * makes the installer check `rk == ak.randomize(alpha)` before storing; without it the pair
   * is checked later, by the client's key-free verifier and by the keyed prover.
   *
   * Ciphertexts first: rejected while any real output's `out_ciphertext` is pending
   * (`IronwoodPsbtError.OutCiphertextPending`). Frozen once signed
   * (`IronwoodPsbtError.AlreadySigned`). **Atomic** — one bad entry stores nothing.
   */
  addSpendRandomizers(
    entries: Array<{ actionIndex: number; alpha: Uint8Array; rk: Uint8Array }>,
    options?: { spendValidatingKey?: Uint8Array },
  ): void {
    this.wasm.add_ironwood_spend_randomizers(entries, options?.spendValidatingKey);
  }

  /** Single-spend counterpart to {@link addSpendRandomizers}. */
  setSpendRandomizer(
    actionIndex: number,
    alpha: Uint8Array,
    rk: Uint8Array,
    options?: { spendValidatingKey?: Uint8Array },
  ): void {
    this.addSpendRandomizers([{ actionIndex, alpha, rk }], options);
  }

  /**
   * The ZIP-244 sig digest (32 bytes) the real spends' spend-auth signatures are computed
   * over — the input to the FROST signing round. Every real output's `out_ciphertext` and
   * every real spend's randomized `rk` must be installed first: the digest commits both
   * (`IronwoodPsbtError.OutCiphertextPending` / `IronwoodPsbtError.RandomizerPending`
   * otherwise).
   */
  spendSighash(): Uint8Array {
    return this.wasm.ironwood_spend_sighash();
  }

  /**
   * Apply the signer's spend-auth signatures: one `{ actionIndex, signature }` entry per real
   * spend, each a 64-byte RedPallas signature over {@link spendSighash}, verified against the
   * spend's installed `rk` before it is stored. **Atomic.** Signing does not freeze this
   * method: every spend-auth signature is over the same digest, so signatures may arrive in
   * several batches.
   */
  addSpendSignatures(entries: Array<{ actionIndex: number; signature: Uint8Array }>): void {
    this.wasm.add_ironwood_spend_signatures(entries);
  }

  /** Single-spend counterpart to {@link addSpendSignatures}. */
  addSpendSignature(actionIndex: number, signature: Uint8Array): void {
    this.addSpendSignatures([{ actionIndex, signature }]);
  }

  /**
   * The proof request for the keyed prover: the raw PCZT bytes with each real spend's
   * randomizer `alpha` patched in — `randomizers` is one `{ actionIndex, alpha }` per real
   * spend. The alphas are written only to the returned bytes, never stored (with `rk`, an
   * `alpha` would reveal the wallet's `ak`); they travel out of band from the FROST round to
   * the prover with the proof request.
   *
   * Gated: every real output's `out_ciphertext`, every real spend's randomized `rk`, and
   * every real spend's spend-auth signature must be installed first. This is the gated
   * counterpart to the raw {@link getPczt} accessor, and replaces it for spend bundles.
   */
  getProofRequest(randomizers: Array<{ actionIndex: number; alpha: Uint8Array }>): Uint8Array {
    return this.wasm.ironwood_proof_request(randomizers);
  }

  /**
   * The orchestration view of the shielded workflow: the input kind, what is still pending at
   * each stage, and whether the PSBT is ready for its proof — `readyForProof` means
   * {@link getProofRequest} succeeds (given the alphas) and {@link combineProof} then needs
   * only the proof.
   */
  shieldedStatus(): IronwoodShieldedStatus {
    return this.wasm.ironwood_shielded_status() as IronwoodShieldedStatus;
  }

  /**
   * The client's key-free verification of the stored shielded bundle, driven by the caller's
   * own expectations. The PSBT is never trusted for who a spend belongs to: the
   * spend-validating key and the signer's randomized keys come in from the caller, never
   * from the PSBT.
   *
   * Runs the key-free verifier's checks — every output's plaintext note commits to its
   * recorded `cmx`, every action's net value commits to its `cv`, the bundle's value balance
   * equals the shown totals, every real spend's note commits to a leaf under the bundle's
   * anchor, no viewing-key material or stray randomizer rides the bundle, and every present
   * spend-auth signature verifies against its spend's `rk`. Once it passes, the only
   * transaction the client can sign over this bundle that verifies on-chain is one that
   * moves exactly the values shown; what the client *cannot* check (note ownership,
   * nullifier validity, a fresh anchor) can only make the transaction invalid, never
   * misdirected.
   *
   * @param options.spendValidatingKey - the client's own spend-validating key (32 bytes,
   *   optional). When given, every randomized real spend must carry
   *   `rk == ak.randomize(alpha)` for the matching `randomizers` entry: the client checks it
   *   is signing for its own wallet (`IronwoodVerifyError.Rk` otherwise).
   * @param options.randomizers - the signer's randomizers, one
   *   `{ actionIndex, alpha, rk }` per randomized real spend (optional). Each entry must
   *   land on a real spend; a spend whose installed `rk` does not match its entry is
   *   rejected.
   *
   * When every real spend's randomized `rk` is installed, the ZIP-244 sig digest is computed
   * here and any present spend-auth signature is verified over it
   * (`IronwoodVerifyError.SpendSignature`); a mid-flow bundle (placeholder `rk`s still
   * pending) verifies without the signature check instead.
   *
   * @returns the verified view of the bundle: {@link IronwoodVerificationReport}.
   * @throws Error with a typed `err.code`: `IronwoodVerifyError.<Check>` when any check
   *   fails, `IronwoodPsbtError.NotSpendBundle` when the PSBT carries no shielded bundle, and
   *   `IronwoodPsbtError.OutCiphertextPending` when randomized `rk`s are installed while a
   *   real output's `out_ciphertext` is still pending.
   */
  verifyShieldedBundle(options?: {
    spendValidatingKey?: Uint8Array;
    randomizers?: Array<{ actionIndex: number; alpha: Uint8Array; rk: Uint8Array }>;
  }): IronwoodVerificationReport {
    return this.wasm.verify_ironwood_shielded_bundle(
      options?.spendValidatingKey,
      options?.randomizers ?? [],
    ) as IronwoodVerificationReport;
  }

  /**
   * The ZIP-317 conventional fee (zatoshi) for this PSBT's shape: the transparent terms plus
   * the Ironwood action count (`max(real spends, real outputs)`) of the stored PCZT — shorthand
   * for `Zip317Dimensions.fromPsbt(psbt).getConventionalFee()`. Before {@link addShieldedSpends}
   * there is no PCZT, so the shielded term is zero; size a change output from the planned
   * counts with {@link Zip317Dimensions} instead.
   */
  zip317ConventionalFee(): bigint {
    return Zip317Dimensions.fromPsbt(this).getConventionalFee();
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
   * Normally you do not call this directly: {@link sign} performs it for **every** action on the
   * first signing round (idempotently — same `ovk`, same bytes).
   *
   * Must be called **before** signing: `out_ciphertext` is committed by the ZIP-244 sighash, so
   * calling this after any transparent signature has been added (via
   * {@link addTransparentSignature}) throws rather than silently invalidating that signature.
   *
   * @param actionIndex - index of the Ironwood action whose output to re-encrypt; use an index
   *   returned by {@link addShieldedOutputs} (the orchard builder may reorder actions, so it is not
   *   necessarily the output's position in the call)
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
   * `ITransaction.getId()`. Defined once the transparent inputs/outputs are in place; unchanged by
   * signing or proving. Works whether or not a shielded output has been added — a transparent-only
   * v6 PSBT has a well-defined ZIP-244 txid too.
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
   * Ingest a transparent-input signature returned by a signer, after verifying it against
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
   * this wallet's `ovk` and finalize **every** action's `out_ciphertext` — the client-managed-`ovk`
   * flow, multi-recipient builds included — before any
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
   * Check whether transparent input `inputIndex` carries a valid signature by `key`, over the
   * ZIP-244 transparent sighash — the digest v6 (Ironwood) keys actually sign (see
   * {@link transparentSighash}). The inherited `BitGoPsbt.verifySignature` digests ZIP-243
   * (Sapling) instead, so it would report `false` for a valid v6 signature; this override routes
   * to the v6 sighash path instead.
   *
   * Mirrors the inherited signature: an xpub (BIP32Arg) resolves to a public key via the input's
   * `bip32_derivation`; a raw key (ECPairArg) verifies with its public key directly.
   *
   * @param inputIndex - 0-based transparent input index
   * @param key - the signing key: an xpub (BIP32Arg: base58 string, BIP32 instance, or WasmBIP32)
   *   or an ECPairArg (Uint8Array, ECPair instance, or WasmECPair)
   * @returns true if a valid signature by the key's public key exists for the input's
   *   ZIP-244 transparent sighash
   * @throws Error if the input index is out of range, the key cannot be parsed, or the v6
   *   sighash cannot be computed. Works whether or not a shielded output has been added; the one
   *   case this still throws for is a shielded output that was added and then consumed by
   *   `combineProof` (its action data is gone, not merely absent).
   *
   * @example
   * ```typescript
   * // Verify the user's signature over the v6 transparent sighash
   * const hasUserSig = psbt.verifySignature(0, userXpub);
   * ```
   */
  override verifySignature(inputIndex: number, key: BIP32Arg | ECPairArg): boolean {
    if (isBIP32Arg(key)) {
      return this.wasm.verify_ironwood_v6_signature_with_xpub(inputIndex, BIP32.from(key).wasm);
    }

    // Otherwise it's an ECPairArg (Uint8Array, ECPair, or WasmECPair)
    const wasmECPair = ECPair.from(key).wasm;
    return this.wasm.verify_ironwood_v6_signature_with_pub(inputIndex, wasmECPair);
  }
  /**
   * Transaction Extractor role: given the external prover's `proof` bytes, finalize the
   * transparent inputs, apply the shielded binding signature, and return the broadcast-ready v6
   * transaction bytes.
   *
   * What must be signed depends on the PSBT's input kind ({@link shieldedStatus}):
   *
   * - **Shielding** — every transparent input, via {@link addTransparentSignature} (2-of-3).
   * - **Shielded spends** — every real spend's spend-auth signature, via
   *   {@link addSpendSignatures}; there are no transparent inputs to sign. The proof here is
   *   the one the prover returned for {@link getProofRequest}'s bytes — pass it straight in.
   *
   * The proof's length must match the bundle's action count (`ProofLength` otherwise), and the
   * shielded binding signature is derived from the actions' value-commitment trapdoors, so the
   * alphas never need to be present at combine time.
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
   * Transaction Extractor role for a transparent-only v6 transaction: valid only when
   * no shielded output was ever added via {@link addShieldedOutput}/{@link addShieldedOutputs} —
   * there is no PCZT, and therefore nothing to combine an external proof into. Finalizes the
   * transparent inputs (the same 2-of-3 signature check {@link combineProof} performs) and
   * returns broadcast-ready v6 transaction bytes with an empty Ironwood bundle slot.
   *
   * Not terminal (unlike {@link combineProof}): there is no stored PCZT to drop, so calling this
   * more than once is safe and simply re-finalizes the same already-signed inputs.
   *
   * Use {@link combineProof} instead for a PSBT that carries (or carried) a shielded output.
   *
   * @throws Error if a shielded output was ever added to this PSBT (even one already extracted),
   *   or if any transparent input is missing a required signature
   */
  extractTransparentOnlyTransaction(): Uint8Array {
    return this.wasm.extract_transparent_only_v6_tx();
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
   * **Raw accessor.** It hands over whatever is stored, with no workflow gate. For a spend
   * bundle, the gated counterpart is {@link getProofRequest}: it only returns bytes once the
   * ciphertexts and randomizers are installed and every real spend is signed, with the alphas
   * patched in — exactly what the keyed prover needs. Shielding keeps
   * using `getPczt()`: the finalize step re-encrypts the dummy actions' ciphertexts itself, so
   * the raw bytes are already final when the proof is requested.
   *
   * Present only after {@link addShieldedOutput} (shielding) or {@link addShieldedSpends}
   * (spends) has been called; `undefined` beforehand, and `undefined` again after
   * {@link combineProof} succeeds, since that call drops the stored PCZT to make extraction
   * terminal (see its doc comment).
   */
  getPczt(): Uint8Array | undefined {
    return this.wasm.ironwood_pczt_bytes();
  }
}
