/**
 * Shared Zcash Ironwood (v6) types for the shielded-spend flow.
 *
 * These describe what the build service, the client and KMS each see as the PSBT moves
 * through the flow in `docs/ironwood-shielded-spend-plan.md` §2. Parse-facing types live in
 * `ZcashIronwoodBitGoPsbt.ts`; this module holds the shared vocabulary.
 */

/** One shielded note to spend, as passed to `addShieldedSpends` (plan PR 5). */
export type ZcashShieldedSpendRequest = {
  /** Raw 43-byte Orchard recipient (diversifier ‖ pk_d). */
  recipient: Uint8Array;
  /** Note value in zatoshi. */
  value: bigint;
  /** The note's rho (the nullifier seed the spend re-derives). */
  rho: Uint8Array;
  /** The note's random seed. */
  rseed: Uint8Array;
  /** The note commitment the on-chain action carried. */
  cmx: Uint8Array;
  /** Merkle witness (position + auth path) proving `cmx` under the bundle's anchor. */
  witness: { position: number; authPath: Uint8Array[] };
  /** The spend's nullifier, from the note store or from KMS. */
  nullifier: Uint8Array;
};

/** One shielded output to create, as passed to `addShieldedSpends` (plan PR 5). */
export type ZcashShieldedOutputRequest = {
  /** Raw 43-byte Orchard recipient. */
  recipient: Uint8Array;
  /** Output value in zatoshi (> 0). */
  amount: bigint;
  /** ZIP-302 memo; defaults to the no-memo encoding. */
  memo?: Uint8Array;
  /** Full Unified Address the output was addressed to, preserved verbatim. */
  unifiedAddress?: string;
};

/**
 * The randomizer state of a shielded spend: `placeholder` while the spend still carries the
 * wallet's spend-validating key as its `rk`, `installed` once the signer delivered the
 * randomized `(alpha, rk)` pair.
 */
export const IronwoodRandomizerState = ["placeholder", "installed"] as const;
export type IronwoodRandomizerState = (typeof IronwoodRandomizerState)[number];

/** Whether a PSBT's inputs are transparent or shielded — exactly one per PSBT. */
export const ZcashInputKind = ["transparent", "shielded"] as const;
export type ZcashInputKind = (typeof ZcashInputKind)[number];

/** One real shielded spend, as surfaced by the Zcash parse. */
export type ZcashShieldedSpend = {
  /** The spend's action index in the orchard bundle. */
  actionIndex: number;
  /** Note value in zatoshi. */
  value: bigint;
  /** Raw Orchard recipient (43 bytes). */
  recipient: Uint8Array;
  /** The nullifier this spend reveals. */
  nullifier: Uint8Array;
  /**
   * The note commitment recomputed from the verified plaintext: the key-free verifier
   * checks it commits to a leaf under the bundle's anchor and matches the recorded `cmx`.
   */
  cmx: Uint8Array;
  /** The witness's leaf position in the commitment tree. */
  position: number;
  /** The single-receiver Unified Address of the spent note's Orchard receiver. */
  address: string;
  /** Randomizer state of the spend's `rk` (see {@link IronwoodRandomizerState}). */
  randomizer: IronwoodRandomizerState;
  /** Whether a spend-auth signature is installed for this spend. */
  signed: boolean;
};

/** The client-side verification report of a shielded bundle (plan PR 4). */
export type IronwoodVerificationReport = {
  /** The bundle's real spends, as verified. */
  spends: ZcashShieldedSpend[];
  /** The bundle's real outputs. */
  outputs: Array<{ actionIndex: number; value: bigint; recipient: Uint8Array }>;
  /** The bundle's value balance (Σv_spend − Σv_out). */
  valueBalance: bigint;
  /** The anchor the spends' witnesses commit to. */
  anchor: Uint8Array;
};

/** Orchestration state of the shielded side of a spend PSBT (plan PR 7). */
export type IronwoodShieldedStatus = {
  inputKind: ZcashInputKind;
  /** Action indices whose `out_ciphertext` is still pending. */
  pendingOutCiphertexts: number[];
  /** Action indices whose randomizer `(alpha, rk)` is still pending. */
  pendingRandomizers: number[];
  /** Action indices whose spend-auth signature is still pending. */
  pendingSpendSignatures: number[];
  /** Whether a Halo2 proof is installed in the PCZT. */
  hasProof: boolean;
  /** Whether the PSBT is ready for `combineProof`. */
  readyToCombine: boolean;
};
