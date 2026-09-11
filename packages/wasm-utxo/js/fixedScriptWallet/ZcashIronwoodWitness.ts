import {
  IronwoodWitness as WasmIronwoodWitness,
  ironwood_build_witness,
  ironwood_build_witness_from_shard,
} from "../wasm/wasm_utxo.js";

/**
 * A node of a pruned Orchard note-commitment (sub)tree, for {@link ZcashIronwoodWitness.buildFromShard}'s
 * `shard`/`cap` inputs. Mirrors a real pruned tree store's shape (e.g. a `shardtree::ShardTree`):
 * most leaves are never individually retained, only enough annotated hashes to reproduce a witness.
 */
export type ShardTreeNode =
  | { type: "Nil" }
  | { type: "Leaf"; hash: Uint8Array }
  | { type: "Parent"; hash?: Uint8Array; left: ShardTreeNode; right: ShardTreeNode };

/**
 * A validated Merkle witness for an Ironwood/Orchard note commitment.
 *
 * Build with {@link ZcashIronwoodWitness.build}: `cmx` is the note commitment being
 * witnessed, `authPath` must be exactly 32 sibling hashes (32 bytes each, leaf-to-root
 * order), and `anchor` is the expected note-commitment-tree root. Throws if any input
 * isn't a canonical field element, or if the witness doesn't recompute to `anchor`.
 *
 * wasm-utxo has no chain state, so the raw sibling-hash path must be supplied by the
 * caller (typically BitGo's backend, querying a Zcash-aware service).
 */
export class ZcashIronwoodWitness {
  private constructor(private _wasm: WasmIronwoodWitness) {}

  /**
   * Build and validate a Merkle witness for an Ironwood/Orchard note commitment.
   * @throws If any input isn't a canonical field element, or the witness doesn't
   *   recompute to `anchor`
   */
  static build(
    cmx: Uint8Array,
    position: number,
    authPath: Uint8Array[],
    anchor: Uint8Array,
  ): ZcashIronwoodWitness {
    return new ZcashIronwoodWitness(ironwood_build_witness(cmx, position, authPath, anchor));
  }

  /**
   * Build and validate a Merkle witness from a pruned shard + cap, instead of a
   * caller-precomputed 32-entry path.
   *
   * `shardHeight` chooses which level the shard's root sits at (it spans up to `2^shardHeight`
   * leaves); `shard` is the pruned subtree containing `position`, rooted at that level; `cap` is
   * the pruned tree above every shard, down to (and including) shard-root nodes. `leafCount` is
   * the total number of leaves committed to the tree as of `anchor` — positions beyond it are
   * treated as canonically empty.
   * @throws Under the same conditions as {@link build}, plus if `shard`/`cap` don't have enough
   *   detail to witness `position` as of `leafCount`
   */
  static buildFromShard(
    position: number,
    shardHeight: number,
    leafCount: bigint,
    cmx: Uint8Array,
    shard: ShardTreeNode,
    cap: ShardTreeNode,
    anchor: Uint8Array,
  ): ZcashIronwoodWitness {
    return new ZcashIronwoodWitness(
      ironwood_build_witness_from_shard(position, shardHeight, leafCount, cmx, shard, cap, anchor),
    );
  }

  /** The leaf's position in the note commitment tree. */
  get position(): number {
    return this._wasm.position;
  }

  /**
   * The 32 sibling hashes (leaf-to-root order), flattened into a single 1024-byte array
   * (32 hashes × 32 bytes each).
   */
  get authPath(): Uint8Array {
    return this._wasm.auth_path;
  }

  /** @internal */
  get wasm(): WasmIronwoodWitness {
    return this._wasm;
  }
}
