import {
  IronwoodWitness as WasmIronwoodWitness,
  ironwood_build_witness,
} from "../wasm/wasm_utxo.js";

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
