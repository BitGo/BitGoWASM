package com.bitgo.wasm.privacycoin.zcash;

import com.bitgo.wasm.privacycoin.MerkleTreeInfo;
import com.bitgo.wasm.privacycoin.WasmException;
import com.bitgo.wasm.privacycoin.proto.AppendCommitmentsRequest;
import com.bitgo.wasm.privacycoin.proto.FromFrontierRequest;
import com.bitgo.wasm.privacycoin.proto.Response;
import com.bitgo.wasm.privacycoin.proto.TreeInfo;
import com.bitgo.wasm.privacycoin.proto.TruncateRequest;
import com.google.protobuf.ByteString;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * High-level Java wrapper for the shielded commitment tree WASM module.
 *
 * <p>Each instance owns a dedicated Chicory WASM runtime; two {@code ShieldedMerkleTree}
 * instances share no state. Implements {@link AutoCloseable} for use in try-with-resources.
 *
 * <p>All type marshaling uses the protobuf wire format: requests are proto-encoded bytes
 * written into WASM linear memory; responses are read from the LAST_RESULT buffer.
 *
 * <p><b>Thread safety:</b> Not thread-safe. Do not share instances across threads.
 */
public final class ShieldedMerkleTree implements AutoCloseable {

  private final WasmBridge bridge;

  private ShieldedMerkleTree(WasmBridge bridge) {
    this.bridge = bridge;
  }

  // -------------------------------------------------------------------------
  // Factory methods
  // -------------------------------------------------------------------------

  private static ShieldedMerkleTree create(Consumer<WasmBridge> init) {
    var bridge = new WasmBridge();
    boolean ok = false;
    try {
      init.accept(bridge);
      ok = true;
      return new ShieldedMerkleTree(bridge);
    } finally {
      if (!ok) bridge.close();
    }
  }

  /**
   * Initializes a new tree from a CommitmentTree v0 frontier
   * (the {@code orchardTree} value from {@code z_gettreestate}).
   *
   * @param frontier     raw CommitmentTree v0 bytes
   * @param blockHeight  block height at which the frontier was captured (u32 range)
   * @return initialized tree instance
   * @throws WasmException if the frontier is invalid
   */
  public static ShieldedMerkleTree fromFrontier(byte[] frontier, long blockHeight) {
    Objects.requireNonNull(frontier, "frontier must not be null");
    requireU32(blockHeight, "blockHeight");
    return create(bridge -> {
      byte[] reqBytes = FromFrontierRequest.newBuilder()
          .setFrontier(ByteString.copyFrom(frontier))
          // safe: requireU32 guarantees blockHeight is in [0, 0xFFFF_FFFF]
          .setBlockHeight((int) blockHeight)
          .build()
          .toByteArray();
      unwrapVoid(bridge.call("from_frontier", reqBytes));
    });
  }

  /**
   * Restores a tree from a {@link TreeState} previously returned by {@link #save()}.
   *
   * @param state  serialized state from a prior {@code save()} call
   * @return restored tree instance
   * @throws WasmException if the state is invalid
   */
  public static ShieldedMerkleTree fromState(TreeState state) {
    Objects.requireNonNull(state, "state must not be null");
    // State bytes are passed directly — no proto wrapper needed for from_state.
    return create(bridge -> unwrapVoid(bridge.call("from_state", state.bytes())));
  }

  // -------------------------------------------------------------------------
  // Instance operations
  // -------------------------------------------------------------------------

  /** Verifies the WASM module is responding. */
  public void ping() {
    bridge.call("ping");
  }

  /**
   * Appends note commitments for a block, checkpoints the tree, and optionally
   * verifies the root.
   *
   * @param blockHeight   block height (u32 range)
   * @param commitments   shielded note commitment values (cmx) for this block
   * @param expectedRoot  root to verify against; {@code null} to skip
   * @return computed root after appending
   * @throws WasmException with code {@code ROOT_MISMATCH} if verification fails
   */
  public ShieldedRoot appendCommitments(
      long blockHeight, List<ShieldedCommitment> commitments, ShieldedRoot expectedRoot) {
    requireU32(blockHeight, "blockHeight");
    Objects.requireNonNull(commitments, "commitments must not be null");

    AppendCommitmentsRequest.Builder req = AppendCommitmentsRequest.newBuilder()
        // safe: requireU32 guarantees blockHeight is in [0, 0xFFFF_FFFF]
        .setBlockHeight((int) blockHeight)
        .addAllCommitments(commitments.stream()
            .map(c -> ByteString.copyFrom(c.bytes()))
            .toList());
    if (expectedRoot != null) {
      req.setExpectedRoot(ByteString.copyFrom(expectedRoot.bytes()));
    }

    Response r = bridge.call("append_commitments", req.build().toByteArray());
    return ShieldedRoot.of(unwrap(r, resp -> resp.getBytesValue().toByteArray()));
  }

  /** Convenience overload — appends without root verification. */
  public ShieldedRoot appendCommitments(long blockHeight, List<ShieldedCommitment> commitments) {
    return appendCommitments(blockHeight, commitments, null);
  }

  /**
   * Rolls the tree back to the checkpoint at the given block height.
   *
   * @param blockHeight  height of the checkpoint to restore (u32 range)
   * @return root at the restored checkpoint
   * @throws WasmException with code {@code CHECKPOINT_NOT_FOUND} if no checkpoint exists
   */
  public ShieldedRoot truncateToCheckpoint(long blockHeight) {
    requireU32(blockHeight, "blockHeight");
    byte[] reqBytes = TruncateRequest.newBuilder()
        // safe: requireU32 guarantees blockHeight is in [0, 0xFFFF_FFFF]
        .setBlockHeight((int) blockHeight)
        .build()
        .toByteArray();
    Response r = bridge.call("truncate_to_checkpoint", reqBytes);
    return ShieldedRoot.of(unwrap(r, resp -> resp.getBytesValue().toByteArray()));
  }

  /**
   * Serializes the current tree state for later restoration via {@link #fromState(TreeState)}.
   *
   * @return opaque state snapshot
   * @throws WasmException if serialization fails
   */
  public TreeState save() {
    Response r = bridge.call("save_state");
    return TreeState.of(unwrap(r, resp -> resp.getBytesValue().toByteArray()));
  }

  /**
   * Returns metadata about the current tree state.
   *
   * @return tree info snapshot
   * @throws WasmException if the call fails
   */
  public MerkleTreeInfo getInfo() {
    Response r = bridge.call("get_info");
    TreeInfo info = unwrap(r, Response::getInfoValue);
    // getTipHeight() returns int; mask to treat as unsigned uint32.
    Long tipHeight = info.hasTipHeight() ? (info.getTipHeight() & 0xFFFFFFFFL) : null;
    return new MerkleTreeInfo(tipHeight, info.getLeafCount(), info.getCheckpointCount());
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private static void unwrapVoid(Response response) {
    if (response.hasError()) throw WasmBridge.toWasmException(response.getError());
  }

  private static <T> T unwrap(Response response, Function<Response, T> extractor) {
    if (response.hasError()) throw WasmBridge.toWasmException(response.getError());
    return extractor.apply(response);
  }

  private static void requireU32(long value, String name) {
    if (value < 0 || value > 0xFFFFFFFFL) {
      throw new IllegalArgumentException(
          name + " must be in u32 range [0, 4294967295], got: " + value);
    }
  }

  @Override
  public void close() {
    try {
      bridge.call("drop_tree");
    } catch (Exception ignored) {
      // Best-effort: drop the in-WASM tree before the instance goes away.
    }
    bridge.close();
  }
}
