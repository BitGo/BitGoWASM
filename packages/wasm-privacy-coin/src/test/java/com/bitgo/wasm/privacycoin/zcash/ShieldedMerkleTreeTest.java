package com.bitgo.wasm.privacycoin.zcash;

import com.bitgo.wasm.privacycoin.MerkleTreeInfo;
import com.bitgo.wasm.privacycoin.WasmException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for {@link ShieldedMerkleTree}.
 *
 * <p>Requires the WASM binary at {@code src/main/resources/wasm/privacy_coin.wasm}.
 * The {@code make test-java} target copies the binary there before running Maven.
 */
class ShieldedMerkleTreeTest {

  /**
   * Minimal valid PersistedShardTreeState JSON representing an empty tree.
   * Matches {@code tree::PersistedShardTreeState} with serde(tag="type") on TreeNode.
   */
  private static final TreeState EMPTY_STATE = new TreeState(
      "{\"shards\":[],\"cap\":{\"type\":\"Nil\"},\"checkpoints\":[],"
      + "\"tip_height\":null,\"leaf_count\":0}");

  /**
   * CommitmentTree v0 frontier encoding for a single-leaf tree.
   * Encoding: 0x01 (left present) | 32-byte hash (value=1 LE, valid Pallas base field element)
   * | 0x00 (right absent) | 0x00 (0 parents) = 35 bytes total.
   */
  private static final byte[] FRONTIER = HexFormat.of().parseHex(
      "0101000000000000000000000000000000000000000000000000000000000000000000");

  /**
   * A valid 32-byte Orchard commitment (Pallas base field element = 1, LE-encoded).
   */
  private static final ShieldedCommitment CMX = ShieldedCommitment.of(HexFormat.of().parseHex(
      "0100000000000000000000000000000000000000000000000000000000000000"));

  // -------------------------------------------------------------------------
  // ping
  // -------------------------------------------------------------------------

  @Test
  void ping_succeeds() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      assertDoesNotThrow(tree::ping);
    }
  }

  // -------------------------------------------------------------------------
  // fromFrontier
  // -------------------------------------------------------------------------

  @Test
  void fromFrontier_setsInitialLeafCountAndTipHeight() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromFrontier(FRONTIER, 1_000_000L)) {
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(1_000_000L), info.tipHeight);
      assertEquals(1L, info.leafCount);
    }
  }

  @Test
  void fromFrontier_emptyBytes_throwsWasmException() {
    assertThrows(WasmException.class, () ->
        ShieldedMerkleTree.fromFrontier(new byte[0], 1L));
  }

  @Test
  void fromFrontier_emptyTree_throwsWasmException() {
    // CommitmentTree v0 with left=absent (0x00): left leaf is required.
    byte[] emptyFrontier = HexFormat.of().parseHex("000000");
    assertThrows(WasmException.class, () ->
        ShieldedMerkleTree.fromFrontier(emptyFrontier, 1L));
  }

  @Test
  void fromFrontier_negativeBlockHeight_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () ->
        ShieldedMerkleTree.fromFrontier(FRONTIER, -1L));
  }

  @Test
  void fromFrontier_blockHeightAtU32Max_succeeds() {
    // 0xFFFF_FFFF is the maximum valid u32 block height; must not throw.
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromFrontier(FRONTIER, 0xFFFFFFFFL)) {
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(0xFFFFFFFFL), info.tipHeight);
    }
  }

  @Test
  void fromFrontier_setsCheckpointCountToOne() {
    // fromFrontier inserts a checkpoint at block-height, so checkpoint count must be 1.
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromFrontier(FRONTIER, 1_000_000L)) {
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(1, info.checkpointCount);
    }
  }

  // -------------------------------------------------------------------------
  // fromState
  // -------------------------------------------------------------------------

  @Test
  void fromState_emptyState_initializesWithNoTipHeight() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      MerkleTreeInfo info = tree.getInfo();
      assertNull(info.tipHeight);
      assertEquals(0L, info.leafCount);
      assertEquals(0, info.checkpointCount);
    }
  }

  @Test
  void fromState_invalidJson_throwsWasmException() {
    assertThrows(WasmException.class, () ->
        ShieldedMerkleTree.fromState(new TreeState("{ not valid json }")));
  }

  // -------------------------------------------------------------------------
  // appendCommitments — empty blocks
  // -------------------------------------------------------------------------

  @Test
  void appendCommitments_nullCommitmentsList_throwsNullPointerException() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      assertThrows(NullPointerException.class, () ->
          tree.appendCommitments(1L, null));
    }
  }

  @Test
  void appendCommitments_emptyBlock_returnsRoot() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      ShieldedRoot root = tree.appendCommitments(1L, Collections.emptyList());
      assertNotNull(root);
      assertEquals(ShieldedRoot.SIZE, root.bytes().length);
    }
  }

  @Test
  void appendCommitments_emptyBlock_doesNotChangeLeafCount() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, Collections.emptyList());
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(0L, info.leafCount);
      assertEquals(Long.valueOf(1L), info.tipHeight);
    }
  }

  @Test
  void appendCommitments_multipleEmptyBlocks_incrementsCheckpointCount() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, Collections.emptyList());
      tree.appendCommitments(2L, Collections.emptyList());
      tree.appendCommitments(3L, Collections.emptyList());
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(3L), info.tipHeight);
      assertEquals(3, info.checkpointCount);
      assertEquals(0L, info.leafCount);
    }
  }

  // -------------------------------------------------------------------------
  // appendCommitments — with commitments
  // -------------------------------------------------------------------------

  @Test
  void appendCommitments_withCommitment_increasesLeafCount() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX));
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(1L, info.leafCount);
      assertEquals(Long.valueOf(1L), info.tipHeight);
    }
  }

  @Test
  void appendCommitments_twoBlocks_leafCountAccumulates() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX));
      tree.appendCommitments(2L, List.of(CMX));
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(2L, info.leafCount);
      assertEquals(Long.valueOf(2L), info.tipHeight);
      assertEquals(2, info.checkpointCount);
    }
  }

  @Test
  void appendCommitments_twoBlocks_rootChanges() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      ShieldedRoot root1 = tree.appendCommitments(1L, List.of(CMX));
      ShieldedRoot root2 = tree.appendCommitments(2L, List.of(CMX));
      assertNotEquals(root1, root2, "Root must change when new leaves are appended");
    }
  }

  @Test
  void appendCommitments_returnsRoot_isDeterministic() {
    // Two fresh trees given the same commitment produce the same root.
    ShieldedRoot root1, root2;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      root1 = tree.appendCommitments(1L, List.of(CMX));
    }
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      root2 = tree.appendCommitments(1L, List.of(CMX));
    }
    assertEquals(root1, root2);
  }

  @Test
  void appendCommitments_correctExpectedRoot_succeeds() {
    // Capture actual root first, then confirm passing it as expectedRoot doesn't throw.
    ShieldedRoot actualRoot;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      actualRoot = tree.appendCommitments(1L, List.of(CMX));
    }
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      ShieldedRoot returned = tree.appendCommitments(1L, List.of(CMX), actualRoot);
      assertEquals(actualRoot, returned);
    }
  }

  @Test
  void appendCommitments_wrongExpectedRoot_throwsRootMismatch() {
    ShieldedRoot wrongRoot = ShieldedRoot.of(new byte[ShieldedRoot.SIZE]);
    WasmException ex = assertThrows(WasmException.class, () -> {
      try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
        tree.appendCommitments(1L, List.of(CMX), wrongRoot);
      }
    });
    assertEquals("ROOT_MISMATCH", ex.getErrorCode());
  }

  @Test
  void appendCommitments_multipleCommitmentsInOneBlock_allLeavesCounted() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX, CMX, CMX));
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(3L, info.leafCount);
      assertEquals(1, info.checkpointCount);
    }
  }

  // -------------------------------------------------------------------------
  // truncateToCheckpoint
  // -------------------------------------------------------------------------

  @Test
  void truncateToCheckpoint_rollsBackTipHeightAndLeafCount() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX));
      tree.appendCommitments(2L, List.of(CMX));

      tree.truncateToCheckpoint(1L);

      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(1L), info.tipHeight);
      assertEquals(1L, info.leafCount);
    }
  }

  @Test
  void truncateToCheckpoint_returnsRootMatchingOriginalAppend() {
    ShieldedRoot rootAt1;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      rootAt1 = tree.appendCommitments(1L, List.of(CMX));
      tree.appendCommitments(2L, List.of(CMX));

      ShieldedRoot restoredRoot = tree.truncateToCheckpoint(1L);
      assertEquals(rootAt1, restoredRoot);
    }
  }

  @Test
  void truncateToCheckpoint_unknownHeight_throwsCheckpointNotFound() {
    WasmException ex = assertThrows(WasmException.class, () -> {
      try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
        tree.appendCommitments(100L, Collections.emptyList());
        tree.truncateToCheckpoint(999L);
      }
    });
    assertEquals("CHECKPOINT_NOT_FOUND", ex.getErrorCode());
  }

  // -------------------------------------------------------------------------
  // save / fromState round-trip
  // -------------------------------------------------------------------------

  @Test
  void saveAndLoad_roundTrip_infoFieldsSurvive() {
    TreeState savedState;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(100L, Collections.emptyList());
      savedState = tree.save();
    }
    try (ShieldedMerkleTree restored = ShieldedMerkleTree.fromState(savedState)) {
      MerkleTreeInfo info = restored.getInfo();
      assertEquals(Long.valueOf(100L), info.tipHeight);
      assertEquals(0L, info.leafCount);
      assertEquals(1, info.checkpointCount);
    }
  }

  @Test
  void saveAndLoad_withLeaves_preservesLeafCount() {
    TreeState savedState;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX, CMX));
      savedState = tree.save();
    }
    try (ShieldedMerkleTree restored = ShieldedMerkleTree.fromState(savedState)) {
      MerkleTreeInfo info = restored.getInfo();
      assertEquals(2L, info.leafCount);
      assertEquals(Long.valueOf(1L), info.tipHeight);
    }
  }

  @Test
  void saveAndLoad_restoredTreeCanContinueAppending() {
    TreeState savedState;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX));
      savedState = tree.save();
    }
    try (ShieldedMerkleTree restored = ShieldedMerkleTree.fromState(savedState)) {
      assertDoesNotThrow(() -> restored.appendCommitments(2L, List.of(CMX)));
      MerkleTreeInfo info = restored.getInfo();
      assertEquals(2L, info.leafCount);
      assertEquals(Long.valueOf(2L), info.tipHeight);
    }
  }

  @Test
  void saveAndLoad_stateBytesRoundTrip() {
    // Verify TreeState.bytes() / TreeState.of() round-trips without data loss.
    TreeState saved;
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(5L, List.of(CMX));
      saved = tree.save();
    }
    TreeState restored = TreeState.of(saved.bytes());
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(restored)) {
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(5L), info.tipHeight);
      assertEquals(1L, info.leafCount);
    }
  }

  @Test
  void appendCommitments_wrongSizeCommitment_throwsIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () ->
        ShieldedCommitment.of(new byte[4])); // must be 32 bytes
  }

  @Test
  void truncateToCheckpoint_treeIsUsableAfterRollback() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      tree.appendCommitments(1L, List.of(CMX));
      tree.appendCommitments(2L, List.of(CMX));
      tree.truncateToCheckpoint(1L);

      ShieldedRoot root = tree.appendCommitments(3L, List.of(CMX));
      assertEquals(ShieldedRoot.SIZE, root.bytes().length);
      MerkleTreeInfo info = tree.getInfo();
      assertEquals(Long.valueOf(3L), info.tipHeight);
      assertEquals(2L, info.leafCount);
    }
  }

  // -------------------------------------------------------------------------
  // blockHeight range validation
  // -------------------------------------------------------------------------

  @Test
  void appendCommitments_negativeBlockHeight_throwsIllegalArgumentException() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      assertThrows(IllegalArgumentException.class, () ->
          tree.appendCommitments(-1L, Collections.emptyList()));
    }
  }

  @Test
  void appendCommitments_blockHeightAboveU32Max_throwsIllegalArgumentException() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      assertThrows(IllegalArgumentException.class, () ->
          tree.appendCommitments(0x1_0000_0000L, Collections.emptyList()));
    }
  }

  @Test
  void truncateToCheckpoint_negativeBlockHeight_throwsIllegalArgumentException() {
    try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(EMPTY_STATE)) {
      assertThrows(IllegalArgumentException.class, () ->
          tree.truncateToCheckpoint(-1L));
    }
  }

  // -------------------------------------------------------------------------
  // Instance isolation
  // -------------------------------------------------------------------------

  @Test
  void twoInstances_shareNoState() {
    try (ShieldedMerkleTree tree1 = ShieldedMerkleTree.fromState(EMPTY_STATE);
         ShieldedMerkleTree tree2 = ShieldedMerkleTree.fromState(EMPTY_STATE)) {

      tree1.appendCommitments(1L, List.of(CMX));

      MerkleTreeInfo info2 = tree2.getInfo();
      assertNull(info2.tipHeight);
      assertEquals(0L, info2.leafCount);
    }
  }
}
