package com.bitgo.wasm.privacycoin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MerkleTreeInfoTest {

  @Test
  void constructor_storesAllFields() {
    MerkleTreeInfo info = new MerkleTreeInfo(1_500_000L, 42L, 3);
    assertEquals(Long.valueOf(1_500_000L), info.tipHeight);
    assertEquals(42L, info.leafCount);
    assertEquals(3, info.checkpointCount);
  }

  @Test
  void tipHeight_canBeNull() {
    MerkleTreeInfo info = new MerkleTreeInfo(null, 0L, 0);
    assertNull(info.tipHeight);
  }

  @Test
  void zeroValues_areStoredCorrectly() {
    MerkleTreeInfo info = new MerkleTreeInfo(0L, 0L, 0);
    assertEquals(Long.valueOf(0L), info.tipHeight);
    assertEquals(0L, info.leafCount);
    assertEquals(0, info.checkpointCount);
  }

  @Test
  void largeLeafCount_isStoredCorrectly() {
    long largeCount = (long) Integer.MAX_VALUE + 1;
    MerkleTreeInfo info = new MerkleTreeInfo(null, largeCount, 0);
    assertEquals(largeCount, info.leafCount);
  }
}
