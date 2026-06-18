package com.bitgo.wasm.privacycoin;

public final class MerkleTreeInfo {
  /** Null if no block has been appended yet. */
  public final Long tipHeight;
  public final long leafCount;
  public final int checkpointCount;

  public MerkleTreeInfo(Long tipHeight, long leafCount, int checkpointCount) {
    this.tipHeight = tipHeight;
    this.leafCount = leafCount;
    this.checkpointCount = checkpointCount;
  }
}
