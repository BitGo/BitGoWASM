package com.bitgo.wasm.privacycoin.zcash;

import java.nio.charset.StandardCharsets;

/**
 * An opaque serialized snapshot of a {@link ShieldedMerkleTree}.
 *
 * <p>Produced by {@link ShieldedMerkleTree#save()} and consumed by
 * {@link ShieldedMerkleTree#fromState(TreeState)}. The internal encoding is an
 * implementation detail; do not interpret the bytes directly.
 */
public final class TreeState {

  private final String json;

  /**
   * Package-private: constructed by {@link ShieldedMerkleTree#save()} and in tests
   * (same package) for bootstrapping from an initial JSON string.
   */
  TreeState(String json) {
    this.json = json;
  }

  /**
   * Restores a {@code TreeState} from bytes previously returned by {@link #bytes()}.
   *
   * @param bytes UTF-8 encoded state bytes from a prior {@code bytes()} call
   */
  public static TreeState of(byte[] bytes) {
    return new TreeState(new String(bytes, StandardCharsets.UTF_8));
  }

  /**
   * Returns the raw bytes of the serialized state (UTF-8 encoded).
   * Round-trips through {@link #of(byte[])}.
   */
  public byte[] bytes() {
    return json.getBytes(StandardCharsets.UTF_8);
  }
}
