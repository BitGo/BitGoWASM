package com.bitgo.wasm.privacycoin.zcash;

import java.util.Arrays;
import java.util.Objects;

/**
 * A 32-byte shielded Merkle tree root.
 *
 * <p>Immutable; {@link #bytes()} returns a defensive copy.
 */
public final class ShieldedRoot {

  public static final int SIZE = 32;

  private final byte[] bytes;

  private ShieldedRoot(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Wraps a 32-byte root value.
   *
   * @throws IllegalArgumentException if {@code bytes.length != 32}
   */
  public static ShieldedRoot of(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes must not be null");
    if (bytes.length != SIZE) {
      throw new IllegalArgumentException(
          "ShieldedRoot must be " + SIZE + " bytes, got " + bytes.length);
    }
    return new ShieldedRoot(bytes.clone());
  }

  /** Returns a defensive copy of the 32 raw bytes. */
  public byte[] bytes() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof ShieldedRoot r && Arrays.equals(bytes, r.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
