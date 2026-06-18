package com.bitgo.wasm.privacycoin.zcash;

import java.util.Arrays;
import java.util.Objects;

/**
 * A 32-byte shielded note commitment value (cmx).
 *
 * <p>Immutable; {@link #bytes()} returns a defensive copy.
 */
public final class ShieldedCommitment {

  public static final int SIZE = 32;

  private final byte[] bytes;

  private ShieldedCommitment(byte[] bytes) {
    this.bytes = bytes;
  }

  /**
   * Wraps a 32-byte commitment value.
   *
   * @throws IllegalArgumentException if {@code bytes.length != 32}
   */
  public static ShieldedCommitment of(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes must not be null");
    if (bytes.length != SIZE) {
      throw new IllegalArgumentException(
          "ShieldedCommitment must be " + SIZE + " bytes, got " + bytes.length);
    }
    return new ShieldedCommitment(bytes.clone());
  }

  /** Returns a defensive copy of the 32 raw bytes. */
  public byte[] bytes() {
    return bytes.clone();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof ShieldedCommitment c && Arrays.equals(bytes, c.bytes);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(bytes);
  }
}
