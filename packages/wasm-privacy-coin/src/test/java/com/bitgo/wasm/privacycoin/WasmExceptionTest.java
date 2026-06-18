package com.bitgo.wasm.privacycoin;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class WasmExceptionTest {

  @Test
  void getMessage_includesCodeInBrackets() {
    WasmException ex = new WasmException("ROOT_MISMATCH", "computed abc but expected def");
    assertEquals("[ROOT_MISMATCH] computed abc but expected def", ex.getMessage());
  }

  @Test
  void getErrorCode_returnsOriginalCode() {
    WasmException ex = new WasmException("CHECKPOINT_NOT_FOUND", "no checkpoint for height 99");
    assertEquals("CHECKPOINT_NOT_FOUND", ex.getErrorCode());
  }

  @Test
  void canBeCaughtAsRuntimeException() {
    // Verifies it propagates through a call site that only handles RuntimeException.
    assertThrows(RuntimeException.class, () -> {
      throw new WasmException("SOME_CODE", "some message");
    });
  }

  @Test
  void emptyMessage_formatsCorrectly() {
    WasmException ex = new WasmException("CODE", "");
    assertEquals("[CODE] ", ex.getMessage());
    assertEquals("CODE", ex.getErrorCode());
  }
}
