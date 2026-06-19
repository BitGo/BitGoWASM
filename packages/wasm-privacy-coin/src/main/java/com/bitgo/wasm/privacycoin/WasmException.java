package com.bitgo.wasm.privacycoin;

public final class WasmException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final String errorCode;

  public WasmException(String errorCode, String message) {
    super("[" + errorCode + "] " + message);
    this.errorCode = errorCode;
  }

  public String getErrorCode() {
    return errorCode;
  }
}
