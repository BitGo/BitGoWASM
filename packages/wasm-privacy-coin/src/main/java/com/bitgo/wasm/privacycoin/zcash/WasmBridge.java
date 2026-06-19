package com.bitgo.wasm.privacycoin.zcash;

import com.bitgo.wasm.privacycoin.WasmException;
import com.bitgo.wasm.privacycoin.proto.Response;
import com.bitgo.wasm.privacycoin.proto.WasmError;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.wasm.Parser;
import com.google.protobuf.InvalidProtocolBufferException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Low-level bridge to the shielded-tree WASM instance.
 *
 * <p>Package-private: consumers use {@link ShieldedMerkleTree} instead.
 *
 * <p>Loads the WASM binary from the classpath, instantiates it via Chicory (pure-JVM, no
 * native/JNI), and exposes typed call/read helpers backed by the protobuf wire format.
 * Each call writes a proto-encoded request into WASM linear memory, invokes the named
 * export, then reads the {@link Response} proto from the LAST_RESULT buffer.
 *
 * <p><b>Thread safety:</b> Not thread-safe. One bridge per {@link ShieldedMerkleTree}.
 */
final class WasmBridge implements AutoCloseable {

  private final Instance instance;
  private final ExportFunction fnAlloc;
  private final ExportFunction fnDealloc;
  private final ExportFunction fnResultPtr;
  private final ExportFunction fnResultLen;

  WasmBridge() {
    byte[] wasmBytes;
    try (InputStream is = WasmBridge.class.getResourceAsStream("/wasm/privacy_coin.wasm")) {
      if (is == null) {
        throw new IllegalStateException(
            "WASM binary not found on classpath: /wasm/privacy_coin.wasm");
      }
      wasmBytes = is.readAllBytes();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load WASM binary", e);
    }

    try {
      var module = Parser.parse(new ByteArrayInputStream(wasmBytes));
      this.instance = Instance.builder(module).build();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to instantiate WASM module", e);
    }

    this.fnAlloc     = instance.export("alloc");
    this.fnDealloc   = instance.export("dealloc");
    this.fnResultPtr = instance.export("last_result_ptr");
    this.fnResultLen = instance.export("last_result_len");
  }

  private final class WasmBuffer implements AutoCloseable {
    final int ptr;
    final int len;

    WasmBuffer(byte[] bytes) {
      this.len = bytes.length;
      this.ptr = (int) fnAlloc.apply(len)[0];
      instance.memory().write(ptr, bytes);
    }

    @Override
    public void close() {
      fnDealloc.apply(ptr, len);
    }
  }

  /**
   * Write {@code requestBytes} into WASM memory, invoke {@code export}, read Response proto.
   *
   * @param export       name of the WASM export to call
   * @param requestBytes proto-encoded request bytes
   * @return decoded {@link Response}
   */
  Response call(String export, byte[] requestBytes) {
    try (var buf = new WasmBuffer(requestBytes)) {
      instance.export(export).apply(buf.ptr, buf.len);
      return readResponse();
    }
  }

  /**
   * Invoke a no-argument {@code export} and read the Response proto.
   *
   * @param export name of the WASM export to call
   * @return decoded {@link Response}
   */
  Response call(String export) {
    instance.export(export).apply();
    return readResponse();
  }

  private Response readResponse() {
    int ptr = (int) fnResultPtr.apply()[0];
    int len = (int) fnResultLen.apply()[0];
    byte[] bytes = instance.memory().readBytes(ptr, len);
    try {
      return Response.parseFrom(bytes);
    } catch (InvalidProtocolBufferException e) {
      throw new IllegalStateException("Failed to decode WASM Response proto", e);
    }
  }

  /** Wraps a proto {@link WasmError} into a {@link WasmException}. */
  static WasmException toWasmException(WasmError error) {
    return new WasmException(error.getCode(), error.getMessage());
  }

  @Override
  public void close() {
    // Chicory Instance has no explicit close method; nothing to do here.
  }
}
