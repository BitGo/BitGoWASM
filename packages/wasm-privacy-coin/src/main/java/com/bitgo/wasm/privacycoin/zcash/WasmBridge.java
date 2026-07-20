package com.bitgo.wasm.privacycoin.zcash;

import com.bitgo.wasm.privacycoin.WasmException;
import com.bitgo.wasm.privacycoin.proto.Response;
import com.bitgo.wasm.privacycoin.proto.WasmError;
import com.dylibso.chicory.compiler.MachineFactoryCompiler;
import com.dylibso.chicory.runtime.ExportFunction;
import com.dylibso.chicory.runtime.Instance;
import com.dylibso.chicory.runtime.Machine;
import com.dylibso.chicory.wasm.Parser;
import com.dylibso.chicory.wasm.WasmModule;
import com.google.protobuf.InvalidProtocolBufferException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.Function;

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
 * <p><b>Performance:</b> The parsed {@link WasmModule}, JIT-compiled machine factory, and
 * instantiated {@link Instance} objects are all cached/pooled. The module is parsed once per
 * JVM (it is immutable and safe to share). The WASM functions are JIT-compiled to JVM bytecode
 * once via {@link MachineFactoryCompiler} — this replaces Chicory's default interpreter with
 * native-speed bytecode execution. Instances are pooled: on {@link #close()}, the in-WASM tree
 * is dropped via the {@code drop_tree} export and the Instance is returned to a pool for reuse
 * by the next {@code WasmBridge}.
 *
 * <p><b>Thread safety:</b> Not thread-safe. One bridge per {@link ShieldedMerkleTree}.
 * The cached module and instance pool are safe for concurrent access.
 */
final class WasmBridge implements AutoCloseable {

  /**
   * Lazily-parsed, JVM-wide cached WASM module. {@link WasmModule} is immutable after
   * construction, so it is safe to share across threads and to build multiple independent
   * {@link Instance}s from it.
   */
  private static volatile WasmModule cachedModule;

  /**
   * JIT-compiled machine factory cached alongside the module. The {@link MachineFactoryCompiler}
   * translates WASM functions into JVM bytecode at load time; the resulting factory is reused
   * by every {@link Instance}, so the compilation cost is paid once per JVM. This replaces
   * Chicory's default interpreter with native-speed bytecode execution.
   */
  private static volatile Function<Instance, Machine> cachedMachineFactory;

  /**
   * Pool of previously-used {@link Instance} objects whose in-WASM tree has been dropped.
   * Reusing an Instance avoids the instantiation cost; the {@code from_frontier} /
   * {@code from_state} export re-initializes the tree state in the existing linear memory.
   */
  private static final ConcurrentLinkedDeque<Instance> instancePool = new ConcurrentLinkedDeque<>();

  private final Instance instance;
  private final ExportFunction fnAlloc;
  private final ExportFunction fnDealloc;
  private final ExportFunction fnResultPtr;
  private final ExportFunction fnResultLen;

  WasmBridge() {
    Instance inst = instancePool.pollFirst();
    if (inst == null) {
      try {
        inst = Instance.builder(loadModule())
            .withMachineFactory(loadMachineFactory())
            .build();
      } catch (Exception e) {
        throw new IllegalStateException("Failed to instantiate WASM module", e);
      }
    }
    this.instance = inst;

    this.fnAlloc     = instance.export("alloc");
    this.fnDealloc   = instance.export("dealloc");
    this.fnResultPtr = instance.export("last_result_ptr");
    this.fnResultLen = instance.export("last_result_len");
  }

  /**
   * Returns the cached parsed module, parsing it on first use. Subsequent calls reuse
   * the same immutable {@link WasmModule}, eliminating redundant parse overhead when
   * multiple {@link ShieldedMerkleTree} instances are created in the same JVM (e.g.
   * in tests or when re-initializing after a reorg).
   */
  private static WasmModule loadModule() {
    WasmModule module = cachedModule;
    if (module != null) {
      return module;
    }
    synchronized (WasmBridge.class) {
      module = cachedModule;
      if (module == null) {
        byte[] wasmBytes = readWasmBytes();
        module = Parser.parse(new ByteArrayInputStream(wasmBytes));
        cachedModule = module;
      }
      return module;
    }
  }

  /**
   * Returns the cached JIT-compiled machine factory, compiling it on first use. The
   * {@link MachineFactoryCompiler} translates all WASM functions to JVM bytecode once;
   * the resulting {@link Machine} is then used by every {@link Instance} built from
   * the same module, providing native-speed execution instead of interpretation.
   */
  private static Function<Instance, Machine> loadMachineFactory() {
    Function<Instance, Machine> factory = cachedMachineFactory;
    if (factory != null) {
      return factory;
    }
    synchronized (WasmBridge.class) {
      factory = cachedMachineFactory;
      if (factory == null) {
        factory = MachineFactoryCompiler.compile(loadModule());
        cachedMachineFactory = factory;
      }
      return factory;
    }
  }

  private static byte[] readWasmBytes() {
    try (InputStream is = WasmBridge.class.getResourceAsStream("/wasm/privacy_coin.wasm")) {
      if (is == null) {
        throw new IllegalStateException(
            "WASM binary not found on classpath: /wasm/privacy_coin.wasm");
      }
      return is.readAllBytes();
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load WASM binary", e);
    }
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

  /**
   * Drops the in-WASM tree and returns the {@link Instance} to the pool for reuse.
   * If {@code drop_tree} fails (e.g. the tree was never initialized), the Instance is
   * still pooled — the next {@code from_frontier} / {@code from_state} call will
   * re-initialize it regardless.
   */
  @Override
  public void close() {
    try {
      instance.export("drop_tree").apply();
    } catch (Exception ignored) {
      // Best-effort cleanup; the instance is still reusable.
    }
    instancePool.addFirst(instance);
  }

  /**
   * Discards this bridge without returning the {@link Instance} to the pool. Use this
   * when initialization failed and the WASM linear memory may be in an inconsistent state.
   */
  void discard() {
    // Instance is simply abandoned; Chicory has no explicit close.
  }
}
