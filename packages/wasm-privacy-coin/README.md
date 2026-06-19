# wasm-privacy-coin

Shielded commitment tree operations (Zcash Orchard, NU6) compiled to a WebAssembly
**cdylib** binary and wrapped with a typed Java API for use by the `indexer-utxo` service.

The Rust core implements the Orchard `ShardTree` from the `shardtree` crate. It is
compiled to `wasm32-unknown-unknown` and embedded in a JAR. The Java layer loads it
via [Chicory](https://github.com/dylibso/chicory) (pure-JVM WASM runtime, no
native/JNI). All type marshaling between Java and Rust uses **protobuf** — messages
are defined in `proto/privacy_coin.proto` and code is generated at build time by
`prost` (Rust) and `protobuf-maven-plugin` (Java).

---

## Table of contents

1. [Prerequisites](#prerequisites)
2. [Project structure](#project-structure)
3. [Build targets](#build-targets)
4. [Architecture](#architecture)
5. [Java API reference](#java-api-reference)
6. [Java usage examples](#java-usage-examples)
7. [Protobuf interface](#protobuf-interface)
8. [Error codes](#error-codes)
9. [Pinned dependencies](#pinned-dependencies)

---

## Prerequisites

| Tool                            | Version              | Notes                                      |
| ------------------------------- | -------------------- | ------------------------------------------ |
| Rust toolchain                  | `nightly-2025-10-23` | via `rustup`                               |
| `wasm32-unknown-unknown` target | —                    | `rustup target add wasm32-unknown-unknown` |
| Java                            | 17                   | required by the Maven build                |
| Maven                           | 3.9+                 | invoked through `make` targets             |

No `cargo-component` or native Wasmtime installation required.

---

## Project structure

```
wasm-privacy-coin/
├── proto/
│   └── privacy_coin.proto            # Single source of truth for the wire format
├── src/
│   ├── lib.rs                        # #[no_mangle] WASM exports, protobuf encode/decode
│   └── zcash/
│       ├── mod.rs                    # Module declaration
│       └── tree.rs                   # OwnedTree, ShardTree logic, serialization
├── src/main/java/com/bitgo/wasm/privacycoin/
│   ├── MerkleTreeInfo.java           # Immutable value type for tree metadata
│   ├── WasmException.java            # Runtime exception with typed error codes
│   └── zcash/
│       ├── WasmBridge.java           # Low-level Chicory bridge (package-private)
│       ├── ShieldedMerkleTree.java   # Public high-level Java API
│       ├── ShieldedCommitment.java   # Immutable 32-byte cmx value type
│       ├── ShieldedRoot.java         # Immutable 32-byte Merkle root value type
│       └── TreeState.java            # Opaque serialized tree state (save/fromState)
├── src/test/java/com/bitgo/wasm/privacycoin/zcash/
│   └── ShieldedMerkleTreeTest.java   # JUnit 5 integration tests
├── build.rs                          # Runs prost-build to generate Rust proto bindings
├── Cargo.toml
├── pom.xml
└── Makefile
```

---

## Build targets

All build steps are driven by `make`.

| Target           | What it does                                                                      |
| ---------------- | --------------------------------------------------------------------------------- |
| `make build`     | Compiles Rust → WASM binary at `dist/wasm-privacy-coin.wasm`                      |
| `make jar`       | Runs `build`, embeds the WASM into the JAR, produces `dist/wasm-privacy-coin.jar` |
| `make test-java` | Copies WASM into resources, runs JUnit 5 tests via Maven                          |
| `make clean`     | Removes `dist/`, `target/`, and the embedded WASM resource                        |

### Quick start

```bash
# 1. Add the WASM compile target (once per machine)
rustup target add wasm32-unknown-unknown

# 2. Compile and package
make jar

# 3. Run tests
make test-java
```

The compiled WASM binary lands at `dist/wasm-privacy-coin.wasm` and is also copied
to `src/main/resources/wasm/privacy_coin.wasm` so it is embedded in the JAR at
`/wasm/privacy_coin.wasm` on the classpath.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Java (indexer-utxo)                                             │
│                                                                  │
│  ShieldedMerkleTree   ← public API                               │
│    uses ShieldedCommitment / ShieldedRoot / TreeState            │
│         │  proto-encoded request bytes                           │
│  WasmBridge           ← package-private                          │
│    holds Chicory Instance (per-instance, pure-JVM)               │
│         │  alloc/write/call/dealloc/read via linear memory       │
└─────────┼────────────────────────────────────────────────────────┘
          │  WASM binary boundary (wasm32-unknown-unknown cdylib)
┌─────────┴────────────────────────────────────────────────────────┐
│  WASM module                                                     │
│                                                                  │
│  lib.rs  (#[no_mangle] exports, prost decode/encode)             │
│    └→  zcash/tree.rs  (OwnedTree / ShieldedShardTree)            │
│           shardtree + incrementalmerkletree + orchard crates     │
└──────────────────────────────────────────────────────────────────┘
```

**Protobuf wire format.** The contract is declared in `proto/privacy_coin.proto`.
`prost-build` generates Rust bindings at compile time; `protobuf-maven-plugin`
generates Java bindings during `mvn generate-sources` (downloads `protoc` automatically,
no system install needed). Each call writes a proto-encoded request into WASM linear
memory and reads a `Response` proto from the `LAST_RESULT` buffer.

**Persistence.** `save()` / `fromState()` use serde JSON internally (the
`PersistedShardTreeState` format). This is the on-disk/DB format, not the Java↔WASM
wire format. The Java layer sees it as opaque `TreeState` bytes.

**One instance = one tree.** Each `ShieldedMerkleTree` owns a dedicated Chicory
`Instance` with its own WASM linear memory. Two instances never share state.

**Thread safety.** `ShieldedMerkleTree` is not thread-safe. Use one instance per
thread or add external synchronization.

---

## Java API reference

### `ShieldedMerkleTree` (public)

`com.bitgo.wasm.privacycoin.zcash.ShieldedMerkleTree`

Implements `AutoCloseable`. Always use in try-with-resources.

#### Factory methods

| Method                                                   | Description                                                                    |
| -------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `static fromFrontier(byte[] frontier, long blockHeight)` | Initialize from a CommitmentTree v0 frontier (raw bytes from `z_gettreestate`) |
| `static fromState(TreeState state)`                      | Restore from a `TreeState` previously returned by `save()`                     |

#### Instance methods

| Method                                                                                                 | Returns          | Description                                                     |
| ------------------------------------------------------------------------------------------------------ | ---------------- | --------------------------------------------------------------- |
| `ping()`                                                                                               | `void`           | Verifies the WASM module is alive                               |
| `appendCommitments(long blockHeight, List<ShieldedCommitment> commitments)`                            | `ShieldedRoot`   | Append cmx values, checkpoint the tree, return the new root     |
| `appendCommitments(long blockHeight, List<ShieldedCommitment> commitments, ShieldedRoot expectedRoot)` | `ShieldedRoot`   | Same, with optional root verification                           |
| `truncateToCheckpoint(long blockHeight)`                                                               | `ShieldedRoot`   | Roll back to a prior checkpoint, return the root at that height |
| `save()`                                                                                               | `TreeState`      | Serialize tree state for persistence                            |
| `getInfo()`                                                                                            | `MerkleTreeInfo` | Return tip height, leaf count, checkpoint count                 |
| `close()`                                                                                              | `void`           | Drop the in-WASM tree and release the Chicory instance          |

**`blockHeight`** must be in the range `[0, 4_294_967_295]` (Rust `u32`). Passing a
negative value or a value above `0xFFFFFFFFL` throws `IllegalArgumentException`
immediately in Java, before any WASM call.

---

### `ShieldedCommitment` (public)

`com.bitgo.wasm.privacycoin.zcash.ShieldedCommitment`

Immutable 32-byte Orchard note commitment value (the `cmx` field of an Orchard output
description). A valid Pallas base field element in little-endian byte order.

```java
ShieldedCommitment cmx = ShieldedCommitment.of(rawBytes); // throws IAE if not 32 bytes
byte[] back = cmx.bytes();                                 // defensive copy
```

---

### `ShieldedRoot` (public)

`com.bitgo.wasm.privacycoin.zcash.ShieldedRoot`

Immutable 32-byte Orchard Merkle tree root.

---

### `TreeState` (public)

`com.bitgo.wasm.privacycoin.zcash.TreeState`

Opaque serialized tree state returned by `save()` and accepted by `fromState()`. The
internal format is UTF-8 JSON (`PersistedShardTreeState`), but callers should treat it
as an opaque blob.

```java
TreeState state = tree.save();
byte[] blob = state.bytes();            // store in DB
TreeState restored = TreeState.of(blob); // load from DB
```

---

### `MerkleTreeInfo` (public)

`com.bitgo.wasm.privacycoin.MerkleTreeInfo`

Immutable snapshot returned by `getInfo()`.

| Field             | Type   | Description                                                              |
| ----------------- | ------ | ------------------------------------------------------------------------ |
| `tipHeight`       | `Long` | Most recently checkpointed block height; `null` if no block appended yet |
| `leafCount`       | `long` | Total Orchard commitments appended across all blocks                     |
| `checkpointCount` | `int`  | Number of checkpoints currently retained (max 100)                       |

---

### `WasmException` (public)

`com.bitgo.wasm.privacycoin.WasmException`

Unchecked exception thrown by all `ShieldedMerkleTree` methods on WASM-level errors.

```java
catch (WasmException e) {
    String code    = e.getErrorCode(); // structured error code (see table below)
    String message = e.getMessage();   // human-readable detail
}
```

---

## Java usage examples

### 1. Initialize from a frontier (first sync)

```java
byte[] frontier    = HexFormat.of().parseHex(orchardTreeHex);
long   blockHeight = 2_500_000L;

try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromFrontier(frontier, blockHeight)) {
    MerkleTreeInfo info = tree.getInfo();
    System.out.println("tip height : " + info.tipHeight);       // 2500000
    System.out.println("leaf count : " + info.leafCount);       // 1
    System.out.println("checkpoints: " + info.checkpointCount); // 1
}
```

### 2. Initialize from an empty state

```java
TreeState emptyState = new TreeState(
    "{\"shards\":[],\"cap\":{\"type\":\"Nil\"},\"checkpoints\":[],"
    + "\"tip_height\":null,\"leaf_count\":0}");

try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(emptyState)) {
    tree.ping();
}
```

### 3. Append commitments for a block

```java
ShieldedCommitment cmx = ShieldedCommitment.of(HexFormat.of().parseHex(
    "0100000000000000000000000000000000000000000000000000000000000000"));

try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(savedState)) {
    ShieldedRoot root = tree.appendCommitments(2_500_001L, List.of(cmx));
    // Empty block — still creates a checkpoint
    tree.appendCommitments(2_500_002L, Collections.emptyList());
}
```

### 4. Append with root verification

```java
ShieldedRoot expected = ShieldedRoot.of(expectedRootBytes);

try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(savedState)) {
    ShieldedRoot root = tree.appendCommitments(2_500_001L, cmxList, expected);
    // root.equals(expected) is guaranteed
}
```

`WasmException` with code `ROOT_MISMATCH` is thrown if the computed root does not match.

### 5. Save and restore state

```java
byte[] snapshot;
try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(emptyState)) {
    tree.appendCommitments(100L, List.of(cmx));
    snapshot = tree.save().bytes();
}

try (ShieldedMerkleTree restored = ShieldedMerkleTree.fromState(TreeState.of(snapshot))) {
    MerkleTreeInfo info = restored.getInfo();
    System.out.println("tip height : " + info.tipHeight); // 100
}
```

### 6. Reorg handling

```java
try (ShieldedMerkleTree tree = ShieldedMerkleTree.fromState(savedState)) {
    ShieldedRoot root100 = tree.appendCommitments(100L, List.of(cmx));
    tree.appendCommitments(101L, List.of(cmx));

    ShieldedRoot restoredRoot = tree.truncateToCheckpoint(100L);
    // restoredRoot.equals(root100)
}
```

---

## Protobuf interface

The wire format between Java and Rust is declared in `proto/privacy_coin.proto`.

**Request messages** (Java → WASM linear memory → Rust):

| Message                    | Export                   | Fields                                                                                 |
| -------------------------- | ------------------------ | -------------------------------------------------------------------------------------- |
| `FromFrontierRequest`      | `from_frontier`          | `frontier: bytes`, `block_height: uint32`                                              |
| `AppendCommitmentsRequest` | `append_commitments`     | `block_height: uint32`, `commitments: repeated bytes`, `expected_root: optional bytes` |
| `TruncateRequest`          | `truncate_to_checkpoint` | `block_height: uint32`                                                                 |

**Response envelope** (WASM LAST_RESULT → Java):

Every export writes a `Response` proto with a `oneof result`:

- `ok: bool` — void success (`ping`, `from_frontier`, `from_state`, `drop_tree`)
- `bytes_value: bytes` — root hash or serialized state
- `info_value: TreeInfo` — from `get_info`
- `error: WasmError { code, message }` — any failure

`from_state` and `save_state` pass state bytes directly (no proto wrapper needed for
the payload; only the `Response` envelope uses proto).

---

## Error codes

| Code                   | Meaning                                                                       |
| ---------------------- | ----------------------------------------------------------------------------- |
| `ROOT_MISMATCH`        | Computed Merkle root differs from the provided `expectedRoot`                 |
| `CHECKPOINT_NOT_FOUND` | No checkpoint exists for the requested block height                           |
| `INVALID_FRONTIER`     | Frontier bytes could not be parsed                                            |
| `INVALID_STATE`        | State bytes could not be deserialized                                         |
| `NO_TREE`              | WASM export called before `from_frontier` / `from_state` initialized the tree |
| `DECODE_ERROR`         | Incoming proto request could not be decoded                                   |
| `SAVE_ERROR`           | Tree serialization failed                                                     |
| `GET_INFO_ERROR`       | `get_info` failed internally                                                  |
| `WASM_ERROR`           | Catch-all for errors without a structured code                                |

---

## Pinned dependencies

| Crate                   | Pinned version | Role                                                       |
| ----------------------- | -------------- | ---------------------------------------------------------- |
| `shardtree`             | `0.6.2`        | Incremental Merkle tree with checkpointing                 |
| `incrementalmerkletree` | `0.8.2`        | Core tree primitives (`Position`, `Address`, `Frontier`)   |
| `orchard`               | `0.14.0`       | `MerkleHashOrchard` hash type and empty-root table         |
| `prost`                 | `0.13`         | Protobuf encode/decode (Rust)                              |
| `serde` / `serde_json`  | `1`            | Persistence serialization (`PersistedShardTreeState` JSON) |
| `hex`                   | `0.4`          | Hex encoding of hash bytes in the persistence format       |

Do not upgrade `shardtree`, `incrementalmerkletree`, or `orchard` without verifying
that the new versions remain compatible with zcashd's serialization format and produce
identical root hashes for the same inputs.
