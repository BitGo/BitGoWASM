# wasm-bip32 Benchmarks

Performance comparison between `wasm-bip32` (pure Rust/WASM) and `@bitgo/utxo-lib` (native C via `tiny-secp256k1`).

## Summary

| Metric              | wasm-bip32      | utxo-lib     |
| ------------------- | --------------- | ------------ |
| **WASM Size**       | 132 KB          | N/A (native) |
| **Private Key Ops** | ~12-20% slower  | baseline     |
| **Public Key Ops**  | **2-4x faster** | baseline     |

## Benchmark Results

All benchmarks run with 1000 operations after a 100-operation warmup phase.

| Operation                       | wasm-bip32     | utxo-lib       | Ratio     |
| ------------------------------- | -------------- | -------------- | --------- |
| `fromBase58(xprv)` + publicKey  | 7,937 ops/sec  | 9,091 ops/sec  | **0.87x** |
| `fromBase58(xpub)`              | 62,500 ops/sec | 15,873 ops/sec | **3.94x** |
| `fromSeed` + publicKey          | 8,130 ops/sec  | 10,204 ops/sec | **0.80x** |
| `derivePath` (xprv) + publicKey | 1,376 ops/sec  | 1,563 ops/sec  | **0.88x** |
| `derivePath` (xpub) + publicKey | 1,600 ops/sec  | 809 ops/sec    | **1.98x** |
| `neutered()` + publicKey        | 8,197 ops/sec  | 6,623 ops/sec  | **1.24x** |
| `derive(0)` + publicKey         | 7,299 ops/sec  | 3,413 ops/sec  | **2.14x** |

## Understanding the Results

### Why Private Key Operations are Slower

Operations involving private keys require **scalar multiplication** (computing `privateKey × G` where G is the generator point). This is the most computationally expensive operation in elliptic curve cryptography.

- `wasm-bip32` uses the pure Rust `k256` crate with precomputed tables
- `utxo-lib` uses `tiny-secp256k1`, which wraps the highly optimized C library `libsecp256k1`

The C library has hand-tuned assembly optimizations that pure Rust cannot match in WASM.

### Why Public Key Operations are Faster

Operations on public keys involve **point decompression** and **point addition**, which are less computationally intensive than scalar multiplication.

- `k256`'s precomputed tables accelerate these operations significantly
- The WASM JIT compilation can optimize tight loops effectively
- Point addition is a simpler operation that benefits from Rust's zero-cost abstractions

### Lazy vs Eager Public Key Computation

An important implementation detail:

- **utxo-lib**: Lazily computes the public key from a private key (only when accessed)
- **wasm-bip32**: Eagerly computes the public key during key creation

The benchmarks account for this by accessing `publicKey` immediately after key creation to ensure fair comparison.

## Implementation Details

### Cryptographic Backend

`wasm-bip32` uses the following pure Rust crates:

| Crate    | Purpose                    |
| -------- | -------------------------- |
| `k256`   | secp256k1 curve operations |
| `bip32`  | HD key derivation          |
| `sha2`   | SHA-256/SHA-512 hashing    |
| `ripemd` | RIPEMD-160 hashing         |
| `bs58`   | Base58Check encoding       |

### k256 Precomputed Tables

The `k256` crate's `precomputed-tables` feature provides:

- ~30KB of precomputed lookup tables for the generator point
- Accelerates `G × scalar` operations (used in public key derivation)
- Tables are lazily initialized on first use
- Trade-off: ~3% performance vs 2x table size (60KB → 30KB)

The table size is fixed and not configurable.

## Trade-offs

### wasm-bip32 Advantages

1. **Small binary size** (132 KB) - ideal for browser/mobile applications
2. **Pure Rust** - no native dependencies, works everywhere WASM runs
3. **Faster public key operations** - beneficial for address derivation workflows
4. **Memory safe** - no risk of C memory bugs

### wasm-bip32 Disadvantages

1. **Slower private key operations** (~12-20% slower)
2. **No hand-tuned assembly** - `libsecp256k1` uses platform-specific optimizations (x86/ARM assembly) that `k256` doesn't leverage. Note: [WASM does support SIMD](https://doc.rust-lang.org/beta/core/arch/wasm32/index.html) via `simd128` (128-bit vectors), but `k256` doesn't currently use these intrinsics.

## Potential Optimizations

### Already Applied

- `precomputed-tables` feature enabled (+2-4x for public key ops)
- Release build with `opt-level = 3`
- `wasm-opt -O4` post-processing
- LTO (Link-Time Optimization) enabled

### Not Currently Applied

| Optimization              | Impact                   | Trade-off        |
| ------------------------- | ------------------------ | ---------------- |
| `secp256k1-ffi` backend   | ~2x faster for all ops   | 1.2 MB WASM size |
| Application-level caching | Varies                   | Memory usage     |
| Batch derivation          | Significant for bulk ops | API complexity   |

### Future: k256 v0.14 with crypto-bigint Scalar Inversion

A [recent commit](https://github.com/RustCrypto/elliptic-curves/commit/c971eaa95a1664a298add84c581de00b92ddc92b) to the `k256` crate implements scalar inversions using the optimized `safegcd-bounds` algorithm from `crypto-bigint`, achieving an **~80% performance improvement** for scalar inversion operations:

```
scalar operations/invert time: [2.66 µs → ~13 µs]
change: [−80.024% −79.497% −78.858%]
```

This optimization will be available in `k256 v0.14` (currently in release candidate). Once `bip32` crate releases a compatible stable version, upgrading could improve operations that involve scalar inversions (though note: standard BIP32 derivation doesn't heavily use inversions, so impact may be limited to signing operations).

## Running Benchmarks

```bash
cd packages/wasm-bip32
npm test
```

The benchmarks are part of the test suite and output results to the console.

## Environment

- Node.js with WASM support
- Benchmarks run single-threaded
- Results may vary based on CPU and JIT warmup
