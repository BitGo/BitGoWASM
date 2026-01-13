import * as assert from "assert";
import { bip32 as utxolibBip32 } from "@bitgo/utxo-lib";
import { BIP32 } from "../js/bip32.js";

describe("WasmBIP32", () => {
  it("should create from base58 xpub", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = BIP32.fromBase58(xpub);

    assert.strictEqual(key.isNeutered(), true);
    assert.strictEqual(key.depth, 3);
    assert.strictEqual(key.toBase58(), xpub);

    // Verify properties exist
    assert.ok(key.chainCode instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.ok(key.identifier instanceof Uint8Array);
    assert.ok(key.fingerprint instanceof Uint8Array);
    assert.strictEqual(key.privateKey, undefined);
  });

  it("should create from base58 xprv", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = BIP32.fromBase58(xprv);

    assert.strictEqual(key.isNeutered(), false);
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.toBase58(), xprv);

    // Verify properties exist
    assert.ok(key.chainCode instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.identifier instanceof Uint8Array);
    assert.ok(key.fingerprint instanceof Uint8Array);
  });

  it("should derive child keys", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = BIP32.fromBase58(xpub);

    const child = key.derive(0);
    assert.strictEqual(child.depth, 4);
    assert.strictEqual(child.isNeutered(), true);
  });

  it("should derive using path", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = BIP32.fromBase58(xprv);

    const derived1 = key.derivePath("0/1/2");
    assert.strictEqual(derived1.depth, 3);

    const derived2 = key.derivePath("m/0/1/2");
    assert.strictEqual(derived2.depth, 3);

    // Both should produce the same result
    assert.strictEqual(derived1.toBase58(), derived2.toBase58());
  });

  it("should neutered a private key", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = BIP32.fromBase58(xprv);
    const neuteredKey = key.neutered();

    assert.strictEqual(neuteredKey.isNeutered(), true);
    assert.strictEqual(neuteredKey.privateKey, undefined);
    assert.ok(neuteredKey.publicKey instanceof Uint8Array);
  });

  it("should derive hardened keys from private key", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = BIP32.fromBase58(xprv);

    const hardened = key.deriveHardened(0);
    assert.strictEqual(hardened.depth, 1);
    assert.strictEqual(hardened.isNeutered(), false);
  });

  it("should fail to derive hardened from public key", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = BIP32.fromBase58(xpub);

    assert.throws(() => {
      key.deriveHardened(0);
    });
  });

  it("should export to WIF", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = BIP32.fromBase58(xprv);

    const wif = key.toWIF();
    assert.ok(typeof wif === "string");
    assert.ok(wif.length > 0);
  });

  it("should fail to export WIF from public key", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = BIP32.fromBase58(xpub);

    assert.throws(() => {
      key.toWIF();
    });
  });

  it("should create from seed", () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = i;
    }

    const key = BIP32.fromSeed(seed);
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.privateKey instanceof Uint8Array);
  });

  it("should create from seed with network", () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = i;
    }

    const key = BIP32.fromSeed(seed, "BitcoinTestnet3");
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.toBase58().startsWith("tprv"));
  });
});

describe("BIP32 Benchmarks: wasm-bip32 vs utxo-lib", function () {
  // Increase timeout for benchmark tests on slower CI runners
  this.timeout(30000);
  const warmupOps = 100;
  const ops = 1000;
  const seed = new Uint8Array(32).fill(1);
  const xprv =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
  const xpub =
    "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
  const path = "m/44'/0'/0'/0/0";

  function benchmark(name: string, wasmFn: () => void, utxolibFn: () => void) {
    it(name, () => {
      // Warm-up phase: initialize lazy structures (precomputed tables, JIT, etc.)
      for (let i = 0; i < warmupOps; i++) {
        wasmFn();
        utxolibFn();
      }

      // Measure wasm-bip32
      let start = Date.now();
      for (let i = 0; i < ops; i++) {
        wasmFn();
      }
      const wasmTime = Date.now() - start;
      const wasmOpsPerSec = ops / (wasmTime / 1000);

      // Measure utxo-lib
      start = Date.now();
      for (let i = 0; i < ops; i++) {
        utxolibFn();
      }
      const utxolibTime = Date.now() - start;
      const utxolibOpsPerSec = ops / (utxolibTime / 1000);

      const ratio = wasmOpsPerSec / utxolibOpsPerSec;

      console.log(`\n  ${name}:`);
      console.log(
        `    wasm-bip32: ${wasmTime.toFixed(2)}ms for ${ops} ops (${wasmOpsPerSec.toFixed(0)} ops/sec)`,
      );
      console.log(
        `    utxo-lib  : ${utxolibTime.toFixed(2)}ms for ${ops} ops (${utxolibOpsPerSec.toFixed(0)} ops/sec)`,
      );
      console.log(`    Ratio: ${ratio.toFixed(2)}x`);
    });
  }

  // Note: utxo-lib lazily computes publicKey, so we access it to make fair comparison
  benchmark(
    "fromBase58 (xprv) + publicKey",
    () => {
      const key = BIP32.fromBase58(xprv);
      void key.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromBase58(xprv);
      void key.publicKey; // Force publicKey computation (lazy in utxo-lib)
    },
  );

  benchmark(
    "fromBase58 (xpub)",
    () => BIP32.fromBase58(xpub),
    () => utxolibBip32.fromBase58(xpub),
  );

  benchmark(
    "fromSeed + publicKey",
    () => {
      const key = BIP32.fromSeed(seed);
      void key.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromSeed(Buffer.from(seed));
      void key.publicKey; // Force publicKey computation (lazy in utxo-lib)
    },
  );

  benchmark(
    "derivePath from xprv + publicKey",
    () => {
      const key = BIP32.fromBase58(xprv);
      const derived = key.derivePath(path);
      void derived.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromBase58(xprv);
      const derived = key.derivePath(path);
      void derived.publicKey; // Force publicKey computation
    },
  );

  benchmark(
    "derivePath from xpub + publicKey",
    () => {
      const key = BIP32.fromBase58(xpub);
      const derived = key.derivePath("0/0/0/0/0");
      void derived.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromBase58(xpub);
      const derived = key.derivePath("0/0/0/0/0");
      void derived.publicKey; // Force publicKey computation
    },
  );

  benchmark(
    "neutered() + publicKey",
    () => {
      const key = BIP32.fromBase58(xprv);
      const pub = key.neutered();
      void pub.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromBase58(xprv);
      const pub = key.neutered();
      void pub.publicKey; // Force publicKey computation
    },
  );

  benchmark(
    "derive single child + publicKey",
    () => {
      const key = BIP32.fromBase58(xpub);
      const derived = key.derive(0);
      void derived.publicKey; // Force publicKey computation
    },
    () => {
      const key = utxolibBip32.fromBase58(xpub);
      const derived = key.derive(0);
      void derived.publicKey; // Force publicKey computation
    },
  );
});
