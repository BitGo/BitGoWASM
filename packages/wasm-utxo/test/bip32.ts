import * as assert from "assert";
import * as crypto from "crypto";
import { bip32 as utxolibBip32 } from "@bitgo/utxo-lib";
import { BIP32 } from "../js/bip32.js";

const bip32 = { BIP32 };

describe("WasmBIP32", () => {
  it("should create from base58 xpub", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = bip32.BIP32.fromBase58(xpub);

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
    const key = bip32.BIP32.fromBase58(xprv);

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
    const key = bip32.BIP32.fromBase58(xpub);

    const child = key.derive(0);
    assert.strictEqual(child.depth, 4);
    assert.strictEqual(child.isNeutered(), true);
  });

  it("should derive using path", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = bip32.BIP32.fromBase58(xprv);

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
    const key = bip32.BIP32.fromBase58(xprv);
    const neuteredKey = key.neutered();

    assert.strictEqual(neuteredKey.isNeutered(), true);
    assert.strictEqual(neuteredKey.privateKey, undefined);
    assert.ok(neuteredKey.publicKey instanceof Uint8Array);
  });

  it("should derive hardened keys from private key", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = bip32.BIP32.fromBase58(xprv);

    const hardened = key.deriveHardened(0);
    assert.strictEqual(hardened.depth, 1);
    assert.strictEqual(hardened.isNeutered(), false);
  });

  it("should fail to derive hardened from public key", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = bip32.BIP32.fromBase58(xpub);

    assert.throws(() => {
      key.deriveHardened(0);
    });
  });

  it("should export to WIF", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
    const key = bip32.BIP32.fromBase58(xprv);

    const wif = key.toWIF();
    assert.ok(typeof wif === "string");
    assert.ok(wif.length > 0);
  });

  it("should fail to export WIF from public key", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
    const key = bip32.BIP32.fromBase58(xpub);

    assert.throws(() => {
      key.toWIF();
    });
  });

  it("should create from seed", () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = i;
    }

    const key = bip32.BIP32.fromSeed(seed);
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.privateKey instanceof Uint8Array);
  });

  it("should create from seed with network", () => {
    const seed = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      seed[i] = i;
    }

    const key = bip32.BIP32.fromSeed(seed, "BitcoinTestnet3");
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.toBase58().startsWith("tprv"));
  });

  it("should create from seed string using SHA256", () => {
    const seedString = "test";
    const key = bip32.BIP32.fromSeedSha256(seedString);
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.privateKey instanceof Uint8Array);
    // Should be deterministic
    const key2 = bip32.BIP32.fromSeedSha256(seedString);
    assert.strictEqual(key.toBase58(), key2.toBase58());
  });

  it("should create from seed string with network", () => {
    const seedString = "test";
    const key = bip32.BIP32.fromSeedSha256(seedString, "BitcoinTestnet3");
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.toBase58().startsWith("tprv"));
  });
});

describe("WasmBIP32 parity with utxolib", () => {
  function bufferEqual(a: Uint8Array, b: Buffer): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  it("should match utxolib when creating from base58 xpub", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";

    const wasmKey = bip32.BIP32.fromBase58(xpub);
    const utxolibKey = utxolibBip32.fromBase58(xpub);

    // Compare all properties
    assert.strictEqual(wasmKey.toBase58(), utxolibKey.toBase58());
    assert.strictEqual(wasmKey.depth, utxolibKey.depth);
    assert.strictEqual(wasmKey.index, utxolibKey.index);
    assert.strictEqual(wasmKey.parentFingerprint, utxolibKey.parentFingerprint);
    assert.strictEqual(wasmKey.isNeutered(), utxolibKey.isNeutered());
    assert.ok(bufferEqual(wasmKey.chainCode, utxolibKey.chainCode));
    assert.ok(bufferEqual(wasmKey.publicKey, utxolibKey.publicKey));
    assert.ok(bufferEqual(wasmKey.identifier, utxolibKey.identifier));
    assert.ok(bufferEqual(wasmKey.fingerprint, utxolibKey.fingerprint));
  });

  it("should match utxolib when creating from base58 xprv", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    // Compare all properties
    assert.strictEqual(wasmKey.toBase58(), utxolibKey.toBase58());
    assert.strictEqual(wasmKey.depth, utxolibKey.depth);
    assert.strictEqual(wasmKey.index, utxolibKey.index);
    assert.strictEqual(wasmKey.parentFingerprint, utxolibKey.parentFingerprint);
    assert.strictEqual(wasmKey.isNeutered(), utxolibKey.isNeutered());
    assert.ok(bufferEqual(wasmKey.chainCode, utxolibKey.chainCode));
    assert.ok(bufferEqual(wasmKey.publicKey, utxolibKey.publicKey));
    assert.ok(bufferEqual(wasmKey.identifier, utxolibKey.identifier));
    assert.ok(bufferEqual(wasmKey.fingerprint, utxolibKey.fingerprint));
    assert.ok(
      wasmKey.privateKey &&
        utxolibKey.privateKey &&
        bufferEqual(wasmKey.privateKey, utxolibKey.privateKey),
    );
  });

  it("should match utxolib when deriving normal child keys", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    // Derive several children and compare
    for (const index of [0, 1, 10, 100, 2147483647]) {
      const wasmChild = wasmKey.derive(index);
      const utxolibChild = utxolibKey.derive(index);

      assert.strictEqual(wasmChild.toBase58(), utxolibChild.toBase58(), `Failed at index ${index}`);
      assert.ok(bufferEqual(wasmChild.publicKey, utxolibChild.publicKey));
      assert.ok(bufferEqual(wasmChild.chainCode, utxolibChild.chainCode));
    }
  });

  it("should match utxolib when deriving hardened child keys", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    // Derive several hardened children and compare
    for (const index of [0, 1, 10, 2147483647]) {
      const wasmChild = wasmKey.deriveHardened(index);
      const utxolibChild = utxolibKey.deriveHardened(index);

      assert.strictEqual(
        wasmChild.toBase58(),
        utxolibChild.toBase58(),
        `Failed at hardened index ${index}`,
      );
      assert.ok(bufferEqual(wasmChild.publicKey, utxolibChild.publicKey));
      assert.ok(bufferEqual(wasmChild.chainCode, utxolibChild.chainCode));
    }
  });

  it("should match utxolib when deriving using paths", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    const paths = ["0", "0/1", "0/1/2", "m/0/1/2", "0'/1", "m/44'/0'/0'", "m/44'/0'/0'/0/0"];

    for (const path of paths) {
      const wasmDerived = wasmKey.derivePath(path);
      const utxolibDerived = utxolibKey.derivePath(path);

      assert.strictEqual(
        wasmDerived.toBase58(),
        utxolibDerived.toBase58(),
        `Failed at path ${path}`,
      );
      assert.ok(bufferEqual(wasmDerived.publicKey, utxolibDerived.publicKey));
      assert.ok(bufferEqual(wasmDerived.chainCode, utxolibDerived.chainCode));
    }
  });

  it("should match utxolib when deriving from public keys", () => {
    const xpub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";

    const wasmKey = bip32.BIP32.fromBase58(xpub);
    const utxolibKey = utxolibBip32.fromBase58(xpub);

    // Derive several children from public key
    for (const index of [0, 1, 10, 100]) {
      const wasmChild = wasmKey.derive(index);
      const utxolibChild = utxolibKey.derive(index);

      assert.strictEqual(wasmChild.toBase58(), utxolibChild.toBase58());
      assert.ok(bufferEqual(wasmChild.publicKey, utxolibChild.publicKey));
    }
  });

  it("should match utxolib when neutering", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    const wasmNeutered = wasmKey.neutered();
    const utxolibNeutered = utxolibKey.neutered();

    assert.strictEqual(wasmNeutered.toBase58(), utxolibNeutered.toBase58());
    assert.ok(bufferEqual(wasmNeutered.publicKey, utxolibNeutered.publicKey));
    assert.ok(bufferEqual(wasmNeutered.chainCode, utxolibNeutered.chainCode));
    assert.strictEqual(wasmNeutered.privateKey, undefined);
  });

  it("should match utxolib when exporting to WIF", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    assert.strictEqual(wasmKey.toWIF(), utxolibKey.toWIF());
  });

  it("should match utxolib for BIP44 wallet derivation (m/44'/0'/0'/0/0)", () => {
    const seed = Buffer.from(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
      "hex",
    );

    const wasmMaster = bip32.BIP32.fromSeed(seed);
    const utxolibMaster = utxolibBip32.fromSeed(seed);

    // Standard BIP44 path for Bitcoin: m/44'/0'/0'/0/0
    const path = "m/44'/0'/0'/0/0";

    const wasmDerived = wasmMaster.derivePath(path);
    const utxolibDerived = utxolibMaster.derivePath(path);

    assert.strictEqual(wasmDerived.toBase58(), utxolibDerived.toBase58());
    assert.ok(bufferEqual(wasmDerived.publicKey, utxolibDerived.publicKey));
    assert.ok(bufferEqual(wasmDerived.chainCode, utxolibDerived.chainCode));
  });

  it("should produce same fingerprint for derived keys", () => {
    const xprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

    const wasmKey = bip32.BIP32.fromBase58(xprv);
    const utxolibKey = utxolibBip32.fromBase58(xprv);

    // Derive a child and check its parent fingerprint matches the parent's fingerprint
    const wasmChild = wasmKey.derive(0);
    const utxolibChild = utxolibKey.derive(0);

    // Parent fingerprints should match
    assert.strictEqual(wasmChild.parentFingerprint, utxolibChild.parentFingerprint);

    // The parent fingerprint should match the parent's fingerprint
    const wasmParentFp = new DataView(wasmKey.fingerprint.buffer).getUint32(0, false);
    assert.strictEqual(wasmChild.parentFingerprint, wasmParentFp);
  });

  it("should match utxolib when using fromSeedSha256", () => {
    // Test various seed strings to ensure parity with manual SHA256 + fromSeed
    const seedStrings = ["test", "user", "backup", "bitgo", "default.0", "default.1", "default.2"];

    for (const seedString of seedStrings) {
      // Manual approach: hash with SHA256, then create from seed
      const hash = crypto.createHash("sha256").update(seedString).digest();
      const utxolibKey = utxolibBip32.fromSeed(hash);

      // WASM approach: fromSeedSha256 does hashing internally
      const wasmKey = bip32.BIP32.fromSeedSha256(seedString);

      assert.strictEqual(
        wasmKey.toBase58(),
        utxolibKey.toBase58(),
        `Failed for seed string: ${seedString}`,
      );
      assert.ok(bufferEqual(wasmKey.publicKey, utxolibKey.publicKey));
      assert.ok(bufferEqual(wasmKey.chainCode, utxolibKey.chainCode));
    }
  });
});
