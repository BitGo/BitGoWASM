import * as assert from "assert";
import * as crypto from "crypto";
import { bip32 as utxolibBip32, BIP32Interface } from "@bitgo/utxo-lib";
import { BIP32 } from "../js/bip32.js";

// Test fixtures
const XPRV =
  "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
const XPUB =
  "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
const BIP39_SEED = Buffer.from(
  "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
  "hex",
);

// Helper to compare Uint8Array with Buffer
function assertBuffersEqual(a: Uint8Array, b: Buffer, msg?: string): void {
  assert.strictEqual(Buffer.from(a).compare(b), 0, msg);
}

// Helper to assert all common BIP32 properties match
function assertKeysMatch(wasm: BIP32, utxolib: BIP32Interface, msg?: string): void {
  const prefix = msg ? `${msg}: ` : "";
  assert.strictEqual(wasm.toBase58(), utxolib.toBase58(), `${prefix}toBase58`);
  assert.strictEqual(wasm.depth, utxolib.depth, `${prefix}depth`);
  assert.strictEqual(wasm.index, utxolib.index, `${prefix}index`);
  assert.strictEqual(
    wasm.parentFingerprint,
    utxolib.parentFingerprint,
    `${prefix}parentFingerprint`,
  );
  assert.strictEqual(wasm.isNeutered(), utxolib.isNeutered(), `${prefix}isNeutered`);
  assertBuffersEqual(wasm.chainCode, utxolib.chainCode, `${prefix}chainCode`);
  assertBuffersEqual(wasm.publicKey, utxolib.publicKey, `${prefix}publicKey`);
  assertBuffersEqual(wasm.identifier, utxolib.identifier, `${prefix}identifier`);
  assertBuffersEqual(wasm.fingerprint, utxolib.fingerprint, `${prefix}fingerprint`);
  if (wasm.privateKey && utxolib.privateKey) {
    assertBuffersEqual(wasm.privateKey, utxolib.privateKey, `${prefix}privateKey`);
  } else {
    assert.strictEqual(wasm.privateKey, utxolib.privateKey, `${prefix}privateKey undefined`);
  }
}

describe("WasmBIP32", () => {
  it("should create from base58 xpub", () => {
    const key = BIP32.fromBase58(XPUB);

    assert.strictEqual(key.isNeutered(), true);
    assert.strictEqual(key.depth, 3);
    assert.strictEqual(key.toBase58(), XPUB);
    assert.ok(key.chainCode instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.ok(key.identifier instanceof Uint8Array);
    assert.ok(key.fingerprint instanceof Uint8Array);
    assert.strictEqual(key.privateKey, undefined);
  });

  it("should create from base58 xprv", () => {
    const key = BIP32.fromBase58(XPRV);

    assert.strictEqual(key.isNeutered(), false);
    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.toBase58(), XPRV);
    assert.ok(key.chainCode instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.identifier instanceof Uint8Array);
    assert.ok(key.fingerprint instanceof Uint8Array);
  });

  it("should derive child keys", () => {
    const key = BIP32.fromBase58(XPUB);
    const child = key.derive(0);

    assert.strictEqual(child.depth, 4);
    assert.strictEqual(child.isNeutered(), true);
  });

  it("should derive using path", () => {
    const key = BIP32.fromBase58(XPRV);

    const derived1 = key.derivePath("0/1/2");
    const derived2 = key.derivePath("m/0/1/2");

    assert.strictEqual(derived1.depth, 3);
    assert.strictEqual(derived2.depth, 3);
    assert.strictEqual(derived1.toBase58(), derived2.toBase58());
  });

  it("should neuter a private key", () => {
    const key = BIP32.fromBase58(XPRV);
    const neutered = key.neutered();

    assert.strictEqual(neutered.isNeutered(), true);
    assert.strictEqual(neutered.privateKey, undefined);
    assert.ok(neutered.publicKey instanceof Uint8Array);
  });

  it("should derive hardened keys from private key", () => {
    const key = BIP32.fromBase58(XPRV);
    const hardened = key.deriveHardened(0);

    assert.strictEqual(hardened.depth, 1);
    assert.strictEqual(hardened.isNeutered(), false);
  });

  it("should fail to derive hardened from public key", () => {
    const key = BIP32.fromBase58(XPUB);
    assert.throws(() => key.deriveHardened(0));
  });

  it("should export to WIF", () => {
    const key = BIP32.fromBase58(XPRV);
    const wif = key.toWIF();

    assert.ok(typeof wif === "string");
    assert.ok(wif.length > 0);
  });

  it("should fail to export WIF from public key", () => {
    const key = BIP32.fromBase58(XPUB);
    assert.throws(() => key.toWIF());
  });

  it("should create from seed", () => {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
    const key = BIP32.fromSeed(seed);

    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.privateKey instanceof Uint8Array);
  });

  it("should create from seed with network", () => {
    const seed = Uint8Array.from({ length: 32 }, (_, i) => i);
    const key = BIP32.fromSeed(seed, "BitcoinTestnet3");

    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.toBase58().startsWith("tprv"));
  });

  it("should create from seed string using SHA256", () => {
    const key1 = BIP32.fromSeedSha256("test");
    const key2 = BIP32.fromSeedSha256("test");

    assert.strictEqual(key1.depth, 0);
    assert.strictEqual(key1.isNeutered(), false);
    assert.ok(key1.privateKey instanceof Uint8Array);
    assert.strictEqual(key1.toBase58(), key2.toBase58()); // deterministic
  });

  it("should create from seed string with network", () => {
    const key = BIP32.fromSeedSha256("test", "BitcoinTestnet3");

    assert.strictEqual(key.depth, 0);
    assert.strictEqual(key.isNeutered(), false);
    assert.ok(key.toBase58().startsWith("tprv"));
  });
});

describe("BIP32.equals", () => {
  it("should return true for identical keys from same base58", () => {
    const a = BIP32.fromBase58(XPUB);
    const b = BIP32.fromBase58(XPUB);
    assert.ok(a.equals(b));
    assert.ok(b.equals(a));
  });

  it("should return true for identical private keys", () => {
    const a = BIP32.fromBase58(XPRV);
    const b = BIP32.fromBase58(XPRV);
    assert.ok(a.equals(b));
  });

  it("should return false for different keys", () => {
    const a = BIP32.fromBase58(XPRV);
    const b = a.derive(0);
    assert.ok(!a.equals(b));
    assert.ok(!b.equals(a));
  });

  it("should return false for private key vs its neutered form", () => {
    const priv = BIP32.fromBase58(XPRV);
    const pub_ = priv.neutered();
    assert.ok(!priv.equals(pub_));
    assert.ok(!pub_.equals(priv));
  });

  it("should return true for neutered keys derived from same private key", () => {
    const a = BIP32.fromBase58(XPRV).neutered();
    const b = BIP32.fromBase58(XPRV).neutered();
    assert.ok(a.equals(b));
  });

  it("should return true for derived keys at same path", () => {
    const root = BIP32.fromBase58(XPRV);
    const a = root.derivePath("0/1/2").neutered();
    const b = root.derivePath("0/1/2").neutered();
    assert.ok(a.equals(b));
  });

  it("should work with BIP32Interface from utxolib", () => {
    const wasmKey = BIP32.fromBase58(XPUB);
    const utxolibKey = utxolibBip32.fromBase58(XPUB);
    assert.ok(wasmKey.equals(utxolibKey));
  });
});

describe("BIP32.toJSON and inspect", () => {
  it("should return xpub and hasPrivateKey=false from toJSON for public key", () => {
    const key = BIP32.fromBase58(XPUB);
    assert.deepStrictEqual(key.toJSON(), { xpub: XPUB, hasPrivateKey: false });
  });

  it("should return xpub and hasPrivateKey=true from toJSON for private key", () => {
    const key = BIP32.fromBase58(XPRV);
    const json = key.toJSON();
    assert.strictEqual(json.hasPrivateKey, true);
    assert.ok(json.xpub.startsWith("xpub"), "should serialize as xpub, not xprv");
    assert.strictEqual(json.xpub, key.neutered().toBase58());
  });

  it("should never leak xprv in JSON.stringify", () => {
    const key = BIP32.fromBase58(XPRV);
    const serialized = JSON.stringify({ key });
    assert.ok(!serialized.includes("xprv"), "serialized JSON must not contain xprv");
    assert.ok(serialized.includes("xpub"), "serialized JSON must contain xpub");
  });

  it("should return formatted string from inspect for public key", () => {
    const key = BIP32.fromBase58(XPUB);
    const inspect = key[
      Symbol.for("nodejs.util.inspect.custom") as unknown as symbol
    ] as () => string;
    assert.strictEqual(inspect.call(key), `BIP32(${XPUB})`);
  });

  it("should return formatted string with flag from inspect for private key", () => {
    const key = BIP32.fromBase58(XPRV);
    const inspect = key[
      Symbol.for("nodejs.util.inspect.custom") as unknown as symbol
    ] as () => string;
    const result = inspect.call(key) as string;
    assert.ok(result.includes("hasPrivateKey"), "should indicate private key presence");
    assert.ok(!result.includes("xprv"), "should not leak xprv");
    assert.ok(result.startsWith("BIP32(xpub"), "should show xpub");
  });
});

describe("WasmBIP32 parity with utxolib", () => {
  it("should match utxolib when creating from base58 xpub", () => {
    assertKeysMatch(BIP32.fromBase58(XPUB), utxolibBip32.fromBase58(XPUB));
  });

  it("should match utxolib when creating from base58 xprv", () => {
    assertKeysMatch(BIP32.fromBase58(XPRV), utxolibBip32.fromBase58(XPRV));
  });

  it("should match utxolib when deriving normal child keys", () => {
    const wasmKey = BIP32.fromBase58(XPRV);
    const utxolibKey = utxolibBip32.fromBase58(XPRV);

    for (const index of [0, 1, 10, 100, 2147483647]) {
      assertKeysMatch(wasmKey.derive(index), utxolibKey.derive(index), `index ${index}`);
    }
  });

  it("should match utxolib when deriving hardened child keys", () => {
    const wasmKey = BIP32.fromBase58(XPRV);
    const utxolibKey = utxolibBip32.fromBase58(XPRV);

    for (const index of [0, 1, 10, 2147483647]) {
      assertKeysMatch(
        wasmKey.deriveHardened(index),
        utxolibKey.deriveHardened(index),
        `hardened ${index}`,
      );
    }
  });

  it("should match utxolib when deriving using paths", () => {
    const wasmKey = BIP32.fromBase58(XPRV);
    const utxolibKey = utxolibBip32.fromBase58(XPRV);

    for (const path of ["0", "0/1", "0/1/2", "m/0/1/2", "0'/1", "m/44'/0'/0'", "m/44'/0'/0'/0/0"]) {
      assertKeysMatch(wasmKey.derivePath(path), utxolibKey.derivePath(path), `path ${path}`);
    }
  });

  it("should match utxolib when deriving from public keys", () => {
    const wasmKey = BIP32.fromBase58(XPUB);
    const utxolibKey = utxolibBip32.fromBase58(XPUB);

    for (const index of [0, 1, 10, 100]) {
      assertKeysMatch(wasmKey.derive(index), utxolibKey.derive(index), `index ${index}`);
    }
  });

  it("should match utxolib when neutering", () => {
    const wasmKey = BIP32.fromBase58(XPRV).neutered();
    const utxolibKey = utxolibBip32.fromBase58(XPRV).neutered();
    assertKeysMatch(wasmKey, utxolibKey);
  });

  it("should match utxolib when exporting to WIF", () => {
    assert.strictEqual(BIP32.fromBase58(XPRV).toWIF(), utxolibBip32.fromBase58(XPRV).toWIF());
  });

  it("should match utxolib for BIP44 wallet derivation", () => {
    const path = "m/44'/0'/0'/0/0";
    assertKeysMatch(
      BIP32.fromSeed(BIP39_SEED).derivePath(path),
      utxolibBip32.fromSeed(BIP39_SEED).derivePath(path),
    );
  });

  it("should produce same fingerprint for derived keys", () => {
    const wasmKey = BIP32.fromBase58(XPRV);
    const utxolibKey = utxolibBip32.fromBase58(XPRV);

    const wasmChild = wasmKey.derive(0);
    const utxolibChild = utxolibKey.derive(0);

    assert.strictEqual(wasmChild.parentFingerprint, utxolibChild.parentFingerprint);
    assert.strictEqual(
      wasmChild.parentFingerprint,
      new DataView(wasmKey.fingerprint.buffer).getUint32(0, false),
    );
  });

  it("should match utxolib when using fromSeedSha256", () => {
    for (const seedString of [
      "test",
      "user",
      "backup",
      "bitgo",
      "default.0",
      "default.1",
      "default.2",
    ]) {
      const hash = crypto.createHash("sha256").update(seedString).digest();
      assertKeysMatch(
        BIP32.fromSeedSha256(seedString),
        utxolibBip32.fromSeed(hash),
        `seed "${seedString}"`,
      );
    }
  });

  it("should create from utxolib BIP32 instance with private key", () => {
    const utxolibKey = utxolibBip32.fromBase58(XPRV);
    const wasmKey = BIP32.from(utxolibKey);

    assertKeysMatch(wasmKey, utxolibKey);
    assertKeysMatch(
      wasmKey.derivePath("m/44'/0'/0'"),
      utxolibKey.derivePath("m/44'/0'/0'"),
      "derived",
    );
  });

  it("should create from utxolib BIP32 instance without private key", () => {
    const utxolibKey = utxolibBip32.fromBase58(XPUB);
    const wasmKey = BIP32.from(utxolibKey);

    assertKeysMatch(wasmKey, utxolibKey);
    assertKeysMatch(wasmKey.derive(0).derive(0), utxolibKey.derive(0).derive(0), "derived");
  });
});
