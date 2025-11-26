import * as assert from "assert";
import { ECPair } from "../js/ecpair.js";

describe("WasmECPair", () => {
  const testPrivateKey = Buffer.from(
    "1111111111111111111111111111111111111111111111111111111111111111",
    "hex",
  );

  const testWifMainnet = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";
  const testWifTestnet = "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA";

  it("should create from private key", () => {
    const key = ECPair.fromPrivateKey(testPrivateKey);

    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.strictEqual(key.privateKey.length, 32);
    assert.strictEqual(key.publicKey.length, 33); // Always compressed
  });

  it("should create from public key", () => {
    const tempKey = ECPair.fromPrivateKey(testPrivateKey);
    const publicKey = tempKey.publicKey;

    const key = ECPair.fromPublicKey(publicKey);

    assert.strictEqual(key.privateKey, undefined);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.strictEqual(key.publicKey.length, 33);
  });

  it("should create from mainnet WIF", () => {
    const key = ECPair.fromWIF(testWifMainnet);

    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.strictEqual(key.privateKey.length, 32);
  });

  it("should create from testnet WIF", () => {
    const key = ECPair.fromWIF(testWifTestnet);

    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
    assert.strictEqual(key.privateKey.length, 32);
  });

  it("should create from mainnet WIF using fromWIFMainnet", () => {
    const key = ECPair.fromWIFMainnet(testWifMainnet);

    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
  });

  it("should create from testnet WIF using fromWIFTestnet", () => {
    const key = ECPair.fromWIFTestnet(testWifTestnet);

    assert.ok(key.privateKey instanceof Uint8Array);
    assert.ok(key.publicKey instanceof Uint8Array);
  });

  it("should fail when using wrong network WIF method", () => {
    assert.throws(() => {
      ECPair.fromWIFMainnet(testWifTestnet);
    });

    assert.throws(() => {
      ECPair.fromWIFTestnet(testWifMainnet);
    });
  });

  it("should export to WIF mainnet", () => {
    const key = ECPair.fromPrivateKey(testPrivateKey);
    const wif = key.toWIF();

    assert.ok(typeof wif === "string");
    assert.ok(wif.length > 0);
    assert.ok(wif.startsWith("K") || wif.startsWith("L")); // Mainnet compressed
  });

  it("should export to WIF testnet", () => {
    const key = ECPair.fromPrivateKey(testPrivateKey);
    const wif = key.toWIFTestnet();

    assert.ok(typeof wif === "string");
    assert.ok(wif.length > 0);
    assert.ok(wif.startsWith("c")); // Testnet compressed
  });

  it("should roundtrip WIF mainnet", () => {
    const key1 = ECPair.fromPrivateKey(testPrivateKey);
    const wif = key1.toWIF();
    const key2 = ECPair.fromWIF(wif);

    assert.deepStrictEqual(key1.privateKey, key2.privateKey);
    assert.deepStrictEqual(key1.publicKey, key2.publicKey);
  });

  it("should roundtrip WIF testnet", () => {
    const key1 = ECPair.fromPrivateKey(testPrivateKey);
    const wif = key1.toWIFTestnet();
    const key2 = ECPair.fromWIF(wif);

    assert.deepStrictEqual(key1.privateKey, key2.privateKey);
    assert.deepStrictEqual(key1.publicKey, key2.publicKey);
  });

  it("should fail to export WIF from public key", () => {
    const tempKey = ECPair.fromPrivateKey(testPrivateKey);
    const publicKey = tempKey.publicKey;
    const key = ECPair.fromPublicKey(publicKey);

    assert.throws(() => {
      key.toWIF();
    });

    assert.throws(() => {
      key.toWIFMainnet();
    });

    assert.throws(() => {
      key.toWIFTestnet();
    });
  });

  it("should reject invalid private keys", () => {
    // All zeros
    assert.throws(() => {
      ECPair.fromPrivateKey(new Uint8Array(32));
    });

    // Wrong length
    assert.throws(() => {
      ECPair.fromPrivateKey(new Uint8Array(31));
    });

    assert.throws(() => {
      ECPair.fromPrivateKey(new Uint8Array(33));
    });
  });

  it("should reject invalid public keys", () => {
    // Wrong length
    assert.throws(() => {
      ECPair.fromPublicKey(new Uint8Array(32));
    });

    assert.throws(() => {
      ECPair.fromPublicKey(new Uint8Array(34));
    });

    // Invalid format
    assert.throws(() => {
      const invalidPubkey = new Uint8Array(33);
      invalidPubkey[0] = 0x01; // Invalid prefix
      ECPair.fromPublicKey(invalidPubkey);
    });
  });

  it("should always produce compressed public keys", () => {
    const key1 = ECPair.fromPrivateKey(testPrivateKey);
    const key2 = ECPair.fromWIF(testWifMainnet);

    // All public keys should be 33 bytes (compressed)
    assert.strictEqual(key1.publicKey.length, 33);
    assert.strictEqual(key2.publicKey.length, 33);

    // All should start with 0x02 or 0x03 (compressed format)
    assert.ok(key1.publicKey[0] === 0x02 || key1.publicKey[0] === 0x03);
    assert.ok(key2.publicKey[0] === 0x02 || key2.publicKey[0] === 0x03);
  });

  it("should derive same public key from same private key", () => {
    const key1 = ECPair.fromPrivateKey(testPrivateKey);
    const key2 = ECPair.fromPrivateKey(testPrivateKey);

    assert.deepStrictEqual(key1.publicKey, key2.publicKey);
  });
});
