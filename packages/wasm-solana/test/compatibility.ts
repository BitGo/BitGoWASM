import * as assert from "assert";
import { Keypair, Pubkey } from "../js/index.js";

/**
 * Compatibility tests to verify our WASM implementation produces the same
 * results as BitGoJS sdk-coin-sol KeyPair.
 *
 * Test vectors from: BitGoJS/modules/sdk-coin-sol/test/resources/sol.ts
 */
describe("Compatibility with BitGoJS sdk-coin-sol", () => {
  describe("accountWithSeed test vector", () => {
    // From BitGoJS/modules/sdk-coin-sol/test/resources/sol.ts
    const testVector = {
      // 32-byte seed (Ed25519 secret key)
      seed: new Uint8Array([
        210, 49, 239, 175, 249, 91, 42, 66, 77, 70, 3, 144, 23, 0, 145, 152, 86, 35, 166, 11, 129,
        49, 201, 162, 255, 195, 94, 229, 98, 78, 76, 38,
      ]),
      // Expected public key / address
      publicKey: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
      // 64-byte Solana secret key format (seed + public key)
      solanaSecretKey: new Uint8Array([
        210, 49, 239, 175, 249, 91, 42, 66, 77, 70, 3, 144, 23, 0, 145, 152, 86, 35, 166, 11, 129,
        49, 201, 162, 255, 195, 94, 229, 98, 78, 76, 38, 212, 208, 16, 9, 69, 152, 60, 244, 226, 41,
        142, 209, 252, 78, 138, 101, 66, 156, 232, 39, 235, 224, 69, 45, 62, 111, 249, 253, 44, 80,
        162, 48,
      ]),
    };

    it("should derive same address from seed as BitGoJS KeyPair", () => {
      // BitGoJS: new KeyPair({ seed: testData.accountWithSeed.seed }).getAddress()
      const keypair = Keypair.fromSecretKey(testVector.seed);
      const address = keypair.getAddress();

      assert.strictEqual(
        address,
        testVector.publicKey,
        `Address mismatch!\n  Expected: ${testVector.publicKey}\n  Got: ${address}`,
      );
    });

    it("should derive same address from 64-byte Solana secret key", () => {
      // BitGoJS: new KeyPair({ prv: base58(solanaSecretKey) }).getAddress()
      const keypair = Keypair.fromSolanaSecretKey(testVector.solanaSecretKey);
      const address = keypair.getAddress();

      assert.strictEqual(address, testVector.publicKey);
    });

    it("should parse public key and roundtrip correctly", () => {
      // BitGoJS: new KeyPair({ pub: testData.accountWithSeed.publicKey })
      const pubkey = Pubkey.fromBase58(testVector.publicKey);
      const roundtripped = pubkey.toBase58();

      assert.strictEqual(roundtripped, testVector.publicKey);
    });

    it("should produce matching public key bytes", () => {
      const keypair = Keypair.fromSecretKey(testVector.seed);
      const pubkeyFromAddress = Pubkey.fromBase58(testVector.publicKey);

      // Public key bytes from keypair should match parsed address
      assert.deepStrictEqual(keypair.publicKey, pubkeyFromAddress.toBytes());
    });
  });

  describe("authAccount test vector", () => {
    // Another test vector from BitGoJS
    const authAccount = {
      pub: "5hr5fisPi6DXNuuRpm5XUbzpiEnmdyxXuBDTwzwZj5Pe",
    };

    it("should parse authAccount public key", () => {
      const pubkey = Pubkey.fromBase58(authAccount.pub);

      assert.strictEqual(pubkey.toBase58(), authAccount.pub);
      assert.strictEqual(pubkey.toBytes().length, 32);
    });
  });
});
