import assert from "assert";
import { BIP32 } from "../../js/bip32.js";
import { loadPsbtFixture, getBitGoPsbt, type Fixture } from "./fixtureUtil.js";

describe("MuSig2 nonce management", function () {
  describe("Bitcoin mainnet", function () {
    const networkName = "bitcoin";
    let fixture: Fixture;
    let userKey: BIP32;
    let backupKey: BIP32;
    let bitgoKey: BIP32;

    before(function () {
      fixture = loadPsbtFixture(networkName, "unsigned");
      userKey = BIP32.fromBase58(fixture.walletKeys[0]);
      backupKey = BIP32.fromBase58(fixture.walletKeys[1]);
      bitgoKey = BIP32.fromBase58(fixture.walletKeys[2]);
    });

    it("should generate nonces for MuSig2 inputs with auto-generated session ID", function () {
      const unsignedBitgoPsbt = getBitGoPsbt(fixture, networkName);
      // Generate nonces with auto-generated session ID (no second parameter)
      assert.doesNotThrow(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(userKey);
      });
      // Verify nonces were stored by serializing and deserializing
      const serializedWithUserNonces = unsignedBitgoPsbt.serialize();
      assert.ok(
        serializedWithUserNonces.length > getBitGoPsbt(fixture, networkName).serialize().length,
      );

      assert.doesNotThrow(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(bitgoKey);
      });

      const serializedWithBitgoNonces = unsignedBitgoPsbt.serialize();
      assert.ok(serializedWithBitgoNonces.length > serializedWithUserNonces.length);

      assert.throws(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(backupKey);
      }, "Should throw error when generating nonces for backup key");
    });

    it("implements combineMusig2Nonces", function () {
      const unsignedBitgoPsbtWithUserNonces = getBitGoPsbt(fixture, networkName);
      unsignedBitgoPsbtWithUserNonces.generateMusig2Nonces(userKey);

      const unsignedBitgoPsbtWithBitgoNonces = getBitGoPsbt(fixture, networkName);
      unsignedBitgoPsbtWithBitgoNonces.generateMusig2Nonces(bitgoKey);

      const unsignedBitgoPsbtWithBothNonces = getBitGoPsbt(fixture, networkName);
      unsignedBitgoPsbtWithBothNonces.combineMusig2Nonces(unsignedBitgoPsbtWithUserNonces);
      unsignedBitgoPsbtWithBothNonces.combineMusig2Nonces(unsignedBitgoPsbtWithBitgoNonces);

      {
        const psbt = getBitGoPsbt(fixture, networkName);
        psbt.combineMusig2Nonces(unsignedBitgoPsbtWithUserNonces);
        assert.strictEqual(
          psbt.serialize().length,
          unsignedBitgoPsbtWithUserNonces.serialize().length,
        );
      }

      {
        const psbt = getBitGoPsbt(fixture, networkName);
        psbt.combineMusig2Nonces(unsignedBitgoPsbtWithBitgoNonces);
        assert.strictEqual(
          psbt.serialize().length,
          unsignedBitgoPsbtWithBitgoNonces.serialize().length,
        );
      }

      {
        const psbt = getBitGoPsbt(fixture, networkName);
        psbt.combineMusig2Nonces(unsignedBitgoPsbtWithUserNonces);
        psbt.combineMusig2Nonces(unsignedBitgoPsbtWithBitgoNonces);
        assert.strictEqual(
          psbt.serialize().length,
          unsignedBitgoPsbtWithBothNonces.serialize().length,
        );
      }
    });

    it("should reject invalid session ID length", function () {
      const unsignedBitgoPsbt = getBitGoPsbt(fixture, networkName);

      // Invalid session ID (wrong length)
      const invalidSessionId = new Uint8Array(16); // Should be 32 bytes

      assert.throws(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(userKey, invalidSessionId);
      }, "Should throw error for invalid session ID length");
    });

    it("should reject custom session ID on mainnet (security)", function () {
      const unsignedBitgoPsbt = getBitGoPsbt(fixture, "bitcoin");
      // Custom session ID should be rejected on mainnet for security
      const customSessionId = new Uint8Array(32).fill(1);

      assert.throws(
        () => {
          unsignedBitgoPsbt.generateMusig2Nonces(userKey, customSessionId);
        },
        /Custom session_id is only allowed on testnets/,
        "Should throw error when providing custom session_id on mainnet",
      );
    });
  });
});
