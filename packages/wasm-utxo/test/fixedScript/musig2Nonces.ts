import assert from "assert";
import { BitGoPsbt } from "../../js/fixedScriptWallet/index.js";
import { BIP32 } from "../../js/bip32.js";
import {
  loadPsbtFixture,
  getBitGoPsbt,
  type Fixture,
} from "./fixtureUtil.js";

describe("MuSig2 nonce management", function () {
  describe("Bitcoin mainnet", function () {
    const networkName = "bitcoin";
    let fixture: Fixture;
    let unsignedBitgoPsbt: BitGoPsbt;
    let userKey: BIP32;

    before(function () {
      fixture = loadPsbtFixture(networkName, "unsigned");
      unsignedBitgoPsbt = getBitGoPsbt(fixture, networkName);
      userKey = BIP32.fromBase58(fixture.walletKeys[0]);
    });

    it("should generate nonces for MuSig2 inputs with auto-generated session ID", function () {
      // Generate nonces with auto-generated session ID (no second parameter)
      assert.doesNotThrow(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(userKey);
      });

      // Verify nonces were stored by serializing and deserializing
      const serialized = unsignedBitgoPsbt.serialize();
      assert.ok(serialized.length > getBitGoPsbt(fixture, networkName).serialize().length);
    });

    it("should reject invalid session ID length", function () {
      // Invalid session ID (wrong length)
      const invalidSessionId = new Uint8Array(16); // Should be 32 bytes

      assert.throws(() => {
        unsignedBitgoPsbt.generateMusig2Nonces(userKey, invalidSessionId);
      }, "Should throw error for invalid session ID length");
    });

    it("should reject custom session ID on mainnet (security)", function () {
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
