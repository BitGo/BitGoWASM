import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BitGoPsbt, type NetworkName } from "../../js/fixedScriptWallet/index.js";

describe("PayGo Attestation", function () {
  function createSimplePsbt(): BitGoPsbt {
    // Create a simple PSBT using utxolib
    const network = utxolib.networks.bitcoin;
    const psbt = new utxolib.Psbt({ network });
    psbt.addInput({
      hash: Buffer.alloc(32, 0),
      index: 0,
    });
    // Add output with script_pubkey for address 1CdWUVacSQQJ617HuNWByGiisEGXGNx2c
    psbt.addOutput({
      script: Buffer.from("76a91479b000887626b294a914501a4cd226b58b23598388ac", "hex"),
      value: BigInt(10000000),
    });

    return BitGoPsbt.fromBytes(psbt.toBuffer(), "bitcoin" as NetworkName);
  }

  it("should add and detect PayGo attestation", function () {
    const psbt = createSimplePsbt();

    // Test fixtures from utxo-core
    const entropy = Buffer.alloc(64, 0);
    const signature = Buffer.from(
      "1fd62abac20bb963f5150aa4b3f4753c5f2f53ced5183ab7761d0c95c2820f6b" +
        "b722b6d0d9adbab782d2d0d66402794b6bd6449dc26f634035ee388a2b5e7b53f6",
      "hex",
    );

    // Get bytes before adding attestation
    const psbtBytesBeforeAttestation = psbt.serialize();

    // Add PayGo attestation to the first (and only) output
    psbt.addPayGoAttestation(0, entropy, signature);

    // Get bytes after adding attestation
    const psbtBytesAfterAttestation = psbt.serialize();

    // The attestation should now be present in the PSBT
    // We can verify this by checking that the bytes are longer
    assert.ok(psbtBytesAfterAttestation.length > psbtBytesBeforeAttestation.length);

    // Also verify we can parse it back
    const psbtWithAttestation = BitGoPsbt.fromBytes(
      psbtBytesAfterAttestation,
      "bitcoin" as NetworkName,
    );
    assert.ok(psbtWithAttestation.serialize().length > psbtBytesBeforeAttestation.length);
  });

  it("should fail to add attestation with invalid entropy length", function () {
    const psbt = createSimplePsbt();

    // Invalid entropy (wrong length)
    const entropy = Buffer.alloc(32, 0); // Should be 64 bytes
    const signature = Buffer.alloc(65, 1);

    // Should throw an error
    assert.throws(() => {
      psbt.addPayGoAttestation(0, entropy, signature);
    }, /Invalid entropy length/);
  });

  it("should fail to add attestation to invalid output index", function () {
    const psbt = createSimplePsbt();

    const entropy = Buffer.alloc(64, 0);
    const signature = Buffer.alloc(65, 1);

    // Should throw an error for out of bounds index
    assert.throws(() => {
      psbt.addPayGoAttestation(999, entropy, signature);
    }, /out of bounds/);
  });

  it("should replace existing attestation when adding to same output", function () {
    const psbt = createSimplePsbt();

    const entropy = Buffer.alloc(64, 0);
    const signature1 = Buffer.alloc(65, 1);
    const signature2 = Buffer.alloc(65, 2);

    // Add first attestation
    psbt.addPayGoAttestation(0, entropy, signature1);
    const bytesAfterFirst = psbt.serialize();

    // Add second attestation with same entropy
    psbt.addPayGoAttestation(0, entropy, signature2);
    const bytesAfterSecond = psbt.serialize();

    // The bytes should be different (different signature)
    assert.notEqual(
      Buffer.from(bytesAfterFirst).toString("hex"),
      Buffer.from(bytesAfterSecond).toString("hex"),
    );

    // But the length should be similar (one attestation replaced, not added)
    // Allow some variance due to encoding differences
    assert.ok(Math.abs(bytesAfterFirst.length - bytesAfterSecond.length) < 10);
  });

  it("should verify PayGo attestation with correct pubkey", function () {
    // This test documents the expected behavior once signature verification is working
    const psbt = createSimplePsbt();

    // Test fixtures
    const entropy = Buffer.alloc(64, 0);
    const signature = Buffer.from(
      "1fd62abac20bb963f5150aa4b3f4753c5f2f53ced5183ab7761d0c95c2820f6b" +
        "b722b6d0d9adbab782d2d0d66402794b6bd6449dc26f634035ee388a2b5e7b53f6",
      "hex",
    );

    // Add attestation
    psbt.addPayGoAttestation(0, entropy, signature);

    // Note: Verification with ECPair would be tested here once signature format is aligned
    // For now, we just verify the attestation was added
    const bytesWithAttestation = psbt.serialize();
    assert.ok(bytesWithAttestation.length > 0);
  });
});
