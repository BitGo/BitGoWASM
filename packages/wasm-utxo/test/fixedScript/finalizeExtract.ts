import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { fixedScriptWallet } from "../../js/index.js";
import {
  loadPsbtFixture,
  getPsbtBuffer,
  getExtractedTransactionHex,
  type Fixture,
} from "./fixtureUtil.js";
import { getFixtureNetworks } from "./networkSupport.util.js";

describe("finalize and extract transaction", function () {
  getFixtureNetworks().forEach((network) => {
    const networkName = utxolib.getNetworkName(network);

    describe(`network: ${networkName}`, function () {
      let fullsignedFixture: Fixture;
      let fullsignedPsbtBuffer: Buffer;
      let fullsignedBitgoPsbt: fixedScriptWallet.BitGoPsbt;

      before(function () {
        fullsignedFixture = loadPsbtFixture(networkName, "fullsigned");
        fullsignedPsbtBuffer = getPsbtBuffer(fullsignedFixture);
        fullsignedBitgoPsbt = fixedScriptWallet.BitGoPsbt.fromBytes(
          fullsignedPsbtBuffer,
          networkName,
        );
      });

      it("should serialize and deserialize PSBT (round-trip)", function () {
        const serialized = fullsignedBitgoPsbt.serialize();

        // Verify we can deserialize what we serialized (functional round-trip)
        const deserialized = fixedScriptWallet.BitGoPsbt.fromBytes(serialized, networkName);

        // Verify the deserialized PSBT has the same unsigned txid
        assert.strictEqual(
          deserialized.unsignedTxid(),
          fullsignedBitgoPsbt.unsignedTxid(),
          "Deserialized PSBT should have same unsigned txid after round-trip",
        );

        // Verify the re-deserialized PSBT can be serialized back to bytes
        const reserialized = deserialized.serialize();

        // Verify functional equivalence by deserializing again and checking txid
        const redeserialized = fixedScriptWallet.BitGoPsbt.fromBytes(reserialized, networkName);
        assert.strictEqual(
          redeserialized.unsignedTxid(),
          fullsignedBitgoPsbt.unsignedTxid(),
          "PSBT should maintain consistency through multiple serialize/deserialize cycles",
        );
      });

      it("should finalize all inputs and be extractable", function () {
        // Create a fresh instance for finalization
        const psbt = fixedScriptWallet.BitGoPsbt.fromBytes(fullsignedPsbtBuffer, networkName);

        // Finalize all inputs
        psbt.finalizeAllInputs();

        // Serialize the finalized PSBT
        const serialized = psbt.serialize();

        // Verify we can deserialize the finalized PSBT
        const deserialized = fixedScriptWallet.BitGoPsbt.fromBytes(serialized, networkName);

        // Verify it can be extracted (which confirms finalization worked)
        const extractedTx = deserialized.extractTransaction();
        const extractedTxHex = Buffer.from(extractedTx).toString("hex");
        const expectedTxHex = getExtractedTransactionHex(fullsignedFixture);

        assert.strictEqual(
          extractedTxHex,
          expectedTxHex,
          "Extracted transaction from finalized PSBT should match expected transaction",
        );
      });

      it("should extract transaction from finalized PSBT", function () {
        // Create a fresh instance for extraction
        const psbt = fixedScriptWallet.BitGoPsbt.fromBytes(fullsignedPsbtBuffer, networkName);

        // Finalize all inputs
        psbt.finalizeAllInputs();

        // Extract transaction
        const extractedTx = psbt.extractTransaction();
        const extractedTxHex = Buffer.from(extractedTx).toString("hex");

        // Get expected transaction hex from fixture
        const expectedTxHex = getExtractedTransactionHex(fullsignedFixture);

        assert.strictEqual(
          extractedTxHex,
          expectedTxHex,
          "Extracted transaction should match expected transaction",
        );
      });
    });
  });
});
