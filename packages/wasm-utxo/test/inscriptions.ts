import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { ECPair } from "../js/ecpair.js";
import { Transaction } from "../js/transaction.js";
import { address, inscriptions } from "../js/index.js";

describe("inscriptions (wasm-utxo)", () => {
  const contentType = "text/plain";

  // Test key (same x-only pubkey as utxo-ord test)
  const xOnlyPubkeyHex = "af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3";

  // Create a keypair from a deterministic private key for testing
  const testPrivateKey = Buffer.from(
    "0000000000000000000000000000000000000000000000000000000000000001",
    "hex",
  );

  describe("createInscriptionRevealData", () => {
    it("should generate an inscription output script", () => {
      const inscriptionData = Buffer.from("Never Gonna Give You Up", "ascii");

      // Create ECPair from x-only pubkey (need to add parity byte for compressed format)
      const compressedPubkey = Buffer.concat([
        Buffer.from([0x02]),
        Buffer.from(xOnlyPubkeyHex, "hex"),
      ]);
      const ecpair = ECPair.fromPublicKey(compressedPubkey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // P2TR output scripts are 34 bytes: OP_1 (0x51) + PUSH32 (0x20) + 32-byte tweaked key
      assert.strictEqual(revealData.outputScript.length, 34);
      assert.strictEqual(revealData.outputScript[0], 0x51); // OP_1
      assert.strictEqual(revealData.outputScript[1], 0x20); // PUSH32

      // Convert to address for testnet
      const commitAddress = address.fromOutputScriptWithCoin(revealData.outputScript, "tbtc");
      assert.ok(commitAddress.startsWith("tb1p")); // Taproot address

      // Verify expected address matches utxo-ord test
      assert.strictEqual(
        commitAddress,
        "tb1pmj939mkrxmnjzh73yyav7ehmp4wajc5p8srpdxy2ztqgfyurzyys4sg9zx",
      );
    });

    it("should generate an inscription output script when data length is > 520", () => {
      const inscriptionData = Buffer.from("Never Gonna Let You Down".repeat(100), "ascii");

      // Create ECPair from x-only pubkey
      const compressedPubkey = Buffer.concat([
        Buffer.from([0x02]),
        Buffer.from(xOnlyPubkeyHex, "hex"),
      ]);
      const ecpair = ECPair.fromPublicKey(compressedPubkey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // Should still produce valid P2TR output
      assert.strictEqual(revealData.outputScript.length, 34);
      assert.strictEqual(revealData.outputScript[0], 0x51);
      assert.strictEqual(revealData.outputScript[1], 0x20);

      // Convert to address for testnet
      const commitAddress = address.fromOutputScriptWithCoin(revealData.outputScript, "tbtc");

      // Verify expected address matches utxo-ord test
      assert.strictEqual(
        commitAddress,
        "tb1pajgt4plnulz5vt4jzua0m3gwqr82dlrfzen8w9cawr69m7e6xxuq7dzypl",
      );
    });

    it("should return valid tap leaf script data", () => {
      const inscriptionData = Buffer.from("Hello Ordinals", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // Validate tap leaf script structure
      assert.ok(revealData.tapLeafScript);
      assert.strictEqual(revealData.tapLeafScript.leafVersion, 0xc0); // TapScript
      assert.ok(revealData.tapLeafScript.script instanceof Uint8Array);
      assert.ok(revealData.tapLeafScript.script.length > 0);
      assert.ok(revealData.tapLeafScript.controlBlock instanceof Uint8Array);
      assert.ok(revealData.tapLeafScript.controlBlock.length > 0);
    });

    it("should return a reasonable vsize estimate", () => {
      const inscriptionData = Buffer.from("Hello Ordinals", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // vsize should be reasonable (at least 100 vbytes for a simple inscription)
      assert.ok(revealData.revealTransactionVSize > 100);
      // But not too large for small data
      assert.ok(revealData.revealTransactionVSize < 500);
    });

    it("should work with ECPair containing private key", () => {
      const inscriptionData = Buffer.from("Test", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);

      // Should not throw - ECPair with private key also has public key
      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      assert.ok(revealData.outputScript.length === 34);
    });
  });

  describe("signRevealTransaction", () => {
    // Create a mock commit transaction with a P2TR output
    function createMockCommitTx(commitOutputScript: Uint8Array): Transaction {
      const psbt = new utxolib.Psbt({ network: utxolib.networks.testnet });

      // Add a dummy input
      psbt.addInput({
        hash: Buffer.alloc(32), // dummy txid
        index: 0,
        witnessUtxo: {
          script: Buffer.from(commitOutputScript),
          value: BigInt(100_000),
        },
      });

      // Add the commit output
      psbt.addOutput({
        script: Buffer.from(commitOutputScript),
        value: BigInt(42),
      });

      // Get the unsigned transaction
      const txBytes = psbt.data.globalMap.unsignedTx.toBuffer();
      return Transaction.fromBytes(txBytes);
    }

    it("should sign a reveal transaction", () => {
      const inscriptionData = Buffer.from("And Desert You", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // Create a mock commit transaction
      const commitTx = createMockCommitTx(revealData.outputScript);

      // Create recipient output script (P2WPKH for simplicity)
      // OP_0 OP_PUSH20 <20-byte hash>
      const recipientOutputScript = Buffer.alloc(22);
      recipientOutputScript[0] = 0x00; // OP_0
      recipientOutputScript[1] = 0x14; // PUSH20
      // Rest is zeros (mock recipient)

      // Sign the reveal transaction
      const txBytes = inscriptions.signRevealTransaction(
        ecpair,
        revealData.tapLeafScript,
        commitTx,
        revealData.outputScript,
        recipientOutputScript,
        10000n, // 10,000 sats output
      );

      // Signed transaction should be non-empty
      assert.ok(txBytes instanceof Uint8Array);
      assert.ok(txBytes.length > 0);

      // Segwit transaction marker/flag: version(4) + marker(0x00) + flag(0x01)
      // Version should be 2 (little-endian)
      assert.strictEqual(txBytes[0], 0x02);
      assert.strictEqual(txBytes[1], 0x00);
      assert.strictEqual(txBytes[2], 0x00);
      assert.strictEqual(txBytes[3], 0x00);
      // Segwit marker and flag
      assert.strictEqual(txBytes[4], 0x00); // marker
      assert.strictEqual(txBytes[5], 0x01); // flag
    });

    it("should fail when commit output not found", () => {
      const inscriptionData = Buffer.from("Test", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      // Create commit tx with WRONG output script
      const wrongOutputScript = Buffer.alloc(34);
      wrongOutputScript[0] = 0x51;
      wrongOutputScript[1] = 0x20;
      // Rest is zeros (different from revealData.outputScript)

      const commitTx = createMockCommitTx(wrongOutputScript);

      const recipientOutputScript = Buffer.alloc(22);
      recipientOutputScript[0] = 0x00;
      recipientOutputScript[1] = 0x14;

      // Should throw because commit output script doesn't match
      assert.throws(() => {
        inscriptions.signRevealTransaction(
          ecpair,
          revealData.tapLeafScript,
          commitTx,
          revealData.outputScript, // Looking for this script
          recipientOutputScript,
          10000n,
        );
      }, /Commit output not found/);
    });

    it("should fail without private key", () => {
      const inscriptionData = Buffer.from("Test", "ascii");
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);
      const publicOnlyEcpair = ECPair.fromPublicKey(ecpair.publicKey);

      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        inscriptionData,
      );

      const commitTx = createMockCommitTx(revealData.outputScript);
      const recipientOutputScript = Buffer.alloc(22);
      recipientOutputScript[0] = 0x00;
      recipientOutputScript[1] = 0x14;

      // Should throw because we need private key for signing
      assert.throws(() => {
        inscriptions.signRevealTransaction(
          publicOnlyEcpair,
          revealData.tapLeafScript,
          commitTx,
          revealData.outputScript,
          recipientOutputScript,
          10000n,
        );
      }, /private key/i);
    });
  });

  describe("types", () => {
    it("TapLeafScript should have correct property names (camelCase)", () => {
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);
      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        Buffer.from("test", "ascii"),
      );

      // Check that properties are camelCase
      assert.ok("leafVersion" in revealData.tapLeafScript);
      assert.ok("script" in revealData.tapLeafScript);
      assert.ok("controlBlock" in revealData.tapLeafScript);

      // Verify types
      assert.strictEqual(typeof revealData.tapLeafScript.leafVersion, "number");
      assert.ok(revealData.tapLeafScript.script instanceof Uint8Array);
      assert.ok(revealData.tapLeafScript.controlBlock instanceof Uint8Array);
    });

    it("PreparedInscriptionRevealData should have correct property names (camelCase)", () => {
      const ecpair = ECPair.fromPrivateKey(testPrivateKey);
      const revealData = inscriptions.createInscriptionRevealData(
        ecpair,
        contentType,
        Buffer.from("test", "ascii"),
      );

      // Check that properties are camelCase
      assert.ok("outputScript" in revealData);
      assert.ok("revealTransactionVSize" in revealData);
      assert.ok("tapLeafScript" in revealData);

      // Verify types
      assert.ok(revealData.outputScript instanceof Uint8Array);
      assert.strictEqual(typeof revealData.revealTransactionVSize, "number");
      assert.strictEqual(typeof revealData.tapLeafScript, "object");
    });
  });
});
