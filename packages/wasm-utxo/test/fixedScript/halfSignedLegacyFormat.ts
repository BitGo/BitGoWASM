/**
 * Tests for getHalfSignedLegacyFormat() method against reference utxo-lib implementation
 */
import { describe, it } from "mocha";
import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BitGoPsbt } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { ChainCode } from "../../js/fixedScriptWallet/chains.js";
import { getDefaultWalletKeys, getKeyTriple } from "../../js/testutils/keys.js";
import { getCoinNameForNetwork } from "../networks.js";

// Zcash Nu5 activation height (mainnet) - use a height after Nu5 activation
const ZCASH_NU5_HEIGHT = 1687105;

// P2ms script types that are supported by extractP2msOnlyHalfSignedTx
const p2msScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;

// Networks that support p2ms script types (mainnet only, excluding bsv and ecash)
const p2msNetworks = utxolib
  .getNetworkList()
  .filter(
    (n) => utxolib.isMainnet(n) && n !== utxolib.networks.bitcoinsv && n !== utxolib.networks.ecash,
  );

/**
 * Create a PSBT with only p2ms inputs (p2sh, p2shP2wsh, p2wsh) and sign it with user key
 */
function createHalfSignedP2msPsbt(network: utxolib.Network): BitGoPsbt {
  const coinName = getCoinNameForNetwork(network);
  const rootWalletKeys = getDefaultWalletKeys();
  const xprvTriple = getKeyTriple("default");

  // Determine which p2ms types are supported by this network
  const supportedTypes = p2msScriptTypes.filter((scriptType) =>
    utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType),
  );

  // Create unsigned PSBT - Zcash requires special handling with blockHeight
  const isZcash = utxolib.getMainnet(network) === utxolib.networks.zcash;
  const psbt = isZcash
    ? ZcashBitGoPsbt.createEmpty(coinName as "zec" | "tzec", rootWalletKeys, {
        version: 4, // Zcash uses version 4
        lockTime: 0,
        blockHeight: ZCASH_NU5_HEIGHT,
      })
    : BitGoPsbt.createEmpty(coinName, rootWalletKeys, {
        version: 2,
        lockTime: 0,
      });

  // Add inputs for each supported p2ms type
  supportedTypes.forEach((scriptType, index) => {
    const scriptId = { chain: ChainCode.value(scriptType, "external"), index };
    psbt.addWalletInput(
      {
        txid: `${"00".repeat(31)}${index.toString(16).padStart(2, "0")}`,
        vout: 0,
        value: BigInt(10000 + index * 10000),
        sequence: 0xfffffffd,
      },
      rootWalletKeys,
      { scriptId },
    );
  });

  // Add a p2sh output
  psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

  // Sign with user key only (halfsigned)
  psbt.sign(xprvTriple[0]);

  return psbt;
}

/**
 * Convert wasm-utxo PSBT to utxo-lib PSBT for comparison
 */
function toUtxolibPsbt(wasmPsbt: BitGoPsbt, network: utxolib.Network): utxolib.bitgo.UtxoPsbt {
  const bytes = wasmPsbt.serialize();
  return utxolib.bitgo.createPsbtFromBuffer(Buffer.from(bytes), network);
}

describe("getHalfSignedLegacyFormat", function () {
  describe("Basic functionality", function () {
    it("should extract half-signed transaction for p2ms inputs", function () {
      const psbt = createHalfSignedP2msPsbt(utxolib.networks.bitcoin);
      assert.ok(psbt, "Should create PSBT");

      const halfSignedTx = psbt.getHalfSignedLegacyFormat();
      assert.ok(halfSignedTx, "Should extract half-signed transaction");
      assert.ok(halfSignedTx.length > 0, "Transaction should have data");

      // Verify it's a valid transaction by deserializing
      const tx = utxolib.bitgo.createTransactionFromBuffer(
        Buffer.from(halfSignedTx),
        utxolib.networks.bitcoin,
        { amountType: "bigint" },
      );
      assert.ok(tx, "Should deserialize as valid transaction");
      // Should have at least 1 input
      assert.ok(tx.ins.length >= 1, "Should have at least 1 input");
    });

    it("should fail for unsigned inputs", function () {
      const rootWalletKeys = getDefaultWalletKeys();

      // Create unsigned PSBT (no signatures)
      const psbt = BitGoPsbt.createEmpty("btc", rootWalletKeys, {
        version: 2,
        lockTime: 0,
      });

      // Add a p2sh input
      psbt.addWalletInput(
        {
          txid: "00".repeat(32),
          vout: 0,
          value: BigInt(10000),
          sequence: 0xfffffffd,
        },
        rootWalletKeys,
        { scriptId: { chain: 0, index: 0 } },
      );

      psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

      // Should fail because no signatures
      assert.throws(
        () => psbt.getHalfSignedLegacyFormat(),
        /expected exactly 1 partial signature/i,
        "Should throw for unsigned inputs",
      );
    });
  });

  describe("Comparison with utxo-lib extractP2msOnlyHalfSignedTx", function () {
    for (const network of p2msNetworks) {
      const networkName = utxolib.getNetworkName(network);
      it(`${networkName}: should produce identical output to utxo-lib extractP2msOnlyHalfSignedTx`, function () {
        const psbt = createHalfSignedP2msPsbt(network);

        // Get half-signed tx from wasm-utxo
        const wasmHalfSignedTx = psbt.getHalfSignedLegacyFormat();

        // Convert to utxo-lib PSBT and extract using reference implementation
        const utxolibPsbt = toUtxolibPsbt(psbt, network);
        const utxolibHalfSignedTx = utxolib.bitgo.extractP2msOnlyHalfSignedTx(utxolibPsbt);
        const utxolibHalfSignedTxBytes = utxolibHalfSignedTx.toBuffer();

        // Compare the results
        assert.strictEqual(
          Buffer.from(wasmHalfSignedTx).toString("hex"),
          utxolibHalfSignedTxBytes.toString("hex"),
          `Half-signed transaction should match utxo-lib output for ${networkName}`,
        );
      });
    }
  });

  describe("Script type specific tests", function () {
    it("should correctly place signature at position 0 (user key)", function () {
      const psbt = createHalfSignedP2msPsbt(utxolib.networks.bitcoin);

      const halfSignedTx = psbt.getHalfSignedLegacyFormat();
      const tx = utxolib.bitgo.createTransactionFromBuffer(
        Buffer.from(halfSignedTx),
        utxolib.networks.bitcoin,
        { amountType: "bigint" },
      );

      // Verify each input has the signature in the correct position
      for (let i = 0; i < tx.ins.length; i++) {
        const input = tx.ins[i];

        // For witness inputs, check witness array
        if (input.witness && input.witness.length > 0) {
          // Format: [empty, sig_or_empty, sig_or_empty, sig_or_empty, witnessScript]
          assert.strictEqual(
            input.witness[0].length,
            0,
            `Input ${i}: First item should be empty (OP_0)`,
          );
          // User key is at position 0, so signature should be at witness[1]
          assert.ok(
            input.witness[1].length > 0,
            `Input ${i}: User signature should be at position 1`,
          );
          assert.strictEqual(input.witness[2].length, 0, `Input ${i}: Position 2 should be empty`);
          assert.strictEqual(input.witness[3].length, 0, `Input ${i}: Position 3 should be empty`);
        } else {
          // For non-witness (p2sh), check scriptSig
          // Format: OP_0 <sig_or_OP_0> <sig_or_OP_0> <sig_or_OP_0> <redeemScript>
          assert.ok(input.script.length > 0, `Input ${i}: Should have scriptSig`);
        }
      }
    });
  });

  describe("Error handling", function () {
    it("should throw descriptive error for empty PSBT", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const psbt = BitGoPsbt.createEmpty("btc", rootWalletKeys, {
        version: 2,
        lockTime: 0,
      });

      assert.throws(
        () => psbt.getHalfSignedLegacyFormat(),
        /empty inputs or outputs/i,
        "Should throw for empty PSBT",
      );
    });

    it("should throw for inputs with 2 signatures", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const xprvTriple = getKeyTriple("default");

      // Create PSBT and sign with both user and bitgo keys
      const psbt = BitGoPsbt.createEmpty("btc", rootWalletKeys, {
        version: 2,
        lockTime: 0,
      });

      psbt.addWalletInput(
        {
          txid: "00".repeat(32),
          vout: 0,
          value: BigInt(10000),
          sequence: 0xfffffffd,
        },
        rootWalletKeys,
        { scriptId: { chain: 0, index: 0 } },
      );

      psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

      // Sign with user key
      psbt.sign(xprvTriple[0]);
      // Sign with bitgo key
      psbt.sign(xprvTriple[2]);

      // Should fail because inputs have 2 signatures
      assert.throws(
        () => psbt.getHalfSignedLegacyFormat(),
        /expected exactly 1 partial signature/i,
        "Should throw for fully signed inputs",
      );
    });
  });
});
