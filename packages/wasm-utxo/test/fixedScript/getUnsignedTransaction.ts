/**
 * Tests for getUnsignedTransaction() method against reference utxo-lib implementation
 */
import { describe, it } from "mocha";
import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BitGoPsbt } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { ChainCode } from "../../js/fixedScriptWallet/chains.js";
import { ECPair } from "../../js/ecpair.js";
import { getDefaultWalletKeys, getKeyTriple } from "../../js/testutils/keys.js";
import { getCoinNameForNetwork } from "../networks.js";

// Zcash Nu5 activation height (mainnet)
const ZCASH_NU5_HEIGHT = 1687105;

const p2msNetworks = utxolib
  .getNetworkList()
  .filter(
    (n) => utxolib.isMainnet(n) && n !== utxolib.networks.bitcoinsv && n !== utxolib.networks.ecash,
  );

/**
 * Create an unsigned PSBT with p2sh inputs across all supported p2ms script types.
 */
function createUnsignedP2msPsbt(network: utxolib.Network): BitGoPsbt {
  const coinName = getCoinNameForNetwork(network);
  const rootWalletKeys = getDefaultWalletKeys();

  const supportedTypes = (["p2sh", "p2shP2wsh", "p2wsh"] as const).filter((scriptType) =>
    utxolib.bitgo.outputScripts.isSupportedScriptType(network, scriptType),
  );

  const isZcash = utxolib.getMainnet(network) === utxolib.networks.zcash;
  const psbt = isZcash
    ? ZcashBitGoPsbt.createEmpty(coinName as "zec" | "tzec", rootWalletKeys, {
        version: 4,
        lockTime: 0,
        blockHeight: ZCASH_NU5_HEIGHT,
      })
    : BitGoPsbt.createEmpty(coinName, rootWalletKeys, { version: 2, lockTime: 0 });

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

  psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

  return psbt;
}

/**
 * Convert wasm-utxo PSBT bytes to a utxo-lib UtxoPsbt for reference comparisons.
 */
function toUtxolibPsbt(wasmPsbt: BitGoPsbt, network: utxolib.Network): utxolib.bitgo.UtxoPsbt {
  return utxolib.bitgo.createPsbtFromBuffer(Buffer.from(wasmPsbt.serialize()), network);
}

describe("getUnsignedTransaction", function () {
  describe("Basic functionality", function () {
    it("returns non-empty bytes for an unsigned PSBT", function () {
      const psbt = createUnsignedP2msPsbt(utxolib.networks.bitcoin);
      const txBytes = psbt.getUnsignedTransaction();
      assert.ok(txBytes.length > 0, "Should return non-empty bytes");
    });

    it("deserializes as a valid transaction with the expected inputs", function () {
      const psbt = createUnsignedP2msPsbt(utxolib.networks.bitcoin);
      const txBytes = psbt.getUnsignedTransaction();

      const tx = utxolib.bitgo.createTransactionFromBuffer(
        Buffer.from(txBytes),
        utxolib.networks.bitcoin,
        { amountType: "bigint" },
      );
      assert.ok(tx, "Should deserialize as valid transaction");
      assert.ok(tx.ins.length >= 1, "Should have at least 1 input");
      assert.ok(tx.outs.length >= 1, "Should have at least 1 output");
    });

    it("returns identical bytes when called on a half-signed PSBT", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const [userXprv] = getKeyTriple("default");

      const psbt = BitGoPsbt.createEmpty("btc", rootWalletKeys, { version: 2, lockTime: 0 });
      psbt.addWalletInput(
        { txid: "00".repeat(32), vout: 0, value: BigInt(10000), sequence: 0xfffffffd },
        rootWalletKeys,
        { scriptId: { chain: 0, index: 0 } },
      );
      psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

      const unsignedBytes = psbt.getUnsignedTransaction();

      psbt.sign(userXprv);
      const halfSignedBytes = psbt.getUnsignedTransaction();

      // The embedded unsigned_tx in the PSBT global map is not affected by partial sigs
      assert.strictEqual(
        Buffer.from(unsignedBytes).toString("hex"),
        Buffer.from(halfSignedBytes).toString("hex"),
        "Unsigned tx bytes should not change after signing",
      );
    });
  });

  describe("Comparison with utxo-lib getUnsignedTx", function () {
    for (const network of p2msNetworks) {
      const networkName = utxolib.getNetworkName(network);
      it(`${networkName}: matches utxo-lib UtxoPsbt.getUnsignedTx().toBuffer()`, function () {
        const psbt = createUnsignedP2msPsbt(network);

        const wasmBytes = psbt.getUnsignedTransaction();

        const utxolibPsbt = toUtxolibPsbt(psbt, network);
        const utxolibBytes = utxolibPsbt.getUnsignedTx().toBuffer();

        assert.strictEqual(
          Buffer.from(wasmBytes).toString("hex"),
          utxolibBytes.toString("hex"),
          `Unsigned tx bytes should match utxo-lib output for ${networkName}`,
        );
      });
    }
  });

  describe("Replay protection inputs", function () {
    it("includes replay protection input in the unsigned transaction", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const ecpair = ECPair.fromPublicKey(rootWalletKeys.userKey().publicKey);

      const psbt = BitGoPsbt.createEmpty("btc", rootWalletKeys, { version: 2, lockTime: 0 });
      psbt.addWalletInput(
        { txid: "00".repeat(32), vout: 0, value: BigInt(10000), sequence: 0xfffffffd },
        rootWalletKeys,
        { scriptId: { chain: 0, index: 0 } },
      );
      psbt.addReplayProtectionInput(
        { txid: "aa".repeat(32), vout: 0, value: BigInt(1000), sequence: 0xfffffffd },
        ecpair,
      );
      psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });

      const txBytes = psbt.getUnsignedTransaction();
      assert.ok(txBytes.length > 0, "Should produce non-empty bytes");

      const tx = utxolib.bitgo.createTransactionFromBuffer(
        Buffer.from(txBytes),
        utxolib.networks.bitcoin,
        { amountType: "bigint" },
      );
      assert.strictEqual(tx.ins.length, 2, "Both wallet and replay protection inputs included");
    });
  });
});
