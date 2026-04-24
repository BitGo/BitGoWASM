/**
 * Tests for BitGoPsbt.fromHalfSignedLegacyTransaction() and BitGoPsbt.fromNetworkFormat().
 *
 * fromHalfSignedLegacyTransaction is deprecated in favour of fromNetworkFormat. This file
 * tests both the deprecated path (to verify it keeps working) and the new path.
 */
import { describe, it } from "mocha";
import * as assert from "assert";
import { BitGoPsbt, type HydrationUnspent } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { supportsScriptType } from "../../js/fixedScriptWallet/index.js";
import { ChainCode } from "../../js/fixedScriptWallet/chains.js";
import { ECPair } from "../../js/ecpair.js";
import { Transaction, ZcashTransaction } from "../../js/transaction.js";
import { coinNames, type CoinName, isMainnet } from "../../js/coinName.js";
import { getDefaultWalletKeys, getKeyTriple } from "../../js/testutils/keys.js";

const ZCASH_NU5_HEIGHT = 1687105;

const p2msScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;

// Coins excluded from round-trip tests (use special handling or not supported)
const EXCLUDED_COINS: CoinName[] = ["bsv", "bcha", "zec"];

function isSupportedCoin(coin: CoinName): boolean {
  return isMainnet(coin) && !EXCLUDED_COINS.includes(coin);
}

function createHalfSignedP2msPsbt(
  coinName: CoinName,
  valueOverride?: bigint,
): { psbt: BitGoPsbt; unspents: HydrationUnspent[] } {
  const rootWalletKeys = getDefaultWalletKeys();
  const [userXprv] = getKeyTriple("default");

  const supportedTypes = p2msScriptTypes.filter((scriptType) =>
    supportsScriptType(coinName, scriptType),
  );

  const isZcash = coinName === "zec" || coinName === "tzec";
  const psbt = isZcash
    ? ZcashBitGoPsbt.createEmpty(coinName, rootWalletKeys, {
        version: 4,
        lockTime: 0,
        blockHeight: ZCASH_NU5_HEIGHT,
      })
    : BitGoPsbt.createEmpty(coinName, rootWalletKeys, { version: 2, lockTime: 0 });

  const unspents: HydrationUnspent[] = [];
  supportedTypes.forEach((scriptType, index) => {
    const chain = ChainCode.value(scriptType, "external");
    const value = valueOverride ?? BigInt(10000 + index * 10000);
    psbt.addWalletInput(
      {
        txid: `${"00".repeat(31)}${index.toString(16).padStart(2, "0")}`,
        vout: 0,
        value,
        sequence: 0xfffffffd,
      },
      rootWalletKeys,
      { scriptId: { chain, index } },
    );
    unspents.push({ chain, index, value });
  });

  psbt.addWalletOutput(rootWalletKeys, { chain: 0, index: 100, value: BigInt(5000) });
  psbt.sign(userXprv);

  return { psbt, unspents };
}

describe("BitGoPsbt.fromHalfSignedLegacyTransaction", function () {
  describe("BigInt value conversion (regression for unchecked-from/as_f64 bug)", function () {
    it("should not throw when unspent values are JS BigInt", function () {
      // With the buggy Rust code this always threw "'value' must be a bigint"
      // because BigInt::from(value_js).as_f64() calls JsValue::as_f64(), which
      // returns None for JS BigInt (it only works for JS Number).
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("btc");
      const txBytes = psbt.getHalfSignedLegacyFormat();
      const tx = Transaction.fromBytes(txBytes, "btc");

      assert.doesNotThrow(() => {
        BitGoPsbt.fromHalfSignedLegacyTransaction(tx, "btc", rootWalletKeys, unspents);
      }, "fromHalfSignedLegacyTransaction must not throw for valid JS BigInt values");
    });

    it("should handle values larger than Number.MAX_SAFE_INTEGER", function () {
      // Values beyond 2^53-1 would silently lose precision through f64; the fixed
      // code converts directly via u64::try_from so precision is preserved.
      const rootWalletKeys = getDefaultWalletKeys();
      // 21 million BTC in satoshis — the maximum possible UTXO value
      const maxSats = 21_000_000n * 100_000_000n;
      const { psbt, unspents } = createHalfSignedP2msPsbt("btc", maxSats);
      const txBytes = psbt.getHalfSignedLegacyFormat();
      const tx = Transaction.fromBytes(txBytes, "btc");

      assert.doesNotThrow(() => {
        BitGoPsbt.fromHalfSignedLegacyTransaction(tx, "btc", rootWalletKeys, unspents);
      }, "fromHalfSignedLegacyTransaction must handle large satoshi values");
    });
  });

  describe("Round-trip: getHalfSignedLegacyFormat → fromHalfSignedLegacyTransaction", function () {
    // Supported coins for round-trip: all mainnet UTXO coins except special formats
    const roundTripCoins = coinNames.filter(isSupportedCoin);

    for (const coinName of roundTripCoins) {
      it(`${coinName}: reconstructed PSBT serializes without error`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { psbt, unspents } = createHalfSignedP2msPsbt(coinName);
        const txBytes = psbt.getHalfSignedLegacyFormat();
        const tx = Transaction.fromBytes(txBytes, coinName);

        const reconstructed = BitGoPsbt.fromHalfSignedLegacyTransaction(
          tx,
          coinName,
          rootWalletKeys,
          unspents,
        );

        const serialized = reconstructed.serialize();
        assert.ok(serialized.length > 0, "Reconstructed PSBT should serialize to non-empty bytes");
      });
    }
  });

  describe("Round-trip with replay protection input", function () {
    it("reconstructs PSBT from legacy tx with wallet + replay protection input", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const [userXprv] = getKeyTriple("default");
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
      // sign() only signs wallet inputs; replay protection input gets 0 sigs
      psbt.sign(userXprv);

      const txBytes = psbt.getHalfSignedLegacyFormat();
      const tx = Transaction.fromBytes(txBytes, "btc");

      const unspents: HydrationUnspent[] = [
        { chain: 0, index: 0, value: BigInt(10000) }, // wallet
        { pubkey: ecpair.publicKey, value: BigInt(1000) }, // replay protection
      ];
      const reconstructed = BitGoPsbt.fromHalfSignedLegacyTransaction(
        tx,
        "btc",
        rootWalletKeys,
        unspents,
      );

      assert.ok(reconstructed.serialize().length > 0, "Reconstructed PSBT serializes");
      assert.strictEqual(reconstructed.inputCount(), 2, "Both inputs present");
      assert.ok(
        reconstructed.verifySignature(0, rootWalletKeys.userKey().neutered().toBase58()),
        "Wallet input signature preserved",
      );
    });
  });

  describe("Full-signed transaction", function () {
    function createFullSignedTxBytes(coinName: CoinName): {
      txBytes: Uint8Array;
      unspents: HydrationUnspent[];
    } {
      const [, , bitgoXprv] = getKeyTriple("default");
      const { psbt, unspents } = createHalfSignedP2msPsbt(coinName);
      psbt.sign(bitgoXprv);
      psbt.finalizeAllInputs();
      return { txBytes: psbt.extractTransaction().toBytes(), unspents };
    }

    const fullSignedCoins = coinNames.filter(isSupportedCoin);

    for (const coinName of fullSignedCoins) {
      it(`${coinName}: throws because fully-signed transaction has 2 signatures`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { txBytes, unspents } = createFullSignedTxBytes(coinName);
        assert.throws(
          () =>
            BitGoPsbt.fromHalfSignedLegacyTransaction(txBytes, coinName, rootWalletKeys, unspents),
          /expected 1 signature for half-signed transaction, found 2/i,
        );
      });
    }
  });

  describe("Zcash legacy format round-trip", function () {
    it("should reject Zcash via type check in fromHalfSignedLegacyTransaction", function () {
      // fromHalfSignedLegacyTransaction validates the transaction type at call time
      // and rejects Zcash with a clear error message.
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt: zcashPsbt, unspents } = createHalfSignedP2msPsbt("zec");

      // Step 1: Extract Zcash PSBT as legacy format
      const txBytes = zcashPsbt.getHalfSignedLegacyFormat();
      assert.ok(txBytes.length > 0, "ZcashBitGoPsbt.getHalfSignedLegacyFormat() produces bytes");

      // Step 2: Parse the transaction (will be ZcashTransaction)
      const tx = Transaction.fromBytes(txBytes, "zec");
      assert.ok(tx instanceof ZcashTransaction, "Parsed transaction is ZcashTransaction");

      // Step 3: Call fromHalfSignedLegacyTransaction with Zcash transaction
      // Expected: Throws clear error after detecting Zcash transaction
      assert.throws(() => {
        BitGoPsbt.fromHalfSignedLegacyTransaction(tx, "zec", rootWalletKeys, unspents);
      }, /Use ZcashBitGoPsbt.fromHalfSignedLegacyTransaction\(\) for Zcash transactions/);
    });

    it("should round-trip Zcash PSBT via ZcashBitGoPsbt.fromHalfSignedLegacyTransaction (with blockHeight)", function () {
      // This test verifies the round-trip: create Zcash PSBT → extract legacy format → reconstruct PSBT
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");

      // Step 1: Extract half-signed legacy format (this is what would be transmitted)
      const legacyBytes = psbt.getHalfSignedLegacyFormat();
      assert.ok(legacyBytes.length > 0, "getHalfSignedLegacyFormat() produces bytes");

      // Step 2: Reconstruct PSBT from legacy format with block height
      const reconstructed = ZcashBitGoPsbt.fromHalfSignedLegacyTransaction(
        legacyBytes,
        "zec",
        rootWalletKeys,
        unspents,
        { blockHeight: ZCASH_NU5_HEIGHT },
      );

      // Step 3: Verify reconstruction succeeded
      assert.ok(reconstructed, "fromHalfSignedLegacyTransaction() reconstructs PSBT");
      assert.ok(reconstructed instanceof ZcashBitGoPsbt, "Reconstructed PSBT is ZcashBitGoPsbt");

      // Step 4: Verify Zcash metadata is preserved
      assert.strictEqual(reconstructed.version(), 4, "Zcash version preserved as 4 (Overwintered)");

      // Step 5: Verify serialization works (round-trip complete)
      const serialized = reconstructed.serialize();
      assert.ok(serialized.length > 0, "Reconstructed Zcash PSBT serializes without error");
    });

    it("should round-trip Zcash PSBT via ZcashBitGoPsbt.fromHalfSignedLegacyTransaction (with consensusBranchId)", function () {
      // This test verifies the round-trip with explicit consensus branch ID instead of block height
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");

      // Step 1: Extract half-signed legacy format
      const legacyBytes = psbt.getHalfSignedLegacyFormat();

      // Step 2: Reconstruct PSBT from legacy format with explicit consensus branch ID
      // 0xC2D6D0B4 is the NU5 consensus branch ID
      const reconstructed = ZcashBitGoPsbt.fromHalfSignedLegacyTransaction(
        legacyBytes,
        "zec",
        rootWalletKeys,
        unspents,
        { consensusBranchId: 0xc2d6d0b4 },
      );

      // Step 3: Verify reconstruction succeeded with explicit branch ID
      assert.ok(
        reconstructed,
        "fromHalfSignedLegacyTransactionZcash() works with consensusBranchId",
      );
      assert.ok(reconstructed instanceof ZcashBitGoPsbt, "Reconstructed PSBT is ZcashBitGoPsbt");

      // Step 4: Verify serialization works
      const serialized = reconstructed.serialize();
      assert.ok(serialized.length > 0, "Reconstructed Zcash PSBT serializes without error");
    });

    it("should accept pre-decoded transaction instance", function () {
      // fromHalfSignedLegacyTransaction accepts a pre-decoded Transaction instance.
      // This is more efficient than parsing bytes twice.
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("btc");
      const txBytes = psbt.getHalfSignedLegacyFormat();

      // Parse transaction once and pass the instance
      const tx = Transaction.fromBytes(txBytes, "btc");
      const psbt1 = BitGoPsbt.fromHalfSignedLegacyTransaction(tx, "btc", rootWalletKeys, unspents);

      // Parse again to compare
      const tx2 = Transaction.fromBytes(txBytes, "btc");
      const psbt2 = BitGoPsbt.fromHalfSignedLegacyTransaction(tx2, "btc", rootWalletKeys, unspents);

      // Both should produce equivalent results
      assert.strictEqual(psbt1.inputCount(), psbt2.inputCount(), "Same input count");
      assert.strictEqual(psbt1.outputCount(), psbt2.outputCount(), "Same output count");
      assert.deepStrictEqual(psbt1.serialize(), psbt2.serialize(), "Identical serialization");
    });
  });
});

describe("BitGoPsbt.fromNetworkFormat", function () {
  const [userXprv, , bitgoXprv] = getKeyTriple("default");

  describe("Half-signed input", function () {
    const roundTripCoins = coinNames.filter(isSupportedCoin);

    for (const coinName of roundTripCoins) {
      it(`${coinName}: succeeds and PSBT has user signature`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { psbt, unspents } = createHalfSignedP2msPsbt(coinName);
        const txBytes = psbt.getHalfSignedLegacyFormat();

        const reconstructed = BitGoPsbt.fromNetworkFormat(
          txBytes,
          coinName,
          rootWalletKeys,
          unspents,
        );

        assert.ok(reconstructed.serialize().length > 0, "PSBT serializes");
        assert.ok(
          reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
          "User signature present in input 0",
        );
      });
    }
  });

  describe("Full-signed input", function () {
    const fullSignedCoins = coinNames.filter(isSupportedCoin);

    for (const coinName of fullSignedCoins) {
      it(`${coinName}: succeeds and PSBT has both user and bitgo signatures`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { psbt, unspents } = createHalfSignedP2msPsbt(coinName);
        psbt.sign(bitgoXprv);
        psbt.finalizeAllInputs();
        const txBytes = psbt.extractTransaction().toBytes();

        const reconstructed = BitGoPsbt.fromNetworkFormat(
          txBytes,
          coinName,
          rootWalletKeys,
          unspents,
        );

        assert.ok(reconstructed.serialize().length > 0, "PSBT serializes");
        assert.ok(
          reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
          "User signature present in input 0",
        );
        assert.ok(
          reconstructed.verifySignature(0, bitgoXprv.neutered().toBase58()),
          "Bitgo signature present in input 0",
        );
      });
    }
  });

  describe("ZcashBitGoPsbt.fromNetworkFormat", function () {
    it("zec half-signed: PSBT has user signature (blockHeight)", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");
      const txBytes = psbt.getHalfSignedLegacyFormat();

      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(
        txBytes,
        "zec",
        rootWalletKeys,
        unspents,
        { blockHeight: ZCASH_NU5_HEIGHT },
      );

      assert.ok(reconstructed instanceof ZcashBitGoPsbt, "Returns ZcashBitGoPsbt");
      assert.ok(reconstructed.serialize().length > 0, "PSBT serializes");
      assert.ok(
        reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
        "User signature present in input 0",
      );
    });

    it("zec half-signed: PSBT has user signature (consensusBranchId)", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");
      const txBytes = psbt.getHalfSignedLegacyFormat();

      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(
        txBytes,
        "zec",
        rootWalletKeys,
        unspents,
        { consensusBranchId: 0xc2d6d0b4 },
      );

      assert.ok(reconstructed instanceof ZcashBitGoPsbt, "Returns ZcashBitGoPsbt");
      assert.ok(reconstructed.serialize().length > 0, "PSBT serializes");
      assert.ok(
        reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
        "User signature present in input 0",
      );
    });

    it("zec full-signed: succeeds and PSBT has both user and bitgo signatures", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");
      psbt.sign(bitgoXprv);
      psbt.finalizeAllInputs();
      const txBytes = psbt.extractTransaction().toBytes();

      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(
        txBytes,
        "zec",
        rootWalletKeys,
        unspents,
        { blockHeight: ZCASH_NU5_HEIGHT },
      );

      assert.ok(reconstructed.serialize().length > 0, "PSBT serializes");
      assert.ok(
        reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
        "User signature present in input 0",
      );
      assert.ok(
        reconstructed.verifySignature(0, bitgoXprv.neutered().toBase58()),
        "Bitgo signature present in input 0",
      );
    });

    it("zec: accepts pre-decoded ZcashTransaction instance", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { psbt, unspents } = createHalfSignedP2msPsbt("zec");
      const txBytes = psbt.getHalfSignedLegacyFormat();
      const tx = ZcashTransaction.fromBytes(txBytes);

      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(tx, "zec", rootWalletKeys, unspents, {
        blockHeight: ZCASH_NU5_HEIGHT,
      });

      assert.ok(reconstructed instanceof ZcashBitGoPsbt, "Returns ZcashBitGoPsbt");
      assert.ok(reconstructed.serialize().length > 0, "Serializes without error");
    });
  });
});
