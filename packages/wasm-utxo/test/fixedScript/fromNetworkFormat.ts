import { describe, it } from "mocha";
import * as assert from "assert";
import { BitGoPsbt, type HydrationUnspent } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { supportsScriptType } from "../../js/fixedScriptWallet/index.js";
import { ChainCode } from "../../js/fixedScriptWallet/chains.js";
import { ECPair } from "../../js/ecpair.js";
import { ZcashTransaction } from "../../js/transaction.js";
import { coinNames, type CoinName, isMainnet } from "../../js/coinName.js";
import { getDefaultWalletKeys, getKeyTriple } from "../../js/testutils/keys.js";

const ZCASH_NU5_HEIGHT = 1687105;

const p2msScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;

const EXCLUDED_COINS: CoinName[] = ["bsv", "bcha"];

function isSupportedCoin(coin: CoinName): boolean {
  return isMainnet(coin) && !EXCLUDED_COINS.includes(coin);
}

function fromNetworkFormat(
  txBytes: Uint8Array,
  coinName: CoinName,
  rootWalletKeys: ReturnType<typeof getDefaultWalletKeys>,
  unspents: HydrationUnspent[],
): BitGoPsbt {
  if (coinName === "zec" || coinName === "tzec") {
    return ZcashBitGoPsbt.fromNetworkFormat(txBytes, coinName, rootWalletKeys, unspents, {
      blockHeight: ZCASH_NU5_HEIGHT,
    });
  }
  return BitGoPsbt.fromNetworkFormat(txBytes, coinName, rootWalletKeys, unspents);
}

function createSignedP2msPsbt(
  coinName: CoinName,
  sigCount: 1 | 2,
  valueOverride?: bigint,
): { txBytes: Uint8Array; unspents: HydrationUnspent[] } {
  const rootWalletKeys = getDefaultWalletKeys();
  const [userXprv, , bitgoXprv] = getKeyTriple("default");

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

  if (sigCount === 2) {
    psbt.sign(bitgoXprv);
    psbt.finalizeAllInputs();
    return { txBytes: psbt.extractTransaction().toBytes(), unspents };
  }

  return { txBytes: psbt.getHalfSignedLegacyFormat(), unspents };
}

describe("BitGoPsbt.fromNetworkFormat", function () {
  const [userXprv, , bitgoXprv] = getKeyTriple("default");

  describe("BigInt value conversion (regression for unchecked-from/as_f64 bug)", function () {
    it("does not throw for JS BigInt unspent values", function () {
      // BigInt::from(value_js).as_f64() returned None for JS BigInt (only works for JS Number),
      // causing "'value' must be a bigint". Fixed by using u64::try_from directly.
      const rootWalletKeys = getDefaultWalletKeys();
      const { txBytes, unspents } = createSignedP2msPsbt("btc", 1);
      assert.doesNotThrow(() =>
        BitGoPsbt.fromNetworkFormat(txBytes, "btc", rootWalletKeys, unspents),
      );
    });

    it("preserves values larger than Number.MAX_SAFE_INTEGER", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const maxSats = 21_000_000n * 100_000_000n;
      const { txBytes, unspents } = createSignedP2msPsbt("btc", 1, maxSats);
      assert.doesNotThrow(() =>
        BitGoPsbt.fromNetworkFormat(txBytes, "btc", rootWalletKeys, unspents),
      );
    });
  });

  describe("half-signed input", function () {
    for (const coinName of coinNames.filter(isSupportedCoin)) {
      it(`${coinName}: user signature preserved`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { txBytes, unspents } = createSignedP2msPsbt(coinName, 1);
        const reconstructed = fromNetworkFormat(txBytes, coinName, rootWalletKeys, unspents);
        assert.ok(reconstructed.serialize().length > 0);
        assert.ok(reconstructed.verifySignature(0, userXprv.neutered().toBase58()));
      });
    }
  });

  describe("full-signed input", function () {
    for (const coinName of coinNames.filter(isSupportedCoin)) {
      it(`${coinName}: both user and bitgo signatures preserved`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const { txBytes, unspents } = createSignedP2msPsbt(coinName, 2);
        const reconstructed = fromNetworkFormat(txBytes, coinName, rootWalletKeys, unspents);
        assert.ok(reconstructed.serialize().length > 0);
        assert.ok(reconstructed.verifySignature(0, userXprv.neutered().toBase58()));
        assert.ok(reconstructed.verifySignature(0, bitgoXprv.neutered().toBase58()));
      });
    }
  });

  describe("with replay protection input", function () {
    type RpCase = { coin: CoinName; desc: string };
    const rpCoins: RpCase[] = [
      { coin: "btc", desc: "BTC" },
      { coin: "bch", desc: "BCH (SIGHASH_FORKID)" },
    ];

    for (const { coin, desc } of rpCoins) {
      it(`${desc}: half-signed — wallet and p2shP2pk sigs preserved`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const ecpair = ECPair.fromPrivateKey(Buffer.from(userXprv.privateKey));

        const psbt = BitGoPsbt.createEmpty(coin, rootWalletKeys, { version: 2, lockTime: 0 });
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
        psbt.sign(userXprv);
        psbt.signInput(1, ecpair);

        const txBytes = psbt.getHalfSignedLegacyFormat();
        const unspents: HydrationUnspent[] = [
          { chain: 0, index: 0, value: BigInt(10000) },
          { pubkey: ecpair.publicKey, value: BigInt(1000) },
        ];
        const reconstructed = BitGoPsbt.fromNetworkFormat(txBytes, coin, rootWalletKeys, unspents);

        assert.strictEqual(reconstructed.inputCount(), 2);
        assert.ok(reconstructed.verifySignature(0, userXprv.neutered().toBase58()), "wallet sig");
        assert.ok(reconstructed.verifySignature(1, ecpair), "p2shP2pk sig");
      });

      it(`${desc}: full-signed — both wallet sigs and p2shP2pk sig preserved`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const ecpair = ECPair.fromPrivateKey(Buffer.from(userXprv.privateKey));

        const psbt = BitGoPsbt.createEmpty(coin, rootWalletKeys, { version: 2, lockTime: 0 });
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
        psbt.sign(userXprv);
        psbt.sign(bitgoXprv);
        psbt.signInput(1, ecpair);
        psbt.finalizeAllInputs();
        const txBytes = psbt.extractTransaction().toBytes();

        const unspents: HydrationUnspent[] = [
          { chain: 0, index: 0, value: BigInt(10000) },
          { pubkey: ecpair.publicKey, value: BigInt(1000) },
        ];
        const reconstructed = BitGoPsbt.fromNetworkFormat(txBytes, coin, rootWalletKeys, unspents);

        assert.strictEqual(reconstructed.inputCount(), 2);
        assert.ok(
          reconstructed.verifySignature(0, userXprv.neutered().toBase58()),
          "user wallet sig",
        );
        assert.ok(
          reconstructed.verifySignature(0, bitgoXprv.neutered().toBase58()),
          "bitgo wallet sig",
        );
        assert.ok(reconstructed.verifySignature(1, ecpair), "p2shP2pk sig");
      });
    }
  });

  describe("ZcashBitGoPsbt Zcash-specific options", function () {
    it("accepts consensusBranchId instead of blockHeight", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { txBytes, unspents } = createSignedP2msPsbt("zec", 1);
      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(
        txBytes,
        "zec",
        rootWalletKeys,
        unspents,
        {
          consensusBranchId: 0xc2d6d0b4,
        },
      );
      assert.ok(reconstructed instanceof ZcashBitGoPsbt);
      assert.ok(reconstructed.verifySignature(0, userXprv.neutered().toBase58()));
    });

    it("accepts pre-decoded ZcashTransaction instance", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const { txBytes, unspents } = createSignedP2msPsbt("zec", 1);
      const tx = ZcashTransaction.fromBytes(txBytes);
      const reconstructed = ZcashBitGoPsbt.fromNetworkFormat(tx, "zec", rootWalletKeys, unspents, {
        blockHeight: ZCASH_NU5_HEIGHT,
      });
      assert.ok(reconstructed instanceof ZcashBitGoPsbt);
      assert.ok(reconstructed.serialize().length > 0);
    });
  });
});
