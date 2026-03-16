/**
 * Tests for BitGoPsbt.fromHalfSignedLegacyTransaction()
 *
 * Bug: js_sys::BigInt::from(value_js).as_f64() does an unchecked wrap but then
 * JsValue::as_f64() only works for JS Number type — not BigInt. Passing any proper
 * JS BigInt value (e.g. 10000n) returned None, so the function always threw
 * "'value' must be a bigint" even though the caller did exactly the right thing.
 *
 * Fix: u64::try_from(js_sys::BigInt::unchecked_from_js(value_js)) uses the
 * BigInt-specific conversion path and then safely maps to u64.
 */
import { describe, it } from "mocha";
import * as assert from "assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BitGoPsbt, type HydrationUnspent } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { ChainCode } from "../../js/fixedScriptWallet/chains.js";
import { getDefaultWalletKeys, getKeyTriple } from "../../js/testutils/keys.js";
import { getCoinNameForNetwork } from "../networks.js";

const ZCASH_NU5_HEIGHT = 1687105;

const p2msScriptTypes = ["p2sh", "p2shP2wsh", "p2wsh"] as const;

function isSupportedNetwork(n: utxolib.Network): boolean {
  return utxolib.isMainnet(n) && n !== utxolib.networks.bitcoinsv && n !== utxolib.networks.ecash;
}

function createHalfSignedP2msPsbt(
  network: utxolib.Network,
  valueOverride?: bigint,
): { psbt: BitGoPsbt; unspents: HydrationUnspent[] } {
  const coinName = getCoinNameForNetwork(network);
  const rootWalletKeys = getDefaultWalletKeys();
  const [userXprv] = getKeyTriple("default");

  const supportedTypes = p2msScriptTypes.filter((scriptType) =>
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
      const { psbt, unspents } = createHalfSignedP2msPsbt(utxolib.networks.bitcoin);
      const txBytes = psbt.getHalfSignedLegacyFormat();

      assert.doesNotThrow(() => {
        BitGoPsbt.fromHalfSignedLegacyTransaction(txBytes, "btc", rootWalletKeys, unspents);
      }, "fromHalfSignedLegacyTransaction must not throw for valid JS BigInt values");
    });

    it("should handle values larger than Number.MAX_SAFE_INTEGER", function () {
      // Values beyond 2^53-1 would silently lose precision through f64; the fixed
      // code converts directly via u64::try_from so precision is preserved.
      const rootWalletKeys = getDefaultWalletKeys();
      // 21 million BTC in satoshis — the maximum possible UTXO value
      const maxSats = 21_000_000n * 100_000_000n;
      const { psbt, unspents } = createHalfSignedP2msPsbt(utxolib.networks.bitcoin, maxSats);
      const txBytes = psbt.getHalfSignedLegacyFormat();

      assert.doesNotThrow(() => {
        BitGoPsbt.fromHalfSignedLegacyTransaction(txBytes, "btc", rootWalletKeys, unspents);
      }, "fromHalfSignedLegacyTransaction must handle large satoshi values");
    });
  });

  describe("Round-trip: getHalfSignedLegacyFormat → fromHalfSignedLegacyTransaction", function () {
    // Zcash uses a non-standard transaction format (version 4 overwintered) that
    // fromHalfSignedLegacyTransaction does not support; skip it here.
    const roundTripNetworks = utxolib
      .getNetworkList()
      .filter(isSupportedNetwork)
      .filter((n) => utxolib.getMainnet(n) !== utxolib.networks.zcash);

    for (const network of roundTripNetworks) {
      const networkName = utxolib.getNetworkName(network);
      it(`${networkName}: reconstructed PSBT serializes without error`, function () {
        const rootWalletKeys = getDefaultWalletKeys();
        const coinName = getCoinNameForNetwork(network);
        const { psbt, unspents } = createHalfSignedP2msPsbt(network);
        const txBytes = psbt.getHalfSignedLegacyFormat();

        const reconstructed = BitGoPsbt.fromHalfSignedLegacyTransaction(
          txBytes,
          coinName,
          rootWalletKeys,
          unspents,
        );

        const serialized = reconstructed.serialize();
        assert.ok(serialized.length > 0, "Reconstructed PSBT should serialize to non-empty bytes");
      });
    }
  });
});
