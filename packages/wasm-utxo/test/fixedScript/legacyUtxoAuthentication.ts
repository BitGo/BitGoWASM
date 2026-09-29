import assert from "node:assert";
import { describe, it } from "mocha";
import { BitGoPsbt } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ECPair } from "../../js/ecpair.js";
import {
  outputScript,
  p2shP2pkOutputScript,
} from "../../js/fixedScriptWallet/index.js";
import { createSyntheticPrevTx } from "../../js/testutils/AcidTest.js";
import { getDefaultWalletKeys } from "../../js/testutils/keys.js";

describe("legacy PSBT prevout authentication", function () {
  const walletKeys = getDefaultWalletKeys();
  const p2sh = outputScript(walletKeys, 0, 0, "btc");
  const value = 10_000n;
  const prevTx = createSyntheticPrevTx(p2sh, value);

  it("requires the matching previous transaction for legacy P2SH", function () {
    const psbt = BitGoPsbt.createEmpty("btc", walletKeys);

    assert.throws(
      () =>
        psbt.addWalletInput(
          { txid: prevTx.txid, vout: 0, value },
          walletKeys,
          { scriptId: { chain: 0, index: 0 } },
        ),
      /non_witness_utxo is required/i,
    );

    assert.doesNotThrow(() =>
      psbt.addWalletInput(
        { ...prevTx, vout: 0, value },
        walletKeys,
        { scriptId: { chain: 0, index: 0 } },
      ),
    );
  });

  it("rejects a previous transaction with a different txid", function () {
    const psbt = BitGoPsbt.createEmpty("btc", walletKeys);

    assert.throws(
      () =>
        psbt.addWalletInput(
          { ...prevTx, txid: "11".repeat(32), vout: 0, value },
          walletKeys,
          { scriptId: { chain: 0, index: 0 } },
        ),
      /does not match prevout txid/i,
    );
  });

  it("rejects a caller value that disagrees with the spent output", function () {
    const psbt = BitGoPsbt.createEmpty("btc", walletKeys);

    assert.throws(
      () =>
        psbt.addWalletInput(
          { ...prevTx, vout: 0, value: value - 1n },
          walletKeys,
          { scriptId: { chain: 0, index: 0 } },
        ),
      /does not match the supplied script and value/i,
    );
  });

  it("requires authenticated replay-protection inputs on Bitcoin", function () {
    const psbt = BitGoPsbt.createEmpty("btc", walletKeys);
    const key = ECPair.fromPublicKey(walletKeys.userKey().publicKey);

    assert.throws(
      () => psbt.addReplayProtectionInput({ txid: "22".repeat(32), vout: 0, value }, key),
      /non_witness_utxo is required/i,
    );

    const replayScript = p2shP2pkOutputScript(key.publicKey);
    const replayPrevTx = createSyntheticPrevTx(replayScript, value);
    assert.doesNotThrow(() =>
      psbt.addReplayProtectionInput({ ...replayPrevTx, vout: 0, value }, key),
    );
  });

  it("rejects a conflicting witness_utxo in the generic input API", function () {
    const psbt = BitGoPsbt.createEmpty("btc", walletKeys);

    assert.throws(
      () =>
        psbt.addInput(
          { ...prevTx, vout: 0, value: value - 1n },
          p2sh,
        ),
      /witness_utxo does not match/i,
    );
  });

  it("keeps witness-only P2SH available on value-committing networks", function () {
    const psbt = BitGoPsbt.createEmpty("bch", walletKeys);

    assert.doesNotThrow(() =>
      psbt.addWalletInput(
        { txid: "33".repeat(32), vout: 0, value },
        walletKeys,
        { scriptId: { chain: 0, index: 0 } },
      ),
    );
  });
});
