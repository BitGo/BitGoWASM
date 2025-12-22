import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { BIP32, fixedScriptWallet } from "../../js/index.js";
import type { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";

function getWalletKeysForSeed(seed: string): RootWalletKeys {
  const triple = utxolib.testutil.getKeyTriple(seed);
  const neutered = triple.map((k) => k.neutered()) as [
    utxolib.BIP32Interface,
    utxolib.BIP32Interface,
    utxolib.BIP32Interface,
  ];
  return fixedScriptWallet.RootWalletKeys.from({
    triple: neutered,
    derivationPrefixes: ["0/0", "0/0", "0/0"],
  });
}

describe("Dogecoin large output limit amount (LOL amounts) (1-in/1-out)", function () {
  it("should sign, finalize, and extract tx with 1e19 output value", function () {
    const networkName = "dogecoin";
    const seed = "doge_1e19";
    const walletKeys = getWalletKeysForSeed(seed);

    const psbt = fixedScriptWallet.BitGoPsbt.createEmpty(networkName, walletKeys, {
      version: 2,
      lockTime: 0,
    });

    const value = 10_000_000_000_000_000_000n; // 1e19
    const txid = "00".repeat(32);

    psbt.addWalletInput({ txid, vout: 0, value }, walletKeys, { scriptId: { chain: 0, index: 0 } });
    psbt.addWalletOutput(walletKeys, { chain: 0, index: 0, value });

    const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, { publicKeys: [] });
    assert.strictEqual(parsed.inputs.length, 1);
    assert.strictEqual(parsed.outputs.length, 1);
    assert.strictEqual(parsed.inputs[0].value, value);
    assert.strictEqual(parsed.outputs[0].value, value);

    // P2SH multisig needs 2 signatures to finalize. Use user + bitgo keys.
    const xprvs = utxolib.testutil.getKeyTriple(seed);
    const userXpriv = BIP32.fromBase58(xprvs[0].toBase58());
    const bitgoXpriv = BIP32.fromBase58(xprvs[2].toBase58());

    psbt.sign(0, userXpriv);
    assert.strictEqual(psbt.verifySignature(0, userXpriv), true, "user signature missing");
    psbt.sign(0, bitgoXpriv);
    assert.strictEqual(psbt.verifySignature(0, bitgoXpriv), true, "bitgo signature missing");

    psbt.finalizeAllInputs();
    const extractedTx = psbt.extractTransaction();
    assert.ok(extractedTx.length > 0, "expected extracted tx bytes");
  });
});
