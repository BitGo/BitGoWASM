/**
 * Regression test for the wallet-platform "Invalid hashType 0" error on BCH PSBTs.
 *
 * Root cause (found in fixed_script_input.rs::from_txin):
 *   For P2SH-P2PK scriptSig = <sig> <redeemScript>, the sig is at instructions[0].
 *   The original slot range instructions[1..len-1] (designed for multisig OP_0 prefix)
 *   produced an empty slice, so sig_bytes was always None. The p2shP2pk partial sig
 *   was lost during fromNetworkFormat hydration.
 *
 * Fix: detect P2PK redeemScript and start slots at index 0 for p2shP2pk inputs.
 *
 * The wallet-platform reported "Invalid hashType 0" at finalizeAllInputs() because
 * the p2shP2pk partial sig was absent from the hydrated PSBT, leaving no valid sig
 * for finalization. With a later combine step, a partial sig with unexpected bytes
 * could produce the literal "Invalid hashType 0" error; the core cause is the lost sig.
 */

import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { AcidTest } from "../../js/testutils/AcidTest.js";
import { BitGoPsbt } from "../../js/fixedScriptWallet/BitGoPsbt.js";
import { ECPair } from "../../js/ecpair.js";
import type { HydrationUnspent } from "../../js/fixedScriptWallet/BitGoPsbt.js";

function buildHydrationUnspents(acid: AcidTest): HydrationUnspent[] {
  const rpPubkey = acid.userXprv.publicKey;
  return acid.inputs.map((input, i) => {
    if ("scriptType" in input && input.scriptType === "p2shP2pk") {
      return { pubkey: rpPubkey, value: input.value };
    }
    const scriptId =
      "scriptId" in input && input.scriptId ? input.scriptId : { chain: 0, index: i };
    return { chain: scriptId.chain, index: scriptId.index, value: input.value };
  });
}

describe("BCH p2shP2pk hydration (regression: 'Invalid hashType 0' / sig lost in fromNetworkFormat)", function () {
  for (const txFormat of ["psbt-lite", "psbt"] as const) {
    describe(`txFormat: ${txFormat}`, function () {
      it("p2shP2pk sig preserved after fromNetworkFormat on half-signed tx", function () {
        const acid = AcidTest.withConfig("bch", "halfsigned", txFormat);
        const rpECPair = ECPair.fromPrivateKey(Buffer.from(acid.userXprv.privateKey));
        const rpIdx = acid.inputs.findIndex(
          (i) => "scriptType" in i && i.scriptType === "p2shP2pk",
        );
        assert.ok(rpIdx >= 0, "AcidTest should include a p2shP2pk input for BCH");

        const halfsignedPsbt = acid.createPsbt(); // user+rp signed
        const legacyBytes = halfsignedPsbt.getHalfSignedLegacyFormat();

        const unspents = buildHydrationUnspents(acid);
        const hydratedPsbt = BitGoPsbt.fromNetworkFormat(
          legacyBytes,
          "bch",
          acid.rootWalletKeys,
          unspents,
        );

        // The p2shP2pk partial sig must survive the round-trip
        assert.ok(
          hydratedPsbt.verifySignature(rpIdx, rpECPair),
          "p2shP2pk partial sig should be preserved after fromNetworkFormat",
        );
      });

      it("p2shP2pk sig preserved after fromNetworkFormat on fully-signed tx", function () {
        const acid = AcidTest.withConfig("bch", "fullsigned", txFormat);
        const rpECPair = ECPair.fromPrivateKey(Buffer.from(acid.userXprv.privateKey));
        const rpIdx = acid.inputs.findIndex(
          (i) => "scriptType" in i && i.scriptType === "p2shP2pk",
        );
        assert.ok(rpIdx >= 0, "AcidTest should include a p2shP2pk input for BCH");

        const fullsignedPsbt = acid.createPsbt();
        fullsignedPsbt.finalizeAllInputs();
        const txBytes = fullsignedPsbt.extractTransaction().toBytes();

        const unspents = buildHydrationUnspents(acid);
        const hydratedPsbt = BitGoPsbt.fromNetworkFormat(
          txBytes,
          "bch",
          acid.rootWalletKeys,
          unspents,
        );

        // The p2shP2pk partial sig must survive hydration from a fully-signed tx
        assert.ok(
          hydratedPsbt.verifySignature(rpIdx, rpECPair),
          "p2shP2pk partial sig should be preserved after fromNetworkFormat from fully-signed tx",
        );
      });

      it("finalization succeeds via utxolib after hydrate-and-cosign (wallet-platform scenario)", function () {
        const acid = AcidTest.withConfig("bch", "halfsigned", txFormat);
        const rpECPair = ECPair.fromPrivateKey(Buffer.from(acid.userXprv.privateKey));
        const rpIdx = acid.inputs.findIndex(
          (i) => "scriptType" in i && i.scriptType === "p2shP2pk",
        );

        // 1. User signs wallet inputs → half-signed legacy tx
        const legacyBytes = acid.createPsbt().getHalfSignedLegacyFormat();

        // 2. indexerdb hydrates (fromNetworkFormat)
        const unspents = buildHydrationUnspents(acid);
        const hydratedPsbt = BitGoPsbt.fromNetworkFormat(
          legacyBytes,
          "bch",
          acid.rootWalletKeys,
          unspents,
        );

        // 3. HSM co-signs wallet inputs + p2shP2pk
        hydratedPsbt.sign(acid.bitgoXprv);
        if (rpIdx >= 0) hydratedPsbt.signInput(rpIdx, rpECPair);

        // 4. wallet-platform finalizes via utxolib
        const utxolibPsbt = utxolib.bitgo.createPsbtFromBuffer(
          Buffer.from(hydratedPsbt.serialize()),
          utxolib.networks.bitcoincash,
        );

        // All partial sigs must have hashType 0x41 (SIGHASH_ALL | SIGHASH_FORKID)
        utxolibPsbt.data.inputs.forEach((input, idx) => {
          (input.partialSig ?? []).forEach((ps) => {
            const hashTypeByte = ps.signature[ps.signature.length - 1];
            assert.strictEqual(
              hashTypeByte,
              0x41,
              `input ${idx}: partial sig hashType = 0x${hashTypeByte.toString(16)}, expected 0x41`,
            );
          });
        });

        // This is the line that threw "Invalid hashType 0" on the wallet-platform
        assert.doesNotThrow(() => utxolibPsbt.finalizeAllInputs());
        assert.ok(utxolibPsbt.extractTransaction());
      });
    });
  }
});
