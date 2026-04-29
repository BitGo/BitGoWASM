/**
 * Regression test for BCH FORKID sighash in partial sigs.
 *
 * The wallet-platform reported: "Error: Invalid hashType 0" when calling
 * utxolib's finalizeAllInputs() on a BCH PSBT after HSM co-signing.
 *
 * Root cause: an older version of wasm-utxo signed BCH p2shP2pk inputs with
 * SIGHASH_ALL (0x01) instead of SIGHASH_ALL|SIGHASH_FORKID (0x41), or produced
 * partial sigs without the hashType byte at all (last byte = 0x00).
 *
 * This test verifies that:
 * 1. WASM-signed BCH PSBTs contain partial sigs with hashType 0x41.
 * 2. utxolib's finalizeAllInputs() succeeds on such a PSBT (no "Invalid hashType" error).
 */

import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";
import { loadPsbtFixture, getPsbtBuffer } from "./fixtureUtil.js";

const BCH_SIGHASH_FORKID = 0x41; // SIGHASH_ALL | SIGHASH_FORKID

type ForkIdTestCase = {
  coin: "bch" | "bcha";
  network: utxolib.Network;
};

const forkIdCoins: ForkIdTestCase[] = [
  { coin: "bch", network: utxolib.networks.bitcoincash },
  { coin: "bcha", network: utxolib.networks.ecash },
];

describe("BCH/XEC FORKID finalization (regression: Invalid hashType 0)", function () {
  for (const { coin, network } of forkIdCoins) {
    for (const txFormat of ["psbt-lite", "psbt"] as const) {
      describe(`coin: ${coin}, txFormat: ${txFormat}`, function () {
        it("all partial sigs have hashType 0x41 (SIGHASH_ALL|SIGHASH_FORKID)", async function () {
          const fixture = await loadPsbtFixture(coin, "fullsigned", txFormat);
          const psbtBuffer = getPsbtBuffer(fixture);
          const psbt = utxolib.bitgo.createPsbtFromBuffer(psbtBuffer, network);

          psbt.data.inputs.forEach((input, idx) => {
            if (!input.partialSig || input.partialSig.length === 0) {
              return;
            }
            input.partialSig.forEach((ps) => {
              const hashTypeByte = ps.signature[ps.signature.length - 1];
              assert.strictEqual(
                hashTypeByte,
                BCH_SIGHASH_FORKID,
                `input ${idx}: partial sig hashType byte is 0x${hashTypeByte.toString(16)}, expected 0x41 (SIGHASH_ALL|SIGHASH_FORKID)`,
              );
            });
          });
        });

        it("utxolib finalizeAllInputs() succeeds on WASM-signed PSBT", async function () {
          const fixture = await loadPsbtFixture(coin, "fullsigned", txFormat);
          const psbtBuffer = getPsbtBuffer(fixture);
          const psbt = utxolib.bitgo.createPsbtFromBuffer(psbtBuffer, network);

          // This is where the wallet-platform error occurred:
          // "Error: Invalid hashType 0 at checkPartialSigSighashes"
          assert.doesNotThrow(() => psbt.finalizeAllInputs());

          const tx = psbt.extractTransaction();
          assert.ok(tx);
        });
      });
    }
  }
});
