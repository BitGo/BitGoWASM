import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ecc, script } from "@bitgo/utxo-lib";
import { ZcashV6Transaction } from "../../js/fixedScriptWallet/ZcashV6Transaction.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesZcash = path.resolve(__dirname, "../fixtures/zcash");

function readFixture(name: string): string {
  return fs.readFileSync(path.join(fixturesZcash, name), "utf8").trim();
}

describe("ZcashV6Transaction", function () {
  // Real testnet transactions captured from the Ironwood reference.
  for (const name of ["shield", "selfsend", "shield1zec"]) {
    it(`decodes, round-trips, and reports the canonical txid for ${name}`, function () {
      const raw = Buffer.from(readFixture(`v6_${name}_rawtx.hex`), "hex");
      const expectedTxid = readFixture(`v6_${name}_txid.hex`);

      const tx = ZcashV6Transaction.fromBytes(raw);

      // getId is the canonical display-order txid — no manual reversing needed.
      assert.strictEqual(tx.getId(), expectedTxid);
      // Internal-order bytes are the reverse of the display id.
      assert.strictEqual(Buffer.from(tx.txidBytes()).reverse().toString("hex"), expectedTxid);
      // Re-encode is byte-identical.
      assert.strictEqual(Buffer.from(tx.toBytes()).toString("hex"), raw.toString("hex"));
      // Every fixture has exactly one Ironwood action.
      assert.strictEqual(tx.ironwoodActionCount, 1);
    });
  }

  it("exposes inspection fields for the self-send (fully shielded) tx", function () {
    const tx = ZcashV6Transaction.fromBytes(
      Buffer.from(readFixture("v6_selfsend_rawtx.hex"), "hex"),
    );
    assert.strictEqual(tx.consensusBranchId, 0x37a5165b);
    assert.strictEqual(tx.expiryHeight, 0);
    assert.strictEqual(tx.ironwoodFlags, 0x07);
    assert.strictEqual(tx.ironwoodAnchor?.length, 32);
    assert.strictEqual(typeof tx.ironwoodValueBalance, "bigint");
  });

  it("throws on non-v6 bytes", function () {
    assert.throws(() => ZcashV6Transaction.fromBytes(Buffer.from("00010203", "hex")));
  });

  /**
   * Golden regression test: `transparentSighash` must hash the spent output's scriptPubKey
   * into the ZIP-244 per-input digest, not the redeem/witness script ("scriptCode"). Those
   * coincide for a P2PKH input (see the Rust-side `golden_transparent_sighash_verifies_real_signature`
   * test), which is why a prior bug that hashed the redeem script there went uncaught until it
   * was exercised against a real P2SH multisig input.
   *
   * The fixture is a real transaction — spending a 2-of-3 P2SH multisig transparent input into
   * an Ironwood shielded output — that was built with this codebase's CLI, submitted to a live
   * Zcash testnet (NU6.3) `zebrad` node via `sendrawtransaction`, and accepted into its
   * mempool: real consensus-rule validation of the transparent scriptSig, not merely
   * self-consistency against this codebase's own sighash.
   */
  it("verifies a real mempool-accepted multisig tx's signatures against transparentSighash", function () {
    const tx = ZcashV6Transaction.fromBytes(
      Buffer.from(readFixture("v6_shield_multisig_rawtx.hex"), "hex"),
    );

    // Spent output (a synthetic 2-of-3 P2SH multisig address funded on Zcash testnet, then
    // spent by this tx); ZIP-244 commits to both.
    const prevoutValue = 2_000_000n;
    const prevoutScript = Buffer.from("a914ed68766fe37d9e2325758ed209ac78db505425a987", "hex");
    const redeemScript = Buffer.from(
      "5221023b4221b042fa25af6609d7e65d322fcb64c497b79ffc8f1891ea6b23d4e7d84a" +
        "2102feaf8248a2f8dcc34f2e2f520201801bb88d20ab549baf47b48bc9f2f4dfcc93" +
        "21030b82f01fd53e7dabe2d904938d64294e3352e9e836240af6ba2cfb9df8f837da53ae",
      "hex",
    );
    // scriptSig = OP_0 <sig1> <sig2> <redeemScript>, as decoded from the fixture's raw bytes.
    const scriptSig = Buffer.from(
      "0047304402204da2cef266325268af039a5ad4992babbb7d6813ac98f4351741c89e0186e41" +
        "10220441b74b62b346ed9a3e1e5b07c850d2c7acfce22b7140f2a9d02bddf221f29c50148" +
        "3045022100ee66c425f9fae3e32ae866534db4cae9b8daf5fb570a3638bf426cab1893e2a" +
        "8022033af0f5ccaf869703e5af54920a771a392c722588ff5660c342d5c06df726e4c014c" +
        "695221023b4221b042fa25af6609d7e65d322fcb64c497b79ffc8f1891ea6b23d4e7d84a2" +
        "102feaf8248a2f8dcc34f2e2f520201801bb88d20ab549baf47b48bc9f2f4dfcc9321030b" +
        "82f01fd53e7dabe2d904938d64294e3352e9e836240af6ba2cfb9df8f837da53ae",
      "hex",
    );

    const pubkeys = (script.decompile(redeemScript) ?? []).filter((el): el is Buffer =>
      Buffer.isBuffer(el),
    );
    assert.strictEqual(pubkeys.length, 3, "2-of-3 redeem script has 3 pubkeys");

    // The signatures correspond to pubkeys[0] and pubkeys[2] (the redeem script's first and
    // third keys).
    const scriptSigChunks = (script.decompile(scriptSig) ?? []).filter(
      (el): el is Buffer => Buffer.isBuffer(el) && el.length > 0,
    );
    assert.strictEqual(
      scriptSigChunks.length,
      3,
      "OP_0 dummy (excluded above), 2 sigs, redeem script",
    );
    const sigPubkeyPairs: [Buffer, Buffer][] = [
      [scriptSigChunks[0], pubkeys[0]],
      [scriptSigChunks[1], pubkeys[2]],
    ];

    const sighash = tx.transparentSighash(0, [prevoutValue], [prevoutScript]);
    assert.strictEqual(sighash.length, 32);

    for (const [derSigWithHashType, pubkey] of sigPubkeyPairs) {
      const { signature, hashType } = script.signature.decode(derSigWithHashType);
      assert.strictEqual(hashType, 0x01, "signature uses SIGHASH_ALL");
      assert.strictEqual(
        ecc.verify(sighash, pubkey, signature),
        true,
        "the real mempool-accepted multisig tx's signature verifies against transparentSighash",
      );
    }
  });
});
