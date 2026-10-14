import assert from "node:assert";
import { describe, it } from "mocha";

import {
  fixedScriptWallet,
  isWasmUtxoError,
  ZcashDimensions,
  Zip317Dimensions,
} from "../js/index.js";
import { ZcashBitGoPsbt } from "../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { ZcashIronwoodBitGoPsbt } from "../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import { ZcashUnifiedAddress } from "../js/fixedScriptWallet/ZcashUnifiedAddress.js";
import { getDefaultWalletKeys, getKeyTriple, getWalletKeysForSeed } from "../js/testutils/index.js";

// NU6.3 (Ironwood) testnet activation height.
const NU6_3_TESTNET_HEIGHT = 4134000;
// A mainnet NU5 height, for a v4 (pre-Ironwood) PSBT.
const NU5_MAINNET_HEIGHT = 2_726_400;

// A valid raw Orchard/Ironwood receiver (43 bytes), encoded as a single-receiver UA.
const RECEIVER = Buffer.from(
  "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
  "hex",
);
const UNIFIED_ADDRESS = ZcashUnifiedAddress.encodeOrchardReceiver(RECEIVER, "zcashTest");
// A zcash testnet p2sh address -> ordinary 23-byte scriptPubKey.
const TRANSPARENT_ADDRESS = "t288NZMrzYi6oednBEnw8UZvGoqX4Z6NXys";

// A BitGo P2SH 2-of-3 input: outpoint (36) + CompactSize (3) + `OP_0 <sig> <sig> <redeemScript>`
// (1 + 2 × 74 + 107 = 256) + sequence (4).
const P2SH_INPUT_SIZE = 299;
// A P2SH output: value (8) + CompactSize (1) + 23-byte script.
const P2SH_OUTPUT_SIZE = 32;

function assertThrowsCode(fn: () => unknown, code: string): void {
  assert.throws(fn, (e: unknown) => isWasmUtxoError(e) && e.code === code);
}

describe("Zip317Dimensions", function () {
  describe("conventional fee", function () {
    it("prices ZIP-317's grace floor at two actions", function () {
      assert.strictEqual(Zip317Dimensions.empty().getLogicalActions(), 0);
      assert.strictEqual(Zip317Dimensions.empty().getConventionalFee(), 10_000n);
    });

    it("prices the transparent terms by size, not count", function () {
      // 3 inputs: ceil(3 × 299 / 150) = 6 logical actions, more than one per input.
      const dims = Zip317Dimensions.fromInput({ chain: 0 }).times(3);
      assert.strictEqual(dims.txInTotalSize, 3 * P2SH_INPUT_SIZE);
      assert.strictEqual(dims.getLogicalActions(), 6);
      assert.strictEqual(dims.getConventionalFee(), 30_000n);
    });

    it("counts Ironwood actions as max(spends, outputs)", function () {
      const dims = Zip317Dimensions.fromIronwoodSpends(2).plus(
        Zip317Dimensions.fromIronwoodOutputs(3),
      );
      assert.strictEqual(dims.ironwoodActions, 3);
      assert.strictEqual(dims.getConventionalFee(), 15_000n);
    });
  });

  describe("fromInput", function () {
    it("sizes a wallet input with its finalized 2-of-3 scriptSig", function () {
      const fromChain = Zip317Dimensions.fromInput({ chain: 0 });
      assert.strictEqual(fromChain.txInTotalSize, P2SH_INPUT_SIZE);
      assert.strictEqual(
        Zip317Dimensions.fromInput({ scriptType: "p2sh" }).txInTotalSize,
        P2SH_INPUT_SIZE,
      );
      assert.strictEqual(Zip317Dimensions.fromInput({ chain: 1 }).txInTotalSize, P2SH_INPUT_SIZE);
    });

    it("sizes a replay-protection input as <sig> <redeemScript>", function () {
      // 36 + 1 + (74 + 36) + 4
      assert.strictEqual(Zip317Dimensions.fromInput({ scriptType: "p2shP2pk" }).txInTotalSize, 151);
    });

    it("rejects inputs a Zcash wallet cannot have", function () {
      assertThrowsCode(
        () => Zip317Dimensions.fromInput({ chain: 20 }),
        "Zip317Error.UnsupportedChain",
      );
      assertThrowsCode(
        () => Zip317Dimensions.fromInput({ scriptType: "p2wsh" as never }),
        "Zip317Error.UnsupportedInputScriptType",
      );
    });
  });

  describe("fromOutput", function () {
    it("sizes a transparent output from its script", function () {
      assert.strictEqual(Zip317Dimensions.fromOutput({ length: 23 }).txOutTotalSize, 32);
      assert.strictEqual(
        Zip317Dimensions.fromOutput(TRANSPARENT_ADDRESS, "tzec").txOutTotalSize,
        P2SH_OUTPUT_SIZE,
      );
    });

    it("sizes a shielded Unified Address as one Ironwood output", function () {
      const dims = Zip317Dimensions.fromOutput(UNIFIED_ADDRESS, "tzec", { isShielded: true });
      assert.strictEqual(dims.ironwoodOutputs, 1);
      assert.strictEqual(dims.txOutTotalSize, 0);
    });

    it("sizes a transparent address as transparent even with isShielded", function () {
      const dims = Zip317Dimensions.fromOutput(TRANSPARENT_ADDRESS, "tzec", { isShielded: true });
      assert.strictEqual(dims.ironwoodOutputs, 0);
      assert.strictEqual(dims.txOutTotalSize, P2SH_OUTPUT_SIZE);
    });

    it("rejects a malformed Unified Address with isShielded, like ZcashDimensions", function () {
      const last = UNIFIED_ADDRESS.slice(-1);
      const corrupted = UNIFIED_ADDRESS.slice(0, -1) + (last === "q" ? "p" : "q");
      assert.throws(() => ZcashDimensions.fromOutput(corrupted, "tzec", { isShielded: true }));
      assert.throws(() => Zip317Dimensions.fromOutput(corrupted, "tzec", { isShielded: true }));
    });
  });

  describe("fromPsbt", function () {
    const walletKeys = getWalletKeysForSeed("zip317-dimensions");

    function buildTransparentPart(): ZcashIronwoodBitGoPsbt {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, walletKeys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 99_900_000n });
      return psbt;
    }

    it("matches the composed dimensions for a shielding PSBT", function () {
      const psbt = buildTransparentPart();
      psbt.addShieldedOutput(RECEIVER, 100_000_000n, { anchor: new Uint8Array(32) });

      const fromPsbt = Zip317Dimensions.fromPsbt(psbt);
      const composed = Zip317Dimensions.fromInput({ chain: 0 })
        .plus(Zip317Dimensions.fromOutput({ length: 23 }))
        .plus(Zip317Dimensions.fromIronwoodOutputs(1));
      assert.strictEqual(fromPsbt.txInTotalSize, composed.txInTotalSize);
      assert.strictEqual(fromPsbt.txOutTotalSize, composed.txOutTotalSize);
      assert.strictEqual(fromPsbt.ironwoodSpends, 0, "the shielding bundle's spends are dummies");
      assert.strictEqual(fromPsbt.ironwoodOutputs, 1);
      // max(ceil(299/150), ceil(32/34)) + 1 = 3 ⇒ 15_000 zatoshi.
      assert.strictEqual(fromPsbt.getLogicalActions(), 3);
      assert.strictEqual(fromPsbt.getConventionalFee(), composed.getConventionalFee());
      assert.strictEqual(fromPsbt.getConventionalFee(), 15_000n);
    });

    it("has no Ironwood term for a transparent-only v6 PSBT", function () {
      const fromPsbt = Zip317Dimensions.fromPsbt(buildTransparentPart());
      assert.strictEqual(fromPsbt.ironwoodActions, 0);
      assert.strictEqual(fromPsbt.txInTotalSize, P2SH_INPUT_SIZE);
    });

    it("still sees the actions and fee after combineProof drops the PCZT", function () {
      const seed = "zip317-dimensions-combine";
      const keys = getWalletKeysForSeed(seed);
      const [userKey, , bitgoKey] = getKeyTriple(seed);
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", keys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      psbt.addWalletInput({ txid: "22".repeat(32), vout: 0, value: 200_000_000n }, keys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(keys, { chain: 1, index: 0, value: 99_900_000n });
      psbt.addShieldedOutput(RECEIVER, 100_000_000n, { anchor: new Uint8Array(32) });
      psbt.sign(userKey, keys);
      psbt.sign(bitgoKey, keys);
      const before = Zip317Dimensions.fromPsbt(psbt);

      // A placeholder proof of the real single-action size stands in for the external prover.
      assert.ok(psbt.combineProof(new Uint8Array(4992)).length > 0);
      assert.strictEqual(psbt.getPczt(), undefined, "the PCZT is gone");

      const after = Zip317Dimensions.fromPsbt(psbt);
      assert.strictEqual(after.ironwoodSpends, 0);
      assert.strictEqual(after.ironwoodOutputs, 1);
      assert.strictEqual(after.txInTotalSize, before.txInTotalSize);
      assert.strictEqual(after.txOutTotalSize, before.txOutTotalSize);
      assert.strictEqual(after.getConventionalFee(), before.getConventionalFee());
      assert.strictEqual(after.getConventionalFee(), 15_000n);
    });

    it("sizes a finalized v4 PSBT's inputs from their real scriptSig", function () {
      const seed = "zip317-dimensions-v4";
      const keys = getWalletKeysForSeed(seed);
      const [userKey, , bitgoKey] = getKeyTriple(seed);
      const psbt = ZcashBitGoPsbt.createEmpty("zcash", keys, { blockHeight: NU5_MAINNET_HEIGHT });
      psbt.addWalletInput({ txid: "11".repeat(32), vout: 0, value: 200_000_000n }, keys, {
        scriptId: { chain: 0, index: 0 },
        signPath: { signer: "user", cosigner: "bitgo" },
      });
      psbt.addWalletOutput(keys, { chain: 1, index: 0, value: 199_900_000n });
      const estimated = Zip317Dimensions.fromPsbt(psbt);
      assert.strictEqual(estimated.ironwoodActions, 0);
      assert.strictEqual(estimated.txInTotalSize, P2SH_INPUT_SIZE);

      psbt.sign(userKey);
      psbt.sign(bitgoKey);
      psbt.finalizeAllInputs();
      const finalized = Zip317Dimensions.fromPsbt(psbt);
      // The real input (DER signatures are at most 73 bytes with sighash) never exceeds the
      // estimate, and is not mis-sized as a P2PKH input once the finalizer clears the redeem script.
      assert.ok(finalized.txInTotalSize <= P2SH_INPUT_SIZE, `${finalized.txInTotalSize}`);
      assert.ok(finalized.txInTotalSize >= P2SH_INPUT_SIZE - 4, `${finalized.txInTotalSize}`);
      assert.strictEqual(finalized.txOutTotalSize, estimated.txOutTotalSize);
      assert.strictEqual(finalized.getConventionalFee(), estimated.getConventionalFee());
    });

    it("rejects a non-Zcash PSBT", function () {
      const rootWalletKeys = getDefaultWalletKeys();
      const psbt = fixedScriptWallet.BitGoPsbt.createEmpty("bitcoin", rootWalletKeys);
      assertThrowsCode(() => Zip317Dimensions.fromPsbt(psbt), "Zip317Error.NotZcashPsbt");
    });
  });
});
