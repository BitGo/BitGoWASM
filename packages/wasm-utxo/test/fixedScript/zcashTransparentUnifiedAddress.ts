import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "mocha";

import { ZcashBitGoPsbt } from "../../js/fixedScriptWallet/ZcashBitGoPsbt.js";
import { ZcashIronwoodBitGoPsbt } from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";
import { ZcashUnifiedAddress } from "../../js/fixedScriptWallet/ZcashUnifiedAddress.js";
import { address as addressNs } from "../../js/index.js";
import { getWalletKeysForSeed } from "../../js/testutils/index.js";

// A deterministic Ironwood receiver — same one used elsewhere in the Ironwood test suite —
// re-encoded here as a single-receiver (Orchard-only, no transparent receiver) UA.
const ORCHARD_RECEIVER = Buffer.from(
  "4559029c0b5dbf941c5ad181a5fe8f45b34630f29d0c8dd8dc1cc3573386f416cb324133156d723df5e62d",
  "hex",
);

// A block height comfortably within NU5, well before NU6.3 (Ironwood) activation — any legacy
// (v4) branch id works here since this feature has nothing to do with sighash rules.
const LEGACY_TESTNET_HEIGHT = 2_000_000;
// NU6.3 (Ironwood) testnet activation height.
const NU6_3_TESTNET_HEIGHT = 4_134_000;

const SCRIPT_ID = { chain: 0, index: 0 } as const;

type UaVector = {
  network: "zec" | "tzec";
  unified: string;
  transparentAddress?: string;
};

const uaFixtures = JSON.parse(
  fs.readFileSync(
    path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../fixtures/zcash/unified_address.json",
    ),
    "utf8",
  ),
) as { testnetWallet: UaVector };
const WALLET = uaFixtures.testnetWallet;

// The UA's transparent receiver, resolved the same way a client would: through the public
// address API rather than by reaching into the UA's internals.
const TRANSPARENT_SCRIPT = addressNs.toOutputScriptWithCoin(WALLET.transparentAddress, "tzec");

describe("ZcashBitGoPsbt.addTransparentOutput (legacy v4 unified_address)", function () {
  const walletKeys = getWalletKeysForSeed("v4-ua-transparent-ts");

  function buildLegacyPsbt(): ZcashBitGoPsbt {
    const psbt = ZcashBitGoPsbt.createEmpty("zcashTest", walletKeys, {
      blockHeight: LEGACY_TESTNET_HEIGHT,
    });
    psbt.addWalletInput({ txid: "22".repeat(32), vout: 0, value: 300_000_000n }, walletKeys, {
      scriptId: SCRIPT_ID,
      signPath: { signer: "user", cosigner: "bitgo" },
    });
    return psbt;
  }

  it("adds the transparent output and stores the unifiedAddress it was resolved from", function () {
    const psbt = buildLegacyPsbt();
    const index = psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n, WALLET.unified);
    psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });

    assert.strictEqual(psbt.transparentOutputUnifiedAddress(index), WALLET.unified);

    const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);
    assert.strictEqual(outputs.length, 2);
    assert.deepStrictEqual(new Uint8Array(outputs[index].script), TRANSPARENT_SCRIPT);
    // The parsed output's `address` prefers the stored unifiedAddress — mirroring how a
    // shielded Ironwood output's `address` prefers its stored UA over a bare address
    // reconstructed from the raw receiver — so it comes back as the exact UA the client
    // originally passed in, not just the plain transparent address the script resolves to.
    assert.strictEqual(outputs[index].address, WALLET.unified);
  });

  it("round-trips the unifiedAddress and the transparent output through serialize/fromBytes", function () {
    const psbt = buildLegacyPsbt();
    const index = psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n, WALLET.unified);
    psbt.addWalletOutput(walletKeys, { chain: 1, index: 0, value: 199_900_000n });

    const bytes = psbt.serialize();
    const round = ZcashBitGoPsbt.fromBytes(bytes, "zcashTest");

    assert.strictEqual(round.transparentOutputUnifiedAddress(index), WALLET.unified);
    const outputs = round.parseOutputsWithWalletKeys(walletKeys);
    assert.deepStrictEqual(new Uint8Array(outputs[index].script), TRANSPARENT_SCRIPT);
    assert.strictEqual(outputs[index].address, WALLET.unified);
  });

  it("works with just a script/value — no unifiedAddress, exactly like addOutput", function () {
    const psbt = buildLegacyPsbt();
    const index = psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n);

    assert.strictEqual(psbt.transparentOutputUnifiedAddress(index), undefined);
    const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);
    assert.deepStrictEqual(new Uint8Array(outputs[index].script), TRANSPARENT_SCRIPT);
    // No unifiedAddress was stored, so `address` falls back to the plain transparent address
    // resolved from the scriptPubkey — exactly like any other legacy output.
    assert.strictEqual(outputs[index].address, WALLET.transparentAddress);
  });

  describe("failure scenarios", function () {
    it("rejects a unifiedAddress whose transparent receiver does not match script", function () {
      const psbt = buildLegacyPsbt();
      // Any well-formed but different P2PKH script.
      const otherScript = addressNs.toOutputScriptWithCoin(
        "tmYXBYJj1K7vhejSec5osXK2QsGa5MTisUQ",
        "tzec",
      );
      assert.throws(
        () => psbt.addTransparentOutput(otherScript, 100_000_000n, WALLET.unified),
        /does not match/,
      );
      // Nothing was inserted on the rejected call.
      const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);
      assert.strictEqual(outputs.length, 0);
    });

    it("rejects a unifiedAddress that is not a valid unified address", function () {
      const psbt = buildLegacyPsbt();
      assert.throws(
        () => psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n, "not-a-valid-address"),
        /invalid unified_address/,
      );
      // Nothing was inserted on the rejected call.
      assert.strictEqual(psbt.parseOutputsWithWalletKeys(walletKeys).length, 0);
    });

    it("rejects a unifiedAddress with no transparent receiver (Orchard-only)", function () {
      const psbt = buildLegacyPsbt();
      const orchardOnlyUa = ZcashUnifiedAddress.encodeOrchardReceiver(ORCHARD_RECEIVER, "tzec");
      assert.throws(
        () => psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n, orchardOnlyUa),
        /no transparent receiver/,
      );
      // Nothing was inserted on the rejected call.
      assert.strictEqual(psbt.parseOutputsWithWalletKeys(walletKeys).length, 0);
    });

    it("rejects a unifiedAddress on a v6 (Ironwood) PSBT", function () {
      const psbt = ZcashIronwoodBitGoPsbt.createEmpty("zcashTest", walletKeys, {
        blockHeight: NU6_3_TESTNET_HEIGHT,
      });
      assert.throws(
        () => psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n, WALLET.unified),
        /v4/,
      );

      // The legacy form (no unifiedAddress) is unaffected, even on a v6 PSBT.
      const index = psbt.addTransparentOutput(TRANSPARENT_SCRIPT, 100_000_000n);
      assert.strictEqual(psbt.transparentOutputUnifiedAddress(index), undefined);
    });
  });
});
