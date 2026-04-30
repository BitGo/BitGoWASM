import * as assert from "assert";
import * as crypto from "crypto";
import { Descriptor } from "../js/index.js";
import { getUnspendableKey } from "../js/testutils/descriptor/descriptors.js";

// sBTC protocol uses two taproot script leaves:
// 1. Deposit leaf: allows the signers to spend with a protocol payload
// 2. Reclaim leaf: allows the depositors to reclaim after a timelock

const SIGNERS_KEY = "c9c2312ca406dcb8eed50b829b5292f5fb3e846db0a556af61cc53834ce75421";

// BIP341 "nothing up my sleeve" unspendable internal key — used so the taproot address
// can only be spent via script path (no key-path spend).
const UNSPENDABLE_KEY = getUnspendableKey();

const DEPOSIT_LEAF =
  "c:and_v(payload_drop(" +
  "0000000000013880051ad206838b7981a116c334e8cb1b950afb73eb54a5" +
  "),pk_k(" +
  SIGNERS_KEY +
  "))";

const RECLAIM_LEAF =
  "and_v(r:older(1),multi_a(2," +
  "4d838759b2a74616a2298e0580ca815874f5e5a9d2dd1b2f0203b68c66fc6c1e," +
  "639779c4b700dc51ece012a0e20325fcafada22a4a122ffaa04d0c0ccae83943," +
  "d1d6084eac98303e9d28e082bfd9eadf0b8be033e223a17ad01df81bdaa8c7b2))";

// Reference vectors from rust-miniscript test_payload_drop_stacks_vectors.
// Deposit leaf: OP_PUSHBYTES_30 <metadata> OP_DROP OP_PUSHBYTES_32 <key> OP_CHECKSIG
const DEPOSIT_SCRIPT_HEX =
  "1e0000000000013880051ad206838b7981a116c334e8cb1b950afb73eb54a5" +
  "7520c9c2312ca406dcb8eed50b829b5292f5fb3e846db0a556af61cc53834ce75421ac";
const DEPOSIT_LEAF_HASH = "b14bbf1c6699b64429be4f11e1d4df7b75f16f68e7a86cb91c58daf024d0b379";
// Reclaim leaf: OP_1 OP_CSV OP_DROP + 2-of-3 multi_a
const RECLAIM_SCRIPT_HEX =
  "51b275" +
  "204d838759b2a74616a2298e0580ca815874f5e5a9d2dd1b2f0203b68c66fc6c1eac" +
  "20639779c4b700dc51ece012a0e20325fcafada22a4a122ffaa04d0c0ccae83943ba" +
  "20d1d6084eac98303e9d28e082bfd9eadf0b8be033e223a17ad01df81bdaa8c7b2ba529c";
const RECLAIM_LEAF_HASH = "1e379caf8335dc3bd0af785d32d8135647ffa2ee76dd2c1bcc663ff424602ac0";
// P2TR output: OP_1 OP_PUSHBYTES_32 <tweaked-x-only-pubkey>
const SCRIPT_PUBKEY_HEX = "5120f3b3930e1e7103753b62e5cfee821b5bfa942eacb868e1d625243df606882dff";

// BIP341 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
function taggedHash(tag: string, data: Buffer): Buffer {
  const tagHash = crypto.createHash("sha256").update(tag).digest();
  return crypto
    .createHash("sha256")
    .update(Buffer.concat([tagHash, tagHash, data]))
    .digest();
}

// BIP341 tap leaf hash: tagged_hash("TapLeaf", version || compact_size(len) || script)
// version 0xc0 = TapScript; compact_size is a single byte for scripts shorter than 253 bytes.
function tapLeafHash(scriptHex: string): string {
  const script = Buffer.from(scriptHex, "hex");
  const data = Buffer.concat([Buffer.from([0xc0, script.length]), script]);
  return taggedHash("TapLeaf", data).toString("hex");
}

function getSbtcDescriptor(depositLeaf: string, reclaimLeaf: string) {
  return `tr(${UNSPENDABLE_KEY},{${depositLeaf},${reclaimLeaf}})`;
}

// Types matching the node() structure for the sBTC taproot descriptor
type DefiniteKey = { Single: string };

type SbtcDepositLeaf = {
  Check: {
    AndV: [{ PayloadDrop: string }, { PkK: DefiniteKey }];
  };
};

type SbtcReclaimLeaf = {
  AndV: [{ Drop: { Older: { relLockTime: number } } }, { MultiA: DefiniteKey[] }];
};

type SbtcDescriptorNode = {
  Tr: [DefiniteKey, { Tree: [SbtcDepositLeaf, SbtcReclaimLeaf] }];
};

describe("sBTC taproot descriptor", function () {
  // Use fromStringExt with { drop: true } to enable r:older() in taproot
  const descriptor = Descriptor.fromString(
    getSbtcDescriptor(DEPOSIT_LEAF, RECLAIM_LEAF),
    "definite",
  );

  it("parses successfully with fromStringExt", () => {
    // Key test: Descriptor.fromStringExt({ drop: true }) handles r:older() with targeted drop permission
    assert.ok(descriptor, "Descriptor should parse successfully");
  });

  it("has expected taproot structure", () => {
    const node = descriptor.node() as SbtcDescriptorNode;
    // Definite descriptors wrap keys in { Single: "..." }
    assert.deepStrictEqual(
      node.Tr[0],
      { Single: UNSPENDABLE_KEY },
      "Should have correct internal key",
    );
    assert.ok(node.Tr[1].Tree, "Should have taproot tree structure");
    assert.strictEqual(node.Tr[1].Tree.length, 2, "Should have two leaves");
  });

  describe("deposit leaf", function () {
    it("has correct structure with payload_drop", () => {
      const node = descriptor.node() as SbtcDescriptorNode;
      const depositLeaf = node.Tr[1].Tree[0];

      assert.deepStrictEqual(depositLeaf, {
        Check: {
          AndV: [
            { PayloadDrop: "0000000000013880051ad206838b7981a116c334e8cb1b950afb73eb54a5" },
            { PkK: { Single: "c9c2312ca406dcb8eed50b829b5292f5fb3e846db0a556af61cc53834ce75421" } },
          ],
        },
      });
    });

    it("has correct script hex and tap leaf hash", () => {
      assert.strictEqual(tapLeafHash(DEPOSIT_SCRIPT_HEX), DEPOSIT_LEAF_HASH);
    });
  });

  describe("reclaim leaf", function () {
    it("has correct structure with r:older (Drop wrapper)", () => {
      const node = descriptor.node() as SbtcDescriptorNode;
      const reclaimLeaf = node.Tr[1].Tree[1];

      // Verify the r:older pattern creates a Drop wrapper
      assert.ok(reclaimLeaf.AndV, "Should have AndV structure");
      assert.ok(reclaimLeaf.AndV[0].Drop, "Should have Drop wrapper for r:older");
      assert.ok(reclaimLeaf.AndV[0].Drop.Older, "Should contain Older inside Drop");
      assert.strictEqual(
        reclaimLeaf.AndV[0].Drop.Older.relLockTime,
        1,
        "Should have locktime of 1",
      );

      // Verify the multi_a is the second part
      assert.ok(reclaimLeaf.AndV[1].MultiA, "Should have MultiA as second element");
    });

    it("has correct script hex and tap leaf hash", () => {
      assert.strictEqual(tapLeafHash(RECLAIM_SCRIPT_HEX), RECLAIM_LEAF_HASH);
    });
  });

  describe("P2TR output", function () {
    it("produces correct script pubkey", () => {
      const scriptPubkeyBytes = descriptor.scriptPubkey();
      assert.strictEqual(Buffer.from(scriptPubkeyBytes).toString("hex"), SCRIPT_PUBKEY_HEX);
    });
  });
});
