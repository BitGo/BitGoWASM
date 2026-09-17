import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashIronwoodWitness } from "../../js/fixedScriptWallet/index.js";
import type { ShardTreeNode } from "../../js/fixedScriptWallet/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesZcash = path.resolve(__dirname, "../fixtures/zcash");

const fixture = JSON.parse(
  fs.readFileSync(path.join(fixturesZcash, "ironwood_witness.json"), "utf8"),
) as {
  cmx: string;
  position: number;
  authPath: string;
  anchor: string;
  wrongAnchor: string;
};

type ShardTreeNodeHex =
  | { type: "Nil" }
  | { type: "Leaf"; hash: string }
  | { type: "Parent"; hash: string | null; left: ShardTreeNodeHex; right: ShardTreeNodeHex };

const shardFixture = JSON.parse(
  fs.readFileSync(path.join(fixturesZcash, "ironwood_witness_shard.json"), "utf8"),
) as {
  position: number;
  shardHeight: number;
  leafCount: string;
  cmx: string;
  shard: ShardTreeNodeHex;
  cap: ShardTreeNodeHex;
  anchor: string;
  wrongAnchor: string;
};

function splitAuthPath(hex: string): Uint8Array[] {
  const bytes = Buffer.from(hex, "hex");
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < 32; i++) {
    siblings.push(new Uint8Array(bytes.subarray(i * 32, (i + 1) * 32)));
  }
  return siblings;
}

function hexNodeToShardTreeNode(node: ShardTreeNodeHex): ShardTreeNode {
  switch (node.type) {
    case "Nil":
      return { type: "Nil" };
    case "Leaf":
      return { type: "Leaf", hash: Buffer.from(node.hash, "hex") };
    case "Parent":
      return {
        type: "Parent",
        hash: node.hash ? Buffer.from(node.hash, "hex") : undefined,
        left: hexNodeToShardTreeNode(node.left),
        right: hexNodeToShardTreeNode(node.right),
      };
  }
}

describe("ZcashIronwoodWitness.build", function () {
  it("builds and validates a witness that recomputes to the expected anchor", function () {
    const witness = ZcashIronwoodWitness.build(
      Buffer.from(fixture.cmx, "hex"),
      fixture.position,
      splitAuthPath(fixture.authPath),
      Buffer.from(fixture.anchor, "hex"),
    );

    assert.strictEqual(witness.position, fixture.position);
    assert.strictEqual(Buffer.from(witness.authPath).toString("hex"), fixture.authPath);
  });

  it("throws when the path does not recompute to the given anchor", function () {
    assert.throws(() =>
      ZcashIronwoodWitness.build(
        Buffer.from(fixture.cmx, "hex"),
        fixture.position,
        splitAuthPath(fixture.authPath),
        Buffer.from(fixture.wrongAnchor, "hex"),
      ),
    );
  });

  it("throws when authPath does not have exactly 32 entries", function () {
    assert.throws(() =>
      ZcashIronwoodWitness.build(
        Buffer.from(fixture.cmx, "hex"),
        fixture.position,
        splitAuthPath(fixture.authPath).slice(0, 31),
        Buffer.from(fixture.anchor, "hex"),
      ),
    );
  });
});

describe("ZcashIronwoodWitness.buildFromShard", function () {
  it("builds and validates a witness that recomputes to the expected anchor", function () {
    const witness = ZcashIronwoodWitness.buildFromShard(
      shardFixture.position,
      shardFixture.shardHeight,
      BigInt(shardFixture.leafCount),
      Buffer.from(shardFixture.cmx, "hex"),
      hexNodeToShardTreeNode(shardFixture.shard),
      hexNodeToShardTreeNode(shardFixture.cap),
      Buffer.from(shardFixture.anchor, "hex"),
    );

    assert.strictEqual(witness.position, shardFixture.position);
  });

  it("throws when the path does not recompute to the given anchor", function () {
    assert.throws(() =>
      ZcashIronwoodWitness.buildFromShard(
        shardFixture.position,
        shardFixture.shardHeight,
        BigInt(shardFixture.leafCount),
        Buffer.from(shardFixture.cmx, "hex"),
        hexNodeToShardTreeNode(shardFixture.shard),
        hexNodeToShardTreeNode(shardFixture.cap),
        Buffer.from(shardFixture.wrongAnchor, "hex"),
      ),
    );
  });
});
