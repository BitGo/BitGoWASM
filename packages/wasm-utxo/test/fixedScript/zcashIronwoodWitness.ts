import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { ZcashIronwoodWitness } from "../../js/fixedScriptWallet/index.js";

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

function splitAuthPath(hex: string): Uint8Array[] {
  const bytes = Buffer.from(hex, "hex");
  const siblings: Uint8Array[] = [];
  for (let i = 0; i < 32; i++) {
    siblings.push(new Uint8Array(bytes.subarray(i * 32, (i + 1) * 32)));
  }
  return siblings;
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
