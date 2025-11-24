import * as assert from "assert";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
import { Descriptor } from "../js/index.js";
import { fixtures } from "./descriptorFixtures.js";
import { assertEqualFixture } from "./descriptorUtil.js";
import { fromDescriptor } from "../js/ast/index.js";
import { formatNode } from "../js/ast/index.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function removeChecksum(descriptor: string): string {
  const parts = descriptor.split("#");
  return parts[0];
}

function getScriptPubKeyLength(descType: string): number {
  switch (descType) {
    case "Wpkh":
      return 22;
    case "Sh":
    case "ShWsh":
    case "ShWpkh":
      return 23;
    case "Pkh":
      return 25;
    case "Wsh":
    case "Tr":
      return 34;
    case "Bare":
      throw new Error("cannot determine scriptPubKey length for Bare descriptor");
    default:
      throw new Error("unexpected descriptor type " + descType);
  }
}

function isDerivable(i: number): boolean {
  return ![33, 34, 35, 41, 42, 43].includes(i);
}

function assertKnownDescriptorType(descriptor: Descriptor) {
  switch (descriptor.descType()) {
    case "Bare":
    case "Pkh":
    case "Sh":
    case "ShWsh":
    case "Wsh":
    case "Wpkh":
    case "ShWpkh":
    case "Tr":
      break;
    default:
      throw new Error("unexpected descriptor type " + descriptor.descType());
  }
}

function assertIsErrorUnknownWrapper(error: unknown, wrapper: string) {
  assert.ok(error instanceof Error);
  assert.ok(error.message.includes(`Error: unknown wrapper «${wrapper}»`));
}

describe("Descriptor fixtures", function () {
  it("throws proper error", function () {
    assert.throws(
      () => Descriptor.fromString("lol", "derivable"),
      (err) => err instanceof Error,
    );
  });

  fixtures.valid.forEach((fixture, i) => {
    describe("fixture " + i, function () {
      const isOpDropFixture = i === 59;
      let descriptor: Descriptor;

      before("setup descriptor", function () {
        try {
          descriptor = Descriptor.fromString(fixture.descriptor, "derivable");
        } catch (e) {
          if (isOpDropFixture) {
            assertIsErrorUnknownWrapper(e, "r:");
            return;
          }
          throw e;
        }
      });

      if (isOpDropFixture) {
        // return;
      }

      it("should detect descriptor type", function () {
        Descriptor.fromStringDetectType(fixture.descriptor);
      });

      it("should round-trip (pkType string)", function () {
        let descriptorString = Descriptor.fromString(fixture.descriptor, "string").toString();
        if (fixture.checksumRequired === false) {
          descriptorString = removeChecksum(descriptorString);
        }
        assert.strictEqual(descriptorString, fixture.descriptor);
      });

      it("should parse (pkType derivable)", function () {
        const descriptor = Descriptor.fromString(fixture.descriptor, "derivable");

        if (isDerivable(i)) {
          assert.doesNotThrow(() =>
            Descriptor.fromString(fixture.descriptor, "derivable").atDerivationIndex(0),
          );

          if (descriptor.descType() !== "Tr") {
            assert.doesNotThrow(() => descriptor.atDerivationIndex(0).encode());
          }

          const scriptPubKey = Buffer.from(
            descriptor.atDerivationIndex(fixture.index ?? 0).scriptPubkey(),
          );
          assert.strictEqual(scriptPubKey.toString("hex"), fixture.script);
          const descType = descriptor.descType() as string;
          if (descType !== "Bare") {
            assert.strictEqual(
              scriptPubKey.length,
              getScriptPubKeyLength(descType),
              `Unexpected scriptPubKey length for descriptor ${descType}: ${scriptPubKey.length}`,
            );
          }
        } else {
          // FIXME(BTC-1337): xprvs with hardened derivations are not supported yet
          console.log("Skipping encoding test for fixture", fixture.descriptor, i);
        }

        assert.ok(Number.isInteger(descriptor.maxWeightToSatisfy()));
        assertKnownDescriptorType(descriptor);
      });

      it("can round-trip with formatNode(toWasmNode(.))", function () {
        const ast = fromDescriptor(descriptor);
        assert.strictEqual(formatNode(ast), removeChecksum(descriptor.toString()));
      });

      it("has expected fixture", async function () {
        await assertEqualFixture(__dirname + `/fixtures/${i}.json`, {
          descriptor: descriptor.toString(),
          wasmNode: descriptor.node(),
          ast: fromDescriptor(descriptor),
        });
      });
    });
  });
});
