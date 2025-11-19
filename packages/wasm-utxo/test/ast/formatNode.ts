import * as assert from "assert";

import { formatNode } from "../../js/ast/index.js";

describe("formatNode", function () {
  it("formats simple nodes", function () {
    assert.strictEqual(formatNode({ pk: "lol" }), "pk(lol)");
    assert.strictEqual(formatNode({ after: 1 }), "after(1)");
    assert.strictEqual(
      formatNode({ and_v: [{ after: 1 }, { after: 1 }] }),
      "and_v(after(1),after(1))",
    );
    // taproot single key
    assert.strictEqual(formatNode({ tr: "k" }), "tr(k)");
    // key with single-node taproot tree
    assert.strictEqual(formatNode({ tr: ["k", { pk: "k1" }] }), "tr(k,pk(k1))");
    // key with multi-node taproot tree
    assert.strictEqual(
      formatNode({ tr: ["k", [{ pk: "k1" }, { pk: "k2" }]] }),
      "tr(k,{pk(k1),pk(k2)})",
    );
  });
});
