import * as assert from "assert";
import * as crypto from "crypto";
import {
  formatNode,
  fromDescriptor,
  type DescriptorNode,
  type MiniscriptNode,
} from "../js/ast/index.js";
import { Descriptor, Miniscript, Psbt } from "../js/index.js";
import { getKey, getKeyTriple } from "../js/testutils/keys.js";

// PoX-5 Bitcoin Staking lockup script (P2WSH + CLTV conditional branch).
//
// Provenance:
//   Contract:   stacks-core 4.0.2, pox-5.clar, construct-lockup-script (lines 3711-3732)
//               https://github.com/stacks-network/stacks-core/blob/1b57c3fb6709ab927f9179ab6814f874c84f5303/stackslib/src/chainstate/stacks/boot/pox-5.clar#L3711-L3732
//   Docs:       https://pox-5.vercel.app/docs/development/paired-btc#the-expected-p2wsh-lockup-script
//   Analysis:   https://linear.app/bitgo/document/pox-5-bitcoin-staking-relation-to-existing-sbtc-implementation-bd07e02129f8
//
// This test uses the same lockup-script scaffolding as
// test_pox5_lockup_script_byte_identity in rust-miniscript, but chooses BitGo's
// 2-of-3 staker-unlock subscript. Related TS test vectors:
//   - test/sbtc.ts       — sBTC Taproot deposit/reclaim (payload_drop + r:older extensions)
//   - test/opdrop.ts     — CoreDAO CLTV+OP_DROP P2WSH (r:after extension)
//
// The PoX-5 lockup script uses ONLY standard miniscript fragments — no fork
// extensions needed. The key insight is that `v:sha256(H)` already produces
// `OP_EQUALVERIFY` (not `OP_EQUAL OP_VERIFY`) because `Builder::push_verify()`
// replaces `OP_EQUAL` with `OP_EQUALVERIFY` when a VERIFY variant exists.

const STAKER_KEYS = [
  "02ae7c3c0ebc315a33151a1985ebb1fdcae72b3b91c38e3193c40ebabfffe9c343",
  "0260ba2407f7c75d525db9f171e9b2f3cf5ba3f0d7fc6067b20d4b91585432f974",
  "03eadd6e4300dac62f1d4cf1131a06c5e140911f04245c64934c27510e93dbe843",
];
const EARLY_EXIT_KEY = "020000000000000000000000000000000000000000000000000000000000000002";

// H = sha256(sha256(to-consensus-buff(staker))) — binds lockup to Stacks principal.
// Fixed 32-byte hash for testing; in production derived via computeRegisterPreimage(stxAddress).
const STAKER_HASH = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

// Bond unlock height — absolute CLTV in Bitcoin block height.
// Must be >= get-bond-l1-unlock-height(bondIndex) and < 500_000_000.
const UNLOCK_HEIGHT = 850_000;

// Miniscript expression for the PoX-5 lockup script, built with AST utilities.
//
// and_v(v:or_i(after(n), and_v(v:sha256(H), pk(K_early))), multi(2, K_user, K_backup, K_bitgo))
//
// Compilation:
//   after(n)                → <n> OP_CLTV
//   sha256(H)               → OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUAL
//   v:sha256(H)             → ... OP_EQUALVERIFY  (push_verify replaces OP_EQUAL)
//   pk(K_early)             → <K_early> OP_CHECKSIG
//   and_v(v:sha256, pk)     → <v:sha256> <pk>
//   or_i(after, and_v)      → OP_IF <after> OP_ELSE <and_v> OP_ENDIF
//   v:or_i(...)             → ... OP_ENDIF OP_VERIFY
//   and_v(v:or_i, multi)    → ... OP_VERIFY OP_2 <K_user> <K_backup> <K_bitgo> OP_3 OP_CHECKMULTISIG
const POX5_MINISCRIPT_NODE: MiniscriptNode = {
  and_v: [
    {
      "v:or_i": [
        { after: UNLOCK_HEIGHT },
        {
          and_v: [{ "v:sha256": STAKER_HASH }, { pk: EARLY_EXIT_KEY }],
        },
      ],
    },
    { multi: [2, ...STAKER_KEYS] },
  ],
};
const POX5_DESCRIPTOR_NODE: DescriptorNode = { wsh: POX5_MINISCRIPT_NODE };
const POX5_MINISCRIPT = formatNode(POX5_MINISCRIPT_NODE);
const POX5_DESCRIPTOR = formatNode(POX5_DESCRIPTOR_NODE);

function createEarlyExitPsbt(): {
  psbt: Psbt;
  principalPreimage: Buffer;
} {
  const [user, backup, bitgo] = getKeyTriple("pox5-finalization");
  const earlyExit = getKey("pox5-early-exit");
  const incompleteKey = getKey("pox5-incomplete");
  const principalPreimage = Buffer.alloc(32, 0x42);
  const descriptor = Descriptor.fromString(
    formatNode({
      wsh: {
        and_v: [
          {
            "v:or_i": [
              { after: UNLOCK_HEIGHT },
              {
                and_v: [
                  {
                    "v:sha256": crypto.createHash("sha256").update(principalPreimage).digest("hex"),
                  },
                  { pk: Buffer.from(earlyExit.publicKey).toString("hex") },
                ],
              },
            ],
          },
          {
            multi: [
              2,
              Buffer.from(user.publicKey).toString("hex"),
              Buffer.from(backup.publicKey).toString("hex"),
              Buffer.from(bitgo.publicKey).toString("hex"),
            ],
          },
        ],
      },
    }),
    "definite",
  );
  const scriptPubKey = descriptor.scriptPubkey();
  const psbt = Psbt.create(2, 0);
  psbt.addInput("01".repeat(32), 0, 100_000n, scriptPubKey, 0xfffffffe);
  psbt.addOutput(scriptPubKey, 90_000n);
  psbt.updateInputWithDescriptor(0, descriptor);

  const incompleteDescriptor = Descriptor.fromString(
    formatNode({ wsh: { pk: Buffer.from(incompleteKey.publicKey).toString("hex") } }),
    "definite",
  );
  psbt.addInput("02".repeat(32), 0, 100_000n, incompleteDescriptor.scriptPubkey(), 0xfffffffe);
  psbt.updateInputWithDescriptor(1, incompleteDescriptor);

  for (const key of [user, backup, earlyExit]) {
    assert.ok(key.privateKey, "test key must include private key material");
    psbt.signWithPrv(key.privateKey);
  }
  return { psbt, principalPreimage };
}

// Expected script flow, verified structurally against construct-lockup-script (pox-5.clar:3711-3732).
//
// OP_IF <height> OP_CLTV
// OP_ELSE OP_SIZE <32> OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY <earlyKey> OP_CHECKSIG
// OP_ENDIF OP_VERIFY OP_2 <userKey> <backupKey> <bitgoKey> OP_3 OP_CHECKMULTISIG

describe("PoX-5 Bitcoin Staking lockup script", function () {
  describe("Miniscript encoding", function () {
    let ms: Miniscript;

    before("parse miniscript", function () {
      // Uses standard fragments only — no extensions needed.
      // Unlike sBTC (payload_drop, r:older) and CoreDAO (r:after), PoX-5
      // uses only or_i, after, sha256, v:, and_v, pk, and multi — all standard miniscript.
      ms = Miniscript.fromString(POX5_MINISCRIPT, "segwitv0");
      assert.ok(ms, "Miniscript should parse successfully");
    });

    it("round-trips toString", function () {
      assert.strictEqual(ms.toString(), POX5_MINISCRIPT);
    });

    it("encodes to the expected opcode sequence", function () {
      assert.deepStrictEqual(
        Descriptor.fromString(POX5_DESCRIPTOR, "definite").toAsmString().split(" "),
        [
          "OP_IF",
          "OP_PUSHBYTES_3",
          "50f80c", // unlock-burn-height (850000)
          "OP_CLTV",
          "OP_ELSE",
          "OP_SIZE",
          "OP_PUSHBYTES_1",
          "20", // 32-byte preimage length
          "OP_EQUALVERIFY",
          "OP_SHA256",
          "OP_PUSHBYTES_32",
          STAKER_HASH,
          "OP_EQUALVERIFY", // v: replaces OP_EQUAL with OP_EQUALVERIFY
          "OP_PUSHBYTES_33",
          EARLY_EXIT_KEY,
          "OP_CHECKSIG", // early-unlock-bytes
          "OP_ENDIF",
          "OP_VERIFY", // v: on or_i — no VERIFY variant for OP_ENDIF
          "OP_PUSHNUM_2", // required signatures
          ...STAKER_KEYS.flatMap((key) => ["OP_PUSHBYTES_33", key]),
          "OP_PUSHNUM_3", // total keys
          "OP_CHECKMULTISIG", // BitGo 2-of-3 staker-unlock-bytes
        ],
        "opcode sequence must match PoX-5 construct-lockup-script",
      );
    });
  });

  describe("P2WSH descriptor", function () {
    let desc: Descriptor;

    before("parse descriptor", function () {
      desc = Descriptor.fromString(POX5_DESCRIPTOR, "definite");
      assert.ok(desc, "Descriptor should parse successfully");
    });

    it("produces a valid P2WSH scriptPubKey", function () {
      const spk = Buffer.from(desc.scriptPubkey());
      // P2WSH: OP_0 (0x00) OP_PUSHBYTES_32 (0x20) <32-byte sha256(witness_script)>
      assert.strictEqual(spk.length, 34, "P2WSH scriptPubKey must be 34 bytes");
      assert.strictEqual(spk[0], 0x00, "P2WSH must start with OP_0");
      assert.strictEqual(spk[1], 0x20, "P2WSH must push 32 bytes");
    });

    it("P2WSH program matches sha256 of witness script", function () {
      const spk = Buffer.from(desc.scriptPubkey());
      const witnessScript = Buffer.from(
        Miniscript.fromString(POX5_MINISCRIPT, "segwitv0").encode(),
      );
      const expectedHash = crypto.createHash("sha256").update(witnessScript).digest();
      assert.deepStrictEqual(
        spk.subarray(2),
        expectedHash,
        "P2WSH program must be sha256 of the witness script",
      );
    });

    it("descriptor round-trips toString", function () {
      // Descriptor.toString() appends a BIP-380 checksum (#...); strip it for comparison.
      const toString = desc.toString();
      assert.strictEqual(toString.split("#")[0], POX5_DESCRIPTOR);
    });
  });

  describe("PSBT early-exit finalization", function () {
    it("satisfies the SHA256 branch from standard PSBT preimage metadata", function () {
      const { psbt, principalPreimage } = createEarlyExitPsbt();

      // Leave a second descriptor input incomplete to prove this only finalizes
      // the requested input rather than requiring every input to be complete.
      assert.throws(() => psbt.finalizeInput(0), /satisfy|preimage|finalize/i);
      psbt.addSha256Preimage(0, principalPreimage);

      psbt.finalizeInput(0);

      assert.deepStrictEqual(psbt.getPartialSignatures(0), []);
      assert.throws(() => psbt.finalizeInput(1), /satisfy|signature|finalize/i);
    });

    it("rejects non-32-byte SHA256 preimages", function () {
      const { psbt } = createEarlyExitPsbt();
      assert.throws(() => psbt.addSha256Preimage(0, Buffer.alloc(31)), /32 bytes/);
    });
  });

  describe("AST round-trip", function () {
    it("fromDescriptor produces expected formatNode output", function () {
      const desc = Descriptor.fromString(POX5_DESCRIPTOR, "definite");
      const ast = fromDescriptor(desc);
      const formatted = formatNode(ast);
      assert.strictEqual(formatted, POX5_DESCRIPTOR);
    });
  });
});
