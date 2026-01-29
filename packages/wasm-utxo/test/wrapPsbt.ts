/**
 * Tests for new WrapPsbt methods introduced in HEAD
 *
 * Tests cover:
 * - signAll / signAllWithEcpair (modern signing API)
 * - inputCount / outputCount (introspection)
 * - getPartialSignatures / hasPartialSignatures (signature inspection)
 * - validateSignatureAtInput / verifySignatureWithKey (signature validation)
 * - unsignedTxId / lockTime / version (metadata access)
 */

import assert from "node:assert";
import { BIP32Interface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { DescriptorNode, formatNode } from "../js/ast/index.js";
import { mockPsbtDefault } from "./psbtFromDescriptor.util.js";
import { Descriptor, Psbt, BIP32, ECPair } from "../js/index.js";
import { toWrappedPsbt } from "./psbt.util.js";

function toKeyWithPath(k: BIP32Interface, path = "*"): string {
  return k.neutered().toBase58() + "/" + path;
}

function toKeyPlainXOnly(k: Buffer): string {
  return k.subarray(1).toString("hex");
}

function fromNodes(node: DescriptorNode, type: "definite" | "derivable") {
  return Descriptor.fromString(formatNode(node), type);
}

const a = getKey("a");
const b = getKey("b");
const c = getKey("c");
const external = getKey("external");

describe("WrapPsbt new methods", function () {
  describe("metadata methods", function () {
    it("inputCount returns correct count", function () {
      const psbt = new Psbt();
      assert.strictEqual(psbt.inputCount(), 0);

      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        100000n,
        Buffer.alloc(34, 0),
      );
      assert.strictEqual(psbt.inputCount(), 1);

      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000002",
        0,
        200000n,
        Buffer.alloc(34, 0),
      );
      assert.strictEqual(psbt.inputCount(), 2);
    });

    it("outputCount returns correct count", function () {
      const psbt = new Psbt();
      assert.strictEqual(psbt.outputCount(), 0);

      psbt.addOutput(Buffer.alloc(34, 0), 50000n);
      assert.strictEqual(psbt.outputCount(), 1);

      psbt.addOutput(Buffer.alloc(34, 0), 40000n);
      assert.strictEqual(psbt.outputCount(), 2);
    });

    it("version returns correct value", function () {
      const psbt1 = new Psbt();
      assert.strictEqual(psbt1.version(), 2);

      const psbt2 = new Psbt(1);
      assert.strictEqual(psbt2.version(), 1);
    });

    it("lockTime returns correct value", function () {
      const psbt1 = new Psbt();
      assert.strictEqual(psbt1.lockTime(), 0);

      const psbt2 = new Psbt(2, 500000);
      assert.strictEqual(psbt2.lockTime(), 500000);
    });

    it("unsignedTxId returns consistent txid", function () {
      const psbt = new Psbt();
      psbt.addInput(
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        100000n,
        Buffer.alloc(34, 0),
      );
      psbt.addOutput(Buffer.alloc(34, 0), 90000n);

      const txid1 = psbt.unsignedTxId();
      const txid2 = psbt.unsignedTxId();

      assert.strictEqual(typeof txid1, "string");
      assert.strictEqual(txid1.length, 64);
      assert.strictEqual(txid1, txid2);
    });
  });

  describe("hasPartialSignatures", function () {
    it("returns false for unsigned input", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(0), false);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(1), false);
    });

    it("returns true after signing (ECDSA)", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      assert.strictEqual(wrappedPsbt.hasPartialSignatures(0), true);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(1), true);
    });

    it("returns true after signing (Taproot)", function () {
      const descriptor = fromNodes(
        { tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]] },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      assert.strictEqual(wrappedPsbt.hasPartialSignatures(0), true);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(1), true);
    });

    it("throws for out of bounds input index", function () {
      const psbt = new Psbt();
      assert.throws(() => psbt.hasPartialSignatures(0), /out of bounds/);
    });
  });

  describe("getPartialSignatures", function () {
    it("returns empty array for unsigned input", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      const sigs = wrappedPsbt.getPartialSignatures(0);

      assert.ok(Array.isArray(sigs));
      assert.strictEqual(sigs.length, 0);
    });

    it("returns signatures after signing (ECDSA)", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      const sigs = wrappedPsbt.getPartialSignatures(0);
      assert.ok(Array.isArray(sigs));
      assert.strictEqual(sigs.length, 1);
      assert.ok(sigs[0].pubkey instanceof Uint8Array);
      assert.ok(sigs[0].signature instanceof Uint8Array);
      assert.strictEqual(sigs[0].pubkey.length, 33);
    });

    it("returns multiple signatures after multiple signings", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());
      wrappedPsbt.signWithXprv(b.toBase58());

      const sigs = wrappedPsbt.getPartialSignatures(0);
      assert.strictEqual(sigs.length, 2);
    });

    it("throws for out of bounds input index", function () {
      const psbt = new Psbt();
      assert.throws(() => psbt.getPartialSignatures(0), /out of bounds/);
    });
  });

  describe("signAll with BIP32", function () {
    it("signs all inputs with BIP32 key (ECDSA)", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      const bip32Key = BIP32.fromBase58(a.toBase58());

      // Pass the underlying WASM instance
      const result = wrappedPsbt.signAll(bip32Key.wasm);

      assert.ok(result);
      assert.ok(0 in result);
      assert.ok(1 in result);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(0), true);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(1), true);
    });

    it("signs all inputs with BIP32 key (Taproot)", function () {
      const descriptor = fromNodes(
        { tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]] },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      const bip32Key = BIP32.fromBase58(a.toBase58());

      // Pass the underlying WASM instance
      const result = wrappedPsbt.signAll(bip32Key.wasm);

      assert.ok(result);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(0), true);
      assert.strictEqual(wrappedPsbt.hasPartialSignatures(1), true);
    });
  });

  describe("signAllWithEcpair", function () {
    it("signs inputs with ECPair key", function () {
      const descriptor = fromNodes(
        {
          tr: [
            toKeyPlainXOnly(external.publicKey),
            [
              { pk: toKeyPlainXOnly(external.publicKey) },
              {
                or_b: [
                  { pk: toKeyPlainXOnly(external.publicKey) },
                  { "s:pk": toKeyPlainXOnly(a.publicKey) },
                ],
              },
            ],
          ],
        },
        "definite",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      assert(a.privateKey);
      const ecpair = ECPair.fromPrivateKey(a.privateKey);

      // Pass the underlying WASM instance
      const result = wrappedPsbt.signAllWithEcpair(ecpair.wasm);

      assert.ok(result);
    });
  });

  describe("verifySignatureWithKey", function () {
    it("returns false for unsigned input", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      const bip32Key = BIP32.fromBase58(a.neutered().toBase58());

      // Pass the underlying WASM instance
      assert.strictEqual(wrappedPsbt.verifySignatureWithKey(0, bip32Key.wasm), false);
    });

    it("returns true for signed input with matching key (ECDSA)", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      // Need to derive to the correct path for verification
      const derivedKey = BIP32.fromBase58(a.derive(0).neutered().toBase58());
      // Pass the underlying WASM instance
      assert.strictEqual(wrappedPsbt.verifySignatureWithKey(0, derivedKey.wasm), true);
    });

    it("returns false for non-matching key", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      // Use a different key (b derived) - should not match signature from a
      const derivedKey = BIP32.fromBase58(b.derive(0).neutered().toBase58());
      // Pass the underlying WASM instance
      assert.strictEqual(wrappedPsbt.verifySignatureWithKey(0, derivedKey.wasm), false);
    });

    it("returns true for Taproot script path signature", function () {
      // For Taproot, test script path signing with key 'b' (not key path with 'a')
      // since key path verification requires tweaked key handling
      const descriptor = fromNodes(
        { tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]] },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      // Sign with 'b' which creates a script path signature
      wrappedPsbt.signWithXprv(b.toBase58());

      const derivedKey = BIP32.fromBase58(b.derive(0).neutered().toBase58());
      // Pass the underlying WASM instance
      assert.strictEqual(wrappedPsbt.verifySignatureWithKey(0, derivedKey.wasm), true);
    });

    it("throws for out of bounds input index", function () {
      const psbt = new Psbt();
      const bip32Key = BIP32.fromBase58(a.neutered().toBase58());
      // Pass the underlying WASM instance
      assert.throws(() => psbt.verifySignatureWithKey(0, bip32Key.wasm), /out of bounds/);
    });
  });

  describe("validateSignatureAtInput", function () {
    it("returns false for unsigned input", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      const pubkey = a.derive(0).publicKey;

      assert.strictEqual(wrappedPsbt.validateSignatureAtInput(0, pubkey), false);
    });

    it("returns true for signed input with matching pubkey (ECDSA)", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      const pubkey = a.derive(0).publicKey;
      assert.strictEqual(wrappedPsbt.validateSignatureAtInput(0, pubkey), true);
    });

    it("returns false for non-matching pubkey", function () {
      const descriptor = fromNodes(
        { wsh: { multi: [2, toKeyWithPath(a), toKeyWithPath(b), toKeyWithPath(c)] } },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      wrappedPsbt.signWithXprv(a.toBase58());

      const pubkey = b.derive(0).publicKey;
      assert.strictEqual(wrappedPsbt.validateSignatureAtInput(0, pubkey), false);
    });

    it("validates Taproot script path with x-only pubkey", function () {
      // For Taproot, test script path validation with key 'b'
      // since key path verification requires tweaked key handling
      const descriptor = fromNodes(
        { tr: [toKeyWithPath(a), [{ pk: toKeyWithPath(b) }, { pk: toKeyWithPath(c) }]] },
        "derivable",
      );
      const psbt = mockPsbtDefault({
        descriptorSelf: descriptor,
        descriptorOther: Descriptor.fromString(
          formatNode({ wpkh: toKeyWithPath(external) }),
          "derivable",
        ),
      });

      const wrappedPsbt = toWrappedPsbt(psbt);
      // Sign with 'b' which creates a script path signature
      wrappedPsbt.signWithXprv(b.toBase58());

      // Use x-only pubkey (32 bytes, without the prefix)
      const xOnlyPubkey = b.derive(0).publicKey.subarray(1);
      assert.strictEqual(xOnlyPubkey.length, 32);
      assert.strictEqual(wrappedPsbt.validateSignatureAtInput(0, xOnlyPubkey), true);
    });

    it("throws for out of bounds input index", function () {
      const psbt = new Psbt();
      assert.throws(() => psbt.validateSignatureAtInput(0, Buffer.alloc(33)), /out of bounds/);
    });
  });

  describe("clone", function () {
    it("creates independent copy", function () {
      const psbt1 = new Psbt(2, 100);
      psbt1.addInput(
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        100000n,
        Buffer.alloc(34, 0),
      );
      psbt1.addOutput(Buffer.alloc(34, 0), 90000n);

      const psbt2 = psbt1.clone();

      assert.strictEqual(psbt1.inputCount(), psbt2.inputCount());
      assert.strictEqual(psbt1.outputCount(), psbt2.outputCount());
      assert.strictEqual(psbt1.version(), psbt2.version());
      assert.strictEqual(psbt1.lockTime(), psbt2.lockTime());
      assert.strictEqual(psbt1.unsignedTxId(), psbt2.unsignedTxId());

      // Modifying one should not affect the other
      psbt2.addOutput(Buffer.alloc(34, 0), 10000n);
      assert.strictEqual(psbt1.outputCount(), 1);
      assert.strictEqual(psbt2.outputCount(), 2);
    });
  });
});
