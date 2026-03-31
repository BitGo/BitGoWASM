import { strict as assert } from "assert";
import { encodeAddress, encode, decode, validate } from "../js/index.js";

describe("Address", () => {
  const validBounceable = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";
  const validNonBounceable = "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBX1aD";

  describe("validate", () => {
    it("should validate correct bounceable addresses", () => {
      assert.ok(validate(validBounceable));
    });

    it("should validate correct non-bounceable addresses", () => {
      assert.ok(validate(validNonBounceable));
    });

    it("should validate raw hex addresses", () => {
      assert.ok(validate("0:348bcf82746945fc38541c77fdd91d4e347eac200f6f2d9fd62dc08885f0415f"));
    });

    it("should reject invalid addresses", () => {
      assert.ok(!validate("randomString"));
      assert.ok(!validate("0xc4173a804406a365e69dfb297ddfgsdcvf"));
      assert.ok(!validate("5ne7phA48Jrvpn39AtupB8ZkCCAy8gLTfpGihZPuDqen"));
    });
  });

  describe("decode", () => {
    it("should decode bounceable address", () => {
      const decoded = decode(validBounceable);
      assert.equal(decoded.workchainId, 0);
      assert.ok(decoded.isBounceable);
      assert.ok(!decoded.isTestnet);
      assert.equal(decoded.addressHash.length, 32);
    });

    it("should decode non-bounceable address", () => {
      const decoded = decode(validNonBounceable);
      assert.equal(decoded.workchainId, 0);
      assert.ok(!decoded.isBounceable);
      assert.ok(!decoded.isTestnet);
    });

    it("should decode raw hex address", () => {
      const decoded = decode("0:348bcf82746945fc38541c77fdd91d4e347eac200f6f2d9fd62dc08885f0415f");
      assert.equal(decoded.workchainId, 0);
      assert.equal(decoded.addressHash.length, 32);
    });
  });

  describe("encode/decode roundtrip", () => {
    it("should roundtrip bounceable", () => {
      const decoded = decode(validBounceable);
      const encoded = encode(decoded.workchainId, decoded.addressHash, true);
      assert.equal(encoded, validBounceable);
    });

    it("should roundtrip non-bounceable", () => {
      const decoded = decode(validNonBounceable);
      const encoded = encode(decoded.workchainId, decoded.addressHash, false);
      assert.equal(encoded, validNonBounceable);
    });
  });

  describe("encodeAddress", () => {
    const knownPublicKey = new Uint8Array([
      0x7d, 0x6b, 0x1a, 0x21, 0x0b, 0x18, 0x0c, 0xa1, 0x41, 0x26, 0x7c, 0xea, 0x69, 0x56, 0x8a,
      0x6a, 0x4f, 0xf2, 0xd8, 0x49, 0xda, 0x9e, 0x6f, 0x47, 0x6d, 0x04, 0x10, 0x05, 0xd4, 0x47,
      0x6c, 0x6e,
    ]);
    const expectedBounceable = "EQAHgNAYSdWyD3kl2RIl_oSo4lS0ECclh-FDjKETwGtSOcsT";
    const expectedNonBounceable = "UQAHgNAYSdWyD3kl2RIl_oSo4lS0ECclh-FDjKETwGtSOZbW";

    it("should encode a public key to a bounceable address", () => {
      const addr = encodeAddress(knownPublicKey, true);
      assert.equal(addr, expectedBounceable);
    });

    it("should encode a public key to a non-bounceable address", () => {
      const addr = encodeAddress(knownPublicKey, false);
      assert.equal(addr, expectedNonBounceable);
    });

    it("should default to bounceable", () => {
      const addr = encodeAddress(knownPublicKey);
      assert.equal(addr, expectedBounceable);
    });

    it("should produce a valid address", () => {
      const addr = encodeAddress(knownPublicKey, true);
      assert.ok(validate(addr));
    });

    it("should reject invalid public key length", () => {
      assert.throws(() => encodeAddress(new Uint8Array(16)), /public key must be 32 bytes/);
    });

    it("should roundtrip with decode", () => {
      const addr = encodeAddress(knownPublicKey, true);
      const decoded = decode(addr);
      assert.equal(decoded.workchainId, 0);
      assert.ok(decoded.isBounceable);
      assert.ok(!decoded.isTestnet);
    });
  });
});
