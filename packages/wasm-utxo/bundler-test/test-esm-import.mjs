/**
 * Test script to verify ESM import works correctly
 * Run with: node --experimental-wasm-modules bundler-test/test-esm-import.mjs
 */

import { Descriptor, Psbt, address, fixedScriptWallet } from "../dist/esm/js/index.js";

console.log("Testing ESM import...\n");

console.log("✓ ESM import successful");
console.log("✓ Descriptor API available");
console.log("✓ Psbt API available");
console.log("✓ address namespace available");
console.log("✓ fixedScriptWallet namespace available");

// Test that we can use the Descriptor API
try {
  const descriptor = Descriptor.fromString(
    "wpkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)",
    "derivable",
  );
  console.log("✓ Descriptor.fromString() works");
  console.log("  Descriptor type:", descriptor.descType());

  // Test address derivation
  const derived = descriptor.atDerivationIndex(0);
  console.log("✓ Descriptor derivation works");
  console.log("  Script pubkey length:", derived.scriptPubkey().length);
} catch (err) {
  console.log("✗ Descriptor test failed:", err.message);
  process.exit(1);
}

console.log("\n✅ All ESM tests passed!");
console.log("\nThis is the primary/recommended way to use this package.");
