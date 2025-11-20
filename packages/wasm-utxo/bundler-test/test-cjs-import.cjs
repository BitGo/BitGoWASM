/**
 * Test script to verify CommonJS compatibility
 * Run with: node bundler-test/test-cjs-import.cjs
 */

console.log("Testing CommonJS require() compatibility...\n");

// Use standard CommonJS require
let wasmUtxo;
try {
  wasmUtxo = require("../dist/cjs/js/index.js");
} catch (error) {
  console.error("✗ require() failed:", error.message);
  process.exit(1);
}

console.log("✓ require() successful from CJS context");
console.log("✓ Available exports:", Object.keys(wasmUtxo).join(", "));

// Test that we can access the main APIs
if (wasmUtxo.Descriptor) {
  console.log("✓ Descriptor API available");
}
if (wasmUtxo.Psbt) {
  console.log("✓ Psbt API available");
}
if (wasmUtxo.address) {
  console.log("✓ address namespace available");
}
if (wasmUtxo.fixedScriptWallet) {
  console.log("✓ fixedScriptWallet namespace available");
}

// Try to use the Descriptor API
try {
  const descriptor = wasmUtxo.Descriptor.fromString(
    "wpkh(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)",
    "derivable",
  );
  console.log("✓ Descriptor.fromString() works");
  console.log("  Descriptor type:", descriptor.descType());
} catch (err) {
  console.log("✗ Descriptor test failed:", err.message);
  process.exit(1);
}

console.log("\n✅ All CJS compatibility tests passed!");
console.log("\nCJS consumers can use standard require() with this package.");
