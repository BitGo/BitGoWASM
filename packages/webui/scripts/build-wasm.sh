#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WEBUI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WASM_UTXO_DIR="$(cd "$WEBUI_DIR/../wasm-utxo" && pwd)"
OUT_DIR="$WEBUI_DIR/wasm"

# Auto-detect Mac and use Homebrew LLVM for WASM compilation
# Apple's Clang doesn't support wasm32-unknown-unknown target
if [[ "$(uname -s)" == "Darwin" ]]; then
  HOMEBREW_LLVM="$(brew --prefix llvm 2>/dev/null || true)"
  if [[ -n "$HOMEBREW_LLVM" ]]; then
    export CC="$HOMEBREW_LLVM/bin/clang"
    export AR="$HOMEBREW_LLVM/bin/llvm-ar"
    echo "Using Homebrew LLVM: $HOMEBREW_LLVM"
  fi
fi

echo "Building wasm-utxo with inspect feature..."
rm -rf "$OUT_DIR"
wasm-pack build \
  --no-opt \
  --no-pack \
  --weak-refs \
  "$WASM_UTXO_DIR" \
  --out-dir "$OUT_DIR" \
  --target bundler \
  --features inspect

echo "Optimizing wasm..."
wasm-opt \
  --enable-bulk-memory \
  --enable-nontrapping-float-to-int \
  --enable-sign-ext \
  -Oz \
  "$OUT_DIR"/wasm_utxo_bg.wasm \
  -o "$OUT_DIR"/wasm_utxo_bg.wasm

# Remove .gitignore files that wasm-pack generates
find "$OUT_DIR" -name .gitignore -delete

# Copy .d.ts to wasm-utxo/js/wasm/ so ts-loader (project references) sees inspect types.
# This is safe: js/wasm/ is a build artifact, and the npm publish uses dist/ which is already built.
cp "$OUT_DIR"/wasm_utxo.d.ts "$WASM_UTXO_DIR/js/wasm/"

echo "wasm build complete: $OUT_DIR"
ls -lh "$OUT_DIR"/*.wasm
