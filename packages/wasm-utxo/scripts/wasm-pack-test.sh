#!/bin/bash
# Wrapper script for wasm-pack test that sets correct compiler on Mac

# Detect Mac and set LLVM compiler
if [[ "$(uname -s)" == "Darwin" ]]; then
    LLVM_PATH=$(brew --prefix llvm 2>/dev/null)
    if [ -n "$LLVM_PATH" ]; then
        export CC="$LLVM_PATH/bin/clang"
        export AR="$LLVM_PATH/bin/llvm-ar"
    fi
fi

# Run wasm-pack test with all passed arguments
wasm-pack test "$@"

