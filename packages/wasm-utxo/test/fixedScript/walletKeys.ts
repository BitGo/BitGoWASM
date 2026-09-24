import assert from "node:assert";
import * as utxolib from "@bitgo/utxo-lib";

import { RootWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import { outputScript } from "../../js/fixedScriptWallet/address.js";
import { WasmBIP32, WasmRootWalletKeys } from "../../js/wasm/wasm_utxo.js";

type Triple<T> = [T, T, T];

function assertDuplicateRootError(fn: () => unknown): void {
  assert.throws(fn, (error: unknown) => {
    assert.ok(error instanceof Error);
    const wasmError = error as Error & { code?: string };
    return (
      wasmError.code === "WalletKeyError.DuplicateRootKeys" &&
      wasmError.message.includes("Wallet role xpubs must be distinct")
    );
  });
}

describe("fixed-script wallet role key uniqueness", function () {
  const xpubs = utxolib.testutil
    .getKeyTriple("duplicate-wallet-role-keys")
    .map((key) => key.neutered().toBase58()) as Triple<string>;
  const duplicatePairs: Triple<string>[] = [
    [xpubs[0], xpubs[0], xpubs[2]],
    [xpubs[0], xpubs[1], xpubs[0]],
    [xpubs[0], xpubs[1], xpubs[1]],
  ];

  it("rejects repeated roles in TypeScript constructors", function () {
    for (const duplicate of duplicatePairs) {
      assertDuplicateRootError(() => RootWalletKeys.fromXpubs(duplicate));
    }

    assertDuplicateRootError(() => RootWalletKeys.fromXpubs([xpubs[0], xpubs[0], xpubs[0]]));
    assertDuplicateRootError(() =>
      RootWalletKeys.withDerivationPrefixes(
        [xpubs[0], xpubs[0], xpubs[2]],
        ["m/0/0", "m/1/0", "m/2/0"],
      ),
    );
  });

  it("rejects repeated roles in direct WASM constructors", function () {
    const wasmXpubs = xpubs.map((xpub) => WasmBIP32.from_xpub(xpub)) as Triple<WasmBIP32>;

    for (const duplicate of duplicatePairs) {
      const wasmDuplicate = duplicate.map((xpub) => WasmBIP32.from_xpub(xpub)) as Triple<WasmBIP32>;
      assertDuplicateRootError(() => new WasmRootWalletKeys(...wasmDuplicate));
    }

    assertDuplicateRootError(() =>
      WasmRootWalletKeys.with_derivation_prefixes(
        wasmXpubs[0],
        wasmXpubs[0],
        wasmXpubs[2],
        "m/0/0",
        "m/1/0",
        "m/2/0",
      ),
    );
    assertDuplicateRootError(() =>
      new WasmRootWalletKeys(wasmXpubs[0], wasmXpubs[0], wasmXpubs[0]),
    );

    // Failed construction must not poison subsequent operations in the WASM module.
    const validWasmKeys = new WasmRootWalletKeys(...wasmXpubs);
    assert.ok(validWasmKeys.user_key());
    const validKeys = RootWalletKeys.fromXpubs(xpubs);
    assert.ok(outputScript(validKeys, 0, 0, "bitcoin").byteLength > 0);
  });
});
