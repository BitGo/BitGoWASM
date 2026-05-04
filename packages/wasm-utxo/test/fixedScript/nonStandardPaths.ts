/**
 * Tests for wallets with nonstandard derivation paths.
 *
 * Some cold wallets use chain codes that do not follow BitGo convention
 * (0/1 = P2sh, 20/21 = P2wsh, etc.) but still produce valid 2-of-3 P2WSH
 * scripts. This test verifies that parseOutputsWithWalletKeys and
 * parseTransactionWithWalletKeys correctly identify wallet outputs and inputs
 * using key-based derivation matching, independent of the chain code value.
 *
 * A PSBT is constructed programmatically using the WrapPsbt / descriptor API
 * with nonstandard chain codes (0 for external, 1 for internal) on a P2WSH
 * multisig wallet.
 */

import assert from "node:assert";

import { BIP32Interface } from "@bitgo/utxo-lib";
import { getKey } from "@bitgo/utxo-lib/dist/src/testutil";

import { formatNode } from "../../js/ast/index.js";
import { Descriptor, Psbt } from "../../js/index.js";
import { BitGoPsbt, RootWalletKeys } from "../../js/fixedScriptWallet/index.js";

// ─── helpers ────────────────────────────────────────────────────────────────

function xpubWithChain(k: BIP32Interface, chain: number): string {
  return `${k.neutered().toBase58()}/${chain}/*`;
}

/** Build a derivable 2-of-3 P2WSH descriptor with the given chain code. */
function makeWshDescriptor(
  user: BIP32Interface,
  backup: BIP32Interface,
  bitgo: BIP32Interface,
  chain: number,
): Descriptor {
  return Descriptor.fromString(
    formatNode({
      wsh: {
        multi: [
          2,
          xpubWithChain(user, chain),
          xpubWithChain(backup, chain),
          xpubWithChain(bitgo, chain),
        ],
      },
    }),
    "derivable",
  );
}

/** Build a derivable P2WPKH descriptor (for the external output). */
function makeWpkhDescriptor(k: BIP32Interface): Descriptor {
  return Descriptor.fromString(formatNode({ wpkh: `${k.neutered().toBase58()}/*` }), "derivable");
}

/**
 * Construct a PSBT with nonstandard chain codes using the WrapPsbt descriptor API.
 *
 * Layout:
 *   Input 0:   P2WSH (2-of-3), chain=nonStdChain, index=inputIndex  — wallet input
 *   Output 0:  P2WPKH external payment
 *   Output 1:  P2WSH change, chain=nonStdChangeChain, index=changeIndex — wallet change
 */
function buildNonStandardPsbt(
  user: BIP32Interface,
  backup: BIP32Interface,
  bitgo: BIP32Interface,
  external: BIP32Interface,
  opts: {
    nonStdChain: number;
    nonStdChangeChain: number;
    inputIndex: number;
    changeIndex: number;
    inputValue?: bigint;
    paymentValue?: bigint;
    changeValue?: bigint;
  },
): BitGoPsbt {
  const {
    nonStdChain,
    nonStdChangeChain,
    inputIndex,
    changeIndex,
    inputValue = 10_000_000n,
    paymentValue = 6_000_000n,
    changeValue = 3_990_000n,
  } = opts;

  const inputDescAt = makeWshDescriptor(user, backup, bitgo, nonStdChain).atDerivationIndex(
    inputIndex,
  );
  const changeDescAt = makeWshDescriptor(user, backup, bitgo, nonStdChangeChain).atDerivationIndex(
    changeIndex,
  );
  const externalDescAt = makeWpkhDescriptor(external).atDerivationIndex(0);

  const psbt = new Psbt();

  psbt.addInput(
    "0000000000000000000000000000000000000000000000000000000000000001",
    0,
    inputValue,
    Buffer.from(inputDescAt.scriptPubkey()),
  );
  psbt.updateInputWithDescriptor(0, inputDescAt);

  psbt.addOutput(Buffer.from(externalDescAt.scriptPubkey()), paymentValue);
  psbt.addOutput(Buffer.from(changeDescAt.scriptPubkey()), changeValue);
  psbt.updateOutputWithDescriptor(1, changeDescAt);

  return BitGoPsbt.fromBytes(psbt.serialize(), "bitcoin");
}

// ─── tests ───────────────────────────────────────────────────────────────────

describe("nonstandard derivation paths", function () {
  const user = getKey("user");
  const backup = getKey("backup");
  const bitgo = getKey("bitgo");
  const external = getKey("external");

  // Nonstandard: P2WSH but with chain codes 0/1 instead of BitGo convention 20/21
  const NONSTANDARD_CHAIN = 0;
  const NONSTANDARD_CHANGE_CHAIN = 1;
  const INPUT_INDEX = 5;
  const CHANGE_INDEX = 2;

  let psbt: BitGoPsbt;
  let walletKeys: RootWalletKeys;

  before(function () {
    psbt = buildNonStandardPsbt(user, backup, bitgo, external, {
      nonStdChain: NONSTANDARD_CHAIN,
      nonStdChangeChain: NONSTANDARD_CHANGE_CHAIN,
      inputIndex: INPUT_INDEX,
      changeIndex: CHANGE_INDEX,
    });

    // xpubs are the signing root — PSBT paths are [chain, index] relative to them
    walletKeys = RootWalletKeys.withDerivationPrefixes(
      [user.neutered().toBase58(), backup.neutered().toBase58(), bitgo.neutered().toBase58()],
      ["", "", ""],
    );
  });

  it("parseOutputsWithWalletKeys identifies change output despite nonstandard chain code", function () {
    const outputs = psbt.parseOutputsWithWalletKeys(walletKeys);

    assert.strictEqual(outputs.length, 2);
    const [external, change] = outputs;

    assert.strictEqual(external.derivationPath, null, "output 0 should be external");

    assert.notStrictEqual(change.derivationPath, null, "change output must have derivationPath");
    assert.strictEqual(change.derivationPath, `${NONSTANDARD_CHANGE_CHAIN}/${CHANGE_INDEX}`);
    assert.strictEqual(change.scriptId, null, "scriptId must be null (nonstandard chain code)");
  });

  it("parseTransactionWithWalletKeys identifies input and change output", function () {
    const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, {
      replayProtection: { publicKeys: [] },
    });

    assert.strictEqual(parsed.inputs.length, 1);
    assert.strictEqual(parsed.outputs.length, 2);

    const [input] = parsed.inputs;
    assert.strictEqual(input.scriptType, "p2wsh");
    assert.strictEqual(input.derivationPath, `${NONSTANDARD_CHAIN}/${INPUT_INDEX}`);
    assert.strictEqual(input.scriptId, null, "input scriptId must be null (nonstandard chain)");

    const [, change] = parsed.outputs;
    assert.notStrictEqual(change.derivationPath, null);
    assert.strictEqual(change.derivationPath, `${NONSTANDARD_CHANGE_CHAIN}/${CHANGE_INDEX}`);
    assert.strictEqual(change.scriptId, null);
  });
});
