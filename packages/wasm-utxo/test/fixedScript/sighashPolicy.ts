import assert from "node:assert";
import { BitGoPsbt, ChainCode } from "../../js/fixedScriptWallet/index.js";
import type { CoinName } from "../../js/coinName.js";
import type { OutputScriptType } from "../../js/fixedScriptWallet/scriptType.js";
import { getKey, getWalletKeysForSeed } from "../../js/testutils/keys.js";

const SEED = "sighash-policy";
const RECIPIENT = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const ATTACKER = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
const INPUT_VALUE = 100_000n;

function userKey(): ReturnType<typeof getKey> {
  return getKey(`${SEED}.0`);
}

/**
 * Build a wallet PSBT with `inputCount` wallet inputs of the given script
 * type. `addWalletInput` stamps each input with the network's default sighash
 * type, mirroring the PSBTs produced by wasm-utxo itself.
 */
function createWalletPsbt(
  coinName: CoinName,
  inputCount: number,
  scriptType: OutputScriptType,
): BitGoPsbt {
  const walletKeys = getWalletKeysForSeed(SEED);
  const psbt = BitGoPsbt.createEmpty(coinName, walletKeys, { version: 2, lockTime: 0 });
  const chain = ChainCode.value(scriptType, "external");
  for (let inputIndex = 0; inputIndex < inputCount; inputIndex++) {
    psbt.addWalletInput(
      {
        txid: inputIndex.toString(16).padStart(2, "0").repeat(32),
        vout: inputIndex,
        value: INPUT_VALUE,
      },
      walletKeys,
      {
        scriptId: { chain, index: inputIndex },
        signPath: scriptType.startsWith("p2tr") ? { signer: "user", cosigner: "bitgo" } : undefined,
      },
    );
  }
  return psbt;
}

function toHex(psbt: BitGoPsbt): string {
  return Buffer.from(psbt.serialize()).toString("hex");
}

function fromHex(hex: string, coinName: CoinName): BitGoPsbt {
  return BitGoPsbt.fromBytes(Buffer.from(hex, "hex"), coinName);
}

function readCompactSize(bytes: Buffer, offset: number): [number, number] {
  const prefix = bytes[offset];
  if (prefix < 0xfd) return [prefix, offset + 1];
  if (prefix === 0xfd) return [bytes.readUInt16LE(offset + 1), offset + 3];
  if (prefix === 0xfe) return [bytes.readUInt32LE(offset + 1), offset + 5];
  return [Number(bytes.readBigUInt64LE(offset + 1)), offset + 9];
}

/**
 * Rewrite (or remove) the BIP-174 PSBT_IN_SIGHASH_TYPE value of a single input
 * in serialized PSBT bytes, simulating a foreign PSBT crafted with an
 * attacker-chosen sighash type.
 */
function rewriteInputSighashType(
  psbtHex: string,
  inputIndex: number,
  sighashType: number | undefined,
): string {
  const bytes = Buffer.from(psbtHex, "hex");
  let offset = 5;

  function readMap(targetInput: boolean): Buffer | undefined {
    while (offset < bytes.length) {
      const entryStart = offset;
      const [keyLength, keyStart] = readCompactSize(bytes, offset);
      offset = keyStart;
      if (keyLength === 0) return undefined;

      const keyType = keyLength === 1 ? bytes[offset] : -1;
      offset += keyLength;
      const [valueLength, valueStart] = readCompactSize(bytes, offset);
      offset = valueStart;
      const valueEnd = valueStart + valueLength;

      if (targetInput && keyType === 0x03) {
        if (sighashType === undefined) {
          return Buffer.concat([bytes.subarray(0, entryStart), bytes.subarray(valueEnd)]);
        }
        if (valueLength !== 4) {
          throw new Error("Expected a four-byte PSBT sighash value");
        }
        bytes.writeUInt32LE(sighashType, valueStart);
        return bytes;
      }
      offset = valueEnd;
    }
    return undefined;
  }

  readMap(false); // global map
  for (let index = 0; index <= inputIndex; index++) {
    const rewritten = readMap(index === inputIndex);
    if (rewritten) return rewritten.toString("hex");
  }
  throw new Error(`No sighash type found for input ${inputIndex}`);
}

function craftPsbt(
  coinName: CoinName,
  inputCount: number,
  scriptType: OutputScriptType,
  inputIndex: number,
  sighashType: number | undefined,
): BitGoPsbt {
  return fromHex(
    rewriteInputSighashType(
      toHex(createWalletPsbt(coinName, inputCount, scriptType)),
      inputIndex,
      sighashType,
    ),
    coinName,
  );
}

describe("BitGoPsbt sighash policy", function () {
  it("reports the declared sighash type of every input", function () {
    const psbt = createWalletPsbt("btc", 2, "p2wsh");
    assert.deepStrictEqual(psbt.getInputSighashTypes(), [0x01, 0x01]);

    const crafted = craftPsbt("btc", 2, "p2wsh", 1, 0x03);
    assert.deepStrictEqual(crafted.getInputSighashTypes(), [0x01, 0x03]);

    const omitted = craftPsbt("btc", 2, "p2wsh", 1, undefined);
    assert.deepStrictEqual(omitted.getInputSighashTypes(), [0x01, undefined]);
  });

  it("accepts SIGHASH_ALL and absent sighash types", function () {
    createWalletPsbt("btc", 1, "p2wsh").assertSighashAllPolicy();
    craftPsbt("btc", 1, "p2wsh", 0, 0x01).assertSighashAllPolicy();
    craftPsbt("btc", 2, "p2wsh", 0, undefined).assertSighashAllPolicy();
  });

  const unsafeSighashModes = [
    ["SIGHASH_NONE", 0x02],
    ["SIGHASH_SINGLE", 0x03],
    ["SIGHASH_ANYONECANPAY", 0x80],
    ["SIGHASH_ALL|ANYONECANPAY", 0x81],
    ["SIGHASH_NONE|ANYONECANPAY", 0x82],
    ["SIGHASH_SINGLE|ANYONECANPAY", 0x83],
  ] as const;

  for (const [name, sighashType] of unsafeSighashModes) {
    it(`rejects ${name}`, function () {
      const psbt = craftPsbt("btc", 1, "p2wsh", 0, sighashType);
      assert.throws(() => psbt.assertSighashAllPolicy(), /Only SIGHASH_ALL/);
    });
  }

  it("rejects an unsafe sighash type on any input and names it", function () {
    // SIGHASH_SINGLE on the second input of a PSBT that has no matching
    // output would produce a signature over the constant "one" hash.
    const psbt = craftPsbt("btc", 2, "p2wsh", 1, 0x03);
    assert.throws(() => psbt.assertSighashAllPolicy(), /Input 1 .*Only SIGHASH_ALL/);
  });

  it("requires the FORKID form of SIGHASH_ALL on BCH-family coins", function () {
    const bch = createWalletPsbt("bch", 1, "p2sh");
    assert.deepStrictEqual(bch.getInputSighashTypes(), [0x41]);
    bch.assertSighashAllPolicy();

    assert.throws(
      () => craftPsbt("bch", 1, "p2sh", 0, 0x01).assertSighashAllPolicy(),
      /Only SIGHASH_ALL/,
    );
    assert.throws(
      () => craftPsbt("bch", 1, "p2sh", 0, 0x42).assertSighashAllPolicy(),
      /Only SIGHASH_ALL/,
    );
    craftPsbt("bch", 1, "p2sh", 0, 0x41).assertSighashAllPolicy();
  });

  it("accepts SIGHASH_DEFAULT only on Taproot inputs", function () {
    const taproot = createWalletPsbt("btc", 1, "p2trLegacy");
    assert.deepStrictEqual(taproot.getInputSighashTypes(), [0x00]);
    taproot.assertSighashAllPolicy();
    craftPsbt("btc", 1, "p2trLegacy", 0, 0x01).assertSighashAllPolicy();
    assert.throws(
      () => craftPsbt("btc", 1, "p2trLegacy", 0, 0x02).assertSighashAllPolicy(),
      /Only SIGHASH_ALL/,
    );

    // SIGHASH_DEFAULT is not a valid ECDSA sighash type
    assert.throws(
      () => craftPsbt("btc", 1, "p2wsh", 0, 0x00).assertSighashAllPolicy(),
      /Only SIGHASH_ALL/,
    );
  });

  it("keeps the policy satisfied when signing wallet PSBTs and binds signatures to the outputs", function () {
    const psbt = createWalletPsbt("btc", 2, "p2wsh");
    psbt.addOutput(RECIPIENT, 190_000n);
    const signedInputIndexes = psbt.sign(userKey());
    assert.deepStrictEqual(signedInputIndexes, [0, 1]);

    psbt.assertSighashAllPolicy();
    for (const inputIndex of signedInputIndexes) {
      assert(psbt.verifySignature(inputIndex, userKey().neutered()), `input ${inputIndex}`);
    }

    // A SIGHASH_ALL signature commits to every output: swapping the
    // recipient output invalidates the signatures.
    const outputValue = psbt.getOutputs()[0].value;
    psbt.removeOutput(0);
    psbt.addOutput(ATTACKER, outputValue);
    for (const inputIndex of [0, 1]) {
      let signatureValid = false;
      try {
        signatureValid = psbt.verifySignature(inputIndex, userKey().neutered());
      } catch {
        // a mismatched sighash may be reported as a verification error
      }
      assert(!signatureValid, `input ${inputIndex} must not validate after an output swap`);
    }
  });

  it("accepts signed BCH PSBTs whose signatures carry SIGHASH_ALL|FORKID", function () {
    const psbt = createWalletPsbt("bch", 1, "p2sh");
    psbt.sign(userKey());
    psbt.assertSighashAllPolicy();
    assert(psbt.verifySignature(0, userKey().neutered()));
  });

  it("accepts signed Taproot PSBTs whose signatures use SIGHASH_DEFAULT", function () {
    const psbt = createWalletPsbt("btc", 1, "p2trLegacy");
    const signedInputIndexes = psbt.sign(userKey());
    assert.deepStrictEqual(signedInputIndexes, [0]);
    psbt.assertSighashAllPolicy();
    assert(psbt.verifySignature(0, userKey().neutered()));
  });
});
