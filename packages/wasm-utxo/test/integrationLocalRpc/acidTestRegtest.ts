/**
 * Run an AcidTest kitchen-sink withdrawal against a live regtest node.
 *
 * Shared loop for every wasm-utxo coin: fund each AcidTest input script type,
 * build/sign via AcidTest.createPsbt with real outpoints, broadcast, return fixture.
 *
 * Pearl-specific: walletless pearld — coinbases go to --miningaddr; we fund
 * destinations by signing key-path spends off-node with the known mining key.
 */
import assert from "node:assert/strict";

import { AcidTest } from "../../js/testutils/AcidTest.js";
import {
  ChainCode,
  outputScript,
  p2shP2pkOutputScript,
  type InputScriptType,
  type OutputScriptType,
} from "../../js/fixedScriptWallet/index.js";
import { Descriptor } from "../../js/index.js";
import { createPsbt } from "../../js/descriptorWallet/psbt/createPsbt.js";
import { signWithKey } from "../../js/descriptorWallet/psbt/sign.js";
import type { CoinName } from "../../js/coinName.js";

import type { RpcClient, RpcTxVerbose } from "./generate/RpcClient.js";
import { toRegtestAddress } from "./regtestAddress.js";
import {
  PEARL_FEE_SATOSHIS,
  PEARL_MINING_DESCRIPTOR,
  PEARL_MINING_PRIVKEY_HEX,
  PEARL_MINING_TAPROOT_SCRIPT,
  PEARL_MIN_HEIGHT,
  PEARL_SIGN_COIN,
} from "./pearlConstants.js";
import type { AcidTestRegtestFixture } from "./fixtures.js";

function inputScriptTypeToOutputScriptType(scriptType: InputScriptType): OutputScriptType {
  switch (scriptType) {
    case "p2sh":
    case "p2shP2wsh":
    case "p2wsh":
    case "p2trLegacy":
      return scriptType;
    case "p2shP2pk":
      return "p2sh";
    case "p2trMusig2ScriptPath":
    case "p2trMusig2KeyPath":
      return "p2trMusig2";
  }
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Pull a mature coinbase UTXO from the mining address stream. */
async function nextMiningCoinbase(
  rpc: RpcClient,
  height: number,
): Promise<{ txid: string; vout: number; value: bigint }> {
  const hash = await rpc.getBlockHash(height);
  const block = await rpc.getBlockVerbose(hash, 2);
  const txs = block.rawtx ?? (block.tx as RpcTxVerbose[]);
  assert.ok(txs?.length, `no txs at height ${height}`);
  const coinbase = typeof txs[0] === "string" ? await rpc.getRawTransactionVerbose(txs[0]) : txs[0];
  const out = coinbase.vout[0];
  const value = BigInt(Math.round(out.value * 1e8));
  return {
    txid: coinbase.txid,
    vout: out.n,
    value,
  };
}

/**
 * Spend a mining coinbase to `destScript` (Taproot key-path), return funding outpoint.
 */
async function fundScriptFromMining(
  rpc: RpcClient,
  coinbaseHeight: number,
  destScript: Uint8Array,
  sendValue: bigint,
): Promise<{ txid: string; vout: number; value: bigint; prevTxHex: string }> {
  const coinbase = await nextMiningCoinbase(rpc, coinbaseHeight);
  assert.ok(
    coinbase.value > sendValue + PEARL_FEE_SATOSHIS,
    `coinbase ${coinbase.value} too small for send ${sendValue}`,
  );

  const descriptor = Descriptor.fromString(PEARL_MINING_DESCRIPTOR, "definite");
  const psbt = createPsbt(
    { version: 2, locktime: 0 },
    [
      {
        hash: coinbase.txid,
        index: coinbase.vout,
        witnessUtxo: {
          script: hexToBytes(PEARL_MINING_TAPROOT_SCRIPT),
          value: coinbase.value,
        },
        descriptor,
      },
    ],
    [
      { script: destScript, value: sendValue },
      {
        script: hexToBytes(PEARL_MINING_TAPROOT_SCRIPT),
        value: coinbase.value - sendValue - PEARL_FEE_SATOSHIS,
      },
    ],
  );

  signWithKey(psbt, hexToBytes(PEARL_MINING_PRIVKEY_HEX));
  // Descriptor Psbt uses finalize() (BitGoPsbt uses finalizeAllInputs)
  psbt.finalize();
  const spendHex = bytesToHex(psbt.extractTransaction().toBytes());
  const txid = await rpc.sendRawTransaction(spendHex);
  await rpc.generateBlocks(1);

  const verbose = await rpc.getRawTransactionVerbose(txid);
  return {
    txid,
    vout: 0,
    value: sendValue,
    prevTxHex: verbose.hex,
  };
}

function walletScriptForInput(
  acid: AcidTest,
  scriptType: InputScriptType,
  index: number,
): Uint8Array {
  if (scriptType === "p2shP2pk") {
    return p2shP2pkOutputScript(acid.getReplayProtectionKey().publicKey);
  }
  const outType = inputScriptTypeToOutputScriptType(scriptType);
  const chain = ChainCode.value(outType, "external");
  return outputScript(acid.rootWalletKeys, chain, index, acid.coin);
}

/**
 * Fund AcidTest inputs, build a real-outpoint fullsigned PSBT, broadcast, return fixture.
 */
export async function runAcidTestAgainstRegtest(
  rpc: RpcClient,
  coin: CoinName,
): Promise<AcidTestRegtestFixture> {
  const signCoin: CoinName = coin === "pearl" || coin === "tpearl" ? PEARL_SIGN_COIN : coin;
  // Default AcidTest config: exclude p2trMusig2ScriptPath (mixed script+key path
  // MuSig2 nonce gen is broken in AcidTest.signPsbt — same as unit suite default).
  const acid = AcidTest.withConfig(signCoin, "fullsigned", "psbt");

  const networkInfo = await rpc.getNetworkInfo();
  let height = await rpc.getBlockCount();
  if (height < PEARL_MIN_HEIGHT) {
    console.log(
      `[${coin}] mining ${PEARL_MIN_HEIGHT - height} blocks to reach ${PEARL_MIN_HEIGHT}`,
    );
    await rpc.generateBlocks(PEARL_MIN_HEIGHT - height);
    height = await rpc.getBlockCount();
  }

  // Coinbases at heights 1..N; start spending from height 1 after maturity
  let nextCoinbaseHeight = 1;
  const outpoints: Array<{ txid: string; vout: number; prevTx: Uint8Array }> = [];

  for (let i = 0; i < acid.inputs.length; i++) {
    const input = acid.inputs[i];
    assert.ok(input.scriptType, "AcidTest inputs must use scriptType");
    const script = walletScriptForInput(acid, input.scriptType, i);
    const addr = toRegtestAddress(script, signCoin);
    console.log(`[${coin}] funding ${input.scriptType} -> ${addr} value=${input.value}`);

    const fundedOut = await fundScriptFromMining(rpc, nextCoinbaseHeight++, script, input.value);
    outpoints.push({
      txid: fundedOut.txid,
      vout: fundedOut.vout,
      prevTx: hexToBytes(fundedOut.prevTxHex),
    });
  }

  const psbt = acid.createPsbt({ outpoints });
  psbt.finalizeAllInputs();
  const spendTx = psbt.extractTransaction();
  const spendTxHex = bytesToHex(spendTx.toBytes());
  const spendTxId = await rpc.sendRawTransaction(spendTxHex);
  await rpc.generateBlocks(1);

  const spendTxVerbose = await rpc.getRawTransactionVerbose(spendTxId);
  assert.strictEqual(spendTxVerbose.txid, spendTxId);

  return {
    coin: signCoin,
    acidTestName: acid.name,
    networkInfo,
    height: await rpc.getBlockCount(),
    inputScriptTypes: acid.inputs.map((i) => {
      assert.ok(i.scriptType);
      return i.scriptType;
    }),
    outputScriptTypes: acid.outputs
      .filter(
        (o): o is { scriptType: OutputScriptType; value: bigint } =>
          "scriptType" in o && !!o.scriptType,
      )
      .map((o) => o.scriptType),
    spendTxHex,
    spendTxId,
    spendTxVerbose,
  };
}
