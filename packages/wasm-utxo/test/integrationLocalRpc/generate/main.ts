/**
 * Generate integrationLocalRpc fixtures against a live regtest node.
 *
 * Usage (from packages/wasm-utxo):
 *   npm run test:integrationLocalRpc:generate
 *
 * Env:
 *   WASM_UTXO_PEARLD_BIN=/path/to/pearld  — native pearld (preferred on Apple Silicon)
 *   WASM_UTXO_PEARL_DOCKER_IMAGE=…       — docker image override
 *   WASM_UTXO_TESTS_LOG_DOCKER=1         — stream node stdout/stderr
 *   WASM_UTXO_REGTEST_COINS=pearl        — comma-separated CoinNames (default: pearl)
 */
import { getRegtestNode, getRegtestNodeUrl } from "./regtestNode.js";
import { RpcClient } from "./RpcClient.js";
import { runAcidTestAgainstRegtest } from "../acidTestRegtest.js";
import { writeFixture } from "../fixtures.js";
import type { CoinName } from "../../../js/coinName.js";

function coinsFromEnv(): CoinName[] {
  const raw = process.env.WASM_UTXO_REGTEST_COINS ?? "pearl";
  return raw.split(",").map((s) => s.trim()) as CoinName[];
}

async function generateForCoin(coin: CoinName): Promise<void> {
  const node = getRegtestNode(coin);
  try {
    const url = getRegtestNodeUrl(coin);
    const rpc = await RpcClient.forUrlWait(coin, url);
    console.log(`[${coin}] RPC ready, network=`, await rpc.getNetworkInfo());

    const fixture = await runAcidTestAgainstRegtest(rpc, coin);
    const path = await writeFixture(coin, "acidTest.fullsigned.json", fixture);
    console.log(`[${coin}] wrote ${path}`);
    console.log(
      `[${coin}] spendTxId=${fixture.spendTxId} inputs=${fixture.inputScriptTypes.join(",")}`,
    );
  } finally {
    console.log(`[${coin}] stopping node…`);
    await node.stop();
  }
}

async function main(): Promise<void> {
  const coins = coinsFromEnv();
  for (const coin of coins) {
    await generateForCoin(coin);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
