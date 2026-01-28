/**
 * Signing Performance Benchmark
 *
 * Benchmarks PSBT signing performance for different script types and input counts.
 * Tests both bulk signing (sign(key)) and per-input signing (signInput(i, key)).
 *
 * Script types tested:
 * - p2sh (chain 0/1)
 * - p2shP2wsh (chain 10/11)
 * - p2wsh (chain 20/21)
 * - p2tr script path (chain 30/31) - "p2trLegacy"
 * - p2trMusig2 keypath (chain 40/41)
 *
 * Run: npx mocha test/benchmark/signing.ts --timeout 300000
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { BIP32 } from "../../js/bip32.js";
import { BitGoPsbt, RootWalletKeys, type NetworkName } from "../../js/fixedScriptWallet/index.js";
import type { IWalletKeys } from "../../js/fixedScriptWallet/RootWalletKeys.js";
import type { BIP32Interface } from "../../js/bip32.js";
import type { SignPath } from "../../js/fixedScriptWallet/BitGoPsbt.js";

type Triple<T> = [T, T, T];

// Script type configuration
type ScriptTypeConfig = {
  name: string;
  chain: number; // external chain
  needsSignPath: boolean;
  signPath?: SignPath;
  isMuSig2KeyPath?: boolean;
};

const SCRIPT_TYPES: ScriptTypeConfig[] = [
  { name: "p2sh", chain: 0, needsSignPath: false },
  { name: "p2shP2wsh", chain: 10, needsSignPath: false },
  { name: "p2wsh", chain: 20, needsSignPath: false },
  {
    name: "p2trLegacy",
    chain: 30,
    needsSignPath: true,
    signPath: { signer: "user", cosigner: "bitgo" },
  },
  {
    name: "p2trMusig2KeyPath",
    chain: 40,
    needsSignPath: true,
    signPath: { signer: "user", cosigner: "bitgo" },
    isMuSig2KeyPath: true,
  },
];

const INPUT_COUNTS = [10, 200, 500, 1000];

function createTestWalletKeys(): { keys: RootWalletKeys; xprivs: Triple<BIP32> } {
  // Create three deterministic keys from seeds
  const seeds = [
    Buffer.alloc(32, 0x01), // user
    Buffer.alloc(32, 0x02), // backup
    Buffer.alloc(32, 0x03), // bitgo
  ];

  const xprivs = seeds.map((seed) => BIP32.fromSeed(seed)) as Triple<BIP32>;
  const xpubs = xprivs.map((k) => k.neutered()) as unknown as Triple<BIP32Interface>;

  const walletKeysLike: IWalletKeys = {
    triple: xpubs,
    derivationPrefixes: ["0/0", "0/0", "0/0"],
  };

  return {
    keys: RootWalletKeys.from(walletKeysLike),
    xprivs,
  };
}

function createPsbtWithInputs(
  inputCount: number,
  scriptType: ScriptTypeConfig,
  walletKeys: RootWalletKeys,
): BitGoPsbt {
  const network: NetworkName = "bitcoin";

  const psbt = BitGoPsbt.createEmpty(network, walletKeys, {
    version: 2,
    lockTime: 0,
  });

  // Add inputs
  for (let i = 0; i < inputCount; i++) {
    // Create a unique txid for each input (32 bytes hex = 64 chars)
    const txidBytes = Buffer.alloc(32);
    txidBytes.writeUInt32BE(i, 0);
    const txid = txidBytes.toString("hex");

    const inputOptions = {
      txid,
      vout: 0,
      value: BigInt(100000), // 0.001 BTC per input
      sequence: 0xfffffffe,
    };

    const walletOptions: {
      scriptId: { chain: number; index: number };
      signPath?: SignPath;
    } = {
      scriptId: { chain: scriptType.chain, index: i },
    };

    if (scriptType.needsSignPath && scriptType.signPath) {
      walletOptions.signPath = scriptType.signPath;
    }

    psbt.addWalletInput(inputOptions, walletKeys, walletOptions);
  }

  // Add a single output (change)
  const changeChain = scriptType.chain + 1; // internal chain
  psbt.addWalletOutput(walletKeys, {
    chain: changeChain,
    index: 0,
    value: BigInt(inputCount * 100000 - 10000), // total minus fee
  });

  return psbt;
}

type BenchmarkResult = {
  scriptType: string;
  inputCount: number;
  bulkSignMs: number;
  perInputSignMs: number | null; // null if skipped (only run for 10 inputs)
  bulkSignPerInputMs: number;
  perInputSignPerInputMs: number | null;
};

function benchmarkBulkSign(
  psbt: BitGoPsbt,
  _walletKeys: RootWalletKeys,
  xprivs: Triple<BIP32>,
  scriptType: ScriptTypeConfig,
): number {
  // Clone PSBT for this benchmark
  const testPsbt = BitGoPsbt.fromBytes(psbt.serialize(), "bitcoin");

  // For MuSig2, generate nonces first (not timed)
  if (scriptType.isMuSig2KeyPath) {
    testPsbt.generateMusig2Nonces(xprivs[0]); // user
    testPsbt.generateMusig2Nonces(xprivs[2]); // bitgo
  }

  const start = performance.now();

  // Sign with user key - the new API handles both ECDSA and MuSig2 in one call
  testPsbt.sign(xprivs[0]);

  // Sign with bitgo key (second signer for 2-of-3)
  testPsbt.sign(xprivs[2]);

  const end = performance.now();
  return end - start;
}

function benchmarkPerInputSign(
  psbt: BitGoPsbt,
  walletKeys: RootWalletKeys,
  xprivs: Triple<BIP32>,
  scriptType: ScriptTypeConfig,
): number {
  // Clone PSBT for this benchmark
  const testPsbt = BitGoPsbt.fromBytes(psbt.serialize(), "bitcoin");

  const parsed = testPsbt.parseTransactionWithWalletKeys(walletKeys, { publicKeys: [] });

  // For MuSig2, generate nonces first (not timed)
  if (scriptType.isMuSig2KeyPath) {
    testPsbt.generateMusig2Nonces(xprivs[0]); // user
    testPsbt.generateMusig2Nonces(xprivs[2]); // bitgo
  }

  const start = performance.now();

  // Sign each input individually with user key
  for (let i = 0; i < parsed.inputs.length; i++) {
    testPsbt.signInput(i, xprivs[0]);
  }

  // Sign each input individually with bitgo key
  for (let i = 0; i < parsed.inputs.length; i++) {
    testPsbt.signInput(i, xprivs[2]);
  }

  const end = performance.now();
  return end - start;
}

function runBenchmark(
  scriptType: ScriptTypeConfig,
  inputCount: number,
  walletKeys: RootWalletKeys,
  xprivs: Triple<BIP32>,
): BenchmarkResult {
  // Create PSBT
  const psbt = createPsbtWithInputs(inputCount, scriptType, walletKeys);

  // Run bulk sign benchmark
  const bulkSignMs = benchmarkBulkSign(psbt, walletKeys, xprivs, scriptType);

  // Run per-input sign benchmark only for 10 inputs (too slow for larger counts)
  const perInputSignMs =
    inputCount === 10 ? benchmarkPerInputSign(psbt, walletKeys, xprivs, scriptType) : null;

  return {
    scriptType: scriptType.name,
    inputCount,
    bulkSignMs,
    perInputSignMs,
    bulkSignPerInputMs: bulkSignMs / inputCount,
    perInputSignPerInputMs: perInputSignMs !== null ? perInputSignMs / inputCount : null,
  };
}

function formatResults(results: BenchmarkResult[]): string {
  const lines: string[] = [];

  lines.push("=".repeat(100));
  lines.push("SIGNING BENCHMARK RESULTS");
  lines.push("=".repeat(100));
  lines.push("");

  // Group by script type
  const byScriptType = new Map<string, BenchmarkResult[]>();
  for (const r of results) {
    const existing = byScriptType.get(r.scriptType) ?? [];
    existing.push(r);
    byScriptType.set(r.scriptType, existing);
  }

  for (const [scriptType, scriptResults] of byScriptType) {
    lines.push(`\n${scriptType.toUpperCase()}`);
    lines.push("-".repeat(100));
    lines.push(
      "| Inputs | Bulk (ms) | Per-Input (ms) | Bulk/Input (ms) | PerInput/Input (ms) | Ratio |",
    );
    lines.push(
      "|--------|-----------|----------------|-----------------|---------------------|-------|",
    );

    for (const r of scriptResults) {
      const perInputStr =
        r.perInputSignMs !== null ? r.perInputSignMs.toFixed(1).padStart(14) : "-".padStart(14);
      const perInputPerInputStr =
        r.perInputSignPerInputMs !== null
          ? r.perInputSignPerInputMs.toFixed(3).padStart(19)
          : "-".padStart(19);
      const ratioStr =
        r.perInputSignMs !== null
          ? (r.perInputSignMs / r.bulkSignMs).toFixed(2).padStart(5) + "x"
          : "-".padStart(6);
      lines.push(
        `| ${r.inputCount.toString().padStart(6)} | ${r.bulkSignMs.toFixed(1).padStart(9)} | ${perInputStr} | ${r.bulkSignPerInputMs.toFixed(3).padStart(15)} | ${perInputPerInputStr} | ${ratioStr} |`,
      );
    }
  }

  lines.push("");
  lines.push("=".repeat(100));

  // JSON output for easy comparison
  lines.push("\nJSON Results (for automated comparison):");
  lines.push(JSON.stringify(results, null, 2));

  return lines.join("\n");
}

describe("Signing Benchmark", function () {
  // Increase timeout for benchmarks
  this.timeout(300000); // 5 minutes

  let walletKeys: RootWalletKeys;
  let xprivs: Triple<BIP32>;
  const allResults: BenchmarkResult[] = [];

  before(function () {
    const testKeys = createTestWalletKeys();
    walletKeys = testKeys.keys;
    xprivs = testKeys.xprivs;
  });

  for (const scriptType of SCRIPT_TYPES) {
    describe(`${scriptType.name}`, function () {
      for (const inputCount of INPUT_COUNTS) {
        it(`should benchmark ${inputCount} inputs`, function () {
          console.log(`\nBenchmarking ${scriptType.name} with ${inputCount} inputs...`);

          const result = runBenchmark(scriptType, inputCount, walletKeys, xprivs);
          allResults.push(result);

          console.log(`  Bulk sign: ${result.bulkSignMs.toFixed(1)}ms`);
          if (result.perInputSignMs !== null) {
            console.log(`  Per-input sign: ${result.perInputSignMs.toFixed(1)}ms`);
            console.log(
              `  Ratio (per-input/bulk): ${(result.perInputSignMs / result.bulkSignMs).toFixed(2)}x`,
            );
          } else {
            console.log(`  Per-input sign: skipped (only run for 10 inputs)`);
          }
        });
      }
    });
  }

  after(function () {
    const output = formatResults(allResults);
    console.log("\n" + output);

    // Write results to file
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const resultsDir = path.join(__dirname, "results");
    if (!fs.existsSync(resultsDir)) {
      fs.mkdirSync(resultsDir, { recursive: true });
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const resultsFile = path.join(resultsDir, `benchmark-${timestamp}.txt`);
    fs.writeFileSync(resultsFile, output);
    console.log(`\nResults written to: ${resultsFile}`);
  });
});
