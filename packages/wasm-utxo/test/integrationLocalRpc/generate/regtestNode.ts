/**
 * Regtest node helper for wasm-utxo integrationLocalRpc tests.
 *
 * Adapted from BitGoJS utxo-lib
 * `test/integration_local_rpc/generate/regtestNode.ts`, keyed by CoinName
 * instead of utxo-lib Network.
 *
 * Pearl on Apple Silicon: prefer native pearld via WASM_UTXO_PEARLD_BIN
 * (Docker amd64 ZK-PoW mining segfaults under emulation).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

import type { CoinName } from "../../../js/coinName.js";
import { PEARL_MINING_REGTEST_ADDRESS } from "../pearlConstants.js";

const execFileAsync = promisify(execFile);

export type DockerImageParams = {
  image: string;
  /** Daemon binary; omit when the image entrypoint is already the daemon. */
  binary?: string;
  rpcPort: number;
  extraArgsDocker?: string[];
  extraArgsNode?: string[];
  /** btcd-style auth uses -rpcuser/-rpcpass; bitcoind uses -rpcpassword. */
  rpcAuthStyle: "bitcoind" | "btcd";
};

/** Shared credentials for the lifetime of a Node process. */
export const rpcUser = "wasmutxo";
export const rpcPassword = randomBytes(16).toString("hex");

/**
 * Coins that have a dockerized regtest harness.
 * This PR wires Pearl only; other coins are stubs for the shared loop.
 */
export function getDockerParams(coin: CoinName): DockerImageParams {
  switch (coin) {
    case "pearl":
    case "tpearl":
    case "tpearlreg":
      // See indexer-utxo/containers/docker-compose.develop-pearl.yml
      // Mining address = keypath Taproot for privkey 0x01 (HRP rprl).
      // Override with WASM_UTXO_PEARL_DOCKER_IMAGE (e.g. local prl-pearld:latest).
      return {
        image:
          process.env.WASM_UTXO_PEARL_DOCKER_IMAGE ??
          "319156457634.dkr.ecr.us-west-2.amazonaws.com/pearl-fullnode:1.0.2",
        // Force pearld even when the image entrypoint is bash (ECR compose style).
        extraArgsDocker: ["--entrypoint=pearld"],
        rpcPort: 18334,
        rpcAuthStyle: "btcd",
        extraArgsNode: [
          "--regtest",
          "--txindex",
          "--addrindex",
          "--notls",
          `--miningaddr=${PEARL_MINING_REGTEST_ADDRESS}`,
          "--debuglevel=info",
        ],
      };
    default:
      throw new Error(
        `no regtest docker image configured for coin=${coin} yet (Pearl only in this PR)`,
      );
  }
}

export interface Node {
  coin: CoinName;
  rpcPort: number;
  stop(): Promise<void>;
}

function pearlNodeArgs(rpcPort: number, datadir?: string): string[] {
  return [
    "--regtest",
    `--rpcuser=${rpcUser}`,
    `--rpcpass=${rpcPassword}`,
    `--rpclisten=127.0.0.1:${rpcPort}`,
    "--txindex",
    "--addrindex",
    "--notls",
    `--miningaddr=${PEARL_MINING_REGTEST_ADDRESS}`,
    "--debuglevel=info",
    ...(datadir ? [`--datadir=${datadir}`] : []),
  ];
}

function stopProcess(proc: ChildProcess): Promise<void> {
  if (proc.killed || proc.exitCode !== null) {
    return Promise.resolve();
  }
  proc.kill();
  return new Promise((resolve) => {
    proc.on("exit", () => resolve());
    setTimeout(resolve, 5_000);
  });
}

/** Native pearld (WASM_UTXO_PEARLD_BIN) — required for mining on Apple Silicon. */
function getNativePearlNode(coin: CoinName): Node {
  const binary = process.env.WASM_UTXO_PEARLD_BIN;
  if (!binary) {
    throw new Error("WASM_UTXO_PEARLD_BIN is not set");
  }
  const { rpcPort } = getDockerParams(coin);
  const datadir = mkdtempSync(path.join(tmpdir(), "wasm-utxo-pearld-"));
  const stdio: "ignore" | "inherit" =
    process.env.WASM_UTXO_TESTS_LOG_DOCKER === "1" ? "inherit" : "ignore";

  console.log(`[${coin}] starting native pearld (${binary}) datadir=${datadir}`);
  const proc = spawn(binary, pearlNodeArgs(rpcPort, datadir), { stdio });

  return {
    coin,
    rpcPort,
    async stop(): Promise<void> {
      await stopProcess(proc);
      try {
        rmSync(datadir, { recursive: true, force: true });
      } catch {
        // best-effort cleanup
      }
    },
  };
}

export function getRegtestNode(coin: CoinName): Node {
  if (
    (coin === "pearl" || coin === "tpearl" || coin === "tpearlreg") &&
    process.env.WASM_UTXO_PEARLD_BIN
  ) {
    return getNativePearlNode(coin);
  }

  const dockerParams = getDockerParams(coin);
  const { rpcPort } = dockerParams;

  const authArgs =
    dockerParams.rpcAuthStyle === "btcd"
      ? [`--rpcuser=${rpcUser}`, `--rpcpass=${rpcPassword}`, `--rpclisten=0.0.0.0:${rpcPort}`]
      : [
          `-rpcuser=${rpcUser}`,
          `-rpcpassword=${rpcPassword}`,
          `-rpcbind=0.0.0.0:${rpcPort}`,
          `-rpcallowip=0.0.0.0/0`,
        ];

  const args = [
    "run",
    "--rm",
    `--publish=${rpcPort}:${rpcPort}`,
    ...(dockerParams.extraArgsDocker ?? []),
    dockerParams.image,
    ...(dockerParams.binary ? [dockerParams.binary] : []),
    ...authArgs,
    ...(dockerParams.extraArgsNode ?? []),
  ];

  const stdio: "ignore" | "inherit" =
    process.env.WASM_UTXO_TESTS_LOG_DOCKER === "1" ? "inherit" : "ignore";

  console.log(`[${coin}] starting regtest docker…`);
  const proc: ChildProcess = spawn("docker", args, { stdio });

  return {
    coin,
    rpcPort,
    stop(): Promise<void> {
      return stopProcess(proc);
    },
  };
}

export function getRegtestNodeUrl(coin: CoinName): string {
  const { rpcPort } = getDockerParams(coin);
  return `http://${rpcUser}:${rpcPassword}@localhost:${rpcPort}`;
}

export async function getRegtestNodeHelp(
  coin: CoinName,
): Promise<{ stdout: string; stderr: string }> {
  if (process.env.WASM_UTXO_PEARLD_BIN) {
    return execFileAsync(process.env.WASM_UTXO_PEARLD_BIN, ["--help"]);
  }
  const dockerParams = getDockerParams(coin);
  const args = [
    "run",
    "--rm",
    ...(dockerParams.extraArgsDocker ?? []),
    dockerParams.image,
    ...(dockerParams.binary ? [dockerParams.binary] : []),
    "--help",
  ];
  return execFileAsync("docker", args);
}
