/**
 * Minimal JSON-RPC client for regtest nodes.
 *
 * Covers Bitcoin Core and btcd-style (pearld) quirks needed by the AcidTest
 * regtest loop. Not a full wallet RPC — pearld is walletless.
 *
 * Uses Authorization header (not user:pass@url) because Node's fetch rejects
 * URLs that include credentials.
 */
import type { CoinName } from "../../../js/coinName.js";

export class RpcError extends Error {
  constructor(public rpcError: { code: number; message: string }) {
    super(`RPC error: ${rpcError.message} (code=${rpcError.code})`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export type RpcTxVerbose = {
  txid: string;
  hex: string;
  vout: Array<{
    n: number;
    value: number;
    scriptPubKey: { hex: string; address?: string; addresses?: string[] };
  }>;
};

export type RpcBlockVerbose = {
  hash: string;
  height: number;
  /** bitcoind */ tx?: Array<string | RpcTxVerbose>;
  /** pearld verbosity=2 */ rawtx?: RpcTxVerbose[];
};

function parseRpcUrl(url: string): { endpoint: string; authorization?: string } {
  const parsed = new URL(url);
  const user = decodeURIComponent(parsed.username);
  const pass = decodeURIComponent(parsed.password);
  parsed.username = "";
  parsed.password = "";
  const endpoint = parsed.toString().replace(/\/$/, "");
  if (!user && !pass) {
    return { endpoint };
  }
  const token = Buffer.from(`${user}:${pass}`, "utf8").toString("base64");
  return { endpoint, authorization: `Basic ${token}` };
}

export class RpcClient {
  private id = 0;
  private readonly endpoint: string;
  private readonly authorization?: string;

  constructor(
    public readonly coin: CoinName,
    url: string,
  ) {
    const parsed = parseRpcUrl(url);
    this.endpoint = parsed.endpoint;
    this.authorization = parsed.authorization;
  }

  async exec<T>(method: string, ...params: unknown[]): Promise<T> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (this.authorization) {
      headers.authorization = this.authorization;
    }

    const response = await fetch(this.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        jsonrpc: "1.0",
        id: `${this.id++}`,
        method,
        params,
      }),
    });

    const text = await response.text();
    let body: { result?: T; error?: { code: number; message: string } };
    try {
      body = JSON.parse(text) as typeof body;
    } catch {
      throw new Error(
        `non-JSON RPC response for ${method} (HTTP ${response.status}): ${text.slice(0, 120)}`,
      );
    }

    if (body.error) {
      throw new RpcError(body.error);
    }
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} for ${method}`);
    }
    return body.result;
  }

  async getNetworkInfo(): Promise<{ subversion: string; version?: number }> {
    return this.exec("getnetworkinfo");
  }

  async getBlockCount(): Promise<number> {
    return this.exec("getblockcount");
  }

  async getBlockHash(height: number): Promise<string> {
    return this.exec("getblockhash", height);
  }

  async getBlockVerbose(hash: string, verbosity = 2): Promise<RpcBlockVerbose> {
    return this.exec("getblock", hash, verbosity);
  }

  async getRawTransaction(txid: string): Promise<string> {
    return this.exec("getrawtransaction", txid);
  }

  async getRawTransactionVerbose(txid: string): Promise<RpcTxVerbose> {
    // pearld (btcd) requires verbose as int; bitcoind accepts bool
    return this.exec("getrawtransaction", txid, 1);
  }

  async sendRawTransaction(hex: string): Promise<string> {
    return this.exec("sendrawtransaction", hex);
  }

  /**
   * Mine `n` blocks.
   * - bitcoind: generatetoaddress
   * - pearld: generate (mines to --miningaddr; address arg ignored)
   */
  async generateBlocks(n: number, address?: string): Promise<void> {
    if (this.coin === "pearl" || this.coin === "tpearl" || this.coin === "tpearlreg") {
      await this.exec("generate", n);
      return;
    }
    if (!address) {
      throw new Error(`generatetoaddress requires an address for coin=${this.coin}`);
    }
    await this.exec("generatetoaddress", n, address);
  }

  /** Wait until RPC responds (docker startup). */
  static async forUrlWait(coin: CoinName, url: string, attempts = 120): Promise<RpcClient> {
    const client = new RpcClient(coin, url);
    for (let i = 0; i < attempts; i++) {
      try {
        await client.getBlockCount();
        return client;
      } catch (e) {
        console.error(`[${coin}] ${e}, waiting 1s...`);
        await sleep(1000);
      }
    }
    throw new Error(`could not connect to ${coin} RPC at ${url}`);
  }
}
