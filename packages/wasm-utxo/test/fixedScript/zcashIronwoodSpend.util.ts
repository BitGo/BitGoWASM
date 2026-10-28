import assert from "node:assert";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { ZcashIronwoodBitGoPsbt } from "../../js/fixedScriptWallet/ZcashIronwoodBitGoPsbt.js";

/**
 * One `test/fixtures/zcash/ironwood_spend_*.json` fixture, generated in Rust by the
 * `#[ignore]`d `generate_ts_spend_fixtures` test (under `orchard-proving`):
 *
 * - `request` is what the builder replays through `addShieldedSpends`;
 * - `psbt` is the seeded post-construction PSBT the lifecycle drives;
 * - `outCiphertexts` / `proof` are the viewing-key holder's and prover's responses (they need
 *   the FVK / Halo2, which the TS side does not hold);
 * - `randomizers` / `signatures` are the stand-in signer's round, keyed to the same run's
 *   ciphertexts (the sighash chain depends on them);
 * - `proofRequest` is the exact alpha-patched PCZT `getProofRequest` must return.
 * - `refresh` is the anchor refresh the generator applied before the signing rounds (fresh
 *   witnesses for every spend under the refreshed root), as `updateAnchorAndWitnesses`
 *   replays it;
 */
export type IronwoodSpendFixture = {
  name: string;
  network: "zcashTest";
  blockHeight: number;
  request: {
    anchor: string;
    spends: Array<{
      recipient: string;
      value: string;
      rho: string;
      rseed: string;
      cmx: string;
      witness: { position: number; authPath: string[] };
      nullifier: string;
    }>;
    outputs: Array<{
      recipient: string;
      amount: string;
      memo: string;
      unifiedAddress: string | null;
    }>;
    transparentOutput: { script: string; value: string } | null;
  };
  psbt: string;
  refresh: {
    anchor: string;
    witnesses: Array<{ actionIndex: number; cmx: string; position: number; authPath: string[] }>;
  };
  spendActionIndices: number[];
  outputActionIndices: number[];
  ak: string;
  outCiphertexts: Array<{ actionIndex: number; outCiphertext: string }>;
  randomizers: Array<{ actionIndex: number; alpha: string; rk: string }>;
  sighash: string;
  signatures: Array<{ actionIndex: number; signature: string }>;
  proofRequest: string;
  proof: string;
  expectedTxid: string;
  zip317ConventionalFee: string;
};

export const hex = (value: string): Uint8Array => Buffer.from(value, "hex");
export const base64 = (value: string): Uint8Array => Buffer.from(value, "base64");

const fixtureDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures/zcash");

export function loadFixture(name: string): IronwoodSpendFixture {
  return JSON.parse(
    fs.readFileSync(path.join(fixtureDir, `ironwood_spend_${name}.json`), "utf8"),
  ) as IronwoodSpendFixture;
}

/** A fresh PSBT at the fixture's post-construction state (the deterministic seeded build). */
export function freshPsbt(fixture: IronwoodSpendFixture): ZcashIronwoodBitGoPsbt {
  return ZcashIronwoodBitGoPsbt.fromBytes(base64(fixture.psbt), "zcashTest");
}

/** Asserts `call` throws with the given typed error code. */
export function assertErrorCode(call: () => unknown, expectedCode: string): void {
  try {
    call();
  } catch (err) {
    assert.strictEqual((err as Error & { code?: string }).code, expectedCode);
    return;
  }
  assert.fail(`expected ${expectedCode}, but the call succeeded`);
}
