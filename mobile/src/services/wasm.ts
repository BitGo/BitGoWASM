import type {
  ParsedInput,
  ParsedOutput,
  ParsedTransaction,
  PsbtHandle,
  SignatureInfo,
  WalletKeysHandle,
} from "../types/index.ts";
import { WasmState } from "../types/index.ts";
import { BIP32, fixedScriptWallet } from "@bitgo/wasm-utxo";

const { BitGoPsbt, RootWalletKeys } = fixedScriptWallet;
type BitGoPsbtInstance = fixedScriptWallet.BitGoPsbt;
type RootWalletKeysInstance = fixedScriptWallet.RootWalletKeys;

// ---------------------------------------------------------------------------
// WASM service — wraps @bitgo/wasm-utxo APIs for the rest of the app.
// ---------------------------------------------------------------------------

// Store init state on globalThis so it survives Vite HMR module reloads.
// Without this, HMR re-evaluates this module (resetting a local `let` to
// Uninitialized) while React state in App.tsx still thinks WASM is ready.
const WASM_STATE_KEY = "__bitgo_wasm_state__";

function getState(): WasmState {
  return (
    ((globalThis as Record<string, unknown>)[WASM_STATE_KEY] as WasmState) ??
    WasmState.Uninitialized
  );
}

function setState(s: WasmState): void {
  (globalThis as Record<string, unknown>)[WASM_STATE_KEY] = s;
}

/** Initialize the WASM module. Call once on app startup. */
export async function initWasm(): Promise<void> {
  if (getState() === WasmState.Ready) return;
  setState(WasmState.Loading);
  try {
    // WASM auto-initializes on import (wasm_utxo.js sets the module at load time).
    // Verify it's functional by performing a lightweight parse operation.
    // Use fromBase58 with a known valid xpub as a smoke test.
    BIP32.fromBase58(SMOKE_TEST_XPUB);
    setState(WasmState.Ready);
  } catch (err) {
    setState(WasmState.Error);
    throw err;
  }
}

export function getWasmState(): WasmState {
  return getState();
}

const SMOKE_TEST_XPUB =
  "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

function assertReady(): void {
  if (getState() === WasmState.Ready) return;

  // Self-heal: state flag may have been lost (e.g., HMR replaced this module
  // after initWasm() ran with the old code). If the WASM module is actually
  // functional, recover instead of crashing.
  try {
    BIP32.fromBase58(SMOKE_TEST_XPUB);
    setState(WasmState.Ready);
  } catch {
    throw new Error(`WASM not ready (state: ${getState()}). Call initWasm() first.`);
  }
}

// ---------------------------------------------------------------------------
// Internal helpers for opaque handles
// ---------------------------------------------------------------------------

function wrapPsbt(psbt: BitGoPsbtInstance): PsbtHandle {
  return { _tag: "PsbtHandle" as const, _inner: psbt };
}

function unwrapPsbt(handle: PsbtHandle): BitGoPsbtInstance {
  return handle._inner as BitGoPsbtInstance;
}

function wrapKeys(keys: RootWalletKeysInstance): WalletKeysHandle {
  return { _tag: "WalletKeysHandle" as const, _inner: keys };
}

function unwrapKeys(handle: WalletKeysHandle): RootWalletKeysInstance {
  return handle._inner as RootWalletKeysInstance;
}

// ---------------------------------------------------------------------------
// Wallet keys
// ---------------------------------------------------------------------------

/** Create a RootWalletKeys handle from the three wallet xpubs. */
export function createWalletKeys(
  userXpub: string,
  backupXpub: string,
  bitgoXpub: string,
): WalletKeysHandle {
  assertReady();
  const keys = RootWalletKeys.fromXpubs([userXpub, backupXpub, bitgoXpub]);
  return wrapKeys(keys);
}

// ---------------------------------------------------------------------------
// PSBT parsing
// ---------------------------------------------------------------------------

/** Decode a base64 or hex PSBT string into a PsbtHandle. */
export function parsePsbt(
  base64OrHex: string,
  network: "bitcoin" | "testnet" = "bitcoin",
): PsbtHandle {
  assertReady();

  let raw: Uint8Array;
  try {
    const binary = atob(base64OrHex);
    raw = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      raw[i] = binary.charCodeAt(i);
    }
  } catch {
    // If not valid base64, try treating as hex
    raw = new Uint8Array((base64OrHex.match(/.{1,2}/g) ?? []).map((b) => parseInt(b, 16)));
  }

  const psbt = BitGoPsbt.fromBytes(raw, network);
  return wrapPsbt(psbt);
}

/** Parse a PSBT into a human-readable transaction using wallet keys. */
export function parseTransaction(
  psbtHandle: PsbtHandle,
  walletKeys: WalletKeysHandle,
): ParsedTransaction {
  assertReady();

  const psbt = unwrapPsbt(psbtHandle);
  const keys = unwrapKeys(walletKeys);

  const noReplayProtection = { replayProtection: { outputScripts: [] as Uint8Array[] } };
  const wasmResult = psbt.parseTransactionWithWalletKeys(keys, noReplayProtection);

  const inputs: ParsedInput[] = wasmResult.inputs.map((inp: fixedScriptWallet.ParsedInput) => ({
    address: inp.address,
    value: inp.value,
    scriptId: inp.scriptId,
  }));

  const outputs: ParsedOutput[] = wasmResult.outputs.map((out: fixedScriptWallet.ParsedOutput) => ({
    address: out.address ?? "OP_RETURN",
    value: out.value,
    scriptId: out.scriptId,
    isChange: out.scriptId !== null,
  }));

  return {
    inputs,
    outputs,
    spendAmount: wasmResult.spendAmount,
    minerFee: wasmResult.minerFee,
  };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/** Sign all wallet inputs on the PSBT with the user's xprv. Returns hex-encoded signed PSBT. */
export function signPsbt(psbtHandle: PsbtHandle, xprv: string): string {
  assertReady();

  const psbt = unwrapPsbt(psbtHandle);
  psbt.sign(xprv);

  const bytes = psbt.serialize();
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Verify that a specific xpub has signed all inputs on the PSBT. */
export function verifySignatures(
  psbtHandle: PsbtHandle,
  xpub: string,
  walletKeys: WalletKeysHandle,
): boolean {
  assertReady();

  const psbt = unwrapPsbt(psbtHandle);
  const keys = unwrapKeys(walletKeys);

  // Get input count by parsing the transaction (inputCount getter not in compiled dist)
  const noReplayProtection = { replayProtection: { outputScripts: [] as Uint8Array[] } };
  const parsed = psbt.parseTransactionWithWalletKeys(keys, noReplayProtection);
  for (let i = 0; i < parsed.inputs.length; i++) {
    if (!psbt.verifySignature(i, xpub)) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Signature counting
// ---------------------------------------------------------------------------

/**
 * Count how many of the 3 wallet keys have signed the PSBT, and determine
 * the required threshold.
 *
 * For fixed-script wallets the threshold is always 2 (2-of-3 multisig).
 * For descriptor wallets the threshold is parsed from the descriptor string.
 */
export function countSignatures(
  psbtHandle: PsbtHandle,
  walletKeys: WalletKeysHandle,
  descriptor?: string,
): SignatureInfo {
  assertReady();

  const psbt = unwrapPsbt(psbtHandle);
  const keys = unwrapKeys(walletKeys);

  // Check each of the 3 wallet xpubs against input 0
  const xpubs = [keys.userKey(), keys.backupKey(), keys.bitgoKey()];
  let current = 0;
  for (const xpub of xpubs) {
    try {
      if (psbt.verifySignature(0, xpub)) current++;
    } catch {
      // Key doesn't match this input type — skip
    }
  }

  // Determine required threshold
  let required = 2; // default: BitGo 2-of-3
  if (descriptor) {
    // Extract m from multi(m, ...) or sortedmulti(m, ...)
    const match = descriptor.match(/(?:sorted)?multi\((\d+)/);
    if (match) {
      required = parseInt(match[1], 10);
    }
  }

  return { current, required };
}

// ---------------------------------------------------------------------------
// Key utilities
// ---------------------------------------------------------------------------

/** Derive the xpub from an xprv. */
export function deriveXpubFromXprv(xprv: string): string {
  assertReady();
  const key = BIP32.fromBase58(xprv);
  return key.neutered().toBase58();
}

/** Validate that a string is a valid xpub (public extended key). */
export function validateXpub(xpub: string): boolean {
  try {
    const key = BIP32.fromBase58(xpub);
    return key.isNeutered();
  } catch {
    return false;
  }
}

/** Validate that a string is a valid xprv (private extended key). */
export function validateXprv(xprv: string): boolean {
  try {
    const key = BIP32.fromBase58(xprv);
    return !key.isNeutered();
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Singleton export
// ---------------------------------------------------------------------------

export const wasmService = {
  initWasm,
  getWasmState,
  createWalletKeys,
  parsePsbt,
  parseTransaction,
  signPsbt,
  verifySignatures,
  countSignatures,
  deriveXpubFromXprv,
  validateXpub,
  validateXprv,
} as const;
