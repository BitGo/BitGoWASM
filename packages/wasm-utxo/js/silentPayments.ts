import { SilentPaymentsNamespace } from "./wasm/wasm_utxo.js";

export interface SilentPaymentAddressComponents {
  scanKey: Uint8Array; // 33-byte compressed
  spendKey: Uint8Array; // 33-byte compressed
}

export interface DerivedOutput {
  script: Uint8Array; // P2TR scriptPubKey
  pubkey: Uint8Array; // 32-byte x-only
  tweak: Uint8Array; // 32-byte t_k
}

export interface ScanMatch {
  outputIndex: number;
  tweak: Uint8Array; // 32-byte t_k
  k: number;
  label: number | null;
  labelTweak: Uint8Array | null; // 32-byte label tweak (if label matched)
}

export interface PrivkeyInput {
  key: Uint8Array; // 32-byte private key
  isTaproot: boolean;
}

export interface Outpoint {
  txid: Uint8Array; // 32-byte txid (LE)
  vout: number;
}

export interface InputData {
  privkeys: PrivkeyInput[];
  outpoints: Outpoint[];
}

export interface PubkeyInput {
  pubkey: Uint8Array; // 33-byte compressed pubkey
}

export interface TaprootOutputData {
  pubkey: Uint8Array; // 32-byte x-only pubkey
}

export interface TxData {
  inputs: PubkeyInput[];
  outpoints: Outpoint[];
  outputs: TaprootOutputData[];
}

/**
 * Decode a silent payment address (sp1q.../tsp1q...) into its component keys.
 */
export function decodeAddress(address: string): SilentPaymentAddressComponents {
  return SilentPaymentsNamespace.decode_address(address) as SilentPaymentAddressComponents;
}

/**
 * Encode a silent payment address from component keys.
 *
 * @param scanKey 33-byte compressed scan public key
 * @param spendKey 33-byte compressed spend public key
 * @param network coin name ("btc", "tbtc", etc.)
 */
export function encodeAddress(scanKey: Uint8Array, spendKey: Uint8Array, network: string): string {
  return SilentPaymentsNamespace.encode_address(scanKey, spendKey, network);
}

/**
 * Derive output scripts for sending to silent payment recipients.
 *
 * @param inputData private keys and outpoints from the transaction inputs
 * @param recipients array of SP address strings (sp1q.../tsp1q...)
 * @returns array of derived P2TR outputs with scripts, pubkeys, and tweaks
 */
export function deriveOutputs(inputData: InputData, recipients: string[]): DerivedOutput[] {
  return SilentPaymentsNamespace.derive_outputs(inputData, recipients) as DerivedOutput[];
}

/**
 * Scan a transaction for silent payment outputs addressed to this receiver.
 *
 * @param scanKey 32-byte b_scan private key
 * @param spendPubkey 33-byte B_spend public key
 * @param txData transaction data (input pubkeys, outpoints, taproot outputs)
 * @param labels optional array of label indices to check
 * @returns array of matched outputs with tweaks
 */
export function scanTransaction(
  scanKey: Uint8Array,
  spendPubkey: Uint8Array,
  txData: TxData,
  labels?: number[] | null,
): ScanMatch[] {
  return SilentPaymentsNamespace.scan_transaction(
    scanKey,
    spendPubkey,
    txData,
    labels ?? null,
  ) as ScanMatch[];
}

/**
 * Derive the private key for spending a matched silent payment output.
 *
 * @param spendKey 32-byte b_spend private key
 * @param tweak 32-byte t_k from scanTransaction
 * @returns 32-byte derived private key p_k
 */
export function deriveSpendKey(spendKey: Uint8Array, tweak: Uint8Array): Uint8Array {
  return SilentPaymentsNamespace.derive_spend_key(spendKey, tweak);
}

/**
 * Create a labeled silent payment address.
 *
 * @param scanKey 32-byte b_scan private key
 * @param spendPubkey 33-byte B_spend public key
 * @param labelIndex the label index m
 * @param network coin name ("btc", "tbtc", etc.)
 * @returns the labeled sp1q.../tsp1q... address string
 */
export function createLabeledAddress(
  scanKey: Uint8Array,
  spendPubkey: Uint8Array,
  labelIndex: number,
  network: string,
): string {
  return SilentPaymentsNamespace.create_labeled_address(scanKey, spendPubkey, labelIndex, network);
}
