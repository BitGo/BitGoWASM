/**
 * BIP-0322 Generic Signed Message Format
 *
 * This module implements BIP-0322 for BitGo fixed-script wallets.
 * It allows proving control of wallet addresses by signing arbitrary messages.
 *
 * @example
 * ```typescript
 * import { bip322, fixedScriptWallet } from '@bitgo/wasm-utxo';
 *
 * // Create wallet keys
 * const walletKeys = fixedScriptWallet.RootWalletKeys.from([userXpub, backupXpub, bitgoXpub]);
 *
 * // Create an empty PSBT for BIP-0322 (version 0 required)
 * const psbt = BitGoPsbt.createEmpty("bitcoin", walletKeys, { version: 0 });
 *
 * // Add BIP-0322 inputs
 * const idx0 = bip322.addBip322Input(psbt, {
 *   message: "Hello, World!",
 *   scriptId: { chain: 10, index: 0 },
 *   rootWalletKeys: walletKeys,
 * });
 *
 * // Sign the input
 * psbt.sign(idx0, userXpriv);
 * psbt.sign(idx0, bitgoXpriv);
 *
 * // Verify the input
 * bip322.verifyBip322PsbtInput(psbt, idx0, {
 *   message: "Hello, World!",
 *   scriptId: { chain: 10, index: 0 },
 *   rootWalletKeys: walletKeys,
 * });
 * ```
 */

import { Bip322Namespace } from "../wasm/wasm_utxo.js";
import {
  BitGoPsbt,
  type NetworkName,
  type ScriptId,
  type SignPath,
} from "../fixedScriptWallet/BitGoPsbt.js";
import { type WalletKeysArg, RootWalletKeys } from "../fixedScriptWallet/RootWalletKeys.js";
import { type OutputScriptType } from "../fixedScriptWallet/scriptType.js";
import { Transaction } from "../transaction.js";

// Re-export OutputScriptType for backwards compatibility
export type { OutputScriptType };

/**
 * Parameters for adding a BIP-0322 input to a PSBT
 */
export type AddBip322InputParams = {
  /** The message to sign (UTF-8 string) */
  message: string;
  /** The wallet script location (chain and index) */
  scriptId: ScriptId;
  /** The wallet's root keys */
  rootWalletKeys: WalletKeysArg;
  /**
   * Sign path for taproot inputs (required for p2tr/p2trMusig2).
   * Specifies which two keys will sign the message.
   */
  signPath?: SignPath;
  /** Custom tag for message hashing (default: "BIP0322-signed-message") */
  tag?: string;
};

/**
 * Parameters for verifying a BIP-0322 input
 */
export type VerifyBip322InputParams = {
  /** The message that was signed */
  message: string;
  /** The wallet script location (chain and index) */
  scriptId: ScriptId;
  /** The wallet's root keys */
  rootWalletKeys: WalletKeysArg;
  /** Custom tag if one was used during signing */
  tag?: string;
};

/**
 * Parameters for verifying a BIP-0322 transaction input
 */
export type VerifyBip322TxInputParams = VerifyBip322InputParams & {
  /** Network name (default: "bitcoin") */
  network?: NetworkName;
};

/**
 * Add a BIP-0322 message input to an existing BitGoPsbt
 *
 * The PSBT must have version 0 per BIP-0322 specification. Use
 * `BitGoPsbt.createEmpty(network, walletKeys, { version: 0 })` to create one.
 *
 * On the first input added, this also adds the required OP_RETURN output.
 *
 * @param psbt - The BitGoPsbt to add the input to (must have version 0)
 * @param params - Input parameters including message, scriptId, and wallet keys
 * @returns The index of the added input
 *
 * @example
 * ```typescript
 * // Create a BIP-0322 PSBT
 * const psbt = BitGoPsbt.createEmpty("bitcoin", walletKeys, { version: 0 });
 *
 * // Add inputs
 * const idx0 = bip322.addBip322Input(psbt, {
 *   message: "I control this address",
 *   scriptId: { chain: 10, index: 5 },
 *   rootWalletKeys: walletKeys,
 * });
 *
 * // Sign with user and bitgo keys
 * psbt.sign(idx0, userXpriv);
 * psbt.sign(idx0, bitgoXpriv);
 * ```
 */
export function addBip322Input(psbt: BitGoPsbt, params: AddBip322InputParams): number {
  const keys = RootWalletKeys.from(params.rootWalletKeys);

  return Bip322Namespace.add_bip322_input(
    psbt.wasm,
    params.message,
    params.scriptId.chain,
    params.scriptId.index,
    keys.wasm,
    params.signPath?.signer,
    params.signPath?.cosigner,
    params.tag,
  );
}

/**
 * Verify a single input of a BIP-0322 transaction proof
 *
 * This verifies that the specified input correctly proves control of the
 * wallet address corresponding to the given message.
 *
 * @param tx - The signed transaction
 * @param inputIndex - The index of the input to verify
 * @param params - Verification parameters including message, scriptId, and wallet keys
 * @throws Error if verification fails
 *
 * @example
 * ```typescript
 * // Extract and verify the transaction
 * psbt.finalizeAllInputs();
 * const txBytes = psbt.extractTransaction();
 * const tx = Transaction.fromBytes(txBytes, "bitcoin");
 *
 * bip322.verifyBip322TxInput(tx, 0, {
 *   message: "Hello, World!",
 *   scriptId: { chain: 10, index: 0 },
 *   rootWalletKeys: walletKeys,
 *   network: "bitcoin",
 * });
 * ```
 */
export function verifyBip322TxInput(
  tx: Transaction,
  inputIndex: number,
  params: VerifyBip322TxInputParams,
): void {
  const keys = RootWalletKeys.from(params.rootWalletKeys);
  const network = params.network ?? "bitcoin";

  Bip322Namespace.verify_bip322_tx_input(
    tx.wasm,
    inputIndex,
    params.message,
    params.scriptId.chain,
    params.scriptId.index,
    keys.wasm,
    network,
    params.tag,
  );
}

/** Signer key name */
export type SignerName = "user" | "backup" | "bitgo";

/** Triple of hex-encoded pubkeys [user, backup, bitgo] */
export type PubkeyTriple = [string, string, string];

/**
 * Parameters for verifying a BIP-0322 input with pubkeys
 */
export type VerifyBip322WithPubkeysParams = {
  /** The message that was signed */
  message: string;
  /** Hex-encoded pubkeys [user, backup, bitgo] */
  pubkeys: PubkeyTriple;
  /** Script type */
  scriptType: OutputScriptType;
  /** For taproot types, whether script path was used */
  isScriptPath?: boolean;
  /** Custom tag if one was used during signing */
  tag?: string;
};

/**
 * Parameters for verifying a BIP-0322 transaction input with pubkeys
 */
export type VerifyBip322TxWithPubkeysParams = VerifyBip322WithPubkeysParams;

/**
 * Verify a single input of a BIP-0322 PSBT proof
 *
 * This verifies that the specified input correctly proves control of the
 * wallet address by checking:
 * - The PSBT structure follows BIP-0322 (version 0, OP_RETURN output)
 * - The input references the correct virtual to_spend transaction
 * - At least one valid signature exists from the wallet keys
 *
 * @param psbt - The signed PSBT
 * @param inputIndex - The index of the input to verify
 * @param params - Verification parameters including message, scriptId, and wallet keys
 * @returns An array of signer names ("user", "backup", "bitgo") that have valid signatures
 * @throws Error if verification fails or no valid signatures found
 *
 * @example
 * ```typescript
 * // Verify the signed PSBT input
 * const signers = bip322.verifyBip322PsbtInput(psbt, 0, {
 *   message: "Hello, World!",
 *   scriptId: { chain: 10, index: 0 },
 *   rootWalletKeys: walletKeys,
 * });
 * console.log(signers); // ["user", "bitgo"]
 * ```
 */
export function verifyBip322PsbtInput(
  psbt: BitGoPsbt,
  inputIndex: number,
  params: VerifyBip322InputParams,
): SignerName[] {
  const keys = RootWalletKeys.from(params.rootWalletKeys);

  return Bip322Namespace.verify_bip322_psbt_input(
    psbt.wasm,
    inputIndex,
    params.message,
    params.scriptId.chain,
    params.scriptId.index,
    keys.wasm,
    params.tag,
  ) as SignerName[];
}

/**
 * Verify a single input of a BIP-0322 PSBT proof using pubkeys directly
 *
 * This verifies that the specified input correctly proves control of the
 * wallet address by checking:
 * - The PSBT structure follows BIP-0322 (version 0, OP_RETURN output)
 * - The input references the correct virtual to_spend transaction
 * - At least one valid signature exists from the provided pubkeys
 *
 * @param psbt - The signed PSBT
 * @param inputIndex - The index of the input to verify
 * @param params - Verification parameters including message, pubkeys, and script type
 * @returns An array of pubkey indices (0, 1, 2) that have valid signatures
 * @throws Error if verification fails or no valid signatures found
 *
 * @example
 * ```typescript
 * // Verify the signed PSBT input with pubkeys
 * const signerIndices = bip322.verifyBip322PsbtInputWithPubkeys(psbt, 0, {
 *   message: "Hello, World!",
 *   pubkeys: [userPubkey, backupPubkey, bitgoPubkey],
 *   scriptType: "p2shP2wsh",
 * });
 * console.log(signerIndices); // [0, 2] for user+bitgo
 * ```
 */
export function verifyBip322PsbtInputWithPubkeys(
  psbt: BitGoPsbt,
  inputIndex: number,
  params: VerifyBip322WithPubkeysParams,
): number[] {
  return Array.from(
    Bip322Namespace.verify_bip322_psbt_input_with_pubkeys(
      psbt.wasm,
      inputIndex,
      params.message,
      params.pubkeys,
      params.scriptType,
      params.isScriptPath,
      params.tag,
    ),
  );
}

/**
 * Verify a single input of a BIP-0322 transaction proof using pubkeys directly
 *
 * This verifies that the specified input correctly proves control of the
 * wallet address corresponding to the given message.
 *
 * @param tx - The signed transaction
 * @param inputIndex - The index of the input to verify
 * @param params - Verification parameters including message, pubkeys, and script type
 * @returns An array of pubkey indices (0, 1, 2) that have valid signatures
 * @throws Error if verification fails
 *
 * @example
 * ```typescript
 * // Verify the signed transaction input with pubkeys
 * const signerIndices = bip322.verifyBip322TxInputWithPubkeys(tx, 0, {
 *   message: "Hello, World!",
 *   pubkeys: [userPubkey, backupPubkey, bitgoPubkey],
 *   scriptType: "p2wsh",
 * });
 * console.log(signerIndices); // [0, 2] for user+bitgo
 * ```
 */
export function verifyBip322TxInputWithPubkeys(
  tx: Transaction,
  inputIndex: number,
  params: VerifyBip322TxWithPubkeysParams,
): number[] {
  return Array.from(
    Bip322Namespace.verify_bip322_tx_input_with_pubkeys(
      tx.wasm,
      inputIndex,
      params.message,
      params.pubkeys,
      params.scriptType,
      params.isScriptPath,
      params.tag,
    ),
  );
}
