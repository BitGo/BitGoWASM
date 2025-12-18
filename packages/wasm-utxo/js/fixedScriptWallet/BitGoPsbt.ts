import { BitGoPsbt as WasmBitGoPsbt } from "../wasm/wasm_utxo.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import { type ReplayProtectionArg, ReplayProtection } from "./ReplayProtection.js";
import { type BIP32Arg, BIP32 } from "../bip32.js";
import { type ECPairArg, ECPair } from "../ecpair.js";
import type { UtxolibName } from "../utxolibCompat.js";
import type { CoinName } from "../coinName.js";

export type NetworkName = UtxolibName | CoinName;

export type ScriptId = { chain: number; index: number };

export type InputScriptType =
  | "p2shP2pk"
  | "p2sh"
  | "p2shP2wsh"
  | "p2wsh"
  | "p2trLegacy"
  | "p2trMusig2ScriptPath"
  | "p2trMusig2KeyPath";

export type OutPoint = {
  txid: string;
  vout: number;
};

export type ParsedInput = {
  previousOutput: OutPoint;
  address: string;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | null;
  scriptType: InputScriptType;
};

export type ParsedOutput = {
  address: string | null;
  script: Uint8Array;
  value: bigint;
  scriptId: ScriptId | null;
  paygo: boolean;
};

export type ParsedTransaction = {
  inputs: ParsedInput[];
  outputs: ParsedOutput[];
  spendAmount: bigint;
  minerFee: bigint;
  virtualSize: number;
};

export type CreateEmptyOptions = {
  /** Transaction version (default: 2) */
  version?: number;
  /** Lock time (default: 0) */
  lockTime?: number;
};

export type AddInputOptions = {
  /** Previous transaction ID (hex string) */
  txid: string;
  /** Output index being spent */
  vout: number;
  /** Value in satoshis (for witness_utxo) */
  value: bigint;
  /** Output script of UTXO being spent */
  script: Uint8Array;
  /** Sequence number (default: 0xFFFFFFFE for RBF) */
  sequence?: number;
};

export type AddOutputOptions = {
  /** Output script (scriptPubKey) */
  script: Uint8Array;
  /** Value in satoshis */
  value: bigint;
};

export class BitGoPsbt {
  private constructor(private wasm: WasmBitGoPsbt) {}

  /**
   * Create an empty PSBT for the given network
   *
   * @param network - Network name (utxolib name like "bitcoin" or coin name like "btc")
   * @param options - Optional transaction parameters (version, lockTime)
   * @returns A new empty BitGoPsbt instance
   *
   * @example
   * ```typescript
   * // Create empty PSBT with defaults (version 2, lockTime 0)
   * const psbt = BitGoPsbt.createEmpty("bitcoin");
   *
   * // Create with custom version and lockTime
   * const psbt = BitGoPsbt.createEmpty("bitcoin", { version: 1, lockTime: 500000 });
   * ```
   */
  static createEmpty(network: NetworkName, options?: CreateEmptyOptions): BitGoPsbt {
    const wasm = WasmBitGoPsbt.create_empty(network, options?.version, options?.lockTime);
    return new BitGoPsbt(wasm);
  }

  /**
   * Deserialize a PSBT from bytes
   * @param bytes - The PSBT bytes
   * @param network - The network to use for deserialization (either utxolib name like "bitcoin" or coin name like "btc")
   * @returns A BitGoPsbt instance
   */
  static fromBytes(bytes: Uint8Array, network: NetworkName): BitGoPsbt {
    const wasm = WasmBitGoPsbt.from_bytes(bytes, network);
    return new BitGoPsbt(wasm);
  }

  /**
   * Add an input to the PSBT
   *
   * This adds a transaction input and corresponding PSBT input metadata.
   * The witness_utxo is automatically populated for modern signing compatibility.
   *
   * @param options - Input options (txid, vout, value, script, sequence)
   * @returns The index of the newly added input
   *
   * @example
   * ```typescript
   * const inputIndex = psbt.addInput({
   *   txid: "abc123...",
   *   vout: 0,
   *   value: 100000n,
   *   script: outputScript,
   * });
   * ```
   */
  addInput(options: AddInputOptions): number {
    return this.wasm.add_input(
      options.txid,
      options.vout,
      options.value,
      options.script,
      options.sequence,
    );
  }

  /**
   * Add an output to the PSBT
   *
   * @param options - Output options (script, value)
   * @returns The index of the newly added output
   *
   * @example
   * ```typescript
   * const outputIndex = psbt.addOutput({
   *   script: outputScript,
   *   value: 50000n,
   * });
   * ```
   */
  addOutput(options: AddOutputOptions): number {
    return this.wasm.add_output(options.script, options.value);
  }

  /**
   * Get the unsigned transaction ID
   * @returns The unsigned transaction ID
   */
  unsignedTxid(): string {
    return this.wasm.unsigned_txid();
  }

  /**
   * Parse transaction with wallet keys to identify wallet inputs/outputs
   * @param walletKeys - The wallet keys to use for identification
   * @param replayProtection - Scripts that are allowed as inputs without wallet validation
   * @param payGoPubkeys - Optional public keys for PayGo attestation verification
   * @returns Parsed transaction information
   */
  parseTransactionWithWalletKeys(
    walletKeys: WalletKeysArg,
    replayProtection: ReplayProtectionArg,
    payGoPubkeys?: ECPairArg[],
  ): ParsedTransaction {
    const keys = RootWalletKeys.from(walletKeys);
    const rp = ReplayProtection.from(replayProtection, this.wasm.network());
    const pubkeys = payGoPubkeys?.map((arg) => ECPair.from(arg).wasm);
    return this.wasm.parse_transaction_with_wallet_keys(
      keys.wasm,
      rp.wasm,
      pubkeys,
    ) as ParsedTransaction;
  }

  /**
   * Parse outputs with wallet keys to identify which outputs belong to a wallet
   * with the given wallet keys.
   *
   * This is useful in cases where we want to identify outputs that belong to a different
   * wallet than the inputs.
   *
   * @param walletKeys - The wallet keys to use for identification
   * @param payGoPubkeys - Optional public keys for PayGo attestation verification
   * @returns Array of parsed outputs
   * @note This method does NOT validate wallet inputs. It only parses outputs.
   */
  parseOutputsWithWalletKeys(
    walletKeys: WalletKeysArg,
    payGoPubkeys?: ECPairArg[],
  ): ParsedOutput[] {
    const keys = RootWalletKeys.from(walletKeys);
    const pubkeys = payGoPubkeys?.map((arg) => ECPair.from(arg).wasm);
    return this.wasm.parse_outputs_with_wallet_keys(keys.wasm, pubkeys) as ParsedOutput[];
  }

  /**
   * Add a PayGo attestation to a PSBT output
   *
   * This adds a cryptographic proof that the output address was authorized by a signing authority.
   * The attestation is stored in PSBT proprietary key-values and can be verified later.
   *
   * @param outputIndex - The index of the output to add the attestation to
   * @param entropy - 64 bytes of entropy (must be exactly 64 bytes)
   * @param signature - ECDSA signature bytes (typically 65 bytes in recoverable format)
   * @throws Error if output index is out of bounds or entropy is not 64 bytes
   */
  addPayGoAttestation(outputIndex: number, entropy: Uint8Array, signature: Uint8Array): void {
    this.wasm.add_paygo_attestation(outputIndex, entropy, signature);
  }

  /**
   * Verify if a valid signature exists for a given key at the specified input index.
   *
   * This method can verify signatures using either:
   * - Extended public key (xpub): Derives the public key using the derivation path from PSBT
   * - ECPair (private key): Extracts the public key and verifies directly
   *
   * When using xpub, it supports:
   * - ECDSA signatures (for legacy/SegWit inputs)
   * - Schnorr signatures (for Taproot script path inputs)
   * - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
   *
   * When using ECPair, it supports:
   * - ECDSA signatures (for legacy/SegWit inputs)
   * - Schnorr signatures (for Taproot script path inputs)
   * Note: MuSig2 inputs require xpubs for derivation
   *
   * @param inputIndex - The index of the input to check (0-based)
   * @param key - Either an extended public key (base58 string, BIP32 instance, or WasmBIP32) or an ECPair (private key Buffer, ECPair instance, or WasmECPair)
   * @returns true if a valid signature exists, false if no signature exists
   * @throws Error if input index is out of bounds, key is invalid, or verification fails
   *
   * @example
   * ```typescript
   * // Verify wallet input signature with xpub
   * const hasUserSig = psbt.verifySignature(0, userXpub);
   *
   * // Verify signature with ECPair (private key)
   * const ecpair = ECPair.fromPrivateKey(privateKeyBuffer);
   * const hasReplaySig = psbt.verifySignature(1, ecpair);
   *
   * // Or pass private key directly
   * const hasReplaySig2 = psbt.verifySignature(1, privateKeyBuffer);
   * ```
   */
  verifySignature(inputIndex: number, key: BIP32Arg | ECPairArg): boolean {
    // Try to parse as BIP32Arg first (string or BIP32 instance)
    if (typeof key === "string" || ("derive" in key && typeof key.derive === "function")) {
      const wasmKey = BIP32.from(key as BIP32Arg).wasm;
      return this.wasm.verify_signature_with_xpub(inputIndex, wasmKey);
    }

    // Otherwise it's an ECPairArg (Uint8Array, ECPair, or WasmECPair)
    const wasmECPair = ECPair.from(key as ECPairArg).wasm;
    return this.wasm.verify_signature_with_pub(inputIndex, wasmECPair);
  }

  /**
   * Sign a single input with a private key
   *
   * This method signs a specific input using the provided key. It accepts either:
   * - An xpriv (BIP32Arg: base58 string, BIP32 instance, or WasmBIP32) for wallet inputs - derives the key and signs
   * - A raw privkey (ECPairArg: Buffer, ECPair instance, or WasmECPair) for replay protection inputs - signs directly
   *
   * This method automatically detects and handles different input types:
   * - For regular inputs: uses standard PSBT signing
   * - For MuSig2 inputs: uses the FirstRound state stored by generateMusig2Nonces()
   * - For replay protection inputs: signs with legacy P2SH sighash
   *
   * @param inputIndex - The index of the input to sign (0-based)
   * @param key - Either an xpriv (BIP32Arg) or a raw privkey (ECPairArg)
   * @throws Error if signing fails, or if generateMusig2Nonces() was not called first for MuSig2 inputs
   *
   * @example
   * ```typescript
   * // Parse transaction to identify input types
   * const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, replayProtection);
   *
   * // Sign regular wallet inputs with xpriv
   * for (let i = 0; i < parsed.inputs.length; i++) {
   *   const input = parsed.inputs[i];
   *   if (input.scriptId !== null && input.scriptType !== "p2shP2pk") {
   *     psbt.sign(i, userXpriv);
   *   }
   * }
   *
   * // Sign replay protection inputs with raw privkey
   * const userPrivkey = bip32.fromBase58(userXpriv).privateKey!;
   * for (let i = 0; i < parsed.inputs.length; i++) {
   *   const input = parsed.inputs[i];
   *   if (input.scriptType === "p2shP2pk") {
   *     psbt.sign(i, userPrivkey);
   *   }
   * }
   * ```
   */
  sign(inputIndex: number, key: BIP32Arg | ECPairArg): void {
    // Detect key type
    // If string or has 'derive' method → BIP32Arg
    // Otherwise → ECPairArg
    if (
      typeof key === "string" ||
      (typeof key === "object" &&
        key !== null &&
        "derive" in key &&
        typeof key.derive === "function")
    ) {
      // It's a BIP32Arg
      const wasmKey = BIP32.from(key as BIP32Arg);
      this.wasm.sign_with_xpriv(inputIndex, wasmKey.wasm);
    } else {
      // It's an ECPairArg
      const wasmKey = ECPair.from(key as ECPairArg);
      this.wasm.sign_with_privkey(inputIndex, wasmKey.wasm);
    }
  }

  /**
   * @deprecated - use verifySignature with the replay protection key instead
   *
   * Verify if a replay protection input has a valid signature.
   *
   * This method checks if a given input is a replay protection input (like P2shP2pk) and verifies
   * the signature. Replay protection inputs don't use standard derivation paths, so this method
   * verifies signatures without deriving from xpub.
   *
   * For P2PK replay protection inputs, this:
   * - Extracts the signature from final_script_sig
   * - Extracts the public key from redeem_script
   * - Computes the legacy P2SH sighash
   * - Verifies the ECDSA signature cryptographically
   *
   * @param inputIndex - The index of the input to check (0-based)
   * @param replayProtection - Scripts that identify replay protection inputs (same format as parseTransactionWithWalletKeys)
   * @returns true if the input is a replay protection input and has a valid signature, false if no valid signature
   * @throws Error if the input is not a replay protection input, index is out of bounds, or scripts are invalid
   */
  verifyReplayProtectionSignature(
    inputIndex: number,
    replayProtection: ReplayProtectionArg,
  ): boolean {
    const rp = ReplayProtection.from(replayProtection, this.wasm.network());
    return this.wasm.verify_replay_protection_signature(inputIndex, rp.wasm);
  }

  /**
   * Serialize the PSBT to bytes
   *
   * @returns The serialized PSBT as a byte array
   */
  serialize(): Uint8Array {
    return this.wasm.serialize();
  }

  /**
   * Generate and store MuSig2 nonces for all MuSig2 inputs
   *
   * This method generates nonces using the State-Machine API and stores them in the PSBT.
   * The nonces are stored as proprietary fields in the PSBT and will be included when serialized.
   * After ALL participants have generated their nonces, you can sign MuSig2 inputs using
   * sign().
   *
   * @param key - The extended private key (xpriv) for signing. Can be a base58 string, BIP32 instance, or WasmBIP32
   * @param sessionId - Optional 32-byte session ID for nonce generation. **Only allowed on testnets**.
   *                    On mainnets, a secure random session ID is always generated automatically.
   *                    Must be unique per signing session.
   * @throws Error if nonce generation fails, sessionId length is invalid, or custom sessionId is
   *         provided on a mainnet (security restriction)
   *
   * @security The sessionId MUST be cryptographically random and unique for each signing session.
   * Never reuse a sessionId with the same key! On mainnets, sessionId is always randomly
   * generated for security. Custom sessionId is only allowed on testnets for testing purposes.
   *
   * @example
   * ```typescript
   * // Phase 1: Both parties generate nonces (with auto-generated session ID)
   * psbt.generateMusig2Nonces(userXpriv);
   * // Nonces are stored in the PSBT
   * // Send PSBT to counterparty
   *
   * // Phase 2: After receiving counterparty PSBT with their nonces
   * const counterpartyPsbt = BitGoPsbt.fromBytes(counterpartyPsbtBytes, network);
   * psbt.combineMusig2Nonces(counterpartyPsbt);
   * // Sign MuSig2 key path inputs
   * const parsed = psbt.parseTransactionWithWalletKeys(walletKeys, replayProtection);
   * for (let i = 0; i < parsed.inputs.length; i++) {
   *   if (parsed.inputs[i].scriptType === "p2trMusig2KeyPath") {
   *     psbt.sign(i, userXpriv);
   *   }
   * }
   * ```
   */
  generateMusig2Nonces(key: BIP32Arg, sessionId?: Uint8Array): void {
    const wasmKey = BIP32.from(key);
    this.wasm.generate_musig2_nonces(wasmKey.wasm, sessionId);
  }

  /**
   * Combine/merge data from another PSBT into this one
   *
   * This method copies MuSig2 nonces and signatures (proprietary key-value pairs) from the
   * source PSBT to this PSBT. This is useful for merging PSBTs during the nonce exchange
   * and signature collection phases.
   *
   * @param sourcePsbt - The source PSBT containing data to merge
   * @throws Error if networks don't match
   *
   * @example
   * ```typescript
   * // After receiving counterparty's PSBT with their nonces
   * const counterpartyPsbt = BitGoPsbt.fromBytes(counterpartyPsbtBytes, network);
   * psbt.combineMusig2Nonces(counterpartyPsbt);
   * // Now can sign with all nonces present
   * psbt.sign(0, userXpriv);
   * ```
   */
  combineMusig2Nonces(sourcePsbt: BitGoPsbt): void {
    this.wasm.combine_musig2_nonces(sourcePsbt.wasm);
  }

  /**
   * Finalize all inputs in the PSBT
   *
   * @throws Error if any input failed to finalize
   */
  finalizeAllInputs(): void {
    this.wasm.finalize_all_inputs();
  }

  /**
   * Extract the final transaction from a finalized PSBT
   *
   * @returns The serialized transaction bytes
   * @throws Error if the PSBT is not fully finalized or extraction fails
   */
  extractTransaction(): Uint8Array {
    return this.wasm.extract_transaction();
  }
}
