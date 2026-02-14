import {
  BitGoPsbt as WasmBitGoPsbt,
  type PsbtInputData,
  type PsbtOutputData,
  type PsbtOutputDataWithAddress,
} from "../wasm/wasm_utxo.js";
import type { IPsbtIntrospectionWithAddress } from "../psbt.js";
import { type WalletKeysArg, RootWalletKeys } from "./RootWalletKeys.js";
import { type ReplayProtectionArg, ReplayProtection } from "./ReplayProtection.js";
import { type BIP32Arg, BIP32, isBIP32Arg } from "../bip32.js";
import { type ECPairArg, ECPair } from "../ecpair.js";
import type { UtxolibName } from "../utxolibCompat.js";
import type { CoinName } from "../coinName.js";
import type { InputScriptType } from "./scriptType.js";
import {
  Transaction,
  DashTransaction,
  ZcashTransaction,
  type ITransaction,
} from "../transaction.js";

export type { InputScriptType };

export type NetworkName = UtxolibName | CoinName;

export type ScriptId = { chain: number; index: number };

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
  sequence: number;
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
  /** Sequence number (default: 0xFFFFFFFE for RBF) */
  sequence?: number;
  /** Full previous transaction (for non-segwit strict compliance) */
  prevTx?: Uint8Array;
};

export type AddOutputOptions =
  | {
      script: Uint8Array;
      /** Value in satoshis */
      value: bigint;
    }
  | {
      address: string;
      /** Value in satoshis */
      value: bigint;
    };

/** Key identifier for signing ("user", "backup", or "bitgo") */
export type SignerKey = "user" | "backup" | "bitgo";

/** Specifies signer and cosigner for Taproot inputs */
export type SignPath = {
  /** Key that will sign */
  signer: SignerKey;
  /** Key that will co-sign */
  cosigner: SignerKey;
};

export type AddWalletInputOptions = {
  /** Script location in wallet (chain + index) */
  scriptId: ScriptId;
  /** Sign path - required for p2tr/p2trMusig2 (chains 30-41) */
  signPath?: SignPath;
};

export type AddWalletOutputOptions = {
  /** Chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2) */
  chain: number;
  /** Derivation index */
  index: number;
  /** Value in satoshis */
  value: bigint;
};

export class BitGoPsbt implements IPsbtIntrospectionWithAddress {
  protected constructor(protected _wasm: WasmBitGoPsbt) {}

  /**
   * Get the underlying WASM instance
   * @internal - for use by other wasm-utxo modules
   */
  get wasm(): WasmBitGoPsbt {
    return this._wasm;
  }

  /**
   * Create an empty PSBT for the given network with wallet keys
   *
   * The wallet keys are used to set global xpubs in the PSBT, which identifies
   * the keys that will be used for signing.
   *
   * For Zcash networks, use ZcashBitGoPsbt.createEmpty() instead.
   *
   * @param network - Network name (utxolib name like "bitcoin" or coin name like "btc")
   * @param walletKeys - The wallet's root keys (sets global xpubs in the PSBT)
   * @param options - Optional transaction parameters (version, lockTime)
   * @returns A new empty BitGoPsbt instance
   *
   * @example
   * ```typescript
   * // Create empty PSBT with wallet keys
   * const psbt = BitGoPsbt.createEmpty("bitcoin", walletKeys);
   *
   * // Create with custom version and lockTime
   * const psbt = BitGoPsbt.createEmpty("bitcoin", walletKeys, { version: 1, lockTime: 500000 });
   * ```
   */
  static createEmpty(
    network: NetworkName,
    walletKeys: WalletKeysArg,
    options?: CreateEmptyOptions,
  ): BitGoPsbt {
    const keys = RootWalletKeys.from(walletKeys);
    const wasmPsbt = WasmBitGoPsbt.create_empty(
      network,
      keys.wasm,
      options?.version,
      options?.lockTime,
    );
    return new BitGoPsbt(wasmPsbt);
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
   * @param options - Input options (txid, vout, value, sequence)
   * @param script - Output script of the UTXO being spent
   * @returns The index of the newly added input
   *
   * @example
   * ```typescript
   * const inputIndex = psbt.addInput({
   *   txid: "abc123...",
   *   vout: 0,
   *   value: 100000n,
   * }, outputScript);
   * ```
   */
  addInput(options: AddInputOptions, script: Uint8Array): number {
    return this._wasm.add_input(
      options.txid,
      options.vout,
      options.value,
      script,
      options.sequence,
      options.prevTx,
    );
  }

  /**
   * Add an output to the PSBT
   *
   * @param script - The output script (scriptPubKey)
   * @param value - Value in satoshis
   * @returns The index of the newly added output
   *
   * @example
   * ```typescript
   * const outputIndex = psbt.addOutput(outputScript, 50000n);
   * ```
   */
  addOutput(script: Uint8Array, value: bigint): number;
  /**
   * Add an output to the PSBT by address
   *
   * @param address - The destination address
   * @param value - Value in satoshis
   * @returns The index of the newly added output
   *
   * @example
   * ```typescript
   * const outputIndex = psbt.addOutput("bc1q...", 50000n);
   * ```
   */
  addOutput(address: string, value: bigint): number;
  /**
   * Add an output to the PSBT
   *
   * @param options - Output options (script or address, and value)
   * @returns The index of the newly added output
   *
   * @example
   * ```typescript
   * // Using script
   * const outputIndex = psbt.addOutput({
   *   script: outputScript,
   *   value: 50000n,
   * });
   *
   * // Using address
   * const outputIndex = psbt.addOutput({
   *   address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
   *   value: 50000n,
   * });
   * ```
   */
  addOutput(options: AddOutputOptions): number;
  addOutput(scriptOrOptions: Uint8Array | string | AddOutputOptions, value?: bigint): number {
    if (scriptOrOptions instanceof Uint8Array || typeof scriptOrOptions === "string") {
      if (value === undefined) {
        throw new Error("Value is required when passing a script or address");
      }
      if (scriptOrOptions instanceof Uint8Array) {
        return this._wasm.add_output(scriptOrOptions, value);
      }
      return this._wasm.add_output_with_address(scriptOrOptions, value);
    }

    const options = scriptOrOptions;
    if ("script" in options) {
      return this._wasm.add_output(options.script, options.value);
    }
    if ("address" in options) {
      return this._wasm.add_output_with_address(options.address, options.value);
    }
    throw new Error("Invalid output options");
  }

  /**
   * Add a wallet input with full PSBT metadata
   *
   * This is a higher-level method that adds an input and populates all required
   * PSBT fields (scripts, derivation info, etc.) based on the wallet's chain type.
   *
   * For p2sh/p2shP2wsh/p2wsh: Sets bip32Derivation, witnessScript, redeemScript (signPath not needed)
   * For p2tr/p2trMusig2 script path: Sets tapLeafScript, tapBip32Derivation (signPath required)
   * For p2trMusig2 key path: Sets tapInternalKey, tapMerkleRoot, tapBip32Derivation, musig2 participants (signPath required)
   *
   * @param inputOptions - Common input options (txid, vout, value, sequence)
   * @param walletKeys - The wallet's root keys
   * @param walletOptions - Wallet-specific options (scriptId, signPath, prevTx)
   * @returns The index of the newly added input
   *
   * @example
   * ```typescript
   * // Add a p2shP2wsh input (signPath not needed)
   * const inputIndex = psbt.addWalletInput(
   *   { txid: "abc123...", vout: 0, value: 100000n },
   *   walletKeys,
   *   { scriptId: { chain: 10, index: 0 } },  // p2shP2wsh external
   * );
   *
   * // Add a p2trMusig2 key path input (signPath required)
   * const inputIndex = psbt.addWalletInput(
   *   { txid: "def456...", vout: 1, value: 50000n },
   *   walletKeys,
   *   { scriptId: { chain: 40, index: 5 }, signPath: { signer: "user", cosigner: "bitgo" } },
   * );
   *
   * // Add p2trMusig2 with backup key (script path spend)
   * const inputIndex = psbt.addWalletInput(
   *   { txid: "ghi789...", vout: 0, value: 75000n },
   *   walletKeys,
   *   { scriptId: { chain: 40, index: 3 }, signPath: { signer: "user", cosigner: "backup" } },
   * );
   * ```
   */
  addWalletInput(
    inputOptions: AddInputOptions,
    walletKeys: WalletKeysArg,
    walletOptions: AddWalletInputOptions,
  ): number {
    const keys = RootWalletKeys.from(walletKeys);
    return this._wasm.add_wallet_input(
      inputOptions.txid,
      inputOptions.vout,
      inputOptions.value,
      keys.wasm,
      walletOptions.scriptId.chain,
      walletOptions.scriptId.index,
      walletOptions.signPath?.signer,
      walletOptions.signPath?.cosigner,
      inputOptions.sequence,
      inputOptions.prevTx,
    );
  }

  /**
   * Add a wallet output with full PSBT metadata
   *
   * This creates a verifiable wallet output (typically for change) with all required
   * PSBT fields (scripts, derivation info) based on the wallet's chain type.
   *
   * For p2sh/p2shP2wsh/p2wsh: Sets bip32Derivation, witnessScript, redeemScript
   * For p2tr/p2trMusig2: Sets tapInternalKey, tapBip32Derivation
   *
   * @param walletKeys - The wallet's root keys
   * @param options - Output options including chain, index, and value
   * @returns The index of the newly added output
   *
   * @example
   * ```typescript
   * // Add a p2shP2wsh change output
   * const outputIndex = psbt.addWalletOutput(walletKeys, {
   *   chain: 11,  // p2shP2wsh internal (change)
   *   index: 0,
   *   value: 50000n,
   * });
   *
   * // Add a p2trMusig2 change output
   * const outputIndex = psbt.addWalletOutput(walletKeys, {
   *   chain: 41,  // p2trMusig2 internal (change)
   *   index: 5,
   *   value: 25000n,
   * });
   * ```
   */
  addWalletOutput(walletKeys: WalletKeysArg, options: AddWalletOutputOptions): number {
    const keys = RootWalletKeys.from(walletKeys);
    return this._wasm.add_wallet_output(options.chain, options.index, options.value, keys.wasm);
  }

  /**
   * Add a replay protection input to the PSBT
   *
   * Replay protection inputs are P2SH-P2PK inputs used on forked networks to prevent
   * transaction replay attacks. They use a simple pubkey script without wallet derivation.
   *
   * @param inputOptions - Common input options (txid, vout, value, sequence)
   * @param key - ECPair containing the public key for the replay protection input
   * @returns The index of the newly added input
   *
   * @example
   * ```typescript
   * // Add a replay protection input using ECPair
   * const inputIndex = psbt.addReplayProtectionInput(
   *   { txid: "abc123...", vout: 0, value: 1000n },
   *   replayProtectionKey,
   * );
   * ```
   */
  addReplayProtectionInput(inputOptions: AddInputOptions, key: ECPairArg): number {
    const ecpair = ECPair.from(key);
    return this._wasm.add_replay_protection_input(
      ecpair.wasm,
      inputOptions.txid,
      inputOptions.vout,
      inputOptions.value,
      inputOptions.sequence,
    );
  }

  /**
   * Get the unsigned transaction ID
   * @returns The unsigned transaction ID
   */
  unsignedTxid(): string {
    return this._wasm.unsigned_txid();
  }

  /**
   * Get the transaction version
   * @returns The transaction version number
   */
  get version(): number {
    return this._wasm.version();
  }

  /**
   * Get the transaction lock time
   * @returns The transaction lock time
   */
  get lockTime(): number {
    return this._wasm.lock_time();
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
    const rp = ReplayProtection.from(replayProtection, this._wasm.network());
    const pubkeys = payGoPubkeys?.map((arg) => ECPair.from(arg).wasm);
    return this._wasm.parse_transaction_with_wallet_keys(
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
    return this._wasm.parse_outputs_with_wallet_keys(keys.wasm, pubkeys) as ParsedOutput[];
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
    this._wasm.add_paygo_attestation(outputIndex, entropy, signature);
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
      return this._wasm.verify_signature_with_xpub(inputIndex, wasmKey);
    }

    // Otherwise it's an ECPairArg (Uint8Array, ECPair, or WasmECPair)
    const wasmECPair = ECPair.from(key as ECPairArg).wasm;
    return this._wasm.verify_signature_with_pub(inputIndex, wasmECPair);
  }

  /**
   * Sign all matching inputs with a private key.
   *
   * This method signs all inputs that match the provided key in a single efficient pass.
   * It accepts either:
   * - An xpriv (BIP32Arg: base58 string, BIP32 instance, or WasmBIP32) for wallet inputs
   * - A raw privkey (ECPairArg: Buffer, ECPair instance, or WasmECPair) for replay protection inputs
   *
   * **Note:** MuSig2 inputs are skipped by this method when using xpriv because they require
   * FirstRound state. After calling this method, sign MuSig2 inputs individually using
   * `signInput()` after calling `generateMusig2Nonces()`.
   *
   * @param key - Either an xpriv (BIP32Arg) or a raw privkey (ECPairArg)
   * @returns Array of input indices that were signed
   * @throws Error if signing fails
   *
   * @example
   * ```typescript
   * // Sign all wallet inputs with user's xpriv
   * const signedIndices = psbt.sign(userXpriv);
   * console.log(`Signed inputs: ${signedIndices.join(", ")}`);
   *
   * // Sign all replay protection inputs with raw privkey
   * const rpSignedIndices = psbt.sign(replayProtectionPrivkey);
   * ```
   */
  sign(key: BIP32Arg | ECPairArg): number[];

  /**
   * Sign a single input with a private key.
   *
   * @deprecated Use `sign(key)` to sign all matching inputs (more efficient), or use
   * `signInput(inputIndex, key)` for explicit single-input signing.
   *
   * **Note:** This method is NOT more efficient than `sign(key)` for non-MuSig2 inputs.
   * The underlying miniscript library signs all inputs regardless. This overload exists
   * for backward compatibility only.
   *
   * @param inputIndex - The index of the input to sign (0-based)
   * @param key - Either an xpriv (BIP32Arg) or a raw privkey (ECPairArg)
   * @throws Error if signing fails, or if generateMusig2Nonces() was not called first for MuSig2 inputs
   */
  sign(inputIndex: number, key: BIP32Arg | ECPairArg): void;

  sign(
    inputIndexOrKey: number | BIP32Arg | ECPairArg,
    key?: BIP32Arg | ECPairArg,
  ): number[] | void {
    // Detect which overload was called
    if (typeof inputIndexOrKey === "number") {
      // Called as sign(inputIndex, key) - deprecated single-input signing
      if (key === undefined) {
        throw new Error("Key is required when signing a single input");
      }
      this.signInput(inputIndexOrKey, key);
      return;
    }

    // Called as sign(key) - sign all matching inputs
    const keyArg = inputIndexOrKey;

    if (isBIP32Arg(keyArg)) {
      // It's a BIP32Arg - sign all wallet inputs (ECDSA + MuSig2)
      const wasmKey = BIP32.from(keyArg);
      // Sign all non-MuSig2 wallet inputs
      const walletSigned = this._wasm.sign_all_wallet_inputs(wasmKey.wasm) as number[];
      // Sign all MuSig2 keypath inputs (more efficient - reuses SighashCache)
      const musig2Signed = this._wasm.sign_all_musig2_inputs(wasmKey.wasm) as number[];
      return [...walletSigned, ...musig2Signed];
    } else {
      // It's an ECPairArg - sign all replay protection inputs
      const wasmKey = ECPair.from(keyArg as ECPairArg);
      return this._wasm.sign_replay_protection_inputs(wasmKey.wasm) as number[];
    }
  }

  /**
   * Sign a single input with a private key.
   *
   * This method signs a specific input using the provided key. It accepts either:
   * - An xpriv (BIP32Arg: base58 string, BIP32 instance, or WasmBIP32) for wallet inputs
   * - A raw privkey (ECPairArg: Buffer, ECPair instance, or WasmECPair) for replay protection inputs
   *
   * **Important:** This method is NOT faster than `sign(key)` for non-MuSig2 inputs.
   * The underlying miniscript library signs all inputs regardless. This method uses a
   * save/restore pattern to ensure only the target input receives the signature.
   *
   * Use this method only when you need precise control over which inputs are signed,
   * for example:
   * - Signing MuSig2 inputs (after calling generateMusig2Nonces())
   * - Mixed transactions where different inputs need different keys
   * - Testing or debugging signing behavior
   *
   * @param inputIndex - The index of the input to sign (0-based)
   * @param key - Either an xpriv (BIP32Arg) or a raw privkey (ECPairArg)
   * @throws Error if signing fails, or if generateMusig2Nonces() was not called first for MuSig2 inputs
   *
   * @example
   * ```typescript
   * // Sign a specific MuSig2 input after nonce generation
   * psbt.generateMusig2Nonces(userXpriv);
   * psbt.signInput(musig2InputIndex, userXpriv);
   *
   * // Sign a specific replay protection input
   * psbt.signInput(rpInputIndex, replayProtectionPrivkey);
   * ```
   */
  signInput(inputIndex: number, key: BIP32Arg | ECPairArg): void {
    if (isBIP32Arg(key)) {
      // It's a BIP32Arg
      const wasmKey = BIP32.from(key);
      // Route to the appropriate method based on input type
      if (this._wasm.is_musig2_input(inputIndex)) {
        // MuSig2 keypath: true single-input signing (efficient)
        this._wasm.sign_musig2_input(inputIndex, wasmKey.wasm);
      } else {
        // ECDSA/Schnorr script path: save/restore pattern (not faster than bulk)
        this._wasm.sign_wallet_input(inputIndex, wasmKey.wasm);
      }
    } else {
      // It's an ECPairArg - for replay protection inputs
      const wasmKey = ECPair.from(key as ECPairArg);
      this._wasm.sign_with_privkey(inputIndex, wasmKey.wasm);
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
    const rp = ReplayProtection.from(replayProtection, this._wasm.network());
    return this._wasm.verify_replay_protection_signature(inputIndex, rp.wasm);
  }

  /**
   * Serialize the PSBT to bytes
   *
   * @returns The serialized PSBT as a byte array
   */
  serialize(): Uint8Array {
    return this._wasm.serialize();
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
    this._wasm.generate_musig2_nonces(wasmKey.wasm, sessionId);
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
    this._wasm.combine_musig2_nonces(sourcePsbt.wasm);
  }

  /**
   * Finalize all inputs in the PSBT
   *
   * @throws Error if any input failed to finalize
   */
  finalizeAllInputs(): void {
    this._wasm.finalize_all_inputs();
  }

  /**
   * Extract the final transaction from a finalized PSBT
   *
   * @returns The extracted transaction instance
   * @throws Error if the PSBT is not fully finalized or extraction fails
   */
  extractTransaction(): ITransaction {
    const networkType = this._wasm.get_network_type();
    const wasm: unknown = this._wasm.extract_transaction();

    switch (networkType) {
      case "dash":
        return DashTransaction.fromWasm(wasm as Parameters<typeof DashTransaction.fromWasm>[0]);
      case "zcash":
        return ZcashTransaction.fromWasm(wasm as Parameters<typeof ZcashTransaction.fromWasm>[0]);
      default:
        return Transaction.fromWasm(wasm as Parameters<typeof Transaction.fromWasm>[0]);
    }
  }

  /**
   * Extract a half-signed transaction in legacy format for p2ms-based script types.
   *
   * This method extracts a transaction where each input has exactly one signature,
   * formatted in the legacy style used by utxo-lib and bitcoinjs-lib. The legacy
   * format places signatures in the correct position (0, 1, or 2) based on which
   * key signed, with empty placeholders for unsigned positions.
   *
   * Requirements:
   * - All inputs must be p2ms-based (p2sh, p2shP2wsh, or p2wsh)
   * - Each input must have exactly 1 partial signature
   *
   * @returns The serialized half-signed transaction bytes
   * @throws Error if any input is not a p2ms type (Taproot, replay protection, etc.)
   * @throws Error if any input has 0 or more than 1 partial signature
   *
   * @example
   * ```typescript
   * // Sign with user key only
   * psbt.sign(userXpriv);
   *
   * // Extract half-signed transaction in legacy format
   * const halfSignedTx = psbt.getHalfSignedLegacyFormat();
   * ```
   */
  getHalfSignedLegacyFormat(): Uint8Array {
    return this._wasm.extract_half_signed_legacy_tx();
  }

  /**
   * Get the number of inputs in the PSBT
   * @returns The number of inputs
   */
  get inputCount(): number {
    return this._wasm.input_count();
  }

  /**
   * Get the number of outputs in the PSBT
   * @returns The number of outputs
   */
  get outputCount(): number {
    return this._wasm.output_count();
  }

  /**
   * Get all PSBT inputs as an array
   *
   * Returns raw PSBT input data including witness_utxo and derivation info.
   * For parsed transaction data with address identification, use
   * parseTransactionWithWalletKeys() instead.
   *
   * @returns Array of PsbtInputData objects
   */
  getInputs(): PsbtInputData[] {
    return this._wasm.get_inputs() as PsbtInputData[];
  }

  /**
   * Get all PSBT outputs as an array
   *
   * Returns raw PSBT output data without address resolution.
   * For output data with addresses, use getOutputsWithAddress().
   *
   * @returns Array of PsbtOutputData objects
   */
  getOutputs(): PsbtOutputData[] {
    return this._wasm.get_outputs() as PsbtOutputData[];
  }

  /**
   * Get all PSBT outputs with resolved address strings
   *
   * Unlike the generic Psbt class which requires a coin parameter,
   * BitGoPsbt automatically uses the network it was created with to resolve addresses.
   *
   * @returns Array of PsbtOutputDataWithAddress objects
   *
   * @example
   * ```typescript
   * const outputs = psbt.getOutputsWithAddress();
   * for (const output of outputs) {
   *   console.log(`${output.address}: ${output.value} satoshis`);
   * }
   * ```
   */
  getOutputsWithAddress(): PsbtOutputDataWithAddress[] {
    return this._wasm.get_outputs_with_address() as PsbtOutputDataWithAddress[];
  }
}
