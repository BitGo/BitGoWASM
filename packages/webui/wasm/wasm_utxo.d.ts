/* tslint:disable */
/* eslint-disable */

export class AddressNamespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static from_output_script_with_coin(script: Uint8Array, coin: string, format?: string | null): string;
    static to_output_script_with_coin(address: string, coin: string): Uint8Array;
}

/**
 * Namespace for BIP-0322 functions
 */
export class Bip322Namespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add a BIP-0322 message input to an existing BitGoPsbt
     *
     * If this is the first input, also adds the OP_RETURN output.
     * The PSBT must have version 0 per BIP-0322 specification.
     *
     * # Arguments
     * * `psbt` - The BitGoPsbt to add the input to
     * * `message` - The message to sign
     * * `chain` - The wallet chain (e.g., 10 for external, 20 for internal)
     * * `index` - The address index
     * * `wallet_keys` - The wallet's root keys
     * * `signer` - Optional signer key name for taproot (e.g., "user", "backup", "bitgo")
     * * `cosigner` - Optional cosigner key name for taproot
     * * `tag` - Optional custom tag for message hashing
     *
     * # Returns
     * The index of the added input
     */
    static add_bip322_input(psbt: BitGoPsbt, message: string, chain: number, index: number, wallet_keys: WasmRootWalletKeys, signer?: string | null, cosigner?: string | null, tag?: string | null): number;
    /**
     * Verify a single input of a BIP-0322 PSBT proof
     *
     * # Arguments
     * * `psbt` - The signed BitGoPsbt
     * * `input_index` - The index of the input to verify
     * * `message` - The message that was signed
     * * `chain` - The wallet chain
     * * `index` - The address index
     * * `wallet_keys` - The wallet's root keys
     * * `tag` - Optional custom tag for message hashing
     *
     * # Returns
     * An array of signer names ("user", "backup", "bitgo") that have valid signatures
     *
     * # Throws
     * Throws an error if verification fails or no valid signatures found
     */
    static verify_bip322_psbt_input(psbt: BitGoPsbt, input_index: number, message: string, chain: number, index: number, wallet_keys: WasmRootWalletKeys, tag?: string | null): string[];
    /**
     * Verify a single input of a BIP-0322 PSBT proof using pubkeys directly
     *
     * # Arguments
     * * `psbt` - The signed BitGoPsbt
     * * `input_index` - The index of the input to verify
     * * `message` - The message that was signed
     * * `pubkeys` - Array of 3 hex-encoded pubkeys [user, backup, bitgo]
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
     * * `is_script_path` - For taproot types, whether script path was used
     * * `tag` - Optional custom tag for message hashing
     *
     * # Returns
     * An array of pubkey indices (0, 1, 2) that have valid signatures
     *
     * # Throws
     * Throws an error if verification fails or no valid signatures found
     */
    static verify_bip322_psbt_input_with_pubkeys(psbt: BitGoPsbt, input_index: number, message: string, pubkeys: string[], script_type: string, is_script_path?: boolean | null, tag?: string | null): Uint32Array;
    /**
     * Verify a single input of a BIP-0322 transaction proof
     *
     * # Arguments
     * * `tx` - The signed transaction
     * * `input_index` - The index of the input to verify
     * * `message` - The message that was signed
     * * `chain` - The wallet chain
     * * `index` - The address index
     * * `wallet_keys` - The wallet's root keys
     * * `network` - Network name
     * * `tag` - Optional custom tag for message hashing
     *
     * # Throws
     * Throws an error if verification fails
     */
    static verify_bip322_tx_input(tx: WasmTransaction, input_index: number, message: string, chain: number, index: number, wallet_keys: WasmRootWalletKeys, network: string, tag?: string | null): void;
    /**
     * Verify a single input of a BIP-0322 transaction proof using pubkeys directly
     *
     * # Arguments
     * * `tx` - The signed transaction
     * * `input_index` - The index of the input to verify
     * * `message` - The message that was signed
     * * `pubkeys` - Array of 3 hex-encoded pubkeys [user, backup, bitgo]
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
     * * `is_script_path` - For taproot types, whether script path was used
     * * `tag` - Optional custom tag for message hashing
     *
     * # Returns
     * An array of pubkey indices (0, 1, 2) that have valid signatures
     *
     * # Throws
     * Throws an error if verification fails
     */
    static verify_bip322_tx_input_with_pubkeys(tx: WasmTransaction, input_index: number, message: string, pubkeys: string[], script_type: string, is_script_path?: boolean | null, tag?: string | null): Uint32Array;
}

export class BitGoPsbt {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add an input to the PSBT
     *
     * # Arguments
     * * `txid` - The transaction ID (hex string) of the output being spent
     * * `vout` - The output index being spent
     * * `value` - The value in satoshis of the output being spent
     * * `script` - The output script (scriptPubKey) of the output being spent
     * * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
     *
     * # Returns
     * The index of the newly added input
     */
    add_input(txid: string, vout: number, value: bigint, script: Uint8Array, sequence?: number | null, prev_tx?: Uint8Array | null): number;
    /**
     * Add an output to the PSBT
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     */
    add_output(script: Uint8Array, value: bigint): number;
    /**
     * Add an output to the PSBT by address
     *
     * # Arguments
     * * `address` - The destination address
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     */
    add_output_with_address(address: string, value: bigint): number;
    /**
     * Add a PayGo attestation to a PSBT output
     *
     * # Arguments
     * - `output_index`: The index of the output to add the attestation to
     * - `entropy`: 64 bytes of entropy
     * - `signature`: ECDSA signature bytes
     *
     * # Returns
     * - `Ok(())` if the attestation was successfully added
     * - `Err(WasmUtxoError)` if the output index is out of bounds or entropy is invalid
     */
    add_paygo_attestation(output_index: number, entropy: Uint8Array, signature: Uint8Array): void;
    /**
     * Add a replay protection input to the PSBT
     *
     * Replay protection inputs are P2SH-P2PK inputs used on forked networks to prevent
     * transaction replay attacks. They use a simple pubkey script without wallet derivation.
     *
     * # Arguments
     * * `ecpair` - The ECPair containing the public key for the replay protection input
     * * `txid` - The transaction ID (hex string) of the output being spent
     * * `vout` - The output index being spent
     * * `value` - The value in satoshis
     * * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
     *
     * # Returns
     * The index of the newly added input
     */
    add_replay_protection_input(ecpair: WasmECPair, txid: string, vout: number, value: bigint, sequence?: number | null, prev_tx?: Uint8Array | null): number;
    /**
     * Add a wallet input with full PSBT metadata
     *
     * This is a higher-level method that adds an input and populates all required
     * PSBT fields (scripts, derivation info, etc.) based on the wallet's chain type.
     *
     * # Arguments
     * * `txid` - The transaction ID (hex string)
     * * `vout` - The output index being spent
     * * `value` - The value in satoshis
     * * `chain` - The chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
     * * `index` - The derivation index
     * * `wallet_keys` - The root wallet keys
     * * `signer` - The key that will sign ("user", "backup", or "bitgo") - required for p2tr/p2trMusig2
     * * `cosigner` - The key that will co-sign - required for p2tr/p2trMusig2
     * * `sequence` - Optional sequence number (default: 0xFFFFFFFE for RBF)
     * * `prev_tx` - Optional full previous transaction bytes (for non-segwit)
     *
     * # Returns
     * The index of the newly added input
     */
    add_wallet_input(txid: string, vout: number, value: bigint, wallet_keys: WasmRootWalletKeys, chain: number, index: number, signer?: string | null, cosigner?: string | null, sequence?: number | null, prev_tx?: Uint8Array | null): number;
    /**
     * Add a wallet output with full PSBT metadata
     *
     * This creates a verifiable wallet output (typically for change) with all required
     * PSBT fields (scripts, derivation info) based on the wallet's chain type.
     *
     * # Arguments
     * * `chain` - The chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
     * * `index` - The derivation index
     * * `value` - The value in satoshis
     * * `wallet_keys` - The root wallet keys
     *
     * # Returns
     * The index of the newly added output
     */
    add_wallet_output(chain: number, index: number, value: bigint, wallet_keys: WasmRootWalletKeys): number;
    /**
     * Combine/merge data from another PSBT into this one
     *
     * This method copies MuSig2 nonces and signatures (proprietary key-value pairs) from the
     * source PSBT to this PSBT. This is useful for merging PSBTs during the nonce exchange
     * and signature collection phases.
     *
     * # Arguments
     * * `source_psbt` - The source PSBT containing data to merge
     *
     * # Returns
     * Ok(()) if data was successfully merged
     *
     * # Errors
     * Returns error if networks don't match
     */
    combine_musig2_nonces(source_psbt: BitGoPsbt): void;
    /**
     * Create an empty PSBT for the given network with wallet keys
     *
     * # Arguments
     * * `network` - Network name (utxolib or coin name)
     * * `wallet_keys` - The wallet's root keys (used to set global xpubs)
     * * `version` - Optional transaction version (default: 2)
     * * `lock_time` - Optional lock time (default: 0)
     */
    static create_empty(network: string, wallet_keys: WasmRootWalletKeys, version?: number | null, lock_time?: number | null): BitGoPsbt;
    /**
     * Create an empty Zcash PSBT with the required consensus branch ID
     *
     * This method is specifically for Zcash networks which require additional
     * parameters for sighash computation.
     *
     * # Arguments
     * * `network` - Network name (must be "zcash" or "zcashTest")
     * * `wallet_keys` - The wallet's root keys (used to set global xpubs)
     * * `consensus_branch_id` - Zcash consensus branch ID (e.g., 0xC2D6D0B4 for NU5)
     * * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
     * * `lock_time` - Optional lock time (default: 0)
     * * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
     * * `expiry_height` - Optional expiry height
     */
    static create_empty_zcash(network: string, wallet_keys: WasmRootWalletKeys, consensus_branch_id: number, version?: number | null, lock_time?: number | null, version_group_id?: number | null, expiry_height?: number | null): BitGoPsbt;
    /**
     * Create an empty Zcash PSBT with consensus branch ID determined from block height
     *
     * This method automatically determines the correct consensus branch ID based on
     * the network and block height using the network upgrade activation heights.
     *
     * # Arguments
     * * `network` - Network name (must be "zcash" or "zcashTest")
     * * `wallet_keys` - The wallet's root keys (used to set global xpubs)
     * * `block_height` - Block height to determine consensus rules
     * * `version` - Optional transaction version (default: 4 for Zcash Sapling+)
     * * `lock_time` - Optional lock time (default: 0)
     * * `version_group_id` - Optional version group ID (defaults to Sapling: 0x892F2085)
     * * `expiry_height` - Optional expiry height
     *
     * # Errors
     * Returns error if block height is before Overwinter activation
     */
    static create_empty_zcash_at_height(network: string, wallet_keys: WasmRootWalletKeys, block_height: number, version?: number | null, lock_time?: number | null, version_group_id?: number | null, expiry_height?: number | null): BitGoPsbt;
    /**
     * Get the Zcash expiry height (returns None for non-Zcash PSBTs)
     */
    expiry_height(): number | undefined;
    /**
     * Extract the final transaction as a WasmTransaction (for BitcoinLike networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Bitcoin-like networks (not Dash or Zcash).
     */
    extract_bitcoin_transaction(): WasmTransaction;
    /**
     * Extract the final transaction as a WasmDashTransaction (for Dash networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Dash networks.
     */
    extract_dash_transaction(): WasmDashTransaction;
    /**
     * Extract a half-signed transaction in legacy format for p2ms-based script types.
     *
     * This method extracts a transaction where each input has exactly one signature,
     * formatted in the legacy style used by utxo-lib and bitcoinjs-lib. The legacy
     * format places signatures in the correct position (0, 1, or 2) based on which
     * key signed, with empty placeholders for unsigned positions.
     *
     * # Requirements
     * - All inputs must be p2ms-based (p2sh, p2shP2wsh, or p2wsh)
     * - Each input must have exactly 1 partial signature
     *
     * # Returns
     * - `Ok(Vec<u8>)` containing the serialized half-signed transaction bytes
     * - `Err(WasmUtxoError)` if validation fails or extraction fails
     *
     * # Errors
     * - Returns error if any input is not a p2ms type (Taproot, replay protection, etc.)
     * - Returns error if any input has 0 or more than 1 partial signature
     */
    extract_half_signed_legacy_tx(): Uint8Array;
    /**
     * Extract the final transaction from a finalized PSBT
     *
     * This method should be called after all inputs have been finalized.
     * It extracts the fully signed transaction as a WASM transaction instance
     * appropriate for the network (WasmTransaction, WasmDashTransaction, or WasmZcashTransaction).
     *
     * # Returns
     * - `Ok(JsValue)` containing the WASM transaction instance
     * - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
     */
    extract_transaction(): any;
    /**
     * Extract the final transaction as a WasmZcashTransaction (for Zcash networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Zcash networks.
     */
    extract_zcash_transaction(): WasmZcashTransaction;
    /**
     * Finalize all inputs in the PSBT
     *
     * This method attempts to finalize all inputs in the PSBT, computing the final
     * scriptSig and witness data for each input.
     *
     * # Returns
     * - `Ok(())` if all inputs were successfully finalized
     * - `Err(WasmUtxoError)` if any input failed to finalize
     */
    finalize_all_inputs(): void;
    /**
     * Deserialize a PSBT from bytes with network-specific logic
     */
    static from_bytes(bytes: Uint8Array, network: string): BitGoPsbt;
    /**
     * Generate and store MuSig2 nonces for all MuSig2 inputs
     *
     * This method generates nonces using the State-Machine API and stores them in the PSBT.
     * The nonces are stored as proprietary fields in the PSBT and will be included when serialized.
     * After ALL participants have generated their nonces, they can sign MuSig2 inputs using
     * sign_with_xpriv().
     *
     * # Arguments
     * * `xpriv` - The extended private key (xpriv) for signing
     * * `session_id_bytes` - Optional 32-byte session ID for nonce generation. **Only allowed on testnets**.
     *                        On mainnets, a secure random session ID is always generated automatically.
     *                        Must be unique per signing session.
     *
     * # Returns
     * Ok(()) if nonces were successfully generated and stored
     *
     * # Errors
     * Returns error if:
     * - Nonce generation fails
     * - session_id length is invalid
     * - Custom session_id is provided on a mainnet (security restriction)
     *
     * # Security
     * The session_id MUST be cryptographically random and unique for each signing session.
     * Never reuse a session_id with the same key! On mainnets, session_id is always randomly
     * generated for security. Custom session_id is only allowed on testnets for testing purposes.
     */
    generate_musig2_nonces(xpriv: WasmBIP32, session_id_bytes?: Uint8Array | null): void;
    /**
     * Get all PSBT inputs as an array of PsbtInputData
     *
     * Returns an array with witness_utxo, bip32_derivation, and tap_bip32_derivation
     * for each input.
     */
    get_inputs(): any;
    /**
     * Get the network type for transaction extraction
     *
     * Returns "bitcoin", "dash", or "zcash" to indicate which transaction
     * wrapper class should be used in TypeScript.
     */
    get_network_type(): string;
    /**
     * Get all PSBT outputs as an array of PsbtOutputData
     *
     * Returns an array with script, value, bip32_derivation, and tap_bip32_derivation
     * for each output.
     */
    get_outputs(): any;
    /**
     * Get all PSBT outputs with resolved address strings.
     *
     * Unlike the generic WrapPsbt which requires a coin parameter, BitGoPsbt
     * uses the network it was created/deserialized with to resolve addresses.
     */
    get_outputs_with_address(): any;
    /**
     * Get the number of inputs in the PSBT
     */
    input_count(): number;
    /**
     * Check if an input is a MuSig2 keypath input.
     *
     * MuSig2 inputs require special handling: nonces must be generated first with
     * `generate_musig2_nonces()`, then signed with `sign_musig2_input()`.
     *
     * # Arguments
     * - `input_index`: The index of the input to check (0-based)
     *
     * # Returns
     * - `true` if the input is a MuSig2 keypath input
     * - `false` otherwise (or if input_index is out of bounds)
     */
    is_musig2_input(input_index: number): boolean;
    /**
     * Get the transaction lock time
     */
    lock_time(): number;
    /**
     * Get the network of the PSBT
     */
    network(): string;
    /**
     * Get the number of outputs in the PSBT
     */
    output_count(): number;
    /**
     * Parse outputs with wallet keys to identify which outputs belong to a wallet
     *
     * Note: This method does NOT validate wallet inputs. It only parses outputs.
     */
    parse_outputs_with_wallet_keys(wallet_keys: WasmRootWalletKeys, paygo_pubkeys?: WasmECPair[] | null): any;
    /**
     * Parse transaction with wallet keys to identify wallet inputs/outputs
     */
    parse_transaction_with_wallet_keys(wallet_keys: WasmRootWalletKeys, replay_protection: WasmReplayProtection, paygo_pubkeys?: WasmECPair[] | null): any;
    /**
     * Serialize the PSBT to bytes
     *
     * # Returns
     * The serialized PSBT as a byte array
     */
    serialize(): Uint8Array;
    /**
     * Sign all MuSig2 keypath inputs in a single pass with optimized sighash computation.
     *
     * This is more efficient than calling `sign_musig2_input()` for each input because
     * it reuses the SighashCache across all inputs, avoiding redundant computation of
     * sha_prevouts, sha_amounts, sha_scriptpubkeys, sha_sequences, and sha_outputs.
     *
     * Each MuSig2 input requires a FirstRound from `generate_musig2_nonces()`.
     * FirstRounds that have already been consumed (signed) are skipped.
     *
     * # Arguments
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(JsValue)` with an array of input indices that were signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_all_musig2_inputs(xpriv: WasmBIP32): any;
    /**
     * Sign all replay protection inputs with a raw private key.
     *
     * This iterates through all inputs looking for P2SH-P2PK (replay protection) inputs
     * that match the provided public key and signs them.
     *
     * # Arguments
     * - `ecpair`: The ECPair containing the private key
     *
     * # Returns
     * - `Ok(JsValue)` with an array of input indices that were signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_all_replay_protection_inputs(ecpair: WasmECPair): any;
    /**
     * Sign all non-MuSig2 wallet inputs in a single efficient pass.
     *
     * This signs all ECDSA (P2SH, P2SH-P2WSH, P2WSH) and Taproot script path (P2TR)
     * inputs that match the provided xpriv. MuSig2 keypath inputs are skipped.
     *
     * This is the most efficient way to sign wallet inputs. After calling this,
     * sign any MuSig2 inputs using `sign_all_musig2_inputs()` or `sign_musig2_input()`.
     *
     * # Arguments
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(JsValue)` with an array of input indices that were signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_all_wallet_inputs(xpriv: WasmBIP32): any;
    /**
     * Sign all non-MuSig2 inputs with an extended private key (xpriv) in a single pass.
     *
     * This is more efficient than calling `sign_with_xpriv` for each input individually.
     * The underlying miniscript library's `sign` method signs all matching inputs at once.
     *
     * **Note:** MuSig2 inputs are skipped by this method because they require FirstRound
     * state from nonce generation. After calling this method, sign MuSig2 inputs
     * individually using `sign_with_xpriv`.
     *
     * # Arguments
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(JsValue)` with an array of input indices that were signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_all_with_xpriv(xpriv: WasmBIP32): any;
    /**
     * Sign a single MuSig2 keypath input.
     *
     * This uses the FirstRound state generated by `generate_musig2_nonces()`.
     * Each FirstRound can only be used once (nonce reuse is a security risk).
     *
     * For non-MuSig2 inputs, returns an error (use `sign_wallet_input` instead).
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(())` if signing was successful
     * - `Err(WasmUtxoError)` if signing fails, no FirstRound exists, or not a MuSig2 input
     */
    sign_musig2_input(input_index: number, xpriv: WasmBIP32): void;
    /**
     * Sign all replay protection inputs with a raw private key.
     *
     * This iterates through all inputs looking for P2SH-P2PK (replay protection) inputs
     * that match the provided public key and signs them.
     *
     * # Arguments
     * - `ecpair`: The ECPair containing the private key
     *
     * # Returns
     * - `Ok(JsValue)` with an array of input indices that were signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_replay_protection_inputs(ecpair: WasmECPair): any;
    /**
     * Sign a single input with a raw private key, using save/restore for regular inputs.
     *
     * For replay protection inputs (P2SH-P2PK), this uses direct signing which is
     * already single-input. For regular inputs, this clones the PSBT, signs all,
     * then copies only the target input's signatures back.
     *
     * **Important:** This is NOT faster than signing all inputs for regular (non-RP) inputs.
     * The underlying miniscript library signs all inputs regardless.
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `ecpair`: The ECPair containing the private key
     *
     * # Returns
     * - `Ok(())` if the input was signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_single_input_with_privkey(input_index: number, ecpair: WasmECPair): void;
    /**
     * Sign a single input with an extended private key, using save/restore for ECDSA inputs.
     *
     * For MuSig2 inputs, this returns an error (use sign_with_xpriv which handles FirstRound).
     * For ECDSA inputs, this clones the PSBT, signs all, then copies only the target
     * input's signatures back.
     *
     * **Important:** This is NOT faster than `sign_all_with_xpriv` for ECDSA inputs.
     * The underlying miniscript library signs all inputs regardless. This method
     * just prevents signatures from being added to other inputs.
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(())` if the input was signed
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_single_input_with_xpriv(input_index: number, xpriv: WasmBIP32): void;
    /**
     * Sign a single non-MuSig2 wallet input using save/restore pattern.
     *
     * For MuSig2 inputs, returns an error (use `sign_musig2_input` instead).
     * For ECDSA inputs, this uses a save/restore pattern: clones the PSBT,
     * signs all inputs on the clone, then copies only the target input's
     * signatures back.
     *
     * **Important:** This is NOT faster than `sign_all_wallet_inputs()` for ECDSA inputs.
     * The underlying library signs all inputs regardless. This method just ensures
     * that only the specified input gets signatures added to the PSBT.
     * Use `sign_all_wallet_inputs()` when signing multiple inputs with the same key.
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(())` if the input was signed
     * - `Err(WasmUtxoError)` if signing fails or input is MuSig2
     */
    sign_wallet_input(input_index: number, xpriv: WasmBIP32): void;
    /**
     * Sign a single input with a raw private key
     *
     * This method signs a specific input using the provided ECPair. It accepts:
     * - A raw privkey (WasmECPair) for replay protection inputs - signs directly
     *
     * This method automatically detects and handles different input types:
     * - For replay protection inputs: signs with legacy P2SH sighash
     * - For regular inputs: uses standard PSBT signing
     * - For MuSig2 inputs: returns error (requires FirstRound, use sign_with_xpriv instead)
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `ecpair`: The ECPair containing the private key
     *
     * # Returns
     * - `Ok(())` if signing was successful
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_with_privkey(input_index: number, ecpair: WasmECPair): void;
    /**
     * Sign a single input with an extended private key (xpriv)
     *
     * This method signs a specific input using the provided xpriv. It accepts:
     * - An xpriv (WasmBIP32) for wallet inputs - derives the key and signs
     *
     * This method automatically detects and handles different input types:
     * - For regular inputs: uses standard PSBT signing
     * - For MuSig2 inputs: uses the FirstRound state stored by generate_musig2_nonces()
     * - For replay protection inputs: returns error (use sign_with_privkey instead)
     *
     * # Arguments
     * - `input_index`: The index of the input to sign (0-based)
     * - `xpriv`: The extended private key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(())` if signing was successful
     * - `Err(WasmUtxoError)` if signing fails
     */
    sign_with_xpriv(input_index: number, xpriv: WasmBIP32): void;
    /**
     * Get the unsigned transaction ID
     */
    unsigned_txid(): string;
    /**
     * Verify if a replay protection input has a valid signature
     *
     * This method checks if a given input is a replay protection input and cryptographically verifies
     * the signature. Replay protection inputs (like P2shP2pk) don't use standard derivation paths,
     * so this method verifies signatures without deriving from xpub.
     *
     * # Arguments
     * - `input_index`: The index of the input to check
     * - `replay_protection`: Replay protection configuration (same format as parseTransactionWithWalletKeys)
     *   Can be either `{ outputScripts: Buffer[] }` or `{ addresses: string[] }`
     *
     * # Returns
     * - `Ok(true)` if the input is a replay protection input and has a valid signature
     * - `Ok(false)` if the input is a replay protection input but has no valid signature
     * - `Err(WasmUtxoError)` if the input is not a replay protection input, index is out of bounds, or configuration is invalid
     */
    verify_replay_protection_signature(input_index: number, replay_protection: WasmReplayProtection): boolean;
    /**
     * Verify if a valid signature exists for a given ECPair key at the specified input index
     *
     * This method verifies the signature directly with the provided ECPair's public key. It supports:
     * - ECDSA signatures (for legacy/SegWit inputs)
     * - Schnorr signatures (for Taproot script path inputs)
     *
     * Note: This method does NOT support MuSig2 inputs, as MuSig2 requires derivation from xpubs.
     * Use `verify_signature_with_xpub` for MuSig2 inputs.
     *
     * # Arguments
     * - `input_index`: The index of the input to check
     * - `ecpair`: The ECPair key (uses the public key for verification)
     *
     * # Returns
     * - `Ok(true)` if a valid signature exists for the public key
     * - `Ok(false)` if no signature exists for the public key
     * - `Err(WasmUtxoError)` if the input index is out of bounds or verification fails
     */
    verify_signature_with_pub(input_index: number, ecpair: WasmECPair): boolean;
    /**
     * Verify if a valid signature exists for a given xpub at the specified input index
     *
     * This method derives the public key from the xpub using the derivation path found in the
     * PSBT input, then verifies the signature. It supports:
     * - ECDSA signatures (for legacy/SegWit inputs)
     * - Schnorr signatures (for Taproot script path inputs)
     * - MuSig2 partial signatures (for Taproot keypath MuSig2 inputs)
     *
     * # Arguments
     * - `input_index`: The index of the input to check
     * - `xpub`: The extended public key as a WasmBIP32 instance
     *
     * # Returns
     * - `Ok(true)` if a valid signature exists for the derived public key
     * - `Ok(false)` if no signature exists for the derived public key
     * - `Err(WasmUtxoError)` if the input index is out of bounds, derivation fails, or verification fails
     */
    verify_signature_with_xpub(input_index: number, xpub: WasmBIP32): boolean;
    /**
     * Get the transaction version
     */
    version(): number;
    /**
     * Get the Zcash version group ID (returns None for non-Zcash PSBTs)
     */
    version_group_id(): number | undefined;
}

export class FixedScriptWalletNamespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    static address(keys: WasmRootWalletKeys, chain: number, index: number, network: any, address_format?: string | null): string;
    static address_with_network_str(keys: WasmRootWalletKeys, chain: number, index: number, network: string, address_format?: string | null): string;
    /**
     * Get all chain code metadata for building TypeScript lookup tables
     *
     * Returns an array of [chainCode, scriptType, scope] tuples where:
     * - chainCode: u32 (0, 1, 10, 11, 20, 21, 30, 31, 40, 41)
     * - scriptType: string ("p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy", "p2trMusig2")
     * - scope: string ("external" or "internal")
     */
    static chain_code_table(): any;
    /**
     * Create an OP_RETURN output script with optional data
     *
     * # Arguments
     * * `data` - Optional data bytes to include in the OP_RETURN script
     *
     * # Returns
     * The OP_RETURN script as bytes
     */
    static create_op_return_script(data?: Uint8Array | null): Uint8Array;
    static output_script(keys: WasmRootWalletKeys, chain: number, index: number, network: any): Uint8Array;
    static output_script_with_network_str(keys: WasmRootWalletKeys, chain: number, index: number, network: string): Uint8Array;
    /**
     * Get the P2SH-P2PK output script for a compressed public key
     *
     * # Arguments
     * * `pubkey` - The compressed public key bytes (33 bytes)
     *
     * # Returns
     * The P2SH-P2PK output script as bytes
     */
    static p2sh_p2pk_output_script(pubkey: Uint8Array): Uint8Array;
    /**
     * Check if a network supports a given fixed-script wallet script type
     *
     * # Arguments
     * * `coin` - Coin name (e.g., "btc", "ltc", "doge")
     * * `script_type` - Script type name: "p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"
     *
     * # Returns
     * `true` if the network supports the script type, `false` otherwise
     *
     * # Examples
     * - Bitcoin supports all script types (p2sh, p2shP2wsh, p2wsh, p2tr, p2trMusig2)
     * - Litecoin supports segwit but not taproot (p2sh, p2shP2wsh, p2wsh)
     * - Dogecoin only supports legacy scripts (p2sh)
     */
    static supports_script_type(coin: string, script_type: string): boolean;
}

/**
 * Namespace for inscription-related functions
 */
export class InscriptionsNamespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create inscription reveal data including the commit output script and tap leaf script
     *
     * # Arguments
     * * `x_only_pubkey` - The x-only public key (32 bytes)
     * * `content_type` - MIME type of the inscription (e.g., "text/plain", "image/png")
     * * `inscription_data` - The inscription data bytes
     *
     * # Returns
     * An object containing:
     * - `output_script`: The commit output script (P2TR, network-agnostic)
     * - `reveal_transaction_vsize`: Estimated vsize of the reveal transaction
     * - `tap_leaf_script`: Object with `leaf_version`, `script`, and `control_block`
     */
    static create_inscription_reveal_data(x_only_pubkey: Uint8Array, content_type: string, inscription_data: Uint8Array): any;
    /**
     * Sign a reveal transaction
     *
     * # Arguments
     * * `private_key` - The private key (32 bytes)
     * * `tap_leaf_script` - The tap leaf script object from `create_inscription_reveal_data`
     * * `commit_tx` - The commit transaction
     * * `commit_output_script` - The commit output script (P2TR)
     * * `recipient_output_script` - Where to send the inscription (output script)
     * * `output_value_sats` - Value in satoshis for the inscription output
     *
     * # Returns
     * The signed PSBT as bytes
     */
    static sign_reveal_transaction(private_key: Uint8Array, tap_leaf_script: any, commit_tx: WasmTransaction, commit_output_script: Uint8Array, recipient_output_script: Uint8Array, output_value_sats: bigint): Uint8Array;
}

export class MessageNamespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Sign a message using Bitcoin message signing (BIP-137)
     *
     * Returns 65-byte signature (1-byte header + 64-byte signature).
     * The key must have a private key (cannot sign with public key only).
     */
    static sign_message(key: WasmECPair, message_str: string): Uint8Array;
    /**
     * Verify a Bitcoin message signature (BIP-137)
     *
     * Signature must be 65 bytes (1-byte header + 64-byte signature).
     * Returns true if the signature is valid for this key.
     */
    static verify_message(key: WasmECPair, message_str: string, signature: Uint8Array): boolean;
}

export class UtxolibCompatNamespace {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Convert output script to address string
     *
     * # Arguments
     * * `script` - The output script as a byte array
     * * `network` - The UtxolibNetwork object from JavaScript
     * * `format` - Optional address format: "default" or "cashaddr" (only applicable for Bitcoin Cash and eCash)
     */
    static from_output_script(script: Uint8Array, network: any, format?: string | null): string;
    /**
     * Convert address string to output script
     *
     * # Arguments
     * * `address` - The address string
     * * `network` - The UtxolibNetwork object from JavaScript
     * * `format` - Optional address format (currently unused for decoding as all formats are accepted)
     */
    static to_output_script(address: string, network: any, format?: string | null): Uint8Array;
}

/**
 * WASM wrapper for BIP32 extended keys (Xpub/Xpriv)
 * Implements the BIP32Interface TypeScript interface
 */
export class WasmBIP32 {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Derive a normal (non-hardened) child key
     */
    derive(index: number): WasmBIP32;
    /**
     * Derive a hardened child key (only works for private keys)
     */
    derive_hardened(index: number): WasmBIP32;
    /**
     * Derive a key using a derivation path (e.g., "0/1/2" or "m/0/1/2")
     */
    derive_path(path: string): WasmBIP32;
    /**
     * Check equality with another WasmBIP32 key.
     * Two keys are equal if they have the same type (public/private) and identical
     * BIP32 metadata (depth, parent fingerprint, child index, chain code, key data).
     */
    equals(other: WasmBIP32): boolean;
    /**
     * Create a BIP32 key from a base58 string (xpub/xprv/tpub/tprv)
     */
    static from_base58(base58_str: string): WasmBIP32;
    /**
     * Create a BIP32 key from a BIP32Interface JavaScript object properties
     * Expects an object with: network.bip32.public, depth, parentFingerprint,
     * index, chainCode, and publicKey properties
     */
    static from_bip32_interface(bip32_key: any): WasmBIP32;
    /**
     * Create a BIP32 key from BIP32 properties
     * Extracts properties from a JavaScript object and constructs an xpub or xprv
     */
    static from_bip32_properties(bip32_key: any): WasmBIP32;
    /**
     * Create a BIP32 master key from a seed
     */
    static from_seed(seed: Uint8Array, network?: string | null): WasmBIP32;
    /**
     * Create a BIP32 master key from a string by hashing it with SHA256.
     * This is useful for deterministic test key generation.
     */
    static from_seed_sha256(seed_string: string, network?: string | null): WasmBIP32;
    /**
     * Create a BIP32 key from an xprv string (base58-encoded)
     */
    static from_xprv(xprv_str: string): WasmBIP32;
    /**
     * Create a BIP32 key from an xpub string (base58-encoded)
     */
    static from_xpub(xpub_str: string): WasmBIP32;
    /**
     * Check if this is a neutered (public) key
     */
    is_neutered(): boolean;
    /**
     * Get the neutered (public) version of this key
     */
    neutered(): WasmBIP32;
    /**
     * Serialize to base58 string
     */
    to_base58(): string;
    /**
     * Get the WIF encoding of the private key
     */
    to_wif(): string;
    /**
     * Get the chain code as a Uint8Array
     */
    readonly chain_code: Uint8Array;
    /**
     * Get the depth
     */
    readonly depth: number;
    /**
     * Get the fingerprint as a Uint8Array
     */
    readonly fingerprint: Uint8Array;
    /**
     * Get the identifier as a Uint8Array
     */
    readonly identifier: Uint8Array;
    /**
     * Get the child index
     */
    readonly index: number;
    /**
     * Get the parent fingerprint
     */
    readonly parent_fingerprint: number;
    /**
     * Get the private key as a Uint8Array (if available)
     */
    readonly private_key: Uint8Array | undefined;
    /**
     * Get the public key as a Uint8Array
     */
    readonly public_key: Uint8Array;
}

/**
 * Dash transaction wrapper that supports Dash special transactions (EVO) by preserving extra payload.
 */
export class WasmDashTransaction {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Deserialize a Dash transaction from bytes (supports EVO special tx extra payload).
     */
    static from_bytes(bytes: Uint8Array): WasmDashTransaction;
    /**
     * Get the transaction ID (txid)
     *
     * The txid is the double SHA256 of the full Dash transaction bytes,
     * displayed in reverse byte order (big-endian) as is standard.
     *
     * # Returns
     * The transaction ID as a hex string
     *
     * # Errors
     * Returns an error if the transaction cannot be serialized
     */
    get_txid(): string;
    /**
     * Serialize the Dash transaction to bytes (preserving tx_type and extra payload).
     */
    to_bytes(): Uint8Array;
}

/**
 * Dimensions for estimating transaction virtual size.
 *
 * Tracks weight internally with min/max bounds to handle ECDSA signature variance.
 * Schnorr signatures have no variance (always 64 bytes).
 */
export class WasmDimensions {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create empty dimensions (zero weight)
     */
    static empty(): WasmDimensions;
    /**
     * Create dimensions for a single input from chain code
     *
     * # Arguments
     * * `chain` - Chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
     * * `signer` - Optional signer key ("user", "backup", "bitgo")
     * * `cosigner` - Optional cosigner key ("user", "backup", "bitgo")
     * * `compat` - When true, use 72-byte signatures for max (matches @bitgo/unspents)
     */
    static from_input(chain: number, signer?: string | null, cosigner?: string | null, compat?: boolean | null): WasmDimensions;
    /**
     * Create dimensions for a single input from script type string
     *
     * # Arguments
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy",
     *                   "p2trMusig2KeyPath", "p2trMusig2ScriptPath", "p2shP2pk"
     * * `compat` - When true, use 72-byte signatures for max (matches @bitgo/unspents)
     */
    static from_input_script_type(script_type: string, compat?: boolean | null): WasmDimensions;
    /**
     * Create dimensions for a single output from script length
     */
    static from_output_script_length(length: number): WasmDimensions;
    /**
     * Create dimensions for a single output from script type string
     *
     * # Arguments
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr"/"p2trLegacy", "p2trMusig2"
     */
    static from_output_script_type(script_type: string): WasmDimensions;
    /**
     * Create dimensions from a BitGoPsbt
     *
     * Parses PSBT inputs and outputs to compute weight bounds without
     * requiring wallet keys. Input types are detected from BIP32 derivation
     * paths stored in the PSBT.
     */
    static from_psbt(psbt: BitGoPsbt): WasmDimensions;
    /**
     * Get input virtual size (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     */
    get_input_vsize(size?: string | null): number;
    /**
     * Get input weight only (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     */
    get_input_weight(size?: string | null): number;
    /**
     * Get output virtual size
     */
    get_output_vsize(): number;
    /**
     * Get output weight
     */
    get_output_weight(): number;
    /**
     * Get virtual size (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     */
    get_vsize(size?: string | null): number;
    /**
     * Get total weight (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     */
    get_weight(size?: string | null): number;
    /**
     * Whether any inputs are segwit (affects overhead calculation)
     */
    has_segwit(): boolean;
    /**
     * Combine with another Dimensions instance
     */
    plus(other: WasmDimensions): WasmDimensions;
    /**
     * Multiply dimensions by a scalar
     */
    times(n: number): WasmDimensions;
}

/**
 * WASM wrapper for elliptic curve key pairs (always uses compressed keys)
 */
export class WasmECPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create an ECPair from a private key (always uses compressed keys)
     */
    static from_private_key(private_key: Uint8Array): WasmECPair;
    /**
     * Create an ECPair from a public key (always uses compressed keys)
     */
    static from_public_key(public_key: Uint8Array): WasmECPair;
    /**
     * Create an ECPair from a WIF string (auto-detects network)
     */
    static from_wif(wif_string: string): WasmECPair;
    /**
     * Create an ECPair from a mainnet WIF string
     */
    static from_wif_mainnet(wif_string: string): WasmECPair;
    /**
     * Create an ECPair from a testnet WIF string
     */
    static from_wif_testnet(wif_string: string): WasmECPair;
    /**
     * Convert to WIF string (mainnet)
     */
    to_wif(): string;
    /**
     * Convert to mainnet WIF string
     */
    to_wif_mainnet(): string;
    /**
     * Convert to testnet WIF string
     */
    to_wif_testnet(): string;
    /**
     * Get the private key as a Uint8Array (if available)
     */
    readonly private_key: Uint8Array | undefined;
    /**
     * Get the compressed public key as a Uint8Array (always 33 bytes)
     */
    readonly public_key: Uint8Array;
}

/**
 * WASM wrapper for ReplayProtection
 */
export class WasmReplayProtection {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Create from addresses (requires network for decoding)
     */
    static from_addresses(addresses: any[], network: string): WasmReplayProtection;
    /**
     * Create from output scripts directly
     */
    static from_output_scripts(output_scripts: Uint8Array[]): WasmReplayProtection;
    /**
     * Create from public keys (derives P2SH-P2PK output scripts)
     */
    static from_public_keys(public_keys: Uint8Array[]): WasmReplayProtection;
}

/**
 * WASM wrapper for RootWalletKeys
 * Represents a set of three extended public keys with their derivation prefixes
 */
export class WasmRootWalletKeys {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Get the backup key (second xpub)
     */
    backup_key(): WasmBIP32;
    /**
     * Get the bitgo key (third xpub)
     */
    bitgo_key(): WasmBIP32;
    /**
     * Create a RootWalletKeys from three BIP32 keys
     * Uses default derivation prefix of m/0/0 for all three keys
     *
     * # Arguments
     * - `user`: User key (first xpub)
     * - `backup`: Backup key (second xpub)
     * - `bitgo`: BitGo key (third xpub)
     */
    constructor(user: WasmBIP32, backup: WasmBIP32, bitgo: WasmBIP32);
    /**
     * Get the user key (first xpub)
     */
    user_key(): WasmBIP32;
    /**
     * Create a RootWalletKeys from three BIP32 keys with custom derivation prefixes
     *
     * # Arguments
     * - `user`: User key (first xpub)
     * - `backup`: Backup key (second xpub)
     * - `bitgo`: BitGo key (third xpub)
     * - `user_derivation`: Derivation path for user key (e.g., "m/0/0")
     * - `backup_derivation`: Derivation path for backup key (e.g., "m/0/0")
     * - `bitgo_derivation`: Derivation path for bitgo key (e.g., "m/0/0")
     */
    static with_derivation_prefixes(user: WasmBIP32, backup: WasmBIP32, bitgo: WasmBIP32, user_derivation: string, backup_derivation: string, bitgo_derivation: string): WasmRootWalletKeys;
}

/**
 * A Bitcoin-like transaction (for all networks except Zcash)
 *
 * This class provides basic transaction parsing and serialization for testing
 * compatibility with third-party transaction fixtures.
 */
export class WasmTransaction {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add an input to the transaction
     *
     * # Arguments
     * * `txid` - The transaction ID (hex string) of the output being spent
     * * `vout` - The output index being spent
     * * `sequence` - Optional sequence number (default: 0xFFFFFFFF)
     *
     * # Returns
     * The index of the newly added input
     */
    add_input(txid: string, vout: number, sequence?: number | null): number;
    /**
     * Add an output to the transaction
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     */
    add_output(script: Uint8Array, value: bigint): number;
    /**
     * Create an empty transaction (version 1, locktime 0)
     */
    static create(): WasmTransaction;
    /**
     * Deserialize a transaction from bytes
     *
     * # Arguments
     * * `bytes` - The serialized transaction bytes
     *
     * # Returns
     * A WasmTransaction instance
     *
     * # Errors
     * Returns an error if the bytes cannot be parsed as a valid transaction
     */
    static from_bytes(bytes: Uint8Array): WasmTransaction;
    /**
     * Get the transaction ID (txid)
     *
     * The txid is the double SHA256 of the transaction bytes (excluding witness
     * data for segwit transactions), displayed in reverse byte order (big-endian)
     * as is standard for Bitcoin.
     *
     * # Returns
     * The transaction ID as a hex string
     */
    get_txid(): string;
    /**
     * Get the virtual size of the transaction
     *
     * Virtual size is calculated as ceil(weight / 4), where weight accounts
     * for the segwit discount on witness data.
     *
     * # Returns
     * The virtual size in virtual bytes (vbytes)
     */
    get_vsize(): number;
    /**
     * Serialize the transaction to bytes
     *
     * # Returns
     * The serialized transaction bytes
     */
    to_bytes(): Uint8Array;
}

/**
 * A Zcash transaction with network-specific fields
 *
 * This class provides basic transaction parsing and serialization for Zcash
 * transactions, which use the Overwinter transaction format.
 */
export class WasmZcashTransaction {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Deserialize a Zcash transaction from bytes
     *
     * # Arguments
     * * `bytes` - The serialized transaction bytes
     *
     * # Returns
     * A WasmZcashTransaction instance
     *
     * # Errors
     * Returns an error if the bytes cannot be parsed as a valid Zcash transaction
     */
    static from_bytes(bytes: Uint8Array): WasmZcashTransaction;
    /**
     * Get the transaction ID (txid)
     *
     * The txid is the double SHA256 of the full Zcash transaction bytes,
     * displayed in reverse byte order (big-endian) as is standard.
     *
     * # Returns
     * The transaction ID as a hex string
     *
     * # Errors
     * Returns an error if the transaction cannot be serialized
     */
    get_txid(): string;
    /**
     * Serialize the transaction to bytes
     *
     * # Returns
     * The serialized transaction bytes
     */
    to_bytes(): Uint8Array;
}

export class WrapDescriptor {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    atDerivationIndex(index: number): WrapDescriptor;
    descType(): any;
    encode(): Uint8Array;
    hasWildcard(): boolean;
    maxWeightToSatisfy(): number;
    node(): any;
    scriptPubkey(): Uint8Array;
    toAsmString(): string;
    toString(): string;
}

export class WrapMiniscript {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    encode(): Uint8Array;
    node(): any;
    toAsmString(): string;
    toString(): string;
}

export class WrapPsbt {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Add an input to the PSBT
     *
     * # Arguments
     * * `txid` - Transaction ID (hex string, 32 bytes reversed)
     * * `vout` - Output index being spent
     * * `value` - Value in satoshis of the output being spent
     * * `script` - The scriptPubKey of the output being spent
     * * `sequence` - Sequence number (default: 0xFFFFFFFE for RBF)
     *
     * # Returns
     * The index of the newly added input
     */
    addInput(txid: string, vout: number, value: bigint, script: Uint8Array, sequence?: number | null): number;
    /**
     * Add an output to the PSBT
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - Value in satoshis
     *
     * # Returns
     * The index of the newly added output
     */
    addOutput(script: Uint8Array, value: bigint): number;
    clone(): WrapPsbt;
    static deserialize(psbt: Uint8Array): WrapPsbt;
    /**
     * Extract the final transaction from a finalized PSBT
     *
     * This method should be called after all inputs have been finalized.
     * It extracts the fully signed transaction as a WasmTransaction instance.
     *
     * # Returns
     * - `Ok(WasmTransaction)` containing the extracted transaction
     * - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
     */
    extractTransaction(): WasmTransaction;
    finalize(): void;
    /**
     * Get all PSBT inputs as an array of PsbtInputData
     *
     * Returns an array with witness_utxo, bip32_derivation, and tap_bip32_derivation
     * for each input. This is useful for introspecting the PSBT structure.
     */
    getInputs(): any;
    /**
     * Get all PSBT outputs as an array of PsbtOutputData
     *
     * Returns an array with script, value, bip32_derivation, and tap_bip32_derivation
     * for each output. This is useful for introspecting the PSBT structure.
     */
    getOutputs(): any;
    /**
     * Get all PSBT outputs with resolved address strings.
     *
     * Like `getOutputs()` but each element also includes an `address` field
     * derived from the output script using the given coin name (e.g. "btc", "tbtc").
     */
    getOutputsWithAddress(coin: string): any;
    /**
     * Get partial signatures for an input
     * Returns array of { pubkey: Uint8Array, signature: Uint8Array }
     */
    getPartialSignatures(input_index: number): any;
    /**
     * Get the unsigned transaction bytes
     *
     * # Returns
     * The serialized unsigned transaction
     */
    getUnsignedTx(): Uint8Array;
    /**
     * Check if an input has any partial signatures
     */
    hasPartialSignatures(input_index: number): boolean;
    /**
     * Get the number of inputs in the PSBT
     */
    inputCount(): number;
    /**
     * Get the transaction lock time
     */
    lockTime(): number;
    /**
     * Create an empty PSBT
     *
     * # Arguments
     * * `version` - Transaction version (default: 2)
     * * `lock_time` - Transaction lock time (default: 0)
     */
    constructor(version?: number | null, lock_time?: number | null);
    /**
     * Get the number of outputs in the PSBT
     */
    outputCount(): number;
    /**
     * Remove an output from the PSBT by index.
     *
     * Removes both the transaction output and the PSBT output metadata.
     */
    removeOutput(index: number): void;
    serialize(): Uint8Array;
    /**
     * Sign all inputs with a WasmBIP32 key
     *
     * This method signs all inputs that match the BIP32 derivation paths in the PSBT.
     * Returns a map of input indices to the public keys that were signed.
     *
     * # Arguments
     * * `key` - The WasmBIP32 key to sign with
     *
     * # Returns
     * A SigningKeysMap converted to JsValue (object mapping input indices to signing keys)
     */
    signAll(key: WasmBIP32): any;
    /**
     * Sign all inputs with a WasmECPair key
     *
     * This method signs all inputs using the private key from the ECPair.
     * Returns a map of input indices to the public keys that were signed.
     *
     * # Arguments
     * * `key` - The WasmECPair key to sign with
     *
     * # Returns
     * A SigningKeysMap converted to JsValue (object mapping input indices to signing keys)
     */
    signAllWithEcpair(key: WasmECPair): any;
    signWithPrv(prv: Uint8Array): any;
    signWithXprv(xprv: string): any;
    /**
     * Get the unsigned transaction ID as a hex string
     */
    unsignedTxId(): string;
    updateInputWithDescriptor(input_index: number, descriptor: WrapDescriptor): void;
    updateOutputWithDescriptor(output_index: number, descriptor: WrapDescriptor): void;
    /**
     * Validate a signature at a specific input against a pubkey
     * Returns true if the signature is valid
     *
     * This method handles both ECDSA (legacy/SegWit) and Schnorr (Taproot) signatures.
     * The pubkey should be provided as bytes (33 bytes for compressed ECDSA, 32 bytes for x-only Schnorr).
     */
    validateSignatureAtInput(input_index: number, pubkey: Uint8Array): boolean;
    /**
     * Verify a signature at a specific input using a WasmBIP32 key
     *
     * This method verifies if a valid signature exists for the given BIP32 key at the specified input.
     * It handles both ECDSA (legacy/SegWit) and Schnorr (Taproot) signatures.
     *
     * Note: This method checks if the key's public key matches any signature in the input.
     * For proper BIP32 verification, the key should be derived to the correct path first.
     *
     * # Arguments
     * * `input_index` - The index of the input to check
     * * `key` - The WasmBIP32 key to verify against
     *
     * # Returns
     * `true` if a valid signature exists for the key, `false` otherwise
     */
    verifySignatureWithKey(input_index: number, key: WasmBIP32): boolean;
    /**
     * Get the transaction version
     */
    version(): number;
}

/**
 * Check if the inspect feature is enabled.
 *
 * # Returns
 * `true` if the feature is enabled, `false` otherwise
 */
export function isInspectEnabled(): boolean;

/**
 * Parse a PSBT at the raw byte level and return a JSON representation.
 *
 * Unlike `parsePsbtToJson`, this function exposes the raw key-value pair
 * structure as defined in BIP-174, showing:
 * - Raw key type IDs and their human-readable names
 * - Proprietary keys with their structured format
 * - Unknown/unrecognized keys that standard parsers might skip
 *
 * # Arguments
 * * `psbt_bytes` - The raw PSBT bytes
 * * `coin_name` - The network coin name (e.g., "btc", "ltc", "zec")
 *
 * # Returns
 * A JSON string representing the raw PSBT key-value structure
 *
 * # Errors
 * Returns an error if:
 * - The `inspect` feature is not enabled
 * - The PSBT bytes are invalid
 * - The network name is unknown
 */
export function parsePsbtRawToJson(psbt_bytes: Uint8Array, coin_name: string): string;

/**
 * Parse a PSBT and return a JSON representation of its structure.
 *
 * This function parses the PSBT using the standard bitcoin crate parser
 * and returns a hierarchical node structure suitable for display.
 *
 * # Arguments
 * * `psbt_bytes` - The raw PSBT bytes
 * * `coin_name` - The network coin name (e.g., "btc", "ltc", "bch")
 *
 * # Returns
 * A JSON string representing the parsed PSBT structure
 *
 * # Errors
 * Returns an error if:
 * - The `inspect` feature is not enabled
 * - The PSBT bytes are invalid
 * - The network name is unknown
 */
export function parsePsbtToJson(psbt_bytes: Uint8Array, coin_name: string): string;

/**
 * Parse a transaction and return a JSON representation of its structure.
 *
 * # Arguments
 * * `tx_bytes` - The raw transaction bytes
 * * `coin_name` - The network coin name (e.g., "btc", "ltc", "bch")
 *
 * # Returns
 * A JSON string representing the parsed transaction structure
 *
 * # Errors
 * Returns an error if:
 * - The `inspect` feature is not enabled
 * - The transaction bytes are invalid
 * - The network name is unknown
 */
export function parseTxToJson(tx_bytes: Uint8Array, coin_name: string): string;
