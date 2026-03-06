export class AddressNamespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        AddressNamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_addressnamespace_free(ptr, 0);
    }
    /**
     * @param {Uint8Array} script
     * @param {string} coin
     * @param {string | null} [format]
     * @returns {string}
     */
    static from_output_script_with_coin(script, coin, format) {
        let deferred5_0;
        let deferred5_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(coin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(format) ? 0 : passStringToWasm0(format, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len2 = WASM_VECTOR_LEN;
            wasm.addressnamespace_from_output_script_with_coin(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr4 = r0;
            var len4 = r1;
            if (r3) {
                ptr4 = 0; len4 = 0;
                throw takeObject(r2);
            }
            deferred5_0 = ptr4;
            deferred5_1 = len4;
            return getStringFromWasm0(ptr4, len4);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred5_0, deferred5_1, 1);
        }
    }
    /**
     * @param {string} address
     * @param {string} coin
     * @returns {Uint8Array}
     */
    static to_output_script_with_coin(address, coin) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(coin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.addressnamespace_to_output_script_with_coin(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) AddressNamespace.prototype[Symbol.dispose] = AddressNamespace.prototype.free;

/**
 * Namespace for BIP-0322 functions
 */
export class Bip322Namespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        Bip322NamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_bip322namespace_free(ptr, 0);
    }
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
     * @param {BitGoPsbt} psbt
     * @param {string} message
     * @param {number} chain
     * @param {number} index
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {string | null} [signer]
     * @param {string | null} [cosigner]
     * @param {string | null} [tag]
     * @returns {number}
     */
    static add_bip322_input(psbt, message, chain, index, wallet_keys, signer, cosigner, tag) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(psbt, BitGoPsbt);
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            var ptr1 = isLikeNone(signer) ? 0 : passStringToWasm0(signer, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(cosigner) ? 0 : passStringToWasm0(cosigner, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(tag) ? 0 : passStringToWasm0(tag, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len3 = WASM_VECTOR_LEN;
            wasm.bip322namespace_add_bip322_input(retptr, psbt.__wbg_ptr, ptr0, len0, chain, index, wallet_keys.__wbg_ptr, ptr1, len1, ptr2, len2, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {BitGoPsbt} psbt
     * @param {number} input_index
     * @param {string} message
     * @param {number} chain
     * @param {number} index
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {string | null} [tag]
     * @returns {string[]}
     */
    static verify_bip322_psbt_input(psbt, input_index, message, chain, index, wallet_keys, tag) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(psbt, BitGoPsbt);
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            var ptr1 = isLikeNone(tag) ? 0 : passStringToWasm0(tag, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.bip322namespace_verify_bip322_psbt_input(retptr, psbt.__wbg_ptr, input_index, ptr0, len0, chain, index, wallet_keys.__wbg_ptr, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayJsValueFromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {BitGoPsbt} psbt
     * @param {number} input_index
     * @param {string} message
     * @param {string[]} pubkeys
     * @param {string} script_type
     * @param {boolean | null} [is_script_path]
     * @param {string | null} [tag]
     * @returns {Uint32Array}
     */
    static verify_bip322_psbt_input_with_pubkeys(psbt, input_index, message, pubkeys, script_type, is_script_path, tag) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(psbt, BitGoPsbt);
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(pubkeys, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(script_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(tag) ? 0 : passStringToWasm0(tag, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len3 = WASM_VECTOR_LEN;
            wasm.bip322namespace_verify_bip322_psbt_input_with_pubkeys(retptr, psbt.__wbg_ptr, input_index, ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(is_script_path) ? 0xFFFFFF : is_script_path ? 1 : 0, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v5 = getArrayU32FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v5;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmTransaction} tx
     * @param {number} input_index
     * @param {string} message
     * @param {number} chain
     * @param {number} index
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {string} network
     * @param {string | null} [tag]
     */
    static verify_bip322_tx_input(tx, input_index, message, chain, index, wallet_keys, network, tag) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(tx, WasmTransaction);
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            const ptr1 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(tag) ? 0 : passStringToWasm0(tag, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len2 = WASM_VECTOR_LEN;
            wasm.bip322namespace_verify_bip322_tx_input(retptr, tx.__wbg_ptr, input_index, ptr0, len0, chain, index, wallet_keys.__wbg_ptr, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmTransaction} tx
     * @param {number} input_index
     * @param {string} message
     * @param {string[]} pubkeys
     * @param {string} script_type
     * @param {boolean | null} [is_script_path]
     * @param {string | null} [tag]
     * @returns {Uint32Array}
     */
    static verify_bip322_tx_input_with_pubkeys(tx, input_index, message, pubkeys, script_type, is_script_path, tag) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(tx, WasmTransaction);
            const ptr0 = passStringToWasm0(message, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArrayJsValueToWasm0(pubkeys, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(script_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(tag) ? 0 : passStringToWasm0(tag, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len3 = WASM_VECTOR_LEN;
            wasm.bip322namespace_verify_bip322_tx_input_with_pubkeys(retptr, tx.__wbg_ptr, input_index, ptr0, len0, ptr1, len1, ptr2, len2, isLikeNone(is_script_path) ? 0xFFFFFF : is_script_path ? 1 : 0, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v5 = getArrayU32FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 4, 4);
            return v5;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) Bip322Namespace.prototype[Symbol.dispose] = Bip322Namespace.prototype.free;

export class BitGoPsbt {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(BitGoPsbt.prototype);
        obj.__wbg_ptr = ptr;
        BitGoPsbtFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BitGoPsbtFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_bitgopsbt_free(ptr, 0);
    }
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
     * @param {string} txid
     * @param {number} vout
     * @param {bigint} value
     * @param {Uint8Array} script
     * @param {number | null} [sequence]
     * @param {Uint8Array | null} [prev_tx]
     * @returns {number}
     */
    add_input(txid, vout, value, script, sequence, prev_tx) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(prev_tx) ? 0 : passArray8ToWasm0(prev_tx, wasm.__wbindgen_export);
            var len2 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_input(retptr, this.__wbg_ptr, ptr0, len0, vout, value, ptr1, len1, isLikeNone(sequence) ? 0x100000001 : (sequence) >>> 0, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Add an output to the PSBT
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     * @param {Uint8Array} script
     * @param {bigint} value
     * @returns {number}
     */
    add_output(script, value) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_output(retptr, this.__wbg_ptr, ptr0, len0, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Add an output to the PSBT by address
     *
     * # Arguments
     * * `address` - The destination address
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     * @param {string} address
     * @param {bigint} value
     * @returns {number}
     */
    add_output_with_address(address, value) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_output_with_address(retptr, this.__wbg_ptr, ptr0, len0, value);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} output_index
     * @param {Uint8Array} entropy
     * @param {Uint8Array} signature
     */
    add_paygo_attestation(output_index, entropy, signature) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(entropy, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(signature, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_paygo_attestation(retptr, this.__wbg_ptr, output_index, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmECPair} ecpair
     * @param {string} txid
     * @param {number} vout
     * @param {bigint} value
     * @param {number | null} [sequence]
     * @param {Uint8Array | null} [prev_tx]
     * @returns {number}
     */
    add_replay_protection_input(ecpair, txid, vout, value, sequence, prev_tx) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(prev_tx) ? 0 : passArray8ToWasm0(prev_tx, wasm.__wbindgen_export);
            var len1 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_replay_protection_input(retptr, this.__wbg_ptr, ecpair.__wbg_ptr, ptr0, len0, vout, value, isLikeNone(sequence) ? 0x100000001 : (sequence) >>> 0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {string} txid
     * @param {number} vout
     * @param {bigint} value
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {number} chain
     * @param {number} index
     * @param {string | null} [signer]
     * @param {string | null} [cosigner]
     * @param {number | null} [sequence]
     * @param {Uint8Array | null} [prev_tx]
     * @returns {number}
     */
    add_wallet_input(txid, vout, value, wallet_keys, chain, index, signer, cosigner, sequence, prev_tx) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            var ptr1 = isLikeNone(signer) ? 0 : passStringToWasm0(signer, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            var ptr2 = isLikeNone(cosigner) ? 0 : passStringToWasm0(cosigner, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len2 = WASM_VECTOR_LEN;
            var ptr3 = isLikeNone(prev_tx) ? 0 : passArray8ToWasm0(prev_tx, wasm.__wbindgen_export);
            var len3 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_add_wallet_input(retptr, this.__wbg_ptr, ptr0, len0, vout, value, wallet_keys.__wbg_ptr, chain, index, ptr1, len1, ptr2, len2, isLikeNone(sequence) ? 0x100000001 : (sequence) >>> 0, ptr3, len3);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} chain
     * @param {number} index
     * @param {bigint} value
     * @param {WasmRootWalletKeys} wallet_keys
     * @returns {number}
     */
    add_wallet_output(chain, index, value, wallet_keys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(wallet_keys, WasmRootWalletKeys);
            wasm.bitgopsbt_add_wallet_output(retptr, this.__wbg_ptr, chain, index, value, wallet_keys.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {BitGoPsbt} source_psbt
     */
    combine_musig2_nonces(source_psbt) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(source_psbt, BitGoPsbt);
            wasm.bitgopsbt_combine_musig2_nonces(retptr, this.__wbg_ptr, source_psbt.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create an empty PSBT for the given network with wallet keys
     *
     * # Arguments
     * * `network` - Network name (utxolib or coin name)
     * * `wallet_keys` - The wallet's root keys (used to set global xpubs)
     * * `version` - Optional transaction version (default: 2)
     * * `lock_time` - Optional lock time (default: 0)
     * @param {string} network
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {number | null} [version]
     * @param {number | null} [lock_time]
     * @returns {BitGoPsbt}
     */
    static create_empty(network, wallet_keys, version, lock_time) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            wasm.bitgopsbt_create_empty(retptr, ptr0, len0, wallet_keys.__wbg_ptr, isLikeNone(version) ? 0x100000001 : (version) >> 0, isLikeNone(lock_time) ? 0x100000001 : (lock_time) >>> 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BitGoPsbt.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {string} network
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {number} consensus_branch_id
     * @param {number | null} [version]
     * @param {number | null} [lock_time]
     * @param {number | null} [version_group_id]
     * @param {number | null} [expiry_height]
     * @returns {BitGoPsbt}
     */
    static create_empty_zcash(network, wallet_keys, consensus_branch_id, version, lock_time, version_group_id, expiry_height) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            wasm.bitgopsbt_create_empty_zcash(retptr, ptr0, len0, wallet_keys.__wbg_ptr, consensus_branch_id, isLikeNone(version) ? 0x100000001 : (version) >> 0, isLikeNone(lock_time) ? 0x100000001 : (lock_time) >>> 0, isLikeNone(version_group_id) ? 0x100000001 : (version_group_id) >>> 0, isLikeNone(expiry_height) ? 0x100000001 : (expiry_height) >>> 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BitGoPsbt.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {string} network
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {number} block_height
     * @param {number | null} [version]
     * @param {number | null} [lock_time]
     * @param {number | null} [version_group_id]
     * @param {number | null} [expiry_height]
     * @returns {BitGoPsbt}
     */
    static create_empty_zcash_at_height(network, wallet_keys, block_height, version, lock_time, version_group_id, expiry_height) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(wallet_keys, WasmRootWalletKeys);
            wasm.bitgopsbt_create_empty_zcash_at_height(retptr, ptr0, len0, wallet_keys.__wbg_ptr, block_height, isLikeNone(version) ? 0x100000001 : (version) >> 0, isLikeNone(lock_time) ? 0x100000001 : (lock_time) >>> 0, isLikeNone(version_group_id) ? 0x100000001 : (version_group_id) >>> 0, isLikeNone(expiry_height) ? 0x100000001 : (expiry_height) >>> 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BitGoPsbt.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the Zcash expiry height (returns None for non-Zcash PSBTs)
     * @returns {number | undefined}
     */
    expiry_height() {
        const ret = wasm.bitgopsbt_expiry_height(this.__wbg_ptr);
        return ret === 0x100000001 ? undefined : ret;
    }
    /**
     * Extract the final transaction as a WasmTransaction (for BitcoinLike networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Bitcoin-like networks (not Dash or Zcash).
     * @returns {WasmTransaction}
     */
    extract_bitcoin_transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_extract_bitcoin_transaction(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Extract the final transaction as a WasmDashTransaction (for Dash networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Dash networks.
     * @returns {WasmDashTransaction}
     */
    extract_dash_transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_extract_dash_transaction(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDashTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
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
     * @returns {Uint8Array}
     */
    extract_half_signed_legacy_tx() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_extract_half_signed_legacy_tx(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @returns {any}
     */
    extract_transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_extract_transaction(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Extract the final transaction as a WasmZcashTransaction (for Zcash networks)
     *
     * This avoids re-parsing bytes by returning the transaction directly.
     * Only valid for Zcash networks.
     * @returns {WasmZcashTransaction}
     */
    extract_zcash_transaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_extract_zcash_transaction(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmZcashTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
    finalize_all_inputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_finalize_all_inputs(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Deserialize a PSBT from bytes with network-specific logic
     * @param {Uint8Array} bytes
     * @param {string} network
     * @returns {BitGoPsbt}
     */
    static from_bytes(bytes, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_from_bytes(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return BitGoPsbt.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmBIP32} xpriv
     * @param {Uint8Array | null} [session_id_bytes]
     */
    generate_musig2_nonces(xpriv, session_id_bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            var ptr0 = isLikeNone(session_id_bytes) ? 0 : passArray8ToWasm0(session_id_bytes, wasm.__wbindgen_export);
            var len0 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_generate_musig2_nonces(retptr, this.__wbg_ptr, xpriv.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get all PSBT inputs as an array of PsbtInputData
     *
     * Returns an array with witness_utxo, bip32_derivation, and tap_bip32_derivation
     * for each input.
     * @returns {any}
     */
    get_inputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_get_inputs(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the network type for transaction extraction
     *
     * Returns "bitcoin", "dash", or "zcash" to indicate which transaction
     * wrapper class should be used in TypeScript.
     * @returns {string}
     */
    get_network_type() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_get_network_type(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get all PSBT outputs as an array of PsbtOutputData
     *
     * Returns an array with script, value, bip32_derivation, and tap_bip32_derivation
     * for each output.
     * @returns {any}
     */
    get_outputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_get_outputs(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get all PSBT outputs with resolved address strings.
     *
     * Unlike the generic WrapPsbt which requires a coin parameter, BitGoPsbt
     * uses the network it was created/deserialized with to resolve addresses.
     * @returns {any}
     */
    get_outputs_with_address() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_get_outputs_with_address(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the number of inputs in the PSBT
     * @returns {number}
     */
    input_count() {
        const ret = wasm.bitgopsbt_input_count(this.__wbg_ptr);
        return ret >>> 0;
    }
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
     * @param {number} input_index
     * @returns {boolean}
     */
    is_musig2_input(input_index) {
        const ret = wasm.bitgopsbt_is_musig2_input(this.__wbg_ptr, input_index);
        return ret !== 0;
    }
    /**
     * Get the transaction lock time
     * @returns {number}
     */
    lock_time() {
        const ret = wasm.bitgopsbt_lock_time(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the network of the PSBT
     * @returns {string}
     */
    network() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_network(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the number of outputs in the PSBT
     * @returns {number}
     */
    output_count() {
        const ret = wasm.bitgopsbt_output_count(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Parse outputs with wallet keys to identify which outputs belong to a wallet
     *
     * Note: This method does NOT validate wallet inputs. It only parses outputs.
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {WasmECPair[] | null} [paygo_pubkeys]
     * @returns {any}
     */
    parse_outputs_with_wallet_keys(wallet_keys, paygo_pubkeys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(wallet_keys, WasmRootWalletKeys);
            var ptr0 = isLikeNone(paygo_pubkeys) ? 0 : passArrayJsValueToWasm0(paygo_pubkeys, wasm.__wbindgen_export);
            var len0 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_parse_outputs_with_wallet_keys(retptr, this.__wbg_ptr, wallet_keys.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Parse transaction with wallet keys to identify wallet inputs/outputs
     * @param {WasmRootWalletKeys} wallet_keys
     * @param {WasmReplayProtection} replay_protection
     * @param {WasmECPair[] | null} [paygo_pubkeys]
     * @returns {any}
     */
    parse_transaction_with_wallet_keys(wallet_keys, replay_protection, paygo_pubkeys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(wallet_keys, WasmRootWalletKeys);
            _assertClass(replay_protection, WasmReplayProtection);
            var ptr0 = isLikeNone(paygo_pubkeys) ? 0 : passArrayJsValueToWasm0(paygo_pubkeys, wasm.__wbindgen_export);
            var len0 = WASM_VECTOR_LEN;
            wasm.bitgopsbt_parse_transaction_with_wallet_keys(retptr, this.__wbg_ptr, wallet_keys.__wbg_ptr, replay_protection.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Serialize the PSBT to bytes
     *
     * # Returns
     * The serialized PSBT as a byte array
     * @returns {Uint8Array}
     */
    serialize() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_serialize(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmBIP32} xpriv
     * @returns {any}
     */
    sign_all_musig2_inputs(xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_all_musig2_inputs(retptr, this.__wbg_ptr, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmECPair} ecpair
     * @returns {any}
     */
    sign_all_replay_protection_inputs(ecpair) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            wasm.bitgopsbt_sign_all_replay_protection_inputs(retptr, this.__wbg_ptr, ecpair.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmBIP32} xpriv
     * @returns {any}
     */
    sign_all_wallet_inputs(xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_all_wallet_inputs(retptr, this.__wbg_ptr, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmBIP32} xpriv
     * @returns {any}
     */
    sign_all_with_xpriv(xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_all_wallet_inputs(retptr, this.__wbg_ptr, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} xpriv
     */
    sign_musig2_input(input_index, xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_musig2_input(retptr, this.__wbg_ptr, input_index, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmECPair} ecpair
     * @returns {any}
     */
    sign_replay_protection_inputs(ecpair) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            wasm.bitgopsbt_sign_all_replay_protection_inputs(retptr, this.__wbg_ptr, ecpair.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmECPair} ecpair
     */
    sign_single_input_with_privkey(input_index, ecpair) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            wasm.bitgopsbt_sign_single_input_with_privkey(retptr, this.__wbg_ptr, input_index, ecpair.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} xpriv
     */
    sign_single_input_with_xpriv(input_index, xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_single_input_with_xpriv(retptr, this.__wbg_ptr, input_index, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} xpriv
     */
    sign_wallet_input(input_index, xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_single_input_with_xpriv(retptr, this.__wbg_ptr, input_index, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmECPair} ecpair
     */
    sign_with_privkey(input_index, ecpair) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            wasm.bitgopsbt_sign_with_privkey(retptr, this.__wbg_ptr, input_index, ecpair.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} xpriv
     */
    sign_with_xpriv(input_index, xpriv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpriv, WasmBIP32);
            wasm.bitgopsbt_sign_with_xpriv(retptr, this.__wbg_ptr, input_index, xpriv.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the unsigned transaction ID
     * @returns {string}
     */
    unsigned_txid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.bitgopsbt_unsigned_txid(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
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
     * @param {number} input_index
     * @param {WasmReplayProtection} replay_protection
     * @returns {boolean}
     */
    verify_replay_protection_signature(input_index, replay_protection) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(replay_protection, WasmReplayProtection);
            wasm.bitgopsbt_verify_replay_protection_signature(retptr, this.__wbg_ptr, input_index, replay_protection.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmECPair} ecpair
     * @returns {boolean}
     */
    verify_signature_with_pub(input_index, ecpair) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(ecpair, WasmECPair);
            wasm.bitgopsbt_verify_signature_with_pub(retptr, this.__wbg_ptr, input_index, ecpair.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} xpub
     * @returns {boolean}
     */
    verify_signature_with_xpub(input_index, xpub) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(xpub, WasmBIP32);
            wasm.bitgopsbt_verify_signature_with_xpub(retptr, this.__wbg_ptr, input_index, xpub.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the transaction version
     * @returns {number}
     */
    version() {
        const ret = wasm.bitgopsbt_version(this.__wbg_ptr);
        return ret;
    }
    /**
     * Get the Zcash version group ID (returns None for non-Zcash PSBTs)
     * @returns {number | undefined}
     */
    version_group_id() {
        const ret = wasm.bitgopsbt_version_group_id(this.__wbg_ptr);
        return ret === 0x100000001 ? undefined : ret;
    }
}
if (Symbol.dispose) BitGoPsbt.prototype[Symbol.dispose] = BitGoPsbt.prototype.free;

export class FixedScriptWalletNamespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FixedScriptWalletNamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_fixedscriptwalletnamespace_free(ptr, 0);
    }
    /**
     * @param {WasmRootWalletKeys} keys
     * @param {number} chain
     * @param {number} index
     * @param {any} network
     * @param {string | null} [address_format]
     * @returns {string}
     */
    static address(keys, chain, index, network, address_format) {
        let deferred3_0;
        let deferred3_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keys, WasmRootWalletKeys);
            var ptr0 = isLikeNone(address_format) ? 0 : passStringToWasm0(address_format, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len0 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_address(retptr, keys.__wbg_ptr, chain, index, addHeapObject(network), ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr2 = r0;
            var len2 = r1;
            if (r3) {
                ptr2 = 0; len2 = 0;
                throw takeObject(r2);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {WasmRootWalletKeys} keys
     * @param {number} chain
     * @param {number} index
     * @param {string} network
     * @param {string | null} [address_format]
     * @returns {string}
     */
    static address_with_network_str(keys, chain, index, network, address_format) {
        let deferred4_0;
        let deferred4_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keys, WasmRootWalletKeys);
            const ptr0 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(address_format) ? 0 : passStringToWasm0(address_format, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_address_with_network_str(retptr, keys.__wbg_ptr, chain, index, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr3 = r0;
            var len3 = r1;
            if (r3) {
                ptr3 = 0; len3 = 0;
                throw takeObject(r2);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Get all chain code metadata for building TypeScript lookup tables
     *
     * Returns an array of [chainCode, scriptType, scope] tuples where:
     * - chainCode: u32 (0, 1, 10, 11, 20, 21, 30, 31, 40, 41)
     * - scriptType: string ("p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy", "p2trMusig2")
     * - scope: string ("external" or "internal")
     * @returns {any}
     */
    static chain_code_table() {
        const ret = wasm.fixedscriptwalletnamespace_chain_code_table();
        return takeObject(ret);
    }
    /**
     * Create an OP_RETURN output script with optional data
     *
     * # Arguments
     * * `data` - Optional data bytes to include in the OP_RETURN script
     *
     * # Returns
     * The OP_RETURN script as bytes
     * @param {Uint8Array | null} [data]
     * @returns {Uint8Array}
     */
    static create_op_return_script(data) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            var ptr0 = isLikeNone(data) ? 0 : passArray8ToWasm0(data, wasm.__wbindgen_export);
            var len0 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_create_op_return_script(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {WasmRootWalletKeys} keys
     * @param {number} chain
     * @param {number} index
     * @param {any} network
     * @returns {Uint8Array}
     */
    static output_script(keys, chain, index, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keys, WasmRootWalletKeys);
            wasm.fixedscriptwalletnamespace_output_script(retptr, keys.__wbg_ptr, chain, index, addHeapObject(network));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {WasmRootWalletKeys} keys
     * @param {number} chain
     * @param {number} index
     * @param {string} network
     * @returns {Uint8Array}
     */
    static output_script_with_network_str(keys, chain, index, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(keys, WasmRootWalletKeys);
            const ptr0 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_output_script_with_network_str(retptr, keys.__wbg_ptr, chain, index, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the P2SH-P2PK output script for a compressed public key
     *
     * # Arguments
     * * `pubkey` - The compressed public key bytes (33 bytes)
     *
     * # Returns
     * The P2SH-P2PK output script as bytes
     * @param {Uint8Array} pubkey
     * @returns {Uint8Array}
     */
    static p2sh_p2pk_output_script(pubkey) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(pubkey, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_p2sh_p2pk_output_script(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v2 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v2;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {string} coin
     * @param {string} script_type
     * @returns {boolean}
     */
    static supports_script_type(coin, script_type) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(coin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(script_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.fixedscriptwalletnamespace_supports_script_type(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) FixedScriptWalletNamespace.prototype[Symbol.dispose] = FixedScriptWalletNamespace.prototype.free;

/**
 * Namespace for inscription-related functions
 */
export class InscriptionsNamespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        InscriptionsNamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_inscriptionsnamespace_free(ptr, 0);
    }
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
     * @param {Uint8Array} x_only_pubkey
     * @param {string} content_type
     * @param {Uint8Array} inscription_data
     * @returns {any}
     */
    static create_inscription_reveal_data(x_only_pubkey, content_type, inscription_data) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(x_only_pubkey, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(content_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(inscription_data, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.inscriptionsnamespace_create_inscription_reveal_data(retptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {Uint8Array} private_key
     * @param {any} tap_leaf_script
     * @param {WasmTransaction} commit_tx
     * @param {Uint8Array} commit_output_script
     * @param {Uint8Array} recipient_output_script
     * @param {bigint} output_value_sats
     * @returns {Uint8Array}
     */
    static sign_reveal_transaction(private_key, tap_leaf_script, commit_tx, commit_output_script, recipient_output_script, output_value_sats) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            _assertClass(commit_tx, WasmTransaction);
            const ptr1 = passArray8ToWasm0(commit_output_script, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passArray8ToWasm0(recipient_output_script, wasm.__wbindgen_export);
            const len2 = WASM_VECTOR_LEN;
            wasm.inscriptionsnamespace_sign_reveal_transaction(retptr, ptr0, len0, addHeapObject(tap_leaf_script), commit_tx.__wbg_ptr, ptr1, len1, ptr2, len2, output_value_sats);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v4 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v4;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) InscriptionsNamespace.prototype[Symbol.dispose] = InscriptionsNamespace.prototype.free;

export class MessageNamespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        MessageNamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_messagenamespace_free(ptr, 0);
    }
    /**
     * Sign a message using Bitcoin message signing (BIP-137)
     *
     * Returns 65-byte signature (1-byte header + 64-byte signature).
     * The key must have a private key (cannot sign with public key only).
     * @param {WasmECPair} key
     * @param {string} message_str
     * @returns {Uint8Array}
     */
    static sign_message(key, message_str) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, WasmECPair);
            const ptr0 = passStringToWasm0(message_str, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.messagenamespace_sign_message(retptr, key.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Verify a Bitcoin message signature (BIP-137)
     *
     * Signature must be 65 bytes (1-byte header + 64-byte signature).
     * Returns true if the signature is valid for this key.
     * @param {WasmECPair} key
     * @param {string} message_str
     * @param {Uint8Array} signature
     * @returns {boolean}
     */
    static verify_message(key, message_str, signature) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, WasmECPair);
            const ptr0 = passStringToWasm0(message_str, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(signature, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.messagenamespace_verify_message(retptr, key.__wbg_ptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) MessageNamespace.prototype[Symbol.dispose] = MessageNamespace.prototype.free;

export class UtxolibCompatNamespace {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        UtxolibCompatNamespaceFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_utxolibcompatnamespace_free(ptr, 0);
    }
    /**
     * Convert output script to address string
     *
     * # Arguments
     * * `script` - The output script as a byte array
     * * `network` - The UtxolibNetwork object from JavaScript
     * * `format` - Optional address format: "default" or "cashaddr" (only applicable for Bitcoin Cash and eCash)
     * @param {Uint8Array} script
     * @param {any} network
     * @param {string | null} [format]
     * @returns {string}
     */
    static from_output_script(script, network, format) {
        let deferred4_0;
        let deferred4_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(format) ? 0 : passStringToWasm0(format, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.utxolibcompatnamespace_from_output_script(retptr, ptr0, len0, addHeapObject(network), ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr3 = r0;
            var len3 = r1;
            if (r3) {
                ptr3 = 0; len3 = 0;
                throw takeObject(r2);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * Convert address string to output script
     *
     * # Arguments
     * * `address` - The address string
     * * `network` - The UtxolibNetwork object from JavaScript
     * * `format` - Optional address format (currently unused for decoding as all formats are accepted)
     * @param {string} address
     * @param {any} network
     * @param {string | null} [format]
     * @returns {Uint8Array}
     */
    static to_output_script(address, network, format) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(address, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(format) ? 0 : passStringToWasm0(format, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.utxolibcompatnamespace_to_output_script(retptr, ptr0, len0, addHeapObject(network), ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v3 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v3;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) UtxolibCompatNamespace.prototype[Symbol.dispose] = UtxolibCompatNamespace.prototype.free;

/**
 * WASM wrapper for BIP32 extended keys (Xpub/Xpriv)
 * Implements the BIP32Interface TypeScript interface
 */
export class WasmBIP32 {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmBIP32.prototype);
        obj.__wbg_ptr = ptr;
        WasmBIP32Finalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmBIP32Finalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmbip32_free(ptr, 0);
    }
    /**
     * Get the chain code as a Uint8Array
     * @returns {Uint8Array}
     */
    get chain_code() {
        const ret = wasm.wasmbip32_chain_code(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Get the depth
     * @returns {number}
     */
    get depth() {
        const ret = wasm.wasmbip32_depth(this.__wbg_ptr);
        return ret;
    }
    /**
     * Derive a normal (non-hardened) child key
     * @param {number} index
     * @returns {WasmBIP32}
     */
    derive(index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_derive(retptr, this.__wbg_ptr, index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Derive a hardened child key (only works for private keys)
     * @param {number} index
     * @returns {WasmBIP32}
     */
    derive_hardened(index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_derive_hardened(retptr, this.__wbg_ptr, index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Derive a key using a derivation path (e.g., "0/1/2" or "m/0/1/2")
     * @param {string} path
     * @returns {WasmBIP32}
     */
    derive_path(path) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(path, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmbip32_derive_path(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Check equality with another WasmBIP32 key.
     * Two keys are equal if they have the same type (public/private) and identical
     * BIP32 metadata (depth, parent fingerprint, child index, chain code, key data).
     * @param {WasmBIP32} other
     * @returns {boolean}
     */
    equals(other) {
        _assertClass(other, WasmBIP32);
        const ret = wasm.wasmbip32_equals(this.__wbg_ptr, other.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Get the fingerprint as a Uint8Array
     * @returns {Uint8Array}
     */
    get fingerprint() {
        const ret = wasm.wasmbip32_fingerprint(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Create a BIP32 key from a base58 string (xpub/xprv/tpub/tprv)
     * @param {string} base58_str
     * @returns {WasmBIP32}
     */
    static from_base58(base58_str) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(base58_str, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmbip32_from_base58(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create a BIP32 key from a BIP32Interface JavaScript object properties
     * Expects an object with: network.bip32.public, depth, parentFingerprint,
     * index, chainCode, and publicKey properties
     * @param {any} bip32_key
     * @returns {WasmBIP32}
     */
    static from_bip32_interface(bip32_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_from_bip32_interface(retptr, addBorrowedObject(bip32_key));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * Create a BIP32 key from BIP32 properties
     * Extracts properties from a JavaScript object and constructs an xpub or xprv
     * @param {any} bip32_key
     * @returns {WasmBIP32}
     */
    static from_bip32_properties(bip32_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_from_bip32_interface(retptr, addBorrowedObject(bip32_key));
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            heap[stack_pointer++] = undefined;
        }
    }
    /**
     * Create a BIP32 master key from a seed
     * @param {Uint8Array} seed
     * @param {string | null} [network]
     * @returns {WasmBIP32}
     */
    static from_seed(seed, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.wasmbip32_from_seed(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create a BIP32 master key from a string by hashing it with SHA256.
     * This is useful for deterministic test key generation.
     * @param {string} seed_string
     * @param {string | null} [network]
     * @returns {WasmBIP32}
     */
    static from_seed_sha256(seed_string, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(seed_string, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(network) ? 0 : passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.wasmbip32_from_seed_sha256(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create a BIP32 key from an xprv string (base58-encoded)
     * @param {string} xprv_str
     * @returns {WasmBIP32}
     */
    static from_xprv(xprv_str) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(xprv_str, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmbip32_from_xprv(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create a BIP32 key from an xpub string (base58-encoded)
     * @param {string} xpub_str
     * @returns {WasmBIP32}
     */
    static from_xpub(xpub_str) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(xpub_str, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmbip32_from_xpub(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmBIP32.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the identifier as a Uint8Array
     * @returns {Uint8Array}
     */
    get identifier() {
        const ret = wasm.wasmbip32_identifier(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Get the child index
     * @returns {number}
     */
    get index() {
        const ret = wasm.wasmbip32_index(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Check if this is a neutered (public) key
     * @returns {boolean}
     */
    is_neutered() {
        const ret = wasm.wasmbip32_is_neutered(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Get the neutered (public) version of this key
     * @returns {WasmBIP32}
     */
    neutered() {
        const ret = wasm.wasmbip32_neutered(this.__wbg_ptr);
        return WasmBIP32.__wrap(ret);
    }
    /**
     * Get the parent fingerprint
     * @returns {number}
     */
    get parent_fingerprint() {
        const ret = wasm.wasmbip32_parent_fingerprint(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the private key as a Uint8Array (if available)
     * @returns {Uint8Array | undefined}
     */
    get private_key() {
        const ret = wasm.wasmbip32_private_key(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Get the public key as a Uint8Array
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmbip32_public_key(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Serialize to base58 string
     * @returns {string}
     */
    to_base58() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_to_base58(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the WIF encoding of the private key
     * @returns {string}
     */
    to_wif() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmbip32_to_wif(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
}
if (Symbol.dispose) WasmBIP32.prototype[Symbol.dispose] = WasmBIP32.prototype.free;

/**
 * Dash transaction wrapper that supports Dash special transactions (EVO) by preserving extra payload.
 */
export class WasmDashTransaction {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmDashTransaction.prototype);
        obj.__wbg_ptr = ptr;
        WasmDashTransactionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmDashTransactionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmdashtransaction_free(ptr, 0);
    }
    /**
     * Deserialize a Dash transaction from bytes (supports EVO special tx extra payload).
     * @param {Uint8Array} bytes
     * @returns {WasmDashTransaction}
     */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmdashtransaction_from_bytes(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDashTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @returns {string}
     */
    get_txid() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmdashtransaction_get_txid(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Serialize the Dash transaction to bytes (preserving tx_type and extra payload).
     * @returns {Uint8Array}
     */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmdashtransaction_to_bytes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) WasmDashTransaction.prototype[Symbol.dispose] = WasmDashTransaction.prototype.free;

/**
 * Dimensions for estimating transaction virtual size.
 *
 * Tracks weight internally with min/max bounds to handle ECDSA signature variance.
 * Schnorr signatures have no variance (always 64 bytes).
 */
export class WasmDimensions {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmDimensions.prototype);
        obj.__wbg_ptr = ptr;
        WasmDimensionsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmDimensionsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmdimensions_free(ptr, 0);
    }
    /**
     * Create empty dimensions (zero weight)
     * @returns {WasmDimensions}
     */
    static empty() {
        const ret = wasm.wasmdimensions_empty();
        return WasmDimensions.__wrap(ret);
    }
    /**
     * Create dimensions for a single input from chain code
     *
     * # Arguments
     * * `chain` - Chain code (0/1=p2sh, 10/11=p2shP2wsh, 20/21=p2wsh, 30/31=p2tr, 40/41=p2trMusig2)
     * * `signer` - Optional signer key ("user", "backup", "bitgo")
     * * `cosigner` - Optional cosigner key ("user", "backup", "bitgo")
     * * `compat` - When true, use 72-byte signatures for max (matches @bitgo/unspents)
     * @param {number} chain
     * @param {string | null} [signer]
     * @param {string | null} [cosigner]
     * @param {boolean | null} [compat]
     * @returns {WasmDimensions}
     */
    static from_input(chain, signer, cosigner, compat) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            var ptr0 = isLikeNone(signer) ? 0 : passStringToWasm0(signer, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len0 = WASM_VECTOR_LEN;
            var ptr1 = isLikeNone(cosigner) ? 0 : passStringToWasm0(cosigner, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            var len1 = WASM_VECTOR_LEN;
            wasm.wasmdimensions_from_input(retptr, chain, ptr0, len0, ptr1, len1, isLikeNone(compat) ? 0xFFFFFF : compat ? 1 : 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDimensions.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create dimensions for a single input from script type string
     *
     * # Arguments
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2trLegacy",
     *                   "p2trMusig2KeyPath", "p2trMusig2ScriptPath", "p2shP2pk"
     * * `compat` - When true, use 72-byte signatures for max (matches @bitgo/unspents)
     * @param {string} script_type
     * @param {boolean | null} [compat]
     * @returns {WasmDimensions}
     */
    static from_input_script_type(script_type, compat) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(script_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmdimensions_from_input_script_type(retptr, ptr0, len0, isLikeNone(compat) ? 0xFFFFFF : compat ? 1 : 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDimensions.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create dimensions for a single output from script length
     * @param {number} length
     * @returns {WasmDimensions}
     */
    static from_output_script_length(length) {
        const ret = wasm.wasmdimensions_from_output_script_length(length);
        return WasmDimensions.__wrap(ret);
    }
    /**
     * Create dimensions for a single output from script type string
     *
     * # Arguments
     * * `script_type` - One of: "p2sh", "p2shP2wsh", "p2wsh", "p2tr"/"p2trLegacy", "p2trMusig2"
     * @param {string} script_type
     * @returns {WasmDimensions}
     */
    static from_output_script_type(script_type) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(script_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmdimensions_from_output_script_type(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDimensions.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create dimensions from a BitGoPsbt
     *
     * Parses PSBT inputs and outputs to compute weight bounds without
     * requiring wallet keys. Input types are detected from BIP32 derivation
     * paths stored in the PSBT.
     * @param {BitGoPsbt} psbt
     * @returns {WasmDimensions}
     */
    static from_psbt(psbt) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(psbt, BitGoPsbt);
            wasm.wasmdimensions_from_psbt(retptr, psbt.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmDimensions.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get input virtual size (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     * @param {string | null} [size]
     * @returns {number}
     */
    get_input_vsize(size) {
        var ptr0 = isLikeNone(size) ? 0 : passStringToWasm0(size, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdimensions_get_input_vsize(this.__wbg_ptr, ptr0, len0);
        return ret >>> 0;
    }
    /**
     * Get input weight only (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     * @param {string | null} [size]
     * @returns {number}
     */
    get_input_weight(size) {
        var ptr0 = isLikeNone(size) ? 0 : passStringToWasm0(size, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdimensions_get_input_weight(this.__wbg_ptr, ptr0, len0);
        return ret >>> 0;
    }
    /**
     * Get output virtual size
     * @returns {number}
     */
    get_output_vsize() {
        const ret = wasm.wasmdimensions_get_output_vsize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get output weight
     * @returns {number}
     */
    get_output_weight() {
        const ret = wasm.wasmdimensions_get_output_weight(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get virtual size (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     * @param {string | null} [size]
     * @returns {number}
     */
    get_vsize(size) {
        var ptr0 = isLikeNone(size) ? 0 : passStringToWasm0(size, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdimensions_get_vsize(this.__wbg_ptr, ptr0, len0);
        return ret >>> 0;
    }
    /**
     * Get total weight (min or max)
     *
     * # Arguments
     * * `size` - "min" or "max", defaults to "max"
     * @param {string | null} [size]
     * @returns {number}
     */
    get_weight(size) {
        var ptr0 = isLikeNone(size) ? 0 : passStringToWasm0(size, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        var len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmdimensions_get_weight(this.__wbg_ptr, ptr0, len0);
        return ret >>> 0;
    }
    /**
     * Whether any inputs are segwit (affects overhead calculation)
     * @returns {boolean}
     */
    has_segwit() {
        const ret = wasm.wasmdimensions_has_segwit(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * Combine with another Dimensions instance
     * @param {WasmDimensions} other
     * @returns {WasmDimensions}
     */
    plus(other) {
        _assertClass(other, WasmDimensions);
        const ret = wasm.wasmdimensions_plus(this.__wbg_ptr, other.__wbg_ptr);
        return WasmDimensions.__wrap(ret);
    }
    /**
     * Multiply dimensions by a scalar
     * @param {number} n
     * @returns {WasmDimensions}
     */
    times(n) {
        const ret = wasm.wasmdimensions_times(this.__wbg_ptr, n);
        return WasmDimensions.__wrap(ret);
    }
}
if (Symbol.dispose) WasmDimensions.prototype[Symbol.dispose] = WasmDimensions.prototype.free;

/**
 * WASM wrapper for elliptic curve key pairs (always uses compressed keys)
 */
export class WasmECPair {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmECPair.prototype);
        obj.__wbg_ptr = ptr;
        WasmECPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    static __unwrap(jsValue) {
        if (!(jsValue instanceof WasmECPair)) {
            return 0;
        }
        return jsValue.__destroy_into_raw();
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmECPairFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmecpair_free(ptr, 0);
    }
    /**
     * Create an ECPair from a private key (always uses compressed keys)
     * @param {Uint8Array} private_key
     * @returns {WasmECPair}
     */
    static from_private_key(private_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(private_key, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmecpair_from_private_key(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmECPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create an ECPair from a public key (always uses compressed keys)
     * @param {Uint8Array} public_key
     * @returns {WasmECPair}
     */
    static from_public_key(public_key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmecpair_from_public_key(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmECPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create an ECPair from a WIF string (auto-detects network)
     * @param {string} wif_string
     * @returns {WasmECPair}
     */
    static from_wif(wif_string) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(wif_string, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmecpair_from_wif(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmECPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create an ECPair from a mainnet WIF string
     * @param {string} wif_string
     * @returns {WasmECPair}
     */
    static from_wif_mainnet(wif_string) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(wif_string, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmecpair_from_wif_mainnet(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmECPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create an ECPair from a testnet WIF string
     * @param {string} wif_string
     * @returns {WasmECPair}
     */
    static from_wif_testnet(wif_string) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(wif_string, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmecpair_from_wif_testnet(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmECPair.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the private key as a Uint8Array (if available)
     * @returns {Uint8Array | undefined}
     */
    get private_key() {
        const ret = wasm.wasmecpair_private_key(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Get the compressed public key as a Uint8Array (always 33 bytes)
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmecpair_public_key(this.__wbg_ptr);
        return takeObject(ret);
    }
    /**
     * Convert to WIF string (mainnet)
     * @returns {string}
     */
    to_wif() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmecpair_to_wif(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Convert to mainnet WIF string
     * @returns {string}
     */
    to_wif_mainnet() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmecpair_to_wif_mainnet(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Convert to testnet WIF string
     * @returns {string}
     */
    to_wif_testnet() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmecpair_to_wif_testnet(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
}
if (Symbol.dispose) WasmECPair.prototype[Symbol.dispose] = WasmECPair.prototype.free;

/**
 * WASM wrapper for ReplayProtection
 */
export class WasmReplayProtection {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmReplayProtection.prototype);
        obj.__wbg_ptr = ptr;
        WasmReplayProtectionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmReplayProtectionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmreplayprotection_free(ptr, 0);
    }
    /**
     * Create from addresses (requires network for decoding)
     * @param {any[]} addresses
     * @param {string} network
     * @returns {WasmReplayProtection}
     */
    static from_addresses(addresses, network) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArrayJsValueToWasm0(addresses, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(network, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.wasmreplayprotection_from_addresses(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmReplayProtection.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Create from output scripts directly
     * @param {Uint8Array[]} output_scripts
     * @returns {WasmReplayProtection}
     */
    static from_output_scripts(output_scripts) {
        const ptr0 = passArrayJsValueToWasm0(output_scripts, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmreplayprotection_from_output_scripts(ptr0, len0);
        return WasmReplayProtection.__wrap(ret);
    }
    /**
     * Create from public keys (derives P2SH-P2PK output scripts)
     * @param {Uint8Array[]} public_keys
     * @returns {WasmReplayProtection}
     */
    static from_public_keys(public_keys) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArrayJsValueToWasm0(public_keys, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmreplayprotection_from_public_keys(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmReplayProtection.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) WasmReplayProtection.prototype[Symbol.dispose] = WasmReplayProtection.prototype.free;

/**
 * WASM wrapper for RootWalletKeys
 * Represents a set of three extended public keys with their derivation prefixes
 */
export class WasmRootWalletKeys {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmRootWalletKeys.prototype);
        obj.__wbg_ptr = ptr;
        WasmRootWalletKeysFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmRootWalletKeysFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmrootwalletkeys_free(ptr, 0);
    }
    /**
     * Get the backup key (second xpub)
     * @returns {WasmBIP32}
     */
    backup_key() {
        const ret = wasm.wasmrootwalletkeys_backup_key(this.__wbg_ptr);
        return WasmBIP32.__wrap(ret);
    }
    /**
     * Get the bitgo key (third xpub)
     * @returns {WasmBIP32}
     */
    bitgo_key() {
        const ret = wasm.wasmrootwalletkeys_bitgo_key(this.__wbg_ptr);
        return WasmBIP32.__wrap(ret);
    }
    /**
     * Create a RootWalletKeys from three BIP32 keys
     * Uses default derivation prefix of m/0/0 for all three keys
     *
     * # Arguments
     * - `user`: User key (first xpub)
     * - `backup`: Backup key (second xpub)
     * - `bitgo`: BitGo key (third xpub)
     * @param {WasmBIP32} user
     * @param {WasmBIP32} backup
     * @param {WasmBIP32} bitgo
     */
    constructor(user, backup, bitgo) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(user, WasmBIP32);
            _assertClass(backup, WasmBIP32);
            _assertClass(bitgo, WasmBIP32);
            wasm.wasmrootwalletkeys_new(retptr, user.__wbg_ptr, backup.__wbg_ptr, bitgo.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            this.__wbg_ptr = r0 >>> 0;
            WasmRootWalletKeysFinalization.register(this, this.__wbg_ptr, this);
            return this;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the user key (first xpub)
     * @returns {WasmBIP32}
     */
    user_key() {
        const ret = wasm.wasmrootwalletkeys_user_key(this.__wbg_ptr);
        return WasmBIP32.__wrap(ret);
    }
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
     * @param {WasmBIP32} user
     * @param {WasmBIP32} backup
     * @param {WasmBIP32} bitgo
     * @param {string} user_derivation
     * @param {string} backup_derivation
     * @param {string} bitgo_derivation
     * @returns {WasmRootWalletKeys}
     */
    static with_derivation_prefixes(user, backup, bitgo, user_derivation, backup_derivation, bitgo_derivation) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(user, WasmBIP32);
            _assertClass(backup, WasmBIP32);
            _assertClass(bitgo, WasmBIP32);
            const ptr0 = passStringToWasm0(user_derivation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(backup_derivation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(bitgo_derivation, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len2 = WASM_VECTOR_LEN;
            wasm.wasmrootwalletkeys_with_derivation_prefixes(retptr, user.__wbg_ptr, backup.__wbg_ptr, bitgo.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmRootWalletKeys.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) WasmRootWalletKeys.prototype[Symbol.dispose] = WasmRootWalletKeys.prototype.free;

/**
 * A Bitcoin-like transaction (for all networks except Zcash)
 *
 * This class provides basic transaction parsing and serialization for testing
 * compatibility with third-party transaction fixtures.
 */
export class WasmTransaction {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmTransaction.prototype);
        obj.__wbg_ptr = ptr;
        WasmTransactionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmTransactionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmtransaction_free(ptr, 0);
    }
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
     * @param {string} txid
     * @param {number} vout
     * @param {number | null} [sequence]
     * @returns {number}
     */
    add_input(txid, vout, sequence) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmtransaction_add_input(retptr, this.__wbg_ptr, ptr0, len0, vout, isLikeNone(sequence) ? 0x100000001 : (sequence) >>> 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Add an output to the transaction
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - The value in satoshis
     *
     * # Returns
     * The index of the newly added output
     * @param {Uint8Array} script
     * @param {bigint} value
     * @returns {number}
     */
    add_output(script, value) {
        const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wasmtransaction_add_output(this.__wbg_ptr, ptr0, len0, value);
        return ret >>> 0;
    }
    /**
     * Create an empty transaction (version 1, locktime 0)
     * @returns {WasmTransaction}
     */
    static create() {
        const ret = wasm.wasmtransaction_create();
        return WasmTransaction.__wrap(ret);
    }
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
     * @param {Uint8Array} bytes
     * @returns {WasmTransaction}
     */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmtransaction_from_bytes(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the transaction ID (txid)
     *
     * The txid is the double SHA256 of the transaction bytes (excluding witness
     * data for segwit transactions), displayed in reverse byte order (big-endian)
     * as is standard for Bitcoin.
     *
     * # Returns
     * The transaction ID as a hex string
     * @returns {string}
     */
    get_txid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmtransaction_get_txid(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Get the virtual size of the transaction
     *
     * Virtual size is calculated as ceil(weight / 4), where weight accounts
     * for the segwit discount on witness data.
     *
     * # Returns
     * The virtual size in virtual bytes (vbytes)
     * @returns {number}
     */
    get_vsize() {
        const ret = wasm.wasmtransaction_get_vsize(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Serialize the transaction to bytes
     *
     * # Returns
     * The serialized transaction bytes
     * @returns {Uint8Array}
     */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmtransaction_to_bytes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) WasmTransaction.prototype[Symbol.dispose] = WasmTransaction.prototype.free;

/**
 * A Zcash transaction with network-specific fields
 *
 * This class provides basic transaction parsing and serialization for Zcash
 * transactions, which use the Overwinter transaction format.
 */
export class WasmZcashTransaction {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmZcashTransaction.prototype);
        obj.__wbg_ptr = ptr;
        WasmZcashTransactionFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmZcashTransactionFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmzcashtransaction_free(ptr, 0);
    }
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
     * @param {Uint8Array} bytes
     * @returns {WasmZcashTransaction}
     */
    static from_bytes(bytes) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wasmzcashtransaction_from_bytes(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmZcashTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @returns {string}
     */
    get_txid() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmzcashtransaction_get_txid(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Serialize the transaction to bytes
     *
     * # Returns
     * The serialized transaction bytes
     * @returns {Uint8Array}
     */
    to_bytes() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wasmzcashtransaction_to_bytes(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
}
if (Symbol.dispose) WasmZcashTransaction.prototype[Symbol.dispose] = WasmZcashTransaction.prototype.free;

export class WrapDescriptor {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WrapDescriptor.prototype);
        obj.__wbg_ptr = ptr;
        WrapDescriptorFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WrapDescriptorFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wrapdescriptor_free(ptr, 0);
    }
    /**
     * @param {number} index
     * @returns {WrapDescriptor}
     */
    atDerivationIndex(index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_atDerivationIndex(retptr, this.__wbg_ptr, index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapDescriptor.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {any}
     */
    descType() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_descType(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Parse a descriptor string with an explicit public key type.
     *
     * Note that this function permits parsing a non-derivable descriptor with a derivable key type.
     * Use `from_string_detect_type` to automatically detect the key type.
     *
     * # Arguments
     * * `descriptor` - A string containing the descriptor to parse
     * * `pk_type` - The type of public key to expect:
     *   - "derivable": For descriptors containing derivation paths (eg. xpubs)
     *   - "definite": For descriptors with fully specified keys
     *   - "string": For descriptors with string placeholders
     *
     * # Returns
     * * `Result<WrapDescriptor, WasmUtxoError>` - The parsed descriptor or an error
     *
     * # Example
     * ```
     * use wasm_utxo::WrapDescriptor;
     * let desc = WrapDescriptor::from_string(
     *   "pk(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/*)",
     *   "derivable"
     * );
     * ```
     * @param {string} descriptor
     * @param {string} pk_type
     * @returns {WrapDescriptor}
     */
    static fromString(descriptor, pk_type) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(descriptor, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(pk_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.wrapdescriptor_fromString(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapDescriptor.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Parse a descriptor string, automatically detecting the appropriate public key type.
     * This will check if the descriptor contains wildcards to determine if it should be
     * parsed as derivable or definite.
     *
     * # Arguments
     * * `descriptor` - A string containing the descriptor to parse
     *
     * # Returns
     * * `Result<WrapDescriptor, WasmUtxoError>` - The parsed descriptor or an error
     *
     * # Example
     * ```
     * use wasm_utxo::WrapDescriptor;
     * // Will be parsed as definite since it has no wildcards
     * let desc = WrapDescriptor::from_string_detect_type(
     *   "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
     * );
     *
     * // Will be parsed as derivable since it contains a wildcard (*)
     * let desc = WrapDescriptor::from_string_detect_type(
     *   "pk(xpub.../0/*)"
     * );
     * ```
     * @param {string} descriptor
     * @returns {WrapDescriptor}
     */
    static fromStringDetectType(descriptor) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(descriptor, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrapdescriptor_fromStringDetectType(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapDescriptor.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {boolean}
     */
    hasWildcard() {
        const ret = wasm.wrapdescriptor_hasWildcard(this.__wbg_ptr);
        return ret !== 0;
    }
    /**
     * @returns {number}
     */
    maxWeightToSatisfy() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_maxWeightToSatisfy(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {any}
     */
    node() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_node(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    scriptPubkey() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_scriptPubkey(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            if (r3) {
                throw takeObject(r2);
            }
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    toAsmString() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_toAsmString(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapdescriptor_toString(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) WrapDescriptor.prototype[Symbol.dispose] = WrapDescriptor.prototype.free;

export class WrapMiniscript {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WrapMiniscript.prototype);
        obj.__wbg_ptr = ptr;
        WrapMiniscriptFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WrapMiniscriptFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wrapminiscript_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    encode() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapminiscript_encode(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} script
     * @param {string} context_type
     * @returns {WrapMiniscript}
     */
    static fromBitcoinScript(script, context_type) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(context_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.wrapminiscript_fromBitcoinScript(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapMiniscript.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} script
     * @param {string} context_type
     * @returns {WrapMiniscript}
     */
    static fromString(script, context_type) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(script, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(context_type, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len1 = WASM_VECTOR_LEN;
            wasm.wrapminiscript_fromString(retptr, ptr0, len0, ptr1, len1);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapMiniscript.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {any}
     */
    node() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapminiscript_node(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {string}
     */
    toAsmString() {
        let deferred2_0;
        let deferred2_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapminiscript_toAsmString(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
            var ptr1 = r0;
            var len1 = r1;
            if (r3) {
                ptr1 = 0; len1 = 0;
                throw takeObject(r2);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * @returns {string}
     */
    toString() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrapminiscript_toString(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
}
if (Symbol.dispose) WrapMiniscript.prototype[Symbol.dispose] = WrapMiniscript.prototype.free;

export class WrapPsbt {
    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WrapPsbt.prototype);
        obj.__wbg_ptr = ptr;
        WrapPsbtFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WrapPsbtFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wrappsbt_free(ptr, 0);
    }
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
     * @param {string} txid
     * @param {number} vout
     * @param {bigint} value
     * @param {Uint8Array} script
     * @param {number | null} [sequence]
     * @returns {number}
     */
    addInput(txid, vout, value, script, sequence) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(txid, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(script, wasm.__wbindgen_export);
            const len1 = WASM_VECTOR_LEN;
            wasm.wrappsbt_addInput(retptr, this.__wbg_ptr, ptr0, len0, vout, value, ptr1, len1, isLikeNone(sequence) ? 0x100000001 : (sequence) >>> 0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 >>> 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Add an output to the PSBT
     *
     * # Arguments
     * * `script` - The output script (scriptPubKey)
     * * `value` - Value in satoshis
     *
     * # Returns
     * The index of the newly added output
     * @param {Uint8Array} script
     * @param {bigint} value
     * @returns {number}
     */
    addOutput(script, value) {
        const ptr0 = passArray8ToWasm0(script, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.wrappsbt_addOutput(this.__wbg_ptr, ptr0, len0, value);
        return ret >>> 0;
    }
    /**
     * @returns {WrapPsbt}
     */
    clone() {
        const ret = wasm.wrappsbt_clone(this.__wbg_ptr);
        return WrapPsbt.__wrap(ret);
    }
    /**
     * @param {Uint8Array} psbt
     * @returns {WrapPsbt}
     */
    static deserialize(psbt) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(psbt, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrappsbt_deserialize(retptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WrapPsbt.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Extract the final transaction from a finalized PSBT
     *
     * This method should be called after all inputs have been finalized.
     * It extracts the fully signed transaction as a WasmTransaction instance.
     *
     * # Returns
     * - `Ok(WasmTransaction)` containing the extracted transaction
     * - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
     * @returns {WasmTransaction}
     */
    extractTransaction() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_extractTransaction(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return WasmTransaction.__wrap(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    finalize() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_finalize(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get all PSBT inputs as an array of PsbtInputData
     *
     * Returns an array with witness_utxo, bip32_derivation, and tap_bip32_derivation
     * for each input. This is useful for introspecting the PSBT structure.
     * @returns {any}
     */
    getInputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_getInputs(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get all PSBT outputs as an array of PsbtOutputData
     *
     * Returns an array with script, value, bip32_derivation, and tap_bip32_derivation
     * for each output. This is useful for introspecting the PSBT structure.
     * @returns {any}
     */
    getOutputs() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_getOutputs(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get all PSBT outputs with resolved address strings.
     *
     * Like `getOutputs()` but each element also includes an `address` field
     * derived from the output script using the given coin name (e.g. "btc", "tbtc").
     * @param {string} coin
     * @returns {any}
     */
    getOutputsWithAddress(coin) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(coin, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrappsbt_getOutputsWithAddress(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get partial signatures for an input
     * Returns array of { pubkey: Uint8Array, signature: Uint8Array }
     * @param {number} input_index
     * @returns {any}
     */
    getPartialSignatures(input_index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_getPartialSignatures(retptr, this.__wbg_ptr, input_index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the unsigned transaction bytes
     *
     * # Returns
     * The serialized unsigned transaction
     * @returns {Uint8Array}
     */
    getUnsignedTx() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_getUnsignedTx(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Check if an input has any partial signatures
     * @param {number} input_index
     * @returns {boolean}
     */
    hasPartialSignatures(input_index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_hasPartialSignatures(retptr, this.__wbg_ptr, input_index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the number of inputs in the PSBT
     * @returns {number}
     */
    inputCount() {
        const ret = wasm.wrappsbt_inputCount(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Get the transaction lock time
     * @returns {number}
     */
    lockTime() {
        const ret = wasm.wrappsbt_lockTime(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Create an empty PSBT
     *
     * # Arguments
     * * `version` - Transaction version (default: 2)
     * * `lock_time` - Transaction lock time (default: 0)
     * @param {number | null} [version]
     * @param {number | null} [lock_time]
     */
    constructor(version, lock_time) {
        const ret = wasm.wrappsbt_new(isLikeNone(version) ? 0x100000001 : (version) >> 0, isLikeNone(lock_time) ? 0x100000001 : (lock_time) >>> 0);
        this.__wbg_ptr = ret >>> 0;
        WrapPsbtFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Get the number of outputs in the PSBT
     * @returns {number}
     */
    outputCount() {
        const ret = wasm.wrappsbt_outputCount(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Remove an output from the PSBT by index.
     *
     * Removes both the transaction output and the PSBT output metadata.
     * @param {number} index
     */
    removeOutput(index) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_removeOutput(retptr, this.__wbg_ptr, index);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    serialize() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_serialize(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var v1 = getArrayU8FromWasm0(r0, r1).slice();
            wasm.__wbindgen_export4(r0, r1 * 1, 1);
            return v1;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmBIP32} key
     * @returns {any}
     */
    signAll(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, WasmBIP32);
            wasm.wrappsbt_signAll(retptr, this.__wbg_ptr, key.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {WasmECPair} key
     * @returns {any}
     */
    signAllWithEcpair(key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, WasmECPair);
            wasm.wrappsbt_signAllWithEcpair(retptr, this.__wbg_ptr, key.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {Uint8Array} prv
     * @returns {any}
     */
    signWithPrv(prv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(prv, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrappsbt_signWithPrv(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {string} xprv
     * @returns {any}
     */
    signWithXprv(xprv) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passStringToWasm0(xprv, wasm.__wbindgen_export, wasm.__wbindgen_export2);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrappsbt_signWithXprv(retptr, this.__wbg_ptr, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return takeObject(r0);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the unsigned transaction ID as a hex string
     * @returns {string}
     */
    unsignedTxId() {
        let deferred1_0;
        let deferred1_1;
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.wrappsbt_unsignedTxId(retptr, this.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            deferred1_0 = r0;
            deferred1_1 = r1;
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export4(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @param {number} input_index
     * @param {WrapDescriptor} descriptor
     */
    updateInputWithDescriptor(input_index, descriptor) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(descriptor, WrapDescriptor);
            wasm.wrappsbt_updateInputWithDescriptor(retptr, this.__wbg_ptr, input_index, descriptor.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * @param {number} output_index
     * @param {WrapDescriptor} descriptor
     */
    updateOutputWithDescriptor(output_index, descriptor) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(descriptor, WrapDescriptor);
            wasm.wrappsbt_updateOutputWithDescriptor(retptr, this.__wbg_ptr, output_index, descriptor.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            if (r1) {
                throw takeObject(r0);
            }
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Validate a signature at a specific input against a pubkey
     * Returns true if the signature is valid
     *
     * This method handles both ECDSA (legacy/SegWit) and Schnorr (Taproot) signatures.
     * The pubkey should be provided as bytes (33 bytes for compressed ECDSA, 32 bytes for x-only Schnorr).
     * @param {number} input_index
     * @param {Uint8Array} pubkey
     * @returns {boolean}
     */
    validateSignatureAtInput(input_index, pubkey) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            const ptr0 = passArray8ToWasm0(pubkey, wasm.__wbindgen_export);
            const len0 = WASM_VECTOR_LEN;
            wasm.wrappsbt_validateSignatureAtInput(retptr, this.__wbg_ptr, input_index, ptr0, len0);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
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
     * @param {number} input_index
     * @param {WasmBIP32} key
     * @returns {boolean}
     */
    verifySignatureWithKey(input_index, key) {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            _assertClass(key, WasmBIP32);
            wasm.wrappsbt_verifySignatureWithKey(retptr, this.__wbg_ptr, input_index, key.__wbg_ptr);
            var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
            var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
            var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
            if (r2) {
                throw takeObject(r1);
            }
            return r0 !== 0;
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
        }
    }
    /**
     * Get the transaction version
     * @returns {number}
     */
    version() {
        const ret = wasm.wrappsbt_version(this.__wbg_ptr);
        return ret;
    }
}
if (Symbol.dispose) WrapPsbt.prototype[Symbol.dispose] = WrapPsbt.prototype.free;

/**
 * Check if the inspect feature is enabled.
 *
 * # Returns
 * `true` if the feature is enabled, `false` otherwise
 * @returns {boolean}
 */
export function isInspectEnabled() {
    const ret = wasm.isInspectEnabled();
    return ret !== 0;
}

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
 * @param {Uint8Array} psbt_bytes
 * @param {string} coin_name
 * @returns {string}
 */
export function parsePsbtRawToJson(psbt_bytes, coin_name) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(psbt_bytes, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(coin_name, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.parsePsbtRawToJson(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {Uint8Array} psbt_bytes
 * @param {string} coin_name
 * @returns {string}
 */
export function parsePsbtToJson(psbt_bytes, coin_name) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(psbt_bytes, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(coin_name, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.parsePsbtToJson(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}

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
 * @param {Uint8Array} tx_bytes
 * @param {string} coin_name
 * @returns {string}
 */
export function parseTxToJson(tx_bytes, coin_name) {
    let deferred4_0;
    let deferred4_1;
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passArray8ToWasm0(tx_bytes, wasm.__wbindgen_export);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(coin_name, wasm.__wbindgen_export, wasm.__wbindgen_export2);
        const len1 = WASM_VECTOR_LEN;
        wasm.parseTxToJson(retptr, ptr0, len0, ptr1, len1);
        var r0 = getDataViewMemory0().getInt32(retptr + 4 * 0, true);
        var r1 = getDataViewMemory0().getInt32(retptr + 4 * 1, true);
        var r2 = getDataViewMemory0().getInt32(retptr + 4 * 2, true);
        var r3 = getDataViewMemory0().getInt32(retptr + 4 * 3, true);
        var ptr3 = r0;
        var len3 = r1;
        if (r3) {
            ptr3 = 0; len3 = 0;
            throw takeObject(r2);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
        wasm.__wbindgen_export4(deferred4_0, deferred4_1, 1);
    }
}
export function __wbg_Error_8c4e43fe74559d73(arg0, arg1) {
    const ret = Error(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
}
export function __wbg___wbindgen_is_function_0095a73b8b156f76(arg0) {
    const ret = typeof(getObject(arg0)) === 'function';
    return ret;
}
export function __wbg___wbindgen_is_null_ac34f5003991759a(arg0) {
    const ret = getObject(arg0) === null;
    return ret;
}
export function __wbg___wbindgen_is_object_5ae8e5880f2c1fbd(arg0) {
    const val = getObject(arg0);
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
}
export function __wbg___wbindgen_is_string_cd444516edc5b180(arg0) {
    const ret = typeof(getObject(arg0)) === 'string';
    return ret;
}
export function __wbg___wbindgen_is_undefined_9e4d92534c42d778(arg0) {
    const ret = getObject(arg0) === undefined;
    return ret;
}
export function __wbg___wbindgen_number_get_8ff4255516ccad3e(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'number' ? obj : undefined;
    getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
}
export function __wbg___wbindgen_string_get_72fb696202c56729(arg0, arg1) {
    const obj = getObject(arg1);
    const ret = typeof(obj) === 'string' ? obj : undefined;
    var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_export, wasm.__wbindgen_export2);
    var len1 = WASM_VECTOR_LEN;
    getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
    getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
}
export function __wbg___wbindgen_throw_be289d5034ed271b(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
}
export function __wbg_call_389efe28435a9388() { return handleError(function (arg0, arg1) {
    const ret = getObject(arg0).call(getObject(arg1));
    return addHeapObject(ret);
}, arguments); }
export function __wbg_call_4708e0c13bdc8e95() { return handleError(function (arg0, arg1, arg2) {
    const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
    return addHeapObject(ret);
}, arguments); }
export function __wbg_crypto_574e78ad8b13b65f(arg0) {
    const ret = getObject(arg0).crypto;
    return addHeapObject(ret);
}
export function __wbg_getRandomValues_b8f5dbd5f3995a9e() { return handleError(function (arg0, arg1) {
    getObject(arg0).getRandomValues(getObject(arg1));
}, arguments); }
export function __wbg_get_b3ed3ad4be2bc8ac() { return handleError(function (arg0, arg1) {
    const ret = Reflect.get(getObject(arg0), getObject(arg1));
    return addHeapObject(ret);
}, arguments); }
export function __wbg_length_32ed9a279acd054c(arg0) {
    const ret = getObject(arg0).length;
    return ret;
}
export function __wbg_msCrypto_a61aeb35a24c1329(arg0) {
    const ret = getObject(arg0).msCrypto;
    return addHeapObject(ret);
}
export function __wbg_new_361308b2356cecd0() {
    const ret = new Object();
    return addHeapObject(ret);
}
export function __wbg_new_3eb36ae241fe6f44() {
    const ret = new Array();
    return addHeapObject(ret);
}
export function __wbg_new_72b49615380db768(arg0, arg1) {
    const ret = new Error(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
}
export function __wbg_new_dd2b680c8bf6ae29(arg0) {
    const ret = new Uint8Array(getObject(arg0));
    return addHeapObject(ret);
}
export function __wbg_new_from_slice_a3d2629dc1826784(arg0, arg1) {
    const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
    return addHeapObject(ret);
}
export function __wbg_new_no_args_1c7c842f08d00ebb(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return addHeapObject(ret);
}
export function __wbg_new_with_length_a2c39cbe88fd8ff1(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return addHeapObject(ret);
}
export function __wbg_node_905d3e251edff8a2(arg0) {
    const ret = getObject(arg0).node;
    return addHeapObject(ret);
}
export function __wbg_process_dc0fbacc7c1c06f7(arg0) {
    const ret = getObject(arg0).process;
    return addHeapObject(ret);
}
export function __wbg_prototypesetcall_bdcdcc5842e4d77d(arg0, arg1, arg2) {
    Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), getObject(arg2));
}
export function __wbg_push_8ffdcb2063340ba5(arg0, arg1) {
    const ret = getObject(arg0).push(getObject(arg1));
    return ret;
}
export function __wbg_randomFillSync_ac0988aba3254290() { return handleError(function (arg0, arg1) {
    getObject(arg0).randomFillSync(takeObject(arg1));
}, arguments); }
export function __wbg_require_60cc747a6bc5215a() { return handleError(function () {
    const ret = module.require;
    return addHeapObject(ret);
}, arguments); }
export function __wbg_set_6cb8631f80447a67() { return handleError(function (arg0, arg1, arg2) {
    const ret = Reflect.set(getObject(arg0), getObject(arg1), getObject(arg2));
    return ret;
}, arguments); }
export function __wbg_static_accessor_GLOBAL_12837167ad935116() {
    const ret = typeof global === 'undefined' ? null : global;
    return isLikeNone(ret) ? 0 : addHeapObject(ret);
}
export function __wbg_static_accessor_GLOBAL_THIS_e628e89ab3b1c95f() {
    const ret = typeof globalThis === 'undefined' ? null : globalThis;
    return isLikeNone(ret) ? 0 : addHeapObject(ret);
}
export function __wbg_static_accessor_SELF_a621d3dfbb60d0ce() {
    const ret = typeof self === 'undefined' ? null : self;
    return isLikeNone(ret) ? 0 : addHeapObject(ret);
}
export function __wbg_static_accessor_WINDOW_f8727f0cf888e0bd() {
    const ret = typeof window === 'undefined' ? null : window;
    return isLikeNone(ret) ? 0 : addHeapObject(ret);
}
export function __wbg_subarray_a96e1fef17ed23cb(arg0, arg1, arg2) {
    const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
    return addHeapObject(ret);
}
export function __wbg_versions_c01dfd4722a88165(arg0) {
    const ret = getObject(arg0).versions;
    return addHeapObject(ret);
}
export function __wbg_wasmdashtransaction_new(arg0) {
    const ret = WasmDashTransaction.__wrap(arg0);
    return addHeapObject(ret);
}
export function __wbg_wasmecpair_unwrap(arg0) {
    const ret = WasmECPair.__unwrap(getObject(arg0));
    return ret;
}
export function __wbg_wasmtransaction_new(arg0) {
    const ret = WasmTransaction.__wrap(arg0);
    return addHeapObject(ret);
}
export function __wbg_wasmzcashtransaction_new(arg0) {
    const ret = WasmZcashTransaction.__wrap(arg0);
    return addHeapObject(ret);
}
export function __wbindgen_cast_0000000000000001(arg0) {
    // Cast intrinsic for `F64 -> Externref`.
    const ret = arg0;
    return addHeapObject(ret);
}
export function __wbindgen_cast_0000000000000002(arg0, arg1) {
    // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
    const ret = getArrayU8FromWasm0(arg0, arg1);
    return addHeapObject(ret);
}
export function __wbindgen_cast_0000000000000003(arg0, arg1) {
    // Cast intrinsic for `Ref(String) -> Externref`.
    const ret = getStringFromWasm0(arg0, arg1);
    return addHeapObject(ret);
}
export function __wbindgen_cast_0000000000000004(arg0) {
    // Cast intrinsic for `U64 -> Externref`.
    const ret = BigInt.asUintN(64, arg0);
    return addHeapObject(ret);
}
export function __wbindgen_object_clone_ref(arg0) {
    const ret = getObject(arg0);
    return addHeapObject(ret);
}
export function __wbindgen_object_drop_ref(arg0) {
    takeObject(arg0);
}
const AddressNamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_addressnamespace_free(ptr >>> 0, 1));
const Bip322NamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_bip322namespace_free(ptr >>> 0, 1));
const BitGoPsbtFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_bitgopsbt_free(ptr >>> 0, 1));
const FixedScriptWalletNamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_fixedscriptwalletnamespace_free(ptr >>> 0, 1));
const InscriptionsNamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_inscriptionsnamespace_free(ptr >>> 0, 1));
const MessageNamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_messagenamespace_free(ptr >>> 0, 1));
const UtxolibCompatNamespaceFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_utxolibcompatnamespace_free(ptr >>> 0, 1));
const WasmBIP32Finalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmbip32_free(ptr >>> 0, 1));
const WasmDashTransactionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdashtransaction_free(ptr >>> 0, 1));
const WasmDimensionsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmdimensions_free(ptr >>> 0, 1));
const WasmECPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmecpair_free(ptr >>> 0, 1));
const WasmReplayProtectionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmreplayprotection_free(ptr >>> 0, 1));
const WasmRootWalletKeysFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmrootwalletkeys_free(ptr >>> 0, 1));
const WasmTransactionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmtransaction_free(ptr >>> 0, 1));
const WasmZcashTransactionFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmzcashtransaction_free(ptr >>> 0, 1));
const WrapDescriptorFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wrapdescriptor_free(ptr >>> 0, 1));
const WrapMiniscriptFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wrapminiscript_free(ptr >>> 0, 1));
const WrapPsbtFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wrappsbt_free(ptr >>> 0, 1));

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function addBorrowedObject(obj) {
    if (stack_pointer == 1) throw new Error('out of js stack');
    heap[--stack_pointer] = obj;
    return stack_pointer;
}

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(takeObject(mem.getUint32(i, true)));
    }
    return result;
}

function getArrayU32FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint32ArrayMemory0().subarray(ptr / 4, ptr / 4 + len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

let cachedUint32ArrayMemory0 = null;
function getUint32ArrayMemory0() {
    if (cachedUint32ArrayMemory0 === null || cachedUint32ArrayMemory0.byteLength === 0) {
        cachedUint32ArrayMemory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32ArrayMemory0;
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getObject(idx) { return heap[idx]; }

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export3(addHeapObject(e));
    }
}

let heap = new Array(128).fill(undefined);
heap.push(undefined, null, true, false);

let heap_next = heap.length;

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    const mem = getDataViewMemory0();
    for (let i = 0; i < array.length; i++) {
        mem.setUint32(ptr + 4 * i, addHeapObject(array[i]), true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let stack_pointer = 128;

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;


let wasm;
export function __wbg_set_wasm(val) {
    wasm = val;
}
