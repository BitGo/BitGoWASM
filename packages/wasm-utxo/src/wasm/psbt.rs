use crate::address::networks::{from_output_script_with_network_and_format, AddressFormat};
use crate::error::WasmUtxoError;
use crate::wasm::bip32::WasmBIP32;
use crate::wasm::descriptor::WrapDescriptorEnum;
use crate::wasm::ecpair::WasmECPair;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use crate::wasm::WrapDescriptor;
use miniscript::bitcoin::bip32::Fingerprint;
use miniscript::bitcoin::locktime::absolute::LockTime;
use miniscript::bitcoin::secp256k1::{Secp256k1, Signing};
use miniscript::bitcoin::transaction::{Transaction, Version};
use miniscript::bitcoin::{
    bip32, psbt, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, XOnlyPublicKey,
};
use miniscript::bitcoin::{PrivateKey, Psbt, Script, TxIn, TxOut, Txid};
use miniscript::descriptor::{SinglePub, SinglePubKey};
use miniscript::psbt::PsbtExt;
use miniscript::{DescriptorPublicKey, ToPublicKey};
use std::str::FromStr;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::{JsError, JsValue};

#[derive(Debug)]
struct SingleKeySigner {
    privkey: PrivateKey,
    pubkey: PublicKey,
    _pubkey_xonly: XOnlyPublicKey,
    fingerprint: Fingerprint,
    fingerprint_xonly: Fingerprint,
}

impl SingleKeySigner {
    fn fingerprint(key: SinglePubKey) -> Fingerprint {
        DescriptorPublicKey::Single(SinglePub { origin: None, key }).master_fingerprint()
    }

    fn from_privkey<C: Signing>(privkey: PrivateKey, secp: &Secp256k1<C>) -> SingleKeySigner {
        let pubkey = privkey.public_key(secp);
        let pubkey_xonly = pubkey.to_x_only_pubkey();
        SingleKeySigner {
            privkey,
            pubkey,
            _pubkey_xonly: pubkey_xonly,
            fingerprint: SingleKeySigner::fingerprint(SinglePubKey::FullKey(pubkey)),
            fingerprint_xonly: SingleKeySigner::fingerprint(SinglePubKey::XOnly(pubkey_xonly)),
        }
    }
}

impl psbt::GetKey for SingleKeySigner {
    type Error = String;

    fn get_key<C: Signing>(
        &self,
        key_request: psbt::KeyRequest,
        _secp: &Secp256k1<C>,
    ) -> Result<Option<PrivateKey>, Self::Error> {
        match key_request {
            // NOTE: this KeyRequest does not occur for taproot signatures
            // even if the descriptor keys are definite, we will receive a bip32 request
            // instead based on `DescriptorPublicKey::Single(SinglePub { origin: None, key, })`
            psbt::KeyRequest::Pubkey(req_pubkey) => {
                if req_pubkey == self.pubkey {
                    Ok(Some(self.privkey))
                } else {
                    Ok(None)
                }
            }

            psbt::KeyRequest::Bip32((fingerprint, _path)) => {
                if fingerprint.eq(&self.fingerprint) || fingerprint.eq(&self.fingerprint_xonly) {
                    Ok(Some(self.privkey))
                } else {
                    Ok(None)
                }
            }

            _ => Ok(None),
        }
    }
}

// ============================================================================
// PSBT Introspection Types
// ============================================================================

/// BIP32 derivation information
#[derive(Debug, Clone)]
pub struct Bip32Derivation {
    pub pubkey: Vec<u8>,
    pub path: String,
}

/// Witness UTXO information
#[derive(Debug, Clone)]
pub struct WitnessUtxo {
    pub script: Vec<u8>,
    pub value: u64,
}

/// Raw PSBT input data for introspection
#[derive(Debug, Clone)]
pub struct PsbtInputData {
    pub witness_utxo: Option<WitnessUtxo>,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub tap_bip32_derivation: Vec<Bip32Derivation>,
}

impl From<&psbt::Input> for PsbtInputData {
    fn from(input: &psbt::Input) -> Self {
        let witness_utxo = input.witness_utxo.as_ref().map(|utxo| WitnessUtxo {
            script: utxo.script_pubkey.to_bytes(),
            value: utxo.value.to_sat(),
        });

        let bip32_derivation: Vec<Bip32Derivation> = input
            .bip32_derivation
            .iter()
            .map(|(pubkey, (_, path))| Bip32Derivation {
                pubkey: pubkey.serialize().to_vec(),
                path: path.to_string(),
            })
            .collect();

        let tap_bip32_derivation: Vec<Bip32Derivation> = input
            .tap_key_origins
            .iter()
            .map(|(xonly_pubkey, (_, (_, path)))| Bip32Derivation {
                pubkey: xonly_pubkey.serialize().to_vec(),
                path: path.to_string(),
            })
            .collect();

        PsbtInputData {
            witness_utxo,
            bip32_derivation,
            tap_bip32_derivation,
        }
    }
}

/// Raw PSBT output data for introspection
#[derive(Debug, Clone)]
pub struct PsbtOutputData {
    pub script: Vec<u8>,
    pub value: u64,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub tap_bip32_derivation: Vec<Bip32Derivation>,
}

impl PsbtOutputData {
    pub fn from(tx_out: &TxOut, psbt_out: &psbt::Output) -> Self {
        let bip32_derivation: Vec<Bip32Derivation> = psbt_out
            .bip32_derivation
            .iter()
            .map(|(pubkey, (_, path))| Bip32Derivation {
                pubkey: pubkey.serialize().to_vec(),
                path: path.to_string(),
            })
            .collect();

        let tap_bip32_derivation: Vec<Bip32Derivation> = psbt_out
            .tap_key_origins
            .iter()
            .map(|(xonly_pubkey, (_, (_, path)))| Bip32Derivation {
                pubkey: xonly_pubkey.serialize().to_vec(),
                path: path.to_string(),
            })
            .collect();

        PsbtOutputData {
            script: tx_out.script_pubkey.to_bytes(),
            value: tx_out.value.to_sat(),
            bip32_derivation,
            tap_bip32_derivation,
        }
    }
}

/// PSBT output data with a resolved address string (requires a coin name for encoding).
#[derive(Debug, Clone)]
pub struct PsbtOutputDataWithAddress {
    pub script: Vec<u8>,
    pub value: u64,
    pub address: String,
    pub bip32_derivation: Vec<Bip32Derivation>,
    pub tap_bip32_derivation: Vec<Bip32Derivation>,
}

impl PsbtOutputDataWithAddress {
    pub fn from(base: PsbtOutputData, network: crate::Network) -> Result<Self, WasmUtxoError> {
        let script_obj = Script::from_bytes(&base.script);
        let address =
            from_output_script_with_network_and_format(script_obj, network, AddressFormat::Default)
                .map_err(|e| WasmUtxoError::new(&e.to_string()))?;
        Ok(PsbtOutputDataWithAddress {
            script: base.script,
            value: base.value,
            address,
            bip32_derivation: base.bip32_derivation,
            tap_bip32_derivation: base.tap_bip32_derivation,
        })
    }
}

// ============================================================================
// Helper functions for PSBT introspection - shared by WrapPsbt and BitGoPsbt
// ============================================================================

/// Get all PSBT inputs as an array of PsbtInputData
pub fn get_inputs_from_psbt(psbt: &Psbt) -> Result<JsValue, WasmUtxoError> {
    let inputs: Vec<PsbtInputData> = psbt.inputs.iter().map(PsbtInputData::from).collect();
    inputs.try_to_js_value()
}

/// Get all PSBT outputs as an array of PsbtOutputData
pub fn get_outputs_from_psbt(psbt: &Psbt) -> Result<JsValue, WasmUtxoError> {
    let outputs: Vec<PsbtOutputData> = psbt
        .unsigned_tx
        .output
        .iter()
        .zip(psbt.outputs.iter())
        .map(|(tx_out, psbt_out)| PsbtOutputData::from(tx_out, psbt_out))
        .collect();
    outputs.try_to_js_value()
}

/// Get global xpubs from a PSBT as an array of WasmBIP32 instances
pub fn get_global_xpubs_from_psbt(psbt: &Psbt) -> JsValue {
    let arr = js_sys::Array::new();
    for xpub in psbt.xpub.keys() {
        arr.push(&WasmBIP32::from_xpub_internal(*xpub).into());
    }
    arr.into()
}

/// Get all PSBT outputs with resolved address strings
pub fn get_outputs_with_address_from_psbt(
    psbt: &Psbt,
    network: crate::Network,
) -> Result<JsValue, WasmUtxoError> {
    let outputs: Vec<PsbtOutputDataWithAddress> = psbt
        .unsigned_tx
        .output
        .iter()
        .zip(psbt.outputs.iter())
        .map(|(tx_out, psbt_out)| {
            let base = PsbtOutputData::from(tx_out, psbt_out);
            PsbtOutputDataWithAddress::from(base, network)
        })
        .collect::<Result<Vec<_>, _>>()?;
    outputs.try_to_js_value()
}

#[wasm_bindgen]
pub struct WrapPsbt(Psbt);

#[wasm_bindgen()]
impl WrapPsbt {
    /// Create an empty PSBT
    ///
    /// # Arguments
    /// * `version` - Transaction version (default: 2)
    /// * `lock_time` - Transaction lock time (default: 0)
    #[wasm_bindgen(constructor)]
    pub fn new(version: Option<i32>, lock_time: Option<u32>) -> WrapPsbt {
        let tx = Transaction {
            version: Version(version.unwrap_or(2)),
            lock_time: LockTime::from_consensus(lock_time.unwrap_or(0)),
            input: vec![],
            output: vec![],
        };
        WrapPsbt(Psbt::from_unsigned_tx(tx).expect("empty transaction should be valid"))
    }

    pub fn deserialize(psbt: Vec<u8>) -> Result<WrapPsbt, JsError> {
        Ok(WrapPsbt(Psbt::deserialize(&psbt).map_err(JsError::from)?))
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize()
    }

    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> WrapPsbt {
        Clone::clone(self)
    }

    /// Add an input to the PSBT
    ///
    /// # Arguments
    /// * `txid` - Transaction ID (hex string, 32 bytes reversed)
    /// * `vout` - Output index being spent
    /// * `value` - Value in satoshis of the output being spent
    /// * `script` - The scriptPubKey of the output being spent
    /// * `sequence` - Sequence number (default: 0xFFFFFFFE for RBF)
    ///
    /// # Returns
    /// The index of the newly added input
    pub fn add_input_at_index(
        &mut self,
        index: usize,
        txid: &str,
        vout: u32,
        value: u64,
        script: &[u8],
        sequence: Option<u32>,
    ) -> Result<usize, JsError> {
        let txid =
            Txid::from_str(txid).map_err(|e| JsError::new(&format!("Invalid txid: {}", e)))?;
        let script = ScriptBuf::from_bytes(script.to_vec());

        let tx_in = TxIn {
            previous_output: OutPoint { txid, vout },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence.unwrap_or(0xFFFFFFFE)),
            witness: miniscript::bitcoin::Witness::default(),
        };
        let psbt_input = psbt::Input {
            witness_utxo: Some(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: script,
            }),
            ..Default::default()
        };

        crate::psbt_ops::insert_input(&mut self.0, index, tx_in, psbt_input)
            .map_err(|e| JsError::new(&e))
    }

    pub fn add_input(
        &mut self,
        txid: &str,
        vout: u32,
        value: u64,
        script: &[u8],
        sequence: Option<u32>,
    ) -> Result<usize, JsError> {
        self.add_input_at_index(self.0.inputs.len(), txid, vout, value, script, sequence)
    }

    /// Add an output to the PSBT
    ///
    /// # Arguments
    /// * `script` - The output script (scriptPubKey)
    /// * `value` - Value in satoshis
    ///
    /// # Returns
    /// The index of the newly added output
    pub fn add_output_at_index(
        &mut self,
        index: usize,
        script: &[u8],
        value: u64,
    ) -> Result<usize, JsError> {
        let script = ScriptBuf::from_bytes(script.to_vec());
        let tx_out = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        };

        crate::psbt_ops::insert_output(&mut self.0, index, tx_out, psbt::Output::default())
            .map_err(|e| JsError::new(&e))
    }

    pub fn add_output(&mut self, script: &[u8], value: u64) -> usize {
        self.add_output_at_index(self.0.outputs.len(), script, value)
            .expect("insert at len should never fail")
    }

    pub fn remove_input(&mut self, index: usize) -> Result<(), JsError> {
        crate::psbt_ops::remove_input(&mut self.0, index).map_err(|e| JsError::new(&e))
    }

    pub fn remove_output(&mut self, index: usize) -> Result<(), JsError> {
        crate::psbt_ops::remove_output(&mut self.0, index).map_err(|e| JsError::new(&e))
    }

    /// Get the unsigned transaction bytes
    ///
    /// # Returns
    /// The serialized unsigned transaction
    pub fn get_unsigned_tx(&self) -> Vec<u8> {
        use miniscript::bitcoin::consensus::Encodable;
        let mut buf = Vec::new();
        self.0
            .unsigned_tx
            .consensus_encode(&mut buf)
            .expect("encoding to vec should not fail");
        buf
    }

    pub fn update_input_with_descriptor(
        &mut self,
        input_index: usize,
        descriptor: &WrapDescriptor,
    ) -> Result<(), JsError> {
        match &descriptor.0 {
            WrapDescriptorEnum::Definite(d) => self
                .0
                .update_input_with_descriptor(input_index, d)
                .map_err(JsError::from),
            WrapDescriptorEnum::Derivable(_, _) => Err(JsError::new(
                "Cannot update input with a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => {
                Err(JsError::new("Cannot update input with a string descriptor"))
            }
        }
    }

    pub fn update_output_with_descriptor(
        &mut self,
        output_index: usize,
        descriptor: &WrapDescriptor,
    ) -> Result<(), JsError> {
        match &descriptor.0 {
            WrapDescriptorEnum::Definite(d) => self
                .0
                .update_output_with_descriptor(output_index, d)
                .map_err(JsError::from),
            WrapDescriptorEnum::Derivable(_, _) => Err(JsError::new(
                "Cannot update output with a derivable descriptor",
            )),
            WrapDescriptorEnum::String(_) => Err(JsError::new(
                "Cannot update output with a string descriptor",
            )),
        }
    }

    pub fn sign_with_xprv(&mut self, xprv: String) -> Result<JsValue, WasmUtxoError> {
        let key = bip32::Xpriv::from_str(&xprv).map_err(|_| WasmUtxoError::new("Invalid xprv"))?;
        self.0
            .sign(&key, &Secp256k1::new())
            .map_err(|(_, errors)| {
                WasmUtxoError::new(&format!("{} errors: {:?}", errors.len(), errors))
            })
            .and_then(|r| r.try_to_js_value())
    }

    pub fn sign_with_prv(&mut self, prv: Vec<u8>) -> Result<JsValue, WasmUtxoError> {
        let privkey = PrivateKey::from_slice(&prv, miniscript::bitcoin::network::Network::Bitcoin)
            .map_err(|_| WasmUtxoError::new("Invalid private key"))?;
        let secp = Secp256k1::new();
        self.0
            .sign(&SingleKeySigner::from_privkey(privkey, &secp), &secp)
            .map_err(|(_r, errors)| {
                WasmUtxoError::new(&format!("{} errors: {:?}", errors.len(), errors))
            })
            .and_then(|r| r.try_to_js_value())
    }

    /// Sign all inputs with a WasmBIP32 key
    ///
    /// This method signs all inputs that match the BIP32 derivation paths in the PSBT.
    /// Returns a map of input indices to the public keys that were signed.
    ///
    /// # Arguments
    /// * `key` - The WasmBIP32 key to sign with
    ///
    /// # Returns
    /// A SigningKeysMap converted to JsValue (object mapping input indices to signing keys)
    pub fn sign_all(&mut self, key: &WasmBIP32) -> Result<JsValue, WasmUtxoError> {
        let xpriv = key.to_xpriv()?;
        self.0
            .sign(&xpriv, &Secp256k1::new())
            .map_err(|(_, errors)| {
                WasmUtxoError::new(&format!("{} errors: {:?}", errors.len(), errors))
            })
            .and_then(|r| r.try_to_js_value())
    }

    /// Sign all inputs with a WasmECPair key
    ///
    /// This method signs all inputs using the private key from the ECPair.
    /// Returns a map of input indices to the public keys that were signed.
    ///
    /// # Arguments
    /// * `key` - The WasmECPair key to sign with
    ///
    /// # Returns
    /// A SigningKeysMap converted to JsValue (object mapping input indices to signing keys)
    pub fn sign_all_with_ecpair(&mut self, key: &WasmECPair) -> Result<JsValue, WasmUtxoError> {
        let privkey = key.get_private_key()?;
        let secp = Secp256k1::new();
        let private_key = PrivateKey::new(privkey, miniscript::bitcoin::network::Network::Bitcoin);
        self.0
            .sign(&SingleKeySigner::from_privkey(private_key, &secp), &secp)
            .map_err(|(_r, errors)| {
                WasmUtxoError::new(&format!("{} errors: {:?}", errors.len(), errors))
            })
            .and_then(|r| r.try_to_js_value())
    }

    /// Verify a signature at a specific input using a WasmBIP32 key
    ///
    /// This method verifies if a valid signature exists for the given BIP32 key at the specified input.
    /// It handles both ECDSA (legacy/SegWit) and Schnorr (Taproot) signatures.
    ///
    /// Note: This method checks if the key's public key matches any signature in the input.
    /// For proper BIP32 verification, the key should be derived to the correct path first.
    ///
    /// # Arguments
    /// * `input_index` - The index of the input to check
    /// * `key` - The WasmBIP32 key to verify against
    ///
    /// # Returns
    /// `true` if a valid signature exists for the key, `false` otherwise
    pub fn verify_signature_with_key(
        &self,
        input_index: usize,
        key: &WasmBIP32,
    ) -> Result<bool, WasmUtxoError> {
        use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input;
        use miniscript::bitcoin::{sighash::SighashCache, CompressedPublicKey, PublicKey};

        let input = self.0.inputs.get(input_index).ok_or_else(|| {
            WasmUtxoError::new(&format!("Input index {} out of bounds", input_index))
        })?;

        let secp = Secp256k1::verification_only();
        let xpub = key.to_xpub()?;

        // Get the public key from Xpub (compressed format)
        let compressed_pubkey = xpub.to_pub();
        let compressed_public_key = CompressedPublicKey::from_slice(&compressed_pubkey.to_bytes())
            .map_err(|e| {
                WasmUtxoError::new(&format!(
                    "Failed to convert to compressed public key: {}",
                    e
                ))
            })?;
        let public_key = PublicKey::from_slice(&compressed_public_key.to_bytes())
            .map_err(|e| WasmUtxoError::new(&format!("Failed to convert public key: {}", e)))?;

        // Try ECDSA signature verification first (for legacy/SegWit)
        // Use standard Bitcoin (no fork_id) for WASM PSBT
        match psbt_wallet_input::verify_ecdsa_signature(
            &secp,
            &self.0,
            input_index,
            compressed_public_key,
            None, // fork_id: None for standard Bitcoin
        ) {
            Ok(true) => return Ok(true),
            Ok(false) => {} // Continue to try Taproot
            Err(e) => {
                return Err(WasmUtxoError::new(&format!(
                    "ECDSA verification error: {}",
                    e
                )))
            }
        }

        // Try Schnorr signature verification (for Taproot)
        let (x_only_key, _parity) = public_key.inner.x_only_public_key();

        // Create cache once for reuse across taproot verifications
        let mut cache = SighashCache::new(&self.0.unsigned_tx);

        // Check taproot script path signatures
        if !input.tap_script_sigs.is_empty() {
            match psbt_wallet_input::verify_taproot_script_signature(
                &secp,
                &self.0,
                input_index,
                compressed_public_key,
                &mut cache,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {} // Continue to try key path
                Err(e) => {
                    return Err(WasmUtxoError::new(&format!(
                        "Taproot script verification error: {}",
                        e
                    )))
                }
            }
        }

        // Check taproot key path signature
        match psbt_wallet_input::verify_taproot_key_signature(
            &secp,
            &self.0,
            input_index,
            x_only_key,
            &mut cache,
        ) {
            Ok(true) => return Ok(true),
            Ok(false) => {} // No signature found
            Err(e) => {
                return Err(WasmUtxoError::new(&format!(
                    "Taproot key verification error: {}",
                    e
                )))
            }
        }

        // No matching signature found
        Ok(false)
    }

    pub fn finalize_mut(&mut self) -> Result<(), WasmUtxoError> {
        self.0
            .finalize_mut(&Secp256k1::verification_only())
            .map_err(|vec_err| {
                WasmUtxoError::new(&format!("{} errors: {:?}", vec_err.len(), vec_err))
            })
    }

    /// Extract the final transaction from a finalized PSBT
    ///
    /// This method should be called after all inputs have been finalized.
    /// It extracts the fully signed transaction as a WasmTransaction instance.
    ///
    /// # Returns
    /// - `Ok(WasmTransaction)` containing the extracted transaction
    /// - `Err(WasmUtxoError)` if the PSBT is not fully finalized or extraction fails
    pub fn extract_transaction(
        &self,
    ) -> Result<crate::wasm::transaction::WasmTransaction, WasmUtxoError> {
        let tx =
            self.0.clone().extract_tx().map_err(|e| {
                WasmUtxoError::new(&format!("Failed to extract transaction: {}", e))
            })?;
        Ok(crate::wasm::transaction::WasmTransaction::from_tx(tx))
    }

    pub fn input_count(&self) -> usize {
        crate::psbt_ops::PsbtAccess::input_count(self)
    }

    pub fn output_count(&self) -> usize {
        crate::psbt_ops::PsbtAccess::output_count(self)
    }

    pub fn get_inputs(&self) -> Result<JsValue, WasmUtxoError> {
        get_inputs_from_psbt(&self.0)
    }

    pub fn get_outputs(&self) -> Result<JsValue, WasmUtxoError> {
        get_outputs_from_psbt(&self.0)
    }

    pub fn get_outputs_with_address(&self, coin: &str) -> Result<JsValue, WasmUtxoError> {
        let network = crate::Network::from_coin_name(coin)
            .ok_or_else(|| WasmUtxoError::new(&format!("Unknown coin: {}", coin)))?;
        get_outputs_with_address_from_psbt(&self.0, network)
    }

    pub fn get_global_xpubs(&self) -> JsValue {
        get_global_xpubs_from_psbt(&self.0)
    }

    pub fn get_partial_signatures(&self, input_index: usize) -> Result<JsValue, WasmUtxoError> {
        use crate::wasm::try_into_js_value::{collect_partial_signatures, TryIntoJsValue};

        let input = self.0.inputs.get(input_index).ok_or_else(|| {
            WasmUtxoError::new(&format!("Input index {} out of bounds", input_index))
        })?;

        let signatures = collect_partial_signatures(input);
        signatures.try_to_js_value()
    }

    pub fn has_partial_signatures(&self, input_index: usize) -> Result<bool, JsError> {
        let input =
            self.0.inputs.get(input_index).ok_or_else(|| {
                JsError::new(&format!("Input index {} out of bounds", input_index))
            })?;

        Ok(!input.partial_sigs.is_empty()
            || !input.tap_script_sigs.is_empty()
            || input.tap_key_sig.is_some())
    }

    pub fn unsigned_tx_id(&self) -> String {
        crate::psbt_ops::PsbtAccess::unsigned_tx_id(self)
    }

    pub fn lock_time(&self) -> u32 {
        crate::psbt_ops::PsbtAccess::lock_time(self)
    }

    pub fn version(&self) -> i32 {
        crate::psbt_ops::PsbtAccess::version(self)
    }

    pub fn validate_signature_at_input(
        &self,
        input_index: usize,
        pubkey: Vec<u8>,
    ) -> Result<bool, JsError> {
        use crate::fixed_script_wallet::bitgo_psbt::psbt_wallet_input;
        use miniscript::bitcoin::{sighash::SighashCache, CompressedPublicKey, XOnlyPublicKey};

        let input =
            self.0.inputs.get(input_index).ok_or_else(|| {
                JsError::new(&format!("Input index {} out of bounds", input_index))
            })?;

        let secp = Secp256k1::verification_only();

        // Try ECDSA signature verification first (for legacy/SegWit)
        if pubkey.len() == 33 {
            let compressed_public_key = CompressedPublicKey::from_slice(&pubkey)
                .map_err(|e| JsError::new(&format!("Invalid public key: {}", e)))?;

            // Use standard Bitcoin (no fork_id) for WASM PSBT
            match psbt_wallet_input::verify_ecdsa_signature(
                &secp,
                &self.0,
                input_index,
                compressed_public_key,
                None, // fork_id: None for standard Bitcoin
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {} // Continue to try Taproot if pubkey length allows
                Err(e) => return Err(JsError::new(&format!("ECDSA verification error: {}", e))),
            }
        }

        // Try Schnorr signature verification (for Taproot)
        if pubkey.len() == 32 {
            let x_only_key = XOnlyPublicKey::from_slice(&pubkey)
                .map_err(|e| JsError::new(&format!("Invalid x-only public key: {}", e)))?;

            // Create cache once for reuse across taproot verifications
            let mut cache = SighashCache::new(&self.0.unsigned_tx);

            // Check taproot script path signatures
            // Convert x_only_key to CompressedPublicKey for the helper function
            // We need to prepend 0x02 (even parity) to create a compressed public key
            let mut compressed_key_bytes = vec![0x02u8];
            compressed_key_bytes.extend_from_slice(&x_only_key.serialize());
            let compressed_public_key = CompressedPublicKey::from_slice(&compressed_key_bytes)
                .map_err(|e| JsError::new(&format!("Failed to convert x-only key: {}", e)))?;

            if !input.tap_script_sigs.is_empty() {
                match psbt_wallet_input::verify_taproot_script_signature(
                    &secp,
                    &self.0,
                    input_index,
                    compressed_public_key,
                    &mut cache,
                ) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {} // Continue to try key path
                    Err(e) => {
                        return Err(JsError::new(&format!(
                            "Taproot script verification error: {}",
                            e
                        )))
                    }
                }
            }

            // Check taproot key path signature
            match psbt_wallet_input::verify_taproot_key_signature(
                &secp,
                &self.0,
                input_index,
                x_only_key,
                &mut cache,
            ) {
                Ok(true) => return Ok(true),
                Ok(false) => {} // No signature found
                Err(e) => {
                    return Err(JsError::new(&format!(
                        "Taproot key verification error: {}",
                        e
                    )))
                }
            }
        }

        // No matching signature found
        Ok(false)
    }
}

impl crate::psbt_ops::PsbtAccess for WrapPsbt {
    fn psbt(&self) -> &Psbt {
        &self.0
    }
    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.0
    }
}

impl Clone for WrapPsbt {
    fn clone(&self) -> Self {
        WrapPsbt(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::error::WasmUtxoError;
    use crate::wasm::psbt::SingleKeySigner;
    use crate::Network;
    use base64::prelude::*;
    use miniscript::bitcoin::bip32::{DerivationPath, Fingerprint, KeySource};
    use miniscript::bitcoin::psbt::{SigningKeys, SigningKeysMap};
    use miniscript::bitcoin::secp256k1::Secp256k1;
    use miniscript::bitcoin::{PrivateKey, Psbt};
    use miniscript::psbt::PsbtExt;
    use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ToPublicKey};
    use std::str::FromStr;

    fn psbt_from_base64(s: &str) -> Result<Psbt, WasmUtxoError> {
        let psbt = BASE64_STANDARD
            .decode(s.as_bytes())
            .map_err(|_| WasmUtxoError::new("Invalid base64"))?;
        Psbt::deserialize(&psbt).map_err(|e| WasmUtxoError::new(&format!("Invalid PSBT: {}", e)))
    }

    #[test]
    pub fn test_wrap_privkey() {
        let desc = "tr(039ab0771c5f88913208a26f81ab8223e98d25176e4648a5a2bb8ff79cf1c5198b,pk(039ab0771c5f88913208a26f81ab8223e98d25176e4648a5a2bb8ff79cf1c5198b))";
        let desc = Descriptor::<DefiniteDescriptorKey>::from_str(desc).unwrap();
        let psbt = "cHNidP8BAKYCAAAAAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAD9////AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAP3///8CgBoGAAAAAAAWABRTtvjcap+5t7odMosMnHl97YJClYAaBgAAAAAAIlEg1S2GuUvFU+Ve4XFLV65ffhuYsGeDkpaER6lQFjONAmEAAAAAAAEBK0BCDwAAAAAAIlEg1S2GuUvFU+Ve4XFLV65ffhuYsGeDkpaER6lQFjONAmEAAQErQEIPAAAAAAAiUSDVLYa5S8VT5V7hcUtXrl9+G5iwZ4OSloRHqVAWM40CYQAAAA==";
        let mut psbt = psbt_from_base64(psbt).unwrap();
        psbt.update_input_with_descriptor(0, &desc).unwrap();
        println!("{:?}", psbt.inputs[0].tap_key_origins);
        let prv =
            PrivateKey::from_str("KzEGYtKcbhYwUWcZygbsqmF31f3iV7HC3iUQug7MBecwCz9hm1Tv").unwrap();
        let pk = prv.public_key(&Secp256k1::new()).to_x_only_pubkey();
        let secp = Secp256k1::new();
        let sks = SingleKeySigner::from_privkey(prv, &secp);
        psbt.inputs[0]
            .tap_key_origins
            .values()
            .for_each(|key_source| {
                let key_source_ref: KeySource = (
                    Fingerprint::from_hex("aeee1e6a").unwrap(),
                    DerivationPath::from(vec![]),
                );
                assert_eq!(key_source.1, key_source_ref);
                assert_eq!(sks.fingerprint, key_source.1 .0,);
            });
        let mut expected_keys = SigningKeysMap::new();
        expected_keys.insert(0, SigningKeys::Schnorr(vec![pk]));
        expected_keys.insert(1, SigningKeys::Schnorr(vec![]));
        assert_eq!(psbt.sign(&sks, &secp).unwrap(), expected_keys);
    }

    #[test]
    fn test_tr_xpub() {
        let d = "tr(xpub661MyMwAqRbcEv1i36otFUwWZRcQBJHjdCoQvqykteW4sMHP3m4h9TzvPhK9q7rtkkWMMTJB4jFxCgVki9GwB9GvfHf366dpXDAaHHHdad2/*,{pk(xpub661MyMwAqRbcFod8uqcC3G2jub4McRVKZsZrvWZXAUFBjeuyMT2UqDFkw3TAUebQRAE7XQKFFhvLRW2mWvmKC2KzNuCkzVkFucWapGqnkXj/*),pk(xpub661MyMwAqRbcFVAMsxk7PkfGh66U9K9qWh2dvS5s4kL4JaDHdZdBbb4CbzQxZMC2MAUcKZudSk86RxeaTQctKa6tpSCPEkKGYfMEFDKWJu9/*)})";
        let desc = Descriptor::<DescriptorPublicKey>::from_str(d).unwrap();
        let psbt = "cHNidP8BAKYCAAAAAgEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAD9////AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAP3///8CgBoGAAAAAAAWABRTtvjcap+5t7odMosMnHl97YJClYAaBgAAAAAAIlEgBBlsh6bt3RStSy0egEjFHML8bVhqFYO8knG5OLcA/zcAAAAAAAEBK0BCDwAAAAAAIlEgBBlsh6bt3RStSy0egEjFHML8bVhqFYO8knG5OLcA/zcAAQErQEIPAAAAAAAiUSDFpFC16pT0pXIHKzV7teFiXul3DtlyYj9DdCpF1CHVQAAAAA==";
        let mut psbt = psbt_from_base64(psbt).unwrap();
        psbt.update_input_with_descriptor(0, &desc.at_derivation_index(0).unwrap())
            .unwrap();
    }

    // Compile-time check to ensure the macro stays in sync with Network::ALL
    #[test]
    fn test_all_networks_macro_is_complete() {
        const _: () = assert!(
            Network::ALL.len() == 21,
            "test_all_networks! macro is out of sync with Network::ALL"
        );
    }
}
