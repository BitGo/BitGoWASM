use crate::error::WasmUtxoError;
use crate::wasm::descriptor::WrapDescriptorEnum;
use crate::wasm::try_into_js_value::TryIntoJsValue;
use crate::wasm::WrapDescriptor;
use miniscript::bitcoin::bip32::Fingerprint;
use miniscript::bitcoin::locktime::absolute::LockTime;
use miniscript::bitcoin::secp256k1::{Secp256k1, Signing};
use miniscript::bitcoin::transaction::{Transaction, Version};
use miniscript::bitcoin::{
    bip32, psbt, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, XOnlyPublicKey,
};
use miniscript::bitcoin::{PrivateKey, Psbt, TxIn, TxOut, Txid};
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
    #[wasm_bindgen(js_name = addInput)]
    pub fn add_input(
        &mut self,
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

        self.0.unsigned_tx.input.push(tx_in);
        self.0.inputs.push(psbt_input);

        Ok(self.0.inputs.len() - 1)
    }

    /// Add an output to the PSBT
    ///
    /// # Arguments
    /// * `script` - The output script (scriptPubKey)
    /// * `value` - Value in satoshis
    ///
    /// # Returns
    /// The index of the newly added output
    #[wasm_bindgen(js_name = addOutput)]
    pub fn add_output(&mut self, script: &[u8], value: u64) -> usize {
        let script = ScriptBuf::from_bytes(script.to_vec());

        let tx_out = TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        };

        let psbt_output = psbt::Output::default();

        self.0.unsigned_tx.output.push(tx_out);
        self.0.outputs.push(psbt_output);

        self.0.outputs.len() - 1
    }

    /// Get the unsigned transaction bytes
    ///
    /// # Returns
    /// The serialized unsigned transaction
    #[wasm_bindgen(js_name = getUnsignedTx)]
    pub fn get_unsigned_tx(&self) -> Vec<u8> {
        use miniscript::bitcoin::consensus::Encodable;
        let mut buf = Vec::new();
        self.0
            .unsigned_tx
            .consensus_encode(&mut buf)
            .expect("encoding to vec should not fail");
        buf
    }

    #[wasm_bindgen(js_name = updateInputWithDescriptor)]
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

    #[wasm_bindgen(js_name = updateOutputWithDescriptor)]
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

    #[wasm_bindgen(js_name = signWithXprv)]
    pub fn sign_with_xprv(&mut self, xprv: String) -> Result<JsValue, WasmUtxoError> {
        let key = bip32::Xpriv::from_str(&xprv).map_err(|_| WasmUtxoError::new("Invalid xprv"))?;
        self.0
            .sign(&key, &Secp256k1::new())
            .map_err(|(_, errors)| {
                WasmUtxoError::new(&format!("{} errors: {:?}", errors.len(), errors))
            })
            .and_then(|r| r.try_to_js_value())
    }

    #[wasm_bindgen(js_name = signWithPrv)]
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

    #[wasm_bindgen(js_name = finalize)]
    pub fn finalize_mut(&mut self) -> Result<(), WasmUtxoError> {
        self.0
            .finalize_mut(&Secp256k1::verification_only())
            .map_err(|vec_err| {
                WasmUtxoError::new(&format!("{} errors: {:?}", vec_err.len(), vec_err))
            })
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
