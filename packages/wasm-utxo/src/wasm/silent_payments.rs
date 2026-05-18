//! WASM bindings for BIP-352 Silent Payments.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::error::WasmUtxoError;
use crate::networks::Network;
use crate::silent_payments::{address, labels, scanner, sender, spending};

/// WASM namespace for Silent Payment operations.
#[wasm_bindgen]
pub struct SilentPaymentsNamespace;

// --- Serde types for JsValue deserialization (Convention #9) ---

#[derive(Deserialize)]
struct JsPrivkeyInput {
    key: Vec<u8>,
    #[serde(rename = "isTaproot")]
    is_taproot: bool,
}

#[derive(Deserialize)]
struct JsOutpoint {
    txid: Vec<u8>,
    vout: u32,
}

#[derive(Deserialize)]
struct JsInputData {
    privkeys: Vec<JsPrivkeyInput>,
    outpoints: Vec<JsOutpoint>,
}

#[derive(Deserialize)]
struct JsPubkeyInput {
    pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct JsTaprootOutput {
    pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct JsTxData {
    inputs: Vec<JsPubkeyInput>,
    outpoints: Vec<JsOutpoint>,
    outputs: Vec<JsTaprootOutput>,
}

#[derive(Serialize)]
struct JsDerivedOutput {
    script: Vec<u8>,
    pubkey: Vec<u8>,
    tweak: Vec<u8>,
}

#[derive(Serialize)]
struct JsScanResult {
    #[serde(rename = "outputIndex")]
    output_index: u32,
    tweak: Vec<u8>,
    k: u32,
    label: Option<u32>,
    #[serde(rename = "labelTweak")]
    label_tweak: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct JsAddressComponents {
    #[serde(rename = "scanKey")]
    scan_key: Vec<u8>,
    #[serde(rename = "spendKey")]
    spend_key: Vec<u8>,
}

#[wasm_bindgen]
impl SilentPaymentsNamespace {
    /// Decode a silent payment address (sp1q.../tsp1q...) into its component keys.
    /// Returns { scanKey: Uint8Array(33), spendKey: Uint8Array(33) }
    #[wasm_bindgen]
    pub fn decode_address(addr: &str) -> Result<JsValue, WasmUtxoError> {
        let decoded = address::decode(addr)?;
        let result = JsAddressComponents {
            scan_key: decoded.scan_key.serialize().to_vec(),
            spend_key: decoded.spend_key.serialize().to_vec(),
        };
        serde_wasm_bindgen::to_value(&result)
            .map_err(|e| WasmUtxoError::StringError(format!("serialization error: {}", e)))
    }

    /// Encode a silent payment address from component keys.
    /// scan_key and spend_key are 33-byte compressed public keys.
    /// network is a coin name ("btc", "tbtc", etc.).
    #[wasm_bindgen]
    pub fn encode_address(
        scan_key: &[u8],
        spend_key: &[u8],
        network: &str,
    ) -> Result<String, WasmUtxoError> {
        use miniscript::bitcoin::secp256k1::PublicKey;

        let scan_pk = PublicKey::from_slice(scan_key)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid scan key: {}", e)))?;
        let spend_pk = PublicKey::from_slice(spend_key)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid spend key: {}", e)))?;

        let net = Network::from_coin_name(network)
            .ok_or_else(|| WasmUtxoError::StringError(format!("unknown network: {}", network)))?;

        Ok(address::encode(&scan_pk, &spend_pk, net)?)
    }

    /// Derive output scripts for sending to silent payment recipients.
    ///
    /// input_data: { privkeys: [{ key: Uint8Array(32), isTaproot: boolean }],
    ///               outpoints: [{ txid: Uint8Array(32), vout: number }] }
    /// recipients: string[] (sp1q... addresses)
    ///
    /// Returns: [{ script: Uint8Array, pubkey: Uint8Array(32), tweak: Uint8Array(32) }]
    #[wasm_bindgen]
    pub fn derive_outputs(
        input_data: JsValue,
        recipients: JsValue,
    ) -> Result<JsValue, WasmUtxoError> {
        use miniscript::bitcoin::secp256k1::SecretKey;

        let data: JsInputData = serde_wasm_bindgen::from_value(input_data)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid input_data: {}", e)))?;
        let recipient_addrs: Vec<String> = serde_wasm_bindgen::from_value(recipients)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid recipients: {}", e)))?;

        // Convert inputs
        let sender_inputs: Vec<sender::SenderInput> = data
            .privkeys
            .iter()
            .map(|p| {
                let sk = SecretKey::from_slice(&p.key)
                    .map_err(|e| WasmUtxoError::StringError(format!("invalid privkey: {}", e)))?;
                Ok(sender::SenderInput {
                    private_key: sk,
                    is_taproot: p.is_taproot,
                })
            })
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Convert outpoints
        let outpoints: Vec<sender::SenderOutpoint> = data
            .outpoints
            .iter()
            .map(|op| {
                let mut txid = [0u8; 32];
                if op.txid.len() != 32 {
                    return Err(WasmUtxoError::StringError(format!(
                        "txid must be 32 bytes, got {}",
                        op.txid.len()
                    )));
                }
                txid.copy_from_slice(&op.txid);
                Ok(sender::SenderOutpoint {
                    txid,
                    vout: op.vout,
                })
            })
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Decode recipient addresses
        let decoded_recipients: Vec<address::SilentPaymentAddress> = recipient_addrs
            .iter()
            .map(|addr| address::decode(addr).map_err(WasmUtxoError::from))
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Derive outputs
        let outputs =
            sender::derive_silent_payment_outputs(&sender_inputs, &outpoints, &decoded_recipients)?;

        // Convert to JS output format
        let js_outputs: Vec<JsDerivedOutput> = outputs
            .iter()
            .map(|o| JsDerivedOutput {
                script: o.script_pubkey.to_bytes(),
                pubkey: o.x_only_pubkey.to_vec(),
                tweak: o.tweak.to_vec(),
            })
            .collect();

        serde_wasm_bindgen::to_value(&js_outputs)
            .map_err(|e| WasmUtxoError::StringError(format!("serialization error: {}", e)))
    }

    /// Scan a transaction for silent payment outputs addressed to this receiver.
    ///
    /// scan_key: Uint8Array(32) -- b_scan private key
    /// spend_pubkey: Uint8Array(33) -- B_spend public key
    /// tx_data: { inputs: [{ pubkey: Uint8Array(33) }],
    ///            outpoints: [{ txid: Uint8Array(32), vout: number }],
    ///            outputs: [{ pubkey: Uint8Array(32) }] }
    /// labels: number[] | null -- label indices to check
    ///
    /// Returns: [{ outputIndex: number, tweak: Uint8Array(32), k: number, label: number | null }]
    #[wasm_bindgen]
    pub fn scan_transaction(
        scan_key: &[u8],
        spend_pubkey: &[u8],
        tx_data: JsValue,
        label_indices: JsValue,
    ) -> Result<JsValue, WasmUtxoError> {
        use miniscript::bitcoin::secp256k1::{PublicKey, SecretKey};

        let b_scan = SecretKey::from_slice(scan_key)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid scan key: {}", e)))?;
        let b_spend_pub = PublicKey::from_slice(spend_pubkey)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid spend pubkey: {}", e)))?;

        let data: JsTxData = serde_wasm_bindgen::from_value(tx_data)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid tx_data: {}", e)))?;

        // Convert input pubkeys
        let input_pubkeys: Vec<PublicKey> = data
            .inputs
            .iter()
            .map(|inp| {
                PublicKey::from_slice(&inp.pubkey)
                    .map_err(|e| WasmUtxoError::StringError(format!("invalid input pubkey: {}", e)))
            })
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Convert outpoints
        let outpoints: Vec<sender::SenderOutpoint> = data
            .outpoints
            .iter()
            .map(|op| {
                let mut txid = [0u8; 32];
                if op.txid.len() != 32 {
                    return Err(WasmUtxoError::StringError(format!(
                        "txid must be 32 bytes, got {}",
                        op.txid.len()
                    )));
                }
                txid.copy_from_slice(&op.txid);
                Ok(sender::SenderOutpoint {
                    txid,
                    vout: op.vout,
                })
            })
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Convert taproot outputs
        let taproot_outputs: Vec<scanner::TaprootOutput> = data
            .outputs
            .iter()
            .enumerate()
            .map(|(idx, out)| {
                let mut x_only = [0u8; 32];
                if out.pubkey.len() != 32 {
                    return Err(WasmUtxoError::StringError(format!(
                        "output pubkey must be 32 bytes, got {}",
                        out.pubkey.len()
                    )));
                }
                x_only.copy_from_slice(&out.pubkey);
                Ok(scanner::TaprootOutput {
                    x_only_pubkey: x_only,
                    index: idx as u32,
                })
            })
            .collect::<Result<Vec<_>, WasmUtxoError>>()?;

        // Build label lookup if labels provided
        let label_list: Option<Vec<u32>> = if label_indices.is_null()
            || label_indices.is_undefined()
        {
            None
        } else {
            Some(
                serde_wasm_bindgen::from_value(label_indices)
                    .map_err(|e| WasmUtxoError::StringError(format!("invalid labels: {}", e)))?,
            )
        };

        let label_lookup = label_list
            .as_ref()
            .map(|indices| labels::build_label_lookup(&b_scan, indices));

        // Scan transaction
        let results = scanner::scan_transaction(
            &b_scan,
            &b_spend_pub,
            &input_pubkeys,
            &outpoints,
            &taproot_outputs,
            label_lookup.as_ref(),
        )?;

        // Convert results
        let js_results: Vec<JsScanResult> = results
            .iter()
            .map(|r| JsScanResult {
                output_index: r.output_index,
                tweak: r.tweak.to_vec(),
                k: r.k,
                label: r.label,
                label_tweak: r.label_tweak.map(|lt| lt.to_vec()),
            })
            .collect();

        serde_wasm_bindgen::to_value(&js_results)
            .map_err(|e| WasmUtxoError::StringError(format!("serialization error: {}", e)))
    }

    /// Derive the private key for spending a matched silent payment output.
    ///
    /// spend_key: Uint8Array(32) -- b_spend private key
    /// tweak: Uint8Array(32) -- t_k from scan_transaction
    ///
    /// Returns: Uint8Array(32) -- the derived private key p_k
    #[wasm_bindgen]
    pub fn derive_spend_key(spend_key: &[u8], tweak: &[u8]) -> Result<Vec<u8>, WasmUtxoError> {
        use miniscript::bitcoin::secp256k1::SecretKey;

        let b_spend = SecretKey::from_slice(spend_key)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid spend key: {}", e)))?;

        if tweak.len() != 32 {
            return Err(WasmUtxoError::StringError(format!(
                "tweak must be 32 bytes, got {}",
                tweak.len()
            )));
        }
        let mut tweak_arr = [0u8; 32];
        tweak_arr.copy_from_slice(tweak);

        let derived = spending::derive_spend_key(&b_spend, &tweak_arr)?;
        Ok(derived.secret_bytes().to_vec())
    }

    /// Create a labeled silent payment address.
    ///
    /// scan_key: Uint8Array(32) -- b_scan private key
    /// spend_pubkey: Uint8Array(33) -- B_spend public key
    /// label_index: number -- the label m
    /// network: string -- coin name
    ///
    /// Returns: string -- the labeled sp1q.../tsp1q... address
    #[wasm_bindgen]
    pub fn create_labeled_address(
        scan_key: &[u8],
        spend_pubkey: &[u8],
        label_index: u32,
        network: &str,
    ) -> Result<String, WasmUtxoError> {
        use miniscript::bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let b_scan = SecretKey::from_slice(scan_key)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid scan key: {}", e)))?;
        let b_spend_pub = PublicKey::from_slice(spend_pubkey)
            .map_err(|e| WasmUtxoError::StringError(format!("invalid spend pubkey: {}", e)))?;
        let scan_pub = PublicKey::from_secret_key(&secp, &b_scan);

        let net = Network::from_coin_name(network)
            .ok_or_else(|| WasmUtxoError::StringError(format!("unknown network: {}", network)))?;

        let labeled_addr =
            labels::create_labeled_address(&scan_pub, &b_spend_pub, &b_scan, label_index, net)?;
        Ok(labeled_addr.to_string())
    }
}
