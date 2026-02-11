//! WASM bindings for Transaction
//!
//! Thin wrapper around core Transaction with #[wasm_bindgen]

use crate::transaction::Transaction;
use crate::types::{Material, ParseContext, Validity};
use crate::WasmDotError;
use wasm_bindgen::prelude::*;

/// WASM-exposed transaction wrapper
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Create a transaction from raw bytes
    ///
    /// # Arguments
    /// * `bytes` - Raw extrinsic bytes (hex string or Uint8Array)
    /// * `context` - Optional parsing context with chain material
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8], context: Option<ParseContextJs>) -> Result<WasmTransaction, JsValue> {
        let ctx = context.map(|c| c.into_inner());
        let inner = Transaction::from_bytes(bytes, ctx)?;
        Ok(WasmTransaction { inner })
    }

    /// Create from hex string
    #[wasm_bindgen(js_name = fromHex)]
    pub fn from_hex(
        hex: &str,
        context: Option<ParseContextJs>,
    ) -> Result<WasmTransaction, JsValue> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)
            .map_err(|e| WasmDotError::InvalidInput(format!("Invalid hex: {}", e)))?;
        let ctx = context.map(|c| c.into_inner());
        let inner = Transaction::from_bytes(&bytes, ctx)?;
        Ok(WasmTransaction { inner })
    }

    /// Get the transaction ID (hash) if signed
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> Option<String> {
        self.inner.id()
    }

    /// Get sender address (SS58 encoded)
    ///
    /// # Arguments
    /// * `prefix` - SS58 address prefix (0 for Polkadot, 2 for Kusama, 42 for generic)
    #[wasm_bindgen]
    pub fn sender(&self, prefix: Option<u16>) -> Option<String> {
        self.inner.sender(prefix.unwrap_or(0))
    }

    /// Get account nonce
    #[wasm_bindgen(getter)]
    pub fn nonce(&self) -> u32 {
        self.inner.nonce()
    }

    /// Get tip amount as BigInt
    #[wasm_bindgen(getter)]
    pub fn tip(&self) -> js_sys::BigInt {
        js_sys::BigInt::from(self.inner.tip())
    }

    /// Check if transaction is signed
    #[wasm_bindgen(getter, js_name = isSigned)]
    pub fn is_signed(&self) -> bool {
        self.inner.is_signed()
    }

    /// Get the call data
    #[wasm_bindgen(js_name = callData)]
    pub fn call_data(&self) -> Vec<u8> {
        self.inner.call_data().to_vec()
    }

    /// Get call data as hex string
    #[wasm_bindgen(js_name = callDataHex)]
    pub fn call_data_hex(&self) -> String {
        format!("0x{}", hex::encode(self.inner.call_data()))
    }

    /// Get the signable payload
    ///
    /// Returns the bytes that should be signed with Ed25519
    #[wasm_bindgen(js_name = signablePayload)]
    pub fn signable_payload(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.signable_payload().map_err(|e| e.into())
    }

    /// Get signable payload as hex
    #[wasm_bindgen(js_name = signablePayloadHex)]
    pub fn signable_payload_hex(&self) -> Result<String, JsValue> {
        let payload = self.inner.signable_payload()?;
        Ok(format!("0x{}", hex::encode(payload)))
    }

    /// Set the signing context (material, validity, reference block)
    ///
    /// Required before calling signablePayload if transaction was created without context
    #[wasm_bindgen(js_name = setContext)]
    pub fn set_context(
        &mut self,
        material: MaterialJs,
        validity: ValidityJs,
        reference_block: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .set_context(
                material.into_inner(),
                validity.into_inner(),
                reference_block,
            )
            .map_err(|e| e.into())
    }

    /// Set account nonce
    #[wasm_bindgen(js_name = setNonce)]
    pub fn set_nonce(&mut self, nonce: u32) {
        self.inner.set_nonce(nonce);
    }

    /// Set tip amount
    #[wasm_bindgen(js_name = setTip)]
    pub fn set_tip(&mut self, tip: js_sys::BigInt) -> Result<(), JsValue> {
        let tip_str = tip
            .to_string(10)
            .map_err(|_| JsValue::from_str("Invalid tip value"))?;
        let tip_str = String::from(tip_str);
        let tip_u128: u128 = tip_str.parse().map_err(|_| {
            JsValue::from_str("Tip value must be a non-negative integer that fits in u128")
        })?;
        self.inner.set_tip(tip_u128);
        Ok(())
    }

    /// Add a signature to the transaction
    ///
    /// # Arguments
    /// * `signature` - 64-byte Ed25519 signature
    /// * `pubkey` - 32-byte public key
    #[wasm_bindgen(js_name = addSignature)]
    pub fn add_signature(&mut self, signature: &[u8], pubkey: &[u8]) -> Result<(), JsValue> {
        self.inner
            .add_signature(pubkey, signature)
            .map_err(|e| e.into())
    }

    /// Serialize to bytes
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Result<Vec<u8>, JsValue> {
        self.inner.to_bytes().map_err(|e| e.into())
    }

    /// Serialize to hex string
    #[wasm_bindgen(js_name = toHex)]
    pub fn to_hex(&self) -> Result<String, JsValue> {
        let bytes = self.inner.to_bytes()?;
        Ok(format!("0x{}", hex::encode(bytes)))
    }

    /// Get era information as JS object
    #[wasm_bindgen(getter)]
    pub fn era(&self) -> JsValue {
        let era = self.inner.era();
        let obj = js_sys::Object::new();
        match era {
            crate::types::Era::Immortal => {
                let _ = js_sys::Reflect::set(&obj, &"type".into(), &"immortal".into());
            }
            crate::types::Era::Mortal { period, phase } => {
                let _ = js_sys::Reflect::set(&obj, &"type".into(), &"mortal".into());
                let _ = js_sys::Reflect::set(&obj, &"period".into(), &JsValue::from(*period));
                let _ = js_sys::Reflect::set(&obj, &"phase".into(), &JsValue::from(*phase));
            }
        }
        obj.into()
    }
}

/// JavaScript-friendly wrapper for ParseContext
#[wasm_bindgen]
pub struct ParseContextJs {
    inner: ParseContext,
}

#[wasm_bindgen]
impl ParseContextJs {
    #[wasm_bindgen(constructor)]
    pub fn new(material: MaterialJs, sender: Option<String>) -> ParseContextJs {
        ParseContextJs {
            inner: ParseContext {
                material: material.into_inner(),
                sender,
            },
        }
    }
}

impl ParseContextJs {
    pub fn into_inner(self) -> ParseContext {
        self.inner
    }
}

/// JavaScript-friendly wrapper for Material
#[wasm_bindgen]
pub struct MaterialJs {
    inner: Material,
}

#[wasm_bindgen]
impl MaterialJs {
    #[wasm_bindgen(constructor)]
    pub fn new(
        genesis_hash: &str,
        chain_name: &str,
        spec_name: &str,
        spec_version: u32,
        tx_version: u32,
        metadata: &str,
    ) -> MaterialJs {
        MaterialJs {
            inner: Material {
                genesis_hash: genesis_hash.to_string(),
                chain_name: chain_name.to_string(),
                spec_name: spec_name.to_string(),
                spec_version,
                tx_version,
                metadata: metadata.to_string(),
            },
        }
    }
}

impl MaterialJs {
    pub fn into_inner(self) -> Material {
        self.inner
    }
}

/// JavaScript-friendly wrapper for Validity
#[wasm_bindgen]
pub struct ValidityJs {
    inner: Validity,
}

#[wasm_bindgen]
impl ValidityJs {
    #[wasm_bindgen(constructor)]
    pub fn new(first_valid: u32, max_duration: u32) -> ValidityJs {
        ValidityJs {
            inner: Validity {
                first_valid,
                max_duration,
            },
        }
    }
}

impl ValidityJs {
    pub fn into_inner(self) -> Validity {
        self.inner
    }
}

// Non-WASM methods for internal use
impl WasmTransaction {
    /// Create from core Transaction (for builder)
    pub fn from_inner(inner: Transaction) -> Self {
        WasmTransaction { inner }
    }
}
