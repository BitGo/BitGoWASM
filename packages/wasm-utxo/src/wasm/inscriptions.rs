//! WASM bindings for inscription functionality

use crate::error::WasmUtxoError;
use crate::inscriptions::{
    create_inscription_reveal_data as create_reveal_data_impl,
    sign_reveal_transaction as sign_reveal_impl, TapLeafScript,
};
use miniscript::bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use wasm_bindgen::prelude::*;

use super::transaction::WasmTransaction;
use super::try_from_js_value::TryFromJsValue;
use super::try_into_js_value::TryIntoJsValue;

/// Namespace for inscription-related functions
#[wasm_bindgen]
pub struct InscriptionsNamespace;

#[wasm_bindgen]
impl InscriptionsNamespace {
    /// Create inscription reveal data including the commit output script and tap leaf script
    ///
    /// # Arguments
    /// * `x_only_pubkey` - The x-only public key (32 bytes)
    /// * `content_type` - MIME type of the inscription (e.g., "text/plain", "image/png"),
    ///   limited to 520 UTF-8 bytes
    /// * `inscription_data` - The inscription data bytes
    ///
    /// # Returns
    /// An object containing:
    /// - `output_script`: The commit output script (P2TR, network-agnostic)
    /// - `reveal_transaction_vsize`: Estimated vsize of the reveal transaction
    /// - `tap_leaf_script`: Object with `leaf_version`, `script`, and `control_block`
    pub fn create_inscription_reveal_data(
        x_only_pubkey: &[u8],
        content_type: &str,
        inscription_data: &[u8],
    ) -> Result<JsValue, WasmUtxoError> {
        // Parse the x-only public key
        if x_only_pubkey.len() != 32 {
            return Err(WasmUtxoError::new(&format!(
                "x_only_pubkey must be 32 bytes, got {}",
                x_only_pubkey.len()
            )));
        }
        let pubkey = XOnlyPublicKey::from_slice(x_only_pubkey)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid x-only public key: {}", e)))?;

        // Create the reveal data
        let reveal_data = create_reveal_data_impl(&pubkey, content_type, inscription_data)?;

        // Convert to JS object using TryIntoJsValue trait
        reveal_data.try_to_js_value()
    }

    /// Sign a reveal transaction
    ///
    /// # Arguments
    /// * `private_key` - The private key (32 bytes)
    /// * `tap_leaf_script` - The tap leaf script object from `create_inscription_reveal_data`
    /// * `commit_tx` - The commit transaction
    /// * `commit_output_script` - The commit output script (P2TR)
    /// * `recipient_output_script` - Where to send the inscription (output script)
    /// * `output_value_sats` - Value in satoshis for the inscription output
    ///
    /// # Returns
    /// The signed PSBT as bytes
    pub fn sign_reveal_transaction(
        private_key: &[u8],
        tap_leaf_script: JsValue,
        commit_tx: &WasmTransaction,
        commit_output_script: &[u8],
        recipient_output_script: &[u8],
        output_value_sats: u64,
    ) -> Result<Vec<u8>, WasmUtxoError> {
        // Parse the private key
        if private_key.len() != 32 {
            return Err(WasmUtxoError::new(&format!(
                "private_key must be 32 bytes, got {}",
                private_key.len()
            )));
        }
        let secret_key = SecretKey::from_slice(private_key)
            .map_err(|e| WasmUtxoError::new(&format!("Invalid private key: {}", e)))?;

        // Parse the tap leaf script from JS using TryFromJsValue trait
        let tap_leaf = TapLeafScript::try_from_js_value(&tap_leaf_script)?;

        // Sign the reveal transaction and return bytes
        sign_reveal_impl(
            &secret_key,
            &tap_leaf,
            &commit_tx.tx,
            commit_output_script,
            recipient_output_script,
            output_value_sats,
        )
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::error::WasmErrorCode;
    use miniscript::bitcoin::secp256k1::Secp256k1;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn create_inscription_reveal_data_enforces_content_type_byte_limit() {
        let secret_key = SecretKey::from_slice(&[1u8; 32]).expect("valid test key");
        let (x_only_pubkey, _) = secret_key.x_only_public_key(&Secp256k1::new());
        let pubkey_bytes = x_only_pubkey.serialize();

        let ascii_520 = "a".repeat(520);
        assert!(InscriptionsNamespace::create_inscription_reveal_data(
            &pubkey_bytes,
            &ascii_520,
            &[],
        )
        .is_ok());

        let unicode_520 = "é".repeat(260);
        assert_eq!(unicode_520.as_bytes().len(), 520);
        assert!(InscriptionsNamespace::create_inscription_reveal_data(
            &pubkey_bytes,
            &unicode_520,
            &[],
        )
        .is_ok());

        for oversized in ["a".repeat(521), "é".repeat(261)] {
            let error = match InscriptionsNamespace::create_inscription_reveal_data(
                &pubkey_bytes,
                &oversized,
                &[],
            ) {
                Ok(_) => panic!("oversized content type must be rejected"),
                Err(error) => error,
            };
            assert_eq!(
                error.to_string(),
                "inscription content type exceeds 520 UTF-8 bytes"
            );
            assert_eq!(error.code(), "WasmUtxoError.StringError");
        }
    }
}
