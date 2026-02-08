//! WASM bindings for versioned transaction building.
//!
//! Exposes `build_from_versioned_data` for building versioned transactions
//! from pre-compiled MessageV0 data (WalletConnect/Jupiter support).

use crate::versioned_builder::{
    build_from_raw_versioned_data, AddressLookupTable, RawMessageHeader,
    RawVersionedTransactionData, VersionedInstruction,
};
use crate::wasm::WasmVersionedTransaction;
use wasm_bindgen::prelude::*;

/// WASM namespace for versioned transaction building.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a versioned transaction from raw MessageV0 data.
    ///
    /// This is used for WalletConnect/Jupiter transactions where we receive
    /// pre-compiled versioned transaction data and just need to serialize it.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw versioned transaction data (from JavaScript)
    ///
    /// # Returns
    ///
    /// A WasmVersionedTransaction instance
    #[wasm_bindgen(js_name = "build_from_versioned_data")]
    pub fn build_from_versioned_data(data: JsValue) -> Result<WasmVersionedTransaction, JsError> {
        let parsed: RawVersionedTransactionDataJs =
            serde_wasm_bindgen::from_value(data).map_err(|e| {
                JsError::new(&format!(
                    "Failed to parse versioned transaction data: {}",
                    e
                ))
            })?;

        // Convert JS types to Rust types
        let rust_data = RawVersionedTransactionData {
            static_account_keys: parsed.static_account_keys,
            address_lookup_tables: parsed
                .address_lookup_tables
                .into_iter()
                .map(|alt| AddressLookupTable {
                    account_key: alt.account_key,
                    writable_indexes: alt.writable_indexes,
                    readonly_indexes: alt.readonly_indexes,
                })
                .collect(),
            versioned_instructions: parsed
                .versioned_instructions
                .into_iter()
                .map(|ix| VersionedInstruction {
                    program_id_index: ix.program_id_index,
                    account_key_indexes: ix.account_key_indexes,
                    data: ix.data,
                })
                .collect(),
            message_header: RawMessageHeader {
                num_required_signatures: parsed.message_header.num_required_signatures,
                num_readonly_signed_accounts: parsed.message_header.num_readonly_signed_accounts,
                num_readonly_unsigned_accounts: parsed
                    .message_header
                    .num_readonly_unsigned_accounts,
            },
            recent_blockhash: parsed.recent_blockhash,
        };

        let bytes = build_from_raw_versioned_data(&rust_data)
            .map_err(|e| JsError::new(&format!("{}", e)))?;

        WasmVersionedTransaction::from_bytes(&bytes)
            .map_err(|e| JsError::new(&format!("Failed to deserialize transaction: {}", e)))
    }
}

// =============================================================================
// JS-friendly types for serde deserialization
// =============================================================================

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawVersionedTransactionDataJs {
    #[serde(rename = "staticAccountKeys")]
    static_account_keys: Vec<String>,
    #[serde(rename = "addressLookupTables")]
    address_lookup_tables: Vec<AddressLookupTableJs>,
    #[serde(rename = "versionedInstructions")]
    versioned_instructions: Vec<VersionedInstructionJs>,
    #[serde(rename = "messageHeader")]
    message_header: MessageHeaderJs,
    #[serde(rename = "recentBlockhash")]
    recent_blockhash: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddressLookupTableJs {
    #[serde(rename = "accountKey")]
    account_key: String,
    #[serde(rename = "writableIndexes")]
    writable_indexes: Vec<u8>,
    #[serde(rename = "readonlyIndexes")]
    readonly_indexes: Vec<u8>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionedInstructionJs {
    #[serde(rename = "programIdIndex")]
    program_id_index: u8,
    #[serde(rename = "accountKeyIndexes")]
    account_key_indexes: Vec<u8>,
    data: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageHeaderJs {
    #[serde(rename = "numRequiredSignatures")]
    num_required_signatures: u8,
    #[serde(rename = "numReadonlySignedAccounts")]
    num_readonly_signed_accounts: u8,
    #[serde(rename = "numReadonlyUnsignedAccounts")]
    num_readonly_unsigned_accounts: u8,
}
