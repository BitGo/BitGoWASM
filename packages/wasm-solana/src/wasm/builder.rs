//! WASM binding for transaction building.
//!
//! Exposes transaction building functions:
//! - `buildTransaction` - Creates a Transaction from a high-level intent structure
//! - `buildFromVersionedData` - Creates a VersionedTransaction from raw MessageV0 data

use crate::builder;
use crate::wasm::transaction::{WasmTransaction, WasmVersionedTransaction};
use wasm_bindgen::prelude::*;

/// Namespace for transaction building operations.
#[wasm_bindgen]
pub struct BuilderNamespace;

#[wasm_bindgen]
impl BuilderNamespace {
    /// Build a Solana transaction from an intent structure.
    ///
    /// Takes a TransactionIntent JSON object and returns serialized transaction bytes.
    ///
    /// # Intent Structure
    ///
    /// ```json
    /// {
    ///   "feePayer": "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB",
    ///   "nonce": {
    ///     "type": "blockhash",
    ///     "value": "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4"
    ///   },
    ///   "instructions": [
    ///     { "type": "transfer", "from": "...", "to": "...", "lamports": "1000000" },
    ///     { "type": "memo", "message": "BitGo tx" }
    ///   ]
    /// }
    /// ```
    ///
    /// # Instruction Types
    ///
    /// - `transfer`: SOL transfer (from, to, lamports)
    /// - `createAccount`: Create new account (from, newAccount, lamports, space, owner)
    /// - `nonceAdvance`: Advance durable nonce (nonce, authority)
    /// - `nonceInitialize`: Initialize nonce account (nonce, authority)
    /// - `allocate`: Allocate space (account, space)
    /// - `assign`: Assign to program (account, owner)
    /// - `memo`: Add memo (message)
    /// - `computeBudget`: Set compute units (unitLimit, unitPrice)
    ///
    /// # Returns
    ///
    /// A `Transaction` object that can be inspected, signed, and serialized.
    /// The transaction will have empty signature placeholders that can be
    /// filled in later by signing via `addSignature()`.
    ///
    /// @param intent - The transaction intent as a JSON object
    /// @returns Transaction object
    #[wasm_bindgen]
    pub fn build_transaction(intent: JsValue) -> Result<WasmTransaction, JsValue> {
        // Deserialize the intent from JavaScript
        let intent: builder::TransactionIntent =
            serde_wasm_bindgen::from_value(intent).map_err(|e| {
                JsValue::from_str(&format!("Failed to parse transaction intent: {}", e))
            })?;

        // Build the transaction bytes
        let bytes =
            builder::build_transaction(intent).map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Wrap in WasmTransaction for rich API access
        WasmTransaction::from_bytes(&bytes).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Build a versioned transaction directly from raw MessageV0 data.
    ///
    /// This function is used for the `fromVersionedTransactionData()` path where we already
    /// have pre-compiled versioned data (indexes + ALT refs). No instruction compilation
    /// is needed - we just serialize the raw structure to bytes.
    ///
    /// # Data Structure
    ///
    /// ```json
    /// {
    ///   "staticAccountKeys": ["pubkey1", "pubkey2", ...],
    ///   "addressLookupTables": [
    ///     { "accountKey": "altPubkey", "writableIndexes": [0, 1], "readonlyIndexes": [2] }
    ///   ],
    ///   "versionedInstructions": [
    ///     { "programIdIndex": 0, "accountKeyIndexes": [1, 2], "data": "base58EncodedData" }
    ///   ],
    ///   "messageHeader": {
    ///     "numRequiredSignatures": 1,
    ///     "numReadonlySignedAccounts": 0,
    ///     "numReadonlyUnsignedAccounts": 3
    ///   },
    ///   "recentBlockhash": "blockhash"
    /// }
    /// ```
    ///
    /// @param data - Raw versioned transaction data as a JSON object
    /// @returns VersionedTransaction object
    #[wasm_bindgen]
    pub fn build_from_versioned_data(data: JsValue) -> Result<WasmVersionedTransaction, JsValue> {
        // Deserialize the raw versioned data from JavaScript
        let data: builder::RawVersionedTransactionData = serde_wasm_bindgen::from_value(data)
            .map_err(|e| {
                JsValue::from_str(&format!(
                    "Failed to parse versioned transaction data: {}",
                    e
                ))
            })?;

        // Build the versioned transaction bytes
        let bytes = builder::build_from_raw_versioned_data(&data)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Wrap in WasmVersionedTransaction for rich API access
        WasmVersionedTransaction::from_bytes(&bytes).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
