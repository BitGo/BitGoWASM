//! WASM binding for transaction building.
//!
//! Exposes a `buildTransaction` function that creates transactions from
//! a high-level intent structure.

use crate::builder;
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
    /// Serialized unsigned transaction bytes (Uint8Array).
    /// The transaction will have empty signature placeholders that can be
    /// filled in later by signing.
    ///
    /// @param intent - The transaction intent as a JSON object
    /// @returns Serialized transaction bytes
    #[wasm_bindgen]
    pub fn build_transaction(intent: JsValue) -> Result<Vec<u8>, JsValue> {
        // Deserialize the intent from JavaScript
        let intent: builder::TransactionIntent =
            serde_wasm_bindgen::from_value(intent).map_err(|e| {
                JsValue::from_str(&format!("Failed to parse transaction intent: {}", e))
            })?;

        // Build the transaction
        builder::build_transaction(intent).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}
