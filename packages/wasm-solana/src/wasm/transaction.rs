//! WASM bindings for Solana transaction deserialization.
//!
//! Wraps `solana_transaction::Transaction` for JavaScript.
//!
//! Note: For semantic transaction parsing with decoded instructions,
//! use `ParserNamespace.parse_transaction()` instead.

use crate::error::WasmSolanaError;
use crate::transaction::{Transaction, TransactionExt};
use wasm_bindgen::prelude::*;

/// WASM wrapper for Solana transactions.
///
/// This type provides low-level access to transaction structure.
/// For high-level semantic parsing, use `ParserNamespace.parse_transaction()`.
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from raw bytes.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmTransaction, WasmSolanaError> {
        Transaction::from_bytes(bytes).map(|inner| WasmTransaction { inner })
    }

    /// Get the fee payer address as a base58 string.
    ///
    /// Returns `null` if there are no account keys (shouldn't happen for valid transactions).
    #[wasm_bindgen(getter)]
    pub fn fee_payer(&self) -> Option<String> {
        self.inner.fee_payer_string()
    }

    /// Get the recent blockhash as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn recent_blockhash(&self) -> String {
        self.inner.blockhash_string()
    }

    /// Get the number of instructions in the transaction.
    #[wasm_bindgen(getter)]
    pub fn num_instructions(&self) -> usize {
        self.inner.num_instructions()
    }

    /// Get the number of signatures in the transaction.
    #[wasm_bindgen(getter)]
    pub fn num_signatures(&self) -> usize {
        self.inner.num_signatures()
    }

    /// Get the signable message payload (what gets signed).
    ///
    /// This is the serialized message that signers sign.
    #[wasm_bindgen]
    pub fn signable_payload(&self) -> js_sys::Uint8Array {
        let bytes = self.inner.signable_payload();
        js_sys::Uint8Array::from(&bytes[..])
    }

    /// Serialize the transaction to bytes.
    #[wasm_bindgen]
    pub fn to_bytes(&self) -> Result<js_sys::Uint8Array, WasmSolanaError> {
        let bytes = self.inner.to_bytes()?;
        Ok(js_sys::Uint8Array::from(&bytes[..]))
    }

    /// Get all account keys as an array of base58 strings.
    #[wasm_bindgen]
    pub fn account_keys(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for key in &self.inner.message.account_keys {
            arr.push(&JsValue::from_str(&key.to_string()));
        }
        arr
    }

    /// Get all signatures as an array of byte arrays.
    ///
    /// Each signature is returned as a Uint8Array.
    #[wasm_bindgen]
    pub fn signatures(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for sig in &self.inner.signatures {
            let bytes: &[u8] = sig.as_ref();
            arr.push(&js_sys::Uint8Array::from(bytes));
        }
        arr
    }

    /// Get all instructions as an array.
    ///
    /// Each instruction is a JS object with programId, accounts, and data.
    #[wasm_bindgen]
    pub fn instructions(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        let msg = &self.inner.message;

        for instruction in &msg.instructions {
            let obj = js_sys::Object::new();

            // Get the program ID
            if let Some(program_id) = msg.account_keys.get(instruction.program_id_index as usize) {
                let _ =
                    js_sys::Reflect::set(&obj, &"programId".into(), &program_id.to_string().into());
            }

            // Build accounts array with signer/writable flags
            let accounts = js_sys::Array::new();
            for &account_index in &instruction.accounts {
                if let Some(pubkey) = msg.account_keys.get(account_index as usize) {
                    let account_obj = js_sys::Object::new();

                    let _ = js_sys::Reflect::set(
                        &account_obj,
                        &"pubkey".into(),
                        &pubkey.to_string().into(),
                    );

                    // Use official Solana methods for signer/writable flags
                    let is_signer = msg.is_signer(account_index as usize);
                    let is_writable = msg.is_maybe_writable(account_index as usize, None);
                    let _ =
                        js_sys::Reflect::set(&account_obj, &"isSigner".into(), &is_signer.into());
                    let _ = js_sys::Reflect::set(
                        &account_obj,
                        &"isWritable".into(),
                        &is_writable.into(),
                    );

                    accounts.push(&account_obj);
                }
            }
            let _ = js_sys::Reflect::set(&obj, &"accounts".into(), &accounts);

            // Set instruction data
            let data = js_sys::Uint8Array::from(&instruction.data[..]);
            let _ = js_sys::Reflect::set(&obj, &"data".into(), &data);

            arr.push(&obj);
        }
        arr
    }
}

impl WasmTransaction {
    /// Get the inner Transaction for internal Rust use.
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }
}
