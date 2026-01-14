//! WASM bindings for Solana transaction deserialization.
//!
//! Wraps `solana_transaction::Transaction` for JavaScript.

use crate::error::WasmSolanaError;
use crate::transaction::{Transaction, TransactionExt};
use wasm_bindgen::prelude::*;

/// WASM wrapper for Solana transactions.
///
/// This type wraps a deserialized Solana transaction and provides
/// accessors for its components (instructions, signatures, etc.).
#[wasm_bindgen]
pub struct WasmTransaction {
    inner: Transaction,
}

#[wasm_bindgen]
impl WasmTransaction {
    /// Deserialize a transaction from a base64-encoded string.
    ///
    /// This is the format used by `@solana/web3.js` `Transaction.serialize()`.
    #[wasm_bindgen]
    pub fn from_base64(base64_str: &str) -> Result<WasmTransaction, WasmSolanaError> {
        Transaction::from_base64(base64_str).map(|inner| WasmTransaction { inner })
    }

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

    /// Serialize the transaction to base64.
    #[wasm_bindgen]
    pub fn to_base64(&self) -> Result<String, WasmSolanaError> {
        self.inner.to_base64()
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

    /// Get a signature at the given index as a base58 string.
    ///
    /// Returns `null` if the index is out of bounds.
    #[wasm_bindgen]
    pub fn signature_at(&self, index: usize) -> Option<String> {
        self.inner.signatures.get(index).map(|s| s.to_string())
    }

    /// Get a signature at the given index as bytes.
    ///
    /// Returns `null` if the index is out of bounds.
    #[wasm_bindgen]
    pub fn signature_bytes_at(&self, index: usize) -> Option<js_sys::Uint8Array> {
        self.inner.signatures.get(index).map(|s| {
            let bytes: &[u8] = s.as_ref();
            js_sys::Uint8Array::from(bytes)
        })
    }

    /// Get an instruction at the given index.
    ///
    /// Returns a JS object with:
    /// - `programId`: base58 string of the program account
    /// - `accounts`: array of { pubkey, isSigner, isWritable }
    /// - `data`: Uint8Array of instruction data
    ///
    /// Returns `null` if the index is out of bounds.
    #[wasm_bindgen]
    pub fn instruction_at(&self, index: usize) -> Option<js_sys::Object> {
        let msg = &self.inner.message;
        let instruction = msg.instructions.get(index)?;

        let obj = js_sys::Object::new();

        // Get the program ID
        let program_id = msg
            .account_keys
            .get(instruction.program_id_index as usize)?;
        js_sys::Reflect::set(&obj, &"programId".into(), &program_id.to_string().into()).ok()?;

        // Build accounts array with signer/writable flags
        let accounts = js_sys::Array::new();
        for &account_index in &instruction.accounts {
            let pubkey = msg.account_keys.get(account_index as usize)?;
            let account_obj = js_sys::Object::new();

            js_sys::Reflect::set(&account_obj, &"pubkey".into(), &pubkey.to_string().into())
                .ok()?;

            // Determine if signer and writable based on account position
            let (is_signer, is_writable) =
                self.account_flags(account_index as usize, msg.account_keys.len());
            js_sys::Reflect::set(&account_obj, &"isSigner".into(), &is_signer.into()).ok()?;
            js_sys::Reflect::set(&account_obj, &"isWritable".into(), &is_writable.into()).ok()?;

            accounts.push(&account_obj);
        }
        js_sys::Reflect::set(&obj, &"accounts".into(), &accounts).ok()?;

        // Set instruction data
        let data = js_sys::Uint8Array::from(&instruction.data[..]);
        js_sys::Reflect::set(&obj, &"data".into(), &data).ok()?;

        Some(obj)
    }

    /// Get all instructions as an array.
    ///
    /// Each instruction is a JS object with programId, accounts, and data.
    #[wasm_bindgen]
    pub fn instructions(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for i in 0..self.inner.message.instructions.len() {
            if let Some(instr) = self.instruction_at(i) {
                arr.push(&instr);
            }
        }
        arr
    }
}

impl WasmTransaction {
    /// Determine if an account at the given index is a signer and/or writable.
    ///
    /// Account order in message.account_keys:
    /// 1. Writable signers: [0, num_required_signatures - num_readonly_signed_accounts)
    /// 2. Read-only signers: [num_required_signatures - num_readonly_signed_accounts, num_required_signatures)
    /// 3. Writable non-signers: [num_required_signatures, total - num_readonly_unsigned_accounts)
    /// 4. Read-only non-signers: [total - num_readonly_unsigned_accounts, total)
    fn account_flags(&self, index: usize, total_accounts: usize) -> (bool, bool) {
        let header = &self.inner.message.header;
        let num_required_signatures = header.num_required_signatures as usize;
        let num_readonly_signed = header.num_readonly_signed_accounts as usize;
        let num_readonly_unsigned = header.num_readonly_unsigned_accounts as usize;

        let is_signer = index < num_required_signatures;

        let is_writable = if index < num_required_signatures {
            // Signer: writable if in the first part (not in readonly signed section)
            index < num_required_signatures - num_readonly_signed
        } else {
            // Non-signer: writable if not in readonly unsigned section
            index < total_accounts - num_readonly_unsigned
        };

        (is_signer, is_writable)
    }

    /// Get the inner Transaction for internal Rust use.
    pub fn inner(&self) -> &Transaction {
        &self.inner
    }
}
