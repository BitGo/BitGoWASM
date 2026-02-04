//! WASM bindings for Solana transaction deserialization.
//!
//! Wraps `solana_transaction::Transaction` and `VersionedTransaction` for JavaScript.
//!
//! Note: For semantic transaction parsing with decoded instructions,
//! use `ParserNamespace.parse_transaction()` instead.

use crate::error::WasmSolanaError;
use crate::transaction::{Transaction, TransactionExt};
use crate::versioned::{detect_transaction_version, TxVersion, VersionedTransactionExt};
use solana_message::VersionedMessage;
use solana_transaction::versioned::VersionedTransaction;
use wasm_bindgen::prelude::*;

/// WASM wrapper for Solana transactions.
///
/// This type provides low-level access to transaction structure and
/// signature manipulation. For high-level semantic parsing, use
/// `ParserNamespace.parse_transaction()`.
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

    /// Add a signature for a given public key.
    ///
    /// The pubkey must be one of the required signers in the transaction.
    /// The signature must be exactly 64 bytes (Ed25519 signature).
    ///
    /// @param pubkey - The public key as a base58 string
    /// @param signature - The 64-byte signature
    #[wasm_bindgen]
    pub fn add_signature(&mut self, pubkey: &str, signature: &[u8]) -> Result<(), WasmSolanaError> {
        self.inner.add_signature(pubkey, signature)
    }

    /// Check if a public key is a required signer for this transaction.
    ///
    /// @param pubkey - The public key as a base58 string
    /// @returns The signer index if the pubkey is a signer, null otherwise
    #[wasm_bindgen]
    pub fn signer_index(&self, pubkey: &str) -> Option<usize> {
        self.inner.signer_index(pubkey)
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

    /// Create a WasmTransaction from an existing Transaction.
    /// Used internally by builders to avoid serialize/deserialize round-trip.
    pub(crate) fn from_inner(inner: Transaction) -> Self {
        WasmTransaction { inner }
    }
}

// ============================================================================
// Versioned Transaction Support
// ============================================================================

/// Detect if transaction bytes represent a versioned transaction.
///
/// @param bytes - Raw transaction bytes
/// @returns true if versioned (MessageV0), false if legacy
#[wasm_bindgen]
pub fn is_versioned_transaction(bytes: &[u8]) -> bool {
    detect_transaction_version(bytes) == TxVersion::V0
}

/// WASM wrapper for Solana versioned transactions.
///
/// Handles both legacy and versioned (MessageV0) transactions with
/// Address Lookup Tables (ALTs).
#[wasm_bindgen]
pub struct WasmVersionedTransaction {
    inner: VersionedTransaction,
}

#[wasm_bindgen]
impl WasmVersionedTransaction {
    /// Deserialize a transaction from raw bytes.
    ///
    /// Automatically handles both legacy and versioned formats.
    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmVersionedTransaction, WasmSolanaError> {
        VersionedTransaction::from_bytes(bytes).map(|inner| WasmVersionedTransaction { inner })
    }

    /// Check if this is a versioned transaction (MessageV0).
    ///
    /// @returns true for MessageV0, false for legacy
    #[wasm_bindgen(getter)]
    pub fn is_versioned(&self) -> bool {
        self.inner.is_versioned()
    }

    /// Get the fee payer address as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn fee_payer(&self) -> Option<String> {
        self.inner.fee_payer_string()
    }

    /// Get the recent blockhash as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn recent_blockhash(&self) -> String {
        self.inner.blockhash_string()
    }

    /// Get the number of instructions.
    #[wasm_bindgen(getter)]
    pub fn num_instructions(&self) -> usize {
        self.inner.num_instructions()
    }

    /// Get the number of signatures.
    #[wasm_bindgen(getter)]
    pub fn num_signatures(&self) -> usize {
        self.inner.num_signatures()
    }

    /// Get the signable message payload.
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

    /// Get static account keys (accounts stored directly in the message).
    ///
    /// For versioned transactions, additional accounts may be referenced
    /// via Address Lookup Tables.
    #[wasm_bindgen]
    pub fn static_account_keys(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for key in self.inner.static_account_keys() {
            arr.push(&JsValue::from_str(&key));
        }
        arr
    }

    /// Get Address Lookup Table data.
    ///
    /// Returns an array of ALT objects, each containing:
    /// - accountKey: The lookup table account address
    /// - writableIndexes: Indices of writable accounts in the table
    /// - readonlyIndexes: Indices of readonly accounts in the table
    ///
    /// For legacy transactions, returns an empty array.
    #[wasm_bindgen]
    pub fn address_lookup_tables(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for alt in self.inner.address_lookup_tables() {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"accountKey".into(), &alt.account_key.into());
            let _ = js_sys::Reflect::set(
                &obj,
                &"writableIndexes".into(),
                &js_sys::Uint8Array::from(&alt.writable_indexes[..]),
            );
            let _ = js_sys::Reflect::set(
                &obj,
                &"readonlyIndexes".into(),
                &js_sys::Uint8Array::from(&alt.readonly_indexes[..]),
            );
            arr.push(&obj);
        }
        arr
    }

    /// Get all signatures as an array of byte arrays.
    #[wasm_bindgen]
    pub fn signatures(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();
        for sig in &self.inner.signatures {
            let bytes: &[u8] = sig.as_ref();
            arr.push(&js_sys::Uint8Array::from(bytes));
        }
        arr
    }

    /// Add a signature for a given public key.
    ///
    /// @param pubkey - The public key as a base58 string
    /// @param signature - The 64-byte signature
    #[wasm_bindgen]
    pub fn add_signature(&mut self, pubkey: &str, signature: &[u8]) -> Result<(), WasmSolanaError> {
        self.inner.add_signature(pubkey, signature)
    }

    /// Check if a public key is a required signer.
    ///
    /// @returns The signer index if the pubkey is a signer, null otherwise
    #[wasm_bindgen]
    pub fn signer_index(&self, pubkey: &str) -> Option<usize> {
        self.inner.signer_index(pubkey)
    }

    /// Get all instructions as an array.
    ///
    /// Note: For versioned transactions with ALTs, account indices may
    /// reference accounts beyond static_account_keys. Use address_lookup_tables()
    /// to resolve additional accounts.
    #[wasm_bindgen]
    pub fn instructions(&self) -> js_sys::Array {
        let arr = js_sys::Array::new();

        let (account_keys, instructions, header) = match &self.inner.message {
            VersionedMessage::Legacy(msg) => (&msg.account_keys, &msg.instructions, &msg.header),
            VersionedMessage::V0(msg) => (&msg.account_keys, &msg.instructions, &msg.header),
        };

        for instruction in instructions {
            let obj = js_sys::Object::new();

            // Get the program ID
            if let Some(program_id) = account_keys.get(instruction.program_id_index as usize) {
                let _ =
                    js_sys::Reflect::set(&obj, &"programId".into(), &program_id.to_string().into());
            }

            // Build accounts array
            let accounts = js_sys::Array::new();
            for &account_index in &instruction.accounts {
                let account_obj = js_sys::Object::new();
                let _ = js_sys::Reflect::set(
                    &account_obj,
                    &"index".into(),
                    &(account_index as u32).into(),
                );

                // Get pubkey if it's a static account (index within static keys)
                if let Some(pubkey) = account_keys.get(account_index as usize) {
                    let _ = js_sys::Reflect::set(
                        &account_obj,
                        &"pubkey".into(),
                        &pubkey.to_string().into(),
                    );
                    let _ =
                        js_sys::Reflect::set(&account_obj, &"isLookupTable".into(), &false.into());
                } else {
                    // Account is from an Address Lookup Table
                    let _ =
                        js_sys::Reflect::set(&account_obj, &"isLookupTable".into(), &true.into());
                }

                // Determine if signer/writable based on index position
                let is_signer = (account_index as usize) < header.num_required_signatures as usize;
                let _ = js_sys::Reflect::set(&account_obj, &"isSigner".into(), &is_signer.into());

                accounts.push(&account_obj);
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

impl WasmVersionedTransaction {
    /// Get the inner VersionedTransaction for internal Rust use.
    pub fn inner(&self) -> &VersionedTransaction {
        &self.inner
    }
}
