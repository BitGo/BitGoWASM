//! Types for transaction building.
//!
//! These types are designed to be serialized from JavaScript via serde.
//! They use string representations for public keys and amounts to ensure
//! compatibility with JavaScript's number limitations.

use serde::Deserialize;

/// Nonce source for transaction - either a recent blockhash or durable nonce account.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Nonce {
    /// Use a recent blockhash (standard transactions)
    Blockhash { value: String },
    /// Use a durable nonce account (offline signing)
    Durable {
        address: String,
        authority: String,
        /// Nonce value stored in the account (this becomes the blockhash)
        value: String,
    },
}

/// Intent to build a transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionIntent {
    /// The fee payer's public key (base58)
    pub fee_payer: String,
    /// Nonce source
    pub nonce: Nonce,
    /// List of instructions to include
    pub instructions: Vec<Instruction>,
}

/// An instruction to include in the transaction.
///
/// This is a discriminated union (tagged enum) that supports all instruction types.
/// Use the `type` field to determine which variant is being used.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Instruction {
    // ===== System Program Instructions =====
    /// Transfer SOL from one account to another
    Transfer {
        from: String,
        to: String,
        /// Amount in lamports (as string for BigInt compatibility)
        lamports: String,
    },

    /// Create a new account
    CreateAccount {
        from: String,
        #[serde(rename = "newAccount")]
        new_account: String,
        /// Lamports to transfer to new account (as string)
        lamports: String,
        /// Space to allocate in bytes
        space: u64,
        /// Program owner of the new account
        owner: String,
    },

    /// Advance a nonce account
    NonceAdvance {
        /// Nonce account address
        nonce: String,
        /// Nonce authority
        authority: String,
    },

    /// Initialize a nonce account
    NonceInitialize {
        /// Nonce account address
        nonce: String,
        /// Nonce authority
        authority: String,
    },

    /// Allocate space in an account
    Allocate { account: String, space: u64 },

    /// Assign account to a program
    Assign { account: String, owner: String },

    // ===== Memo Program =====
    /// Add a memo to the transaction
    Memo { message: String },

    // ===== Compute Budget Program =====
    /// Set compute budget (priority fees)
    ComputeBudget {
        /// Compute unit limit (optional)
        #[serde(rename = "unitLimit")]
        unit_limit: Option<u32>,
        /// Compute unit price in micro-lamports (optional)
        #[serde(rename = "unitPrice")]
        unit_price: Option<u64>,
    },
    // ===== Stake Program Instructions (Phase 10) =====
    // TODO: Add in Phase 10
    // StakeInitialize { ... }
    // StakeDelegate { ... }
    // StakeDeactivate { ... }
    // StakeWithdraw { ... }
    // StakeAuthorize { ... }
    // StakeSplit { ... }
    // StakeMerge { ... }

    // ===== SPL Token Instructions (Phase 11) =====
    // TODO: Add in Phase 11
    // TokenTransfer { ... }
    // CreateAta { ... }
    // CloseAta { ... }
}
