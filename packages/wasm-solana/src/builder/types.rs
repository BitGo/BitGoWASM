//! Types for transaction building.
//!
//! These types are designed to be serialized from JavaScript via serde.
//! Public keys use string (base58) representations.
//! Amounts use u64 which maps to JavaScript BigInt via wasm-bindgen.

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

    // ===== Versioned Transaction Fields (MessageV0) =====
    // If these fields are provided, a versioned transaction is built.
    /// Address Lookup Tables for versioned transactions.
    /// If provided, builds a MessageV0 transaction instead of legacy.
    #[serde(rename = "addressLookupTables", default)]
    pub address_lookup_tables: Option<Vec<AddressLookupTable>>,

    /// Static account keys (for versioned transaction round-trip).
    /// These are the accounts stored directly in the message.
    #[serde(rename = "staticAccountKeys", default)]
    pub static_account_keys: Option<Vec<String>>,
}

/// Address Lookup Table data for versioned transactions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressLookupTable {
    /// The lookup table account address (base58)
    #[serde(rename = "accountKey")]
    pub account_key: String,
    /// Indices of writable accounts in the lookup table
    #[serde(rename = "writableIndexes")]
    pub writable_indexes: Vec<u8>,
    /// Indices of readonly accounts in the lookup table
    #[serde(rename = "readonlyIndexes")]
    pub readonly_indexes: Vec<u8>,
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
        /// Amount in lamports
        lamports: u64,
    },

    /// Create a new account
    CreateAccount {
        from: String,
        #[serde(rename = "newAccount")]
        new_account: String,
        /// Lamports to transfer to new account
        lamports: u64,
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
    // ===== Stake Program Instructions =====
    /// Initialize a stake account with authorized staker and withdrawer
    StakeInitialize {
        /// Stake account address
        stake: String,
        /// Authorized staker pubkey
        staker: String,
        /// Authorized withdrawer pubkey
        withdrawer: String,
    },

    /// Delegate stake to a validator
    StakeDelegate {
        /// Stake account address
        stake: String,
        /// Vote account (validator) to delegate to
        vote: String,
        /// Stake authority
        authority: String,
    },

    /// Deactivate a stake account
    StakeDeactivate {
        /// Stake account address
        stake: String,
        /// Stake authority
        authority: String,
    },

    /// Withdraw from a stake account
    StakeWithdraw {
        /// Stake account address
        stake: String,
        /// Recipient address for withdrawn lamports
        recipient: String,
        /// Amount in lamports to withdraw
        lamports: u64,
        /// Withdraw authority
        authority: String,
    },

    /// Change stake account authorization
    StakeAuthorize {
        /// Stake account address
        stake: String,
        /// New authority pubkey
        #[serde(rename = "newAuthority")]
        new_authority: String,
        /// Authorization type: "staker" or "withdrawer"
        #[serde(rename = "authorizeType")]
        authorize_type: String,
        /// Current authority
        authority: String,
    },

    /// Split stake account (used for partial deactivation)
    StakeSplit {
        /// Source stake account address
        stake: String,
        /// Destination stake account (must be uninitialized/created first)
        #[serde(rename = "splitStake")]
        split_stake: String,
        /// Stake authority
        authority: String,
        /// Amount in lamports to split
        lamports: u64,
    },

    // ===== SPL Token Instructions =====
    /// Transfer tokens (uses TransferChecked for safety)
    TokenTransfer {
        /// Source token account
        source: String,
        /// Destination token account
        destination: String,
        /// Token mint address
        mint: String,
        /// Amount of tokens to transfer (in smallest units)
        amount: u64,
        /// Number of decimals for the token
        decimals: u8,
        /// Owner/authority of the source account
        authority: String,
        /// Token program ID (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA or Token-2022)
        #[serde(rename = "programId", default = "default_token_program")]
        program_id: String,
    },

    /// Create an Associated Token Account
    CreateAssociatedTokenAccount {
        /// Payer for account creation
        payer: String,
        /// Owner of the new ATA
        owner: String,
        /// Token mint address
        mint: String,
        /// Token program ID (optional, defaults to Token Program)
        #[serde(rename = "tokenProgramId", default = "default_token_program")]
        token_program_id: String,
    },

    /// Close an Associated Token Account
    CloseAssociatedTokenAccount {
        /// Token account to close
        account: String,
        /// Destination for remaining lamports
        destination: String,
        /// Authority of the account
        authority: String,
        /// Token program ID (optional, defaults to Token Program)
        #[serde(rename = "programId", default = "default_token_program")]
        program_id: String,
    },

    /// Mint tokens to an account (requires mint authority)
    MintTo {
        /// Token mint address
        mint: String,
        /// Destination token account
        destination: String,
        /// Mint authority
        authority: String,
        /// Amount of tokens to mint (in smallest units)
        amount: u64,
        /// Token program ID (optional, defaults to Token Program)
        #[serde(rename = "programId", default = "default_token_program")]
        program_id: String,
    },

    /// Burn tokens from an account
    Burn {
        /// Token mint address
        mint: String,
        /// Source token account to burn from
        account: String,
        /// Token account authority
        authority: String,
        /// Amount of tokens to burn (in smallest units)
        amount: u64,
        /// Token program ID (optional, defaults to Token Program)
        #[serde(rename = "programId", default = "default_token_program")]
        program_id: String,
    },

    /// Approve a delegate to transfer tokens
    Approve {
        /// Token account to approve delegation for
        account: String,
        /// Delegate address (who can transfer)
        delegate: String,
        /// Token account owner
        owner: String,
        /// Amount of tokens to approve (in smallest units)
        amount: u64,
        /// Token program ID (optional, defaults to Token Program)
        #[serde(rename = "programId", default = "default_token_program")]
        program_id: String,
    },

    // ===== Jito Stake Pool Instructions =====
    /// Deposit SOL into a stake pool (Jito liquid staking)
    StakePoolDepositSol {
        /// Stake pool address
        #[serde(rename = "stakePool")]
        stake_pool: String,
        /// Withdraw authority PDA
        #[serde(rename = "withdrawAuthority")]
        withdraw_authority: String,
        /// Reserve stake account
        #[serde(rename = "reserveStake")]
        reserve_stake: String,
        /// Funding account (SOL source, signer)
        #[serde(rename = "fundingAccount")]
        funding_account: String,
        /// Destination for pool tokens
        #[serde(rename = "destinationPoolAccount")]
        destination_pool_account: String,
        /// Manager fee account
        #[serde(rename = "managerFeeAccount")]
        manager_fee_account: String,
        /// Referral pool account
        #[serde(rename = "referralPoolAccount")]
        referral_pool_account: String,
        /// Pool mint address
        #[serde(rename = "poolMint")]
        pool_mint: String,
        /// Amount in lamports to deposit
        lamports: u64,
    },

    /// Withdraw stake from a stake pool (Jito liquid staking)
    StakePoolWithdrawStake {
        /// Stake pool address
        #[serde(rename = "stakePool")]
        stake_pool: String,
        /// Validator list account
        #[serde(rename = "validatorList")]
        validator_list: String,
        /// Withdraw authority PDA
        #[serde(rename = "withdrawAuthority")]
        withdraw_authority: String,
        /// Validator stake account to split from
        #[serde(rename = "validatorStake")]
        validator_stake: String,
        /// Destination stake account (uninitialized)
        #[serde(rename = "destinationStake")]
        destination_stake: String,
        /// Authority for the destination stake account
        #[serde(rename = "destinationStakeAuthority")]
        destination_stake_authority: String,
        /// Source pool token account authority (signer)
        #[serde(rename = "sourceTransferAuthority")]
        source_transfer_authority: String,
        /// Source pool token account
        #[serde(rename = "sourcePoolAccount")]
        source_pool_account: String,
        /// Manager fee account
        #[serde(rename = "managerFeeAccount")]
        manager_fee_account: String,
        /// Pool mint address
        #[serde(rename = "poolMint")]
        pool_mint: String,
        /// Amount of pool tokens to burn
        #[serde(rename = "poolTokens")]
        pool_tokens: u64,
    },

    // ===== Custom/Raw Instruction =====
    /// A custom instruction that can invoke any program.
    /// This enables passthrough of arbitrary instructions for extensibility.
    Custom {
        /// The program ID to invoke (base58)
        #[serde(rename = "programId")]
        program_id: String,
        /// Account metas for the instruction
        accounts: Vec<CustomAccountMeta>,
        /// Instruction data (base64 or hex encoded)
        data: String,
        /// Encoding of the data field: "base64" (default) or "hex"
        #[serde(default = "default_encoding")]
        encoding: String,
    },
}

/// Account meta for custom instructions
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomAccountMeta {
    /// Account public key (base58)
    pub pubkey: String,
    /// Whether the account is a signer
    #[serde(default)]
    pub is_signer: bool,
    /// Whether the account is writable
    #[serde(default)]
    pub is_writable: bool,
}

fn default_token_program() -> String {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()
}

fn default_encoding() -> String {
    "base64".to_string()
}

// =============================================================================
// Raw Versioned Transaction Data (for fromVersionedTransactionData path)
// =============================================================================

/// Raw versioned transaction data for direct serialization.
/// This is used when we have pre-formed MessageV0 data that just needs to be serialized.
/// No instruction compilation is needed - just serialize the raw structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawVersionedTransactionData {
    /// Static account keys (base58 encoded public keys)
    #[serde(rename = "staticAccountKeys")]
    pub static_account_keys: Vec<String>,

    /// Address lookup tables
    #[serde(rename = "addressLookupTables")]
    pub address_lookup_tables: Vec<AddressLookupTable>,

    /// Pre-compiled instructions with index-based account references
    #[serde(rename = "versionedInstructions")]
    pub versioned_instructions: Vec<VersionedInstruction>,

    /// Message header
    #[serde(rename = "messageHeader")]
    pub message_header: MessageHeader,

    /// Recent blockhash (base58)
    #[serde(rename = "recentBlockhash")]
    pub recent_blockhash: String,
}

/// A pre-compiled versioned instruction (uses indexes, not pubkeys)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedInstruction {
    /// Index into the account keys array for the program ID
    #[serde(rename = "programIdIndex")]
    pub program_id_index: u8,

    /// Indexes into the account keys array for instruction accounts
    #[serde(rename = "accountKeyIndexes")]
    pub account_key_indexes: Vec<u8>,

    /// Instruction data (base58 encoded)
    pub data: String,
}

/// Message header for versioned transactions
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageHeader {
    /// Number of required signatures
    #[serde(rename = "numRequiredSignatures")]
    pub num_required_signatures: u8,

    /// Number of readonly signed accounts
    #[serde(rename = "numReadonlySignedAccounts")]
    pub num_readonly_signed_accounts: u8,

    /// Number of readonly unsigned accounts
    #[serde(rename = "numReadonlyUnsignedAccounts")]
    pub num_readonly_unsigned_accounts: u8,
}
