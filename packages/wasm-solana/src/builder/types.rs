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
        /// Amount in lamports to withdraw (as string)
        lamports: String,
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

    // ===== SPL Token Instructions =====
    /// Transfer tokens (uses TransferChecked for safety)
    TokenTransfer {
        /// Source token account
        source: String,
        /// Destination token account
        destination: String,
        /// Token mint address
        mint: String,
        /// Amount of tokens to transfer (as string, in smallest units)
        amount: String,
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
        /// Amount in lamports to deposit (as string)
        lamports: String,
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
        /// Amount of pool tokens to burn (as string)
        #[serde(rename = "poolTokens")]
        pool_tokens: String,
    },
}

fn default_token_program() -> String {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string()
}
