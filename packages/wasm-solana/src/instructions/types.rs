//! Parsed instruction types matching BitGoJS InstructionParams.
//!
//! These types are designed to serialize to JSON that matches the TypeScript
//! interfaces in sdk-coin-sol/src/lib/iface.ts.

use serde::Serialize;

/// Program IDs as base58 strings.
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// A parsed instruction with type discriminant and params.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ParsedInstruction {
    // System Program instructions
    Transfer(TransferParams),
    CreateAccount(CreateAccountParams),
    NonceAdvance(NonceAdvanceParams),
    CreateNonceAccount(CreateNonceAccountParams),
    /// Intermediate type for SystemInstruction::InitializeNonceAccount
    /// Will be combined with CreateAccount to form CreateNonceAccount
    #[serde(rename = "NonceInitialize")]
    NonceInitialize(NonceInitializeParams),

    // Stake Program instructions
    StakingActivate(StakingActivateParams),
    StakingDeactivate(StakingDeactivateParams),
    StakingWithdraw(StakingWithdrawParams),
    StakingDelegate(StakingDelegateParams),
    StakingAuthorize(StakingAuthorizeParams),
    /// Intermediate type for stake initialize - will be combined with CreateAccount + DelegateStake
    #[serde(rename = "StakeInitialize")]
    StakeInitialize(StakeInitializeParams),

    // ComputeBudget instructions
    SetComputeUnitLimit(SetComputeUnitLimitParams),
    SetPriorityFee(SetPriorityFeeParams),

    // Token instructions (basic support)
    TokenTransfer(TokenTransferParams),
    CreateAssociatedTokenAccount(CreateAtaParams),
    CloseAssociatedTokenAccount(CloseAtaParams),

    // Memo
    Memo(MemoParams),

    // Fallback for unknown/custom instructions
    Unknown(UnknownInstructionParams),
}

// =============================================================================
// System Program Params
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TransferParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "toAddress")]
    pub to_address: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAccountParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "newAddress")]
    pub new_address: String,
    pub amount: String,
    pub space: u64,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NonceAdvanceParams {
    #[serde(rename = "walletNonceAddress")]
    pub wallet_nonce_address: String,
    #[serde(rename = "authWalletAddress")]
    pub auth_wallet_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateNonceAccountParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "nonceAddress")]
    pub nonce_address: String,
    #[serde(rename = "authAddress")]
    pub auth_address: String,
    pub amount: String,
}

/// Intermediate type for SystemInstruction::InitializeNonceAccount
/// Will be combined with CreateAccount to form CreateNonceAccount
#[derive(Debug, Clone, Serialize)]
pub struct NonceInitializeParams {
    #[serde(rename = "nonceAddress")]
    pub nonce_address: String,
    #[serde(rename = "authAddress")]
    pub auth_address: String,
}

// =============================================================================
// Stake Program Params
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct StakingActivateParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    pub amount: String,
    pub validator: String,
    #[serde(rename = "stakingType")]
    pub staking_type: String, // "NATIVE", "JITO", "MARINADE"
}

#[derive(Debug, Clone, Serialize)]
pub struct StakingDeactivateParams {
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    #[serde(rename = "fromAddress")]
    pub from_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StakingWithdrawParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    pub amount: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StakingDelegateParams {
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    pub validator: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StakingAuthorizeParams {
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    #[serde(rename = "oldAuthorizeAddress")]
    pub old_authorize_address: String,
    #[serde(rename = "newAuthorizeAddress")]
    pub new_authorize_address: String,
    #[serde(rename = "authorizeType")]
    pub authorize_type: String, // "Staker" or "Withdrawer"
}

/// Intermediate type for StakeInstruction::Initialize
/// Will be combined with CreateAccount + DelegateStake to form StakingActivate
#[derive(Debug, Clone, Serialize)]
pub struct StakeInitializeParams {
    #[serde(rename = "stakingAddress")]
    pub staking_address: String,
    pub staker: String,
    pub withdrawer: String,
}

// =============================================================================
// ComputeBudget Params
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct SetComputeUnitLimitParams {
    pub units: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetPriorityFeeParams {
    /// Fee as string for BigInt compatibility in JavaScript
    pub fee: String,
}

// =============================================================================
// Token Params
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct TokenTransferParams {
    #[serde(rename = "fromAddress")]
    pub from_address: String,
    #[serde(rename = "toAddress")]
    pub to_address: String,
    pub amount: String,
    #[serde(rename = "sourceAddress")]
    pub source_address: String,
    #[serde(rename = "tokenAddress", skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,
    #[serde(rename = "programId")]
    pub program_id: String,
    #[serde(rename = "decimalPlaces", skip_serializing_if = "Option::is_none")]
    pub decimal_places: Option<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateAtaParams {
    #[serde(rename = "mintAddress")]
    pub mint_address: String,
    #[serde(rename = "ataAddress")]
    pub ata_address: String,
    #[serde(rename = "ownerAddress")]
    pub owner_address: String,
    #[serde(rename = "payerAddress")]
    pub payer_address: String,
    #[serde(rename = "programId")]
    pub program_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloseAtaParams {
    #[serde(rename = "accountAddress")]
    pub account_address: String,
    #[serde(rename = "destinationAddress")]
    pub destination_address: String,
    #[serde(rename = "authorityAddress")]
    pub authority_address: String,
}

// =============================================================================
// Memo & Unknown
// =============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct MemoParams {
    pub memo: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnknownInstructionParams {
    #[serde(rename = "programId")]
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountMeta {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
    #[serde(rename = "isWritable")]
    pub is_writable: bool,
}

/// Custom serializer for bytes as base64.
mod base64_bytes {
    use base64::prelude::*;
    use serde::{Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        BASE64_STANDARD.encode(bytes).serialize(serializer)
    }
}
