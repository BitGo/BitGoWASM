//! Parsed instruction types matching BitGoJS InstructionParams.
//!
//! These types are designed to convert directly to JavaScript values
//! using TryIntoJsValue, matching the TypeScript interfaces in
//! sdk-coin-sol/src/lib/iface.ts.

/// Program IDs as base58 strings.
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
pub const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
pub const TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM_ID: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
pub const ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
pub const STAKE_POOL_PROGRAM_ID: &str = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy";

/// Sysvar Recent Blockhashes address.
/// Required for NonceAdvance instruction to verify the nonce account's stored blockhash.
///
/// Note: We hardcode this because solana_sdk::sysvar::recent_blockhashes::ID
/// is not available in the WASM-compatible subset of solana-sdk.
/// The value matches: https://github.com/solana-labs/solana/blob/v1.18.26/sdk/program/src/sysvar/recent_blockhashes.rs
pub const SYSVAR_RECENT_BLOCKHASHES: &str = "SysvarRecentB1ockHashes11111111111111111111";

/// A parsed instruction with type discriminant and params.
///
/// Note: Some variants like `CreateNonceAccount` and `StakingActivate` are defined
/// for API completeness but never constructed in Rust. Instruction combining
/// (e.g., CreateAccount + NonceInitialize → CreateNonceAccount) is handled by
/// TypeScript in mapWasmInstructionsToBitGoJS for flexibility.
#[derive(Debug, Clone)]
pub enum ParsedInstruction {
    // System Program instructions
    Transfer(TransferParams),
    CreateAccount(CreateAccountParams),
    NonceAdvance(NonceAdvanceParams),
    /// Combined type for CreateAccount + NonceInitialize (constructed in TypeScript)
    #[allow(dead_code)]
    CreateNonceAccount(CreateNonceAccountParams),
    /// Intermediate type for SystemInstruction::InitializeNonceAccount
    /// Will be combined with CreateAccount to form CreateNonceAccount
    NonceInitialize(NonceInitializeParams),

    // Stake Program instructions
    /// Combined type for CreateAccount + StakeInitialize + Delegate (constructed in TypeScript)
    #[allow(dead_code)]
    StakingActivate(StakingActivateParams),
    StakingDeactivate(StakingDeactivateParams),
    StakingWithdraw(StakingWithdrawParams),
    StakingDelegate(StakingDelegateParams),
    StakingAuthorize(StakingAuthorizeParams),
    /// Intermediate type for stake initialize - will be combined with CreateAccount + DelegateStake
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

    // Stake Pool (Jito liquid staking) instructions
    StakePoolDepositSol(StakePoolDepositSolParams),
    StakePoolWithdrawStake(StakePoolWithdrawStakeParams),

    // Fallback for unknown/custom instructions
    Unknown(UnknownInstructionParams),
}

// =============================================================================
// System Program Params
// =============================================================================

#[derive(Debug, Clone)]
pub struct TransferParams {
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct CreateAccountParams {
    pub from_address: String,
    pub new_address: String,
    pub amount: u64,
    pub space: u64,
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct NonceAdvanceParams {
    pub wallet_nonce_address: String,
    pub auth_wallet_address: String,
}

#[derive(Debug, Clone)]
pub struct CreateNonceAccountParams {
    pub from_address: String,
    pub nonce_address: String,
    pub auth_address: String,
    pub amount: u64,
}

/// Intermediate type for SystemInstruction::InitializeNonceAccount
/// Will be combined with CreateAccount to form CreateNonceAccount
#[derive(Debug, Clone)]
pub struct NonceInitializeParams {
    pub nonce_address: String,
    pub auth_address: String,
}

// =============================================================================
// Stake Program Params
// =============================================================================

#[derive(Debug, Clone)]
pub struct StakingActivateParams {
    pub from_address: String,
    pub staking_address: String,
    pub amount: u64,
    pub validator: String,
    pub staking_type: String, // "NATIVE", "JITO", "MARINADE"
}

#[derive(Debug, Clone)]
pub struct StakingDeactivateParams {
    pub staking_address: String,
    pub from_address: String,
}

#[derive(Debug, Clone)]
pub struct StakingWithdrawParams {
    pub from_address: String,
    pub staking_address: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct StakingDelegateParams {
    pub staking_address: String,
    pub from_address: String,
    pub validator: String,
}

#[derive(Debug, Clone)]
pub struct StakingAuthorizeParams {
    pub staking_address: String,
    pub old_authorize_address: String,
    pub new_authorize_address: String,
    pub authorize_type: String, // "Staker" or "Withdrawer"
    pub custodian_address: Option<String>,
}

/// Intermediate type for StakeInstruction::Initialize
/// Will be combined with CreateAccount + DelegateStake to form StakingActivate
#[derive(Debug, Clone)]
pub struct StakeInitializeParams {
    pub staking_address: String,
    pub staker: String,
    pub withdrawer: String,
}

// =============================================================================
// ComputeBudget Params
// =============================================================================

#[derive(Debug, Clone)]
pub struct SetComputeUnitLimitParams {
    pub units: u32,
}

#[derive(Debug, Clone)]
pub struct SetPriorityFeeParams {
    pub fee: u64,
}

// =============================================================================
// Token Params
// =============================================================================

#[derive(Debug, Clone)]
pub struct TokenTransferParams {
    pub from_address: String,
    pub to_address: String,
    pub amount: u64,
    pub source_address: String,
    pub token_address: Option<String>,
    pub program_id: String,
    pub decimal_places: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct CreateAtaParams {
    pub mint_address: String,
    pub ata_address: String,
    pub owner_address: String,
    pub payer_address: String,
    pub program_id: String,
}

#[derive(Debug, Clone)]
pub struct CloseAtaParams {
    pub account_address: String,
    pub destination_address: String,
    pub authority_address: String,
}

// =============================================================================
// Stake Pool (Jito) Params
// =============================================================================

/// Parameters for DepositSol instruction in stake pool (Jito liquid staking).
/// Discriminator: 14
#[derive(Debug, Clone)]
pub struct StakePoolDepositSolParams {
    pub stake_pool: String,
    pub withdraw_authority: String,
    pub reserve_stake: String,
    pub funding_account: String,
    pub destination_pool_account: String,
    pub manager_fee_account: String,
    pub referral_pool_account: String,
    pub pool_mint: String,
    pub lamports: u64,
}

/// Parameters for WithdrawStake instruction in stake pool (Jito liquid staking).
/// Discriminator: 10
#[derive(Debug, Clone)]
pub struct StakePoolWithdrawStakeParams {
    pub stake_pool: String,
    pub validator_list: String,
    pub withdraw_authority: String,
    pub validator_stake: String,
    pub destination_stake: String,
    pub destination_stake_authority: String,
    pub source_transfer_authority: String,
    pub source_pool_account: String,
    pub manager_fee_account: String,
    pub pool_mint: String,
    pub pool_tokens: u64,
}

// =============================================================================
// Memo & Unknown
// =============================================================================

#[derive(Debug, Clone)]
pub struct MemoParams {
    pub memo: String,
}

#[derive(Debug, Clone)]
pub struct UnknownInstructionParams {
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}
