//! TryIntoJsValue implementations for instruction types.
//!
//! Converts Rust instruction types directly to JavaScript objects with
//! proper BigInt handling for u64 amounts.

use crate::js_obj;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use base64::prelude::*;
use wasm_bindgen::JsValue;

use super::types::*;
use crate::intent::{AuthorizeType, KeypairPurpose, StakingType};

// =============================================================================
// Enum → JS string conversions
// =============================================================================

impl TryIntoJsValue for StakingType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let s = match self {
            StakingType::Native => "NATIVE",
            StakingType::Jito => "JITO",
            StakingType::Marinade => "MARINADE",
        };
        Ok(JsValue::from_str(s))
    }
}

impl TryIntoJsValue for AuthorizeType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let s = match self {
            AuthorizeType::Staker => "Staker",
            AuthorizeType::Withdrawer => "Withdrawer",
        };
        Ok(JsValue::from_str(s))
    }
}

impl TryIntoJsValue for KeypairPurpose {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        let s = match self {
            KeypairPurpose::StakeAccount => "stakeAccount",
            KeypairPurpose::UnstakeAccount => "unstakeAccount",
            KeypairPurpose::TransferAuthority => "transferAuthority",
        };
        Ok(JsValue::from_str(s))
    }
}

// =============================================================================
// System Program Params
// =============================================================================

impl TryIntoJsValue for TransferParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "Transfer",
            "fromAddress" => self.from_address,
            "toAddress" => self.to_address,
            "amount" => self.amount
        )
    }
}

impl TryIntoJsValue for CreateAccountParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "CreateAccount",
            "fromAddress" => self.from_address,
            "newAddress" => self.new_address,
            "amount" => self.amount,
            "space" => self.space,
            "owner" => self.owner
        )
    }
}

impl TryIntoJsValue for NonceAdvanceParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "NonceAdvance",
            "walletNonceAddress" => self.wallet_nonce_address,
            "authWalletAddress" => self.auth_wallet_address
        )
    }
}

impl TryIntoJsValue for CreateNonceAccountParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "CreateNonceAccount",
            "fromAddress" => self.from_address,
            "nonceAddress" => self.nonce_address,
            "authAddress" => self.auth_address,
            "amount" => self.amount
        )
    }
}

impl TryIntoJsValue for NonceInitializeParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "NonceInitialize",
            "nonceAddress" => self.nonce_address,
            "authAddress" => self.auth_address
        )
    }
}

// =============================================================================
// Stake Program Params
// =============================================================================

impl TryIntoJsValue for StakingActivateParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakingActivate",
            "fromAddress" => self.from_address,
            "stakingAddress" => self.staking_address,
            "amount" => self.amount,
            "validator" => self.validator,
            "stakingType" => self.staking_type
        )
    }
}

impl TryIntoJsValue for StakingDeactivateParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakingDeactivate",
            "stakingAddress" => self.staking_address,
            "fromAddress" => self.from_address
        )
    }
}

impl TryIntoJsValue for StakingWithdrawParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakingWithdraw",
            "fromAddress" => self.from_address,
            "stakingAddress" => self.staking_address,
            "amount" => self.amount
        )
    }
}

impl TryIntoJsValue for StakingDelegateParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakingDelegate",
            "stakingAddress" => self.staking_address,
            "fromAddress" => self.from_address,
            "validator" => self.validator
        )
    }
}

impl TryIntoJsValue for StakingAuthorizeParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakingAuthorize",
            "stakingAddress" => self.staking_address,
            "oldAuthorizeAddress" => self.old_authorize_address,
            "newAuthorizeAddress" => self.new_authorize_address,
            "authorizeType" => self.authorize_type,
            "custodianAddress" => self.custodian_address
        )
    }
}

impl TryIntoJsValue for StakeInitializeParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakeInitialize",
            "stakingAddress" => self.staking_address,
            "staker" => self.staker,
            "withdrawer" => self.withdrawer
        )
    }
}

// =============================================================================
// ComputeBudget Params
// =============================================================================

impl TryIntoJsValue for SetComputeUnitLimitParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "SetComputeUnitLimit",
            "units" => self.units
        )
    }
}

impl TryIntoJsValue for SetPriorityFeeParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "SetPriorityFee",
            "fee" => self.fee
        )
    }
}

// =============================================================================
// Token Params
// =============================================================================

impl TryIntoJsValue for TokenTransferParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "TokenTransfer",
            "fromAddress" => self.from_address,
            "toAddress" => self.to_address,
            "amount" => self.amount,
            "sourceAddress" => self.source_address,
            "tokenAddress" => self.token_address,
            "programId" => self.program_id,
            "decimalPlaces" => self.decimal_places
        )
    }
}

impl TryIntoJsValue for CreateAtaParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "CreateAssociatedTokenAccount",
            "mintAddress" => self.mint_address,
            "ataAddress" => self.ata_address,
            "ownerAddress" => self.owner_address,
            "payerAddress" => self.payer_address,
            "programId" => self.program_id
        )
    }
}

impl TryIntoJsValue for CloseAtaParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "CloseAssociatedTokenAccount",
            "accountAddress" => self.account_address,
            "destinationAddress" => self.destination_address,
            "authorityAddress" => self.authority_address
        )
    }
}

// =============================================================================
// Stake Pool (Jito) Params
// =============================================================================

impl TryIntoJsValue for StakePoolDepositSolParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakePoolDepositSol",
            "stakePool" => self.stake_pool,
            "withdrawAuthority" => self.withdraw_authority,
            "reserveStake" => self.reserve_stake,
            "fundingAccount" => self.funding_account,
            "destinationPoolAccount" => self.destination_pool_account,
            "managerFeeAccount" => self.manager_fee_account,
            "referralPoolAccount" => self.referral_pool_account,
            "poolMint" => self.pool_mint,
            "lamports" => self.lamports
        )
    }
}

impl TryIntoJsValue for StakePoolWithdrawStakeParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "StakePoolWithdrawStake",
            "stakePool" => self.stake_pool,
            "validatorList" => self.validator_list,
            "withdrawAuthority" => self.withdraw_authority,
            "validatorStake" => self.validator_stake,
            "destinationStake" => self.destination_stake,
            "destinationStakeAuthority" => self.destination_stake_authority,
            "sourceTransferAuthority" => self.source_transfer_authority,
            "sourcePoolAccount" => self.source_pool_account,
            "managerFeeAccount" => self.manager_fee_account,
            "poolMint" => self.pool_mint,
            "poolTokens" => self.pool_tokens
        )
    }
}

// =============================================================================
// Memo & Unknown
// =============================================================================

impl TryIntoJsValue for MemoParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "Memo",
            "memo" => self.memo
        )
    }
}

impl TryIntoJsValue for AccountMeta {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "pubkey" => self.pubkey,
            "isSigner" => self.is_signer,
            "isWritable" => self.is_writable
        )
    }
}

impl TryIntoJsValue for UnknownInstructionParams {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "type" => "Unknown",
            "programId" => self.program_id,
            "accounts" => self.accounts,
            "data" => BASE64_STANDARD.encode(&self.data)
        )
    }
}

// =============================================================================
// ParsedInstruction enum
// =============================================================================

impl TryIntoJsValue for ParsedInstruction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        match self {
            ParsedInstruction::Transfer(p) => p.try_to_js_value(),
            ParsedInstruction::CreateAccount(p) => p.try_to_js_value(),
            ParsedInstruction::NonceAdvance(p) => p.try_to_js_value(),
            ParsedInstruction::CreateNonceAccount(p) => p.try_to_js_value(),
            ParsedInstruction::NonceInitialize(p) => p.try_to_js_value(),
            ParsedInstruction::StakingActivate(p) => p.try_to_js_value(),
            ParsedInstruction::StakingDeactivate(p) => p.try_to_js_value(),
            ParsedInstruction::StakingWithdraw(p) => p.try_to_js_value(),
            ParsedInstruction::StakingDelegate(p) => p.try_to_js_value(),
            ParsedInstruction::StakingAuthorize(p) => p.try_to_js_value(),
            ParsedInstruction::StakeInitialize(p) => p.try_to_js_value(),
            ParsedInstruction::SetComputeUnitLimit(p) => p.try_to_js_value(),
            ParsedInstruction::SetPriorityFee(p) => p.try_to_js_value(),
            ParsedInstruction::TokenTransfer(p) => p.try_to_js_value(),
            ParsedInstruction::CreateAssociatedTokenAccount(p) => p.try_to_js_value(),
            ParsedInstruction::CloseAssociatedTokenAccount(p) => p.try_to_js_value(),
            ParsedInstruction::Memo(p) => p.try_to_js_value(),
            ParsedInstruction::StakePoolDepositSol(p) => p.try_to_js_value(),
            ParsedInstruction::StakePoolWithdrawStake(p) => p.try_to_js_value(),
            ParsedInstruction::Unknown(p) => p.try_to_js_value(),
        }
    }
}
