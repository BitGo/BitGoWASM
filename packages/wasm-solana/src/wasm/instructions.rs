//! WASM bindings for instruction decoders.
//!
//! Provides JavaScript-friendly interfaces for decoding Solana program instructions
//! using official Solana interface crates.

use crate::error::WasmSolanaError;
use crate::instructions::{
    decode_compute_budget_instruction, decode_stake_instruction, decode_system_instruction,
    is_compute_budget_program, is_stake_program, is_system_program, ComputeBudgetInstruction,
    StakeInstruction, SystemInstruction, COMPUTE_BUDGET_PROGRAM_ID, STAKE_PROGRAM_ID,
    SYSTEM_PROGRAM_ID,
};
use wasm_bindgen::prelude::*;

// =============================================================================
// System Instruction WASM Bindings
// =============================================================================

/// WASM namespace for System Program instruction decoding.
#[wasm_bindgen]
pub struct SystemInstructionDecoder;

#[wasm_bindgen]
impl SystemInstructionDecoder {
    /// The System Program ID as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn program_id() -> String {
        SYSTEM_PROGRAM_ID.to_string()
    }

    /// Check if the given program ID is the System Program.
    #[wasm_bindgen]
    pub fn is_system_program(program_id: &str) -> bool {
        is_system_program(program_id)
    }

    /// Decode a System instruction from raw bytes.
    ///
    /// Returns a JS object with:
    /// - `type`: string (e.g., "Transfer", "CreateAccount")
    /// - Additional fields depending on the instruction type
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = decode_system_instruction(data)?;
        let obj = js_sys::Object::new();

        // Set the instruction type and fields based on variant
        match instr {
            SystemInstruction::CreateAccount {
                lamports,
                space,
                owner,
            } => {
                set_string(&obj, "type", "CreateAccount")?;
                set_u64(&obj, "lamports", lamports)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::Assign { owner } => {
                set_string(&obj, "type", "Assign")?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::Transfer { lamports } => {
                set_string(&obj, "type", "Transfer")?;
                set_u64(&obj, "lamports", lamports)?;
            }
            SystemInstruction::CreateAccountWithSeed {
                base,
                seed,
                lamports,
                space,
                owner,
            } => {
                set_string(&obj, "type", "CreateAccountWithSeed")?;
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_u64(&obj, "lamports", lamports)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::AdvanceNonceAccount => {
                set_string(&obj, "type", "AdvanceNonceAccount")?;
            }
            SystemInstruction::WithdrawNonceAccount(lamports) => {
                set_string(&obj, "type", "WithdrawNonceAccount")?;
                set_u64(&obj, "lamports", lamports)?;
            }
            SystemInstruction::InitializeNonceAccount(authority) => {
                set_string(&obj, "type", "InitializeNonceAccount")?;
                set_string(&obj, "authorized", &authority.to_string())?;
            }
            SystemInstruction::AuthorizeNonceAccount(authority) => {
                set_string(&obj, "type", "AuthorizeNonceAccount")?;
                set_string(&obj, "authorized", &authority.to_string())?;
            }
            SystemInstruction::Allocate { space } => {
                set_string(&obj, "type", "Allocate")?;
                set_u64(&obj, "space", space)?;
            }
            SystemInstruction::AllocateWithSeed {
                base,
                seed,
                space,
                owner,
            } => {
                set_string(&obj, "type", "AllocateWithSeed")?;
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::AssignWithSeed { base, seed, owner } => {
                set_string(&obj, "type", "AssignWithSeed")?;
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::TransferWithSeed {
                lamports,
                from_seed,
                from_owner,
            } => {
                set_string(&obj, "type", "TransferWithSeed")?;
                set_u64(&obj, "lamports", lamports)?;
                set_string(&obj, "fromSeed", &from_seed)?;
                set_string(&obj, "fromOwner", &from_owner.to_string())?;
            }
            SystemInstruction::UpgradeNonceAccount => {
                set_string(&obj, "type", "UpgradeNonceAccount")?;
            }
        }

        Ok(obj)
    }
}

// =============================================================================
// Stake Instruction WASM Bindings
// =============================================================================

/// WASM namespace for Stake Program instruction decoding.
#[wasm_bindgen]
pub struct StakeInstructionDecoder;

#[wasm_bindgen]
impl StakeInstructionDecoder {
    /// The Stake Program ID as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn program_id() -> String {
        STAKE_PROGRAM_ID.to_string()
    }

    /// Check if the given program ID is the Stake Program.
    #[wasm_bindgen]
    pub fn is_stake_program(program_id: &str) -> bool {
        is_stake_program(program_id)
    }

    /// Decode a Stake instruction from raw bytes.
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = decode_stake_instruction(data)?;
        let obj = js_sys::Object::new();

        match instr {
            StakeInstruction::Initialize(authorized, lockup) => {
                set_string(&obj, "type", "Initialize")?;
                set_string(&obj, "staker", &authorized.staker.to_string())?;
                set_string(&obj, "withdrawer", &authorized.withdrawer.to_string())?;
                // Add lockup info
                let lockup_obj = js_sys::Object::new();
                set_i64(&lockup_obj, "unixTimestamp", lockup.unix_timestamp)?;
                set_u64(&lockup_obj, "epoch", lockup.epoch)?;
                set_string(&lockup_obj, "custodian", &lockup.custodian.to_string())?;
                js_sys::Reflect::set(&obj, &"lockup".into(), &lockup_obj)
                    .map_err(|_| WasmSolanaError::new("Failed to set lockup"))?;
            }
            StakeInstruction::Authorize(new_authority, stake_authorize) => {
                set_string(&obj, "type", "Authorize")?;
                set_string(&obj, "newAuthority", &new_authority.to_string())?;
                let auth_type = match stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                set_string(&obj, "stakeAuthorize", auth_type)?;
            }
            StakeInstruction::DelegateStake => {
                set_string(&obj, "type", "DelegateStake")?;
            }
            StakeInstruction::Split(lamports) => {
                set_string(&obj, "type", "Split")?;
                set_u64(&obj, "lamports", lamports)?;
            }
            StakeInstruction::Withdraw(lamports) => {
                set_string(&obj, "type", "Withdraw")?;
                set_u64(&obj, "lamports", lamports)?;
            }
            StakeInstruction::Deactivate => {
                set_string(&obj, "type", "Deactivate")?;
            }
            StakeInstruction::SetLockup(lockup_args) => {
                set_string(&obj, "type", "SetLockup")?;
                if let Some(ts) = lockup_args.unix_timestamp {
                    set_i64(&obj, "unixTimestamp", ts)?;
                }
                if let Some(e) = lockup_args.epoch {
                    set_u64(&obj, "epoch", e)?;
                }
                if let Some(c) = lockup_args.custodian {
                    set_string(&obj, "custodian", &c.to_string())?;
                }
            }
            StakeInstruction::Merge => {
                set_string(&obj, "type", "Merge")?;
            }
            StakeInstruction::AuthorizeWithSeed(args) => {
                set_string(&obj, "type", "AuthorizeWithSeed")?;
                set_string(&obj, "newAuthority", &args.new_authorized_pubkey.to_string())?;
                let auth_type = match args.stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                set_string(&obj, "stakeAuthorize", auth_type)?;
                set_string(&obj, "authoritySeed", &args.authority_seed)?;
                set_string(&obj, "authorityOwner", &args.authority_owner.to_string())?;
            }
            StakeInstruction::InitializeChecked => {
                set_string(&obj, "type", "InitializeChecked")?;
            }
            StakeInstruction::AuthorizeChecked(stake_authorize) => {
                set_string(&obj, "type", "AuthorizeChecked")?;
                let auth_type = match stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                set_string(&obj, "stakeAuthorize", auth_type)?;
            }
            StakeInstruction::AuthorizeCheckedWithSeed(args) => {
                set_string(&obj, "type", "AuthorizeCheckedWithSeed")?;
                let auth_type = match args.stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                set_string(&obj, "stakeAuthorize", auth_type)?;
                set_string(&obj, "authoritySeed", &args.authority_seed)?;
                set_string(&obj, "authorityOwner", &args.authority_owner.to_string())?;
            }
            StakeInstruction::SetLockupChecked(lockup_args) => {
                set_string(&obj, "type", "SetLockupChecked")?;
                if let Some(ts) = lockup_args.unix_timestamp {
                    set_i64(&obj, "unixTimestamp", ts)?;
                }
                if let Some(e) = lockup_args.epoch {
                    set_u64(&obj, "epoch", e)?;
                }
            }
            StakeInstruction::GetMinimumDelegation => {
                set_string(&obj, "type", "GetMinimumDelegation")?;
            }
            StakeInstruction::DeactivateDelinquent => {
                set_string(&obj, "type", "DeactivateDelinquent")?;
            }
            StakeInstruction::Redelegate => {
                set_string(&obj, "type", "Redelegate")?;
            }
            StakeInstruction::MoveStake(lamports) => {
                set_string(&obj, "type", "MoveStake")?;
                set_u64(&obj, "lamports", lamports)?;
            }
            StakeInstruction::MoveLamports(lamports) => {
                set_string(&obj, "type", "MoveLamports")?;
                set_u64(&obj, "lamports", lamports)?;
            }
        }

        Ok(obj)
    }
}

// =============================================================================
// ComputeBudget Instruction WASM Bindings
// =============================================================================

/// WASM namespace for ComputeBudget Program instruction decoding.
#[wasm_bindgen]
pub struct ComputeBudgetInstructionDecoder;

#[wasm_bindgen]
impl ComputeBudgetInstructionDecoder {
    /// The ComputeBudget Program ID as a base58 string.
    #[wasm_bindgen(getter)]
    pub fn program_id() -> String {
        COMPUTE_BUDGET_PROGRAM_ID.to_string()
    }

    /// Check if the given program ID is the ComputeBudget Program.
    #[wasm_bindgen]
    pub fn is_compute_budget_program(program_id: &str) -> bool {
        is_compute_budget_program(program_id)
    }

    /// Decode a ComputeBudget instruction from raw bytes.
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = decode_compute_budget_instruction(data)?;
        let obj = js_sys::Object::new();

        match instr {
            ComputeBudgetInstruction::Unused => {
                set_string(&obj, "type", "Unused")?;
            }
            ComputeBudgetInstruction::RequestHeapFrame(bytes) => {
                set_string(&obj, "type", "RequestHeapFrame")?;
                set_u32(&obj, "bytes", bytes)?;
            }
            ComputeBudgetInstruction::SetComputeUnitLimit(units) => {
                set_string(&obj, "type", "SetComputeUnitLimit")?;
                set_u32(&obj, "units", units)?;
            }
            ComputeBudgetInstruction::SetComputeUnitPrice(micro_lamports) => {
                set_string(&obj, "type", "SetComputeUnitPrice")?;
                set_u64(&obj, "microLamports", micro_lamports)?;
            }
            ComputeBudgetInstruction::SetLoadedAccountsDataSizeLimit(bytes) => {
                set_string(&obj, "type", "SetLoadedAccountsDataSizeLimit")?;
                set_u32(&obj, "bytes", bytes)?;
            }
        }

        Ok(obj)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

fn set_string(obj: &js_sys::Object, key: &str, value: &str) -> Result<(), WasmSolanaError> {
    js_sys::Reflect::set(obj, &key.into(), &value.into())
        .map_err(|_| WasmSolanaError::new(&format!("Failed to set {}", key)))?;
    Ok(())
}

fn set_u32(obj: &js_sys::Object, key: &str, value: u32) -> Result<(), WasmSolanaError> {
    js_sys::Reflect::set(obj, &key.into(), &JsValue::from(value))
        .map_err(|_| WasmSolanaError::new(&format!("Failed to set {}", key)))?;
    Ok(())
}

fn set_u64(obj: &js_sys::Object, key: &str, value: u64) -> Result<(), WasmSolanaError> {
    // Use BigInt for u64 to preserve precision
    js_sys::Reflect::set(obj, &key.into(), &js_sys::BigInt::from(value).into())
        .map_err(|_| WasmSolanaError::new(&format!("Failed to set {}", key)))?;
    Ok(())
}

fn set_i64(obj: &js_sys::Object, key: &str, value: i64) -> Result<(), WasmSolanaError> {
    // Use BigInt for i64 to preserve precision
    js_sys::Reflect::set(obj, &key.into(), &js_sys::BigInt::from(value).into())
        .map_err(|_| WasmSolanaError::new(&format!("Failed to set {}", key)))?;
    Ok(())
}
