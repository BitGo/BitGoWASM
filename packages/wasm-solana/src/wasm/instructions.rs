//! WASM bindings for instruction decoders.
//!
//! Provides JavaScript-friendly interfaces for decoding Solana program instructions.

use crate::error::WasmSolanaError;
use crate::instructions::{
    compute_budget::{ComputeBudgetInstruction, COMPUTE_BUDGET_PROGRAM_ID},
    stake::{StakeInstruction, STAKE_PROGRAM_ID},
    system::{SystemInstruction, SYSTEM_PROGRAM_ID},
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
        SystemInstruction::is_system_program(program_id)
    }

    /// Decode a System instruction from raw bytes.
    ///
    /// Returns a JS object with:
    /// - `type`: string (e.g., "Transfer", "CreateAccount")
    /// - Additional fields depending on the instruction type
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = SystemInstruction::decode(data)?;
        let obj = js_sys::Object::new();

        // Set the instruction type
        let type_str = instr.instruction_type().as_str();
        js_sys::Reflect::set(&obj, &"type".into(), &type_str.into())
            .map_err(|_| WasmSolanaError::new("Failed to set type"))?;

        // Set instruction-specific fields
        match instr {
            SystemInstruction::CreateAccount {
                lamports,
                space,
                owner,
            } => {
                set_u64(&obj, "lamports", lamports)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::Assign { owner } => {
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::Transfer { lamports } => {
                set_u64(&obj, "lamports", lamports)?;
            }
            SystemInstruction::CreateAccountWithSeed {
                base,
                seed,
                lamports,
                space,
                owner,
            } => {
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_u64(&obj, "lamports", lamports)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::AdvanceNonceAccount => {}
            SystemInstruction::WithdrawNonceAccount { lamports } => {
                set_u64(&obj, "lamports", lamports)?;
            }
            SystemInstruction::InitializeNonceAccount { authorized } => {
                set_string(&obj, "authorized", &authorized.to_string())?;
            }
            SystemInstruction::AuthorizeNonceAccount { authorized } => {
                set_string(&obj, "authorized", &authorized.to_string())?;
            }
            SystemInstruction::Allocate { space } => {
                set_u64(&obj, "space", space)?;
            }
            SystemInstruction::AllocateWithSeed {
                base,
                seed,
                space,
                owner,
            } => {
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_u64(&obj, "space", space)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::AssignWithSeed { base, seed, owner } => {
                set_string(&obj, "base", &base.to_string())?;
                set_string(&obj, "seed", &seed)?;
                set_string(&obj, "owner", &owner.to_string())?;
            }
            SystemInstruction::TransferWithSeed {
                lamports,
                from_seed,
                from_owner,
            } => {
                set_u64(&obj, "lamports", lamports)?;
                set_string(&obj, "fromSeed", &from_seed)?;
                set_string(&obj, "fromOwner", &from_owner.to_string())?;
            }
            SystemInstruction::UpgradeNonceAccount => {}
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
        StakeInstruction::is_stake_program(program_id)
    }

    /// Decode a Stake instruction from raw bytes.
    ///
    /// Returns a JS object with:
    /// - `type`: string (e.g., "DelegateStake", "Deactivate")
    /// - Additional fields depending on the instruction type
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = StakeInstruction::decode(data)?;
        let obj = js_sys::Object::new();

        // Set the instruction type
        let type_str = instr.instruction_type().as_str();
        js_sys::Reflect::set(&obj, &"type".into(), &type_str.into())
            .map_err(|_| WasmSolanaError::new("Failed to set type"))?;

        // Set instruction-specific fields
        match instr {
            StakeInstruction::Initialize {
                staker,
                withdrawer,
                lockup,
            } => {
                set_string(&obj, "staker", &staker.to_string())?;
                set_string(&obj, "withdrawer", &withdrawer.to_string())?;
                if let Some(lockup) = lockup {
                    let lockup_obj = js_sys::Object::new();
                    set_i64(&lockup_obj, "unixTimestamp", lockup.unix_timestamp)?;
                    set_u64(&lockup_obj, "epoch", lockup.epoch)?;
                    set_string(&lockup_obj, "custodian", &lockup.custodian.to_string())?;
                    js_sys::Reflect::set(&obj, &"lockup".into(), &lockup_obj)
                        .map_err(|_| WasmSolanaError::new("Failed to set lockup"))?;
                }
            }
            StakeInstruction::Authorize {
                new_authority,
                stake_authorize,
            } => {
                set_string(&obj, "newAuthority", &new_authority.to_string())?;
                set_string(&obj, "stakeAuthorize", stake_authorize.as_str())?;
            }
            StakeInstruction::DelegateStake => {}
            StakeInstruction::Split { lamports } => {
                set_u64(&obj, "lamports", lamports)?;
            }
            StakeInstruction::Withdraw { lamports } => {
                set_u64(&obj, "lamports", lamports)?;
            }
            StakeInstruction::Deactivate => {}
            StakeInstruction::SetLockup {
                unix_timestamp,
                epoch,
                custodian,
            } => {
                if let Some(ts) = unix_timestamp {
                    set_i64(&obj, "unixTimestamp", ts)?;
                }
                if let Some(e) = epoch {
                    set_u64(&obj, "epoch", e)?;
                }
                if let Some(c) = custodian {
                    set_string(&obj, "custodian", &c.to_string())?;
                }
            }
            StakeInstruction::Merge => {}
            StakeInstruction::AuthorizeWithSeed {
                new_authority,
                stake_authorize,
                authority_seed,
                authority_owner,
            } => {
                set_string(&obj, "newAuthority", &new_authority.to_string())?;
                set_string(&obj, "stakeAuthorize", stake_authorize.as_str())?;
                set_string(&obj, "authoritySeed", &authority_seed)?;
                set_string(&obj, "authorityOwner", &authority_owner.to_string())?;
            }
            StakeInstruction::InitializeChecked => {}
            StakeInstruction::AuthorizeChecked { stake_authorize } => {
                set_string(&obj, "stakeAuthorize", stake_authorize.as_str())?;
            }
            StakeInstruction::AuthorizeCheckedWithSeed {
                stake_authorize,
                authority_seed,
                authority_owner,
            } => {
                set_string(&obj, "stakeAuthorize", stake_authorize.as_str())?;
                set_string(&obj, "authoritySeed", &authority_seed)?;
                set_string(&obj, "authorityOwner", &authority_owner.to_string())?;
            }
            StakeInstruction::SetLockupChecked {
                unix_timestamp,
                epoch,
            } => {
                if let Some(ts) = unix_timestamp {
                    set_i64(&obj, "unixTimestamp", ts)?;
                }
                if let Some(e) = epoch {
                    set_u64(&obj, "epoch", e)?;
                }
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
        ComputeBudgetInstruction::is_compute_budget_program(program_id)
    }

    /// Decode a ComputeBudget instruction from raw bytes.
    ///
    /// Returns a JS object with:
    /// - `type`: string (e.g., "SetComputeUnitLimit", "SetComputeUnitPrice")
    /// - Additional fields depending on the instruction type
    #[wasm_bindgen]
    pub fn decode(data: &[u8]) -> Result<js_sys::Object, WasmSolanaError> {
        let instr = ComputeBudgetInstruction::decode(data)?;
        let obj = js_sys::Object::new();

        // Set the instruction type
        let type_str = instr.instruction_type().as_str();
        js_sys::Reflect::set(&obj, &"type".into(), &type_str.into())
            .map_err(|_| WasmSolanaError::new("Failed to set type"))?;

        // Set instruction-specific fields
        match instr {
            ComputeBudgetInstruction::RequestUnitsDeprecated {
                units,
                additional_fee,
            } => {
                set_u32(&obj, "units", units)?;
                set_u32(&obj, "additionalFee", additional_fee)?;
            }
            ComputeBudgetInstruction::RequestHeapFrame { bytes } => {
                set_u32(&obj, "bytes", bytes)?;
            }
            ComputeBudgetInstruction::SetComputeUnitLimit { units } => {
                set_u32(&obj, "units", units)?;
            }
            ComputeBudgetInstruction::SetComputeUnitPrice { micro_lamports } => {
                set_u64(&obj, "microLamports", micro_lamports)?;
            }
            ComputeBudgetInstruction::SetLoadedAccountsDataSizeLimit { bytes } => {
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
