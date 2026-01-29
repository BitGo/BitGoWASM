//! Program ID constants exported via WASM.
//!
//! These constants allow JavaScript code to reference well-known Solana program IDs
//! without needing to import @solana/web3.js.

use wasm_bindgen::prelude::*;

// Use re-exported constants from instructions module
use crate::instructions::{
    ATA_PROGRAM_ID, COMPUTE_BUDGET_PROGRAM_ID, MEMO_PROGRAM_ID, STAKE_POOL_PROGRAM_ID,
    STAKE_PROGRAM_ID, SYSTEM_PROGRAM_ID, SYSVAR_RECENT_BLOCKHASHES, TOKEN_2022_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
};

/// System Program ID
#[wasm_bindgen]
pub fn system_program_id() -> String {
    SYSTEM_PROGRAM_ID.to_string()
}

/// Stake Program ID
#[wasm_bindgen]
pub fn stake_program_id() -> String {
    STAKE_PROGRAM_ID.to_string()
}

/// Compute Budget Program ID
#[wasm_bindgen]
pub fn compute_budget_program_id() -> String {
    COMPUTE_BUDGET_PROGRAM_ID.to_string()
}

/// Memo Program ID
#[wasm_bindgen]
pub fn memo_program_id() -> String {
    MEMO_PROGRAM_ID.to_string()
}

/// Token Program ID (SPL Token)
#[wasm_bindgen]
pub fn token_program_id() -> String {
    TOKEN_PROGRAM_ID.to_string()
}

/// Token 2022 Program ID
#[wasm_bindgen]
pub fn token_2022_program_id() -> String {
    TOKEN_2022_PROGRAM_ID.to_string()
}

/// Associated Token Account Program ID
#[wasm_bindgen]
pub fn ata_program_id() -> String {
    ATA_PROGRAM_ID.to_string()
}

/// Stake Pool Program ID (Jito)
#[wasm_bindgen]
pub fn stake_pool_program_id() -> String {
    STAKE_POOL_PROGRAM_ID.to_string()
}

/// Sysvar Recent Blockhashes address
/// Reference: https://github.com/solana-labs/solana/blob/v1.18.26/sdk/program/src/sysvar/recent_blockhashes.rs
#[wasm_bindgen]
pub fn sysvar_recent_blockhashes() -> String {
    SYSVAR_RECENT_BLOCKHASHES.to_string()
}

/// Stake account space in bytes (200)
#[wasm_bindgen]
pub fn stake_account_space() -> u64 {
    200
}

/// Nonce account space in bytes (80)
#[wasm_bindgen]
pub fn nonce_account_space() -> u64 {
    80
}

/// Derive the Associated Token Account address for a given wallet and mint.
///
/// This allows JavaScript code to compute ATA addresses without needing @solana/web3.js.
/// The ATA is a PDA derived from seeds: [wallet_address, token_program_id, mint_address]
///
/// @param wallet_address - Owner wallet address (base58)
/// @param mint_address - Token mint address (base58)
/// @param token_program_id - Token program ID (base58), use TOKEN_PROGRAM_ID or TOKEN_2022_PROGRAM_ID
/// @returns The derived ATA address (base58)
#[wasm_bindgen]
pub fn get_associated_token_address(
    wallet_address: &str,
    mint_address: &str,
    token_program_id: &str,
) -> Result<String, JsValue> {
    use solana_sdk::pubkey::Pubkey;

    let wallet: Pubkey = wallet_address
        .parse()
        .map_err(|_| JsValue::from_str(&format!("Invalid wallet address: {}", wallet_address)))?;
    let mint: Pubkey = mint_address
        .parse()
        .map_err(|_| JsValue::from_str(&format!("Invalid mint address: {}", mint_address)))?;
    let token_program: Pubkey = token_program_id.parse().map_err(|_| {
        JsValue::from_str(&format!("Invalid token program ID: {}", token_program_id))
    })?;

    // ATA PDA derivation: seeds = [wallet, token_program, mint], program = ATA_PROGRAM
    let ata_program: Pubkey = ATA_PROGRAM_ID
        .parse()
        .map_err(|_| JsValue::from_str("Failed to parse ATA program ID"))?;

    let seeds = &[wallet.as_ref(), token_program.as_ref(), mint.as_ref()];
    let (ata, _bump) = Pubkey::find_program_address(seeds, &ata_program);

    Ok(ata.to_string())
}

/// Derive the Stake Pool withdraw authority PDA.
///
/// This allows JavaScript code to compute the withdraw authority without needing @solana/spl-stake-pool.
/// The withdraw authority is a PDA derived from seeds: ["withdraw", stake_pool_address]
///
/// @param stake_pool_address - Stake pool address (base58)
/// @returns The derived withdraw authority address (base58)
#[wasm_bindgen]
pub fn find_withdraw_authority_program_address(
    stake_pool_address: &str,
) -> Result<String, JsValue> {
    use solana_sdk::pubkey::Pubkey;

    let stake_pool: Pubkey = stake_pool_address.parse().map_err(|_| {
        JsValue::from_str(&format!(
            "Invalid stake pool address: {}",
            stake_pool_address
        ))
    })?;

    let stake_pool_program: Pubkey = STAKE_POOL_PROGRAM_ID
        .parse()
        .map_err(|_| JsValue::from_str("Failed to parse stake pool program ID"))?;

    let seeds = &[stake_pool.as_ref(), b"withdraw".as_ref()];
    let (withdraw_authority, _bump) = Pubkey::find_program_address(seeds, &stake_pool_program);

    Ok(withdraw_authority.to_string())
}
