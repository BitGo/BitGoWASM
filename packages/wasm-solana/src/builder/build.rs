//! Transaction building implementation.
//!
//! Uses the Solana SDK for transaction construction and serialization.

use crate::error::WasmSolanaError;

use super::types::{Instruction as IntentInstruction, Nonce, TransactionIntent};

// Use SDK types for building (3.x ecosystem)
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::sysvar::clock as clock_sysvar;
use solana_sdk::transaction::Transaction;
// Use stake instruction helpers from the crate (handles sysvars internally)
use solana_stake_interface::instruction as stake_ix;
use solana_stake_interface::state::{Authorized, Lockup, StakeAuthorize};
use solana_system_interface::instruction::{self as system_ix, SystemInstruction};
use spl_stake_pool::instruction::StakePoolInstruction;
// SPL Token instruction encoding - use the crate for data packing to avoid manual byte construction
use spl_token::instruction::TokenInstruction;

/// Well-known program IDs.
///
/// Note: Solana ecosystem is split between SDK 2.x (solana_program) and SDK 3.x (solana_sdk):
/// - SDK 3.x compatible crates export IDs we can use directly (e.g., solana_stake_interface::program::ID)
/// - SPL crates (spl-token, spl-memo, spl-associated-token-account) use solana_program (2.x) types
///   which are incompatible with our solana_sdk (3.x) types at compile time.
///
/// These program IDs are string-parsed because the SPL crates' ID constants return
/// `solana_program::pubkey::Pubkey`, not `solana_sdk::pubkey::Pubkey`. While the bytes are
/// identical, Rust's type system prevents direct usage across the SDK version boundary.
///
/// The values here match the SPL crate declare_id! macros:
/// - spl_memo: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
/// - spl_associated_token_account: "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
/// - spl_token: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
/// - spl_stake_pool: "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy"
mod program_ids {
    use super::Pubkey;

    /// SPL Memo Program v2.
    /// https://github.com/solana-program/memo/blob/main/interface/src/lib.rs#L15
    pub fn memo_program() -> Pubkey {
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
            .parse()
            .unwrap()
    }

    /// Associated Token Account Program.
    /// https://github.com/solana-program/associated-token-account/blob/main/interface/src/lib.rs#L10
    pub fn ata_program() -> Pubkey {
        "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
            .parse()
            .unwrap()
    }

    /// Native System Program.
    /// https://docs.solanalabs.com/runtime/programs#system-program
    /// Used for ATA creation which requires system program in accounts.
    pub fn system_program() -> Pubkey {
        "11111111111111111111111111111111".parse().unwrap()
    }

    /// SPL Token Program.
    /// https://github.com/solana-program/token/blob/main/interface/src/lib.rs#L17
    /// Used for stake pool operations that need token program in accounts.
    pub fn token_program() -> Pubkey {
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
            .parse()
            .unwrap()
    }

    /// SPL Stake Pool Program.
    /// https://github.com/solana-program/stake-pool/blob/main/program/src/lib.rs#L11
    /// Note: spl_stake_pool::id() exists but returns solana_program::pubkey::Pubkey (2.x types),
    /// which is incompatible with solana_sdk::pubkey::Pubkey (3.x types).
    pub fn stake_pool_program() -> Pubkey {
        "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy"
            .parse()
            .unwrap()
    }
}

/// Build a transaction from an intent structure.
///
/// Returns the serialized unsigned transaction (wire format).
///
/// # Transaction Types
///
/// - If `intent.address_lookup_tables` is set, builds a versioned transaction (MessageV0)
/// - Otherwise, builds a legacy transaction
pub fn build_transaction(intent: TransactionIntent) -> Result<Vec<u8>, WasmSolanaError> {
    // Check if this should be a versioned transaction
    if super::versioned::should_build_versioned(&intent) {
        return build_versioned_transaction(intent);
    }

    // Legacy transaction building
    build_legacy_transaction(intent)
}

/// Build a versioned transaction (MessageV0) with Address Lookup Tables.
fn build_versioned_transaction(intent: TransactionIntent) -> Result<Vec<u8>, WasmSolanaError> {
    // Build instructions first (same as legacy)
    let mut instructions: Vec<Instruction> = Vec::new();

    // Handle nonce
    if let Nonce::Durable {
        address, authority, ..
    } = &intent.nonce
    {
        let nonce_pubkey: Pubkey = address
            .parse()
            .map_err(|_| WasmSolanaError::new(&format!("Invalid nonce.address: {}", address)))?;
        let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
            WasmSolanaError::new(&format!("Invalid nonce.authority: {}", authority))
        })?;
        instructions.push(solana_system_interface::instruction::advance_nonce_account(
            &nonce_pubkey,
            &authority_pubkey,
        ));
    }

    // Build each instruction
    for ix in intent.instructions.clone() {
        instructions.push(build_instruction(ix)?);
    }

    // Delegate to versioned module
    super::versioned::build_versioned_transaction(&intent, instructions)
}

/// Build a legacy transaction (original format).
fn build_legacy_transaction(intent: TransactionIntent) -> Result<Vec<u8>, WasmSolanaError> {
    // Parse fee payer
    let fee_payer: Pubkey = intent
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new(&format!("Invalid fee_payer: {}", intent.fee_payer)))?;

    // Build all instructions
    let mut instructions: Vec<Instruction> = Vec::new();

    // Handle nonce - either blockhash or durable nonce
    let blockhash_str = match &intent.nonce {
        Nonce::Blockhash { value } => value.clone(),
        Nonce::Durable {
            address,
            authority,
            value,
        } => {
            // For durable nonce, prepend the nonce advance instruction
            let nonce_pubkey: Pubkey = address.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonce.address: {}", address))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonce.authority: {}", authority))
            })?;
            instructions.push(system_ix::advance_nonce_account(
                &nonce_pubkey,
                &authority_pubkey,
            ));

            // The blockhash is the nonce value stored in the nonce account
            value.clone()
        }
    };

    // Parse blockhash
    let blockhash: Hash = blockhash_str
        .parse()
        .map_err(|_| WasmSolanaError::new(&format!("Invalid blockhash: {}", blockhash_str)))?;

    // Build each instruction
    for ix in intent.instructions {
        instructions.push(build_instruction(ix)?);
    }

    // Create message using SDK (handles account ordering correctly)
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer), &blockhash);

    // Create unsigned transaction
    let mut tx = Transaction::new_unsigned(message);
    tx.message.recent_blockhash = blockhash;

    // Serialize using bincode (standard Solana serialization)
    let tx_bytes =
        bincode::serialize(&tx).map_err(|e| WasmSolanaError::new(&format!("Serialize: {}", e)))?;

    Ok(tx_bytes)
}

/// Build a single instruction from the IntentInstruction enum.
fn build_instruction(ix: IntentInstruction) -> Result<Instruction, WasmSolanaError> {
    match ix {
        // ===== System Program =====
        IntentInstruction::Transfer { from, to, lamports } => {
            let from_pubkey: Pubkey = from
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid transfer.from: {}", from)))?;
            let to_pubkey: Pubkey = to
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid transfer.to: {}", to)))?;
            Ok(system_ix::transfer(&from_pubkey, &to_pubkey, lamports))
        }

        IntentInstruction::CreateAccount {
            from,
            new_account,
            lamports,
            space,
            owner,
        } => {
            let from_pubkey: Pubkey = from.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAccount.from: {}", from))
            })?;
            let new_pubkey: Pubkey = new_account.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid createAccount.newAccount: {}",
                    new_account
                ))
            })?;
            let owner_pubkey: Pubkey = owner.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAccount.owner: {}", owner))
            })?;
            Ok(system_ix::create_account(
                &from_pubkey,
                &new_pubkey,
                lamports,
                space,
                &owner_pubkey,
            ))
        }

        IntentInstruction::NonceAdvance { nonce, authority } => {
            let nonce_pubkey: Pubkey = nonce.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonceAdvance.nonce: {}", nonce))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonceAdvance.authority: {}", authority))
            })?;
            Ok(system_ix::advance_nonce_account(
                &nonce_pubkey,
                &authority_pubkey,
            ))
        }

        IntentInstruction::NonceInitialize { nonce, authority } => {
            // Note: In SDK 3.x, nonce initialization is combined with creation.
            // This creates an InitializeNonceAccount instruction manually.
            let nonce_pubkey: Pubkey = nonce.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonceInitialize.nonce: {}", nonce))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonceInitialize.authority: {}", authority))
            })?;
            Ok(build_nonce_initialize(&nonce_pubkey, &authority_pubkey))
        }

        IntentInstruction::Allocate { account, space } => {
            let account_pubkey: Pubkey = account.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid allocate.account: {}", account))
            })?;
            Ok(system_ix::allocate(&account_pubkey, space))
        }

        IntentInstruction::Assign { account, owner } => {
            let account_pubkey: Pubkey = account.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid assign.account: {}", account))
            })?;
            let owner_pubkey: Pubkey = owner
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid assign.owner: {}", owner)))?;
            Ok(system_ix::assign(&account_pubkey, &owner_pubkey))
        }

        // ===== Memo Program =====
        IntentInstruction::Memo { message } => Ok(build_memo(&message)),

        // ===== Compute Budget Program =====
        IntentInstruction::ComputeBudget {
            unit_limit,
            unit_price,
        } => {
            // Return a single instruction - prefer unit_price if both specified
            // Use SDK's ComputeBudgetInstruction 3.x methods (compatible with solana-sdk 3.x)
            if let Some(price) = unit_price {
                Ok(ComputeBudgetInstruction::set_compute_unit_price(price))
            } else if let Some(limit) = unit_limit {
                Ok(ComputeBudgetInstruction::set_compute_unit_limit(limit))
            } else {
                Err(WasmSolanaError::new(
                    "ComputeBudget instruction requires either unitLimit or unitPrice",
                ))
            }
        }

        // ===== Stake Program =====
        IntentInstruction::StakeInitialize {
            stake,
            staker,
            withdrawer,
        } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeInitialize.stake: {}", stake))
            })?;
            let staker_pubkey: Pubkey = staker.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeInitialize.staker: {}", staker))
            })?;
            let withdrawer_pubkey: Pubkey = withdrawer.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakeInitialize.withdrawer: {}",
                    withdrawer
                ))
            })?;
            Ok(build_stake_initialize(
                &stake_pubkey,
                &Authorized {
                    staker: staker_pubkey,
                    withdrawer: withdrawer_pubkey,
                },
            ))
        }

        IntentInstruction::StakeDelegate {
            stake,
            vote,
            authority,
        } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeDelegate.stake: {}", stake))
            })?;
            let vote_pubkey: Pubkey = vote.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeDelegate.vote: {}", vote))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeDelegate.authority: {}", authority))
            })?;
            Ok(build_stake_delegate(
                &stake_pubkey,
                &vote_pubkey,
                &authority_pubkey,
            ))
        }

        IntentInstruction::StakeDeactivate { stake, authority } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeDeactivate.stake: {}", stake))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeDeactivate.authority: {}", authority))
            })?;
            Ok(build_stake_deactivate(&stake_pubkey, &authority_pubkey))
        }

        IntentInstruction::StakeWithdraw {
            stake,
            recipient,
            lamports,
            authority,
        } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeWithdraw.stake: {}", stake))
            })?;
            let recipient_pubkey: Pubkey = recipient.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeWithdraw.recipient: {}", recipient))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeWithdraw.authority: {}", authority))
            })?;
            Ok(build_stake_withdraw(
                &stake_pubkey,
                &recipient_pubkey,
                lamports,
                &authority_pubkey,
            ))
        }

        IntentInstruction::StakeAuthorize {
            stake,
            new_authority,
            authorize_type,
            authority,
        } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeAuthorize.stake: {}", stake))
            })?;
            let new_authority_pubkey: Pubkey = new_authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakeAuthorize.newAuthority: {}",
                    new_authority
                ))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeAuthorize.authority: {}", authority))
            })?;
            let stake_authorize = match authorize_type.to_lowercase().as_str() {
                "staker" => StakeAuthorize::Staker,
                "withdrawer" => StakeAuthorize::Withdrawer,
                _ => {
                    return Err(WasmSolanaError::new(&format!(
                    "Invalid stakeAuthorize.authorizeType: {} (expected 'staker' or 'withdrawer')",
                    authorize_type
                )))
                }
            };
            Ok(build_stake_authorize(
                &stake_pubkey,
                &authority_pubkey,
                &new_authority_pubkey,
                stake_authorize,
            ))
        }

        IntentInstruction::StakeSplit {
            stake,
            split_stake,
            authority,
            lamports,
        } => {
            let stake_pubkey: Pubkey = stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeSplit.stake: {}", stake))
            })?;
            let split_stake_pubkey: Pubkey = split_stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeSplit.splitStake: {}", split_stake))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeSplit.authority: {}", authority))
            })?;
            Ok(build_stake_split(
                &stake_pubkey,
                &split_stake_pubkey,
                &authority_pubkey,
                lamports,
            ))
        }

        // ===== SPL Token Program =====
        IntentInstruction::TokenTransfer {
            source,
            destination,
            mint,
            amount,
            decimals,
            authority,
            program_id,
        } => {
            let source_pubkey: Pubkey = source.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid tokenTransfer.source: {}", source))
            })?;
            let destination_pubkey: Pubkey = destination.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid tokenTransfer.destination: {}",
                    destination
                ))
            })?;
            let mint_pubkey: Pubkey = mint.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid tokenTransfer.mint: {}", mint))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid tokenTransfer.authority: {}", authority))
            })?;
            let token_program: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid tokenTransfer.programId: {}", program_id))
            })?;
            Ok(build_token_transfer_checked(
                &source_pubkey,
                &mint_pubkey,
                &destination_pubkey,
                &authority_pubkey,
                amount,
                decimals,
                &token_program,
            ))
        }

        IntentInstruction::CreateAssociatedTokenAccount {
            payer,
            owner,
            mint,
            token_program_id,
        } => {
            let payer_pubkey: Pubkey = payer.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAta.payer: {}", payer))
            })?;
            let owner_pubkey: Pubkey = owner.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAta.owner: {}", owner))
            })?;
            let mint_pubkey: Pubkey = mint
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid createAta.mint: {}", mint)))?;
            let token_program: Pubkey = token_program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid createAta.tokenProgramId: {}",
                    token_program_id
                ))
            })?;
            Ok(build_create_ata(
                &payer_pubkey,
                &owner_pubkey,
                &mint_pubkey,
                &token_program,
            ))
        }

        IntentInstruction::CloseAssociatedTokenAccount {
            account,
            destination,
            authority,
            program_id,
        } => {
            let account_pubkey: Pubkey = account.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid closeAta.account: {}", account))
            })?;
            let destination_pubkey: Pubkey = destination.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid closeAta.destination: {}", destination))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid closeAta.authority: {}", authority))
            })?;
            let token_program: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid closeAta.programId: {}", program_id))
            })?;
            Ok(build_close_account(
                &account_pubkey,
                &destination_pubkey,
                &authority_pubkey,
                &token_program,
            ))
        }

        IntentInstruction::MintTo {
            mint,
            destination,
            authority,
            amount,
            program_id,
        } => {
            let mint_pubkey: Pubkey = mint
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid mintTo.mint: {}", mint)))?;
            let destination_pubkey: Pubkey = destination.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid mintTo.destination: {}", destination))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid mintTo.authority: {}", authority))
            })?;
            let token_program: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid mintTo.programId: {}", program_id))
            })?;
            Ok(build_mint_to(
                &mint_pubkey,
                &destination_pubkey,
                &authority_pubkey,
                amount,
                &token_program,
            ))
        }

        IntentInstruction::Burn {
            mint,
            account,
            authority,
            amount,
            program_id,
        } => {
            let mint_pubkey: Pubkey = mint
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid burn.mint: {}", mint)))?;
            let account_pubkey: Pubkey = account
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid burn.account: {}", account)))?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid burn.authority: {}", authority))
            })?;
            let token_program: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid burn.programId: {}", program_id))
            })?;
            Ok(build_burn(
                &account_pubkey,
                &mint_pubkey,
                &authority_pubkey,
                amount,
                &token_program,
            ))
        }

        IntentInstruction::Approve {
            account,
            delegate,
            owner,
            amount,
            program_id,
        } => {
            let account_pubkey: Pubkey = account.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid approve.account: {}", account))
            })?;
            let delegate_pubkey: Pubkey = delegate.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid approve.delegate: {}", delegate))
            })?;
            let owner_pubkey: Pubkey = owner
                .parse()
                .map_err(|_| WasmSolanaError::new(&format!("Invalid approve.owner: {}", owner)))?;
            let token_program: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid approve.programId: {}", program_id))
            })?;
            Ok(build_approve(
                &account_pubkey,
                &delegate_pubkey,
                &owner_pubkey,
                amount,
                &token_program,
            ))
        }

        // ===== Jito Stake Pool =====
        IntentInstruction::StakePoolDepositSol {
            stake_pool,
            withdraw_authority,
            reserve_stake,
            funding_account,
            destination_pool_account,
            manager_fee_account,
            referral_pool_account,
            pool_mint,
            lamports,
        } => {
            let stake_pool_pubkey: Pubkey = stake_pool.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.stakePool: {}",
                    stake_pool
                ))
            })?;
            let withdraw_authority_pubkey: Pubkey = withdraw_authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.withdrawAuthority: {}",
                    withdraw_authority
                ))
            })?;
            let reserve_stake_pubkey: Pubkey = reserve_stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.reserveStake: {}",
                    reserve_stake
                ))
            })?;
            let funding_account_pubkey: Pubkey = funding_account.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.fundingAccount: {}",
                    funding_account
                ))
            })?;
            let destination_pool_account_pubkey: Pubkey =
                destination_pool_account.parse().map_err(|_| {
                    WasmSolanaError::new(&format!(
                        "Invalid stakePoolDepositSol.destinationPoolAccount: {}",
                        destination_pool_account
                    ))
                })?;
            let manager_fee_account_pubkey: Pubkey = manager_fee_account.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.managerFeeAccount: {}",
                    manager_fee_account
                ))
            })?;
            let referral_pool_account_pubkey: Pubkey =
                referral_pool_account.parse().map_err(|_| {
                    WasmSolanaError::new(&format!(
                        "Invalid stakePoolDepositSol.referralPoolAccount: {}",
                        referral_pool_account
                    ))
                })?;
            let pool_mint_pubkey: Pubkey = pool_mint.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolDepositSol.poolMint: {}",
                    pool_mint
                ))
            })?;
            Ok(build_stake_pool_deposit_sol(
                &stake_pool_pubkey,
                &withdraw_authority_pubkey,
                &reserve_stake_pubkey,
                &funding_account_pubkey,
                &destination_pool_account_pubkey,
                &manager_fee_account_pubkey,
                &referral_pool_account_pubkey,
                &pool_mint_pubkey,
                lamports,
            ))
        }

        IntentInstruction::StakePoolWithdrawStake {
            stake_pool,
            validator_list,
            withdraw_authority,
            validator_stake,
            destination_stake,
            destination_stake_authority,
            source_transfer_authority,
            source_pool_account,
            manager_fee_account,
            pool_mint,
            pool_tokens,
        } => {
            let stake_pool_pubkey: Pubkey = stake_pool.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.stakePool: {}",
                    stake_pool
                ))
            })?;
            let validator_list_pubkey: Pubkey = validator_list.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.validatorList: {}",
                    validator_list
                ))
            })?;
            let withdraw_authority_pubkey: Pubkey = withdraw_authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.withdrawAuthority: {}",
                    withdraw_authority
                ))
            })?;
            let validator_stake_pubkey: Pubkey = validator_stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.validatorStake: {}",
                    validator_stake
                ))
            })?;
            let destination_stake_pubkey: Pubkey = destination_stake.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.destinationStake: {}",
                    destination_stake
                ))
            })?;
            let destination_stake_authority_pubkey: Pubkey =
                destination_stake_authority.parse().map_err(|_| {
                    WasmSolanaError::new(&format!(
                        "Invalid stakePoolWithdrawStake.destinationStakeAuthority: {}",
                        destination_stake_authority
                    ))
                })?;
            let source_transfer_authority_pubkey: Pubkey =
                source_transfer_authority.parse().map_err(|_| {
                    WasmSolanaError::new(&format!(
                        "Invalid stakePoolWithdrawStake.sourceTransferAuthority: {}",
                        source_transfer_authority
                    ))
                })?;
            let source_pool_account_pubkey: Pubkey = source_pool_account.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.sourcePoolAccount: {}",
                    source_pool_account
                ))
            })?;
            let manager_fee_account_pubkey: Pubkey = manager_fee_account.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.managerFeeAccount: {}",
                    manager_fee_account
                ))
            })?;
            let pool_mint_pubkey: Pubkey = pool_mint.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid stakePoolWithdrawStake.poolMint: {}",
                    pool_mint
                ))
            })?;

            Ok(build_stake_pool_withdraw_stake(
                &stake_pool_pubkey,
                &validator_list_pubkey,
                &withdraw_authority_pubkey,
                &validator_stake_pubkey,
                &destination_stake_pubkey,
                &destination_stake_authority_pubkey,
                &source_transfer_authority_pubkey,
                &source_pool_account_pubkey,
                &manager_fee_account_pubkey,
                &pool_mint_pubkey,
                pool_tokens,
            ))
        }

        // ===== Custom/Raw Instruction =====
        IntentInstruction::Custom {
            program_id,
            accounts,
            data,
            encoding,
        } => {
            let program_pubkey: Pubkey = program_id.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid custom.programId: {}", program_id))
            })?;

            // Decode the data based on encoding
            let data_bytes = match encoding.as_str() {
                "hex" => hex::decode(&data).map_err(|e| {
                    WasmSolanaError::new(&format!("Invalid hex data in custom instruction: {}", e))
                })?,
                _ => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(&data)
                        .map_err(|e| {
                            WasmSolanaError::new(&format!(
                                "Invalid base64 data in custom instruction: {}",
                                e
                            ))
                        })?
                }
            };

            // Parse account metas
            let account_metas: Vec<AccountMeta> = accounts
                .into_iter()
                .map(|acc| {
                    let pubkey: Pubkey = acc.pubkey.parse().map_err(|_| {
                        WasmSolanaError::new(&format!("Invalid account pubkey: {}", acc.pubkey))
                    })?;
                    Ok(if acc.is_writable {
                        AccountMeta::new(pubkey, acc.is_signer)
                    } else {
                        AccountMeta::new_readonly(pubkey, acc.is_signer)
                    })
                })
                .collect::<Result<Vec<_>, WasmSolanaError>>()?;

            Ok(Instruction::new_with_bytes(
                program_pubkey,
                &data_bytes,
                account_metas,
            ))
        }
    }
}

// ===== Nonce Instruction Builders =====

/// Build an InitializeNonceAccount instruction using the SDK's SystemInstruction enum.
/// SDK 3.x `create_nonce_account` combines create + initialize; we extract just initialize.
fn build_nonce_initialize(nonce: &Pubkey, authority: &Pubkey) -> Instruction {
    // System program ID
    let system_program_id: Pubkey = "11111111111111111111111111111111".parse().unwrap();

    // Sysvars (same addresses as used by SDK)
    let recent_blockhashes_sysvar: Pubkey = "SysvarRecentB1ockHashes11111111111111111111"
        .parse()
        .unwrap();
    let rent_sysvar: Pubkey = "SysvarRent111111111111111111111111111111111"
        .parse()
        .unwrap();

    // Use SDK's SystemInstruction enum with bincode serialization (same as SDK does)
    Instruction::new_with_bincode(
        system_program_id,
        &SystemInstruction::InitializeNonceAccount(*authority),
        vec![
            AccountMeta::new(*nonce, false), // nonce account: writable
            AccountMeta::new_readonly(recent_blockhashes_sysvar, false), // RecentBlockhashes sysvar
            AccountMeta::new_readonly(rent_sysvar, false), // Rent sysvar
        ],
    )
}

// ===== Other Instruction Builders =====

/// Build a memo instruction.
fn build_memo(message: &str) -> Instruction {
    Instruction::new_with_bytes(program_ids::memo_program(), message.as_bytes(), vec![])
}

// ===== Stake Instruction Builders =====
// These use solana_stake_interface helpers which handle sysvars internally.

/// Build a stake initialize instruction.
/// Uses solana_stake_interface::instruction::initialize which handles rent sysvar.
fn build_stake_initialize(stake: &Pubkey, authorized: &Authorized) -> Instruction {
    stake_ix::initialize(stake, authorized, &Lockup::default())
}

/// Build a stake delegate instruction.
/// Uses solana_stake_interface::instruction::delegate_stake which handles
/// clock, stake_history, and stake_config sysvars internally.
fn build_stake_delegate(stake: &Pubkey, vote: &Pubkey, authority: &Pubkey) -> Instruction {
    stake_ix::delegate_stake(stake, authority, vote)
}

/// Build a stake deactivate instruction.
/// Uses solana_stake_interface::instruction::deactivate_stake which handles clock sysvar.
fn build_stake_deactivate(stake: &Pubkey, authority: &Pubkey) -> Instruction {
    stake_ix::deactivate_stake(stake, authority)
}

/// Build a stake withdraw instruction.
/// Uses solana_stake_interface::instruction::withdraw which handles
/// clock and stake_history sysvars internally.
fn build_stake_withdraw(
    stake: &Pubkey,
    recipient: &Pubkey,
    lamports: u64,
    authority: &Pubkey,
) -> Instruction {
    stake_ix::withdraw(stake, authority, recipient, lamports, None)
}

/// Build a stake authorize instruction.
/// Uses solana_stake_interface::instruction::authorize which handles clock sysvar.
fn build_stake_authorize(
    stake: &Pubkey,
    authority: &Pubkey,
    new_authority: &Pubkey,
    stake_authorize: StakeAuthorize,
) -> Instruction {
    stake_ix::authorize(stake, authority, new_authority, stake_authorize, None)
}

/// Build a stake split instruction.
/// Note: We build this manually because stake_ix::split returns Vec<Instruction>
/// (including account creation), but our interface expects a single instruction.
/// Callers should ensure the split_stake account is already created.
fn build_stake_split(
    stake: &Pubkey,
    split_stake: &Pubkey,
    authority: &Pubkey,
    lamports: u64,
) -> Instruction {
    use solana_stake_interface::instruction::StakeInstruction;

    Instruction::new_with_bincode(
        solana_stake_interface::program::ID,
        &StakeInstruction::Split(lamports),
        vec![
            AccountMeta::new(*stake, false),             // source stake account
            AccountMeta::new(*split_stake, false),       // destination stake account
            AccountMeta::new_readonly(*authority, true), // stake authority (signer)
        ],
    )
}

// ===== SPL Token Instruction Builders =====
// These use spl_token::instruction::TokenInstruction for data encoding to avoid manual byte construction.
// This ensures we stay in sync with any changes to the SPL Token program instruction format.

/// Build a TransferChecked instruction for SPL Token.
/// TransferChecked is safer than Transfer as it verifies decimals.
fn build_token_transfer_checked(
    source: &Pubkey,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    decimals: u8,
    token_program: &Pubkey,
) -> Instruction {
    // Use SPL Token crate for instruction data encoding
    let data = TokenInstruction::TransferChecked { amount, decimals }.pack();

    Instruction::new_with_bytes(
        *token_program,
        &data,
        vec![
            AccountMeta::new(*source, false),            // source token account
            AccountMeta::new_readonly(*mint, false),     // mint
            AccountMeta::new(*destination, false),       // destination token account
            AccountMeta::new_readonly(*authority, true), // owner/authority (signer)
        ],
    )
}

/// Build a CreateAssociatedTokenAccount instruction.
fn build_create_ata(
    payer: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    // Derive the ATA address
    let ata = get_associated_token_address(owner, mint, token_program);

    // ATA program create instruction has no data (or discriminator 0)
    Instruction::new_with_bytes(
        program_ids::ata_program(),
        &[],
        vec![
            AccountMeta::new(*payer, true),           // payer (signer)
            AccountMeta::new(ata, false),             // associated token account
            AccountMeta::new_readonly(*owner, false), // wallet owner
            AccountMeta::new_readonly(*mint, false),  // token mint
            AccountMeta::new_readonly(program_ids::system_program(), false), // system program
            AccountMeta::new_readonly(*token_program, false), // token program
        ],
    )
}

/// Build a CloseAccount instruction for SPL Token.
fn build_close_account(
    account: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    // Use SPL Token crate for instruction data encoding
    let data = TokenInstruction::CloseAccount.pack();

    Instruction::new_with_bytes(
        *token_program,
        &data,
        vec![
            AccountMeta::new(*account, false),           // account to close
            AccountMeta::new(*destination, false),       // destination for lamports
            AccountMeta::new_readonly(*authority, true), // owner/authority (signer)
        ],
    )
}

/// Derive the Associated Token Account address.
fn get_associated_token_address(owner: &Pubkey, mint: &Pubkey, token_program: &Pubkey) -> Pubkey {
    // ATA is a PDA with seeds: [owner, token_program, mint]
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    let (ata, _bump) = Pubkey::find_program_address(seeds, &program_ids::ata_program());
    ata
}

/// Build a MintTo instruction for SPL Token.
fn build_mint_to(
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
) -> Instruction {
    // Use SPL Token crate for instruction data encoding
    let data = TokenInstruction::MintTo { amount }.pack();

    Instruction::new_with_bytes(
        *token_program,
        &data,
        vec![
            AccountMeta::new(*mint, false),              // mint
            AccountMeta::new(*destination, false),       // destination token account
            AccountMeta::new_readonly(*authority, true), // mint authority (signer)
        ],
    )
}

/// Build a Burn instruction for SPL Token.
fn build_burn(
    account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
) -> Instruction {
    // Use SPL Token crate for instruction data encoding
    let data = TokenInstruction::Burn { amount }.pack();

    Instruction::new_with_bytes(
        *token_program,
        &data,
        vec![
            AccountMeta::new(*account, false),           // source token account
            AccountMeta::new(*mint, false),              // mint
            AccountMeta::new_readonly(*authority, true), // owner/authority (signer)
        ],
    )
}

/// Build an Approve instruction for SPL Token.
fn build_approve(
    account: &Pubkey,
    delegate: &Pubkey,
    owner: &Pubkey,
    amount: u64,
    token_program: &Pubkey,
) -> Instruction {
    // Use SPL Token crate for instruction data encoding
    let data = TokenInstruction::Approve { amount }.pack();

    Instruction::new_with_bytes(
        *token_program,
        &data,
        vec![
            AccountMeta::new(*account, false),           // token account
            AccountMeta::new_readonly(*delegate, false), // delegate
            AccountMeta::new_readonly(*owner, true),     // owner (signer)
        ],
    )
}

// ===== Jito Stake Pool Instruction Builders =====

/// Build a DepositSol instruction for SPL Stake Pool (Jito).
#[allow(clippy::too_many_arguments)]
fn build_stake_pool_deposit_sol(
    stake_pool: &Pubkey,
    withdraw_authority: &Pubkey,
    reserve_stake: &Pubkey,
    funding_account: &Pubkey,
    destination_pool_account: &Pubkey,
    manager_fee_account: &Pubkey,
    referral_pool_account: &Pubkey,
    pool_mint: &Pubkey,
    lamports: u64,
) -> Instruction {
    use borsh::BorshSerialize;

    // DepositSol instruction data using spl-stake-pool
    let instruction_data = StakePoolInstruction::DepositSol(lamports);
    let mut data = Vec::new();
    instruction_data.serialize(&mut data).unwrap();

    Instruction::new_with_bytes(
        program_ids::stake_pool_program(),
        &data,
        vec![
            AccountMeta::new(*stake_pool, false),
            AccountMeta::new_readonly(*withdraw_authority, false),
            AccountMeta::new(*reserve_stake, false),
            AccountMeta::new(*funding_account, true), // signer
            AccountMeta::new(*destination_pool_account, false),
            AccountMeta::new(*manager_fee_account, false),
            AccountMeta::new(*referral_pool_account, false),
            AccountMeta::new(*pool_mint, false),
            AccountMeta::new_readonly(program_ids::system_program(), false),
            AccountMeta::new_readonly(program_ids::token_program(), false),
        ],
    )
}

/// Build a WithdrawStake instruction for SPL Stake Pool (Jito).
/// Uses solana_stake_interface::program::ID for the stake program.
#[allow(clippy::too_many_arguments)]
fn build_stake_pool_withdraw_stake(
    stake_pool: &Pubkey,
    validator_list: &Pubkey,
    withdraw_authority: &Pubkey,
    validator_stake: &Pubkey,
    destination_stake: &Pubkey,
    destination_stake_authority: &Pubkey,
    source_transfer_authority: &Pubkey,
    source_pool_account: &Pubkey,
    manager_fee_account: &Pubkey,
    pool_mint: &Pubkey,
    pool_tokens: u64,
) -> Instruction {
    use borsh::BorshSerialize;

    // WithdrawStake instruction data using spl-stake-pool
    let instruction_data = StakePoolInstruction::WithdrawStake(pool_tokens);
    let mut data = Vec::new();
    instruction_data.serialize(&mut data).unwrap();

    Instruction::new_with_bytes(
        program_ids::stake_pool_program(),
        &data,
        vec![
            AccountMeta::new(*stake_pool, false),
            AccountMeta::new(*validator_list, false),
            AccountMeta::new_readonly(*withdraw_authority, false),
            AccountMeta::new(*validator_stake, false),
            AccountMeta::new(*destination_stake, false),
            AccountMeta::new_readonly(*destination_stake_authority, false),
            AccountMeta::new_readonly(*source_transfer_authority, true), // signer
            AccountMeta::new(*source_pool_account, false),
            AccountMeta::new(*manager_fee_account, false),
            AccountMeta::new(*pool_mint, false),
            AccountMeta::new_readonly(clock_sysvar::ID, false),
            AccountMeta::new_readonly(program_ids::token_program(), false),
            AccountMeta::new_readonly(solana_stake_interface::program::ID, false),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Use our 2.x parsing Transaction for verification (different type than SDK Transaction)
    fn verify_tx_structure(tx_bytes: &[u8], expected_instructions: usize) {
        use crate::transaction::TransactionExt;
        let tx = crate::Transaction::from_bytes(tx_bytes).unwrap();
        assert_eq!(tx.num_instructions(), expected_instructions);
    }

    #[test]
    fn test_build_simple_transfer() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::Transfer {
                from: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                to: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                lamports: 1000000,
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build transaction: {:?}", result);

        let tx_bytes = result.unwrap();
        assert!(!tx_bytes.is_empty());
        verify_tx_structure(&tx_bytes, 1);
    }

    #[test]
    fn test_build_with_memo() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![
                IntentInstruction::Transfer {
                    from: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                    to: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                    lamports: 1000000,
                },
                IntentInstruction::Memo {
                    message: "BitGo transfer".to_string(),
                },
            ],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok());

        let tx_bytes = result.unwrap();
        verify_tx_structure(&tx_bytes, 2);
    }

    #[test]
    fn test_build_with_compute_budget() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![
                IntentInstruction::ComputeBudget {
                    unit_limit: Some(200000),
                    unit_price: None,
                },
                IntentInstruction::Transfer {
                    from: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                    to: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                    lamports: 1000000,
                },
            ],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_pubkey() {
        let intent = TransactionIntent {
            fee_payer: "invalid".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid"));
    }

    #[test]
    fn test_build_stake_delegate() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakeDelegate {
                stake: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                vote: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build stake delegate: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_stake_deactivate() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakeDeactivate {
                stake: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build stake deactivate: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_stake_withdraw() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakeWithdraw {
                stake: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                recipient: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                lamports: 1000000,
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build stake withdraw: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_token_transfer() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::TokenTransfer {
                source: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                destination: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(), // USDC mint
                amount: 1000000,
                decimals: 6,
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build token transfer: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_create_ata() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::CreateAssociatedTokenAccount {
                payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                owner: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(), // USDC mint
                token_program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build create ATA: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_close_ata() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::CloseAssociatedTokenAccount {
                account: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                destination: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build close ATA: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_mint_to() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::MintTo {
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                destination: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                amount: 1000000,
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build mint to: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_burn() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::Burn {
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                account: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                amount: 1000000,
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build burn: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_approve() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::Approve {
                account: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                delegate: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                owner: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                amount: 1000000,
                program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build approve: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_stake_pool_deposit_sol() {
        // Jito stake pool addresses (testnet-like)
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakePoolDepositSol {
                stake_pool: "Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb".to_string(),
                withdraw_authority: "6iQKfEyhr3bZMotVkW6beNZz5CPAkiwvgV2CTje9pVSS".to_string(),
                reserve_stake: "BgKUXdS4Wy6Vdgp1jwT2dz5ZgxPG94aPL77dQscSPGmc".to_string(),
                funding_account: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                destination_pool_account: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH"
                    .to_string(),
                manager_fee_account: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                referral_pool_account: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                pool_mint: "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn".to_string(),
                lamports: 1000000000, // 1 SOL
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build stake pool deposit sol: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_stake_pool_withdraw_stake() {
        // Jito stake pool addresses (testnet-like)
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakePoolWithdrawStake {
                stake_pool: "Jito4APyf642JPZPx3hGc6WWJ8zPKtRbRs4P815Awbb".to_string(),
                validator_list: "3R3nGZpQs2aZo5FDQvd2MUQ5R5E9g7NvHQaxpLPYA8r2".to_string(),
                withdraw_authority: "6iQKfEyhr3bZMotVkW6beNZz5CPAkiwvgV2CTje9pVSS".to_string(),
                validator_stake: "BgKUXdS4Wy6Vdgp1jwT2dz5ZgxPG94aPL77dQscSPGmc".to_string(),
                destination_stake: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                destination_stake_authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB"
                    .to_string(),
                source_transfer_authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB"
                    .to_string(),
                source_pool_account: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                manager_fee_account: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                pool_mint: "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn".to_string(),
                pool_tokens: 1000000000, // 1 JitoSOL
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(
            result.is_ok(),
            "Failed to build stake pool withdraw stake: {:?}",
            result
        );
        verify_tx_structure(&result.unwrap(), 1);
    }

    #[test]
    fn test_build_stake_split() {
        let intent = TransactionIntent {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
            instructions: vec![IntentInstruction::StakeSplit {
                stake: "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH".to_string(),
                split_stake: "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
                lamports: 500000000, // 0.5 SOL
            }],
            address_lookup_tables: None,
            static_account_keys: None,
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build stake split: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }
}
