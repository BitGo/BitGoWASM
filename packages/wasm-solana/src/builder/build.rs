//! Transaction building implementation.
//!
//! Uses the Solana SDK for transaction construction and serialization.

use crate::error::WasmSolanaError;

use super::types::{Instruction as IntentInstruction, Nonce, TransactionIntent};

// Use SDK types for building (3.x ecosystem)
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_stake_interface::instruction::StakeInstruction;
use solana_stake_interface::state::{Authorized, Lockup, StakeAuthorize};
use solana_system_interface::instruction::{self as system_ix, SystemInstruction};

/// Well-known program IDs and sysvars
mod program_ids {
    use super::Pubkey;

    pub fn memo_program() -> Pubkey {
        "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
            .parse()
            .unwrap()
    }

    pub fn stake_program() -> Pubkey {
        "Stake11111111111111111111111111111111111111"
            .parse()
            .unwrap()
    }

    pub fn clock_sysvar() -> Pubkey {
        "SysvarC1ock11111111111111111111111111111111"
            .parse()
            .unwrap()
    }

    pub fn rent_sysvar() -> Pubkey {
        "SysvarRent111111111111111111111111111111111"
            .parse()
            .unwrap()
    }

    pub fn stake_history_sysvar() -> Pubkey {
        "SysvarStakeHistory1111111111111111111111111"
            .parse()
            .unwrap()
    }

    pub fn stake_config() -> Pubkey {
        "StakeConfig11111111111111111111111111111111"
            .parse()
            .unwrap()
    }
}

/// Build a transaction from an intent structure.
///
/// Returns the serialized unsigned transaction (wire format).
pub fn build_transaction(intent: TransactionIntent) -> Result<Vec<u8>, WasmSolanaError> {
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
            instructions.push(system_ix::advance_nonce_account(&nonce_pubkey, &authority_pubkey));

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
            let amount: u64 = lamports.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid transfer.lamports: {}", lamports))
            })?;
            Ok(system_ix::transfer(&from_pubkey, &to_pubkey, amount))
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
                WasmSolanaError::new(&format!("Invalid createAccount.newAccount: {}", new_account))
            })?;
            let owner_pubkey: Pubkey = owner.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAccount.owner: {}", owner))
            })?;
            let amount: u64 = lamports.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid createAccount.lamports: {}", lamports))
            })?;
            Ok(system_ix::create_account(
                &from_pubkey,
                &new_pubkey,
                amount,
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
            let owner_pubkey: Pubkey = owner.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid assign.owner: {}", owner))
            })?;
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
            let amount: u64 = lamports.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeWithdraw.lamports: {}", lamports))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid stakeWithdraw.authority: {}", authority))
            })?;
            Ok(build_stake_withdraw(
                &stake_pubkey,
                &recipient_pubkey,
                amount,
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

/// Build a stake initialize instruction.
fn build_stake_initialize(stake: &Pubkey, authorized: &Authorized) -> Instruction {
    Instruction::new_with_bincode(
        program_ids::stake_program(),
        &StakeInstruction::Initialize(*authorized, Lockup::default()),
        vec![
            AccountMeta::new(*stake, false),
            AccountMeta::new_readonly(program_ids::rent_sysvar(), false),
        ],
    )
}

/// Build a stake delegate instruction.
fn build_stake_delegate(stake: &Pubkey, vote: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        program_ids::stake_program(),
        &StakeInstruction::DelegateStake,
        vec![
            AccountMeta::new(*stake, false),
            AccountMeta::new_readonly(*vote, false),
            AccountMeta::new_readonly(program_ids::clock_sysvar(), false),
            AccountMeta::new_readonly(program_ids::stake_history_sysvar(), false),
            AccountMeta::new_readonly(program_ids::stake_config(), false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Build a stake deactivate instruction.
fn build_stake_deactivate(stake: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        program_ids::stake_program(),
        &StakeInstruction::Deactivate,
        vec![
            AccountMeta::new(*stake, false),
            AccountMeta::new_readonly(program_ids::clock_sysvar(), false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Build a stake withdraw instruction.
fn build_stake_withdraw(
    stake: &Pubkey,
    recipient: &Pubkey,
    lamports: u64,
    authority: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        program_ids::stake_program(),
        &StakeInstruction::Withdraw(lamports),
        vec![
            AccountMeta::new(*stake, false),
            AccountMeta::new(*recipient, false),
            AccountMeta::new_readonly(program_ids::clock_sysvar(), false),
            AccountMeta::new_readonly(program_ids::stake_history_sysvar(), false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Build a stake authorize instruction.
fn build_stake_authorize(
    stake: &Pubkey,
    authority: &Pubkey,
    new_authority: &Pubkey,
    stake_authorize: StakeAuthorize,
) -> Instruction {
    Instruction::new_with_bincode(
        program_ids::stake_program(),
        &StakeInstruction::Authorize(*new_authority, stake_authorize),
        vec![
            AccountMeta::new(*stake, false),
            AccountMeta::new_readonly(program_ids::clock_sysvar(), false),
            AccountMeta::new_readonly(*authority, true),
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
                lamports: "1000000".to_string(),
            }],
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
                    lamports: "1000000".to_string(),
                },
                IntentInstruction::Memo {
                    message: "BitGo transfer".to_string(),
                },
            ],
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
                    lamports: "1000000".to_string(),
                },
            ],
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
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build stake delegate: {:?}", result);
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
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build stake deactivate: {:?}", result);
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
                lamports: "1000000".to_string(),
                authority: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            }],
        };

        let result = build_transaction(intent);
        assert!(result.is_ok(), "Failed to build stake withdraw: {:?}", result);
        verify_tx_structure(&result.unwrap(), 1);
    }
}
