//! Intent-based transaction building implementation.
//!
//! Builds transactions directly from BitGo intents without an intermediate
//! instruction abstraction.

use crate::error::WasmSolanaError;
use crate::keypair::{Keypair, KeypairExt};
use crate::transaction::TransactionExt;

use super::types::*;

// Solana SDK types
use solana_sdk::hash::Hash;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::message::Message;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::transaction::Transaction;

// Base64 decoding
use base64::Engine;

// Instruction builders from existing crates
use solana_stake_interface::instruction as stake_ix;
use solana_stake_interface::state::{Authorized, Lockup};
use solana_system_interface::instruction as system_ix;

// Well-known Solana program IDs
// SPL Token Program: https://www.solana-program.com/docs/token
const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
// Associated Token Account Program: https://www.solana-program.com/docs/associated-token-account
const SPL_ATA_PROGRAM_ID: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
// System Program
const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

// Constants
const STAKE_ACCOUNT_SPACE: u64 = 200;
const STAKE_ACCOUNT_RENT: u64 = 2282880; // ~0.00228288 SOL

/// Build a transaction from a BitGo intent.
///
/// # Arguments
/// * `intent_json` - The full intent as JSON (serde_json::Value)
/// * `params` - Build parameters (feePayer, nonce)
///
/// # Returns
/// * `IntentBuildResult` with transaction and generated keypairs
pub fn build_from_intent(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<IntentBuildResult, WasmSolanaError> {
    // Extract intent type
    let intent_type = intent_json
        .get("intentType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WasmSolanaError::new("Missing intentType in intent"))?;

    // Authorize is a special case: the message is pre-built, so we skip nonce/memo
    if intent_type == "authorize" {
        return build_authorize(intent_json);
    }

    // Build based on intent type
    let (instructions, generated_keypairs) = match intent_type {
        "payment" | "goUnstake" => build_payment(intent_json, params)?,
        "stake" => build_stake(intent_json, params)?,
        "unstake" => build_unstake(intent_json, params)?,
        "claim" => build_claim(intent_json, params)?,
        "deactivate" => build_deactivate(intent_json, params)?,
        "delegate" => build_delegate(intent_json, params)?,
        "enableToken" => build_enable_token(intent_json, params)?,
        "closeAssociatedTokenAccount" => build_close_ata(intent_json, params)?,
        "consolidate" => build_consolidate(intent_json, params)?,
        "customTx" => build_custom_tx(intent_json)?,
        _ => {
            return Err(WasmSolanaError::new(&format!(
                "Unsupported intent type: {}",
                intent_type
            )))
        }
    };

    // Add memo if present
    let mut all_instructions = instructions;
    if let Some(memo) = intent_json.get("memo").and_then(|v| v.as_str()) {
        if !memo.is_empty() {
            all_instructions.push(build_memo(memo));
        }
    }

    // Build the transaction
    let mut transaction = build_transaction_from_instructions(all_instructions, params)?;

    // Sign with generated keypairs that are required signers
    for kp in &generated_keypairs {
        let secret_bytes: Vec<u8> = solana_sdk::bs58::decode(&kp.secret_key)
            .into_vec()
            .map_err(|e| WasmSolanaError::new(&format!("Failed to decode secret key: {}", e)))?;
        let keypair = Keypair::from_secret_key_bytes(&secret_bytes)?;
        use solana_signer::Signer;
        let address = keypair.address();
        if transaction.signer_index(&address).is_some() {
            let msg_bytes = transaction.message.serialize();
            let sig = keypair.sign_message(&msg_bytes);
            transaction.add_signature(&address, sig.as_ref())?;
        }
    }

    Ok(IntentBuildResult {
        transaction,
        generated_keypairs,
    })
}

/// Build a Transaction from instructions and params.
fn build_transaction_from_instructions(
    instructions: Vec<Instruction>,
    params: &BuildParams,
) -> Result<Transaction, WasmSolanaError> {
    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new(&format!("Invalid feePayer: {}", params.fee_payer)))?;

    let (blockhash_str, nonce_instruction) = match &params.nonce {
        Nonce::Blockhash { value } => (value.clone(), None),
        Nonce::Durable {
            address,
            authority,
            value,
        } => {
            let nonce_pubkey: Pubkey = address.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonce.address: {}", address))
            })?;
            let authority_pubkey: Pubkey = authority.parse().map_err(|_| {
                WasmSolanaError::new(&format!("Invalid nonce.authority: {}", authority))
            })?;
            (
                value.clone(),
                Some(system_ix::advance_nonce_account(
                    &nonce_pubkey,
                    &authority_pubkey,
                )),
            )
        }
    };

    let blockhash: Hash = blockhash_str
        .parse()
        .map_err(|_| WasmSolanaError::new(&format!("Invalid blockhash: {}", blockhash_str)))?;

    // Build instruction list: nonce advance first (if durable), then intent instructions
    let mut all_instructions = Vec::new();
    if let Some(nonce_ix) = nonce_instruction {
        all_instructions.push(nonce_ix);
    }
    all_instructions.extend(instructions);

    let message = Message::new_with_blockhash(&all_instructions, Some(&fee_payer), &blockhash);
    let tx = Transaction::new_unsigned(message);

    Ok(tx)
}

// =============================================================================
// Intent Builders
// =============================================================================

fn build_payment(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: PaymentIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse payment intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let mut instructions = Vec::new();

    for recipient in intent.recipients {
        let address = recipient
            .address
            .as_ref()
            .map(|a| &a.address)
            .ok_or_else(|| WasmSolanaError::new("Recipient missing address"))?;
        let amount = recipient
            .amount
            .as_ref()
            .map(|a| &a.value)
            .ok_or_else(|| WasmSolanaError::new("Recipient missing amount"))?;

        let to_pubkey: Pubkey = address.parse().map_err(|_| {
            WasmSolanaError::new(&format!("Invalid recipient address: {}", address))
        })?;
        let lamports: u64 = *amount;

        instructions.push(system_ix::transfer(&fee_payer, &to_pubkey, lamports));
    }

    Ok((instructions, vec![]))
}

fn build_stake(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: StakeIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse stake intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let amount: u64 = intent.amount.as_ref().map(|a| a.value).unwrap_or(0);

    // Check if Jito staking
    if intent.staking_type == Some(StakingType::Jito) {
        if let Some(config) = &intent.stake_pool_config {
            return build_jito_stake(config, &fee_payer, &intent.validator_address, amount);
        }
    }

    // Generate stake account keypair (used by both native and Marinade)
    let stake_keypair = Keypair::new();
    let stake_address = stake_keypair.address();
    let stake_pubkey: Pubkey = stake_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Failed to generate stake address"))?;

    let validator_pubkey: Pubkey = intent
        .validator_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid validatorAddress"))?;

    // Marinade staking: CreateAccount + Initialize (no Delegate)
    // Staker authority is the validator, withdrawer is the user
    if intent.staking_type == Some(StakingType::Marinade) {
        let instructions = vec![
            system_ix::create_account(
                &fee_payer,
                &stake_pubkey,
                amount,
                STAKE_ACCOUNT_SPACE,
                &solana_stake_interface::program::ID,
            ),
            stake_ix::initialize(
                &stake_pubkey,
                &Authorized {
                    staker: validator_pubkey,
                    withdrawer: fee_payer,
                },
                &Lockup::default(),
            ),
        ];

        let generated = vec![GeneratedKeypair {
            purpose: KeypairPurpose::StakeAccount,
            address: stake_address,
            secret_key: solana_sdk::bs58::encode(stake_keypair.secret_key_bytes()).into_string(),
        }];

        return Ok((instructions, generated));
    }

    // Native staking: CreateAccount + Initialize + Delegate
    let instructions = vec![
        system_ix::create_account(
            &fee_payer,
            &stake_pubkey,
            amount,
            STAKE_ACCOUNT_SPACE,
            &solana_stake_interface::program::ID,
        ),
        stake_ix::initialize(
            &stake_pubkey,
            &Authorized {
                staker: fee_payer,
                withdrawer: fee_payer,
            },
            &Lockup::default(),
        ),
        stake_ix::delegate_stake(&stake_pubkey, &fee_payer, &validator_pubkey),
    ];

    let generated = vec![GeneratedKeypair {
        purpose: KeypairPurpose::StakeAccount,
        address: stake_address,
        secret_key: solana_sdk::bs58::encode(stake_keypair.secret_key_bytes()).into_string(),
    }];

    Ok((instructions, generated))
}

fn build_jito_stake(
    config: &StakePoolConfig,
    fee_payer: &Pubkey,
    validator_address: &str,
    amount: u64,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    use borsh::BorshSerialize;
    use spl_stake_pool::instruction::StakePoolInstruction;

    let stake_pool_program: Pubkey = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy"
        .parse()
        .unwrap();
    let system_program: Pubkey = SYSTEM_PROGRAM_ID.parse().unwrap();
    let token_program: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().unwrap();
    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID.parse().unwrap();

    // For Jito, validatorAddress is the stake pool address
    let stake_pool: Pubkey = config
        .stake_pool_address
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or(validator_address)
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid stakePoolAddress"))?;

    // Derive withdraw authority PDA if not provided
    let withdraw_authority: Pubkey = if let Some(wa) = &config.withdraw_authority {
        wa.parse()
            .map_err(|_| WasmSolanaError::new("Invalid withdrawAuthority"))?
    } else {
        let (pda, _) =
            Pubkey::find_program_address(&[stake_pool.as_ref(), b"withdraw"], &stake_pool_program);
        pda
    };

    let reserve_stake: Pubkey = config
        .reserve_stake
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing reserveStake"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid reserveStake"))?;

    let pool_mint: Pubkey = config
        .pool_mint
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing poolMint"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid poolMint"))?;

    let manager_fee_account: Pubkey = config
        .manager_fee_account
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing managerFeeAccount"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid managerFeeAccount"))?;

    // Derive destination pool account (user's ATA for pool mint) if not provided
    let destination_pool_account: Pubkey = if let Some(dpa) = &config.destination_pool_account {
        dpa.parse()
            .map_err(|_| WasmSolanaError::new("Invalid destinationPoolAccount"))?
    } else {
        let seeds = &[
            fee_payer.as_ref(),
            token_program.as_ref(),
            pool_mint.as_ref(),
        ];
        let (ata, _) = Pubkey::find_program_address(seeds, &ata_program);
        ata
    };

    // Referral pool account defaults to destination pool account
    let referral_pool_account: Pubkey = if let Some(rpa) = &config.referral_pool_account {
        rpa.parse()
            .map_err(|_| WasmSolanaError::new("Invalid referralPoolAccount"))?
    } else {
        destination_pool_account
    };

    // Build instruction data
    let instruction_data = StakePoolInstruction::DepositSol(amount);
    let mut data = Vec::new();
    instruction_data.serialize(&mut data).unwrap();

    use solana_sdk::instruction::AccountMeta;

    let mut instructions = Vec::new();

    // Optionally create ATA for pool mint (JitoSOL) if requested
    if config.create_associated_token_account == Some(true) {
        instructions.push(Instruction::new_with_bytes(
            ata_program,
            &[],
            vec![
                AccountMeta::new(*fee_payer, true),
                AccountMeta::new(destination_pool_account, false),
                AccountMeta::new_readonly(*fee_payer, false),
                AccountMeta::new_readonly(pool_mint, false),
                AccountMeta::new_readonly(system_program, false),
                AccountMeta::new_readonly(token_program, false),
            ],
        ));
    }

    instructions.push(Instruction::new_with_bytes(
        stake_pool_program,
        &data,
        vec![
            AccountMeta::new(stake_pool, false),
            AccountMeta::new_readonly(withdraw_authority, false),
            AccountMeta::new(reserve_stake, false),
            AccountMeta::new(*fee_payer, true),
            AccountMeta::new(destination_pool_account, false),
            AccountMeta::new(manager_fee_account, false),
            AccountMeta::new(referral_pool_account, false),
            AccountMeta::new(pool_mint, false),
            AccountMeta::new_readonly(system_program, false),
            AccountMeta::new_readonly(token_program, false),
        ],
    ));

    Ok((instructions, vec![]))
}

fn build_unstake(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: UnstakeIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse unstake intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    // Marinade unstake: SystemProgram.transfer to recipient (no stake account involved)
    if intent.staking_type == Some(StakingType::Marinade) {
        return build_marinade_unstake(&intent, &fee_payer);
    }

    // For native/Jito, staking_address is required
    let staking_address = intent
        .staking_address
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing stakingAddress for native/Jito unstake"))?;
    let stake_pubkey: Pubkey = staking_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid stakingAddress"))?;

    // Check if Jito unstaking
    if intent.staking_type == Some(StakingType::Jito) {
        if let Some(config) = &intent.stake_pool_config {
            let amount: u64 = intent.amount.as_ref().map(|a| a.value).unwrap_or(0);
            return build_jito_unstake(config, &fee_payer, &intent.validator_address, amount);
        }
    }

    // Check if partial unstake
    let amount = intent.amount.as_ref().map(|a| a.value);
    let remaining = intent.remaining_staking_amount.as_ref().map(|a| a.value);

    if let (Some(amt_val), Some(rem_val)) = (amount, remaining) {
        if amt_val > 0 && rem_val > 0 {
            return build_partial_unstake(&stake_pubkey, &fee_payer, amt_val);
        }
    }

    // Simple deactivate
    let instructions = vec![stake_ix::deactivate_stake(&stake_pubkey, &fee_payer)];

    Ok((instructions, vec![]))
}

fn build_partial_unstake(
    stake_pubkey: &Pubkey,
    fee_payer: &Pubkey,
    amount: u64,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    use solana_stake_interface::instruction::StakeInstruction;

    // Generate new stake account for the split
    let unstake_keypair = Keypair::new();
    let unstake_address = unstake_keypair.address();
    let unstake_pubkey: Pubkey = unstake_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Failed to generate unstake address"))?;

    let instructions = vec![
        // Transfer rent to new account
        system_ix::transfer(fee_payer, &unstake_pubkey, STAKE_ACCOUNT_RENT),
        // Allocate space
        system_ix::allocate(&unstake_pubkey, STAKE_ACCOUNT_SPACE),
        // Assign to stake program
        system_ix::assign(&unstake_pubkey, &solana_stake_interface::program::ID),
        // Split stake
        Instruction::new_with_bincode(
            solana_stake_interface::program::ID,
            &StakeInstruction::Split(amount),
            vec![
                solana_sdk::instruction::AccountMeta::new(*stake_pubkey, false),
                solana_sdk::instruction::AccountMeta::new(unstake_pubkey, true),
                solana_sdk::instruction::AccountMeta::new_readonly(*fee_payer, true),
            ],
        ),
        // Deactivate split portion
        stake_ix::deactivate_stake(&unstake_pubkey, fee_payer),
    ];

    let generated = vec![GeneratedKeypair {
        purpose: KeypairPurpose::UnstakeAccount,
        address: unstake_address,
        secret_key: solana_sdk::bs58::encode(unstake_keypair.secret_key_bytes()).into_string(),
    }];

    Ok((instructions, generated))
}

fn build_marinade_unstake(
    intent: &UnstakeIntent,
    fee_payer: &Pubkey,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let recipients = intent
        .recipients
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing recipients for Marinade unstake"))?;

    if recipients.is_empty() {
        return Err(WasmSolanaError::new(
            "Recipients array is empty for Marinade unstake",
        ));
    }

    let recipient = &recipients[0];
    let to_address = recipient
        .address
        .as_ref()
        .map(|a| &a.address)
        .ok_or_else(|| WasmSolanaError::new("Recipient missing address for Marinade unstake"))?;
    let amount = recipient
        .amount
        .as_ref()
        .map(|a| a.value)
        .ok_or_else(|| WasmSolanaError::new("Recipient missing amount for Marinade unstake"))?;

    let to_pubkey: Pubkey = to_address
        .parse()
        .map_err(|_| WasmSolanaError::new(&format!("Invalid recipient address: {}", to_address)))?;

    let instructions = vec![system_ix::transfer(fee_payer, &to_pubkey, amount)];

    Ok((instructions, vec![]))
}

fn build_jito_unstake(
    config: &StakePoolConfig,
    fee_payer: &Pubkey,
    validator_address: &Option<String>,
    amount: u64,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    use borsh::BorshSerialize;
    use spl_stake_pool::instruction::StakePoolInstruction;

    let stake_pool_program: Pubkey = "SPoo1Ku8WFXoNDMHPsrGSTSG1Y47rzgn41SLUNakuHy"
        .parse()
        .unwrap();
    let token_program: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().unwrap();
    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID.parse().unwrap();
    let clock_sysvar: Pubkey = solana_sdk::sysvar::clock::ID;

    // Generate destination stake account
    let unstake_keypair = Keypair::new();
    let unstake_address = unstake_keypair.address();
    let unstake_pubkey: Pubkey = unstake_address.parse().unwrap();

    // Generate transfer authority
    let transfer_authority_keypair = Keypair::new();
    let transfer_authority_address = transfer_authority_keypair.address();
    let transfer_authority_pubkey: Pubkey = transfer_authority_address.parse().unwrap();

    // Parse config addresses (with derivation for missing fields)
    let stake_pool: Pubkey = config
        .stake_pool_address
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing stakePoolAddress"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid stakePoolAddress"))?;
    let validator_list: Pubkey = config
        .validator_list
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing validatorList"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid validatorList"))?;

    // Derive withdraw authority PDA if not provided
    let withdraw_authority: Pubkey = if let Some(wa) = &config.withdraw_authority {
        wa.parse()
            .map_err(|_| WasmSolanaError::new("Invalid withdrawAuthority"))?
    } else {
        let (pda, _) =
            Pubkey::find_program_address(&[stake_pool.as_ref(), b"withdraw"], &stake_pool_program);
        pda
    };

    let validator_stake: Pubkey = validator_address
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing validatorAddress"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid validatorAddress"))?;

    let pool_mint: Pubkey = config
        .pool_mint
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing poolMint"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid poolMint"))?;

    // Derive source pool account (user's ATA for pool mint) if not provided
    let source_pool_account: Pubkey = if let Some(spa) = &config.source_pool_account {
        spa.parse()
            .map_err(|_| WasmSolanaError::new("Invalid sourcePoolAccount"))?
    } else {
        let seeds = &[
            fee_payer.as_ref(),
            token_program.as_ref(),
            pool_mint.as_ref(),
        ];
        let (ata, _) = Pubkey::find_program_address(seeds, &ata_program);
        ata
    };

    let manager_fee_account: Pubkey = config
        .manager_fee_account
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing managerFeeAccount"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid managerFeeAccount"))?;

    // 1. Approve: allow transfer_authority to spend pool tokens from user's ATA
    //    SPL Token Approve instruction (index 4): [4u8] + amount as u64 LE
    let mut approve_data = vec![4u8];
    approve_data.extend_from_slice(&amount.to_le_bytes());
    let approve_ix = Instruction::new_with_bytes(
        token_program,
        &approve_data,
        vec![
            AccountMeta::new(source_pool_account, false),
            AccountMeta::new_readonly(transfer_authority_pubkey, false),
            AccountMeta::new_readonly(*fee_payer, true),
        ],
    );

    // 2. CreateAccount: create the destination stake account (makes unstake_pubkey a signer)
    let create_account_ix = system_ix::create_account(
        fee_payer,
        &unstake_pubkey,
        STAKE_ACCOUNT_RENT,
        STAKE_ACCOUNT_SPACE,
        &solana_stake_interface::program::ID,
    );

    // 3. WithdrawStake: withdraw from stake pool into the new stake account
    let withdraw_data = StakePoolInstruction::WithdrawStake(amount);
    let mut data = Vec::new();
    withdraw_data.serialize(&mut data).unwrap();

    use solana_sdk::instruction::AccountMeta;
    let withdraw_stake_ix = Instruction::new_with_bytes(
        stake_pool_program,
        &data,
        vec![
            AccountMeta::new(stake_pool, false),
            AccountMeta::new(validator_list, false),
            AccountMeta::new_readonly(withdraw_authority, false),
            AccountMeta::new(validator_stake, false),
            AccountMeta::new(unstake_pubkey, false),
            AccountMeta::new_readonly(*fee_payer, false),
            AccountMeta::new_readonly(transfer_authority_pubkey, true),
            AccountMeta::new(source_pool_account, false),
            AccountMeta::new(manager_fee_account, false),
            AccountMeta::new(pool_mint, false),
            AccountMeta::new_readonly(clock_sysvar, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(solana_stake_interface::program::ID, false),
        ],
    );

    // 4. Deactivate: deactivate the newly created stake account
    let deactivate_ix = stake_ix::deactivate_stake(&unstake_pubkey, fee_payer);

    let generated = vec![
        GeneratedKeypair {
            purpose: KeypairPurpose::UnstakeAccount,
            address: unstake_address,
            secret_key: solana_sdk::bs58::encode(unstake_keypair.secret_key_bytes()).into_string(),
        },
        GeneratedKeypair {
            purpose: KeypairPurpose::TransferAuthority,
            address: transfer_authority_address,
            secret_key: solana_sdk::bs58::encode(transfer_authority_keypair.secret_key_bytes())
                .into_string(),
        },
    ];

    Ok((
        vec![
            approve_ix,
            create_account_ix,
            withdraw_stake_ix,
            deactivate_ix,
        ],
        generated,
    ))
}

fn build_claim(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: ClaimIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse claim intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let stake_pubkey: Pubkey = intent
        .staking_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid stakingAddress"))?;

    let amount: u64 = intent.amount.as_ref().map(|a| a.value).unwrap_or(0);

    let instructions = vec![stake_ix::withdraw(
        &stake_pubkey,
        &fee_payer,
        &fee_payer,
        amount,
        None,
    )];

    Ok((instructions, vec![]))
}

fn build_deactivate(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: DeactivateIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse deactivate intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    // Get addresses - either single or multiple
    let addresses: Vec<String> = intent
        .staking_addresses
        .unwrap_or_else(|| intent.staking_address.into_iter().collect());

    let mut instructions = Vec::new();
    for addr in addresses {
        let stake_pubkey: Pubkey = addr
            .parse()
            .map_err(|_| WasmSolanaError::new(&format!("Invalid stakingAddress: {}", addr)))?;
        instructions.push(stake_ix::deactivate_stake(&stake_pubkey, &fee_payer));
    }

    Ok((instructions, vec![]))
}

fn build_delegate(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: DelegateIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse delegate intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let validator_pubkey: Pubkey = intent
        .validator_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid validatorAddress"))?;

    // Get addresses - either single or multiple
    let addresses: Vec<String> = intent
        .staking_addresses
        .unwrap_or_else(|| intent.staking_address.into_iter().collect());

    let mut instructions = Vec::new();
    for addr in addresses {
        let stake_pubkey: Pubkey = addr
            .parse()
            .map_err(|_| WasmSolanaError::new(&format!("Invalid stakingAddress: {}", addr)))?;
        instructions.push(stake_ix::delegate_stake(
            &stake_pubkey,
            &fee_payer,
            &validator_pubkey,
        ));
    }

    Ok((instructions, vec![]))
}

fn build_enable_token(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: EnableTokenIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse enableToken intent: {}", e)))?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let owner: Pubkey = intent
        .recipient_address
        .as_ref()
        .map(|a| a.parse())
        .transpose()
        .map_err(|_| WasmSolanaError::new("Invalid recipientAddress"))?
        .unwrap_or(fee_payer);

    // Build list of (mint, token_program) pairs from either array or single format
    let default_program: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().unwrap();
    let token_pairs: Vec<(Pubkey, Pubkey)> = if let Some(ref addresses) = intent.token_addresses {
        // Array format: tokenAddresses + tokenProgramIds
        let program_ids = intent.token_program_ids.as_ref();

        addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let mint: Pubkey = addr.parse().map_err(|_| {
                    WasmSolanaError::new(&format!("Invalid tokenAddress at index {}", i))
                })?;
                let program: Pubkey = program_ids
                    .and_then(|ids| ids.get(i))
                    .map(|p| p.parse().unwrap_or(default_program))
                    .unwrap_or(default_program);
                Ok((mint, program))
            })
            .collect::<Result<Vec<_>, WasmSolanaError>>()?
    } else if let Some(ref addr) = intent.token_address {
        // Single format: tokenAddress + tokenProgramId
        let mint: Pubkey = addr
            .parse()
            .map_err(|_| WasmSolanaError::new("Invalid tokenAddress"))?;
        let token_program: Pubkey = intent
            .token_program_id
            .as_ref()
            .map(|p| p.parse())
            .transpose()
            .map_err(|_| WasmSolanaError::new("Invalid tokenProgramId"))?
            .unwrap_or(default_program);
        vec![(mint, token_program)]
    } else {
        return Err(WasmSolanaError::new(
            "Missing tokenAddress or tokenAddresses",
        ));
    };

    let ata_program: Pubkey = SPL_ATA_PROGRAM_ID.parse().unwrap();
    let system_program: Pubkey = SYSTEM_PROGRAM_ID.parse().unwrap();

    use solana_sdk::instruction::AccountMeta;

    // Build one instruction per token
    let instructions: Vec<Instruction> = token_pairs
        .iter()
        .map(|(mint, token_program)| {
            let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
            let (ata, _bump) = Pubkey::find_program_address(seeds, &ata_program);

            Instruction::new_with_bytes(
                ata_program,
                &[],
                vec![
                    AccountMeta::new(fee_payer, true),
                    AccountMeta::new(ata, false),
                    AccountMeta::new_readonly(owner, false),
                    AccountMeta::new_readonly(*mint, false),
                    AccountMeta::new_readonly(system_program, false),
                    AccountMeta::new_readonly(*token_program, false),
                ],
            )
        })
        .collect();

    Ok((instructions, vec![]))
}

fn build_close_ata(
    intent_json: &serde_json::Value,
    params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: CloseAtaIntent = serde_json::from_value(intent_json.clone()).map_err(|e| {
        WasmSolanaError::new(&format!(
            "Failed to parse closeAssociatedTokenAccount intent: {}",
            e
        ))
    })?;

    let fee_payer: Pubkey = params
        .fee_payer
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid feePayer"))?;

    let account: Pubkey = intent
        .token_account_address
        .as_ref()
        .ok_or_else(|| WasmSolanaError::new("Missing tokenAccountAddress"))?
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid tokenAccountAddress"))?;

    let default_program: Pubkey = SPL_TOKEN_PROGRAM_ID.parse().unwrap();
    let token_program: Pubkey = intent
        .token_program_id
        .as_ref()
        .map(|p| p.parse())
        .transpose()
        .map_err(|_| WasmSolanaError::new("Invalid tokenProgramId"))?
        .unwrap_or(default_program);

    // CloseAccount instruction
    use spl_token::instruction::TokenInstruction;
    let data = TokenInstruction::CloseAccount.pack();

    use solana_sdk::instruction::AccountMeta;
    let instruction = Instruction::new_with_bytes(
        token_program,
        &data,
        vec![
            AccountMeta::new(account, false),
            AccountMeta::new(fee_payer, false),
            AccountMeta::new_readonly(fee_payer, true),
        ],
    );

    Ok((vec![instruction], vec![]))
}

fn build_consolidate(
    intent_json: &serde_json::Value,
    _params: &BuildParams,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: ConsolidateIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse consolidate intent: {}", e)))?;

    // The sender is the child address being consolidated (receiveAddress in the intent)
    let sender: Pubkey = intent
        .receive_address
        .parse()
        .map_err(|_| WasmSolanaError::new("Invalid receiveAddress (sender)"))?;

    let mut instructions = Vec::new();

    for recipient in intent.recipients {
        let address = recipient
            .address
            .as_ref()
            .map(|a| &a.address)
            .ok_or_else(|| WasmSolanaError::new("Recipient missing address"))?;
        let amount = recipient
            .amount
            .as_ref()
            .map(|a| &a.value)
            .ok_or_else(|| WasmSolanaError::new("Recipient missing amount"))?;

        let to_pubkey: Pubkey = address.parse().map_err(|_| {
            WasmSolanaError::new(&format!("Invalid recipient address: {}", address))
        })?;
        let lamports: u64 = *amount;

        // Transfer from sender (child address), not fee_payer
        instructions.push(system_ix::transfer(&sender, &to_pubkey, lamports));
    }

    Ok((instructions, vec![]))
}

/// Build an authorize transaction from a pre-built message.
///
/// The authorize intent contains a `transactionMessage` field with a base64-encoded
/// bincode-serialized Solana Message. We decode and wrap it in a Transaction directly.
/// No nonce advance or memo is added — the message is already complete.
fn build_authorize(intent_json: &serde_json::Value) -> Result<IntentBuildResult, WasmSolanaError> {
    let intent: AuthorizeIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse authorize intent: {}", e)))?;

    // Decode base64 → bytes
    let message_bytes = base64::engine::general_purpose::STANDARD
        .decode(&intent.transaction_message)
        .map_err(|e| {
            WasmSolanaError::new(&format!(
                "Failed to decode transactionMessage base64: {}",
                e
            ))
        })?;

    // Deserialize bytes → Message (bincode format, matching @solana/web3.js)
    let message: Message = bincode::deserialize(&message_bytes).map_err(|e| {
        WasmSolanaError::new(&format!("Failed to deserialize transactionMessage: {}", e))
    })?;

    let transaction = Transaction::new_unsigned(message);

    Ok(IntentBuildResult {
        transaction,
        generated_keypairs: vec![],
    })
}

/// Build a custom transaction from explicit instruction data.
///
/// Reads `solInstructions` from the intent and converts each to a Solana Instruction.
/// Returns through the normal path so nonce advance and memo are added.
fn build_custom_tx(
    intent_json: &serde_json::Value,
) -> Result<(Vec<Instruction>, Vec<GeneratedKeypair>), WasmSolanaError> {
    let intent: CustomTxIntent = serde_json::from_value(intent_json.clone())
        .map_err(|e| WasmSolanaError::new(&format!("Failed to parse customTx intent: {}", e)))?;

    let mut instructions = Vec::new();

    for (i, ix) in intent.sol_instructions.iter().enumerate() {
        let program_id: Pubkey = ix.program_id.parse().map_err(|_| {
            WasmSolanaError::new(&format!(
                "Invalid programId at instruction {}: {}",
                i, ix.program_id
            ))
        })?;

        let mut accounts = Vec::new();
        for (j, key) in ix.keys.iter().enumerate() {
            let pubkey: Pubkey = key.pubkey.parse().map_err(|_| {
                WasmSolanaError::new(&format!(
                    "Invalid pubkey at instruction {} key {}: {}",
                    i, j, key.pubkey
                ))
            })?;
            if key.is_writable {
                if key.is_signer {
                    accounts.push(AccountMeta::new(pubkey, true));
                } else {
                    accounts.push(AccountMeta::new(pubkey, false));
                }
            } else if key.is_signer {
                accounts.push(AccountMeta::new_readonly(pubkey, true));
            } else {
                accounts.push(AccountMeta::new_readonly(pubkey, false));
            }
        }

        let data = base64::engine::general_purpose::STANDARD
            .decode(&ix.data)
            .map_err(|e| {
                WasmSolanaError::new(&format!("Failed to decode instruction {} data: {}", i, e))
            })?;

        instructions.push(Instruction::new_with_bytes(program_id, &data, accounts));
    }

    Ok((instructions, vec![]))
}

/// Build a memo instruction.
fn build_memo(message: &str) -> Instruction {
    let memo_program: Pubkey = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
        .parse()
        .unwrap();
    Instruction::new_with_bytes(memo_program, message.as_bytes(), vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> BuildParams {
        BuildParams {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Blockhash {
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
        }
    }

    #[test]
    fn test_build_payment_intent() {
        let intent = serde_json::json!({
            "intentType": "payment",
            "recipients": [{
                "address": { "address": "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH" },
                "amount": { "value": "1000000" }
            }]
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();
        assert!(result.generated_keypairs.is_empty());
    }

    #[test]
    fn test_build_stake_intent() {
        let intent = serde_json::json!({
            "intentType": "stake",
            "validatorAddress": "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
            "amount": { "value": "1000000000" }
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.generated_keypairs.len(), 1);
        assert_eq!(
            result.generated_keypairs[0].purpose,
            KeypairPurpose::StakeAccount
        );
    }

    #[test]
    fn test_stake_with_durable_nonce_structure() {
        use crate::transaction::TransactionExt;

        let nonce_authority = Keypair::new();
        let params = BuildParams {
            fee_payer: "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB".to_string(),
            nonce: Nonce::Durable {
                address: "27E3MXFvXMUNYeMJeX1pAbERGsJfUbkaZTfgMgpmNN5g".to_string(),
                authority: nonce_authority.address(),
                value: "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4".to_string(),
            },
        };

        let intent = serde_json::json!({
            "intentType": "stake",
            "validatorAddress": "5ZWgXcyqrrNpQHCme5SdC5hCeYb2o3fEJhF7Gok3bTVN",
            "amount": { "value": "1000000000" }
        });

        let result = build_from_intent(&intent, &params).unwrap();

        // Transaction should have 3 required signatures: fee_payer + stake_account + nonce_authority
        assert_eq!(
            result.transaction.num_signatures(),
            3,
            "Durable nonce stake tx should have 3 signature slots"
        );

        // Generated keypair (stake account) should already be signed in Rust
        let zero_sig = [0u8; 64];
        let non_zero_count = result
            .transaction
            .signatures
            .iter()
            .filter(|s| s.as_ref() != &zero_sig)
            .count();
        assert_eq!(
            non_zero_count, 1,
            "build_from_intent should sign generated keypairs in Rust"
        );
    }

    #[test]
    fn test_build_deactivate_intent() {
        let intent = serde_json::json!({
            "intentType": "deactivate",
            "stakingAddress": "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH"
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
    }

    #[test]
    fn test_build_claim_intent() {
        let intent = serde_json::json!({
            "intentType": "claim",
            "stakingAddress": "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH",
            "amount": { "value": "1000000000" }
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
    }

    #[test]
    fn test_build_authorize_intent() {
        // Build a simple message, serialize it with bincode, then base64 encode
        let fee_payer: Pubkey = "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB"
            .parse()
            .unwrap();
        let blockhash: Hash = "GWaQEymC3Z9SHM2gkh8u12xL1zJPMHPCSVR3pSDpEXE4"
            .parse()
            .unwrap();
        let to: Pubkey = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH"
            .parse()
            .unwrap();

        let ix = solana_system_interface::instruction::transfer(&fee_payer, &to, 1_000_000);
        let message = Message::new_with_blockhash(&[ix], Some(&fee_payer), &blockhash);
        let message_bytes = bincode::serialize(&message).unwrap();
        let message_b64 = base64::engine::general_purpose::STANDARD.encode(&message_bytes);

        let intent = serde_json::json!({
            "intentType": "authorize",
            "transactionMessage": message_b64,
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();
        assert!(result.generated_keypairs.is_empty());
        // Verify the transaction message matches the original
        assert_eq!(result.transaction.message, message);
    }

    #[test]
    fn test_build_custom_tx_intent() {
        use base64::Engine;

        let program_id = "11111111111111111111111111111111";
        let fee_payer_str = "DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB";
        let to_str = "FKjSjCqByQRwSzZoMXA7bKnDbJe41YgJTHFFzBeC42bH";

        // Build transfer instruction data manually (SystemInstruction::Transfer = index 2, then u64 LE)
        let mut data = vec![2, 0, 0, 0]; // Transfer discriminant
        data.extend_from_slice(&1_000_000u64.to_le_bytes());
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&data);

        let intent = serde_json::json!({
            "intentType": "customTx",
            "solInstructions": [{
                "programId": program_id,
                "keys": [
                    { "pubkey": fee_payer_str, "isSigner": true, "isWritable": true },
                    { "pubkey": to_str, "isSigner": false, "isWritable": true },
                ],
                "data": data_b64,
            }],
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();
        assert!(result.generated_keypairs.is_empty());
    }

    #[test]
    fn test_build_marinade_stake_intent() {
        // Marinade stake: CreateAccount + Initialize (no Delegate)
        // Staker = validator, Withdrawer = fee_payer
        let intent = serde_json::json!({
            "intentType": "stake",
            "validatorAddress": "CyjoLt3kjqB57K7ewCBHmnHq3UgEj3ak6A7m6EsBsuhA",
            "amount": { "value": "300000" },
            "stakingType": "MARINADE"
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();

        // Should generate a stake account keypair
        assert_eq!(result.generated_keypairs.len(), 1);
        assert_eq!(
            result.generated_keypairs[0].purpose,
            KeypairPurpose::StakeAccount
        );

        // Transaction should have 2 instructions (CreateAccount + Initialize)
        // No Delegate instruction for Marinade
        let msg = result.transaction.message();
        assert_eq!(
            msg.instructions.len(),
            2,
            "Marinade stake should have exactly 2 instructions (CreateAccount + Initialize)"
        );
    }

    #[test]
    fn test_build_marinade_unstake_intent() {
        // Marinade unstake: SystemProgram.transfer to recipient
        let intent = serde_json::json!({
            "intentType": "unstake",
            "stakingType": "MARINADE",
            "amount": { "value": "500000000000" },
            "recipients": [{
                "address": { "address": "opNS8ENpEMWdXcJUgJCsJTDp7arTXayoBEeBUg6UezP" },
                "amount": { "value": "500000000000" }
            }],
            "memo": "{\"PrepareForRevoke\":{\"user\":\"DgT9qyYwYKBRDyDw3EfR12LHQCQjtNrKu2qMsXHuosmB\",\"amount\":\"500000000000\"}}"
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_ok(), "Failed: {:?}", result);
        let result = result.unwrap();

        // No generated keypairs for Marinade unstake
        assert!(result.generated_keypairs.is_empty());

        // Transaction should have 1 transfer + 1 memo = 2 instructions
        let msg = result.transaction.message();
        assert_eq!(
            msg.instructions.len(),
            2,
            "Marinade unstake should have transfer + memo instructions"
        );
    }

    #[test]
    fn test_build_marinade_unstake_requires_recipients() {
        let intent = serde_json::json!({
            "intentType": "unstake",
            "stakingType": "MARINADE",
            "amount": { "value": "500000000000" }
        });

        let result = build_from_intent(&intent, &test_params());
        assert!(result.is_err(), "Should fail without recipients");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Missing recipients"),
            "Error should mention missing recipients"
        );
    }
}
