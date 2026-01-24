//! Instruction decoding using official Solana interface crates.

use super::types::*;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_stake_interface::instruction::StakeInstruction;
use solana_system_interface::instruction::SystemInstruction;
use spl_stake_pool::instruction::StakePoolInstruction;

/// Context for decoding an instruction - provides account addresses.
pub struct InstructionContext<'a> {
    pub program_id: &'a str,
    pub accounts: &'a [String],
    pub data: &'a [u8],
}

/// Decode a single instruction into a ParsedInstruction.
pub fn decode_instruction(ctx: InstructionContext) -> ParsedInstruction {
    match ctx.program_id {
        SYSTEM_PROGRAM_ID => decode_system_instruction(ctx),
        STAKE_PROGRAM_ID => decode_stake_instruction(ctx),
        COMPUTE_BUDGET_PROGRAM_ID => decode_compute_budget_instruction(ctx),
        MEMO_PROGRAM_ID => decode_memo_instruction(ctx),
        TOKEN_PROGRAM_ID | TOKEN_2022_PROGRAM_ID => decode_token_instruction(ctx),
        ATA_PROGRAM_ID => decode_ata_instruction(ctx),
        STAKE_POOL_PROGRAM_ID => decode_stake_pool_instruction(ctx),
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// System Program Decoding
// =============================================================================

fn decode_system_instruction(ctx: InstructionContext) -> ParsedInstruction {
    let Ok(instr) = bincode::deserialize::<SystemInstruction>(ctx.data) else {
        return make_unknown(ctx);
    };

    match instr {
        SystemInstruction::Transfer { lamports } => {
            if ctx.accounts.len() >= 2 {
                ParsedInstruction::Transfer(TransferParams {
                    from_address: ctx.accounts[0].clone(),
                    to_address: ctx.accounts[1].clone(),
                    amount: lamports,
                })
            } else {
                make_unknown(ctx)
            }
        }
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            if ctx.accounts.len() >= 2 {
                ParsedInstruction::CreateAccount(CreateAccountParams {
                    from_address: ctx.accounts[0].clone(),
                    new_address: ctx.accounts[1].clone(),
                    amount: lamports,
                    space,
                    owner: owner.to_string(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        SystemInstruction::AdvanceNonceAccount => {
            if ctx.accounts.len() >= 3 {
                ParsedInstruction::NonceAdvance(NonceAdvanceParams {
                    wallet_nonce_address: ctx.accounts[0].clone(),
                    auth_wallet_address: ctx.accounts[2].clone(), // authority is at index 2
                })
            } else {
                make_unknown(ctx)
            }
        }
        SystemInstruction::InitializeNonceAccount(authority) => {
            // This is part of CreateNonceAccount flow - parsed as intermediate NonceInitialize
            // Will be combined with CreateAccount in post-processing
            // Accounts: [0] nonce, [1] recent_blockhashes_sysvar, [2] rent_sysvar
            if ctx.accounts.len() >= 1 {
                ParsedInstruction::NonceInitialize(NonceInitializeParams {
                    nonce_address: ctx.accounts[0].clone(),
                    auth_address: authority.to_string(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// Stake Program Decoding
// =============================================================================

fn decode_stake_instruction(ctx: InstructionContext) -> ParsedInstruction {
    let Ok(instr) = bincode::deserialize::<StakeInstruction>(ctx.data) else {
        return make_unknown(ctx);
    };

    match instr {
        StakeInstruction::DelegateStake => {
            // Accounts: [0] stake, [1] vote, [2] clock, [3] stake_history, [4] config, [5] authority
            if ctx.accounts.len() >= 6 {
                ParsedInstruction::StakingDelegate(StakingDelegateParams {
                    staking_address: ctx.accounts[0].clone(),
                    from_address: ctx.accounts[5].clone(), // authority
                    validator: ctx.accounts[1].clone(),    // vote account
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::Deactivate => {
            // Accounts: [0] stake, [1] clock, [2] authority
            if ctx.accounts.len() >= 3 {
                ParsedInstruction::StakingDeactivate(StakingDeactivateParams {
                    staking_address: ctx.accounts[0].clone(),
                    from_address: ctx.accounts[2].clone(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::Withdraw(lamports) => {
            // Accounts: [0] stake, [1] recipient, [2] clock, [3] stake_history, [4] authority
            if ctx.accounts.len() >= 5 {
                ParsedInstruction::StakingWithdraw(StakingWithdrawParams {
                    staking_address: ctx.accounts[0].clone(),
                    from_address: ctx.accounts[4].clone(),
                    amount: lamports,
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::Initialize(authorized, _lockup) => {
            // This is part of StakingActivate flow - parsed as intermediate StakeInitialize
            // Will be combined with CreateAccount + DelegateStake in post-processing
            // Accounts: [0] stake, [1] rent_sysvar
            if ctx.accounts.len() >= 1 {
                ParsedInstruction::StakeInitialize(StakeInitializeParams {
                    staking_address: ctx.accounts[0].clone(),
                    staker: authorized.staker.to_string(),
                    withdrawer: authorized.withdrawer.to_string(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::Authorize(new_authority, stake_authorize) => {
            // Accounts: [0] stake, [1] clock, [2] authority, [3] optional custodian
            if ctx.accounts.len() >= 3 {
                let auth_type = match stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                let custodian = if ctx.accounts.len() >= 4 {
                    Some(ctx.accounts[3].clone())
                } else {
                    None
                };
                ParsedInstruction::StakingAuthorize(StakingAuthorizeParams {
                    staking_address: ctx.accounts[0].clone(),
                    old_authorize_address: ctx.accounts[2].clone(),
                    new_authorize_address: new_authority.to_string(),
                    authorize_type: auth_type.to_string(),
                    custodian_address: custodian,
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            // Accounts: [0] stake, [1] clock, [2] authority, [3] new_authority (signer), [4] optional custodian
            if ctx.accounts.len() >= 4 {
                let auth_type = match stake_authorize {
                    solana_stake_interface::state::StakeAuthorize::Staker => "Staker",
                    solana_stake_interface::state::StakeAuthorize::Withdrawer => "Withdrawer",
                };
                let custodian = if ctx.accounts.len() >= 5 {
                    Some(ctx.accounts[4].clone())
                } else {
                    None
                };
                ParsedInstruction::StakingAuthorize(StakingAuthorizeParams {
                    staking_address: ctx.accounts[0].clone(),
                    old_authorize_address: ctx.accounts[2].clone(),
                    new_authorize_address: ctx.accounts[3].clone(),
                    authorize_type: auth_type.to_string(),
                    custodian_address: custodian,
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakeInstruction::Split(_lamports) => {
            // Accounts: [0] source stake, [1] dest stake, [2] authority
            if ctx.accounts.len() >= 3 {
                ParsedInstruction::StakingDeactivate(StakingDeactivateParams {
                    staking_address: ctx.accounts[0].clone(),
                    from_address: ctx.accounts[2].clone(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// ComputeBudget Program Decoding
// =============================================================================

fn decode_compute_budget_instruction(ctx: InstructionContext) -> ParsedInstruction {
    use borsh::BorshDeserialize;

    let Ok(instr) = ComputeBudgetInstruction::try_from_slice(ctx.data) else {
        return make_unknown(ctx);
    };

    match instr {
        ComputeBudgetInstruction::SetComputeUnitLimit(units) => {
            ParsedInstruction::SetComputeUnitLimit(SetComputeUnitLimitParams { units })
        }
        ComputeBudgetInstruction::SetComputeUnitPrice(micro_lamports) => {
            ParsedInstruction::SetPriorityFee(SetPriorityFeeParams {
                fee: micro_lamports,
            })
        }
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// Memo Program Decoding
// =============================================================================

fn decode_memo_instruction(ctx: InstructionContext) -> ParsedInstruction {
    // Memo data is just UTF-8 text
    if let Ok(memo) = std::str::from_utf8(ctx.data) {
        ParsedInstruction::Memo(MemoParams {
            memo: memo.to_string(),
        })
    } else {
        make_unknown(ctx)
    }
}

// =============================================================================
// Token Program Decoding (basic)
// =============================================================================

fn decode_token_instruction(ctx: InstructionContext) -> ParsedInstruction {
    // SPL Token instruction format: first byte is discriminator
    if ctx.data.is_empty() {
        return make_unknown(ctx);
    }

    let discriminator = ctx.data[0];

    match discriminator {
        // TransferChecked = 12
        12 => {
            // Accounts: [0] source, [1] mint, [2] destination, [3] owner/delegate
            if ctx.accounts.len() >= 4 {
                // Amount is a u64 at bytes 1-8, decimals at byte 9
                let amount = if ctx.data.len() >= 9 {
                    u64::from_le_bytes(ctx.data[1..9].try_into().unwrap_or([0; 8]))
                } else {
                    0
                };
                let decimals = if ctx.data.len() >= 10 {
                    Some(ctx.data[9])
                } else {
                    None
                };
                ParsedInstruction::TokenTransfer(TokenTransferParams {
                    from_address: ctx.accounts[3].clone(), // owner
                    to_address: ctx.accounts[2].clone(),   // destination
                    amount,
                    source_address: ctx.accounts[0].clone(),
                    token_address: Some(ctx.accounts[1].clone()), // mint
                    program_id: ctx.program_id.to_string(),
                    decimal_places: decimals,
                })
            } else {
                make_unknown(ctx)
            }
        }
        // Transfer = 3
        3 => {
            // Accounts: [0] source, [1] destination, [2] owner/delegate
            if ctx.accounts.len() >= 3 {
                let amount = if ctx.data.len() >= 9 {
                    u64::from_le_bytes(ctx.data[1..9].try_into().unwrap_or([0; 8]))
                } else {
                    0
                };
                ParsedInstruction::TokenTransfer(TokenTransferParams {
                    from_address: ctx.accounts[2].clone(),
                    to_address: ctx.accounts[1].clone(),
                    amount,
                    source_address: ctx.accounts[0].clone(),
                    token_address: None,
                    program_id: ctx.program_id.to_string(),
                    decimal_places: None, // Not available in basic Transfer
                })
            } else {
                make_unknown(ctx)
            }
        }
        // CloseAccount = 9
        9 => {
            // Accounts: [0] account, [1] destination, [2] owner
            if ctx.accounts.len() >= 3 {
                ParsedInstruction::CloseAssociatedTokenAccount(CloseAtaParams {
                    account_address: ctx.accounts[0].clone(),
                    destination_address: ctx.accounts[1].clone(),
                    authority_address: ctx.accounts[2].clone(),
                })
            } else {
                make_unknown(ctx)
            }
        }
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// ATA Program Decoding
// =============================================================================

fn decode_ata_instruction(ctx: InstructionContext) -> ParsedInstruction {
    // ATA program: Create instruction has no data (discriminator 0 or empty)
    // Accounts: [0] payer, [1] ata, [2] owner, [3] mint, [4] system, [5] token
    if ctx.accounts.len() >= 4 {
        ParsedInstruction::CreateAssociatedTokenAccount(CreateAtaParams {
            payer_address: ctx.accounts[0].clone(),
            ata_address: ctx.accounts[1].clone(),
            owner_address: ctx.accounts[2].clone(),
            mint_address: ctx.accounts[3].clone(),
            program_id: ctx.program_id.to_string(),
        })
    } else {
        make_unknown(ctx)
    }
}

// =============================================================================
// Stake Pool Program Decoding (Jito liquid staking)
// =============================================================================

fn decode_stake_pool_instruction(ctx: InstructionContext) -> ParsedInstruction {
    use borsh::BorshDeserialize;

    let Ok(instr) = StakePoolInstruction::try_from_slice(ctx.data) else {
        return make_unknown(ctx);
    };

    match instr {
        StakePoolInstruction::DepositSol(lamports) => {
            // DepositSol: deposit SOL into stake pool, receive pool tokens
            // Accounts:
            //   [0] stakePool
            //   [1] withdrawAuthority
            //   [2] reserveStake
            //   [3] fundingAccount (signer)
            //   [4] destinationPoolAccount
            //   [5] managerFeeAccount
            //   [6] referralPoolAccount
            //   [7] poolMint
            //   [8] systemProgram
            //   [9] tokenProgram
            //   [10] depositAuthority (optional)
            if ctx.accounts.len() >= 8 {
                ParsedInstruction::StakePoolDepositSol(StakePoolDepositSolParams {
                    stake_pool: ctx.accounts[0].clone(),
                    withdraw_authority: ctx.accounts[1].clone(),
                    reserve_stake: ctx.accounts[2].clone(),
                    funding_account: ctx.accounts[3].clone(),
                    destination_pool_account: ctx.accounts[4].clone(),
                    manager_fee_account: ctx.accounts[5].clone(),
                    referral_pool_account: ctx.accounts[6].clone(),
                    pool_mint: ctx.accounts[7].clone(),
                    lamports,
                })
            } else {
                make_unknown(ctx)
            }
        }
        StakePoolInstruction::WithdrawStake(pool_tokens) => {
            // WithdrawStake: withdraw stake from pool by burning pool tokens
            // Accounts:
            //   [0] stakePool
            //   [1] validatorList
            //   [2] withdrawAuthority
            //   [3] validatorStake
            //   [4] destinationStake
            //   [5] destinationStakeAuthority
            //   [6] sourceTransferAuthority (signer)
            //   [7] sourcePoolAccount
            //   [8] managerFeeAccount
            //   [9] poolMint
            //   [10] clockSysvar
            //   [11] tokenProgram
            //   [12] stakeProgram
            if ctx.accounts.len() >= 10 {
                ParsedInstruction::StakePoolWithdrawStake(StakePoolWithdrawStakeParams {
                    stake_pool: ctx.accounts[0].clone(),
                    validator_list: ctx.accounts[1].clone(),
                    withdraw_authority: ctx.accounts[2].clone(),
                    validator_stake: ctx.accounts[3].clone(),
                    destination_stake: ctx.accounts[4].clone(),
                    destination_stake_authority: ctx.accounts[5].clone(),
                    source_transfer_authority: ctx.accounts[6].clone(),
                    source_pool_account: ctx.accounts[7].clone(),
                    manager_fee_account: ctx.accounts[8].clone(),
                    pool_mint: ctx.accounts[9].clone(),
                    pool_tokens,
                })
            } else {
                make_unknown(ctx)
            }
        }
        _ => make_unknown(ctx),
    }
}

// =============================================================================
// Fallback
// =============================================================================

fn make_unknown(ctx: InstructionContext) -> ParsedInstruction {
    ParsedInstruction::Unknown(UnknownInstructionParams {
        program_id: ctx.program_id.to_string(),
        accounts: ctx
            .accounts
            .iter()
            .map(|a| AccountMeta {
                pubkey: a.clone(),
                is_signer: false,   // We don't have this info at decode time
                is_writable: false, // We don't have this info at decode time
            })
            .collect(),
        data: ctx.data.to_vec(),
    })
}
