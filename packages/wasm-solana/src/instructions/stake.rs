//! Stake Program instruction decoder.
//!
//! The Stake Program handles Solana staking operations:
//! - Creating and initializing stake accounts
//! - Delegating stake to validators
//! - Deactivating and withdrawing stake
//!
//! # Wire Format
//!
//! Stake instructions start with a 4-byte little-endian discriminator:
//! - 0: Initialize
//! - 1: Authorize
//! - 2: DelegateStake
//! - 3: Split
//! - 4: Withdraw
//! - 5: Deactivate
//! - 6: SetLockup
//! - 7: Merge
//! - 8: AuthorizeWithSeed
//! - 9: InitializeChecked
//! - 10: AuthorizeChecked
//! - 11: AuthorizeCheckedWithSeed
//! - 12: SetLockupChecked

use crate::error::WasmSolanaError;
use crate::Pubkey;

/// Stake Program ID
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";

/// Authorization types for stake accounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeAuthorize {
    /// Authority to delegate/activate stake.
    Staker,
    /// Authority to withdraw stake.
    Withdrawer,
}

impl StakeAuthorize {
    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Staker => "Staker",
            Self::Withdrawer => "Withdrawer",
        }
    }
}

/// Stake instruction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StakeInstructionType {
    Initialize,
    Authorize,
    DelegateStake,
    Split,
    Withdraw,
    Deactivate,
    SetLockup,
    Merge,
    AuthorizeWithSeed,
    InitializeChecked,
    AuthorizeChecked,
    AuthorizeCheckedWithSeed,
    SetLockupChecked,
}

impl StakeInstructionType {
    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initialize => "Initialize",
            Self::Authorize => "Authorize",
            Self::DelegateStake => "DelegateStake",
            Self::Split => "Split",
            Self::Withdraw => "Withdraw",
            Self::Deactivate => "Deactivate",
            Self::SetLockup => "SetLockup",
            Self::Merge => "Merge",
            Self::AuthorizeWithSeed => "AuthorizeWithSeed",
            Self::InitializeChecked => "InitializeChecked",
            Self::AuthorizeChecked => "AuthorizeChecked",
            Self::AuthorizeCheckedWithSeed => "AuthorizeCheckedWithSeed",
            Self::SetLockupChecked => "SetLockupChecked",
        }
    }
}

/// Lockup configuration for stake accounts.
#[derive(Debug, Clone)]
pub struct Lockup {
    /// Unix timestamp until which the stake is locked.
    pub unix_timestamp: i64,
    /// Epoch until which the stake is locked.
    pub epoch: u64,
    /// Custodian who can modify the lockup.
    pub custodian: Pubkey,
}

/// Decoded Stake Program instruction.
#[derive(Debug, Clone)]
pub enum StakeInstruction {
    /// Initialize a stake account.
    /// Accounts: [stake_account, rent_sysvar]
    Initialize {
        /// The staker authority.
        staker: Pubkey,
        /// The withdrawer authority.
        withdrawer: Pubkey,
        /// Optional lockup configuration.
        lockup: Option<Lockup>,
    },

    /// Authorize a new key for the stake account.
    /// Accounts: [stake_account, clock_sysvar, authority, (optional) lockup_authority]
    Authorize {
        /// The new authority pubkey.
        new_authority: Pubkey,
        /// The type of authority to change.
        stake_authorize: StakeAuthorize,
    },

    /// Delegate stake to a validator.
    /// Accounts: [stake_account, vote_account, clock_sysvar, stake_history_sysvar, config_account, stake_authority]
    DelegateStake,

    /// Split stake into a new stake account.
    /// Accounts: [stake_account, new_stake_account, stake_authority]
    Split {
        /// Lamports to move to new stake account.
        lamports: u64,
    },

    /// Withdraw from a stake account.
    /// Accounts: [stake_account, to_account, clock_sysvar, stake_history_sysvar, withdraw_authority, (optional) lockup_authority]
    Withdraw {
        /// Lamports to withdraw.
        lamports: u64,
    },

    /// Deactivate a stake account.
    /// Accounts: [stake_account, clock_sysvar, stake_authority]
    Deactivate,

    /// Set lockup parameters.
    /// Accounts: [stake_account, lockup_authority]
    SetLockup {
        /// Unix timestamp (None to leave unchanged).
        unix_timestamp: Option<i64>,
        /// Epoch (None to leave unchanged).
        epoch: Option<u64>,
        /// Custodian (None to leave unchanged).
        custodian: Option<Pubkey>,
    },

    /// Merge two stake accounts.
    /// Accounts: [destination_stake, source_stake, clock_sysvar, stake_history_sysvar, stake_authority]
    Merge,

    /// Authorize with seed.
    /// Accounts: [stake_account, authority_base, clock_sysvar]
    AuthorizeWithSeed {
        /// New authority pubkey.
        new_authority: Pubkey,
        /// Type of authority.
        stake_authorize: StakeAuthorize,
        /// Seed for deriving authority.
        authority_seed: String,
        /// Owner for deriving authority.
        authority_owner: Pubkey,
    },

    /// Initialize with checked authorities (must be signers).
    /// Accounts: [stake_account, rent_sysvar, staker, withdrawer]
    InitializeChecked,

    /// Authorize with checked new authority (must be signer).
    /// Accounts: [stake_account, clock_sysvar, authority, new_authority]
    AuthorizeChecked {
        /// Type of authority.
        stake_authorize: StakeAuthorize,
    },

    /// Authorize with seed and checked new authority.
    /// Accounts: [stake_account, authority_base, clock_sysvar, new_authority]
    AuthorizeCheckedWithSeed {
        /// Type of authority.
        stake_authorize: StakeAuthorize,
        /// Seed for deriving authority.
        authority_seed: String,
        /// Owner for deriving authority.
        authority_owner: Pubkey,
    },

    /// Set lockup with checked custodian.
    /// Accounts: [stake_account, lockup_authority, (optional) new_lockup_authority]
    SetLockupChecked {
        /// Unix timestamp (None to leave unchanged).
        unix_timestamp: Option<i64>,
        /// Epoch (None to leave unchanged).
        epoch: Option<u64>,
    },
}

impl StakeInstruction {
    /// Check if the given program ID is the Stake Program.
    pub fn is_stake_program(program_id: &str) -> bool {
        program_id == STAKE_PROGRAM_ID
    }

    /// Decode a Stake Program instruction from raw data.
    pub fn decode(data: &[u8]) -> Result<Self, WasmSolanaError> {
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "Stake instruction too short: need at least 4 bytes",
            ));
        }

        let discriminator = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let data = &data[4..];

        match discriminator {
            0 => Self::decode_initialize(data),
            1 => Self::decode_authorize(data),
            2 => Ok(StakeInstruction::DelegateStake),
            3 => Self::decode_split(data),
            4 => Self::decode_withdraw(data),
            5 => Ok(StakeInstruction::Deactivate),
            6 => Self::decode_set_lockup(data),
            7 => Ok(StakeInstruction::Merge),
            8 => Self::decode_authorize_with_seed(data),
            9 => Ok(StakeInstruction::InitializeChecked),
            10 => Self::decode_authorize_checked(data),
            11 => Self::decode_authorize_checked_with_seed(data),
            12 => Self::decode_set_lockup_checked(data),
            _ => Err(WasmSolanaError::new(&format!(
                "Unknown Stake instruction discriminator: {}",
                discriminator
            ))),
        }
    }

    /// Get the instruction type.
    pub fn instruction_type(&self) -> StakeInstructionType {
        match self {
            Self::Initialize { .. } => StakeInstructionType::Initialize,
            Self::Authorize { .. } => StakeInstructionType::Authorize,
            Self::DelegateStake => StakeInstructionType::DelegateStake,
            Self::Split { .. } => StakeInstructionType::Split,
            Self::Withdraw { .. } => StakeInstructionType::Withdraw,
            Self::Deactivate => StakeInstructionType::Deactivate,
            Self::SetLockup { .. } => StakeInstructionType::SetLockup,
            Self::Merge => StakeInstructionType::Merge,
            Self::AuthorizeWithSeed { .. } => StakeInstructionType::AuthorizeWithSeed,
            Self::InitializeChecked => StakeInstructionType::InitializeChecked,
            Self::AuthorizeChecked { .. } => StakeInstructionType::AuthorizeChecked,
            Self::AuthorizeCheckedWithSeed { .. } => StakeInstructionType::AuthorizeCheckedWithSeed,
            Self::SetLockupChecked { .. } => StakeInstructionType::SetLockupChecked,
        }
    }

    // Private decode helpers

    fn decode_initialize(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Initialize: staker(Pubkey) + withdrawer(Pubkey) + lockup(i64 + u64 + Pubkey)
        // Lockup: unix_timestamp(i64) + epoch(u64) + custodian(Pubkey)
        if data.len() < 64 {
            return Err(WasmSolanaError::new("Initialize instruction too short"));
        }

        let staker = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid staker pubkey"))?;
        let withdrawer = Pubkey::try_from(&data[32..64])
            .map_err(|_| WasmSolanaError::new("Invalid withdrawer pubkey"))?;

        // Lockup is optional but usually present (48 bytes: i64 + u64 + Pubkey)
        let lockup = if data.len() >= 112 {
            let unix_timestamp = i64::from_le_bytes(data[64..72].try_into().unwrap());
            let epoch = u64::from_le_bytes(data[72..80].try_into().unwrap());
            let custodian = Pubkey::try_from(&data[80..112])
                .map_err(|_| WasmSolanaError::new("Invalid custodian pubkey"))?;

            // Check if lockup is meaningful (not all zeros)
            if unix_timestamp != 0 || epoch != 0 || custodian.to_string() != STAKE_PROGRAM_ID {
                Some(Lockup {
                    unix_timestamp,
                    epoch,
                    custodian,
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self::Initialize {
            staker,
            withdrawer,
            lockup,
        })
    }

    fn decode_authorize(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Authorize: new_authority(Pubkey) + stake_authorize(u32)
        if data.len() < 36 {
            return Err(WasmSolanaError::new("Authorize instruction too short"));
        }

        let new_authority = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid new_authority pubkey"))?;

        let stake_authorize = match u32::from_le_bytes(data[32..36].try_into().unwrap()) {
            0 => StakeAuthorize::Staker,
            1 => StakeAuthorize::Withdrawer,
            n => {
                return Err(WasmSolanaError::new(&format!(
                    "Invalid stake authorize type: {}",
                    n
                )))
            }
        };

        Ok(Self::Authorize {
            new_authority,
            stake_authorize,
        })
    }

    fn decode_split(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Split: lamports(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new("Split instruction too short"));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::Split { lamports })
    }

    fn decode_withdraw(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Withdraw: lamports(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new("Withdraw instruction too short"));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::Withdraw { lamports })
    }

    fn decode_set_lockup(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // SetLockup uses COption format: present(u8) + value
        let mut offset = 0;

        // unix_timestamp: Option<i64>
        let unix_timestamp = if data.get(offset).copied() == Some(1) {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(WasmSolanaError::new("SetLockup: truncated unix_timestamp"));
            }
            let val = i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            Some(val)
        } else {
            offset += 1;
            None
        };

        // epoch: Option<u64>
        let epoch = if data.get(offset).copied() == Some(1) {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(WasmSolanaError::new("SetLockup: truncated epoch"));
            }
            let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            Some(val)
        } else {
            offset += 1;
            None
        };

        // custodian: Option<Pubkey>
        let custodian = if data.get(offset).copied() == Some(1) {
            offset += 1;
            if data.len() < offset + 32 {
                return Err(WasmSolanaError::new("SetLockup: truncated custodian"));
            }
            Some(
                Pubkey::try_from(&data[offset..offset + 32])
                    .map_err(|_| WasmSolanaError::new("Invalid custodian pubkey"))?,
            )
        } else {
            None
        };

        Ok(Self::SetLockup {
            unix_timestamp,
            epoch,
            custodian,
        })
    }

    fn decode_authorize_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AuthorizeWithSeed: new_authority(Pubkey) + stake_authorize(u32) + seed_len(u64) + seed(bytes) + authority_owner(Pubkey)
        if data.len() < 36 {
            return Err(WasmSolanaError::new(
                "AuthorizeWithSeed instruction too short",
            ));
        }

        let new_authority = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid new_authority pubkey"))?;

        let stake_authorize = match u32::from_le_bytes(data[32..36].try_into().unwrap()) {
            0 => StakeAuthorize::Staker,
            1 => StakeAuthorize::Withdrawer,
            n => {
                return Err(WasmSolanaError::new(&format!(
                    "Invalid stake authorize type: {}",
                    n
                )))
            }
        };

        if data.len() < 44 {
            return Err(WasmSolanaError::new(
                "AuthorizeWithSeed: missing seed length",
            ));
        }

        let seed_len = u64::from_le_bytes(data[36..44].try_into().unwrap()) as usize;
        if data.len() < 44 + seed_len + 32 {
            return Err(WasmSolanaError::new("AuthorizeWithSeed: truncated"));
        }

        let authority_seed = String::from_utf8(data[44..44 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 44 + seed_len;
        let authority_owner = Pubkey::try_from(&data[offset..offset + 32])
            .map_err(|_| WasmSolanaError::new("Invalid authority_owner pubkey"))?;

        Ok(Self::AuthorizeWithSeed {
            new_authority,
            stake_authorize,
            authority_seed,
            authority_owner,
        })
    }

    fn decode_authorize_checked(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AuthorizeChecked: stake_authorize(u32)
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "AuthorizeChecked instruction too short",
            ));
        }

        let stake_authorize = match u32::from_le_bytes(data[0..4].try_into().unwrap()) {
            0 => StakeAuthorize::Staker,
            1 => StakeAuthorize::Withdrawer,
            n => {
                return Err(WasmSolanaError::new(&format!(
                    "Invalid stake authorize type: {}",
                    n
                )))
            }
        };

        Ok(Self::AuthorizeChecked { stake_authorize })
    }

    fn decode_authorize_checked_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AuthorizeCheckedWithSeed: stake_authorize(u32) + seed_len(u64) + seed(bytes) + authority_owner(Pubkey)
        if data.len() < 12 {
            return Err(WasmSolanaError::new(
                "AuthorizeCheckedWithSeed instruction too short",
            ));
        }

        let stake_authorize = match u32::from_le_bytes(data[0..4].try_into().unwrap()) {
            0 => StakeAuthorize::Staker,
            1 => StakeAuthorize::Withdrawer,
            n => {
                return Err(WasmSolanaError::new(&format!(
                    "Invalid stake authorize type: {}",
                    n
                )))
            }
        };

        let seed_len = u64::from_le_bytes(data[4..12].try_into().unwrap()) as usize;
        if data.len() < 12 + seed_len + 32 {
            return Err(WasmSolanaError::new("AuthorizeCheckedWithSeed: truncated"));
        }

        let authority_seed = String::from_utf8(data[12..12 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 12 + seed_len;
        let authority_owner = Pubkey::try_from(&data[offset..offset + 32])
            .map_err(|_| WasmSolanaError::new("Invalid authority_owner pubkey"))?;

        Ok(Self::AuthorizeCheckedWithSeed {
            stake_authorize,
            authority_seed,
            authority_owner,
        })
    }

    fn decode_set_lockup_checked(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // SetLockupChecked: same as SetLockup but custodian comes from accounts
        let mut offset = 0;

        // unix_timestamp: Option<i64>
        let unix_timestamp = if data.get(offset).copied() == Some(1) {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(WasmSolanaError::new(
                    "SetLockupChecked: truncated unix_timestamp",
                ));
            }
            let val = i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            offset += 8;
            Some(val)
        } else {
            offset += 1;
            None
        };

        // epoch: Option<u64>
        let epoch = if data.get(offset).copied() == Some(1) {
            offset += 1;
            if data.len() < offset + 8 {
                return Err(WasmSolanaError::new("SetLockupChecked: truncated epoch"));
            }
            let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
            Some(val)
        } else {
            None
        };

        Ok(Self::SetLockupChecked {
            unix_timestamp,
            epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_delegate_stake() {
        let data = [2, 0, 0, 0]; // discriminator = 2 (DelegateStake)

        let instr = StakeInstruction::decode(&data).unwrap();
        assert!(matches!(instr, StakeInstruction::DelegateStake));
    }

    #[test]
    fn test_decode_deactivate() {
        let data = [5, 0, 0, 0]; // discriminator = 5 (Deactivate)

        let instr = StakeInstruction::decode(&data).unwrap();
        assert!(matches!(instr, StakeInstruction::Deactivate));
    }

    #[test]
    fn test_decode_withdraw() {
        let data = [
            4, 0, 0, 0, // discriminator = 4 (Withdraw)
            0, 0, 0, 0, 1, 0, 0, 0, // lamports = 4294967296 (2^32)
        ];

        let instr = StakeInstruction::decode(&data).unwrap();
        match instr {
            StakeInstruction::Withdraw { lamports } => {
                assert_eq!(lamports, 4294967296);
            }
            _ => panic!("Expected Withdraw instruction"),
        }
    }

    #[test]
    fn test_decode_split() {
        let data = [
            3, 0, 0, 0, // discriminator = 3 (Split)
            128, 150, 152, 0, 0, 0, 0, 0, // lamports = 10000000
        ];

        let instr = StakeInstruction::decode(&data).unwrap();
        match instr {
            StakeInstruction::Split { lamports } => {
                assert_eq!(lamports, 10000000);
            }
            _ => panic!("Expected Split instruction"),
        }
    }

    #[test]
    fn test_is_stake_program() {
        assert!(StakeInstruction::is_stake_program(STAKE_PROGRAM_ID));
        assert!(!StakeInstruction::is_stake_program(
            "11111111111111111111111111111111"
        ));
    }

    #[test]
    fn test_instruction_type() {
        let deactivate = StakeInstruction::Deactivate;
        assert_eq!(
            deactivate.instruction_type(),
            StakeInstructionType::Deactivate
        );
        assert_eq!(deactivate.instruction_type().as_str(), "Deactivate");
    }
}
