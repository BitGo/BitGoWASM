//! System Program instruction decoder.
//!
//! The System Program is responsible for:
//! - Creating new accounts
//! - Allocating account data
//! - Assigning accounts to programs
//! - Transferring lamports
//! - Nonce account operations
//!
//! # Wire Format
//!
//! System instructions start with a 4-byte little-endian discriminator:
//! - 0: CreateAccount
//! - 1: Assign
//! - 2: Transfer
//! - 3: CreateAccountWithSeed
//! - 4: AdvanceNonceAccount
//! - 5: WithdrawNonceAccount
//! - 6: InitializeNonceAccount
//! - 7: AuthorizeNonceAccount
//! - 8: Allocate
//! - 9: AllocateWithSeed
//! - 10: AssignWithSeed
//! - 11: TransferWithSeed
//! - 12: UpgradeNonceAccount

use crate::error::WasmSolanaError;
use crate::Pubkey;

/// System Program ID (all zeros, represented as base58 "11111111111111111111111111111111")
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// System instruction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemInstructionType {
    CreateAccount,
    Assign,
    Transfer,
    CreateAccountWithSeed,
    AdvanceNonceAccount,
    WithdrawNonceAccount,
    InitializeNonceAccount,
    AuthorizeNonceAccount,
    Allocate,
    AllocateWithSeed,
    AssignWithSeed,
    TransferWithSeed,
    UpgradeNonceAccount,
}

impl SystemInstructionType {
    /// Get the string representation of this instruction type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateAccount => "CreateAccount",
            Self::Assign => "Assign",
            Self::Transfer => "Transfer",
            Self::CreateAccountWithSeed => "CreateAccountWithSeed",
            Self::AdvanceNonceAccount => "AdvanceNonceAccount",
            Self::WithdrawNonceAccount => "WithdrawNonceAccount",
            Self::InitializeNonceAccount => "InitializeNonceAccount",
            Self::AuthorizeNonceAccount => "AuthorizeNonceAccount",
            Self::Allocate => "Allocate",
            Self::AllocateWithSeed => "AllocateWithSeed",
            Self::AssignWithSeed => "AssignWithSeed",
            Self::TransferWithSeed => "TransferWithSeed",
            Self::UpgradeNonceAccount => "UpgradeNonceAccount",
        }
    }
}

/// Decoded System Program instruction.
#[derive(Debug, Clone)]
pub enum SystemInstruction {
    /// Create a new account.
    /// Accounts: [funding_account, new_account]
    CreateAccount {
        /// Number of lamports to transfer to the new account.
        lamports: u64,
        /// Number of bytes of memory to allocate.
        space: u64,
        /// Address of the program to assign as the owner.
        owner: Pubkey,
    },

    /// Assign account to a program.
    /// Accounts: [assigned_account]
    Assign {
        /// Owner program account.
        owner: Pubkey,
    },

    /// Transfer lamports.
    /// Accounts: [from, to]
    Transfer {
        /// Number of lamports to transfer.
        lamports: u64,
    },

    /// Create a new account at an address derived from seed.
    /// Accounts: [funding_account, created_account, base_account (optional)]
    CreateAccountWithSeed {
        /// Base public key.
        base: Pubkey,
        /// Seed string.
        seed: String,
        /// Number of lamports to transfer.
        lamports: u64,
        /// Number of bytes to allocate.
        space: u64,
        /// Owner program.
        owner: Pubkey,
    },

    /// Advance the nonce in a nonce account.
    /// Accounts: [nonce_account, recent_blockhashes_sysvar, nonce_authority]
    AdvanceNonceAccount,

    /// Withdraw funds from a nonce account.
    /// Accounts: [nonce_account, to_account, recent_blockhashes_sysvar, rent_sysvar, nonce_authority]
    WithdrawNonceAccount {
        /// Lamports to withdraw.
        lamports: u64,
    },

    /// Initialize a nonce account.
    /// Accounts: [nonce_account, recent_blockhashes_sysvar, rent_sysvar]
    InitializeNonceAccount {
        /// The entity authorized to execute nonce instructions.
        authorized: Pubkey,
    },

    /// Authorize a new entity to execute nonce instructions.
    /// Accounts: [nonce_account, nonce_authority]
    AuthorizeNonceAccount {
        /// New authorized entity.
        authorized: Pubkey,
    },

    /// Allocate space for an account without funding.
    /// Accounts: [new_account]
    Allocate {
        /// Number of bytes to allocate.
        space: u64,
    },

    /// Allocate space for an account with seed.
    /// Accounts: [allocated_account, base_account]
    AllocateWithSeed {
        /// Base public key.
        base: Pubkey,
        /// Seed string.
        seed: String,
        /// Number of bytes to allocate.
        space: u64,
        /// Owner program.
        owner: Pubkey,
    },

    /// Assign account to a program with seed.
    /// Accounts: [assigned_account, base_account]
    AssignWithSeed {
        /// Base public key.
        base: Pubkey,
        /// Seed string.
        seed: String,
        /// Owner program.
        owner: Pubkey,
    },

    /// Transfer lamports from a derived address.
    /// Accounts: [from_account, base_account, to_account]
    TransferWithSeed {
        /// Lamports to transfer.
        lamports: u64,
        /// Seed for derived address.
        from_seed: String,
        /// Owner of derived address.
        from_owner: Pubkey,
    },

    /// Upgrade a nonce account.
    /// Accounts: [nonce_account]
    UpgradeNonceAccount,
}

impl SystemInstruction {
    /// Check if the given program ID is the System Program.
    pub fn is_system_program(program_id: &str) -> bool {
        program_id == SYSTEM_PROGRAM_ID
    }

    /// Decode a System Program instruction from raw data.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw instruction data bytes
    ///
    /// # Returns
    ///
    /// The decoded instruction or an error if the data is invalid.
    pub fn decode(data: &[u8]) -> Result<Self, WasmSolanaError> {
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "System instruction too short: need at least 4 bytes",
            ));
        }

        let discriminator = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let data = &data[4..];

        match discriminator {
            0 => Self::decode_create_account(data),
            1 => Self::decode_assign(data),
            2 => Self::decode_transfer(data),
            3 => Self::decode_create_account_with_seed(data),
            4 => Ok(SystemInstruction::AdvanceNonceAccount),
            5 => Self::decode_withdraw_nonce(data),
            6 => Self::decode_initialize_nonce(data),
            7 => Self::decode_authorize_nonce(data),
            8 => Self::decode_allocate(data),
            9 => Self::decode_allocate_with_seed(data),
            10 => Self::decode_assign_with_seed(data),
            11 => Self::decode_transfer_with_seed(data),
            12 => Ok(SystemInstruction::UpgradeNonceAccount),
            _ => Err(WasmSolanaError::new(&format!(
                "Unknown System instruction discriminator: {}",
                discriminator
            ))),
        }
    }

    /// Get the instruction type.
    pub fn instruction_type(&self) -> SystemInstructionType {
        match self {
            Self::CreateAccount { .. } => SystemInstructionType::CreateAccount,
            Self::Assign { .. } => SystemInstructionType::Assign,
            Self::Transfer { .. } => SystemInstructionType::Transfer,
            Self::CreateAccountWithSeed { .. } => SystemInstructionType::CreateAccountWithSeed,
            Self::AdvanceNonceAccount => SystemInstructionType::AdvanceNonceAccount,
            Self::WithdrawNonceAccount { .. } => SystemInstructionType::WithdrawNonceAccount,
            Self::InitializeNonceAccount { .. } => SystemInstructionType::InitializeNonceAccount,
            Self::AuthorizeNonceAccount { .. } => SystemInstructionType::AuthorizeNonceAccount,
            Self::Allocate { .. } => SystemInstructionType::Allocate,
            Self::AllocateWithSeed { .. } => SystemInstructionType::AllocateWithSeed,
            Self::AssignWithSeed { .. } => SystemInstructionType::AssignWithSeed,
            Self::TransferWithSeed { .. } => SystemInstructionType::TransferWithSeed,
            Self::UpgradeNonceAccount => SystemInstructionType::UpgradeNonceAccount,
        }
    }

    // Private decode helpers

    fn decode_create_account(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // CreateAccount: lamports(u64) + space(u64) + owner(Pubkey)
        if data.len() < 48 {
            return Err(WasmSolanaError::new("CreateAccount instruction too short"));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let space = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let owner = Pubkey::try_from(&data[16..48])
            .map_err(|_| WasmSolanaError::new("Invalid owner pubkey in CreateAccount"))?;

        Ok(Self::CreateAccount {
            lamports,
            space,
            owner,
        })
    }

    fn decode_assign(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Assign: owner(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new("Assign instruction too short"));
        }

        let owner = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid owner pubkey in Assign"))?;

        Ok(Self::Assign { owner })
    }

    fn decode_transfer(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Transfer: lamports(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new("Transfer instruction too short"));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::Transfer { lamports })
    }

    fn decode_create_account_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // CreateAccountWithSeed: base(Pubkey) + seed_len(u64) + seed(bytes) + lamports(u64) + space(u64) + owner(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new(
                "CreateAccountWithSeed instruction too short",
            ));
        }

        let base = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid base pubkey"))?;

        let seed_len = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        if data.len() < 40 + seed_len + 48 {
            return Err(WasmSolanaError::new(
                "CreateAccountWithSeed instruction too short for seed",
            ));
        }

        let seed = String::from_utf8(data[40..40 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 40 + seed_len;
        let lamports = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let space = u64::from_le_bytes(data[offset + 8..offset + 16].try_into().unwrap());
        let owner = Pubkey::try_from(&data[offset + 16..offset + 48])
            .map_err(|_| WasmSolanaError::new("Invalid owner pubkey"))?;

        Ok(Self::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        })
    }

    fn decode_withdraw_nonce(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // WithdrawNonceAccount: lamports(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new(
                "WithdrawNonceAccount instruction too short",
            ));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::WithdrawNonceAccount { lamports })
    }

    fn decode_initialize_nonce(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // InitializeNonceAccount: authorized(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new(
                "InitializeNonceAccount instruction too short",
            ));
        }

        let authorized = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid authorized pubkey"))?;

        Ok(Self::InitializeNonceAccount { authorized })
    }

    fn decode_authorize_nonce(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AuthorizeNonceAccount: authorized(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new(
                "AuthorizeNonceAccount instruction too short",
            ));
        }

        let authorized = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid authorized pubkey"))?;

        Ok(Self::AuthorizeNonceAccount { authorized })
    }

    fn decode_allocate(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // Allocate: space(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new("Allocate instruction too short"));
        }

        let space = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::Allocate { space })
    }

    fn decode_allocate_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AllocateWithSeed: base(Pubkey) + seed_len(u64) + seed(bytes) + space(u64) + owner(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new(
                "AllocateWithSeed instruction too short",
            ));
        }

        let base = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid base pubkey"))?;

        let seed_len = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        if data.len() < 40 + seed_len + 40 {
            return Err(WasmSolanaError::new(
                "AllocateWithSeed instruction too short for seed",
            ));
        }

        let seed = String::from_utf8(data[40..40 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 40 + seed_len;
        let space = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let owner = Pubkey::try_from(&data[offset + 8..offset + 40])
            .map_err(|_| WasmSolanaError::new("Invalid owner pubkey"))?;

        Ok(Self::AllocateWithSeed {
            base,
            seed,
            space,
            owner,
        })
    }

    fn decode_assign_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // AssignWithSeed: base(Pubkey) + seed_len(u64) + seed(bytes) + owner(Pubkey)
        if data.len() < 32 {
            return Err(WasmSolanaError::new("AssignWithSeed instruction too short"));
        }

        let base = Pubkey::try_from(&data[0..32])
            .map_err(|_| WasmSolanaError::new("Invalid base pubkey"))?;

        let seed_len = u64::from_le_bytes(data[32..40].try_into().unwrap()) as usize;
        if data.len() < 40 + seed_len + 32 {
            return Err(WasmSolanaError::new(
                "AssignWithSeed instruction too short for seed",
            ));
        }

        let seed = String::from_utf8(data[40..40 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 40 + seed_len;
        let owner = Pubkey::try_from(&data[offset..offset + 32])
            .map_err(|_| WasmSolanaError::new("Invalid owner pubkey"))?;

        Ok(Self::AssignWithSeed { base, seed, owner })
    }

    fn decode_transfer_with_seed(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // TransferWithSeed: lamports(u64) + seed_len(u64) + seed(bytes) + from_owner(Pubkey)
        if data.len() < 16 {
            return Err(WasmSolanaError::new(
                "TransferWithSeed instruction too short",
            ));
        }

        let lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let seed_len = u64::from_le_bytes(data[8..16].try_into().unwrap()) as usize;

        if data.len() < 16 + seed_len + 32 {
            return Err(WasmSolanaError::new(
                "TransferWithSeed instruction too short for seed",
            ));
        }

        let from_seed = String::from_utf8(data[16..16 + seed_len].to_vec())
            .map_err(|_| WasmSolanaError::new("Invalid UTF-8 seed"))?;

        let offset = 16 + seed_len;
        let from_owner = Pubkey::try_from(&data[offset..offset + 32])
            .map_err(|_| WasmSolanaError::new("Invalid from_owner pubkey"))?;

        Ok(Self::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_transfer() {
        // Transfer 100000 lamports (discriminator 2 + u64 lamports)
        let data = [
            2, 0, 0, 0, // discriminator = 2 (Transfer)
            160, 134, 1, 0, 0, 0, 0, 0, // lamports = 100000
        ];

        let instr = SystemInstruction::decode(&data).unwrap();
        match instr {
            SystemInstruction::Transfer { lamports } => {
                assert_eq!(lamports, 100000);
            }
            _ => panic!("Expected Transfer instruction"),
        }
    }

    #[test]
    fn test_decode_advance_nonce() {
        let data = [4, 0, 0, 0]; // discriminator = 4 (AdvanceNonceAccount)

        let instr = SystemInstruction::decode(&data).unwrap();
        assert!(matches!(instr, SystemInstruction::AdvanceNonceAccount));
    }

    #[test]
    fn test_is_system_program() {
        assert!(SystemInstruction::is_system_program(SYSTEM_PROGRAM_ID));
        assert!(!SystemInstruction::is_system_program(
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
        ));
    }

    #[test]
    fn test_instruction_type() {
        let transfer = SystemInstruction::Transfer { lamports: 100 };
        assert_eq!(transfer.instruction_type(), SystemInstructionType::Transfer);
        assert_eq!(transfer.instruction_type().as_str(), "Transfer");
    }
}
