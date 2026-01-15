//! Instruction decoders using official Solana interface crates.
//!
//! This module wraps official Solana instruction types for WASM compatibility:
//! - `solana-system-interface` for System program
//! - `solana-stake-interface` for Stake program
//! - `solana-compute-budget-interface` for ComputeBudget program

use crate::error::WasmSolanaError;

// Re-export official instruction types
pub use solana_compute_budget_interface::ComputeBudgetInstruction;
pub use solana_stake_interface::instruction::StakeInstruction;
pub use solana_system_interface::instruction::SystemInstruction;

/// Program IDs as base58 strings
pub const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";
pub const STAKE_PROGRAM_ID: &str = "Stake11111111111111111111111111111111111111";
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// Decode a System program instruction from raw bytes.
pub fn decode_system_instruction(data: &[u8]) -> Result<SystemInstruction, WasmSolanaError> {
    bincode::deserialize(data)
        .map_err(|e| WasmSolanaError::new(&format!("Failed to decode System instruction: {}", e)))
}

/// Decode a Stake program instruction from raw bytes.
pub fn decode_stake_instruction(data: &[u8]) -> Result<StakeInstruction, WasmSolanaError> {
    bincode::deserialize(data)
        .map_err(|e| WasmSolanaError::new(&format!("Failed to decode Stake instruction: {}", e)))
}

/// Decode a ComputeBudget program instruction from raw bytes.
pub fn decode_compute_budget_instruction(
    data: &[u8],
) -> Result<ComputeBudgetInstruction, WasmSolanaError> {
    use borsh::BorshDeserialize;
    ComputeBudgetInstruction::try_from_slice(data)
        .map_err(|e| WasmSolanaError::new(&format!("Failed to decode ComputeBudget instruction: {}", e)))
}

/// Check if a program ID is the System program.
pub fn is_system_program(program_id: &str) -> bool {
    program_id == SYSTEM_PROGRAM_ID
}

/// Check if a program ID is the Stake program.
pub fn is_stake_program(program_id: &str) -> bool {
    program_id == STAKE_PROGRAM_ID
}

/// Check if a program ID is the ComputeBudget program.
pub fn is_compute_budget_program(program_id: &str) -> bool {
    program_id == COMPUTE_BUDGET_PROGRAM_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_system_transfer() {
        // Transfer 100000 lamports (discriminator 2 + u64 lamports)
        let data = [
            2, 0, 0, 0, // discriminator = 2 (Transfer)
            160, 134, 1, 0, 0, 0, 0, 0, // lamports = 100000
        ];

        let instr = decode_system_instruction(&data).unwrap();
        match instr {
            SystemInstruction::Transfer { lamports } => {
                assert_eq!(lamports, 100000);
            }
            _ => panic!("Expected Transfer instruction"),
        }
    }

    #[test]
    fn test_decode_system_advance_nonce() {
        let data = [4, 0, 0, 0]; // discriminator = 4 (AdvanceNonceAccount)
        let instr = decode_system_instruction(&data).unwrap();
        assert!(matches!(instr, SystemInstruction::AdvanceNonceAccount));
    }

    #[test]
    fn test_decode_stake_delegate() {
        let data = [2, 0, 0, 0]; // discriminator = 2 (DelegateStake)
        let instr = decode_stake_instruction(&data).unwrap();
        assert!(matches!(instr, StakeInstruction::DelegateStake));
    }

    #[test]
    fn test_decode_stake_deactivate() {
        let data = [5, 0, 0, 0]; // discriminator = 5 (Deactivate)
        let instr = decode_stake_instruction(&data).unwrap();
        assert!(matches!(instr, StakeInstruction::Deactivate));
    }

    #[test]
    fn test_decode_compute_budget_set_limit() {
        let data = [
            2, // discriminator = 2 (SetComputeUnitLimit)
            64, 66, 15, 0, // units = 1000000
        ];
        let instr = decode_compute_budget_instruction(&data).unwrap();
        assert!(matches!(
            instr,
            ComputeBudgetInstruction::SetComputeUnitLimit(1000000)
        ));
    }

    #[test]
    fn test_decode_compute_budget_set_price() {
        let data = [
            3, // discriminator = 3 (SetComputeUnitPrice)
            232, 3, 0, 0, 0, 0, 0, 0, // micro_lamports = 1000
        ];
        let instr = decode_compute_budget_instruction(&data).unwrap();
        assert!(matches!(
            instr,
            ComputeBudgetInstruction::SetComputeUnitPrice(1000)
        ));
    }

    #[test]
    fn test_program_id_checks() {
        assert!(is_system_program(SYSTEM_PROGRAM_ID));
        assert!(!is_system_program(STAKE_PROGRAM_ID));
        assert!(is_stake_program(STAKE_PROGRAM_ID));
        assert!(is_compute_budget_program(COMPUTE_BUDGET_PROGRAM_ID));
    }
}
