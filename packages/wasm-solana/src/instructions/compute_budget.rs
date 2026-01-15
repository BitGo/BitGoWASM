//! ComputeBudget Program instruction decoder.
//!
//! The ComputeBudget Program controls transaction compute limits and priority fees:
//! - Set compute unit limit
//! - Set compute unit price (priority fee)
//! - Request heap frame size
//!
//! # Wire Format
//!
//! ComputeBudget instructions use a single-byte discriminator:
//! - 0: Deprecated (RequestUnitsDeprecated)
//! - 1: RequestHeapFrame
//! - 2: SetComputeUnitLimit
//! - 3: SetComputeUnitPrice
//! - 4: SetLoadedAccountsDataSizeLimit

use crate::error::WasmSolanaError;

/// ComputeBudget Program ID
pub const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";

/// ComputeBudget instruction types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeBudgetInstructionType {
    /// Deprecated instruction.
    RequestUnitsDeprecated,
    /// Request a specific heap frame size.
    RequestHeapFrame,
    /// Set the compute unit limit for the transaction.
    SetComputeUnitLimit,
    /// Set the compute unit price (priority fee).
    SetComputeUnitPrice,
    /// Set the maximum loaded accounts data size.
    SetLoadedAccountsDataSizeLimit,
}

impl ComputeBudgetInstructionType {
    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RequestUnitsDeprecated => "RequestUnitsDeprecated",
            Self::RequestHeapFrame => "RequestHeapFrame",
            Self::SetComputeUnitLimit => "SetComputeUnitLimit",
            Self::SetComputeUnitPrice => "SetComputeUnitPrice",
            Self::SetLoadedAccountsDataSizeLimit => "SetLoadedAccountsDataSizeLimit",
        }
    }
}

/// Decoded ComputeBudget instruction.
#[derive(Debug, Clone)]
pub enum ComputeBudgetInstruction {
    /// Deprecated: Request units (replaced by SetComputeUnitLimit).
    RequestUnitsDeprecated {
        /// Compute units requested.
        units: u32,
        /// Additional fee in lamports.
        additional_fee: u32,
    },

    /// Request a specific heap frame size.
    /// Accounts: none
    RequestHeapFrame {
        /// Heap size in bytes (must be multiple of 1024).
        bytes: u32,
    },

    /// Set the compute unit limit for the transaction.
    /// Accounts: none
    SetComputeUnitLimit {
        /// Maximum compute units.
        units: u32,
    },

    /// Set the compute unit price (priority fee per compute unit).
    /// Accounts: none
    SetComputeUnitPrice {
        /// Price in micro-lamports per compute unit.
        micro_lamports: u64,
    },

    /// Set the maximum loaded accounts data size limit.
    /// Accounts: none
    SetLoadedAccountsDataSizeLimit {
        /// Maximum bytes of account data that can be loaded.
        bytes: u32,
    },
}

impl ComputeBudgetInstruction {
    /// Check if the given program ID is the ComputeBudget Program.
    pub fn is_compute_budget_program(program_id: &str) -> bool {
        program_id == COMPUTE_BUDGET_PROGRAM_ID
    }

    /// Decode a ComputeBudget Program instruction from raw data.
    pub fn decode(data: &[u8]) -> Result<Self, WasmSolanaError> {
        if data.is_empty() {
            return Err(WasmSolanaError::new(
                "ComputeBudget instruction empty: need at least 1 byte",
            ));
        }

        let discriminator = data[0];
        let data = &data[1..];

        match discriminator {
            0 => Self::decode_request_units_deprecated(data),
            1 => Self::decode_request_heap_frame(data),
            2 => Self::decode_set_compute_unit_limit(data),
            3 => Self::decode_set_compute_unit_price(data),
            4 => Self::decode_set_loaded_accounts_data_size_limit(data),
            _ => Err(WasmSolanaError::new(&format!(
                "Unknown ComputeBudget instruction discriminator: {}",
                discriminator
            ))),
        }
    }

    /// Get the instruction type.
    pub fn instruction_type(&self) -> ComputeBudgetInstructionType {
        match self {
            Self::RequestUnitsDeprecated { .. } => {
                ComputeBudgetInstructionType::RequestUnitsDeprecated
            }
            Self::RequestHeapFrame { .. } => ComputeBudgetInstructionType::RequestHeapFrame,
            Self::SetComputeUnitLimit { .. } => ComputeBudgetInstructionType::SetComputeUnitLimit,
            Self::SetComputeUnitPrice { .. } => ComputeBudgetInstructionType::SetComputeUnitPrice,
            Self::SetLoadedAccountsDataSizeLimit { .. } => {
                ComputeBudgetInstructionType::SetLoadedAccountsDataSizeLimit
            }
        }
    }

    /// Get the compute unit limit if this is a SetComputeUnitLimit instruction.
    pub fn compute_unit_limit(&self) -> Option<u32> {
        match self {
            Self::SetComputeUnitLimit { units } => Some(*units),
            _ => None,
        }
    }

    /// Get the compute unit price in micro-lamports if this is a SetComputeUnitPrice instruction.
    pub fn compute_unit_price(&self) -> Option<u64> {
        match self {
            Self::SetComputeUnitPrice { micro_lamports } => Some(*micro_lamports),
            _ => None,
        }
    }

    // Private decode helpers

    fn decode_request_units_deprecated(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // RequestUnitsDeprecated: units(u32) + additional_fee(u32)
        if data.len() < 8 {
            return Err(WasmSolanaError::new(
                "RequestUnitsDeprecated instruction too short",
            ));
        }

        let units = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let additional_fee = u32::from_le_bytes(data[4..8].try_into().unwrap());

        Ok(Self::RequestUnitsDeprecated {
            units,
            additional_fee,
        })
    }

    fn decode_request_heap_frame(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // RequestHeapFrame: bytes(u32)
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "RequestHeapFrame instruction too short",
            ));
        }

        let bytes = u32::from_le_bytes(data[0..4].try_into().unwrap());

        Ok(Self::RequestHeapFrame { bytes })
    }

    fn decode_set_compute_unit_limit(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // SetComputeUnitLimit: units(u32)
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "SetComputeUnitLimit instruction too short",
            ));
        }

        let units = u32::from_le_bytes(data[0..4].try_into().unwrap());

        Ok(Self::SetComputeUnitLimit { units })
    }

    fn decode_set_compute_unit_price(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // SetComputeUnitPrice: micro_lamports(u64)
        if data.len() < 8 {
            return Err(WasmSolanaError::new(
                "SetComputeUnitPrice instruction too short",
            ));
        }

        let micro_lamports = u64::from_le_bytes(data[0..8].try_into().unwrap());

        Ok(Self::SetComputeUnitPrice { micro_lamports })
    }

    fn decode_set_loaded_accounts_data_size_limit(data: &[u8]) -> Result<Self, WasmSolanaError> {
        // SetLoadedAccountsDataSizeLimit: bytes(u32)
        if data.len() < 4 {
            return Err(WasmSolanaError::new(
                "SetLoadedAccountsDataSizeLimit instruction too short",
            ));
        }

        let bytes = u32::from_le_bytes(data[0..4].try_into().unwrap());

        Ok(Self::SetLoadedAccountsDataSizeLimit { bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_set_compute_unit_limit() {
        let data = [
            2, // discriminator = 2 (SetComputeUnitLimit)
            64, 66, 15, 0, // units = 1000000
        ];

        let instr = ComputeBudgetInstruction::decode(&data).unwrap();
        match instr {
            ComputeBudgetInstruction::SetComputeUnitLimit { units } => {
                assert_eq!(units, 1000000);
            }
            _ => panic!("Expected SetComputeUnitLimit instruction"),
        }
    }

    #[test]
    fn test_decode_set_compute_unit_price() {
        let data = [
            3, // discriminator = 3 (SetComputeUnitPrice)
            232, 3, 0, 0, 0, 0, 0, 0, // micro_lamports = 1000
        ];

        let instr = ComputeBudgetInstruction::decode(&data).unwrap();
        match instr {
            ComputeBudgetInstruction::SetComputeUnitPrice { micro_lamports } => {
                assert_eq!(micro_lamports, 1000);
            }
            _ => panic!("Expected SetComputeUnitPrice instruction"),
        }
    }

    #[test]
    fn test_decode_request_heap_frame() {
        let data = [
            1, // discriminator = 1 (RequestHeapFrame)
            0, 0, 4, 0, // bytes = 262144 (256KB)
        ];

        let instr = ComputeBudgetInstruction::decode(&data).unwrap();
        match instr {
            ComputeBudgetInstruction::RequestHeapFrame { bytes } => {
                assert_eq!(bytes, 262144);
            }
            _ => panic!("Expected RequestHeapFrame instruction"),
        }
    }

    #[test]
    fn test_is_compute_budget_program() {
        assert!(ComputeBudgetInstruction::is_compute_budget_program(
            COMPUTE_BUDGET_PROGRAM_ID
        ));
        assert!(!ComputeBudgetInstruction::is_compute_budget_program(
            "11111111111111111111111111111111"
        ));
    }

    #[test]
    fn test_instruction_type() {
        let limit = ComputeBudgetInstruction::SetComputeUnitLimit { units: 1000 };
        assert_eq!(
            limit.instruction_type(),
            ComputeBudgetInstructionType::SetComputeUnitLimit
        );
        assert_eq!(limit.instruction_type().as_str(), "SetComputeUnitLimit");
    }

    #[test]
    fn test_helper_methods() {
        let limit = ComputeBudgetInstruction::SetComputeUnitLimit { units: 500000 };
        assert_eq!(limit.compute_unit_limit(), Some(500000));
        assert_eq!(limit.compute_unit_price(), None);

        let price = ComputeBudgetInstruction::SetComputeUnitPrice {
            micro_lamports: 1000,
        };
        assert_eq!(price.compute_unit_limit(), None);
        assert_eq!(price.compute_unit_price(), Some(1000));
    }
}
