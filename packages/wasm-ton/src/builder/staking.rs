//! Staking message construction for TON staking protocols.
//!
//! Supports three staking types:
//! - TON Whales: pool-based staking with deposit/withdraw opcodes
//! - Single Nominator: dedicated validator with withdraw opcode
//! - Multi Nominator: validator with memo-based commands ('d' for delegate, 'w' for withdraw)

use num_bigint::BigUint;
use tlb_ton::{
    action::SendMsgAction,
    currency::CurrencyCollection,
    message::{CommonMsgInfo, InternalMsgInfo, Message},
    ser::CellSerializeExt,
    Cell, MsgAddress,
};

use crate::error::WasmTonError;

/// TON Whales deposit opcode
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;

/// TON Whales withdraw opcode
const WHALES_WITHDRAW_OPCODE: u32 = 0xda803efd;

/// Single nominator withdraw opcode
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x1000;

// =========================================================================
// TON Whales
// =========================================================================

/// Build a TON Whales deposit action.
///
/// Sends a deposit message to the whales pool contract with the deposit opcode.
pub fn build_whales_deposit_action(
    pool_address: MsgAddress,
    amount: u64,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_opcode_body(WHALES_DEPOSIT_OPCODE, 0)?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: pool_address,
        value: CurrencyCollection {
            grams: BigUint::from(amount),
            other: Default::default(),
        },
        ihr_fee: BigUint::ZERO,
        fwd_fee: BigUint::ZERO,
        created_lt: 0,
        created_at: Default::default(),
    };

    let msg: Message<Cell> = Message {
        info: CommonMsgInfo::Internal(internal_info),
        init: None,
        body,
    };

    Ok(SendMsgAction { mode, message: msg })
}

/// Build a TON Whales withdraw action.
///
/// Sends a withdrawal message to the whales pool contract.
/// If `withdrawal_amount` is 0, requests full withdrawal.
pub fn build_whales_withdraw_action(
    pool_address: MsgAddress,
    transfer_amount: u64,
    withdrawal_amount: u64,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_whales_withdraw_body(withdrawal_amount)?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: pool_address,
        value: CurrencyCollection {
            grams: BigUint::from(transfer_amount),
            other: Default::default(),
        },
        ihr_fee: BigUint::ZERO,
        fwd_fee: BigUint::ZERO,
        created_lt: 0,
        created_at: Default::default(),
    };

    let msg: Message<Cell> = Message {
        info: CommonMsgInfo::Internal(internal_info),
        init: None,
        body,
    };

    Ok(SendMsgAction { mode, message: msg })
}

/// Build TON Whales withdraw body: opcode + query_id + gas_limit + amount
fn build_whales_withdraw_body(withdrawal_amount: u64) -> Result<Cell, WasmTonError> {
    let body = WhalesWithdrawBody {
        opcode: WHALES_WITHDRAW_OPCODE,
        query_id: 0,
        gas_limit: BigUint::ZERO,
        amount: BigUint::from(withdrawal_amount),
    };
    body.to_cell(()).map_err(|e| {
        WasmTonError::CellError(format!("Failed to build whales withdraw body: {}", e))
    })
}

struct WhalesWithdrawBody {
    opcode: u32,
    query_id: u64,
    gas_limit: BigUint,
    amount: BigUint,
}

impl tlb_ton::ser::CellSerialize for WhalesWithdrawBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        use tlb_ton::currency::Coins;
        builder.pack(self.opcode, ())?;
        builder.pack(self.query_id, ())?;
        builder.pack_as::<_, &Coins>(&self.gas_limit, ())?;
        builder.pack_as::<_, &Coins>(&self.amount, ())?;
        Ok(())
    }
}

// =========================================================================
// Single Nominator
// =========================================================================

/// Build a single nominator withdraw action.
///
/// Sends a withdrawal message with the single nominator opcode.
/// Transfer amount is typically 1 TON (for gas), withdrawal amount is the actual amount to withdraw.
pub fn build_single_nominator_withdraw_action(
    validator_address: MsgAddress,
    transfer_amount: u64,
    withdrawal_amount: u64,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_single_nominator_withdraw_body(withdrawal_amount)?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: validator_address,
        value: CurrencyCollection {
            grams: BigUint::from(transfer_amount),
            other: Default::default(),
        },
        ihr_fee: BigUint::ZERO,
        fwd_fee: BigUint::ZERO,
        created_lt: 0,
        created_at: Default::default(),
    };

    let msg: Message<Cell> = Message {
        info: CommonMsgInfo::Internal(internal_info),
        init: None,
        body,
    };

    Ok(SendMsgAction { mode, message: msg })
}

/// Build single nominator withdraw body: opcode(32) + query_id(64) + amount(coins)
fn build_single_nominator_withdraw_body(amount: u64) -> Result<Cell, WasmTonError> {
    let body = SingleNominatorWithdrawBody {
        opcode: SINGLE_NOMINATOR_WITHDRAW_OPCODE,
        query_id: 0,
        amount: BigUint::from(amount),
    };
    body.to_cell(()).map_err(|e| {
        WasmTonError::CellError(format!(
            "Failed to build single nominator withdraw body: {}",
            e
        ))
    })
}

struct SingleNominatorWithdrawBody {
    opcode: u32,
    query_id: u64,
    amount: BigUint,
}

impl tlb_ton::ser::CellSerialize for SingleNominatorWithdrawBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        use tlb_ton::currency::Coins;
        builder.pack(self.opcode, ())?;
        builder.pack(self.query_id, ())?;
        builder.pack_as::<_, &Coins>(&self.amount, ())?;
        Ok(())
    }
}

// =========================================================================
// TON Whales Vesting
// =========================================================================

/// Build a TON Whales vesting deposit action.
///
/// Vesting deposits use a text body "Deposit" instead of the opcode-based payload.
/// The message is bounceable to the pool address.
pub fn build_whales_vesting_deposit_action(
    pool_address: MsgAddress,
    amount: u64,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_text_body("Deposit")?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: pool_address,
        value: CurrencyCollection {
            grams: BigUint::from(amount),
            other: Default::default(),
        },
        ihr_fee: BigUint::ZERO,
        fwd_fee: BigUint::ZERO,
        created_lt: 0,
        created_at: Default::default(),
    };

    let msg: Message<Cell> = Message {
        info: CommonMsgInfo::Internal(internal_info),
        init: None,
        body,
    };

    Ok(SendMsgAction { mode, message: msg })
}

/// Build a TON Whales vesting withdraw action.
///
/// Vesting withdrawals use a text body "Withdraw" instead of the opcode-based payload.
/// The message is bounceable to the pool address.
pub fn build_whales_vesting_withdraw_action(
    pool_address: MsgAddress,
    transfer_amount: u64,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_text_body("Withdraw")?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: pool_address,
        value: CurrencyCollection {
            grams: BigUint::from(transfer_amount),
            other: Default::default(),
        },
        ihr_fee: BigUint::ZERO,
        fwd_fee: BigUint::ZERO,
        created_lt: 0,
        created_at: Default::default(),
    };

    let msg: Message<Cell> = Message {
        info: CommonMsgInfo::Internal(internal_info),
        init: None,
        body,
    };

    Ok(SendMsgAction { mode, message: msg })
}

/// Build a text body cell: 0x00000000 (32-bit zero opcode prefix for text comments) + UTF-8 string.
fn build_text_body(text: &str) -> Result<Cell, WasmTonError> {
    let body = TextBody {
        prefix: 0u32,
        text: text.to_string(),
    };
    body.to_cell(())
        .map_err(|e| WasmTonError::CellError(format!("Failed to build text body: {}", e)))
}

struct TextBody {
    prefix: u32,
    text: String,
}

impl tlb_ton::ser::CellSerialize for TextBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        builder.pack(self.prefix, ())?;
        // Write string bytes directly
        for byte in self.text.as_bytes() {
            builder.pack(*byte, ())?;
        }
        Ok(())
    }
}

// =========================================================================
// Helpers
// =========================================================================

/// Build a simple opcode + query_id body cell.
fn build_opcode_body(opcode: u32, query_id: u64) -> Result<Cell, WasmTonError> {
    let body = OpcodeBody { opcode, query_id };
    body.to_cell(())
        .map_err(|e| WasmTonError::CellError(format!("Failed to build opcode body: {}", e)))
}

struct OpcodeBody {
    opcode: u32,
    query_id: u64,
}

impl tlb_ton::ser::CellSerialize for OpcodeBody {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use tlb_ton::bits::ser::BitWriterExt;
        builder.pack(self.opcode, ())?;
        builder.pack(self.query_id, ())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_whales_deposit() {
        let pool = MsgAddress {
            workchain_id: 0,
            address: [1u8; 32],
        };
        let action = build_whales_deposit_action(pool, 5_000_000_000, 3).unwrap();
        assert_eq!(action.mode, 3);
        match &action.message.info {
            CommonMsgInfo::Internal(info) => {
                assert!(info.bounce);
                assert_eq!(info.value.grams, BigUint::from(5_000_000_000u64));
            }
            _ => panic!("Expected Internal message"),
        }
    }

    #[test]
    fn test_build_whales_withdraw() {
        let pool = MsgAddress {
            workchain_id: 0,
            address: [1u8; 32],
        };
        let action = build_whales_withdraw_action(pool, 1_000_000_000, 0, 3).unwrap();
        assert_eq!(action.mode, 3);
    }

    #[test]
    fn test_build_single_nominator_withdraw() {
        let validator = MsgAddress {
            workchain_id: 0,
            address: [2u8; 32],
        };
        let action =
            build_single_nominator_withdraw_action(validator, 1_000_000_000, 5_000_000_000, 3)
                .unwrap();
        assert_eq!(action.mode, 3);
        match &action.message.info {
            CommonMsgInfo::Internal(info) => {
                assert!(info.bounce);
                // Transfer amount is 1 TON for gas
                assert_eq!(info.value.grams, BigUint::from(1_000_000_000u64));
            }
            _ => panic!("Expected Internal message"),
        }
    }
}
