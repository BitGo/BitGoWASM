//! Custom CellSerialize/CellDeserialize for staking opcodes.
//!
//! These types are not provided by toner since they are application-level
//! (BitGo-specific staking pool contracts).

use num_bigint::BigUint;
use tlb::{
    bits::{de::BitReaderExt, ser::BitWriterExt, VarInt},
    de::{CellDeserialize, CellParser, CellParserError},
    ser::{CellBuilder, CellBuilderError, CellSerialize},
};

/// Single Nominator Withdraw payload:
///   opcode(32) = 0x00001000 = 4096
///   query_id(64)
///   amount: Coins (VarUInteger 16)
#[derive(Debug, Clone)]
pub struct NominatorWithdraw {
    pub query_id: u64,
    pub amount: BigUint,
}

pub const NOMINATOR_WITHDRAW_OPCODE: u32 = 0x00001000;

impl CellSerialize for NominatorWithdraw {
    type Args = ();

    fn store(&self, builder: &mut CellBuilder, _: Self::Args) -> Result<(), CellBuilderError> {
        builder.pack(NOMINATOR_WITHDRAW_OPCODE, ())?;
        builder.pack(self.query_id, ())?;
        builder.pack_as::<_, &VarInt<4>>(&self.amount, ())?;
        Ok(())
    }
}

impl<'de> CellDeserialize<'de> for NominatorWithdraw {
    type Args = ();

    fn parse(parser: &mut CellParser<'de>, _: Self::Args) -> Result<Self, CellParserError<'de>> {
        let _opcode: u32 = parser.unpack(())?;
        let query_id: u64 = parser.unpack(())?;
        let amount: BigUint = parser.unpack_as::<_, VarInt<4>>(())?;
        Ok(Self { query_id, amount })
    }
}

/// TON Whales Deposit payload:
///   opcode(32) = 2077040623 (0x7bcd1eef)
///   query_id(64)
///   gas_limit: Coins (VarUInteger 16) -- hardcoded 1 TON
#[derive(Debug, Clone)]
pub struct WhalesDeposit {
    pub query_id: u64,
}

pub const WHALES_DEPOSIT_OPCODE: u32 = 2077040623;

impl CellSerialize for WhalesDeposit {
    type Args = ();

    fn store(&self, builder: &mut CellBuilder, _: Self::Args) -> Result<(), CellBuilderError> {
        builder.pack(WHALES_DEPOSIT_OPCODE, ())?;
        builder.pack(self.query_id, ())?;
        builder.pack_as::<_, &VarInt<4>>(&BigUint::from(1_000_000_000u64), ())?;
        Ok(())
    }
}

impl<'de> CellDeserialize<'de> for WhalesDeposit {
    type Args = ();

    fn parse(parser: &mut CellParser<'de>, _: Self::Args) -> Result<Self, CellParserError<'de>> {
        let _opcode: u32 = parser.unpack(())?;
        let query_id: u64 = parser.unpack(())?;
        let _gas_limit: BigUint = parser.unpack_as::<_, VarInt<4>>(())?;
        Ok(Self { query_id })
    }
}

/// TON Whales Withdrawal payload:
///   opcode(32) = 3665837821 (0xda787efd)
///   query_id(64)
///   gas_limit: Coins (VarUInteger 16) -- hardcoded 1 TON
///   unstake_amount: Coins (VarUInteger 16) -- 0 = full withdrawal
#[derive(Debug, Clone)]
pub struct WhalesWithdraw {
    pub query_id: u64,
    pub unstake_amount: BigUint,
}

pub const WHALES_WITHDRAW_OPCODE: u32 = 3665837821;

impl CellSerialize for WhalesWithdraw {
    type Args = ();

    fn store(&self, builder: &mut CellBuilder, _: Self::Args) -> Result<(), CellBuilderError> {
        builder.pack(WHALES_WITHDRAW_OPCODE, ())?;
        builder.pack(self.query_id, ())?;
        builder.pack_as::<_, &VarInt<4>>(&BigUint::from(1_000_000_000u64), ())?;
        builder.pack_as::<_, &VarInt<4>>(&self.unstake_amount, ())?;
        Ok(())
    }
}

impl<'de> CellDeserialize<'de> for WhalesWithdraw {
    type Args = ();

    fn parse(parser: &mut CellParser<'de>, _: Self::Args) -> Result<Self, CellParserError<'de>> {
        let _opcode: u32 = parser.unpack(())?;
        let query_id: u64 = parser.unpack(())?;
        let _gas_limit: BigUint = parser.unpack_as::<_, VarInt<4>>(())?;
        let unstake_amount: BigUint = parser.unpack_as::<_, VarInt<4>>(())?;
        Ok(Self {
            query_id,
            unstake_amount,
        })
    }
}

/// Jetton Transfer opcode
pub const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;

/// Text comment opcode
pub const TEXT_COMMENT_OPCODE: u32 = 0x00000000;
