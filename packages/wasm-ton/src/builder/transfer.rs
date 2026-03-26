//! Native TON transfer message construction.
//!
//! Builds internal messages for native TON transfers, including
//! optional text memo comments.

use num_bigint::BigUint;
use tlb_ton::{
    action::SendMsgAction,
    currency::CurrencyCollection,
    message::{CommonMsgInfo, InternalMsgInfo, Message},
    ser::CellSerializeExt,
    Cell, MsgAddress,
};

use crate::error::WasmTonError;

/// Build an internal message for a native TON transfer.
///
/// # Arguments
/// * `dst` - Destination address
/// * `amount` - Amount in nanoTON
/// * `bounceable` - Whether the message is bounceable
/// * `memo` - Optional text comment
/// * `mode` - Send mode (3 = standard, 128 = send all balance)
pub fn build_transfer_action(
    dst: MsgAddress,
    amount: u64,
    bounceable: bool,
    memo: Option<&str>,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let body = build_transfer_body(memo)?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: bounceable,
        bounced: false,
        src: MsgAddress::NULL,
        dst,
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

/// Build the body cell for a transfer, optionally with a text comment.
fn build_transfer_body(memo: Option<&str>) -> Result<Cell, WasmTonError> {
    match memo {
        Some(text) if !text.is_empty() => {
            // Text comment: opcode 0x00000000 followed by UTF-8 bytes
            let comment = TextComment(text.to_string());
            comment.to_cell(()).map_err(|e| {
                WasmTonError::CellError(format!("Failed to build comment cell: {}", e))
            })
        }
        _ => {
            // Empty body
            Cell::default()
                .to_cell(())
                .map_err(|e| WasmTonError::CellError(format!("Failed to build empty cell: {}", e)))
        }
    }
}

/// A text comment body (opcode 0x00000000 + UTF-8 text).
struct TextComment(String);

impl tlb_ton::ser::CellSerialize for TextComment {
    type Args = ();

    fn store(
        &self,
        builder: &mut tlb_ton::ser::CellBuilder,
        _: Self::Args,
    ) -> Result<(), tlb_ton::ser::CellBuilderError> {
        use bitvec::view::AsBits;
        use tlb_ton::bits::ser::{BitWriter, BitWriterExt};
        // opcode 0x00000000
        builder.pack(0u32, ())?;
        // UTF-8 text bytes as raw bits
        builder.write_bitslice(self.0.as_bytes().as_bits())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_transfer_action_no_memo() {
        let dst = MsgAddress {
            workchain_id: 0,
            address: [1u8; 32],
        };
        let action = build_transfer_action(dst, 1_000_000_000, false, None, 3).unwrap();
        assert_eq!(action.mode, 3);
        match &action.message.info {
            CommonMsgInfo::Internal(info) => {
                assert_eq!(info.dst, dst);
                assert!(!info.bounce);
            }
            _ => panic!("Expected Internal message"),
        }
    }

    #[test]
    fn test_build_transfer_action_with_memo() {
        let dst = MsgAddress {
            workchain_id: 0,
            address: [2u8; 32],
        };
        let action = build_transfer_action(dst, 500_000_000, true, Some("test memo"), 3).unwrap();
        assert_eq!(action.mode, 3);
        match &action.message.info {
            CommonMsgInfo::Internal(info) => {
                assert!(info.bounce);
            }
            _ => panic!("Expected Internal message"),
        }
    }
}
