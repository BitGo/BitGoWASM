//! Jetton (TEP-74) transfer message construction.
//!
//! Builds internal messages for jetton transfers, including the
//! JettonTransfer body with forward_payload for memos.

use num_bigint::BigUint;
use tlb_ton::{
    action::SendMsgAction,
    currency::CurrencyCollection,
    message::{CommonMsgInfo, InternalMsgInfo, Message},
    ser::CellSerializeExt,
    Cell, MsgAddress,
};
use ton_contracts::jetton::{ForwardPayload, ForwardPayloadComment, JettonTransfer};

use crate::error::WasmTonError;

/// Default TON amount to attach to jetton transfer for gas (0.1 TON).
const DEFAULT_TON_AMOUNT: u64 = 100_000_000;

/// Forward TON amount for notification (100 nanoTON).
const DEFAULT_FORWARD_TON_AMOUNT: u64 = 100;

/// Build a SendMsgAction for a jetton transfer (TEP-74).
///
/// The message is sent to the sender's jetton wallet address, which then
/// forwards tokens to the destination via the jetton protocol.
///
/// # Arguments
/// * `sender_jetton_addr` - Sender's jetton wallet address
/// * `destination` - Final token recipient address
/// * `response_destination` - Address to receive excess TON (typically sender)
/// * `jetton_amount` - Amount of jettons to transfer
/// * `memo` - Optional text comment (forwarded in forward_payload)
/// * `mode` - Send mode
pub fn build_jetton_transfer_action(
    sender_jetton_addr: MsgAddress,
    destination: MsgAddress,
    response_destination: MsgAddress,
    jetton_amount: u64,
    memo: Option<&str>,
    mode: u8,
) -> Result<SendMsgAction, WasmTonError> {
    let forward_payload = match memo {
        Some(text) if !text.is_empty() => {
            ForwardPayload::Comment(ForwardPayloadComment::Text(text.to_string()))
        }
        _ => ForwardPayload::Comment(ForwardPayloadComment::Text(String::new())),
    };

    let jetton_transfer = JettonTransfer::<Cell, Cell> {
        query_id: 0,
        amount: BigUint::from(jetton_amount),
        dst: destination,
        response_dst: response_destination,
        custom_payload: None,
        forward_ton_amount: BigUint::from(DEFAULT_FORWARD_TON_AMOUNT),
        forward_payload,
    };

    let body_cell = jetton_transfer.to_cell(()).map_err(|e| {
        WasmTonError::CellError(format!("Failed to build jetton transfer cell: {}", e))
    })?;

    let internal_info = InternalMsgInfo {
        ihr_disabled: true,
        bounce: true,
        bounced: false,
        src: MsgAddress::NULL,
        dst: sender_jetton_addr,
        value: CurrencyCollection {
            grams: BigUint::from(DEFAULT_TON_AMOUNT),
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
        body: body_cell,
    };

    Ok(SendMsgAction { mode, message: msg })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_jetton_transfer_action() {
        let sender_jetton = MsgAddress {
            workchain_id: 0,
            address: [1u8; 32],
        };
        let destination = MsgAddress {
            workchain_id: 0,
            address: [2u8; 32],
        };
        let response = MsgAddress {
            workchain_id: 0,
            address: [3u8; 32],
        };

        let action = build_jetton_transfer_action(
            sender_jetton,
            destination,
            response,
            5_000_000,
            Some("jetton memo"),
            3,
        )
        .unwrap();

        assert_eq!(action.mode, 3);
        match &action.message.info {
            CommonMsgInfo::Internal(info) => {
                // Message goes to the sender's jetton wallet
                assert_eq!(info.dst, sender_jetton);
                assert!(info.bounce);
                // Attached TON for gas
                assert_eq!(info.value.grams, BigUint::from(DEFAULT_TON_AMOUNT));
            }
            _ => panic!("Expected Internal message"),
        }
    }
}
