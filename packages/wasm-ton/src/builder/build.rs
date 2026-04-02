use chrono::DateTime;
use num_bigint::BigUint;
use tlb_ton::{
    action::SendMsgAction,
    bits::ser::BitWriterExt,
    currency::Grams,
    message::{CommonMsgInfo, ExternalInMsgInfo, Message},
    ser::CellSerializeExt,
    BagOfCells, BagOfCellsArgs, Cell, MsgAddress,
};
use ton_contracts::jetton::{ForwardPayload, ForwardPayloadComment, JettonTransfer};
use ton_contracts::wallet::v4r2::{WalletV4R2ExternalBody, WalletV4R2SignBody, V4R2};
use ton_contracts::wallet::WalletVersion;

use super::types::{BuildContext, TonIntent, TonStakingType};
use crate::error::WasmTonError;

// Opcodes for staking operations
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;
const WHALES_WITHDRAW_OPCODE: u32 = 0xda803efd;
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x00001000;

const BOC_ARGS: BagOfCellsArgs = BagOfCellsArgs {
    has_idx: false,
    has_crc32c: true,
};

/// Build a transaction from an intent and context.
/// Returns the serialized BOC bytes.
pub fn build_transaction(
    context: &BuildContext,
    intent: &TonIntent,
) -> Result<Vec<u8>, WasmTonError> {
    intent.validate(context)?;

    let expire_at = DateTime::from_timestamp(context.expire_time as i64, 0)
        .ok_or_else(|| WasmTonError::new("invalid expire_time"))?;

    let sender_addr = parse_address(&context.sender)?;

    let wallet_id = context
        .sub_wallet_id
        .map(|id| id as u32)
        .unwrap_or(V4R2::DEFAULT_WALLET_ID);

    let send_actions = build_send_actions(context, intent, sender_addr)?;

    let sign_body = WalletV4R2SignBody {
        wallet_id,
        expire_at,
        seqno: context.seqno,
        op: ton_contracts::wallet::v4r2::WalletV4R2Op::Send(send_actions),
    };

    let external_body = WalletV4R2ExternalBody {
        signature: [0u8; 64], // placeholder, to be filled by TSS
        body: sign_body,
    };

    // When seqno == 0 and publicKey is provided, include StateInit to deploy the wallet contract
    let init = if let (0, Some(public_key)) = (context.seqno, context.public_key.as_ref()) {
        let pubkey_bytes = hex::decode(public_key)
            .map_err(|e| WasmTonError::new(&format!("invalid publicKey hex: {e}")))?;
        if pubkey_bytes.len() != 32 {
            return Err(WasmTonError::new("publicKey must be 32 bytes"));
        }
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&pubkey_bytes);
        let typed_init = V4R2::state_init(wallet_id, pubkey);
        // Serialize typed StateInit fields to plain Cells for Message<_>
        let code_cell = typed_init.code.as_ref().map(|c| (**c).clone());
        let data_cell = typed_init
            .data
            .as_ref()
            .map(|d| {
                d.to_cell(()).map_err(|e| {
                    WasmTonError::new(&format!("failed to serialize StateInit data: {e}"))
                })
            })
            .transpose()?;
        Some(tlb_ton::state_init::StateInit {
            code: code_cell,
            data: data_cell,
            ..Default::default()
        })
    } else {
        None
    };

    let message: Message<WalletV4R2ExternalBody> = Message {
        info: CommonMsgInfo::ExternalIn(ExternalInMsgInfo {
            src: MsgAddress::NULL,
            dst: sender_addr,
            import_fee: BigUint::ZERO,
        }),
        init,
        body: external_body,
    };

    let cell = message
        .to_cell(())
        .map_err(|e| WasmTonError::new(&format!("failed to serialize message: {e}")))?;
    let boc = BagOfCells::from_root(cell);
    boc.serialize(BOC_ARGS)
        .map_err(|e| WasmTonError::new(&format!("failed to serialize BOC: {e}")))
}

fn build_send_actions(
    _context: &BuildContext,
    intent: &TonIntent,
    sender_addr: MsgAddress,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    match intent {
        TonIntent::Payment {
            to,
            amount,
            bounceable,
            memo,
        } => {
            let dst = parse_address(to)?;
            let bounce = bounceable.unwrap_or(false);
            let body = build_comment_body(memo.as_deref())?;
            Ok(vec![build_internal_send(dst, *amount, bounce, body, 3)])
        }

        TonIntent::TokenPayment {
            to,
            amount,
            jetton_address,
            ton_amount,
            forward_ton_amount,
            memo,
        } => {
            let jetton_wallet = parse_address(jetton_address)?;
            let dst = parse_address(to)?;

            let body = build_jetton_transfer_body(
                0, // query_id
                *amount,
                dst,
                sender_addr,
                *forward_ton_amount,
                memo.as_deref(),
            )?;

            Ok(vec![build_internal_send(
                jetton_wallet,
                *ton_amount,
                true,
                body,
                3,
            )])
        }

        TonIntent::FillNonce {
            is_token,
            jetton_address,
        } => {
            if *is_token {
                let jetton_wallet = parse_address(jetton_address.as_deref().ok_or_else(|| {
                    WasmTonError::new("jetton_address required for token fillNonce")
                })?)?;
                let body = build_jetton_transfer_body(0, 1, sender_addr, sender_addr, 100, None)?;
                Ok(vec![build_internal_send(
                    jetton_wallet,
                    100_000_000,
                    true,
                    body,
                    3,
                )])
            } else {
                let body = build_comment_body(None)?;
                Ok(vec![build_internal_send(sender_addr, 1, false, body, 3)])
            }
        }

        TonIntent::Consolidate {
            is_token,
            jetton_address,
        } => {
            if *is_token {
                let jetton_wallet = parse_address(jetton_address.as_deref().ok_or_else(|| {
                    WasmTonError::new("jetton_address required for token consolidate")
                })?)?;
                let body = build_jetton_transfer_body(0, 1, sender_addr, sender_addr, 100, None)?;
                Ok(vec![build_internal_send(
                    jetton_wallet,
                    100_000_000,
                    true,
                    body,
                    3,
                )])
            } else {
                let body = build_comment_body(None)?;
                Ok(vec![build_internal_send(sender_addr, 1, false, body, 3)])
            }
        }

        TonIntent::Delegate {
            amount,
            validator_address,
            staking_type,
            query_id,
        } => {
            let validator = parse_address(validator_address)?;

            match staking_type {
                TonStakingType::TonWhales => {
                    let body = build_whales_deposit_body(query_id.unwrap_or(0))?;
                    Ok(vec![build_internal_send(validator, *amount, true, body, 3)])
                }
                TonStakingType::SingleNominator => {
                    let body = build_comment_body(None)?;
                    Ok(vec![build_internal_send(validator, *amount, true, body, 3)])
                }
                TonStakingType::MultiNominator => {
                    let body = build_comment_body(Some("d"))?;
                    Ok(vec![build_internal_send(validator, *amount, true, body, 3)])
                }
            }
        }

        TonIntent::Undelegate {
            amount,
            validator_address,
            staking_type,
        } => {
            let validator = parse_address(validator_address)?;

            match staking_type {
                TonStakingType::TonWhales => {
                    let withdraw_amount = amount.unwrap_or(0);
                    let body = build_whales_withdraw_body(0, withdraw_amount)?;
                    Ok(vec![build_internal_send(
                        validator,
                        200_000_000,
                        true,
                        body,
                        3,
                    )])
                }
                TonStakingType::SingleNominator => {
                    let withdraw_amount = amount.unwrap_or(0);
                    let body = build_single_nominator_withdraw_body(0, withdraw_amount)?;
                    Ok(vec![build_internal_send(
                        validator,
                        200_000_000,
                        true,
                        body,
                        3,
                    )])
                }
                TonStakingType::MultiNominator => {
                    let body = build_comment_body(Some("w"))?;
                    Ok(vec![build_internal_send(
                        validator,
                        200_000_000,
                        true,
                        body,
                        3,
                    )])
                }
            }
        }
    }
}

fn parse_address(addr: &str) -> Result<MsgAddress, WasmTonError> {
    addr.parse::<MsgAddress>()
        .map_err(|e| WasmTonError::new(&format!("invalid address '{addr}': {e}")))
}

fn build_comment_body(memo: Option<&str>) -> Result<Cell, WasmTonError> {
    let mut builder = Cell::builder();
    if let Some(text) = memo {
        builder
            .pack(0u32, ())
            .map_err(|e| WasmTonError::new(&format!("failed to write comment opcode: {e}")))?;
        for byte in text.as_bytes() {
            builder
                .pack(*byte, ())
                .map_err(|e| WasmTonError::new(&format!("failed to write comment: {e}")))?;
        }
    }
    Ok(builder.into_cell())
}

fn build_jetton_transfer_body(
    query_id: u64,
    amount: u64,
    destination: MsgAddress,
    response_destination: MsgAddress,
    forward_ton_amount: u64,
    memo: Option<&str>,
) -> Result<Cell, WasmTonError> {
    let forward_payload = match memo {
        Some(text) => ForwardPayload::Comment(ForwardPayloadComment::Text(text.to_string())),
        None => ForwardPayload::Data(Cell::default()),
    };
    JettonTransfer::<Cell> {
        query_id,
        amount: BigUint::from(amount),
        dst: destination,
        response_dst: response_destination,
        custom_payload: None,
        forward_ton_amount: BigUint::from(forward_ton_amount),
        forward_payload,
    }
    .to_cell(())
    .map_err(|e| WasmTonError::new(&format!("jetton: failed to serialize transfer: {e}")))
}

fn build_whales_deposit_body(query_id: u64) -> Result<Cell, WasmTonError> {
    let mut builder = Cell::builder();
    builder
        .pack(WHALES_DEPOSIT_OPCODE, ())
        .map_err(|e| WasmTonError::new(&format!("whales deposit: failed to write opcode: {e}")))?;
    builder.pack(query_id, ()).map_err(|e| {
        WasmTonError::new(&format!("whales deposit: failed to write query_id: {e}"))
    })?;
    Ok(builder.into_cell())
}

fn build_whales_withdraw_body(query_id: u64, amount: u64) -> Result<Cell, WasmTonError> {
    let mut builder = Cell::builder();
    builder
        .pack(WHALES_WITHDRAW_OPCODE, ())
        .map_err(|e| WasmTonError::new(&format!("whales withdraw: failed to write opcode: {e}")))?;
    builder.pack(query_id, ()).map_err(|e| {
        WasmTonError::new(&format!("whales withdraw: failed to write query_id: {e}"))
    })?;
    builder
        .pack_as::<_, &Grams>(&BigUint::from(amount), ())
        .map_err(|e| WasmTonError::new(&format!("whales withdraw: failed to write amount: {e}")))?;
    Ok(builder.into_cell())
}

fn build_single_nominator_withdraw_body(query_id: u64, amount: u64) -> Result<Cell, WasmTonError> {
    let mut builder = Cell::builder();
    builder
        .pack(SINGLE_NOMINATOR_WITHDRAW_OPCODE, ())
        .map_err(|e| {
            WasmTonError::new(&format!(
                "single nominator withdraw: failed to write opcode: {e}"
            ))
        })?;
    builder.pack(query_id, ()).map_err(|e| {
        WasmTonError::new(&format!(
            "single nominator withdraw: failed to write query_id: {e}"
        ))
    })?;
    builder
        .pack_as::<_, &Grams>(&BigUint::from(amount), ())
        .map_err(|e| {
            WasmTonError::new(&format!(
                "single nominator withdraw: failed to write amount: {e}"
            ))
        })?;
    Ok(builder.into_cell())
}

fn build_internal_send(
    dst: MsgAddress,
    amount: u64,
    bounce: bool,
    body: Cell,
    mode: u8,
) -> SendMsgAction {
    let msg = Message {
        info: CommonMsgInfo::transfer(dst, BigUint::from(amount), bounce),
        init: None,
        body,
    };
    SendMsgAction { mode, message: msg }
}
