//! Transaction building logic.
//!
//! Converts high-level business intents into unsigned WalletV4R2 external messages.

use chrono::DateTime;
use num_bigint::BigUint;
use std::sync::Arc;
use tlb_ton::{
    action::SendMsgAction,
    bits::{ser::BitWriterExt, NoArgs},
    message::{CommonMsgInfo, ExternalInMsgInfo, Message},
    ser::{CellBuilderError, CellSerializeExt},
    BagOfCells, BagOfCellsArgs, Cell, MsgAddress,
};
use ton_contracts::wallet::{
    v4r2::{WalletV4R2ExternalBody, V4R2},
    WalletVersion,
};

use super::types::*;
use crate::error::WasmTonError;
use crate::transaction::Transaction;

// =============================================================================
// Opcode constants
// =============================================================================

/// Jetton transfer opcode (TEP-74)
const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;

/// TON Whales deposit opcode
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;

/// TON Whales withdrawal opcode
const WHALES_WITHDRAWAL_OPCODE: u32 = 0xda803efd;

/// Single nominator withdraw opcode
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x00001000;

/// Default TON amount for jetton transfers (0.1 TON = 100_000_000 nanotons)
const DEFAULT_JETTON_GAS_AMOUNT: u64 = 100_000_000;

/// Default forward TON amount for jetton transfers (1 nanoton)
const DEFAULT_FORWARD_TON_AMOUNT: u64 = 1;

/// Default send mode: pay transfer fees separately + ignore errors (3)
const DEFAULT_SEND_MODE: u8 = 3;

/// Send mode for consolidation: carry all remaining balance (128)
const SEND_MODE_CARRY_ALL: u8 = 128;

// =============================================================================
// Main entry point
// =============================================================================

/// Build an unsigned transaction from a business intent.
///
/// Returns a `Transaction` object ready for signing (signable_payload → addSignature → toBytes).
pub fn build_transaction(
    intent: &TonTransactionIntent,
    context: &BuildContext,
) -> Result<Transaction, WasmTonError> {
    // Build the inner message(s) based on intent type
    let actions = build_inner_messages(intent, context)?;

    // Construct the WalletV4R2SignBody
    let wallet_id = context.effective_wallet_id();
    let expire_at = DateTime::from_timestamp(context.expire_time as i64, 0).ok_or_else(|| {
        WasmTonError::InvalidInput(format!("Invalid expire_time: {}", context.expire_time))
    })?;

    let sign_body =
        V4R2::create_sign_body(wallet_id, expire_at, context.seqno, actions.into_iter());

    // Wrap in WalletV4R2ExternalBody with empty signature (unsigned)
    let external_body = WalletV4R2ExternalBody {
        signature: [0u8; 64],
        body: sign_body,
    };

    // Parse the sender address to get MsgAddress for the external message
    let sender_addr = parse_address(&context.sender_address)?;

    // Build the external message, with optional StateInit for seqno == 0
    let state_init = if context.seqno == 0 {
        let pubkey = context
            .public_key
            .as_ref()
            .ok_or_else(|| {
                WasmTonError::InvalidInput(
                    "publicKey is required when seqno == 0 (for StateInit)".into(),
                )
            })
            .and_then(|pk| parse_public_key(pk))?;
        Some(V4R2::state_init(wallet_id, pubkey))
    } else {
        None
    };

    let msg: Message<WalletV4R2ExternalBody, Arc<Cell>, _> = Message {
        info: CommonMsgInfo::ExternalIn(ExternalInMsgInfo {
            src: MsgAddress::NULL,
            dst: sender_addr,
            import_fee: BigUint::ZERO,
        }),
        init: state_init,
        body: external_body,
    };

    // Serialize to BOC
    let cell = msg.to_cell(NoArgs::EMPTY).map_err(|e| {
        WasmTonError::InvalidTransaction(format!("Failed to serialize message to cell: {}", e))
    })?;

    let boc = BagOfCells::from_root(cell);
    let bytes = boc
        .serialize(BagOfCellsArgs {
            has_idx: false,
            has_crc32c: true,
        })
        .map_err(|e| WasmTonError::InvalidTransaction(format!("Failed to serialize BOC: {}", e)))?;

    // Parse back into a Transaction for the caller
    Transaction::from_bytes(&bytes)
}

// =============================================================================
// Intent dispatch
// =============================================================================

fn build_inner_messages(
    intent: &TonTransactionIntent,
    context: &BuildContext,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    match intent {
        TonTransactionIntent::Payment {
            recipients,
            memo,
            is_token,
            sender_jetton_address,
            ton_amount,
            forward_ton_amount,
        } => {
            if *is_token {
                build_token_transfer(
                    recipients,
                    sender_jetton_address.as_deref().ok_or_else(|| {
                        WasmTonError::InvalidInput(
                            "senderJettonAddress required for token payment".into(),
                        )
                    })?,
                    *ton_amount,
                    *forward_ton_amount,
                    memo.as_deref(),
                    &context.sender_address,
                    DEFAULT_SEND_MODE,
                )
            } else {
                build_native_transfer(
                    recipients,
                    memo.as_deref(),
                    context.bounceable,
                    DEFAULT_SEND_MODE,
                )
            }
        }

        TonTransactionIntent::FillNonce {
            is_token,
            sender_jetton_address,
            ton_amount,
        } => {
            if *is_token {
                // Token fill nonce: self-send of 0 tokens via jetton wallet
                let self_recipient = Recipient {
                    address: context.sender_address.clone(),
                    amount: 0,
                };
                build_token_transfer(
                    &[self_recipient],
                    sender_jetton_address.as_deref().ok_or_else(|| {
                        WasmTonError::InvalidInput(
                            "senderJettonAddress required for token fillNonce".into(),
                        )
                    })?,
                    *ton_amount,
                    Some(DEFAULT_FORWARD_TON_AMOUNT),
                    None,
                    &context.sender_address,
                    DEFAULT_SEND_MODE,
                )
            } else {
                // Native fill nonce: self-send of 0 TON
                let self_recipient = Recipient {
                    address: context.sender_address.clone(),
                    amount: 0,
                };
                build_native_transfer(&[self_recipient], None, false, DEFAULT_SEND_MODE)
            }
        }

        TonTransactionIntent::Consolidate {
            recipients,
            is_token,
            sender_jetton_address,
            ton_amount,
            forward_ton_amount,
        } => {
            if *is_token {
                build_token_transfer(
                    recipients,
                    sender_jetton_address.as_deref().ok_or_else(|| {
                        WasmTonError::InvalidInput(
                            "senderJettonAddress required for token consolidate".into(),
                        )
                    })?,
                    *ton_amount,
                    *forward_ton_amount,
                    None,
                    &context.sender_address,
                    DEFAULT_SEND_MODE,
                )
            } else {
                // Native consolidation: send mode 128 (carry all remaining balance)
                build_native_transfer(recipients, None, false, SEND_MODE_CARRY_ALL)
            }
        }

        TonTransactionIntent::Delegate {
            staking_type,
            validator_address,
            amount,
        } => build_delegate(staking_type, validator_address, *amount, context),

        TonTransactionIntent::Undelegate {
            staking_type,
            validator_address,
            amount,
            withdrawal_amount,
        } => build_undelegate(staking_type, validator_address, *amount, *withdrawal_amount),
    }
}

// =============================================================================
// Native transfer
// =============================================================================

fn build_native_transfer(
    recipients: &[Recipient],
    memo: Option<&str>,
    bounceable: bool,
    send_mode: u8,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    if recipients.is_empty() {
        return Err(WasmTonError::InvalidInput(
            "At least one recipient is required".into(),
        ));
    }

    let mut actions = Vec::with_capacity(recipients.len());

    for (i, recipient) in recipients.iter().enumerate() {
        let dst = parse_address(&recipient.address)?;
        let body = if i == 0 {
            // Only the first message gets the memo
            build_text_comment_cell(memo)?
        } else {
            Cell::default()
        };

        let inner_msg = Message {
            info: CommonMsgInfo::Internal(tlb_ton::message::InternalMsgInfo::transfer(
                dst,
                BigUint::from(recipient.amount),
                bounceable,
            )),
            init: None::<tlb_ton::state_init::StateInit>,
            body,
        };

        actions.push(SendMsgAction {
            mode: send_mode,
            message: inner_msg.normalize().map_err(|e| {
                WasmTonError::InvalidTransaction(format!("Failed to normalize message: {}", e))
            })?,
        });
    }

    Ok(actions)
}

// =============================================================================
// Token (Jetton) transfer
// =============================================================================

fn build_token_transfer(
    recipients: &[Recipient],
    sender_jetton_address: &str,
    ton_amount: Option<u64>,
    forward_ton_amount: Option<u64>,
    memo: Option<&str>,
    response_address: &str,
    send_mode: u8,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    if recipients.is_empty() {
        return Err(WasmTonError::InvalidInput(
            "At least one recipient is required for token transfer".into(),
        ));
    }

    let jetton_wallet_addr = parse_address(sender_jetton_address)?;
    let response_addr = parse_address(response_address)?;
    let gas_amount = ton_amount.unwrap_or(DEFAULT_JETTON_GAS_AMOUNT);
    let fwd_amount = forward_ton_amount.unwrap_or(DEFAULT_FORWARD_TON_AMOUNT);

    let mut actions = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let dest_addr = parse_address(&recipient.address)?;

        // Build JettonTransfer body cell
        let jetton_body = build_jetton_transfer_cell(
            recipient.amount,
            dest_addr,
            response_addr,
            fwd_amount,
            memo,
        )?;

        let inner_msg = Message {
            info: CommonMsgInfo::Internal(tlb_ton::message::InternalMsgInfo::transfer(
                jetton_wallet_addr,
                BigUint::from(gas_amount),
                true, // jetton wallet messages are always bounceable
            )),
            init: None::<tlb_ton::state_init::StateInit>,
            body: jetton_body,
        };

        actions.push(SendMsgAction {
            mode: send_mode,
            message: inner_msg.normalize().map_err(|e| {
                WasmTonError::InvalidTransaction(format!(
                    "Failed to normalize jetton message: {}",
                    e
                ))
            })?,
        });
    }

    Ok(actions)
}

// =============================================================================
// Delegate (staking deposit)
// =============================================================================

fn build_delegate(
    staking_type: &TonStakingType,
    validator_address: &str,
    amount: u64,
    _context: &BuildContext,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    let dst = parse_address(validator_address)?;

    match staking_type {
        TonStakingType::TonWhales => {
            // Whales deposit: bounceable transfer with deposit opcode body
            let body = build_whales_deposit_cell()?;
            let inner_msg = Message {
                info: CommonMsgInfo::Internal(tlb_ton::message::InternalMsgInfo::transfer(
                    dst,
                    BigUint::from(amount),
                    true,
                )),
                init: None::<tlb_ton::state_init::StateInit>,
                body,
            };
            Ok(vec![SendMsgAction {
                mode: DEFAULT_SEND_MODE,
                message: inner_msg.normalize().map_err(|e| {
                    WasmTonError::InvalidTransaction(format!(
                        "Failed to normalize whales deposit: {}",
                        e
                    ))
                })?,
            }])
        }

        TonStakingType::SingleNominator => {
            // Simple bounceable transfer to validator
            build_native_transfer(
                &[Recipient {
                    address: validator_address.to_string(),
                    amount,
                }],
                None,
                true,
                DEFAULT_SEND_MODE,
            )
        }

        TonStakingType::MultiNominator => {
            // Bounceable transfer with memo='d'
            build_native_transfer(
                &[Recipient {
                    address: validator_address.to_string(),
                    amount,
                }],
                Some("d"),
                true,
                DEFAULT_SEND_MODE,
            )
        }
    }
}

// =============================================================================
// Undelegate (staking withdrawal)
// =============================================================================

fn build_undelegate(
    staking_type: &TonStakingType,
    validator_address: &str,
    amount: u64,
    withdrawal_amount: Option<u64>,
) -> Result<Vec<SendMsgAction>, WasmTonError> {
    let dst = parse_address(validator_address)?;

    match staking_type {
        TonStakingType::TonWhales => {
            let withdraw_amt = withdrawal_amount.ok_or_else(|| {
                WasmTonError::InvalidInput(
                    "withdrawalAmount is required for TonWhales undelegate".into(),
                )
            })?;

            let body = build_whales_withdrawal_cell(withdraw_amt)?;
            let inner_msg = Message {
                info: CommonMsgInfo::Internal(tlb_ton::message::InternalMsgInfo::transfer(
                    dst,
                    BigUint::from(amount),
                    true,
                )),
                init: None::<tlb_ton::state_init::StateInit>,
                body,
            };
            Ok(vec![SendMsgAction {
                mode: DEFAULT_SEND_MODE,
                message: inner_msg.normalize().map_err(|e| {
                    WasmTonError::InvalidTransaction(format!(
                        "Failed to normalize whales withdrawal: {}",
                        e
                    ))
                })?,
            }])
        }

        TonStakingType::SingleNominator => {
            let withdraw_amt = withdrawal_amount.ok_or_else(|| {
                WasmTonError::InvalidInput(
                    "withdrawalAmount is required for SingleNominator undelegate".into(),
                )
            })?;

            let body = build_single_nominator_withdraw_cell(withdraw_amt)?;
            let inner_msg = Message {
                info: CommonMsgInfo::Internal(tlb_ton::message::InternalMsgInfo::transfer(
                    dst,
                    BigUint::from(amount),
                    true,
                )),
                init: None::<tlb_ton::state_init::StateInit>,
                body,
            };
            Ok(vec![SendMsgAction {
                mode: DEFAULT_SEND_MODE,
                message: inner_msg.normalize().map_err(|e| {
                    WasmTonError::InvalidTransaction(format!(
                        "Failed to normalize single nominator withdrawal: {}",
                        e
                    ))
                })?,
            }])
        }

        TonStakingType::MultiNominator => {
            // Bounceable transfer with memo='w'
            build_native_transfer(
                &[Recipient {
                    address: validator_address.to_string(),
                    amount,
                }],
                Some("w"),
                true,
                DEFAULT_SEND_MODE,
            )
        }
    }
}

// =============================================================================
// Cell builders for specific body payloads
// =============================================================================

/// Build a text comment Cell (opcode 0x00000000 + UTF-8 text).
fn build_text_comment_cell(memo: Option<&str>) -> Result<Cell, WasmTonError> {
    match memo {
        Some(text) if !text.is_empty() => {
            let mut builder = Cell::builder();
            BitWriterExt::pack(&mut builder, 0u32, ()).map_err(cell_err)?;
            // Write text bytes
            for byte in text.as_bytes() {
                BitWriterExt::pack(&mut builder, *byte, ()).map_err(cell_err)?;
            }
            Ok(builder.into_cell())
        }
        _ => Ok(Cell::default()),
    }
}

/// Build JettonTransfer body Cell (TEP-74).
///
/// Format:
///   opcode: u32 = 0x0f8a7ea5
///   query_id: u64 = 0
///   amount: VarUInteger 16
///   destination: MsgAddress
///   response_destination: MsgAddress
///   custom_payload: Maybe ^Cell = false
///   forward_ton_amount: VarUInteger 16
///   forward_payload: Either Cell ^Cell
fn build_jetton_transfer_cell(
    amount: u64,
    destination: MsgAddress,
    response_destination: MsgAddress,
    forward_ton_amount: u64,
    memo: Option<&str>,
) -> Result<Cell, WasmTonError> {
    use tlb_ton::bits::VarInt;

    let mut builder = Cell::builder();
    BitWriterExt::pack(&mut builder, JETTON_TRANSFER_OPCODE, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, 0u64, ()).map_err(cell_err)?; // query_id
    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(amount), ())
        .map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, destination, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, response_destination, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, false, ()).map_err(cell_err)?; // custom_payload = None

    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(forward_ton_amount), ())
        .map_err(cell_err)?;

    // forward_payload: Either Cell ^Cell
    if let Some(text) = memo {
        if !text.is_empty() {
            let comment_cell = build_text_comment_cell(Some(text))?;
            BitWriterExt::pack(&mut builder, true, ()).map_err(cell_err)?;
            builder
                .store_as::<_, tlb_ton::Ref>(&comment_cell, ())
                .map_err(cell_err)?;
        } else {
            BitWriterExt::pack(&mut builder, false, ()).map_err(cell_err)?;
        }
    } else {
        BitWriterExt::pack(&mut builder, false, ()).map_err(cell_err)?;
    }

    Ok(builder.into_cell())
}

/// Build Whales deposit body Cell (opcode + query_id + gas_limit).
fn build_whales_deposit_cell() -> Result<Cell, WasmTonError> {
    use tlb_ton::bits::VarInt;

    let mut builder = Cell::builder();
    BitWriterExt::pack(&mut builder, WHALES_DEPOSIT_OPCODE, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, 0u64, ()).map_err(cell_err)?; // query_id
                                                                   // gas_limit: VarUInteger (Coins)
    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(0u64), ())
        .map_err(cell_err)?;
    Ok(builder.into_cell())
}

/// Build Whales withdrawal body Cell (opcode + query_id + gas_limit + amount).
fn build_whales_withdrawal_cell(withdrawal_amount: u64) -> Result<Cell, WasmTonError> {
    use tlb_ton::bits::VarInt;

    let mut builder = Cell::builder();
    BitWriterExt::pack(&mut builder, WHALES_WITHDRAWAL_OPCODE, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, 0u64, ()).map_err(cell_err)?; // query_id
                                                                   // gas_limit: VarUInteger (Coins)
    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(0u64), ())
        .map_err(cell_err)?;
    // withdrawal amount: VarUInteger (Coins)
    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(withdrawal_amount), ())
        .map_err(cell_err)?;
    Ok(builder.into_cell())
}

/// Build SingleNominator withdrawal body Cell (opcode + query_id + amount).
fn build_single_nominator_withdraw_cell(withdrawal_amount: u64) -> Result<Cell, WasmTonError> {
    use tlb_ton::bits::VarInt;

    let mut builder = Cell::builder();
    BitWriterExt::pack(&mut builder, SINGLE_NOMINATOR_WITHDRAW_OPCODE, ()).map_err(cell_err)?;
    BitWriterExt::pack(&mut builder, 0u64, ()).map_err(cell_err)?; // query_id
                                                                   // withdrawal amount: VarUInteger (Coins)
    BitWriterExt::pack_as::<_, VarInt<4>>(&mut builder, BigUint::from(withdrawal_amount), ())
        .map_err(cell_err)?;
    Ok(builder.into_cell())
}

// =============================================================================
// Helpers
// =============================================================================

/// Parse an address string (user-friendly or raw) to MsgAddress.
fn parse_address(address: &str) -> Result<MsgAddress, WasmTonError> {
    // Try user-friendly format first (48 chars base64)
    if address.len() == 48 {
        let (addr, _, _) = MsgAddress::from_base64_url_flags(address)
            .or_else(|_| MsgAddress::from_base64_std_flags(address))
            .map_err(|e| {
                WasmTonError::InvalidAddress(format!("Invalid user-friendly address: {}", e))
            })?;
        return Ok(addr);
    }

    // Try raw format (workchain:hex_hash)
    if address.contains(':') {
        let addr = MsgAddress::from_hex(address)
            .map_err(|e| WasmTonError::InvalidAddress(format!("Invalid raw address: {}", e)))?;
        return Ok(addr);
    }

    Err(WasmTonError::InvalidAddress(format!(
        "Unrecognized address format: {}",
        address
    )))
}

/// Parse a hex public key string to [u8; 32].
fn parse_public_key(hex_str: &str) -> Result<[u8; 32], WasmTonError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| WasmTonError::InvalidInput(format!("Invalid hex public key: {}", e)))?;
    if bytes.len() != 32 {
        return Err(WasmTonError::InvalidInput(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Convert CellBuilderError to WasmTonError.
fn cell_err(e: CellBuilderError) -> WasmTonError {
    WasmTonError::InvalidTransaction(format!("Cell build error: {}", e))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_transaction, TransactionType};

    fn test_context() -> BuildContext {
        BuildContext {
            sender_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            seqno: 10,
            public_key: None,
            expire_time: 1700000000,
            bounceable: false,
            is_vesting_contract: false,
            sub_wallet_id: None,
        }
    }

    fn test_context_with_pubkey() -> BuildContext {
        BuildContext {
            sender_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            seqno: 0,
            public_key: Some(
                "a26a1e5a8acab8c52e1bb9dd0e5cb8eee0ba403a7b5f3e1ec8c1cd0c1e1a3b2d".to_string(),
            ),
            expire_time: 1700000000,
            bounceable: false,
            is_vesting_contract: false,
            sub_wallet_id: None,
        }
    }

    // =========================================================================
    // Payment (native)
    // =========================================================================

    #[test]
    fn test_build_native_payment() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 1_000_000_000, // 1 TON
            }],
            memo: None,
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.output_amount, 1_000_000_000);
        assert_eq!(parsed.seqno, 10);
    }

    #[test]
    fn test_build_native_payment_with_memo() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 500_000_000,
            }],
            memo: Some("test memo".to_string()),
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.memo.as_deref(), Some("test memo"));
        assert_eq!(parsed.output_amount, 500_000_000);
    }

    // =========================================================================
    // Payment (token/jetton)
    // =========================================================================

    #[test]
    fn test_build_token_payment() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 1000, // 1000 jetton units
            }],
            memo: None,
            is_token: true,
            sender_jetton_address: Some(
                "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG".to_string(),
            ),
            ton_amount: Some(100_000_000), // 0.1 TON gas
            forward_ton_amount: Some(1),
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::SendToken);
        assert_eq!(parsed.jetton_amount, Some(1000));
        assert!(parsed.jetton_destination.is_some());
        assert_eq!(parsed.forward_ton_amount, Some(1));
    }

    // =========================================================================
    // FillNonce
    // =========================================================================

    #[test]
    fn test_build_fill_nonce_native() {
        let intent = TonTransactionIntent::FillNonce {
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.output_amount, 0);
        assert_eq!(parsed.seqno, 10);
    }

    // =========================================================================
    // Consolidate
    // =========================================================================

    #[test]
    fn test_build_consolidate_native() {
        let intent = TonTransactionIntent::Consolidate {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 5_000_000_000,
            }],
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        // Send mode 128 = carry all remaining balance
        assert_eq!(parsed.send_mode, 128);
    }

    // =========================================================================
    // Delegate
    // =========================================================================

    #[test]
    fn test_build_delegate_whales() {
        let intent = TonTransactionIntent::Delegate {
            staking_type: TonStakingType::TonWhales,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 10_000_000_000,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::TonWhalesDeposit);
        assert_eq!(parsed.output_amount, 10_000_000_000);
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_delegate_single_nominator() {
        let intent = TonTransactionIntent::Delegate {
            staking_type: TonStakingType::SingleNominator,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 5_000_000_000,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_delegate_multi_nominator() {
        let intent = TonTransactionIntent::Delegate {
            staking_type: TonStakingType::MultiNominator,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 5_000_000_000,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // Multi-nominator delegate uses memo='d', which parser detects as VestingDeposit
        // because the parser's opcode 0 + "d" maps to vesting deposit
        // This is correct behavior - the parser sees the same wire format
        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesVestingDeposit
        );
        assert_eq!(parsed.memo.as_deref(), Some("d"));
    }

    // =========================================================================
    // Undelegate
    // =========================================================================

    #[test]
    fn test_build_undelegate_whales() {
        let intent = TonTransactionIntent::Undelegate {
            staking_type: TonStakingType::TonWhales,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 1_000_000_000,
            withdrawal_amount: Some(5_000_000_000),
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesWithdrawal
        );
        assert!(parsed.bounceable);
    }

    #[test]
    fn test_build_undelegate_single_nominator() {
        let intent = TonTransactionIntent::Undelegate {
            staking_type: TonStakingType::SingleNominator,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 1_000_000_000, // 1 TON fee
            withdrawal_amount: Some(10_000_000_000),
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::SingleNominatorWithdraw
        );
    }

    #[test]
    fn test_build_undelegate_multi_nominator() {
        let intent = TonTransactionIntent::Undelegate {
            staking_type: TonStakingType::MultiNominator,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 1_000_000_000,
            withdrawal_amount: None,
        };

        let tx = build_transaction(&intent, &test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // Multi-nominator undelegate uses memo='w'
        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesVestingWithdrawal
        );
        assert_eq!(parsed.memo.as_deref(), Some("w"));
    }

    // =========================================================================
    // StateInit (seqno == 0)
    // =========================================================================

    #[test]
    fn test_build_with_state_init() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 1_000_000,
            }],
            memo: None,
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        let tx = build_transaction(&intent, &test_context_with_pubkey()).unwrap();
        assert!(tx.has_state_init());
        assert_eq!(tx.sign_body().seqno, 0);
    }

    // =========================================================================
    // Vesting wallet ID
    // =========================================================================

    #[test]
    fn test_vesting_wallet_id() {
        let mut ctx = test_context();
        ctx.is_vesting_contract = true;

        let intent = TonTransactionIntent::Delegate {
            staking_type: TonStakingType::TonWhales,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 10_000_000_000,
        };

        let tx = build_transaction(&intent, &ctx).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.wallet_id, 268);
    }

    // =========================================================================
    // Error cases
    // =========================================================================

    #[test]
    fn test_build_empty_recipients() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![],
            memo: None,
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        assert!(build_transaction(&intent, &test_context()).is_err());
    }

    #[test]
    fn test_build_token_without_jetton_address() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 100,
            }],
            memo: None,
            is_token: true,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        assert!(build_transaction(&intent, &test_context()).is_err());
    }

    #[test]
    fn test_build_whales_undelegate_without_withdrawal_amount() {
        let intent = TonTransactionIntent::Undelegate {
            staking_type: TonStakingType::TonWhales,
            validator_address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
            amount: 1_000_000_000,
            withdrawal_amount: None,
        };

        assert!(build_transaction(&intent, &test_context()).is_err());
    }

    // =========================================================================
    // Build → sign → toBroadcastFormat roundtrip
    // =========================================================================

    #[test]
    fn test_build_sign_roundtrip() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: "EQBGXZ9ddZeWypx8EkJieHJX75ct0bpkmu0Y4YoYr3NM0Z9e".to_string(),
                amount: 1_000_000_000,
            }],
            memo: Some("roundtrip test".to_string()),
            is_token: false,
            sender_jetton_address: None,
            ton_amount: None,
            forward_ton_amount: None,
        };

        let mut tx = build_transaction(&intent, &test_context()).unwrap();
        let payload = tx.signable_payload().unwrap();
        assert_eq!(payload.len(), 32);

        // Simulate signing
        let fake_sig = [42u8; 64];
        tx.add_signature(&fake_sig).unwrap();

        // Serialize and re-parse
        let broadcast = tx.to_broadcast_format().unwrap();
        let tx2 = Transaction::from_base64(&broadcast).unwrap();

        assert_eq!(tx2.sign_body().seqno, 10);
        assert_eq!(tx2.signature(), &fake_sig);

        let parsed = parse_transaction(&tx2).unwrap();
        assert_eq!(parsed.memo.as_deref(), Some("roundtrip test"));
    }
}
