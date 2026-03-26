//! Transaction building from intents.
//!
//! Converts business-level `TonTransactionIntent` + `TonBuildContext` into
//! an unsigned `TonTransaction` ready for signing.
//!
//! All building is offline. No network calls.

use std::sync::Arc;

use num_bigint::BigUint;
use num_traits::Zero;
use tonlib_core::cell::{ArcCell, CellBuilder};
use tonlib_core::message::{
    CommonMsgInfo, InternalMessage, JettonTransferMessage, TonMessage, TransferMessage,
    WithForwardPayload,
};
use tonlib_core::tlb_types::block::coins::Grams;
use tonlib_core::tlb_types::block::message::{
    CommonMsgInfo as TlbCommonMsgInfo, ExtInMsgInfo, Message,
};
use tonlib_core::tlb_types::block::msg_address::{MsgAddrNone, MsgAddressExt};
use tonlib_core::tlb_types::tlb::TLB;
use tonlib_core::types::TonAddress;
use tonlib_core::wallet::version_helper::VersionHelper;

use crate::error::WasmTonError;
use crate::transaction::TonTransaction;

use super::types::{Recipient, TonBuildContext, TonStakingType, TonTransactionIntent};

// Staking opcodes (matching parser.rs and BitGoJS constants)
const WHALES_DEPOSIT_OPCODE: u32 = 2_077_040_623; // 0x7BCD1FEF
const WHALES_WITHDRAWAL_OPCODE: u32 = 3_665_837_821; // 0xDA6A617D
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x1000;

// Token transfer constants
const JETTON_ATTACHED_AMOUNT: u64 = 100_000_000; // 0.1 TON in nanotons
const JETTON_FORWARD_AMOUNT: u64 = 100; // 100 nanoton forward amount

// Single nominator withdraw attached amount
const SINGLE_NOMINATOR_ATTACHED_AMOUNT: u64 = 1_000_000_000; // 1 TON

/// Build a transaction from a business-level intent and context.
///
/// The intent describes *what* to do and the context provides *how* to build it.
/// Returns an unsigned `TonTransaction` ready for `signable_payload()` and `add_signature()`.
pub fn build_transaction(
    intent: TonTransactionIntent,
    context: TonBuildContext,
) -> Result<TonTransaction, WasmTonError> {
    let wallet_version = context.parsed_wallet_version()?;
    let tonlib_version = wallet_version.as_tonlib();

    // Build internal messages based on intent
    let internal_msg_cells = build_internal_messages(&intent, &context)?;

    // Build the unsigned external message body via VersionHelper
    let unsigned_body = VersionHelper::build_ext_msg(
        tonlib_version,
        context.expire_time,
        context.seqno,
        context.wallet_id,
        &internal_msg_cells,
    )?;

    // Wrap in external message with zero signature (unsigned)
    let zero_sig = vec![0u8; 64];
    let signed_body = VersionHelper::sign_msg(tonlib_version, &unsigned_body, &zero_sig)?;

    let dest_address = TonAddress::from_base64_url(&context.sender)?;

    let ext_in_info = ExtInMsgInfo {
        src: MsgAddressExt::None(MsgAddrNone {}),
        dest: dest_address.to_msg_address_int(),
        import_fee: Grams::new(BigUint::zero()),
    };

    let mut message = Message::new(TlbCommonMsgInfo::ExtIn(ext_in_info), signed_body.to_arc());

    // Add state_init if seqno is 0 (first transaction from this wallet)
    if context.seqno == 0 {
        let public_key_bytes = hex::decode(&context.public_key)
            .map_err(|e| WasmTonError::StringError(format!("Invalid public key hex: {}", e)))?;
        let key_pair = tonlib_core::wallet::mnemonic::KeyPair {
            public_key: public_key_bytes,
            secret_key: vec![0u8; 64],
        };
        let code = VersionHelper::get_code(tonlib_version)?;
        let data = VersionHelper::get_data(tonlib_version, &key_pair, context.wallet_id)?;
        let state_init =
            tonlib_core::tlb_types::block::state_init::StateInit::new(code.clone(), data.to_arc());
        message.with_state_init(state_init);
    }

    let root_cell = message.to_cell()?;

    // Parse back into TonTransaction for a consistent API
    let boc = tonlib_core::cell::BagOfCells::from_root(root_cell);
    let bytes = boc.serialize(true)?;
    TonTransaction::from_boc(&bytes)
}

/// Build internal message cells from an intent.
fn build_internal_messages(
    intent: &TonTransactionIntent,
    context: &TonBuildContext,
) -> Result<Vec<ArcCell>, WasmTonError> {
    match intent {
        TonTransactionIntent::Payment {
            recipients,
            memo,
            bounceable,
            is_token,
            sender_jetton_wallet_address,
        } => {
            if *is_token {
                build_token_transfer_messages(
                    recipients,
                    memo.as_deref(),
                    sender_jetton_wallet_address.as_deref(),
                    &context.sender,
                )
            } else {
                build_native_transfer_messages(recipients, memo.as_deref(), *bounceable)
            }
        }

        TonTransactionIntent::FillNonce { sender, bounceable } => {
            let recipient = Recipient {
                address: sender.clone(),
                amount: 0,
            };
            build_native_transfer_messages(&[recipient], None, *bounceable)
        }

        TonTransactionIntent::Consolidate {
            recipients,
            receive_address: _,
            is_token,
            sender_jetton_wallet_address,
        } => {
            if *is_token {
                // Token consolidate forces memo=' ' (single space)
                build_token_transfer_messages(
                    recipients,
                    Some(" "),
                    sender_jetton_wallet_address.as_deref(),
                    &context.sender,
                )
            } else {
                build_native_transfer_messages(recipients, None, None)
            }
        }

        TonTransactionIntent::Delegate {
            validator_address,
            amount,
            staking_type,
        } => build_delegate_messages(validator_address, *amount, staking_type),

        TonTransactionIntent::Undelegate {
            validator_address,
            amount,
            staking_type,
            withdrawal_amount,
        } => {
            build_undelegate_messages(validator_address, *amount, staking_type, *withdrawal_amount)
        }
    }
}

// =============================================================================
// Native transfer
// =============================================================================

/// Build internal messages for native TON transfers.
fn build_native_transfer_messages(
    recipients: &[Recipient],
    memo: Option<&str>,
    bounceable: Option<bool>,
) -> Result<Vec<ArcCell>, WasmTonError> {
    let mut cells = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let dest = TonAddress::from_base64_url(&recipient.address)?;
        let bounce = bounceable.unwrap_or(true);

        let body = build_comment_cell(memo)?;

        let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
            ihr_disabled: true,
            bounce,
            bounced: false,
            src: TonAddress::NULL,
            dest,
            value: BigUint::from(recipient.amount),
            ihr_fee: BigUint::zero(),
            fwd_fee: BigUint::zero(),
            created_lt: 0,
            created_at: 0,
        });

        let transfer = TransferMessage::new(msg_info, body);
        let cell = transfer.build().map_err(|e| {
            WasmTonError::CellError(format!("Failed to build transfer message: {}", e))
        })?;
        cells.push(Arc::new(cell));
    }

    Ok(cells)
}

// =============================================================================
// Token (Jetton) transfer
// =============================================================================

/// Build internal messages for Jetton (token) transfers.
///
/// Each recipient becomes a JettonTransferMessage sent to the sender's Jetton wallet.
/// The Jetton wallet contract then forwards tokens to the destination.
fn build_token_transfer_messages(
    recipients: &[Recipient],
    memo: Option<&str>,
    sender_jetton_wallet_address: Option<&str>,
    sender_address: &str,
) -> Result<Vec<ArcCell>, WasmTonError> {
    let jetton_wallet = sender_jetton_wallet_address.ok_or_else(|| {
        WasmTonError::StringError(
            "senderJettonWalletAddress is required for token transfers".to_string(),
        )
    })?;

    let jetton_wallet_addr = TonAddress::from_base64_url(jetton_wallet)?;
    let response_addr = TonAddress::from_base64_url(sender_address)?;

    let mut cells = Vec::with_capacity(recipients.len());

    for recipient in recipients {
        let dest = TonAddress::from_base64_url(&recipient.address)?;

        // Build the Jetton transfer body
        let mut jetton_msg = JettonTransferMessage::new(&dest, &BigUint::from(recipient.amount));
        jetton_msg.with_response_destination(&response_addr);

        // Add forward payload with memo if present
        if let Some(memo_text) = memo {
            let comment_cell = build_comment_cell(Some(memo_text))?;
            jetton_msg.with_forward_payload(BigUint::from(JETTON_FORWARD_AMOUNT), comment_cell);
        } else {
            // Even without memo, set forward amount to 100 nanoton
            jetton_msg.forward_ton_amount = BigUint::from(JETTON_FORWARD_AMOUNT);
        }

        let jetton_body = jetton_msg.build().map_err(|e| {
            WasmTonError::CellError(format!("Failed to build jetton transfer: {}", e))
        })?;

        // Wrap in internal message to the Jetton wallet with 0.1 TON attached
        let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
            ihr_disabled: true,
            bounce: true,
            bounced: false,
            src: TonAddress::NULL,
            dest: jetton_wallet_addr.clone(),
            value: BigUint::from(JETTON_ATTACHED_AMOUNT),
            ihr_fee: BigUint::zero(),
            fwd_fee: BigUint::zero(),
            created_lt: 0,
            created_at: 0,
        });

        let transfer = TransferMessage::new(msg_info, Arc::new(jetton_body));
        let cell = transfer.build().map_err(|e| {
            WasmTonError::CellError(format!("Failed to build token transfer message: {}", e))
        })?;
        cells.push(Arc::new(cell));
    }

    Ok(cells)
}

// =============================================================================
// Staking: delegate
// =============================================================================

/// Build internal messages for staking deposits.
fn build_delegate_messages(
    validator_address: &str,
    amount: u64,
    staking_type: &TonStakingType,
) -> Result<Vec<ArcCell>, WasmTonError> {
    let dest = TonAddress::from_base64_url(validator_address)?;

    match staking_type {
        TonStakingType::TonWhales => {
            // Build deposit Cell: opcode 0x7BCD1FEF + queryId(u64) + deposit_amount(coins)
            let mut builder = CellBuilder::new();
            builder.store_u32(32, WHALES_DEPOSIT_OPCODE)?;
            builder.store_u64(64, 0)?; // queryId = 0
            builder.store_coins(&BigUint::from(amount))?;
            let body = Arc::new(builder.build()?);

            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(amount),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!("Failed to build Whales deposit: {}", e))
            })?;
            Ok(vec![Arc::new(cell)])
        }

        TonStakingType::SingleNominator => {
            // Simple transfer with bounceable=true to validator
            let body = build_comment_cell(None)?;
            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(amount),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!("Failed to build SingleNominator deposit: {}", e))
            })?;
            Ok(vec![Arc::new(cell)])
        }

        TonStakingType::MultiNominator => {
            // Transfer with memo='d' to validator
            let body = build_comment_cell(Some("d"))?;
            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(amount),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!("Failed to build MultiNominator deposit: {}", e))
            })?;
            Ok(vec![Arc::new(cell)])
        }
    }
}

// =============================================================================
// Staking: undelegate
// =============================================================================

/// Build internal messages for staking withdrawals.
fn build_undelegate_messages(
    validator_address: &str,
    amount: u64,
    staking_type: &TonStakingType,
    withdrawal_amount: Option<u64>,
) -> Result<Vec<ArcCell>, WasmTonError> {
    let dest = TonAddress::from_base64_url(validator_address)?;

    match staking_type {
        TonStakingType::TonWhales => {
            // Build withdrawal Cell: opcode 0xDA6A617D + queryId(u64) + withdrawal_amount(coins)
            let withdraw_coins = withdrawal_amount.unwrap_or(amount);
            let mut builder = CellBuilder::new();
            builder.store_u32(32, WHALES_WITHDRAWAL_OPCODE)?;
            builder.store_u64(64, 0)?; // queryId = 0
            builder.store_coins(&BigUint::from(withdraw_coins))?;
            let body = Arc::new(builder.build()?);

            // Attached amount: use the intent amount if non-zero, else a small amount
            let attached = if amount > 0 { amount } else { 200_000_000 }; // 0.2 TON default

            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(attached),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!("Failed to build Whales withdrawal: {}", e))
            })?;
            Ok(vec![Arc::new(cell)])
        }

        TonStakingType::SingleNominator => {
            // Build SingleNominator withdraw Cell: opcode 0x1000 + queryId(u64) + amount(coins)
            let mut builder = CellBuilder::new();
            builder.store_u32(32, SINGLE_NOMINATOR_WITHDRAW_OPCODE)?;
            builder.store_u64(64, 0)?; // queryId = 0
            builder.store_coins(&BigUint::from(amount))?;
            let body = Arc::new(builder.build()?);

            // Attach 1 TON for the withdrawal operation
            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(SINGLE_NOMINATOR_ATTACHED_AMOUNT),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!(
                    "Failed to build SingleNominator withdrawal: {}",
                    e
                ))
            })?;
            Ok(vec![Arc::new(cell)])
        }

        TonStakingType::MultiNominator => {
            // Transfer with memo='w' to validator
            let body = build_comment_cell(Some("w"))?;
            let msg_info = CommonMsgInfo::InternalMessage(InternalMessage {
                ihr_disabled: true,
                bounce: true,
                bounced: false,
                src: TonAddress::NULL,
                dest,
                value: BigUint::from(amount),
                ihr_fee: BigUint::zero(),
                fwd_fee: BigUint::zero(),
                created_lt: 0,
                created_at: 0,
            });

            let transfer = TransferMessage::new(msg_info, body);
            let cell = transfer.build().map_err(|e| {
                WasmTonError::CellError(format!("Failed to build MultiNominator withdrawal: {}", e))
            })?;
            Ok(vec![Arc::new(cell)])
        }
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Build a comment cell (opcode 0 + UTF-8 text).
///
/// Returns an empty cell if no memo is provided.
fn build_comment_cell(memo: Option<&str>) -> Result<ArcCell, WasmTonError> {
    match memo {
        Some(text) if !text.is_empty() => {
            let mut builder = CellBuilder::new();
            builder.store_u32(32, 0)?; // text comment opcode
            builder.store_slice(text.as_bytes())?;
            Ok(Arc::new(builder.build()?))
        }
        _ => {
            let mut builder = CellBuilder::new();
            Ok(Arc::new(builder.build()?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{parse_transaction, TransactionType};

    const TEST_PUBLIC_KEY: &str =
        "f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f";
    const TEST_RECIPIENT: &str = "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG";
    const TEST_VALIDATOR: &str = "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq";

    /// Derive the sender address from the test public key so it's always valid.
    fn test_sender() -> String {
        crate::encode_address(
            &hex::decode(TEST_PUBLIC_KEY).unwrap(),
            true,
            crate::WalletVersion::V4R2,
        )
        .unwrap()
    }

    fn test_context() -> TonBuildContext {
        TonBuildContext {
            sender: test_sender(),
            public_key: TEST_PUBLIC_KEY.to_string(),
            seqno: 10,
            expire_time: 1700000000,
            wallet_version: "V4R2".to_string(),
            wallet_id: 698983191,
        }
    }

    #[test]
    fn test_build_native_payment() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: TEST_RECIPIENT.to_string(),
                amount: 10_000_000,
            }],
            memo: None,
            bounceable: None,
            is_token: false,
            sender_jetton_wallet_address: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.recipients.len(), 1);
        assert_eq!(parsed.recipients[0].amount, 10_000_000);
        assert_eq!(parsed.seqno, 10);
        assert_eq!(parsed.expire_time, 1_700_000_000);
    }

    #[test]
    fn test_build_native_payment_with_memo() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: TEST_RECIPIENT.to_string(),
                amount: 50_000_000,
            }],
            memo: Some("hello world".to_string()),
            bounceable: Some(false),
            is_token: false,
            sender_jetton_wallet_address: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.memo.as_deref(), Some("hello world"));
        assert_eq!(parsed.recipients[0].amount, 50_000_000);
    }

    #[test]
    fn test_build_multiple_recipients() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![
                Recipient {
                    address: TEST_RECIPIENT.to_string(),
                    amount: 10_000_000,
                },
                Recipient {
                    address: TEST_VALIDATOR.to_string(),
                    amount: 20_000_000,
                },
            ],
            memo: None,
            bounceable: None,
            is_token: false,
            sender_jetton_wallet_address: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.recipients.len(), 2);
        assert_eq!(parsed.recipients[0].amount, 10_000_000);
        assert_eq!(parsed.recipients[1].amount, 20_000_000);
    }

    #[test]
    fn test_build_fill_nonce() {
        let intent = TonTransactionIntent::FillNonce {
            sender: test_sender(),
            bounceable: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.recipients.len(), 1);
        assert_eq!(parsed.recipients[0].amount, 0);
    }

    #[test]
    fn test_build_delegate_whales() {
        let intent = TonTransactionIntent::Delegate {
            validator_address: TEST_VALIDATOR.to_string(),
            amount: 10_000_000_000,
            staking_type: TonStakingType::TonWhales,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::TonWhalesDeposit);
        assert_eq!(parsed.recipients.len(), 1);
    }

    #[test]
    fn test_build_delegate_single_nominator() {
        let intent = TonTransactionIntent::Delegate {
            validator_address: TEST_VALIDATOR.to_string(),
            amount: 5_000_000_000,
            staking_type: TonStakingType::SingleNominator,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // SingleNominator deposit is just a transfer, so it parses as Send
        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.recipients[0].amount, 5_000_000_000);
    }

    #[test]
    fn test_build_delegate_multi_nominator() {
        let intent = TonTransactionIntent::Delegate {
            validator_address: TEST_VALIDATOR.to_string(),
            amount: 5_000_000_000,
            staking_type: TonStakingType::MultiNominator,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // MultiNominator deposit has memo='d'
        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.memo.as_deref(), Some("d"));
    }

    #[test]
    fn test_build_undelegate_whales() {
        let intent = TonTransactionIntent::Undelegate {
            validator_address: TEST_VALIDATOR.to_string(),
            amount: 200_000_000,
            staking_type: TonStakingType::TonWhales,
            withdrawal_amount: Some(5_000_000_000),
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesWithdrawal
        );
    }

    #[test]
    fn test_build_undelegate_single_nominator() {
        let intent = TonTransactionIntent::Undelegate {
            validator_address: TEST_RECIPIENT.to_string(),
            amount: 123_400_000,
            staking_type: TonStakingType::SingleNominator,
            withdrawal_amount: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::SingleNominatorWithdraw
        );
        // Attached amount should be 1 TON
        assert_eq!(parsed.recipients[0].amount, 1_000_000_000);
    }

    #[test]
    fn test_build_undelegate_multi_nominator() {
        let intent = TonTransactionIntent::Undelegate {
            validator_address: TEST_VALIDATOR.to_string(),
            amount: 1_000_000_000,
            staking_type: TonStakingType::MultiNominator,
            withdrawal_amount: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.memo.as_deref(), Some("w"));
    }

    #[test]
    fn test_build_roundtrip() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: TEST_RECIPIENT.to_string(),
                amount: 10_000_000,
            }],
            memo: Some("roundtrip test".to_string()),
            bounceable: None,
            is_token: false,
            sender_jetton_wallet_address: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();

        // Roundtrip through serialization
        let bytes = tx.to_boc().unwrap();
        let tx2 = TonTransaction::from_boc(&bytes).unwrap();

        assert_eq!(tx.seqno, tx2.seqno);
        assert_eq!(tx.expire_time, tx2.expire_time);
        assert_eq!(tx.wallet_id, tx2.wallet_id);
        assert_eq!(tx.signable_payload(), tx2.signable_payload());
    }

    #[test]
    fn test_build_consolidate() {
        let intent = TonTransactionIntent::Consolidate {
            recipients: vec![Recipient {
                address: TEST_RECIPIENT.to_string(),
                amount: 50_000_000,
            }],
            receive_address: TEST_RECIPIENT.to_string(),
            is_token: false,
            sender_jetton_wallet_address: None,
        };
        let tx = build_transaction(intent, test_context()).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.recipients[0].amount, 50_000_000);
    }

    #[test]
    fn test_token_transfer_requires_jetton_wallet() {
        let intent = TonTransactionIntent::Payment {
            recipients: vec![Recipient {
                address: TEST_RECIPIENT.to_string(),
                amount: 1_000_000_000,
            }],
            memo: None,
            bounceable: None,
            is_token: true,
            sender_jetton_wallet_address: None,
        };
        let result = build_transaction(intent, test_context());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("senderJettonWalletAddress"));
    }
}
