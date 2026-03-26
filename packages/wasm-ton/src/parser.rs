//! High-level TON transaction parser.
//!
//! Provides `parse_transaction` that extracts structured data from a TonTransaction,
//! including internal message details, Jetton transfers, and staking operations.

use crate::error::WasmTonError;
use crate::js_obj;
use crate::transaction::TonTransaction;
use crate::wasm::try_into_js_value::{JsConversionError, TryIntoJsValue};
use tonlib_core::cell::ArcCell;
use tonlib_core::message::JETTON_TRANSFER;
use tonlib_core::tlb_types::block::message::{CommonMsgInfo, IntMsgInfo, Message};
use tonlib_core::tlb_types::block::msg_address::{MsgAddress, MsgAddressInt};
use tonlib_core::tlb_types::tlb::TLB;
use tonlib_core::types::TonAddress;
use wasm_bindgen::JsValue;

// Staking opcodes (from BitGoJS sdk-coin-ton/src/lib/constants.ts)
// TON_WHALES_DEPOSIT_OPCODE = '2077040623' (decimal) = 0x7BCD1FEF
const WHALES_DEPOSIT_OPCODE: u32 = 2_077_040_623;
// TON_WHALES_WITHDRAW_OPCODE = '3665837821' (decimal) = 0xDA6A617D
const WHALES_WITHDRAWAL_OPCODE: u32 = 3_665_837_821;
// WITHDRAW_OPCODE = '00001000' (hex) = 0x1000 = 4096
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x1000;

/// Transaction type classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionType {
    Send,
    SendToken,
    SingleNominatorWithdraw,
    TonWhalesDeposit,
    TonWhalesWithdrawal,
}

impl std::fmt::Display for TransactionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionType::Send => write!(f, "Send"),
            TransactionType::SendToken => write!(f, "SendToken"),
            TransactionType::SingleNominatorWithdraw => write!(f, "SingleNominatorWithdraw"),
            TransactionType::TonWhalesDeposit => write!(f, "TonWhalesDeposit"),
            TransactionType::TonWhalesWithdrawal => write!(f, "TonWhalesWithdrawal"),
        }
    }
}

impl TryIntoJsValue for TransactionType {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        Ok(JsValue::from_str(&self.to_string()))
    }
}

/// Parsed recipient information from an internal message.
#[derive(Debug, Clone)]
pub struct ParsedRecipient {
    /// Destination address (bounceable base64url)
    pub address: String,
    /// Amount in nanotons
    pub amount: u64,
    /// Whether the address is bounceable
    pub bounceable: bool,
}

impl TryIntoJsValue for ParsedRecipient {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "address" => self.address,
            "amount" => self.amount,
            "bounceable" => self.bounceable
        )
    }
}

/// Parsed Jetton transfer details.
#[derive(Debug, Clone)]
pub struct ParsedJettonTransfer {
    /// Query ID from the Jetton transfer
    pub query_id: u64,
    /// Jetton amount (as string, since BigUint)
    pub amount: String,
    /// Destination address
    pub destination: String,
    /// Response destination address
    pub response_destination: String,
    /// Forward TON amount in nanotons (as string)
    pub forward_ton_amount: String,
    /// Forward payload comment (if text)
    pub forward_payload_comment: Option<String>,
}

impl TryIntoJsValue for ParsedJettonTransfer {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "queryId" => self.query_id,
            "amount" => self.amount,
            "destination" => self.destination,
            "responseDestination" => self.response_destination,
            "forwardTonAmount" => self.forward_ton_amount,
            "forwardPayloadComment" => self.forward_payload_comment
        )
    }
}

/// Fully parsed TON transaction.
#[derive(Debug, Clone)]
pub struct ParsedTonTransaction {
    /// Sender wallet address (bounceable, from destination of external message)
    pub sender: String,
    /// Recipients with amounts
    pub recipients: Vec<ParsedRecipient>,
    /// Sequence number
    pub seqno: u32,
    /// Expiration time (unix timestamp)
    pub expire_time: u32,
    /// Sub-wallet ID
    pub wallet_id: i32,
    /// Memo/comment from internal message body (if present)
    pub memo: Option<String>,
    /// Transaction type classification
    pub transaction_type: TransactionType,
    /// Transaction ID (base64url hash)
    pub id: Option<String>,
    /// Jetton transfer details (if applicable)
    pub jetton_transfer: Option<ParsedJettonTransfer>,
    /// Wallet version
    pub wallet_version: String,
}

impl TryIntoJsValue for ParsedTonTransaction {
    fn try_to_js_value(&self) -> Result<JsValue, JsConversionError> {
        js_obj!(
            "sender" => self.sender,
            "recipients" => self.recipients,
            "seqno" => self.seqno,
            "expireTime" => self.expire_time,
            "walletId" => self.wallet_id,
            "memo" => self.memo,
            "transactionType" => self.transaction_type,
            "id" => self.id,
            "jettonTransfer" => self.jetton_transfer,
            "walletVersion" => self.wallet_version
        )
    }
}

/// Parse a TonTransaction into structured data.
///
/// Extracts recipients, amounts, memos, transaction type, and Jetton/staking details.
pub fn parse_transaction(tx: &TonTransaction) -> Result<ParsedTonTransaction, WasmTonError> {
    let sender = tx.destination.to_base64_url_flags(false, false);

    let mut recipients = Vec::new();
    let mut memo = None;
    let mut transaction_type = TransactionType::Send;
    let mut jetton_transfer = None;

    for msg_cell in &tx.internal_messages {
        let parsed = parse_internal_message(msg_cell)?;

        if let Some(ref recipient) = parsed.recipient {
            recipients.push(recipient.clone());
        }

        // Check for memo in message body
        if parsed.memo.is_some() && memo.is_none() {
            memo = parsed.memo.clone();
        }

        // Detect transaction type from opcode
        match parsed.detected_type {
            Some(DetectedType::JettonTransfer(jt)) => {
                transaction_type = TransactionType::SendToken;
                jetton_transfer = Some(jt);
            }
            Some(DetectedType::WhalesDeposit) => {
                transaction_type = TransactionType::TonWhalesDeposit;
            }
            Some(DetectedType::WhalesWithdrawal) => {
                transaction_type = TransactionType::TonWhalesWithdrawal;
            }
            Some(DetectedType::SingleNominatorWithdraw) => {
                transaction_type = TransactionType::SingleNominatorWithdraw;
            }
            None => {}
        }
    }

    Ok(ParsedTonTransaction {
        sender,
        recipients,
        seqno: tx.seqno,
        expire_time: tx.expire_time,
        wallet_id: tx.wallet_id,
        memo,
        transaction_type,
        id: tx.id(),
        jetton_transfer,
        wallet_version: format!("{:?}", tx.wallet_version),
    })
}

/// Detected special message type.
enum DetectedType {
    JettonTransfer(ParsedJettonTransfer),
    WhalesDeposit,
    WhalesWithdrawal,
    SingleNominatorWithdraw,
}

/// Result of parsing a single internal message.
struct ParsedInternalMsg {
    recipient: Option<ParsedRecipient>,
    memo: Option<String>,
    detected_type: Option<DetectedType>,
}

/// Parse a single internal message cell.
fn parse_internal_message(msg_cell: &ArcCell) -> Result<ParsedInternalMsg, WasmTonError> {
    let message = Message::from_cell(msg_cell)?;

    let (dest_address, amount, bounceable) = match &message.info {
        CommonMsgInfo::Int(int_msg) => extract_int_msg_info(int_msg)?,
        _ => {
            return Ok(ParsedInternalMsg {
                recipient: None,
                memo: None,
                detected_type: None,
            })
        }
    };

    // Parse the message body for opcode, memo, etc.
    let body_cell = &message.body.value;
    let (memo, detected_type) = parse_message_body(body_cell, &dest_address)?;

    let recipient = ParsedRecipient {
        address: dest_address,
        amount,
        bounceable,
    };

    Ok(ParsedInternalMsg {
        recipient: Some(recipient),
        memo,
        detected_type,
    })
}

/// Extract address, amount, and bounceable flag from IntMsgInfo.
fn extract_int_msg_info(int_msg: &IntMsgInfo) -> Result<(String, u64, bool), WasmTonError> {
    let bounceable = int_msg.bounce;

    let dest_address = match &int_msg.dest {
        MsgAddress::Int(addr_int) => {
            let ton_addr = msg_address_int_to_ton_address(addr_int)?;
            // Encode with bounceable flag matching the message
            ton_addr.to_base64_url_flags(!bounceable, false)
        }
        _ => "unknown".to_string(),
    };

    // Extract amount from value.grams
    let amount = coins_to_u64(&int_msg.value.grams.amount);

    Ok((dest_address, amount, bounceable))
}

/// Convert MsgAddressInt to TonAddress.
fn msg_address_int_to_ton_address(addr: &MsgAddressInt) -> Result<TonAddress, WasmTonError> {
    match addr {
        MsgAddressInt::Std(std_addr) => {
            if std_addr.address.len() != 32 {
                return Err(WasmTonError::AddressError(format!(
                    "Expected 32-byte address hash, got {}",
                    std_addr.address.len()
                )));
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&std_addr.address);
            let ton_hash = tonlib_core::TonHash::from(hash);
            Ok(TonAddress::new(std_addr.workchain, ton_hash))
        }
        MsgAddressInt::Var(_) => Err(WasmTonError::AddressError(
            "Variable-length address not supported".to_string(),
        )),
    }
}

/// Convert BigUint coins to u64 nanotons.
fn coins_to_u64(coins: &num_bigint::BigUint) -> u64 {
    use num_traits::ToPrimitive;
    coins.to_u64().unwrap_or(0)
}

/// Parse the body of an internal message for opcodes and memos.
fn parse_message_body(
    body_cell: &ArcCell,
    _dest_address: &str,
) -> Result<(Option<String>, Option<DetectedType>), WasmTonError> {
    if body_cell.bit_len() == 0 && body_cell.references().is_empty() {
        return Ok((None, None));
    }

    // If body has no bits but has a reference, the actual body is in the reference
    let effective_cell: &ArcCell = if body_cell.bit_len() == 0 && !body_cell.references().is_empty()
    {
        &body_cell.references()[0]
    } else {
        body_cell
    };

    let mut parser = effective_cell.parser();

    // Try to read a 32-bit opcode
    if effective_cell.bit_len() >= 32 {
        let opcode = parser.load_u32(32).unwrap_or(0);

        match opcode {
            0 => {
                // Text comment: opcode 0 followed by UTF-8 text
                let remaining_bytes = (effective_cell.bit_len() - 32) / 8;
                if remaining_bytes > 0 {
                    if let Ok(text_bytes) = parser.load_bytes(remaining_bytes) {
                        if let Ok(text) = String::from_utf8(text_bytes) {
                            if !text.is_empty() {
                                return Ok((Some(text), None));
                            }
                        }
                    }
                }
                Ok((None, None))
            }
            JETTON_TRANSFER => {
                // Jetton transfer: parse fields
                parse_jetton_transfer_body(&mut parser, effective_cell)
            }
            WHALES_DEPOSIT_OPCODE => Ok((None, Some(DetectedType::WhalesDeposit))),
            WHALES_WITHDRAWAL_OPCODE => Ok((None, Some(DetectedType::WhalesWithdrawal))),
            SINGLE_NOMINATOR_WITHDRAW_OPCODE => {
                Ok((None, Some(DetectedType::SingleNominatorWithdraw)))
            }
            _ => Ok((None, None)),
        }
    } else {
        Ok((None, None))
    }
}

/// Parse a Jetton transfer message body (after the opcode has been consumed).
fn parse_jetton_transfer_body(
    parser: &mut tonlib_core::cell::CellParser,
    body_cell: &ArcCell,
) -> Result<(Option<String>, Option<DetectedType>), WasmTonError> {
    // query_id: uint64
    let query_id = parser.load_u64(64).unwrap_or(0);
    // amount: VarUInteger 16
    let amount = parser
        .load_coins()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| "0".to_string());
    // destination: MsgAddress
    let destination = parser
        .load_address()
        .map(|a| a.to_base64_url_flags(false, false))
        .unwrap_or_else(|_| "unknown".to_string());
    // response_destination: MsgAddress
    let response_destination = parser
        .load_address()
        .map(|a| a.to_base64_url_flags(false, false))
        .unwrap_or_else(|_| "unknown".to_string());
    // custom_payload: Maybe ^Cell (skip)
    let _custom_payload = parser.load_maybe_cell_ref().ok();
    // forward_ton_amount: VarUInteger 16
    let forward_ton_amount = parser
        .load_coins()
        .map(|c| c.to_string())
        .unwrap_or_else(|_| "0".to_string());

    // Try to read forward_payload comment
    let forward_payload_comment = extract_forward_payload_comment(parser, body_cell);

    let jt = ParsedJettonTransfer {
        query_id,
        amount,
        destination,
        response_destination,
        forward_ton_amount,
        forward_payload_comment: forward_payload_comment.clone(),
    };

    Ok((
        forward_payload_comment,
        Some(DetectedType::JettonTransfer(jt)),
    ))
}

/// Try to extract a text comment from the forward payload.
fn extract_forward_payload_comment(
    parser: &mut tonlib_core::cell::CellParser,
    _body_cell: &ArcCell,
) -> Option<String> {
    // forward_payload: Either Cell ^Cell
    // If bit 0, inline; if bit 1, reference
    let is_ref = parser.load_bit().ok()?;
    if is_ref {
        // Reference: try to parse the referenced cell
        let ref_cell = parser.next_reference().ok()?;
        parse_text_comment(&ref_cell)
    } else {
        // Inline: remaining bits in the current cell
        // Try to read remaining as text (opcode 0 + text)
        let remaining_bits = parser.remaining_bits();
        if remaining_bits >= 32 {
            let opcode = parser.load_u32(32).ok()?;
            if opcode == 0 {
                let text_bytes_len = (remaining_bits - 32) / 8;
                if text_bytes_len > 0 {
                    let bytes = parser.load_bytes(text_bytes_len).ok()?;
                    return String::from_utf8(bytes).ok();
                }
            }
        }
        None
    }
}

/// Parse a cell as a text comment (opcode 0 + UTF-8 text).
fn parse_text_comment(cell: &ArcCell) -> Option<String> {
    if cell.bit_len() < 32 {
        return None;
    }
    let mut parser = cell.parser();
    let opcode = parser.load_u32(32).ok()?;
    if opcode != 0 {
        return None;
    }
    let remaining = (cell.bit_len() - 32) / 8;
    if remaining == 0 {
        return None;
    }
    let bytes = parser.load_bytes(remaining).ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    #[test]
    fn test_parse_send_transaction() {
        let tx = TonTransaction::from_base64(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert!(parsed.seqno > 0);
        assert_eq!(parsed.recipients.len(), 1);
        assert_eq!(parsed.recipients[0].amount, 10_000_000); // 0.01 TON
        assert!(!parsed.recipients[0].address.is_empty());
        assert!(parsed.id.is_some());
    }

    // Jetton transfer transaction
    const TOKEN_SEND_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_parse_token_send_transaction() {
        let tx = TonTransaction::from_base64(TOKEN_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::SendToken);
        assert!(parsed.jetton_transfer.is_some());
        let jt = parsed.jetton_transfer.unwrap();
        assert_eq!(jt.amount, "1000000000");
        assert!(jt.forward_payload_comment.is_some());
        assert_eq!(jt.forward_payload_comment.unwrap(), "jetton testing");
    }

    // Single nominator withdraw transaction
    const SINGLE_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_parse_single_nominator_withdraw() {
        let tx = TonTransaction::from_base64(SINGLE_NOMINATOR_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::SingleNominatorWithdraw
        );
        assert_eq!(parsed.recipients.len(), 1);
        assert_eq!(parsed.recipients[0].amount, 123_400_000);
    }

    // Whales deposit transaction
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_parse_whales_deposit() {
        let tx = TonTransaction::from_base64(WHALES_DEPOSIT_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();
        assert_eq!(parsed.transaction_type, TransactionType::TonWhalesDeposit);
        assert_eq!(parsed.seqno, 92);
    }

    // Whales withdrawal transaction
    const WHALES_WITHDRAWAL_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_parse_whales_withdrawal() {
        let tx = TonTransaction::from_base64(WHALES_WITHDRAWAL_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesWithdrawal
        );
        assert_eq!(parsed.seqno, 93);
    }
}
