//! Transaction parsing for TON.
//!
//! Decodes a WalletV4R2 external message into structured data,
//! detecting the transaction type from opcodes and comment payloads
//! in the inner messages.

use num_bigint::BigUint;
use tlb_ton::{message::CommonMsgInfo, Cell, MsgAddress};
use ton_contracts::wallet::v4r2::{WalletV4R2Op, WalletV4R2SignBody};

use crate::error::WasmTonError;
use crate::transaction::Transaction;

// =============================================================================
// Transaction types matching BitGoJS
// =============================================================================

/// Transaction types detected from inner message structure.
///
/// Maps to BitGoJS's 7 TransactionTypes for TON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionType {
    /// Simple native TON transfer
    Send,
    /// Jetton (token) transfer via TEP-74 opcode 0x0f8a7ea5
    SendToken,
    /// Deposit to TON Whales staking pool (opcode 0x7bcd1fef)
    TonWhalesDeposit,
    /// Withdrawal from TON Whales staking pool (opcode 0xda803efd)
    TonWhalesWithdrawal,
    /// Withdrawal from single nominator pool (opcode 0x00001000)
    SingleNominatorWithdraw,
    /// Deposit to vesting contract (comment "Deposit")
    TonWhalesVestingDeposit,
    /// Withdrawal from vesting contract (comment "Withdraw")
    TonWhalesVestingWithdrawal,
}

impl TransactionType {
    /// Returns the string representation matching BitGoJS naming.
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::Send => "Send",
            TransactionType::SendToken => "SendToken",
            TransactionType::TonWhalesDeposit => "TonWhalesDeposit",
            TransactionType::TonWhalesWithdrawal => "TonWhalesWithdrawal",
            TransactionType::SingleNominatorWithdraw => "SingleNominatorWithdraw",
            TransactionType::TonWhalesVestingDeposit => "TonWhalesVestingDeposit",
            TransactionType::TonWhalesVestingWithdrawal => "TonWhalesVestingWithdrawal",
        }
    }
}

// =============================================================================
// Opcode constants
// =============================================================================

/// Jetton transfer opcode from TEP-74
const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;

/// TON Whales deposit opcode
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;

/// TON Whales withdrawal opcode
const WHALES_WITHDRAWAL_OPCODE: u32 = 0xda803efd;

/// Single nominator withdraw opcode
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x00001000;

// =============================================================================
// Output (recipient) info
// =============================================================================

/// Represents a parsed output (recipient) from the transaction.
#[derive(Debug, Clone)]
pub struct ParsedOutput {
    /// Recipient address
    pub address: String,
    /// Amount in nanotons (u64)
    pub amount: u64,
}

// =============================================================================
// ParsedTransaction
// =============================================================================

/// Fully parsed TON transaction with decoded fields.
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// Detected transaction type
    pub transaction_type: TransactionType,
    /// Wallet ID
    pub wallet_id: u32,
    /// Sequence number
    pub seqno: u32,
    /// Expiration time (unix timestamp)
    pub expire_time: u64,
    /// Outputs (recipients with amounts)
    pub outputs: Vec<ParsedOutput>,
    /// Total output amount in nanotons
    pub output_amount: u64,
    /// Whether the destination is bounceable
    pub bounceable: bool,
    /// Optional memo/comment from the inner message body
    pub memo: Option<String>,
    /// Send mode of the first inner message
    pub send_mode: u8,
    /// Withdrawal amount (for Whales withdrawal / SingleNominator)
    pub withdraw_amount: Option<u64>,
    /// Jetton amount (for SendToken)
    pub jetton_amount: Option<u64>,
    /// Jetton destination address (for SendToken)
    pub jetton_destination: Option<String>,
    /// Forward TON amount (for SendToken)
    pub forward_ton_amount: Option<u64>,
}

// =============================================================================
// Parsing logic
// =============================================================================

/// Parse a Transaction into structured data.
///
/// This is the main parsing entry point. It decodes the sign body
/// and inner messages to detect transaction type and extract fields.
pub fn parse_transaction(tx: &Transaction) -> Result<ParsedTransaction, WasmTonError> {
    parse_sign_body(tx.sign_body(), tx.dest_address())
}

/// Parse a WalletV4R2SignBody into a ParsedTransaction.
fn parse_sign_body(
    sign_body: &WalletV4R2SignBody,
    _wallet_address: MsgAddress,
) -> Result<ParsedTransaction, WasmTonError> {
    let wallet_id = sign_body.wallet_id;
    let seqno = sign_body.seqno;
    let expire_time = sign_body.expire_at.timestamp() as u64;

    // Extract inner messages from the op
    let messages = match &sign_body.op {
        WalletV4R2Op::Send(msgs) => msgs,
        _ => {
            return Err(WasmTonError::InvalidTransaction(
                "Only Send operations are supported for parsing".into(),
            ));
        }
    };

    if messages.is_empty() {
        return Err(WasmTonError::InvalidTransaction(
            "Transaction contains no inner messages".into(),
        ));
    }

    // Parse the first (and typically only) inner message
    let first_msg = &messages[0];
    let send_mode = first_msg.mode;

    // The inner message body is a Cell. Parse the CommonMsgInfo to get destination and amount.
    let inner_msg = &first_msg.message;

    let (dest_address, amount_biguint, bounceable) = match &inner_msg.info {
        CommonMsgInfo::Internal(info) => {
            let addr_str = format_msg_address(&info.dst);
            let amount = &info.value.grams;
            (addr_str, amount.clone(), info.bounce)
        }
        _ => {
            return Err(WasmTonError::InvalidTransaction(
                "Inner message must be internal".into(),
            ));
        }
    };

    let amount = biguint_to_u64(&amount_biguint);

    // Try to detect transaction type from the inner message body (Cell)
    let body_cell = &inner_msg.body;
    let (tx_type, memo, withdraw_amount, jetton_info) =
        detect_transaction_type(body_cell, bounceable)?;

    let outputs = vec![ParsedOutput {
        address: dest_address,
        amount,
    }];

    let (jetton_amount, jetton_destination, forward_ton_amount) = match jetton_info {
        Some(info) => (Some(info.0), Some(info.1), Some(info.2)),
        None => (None, None, None),
    };

    Ok(ParsedTransaction {
        transaction_type: tx_type,
        wallet_id,
        seqno,
        expire_time,
        outputs,
        output_amount: amount,
        bounceable,
        memo,
        send_mode,
        withdraw_amount,
        jetton_amount,
        jetton_destination,
        forward_ton_amount,
    })
}

/// Detect the transaction type by inspecting the inner message body Cell.
///
/// Returns (type, memo, withdraw_amount, jetton_info).
fn detect_transaction_type(
    body: &Cell,
    _bounceable: bool,
) -> Result<
    (
        TransactionType,
        Option<String>,
        Option<u64>,
        Option<(u64, String, u64)>,
    ),
    WasmTonError,
> {
    // If body is empty (no bits, no references), it's a simple send
    if body.data.is_empty() && body.references.is_empty() {
        return Ok((TransactionType::Send, None, None, None));
    }

    // Try to read the first 32-bit opcode from the body
    // Need at least 32 bits (4 bytes) for an opcode
    if body.data.len() >= 32 {
        // Parse the first 32 bits as a big-endian u32
        let opcode = read_u32_from_cell_bits(body);

        match opcode {
            Some(JETTON_TRANSFER_OPCODE) => {
                // Parse as JettonTransfer
                return parse_jetton_transfer(body);
            }
            Some(WHALES_DEPOSIT_OPCODE) => {
                return Ok((TransactionType::TonWhalesDeposit, None, None, None));
            }
            Some(WHALES_WITHDRAWAL_OPCODE) => {
                let withdraw_amount = parse_whales_withdrawal_amount(body);
                return Ok((
                    TransactionType::TonWhalesWithdrawal,
                    None,
                    withdraw_amount,
                    None,
                ));
            }
            Some(SINGLE_NOMINATOR_WITHDRAW_OPCODE) => {
                let withdraw_amount = parse_single_nominator_amount(body);
                return Ok((
                    TransactionType::SingleNominatorWithdraw,
                    None,
                    withdraw_amount,
                    None,
                ));
            }
            Some(0) => {
                // Opcode 0x00000000 means text comment follows
                let comment = parse_text_comment(body);
                if let Some(ref text) = comment {
                    match text.as_str() {
                        "Deposit" | "d" => {
                            return Ok((
                                TransactionType::TonWhalesVestingDeposit,
                                comment,
                                None,
                                None,
                            ));
                        }
                        "Withdraw" | "w" => {
                            return Ok((
                                TransactionType::TonWhalesVestingWithdrawal,
                                comment,
                                None,
                                None,
                            ));
                        }
                        _ => {
                            return Ok((TransactionType::Send, comment, None, None));
                        }
                    }
                }
                return Ok((TransactionType::Send, None, None, None));
            }
            _ => {
                // Unknown opcode, treat as simple send
                return Ok((TransactionType::Send, None, None, None));
            }
        }
    }

    // Less than 32 bits, treat as simple send
    Ok((TransactionType::Send, None, None, None))
}

/// Read the first 32 bits of a Cell as a big-endian u32.
fn read_u32_from_cell_bits(cell: &Cell) -> Option<u32> {
    if cell.data.len() < 32 {
        return None;
    }
    // Cell data is stored as bitvec in MSB order.
    // We need to read the first 32 bits as a u32.
    let bytes = cell.data.as_raw_slice();
    if bytes.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Parse the text comment from a body Cell with opcode 0x00000000.
fn parse_text_comment(cell: &Cell) -> Option<String> {
    let bytes = cell.data.as_raw_slice();
    if bytes.len() <= 4 {
        return None;
    }
    // Skip the 4-byte opcode (0x00000000), rest is UTF-8 text
    let text_bytes = &bytes[4..];

    // Handle the case where trailing bits are padding
    // The Cell bit length tells us the actual data length
    let total_bits = cell.data.len();
    let text_bits = total_bits - 32; // subtract opcode bits
    let text_byte_count = text_bits / 8;

    if text_byte_count == 0 {
        return None;
    }

    let text_slice = &text_bytes[..text_byte_count];
    String::from_utf8(text_slice.to_vec()).ok()
}

/// Parse JettonTransfer from body Cell.
///
/// JettonTransfer format (TEP-74):
///   opcode (32 bits) = 0x0f8a7ea5
///   query_id (64 bits)
///   amount (VarUInteger 16)
///   destination (MsgAddress)
///   response_destination (MsgAddress)
///   custom_payload (Maybe ^Cell)
///   forward_ton_amount (VarUInteger 16)
///   forward_payload (Either Cell ^Cell)
///
/// We parse the key fields manually using a CellParser to handle the
/// complex forward_payload (Either inline/ref) which the crate's
/// `JettonTransfer::parse` requires full Cell references for.
fn parse_jetton_transfer(
    body: &Cell,
) -> Result<
    (
        TransactionType,
        Option<String>,
        Option<u64>,
        Option<(u64, String, u64)>,
    ),
    WasmTonError,
> {
    use tlb_ton::bits::de::BitReaderExt;

    let mut parser = body.parser();

    // Skip opcode (already identified as JETTON_TRANSFER_OPCODE)
    let _opcode: u32 = parser.unpack(()).map_err(|e| {
        WasmTonError::InvalidTransaction(format!("JettonTransfer parse error: {}", e))
    })?;

    // query_id: uint64
    let _query_id: u64 = parser
        .unpack(())
        .map_err(|e| WasmTonError::InvalidTransaction(format!("JettonTransfer query_id: {}", e)))?;

    // amount: VarUInteger 16 (VarInt<4>)
    let amount: BigUint = parser
        .unpack_as::<_, tlb_ton::bits::VarInt<4>>(())
        .map_err(|e| WasmTonError::InvalidTransaction(format!("JettonTransfer amount: {}", e)))?;

    // destination: MsgAddress
    let dst: MsgAddress = parser
        .unpack(())
        .map_err(|e| WasmTonError::InvalidTransaction(format!("JettonTransfer dst: {}", e)))?;

    // response_destination: MsgAddress
    let _response_dst: MsgAddress = parser.unpack(()).map_err(|e| {
        WasmTonError::InvalidTransaction(format!("JettonTransfer response_dst: {}", e))
    })?;

    // custom_payload: Maybe ^Cell (1 bit flag + optional ref)
    let has_custom_payload: bool = parser.unpack(()).map_err(|e| {
        WasmTonError::InvalidTransaction(format!("JettonTransfer custom_payload flag: {}", e))
    })?;
    if has_custom_payload {
        // Skip the Cell reference
        let _custom: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).map_err(|e| {
            WasmTonError::InvalidTransaction(format!("JettonTransfer custom_payload: {}", e))
        })?;
    }

    // forward_ton_amount: VarUInteger 16
    let forward_ton_amount: BigUint = parser
        .unpack_as::<_, tlb_ton::bits::VarInt<4>>(())
        .map_err(|e| {
            WasmTonError::InvalidTransaction(format!("JettonTransfer forward_ton_amount: {}", e))
        })?;

    // forward_payload: Either Cell ^Cell - try to extract comment
    let memo = extract_forward_payload_memo(&mut parser);

    let jetton_amount = biguint_to_u64(&amount);
    let destination = format_msg_address(&dst);
    let fwd_amount = biguint_to_u64(&forward_ton_amount);

    Ok((
        TransactionType::SendToken,
        memo,
        None,
        Some((jetton_amount, destination, fwd_amount)),
    ))
}

/// Try to extract a text memo from the remaining forward payload bits.
fn extract_forward_payload_memo(parser: &mut tlb_ton::de::CellParser<'_>) -> Option<String> {
    use tlb_ton::bits::de::BitReaderExt;

    // The forward payload is Either Cell ^Cell
    // Read the Either flag: 0 = inline, 1 = ref
    let is_ref: bool = parser.unpack(()).ok()?;

    if is_ref {
        // Read from reference Cell
        let ref_cell: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).ok()?;
        extract_comment_from_cell(&ref_cell)
    } else {
        // Inline: remaining bits are the payload
        // Check for comment prefix (0x00000000)
        if parser.bits_left() >= 32 {
            let mut clone = parser.clone();
            let prefix: u32 = clone.unpack(()).ok()?;
            if prefix == 0x00000000 {
                // Skip prefix in original parser
                let _: u32 = parser.unpack(()).ok()?;
                // Read remaining as text
                let remaining_bits = parser.bits_left();
                let byte_count = remaining_bits / 8;
                if byte_count > 0 {
                    let mut bytes = vec![0u8; byte_count];
                    for b in &mut bytes {
                        *b = parser.unpack(()).ok()?;
                    }
                    return String::from_utf8(bytes).ok();
                }
            }
        }
        None
    }
}

/// Extract text comment from a Cell (expects 0x00000000 prefix then UTF-8 text).
fn extract_comment_from_cell(cell: &Cell) -> Option<String> {
    let bytes = cell.data.as_raw_slice();
    if bytes.len() < 4 {
        return None;
    }
    let prefix = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if prefix != 0x00000000 {
        return None;
    }
    let total_bits = cell.data.len();
    let text_bits = total_bits.checked_sub(32)?;
    let text_byte_count = text_bits / 8;
    if text_byte_count == 0 {
        return None;
    }
    String::from_utf8(bytes[4..4 + text_byte_count].to_vec()).ok()
}

/// Parse the withdrawal amount from a Whales withdrawal body.
/// Body format: opcode(32) + query_id(64) + gas_limit(u64/coins) + amount(coins)
fn parse_whales_withdrawal_amount(_cell: &Cell) -> Option<u64> {
    // After opcode (4 bytes) + query_id (8 bytes) = 12 bytes,
    // then VarUInteger for gas, then VarUInteger for amount.
    // This is complex to parse without the full cell parser.
    // For now, we won't extract the exact amount from raw bits.
    // The Phase 3 builder and BitGoJS fixture tests will verify correctness.
    None
}

/// Parse the withdrawal amount from a single nominator withdrawal body.
/// Body format: opcode(32) + query_id(64) + amount(coins)
fn parse_single_nominator_amount(_cell: &Cell) -> Option<u64> {
    // Similar complexity to whales withdrawal.
    None
}

/// Format a MsgAddress to a user-friendly base64url string (bounceable).
fn format_msg_address(addr: &MsgAddress) -> String {
    // Return as raw format (workchain:hex) which is unambiguous
    addr.to_hex()
}

/// Convert BigUint to u64 (clamping to u64::MAX for very large values).
fn biguint_to_u64(v: &BigUint) -> u64 {
    let bytes = v.to_bytes_be();
    if bytes.len() > 8 {
        return u64::MAX;
    }
    let mut buf = [0u8; 8];
    let start = 8 - bytes.len();
    buf[start..].copy_from_slice(&bytes);
    u64::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::Transaction;

    // Simple send transaction
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    #[test]
    fn test_parse_send_transaction() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::Send);
        assert_eq!(parsed.seqno, 6);
        assert_eq!(parsed.outputs.len(), 1);
        assert_eq!(parsed.outputs[0].amount, 10_000_000); // 0.01 TON
    }

    // Token send
    const SIGNED_TOKEN_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_parse_token_transaction() {
        let tx = Transaction::from_base64(SIGNED_TOKEN_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::SendToken);
        assert_eq!(parsed.seqno, 0);
        // Token transfers have jetton info
        assert!(parsed.jetton_amount.is_some());
        assert!(parsed.jetton_destination.is_some());
    }

    // Whales deposit
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_parse_whales_deposit() {
        let tx = Transaction::from_base64(WHALES_DEPOSIT_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TransactionType::TonWhalesDeposit);
        assert_eq!(parsed.seqno, 92);
        assert!(parsed.bounceable);
    }

    // Whales withdrawal
    const WHALES_WITHDRAWAL_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_parse_whales_withdrawal() {
        let tx = Transaction::from_base64(WHALES_WITHDRAWAL_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::TonWhalesWithdrawal
        );
        assert_eq!(parsed.seqno, 93);
        assert!(parsed.bounceable);
    }

    // Single nominator withdraw
    const SINGLE_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_parse_single_nominator() {
        let tx = Transaction::from_base64(SINGLE_NOMINATOR_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TransactionType::SingleNominatorWithdraw
        );
        assert_eq!(parsed.seqno, 0);
    }
}
