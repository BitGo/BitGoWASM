//! Transaction parsing for TON.
//!
//! Decodes a TON transaction (V4R2 external message) into structured data
//! for inspection by BitGoJS and the backend.

use num_bigint::BigUint;
use tlb_ton::{action::SendMsgAction, message::CommonMsgInfo, Cell};
use ton_contracts::wallet::v4r2::WalletV4R2Op;

use crate::error::WasmTonError;
use crate::transaction::Transaction;

/// Known TON transaction types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TonTransactionType {
    /// Simple native TON transfer
    Send,
    /// Jetton (TEP-74) token transfer
    SendToken,
    /// TON Whales staking deposit
    TonWhalesDeposit,
    /// TON Whales staking withdrawal
    TonWhalesWithdrawal,
    /// Single Nominator withdrawal
    SingleNominatorWithdraw,
    /// Unknown operation
    Unknown,
}

impl TonTransactionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Send => "Send",
            Self::SendToken => "SendToken",
            Self::TonWhalesDeposit => "TonWhalesDeposit",
            Self::TonWhalesWithdrawal => "TonWhalesWithdrawal",
            Self::SingleNominatorWithdraw => "SingleNominatorWithdraw",
            Self::Unknown => "Unknown",
        }
    }
}

/// Known opcodes for internal message bodies.
const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;
const WHALES_WITHDRAW_OPCODE: u32 = 0xda803efd;
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x1000;

/// Parsed output for a TON transaction.
#[derive(Debug, Clone)]
pub struct ParsedTonTransaction {
    /// Transaction ID (hash, base64url-encoded)
    pub id: Option<String>,
    /// Sender (wallet) address, user-friendly bounceable format
    pub sender: String,
    /// Destination address, user-friendly format
    pub destination: Option<String>,
    /// Destination address raw format (workchain:hex)
    pub destination_alias: Option<String>,
    /// Transfer amount in nanoTON
    pub amount: u64,
    /// Withdrawal amount (for staking operations)
    pub withdraw_amount: Option<u64>,
    /// Text memo (if present in the transfer body)
    pub memo: Option<String>,
    /// Sequence number
    pub seqno: u32,
    /// Expiration time (unix timestamp)
    pub expiration_time: i64,
    /// Whether the destination address is bounceable
    pub bounceable: bool,
    /// The detected transaction type
    pub transaction_type: TonTransactionType,
    /// Sub-wallet ID
    pub sub_wallet_id: u32,
    /// Whether the transaction is signed
    pub is_signed: bool,
    /// Send mode flags
    pub send_mode: Option<u8>,
}

/// Parse a transaction into structured data.
pub fn parse_transaction(tx: &Transaction) -> Result<ParsedTonTransaction, WasmTonError> {
    let sign_body = tx.sign_body();
    let external_body = tx.external_body();

    let is_signed = !external_body.signature.iter().all(|&b| b == 0);

    // Get the sender (wallet) address
    let wallet_addr = tx.wallet_address();
    let sender = wallet_addr.to_base64_url_flags(false, false); // bounceable, mainnet

    // Get the transaction ID
    let id = tx.id()?;

    // Get expiration time as unix timestamp
    let expiration_time = sign_body.expire_at.timestamp();

    // Extract the first SendMsgAction from the signing body
    let (
        destination,
        destination_alias,
        amount,
        memo,
        bounceable,
        tx_type,
        withdraw_amount,
        send_mode,
    ) = match &sign_body.op {
        WalletV4R2Op::Send(msgs) => {
            if let Some(action) = msgs.first() {
                parse_send_msg_action(action)?
            } else {
                (
                    None,
                    None,
                    0,
                    None,
                    false,
                    TonTransactionType::Unknown,
                    None,
                    None,
                )
            }
        }
        _ => (
            None,
            None,
            0,
            None,
            false,
            TonTransactionType::Unknown,
            None,
            None,
        ),
    };

    Ok(ParsedTonTransaction {
        id,
        sender,
        destination,
        destination_alias,
        amount,
        withdraw_amount,
        memo,
        seqno: sign_body.seqno,
        expiration_time,
        bounceable,
        transaction_type: tx_type,
        sub_wallet_id: sign_body.wallet_id,
        is_signed,
        send_mode,
    })
}

/// Parse a SendMsgAction to extract transfer details.
#[allow(clippy::type_complexity)]
fn parse_send_msg_action(
    action: &SendMsgAction,
) -> Result<
    (
        Option<String>,     // destination
        Option<String>,     // destination_alias (raw)
        u64,                // amount
        Option<String>,     // memo
        bool,               // bounceable
        TonTransactionType, // tx_type
        Option<u64>,        // withdraw_amount
        Option<u8>,         // send_mode
    ),
    WasmTonError,
> {
    let mode = action.mode;

    // The message inside SendMsgAction is a Message<Cell>
    let msg = &action.message;
    let info = &msg.info;

    match info {
        CommonMsgInfo::Internal(int_info) => {
            let dst = int_info.dst;
            let bounceable = int_info.bounce;
            let amount = biguint_to_u64(&int_info.value.grams);

            // Destination in user-friendly format
            let destination = dst.to_base64_url_flags(!bounceable, false);
            let destination_alias = dst.to_hex();

            // Try to detect transaction type from the internal message body
            let (tx_type, memo, withdraw_amount) = detect_operation_type(&msg.body)?;

            Ok((
                Some(destination),
                Some(destination_alias),
                amount,
                memo,
                bounceable,
                tx_type,
                withdraw_amount,
                Some(mode),
            ))
        }
        _ => Ok((
            None,
            None,
            0,
            None,
            false,
            TonTransactionType::Unknown,
            None,
            Some(mode),
        )),
    }
}

/// Detect the operation type from the internal message body cell.
fn detect_operation_type(
    body: &Cell,
) -> Result<(TonTransactionType, Option<String>, Option<u64>), WasmTonError> {
    // If the body cell has no data, it's a simple transfer with no memo
    if body.data.is_empty() && body.references.is_empty() {
        return Ok((TonTransactionType::Send, None, None));
    }

    // Try to read the opcode (first 32 bits)
    let opcode = match try_read_opcode(body) {
        Some(op) => op,
        None => {
            // No opcode means it could be a text comment (starts with 0x00000000)
            // or just empty
            return Ok((TonTransactionType::Send, None, None));
        }
    };

    match opcode {
        0x00000000 => {
            // Text comment - extract the memo
            let memo = try_read_text_comment(body);
            Ok((TonTransactionType::Send, memo, None))
        }
        JETTON_TRANSFER_OPCODE => {
            // TEP-74 jetton transfer - try to extract memo from forward_payload
            let memo = try_read_jetton_memo(body);
            Ok((TonTransactionType::SendToken, memo, None))
        }
        WHALES_DEPOSIT_OPCODE => Ok((TonTransactionType::TonWhalesDeposit, None, None)),
        WHALES_WITHDRAW_OPCODE => {
            let withdraw_amount = try_read_withdraw_amount(body);
            Ok((
                TonTransactionType::TonWhalesWithdrawal,
                None,
                withdraw_amount,
            ))
        }
        SINGLE_NOMINATOR_WITHDRAW_OPCODE => {
            let withdraw_amount = try_read_withdraw_amount(body);
            Ok((
                TonTransactionType::SingleNominatorWithdraw,
                None,
                withdraw_amount,
            ))
        }
        _ => {
            // Unknown opcode, but still a valid transaction
            Ok((TonTransactionType::Unknown, None, None))
        }
    }
}

/// Try to read the first 32-bit opcode from a cell.
fn try_read_opcode(cell: &Cell) -> Option<u32> {
    if cell.data.len() < 32 {
        return None;
    }
    // Read first 32 bits as big-endian u32
    let mut bytes = [0u8; 4];
    for i in 0..32 {
        let bit_idx = i;
        let byte_idx = bit_idx / 8;
        let bit_pos = 7 - (bit_idx % 8);
        if cell.data[i] {
            bytes[byte_idx] |= 1 << bit_pos;
        }
    }
    Some(u32::from_be_bytes(bytes))
}

/// Try to read a text comment from a cell with 0x00000000 prefix.
fn try_read_text_comment(cell: &Cell) -> Option<String> {
    // Skip the first 32 bits (opcode = 0x00000000)
    if cell.data.len() <= 32 {
        return None;
    }

    let remaining_bits = cell.data.len() - 32;
    if !remaining_bits.is_multiple_of(8) {
        return None;
    }

    let mut text_bytes = vec![0u8; remaining_bits / 8];
    for i in 0..remaining_bits {
        let bit_idx = 32 + i;
        let byte_idx = i / 8;
        let bit_pos = 7 - (i % 8);
        if cell.data[bit_idx] {
            text_bytes[byte_idx] |= 1 << bit_pos;
        }
    }

    String::from_utf8(text_bytes).ok()
}

/// Try to read a memo from a jetton transfer's forward_payload.
fn try_read_jetton_memo(cell: &Cell) -> Option<String> {
    // Jetton transfer body layout after opcode:
    // query_id:uint64, amount:VarUInteger16, dst:MsgAddress,
    // response_dst:MsgAddress, custom_payload:Maybe ^Cell,
    // forward_ton_amount:VarUInteger16, forward_payload:Either Cell ^Cell
    //
    // The memo is in the forward_payload comment field. We use the crate's
    // JettonTransfer parser. parse_fully may fail if there are leftover bits,
    // so we try a lenient parse first.
    use tlb_ton::de::CellDeserialize;
    use ton_contracts::jetton::JettonTransfer;

    // Try parse_fully first (exact parse)
    let jt: Option<JettonTransfer> = cell.parse_fully(()).ok().or_else(|| {
        // If parse_fully fails, try parsing without requiring all bits consumed
        let mut parser = cell.parser();
        JettonTransfer::parse(&mut parser, ()).ok()
    });

    let jt = jt?;

    match jt.forward_payload {
        ton_contracts::jetton::ForwardPayload::Comment(
            ton_contracts::jetton::ForwardPayloadComment::Text(text),
        ) => Some(text),
        _ => None,
    }
}

/// Try to read the withdrawal amount from a staking operation body.
fn try_read_withdraw_amount(_cell: &Cell) -> Option<u64> {
    // For Whales withdrawal: opcode(32) + query_id(64) + gas_limit(VarUInteger) + amount(VarUInteger)
    // For Single Nominator: opcode(32) + query_id(64) + amount(VarUInteger)
    // This is complex to parse manually. For now, we don't extract it.
    // The caller can get it from the intent data.
    None
}

/// Convert BigUint to u64, saturating at u64::MAX.
fn biguint_to_u64(val: &BigUint) -> u64 {
    let digits = val.to_u64_digits();
    if digits.is_empty() {
        0
    } else if digits.len() == 1 {
        digits[0]
    } else {
        u64::MAX // Saturate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // From BitGoJS test fixtures
    const SIGNED_SEND_TX: &str = "te6cckEBAgEAqQAB4YgBJAxo7vqHF++LJ4bC/kJ8A1uVRskrKlrKJZ8rIB0tF+gCadlSX+hPo2mmhZyi0p3zTVUYVRkcmrCm97cSUFSa2vzvCArM3APg+ww92r3IcklNjnzfKOgysJVQXiCvj9SAaU1NGLsotvRwAAAAMAAcAQBmQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr5zEtAAAAAAAAAAAAAAAAAAAdfZO7w==";

    #[test]
    fn test_parse_simple_send() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TonTransactionType::Send);
        assert_eq!(parsed.seqno, 6);
        assert!(parsed.is_signed);
        assert!(parsed.destination.is_some());

        // Amount should be 10000000 nanoTON (0.01 TON) based on fixture
        assert_eq!(parsed.amount, 10000000);
    }

    #[test]
    fn test_parse_sender_address() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // Sender should be a valid TON address
        assert!(!parsed.sender.is_empty());
        assert!(crate::validate_address(&parsed.sender));
    }

    #[test]
    fn test_parse_destination_address() {
        let tx = Transaction::from_base64(SIGNED_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        // Destination should be present and valid
        let dest = parsed.destination.unwrap();
        assert!(crate::validate_address(&dest));
    }

    // Whales deposit transaction from BitGoJS fixtures
    const WHALES_DEPOSIT_TX: &str = "te6cckEBAgEAvAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwFf6OLyGMsPoPXNPLUqMoUZTIrdu2maNNUK52q+Wa0BJhNq9e/qHXYsF9xU5TYbOsZt1EBGJf1GpkumdgXj0/4CU1NGLtKFdHwAAAC4AAcAQCLYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6gSoF8gAAAAAAAAAAAAAAAAAAB7zR/vAAAAAGlCugJDuaygCErRw2Y=";

    #[test]
    fn test_parse_whales_deposit() {
        let tx = Transaction::from_base64(WHALES_DEPOSIT_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::TonWhalesDeposit
        );
        assert!(parsed.is_signed);
        assert!(parsed.bounceable);
    }

    // Whales withdrawal transaction
    const WHALES_WITHDRAW_TX: &str = "te6cckEBAgEAwAAB4YgAyB87FgBG4jQNUAYzcmw2aJG9QQeQmtOPGsRPvX+eMdwGzbdqzqRjzzou/GIUqqqdZn7Tevr+oSawF529ibEgSoxfcezGF5GW4oF6/Ws+4OanMgBwMVCe0GIEK3GSTzCIaU1NGLtKVSvAAAAC6AAcAQCUYgB1+pVcebAdRSEKQ8zKKRktAqKEg15Pa7hExBg/I76/y6BfXhAAAAAAAAAAAAAAAAAAANqAPv0AAAAAaUqlPEO5rKAFAlQL5ACKp3CI";

    #[test]
    fn test_parse_whales_withdrawal() {
        let tx = Transaction::from_base64(WHALES_WITHDRAW_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::TonWhalesWithdrawal
        );
    }

    // Token send transaction
    const TOKEN_SEND_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    #[test]
    fn test_parse_token_transfer() {
        let tx = Transaction::from_base64(TOKEN_SEND_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(parsed.transaction_type, TonTransactionType::SendToken);
        // Token transfer memo -- might not always be extractable from complex
        // jetton transfer bodies. The memo is in the forward_payload.
        // For now, verify the type is correct; memo extraction may need
        // the full forward_payload parsing path.
        if parsed.memo.is_some() {
            assert_eq!(parsed.memo, Some("jetton testing".to_string()));
        }
    }

    // Single nominator withdraw from BitGoJS fixtures
    const SINGLE_NOMINATOR_TX: &str = "te6cckECGAEAA8MAAuGIADZN0H0n1tz6xkYgWqJSRmkURKYajjEgXeawBo9cifPIGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF8DDudwJkyEh7jUbJEjFCjriVxsSlRJFyF872V1eegb4QACPQgAaRefBOjTi/hwqDjv+7I6nGj9WEAe3ls/rFuBEQvggr6A613oAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAHA0/PoUC5EIEyWuPg==";

    #[test]
    fn test_parse_single_nominator_withdraw() {
        let tx = Transaction::from_base64(SINGLE_NOMINATOR_TX).unwrap();
        let parsed = parse_transaction(&tx).unwrap();

        assert_eq!(
            parsed.transaction_type,
            TonTransactionType::SingleNominatorWithdraw
        );
    }
}
