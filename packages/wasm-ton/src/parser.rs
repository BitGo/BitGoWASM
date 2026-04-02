use num_bigint::BigUint;
use tlb_ton::{bits::de::BitReaderExt, currency::Grams, message::CommonMsgInfo, Cell, MsgAddress};
use ton_contracts::wallet::v4r2::{WalletV4R2Op, WalletV4R2SignBody};

use crate::error::WasmTonError;
use crate::transaction::Transaction;

/// Body parse result: (opcode, memo, jetton_transfer)
type BodyParseResult = (Option<u32>, Option<String>, Option<JettonTransferFields>);

/// Transaction type enum
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionType {
    Transfer,
    TokenTransfer,
    WhalesDeposit,
    WhalesVestingDeposit,
    WhalesWithdraw,
    WhalesVestingWithdraw,
    SingleNominatorWithdraw,
    Unknown,
}

impl TransactionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TransactionType::Transfer => "Transfer",
            TransactionType::TokenTransfer => "TokenTransfer",
            TransactionType::WhalesDeposit => "WhalesDeposit",
            TransactionType::WhalesVestingDeposit => "WhalesVestingDeposit",
            TransactionType::WhalesWithdraw => "WhalesWithdraw",
            TransactionType::WhalesVestingWithdraw => "WhalesVestingWithdraw",
            TransactionType::SingleNominatorWithdraw => "SingleNominatorWithdraw",
            TransactionType::Unknown => "Unknown",
        }
    }
}

// Opcodes
const JETTON_TRANSFER_OPCODE: u32 = 0x0f8a7ea5;
const WHALES_DEPOSIT_OPCODE: u32 = 0x7bcd1fef;
const WHALES_WITHDRAW_OPCODE: u32 = 0xda803efd;
const SINGLE_NOMINATOR_WITHDRAW_OPCODE: u32 = 0x00001000; // 4096

/// Parsed jetton transfer fields exposed to the JS layer.
#[derive(Debug, Clone)]
pub struct JettonTransferFields {
    pub query_id: u64,
    pub amount: u64,
    pub destination: String,
    pub response_destination: String,
    pub forward_ton_amount: u64,
}

/// A single send action parsed from the transaction
#[derive(Debug, Clone)]
pub struct ParsedSendAction {
    pub mode: u8,
    pub destination: String,
    pub destination_bounceable: String,
    pub amount: u64,
    pub bounce: bool,
    pub body_opcode: Option<u32>,
    pub state_init: bool,
    pub memo: Option<String>,
    pub jetton_transfer: Option<JettonTransferFields>,
}

/// A fully parsed TON transaction
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    pub transaction_type: TransactionType,
    pub sender: String,
    pub wallet_id: u32,
    pub seqno: u32,
    pub expire_at: u64,
    pub signature: String,
    pub send_actions: Vec<ParsedSendAction>,
}

/// Parse a transaction from raw BOC bytes.
pub fn parse_transaction(bytes: &[u8]) -> Result<ParsedTransaction, WasmTonError> {
    let tx = Transaction::from_bytes(bytes)?;
    parse_from_transaction(&tx)
}

/// Parse a pre-deserialized Transaction.
pub fn parse_from_transaction(tx: &Transaction) -> Result<ParsedTransaction, WasmTonError> {
    let sender = match &tx.message.info {
        CommonMsgInfo::ExternalIn(info) => {
            if info.dst.is_null() {
                "null".to_string()
            } else {
                info.dst.to_base64_url_flags(false, false)
            }
        }
        _ => return Err(WasmTonError::new("expected external-in message")),
    };

    let sign_body = tx.sign_body();
    let signature = hex::encode(tx.signature());
    let expire_at = sign_body.expire_at.timestamp() as u64;

    let send_actions = parse_sign_body_actions(sign_body)?;
    let transaction_type = determine_transaction_type(&send_actions);

    Ok(ParsedTransaction {
        transaction_type,
        sender,
        wallet_id: sign_body.wallet_id,
        seqno: sign_body.seqno,
        expire_at,
        signature,
        send_actions,
    })
}

fn parse_sign_body_actions(
    sign_body: &WalletV4R2SignBody,
) -> Result<Vec<ParsedSendAction>, WasmTonError> {
    match &sign_body.op {
        WalletV4R2Op::Send(actions) => {
            let mut parsed = Vec::new();
            for action in actions {
                let msg = &action.message;

                let (destination_addr, amount, bounce) = match &msg.info {
                    CommonMsgInfo::Internal(info) => {
                        let amount = biguint_to_u64(&info.value.grams);
                        (info.dst, amount, info.bounce)
                    }
                    _ => {
                        return Err(WasmTonError::new(
                            "expected internal message in send action",
                        ))
                    }
                };

                let bounceable_str = destination_addr.to_base64_url_flags(false, false);
                let non_bounceable_str = destination_addr.to_base64_url_flags(true, false);

                let state_init = msg.init.is_some();

                // Parse body
                let (body_opcode, memo, jetton_transfer) = parse_message_body(&msg.body)?;

                parsed.push(ParsedSendAction {
                    mode: action.mode,
                    destination: if bounce {
                        bounceable_str.clone()
                    } else {
                        non_bounceable_str
                    },
                    destination_bounceable: bounceable_str,
                    amount,
                    bounce,
                    body_opcode,
                    state_init,
                    memo,
                    jetton_transfer,
                });
            }
            Ok(parsed)
        }
        _ => Err(WasmTonError::new("unsupported wallet op (not Send)")),
    }
}

fn parse_message_body(body: &Cell) -> Result<BodyParseResult, WasmTonError> {
    let mut parser = body.parser();
    let bits_left = parser.bits_left();

    // Empty body
    if bits_left == 0 {
        return Ok((None, None, None));
    }

    // Need at least 32 bits for opcode
    if bits_left < 32 {
        return Ok((None, None, None));
    }

    let opcode: u32 = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("failed to read opcode: {e}")))?;

    if opcode == 0 {
        // Text comment - read remaining bytes as UTF-8
        let remaining = parser.bits_left() / 8;
        let mut bytes = Vec::with_capacity(remaining);
        for _ in 0..remaining {
            match parser.unpack::<u8>(()) {
                Ok(v) => bytes.push(v),
                Err(_) => break,
            };
        }
        let memo = String::from_utf8_lossy(&bytes).to_string();
        return Ok((Some(0), Some(memo), None));
    }

    if opcode == JETTON_TRANSFER_OPCODE {
        let (jetton, memo) = parse_jetton_transfer_body(&mut parser, body)?;
        return Ok((Some(opcode), memo, Some(jetton)));
    }

    // Other known opcodes
    Ok((Some(opcode), None, None))
}

/// Parse a jetton transfer body, returning the parsed fields and any text memo.
///
/// Parses TEP-74 fields manually instead of using `JettonTransfer::<Cell>::parse` due to
/// a bug in `tlbits` 0.7.3: `Remainder::unpack_as` for byte/string types passes `bits_left()`
/// (bits) to `BorrowCow` which expects bytes, causing "EOF" errors when parsing text comments.
/// See `test_tlbits_remainder_bug_prevents_crate_jetton_parse` for the proof.
fn parse_jetton_transfer_body(
    parser: &mut tlb_ton::de::CellParser<'_>,
    body: &Cell,
) -> Result<(JettonTransferFields, Option<String>), WasmTonError> {
    // query_id: uint64
    let query_id: u64 = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("jetton: failed to read query_id: {e}")))?;

    // amount: VarUInteger 16 (Grams encoding)
    let amount_big: BigUint = parser
        .unpack_as::<_, Grams>(())
        .map_err(|e| WasmTonError::new(&format!("jetton: failed to read amount: {e}")))?;
    let amount = biguint_to_u64(&amount_big);

    // destination: MsgAddress
    let dst: MsgAddress = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("jetton: failed to read destination: {e}")))?;
    let destination = dst.to_base64_url_flags(false, false);

    // response_destination: MsgAddress
    let response_dst: MsgAddress = parser.unpack(()).map_err(|e| {
        WasmTonError::new(&format!("jetton: failed to read response_destination: {e}"))
    })?;
    let response_destination = if response_dst.is_null() {
        "null".to_string()
    } else {
        response_dst.to_base64_url_flags(false, false)
    };

    // custom_payload: Maybe ^Cell — skip if present
    let has_custom_payload: bool = parser.unpack(()).unwrap_or(false);
    if has_custom_payload {
        let _: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).unwrap_or_default();
    }

    // forward_ton_amount: VarUInteger 16
    let forward_big: BigUint = parser.unpack_as::<_, Grams>(()).map_err(|e| {
        WasmTonError::new(&format!("jetton: failed to read forward_ton_amount: {e}"))
    })?;
    let forward_ton_amount = biguint_to_u64(&forward_big);

    // forward_payload: Either Cell ^Cell — extract text memo if present
    let memo = parse_forward_payload_memo(parser, body);

    Ok((
        JettonTransferFields {
            query_id,
            amount,
            destination,
            response_destination,
            forward_ton_amount,
        },
        memo,
    ))
}

/// Extract a text memo from `forward_payload:(Either Cell ^Cell)`.
///
/// Handles both inline (bit=0) and ref (bit=1) forward_payload storage.
/// Returns `None` on any parse error or if the payload is not a text comment.
fn parse_forward_payload_memo(
    parser: &mut tlb_ton::de::CellParser<'_>,
    _body: &Cell,
) -> Option<String> {
    // Read the Either bit: 0 = inline, 1 = ref
    let is_ref: bool = parser.unpack(()).ok()?;

    if is_ref {
        // Payload is in the next ref cell — read the ref and parse from there
        let ref_cell: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).ok()?;
        read_text_comment(&mut ref_cell.parser())
    } else {
        // Payload is inline in the remaining bits
        read_text_comment(parser)
    }
}

/// Read a TEP-74 text comment: `0x00000000` prefix followed by UTF-8 bytes.
/// Returns `None` if the data doesn't start with the comment prefix or is not valid text.
fn read_text_comment(parser: &mut tlb_ton::de::CellParser<'_>) -> Option<String> {
    const COMMENT_PREFIX: u32 = 0x0000_0000;
    if parser.bits_left() < 32 {
        return None;
    }
    let prefix: u32 = parser.unpack(()).ok()?;
    if prefix != COMMENT_PREFIX {
        return None;
    }
    let remaining = parser.bits_left() / 8;
    let mut bytes = Vec::with_capacity(remaining);
    for _ in 0..remaining {
        match parser.unpack::<u8>(()) {
            Ok(b) => bytes.push(b),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn determine_transaction_type(actions: &[ParsedSendAction]) -> TransactionType {
    if actions.is_empty() {
        return TransactionType::Unknown;
    }

    let first = &actions[0];

    // Check for jetton transfer
    if first.jetton_transfer.is_some() {
        return TransactionType::TokenTransfer;
    }

    // Check for known opcodes
    if let Some(opcode) = first.body_opcode {
        match opcode {
            WHALES_DEPOSIT_OPCODE => {
                return if first.state_init {
                    TransactionType::WhalesVestingDeposit
                } else {
                    TransactionType::WhalesDeposit
                };
            }
            WHALES_WITHDRAW_OPCODE => {
                return if first.state_init {
                    TransactionType::WhalesVestingWithdraw
                } else {
                    TransactionType::WhalesWithdraw
                };
            }
            SINGLE_NOMINATOR_WITHDRAW_OPCODE => {
                return TransactionType::SingleNominatorWithdraw;
            }
            _ => {}
        }
    }

    // Plain transfer
    if first.body_opcode.is_none() || first.body_opcode == Some(0) {
        return TransactionType::Transfer;
    }

    TransactionType::Unknown
}

fn biguint_to_u64(v: &BigUint) -> u64 {
    let max = BigUint::from(u64::MAX);
    if *v > max {
        u64::MAX
    } else {
        v.to_u64_digits().first().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use crate::transaction::Transaction;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use tlb_ton::de::CellDeserialize;
    use tlb_ton::Cell;
    use ton_contracts::jetton::JettonTransfer;
    use ton_contracts::wallet::v4r2::WalletV4R2Op;

    /// signedTokenSendTransaction.tx from sdk-coin-ton fixtures.
    /// forward_payload is stored as a ref cell (Either bit=1) with memo "jetton testing".
    const TOKEN_TX: &str = "te6cckECGgEABB0AAuGIAVSGb+UGjjP3lvt+zFA8wouI3McEd6CKbO2TwcZ3OfLKGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACmpoxdJlgLSAAAAAAADgEXAgE0AhYBFP8A9KQT9LzyyAsDAgEgBBECAUgFCALm0AHQ0wMhcbCSXwTgItdJwSCSXwTgAtMfIYIQcGx1Z70ighBkc3RyvbCSXwXgA/pAMCD6RAHIygfL/8nQ7UTQgQFA1yH0BDBcgQEI9ApvoTGzkl8H4AXTP8glghBwbHVnupI4MOMNA4IQZHN0crqSXwbjDQYHAHgB+gD0BDD4J28iMFAKoSG+8uBQghBwbHVngx6xcIAYUATLBSbPFlj6Ahn0AMtpF8sfUmDLPyDJgED7AAYAilAEgQEI9Fkw7UTQgQFA1yDIAc8W9ADJ7VQBcrCOI4IQZHN0coMesXCAGFAFywVQA88WI/oCE8tqyx/LP8mAQPsAkl8D4gIBIAkQAgEgCg8CAVgLDAA9sp37UTQgQFA1yH0BDACyMoHy//J0AGBAQj0Cm+hMYAIBIA0OABmtznaiaEAga5Drhf/AABmvHfaiaEAQa5DrhY/AABG4yX7UTQ1wsfgAWb0kK29qJoQICga5D6AhhHDUCAhHpJN9KZEM5pA+n/mDeBKAG3gQFImHFZ8xhAT48oMI1xgg0x/TH9MfAvgju/Jk7UTQ0x/TH9P/9ATRUUO68qFRUbryogX5AVQQZPkQ8qP4ACSkyMsfUkDLH1Iwy/9SEPQAye1U+A8B0wchwACfbFGTINdKltMH1AL7AOgw4CHAAeMAIcAC4wABwAORMOMNA6TIyx8Syx/L/xITFBUAbtIH+gDU1CL5AAXIygcVy//J0Hd0gBjIywXLAiLPFlAF+gIUy2sSzMzJc/sAyEAUgQEI9FHypwIAcIEBCNcY+gDTP8hUIEeBAQj0UfKnghBub3RlcHSAGMjLBcsCUAbPFlAE+gIUy2oSyx/LP8lz+wACAGyBAQjXGPoA0z8wUiSBAQj0WfKnghBkc3RycHSAGMjLBcsCUAXPFlAD+gITy2rLHxLLP8lz+wAACvQAye1UAFEAAAAAKamjF9NTAQHUHhbX00VGZ3d2r8hbJxuz7PaxmuCOJ6kgckppQAFmQgABT9LR3Iqffskp0J9gWYO8Azlnb33BCMj8FqIUIGxGOZpiWgAAAAAAAAAAAAAAAAABGAGuD4p+pQAAAAAAAAAAQ7msoAgA/BGdBi/R01erquxJOvPgGKclBawUs3MAi0/IdctKQz8AKpDN/KDRxn7y32/ZigeYUXEbmOCO9BFNnbJ4OM7nPllGHoSBGQAkAAAAAGpldHRvbiB0ZXN0aW5nwHtw7A==";

    /// Demonstrates a bug in `tlbits` 0.7.3 `Remainder` adapter that prevents
    /// `JettonTransfer::<Cell>::parse` from working on messages with text comments.
    ///
    /// Root cause: `Remainder::unpack_as` for byte-oriented types (`Cow<[u8]>`,
    /// `Vec<u8>`, `Cow<str>`, `String`) passes `bits_left()` (a value in bits) to
    /// `BorrowCow` which expects the argument in bytes. This causes `BorrowCow` to
    /// attempt reading `bits_left * 8` bits, resulting in an "EOF" error.
    ///
    /// File: `tlbits-0.7.3/src/as/remainder.rs` lines 40-51 and 65-76.
    /// Upstream: https://github.com/mitinarseny/toner
    ///
    /// Until this is fixed upstream, we parse jetton transfer fields manually in
    /// `parse_jetton_transfer_body` / `parse_forward_payload_memo`.
    #[test]
    fn test_tlbits_remainder_bug_prevents_crate_jetton_parse() {
        let bytes = STANDARD.decode(TOKEN_TX).unwrap();
        let tx = Transaction::from_bytes(&bytes).unwrap();
        let sign_body = tx.sign_body();

        let actions = match &sign_body.op {
            WalletV4R2Op::Send(actions) => actions,
            _ => panic!("expected Send op"),
        };
        let body = &actions[0].message.body;
        let ref_cell = &*body.references[0];

        // BorrowCow with correct byte count works
        use tlb_ton::bits::de::BitReaderExt;
        let mut p1 = ref_cell.parser();
        let _: u32 = p1.unpack(()).unwrap(); // skip 0x00000000 comment prefix
        let bytes_left = p1.bits_left() / 8;
        let ok: Result<std::borrow::Cow<str>, _> =
            p1.unpack_as::<_, tlb_ton::bits::BorrowCow>(bytes_left);
        assert_eq!(ok.unwrap().as_ref(), "jetton testing");

        // Remainder passes bits_left() (112) to BorrowCow which expects bytes (14)
        let mut p2 = ref_cell.parser();
        let _: u32 = p2.unpack(()).unwrap();
        let err = p2
            .unpack_as::<String, tlb_ton::bits::Remainder>(())
            .unwrap_err();
        assert_eq!(err.to_string(), "EOF");

        // JettonTransfer::<Cell>::parse fails due to the same Remainder bug
        let mut parser = body.parser();
        let err = JettonTransfer::<Cell>::parse(&mut parser, ()).unwrap_err();
        assert!(
            err.to_string().contains("EOF"),
            "expected EOF error, got: {err}"
        );
    }

    #[test]
    fn test_jetton_transfer_memo_from_ref_cell() {
        // Verifies that memos stored as ref cells (forward_payload bit=1) are correctly extracted.
        let bytes = STANDARD.decode(TOKEN_TX).unwrap();
        let tx = Transaction::from_bytes(&bytes).unwrap();
        let parsed = parse_from_transaction(&tx).unwrap();
        assert_eq!(parsed.transaction_type, TransactionType::TokenTransfer);
        let action = &parsed.send_actions[0];
        assert!(action.jetton_transfer.is_some());
        assert_eq!(action.memo.as_deref(), Some("jetton testing"));
        assert_eq!(
            action.jetton_transfer.as_ref().unwrap().amount,
            1_000_000_000
        );
    }
}
