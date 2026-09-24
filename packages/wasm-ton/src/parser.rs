use num_bigint::BigUint;
use tlb_ton::{bits::de::BitReaderExt, currency::Grams, message::CommonMsgInfo, Cell, MsgAddress};
use ton_contracts::wallet::v4r2::{WalletV4R2Op, WalletV4R2SignBody};

use crate::error::WasmTonError;
use crate::transaction::Transaction;

/// Parsed result of a message body.
#[derive(Debug, Default)]
struct BodyParseResult {
    opcode: Option<u32>,
    memo: Option<String>,
    jetton_transfer: Option<JettonTransferFields>,
    withdraw_amount: Option<u64>,
}

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
    /// Withdraw amount encoded in the message body (SingleNominator/Whales withdrawal types).
    pub withdraw_amount: Option<u64>,
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
                let body = parse_message_body(&msg.body)?;

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
                    body_opcode: body.opcode,
                    state_init,
                    memo: body.memo,
                    jetton_transfer: body.jetton_transfer,
                    withdraw_amount: body.withdraw_amount,
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
        return Ok(BodyParseResult::default());
    }

    // Need at least 32 bits for opcode
    if bits_left < 32 {
        return Ok(BodyParseResult::default());
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
        return Ok(BodyParseResult {
            opcode: Some(0),
            memo: Some(memo),
            ..Default::default()
        });
    }

    if opcode == JETTON_TRANSFER_OPCODE {
        let (jetton, memo) = parse_jetton_transfer_body(&mut parser, body)?;
        return Ok(BodyParseResult {
            opcode: Some(opcode),
            memo,
            jetton_transfer: Some(jetton),
            ..Default::default()
        });
    }

    if opcode == WHALES_WITHDRAW_OPCODE || opcode == SINGLE_NOMINATOR_WITHDRAW_OPCODE {
        let amount = parse_withdraw_amount_body(&mut parser)?;
        return Ok(BodyParseResult {
            opcode: Some(opcode),
            withdraw_amount: Some(amount),
            ..Default::default()
        });
    }

    // Other known opcodes
    Ok(BodyParseResult {
        opcode: Some(opcode),
        ..Default::default()
    })
}

/// Parse query_id + amount from a withdrawal message body (Whales or SingleNominator).
fn parse_withdraw_amount_body(
    parser: &mut tlb_ton::de::CellParser<'_>,
) -> Result<u64, WasmTonError> {
    let _query_id: u64 = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("withdraw: failed to read query_id: {e}")))?;
    let amount_big: BigUint = parser
        .unpack_as::<_, Grams>(())
        .map_err(|e| WasmTonError::new(&format!("withdraw: failed to read amount: {e}")))?;
    Ok(biguint_to_u64(&amount_big))
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

    // custom_payload: Maybe ^Cell. This parser cannot represent its semantics.
    let has_custom_payload: bool = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("jetton: failed to read custom_payload: {e}")))?;
    if has_custom_payload {
        let _: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).map_err(|e| {
            WasmTonError::new(&format!("jetton: failed to read custom_payload cell: {e}"))
        })?;
        return Err(WasmTonError::new(
            "unsupported opaque Jetton custom_payload",
        ));
    }

    // forward_ton_amount: VarUInteger 16
    let forward_big: BigUint = parser.unpack_as::<_, Grams>(()).map_err(|e| {
        WasmTonError::new(&format!("jetton: failed to read forward_ton_amount: {e}"))
    })?;
    let forward_ton_amount = biguint_to_u64(&forward_big);

    // forward_payload: Either Cell ^Cell — accept only empty or UTF-8 text comments.
    let memo = parse_forward_payload_memo(parser, body)?;

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

/// Payload forms this parser can safely identify without decoding contract semantics.
enum ForwardPayload {
    Empty,
    Text(String),
    BinaryComment,
    Opaque,
}

/// Extract a memo from `forward_payload:(Either Cell ^Cell)`.
///
/// Only empty payloads and text comments have a lossless representation in the
/// public parser result. Binary comments and other payloads must not be hidden.
fn parse_forward_payload_memo(
    parser: &mut tlb_ton::de::CellParser<'_>,
    body: &Cell,
) -> Result<Option<String>, WasmTonError> {
    // Read the Either bit: 0 = inline, 1 = ref.
    let is_ref: bool = parser
        .unpack(())
        .map_err(|e| WasmTonError::new(&format!("jetton: failed to read forward_payload: {e}")))?;

    let payload = if is_ref {
        if body.references.len() != 1 {
            ForwardPayload::Opaque
        } else {
            let ref_cell: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).map_err(|e| {
                WasmTonError::new(&format!("jetton: failed to read forward_payload cell: {e}"))
            })?;
            classify_forward_payload(&mut ref_cell.parser(), !ref_cell.references.is_empty())
        }
    } else {
        classify_forward_payload(parser, !body.references.is_empty())
    };

    // The forward payload is the final field. Do not ignore signed trailing bits.
    if parser.bits_left() != 0 {
        return Err(WasmTonError::new(
            "unsupported opaque Jetton forward_payload",
        ));
    }

    match payload {
        ForwardPayload::Empty => Ok(None),
        ForwardPayload::Text(text) => Ok(Some(text)),
        ForwardPayload::BinaryComment | ForwardPayload::Opaque => Err(WasmTonError::new(
            "unsupported opaque Jetton forward_payload",
        )),
    }
}

/// Classify a payload cell's bits without lossy decoding or ignoring references.
fn classify_forward_payload(
    parser: &mut tlb_ton::de::CellParser<'_>,
    has_references: bool,
) -> ForwardPayload {
    if has_references {
        return ForwardPayload::Opaque;
    }

    let bits_left = parser.bits_left();
    if bits_left == 0 {
        return ForwardPayload::Empty;
    }
    if bits_left < 32 || !bits_left.is_multiple_of(8) {
        return ForwardPayload::Opaque;
    }

    let prefix: u32 = match parser.unpack(()) {
        Ok(prefix) => prefix,
        Err(_) => return ForwardPayload::Opaque,
    };
    if prefix != 0 {
        return ForwardPayload::Opaque;
    }

    let remaining = parser.bits_left() / 8;
    let mut bytes = Vec::with_capacity(remaining);
    for _ in 0..remaining {
        match parser.unpack::<u8>(()) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return ForwardPayload::Opaque,
        }
    }

    if bytes.first() == Some(&0xff) {
        return ForwardPayload::BinaryComment;
    }

    match String::from_utf8(bytes) {
        Ok(text) => ForwardPayload::Text(text),
        Err(_) => ForwardPayload::Opaque,
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
    use tlb_ton::ser::{CellSerialize, CellSerializeExt};
    use tlb_ton::Cell;
    use ton_contracts::jetton::{ForwardPayload, ForwardPayloadComment, JettonTransfer};
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

    fn test_jetton_transfer(
        custom_payload: Option<Cell>,
        forward_payload: ForwardPayload<Cell>,
    ) -> JettonTransfer<Cell> {
        JettonTransfer {
            query_id: 1,
            amount: BigUint::from(10u8),
            dst: MsgAddress::NULL,
            response_dst: MsgAddress::NULL,
            custom_payload,
            forward_ton_amount: BigUint::ZERO,
            forward_payload,
        }
    }

    fn test_jetton_body(
        custom_payload: Option<Cell>,
        forward_payload: ForwardPayload<Cell>,
    ) -> Cell {
        test_jetton_transfer(custom_payload, forward_payload)
            .to_cell(())
            .unwrap()
    }

    fn payload_cell(bytes: &[u8]) -> Cell {
        use tlb_ton::bits::ser::BitWriterExt;

        let mut builder = Cell::builder();
        for byte in bytes {
            builder.pack(*byte, ()).unwrap();
        }
        builder.into_cell()
    }

    fn inline_forward_payload_cell(bytes: &[u8]) -> Cell {
        use tlb_ton::bits::ser::BitWriterExt;

        let mut builder = Cell::builder();
        builder.pack(false, ()).unwrap();
        for byte in bytes {
            builder.pack(*byte, ()).unwrap();
        }
        builder.into_cell()
    }

    #[test]
    fn test_empty_jetton_forward_payload_is_supported() {
        let body = test_jetton_body(None, ForwardPayload::Data(Cell::default()));

        let parsed = parse_message_body(&body).unwrap();
        assert_eq!(parsed.memo, None);
    }

    #[test]
    fn test_jetton_forward_payload_text_comment_is_supported() {
        let body = test_jetton_body(
            None,
            ForwardPayload::Comment(ForwardPayloadComment::Text("reviewed".to_string())),
        );

        let parsed = parse_message_body(&body).unwrap();
        assert_eq!(parsed.memo.as_deref(), Some("reviewed"));
    }

    #[test]
    fn test_inline_jetton_text_comment_is_supported() {
        let body = inline_forward_payload_cell(&[0, 0, 0, 0, b'o', b'k']);
        let mut parser = body.parser();

        assert_eq!(
            parse_forward_payload_memo(&mut parser, &body)
                .unwrap()
                .as_deref(),
            Some("ok")
        );
    }

    #[test]
    fn test_inline_opaque_jetton_forward_payload_is_rejected() {
        let body = inline_forward_payload_cell(&[0xde, 0xad, 0xbe, 0xef]);
        let mut parser = body.parser();

        let error = parse_forward_payload_memo(&mut parser, &body).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported opaque Jetton forward_payload"
        );
    }

    #[test]
    fn test_referenced_opaque_jetton_forward_payload_is_rejected() {
        let body = test_jetton_body(None, ForwardPayload::Data(payload_cell(&[0xaa; 127])));
        assert_eq!(body.references.len(), 1);

        let error = parse_message_body(&body).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported opaque Jetton forward_payload"
        );
    }

    #[test]
    fn test_binary_jetton_comment_is_rejected() {
        let body = test_jetton_body(
            None,
            ForwardPayload::Data(payload_cell(&[0, 0, 0, 0, 0xff, 0x41])),
        );

        let error = parse_message_body(&body).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported opaque Jetton forward_payload"
        );
    }

    #[test]
    fn test_referenced_jetton_comment_with_trailing_body_bits_is_rejected() {
        use tlb_ton::bits::ser::BitWriterExt;

        let transfer = test_jetton_transfer(
            None,
            ForwardPayload::Comment(ForwardPayloadComment::Text("a".repeat(123))),
        );
        let mut builder = Cell::builder();
        transfer.store(&mut builder, ()).unwrap();
        builder.pack(true, ()).unwrap();
        let body = builder.into_cell();
        assert_eq!(body.references.len(), 1);

        let error = parse_message_body(&body).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported opaque Jetton forward_payload"
        );
    }

    #[test]
    fn test_present_jetton_custom_payload_is_rejected() {
        let body = test_jetton_body(Some(Cell::default()), ForwardPayload::Data(Cell::default()));

        let error = parse_message_body(&body).unwrap_err();
        assert_eq!(
            error.to_string(),
            "unsupported opaque Jetton custom_payload"
        );
    }

    #[test]
    fn test_malformed_jetton_forward_payload_is_rejected() {
        let body = Cell::default();
        let mut parser = body.parser();

        assert!(parse_forward_payload_memo(&mut parser, &body).is_err());
    }
}
