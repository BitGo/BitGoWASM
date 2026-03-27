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

/// Parsed jetton transfer fields (manually parsed, not using ton_contracts JettonTransfer)
#[derive(Debug, Clone)]
pub struct JettonTransferFields {
    pub query_id: u64,
    pub amount: u64,
    pub destination: String,
    pub response_destination: String,
    pub forward_ton_amount: u64,
    pub forward_payload: Option<Vec<u8>>,
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
        let jetton = parse_jetton_transfer_body(&mut parser)?;
        return Ok((Some(opcode), None, Some(jetton)));
    }

    // Other known opcodes
    Ok((Some(opcode), None, None))
}

fn parse_jetton_transfer_body(
    parser: &mut tlb_ton::de::CellParser<'_>,
) -> Result<JettonTransferFields, WasmTonError> {
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

    // custom_payload: Maybe ^Cell (skip it)
    let has_custom_payload: bool = parser.unpack(()).unwrap_or(false);
    if has_custom_payload {
        // Skip the ref
        let _: Cell = parser.parse_as::<_, tlb_ton::Ref>(()).unwrap_or_default();
    }

    // forward_ton_amount: VarUInteger 16
    let forward_big: BigUint = parser.unpack_as::<_, Grams>(()).map_err(|e| {
        WasmTonError::new(&format!("jetton: failed to read forward_ton_amount: {e}"))
    })?;
    let forward_ton_amount = biguint_to_u64(&forward_big);

    Ok(JettonTransferFields {
        query_id,
        amount,
        destination,
        response_destination,
        forward_ton_amount,
        forward_payload: None,
    })
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
