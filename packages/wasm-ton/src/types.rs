//! Shared types for TON transaction parsing.

use num_bigint::BigUint;
use serde::Serialize;
use tlb_ton::MsgAddress;

/// Transaction type enum matching BitGoJS TransactionType for TON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum TonTransactionType {
    Send,
    SendToken,
    SingleNominatorWithdraw,
    TonWhalesDeposit,
    TonWhalesWithdrawal,
    TonWhalesVestingDeposit,
    TonWhalesVestingWithdrawal,
}

/// Parsed payload variants from the inner message body.
#[derive(Debug, Clone)]
pub enum ParsedPayload {
    /// Empty body (plain transfer)
    Empty,
    /// Text comment (opcode 0x00000000)
    TextComment(String),
    /// Jetton transfer (opcode 0x0f8a7ea5)
    JettonTransfer {
        query_id: u64,
        amount: BigUint,
        destination: MsgAddress,
        response_destination: MsgAddress,
        forward_ton_amount: BigUint,
    },
    /// Single nominator withdraw (opcode 0x00001000)
    NominatorWithdraw { query_id: u64, amount: BigUint },
    /// TON Whales deposit (opcode 2077040623)
    WhalesDeposit { query_id: u64 },
    /// TON Whales withdrawal (opcode 3665837821)
    WhalesWithdraw {
        query_id: u64,
        unstake_amount: BigUint,
    },
    /// Vesting deposit (text comment "Deposit")
    VestingDeposit,
    /// Vesting withdrawal (text comment "Withdraw")
    VestingWithdrawal,
    /// Unknown opcode
    Unknown(u32),
}

/// Fully parsed TON transaction.
#[derive(Debug, Clone)]
pub struct ParsedTransaction {
    /// Transaction type
    pub tx_type: TonTransactionType,
    /// Sender address (user-friendly, non-bounceable)
    pub sender: String,
    /// Recipient address (user-friendly)
    pub recipient: String,
    /// Transfer amount in nanoTON
    pub amount: BigUint,
    /// Whether the recipient address is bounceable
    pub bounceable: bool,
    /// Wallet sequence number
    pub seqno: u32,
    /// Wallet ID
    pub wallet_id: u32,
    /// Expiration timestamp (unix)
    pub expire_time: u64,
    /// Optional memo/comment
    pub memo: Option<String>,
    /// Parsed payload data
    pub payload: ParsedPayload,
    /// Signature hex (empty string if unsigned)
    pub signature: String,
    /// Public key hex (from StateInit, if seqno=0)
    pub public_key: Option<String>,
    /// Token-specific fields for jetton transfers
    pub token_amount: Option<BigUint>,
    /// Token destination (the actual recipient in jetton transfers)
    pub token_recipient: Option<String>,
}
