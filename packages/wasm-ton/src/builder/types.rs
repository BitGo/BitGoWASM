//! Types for intent-based transaction building.
//!
//! These types are deserialized from JavaScript via `serde_wasm_bindgen`.
//! All amounts use `u64` (nanoTON) which maps to `bigint` in TypeScript.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer};

/// Deserialize a u64 amount from either a number or string.
///
/// JavaScript BigInt values are serialized as strings by serde_wasm_bindgen,
/// so we need to accept both formats.
fn deserialize_amount<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct AmountVisitor;

    impl<'de> Visitor<'de> for AmountVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u64 as number or string")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(v)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u64::try_from(v).map_err(de::Error::custom)
        }

        fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v >= 0.0 && v <= u64::MAX as f64 {
                Ok(v as u64)
            } else {
                Err(de::Error::custom(format!("f64 out of u64 range: {v}")))
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>().map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

/// Deserialize an optional u64 amount.
fn deserialize_amount_opt<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper(#[serde(deserialize_with = "deserialize_amount")] u64);

    Option::<Wrapper>::deserialize(deserializer).map(|opt| opt.map(|w| w.0))
}

/// Tagged intent enum. The `intentType` field in JSON selects the variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "intentType")]
pub enum TonIntent {
    Payment(PaymentIntent),
    JettonTransfer(JettonTransferIntent),
    SingleNominatorWithdraw(NominatorWithdrawIntent),
    TonWhalesDeposit(WhalesDepositIntent),
    TonWhalesWithdrawal(WhalesWithdrawalIntent),
    TonWhalesVestingDeposit(VestingDepositIntent),
    TonWhalesVestingWithdrawal(VestingWithdrawalIntent),
}

/// Native TON transfer.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIntent {
    /// Recipient address (user-friendly)
    pub recipient: String,
    /// Amount in nanoTON
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
    /// Optional text memo
    #[serde(default)]
    pub memo: Option<String>,
    /// Whether recipient address is bounceable (default false)
    #[serde(default)]
    pub bounceable: Option<bool>,
}

/// Jetton (token) transfer.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JettonTransferIntent {
    /// Sender's jetton wallet address
    pub jetton_wallet_address: String,
    /// Final recipient of the tokens
    pub recipient: String,
    /// Token amount (in token's smallest unit)
    #[serde(deserialize_with = "deserialize_amount")]
    pub token_amount: u64,
    /// TON amount to attach to the message (default 100_000_000 = 0.1 TON)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub ton_amount: Option<u64>,
    /// TON forwarded to recipient (default 100 nanoTON)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub forward_ton_amount: Option<u64>,
    /// Optional text memo forwarded to recipient
    #[serde(default)]
    pub memo: Option<String>,
    /// Query ID (default 0)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub query_id: Option<u64>,
}

/// Single nominator withdraw.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NominatorWithdrawIntent {
    /// Validator/nominator contract address
    pub validator_address: String,
    /// TON amount to send with the message (covers fees, default 1 TON)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub amount: Option<u64>,
    /// Amount to withdraw from the nominator
    #[serde(deserialize_with = "deserialize_amount")]
    pub withdraw_amount: u64,
    /// Query ID (default 0)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub query_id: Option<u64>,
}

/// TON Whales staking pool deposit.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhalesDepositIntent {
    /// Validator/pool address
    pub validator_address: String,
    /// Amount to stake in nanoTON
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
    /// Query ID (default 0)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub query_id: Option<u64>,
}

/// TON Whales staking pool withdrawal.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WhalesWithdrawalIntent {
    /// Validator/pool address
    pub validator_address: String,
    /// TON amount to send with the message (covers fees)
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
    /// Amount to unstake (0 = full withdrawal)
    #[serde(deserialize_with = "deserialize_amount")]
    pub withdrawal_amount: u64,
    /// Query ID (default 0)
    #[serde(default, deserialize_with = "deserialize_amount_opt")]
    pub query_id: Option<u64>,
}

/// TON Whales vesting deposit.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VestingDepositIntent {
    /// Vesting contract address
    pub contract_address: String,
    /// Amount to deposit in nanoTON
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
}

/// TON Whales vesting withdrawal.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VestingWithdrawalIntent {
    /// Vesting contract address
    pub contract_address: String,
    /// Amount to withdraw in nanoTON
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
}

/// Build context provided by the caller for all intents.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TonBuildContext {
    /// Sender address (user-friendly)
    pub sender: String,
    /// Hex-encoded Ed25519 public key (32 bytes)
    pub public_key: String,
    /// Wallet sequence number
    pub seqno: u32,
    /// Unix timestamp for transaction expiration
    #[serde(deserialize_with = "deserialize_amount")]
    pub expire_time: u64,
    /// Wallet ID (default 698983191 for v4r2, 268 for vesting)
    #[serde(default)]
    pub wallet_id: Option<u32>,
    /// Address format flag
    #[serde(default)]
    pub bounceable: Option<bool>,
}
