//! Intent types for TON transaction building.
//!
//! These types represent business-level intents that the caller passes in.
//! The builder handles composing them into the correct TON messages.

use serde::{Deserialize, Serialize};

/// High-level business intent for TON transaction building.
///
/// Each variant represents a user action, not a low-level blockchain operation.
/// The builder handles message composition internally.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "intentType")]
pub enum TonTransactionIntent {
    /// Transfer TON or jetton tokens to recipient(s)
    #[serde(rename = "payment")]
    Payment {
        /// Recipients with address and amount
        recipients: Vec<Recipient>,
        /// Optional text memo
        #[serde(default)]
        memo: Option<String>,
        /// Whether destination addresses are bounceable (default: false)
        #[serde(default)]
        bounceable: Option<bool>,
        /// Sender wallet address (user-friendly format)
        sender: String,
        /// Wallet sequence number
        seqno: u32,
        /// Expiration unix timestamp
        #[serde(rename = "expireAt")]
        expire_at: u32,
        /// Hex-encoded Ed25519 public key (for wallet address derivation)
        #[serde(rename = "publicKey")]
        public_key: String,
        /// Sender's jetton wallet address (if present, this is a jetton transfer)
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
    },

    /// Self-send to advance the wallet nonce
    #[serde(rename = "fillNonce")]
    FillNonce {
        /// Self-send target address
        address: String,
        /// Wallet sequence number
        seqno: u32,
        /// Expiration unix timestamp
        #[serde(rename = "expireAt")]
        expire_at: u32,
        /// Hex-encoded Ed25519 public key
        #[serde(rename = "publicKey")]
        public_key: String,
        /// Sender's jetton wallet address (optional, for token fill nonce)
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
    },

    /// Consolidate funds to recipient(s)
    #[serde(rename = "consolidate")]
    Consolidate {
        /// Recipients with address and amount
        recipients: Vec<Recipient>,
        /// Sender wallet address
        sender: String,
        /// Wallet sequence number
        seqno: u32,
        /// Expiration unix timestamp
        #[serde(rename = "expireAt")]
        expire_at: u32,
        /// Hex-encoded Ed25519 public key
        #[serde(rename = "publicKey")]
        public_key: String,
        /// Sender's jetton wallet address (optional, for token consolidation)
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
    },

    /// Delegate (stake) TON with a validator
    #[serde(rename = "delegate")]
    Delegate {
        /// Validator/pool address
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        /// Amount in nanoTON
        #[serde(deserialize_with = "deserialize_amount")]
        amount: u64,
        /// Staking protocol type
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
        /// Sender wallet address
        sender: String,
        /// Wallet sequence number
        seqno: u32,
        /// Expiration unix timestamp
        #[serde(rename = "expireAt")]
        expire_at: u32,
        /// Hex-encoded Ed25519 public key
        #[serde(rename = "publicKey")]
        public_key: String,
        /// Whether this is a vesting contract wallet (default: false)
        #[serde(default, rename = "isVesting")]
        is_vesting: Option<bool>,
        /// Custom sub-wallet ID for vesting contracts (required when isVesting=true)
        #[serde(default, rename = "subWalletId")]
        sub_wallet_id: Option<u32>,
    },

    /// Undelegate (unstake) TON from a validator
    #[serde(rename = "undelegate")]
    Undelegate {
        /// Validator/pool address
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        /// Amount in nanoTON (transfer amount to validator, e.g. 1 TON for single nominator)
        #[serde(deserialize_with = "deserialize_amount")]
        amount: u64,
        /// Withdrawal amount for whales pool (0 = full withdrawal)
        #[serde(
            default,
            rename = "withdrawalAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        withdrawal_amount: Option<u64>,
        /// Staking protocol type
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
        /// Sender wallet address
        sender: String,
        /// Wallet sequence number
        seqno: u32,
        /// Expiration unix timestamp
        #[serde(rename = "expireAt")]
        expire_at: u32,
        /// Hex-encoded Ed25519 public key
        #[serde(rename = "publicKey")]
        public_key: String,
        /// Whether this is a vesting contract wallet (default: false)
        #[serde(default, rename = "isVesting")]
        is_vesting: Option<bool>,
        /// Custom sub-wallet ID for vesting contracts (required when isVesting=true)
        #[serde(default, rename = "subWalletId")]
        sub_wallet_id: Option<u32>,
    },
}

/// Staking protocol variants supported by TON.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TonStakingType {
    TonWhales,
    SingleNominator,
    MultiNominator,
}

/// A recipient with address and amount.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    /// Destination address (user-friendly TON format)
    pub address: String,
    /// Amount in nanoTON
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
}

/// Deserialize amount from either string or number (for JS BigInt compatibility).
fn deserialize_amount<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct AmountVisitor;

    impl<'de> Visitor<'de> for AmountVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or number representing an amount")
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
            Ok(u64::try_from(v).unwrap_or(0))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>().or_else(|_| {
                v.parse::<i64>()
                    .map(|n| u64::try_from(n).unwrap_or(0))
                    .map_err(de::Error::custom)
            })
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

/// Deserialize optional amount from string, number, or null.
fn deserialize_optional_amount<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct OptionalAmountVisitor;

    impl<'de> Visitor<'de> for OptionalAmountVisitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string, number, or null representing an optional amount")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_amount(deserializer).map(Some)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(u64::try_from(v).unwrap_or(0)))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse::<u64>()
                .or_else(|_| {
                    v.parse::<i64>()
                        .map(|n| u64::try_from(n).unwrap_or(0))
                        .map_err(de::Error::custom)
                })
                .map(Some)
        }
    }

    deserializer.deserialize_any(OptionalAmountVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_payment_intent() {
        let json = r#"{
            "intentType": "payment",
            "recipients": [{"address": "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": 1000000000}],
            "sender": "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "seqno": 1,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Payment {
                recipients, seqno, ..
            } => {
                assert_eq!(recipients.len(), 1);
                assert_eq!(recipients[0].amount, 1_000_000_000);
                assert_eq!(seqno, 1);
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_payment_with_jetton() {
        let json = r#"{
            "intentType": "payment",
            "recipients": [{"address": "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": "5000000"}],
            "sender": "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "seqno": 2,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001",
            "senderJettonAddress": "EQBjetton..."
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Payment {
                sender_jetton_address,
                ..
            } => {
                assert!(sender_jetton_address.is_some());
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_fill_nonce() {
        let json = r#"{
            "intentType": "fillNonce",
            "address": "UQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "seqno": 5,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        assert!(matches!(intent, TonTransactionIntent::FillNonce { .. }));
    }

    #[test]
    fn test_deserialize_delegate() {
        let json = r#"{
            "intentType": "delegate",
            "validatorAddress": "EQValidator...",
            "amount": 5000000000,
            "stakingType": "TON_WHALES",
            "sender": "UQSender...",
            "seqno": 10,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Delegate {
                staking_type,
                amount,
                ..
            } => {
                assert_eq!(staking_type, TonStakingType::TonWhales);
                assert_eq!(amount, 5_000_000_000);
            }
            _ => panic!("Expected Delegate"),
        }
    }

    #[test]
    fn test_deserialize_undelegate() {
        let json = r#"{
            "intentType": "undelegate",
            "validatorAddress": "EQValidator...",
            "amount": 1000000000,
            "withdrawalAmount": 0,
            "stakingType": "SINGLE_NOMINATOR",
            "sender": "UQSender...",
            "seqno": 11,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Undelegate {
                staking_type,
                withdrawal_amount,
                ..
            } => {
                assert_eq!(staking_type, TonStakingType::SingleNominator);
                assert_eq!(withdrawal_amount, Some(0));
            }
            _ => panic!("Expected Undelegate"),
        }
    }

    #[test]
    fn test_deserialize_amount_from_string() {
        let json = r#"{"address": "UQAddr...", "amount": "999999999999"}"#;
        let r: Recipient = serde_json::from_str(json).unwrap();
        assert_eq!(r.amount, 999_999_999_999);
    }

    #[test]
    fn test_deserialize_consolidate() {
        let json = r#"{
            "intentType": "consolidate",
            "recipients": [{"address": "UQAddr...", "amount": 1000}],
            "sender": "UQSender...",
            "seqno": 1,
            "expireAt": 1700000000,
            "publicKey": "0000000000000000000000000000000000000000000000000000000000000001"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        assert!(matches!(intent, TonTransactionIntent::Consolidate { .. }));
    }
}
