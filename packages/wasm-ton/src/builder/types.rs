//! Intent types for TON transaction building.
//!
//! Two-layer design following the DOT/SOL pattern:
//! - `TonTransactionIntent`: public, business-level intents (payment, delegate, etc.)
//! - Build logic in `build.rs` handles composition into internal messages.
//!
//! All amounts are `u64` (nanotons). TypeScript callers pass `bigint`.

use crate::address::WalletVersion;
use serde::Deserialize;

// =============================================================================
// Public API: Business-level intents
// =============================================================================

/// High-level business intent for TON transaction building.
///
/// Each variant represents a single user action. The builder handles
/// low-level details (opcodes, cell layout, message composition) internally.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "intentType")]
pub enum TonTransactionIntent {
    /// Native TON transfer or Jetton (token) transfer.
    ///
    /// Multiple recipients produce multiple internal messages in one external message.
    /// Token transfers go through the sender's Jetton wallet contract.
    #[serde(rename = "payment")]
    Payment {
        /// Recipients with addresses and amounts
        recipients: Vec<Recipient>,
        /// Optional text memo/comment
        #[serde(default)]
        memo: Option<String>,
        /// Whether destination addresses are bounceable (default: true for internal messages)
        #[serde(default)]
        bounceable: Option<bool>,
        /// Whether this is a token (Jetton) transfer
        #[serde(default, rename = "isToken")]
        is_token: bool,
        /// Sender's Jetton wallet address (required when is_token=true)
        #[serde(default, rename = "senderJettonWalletAddress")]
        sender_jetton_wallet_address: Option<String>,
    },

    /// Self-send to fill a seqno gap.
    ///
    /// Equivalent to a 0-amount payment to self.
    #[serde(rename = "fillNonce")]
    FillNonce {
        /// Sender address (recipient = sender)
        sender: String,
        /// Whether the address is bounceable
        #[serde(default)]
        bounceable: Option<bool>,
    },

    /// Sweep funds to a destination.
    ///
    /// Same builders as payment but with 7-day expiry (vs 30 min default).
    /// Token consolidate forces memo=' ' (single space).
    #[serde(rename = "consolidate")]
    Consolidate {
        /// Recipients with addresses and amounts
        recipients: Vec<Recipient>,
        /// Receive address for the consolidation
        #[serde(rename = "receiveAddress")]
        receive_address: String,
        /// Whether this is a token (Jetton) consolidation
        #[serde(default, rename = "isToken")]
        is_token: bool,
        /// Sender's Jetton wallet address (required when is_token=true)
        #[serde(default, rename = "senderJettonWalletAddress")]
        sender_jetton_wallet_address: Option<String>,
    },

    /// Staking deposit.
    ///
    /// The staking type determines the cell layout:
    /// - TON_WHALES: deposit opcode + queryId + amount
    /// - SINGLE_NOMINATOR: simple transfer with bounceable=true
    /// - MULTI_NOMINATOR: transfer with memo='d'
    #[serde(rename = "delegate")]
    Delegate {
        /// Validator/pool address
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        /// Amount to stake in nanotons
        #[serde(deserialize_with = "deserialize_u64_from_number_or_string")]
        amount: u64,
        /// Staking protocol type
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
    },

    /// Staking withdrawal.
    ///
    /// The staking type determines the cell layout:
    /// - TON_WHALES: withdrawal opcode. Full if amount=0, partial otherwise.
    /// - SINGLE_NOMINATOR: withdraw opcode (0x1000) with 1 TON attached.
    /// - MULTI_NOMINATOR: transfer with memo='w'
    #[serde(rename = "undelegate")]
    Undelegate {
        /// Validator/pool address
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        /// Amount to unstake in nanotons (0 = full withdrawal for Whales/SingleNom)
        #[serde(deserialize_with = "deserialize_u64_from_number_or_string")]
        amount: u64,
        /// Staking protocol type
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
        /// Withdrawal amount for Whales (the actual TON to withdraw)
        #[serde(
            default,
            rename = "withdrawalAmount",
            deserialize_with = "deserialize_option_u64_from_number_or_string"
        )]
        withdrawal_amount: Option<u64>,
    },
}

// =============================================================================
// Shared types
// =============================================================================

/// Recipient for a payment or consolidation intent.
#[derive(Debug, Clone, Deserialize)]
pub struct Recipient {
    /// Destination address (base64url TON address)
    pub address: String,
    /// Amount in nanotons
    #[serde(deserialize_with = "deserialize_u64_from_number_or_string")]
    pub amount: u64,
}

/// TON staking protocol type.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum TonStakingType {
    /// TON Whales liquid staking pool
    #[serde(rename = "TON_WHALES")]
    TonWhales,
    /// Single Nominator contract
    #[serde(rename = "SINGLE_NOMINATOR")]
    SingleNominator,
    /// Multi Nominator pool
    #[serde(rename = "MULTI_NOMINATOR")]
    MultiNominator,
}

/// Build context provided by the caller.
///
/// Contains all the information needed to build an external message
/// without any network calls.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TonBuildContext {
    /// Wallet address (base64url)
    pub sender: String,
    /// Hex-encoded Ed25519 public key (32 bytes)
    pub public_key: String,
    /// Current sequence number
    pub seqno: u32,
    /// Unix timestamp for transaction expiry
    pub expire_time: u32,
    /// Wallet version string ("V3R2", "V4R2", "V5R1")
    #[serde(default = "default_wallet_version")]
    pub wallet_version: String,
    /// Sub-wallet ID (default 698983191)
    #[serde(default = "default_wallet_id")]
    pub wallet_id: i32,
}

impl TonBuildContext {
    /// Parse wallet version string into WalletVersion enum.
    pub fn parsed_wallet_version(&self) -> Result<WalletVersion, crate::error::WasmTonError> {
        self.wallet_version.parse()
    }
}

fn default_wallet_version() -> String {
    "V4R2".to_string()
}

fn default_wallet_id() -> i32 {
    698983191
}

// =============================================================================
// Custom deserializers for u64 from number or string
// =============================================================================

/// Deserialize u64 from either a JSON number or a string.
/// JavaScript BigInt values are serialized as strings by serde_wasm_bindgen.
fn deserialize_u64_from_number_or_string<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct U64Visitor;

    impl<'de> serde::de::Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u64 as number or string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            Ok(value)
        }

        fn visit_i64<E>(self, value: i64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            u64::try_from(value).map_err(E::custom)
        }

        fn visit_f64<E>(self, value: f64) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            if value >= 0.0 && value <= u64::MAX as f64 && value.fract() == 0.0 {
                Ok(value as u64)
            } else {
                Err(E::custom(format!(
                    "f64 value {} cannot be converted to u64",
                    value
                )))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            value.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U64Visitor)
}

/// Deserialize Option<u64> from either a JSON number, string, or null.
fn deserialize_option_u64_from_number_or_string<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptionU64Visitor;

    impl<'de> serde::de::Visitor<'de> for OptionU64Visitor {
        type Value = Option<u64>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an optional u64 as number, string, or null")
        }

        fn visit_none<E>(self) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Option<u64>, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Option<u64>, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserialize_u64_from_number_or_string(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptionU64Visitor)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_payment_intent() {
        let json = r#"{
            "intentType": "payment",
            "recipients": [{"address": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": 10000000}],
            "isToken": false
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Payment {
                recipients,
                is_token,
                ..
            } => {
                assert_eq!(recipients.len(), 1);
                assert_eq!(recipients[0].amount, 10_000_000);
                assert!(!is_token);
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_payment_with_string_amount() {
        let json = r#"{
            "intentType": "payment",
            "recipients": [{"address": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": "10000000000000"}],
            "isToken": false
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Payment { recipients, .. } => {
                assert_eq!(recipients[0].amount, 10_000_000_000_000);
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_token_payment() {
        let json = r#"{
            "intentType": "payment",
            "recipients": [{"address": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": 1000000000}],
            "isToken": true,
            "senderJettonWalletAddress": "EQB-CM6DF-jpq9XVdiSdefAMU5KC1gpZuYBFp-Q65aUhnx5K",
            "memo": "test payment"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Payment {
                is_token,
                sender_jetton_wallet_address,
                memo,
                ..
            } => {
                assert!(is_token);
                assert!(sender_jetton_wallet_address.is_some());
                assert_eq!(memo.unwrap(), "test payment");
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_fill_nonce() {
        let json = r#"{
            "intentType": "fillNonce",
            "sender": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::FillNonce { sender, .. } => {
                assert!(!sender.is_empty());
            }
            _ => panic!("Expected FillNonce"),
        }
    }

    #[test]
    fn test_deserialize_consolidate() {
        let json = r#"{
            "intentType": "consolidate",
            "recipients": [{"address": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG", "amount": 50000000}],
            "receiveAddress": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "isToken": false
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        assert!(matches!(intent, TonTransactionIntent::Consolidate { .. }));
    }

    #[test]
    fn test_deserialize_delegate_whales() {
        let json = r#"{
            "intentType": "delegate",
            "validatorAddress": "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq",
            "amount": 10000000000,
            "stakingType": "TON_WHALES"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Delegate {
                amount,
                staking_type,
                ..
            } => {
                assert_eq!(amount, 10_000_000_000);
                assert_eq!(staking_type, TonStakingType::TonWhales);
            }
            _ => panic!("Expected Delegate"),
        }
    }

    #[test]
    fn test_deserialize_delegate_single_nominator() {
        let json = r#"{
            "intentType": "delegate",
            "validatorAddress": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "amount": 5000000000,
            "stakingType": "SINGLE_NOMINATOR"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Delegate { staking_type, .. } => {
                assert_eq!(staking_type, TonStakingType::SingleNominator);
            }
            _ => panic!("Expected Delegate"),
        }
    }

    #[test]
    fn test_deserialize_undelegate_whales() {
        let json = r#"{
            "intentType": "undelegate",
            "validatorAddress": "EQDr9Sq482A6ikIUh5mUUjJaBUUJBrye13CJiDB-R31_lwIq",
            "amount": 0,
            "stakingType": "TON_WHALES",
            "withdrawalAmount": 5000000000
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Undelegate {
                amount,
                staking_type,
                withdrawal_amount,
                ..
            } => {
                assert_eq!(amount, 0);
                assert_eq!(staking_type, TonStakingType::TonWhales);
                assert_eq!(withdrawal_amount, Some(5_000_000_000));
            }
            _ => panic!("Expected Undelegate"),
        }
    }

    #[test]
    fn test_deserialize_undelegate_multi_nominator() {
        let json = r#"{
            "intentType": "undelegate",
            "validatorAddress": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "amount": 1000000000,
            "stakingType": "MULTI_NOMINATOR"
        }"#;
        let intent: TonTransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TonTransactionIntent::Undelegate { staking_type, .. } => {
                assert_eq!(staking_type, TonStakingType::MultiNominator);
            }
            _ => panic!("Expected Undelegate"),
        }
    }

    #[test]
    fn test_deserialize_context() {
        let json = r#"{
            "sender": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "publicKey": "f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f",
            "seqno": 5,
            "expireTime": 1700000000,
            "walletVersion": "V4R2",
            "walletId": 698983191
        }"#;
        let ctx: TonBuildContext = serde_json::from_str(json).unwrap();
        assert_eq!(ctx.seqno, 5);
        assert_eq!(ctx.expire_time, 1_700_000_000);
        assert_eq!(ctx.wallet_id, 698983191);
        assert_eq!(ctx.wallet_version, "V4R2");
    }

    #[test]
    fn test_context_defaults() {
        let json = r#"{
            "sender": "EQA0i8-CdGnF_DhUHHf92R1ONH6sIA9vLZ_WLcCIhfBBXwtG",
            "publicKey": "f61b63341a65e5e23adbf052a7e27fad28bb6f461ef63c1c04e9f63d9eb1e54f",
            "seqno": 0,
            "expireTime": 1700000000
        }"#;
        let ctx: TonBuildContext = serde_json::from_str(json).unwrap();
        assert_eq!(ctx.wallet_version, "V4R2");
        assert_eq!(ctx.wallet_id, 698983191);
    }
}
