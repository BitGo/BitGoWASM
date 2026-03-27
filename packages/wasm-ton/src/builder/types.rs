//! Intent types for TON transaction building.
//!
//! Business-level intents: the caller says what they want to do,
//! the builder decides how to compose the inner messages.

use serde::Deserialize;

// =============================================================================
// Staking type enum
// =============================================================================

/// TON staking provider type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum TonStakingType {
    TonWhales,
    SingleNominator,
    MultiNominator,
}

// =============================================================================
// Recipient
// =============================================================================

/// A transfer recipient.
#[derive(Debug, Clone, Deserialize)]
pub struct Recipient {
    /// Destination address (user-friendly or raw format)
    pub address: String,
    /// Amount in nanotons
    #[serde(deserialize_with = "deserialize_amount")]
    pub amount: u64,
}

// =============================================================================
// Build context (common to all intents)
// =============================================================================

/// Parameters needed to build any TON transaction.
///
/// These are not part of the intent itself but are required
/// by the wallet contract to produce a valid external message.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildContext {
    /// Sender (wallet) address
    pub sender_address: String,
    /// Sequence number
    pub seqno: u32,
    /// Public key (hex, needed when seqno == 0 for StateInit)
    pub public_key: Option<String>,
    /// Expiration time (unix timestamp)
    #[serde(deserialize_with = "deserialize_amount")]
    pub expire_time: u64,
    /// Whether destination addresses are bounceable (default: false)
    #[serde(default)]
    pub bounceable: bool,
    /// Whether this is a vesting contract wallet (default: false)
    #[serde(default)]
    pub is_vesting_contract: bool,
    /// Sub-wallet ID (698983191 default, 268 for vesting)
    pub sub_wallet_id: Option<u32>,
}

impl BuildContext {
    /// Get the effective wallet ID.
    pub fn effective_wallet_id(&self) -> u32 {
        if let Some(id) = self.sub_wallet_id {
            return id;
        }
        if self.is_vesting_contract {
            268
        } else {
            0x29a9a317 // V4R2 default
        }
    }
}

// =============================================================================
// Transaction intent (tagged enum)
// =============================================================================

/// High-level business intent for TON transaction building.
///
/// Each variant represents a user action. The builder composes the
/// correct inner messages (including staking opcodes, jetton transfers, etc.)
/// internally based on the intent fields.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "intentType", rename_all = "camelCase")]
pub enum TonTransactionIntent {
    /// Native TON transfer or Jetton (token) transfer.
    Payment {
        recipients: Vec<Recipient>,
        #[serde(default)]
        memo: Option<String>,
        #[serde(default, rename = "isToken")]
        is_token: bool,
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
        #[serde(
            default,
            rename = "tonAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        ton_amount: Option<u64>,
        #[serde(
            default,
            rename = "forwardTonAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        forward_ton_amount: Option<u64>,
    },

    /// Self-send for seqno advancement.
    FillNonce {
        #[serde(default, rename = "isToken")]
        is_token: bool,
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
        #[serde(
            default,
            rename = "tonAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        ton_amount: Option<u64>,
    },

    /// Sweep all funds to receive address.
    Consolidate {
        recipients: Vec<Recipient>,
        #[serde(default, rename = "isToken")]
        is_token: bool,
        #[serde(default, rename = "senderJettonAddress")]
        sender_jetton_address: Option<String>,
        #[serde(
            default,
            rename = "tonAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        ton_amount: Option<u64>,
        #[serde(
            default,
            rename = "forwardTonAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        forward_ton_amount: Option<u64>,
    },

    /// Staking deposit.
    Delegate {
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        #[serde(deserialize_with = "deserialize_amount")]
        amount: u64,
    },

    /// Staking withdrawal.
    Undelegate {
        #[serde(rename = "stakingType")]
        staking_type: TonStakingType,
        #[serde(rename = "validatorAddress")]
        validator_address: String,
        #[serde(deserialize_with = "deserialize_amount")]
        amount: u64,
        #[serde(
            default,
            rename = "withdrawalAmount",
            deserialize_with = "deserialize_optional_amount"
        )]
        withdrawal_amount: Option<u64>,
    },
}

// =============================================================================
// Custom deserializers for amounts (accept both numbers and strings)
// =============================================================================

fn deserialize_amount<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AmountVisitor;

    impl<'de> serde::de::Visitor<'de> for AmountVisitor {
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
            Ok(value as u64)
        }

        fn visit_str<E>(self, value: &str) -> Result<u64, E>
        where
            E: serde::de::Error,
        {
            value.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

fn deserialize_optional_amount<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct OptAmountVisitor;

    impl<'de> serde::de::Visitor<'de> for OptAmountVisitor {
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
            deserialize_amount(deserializer).map(Some)
        }
    }

    deserializer.deserialize_option(OptAmountVisitor)
}
