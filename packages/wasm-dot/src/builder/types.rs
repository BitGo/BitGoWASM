//! Intent types for transaction building
//!
//! Matches wallet-platform pattern: buildTransaction(intent, context)
//! - intent: what to do (transfer, stake, etc.) - single operation
//! - context: how to build it (sender, nonce, material, validity)

use crate::types::{Material, Validity};
use serde::{de, Deserialize, Deserializer, Serialize};

/// Deserialize u128 from either a number or string
fn deserialize_u128<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    struct U128Visitor;

    impl<'de> de::Visitor<'de> for U128Visitor {
        type Value = u128;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a u128 as number or string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<u128, E>
        where
            E: de::Error,
        {
            Ok(value as u128)
        }

        fn visit_i64<E>(self, value: i64) -> Result<u128, E>
        where
            E: de::Error,
        {
            if value >= 0 {
                Ok(value as u128)
            } else {
                Err(E::custom("negative values not allowed"))
            }
        }

        fn visit_str<E>(self, value: &str) -> Result<u128, E>
        where
            E: de::Error,
        {
            value.parse().map_err(E::custom)
        }
    }

    deserializer.deserialize_any(U128Visitor)
}

/// Transaction intent - what to do
///
/// Single operation (transfer, stake, etc.). For multiple ops, use Batch.
/// Matches wallet-platform's DOTPaymentIntent, DOTStakingIntent, etc.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TransactionIntent {
    /// Transfer DOT to recipient
    Transfer {
        /// Recipient address (SS58)
        to: String,
        /// Amount in planck
        #[serde(deserialize_with = "deserialize_u128")]
        amount: u128,
        /// Use transferKeepAlive (default: true)
        #[serde(default = "default_keep_alive", rename = "keepAlive")]
        keep_alive: bool,
    },
    /// Transfer all DOT to recipient
    TransferAll {
        /// Recipient address (SS58)
        to: String,
        /// Keep account alive after transfer
        #[serde(default, rename = "keepAlive")]
        keep_alive: bool,
    },
    /// Stake (bond) DOT
    Stake {
        /// Amount to stake in planck
        #[serde(deserialize_with = "deserialize_u128")]
        amount: u128,
        /// Where to send staking rewards
        #[serde(default)]
        payee: StakePayee,
    },
    /// Unstake (unbond) DOT
    Unstake {
        /// Amount to unstake in planck
        #[serde(deserialize_with = "deserialize_u128")]
        amount: u128,
    },
    /// Withdraw unbonded DOT
    WithdrawUnbonded {
        /// Number of slashing spans (usually 0)
        #[serde(default, rename = "slashingSpans")]
        slashing_spans: u32,
    },
    /// Stop nominating/validating
    Chill,
    /// Add a proxy account
    AddProxy {
        /// Delegate address (SS58)
        delegate: String,
        /// Proxy type (Any, NonTransfer, Staking, etc.)
        #[serde(rename = "proxyType")]
        proxy_type: String,
        /// Delay in blocks
        #[serde(default)]
        delay: u32,
    },
    /// Remove a proxy account
    RemoveProxy {
        /// Delegate address (SS58)
        delegate: String,
        /// Proxy type
        #[serde(rename = "proxyType")]
        proxy_type: String,
        /// Delay in blocks
        #[serde(default)]
        delay: u32,
    },
    /// Batch multiple intents atomically
    Batch {
        /// List of intents to execute
        calls: Vec<TransactionIntent>,
        /// Use batchAll (atomic) instead of batch
        #[serde(default = "default_atomic")]
        atomic: bool,
    },
}

fn default_keep_alive() -> bool {
    true
}

fn default_atomic() -> bool {
    true
}

/// Build context - how to build the transaction
///
/// Matches wallet-platform's material + nonce + validity pattern
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildContext {
    /// Sender address (SS58 encoded)
    pub sender: String,
    /// Account nonce
    pub nonce: u32,
    /// Optional tip amount (in planck)
    #[serde(default, deserialize_with = "deserialize_u128_optional")]
    pub tip: u128,
    /// Chain material metadata
    pub material: Material,
    /// Validity window
    pub validity: Validity,
    /// Reference block hash for mortality
    pub reference_block: String,
}

fn deserialize_u128_optional<'de, D>(deserializer: D) -> Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U128OrDefault {
        Number(u64),
        String(String),
        None,
    }

    match U128OrDefault::deserialize(deserializer)? {
        U128OrDefault::Number(n) => Ok(n as u128),
        U128OrDefault::String(s) if s.is_empty() => Ok(0),
        U128OrDefault::String(s) => s.parse().map_err(de::Error::custom),
        U128OrDefault::None => Ok(0),
    }
}

/// Staking reward destination
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum StakePayee {
    /// Compound rewards (re-stake)
    #[default]
    Staked,
    /// Send to stash account
    Stash,
    /// Send to controller account
    Controller,
    /// Send to specific account
    Account {
        /// Destination address
        address: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_transfer_intent() {
        let json = r#"{
            "type": "transfer",
            "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "amount": 1000000000000
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Transfer {
                amount, keep_alive, ..
            } => {
                assert_eq!(amount, 1_000_000_000_000);
                assert!(keep_alive); // default
            }
            _ => panic!("Expected Transfer"),
        }
    }

    #[test]
    fn test_deserialize_stake_intent() {
        let json = r#"{
            "type": "stake",
            "amount": 5000000000000,
            "payee": { "type": "staked" }
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Stake { amount, .. } => {
                assert_eq!(amount, 5_000_000_000_000);
            }
            _ => panic!("Expected Stake"),
        }
    }

    #[test]
    fn test_deserialize_batch_intent() {
        let json = r#"{
            "type": "batch",
            "calls": [
                { "type": "transfer", "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", "amount": "1000" },
                { "type": "chill" }
            ]
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Batch { calls, atomic } => {
                assert_eq!(calls.len(), 2);
                assert!(atomic); // default
            }
            _ => panic!("Expected Batch"),
        }
    }

    #[test]
    fn test_deserialize_context() {
        let json = r#"{
            "sender": "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr",
            "nonce": 5,
            "tip": "0",
            "material": {
                "genesisHash": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                "chainName": "Polkadot",
                "specName": "polkadot",
                "specVersion": 9150,
                "txVersion": 9,
                "metadataHex": "0x00"
            },
            "validity": {
                "firstValid": 1000,
                "maxDuration": 2400
            },
            "referenceBlock": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3"
        }"#;

        let ctx: BuildContext = serde_json::from_str(json).unwrap();
        assert_eq!(
            ctx.sender,
            "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr"
        );
        assert_eq!(ctx.nonce, 5);
    }
}
