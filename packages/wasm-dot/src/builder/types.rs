//! Intent types for transaction building

use serde::{de, Deserialize, Deserializer};

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

/// High-level transaction intent
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TransactionIntent {
    /// Transfer DOT to an address
    Transfer(TransferIntent),
    /// Transfer all DOT to an address
    TransferAll(TransferAllIntent),
    /// Stake (bond) DOT
    Stake(StakeIntent),
    /// Unstake (unbond) DOT
    Unstake(UnstakeIntent),
    /// Withdraw unbonded DOT
    WithdrawUnbonded(WithdrawUnbondedIntent),
    /// Stop nominating/validating
    Chill,
    /// Add a proxy account
    AddProxy(AddProxyIntent),
    /// Remove a proxy account
    RemoveProxy(RemoveProxyIntent),
    /// Batch multiple calls
    Batch(BatchIntent),
}

/// Transfer intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferIntent {
    /// Recipient address (SS58)
    pub to: String,
    /// Amount in planck
    #[serde(deserialize_with = "deserialize_u128")]
    pub amount: u128,
    /// Use transferKeepAlive (default: true)
    #[serde(default = "default_keep_alive")]
    pub keep_alive: bool,
}

fn default_keep_alive() -> bool {
    true
}

/// Transfer all intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferAllIntent {
    /// Recipient address (SS58)
    pub to: String,
    /// Keep account alive after transfer
    #[serde(default)]
    pub keep_alive: bool,
}

/// Stake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeIntent {
    /// Amount to stake in planck
    #[serde(deserialize_with = "deserialize_u128")]
    pub amount: u128,
    /// Where to send staking rewards
    #[serde(default)]
    pub payee: StakePayee,
}

/// Staking reward destination
#[derive(Debug, Clone, Deserialize, Default)]
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

/// Unstake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnstakeIntent {
    /// Amount to unstake in planck
    #[serde(deserialize_with = "deserialize_u128")]
    pub amount: u128,
}

/// Withdraw unbonded intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawUnbondedIntent {
    /// Number of slashing spans (usually 0)
    #[serde(default)]
    pub slashing_spans: u32,
}

/// Add proxy intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddProxyIntent {
    /// Delegate address (SS58)
    pub delegate: String,
    /// Proxy type (Any, NonTransfer, Staking, etc.)
    pub proxy_type: String,
    /// Delay in blocks
    #[serde(default)]
    pub delay: u32,
}

/// Remove proxy intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveProxyIntent {
    /// Delegate address (SS58)
    pub delegate: String,
    /// Proxy type
    pub proxy_type: String,
    /// Delay in blocks
    #[serde(default)]
    pub delay: u32,
}

/// Batch intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchIntent {
    /// Calls to batch
    pub calls: Vec<TransactionIntent>,
    /// Use batchAll (atomic) instead of batch
    #[serde(default)]
    pub atomic: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_transfer() {
        let json = r#"{
            "type": "transfer",
            "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "amount": 1000000000000
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Transfer(t) => {
                assert_eq!(t.amount, 1_000_000_000_000);
                assert!(t.keep_alive); // default
            }
            _ => panic!("Expected Transfer"),
        }
    }

    #[test]
    fn test_deserialize_stake() {
        let json = r#"{
            "type": "stake",
            "amount": 5000000000000,
            "payee": { "type": "staked" }
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Stake(s) => {
                assert_eq!(s.amount, 5_000_000_000_000);
            }
            _ => panic!("Expected Stake"),
        }
    }

    #[test]
    fn test_deserialize_batch() {
        let json = r#"{
            "type": "batch",
            "calls": [
                { "type": "transfer", "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty", "amount": 100 },
                { "type": "chill" }
            ],
            "atomic": true
        }"#;

        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Batch(b) => {
                assert_eq!(b.calls.len(), 2);
                assert!(b.atomic);
            }
            _ => panic!("Expected Batch"),
        }
    }
}
