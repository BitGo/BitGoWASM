//! Intent types for transaction building
//!
//! Two-layer design:
//! - `TransactionIntent`: public, business-level intents (payment, stake, unstake, etc.)
//! - `CallIntent`: internal, call-level intents (transfer, bond, addProxy, etc.)
//!
//! The composition function `intent_to_calls()` converts business intents into
//! one or more call intents, handling batch composition automatically.

use crate::error::WasmDotError;
use crate::types::{Material, Validity};
use serde::{Deserialize, Serialize};

// =============================================================================
// Public API: Business-level intents
// =============================================================================

/// High-level business intent for transaction building.
///
/// These intents represent what the caller wants to do (payment, stake, etc.).
/// The crate handles composing them into the correct Polkadot extrinsic calls,
/// including batching when multiple calls are needed (e.g., bond + addProxy).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TransactionIntent {
    /// Transfer DOT to a recipient
    Payment {
        /// Recipient address (SS58)
        to: String,
        /// Amount in planck
        amount: u64,
        /// Use transferKeepAlive to prevent reaping (default: true)
        #[serde(default = "default_true", rename = "keepAlive")]
        keep_alive: bool,
    },

    /// Sweep all DOT to a recipient (transferAll)
    Consolidate {
        /// Recipient address (SS58)
        to: String,
        /// Keep sender account alive after transfer (default: true)
        #[serde(default = "default_true", rename = "keepAlive")]
        keep_alive: bool,
    },

    /// Stake DOT.
    ///
    /// - With `proxy_address`: new stake → batchAll(bond, addProxy)
    /// - Without `proxy_address`: top-up → bondExtra
    Stake {
        /// Amount to stake in planck
        amount: u64,
        /// Reward destination (default: Staked / compound)
        #[serde(default)]
        payee: StakePayee,
        /// Proxy address for new stake. Absent means top-up (bondExtra).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "proxyAddress"
        )]
        proxy_address: Option<String>,
    },

    /// Unstake DOT.
    ///
    /// - `stop_staking=true`: full unstake → batchAll(removeProxy, chill, unbond)
    /// - `stop_staking=false`: partial unstake → unbond
    Unstake {
        /// Amount to unstake in planck
        amount: u64,
        /// Full unstake (remove proxy + chill) or partial (just unbond)
        #[serde(default, rename = "stopStaking")]
        stop_staking: bool,
        /// Proxy address to remove (required when stopStaking=true)
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            rename = "proxyAddress"
        )]
        proxy_address: Option<String>,
    },

    /// Claim (withdraw unbonded) DOT after the unbonding period
    Claim {
        /// Number of slashing spans (default: 0)
        #[serde(default, rename = "slashingSpans")]
        slashing_spans: u32,
    },

    /// Zero-value self-transfer to advance the account nonce.
    ///
    /// The sender address comes from `BuildContext.sender`.
    FillNonce,
}

// =============================================================================
// Internal: Call-level intents
// =============================================================================

/// Low-level call intent representing a single Polkadot extrinsic call.
///
/// These are internal building blocks used by `intent_to_calls()` and the
/// call encoder. Not part of the public API.
#[derive(Debug, Clone)]
pub(crate) enum CallIntent {
    Transfer {
        to: String,
        amount: u64,
        keep_alive: bool,
    },
    TransferAll {
        to: String,
        keep_alive: bool,
    },
    Bond {
        amount: u64,
        payee: StakePayee,
    },
    BondExtra {
        amount: u64,
    },
    Unbond {
        amount: u64,
    },
    WithdrawUnbonded {
        slashing_spans: u32,
    },
    Chill,
    AddProxy {
        delegate: String,
        proxy_type: String,
        delay: u32,
    },
    RemoveProxy {
        delegate: String,
        proxy_type: String,
        delay: u32,
    },
}

// =============================================================================
// Composition: business intent → call sequence
// =============================================================================

/// Convert a business-level intent into a sequence of call-level intents.
///
/// Returns one call for simple operations, multiple for batched operations
/// (e.g., stake with proxy → bond + addProxy).
pub(crate) fn intent_to_calls(
    intent: &TransactionIntent,
    sender: &str,
) -> Result<Vec<CallIntent>, WasmDotError> {
    match intent {
        TransactionIntent::Payment {
            to,
            amount,
            keep_alive,
        } => Ok(vec![CallIntent::Transfer {
            to: to.clone(),
            amount: *amount,
            keep_alive: *keep_alive,
        }]),

        TransactionIntent::Consolidate { to, keep_alive } => Ok(vec![CallIntent::TransferAll {
            to: to.clone(),
            keep_alive: *keep_alive,
        }]),

        TransactionIntent::Stake {
            amount,
            payee,
            proxy_address,
        } => match proxy_address {
            Some(proxy) => Ok(vec![
                CallIntent::Bond {
                    amount: *amount,
                    payee: payee.clone(),
                },
                CallIntent::AddProxy {
                    delegate: proxy.clone(),
                    proxy_type: "Staking".to_string(),
                    delay: 0,
                },
            ]),
            None => Ok(vec![CallIntent::BondExtra { amount: *amount }]),
        },

        TransactionIntent::Unstake {
            amount,
            stop_staking,
            proxy_address,
        } => {
            if *stop_staking {
                let proxy = proxy_address.as_ref().ok_or_else(|| {
                    WasmDotError::InvalidInput(
                        "Unstake with stopStaking=true requires proxyAddress".to_string(),
                    )
                })?;
                Ok(vec![
                    CallIntent::RemoveProxy {
                        delegate: proxy.clone(),
                        proxy_type: "Staking".to_string(),
                        delay: 0,
                    },
                    CallIntent::Chill,
                    CallIntent::Unbond { amount: *amount },
                ])
            } else {
                Ok(vec![CallIntent::Unbond { amount: *amount }])
            }
        }

        TransactionIntent::Claim { slashing_spans } => Ok(vec![CallIntent::WithdrawUnbonded {
            slashing_spans: *slashing_spans,
        }]),

        TransactionIntent::FillNonce => Ok(vec![CallIntent::Transfer {
            to: sender.to_string(),
            amount: 0,
            keep_alive: true,
        }]),
    }
}

// =============================================================================
// Shared types
// =============================================================================

/// Build context: how to build the transaction (sender, nonce, material, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildContext {
    /// Sender address (SS58 encoded)
    pub sender: String,
    /// Account nonce
    pub nonce: u32,
    /// Optional tip amount (in planck)
    #[serde(default)]
    pub tip: u64,
    /// Chain material metadata
    pub material: Material,
    /// Validity window
    pub validity: Validity,
    /// Reference block hash for mortality
    pub reference_block: String,
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

fn default_true() -> bool {
    true
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Deserialization tests ----

    #[test]
    fn test_deserialize_payment_intent() {
        let json = r#"{
            "type": "payment",
            "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "amount": 1000000000000
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Payment {
                amount, keep_alive, ..
            } => {
                assert_eq!(amount, 1_000_000_000_000);
                assert!(keep_alive); // default
            }
            _ => panic!("Expected Payment"),
        }
    }

    #[test]
    fn test_deserialize_consolidate_intent() {
        let json = r#"{
            "type": "consolidate",
            "to": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
            "keepAlive": false
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Consolidate { keep_alive, .. } => {
                assert!(!keep_alive);
            }
            _ => panic!("Expected Consolidate"),
        }
    }

    #[test]
    fn test_deserialize_stake_new() {
        let json = r#"{
            "type": "stake",
            "amount": 5000000000000,
            "payee": { "type": "staked" },
            "proxyAddress": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Stake {
                amount,
                proxy_address,
                ..
            } => {
                assert_eq!(amount, 5_000_000_000_000);
                assert!(proxy_address.is_some());
            }
            _ => panic!("Expected Stake"),
        }
    }

    #[test]
    fn test_deserialize_stake_topup() {
        let json = r#"{
            "type": "stake",
            "amount": 2000000000000
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Stake {
                amount,
                proxy_address,
                ..
            } => {
                assert_eq!(amount, 2_000_000_000_000);
                assert!(proxy_address.is_none());
            }
            _ => panic!("Expected Stake"),
        }
    }

    #[test]
    fn test_deserialize_unstake_full() {
        let json = r#"{
            "type": "unstake",
            "amount": 1000000000000,
            "stopStaking": true,
            "proxyAddress": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Unstake {
                stop_staking,
                proxy_address,
                ..
            } => {
                assert!(stop_staking);
                assert!(proxy_address.is_some());
            }
            _ => panic!("Expected Unstake"),
        }
    }

    #[test]
    fn test_deserialize_unstake_partial() {
        let json = r#"{
            "type": "unstake",
            "amount": 500000000000
        }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Unstake {
                amount,
                stop_staking,
                ..
            } => {
                assert_eq!(amount, 500_000_000_000);
                assert!(!stop_staking); // default
            }
            _ => panic!("Expected Unstake"),
        }
    }

    #[test]
    fn test_deserialize_claim() {
        let json = r#"{ "type": "claim" }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        match intent {
            TransactionIntent::Claim { slashing_spans } => {
                assert_eq!(slashing_spans, 0); // default
            }
            _ => panic!("Expected Claim"),
        }
    }

    #[test]
    fn test_deserialize_fill_nonce() {
        let json = r#"{ "type": "fillNonce" }"#;
        let intent: TransactionIntent = serde_json::from_str(json).unwrap();
        assert!(matches!(intent, TransactionIntent::FillNonce));
    }

    #[test]
    fn test_deserialize_context() {
        let json = r#"{
            "sender": "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr",
            "nonce": 5,
            "tip": 0,
            "material": {
                "genesisHash": "0x91b171bb158e2d3848fa23a9f1c25182fb8e20313b2c1eb49219da7a70ce90c3",
                "chainName": "Polkadot",
                "specName": "polkadot",
                "specVersion": 9150,
                "txVersion": 9,
                "metadata": "0x00"
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

    // ---- Composition tests ----

    const SENDER: &str = "5EGoFA95omzemRssELLDjVenNZ68aXyUeqtKQScXSEBvVJkr";
    const PROXY: &str = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";

    #[test]
    fn test_payment_composes_to_transfer() {
        let intent = TransactionIntent::Payment {
            to: PROXY.to_string(),
            amount: 1_000_000_000_000,
            keep_alive: true,
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(
            calls[0],
            CallIntent::Transfer {
                keep_alive: true,
                ..
            }
        ));
    }

    #[test]
    fn test_consolidate_composes_to_transfer_all() {
        let intent = TransactionIntent::Consolidate {
            to: PROXY.to_string(),
            keep_alive: false,
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(
            calls[0],
            CallIntent::TransferAll {
                keep_alive: false,
                ..
            }
        ));
    }

    #[test]
    fn test_stake_new_composes_to_bond_and_add_proxy() {
        let intent = TransactionIntent::Stake {
            amount: 1_000_000_000_000,
            payee: StakePayee::Staked,
            proxy_address: Some(PROXY.to_string()),
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], CallIntent::Bond { .. }));
        assert!(matches!(calls[1], CallIntent::AddProxy { .. }));
    }

    #[test]
    fn test_stake_topup_composes_to_bond_extra() {
        let intent = TransactionIntent::Stake {
            amount: 1_000_000_000_000,
            payee: StakePayee::Staked,
            proxy_address: None,
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], CallIntent::BondExtra { .. }));
    }

    #[test]
    fn test_unstake_full_composes_to_remove_proxy_chill_unbond() {
        let intent = TransactionIntent::Unstake {
            amount: 1_000_000_000_000,
            stop_staking: true,
            proxy_address: Some(PROXY.to_string()),
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 3);
        // Order matters: removeProxy, chill, unbond
        assert!(matches!(calls[0], CallIntent::RemoveProxy { .. }));
        assert!(matches!(calls[1], CallIntent::Chill));
        assert!(matches!(calls[2], CallIntent::Unbond { .. }));
    }

    #[test]
    fn test_unstake_partial_composes_to_unbond() {
        let intent = TransactionIntent::Unstake {
            amount: 500_000_000_000,
            stop_staking: false,
            proxy_address: None,
        };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], CallIntent::Unbond { .. }));
    }

    #[test]
    fn test_unstake_full_without_proxy_errors() {
        let intent = TransactionIntent::Unstake {
            amount: 1_000_000_000_000,
            stop_staking: true,
            proxy_address: None,
        };
        let result = intent_to_calls(&intent, SENDER);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires proxyAddress"));
    }

    #[test]
    fn test_claim_composes_to_withdraw_unbonded() {
        let intent = TransactionIntent::Claim { slashing_spans: 0 };
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        assert!(matches!(calls[0], CallIntent::WithdrawUnbonded { .. }));
    }

    #[test]
    fn test_fill_nonce_composes_to_zero_self_transfer() {
        let intent = TransactionIntent::FillNonce;
        let calls = intent_to_calls(&intent, SENDER).unwrap();
        assert_eq!(calls.len(), 1);
        match &calls[0] {
            CallIntent::Transfer {
                to,
                amount,
                keep_alive,
            } => {
                assert_eq!(to, SENDER);
                assert_eq!(*amount, 0);
                assert!(*keep_alive);
            }
            _ => panic!("Expected Transfer"),
        }
    }
}
