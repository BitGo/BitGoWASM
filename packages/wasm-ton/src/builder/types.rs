use serde::Deserialize;

use crate::error::WasmTonError;

/// Build context for constructing transactions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildContext {
    pub sender: String,
    pub seqno: u32,
    pub expire_time: u64,
    pub public_key: Option<String>,
    #[serde(default = "default_wallet_version")]
    pub wallet_version: u32,
    #[serde(default)]
    pub is_vesting_contract: bool,
    #[serde(default)]
    pub sub_wallet_id: Option<u64>,
}

fn default_wallet_version() -> u32 {
    4
}

/// Staking type for delegate/undelegate intents.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub enum TonStakingType {
    TonWhales,
    SingleNominator,
    MultiNominator,
}

/// Intent types for building TON transactions.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TonIntent {
    /// Native TON payment
    #[serde(rename_all = "camelCase")]
    Payment {
        to: String,
        amount: u64,
        bounceable: Option<bool>,
        memo: Option<String>,
    },

    /// Token (jetton) payment
    #[serde(rename = "tokenPayment", rename_all = "camelCase")]
    TokenPayment {
        to: String,
        amount: u64,
        jetton_address: String,
        #[serde(default = "default_ton_amount")]
        ton_amount: u64,
        #[serde(default = "default_forward_ton_amount")]
        forward_ton_amount: u64,
        memo: Option<String>,
    },

    /// Fill nonce (native self-send)
    #[serde(rename = "fillNonce", rename_all = "camelCase")]
    FillNonce {
        #[serde(default)]
        is_token: bool,
        jetton_address: Option<String>,
    },

    /// Consolidate
    #[serde(rename_all = "camelCase")]
    Consolidate {
        #[serde(default)]
        is_token: bool,
        jetton_address: Option<String>,
    },

    /// Delegate (staking)
    #[serde(rename_all = "camelCase")]
    Delegate {
        amount: u64,
        validator_address: String,
        staking_type: TonStakingType,
        #[serde(default)]
        query_id: Option<u64>,
    },

    /// Undelegate (unstaking)
    #[serde(rename_all = "camelCase")]
    Undelegate {
        #[serde(default)]
        amount: Option<u64>,
        validator_address: String,
        staking_type: TonStakingType,
    },
}

fn default_ton_amount() -> u64 {
    100_000_000 // 0.1 TON
}

fn default_forward_ton_amount() -> u64 {
    100 // 100 nanoTON
}

impl TonIntent {
    pub fn validate(&self, context: &BuildContext) -> Result<(), WasmTonError> {
        if let TonIntent::Consolidate { .. } = self {
            if context.wallet_version == 1 {
                return Err(WasmTonError::new(
                    "consolidate not supported for wallet version 1",
                ));
            }
        }
        Ok(())
    }
}
