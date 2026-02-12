//! Types for intent-based transaction building.
//!
//! These types mirror the BitGo intent structures and are deserialized from JavaScript.

use serde::{Deserialize, Serialize};

/// Intent type discriminant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum IntentType {
    Payment,
    GoUnstake,
    Stake,
    Unstake,
    Claim,
    Deactivate,
    Delegate,
    EnableToken,
    CloseAssociatedTokenAccount,
    Consolidate,
    Authorize,
    CustomTx,
}

/// Staking type for stake/unstake intents.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StakingType {
    Jito,
    Marinade,
}

/// Build parameters provided by wallet-platform.
/// These are NOT part of the intent but needed to build the transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildParams {
    /// Fee payer address (wallet root)
    pub fee_payer: String,
    /// Nonce configuration
    pub nonce: Nonce,
}

/// Nonce source for the transaction.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Nonce {
    /// Recent blockhash (standard transactions)
    Blockhash { value: String },
    /// Durable nonce (offline signing)
    Durable {
        address: String,
        authority: String,
        value: String,
    },
}

/// Result from building a transaction from intent.
#[derive(Debug, Clone)]
pub struct IntentBuildResult {
    /// The built transaction
    pub transaction: solana_sdk::transaction::Transaction,
    /// Generated keypairs (for stake accounts, etc.)
    pub generated_keypairs: Vec<GeneratedKeypair>,
}

/// A keypair generated during transaction building.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneratedKeypair {
    /// Purpose of this keypair
    pub purpose: String,
    /// Public address (base58)
    pub address: String,
    /// Secret key (base58)
    pub secret_key: String,
}

// =============================================================================
// Intent Types (match BitGo public-types shapes)
// =============================================================================

/// Base intent - all intents have intentType
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseIntent {
    pub intent_type: String,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Recipient for payment intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    pub address: Option<AddressWrapper>,
    pub amount: Option<AmountWrapper>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressWrapper {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountWrapper {
    /// Amount value - accepts bigint from JS (deserialized as u64)
    #[serde(deserialize_with = "deserialize_amount")]
    pub value: u64,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// Deserialize amount from either string or number (for JS BigInt compatibility)
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
            u64::try_from(v).map_err(|_| de::Error::custom("negative amount"))
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            v.parse().map_err(de::Error::custom)
        }
    }

    deserializer.deserialize_any(AmountVisitor)
}

/// Payment intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentIntent {
    pub intent_type: String,
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Stake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeIntent {
    pub intent_type: IntentType,
    pub validator_address: String,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub staking_type: Option<StakingType>,
    #[serde(default)]
    pub stake_pool_config: Option<StakePoolConfig>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Stake pool configuration (for Jito and other stake pool programs)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakePoolConfig {
    #[serde(default)]
    pub stake_pool_address: Option<String>,
    #[serde(default)]
    pub withdraw_authority: Option<String>,
    pub reserve_stake: String,
    #[serde(default)]
    pub destination_pool_account: Option<String>,
    pub manager_fee_account: String,
    #[serde(default)]
    pub referral_pool_account: Option<String>,
    pub pool_mint: String,
    #[serde(default)]
    pub validator_list: Option<String>,
    #[serde(default)]
    pub source_pool_account: Option<String>,
}

/// Unstake intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnstakeIntent {
    pub intent_type: IntentType,
    /// Staking address - required for native/Jito, must NOT be set for Marinade
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub validator_address: Option<String>,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub remaining_staking_amount: Option<AmountWrapper>,
    #[serde(default)]
    pub staking_type: Option<StakingType>,
    #[serde(default)]
    pub stake_pool_config: Option<StakePoolConfig>,
    /// Recipients - used by Marinade unstake (transfer to contract address)
    #[serde(default)]
    pub recipients: Option<Vec<Recipient>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Claim intent (withdraw from deactivated stake)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimIntent {
    pub intent_type: String,
    pub staking_address: String,
    #[serde(default)]
    pub amount: Option<AmountWrapper>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Deactivate intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeactivateIntent {
    pub intent_type: String,
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub staking_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Delegate intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateIntent {
    pub intent_type: String,
    pub validator_address: String,
    #[serde(default)]
    pub staking_address: Option<String>,
    #[serde(default)]
    pub staking_addresses: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Enable token intent (create ATA)
/// Supports both single token (tokenAddress) and multiple tokens (tokenAddresses array)
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableTokenIntent {
    pub intent_type: String,
    #[serde(default)]
    pub recipient_address: Option<String>,
    /// Single token address (legacy format)
    #[serde(default)]
    pub token_address: Option<String>,
    /// Multiple token addresses (array format from wallet-platform)
    #[serde(default)]
    pub token_addresses: Option<Vec<String>>,
    /// Single token program ID (legacy format)
    #[serde(default)]
    pub token_program_id: Option<String>,
    /// Multiple token program IDs (array format, parallel to token_addresses)
    #[serde(default)]
    pub token_program_ids: Option<Vec<String>>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Close ATA intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloseAtaIntent {
    pub intent_type: String,
    #[serde(default)]
    pub token_account_address: Option<String>,
    #[serde(default)]
    pub token_program_id: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Consolidate intent - transfer from child address to root
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsolidateIntent {
    pub intent_type: String,
    /// The child address to consolidate from (sender)
    pub receive_address: String,
    /// Recipients (root address for SOL, ATAs for tokens)
    #[serde(default)]
    pub recipients: Vec<Recipient>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// Authorize intent - pre-built transaction message
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeIntent {
    pub intent_type: String,
    /// Base64-encoded serialized Solana Message (bincode)
    pub transaction_message: String,
}

/// Custom transaction intent
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxIntent {
    pub intent_type: String,
    /// Custom instructions to include in the transaction
    pub sol_instructions: Vec<CustomTxInstruction>,
    #[serde(default)]
    pub memo: Option<String>,
}

/// A single custom instruction
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxInstruction {
    /// Program ID (base58)
    pub program_id: String,
    /// Account keys for the instruction
    pub keys: Vec<CustomTxKey>,
    /// Instruction data (base64)
    pub data: String,
}

/// Account key for a custom instruction
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTxKey {
    /// Account public key (base58)
    pub pubkey: String,
    /// Whether this account must sign the transaction
    pub is_signer: bool,
    /// Whether this account is writable
    pub is_writable: bool,
}
